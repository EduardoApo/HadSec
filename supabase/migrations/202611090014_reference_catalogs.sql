begin;
create table public.reference_sync_runs(
 id uuid primary key default gen_random_uuid(),source text not null check(source in ('sigma','atomic')),status text not null default 'running' check(status in ('running','success','failed')),
 actor_id uuid not null references public.profiles,started_at timestamptz not null default now(),finished_at timestamptz,commit text,total integer,error text,unique(id,source)
);
create table public.reference_staging(
 run_id uuid not null,source text not null,id text not null,entry jsonb not null,
 primary key(run_id,id),foreign key(run_id,source) references public.reference_sync_runs(id,source),check(length(entry::text)<700000)
);
create table public.reference_rules(
 source text not null check(source in ('sigma','atomic')),id text not null,title text not null,description text not null,
 level text not null,status text not null,category text not null,logsource jsonb not null,tags text[] not null,techniques text[] not null,
 details jsonb not null,original text not null,path text not null,sha256 text not null check(sha256~'^[0-9a-f]{64}$'),
 sync_id uuid not null references public.reference_sync_runs,active boolean not null default true,
 primary key(source,id)
);
create index reference_rules_techniques on public.reference_rules using gin(techniques);
create table public.reference_rule_revisions(
 source text not null,id text not null,sha256 text not null,original text not null,details jsonb not null,path text not null,
 sync_id uuid not null references public.reference_sync_runs,imported_at timestamptz not null default now(),
 primary key(source,id,sha256),foreign key(source,id) references public.reference_rules(source,id)
);
create table public.reference_rule_links(
 source text not null,reference_id text not null,rule_id uuid not null references public.rules,
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),
 primary key(source,reference_id,rule_id),foreign key(source,reference_id) references public.reference_rules(source,id)
);
create table public.reference_request_links(
 request_id uuid primary key references public.change_requests,source text not null,reference_id text not null,sha256 text not null,
 foreign key(source,reference_id,sha256) references public.reference_rule_revisions(source,id,sha256)
);
create function public.begin_reference_sync(p_source text) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;
begin
 if not has_permission('catalogs.manage') then raise exception 'Sem permissão para sincronizar catálogos';end if;
 if p_source is null or p_source not in ('sigma','atomic') then raise exception 'Fonte inválida';end if;
 perform pg_advisory_xact_lock(940014);
 update reference_sync_runs set status='failed',finished_at=now(),error='Sincronização interrompida ou expirada.' where source=p_source and status='running' and started_at<now()-interval '10 minutes';
 if exists(select 1 from reference_sync_runs where source=p_source and status='running') then raise exception 'Uma sincronização desta fonte já está em andamento';end if;
 insert into reference_sync_runs(source,actor_id) values(p_source,auth.uid()) returning id into rid;perform audit('catalog.sync_started',rid::text,jsonb_build_object('source',p_source));return rid;
end $$;
create function public.finish_reference_sync(p_run uuid,p_commit text,p_unchanged boolean default false) returns jsonb language plpgsql security definer set search_path=public set statement_timeout='60s' as $$
declare run reference_sync_runs; n integer;
begin
 perform pg_advisory_xact_lock(940014);select * into run from reference_sync_runs where id=p_run and status='running' for update;
 if run.id is null or p_commit is null or p_commit!~'^[0-9a-f]{40}$' then raise exception 'Sincronização inválida';end if;
 if p_unchanged then
  select total into n from reference_sync_runs where source=run.source and commit=p_commit and status='success' order by started_at desc limit 1;
  if n is null then raise exception 'Snapshot anterior inexistente';end if;
 else
  select count(*) into n from reference_staging where run_id=p_run;
  if n<(case when run.source='sigma' then 100 else 1 end) or n>20000 then raise exception 'Catálogo incompleto ou excessivo';end if;
  if exists(select 1 from reference_staging where run_id=p_run and (coalesce(entry->>'sha256','')!~'^[0-9a-f]{64}$' or entry->>'id' is distinct from id or length(coalesce(entry->>'title',''))<3)) then raise exception 'Registro de catálogo inválido';end if;
  update reference_rules r set active=false where r.source=run.source and r.active and not exists(select 1 from reference_staging s where s.run_id=p_run and s.id=r.id);
  insert into reference_rules(source,id,title,description,level,status,category,logsource,tags,techniques,details,original,path,sha256,sync_id)
   select run.source,x.id,x.title,x.description,x.level,x.status,x.category,x.logsource,x.tags,x.techniques,x.details,x.original,x.path,x.sha256,p_run
   from reference_staging s cross join lateral jsonb_to_record(s.entry) as x(id text,title text,description text,level text,status text,category text,logsource jsonb,tags text[],techniques text[],details jsonb,original text,path text,sha256 text) where s.run_id=p_run
   on conflict(source,id) do update set title=excluded.title,description=excluded.description,level=excluded.level,status=excluded.status,category=excluded.category,logsource=excluded.logsource,tags=excluded.tags,techniques=excluded.techniques,details=excluded.details,original=excluded.original,path=excluded.path,sha256=excluded.sha256,sync_id=p_run,active=true where reference_rules.sha256 is distinct from excluded.sha256 or not reference_rules.active;
  insert into reference_rule_revisions(source,id,sha256,original,details,path,sync_id)
   select source,id,sha256,original,details,path,sync_id from reference_rules where source=run.source and active on conflict do nothing;
  delete from reference_staging where run_id=p_run;
 end if;
 update reference_sync_runs set status='success',finished_at=now(),commit=p_commit,total=n where id=p_run;
 insert into audit_events(actor_id,action,entity_id,detail) values(run.actor_id,'catalog.synced',p_run::text,jsonb_build_object('source',run.source,'commit',p_commit,'total',n,'unchanged',p_unchanged));
 return jsonb_build_object('ok',true,'source',run.source,'commit',p_commit,'total',n,'unchanged',p_unchanged);
end $$;
create function public.search_reference_rules(p_source text,p_query text default '',p_level text default '',p_status text default '',p_category text default '',p_offset integer default 0,p_limit integer default 30) returns jsonb language plpgsql security definer set search_path=public as $$
declare result jsonb;
begin
 if not has_permission('coverage.read') then raise exception 'Sem permissão para consultar catálogos';end if;
 if p_source not in ('sigma','atomic') or p_source is null or p_offset<0 or p_offset>100000 or p_limit not between 1 and 100 or length(p_query)>200 then raise exception 'Filtro inválido';end if;
 with filtered as (select * from reference_rules where source=p_source and active
  and (p_query='' or position(lower(p_query) in lower(title||' '||description||' '||array_to_string(tags,' ')||' '||logsource::text||' '||array_to_string(techniques,' ')))>0)
  and (p_level='' or level=p_level) and (p_status='' or status=p_status) and (p_category='' or category=p_category)),
 items as (select source,id,title,left(description,240) description,level,status,category,logsource,tags,techniques,sha256,path from filtered order by title,id offset p_offset limit p_limit)
 select jsonb_build_object('total',(select count(*) from filtered),'items',coalesce((select jsonb_agg(to_jsonb(items)) from items),'[]'::jsonb),
 'facets',jsonb_build_object('levels',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct level v from reference_rules where source=p_source and active order by level)a),'statuses',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct status v from reference_rules where source=p_source and active order by status)a),'categories',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct category v from reference_rules where source=p_source and active order by category)a))) into result;
 return result;
end $$;
create function public.link_reference_rule(p_source text,p_reference text,p_rule uuid,p_remove boolean default false) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('coverage.write') then raise exception 'Sem permissão para relacionar regras';end if;
 if not exists(select 1 from reference_rules where source=p_source and id=p_reference and active) or not exists(select 1 from rules where id=p_rule and not archived) then raise exception 'Regra indisponível';end if;
 if p_remove then delete from reference_rule_links where source=p_source and reference_id=p_reference and rule_id=p_rule;
 else insert into reference_rule_links(source,reference_id,rule_id,created_by) values(p_source,p_reference,p_rule,auth.uid()) on conflict do nothing;end if;
 perform audit(case when p_remove then 'catalog.rule_unlinked' else 'catalog.rule_linked' end,p_reference,jsonb_build_object('source',p_source,'rule_id',p_rule));
end $$;
create function public.create_sigma_request(p_reference text,p_title text,p_description text) returns uuid language plpgsql security definer set search_path=public as $$
declare reference reference_rules;run reference_sync_runs;rid uuid;
begin
 if not has_permission('requests.create') or not has_permission('coverage.read') then raise exception 'Sem permissão para solicitar regras do catálogo';end if;
 select * into reference from reference_rules where source='sigma' and id=p_reference and active;
 if reference.id is null then raise exception 'Referência Sigma indisponível';end if;
 select * into run from reference_sync_runs where id=reference.sync_id;
 rid=submit_change_request('create',p_title,left(p_description,7000)||E'\n\nReferência SigmaHQ: '||reference.title||E'\nhttps://github.com/SigmaHQ/sigma/blob/'||run.commit||'/'||reference.path||E'\nSHA-256: '||reference.sha256,'sigma','Native',null,null);
 insert into reference_request_links(request_id,source,reference_id,sha256) values(rid,'sigma',reference.id,reference.sha256);
 perform audit('catalog.request_created',rid::text,jsonb_build_object('source','sigma','reference_id',reference.id,'sha256',reference.sha256));return rid;
end $$;
do $$declare t text;begin
 foreach t in array array['reference_sync_runs','reference_rules','reference_rule_revisions','reference_rule_links','reference_request_links','reference_staging'] loop
 execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);
 if t<>'reference_staging' then execute format('grant select on public.%I to authenticated',t);execute format('create policy coverage_read on public.%I for select to authenticated using(public.has_permission(''coverage.read''))',t);end if;
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.begin_reference_sync(text),public.finish_reference_sync(uuid,text,boolean),public.search_reference_rules(text,text,text,text,text,integer,integer),public.link_reference_rule(text,text,uuid,boolean),public.create_sigma_request(text,text,text) from public,anon,authenticated;
grant execute on function public.begin_reference_sync(text),public.search_reference_rules(text,text,text,text,text,integer,integer),public.link_reference_rule(text,text,uuid,boolean),public.create_sigma_request(text,text,text) to authenticated;
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant execute on function public.finish_reference_sync(uuid,text,boolean) to service_role;end if;end $$;
commit;
