begin;
create table public.hunting_imports(
 id uuid primary key default gen_random_uuid(),hypothesis_id uuid not null references public.hunting_hypotheses,file_id uuid not null references public.operational_evidence,
 file_sha256 text not null,source text not null check(source in ('chainsaw','hayabusa','velociraptor','structured')),
 adapter_version text not null,mapping jsonb not null check(length(mapping::text)<10000),mapping_sha256 text not null,
 expected_count integer not null check(expected_count between 1 and 5000),missing_date_count integer not null,
 rule_id uuid references public.rules,actor_id uuid not null references public.profiles,
 status text not null default 'running' check(status in ('running','ready','failed')),active boolean not null default false,
 created_at timestamptz not null default now(),finished_at timestamptz,error text
);
create unique index unique_ready_hunting_import on public.hunting_imports(hypothesis_id,file_sha256,source,mapping_sha256) where status='ready';
create table public.hunting_event_staging(
 import_id uuid not null references public.hunting_imports,record_index integer not null check(record_index between 1 and 5000),entry jsonb not null check(length(entry::text)<150000),primary key(import_id,record_index)
);
create table public.hunting_events(
 id uuid primary key default gen_random_uuid(),import_id uuid not null references public.hunting_imports,record_index integer not null check(record_index between 1 and 5000),
 event_at timestamptz check(event_at is null or isfinite(event_at)),original_timestamp text not null default '' check(length(original_timestamp)<=300),
 host text not null default '' check(length(host)<=300),user_name text not null default '' check(length(user_name)<=300),
 source_ip text not null default '' check(length(source_ip)<=200),destination_ip text not null default '' check(length(destination_ip)<=200),event_identifier text not null default '' check(length(event_identifier)<=300),
 techniques text[] not null default '{}',summary text not null default '' check(length(summary)<=4000),
 normalization_warnings jsonb not null default '[]' check(jsonb_typeof(normalization_warnings)='array' and jsonb_array_length(normalization_warnings)<=20),
 raw_event jsonb not null check(jsonb_typeof(raw_event)='object' and length(raw_event::text)<120000),unique(import_id,record_index)
);
create index hunting_events_time on public.hunting_events(event_at,id);
create index hunting_events_techniques on public.hunting_events using gin(techniques);
create function public.begin_hunting_import(p_actor uuid,p_hypothesis uuid,p_file uuid,p_source text,p_adapter text,p_mapping jsonb,p_count integer,p_missing_dates integer,p_rule uuid default null) returns jsonb language plpgsql security definer set search_path=public as $$
declare file operational_evidence;previous hunting_imports;rid uuid;map_sha text;
begin
 if not actor_has_permission(p_actor,'hunting.write') or not actor_has_permission(p_actor,'hunting.read') then raise exception 'Sem permissão para importar evidências';end if;
 if not exists(select 1 from hunting_hypotheses h join operational_subjects s on s.id=h.id where h.id=p_hypothesis and not s.archived) then raise exception 'Hipótese indisponível';end if;
 select * into file from operational_evidence where id=p_file and subject_id=p_hypothesis and status='ready';
 if file.id is null or file.mime not in ('application/json','text/csv','text/plain') then raise exception 'Selecione um arquivo estruturado e verificado desta hipótese';end if;
 if p_source is null or p_source not in ('chainsaw','hayabusa','velociraptor','structured') or p_adapter is distinct from 'hadsec-structured-1' or p_mapping is null or jsonb_typeof(p_mapping)<>'object' or length(p_mapping::text)>=10000 then raise exception 'Adaptador ou mapeamento inválido';end if;
 if p_rule is not null and not exists(select 1 from rules where id=p_rule and not archived) then raise exception 'Regra interna indisponível';end if;
 if p_count is null or p_count not between 1 and 5000 or p_missing_dates is null or p_missing_dates not between 0 and p_count then raise exception 'Totais de importação inválidos';end if;
 map_sha=encode(sha256(convert_to(p_mapping::text||coalesce(p_rule::text,''),'UTF8')),'hex');perform pg_advisory_xact_lock(940020);
 select * into previous from hunting_imports where hypothesis_id=p_hypothesis and file_sha256=file.sha256 and source=p_source and mapping_sha256=map_sha and status='ready';
 if previous.id is not null then
  update hunting_imports set active=false where hypothesis_id=p_hypothesis and file_sha256=file.sha256 and source=p_source and active and id<>previous.id;
  update hunting_imports set active=true where id=previous.id;
  insert into audit_events(actor_id,action,entity_id,detail) values(p_actor,'hunting.import_reused',previous.id::text,jsonb_build_object('hypothesis_id',p_hypothesis,'events',previous.expected_count));
  return jsonb_build_object('id',previous.id,'unchanged',true,'total',previous.expected_count);
 end if;
 update hunting_imports set status='failed',finished_at=now(),error='Importação interrompida ou expirada.' where hypothesis_id=p_hypothesis and file_sha256=file.sha256 and source=p_source and status='running' and created_at<now()-interval '10 minutes';
 if exists(select 1 from hunting_imports where hypothesis_id=p_hypothesis and file_sha256=file.sha256 and source=p_source and status='running') then raise exception 'Uma importação deste arquivo já está em andamento';end if;
 insert into hunting_imports(hypothesis_id,file_id,file_sha256,source,adapter_version,mapping,mapping_sha256,expected_count,missing_date_count,rule_id,actor_id)
 values(p_hypothesis,p_file,file.sha256,p_source,p_adapter,p_mapping,map_sha,p_count,p_missing_dates,p_rule,p_actor) returning id into rid;
 insert into audit_events(actor_id,action,entity_id,detail) values(p_actor,'hunting.import_started',rid::text,jsonb_build_object('hypothesis_id',p_hypothesis,'file_sha256',file.sha256,'source',p_source));
 return jsonb_build_object('id',rid,'unchanged',false);
end $$;
create function public.publish_hunting_import(p_import uuid,p_actor uuid) returns jsonb language plpgsql security definer set search_path=public set statement_timeout='60s' as $$
declare run hunting_imports;n integer;
begin
 if not actor_has_permission(p_actor,'hunting.write') or not actor_has_permission(p_actor,'hunting.read') then raise exception 'Sem permissão para publicar esta importação';end if;
 select * into run from hunting_imports where id=p_import and actor_id=p_actor and status='running' for update;
 if run.id is null then raise exception 'Importação indisponível';end if;
 if not exists(select 1 from operational_subjects where id=run.hypothesis_id and kind='hypothesis' and not archived) then raise exception 'Hipótese indisponível';end if;
 if not exists(select 1 from operational_evidence where id=run.file_id and subject_id=run.hypothesis_id and status='ready' and sha256=run.file_sha256) then raise exception 'Evidência original não confirmada';end if;
 select count(*) into n from hunting_event_staging where import_id=p_import;
 if n<>run.expected_count then raise exception 'O lote recebido está incompleto';end if;
 insert into hunting_events(import_id,record_index,event_at,original_timestamp,host,user_name,source_ip,destination_ip,event_identifier,techniques,summary,normalization_warnings,raw_event)
 select p_import,s.record_index,x.event_at,x.original_timestamp,x.host,x.user_name,x.source_ip,x.destination_ip,x.event_identifier,x.techniques,x.summary,x.normalization_warnings,x.raw_event
 from hunting_event_staging s cross join lateral jsonb_to_record(s.entry) as x(event_at timestamptz,original_timestamp text,host text,user_name text,source_ip text,destination_ip text,event_identifier text,techniques text[],summary text,normalization_warnings jsonb,raw_event jsonb) where s.import_id=p_import;
 if (select count(*) from hunting_events where import_id=p_import and event_at is null)<>run.missing_date_count then raise exception 'A contagem de eventos sem data diverge do lote';end if;
 update hunting_imports set active=false where hypothesis_id=run.hypothesis_id and file_sha256=run.file_sha256 and source=run.source and active and id<>p_import;
 update hunting_imports set active=true,status='ready',finished_at=now() where id=p_import;
 delete from hunting_event_staging where import_id=p_import;
 insert into audit_events(actor_id,action,entity_id,detail) values(p_actor,'hunting.imported',p_import::text,jsonb_build_object('hypothesis_id',run.hypothesis_id,'source',run.source,'events',n,'missing_dates',run.missing_date_count,'file_sha256',run.file_sha256));
 return jsonb_build_object('ok',true,'id',p_import,'total',n,'missingDates',run.missing_date_count,'unchanged',false);
end $$;
create function public.search_hunting_events(p_hypothesis uuid default null,p_query text default '',p_host text default '',p_user text default '',p_ip text default '',p_technique text default '',p_source text default '',p_from timestamptz default null,p_to timestamptz default null,p_offset integer default 0,p_limit integer default 50) returns jsonb language plpgsql security definer set search_path=public as $$
declare result jsonb;
begin
 if not has_permission('hunting.read') then raise exception 'Sem permissão para consultar a timeline';end if;
 if p_offset<0 or p_offset>1000000 or p_limit not between 1 and 200 or length(p_query)>200 or length(p_host)>200 or length(p_user)>200 or length(p_ip)>200 or (p_from is not null and p_to is not null and p_from>p_to) then raise exception 'Filtro de timeline inválido';end if;
 with filtered as(select e.*,i.hypothesis_id,i.source,i.file_id,i.file_sha256,i.rule_id,i.mapping,i.adapter_version
  from hunting_events e join hunting_imports i on i.id=e.import_id join operational_subjects s on s.id=i.hypothesis_id
  where i.status='ready' and i.active and not s.archived and (p_hypothesis is null or i.hypothesis_id=p_hypothesis)
  and (p_query='' or position(lower(p_query) in lower(e.summary||' '||e.event_identifier||' '||e.host||' '||e.user_name))>0)
  and (p_host='' or position(lower(p_host) in lower(e.host))>0) and(p_user='' or position(lower(p_user) in lower(e.user_name))>0)
  and (p_ip='' or position(p_ip in e.source_ip)>0 or position(p_ip in e.destination_ip)>0)
  and (p_technique='' or upper(p_technique)=any(e.techniques)) and (p_source='' or i.source=p_source)
  and (p_from is null or e.event_at>=p_from) and (p_to is null or e.event_at<=p_to)),
 items as(select id,import_id,record_index,event_at,original_timestamp,host,user_name,source_ip,destination_ip,event_identifier,techniques,summary,normalization_warnings,hypothesis_id,source,file_id,file_sha256,rule_id from filtered order by event_at nulls last,id offset p_offset limit p_limit)
 select jsonb_build_object('total',(select count(*) from filtered),'missingDates',(select count(*) from filtered where event_at is null),'items',coalesce((select jsonb_agg(to_jsonb(items)) from items),'[]'::jsonb)) into result;return result;
end $$;
do $$declare t text;begin
 foreach t in array array['hunting_imports','hunting_events','hunting_event_staging'] loop
 execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);
 if t<>'hunting_event_staging' then execute format('grant select on public.%I to authenticated',t);execute format('create policy hunting_read on public.%I for select to authenticated using(public.has_permission(''hunting.read''))',t);end if;
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.begin_hunting_import(uuid,uuid,uuid,text,text,jsonb,integer,integer,uuid),public.publish_hunting_import(uuid,uuid),public.search_hunting_events(uuid,text,text,text,text,text,text,timestamptz,timestamptz,integer,integer) from public,anon,authenticated;
grant execute on function public.search_hunting_events(uuid,text,text,text,text,text,text,timestamptz,timestamptz,integer,integer) to authenticated;
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant execute on function public.begin_hunting_import(uuid,uuid,uuid,text,text,jsonb,integer,integer,uuid),public.publish_hunting_import(uuid,uuid) to service_role;end if;end $$;
commit;
