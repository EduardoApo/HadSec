begin;
alter table public.roles drop constraint known_permissions;
insert into public.permission_definitions(key,label,description) values
 ('coverage.read','Consultar cobertura de detecção','Consultar catálogos, matriz e vínculos ATT&CK.'),
 ('coverage.write','Mapear cobertura de detecção','Relacionar técnicas, regras e evidências de testes.'),
 ('catalogs.manage','Sincronizar catálogos oficiais','Atualizar snapshots de fontes oficiais com proveniência.');
update public.roles set permissions=permissions||array['coverage.read','coverage.write','catalogs.manage'] where system and name='Administrador';
update public.roles set permissions=permissions||array['coverage.read','coverage.write'] where system and name in ('Engenheiro','Revisor');
update public.roles set permissions=permissions||array['coverage.read'] where system and name='Leitor';
-- Definitions are authoritative; this allows future permission additions without a fixed array constraint.
create function public.guard_role_permissions() returns trigger language plpgsql set search_path=public as $$
begin
 if exists(select 1 from unnest(new.permissions) p where not exists(select 1 from permission_definitions d where d.key=p)) then raise exception 'Permissão desconhecida'; end if;
 return new;
end $$;
create trigger guard_role_permissions before insert or update of permissions on public.roles for each row execute function public.guard_role_permissions();
revoke all on function public.guard_role_permissions() from public,anon,authenticated;

create table public.attack_sync_runs(
 id uuid primary key default gen_random_uuid(), status text not null default 'running' check(status in ('running','success','failed')),
 actor_id uuid not null references public.profiles, started_at timestamptz not null default now(),finished_at timestamptz,
 version text,source_commit text,source_url text,sha256 text,technique_count integer,tactic_count integer,relationship_count integer,error text,
 constraint source_commit_format check(source_commit is null or source_commit~'^[0-9a-f]{40}$')
);
create table public.attack_tactics(
 id text primary key check(id~'^TA[0-9]{4}$'),stix_id text not null unique,shortname text not null unique,name text not null,description text not null,
 ordinal integer not null,sync_id uuid not null references public.attack_sync_runs,active boolean not null default true
);
create table public.attack_techniques(
 id text primary key check(id~'^T[0-9]{4}(\.[0-9]{3})?$'),stix_id text not null unique,name text not null,description text not null,
 platforms text[] not null default '{}',tactics text[] not null default '{}',parent_id text references public.attack_techniques deferrable initially deferred,
 url text not null,modified timestamptz,revoked boolean not null default false,deprecated boolean not null default false,
 active boolean not null default true,sync_id uuid not null references public.attack_sync_runs
);
create index attack_techniques_tactics on public.attack_techniques using gin(tactics);
create index attack_techniques_platforms on public.attack_techniques using gin(platforms);
create table public.attack_relationships(
 stix_id text primary key,source_ref text not null,target_ref text not null,relationship_type text not null,
 description text not null default '',sync_id uuid not null references public.attack_sync_runs,active boolean not null default true
);
create table public.attack_rule_links(
 technique_id text not null references public.attack_techniques,rule_id uuid not null references public.rules,
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),
 primary key(technique_id,rule_id)
);
create table public.attack_test_links(
 technique_id text not null references public.attack_techniques,evidence_id uuid not null references public.test_evidence,
 environment text not null check(length(trim(environment)) between 2 and 160),
 notes text not null check(length(trim(notes)) between 10 and 4000),
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),
 primary key(technique_id,evidence_id)
);
create function public.begin_attack_sync() returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;
begin
 if not has_permission('catalogs.manage') then raise exception 'Sem permissão para sincronizar catálogos'; end if;
 perform pg_advisory_xact_lock(940010);
 update attack_sync_runs set status='failed',finished_at=now(),error='Sincronização interrompida ou expirada. Tente novamente.' where status='running' and started_at<now()-interval '10 minutes';
 if exists(select 1 from attack_sync_runs where status='running') then raise exception 'Uma sincronização MITRE já está em andamento'; end if;
 insert into attack_sync_runs(actor_id) values(auth.uid()) returning id into rid;
 perform audit('attack.sync_started',rid::text);return rid;
end $$;
create function public.publish_attack_sync(p_run uuid,p_catalog jsonb) returns jsonb language plpgsql security definer set search_path=public as $$
declare run attack_sync_runs; n integer; t integer; r integer;
begin
 perform pg_advisory_xact_lock(940010);
 select * into run from attack_sync_runs where id=p_run and status='running' for update;
 if run.id is null then raise exception 'Sincronização indisponível'; end if;
 if coalesce(p_catalog->>'sha256','')!~'^[0-9a-f]{64}$' or coalesce(p_catalog->>'commit','')!~'^[0-9a-f]{40}$' or coalesce(p_catalog->>'version','')!~'^[0-9]+\.[0-9]+$'
  or coalesce(jsonb_typeof(p_catalog->'techniques'),'')<>'array' or coalesce(jsonb_typeof(p_catalog->'tactics'),'')<>'array' or coalesce(jsonb_typeof(p_catalog->'relationships'),'')<>'array' then raise exception 'Snapshot MITRE inválido'; end if;
 if jsonb_array_length(p_catalog->'techniques') not between 100 and 5000 or jsonb_array_length(p_catalog->'tactics') not between 5 and 30 then raise exception 'Snapshot MITRE inválido'; end if;
 update attack_tactics set active=false;update attack_techniques set active=false;update attack_relationships set active=false;
 insert into attack_tactics(id,stix_id,shortname,name,description,ordinal,sync_id)
 select x.id,x.stix_id,x.shortname,x.name,x.description,x.ordinal,p_run from jsonb_to_recordset(p_catalog->'tactics') as x(id text,stix_id text,shortname text,name text,description text,ordinal integer)
 on conflict(id) do update set stix_id=excluded.stix_id,shortname=excluded.shortname,name=excluded.name,description=excluded.description,ordinal=excluded.ordinal,sync_id=p_run,active=true;
 get diagnostics t=row_count;
 insert into attack_techniques(id,stix_id,name,description,platforms,tactics,parent_id,url,modified,revoked,deprecated,sync_id)
 select x.id,x.stix_id,x.name,x.description,x.platforms,x.tactics,x.parent_id,x.url,x.modified,x.revoked,x.deprecated,p_run
 from jsonb_to_recordset(p_catalog->'techniques') as x(id text,stix_id text,name text,description text,platforms text[],tactics text[],parent_id text,url text,modified timestamptz,revoked boolean,deprecated boolean)
 on conflict(id) do update set stix_id=excluded.stix_id,name=excluded.name,description=excluded.description,platforms=excluded.platforms,tactics=excluded.tactics,parent_id=excluded.parent_id,url=excluded.url,modified=excluded.modified,revoked=excluded.revoked,deprecated=excluded.deprecated,sync_id=p_run,active=true;
 get diagnostics n=row_count;
 insert into attack_relationships(stix_id,source_ref,target_ref,relationship_type,description,sync_id)
 select x.stix_id,x.source_ref,x.target_ref,x.relationship_type,x.description,p_run
 from jsonb_to_recordset(p_catalog->'relationships') as x(stix_id text,source_ref text,target_ref text,relationship_type text,description text)
 on conflict(stix_id) do update set source_ref=excluded.source_ref,target_ref=excluded.target_ref,relationship_type=excluded.relationship_type,description=excluded.description,sync_id=p_run,active=true;
 get diagnostics r=row_count;
 update attack_sync_runs set status='success',finished_at=now(),version=p_catalog->>'version',source_commit=p_catalog->>'commit',source_url=p_catalog->>'url',sha256=p_catalog->>'sha256',technique_count=n,tactic_count=t,relationship_count=r where id=p_run;
 insert into audit_events(actor_id,action,entity_id,detail) values(run.actor_id,'attack.synced',p_run::text,jsonb_build_object('version',p_catalog->>'version','techniques',n,'tactics',t,'relationships',r));
 return jsonb_build_object('ok',true,'techniques',n,'tactics',t,'relationships',r,'version',p_catalog->>'version');
end $$;
create function public.link_attack_rule(p_technique text,p_rule uuid,p_remove boolean default false) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('coverage.write') then raise exception 'Sem permissão para mapear cobertura'; end if;
 if not exists(select 1 from attack_techniques where id=p_technique and active and not revoked and not deprecated) then raise exception 'Técnica indisponível'; end if;
 if not exists(select 1 from rules where id=p_rule and not archived) then raise exception 'Regra indisponível'; end if;
 if p_remove then delete from attack_rule_links where technique_id=p_technique and rule_id=p_rule;
 else insert into attack_rule_links(technique_id,rule_id,created_by) values(p_technique,p_rule,auth.uid()) on conflict do nothing;end if;
 perform audit(case when p_remove then 'attack.rule_unlinked' else 'attack.rule_linked' end,p_technique,jsonb_build_object('rule_id',p_rule));
end $$;
create function public.link_attack_test(p_technique text,p_evidence uuid,p_environment text,p_notes text,p_remove boolean default false) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('coverage.write') then raise exception 'Sem permissão para mapear cobertura'; end if;
 if not exists(select 1 from attack_techniques where id=p_technique and active and not revoked and not deprecated) then raise exception 'Técnica indisponível'; end if;
 if not exists(select 1 from test_evidence e join rule_versions v on v.id=e.version_id join attack_rule_links l on l.rule_id=v.rule_id and l.technique_id=p_technique join rules r on r.id=v.rule_id where e.id=p_evidence and not r.archived) then raise exception 'Vincule primeiro a regra desta evidência à técnica';end if;
 if p_remove then delete from attack_test_links where technique_id=p_technique and evidence_id=p_evidence;
 else insert into attack_test_links(technique_id,evidence_id,environment,notes,created_by) values(p_technique,p_evidence,trim(p_environment),trim(p_notes),auth.uid()) on conflict(technique_id,evidence_id) do update set environment=excluded.environment,notes=excluded.notes;end if;
 perform audit(case when p_remove then 'attack.test_unlinked' else 'attack.test_linked' end,p_technique,jsonb_build_object('evidence_id',p_evidence));
end $$;
do $$declare t text;begin
 foreach t in array array['attack_sync_runs','attack_tactics','attack_techniques','attack_relationships','attack_rule_links','attack_test_links'] loop
 execute format('alter table public.%I enable row level security',t);
 execute format('revoke all on public.%I from anon,authenticated',t);
 execute format('grant select on public.%I to authenticated',t);
 execute format('create policy coverage_read on public.%I for select to authenticated using(public.has_permission(''coverage.read''))',t);
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.begin_attack_sync(),public.publish_attack_sync(uuid,jsonb),public.link_attack_rule(text,uuid,boolean),public.link_attack_test(text,uuid,text,text,boolean) from public,anon,authenticated;
grant execute on function public.begin_attack_sync(),public.link_attack_rule(text,uuid,boolean),public.link_attack_test(text,uuid,text,text,boolean) to authenticated;
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant execute on function public.publish_attack_sync(uuid,jsonb) to service_role;end if;end $$;
commit;
