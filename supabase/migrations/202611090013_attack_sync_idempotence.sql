begin;
-- Idempotent synchronization: avoid rewriting an unchanged public catalog.
create or replace function public.publish_attack_sync(p_run uuid,p_catalog jsonb) returns jsonb language plpgsql security definer set search_path=public set statement_timeout='60s' as $$
declare run attack_sync_runs; n integer; t integer; r integer;
begin
 perform pg_advisory_xact_lock(940010);
 select * into run from attack_sync_runs where id=p_run and status='running' for update;
 if run.id is null then raise exception 'Sincronização indisponível'; end if;
 if coalesce(p_catalog->>'sha256','')!~'^[0-9a-f]{64}$' or coalesce(p_catalog->>'commit','')!~'^[0-9a-f]{40}$' or coalesce(p_catalog->>'version','')!~'^[0-9]+\.[0-9]+$'
  or coalesce(jsonb_typeof(p_catalog->'techniques'),'')<>'array' or coalesce(jsonb_typeof(p_catalog->'tactics'),'')<>'array' or coalesce(jsonb_typeof(p_catalog->'relationships'),'')<>'array' then raise exception 'Snapshot MITRE inválido'; end if;
 if jsonb_array_length(p_catalog->'techniques') not between 100 and 5000 or jsonb_array_length(p_catalog->'tactics') not between 5 and 30 then raise exception 'Snapshot MITRE inválido'; end if;
 if exists(select 1 from attack_sync_runs where status='success' and sha256=p_catalog->>'sha256') then
  n=jsonb_array_length(p_catalog->'techniques');t=jsonb_array_length(p_catalog->'tactics');r=jsonb_array_length(p_catalog->'relationships');
  update attack_sync_runs set status='success',finished_at=now(),version=p_catalog->>'version',source_commit=p_catalog->>'commit',source_url=p_catalog->>'url',sha256=p_catalog->>'sha256',technique_count=n,tactic_count=t,relationship_count=r where id=p_run;
  insert into audit_events(actor_id,action,entity_id,detail) values(run.actor_id,'attack.synced',p_run::text,jsonb_build_object('version',p_catalog->>'version','techniques',n,'unchanged',true));
  return jsonb_build_object('ok',true,'techniques',n,'tactics',t,'relationships',r,'version',p_catalog->>'version','unchanged',true);
 end if;
 update attack_tactics set active=false where active;update attack_techniques set active=false where active;update attack_relationships set active=false where active;
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
commit;
