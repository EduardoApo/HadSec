begin;
create table public.reference_source_files(
 source text not null check(source='atomic'),sha256 text not null check(sha256~'^[0-9a-f]{64}$'),original text not null check(length(original)<=500000),path text not null,
 sync_id uuid not null references public.reference_sync_runs,primary key(source,sha256)
);
alter table public.reference_rules add column file_sha256 text,add foreign key(source,file_sha256) references public.reference_source_files(source,sha256),add check(source<>'atomic' or file_sha256 is not null);
alter table public.reference_rule_revisions add column file_sha256 text,add foreign key(source,file_sha256) references public.reference_source_files(source,sha256);
alter table public.reference_source_files enable row level security;revoke all on public.reference_source_files from anon,authenticated;grant select on public.reference_source_files to authenticated;
create policy coverage_read on public.reference_source_files for select to authenticated using(public.has_permission('coverage.read'));
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant all on public.reference_source_files to service_role;end if;end $$;
create or replace function public.finish_reference_sync(p_run uuid,p_commit text,p_unchanged boolean default false) returns jsonb language plpgsql security definer set search_path=public set statement_timeout='60s' as $$
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
  insert into reference_rules(source,id,title,description,level,status,category,logsource,tags,techniques,details,original,path,sha256,file_sha256,sync_id)
   select run.source,x.id,x.title,x.description,x.level,x.status,x.category,x.logsource,x.tags,x.techniques,x.details,x.original,x.path,x.sha256,x.file_sha256,p_run
   from reference_staging s cross join lateral jsonb_to_record(s.entry) as x(id text,title text,description text,level text,status text,category text,logsource jsonb,tags text[],techniques text[],details jsonb,original text,path text,sha256 text,file_sha256 text) where s.run_id=p_run
   on conflict(source,id) do update set title=excluded.title,description=excluded.description,level=excluded.level,status=excluded.status,category=excluded.category,logsource=excluded.logsource,tags=excluded.tags,techniques=excluded.techniques,details=excluded.details,original=excluded.original,path=excluded.path,sha256=excluded.sha256,file_sha256=excluded.file_sha256,sync_id=p_run,active=true where reference_rules.sha256 is distinct from excluded.sha256 or not reference_rules.active;
  insert into reference_rule_revisions(source,id,sha256,original,details,path,sync_id,file_sha256)
   select source,id,sha256,original,details,path,sync_id,file_sha256 from reference_rules where source=run.source and active on conflict do nothing;
  delete from reference_staging where run_id=p_run;
 end if;
 update reference_sync_runs set status='success',finished_at=now(),commit=p_commit,total=n where id=p_run;
 insert into audit_events(actor_id,action,entity_id,detail) values(run.actor_id,'catalog.synced',p_run::text,jsonb_build_object('source',run.source,'commit',p_commit,'total',n,'unchanged',p_unchanged));
 return jsonb_build_object('ok',true,'source',run.source,'commit',p_commit,'total',n,'unchanged',p_unchanged);
end $$;
commit;
