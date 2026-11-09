begin;
create table public.operational_evidence(
 id uuid primary key default gen_random_uuid(),subject_id uuid not null references public.operational_subjects,
 original_name text not null check(length(original_name) between 1 and 200),size_bytes integer not null check(size_bytes between 1 and 10000000),
 mime text not null check(mime in ('text/plain','text/csv','application/json','application/pdf','image/png','image/jpeg')),
 sha256 text not null check(sha256~'^[0-9a-f]{64}$'),storage_path text not null unique,
 status text not null default 'pending' check(status in ('pending','ready')),
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),verified_at timestamptz
);
create function public.can_read_subject(p_subject uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from operational_subjects where id=p_subject and not archived and
  case when kind='validation' then has_permission('coverage.read') else has_permission('hunting.read') end)
$$;
create function public.can_write_subject(p_subject uuid) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from operational_subjects where id=p_subject and not archived and
  case when kind='validation' then has_permission('validation.record') else has_permission('hunting.write') end)
$$;
create function public.begin_operational_evidence(p_subject uuid,p_name text,p_size integer,p_mime text,p_sha256 text) returns public.operational_evidence language plpgsql security definer set search_path=public as $$
declare row operational_evidence;fid uuid=gen_random_uuid();ext text;
begin
 if not can_write_subject(p_subject) then raise exception 'Sem permissão para anexar evidências neste registro';end if;
 perform id from operational_subjects where id=p_subject for update;
 if (select count(*) from operational_evidence where subject_id=p_subject)>=50 or (select coalesce(sum(size_bytes),0) from operational_evidence where subject_id=p_subject)+p_size>100000000 then raise exception 'O registro atingiu o limite de 50 arquivos ou 100 MB';end if;
 if p_name is null or p_name~'[[:cntrl:]/\\]' or lower(p_name)!~'\.(png|jpe?g|pdf|json|ndjson|csv|txt|log)$' then raise exception 'Formato de evidência não permitido';end if;
 ext=lower(substring(p_name from '\.([^.]+)$'));
 insert into operational_evidence(id,subject_id,original_name,size_bytes,mime,sha256,storage_path,created_by)
 values(fid,p_subject,p_name,p_size,p_mime,p_sha256,p_subject::text||'/'||fid::text||'.'||ext,auth.uid()) returning * into row;
 perform audit('evidence.upload_started',fid::text,jsonb_build_object('subject_id',p_subject,'size',p_size,'sha256',p_sha256));return row;
end $$;
create function public.finalize_operational_evidence(p_file uuid,p_actor uuid,p_sha256 text) returns void language plpgsql security definer set search_path=public as $$
declare row operational_evidence;
begin
 select * into row from operational_evidence where id=p_file for update;
 if row.id is null or row.created_by<>p_actor or row.sha256 is distinct from p_sha256 then raise exception 'Integridade ou autoria da evidência inválida';end if;
 if not exists(select 1 from profiles where id=p_actor and active and deleted_at is null and not must_change_password) then raise exception 'Conta indisponível';end if;
 if row.status='ready' then return;end if;
 update operational_evidence set status='ready',verified_at=now() where id=p_file;
 insert into audit_events(actor_id,action,entity_id,detail) values(p_actor,'evidence.upload_verified',p_file::text,jsonb_build_object('subject_id',row.subject_id,'sha256',row.sha256,'size',row.size_bytes));
end $$;
alter table public.operational_evidence enable row level security;
revoke all on public.operational_evidence from anon,authenticated;
grant select on public.operational_evidence to authenticated;
create policy subject_read on public.operational_evidence for select to authenticated using(public.can_read_subject(subject_id) and (status='ready' or created_by=auth.uid()));
revoke all on function public.can_read_subject(uuid),public.can_write_subject(uuid),public.begin_operational_evidence(uuid,text,integer,text,text),public.finalize_operational_evidence(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.can_read_subject(uuid),public.can_write_subject(uuid),public.begin_operational_evidence(uuid,text,integer,text,text) to authenticated;
do $$begin
 if exists(select 1 from pg_roles where rolname='service_role') then grant all on public.operational_evidence to service_role;grant execute on function public.finalize_operational_evidence(uuid,uuid,text) to service_role;end if;
 if to_regclass('storage.buckets') is not null then
 execute $sql$insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
 values('hadsec-evidence','hadsec-evidence',false,10000000,array['text/plain','text/csv','application/json','application/pdf','image/png','image/jpeg'])
 on conflict(id) do update set public=false,file_size_limit=10000000,allowed_mime_types=excluded.allowed_mime_types$sql$;
 end if;
end $$;
-- No public Storage policies: uploads and downloads require server-authorized signed URLs.
commit;
