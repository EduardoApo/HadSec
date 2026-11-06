begin;

-- Ownership is pinned to an identity once, never inferred from a caller's role/name.
create table public.workspace_owner (
 singleton boolean primary key default true check(singleton),
 user_id uuid not null unique references public.profiles(id)
);
alter table public.workspace_owner enable row level security;
revoke all on public.workspace_owner from public,anon,authenticated;
insert into public.workspace_owner(user_id)
 select p.id from public.profiles p join public.roles r on r.id=p.role_id
 where lower(p.username)='hadsec' and p.active and p.deleted_at is null
 and r.system and r.name='Administrador'
 on conflict(singleton) do nothing;

-- Supports a fresh installation whose initial HadSec account is created after migrations.
create function public.pin_initial_workspace_owner() returns trigger
language plpgsql security definer set search_path=public as $$
begin
 if lower(new.username)='hadsec' and new.active and new.deleted_at is null
 and exists(select 1 from roles where id=new.role_id and system and name='Administrador') then
  insert into workspace_owner(user_id) values(new.id) on conflict(singleton) do nothing;
 end if;
 return new;
end $$;
revoke all on function public.pin_initial_workspace_owner() from public,anon,authenticated;
create trigger pin_initial_workspace_owner after insert on public.profiles
 for each row execute function public.pin_initial_workspace_owner();

create function public.record_capabilities() returns jsonb
language sql stable security definer set search_path=public as $$
 select jsonb_build_object('owner',exists(
  select 1 from workspace_owner o join profiles p on p.id=o.user_id
  where o.user_id=auth.uid() and p.active and p.deleted_at is null and not p.must_change_password
 ));
$$;

alter table public.change_requests
 add column deleted_at timestamptz,
 add column deleted_by uuid references public.profiles(id),
 add column github_hidden_at timestamptz,
 add column github_hidden_by uuid references public.profiles(id),
 add constraint request_deletion_pair check((deleted_at is null)=(deleted_by is null)),
 add constraint github_deletion_pair check((github_hidden_at is null)=(github_hidden_by is null));

-- A deleted, unpublished review may be requested again. A published version stays unique.
drop index public.one_active_version_request;
create unique index one_active_version_request on public.change_requests(version_id)
 where version_id is not null and (status='published' or (deleted_at is null and status in ('review','approved')));

create function public.delete_request(p_request uuid,p_confirmation text) returns void
language plpgsql security definer set search_path=public as $$
declare r change_requests;
begin
 if not (record_capabilities()->>'owner')::boolean then raise exception 'Somente o proprietário pode excluir solicitações'; end if;
 select * into r from change_requests where id=p_request for update;
 if r.id is null then raise exception 'Solicitação indisponível'; end if;
 if p_confirmation is distinct from r.title then raise exception 'Digite o título exato da solicitação para confirmar'; end if;
 if r.deleted_at is not null then return; end if;
 if r.export_lease_until>now() then raise exception 'Aguarde a conclusão do envio ao GitHub antes de excluir'; end if;
 update change_requests set deleted_at=now(),deleted_by=auth.uid(),updated_at=now(),
  github_hidden_at=case when status='published' then coalesce(github_hidden_at,now()) else github_hidden_at end,
  github_hidden_by=case when status='published' then coalesce(github_hidden_by,auth.uid()) else github_hidden_by end
 where id=r.id;
 perform audit('request.deleted',r.id::text,jsonb_build_object('title',r.title,'status',r.status,'version_id',r.version_id,'github_url',r.github_url));
end $$;

create function public.hide_github_submission(p_request uuid,p_confirmation text) returns void
language plpgsql security definer set search_path=public as $$
declare r change_requests;
begin
 if not (record_capabilities()->>'owner')::boolean then raise exception 'Somente o proprietário pode excluir envios'; end if;
 select * into r from change_requests where id=p_request for update;
 if r.id is null or r.deleted_at is not null or r.status<>'published' then raise exception 'Envio indisponível'; end if;
 if p_confirmation is distinct from r.title then raise exception 'Digite o título exato do envio para confirmar'; end if;
 if r.github_hidden_at is not null then return; end if;
 if r.export_lease_until>now() then raise exception 'Aguarde a conclusão do envio ao GitHub antes de excluir'; end if;
 update change_requests set github_hidden_at=now(),github_hidden_by=auth.uid() where id=r.id;
 perform audit('github.submission_hidden',r.id::text,jsonb_build_object('title',r.title,'version_id',r.version_id,'github_url',r.github_url));
end $$;

-- Also protect callers of existing RPCs, stale tabs, and in-flight workflow actions.
create function public.guard_deleted_request() returns trigger
language plpgsql security definer set search_path=public as $$
begin
 if old.deleted_at is not null then raise exception 'Esta solicitação foi excluída'; end if;
 return new;
end $$;
create trigger guard_deleted_request before update on public.change_requests
 for each row execute function public.guard_deleted_request();

create function public.guard_deleted_request_comment() returns trigger
language plpgsql security definer set search_path=public as $$
declare r change_requests;
begin
 select * into r from change_requests where id=new.request_id for share;
 if r.id is null or r.deleted_at is not null then raise exception 'Solicitação indisponível'; end if;
 return new;
end $$;
create trigger guard_deleted_request_comment before insert on public.comments
 for each row execute function public.guard_deleted_request_comment();

revoke all on function public.guard_deleted_request(),public.guard_deleted_request_comment() from public,anon,authenticated;
revoke all on function public.record_capabilities(),public.delete_request(uuid,text),public.hide_github_submission(uuid,text) from public,anon;
grant execute on function public.record_capabilities(),public.delete_request(uuid,text),public.hide_github_submission(uuid,text) to authenticated;

commit;
