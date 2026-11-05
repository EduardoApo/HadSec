begin;
create table public.roles (
 id uuid primary key default gen_random_uuid(), name text unique not null,
 permissions text[] not null default '{}', system boolean not null default false,
 constraint known_permissions check (permissions <@ array['rules.write','requests.create','requests.review','tests.record','github.publish','users.manage','roles.manage','audit.read']::text[])
);
insert into public.roles(name,permissions,system) values
 ('Administrador',array['rules.write','requests.create','requests.review','tests.record','github.publish','users.manage','roles.manage','audit.read'],true),
 ('Engenheiro',array['rules.write','requests.create','tests.record'],true),
 ('Revisor',array['requests.create','requests.review','tests.record'],true),
 ('Leitor',array['requests.create'],true);
create table public.profiles (
 id uuid primary key references auth.users on delete cascade,
 username text unique not null check (username ~ '^[A-Za-z0-9_.-]{3,40}$'),
 display_name text not null, role_id uuid not null references public.roles,
 active boolean not null default true, must_change_password boolean not null default true,
 created_at timestamptz not null default now()
);
create function public.has_permission(p text) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from profiles u join roles r on u.role_id=r.id where u.id=auth.uid() and u.active and not u.must_change_password and p=any(r.permissions))
$$;
create function public.is_member() returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from profiles where id=auth.uid() and active)
$$;
create table public.rules (
 id uuid primary key default gen_random_uuid(), name text not null check(length(name) between 3 and 160),
 description text not null default '', severity text not null check(severity in ('Crítica','Alta','Média','Baixa')),
 technique text not null default '', mode text not null check(mode in ('Streaming','Scheduled','Scheduled via SQL')),
 format text not null check(format in ('xml','sql')), created_by uuid not null references profiles,
 created_at timestamptz not null default now(), archived boolean not null default false,
 constraint format_mode check ((format='sql' and mode='Scheduled via SQL') or (format='xml' and mode in ('Streaming','Scheduled')))
);
create table public.rule_versions (
 id uuid primary key default gen_random_uuid(), rule_id uuid not null references rules,
 number integer not null, content text not null check(length(content) between 1 and 500000),
 change_note text not null check(length(change_note) between 3 and 4000),
 created_by uuid not null references profiles, created_at timestamptz not null default now(),
 validated boolean not null default false, validation_report jsonb, content_sha256 text not null,
 unique(rule_id,number)
);
create table public.change_requests (
 id uuid primary key default gen_random_uuid(), rule_id uuid references rules, version_id uuid references rule_versions,
 title text not null check(length(title) between 3 and 160), description text not null check(length(description) between 3 and 8000),
 status text not null default 'requested' check(status in ('requested','review','changes','approved','published','rejected')),
 created_by uuid not null references profiles, reviewed_by uuid references profiles, review_note text,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 github_url text, export_lease_until timestamptz, exported_sha text,
 constraint reviewed_by_other check (reviewed_by is null or reviewed_by<>created_by)
);
create unique index one_active_version_request on change_requests(version_id) where version_id is not null and status in ('review','approved','published');
create table public.test_evidence (
 id uuid primary key default gen_random_uuid(), version_id uuid not null references rule_versions,
 method text not null check(method in ('FortiSIEM Streaming','FortiSIEM SQL','Revisão manual')),
 result text not null check(result in ('pass','fail')), notes text not null check(length(notes) between 10 and 8000),
 created_by uuid not null references profiles, created_at timestamptz not null default now()
);
create table public.comments (
 id uuid primary key default gen_random_uuid(), request_id uuid not null references change_requests,
 body text not null check(length(body) between 1 and 8000), created_by uuid not null references profiles,
 created_at timestamptz not null default now()
);
create table public.audit_events (
 id bigint generated always as identity primary key, actor_id uuid references profiles,
 action text not null, entity_id text, detail jsonb not null default '{}', created_at timestamptz not null default now()
);
create function public.audit(p_action text,p_id text,p_detail jsonb default '{}') returns void
language sql security definer set search_path=public as $$
 insert into audit_events(actor_id,action,entity_id,detail) values(auth.uid(),p_action,p_id,p_detail)
$$;
revoke execute on function public.audit(text,text,jsonb) from public,anon,authenticated;
create function public.save_rule(p_rule_id uuid,p_name text,p_description text,p_severity text,p_technique text,p_mode text,p_format text,p_content text,p_note text,p_expected_version integer default 0)
returns uuid language plpgsql security definer set search_path=public,extensions as $$
declare rid uuid; vid uuid; n integer;
begin
 if not has_permission('rules.write') then raise exception 'Permission refusée'; end if;
 if p_rule_id is null then
  insert into rules(name,description,severity,technique,mode,format,created_by) values(p_name,p_description,p_severity,p_technique,p_mode,p_format,auth.uid()) returning id into rid;
 else
  select id into rid from rules where id=p_rule_id and not archived for update;
  if rid is null then raise exception 'Regra indisponível'; end if;
  -- Metadata belongs to the rule. Changing its format/mode would invalidate historical versions.
  if exists(select 1 from rules where id=rid and (format<>p_format or mode<>p_mode)) then raise exception 'Crie outra regra para alterar formato ou modo'; end if;
 end if;
 select coalesce(max(number),0) into n from rule_versions where rule_id=rid;
 if n<>p_expected_version then raise exception 'A regra mudou. Atualize antes de salvar.'; end if;
 insert into rule_versions(rule_id,number,content,change_note,created_by,content_sha256)
 values(rid,n+1,p_content,p_note,auth.uid(),encode(sha256(convert_to(p_content,'UTF8')),'hex')) returning id into vid;
 perform audit('version.created',vid::text,jsonb_build_object('rule_id',rid,'number',n+1));
 return vid;
end $$;
create function public.create_request(p_title text,p_description text,p_rule_id uuid default null,p_version_id uuid default null)
returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;
begin
 if not has_permission('requests.create') then raise exception 'Sem permissão'; end if;
 if p_version_id is not null and not exists(select 1 from rule_versions where id=p_version_id and rule_id=p_rule_id and validated) then raise exception 'Valide a versão antes de solicitar revisão'; end if;
 insert into change_requests(title,description,rule_id,version_id,status,created_by)
 values(p_title,p_description,p_rule_id,p_version_id,case when p_version_id is null then 'requested' else 'review' end,auth.uid()) returning id into rid;
 perform audit('request.created',rid::text); return rid;
end $$;
create function public.attach_version(p_request uuid,p_version uuid) returns void language plpgsql security definer set search_path=public as $$
declare r change_requests; v rule_versions;
begin
 if not has_permission('rules.write') then raise exception 'Sem permissão'; end if;
 select * into r from change_requests where id=p_request for update;
 select * into v from rule_versions where id=p_version;
 if r.id is null or v.id is null or r.status not in ('requested','changes') then raise exception 'Solicitação indisponível'; end if;
 if r.rule_id is not null and r.rule_id<>v.rule_id then raise exception 'Versão de outra regra'; end if;
 if not v.validated then raise exception 'Valide a versão'; end if;
 update change_requests set rule_id=v.rule_id,version_id=v.id,status='review',reviewed_by=null,review_note=null,updated_at=now() where id=r.id;
 perform audit('request.version_attached',r.id::text,jsonb_build_object('version',v.id));
end $$;
create function public.record_evidence(p_version uuid,p_method text,p_result text,p_notes text) returns void language plpgsql security definer set search_path=public as $$
declare m text;
begin
 if not has_permission('tests.record') then raise exception 'Sem permissão'; end if;
 select r.mode into m from rules r join rule_versions v on v.rule_id=r.id where v.id=p_version;
 if m is null then raise exception 'Versão inexistente'; end if;
 if (m<>'Streaming' and p_method='FortiSIEM Streaming') or (m='Streaming' and p_method='FortiSIEM SQL') then raise exception 'Método incompatível com modo de execução'; end if;
 insert into test_evidence(version_id,method,result,notes,created_by) values(p_version,p_method,p_result,p_notes,auth.uid());
 perform audit('evidence.recorded',p_version::text,jsonb_build_object('result',p_result));
end $$;
create function public.decide_request(p_request uuid,p_decision text,p_note text) returns void language plpgsql security definer set search_path=public as $$
declare r change_requests; v rule_versions;
begin
 if not has_permission('requests.review') then raise exception 'Sem permissão'; end if;
 select * into r from change_requests where id=p_request for update;
 if r.id is null or r.status<>'review' then raise exception 'Solicitação fora de revisão'; end if;
 select * into v from rule_versions where id=r.version_id;
 if r.created_by=auth.uid() or v.created_by=auth.uid() then raise exception 'A aprovação exige outro revisor'; end if;
 if p_decision not in ('approved','changes','rejected') or length(trim(p_note))<5 then raise exception 'Informe decisão e justificativa'; end if;
 if p_decision='approved' then
  if not v.validated then raise exception 'Validação estática pendente'; end if;
  if not exists(select 1 from test_evidence e where e.version_id=r.version_id and e.result='pass' and e.method<>'Revisão manual'
   and not exists(select 1 from test_evidence later where later.version_id=e.version_id and later.created_at>e.created_at and later.result='fail')) then raise exception 'Registre teste aprovado no FortiSIEM para esta versão'; end if;
 end if;
 update change_requests set status=p_decision,reviewed_by=auth.uid(),review_note=p_note,updated_at=now() where id=r.id;
 perform audit('request.'||p_decision,r.id::text,jsonb_build_object('note',p_note));
end $$;
create function public.add_comment(p_request uuid,p_body text) returns void language plpgsql security definer set search_path=public as $$
begin
 if not is_member() then raise exception 'Sem acesso'; end if;
 insert into comments(request_id,body,created_by) values(p_request,p_body,auth.uid());
 perform audit('comment.created',p_request::text);
end $$;
create function public.save_role(p_id uuid,p_name text,p_permissions text[]) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;
begin
 if not has_permission('roles.manage') then raise exception 'Sem permissão'; end if;
 if length(trim(p_name))<3 then raise exception 'Nome muito curto'; end if;
 if p_id is null then insert into roles(name,permissions) values(p_name,p_permissions) returning id into rid;
 else
  if exists(select 1 from roles where id=p_id and system) then raise exception 'Duplique o perfil do sistema para personalizar'; end if;
  update roles set name=p_name,permissions=p_permissions where id=p_id returning id into rid;
 end if;
 perform audit('role.saved',rid::text,jsonb_build_object('permissions',p_permissions));return rid;
end $$;
create function public.claim_export(p_request uuid) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('github.publish') then raise exception 'Sem permissão'; end if;
 update change_requests set export_lease_until=now()+interval '2 minutes' where id=p_request and status='approved' and (export_lease_until is null or export_lease_until<now());
 if not found then raise exception 'Publicação indisponível ou já em execução'; end if;
 perform audit('github.export_started',p_request::text);
end $$;
-- Every mutation above is an RPC with its own permission and transition checks.
alter table roles enable row level security;
alter table profiles enable row level security;
alter table rules enable row level security;
alter table rule_versions enable row level security;
alter table change_requests enable row level security;
alter table test_evidence enable row level security;
alter table comments enable row level security;
alter table audit_events enable row level security;
create policy member_read on roles for select to authenticated using(is_member());
create policy member_read on profiles for select to authenticated using(is_member());
create policy member_read on rules for select to authenticated using(is_member());
create policy member_read on rule_versions for select to authenticated using(is_member());
create policy member_read on change_requests for select to authenticated using(is_member());
create policy member_read on test_evidence for select to authenticated using(is_member());
create policy member_read on comments for select to authenticated using(is_member());
create policy audit_read on audit_events for select to authenticated using(has_permission('audit.read'));
revoke all on roles,profiles,rules,rule_versions,change_requests,test_evidence,comments,audit_events from anon,authenticated;
grant select on roles,profiles,rules,rule_versions,change_requests,test_evidence,comments,audit_events to authenticated;
revoke execute on function public.has_permission(text),public.is_member(),public.save_rule(uuid,text,text,text,text,text,text,text,text,integer),public.create_request(text,text,uuid,uuid),public.attach_version(uuid,uuid),public.record_evidence(uuid,text,text,text),public.decide_request(uuid,text,text),public.add_comment(uuid,text),public.save_role(uuid,text,text[]),public.claim_export(uuid) from public,anon;
grant execute on function public.has_permission(text),public.is_member(),public.save_rule(uuid,text,text,text,text,text,text,text,text,integer),public.create_request(text,text,uuid,uuid),public.attach_version(uuid,uuid),public.record_evidence(uuid,text,text,text),public.decide_request(uuid,text,text),public.add_comment(uuid,text),public.save_role(uuid,text,text[]),public.claim_export(uuid) to authenticated;
commit;
