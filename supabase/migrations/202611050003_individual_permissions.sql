begin;
create table public.permission_definitions (
 key text primary key,
 label text not null check(length(trim(label)) between 3 and 100),
 description text not null default '' check(length(description)<=500)
);
insert into public.permission_definitions(key,label,description) values
 ('rules.write','Criar e versionar regras','Salvar novas regras e versões.'),
 ('requests.create','Solicitar ajustes e revisão','Abrir solicitações e encaminhar versões.'),
 ('requests.review','Aprovar e devolver revisões','Revisar versões criadas por outras pessoas.'),
 ('tests.record','Registrar testes','Adicionar evidências de homologação.'),
 ('github.publish','Publicar no GitHub','Criar branches e pull requests de versões aprovadas.'),
 ('users.manage','Gerenciar contas','Criar, desativar e excluir usuários.'),
 ('roles.manage','Gerenciar perfis e permissões','Alterar perfis globais, exceções individuais e nomes das permissões.'),
 ('audit.read','Consultar auditoria','Consultar e exportar o histórico de ações.');
create table public.user_permission_overrides (
 user_id uuid not null references public.profiles on delete cascade,
 permission text not null references public.permission_definitions(key),
 granted boolean not null,
 updated_by uuid not null references public.profiles,
 updated_at timestamptz not null default now(),
 primary key(user_id,permission)
);
alter table public.permission_definitions enable row level security;
alter table public.user_permission_overrides enable row level security;
create policy member_read on public.permission_definitions for select to authenticated using(public.is_member());
create policy member_read on public.user_permission_overrides for select to authenticated using(public.is_member());
revoke all on public.permission_definitions,public.user_permission_overrides from anon,authenticated;
grant select on public.permission_definitions,public.user_permission_overrides to authenticated;
create or replace function public.has_permission(p text) returns boolean language sql stable security definer set search_path=public as $$
 select exists(
  select 1 from profiles u join roles r on u.role_id=r.id
  left join user_permission_overrides o on o.user_id=u.id and o.permission=p
  where u.id=auth.uid() and u.active and u.deleted_at is null and not u.must_change_password
  and coalesce(o.granted,p=any(r.permissions))
 )
$$;
create function public.set_user_permissions(p_user uuid,p_overrides jsonb) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('roles.manage') then raise exception 'Sem permissão'; end if;
 if p_user=auth.uid() then raise exception 'Outro administrador deve alterar suas permissões individuais'; end if;
 perform id from profiles where id=p_user and deleted_at is null for update;
 if not found then raise exception 'Usuário indisponível'; end if;
 if exists(select 1 from profiles u join roles r on r.id=u.role_id where u.id=p_user and r.system and r.name='Administrador') then raise exception 'As permissões do administrador do sistema são protegidas'; end if;
 if p_overrides is null or jsonb_typeof(p_overrides)<>'object' then raise exception 'Informe as exceções como objeto'; end if;
 if exists(select 1 from jsonb_each(p_overrides) e where jsonb_typeof(e.value)<>'boolean' or not exists(select 1 from permission_definitions d where d.key=e.key)) then raise exception 'Permissão ou valor inválido'; end if;
 delete from user_permission_overrides where user_id=p_user;
 insert into user_permission_overrides(user_id,permission,granted,updated_by)
 select p_user,e.key,(e.value::text)::boolean,auth.uid() from jsonb_each(p_overrides) e;
 perform audit('permissions.user_updated',p_user::text,jsonb_build_object('overrides',p_overrides));
end $$;
create function public.save_permission_labels(p_definitions jsonb) returns void language plpgsql security definer set search_path=public as $$
declare item jsonb;
begin
 if not has_permission('roles.manage') then raise exception 'Sem permissão'; end if;
 if p_definitions is null or jsonb_typeof(p_definitions)<>'array' then raise exception 'Lista de permissões inválida'; end if;
 for item in select value from jsonb_array_elements(p_definitions) loop
  if not exists(select 1 from permission_definitions where key=item->>'key') or item->>'label' is null then raise exception 'Identificador de permissão inválido'; end if;
  update permission_definitions set label=trim(item->>'label'),description=coalesce(item->>'description','') where key=item->>'key';
 end loop;
 perform audit('permissions.labels_updated',null,jsonb_build_object('count',jsonb_array_length(p_definitions)));
end $$;
create or replace function public.save_role(p_id uuid,p_name text,p_permissions text[]) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;
begin
 if not has_permission('roles.manage') then raise exception 'Sem permissão'; end if;
 if length(trim(p_name))<3 then raise exception 'Nome muito curto'; end if;
 if p_id is null then insert into roles(name,permissions) values(p_name,p_permissions) returning id into rid;
 else
  if exists(select 1 from roles where id=p_id and system and name='Administrador') then raise exception 'O perfil Administrador do sistema é protegido'; end if;
  update roles set name=p_name,permissions=p_permissions where id=p_id returning id into rid;
  if rid is null then raise exception 'Perfil indisponível'; end if;
 end if;
 perform audit('role.saved',rid::text,jsonb_build_object('permissions',p_permissions));return rid;
end $$;
revoke execute on function public.set_user_permissions(uuid,jsonb),public.save_permission_labels(jsonb) from public,anon;
grant execute on function public.set_user_permissions(uuid,jsonb),public.save_permission_labels(jsonb) to authenticated;
commit;
