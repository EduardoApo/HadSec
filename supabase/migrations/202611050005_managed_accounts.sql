begin;
create function public.create_managed_user(p_username text,p_display_name text,p_password text,p_role_id uuid)
returns uuid language plpgsql security definer set search_path=public as $$
declare uid uuid; email_address text; assigned_role roles;
begin
 if not has_permission('users.manage') then raise exception 'Sem permissão para criar contas'; end if;
 p_username=trim(p_username);p_display_name=trim(p_display_name);
 if p_username is null or p_username !~ '^[A-Za-z0-9_.-]{3,40}$' then raise exception 'Usuário inválido: use de 3 a 40 letras, números, pontos, hífens ou sublinhados'; end if;
 if p_display_name is null or length(p_display_name) not between 2 and 80 then raise exception 'O nome deve ter entre 2 e 80 caracteres'; end if;
 if p_password is null or length(p_password)<10 or octet_length(p_password)>72 then raise exception 'A senha deve ter pelo menos 10 caracteres e no máximo 72 bytes'; end if;
 select * into assigned_role from roles where id=p_role_id;
 if assigned_role.id is null then raise exception 'Perfil de acesso inexistente'; end if;
 if not has_permission('roles.manage') and exists(select 1 from unnest(assigned_role.permissions) p where not has_permission(p)) then raise exception 'Sem permissão para atribuir este perfil'; end if;
 perform pg_advisory_xact_lock(hashtext('hadsec.account.'||lower(p_username)));
 email_address=lower(p_username)||'@hadsec.local';
 if exists(select 1 from profiles where lower(username)=lower(p_username)) or exists(select 1 from auth.users where lower(email)=email_address) then raise exception 'Este usuário já está cadastrado'; end if;
 uid=gen_random_uuid();
 insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,
  confirmation_token,recovery_token,email_change_token_new,email_change_token_current,email_change,
  reauthentication_token,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,is_sso_user,is_anonymous)
 values('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',email_address,
  extensions.crypt(p_password,extensions.gen_salt('bf',10)),now(),'','','','','','',
  '{"provider":"email","providers":["email"]}'::jsonb,jsonb_build_object('username',p_username),now(),now(),false,false);
 insert into auth.identities(id,provider_id,user_id,identity_data,provider,created_at,updated_at)
 values(gen_random_uuid(),uid::text,uid,jsonb_build_object('sub',uid::text,'email',email_address,'email_verified',true,'phone_verified',false),'email',now(),now());
 insert into profiles(id,username,display_name,role_id,must_change_password) values(uid,p_username,p_display_name,p_role_id,true);
 perform audit('user.created',uid::text,jsonb_build_object('username',p_username));
 return uid;
exception when unique_violation then raise exception 'Este usuário já está cadastrado';
end $$;

create function public.update_managed_user(p_user uuid,p_role_id uuid,p_active boolean)
returns void language plpgsql security definer set search_path=public as $$
declare target profiles; assigned_role roles;
begin
 if not has_permission('users.manage') then raise exception 'Sem permissão para gerenciar contas'; end if;
 if p_user=auth.uid() then raise exception 'Outro administrador deve alterar sua conta'; end if;
 select * into target from profiles where id=p_user and deleted_at is null for update;
 if target.id is null then raise exception 'Conta indisponível'; end if;
 if exists(select 1 from roles where id=target.role_id and system and name='Administrador') then raise exception 'O administrador do sistema é protegido'; end if;
 if p_active is null then raise exception 'Status da conta inválido'; end if;
 select * into assigned_role from roles where id=p_role_id;
 if assigned_role.id is null then raise exception 'Perfil de acesso inexistente'; end if;
 if not has_permission('roles.manage') and (p_active or p_role_id<>target.role_id) and exists(select 1 from unnest(assigned_role.permissions) p where not has_permission(p)) then raise exception 'Sem permissão para atribuir este perfil'; end if;
 update profiles set role_id=p_role_id,active=p_active where id=p_user;
 if not p_active then
  delete from auth.refresh_tokens where user_id::text=p_user::text;
  delete from auth.sessions where user_id=p_user;
 end if;
 perform audit('user.updated',p_user::text,jsonb_build_object('role_id',p_role_id,'active',p_active));
end $$;

create function public.delete_managed_user(p_user uuid,p_confirmation text)
returns void language plpgsql security definer set search_path=public as $$
declare target profiles;
begin
 if not has_permission('users.manage') then raise exception 'Sem permissão para excluir contas'; end if;
 if p_user=auth.uid() then raise exception 'Não é permitido excluir sua própria conta'; end if;
 select * into target from profiles where id=p_user for update;
 if target.id is null then raise exception 'Conta inexistente'; end if;
 if exists(select 1 from roles where id=target.role_id and system and name='Administrador') then raise exception 'O administrador do sistema é protegido'; end if;
 if target.deleted_at is not null then return; end if;
 if p_confirmation is distinct from target.username then raise exception 'Digite o usuário exato para confirmar a exclusão'; end if;
 update profiles set active=false,deleted_at=now(),username='deleted.'||replace(p_user::text,'-',''),display_name='Conta excluída' where id=p_user;
 delete from user_permission_overrides where user_id=p_user;
 delete from auth.refresh_tokens where user_id::text=p_user::text;
 delete from auth.sessions where user_id=p_user;
 delete from auth.identities where user_id=p_user;
 -- Retain the UUID so versions and audit foreign keys remain intact, while disabling Auth credentials.
 update auth.users set deleted_at=now(),banned_until='infinity'::timestamptz,email=null,phone=null,encrypted_password=null,
  confirmation_token='',recovery_token='',email_change_token_new='',email_change_token_current='',email_change='',
  reauthentication_token='',raw_user_meta_data='{}'::jsonb,updated_at=now() where id=p_user;
 perform audit('user.deleted',p_user::text,'{"history_preserved":true}'::jsonb);
end $$;

revoke execute on function public.create_managed_user(text,text,text,uuid),public.update_managed_user(uuid,uuid,boolean),public.delete_managed_user(uuid,text) from public,anon;
grant execute on function public.create_managed_user(text,text,text,uuid),public.update_managed_user(uuid,uuid,boolean),public.delete_managed_user(uuid,text) to authenticated;
commit;
