export function ownerRenameSQL(username='Admin'){
 if(!/^[A-Za-z0-9_.-]{3,40}$/.test(username))throw Error('Nome de usuário inválido.');
 // The validated username contains no SQL quotes. The account is selected only by its pinned ID.
 return `begin;
 do $$
 declare owner_id uuid; previous_name text; previous_email text; password_hash text;
 target_name text := '${username}'; target_email text := '${username.toLowerCase()}@hadsec.local';
 begin
  select user_id into owner_id from public.workspace_owner where singleton for update;
  if owner_id is null then raise exception 'Conta proprietária não configurada'; end if;
  select username into previous_name from public.profiles where id=owner_id and active and deleted_at is null for update;
  if previous_name is null then raise exception 'Conta proprietária indisponível'; end if;
  select email,encrypted_password into previous_email,password_hash from auth.users where id=owner_id for update;
  if not found then raise exception 'Identidade de autenticação indisponível'; end if;
  if exists(select 1 from public.profiles where lower(username)=lower(target_name) and id<>owner_id)
   or exists(select 1 from auth.users where lower(email)=target_email and id<>owner_id)
   or exists(select 1 from auth.identities where provider='email' and lower(identity_data->>'email')=target_email and user_id<>owner_id) then
   raise exception 'O novo usuário já está em uso';
  end if;
  if not exists(select 1 from auth.identities where user_id=owner_id and provider='email') then raise exception 'Identidade de e-mail indisponível'; end if;
  update auth.users set email=target_email,
   raw_user_meta_data=jsonb_set(coalesce(raw_user_meta_data,'{}'::jsonb),'{username}',to_jsonb(target_name)),updated_at=now()
   where id=owner_id;
  update auth.identities set identity_data=jsonb_set(coalesce(identity_data,'{}'::jsonb),'{email}',to_jsonb(target_email)),updated_at=now()
   where user_id=owner_id and provider='email';
  update public.profiles set username=target_name,display_name=target_name where id=owner_id;
  if (select encrypted_password from auth.users where id=owner_id) is distinct from password_hash then raise exception 'A senha foi alterada inesperadamente'; end if;
  if previous_name is distinct from target_name or previous_email is distinct from target_email then
   insert into public.audit_events(actor_id,action,entity_id,detail)
   values(owner_id,'user.renamed',owner_id::text,jsonb_build_object('previous_username',previous_name,'username',target_name));
  end if;
 end $$;
 commit;`;
}
