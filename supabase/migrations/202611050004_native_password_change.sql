begin;
-- Supabase Auth updates this protected column after accepting a password change.
-- Only profiles belonging to this application are affected by the trigger.
create function public.on_hadsec_password_changed() returns trigger language plpgsql security definer set search_path=public as $$
begin
 update public.profiles set must_change_password=false where id=new.id;
 if found then
  insert into public.audit_events(actor_id,action,entity_id,detail)
  values(coalesce(auth.uid(),new.id),'password.changed',new.id::text,'{"method":"supabase_auth"}'::jsonb);
 end if;
 return new;
end $$;
revoke execute on function public.on_hadsec_password_changed() from public,anon,authenticated;
create trigger hadsec_password_changed after update of encrypted_password on auth.users
for each row when (old.encrypted_password is distinct from new.encrypted_password and new.encrypted_password is not null)
execute function public.on_hadsec_password_changed();
commit;
