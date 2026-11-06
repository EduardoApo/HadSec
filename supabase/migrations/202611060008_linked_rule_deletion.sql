begin;

-- The owner identity survives a username change. New installations use Admin.
create or replace function public.pin_initial_workspace_owner() returns trigger
language plpgsql security definer set search_path=public as $$
begin
 if lower(new.username) in ('admin','hadsec') and new.active and new.deleted_at is null
 and exists(select 1 from roles where id=new.role_id and system and name='Administrador') then
  insert into workspace_owner(user_id) values(new.id) on conflict(singleton) do nothing;
 end if;
 return new;
end $$;

create function public.archive_rule(p_rule uuid,p_confirmation text) returns jsonb
language plpgsql security definer set search_path=public as $$
declare r rules; q change_requests; owner boolean; removed uuid[]='{}';
begin
 if not has_permission('rules.write') then raise exception 'Sem permissão'; end if;
 select * into r from rules where id=p_rule for update;
 if r.id is null then raise exception 'Regra não encontrada'; end if;
 if p_confirmation is distinct from r.name then raise exception 'Digite o nome exato da regra para confirmar'; end if;
 if r.archived then return jsonb_build_object('ok',true,'archived',true,'deleted_requests',0); end if;
 owner:=(record_capabilities()->>'owner')::boolean;
 if not owner and exists(select 1 from change_requests where rule_id=r.id and (deleted_at is null or status='published')) then
  raise exception 'Somente o proprietário pode excluir regras com solicitações vinculadas';
 end if;
 if owner then
  for q in select * from change_requests where rule_id=r.id and deleted_at is null order by id for update loop
   -- Reuse the owner authorization, export lease, confirmation and audit checks.
   perform delete_request(q.id,q.title);
   removed:=array_append(removed,q.id);
  end loop;
 end if;
 update rules set archived=true where id=r.id;
 perform audit('rule.archived',r.id::text,jsonb_build_object('name',r.name,'deleted_request_ids',removed,'deleted_requests',cardinality(removed)));
 return jsonb_build_object('ok',true,'archived',true,'deleted_requests',cardinality(removed));
end $$;
revoke all on function public.archive_rule(uuid,text) from public,anon;
grant execute on function public.archive_rule(uuid,text) to authenticated;

-- Serialize new workflow actions with archival so stale tabs cannot revive a removed rule.
create function public.guard_archived_request_rule() returns trigger
language plpgsql security definer set search_path=public as $$
declare rule_id uuid; is_archived boolean;
begin
 if new.deleted_at is not null then return new; end if;
 rule_id:=new.rule_id;
 if rule_id is null and new.version_id is not null then select v.rule_id into rule_id from rule_versions v where v.id=new.version_id; end if;
 if rule_id is not null then
  select r.archived into is_archived from rules r where r.id=rule_id for share;
  if not found or is_archived then raise exception 'Esta regra foi excluída da lista'; end if;
 end if;
 return new;
end $$;
revoke all on function public.guard_archived_request_rule() from public,anon,authenticated;
create trigger guard_archived_request_rule before insert or update of rule_id,version_id,status
 on public.change_requests for each row execute function public.guard_archived_request_rule();

commit;
