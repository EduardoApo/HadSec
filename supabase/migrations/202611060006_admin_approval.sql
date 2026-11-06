begin;

-- Ordinary reviewers still need a different author; the system Administrator may self-approve.
alter table public.change_requests drop constraint if exists reviewed_by_other;

create or replace function public.guard_self_review() returns trigger
language plpgsql security definer set search_path=public as $$
declare author uuid;
begin
 if new.reviewed_by is null then return new; end if;
 select created_by into author from rule_versions where id=new.version_id;
 if new.reviewed_by=new.created_by or new.reviewed_by=author then
  if not exists(select 1 from profiles p join roles r on r.id=p.role_id where p.id=new.reviewed_by and p.active and not p.must_change_password and r.system and r.name='Administrador') then
   raise exception 'A aprovação exige outro revisor';
  end if;
 end if;
 return new;
end $$;
revoke all on function public.guard_self_review() from public,anon,authenticated;
create trigger guard_request_self_review before insert or update of reviewed_by,created_by,version_id
on public.change_requests for each row execute function public.guard_self_review();

create or replace function public.decide_request(p_request uuid,p_decision text,p_note text) returns void
language plpgsql security definer set search_path=public as $$
declare r change_requests; v rule_versions; administrator boolean; own_work boolean;
begin
 if not has_permission('requests.review') then raise exception 'Sem permissão'; end if;
 select * into r from change_requests where id=p_request for update;
 if r.id is null or r.status<>'review' then raise exception 'Solicitação fora de revisão'; end if;
 select * into v from rule_versions where id=r.version_id;
 if v.id is null then raise exception 'Versão indisponível'; end if;
 if exists(select 1 from rules where id=v.rule_id and archived) then raise exception 'Regra excluída da lista'; end if;
 select exists(select 1 from profiles p join roles role on role.id=p.role_id where p.id=auth.uid() and p.active and not p.must_change_password and role.system and role.name='Administrador') into administrator;
 own_work := r.created_by=auth.uid() or v.created_by=auth.uid();
 if own_work and not administrator then raise exception 'A aprovação exige outro revisor'; end if;
 if p_decision is null or p_decision not in ('approved','changes','rejected') or p_note is null or length(trim(p_note))<5 or length(p_note)>8000 then raise exception 'Informe decisão e justificativa'; end if;
 if p_decision='approved' then
  if not v.validated then raise exception 'Validação estática pendente'; end if;
  if not exists(select 1 from test_evidence e where e.version_id=r.version_id and e.result='pass' and e.method<>'Revisão manual'
   and not exists(select 1 from test_evidence later where later.version_id=e.version_id and later.created_at>e.created_at and later.result='fail')) then raise exception 'Registre teste aprovado no FortiSIEM para esta versão'; end if;
 end if;
 update change_requests set status=p_decision,reviewed_by=auth.uid(),review_note=trim(p_note),updated_at=now() where id=r.id;
 perform audit('request.'||p_decision,r.id::text,jsonb_build_object('note',trim(p_note),'administrator_self_approval',administrator and own_work and p_decision='approved'));
end $$;

commit;
