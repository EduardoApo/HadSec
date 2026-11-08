begin;
alter table public.rules drop constraint rules_format_check,drop constraint rules_mode_check,drop constraint format_mode;
alter table public.rules add constraint rules_format_check check(format in ('xml','sql','sigma','kusto','aql','eql','kibana_kql','spl','yara')),
 add constraint rules_mode_check check(mode in ('Streaming','Scheduled','Scheduled via SQL','Native')),
 add constraint format_mode check((format='sql' and mode='Scheduled via SQL') or (format='xml' and mode in ('Streaming','Scheduled')) or (format in ('sigma','kusto','aql','eql','kibana_kql','spl','yara') and mode='Native'));

-- A still-running older gateway must not certify formats it does not understand.
create function public.guard_multiformat_validation() returns trigger
language plpgsql security definer set search_path=public as $$
declare f text;
begin
 select format into f from rules where id=new.rule_id;
 if new.validated and f not in ('xml','sql') and (
  new.validation_report is null or new.validation_report->>'engine' is distinct from 'hadsec-multiformat-1'
  or new.validation_report->>'format' is distinct from f or new.validation_report->>'ok' is distinct from 'true'
 ) then raise exception 'Atualize o serviço de validação para este formato'; end if;
 return new;
end $$;
revoke all on function public.guard_multiformat_validation() from public,anon,authenticated;
create trigger guard_multiformat_validation before insert or update of validated,validation_report on public.rule_versions for each row execute function public.guard_multiformat_validation();

alter table public.change_requests add column request_kind text not null default 'create' check(request_kind in ('create','change')),
 add column baseline_version_id uuid references public.rule_versions(id),
 add column requested_format text check(requested_format in ('xml','sql','sigma','kusto','aql','eql','kibana_kql','spl','yara'));
-- Existing workflow rows retain their timestamps and deletion state.
alter table public.change_requests disable trigger guard_deleted_request;
update public.change_requests set request_kind=case when rule_id is null then 'create' else 'change' end;
alter table public.change_requests enable trigger guard_deleted_request;

create function public.submit_change_request(p_kind text,p_title text,p_description text,p_format text,p_mode text,
 p_rule_id uuid default null,p_baseline_content text default null) returns uuid
language plpgsql security definer set search_path=public as $$
declare rid uuid; baseline uuid; qid uuid; current_rule rules; content_length integer;
begin
 if not has_permission('requests.create') then raise exception 'Sem permissão'; end if;
 if p_kind is null or p_kind not in ('create','change') then raise exception 'Escolha criar ou alterar uma regra'; end if;
 if p_title is null or length(trim(p_title)) not between 3 and 160 or p_description is null or length(trim(p_description)) not between 3 and 8000 then raise exception 'Informe título e contexto'; end if;
 if p_format is null or p_format not in ('xml','sql','sigma','kusto','aql','eql','kibana_kql','spl','yara') then raise exception 'Formato inválido'; end if;
 if p_mode is null or not ((p_format='sql' and p_mode='Scheduled via SQL') or (p_format='xml' and p_mode in ('Streaming','Scheduled')) or (p_format not in ('xml','sql') and p_mode='Native')) then raise exception 'Formato incompatível'; end if;
 if p_kind='create' then
  if p_rule_id is not null or nullif(p_baseline_content,'') is not null then raise exception 'Nova regra não deve informar versão anterior'; end if;
 else
  if p_rule_id is not null then
   select * into current_rule from rules where id=p_rule_id and not archived for update;
   if current_rule.id is null then raise exception 'Regra indisponível'; end if;
   if current_rule.format<>p_format then raise exception 'Use o formato da regra original'; end if;
   rid:=current_rule.id;
   select id into baseline from rule_versions where rule_id=rid order by number desc limit 1;
   if baseline is null then raise exception 'Regra sem versão original'; end if;
   if nullif(p_baseline_content,'') is not null and p_baseline_content is distinct from (select content from rule_versions where id=baseline) then raise exception 'A regra mudou. Atualize a versão original antes de solicitar'; end if;
  else
   content_length:=length(p_baseline_content);
   if p_baseline_content is null or content_length not between 1 and 500000 or length(trim(p_baseline_content))=0 then raise exception 'Informe a regra original, até 500 KB'; end if;
   insert into rules(name,description,severity,mode,format,created_by) values(trim(p_title),trim(p_description),'Média',p_mode,p_format,auth.uid()) returning id into rid;
   insert into rule_versions(rule_id,number,content,change_note,created_by,content_sha256)
   values(rid,1,p_baseline_content,'Versão original anexada à solicitação.',auth.uid(),encode(sha256(convert_to(p_baseline_content,'UTF8')),'hex')) returning id into baseline;
   perform audit('version.baseline_imported',baseline::text,jsonb_build_object('rule_id',rid,'number',1));
  end if;
 end if;
 insert into change_requests(title,description,rule_id,created_by,request_kind,baseline_version_id,requested_format)
 values(trim(p_title),trim(p_description),rid,auth.uid(),p_kind,baseline,p_format) returning id into qid;
 perform audit('request.created',qid::text,jsonb_build_object('request_kind',p_kind,'baseline_version_id',baseline));
 return qid;
end $$;
revoke all on function public.submit_change_request(text,text,text,text,text,uuid,text) from public,anon;
grant execute on function public.submit_change_request(text,text,text,text,text,uuid,text) to authenticated;

create function public.guard_request_baseline() returns trigger
language plpgsql security definer set search_path=public as $$
declare original rule_versions; proposed rule_versions;
begin
 if tg_op='UPDATE' and (new.baseline_version_id is distinct from old.baseline_version_id or new.request_kind is distinct from old.request_kind) then raise exception 'O tipo e a versão original da solicitação são imutáveis'; end if;
 if new.baseline_version_id is not null then
  select * into original from rule_versions where id=new.baseline_version_id;
  if original.id is null or new.rule_id is distinct from original.rule_id then raise exception 'Versão original de outra regra'; end if;
  if new.version_id is not null then
   select * into proposed from rule_versions where id=new.version_id;
   if proposed.id is null or proposed.rule_id<>original.rule_id or proposed.number<=original.number or proposed.content_sha256=original.content_sha256 then raise exception 'Salve uma nova versão com o ajuste; a regra original deve permanecer preservada'; end if;
  end if;
 end if;
 return new;
end $$;
revoke all on function public.guard_request_baseline() from public,anon,authenticated;
create trigger guard_request_baseline before insert or update of rule_id,version_id,baseline_version_id,request_kind on public.change_requests for each row execute function public.guard_request_baseline();

alter table public.test_evidence drop constraint test_evidence_method_check;
alter table public.test_evidence add constraint test_evidence_method_check check(method in ('FortiSIEM Streaming','FortiSIEM SQL','Revisão manual','Teste no motor de destino','Simulação local'));
create or replace function public.record_evidence(p_version uuid,p_method text,p_result text,p_notes text) returns void
language plpgsql security definer set search_path=public as $$
declare m text; f text;
begin
 if not has_permission('tests.record') then raise exception 'Sem permissão'; end if;
 select r.mode,r.format into m,f from rules r join rule_versions v on v.rule_id=r.id where v.id=p_version;
 if m is null then raise exception 'Versão inexistente'; end if;
 if p_method='FortiSIEM Streaming' and (f<>'xml' or m<>'Streaming') or p_method='FortiSIEM SQL' and f not in ('xml','sql') then raise exception 'Método incompatível com formato'; end if;
 if m='Streaming' and p_method='FortiSIEM SQL' or m<>'Streaming' and p_method='FortiSIEM Streaming' then raise exception 'Método incompatível com modo de execução'; end if;
 insert into test_evidence(version_id,method,result,notes,created_by) values(p_version,p_method,p_result,p_notes,auth.uid());
 perform audit('evidence.recorded',p_version::text,jsonb_build_object('result',p_result));
end $$;

create or replace function public.decide_request(p_request uuid,p_decision text,p_note text) returns void
language plpgsql security definer set search_path=public as $$
declare r change_requests; v rule_versions; administrator boolean; own_work boolean;
begin
 if not has_permission('requests.review') then raise exception 'Sem permissão'; end if;
 select * into r from change_requests where id=p_request for update;
 if r.deleted_at is not null then raise exception 'Esta solicitação foi excluída'; end if;
 if r.id is null or r.status<>'review' then raise exception 'Solicitação fora de revisão'; end if;
 select * into v from rule_versions where id=r.version_id;
 if v.id is null then raise exception 'Versão indisponível'; end if;
 if exists(select 1 from rules where id=v.rule_id and archived) then raise exception 'Regra excluída da lista'; end if;
 select exists(select 1 from profiles p join roles role on role.id=p.role_id where p.id=auth.uid() and p.active and not p.must_change_password and role.system and role.name='Administrador') into administrator;
 own_work:=r.created_by=auth.uid() or v.created_by=auth.uid();
 if own_work and not administrator then raise exception 'A aprovação exige outro revisor'; end if;
 if p_decision is null or p_decision not in ('approved','changes','rejected') or p_note is null or length(trim(p_note))<5 or length(p_note)>8000 then raise exception 'Informe decisão e justificativa'; end if;
 if p_decision='approved' then
  if not v.validated then raise exception 'Validação estática pendente'; end if;
  if not exists(select 1 from test_evidence e where e.version_id=r.version_id and e.result='pass' and e.method in ('FortiSIEM Streaming','FortiSIEM SQL','Teste no motor de destino')
    and not exists(select 1 from test_evidence later where later.version_id=e.version_id and later.created_at>e.created_at and later.result='fail')) then raise exception 'Registre teste aprovado no motor de destino para esta versão'; end if;
 end if;
 update change_requests set status=p_decision,reviewed_by=auth.uid(),review_note=trim(p_note),updated_at=now() where id=r.id;
 perform audit('request.'||p_decision,r.id::text,jsonb_build_object('note',trim(p_note),'administrator_self_decision',administrator and own_work,'administrator_self_approval',administrator and own_work and p_decision='approved'));
end $$;

commit;
