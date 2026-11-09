begin;
insert into permission_definitions(key,label,description) values('fp.read','Consultar falsos positivos','Consultar causas, ocorrências e recomendações.'),('fp.write','Registrar falsos positivos','Documentar ocorrências, evidências e resultados de tuning.');
update roles set permissions=permissions||array['fp.read','fp.write'] where system and name in ('Administrador','Engenheiro','Revisor');update roles set permissions=permissions||array['fp.read'] where system and name='Leitor';
alter table operational_subjects drop constraint operational_subjects_kind_check;alter table operational_subjects add constraint operational_subjects_kind_check check(kind in ('campaign','hypothesis','validation','false_positive'));
alter table attack_subject_links add constraint mapped_subject_kinds check(subject_kind in ('campaign','hypothesis','validation'));
drop policy coverage_read on operational_subjects;create policy coverage_read on operational_subjects for select to authenticated using(has_permission('coverage.read') and kind in ('campaign','hypothesis','validation'));
create policy fp_subject_read on operational_subjects for select to authenticated using(has_permission('fp.read') and kind='false_positive');
create or replace function can_read_subject(p_subject uuid) returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from operational_subjects where id=p_subject and not archived and case kind when 'validation' then has_permission('coverage.read') when 'false_positive' then has_permission('fp.read') else has_permission('hunting.read') end)$$;
create or replace function can_write_subject(p_subject uuid) returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from operational_subjects where id=p_subject and not archived and case kind when 'validation' then has_permission('validation.record') when 'false_positive' then has_permission('fp.write') else has_permission('hunting.write') end)$$;
create table false_positive_cases(
 id uuid primary key references operational_subjects,subject_kind text not null default 'false_positive' check(subject_kind='false_positive'),
 rule_id uuid not null references rules,tool text not null check(length(trim(tool)) between 2 and 100),description text not null check(length(trim(description)) between 10 and 8000),cause text not null check(length(trim(cause)) between 5 and 4000),responsible_id uuid not null references profiles,
 foreign key(id,subject_kind) references operational_subjects(id,kind)
);
create table fp_occurrences(
 id uuid primary key default gen_random_uuid(),case_id uuid not null references false_positive_cases,occurred_at timestamptz not null,
 rule_version_id uuid not null references rule_versions,description text not null check(length(trim(description)) between 10 and 8000),
 host text not null default '' check(length(host)<=200),application text not null default '' check(length(application)<=200),evidence_ids uuid[] not null default '{}' check(cardinality(evidence_ids)<=20),created_by uuid not null references profiles,created_at timestamptz not null default now()
);
create table fp_tuning_results(
 id uuid primary key default gen_random_uuid(),case_id uuid not null references false_positive_cases,recommendation text not null check(length(trim(recommendation)) between 10 and 8000),
 outcome text not null check(outcome in ('proposed','applied','effective','ineffective','not_measured')),result text not null check(length(trim(result)) between 10 and 8000),
 before_version uuid not null references rule_versions,after_version uuid references rule_versions,evidence_ids uuid[] not null default '{}' check(cardinality(evidence_ids)<=20),created_by uuid not null references profiles,created_at timestamptz not null default now()
);
create table fp_tuning_requests(case_id uuid not null references false_positive_cases,request_id uuid not null references change_requests,created_by uuid not null references profiles,created_at timestamptz not null default now(),primary key(case_id,request_id));
create function save_false_positive(p_id uuid,p_title text,p_rule uuid,p_tool text,p_description text,p_cause text,p_responsible uuid,p_status text,p_occurred timestamptz default null,p_version uuid default null,p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;s operational_subjects;old false_positive_cases;
begin
 if not has_permission('fp.read') or not has_permission('fp.write') then raise exception 'Sem permissão para registrar falsos positivos';end if;
 if p_status is null or p_status not in ('open','in_tuning','monitoring','resolved') then raise exception 'Estado inválido';end if;
 if not exists(select 1 from profiles where id=p_responsible and active and deleted_at is null and not must_change_password) then raise exception 'Responsável indisponível';end if;
 if p_id is null then
  if not exists(select 1 from rules where id=p_rule and not archived) or not exists(select 1 from rule_versions where id=p_version and rule_id=p_rule) or p_occurred is null or not isfinite(p_occurred) or p_occurred>now()+interval '5 minutes' then raise exception 'Selecione regra, versão e data válida da ocorrência';end if;
  insert into operational_subjects(kind,title,status,created_by) values('false_positive',trim(p_title),p_status,auth.uid()) returning id into rid;
 else select * into s from operational_subjects where id=p_id and kind='false_positive' and not archived for update;select * into old from false_positive_cases where id=p_id;
  if s.id is null or old.id is null or s.updated_at is distinct from p_expected_updated then raise exception 'O registro mudou. Atualize antes de salvar';end if;if old.rule_id is distinct from p_rule then raise exception 'A regra de um histórico não pode ser trocada';end if;rid=p_id;
 end if;
 if p_status='resolved' and not exists(select 1 from fp_tuning_results where case_id=rid and outcome='effective') then raise exception 'Registre um resultado de tuning efetivo com sua análise antes de resolver';end if;
 update operational_subjects set title=trim(p_title),status=p_status,updated_at=now() where id=rid;
 insert into false_positive_cases(id,rule_id,tool,description,cause,responsible_id) values(rid,p_rule,trim(p_tool),trim(p_description),trim(p_cause),p_responsible) on conflict(id) do update set tool=excluded.tool,description=excluded.description,cause=excluded.cause,responsible_id=excluded.responsible_id;
 if p_id is null then insert into fp_occurrences(case_id,occurred_at,rule_version_id,description,created_by) values(rid,p_occurred,p_version,trim(p_description),auth.uid());end if;
 perform audit('fp.case_saved',rid::text,jsonb_build_object('rule_id',p_rule,'status',p_status));return rid;
end $$;
create function record_fp_occurrence(p_case uuid,p_occurred timestamptz,p_version uuid,p_description text,p_host text,p_application text,p_evidence uuid[]) returns uuid language plpgsql security definer set search_path=public as $$
declare c false_positive_cases;rid uuid;
begin
 if not has_permission('fp.read') or not has_permission('fp.write') then raise exception 'Sem permissão para registrar ocorrências';end if;select * into c from false_positive_cases where id=p_case;
 if c.id is null or not can_write_subject(p_case) then raise exception 'Registro indisponível';end if;
 if p_occurred is null or not isfinite(p_occurred) or p_occurred>now()+interval '5 minutes' or not exists(select 1 from rule_versions where id=p_version and rule_id=c.rule_id) then raise exception 'Versão ou data inválida';end if;
 if exists(select 1 from unnest(p_evidence) e where not exists(select 1 from operational_evidence f where f.id=e and f.subject_id=p_case and f.status='ready')) then raise exception 'Evidência inválida para este registro';end if;
 insert into fp_occurrences(case_id,occurred_at,rule_version_id,description,host,application,evidence_ids,created_by) values(p_case,p_occurred,p_version,trim(p_description),coalesce(p_host,''),coalesce(p_application,''),coalesce(p_evidence,'{}'),auth.uid()) returning id into rid;
 update operational_subjects set status=case when status='resolved' then 'open' else status end,updated_at=now() where id=p_case;
 perform audit('fp.occurrence_recorded',rid::text,jsonb_build_object('case_id',p_case,'version_id',p_version));return rid;
end $$;
create function record_fp_tuning(p_case uuid,p_recommendation text,p_outcome text,p_result text,p_before uuid,p_after uuid,p_evidence uuid[]) returns uuid language plpgsql security definer set search_path=public as $$
declare c false_positive_cases;rid uuid;
begin
 if not has_permission('fp.read') or not has_permission('fp.write') then raise exception 'Sem permissão para registrar tuning';end if;select * into c from false_positive_cases where id=p_case;
 if c.id is null or not can_write_subject(p_case) then raise exception 'Registro indisponível';end if;
 if not exists(select 1 from rule_versions where id=p_before and rule_id=c.rule_id) or (p_after is not null and not exists(select 1 from rule_versions where id=p_after and rule_id=c.rule_id)) then raise exception 'Versão de outra regra ou indisponível';end if;
 if p_outcome in ('applied','effective','ineffective') and (p_after is null or p_after=p_before) then raise exception 'Identifique versões distintas antes e depois do ajuste';end if;
 if p_outcome in ('effective','ineffective') and coalesce(cardinality(p_evidence),0)=0 then raise exception 'Anexe evidência para documentar o resultado avaliado';end if;
 if exists(select 1 from unnest(p_evidence) e where not exists(select 1 from operational_evidence f where f.id=e and f.subject_id=p_case and f.status='ready')) then raise exception 'Evidência inválida para este registro';end if;
 insert into fp_tuning_results(case_id,recommendation,outcome,result,before_version,after_version,evidence_ids,created_by) values(p_case,trim(p_recommendation),p_outcome,trim(p_result),p_before,p_after,coalesce(p_evidence,'{}'),auth.uid()) returning id into rid;
 update operational_subjects set updated_at=now() where id=p_case;
 perform audit('fp.tuning_recorded',rid::text,jsonb_build_object('case_id',p_case,'outcome',p_outcome,'before',p_before,'after',p_after));return rid;
end $$;
create function request_fp_tuning(p_case uuid,p_title text,p_context text) returns uuid language plpgsql security definer set search_path=public as $$
declare c false_positive_cases;r rules;rid uuid;
begin
 if not has_permission('fp.read') or not has_permission('fp.write') or not has_permission('requests.create') then raise exception 'Sem permissão para solicitar tuning';end if;
 select * into c from false_positive_cases where id=p_case;select * into r from rules where id=c.rule_id and not archived;if c.id is null or r.id is null or not can_write_subject(p_case) then raise exception 'Registro ou regra indisponível';end if;
 if length(trim(coalesce(p_context,'')))<10 then raise exception 'Descreva o tuning esperado';end if;
 rid=submit_change_request('change',p_title,left(p_context||E'\n\nFalso positivo: '||p_case||E'\nCausa: '||c.cause||E'\nDescrição: '||left(c.description,2000),8000),r.format,r.mode,r.id,null);
 insert into fp_tuning_requests(case_id,request_id,created_by) values(p_case,rid,auth.uid());perform audit('fp.tuning_requested',rid::text,jsonb_build_object('case_id',p_case));return rid;
end $$;
do $$declare t text;begin foreach t in array array['false_positive_cases','fp_occurrences','fp_tuning_results','fp_tuning_requests'] loop execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);execute format('create policy fp_read on public.%I for select to authenticated using(public.has_permission(''fp.read''))',t);if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;end loop;end $$;
revoke all on function save_false_positive(uuid,text,uuid,text,text,text,uuid,text,timestamptz,uuid,timestamptz),record_fp_occurrence(uuid,timestamptz,uuid,text,text,text,uuid[]),record_fp_tuning(uuid,text,text,text,uuid,uuid,uuid[]),request_fp_tuning(uuid,text,text) from public,anon;
grant execute on function save_false_positive(uuid,text,uuid,text,text,text,uuid,text,timestamptz,uuid,timestamptz),record_fp_occurrence(uuid,timestamptz,uuid,text,text,text,uuid[]),record_fp_tuning(uuid,text,text,text,uuid,uuid,uuid[]),request_fp_tuning(uuid,text,text) to authenticated;
commit;
