begin;
insert into public.permission_definitions(key,label,description) values
 ('validation.request','Solicitar testes de detecção','Criar e encaminhar solicitações de testes manuais.'),
 ('validation.approve','Aprovar testes de detecção','Aprovar execução e revisar resultados documentados.'),
 ('validation.record','Registrar execução de testes','Registrar execução manual, resultados e evidências.');
update public.roles set permissions=permissions||array['validation.request','validation.approve','validation.record'] where system and name='Administrador';
update public.roles set permissions=permissions||array['validation.request','validation.record'] where system and name='Engenheiro';
update public.roles set permissions=permissions||array['validation.request','validation.approve','validation.record'] where system and name='Revisor';
update public.roles set permissions=permissions||array['validation.request'] where system and name='Leitor';
create function public.is_platform_admin() returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from profiles p join roles r on r.id=p.role_id where p.id=auth.uid() and p.active and p.deleted_at is null and not p.must_change_password and r.system and r.name='Administrador')
$$;
create table public.atomic_validation_requests(
 id uuid primary key references public.operational_subjects,subject_kind text not null default 'validation' check(subject_kind='validation'),
 source text not null default 'atomic' check(source='atomic'),reference_id text not null,reference_sha256 text not null,
 technique_id text not null references public.attack_techniques,rule_version_id uuid references public.rule_versions,
 responsible_id uuid not null references public.profiles,environment text not null check(length(trim(environment)) between 2 and 160),
 objective text not null check(length(trim(objective)) between 10 and 4000),justification text not null check(length(trim(justification)) between 10 and 4000),
 priority text not null check(priority in ('Baixa','Média','Alta','Crítica')),scheduled_at timestamptz not null,
 retest_of uuid references public.atomic_validation_requests,
 foreign key(id,subject_kind) references public.operational_subjects(id,kind),
 foreign key(source,reference_id,reference_sha256) references public.reference_rule_revisions(source,id,sha256)
);
create table public.atomic_execution_results(
 id uuid primary key default gen_random_uuid(),request_id uuid not null references public.atomic_validation_requests,
 executed_at timestamptz not null,execution text not null check(execution in ('success','failure')),detected text not null check(detected in ('yes','no','unknown')),
 notes text not null check(length(trim(notes)) between 10 and 8000),created_by uuid not null references public.profiles,created_at timestamptz not null default now(),
 check(execution='success' or detected='unknown')
);
create table public.atomic_result_evidence(
 result_id uuid not null references public.atomic_execution_results,evidence_id uuid not null references public.operational_evidence,
 primary key(result_id,evidence_id)
);
create table public.atomic_validation_history(
 id uuid primary key default gen_random_uuid(),request_id uuid not null references public.atomic_validation_requests,
 from_status text,to_status text not null,note text not null,actor_id uuid not null references public.profiles,created_at timestamptz not null default now()
);
create function public.save_atomic_request(p_id uuid,p_reference text,p_title text,p_responsible uuid,p_environment text,p_objective text,p_justification text,p_priority text,p_scheduled timestamptz,p_rule_version uuid default null,p_submit boolean default false,p_retest uuid default null,p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare ref reference_rules;subject operational_subjects;rid uuid;tech text;next_status text;
begin
 if not has_permission('validation.request') or not has_permission('coverage.read') then raise exception 'Sem permissão para solicitar testes';end if;
 select * into ref from reference_rules where source='atomic' and id=p_reference and active;
 if ref.id is null then raise exception 'Teste Atomic indisponível';end if;
 tech=ref.techniques[1];if not exists(select 1 from attack_techniques where id=tech) then raise exception 'Sincronize MITRE: técnica Atomic não encontrada no catálogo';end if;
 if not exists(select 1 from profiles p join roles r on r.id=p.role_id left join user_permission_overrides o on o.user_id=p.id and o.permission='validation.record' where p.id=p_responsible and p.active and p.deleted_at is null and not p.must_change_password and coalesce(o.granted,'validation.record'=any(r.permissions))) then raise exception 'O responsável precisa de permissão para registrar testes';end if;
 if p_rule_version is not null and not exists(select 1 from rule_versions v join rules r on r.id=v.rule_id where v.id=p_rule_version and not r.archived) then raise exception 'Versão da regra indisponível';end if;
 if p_retest is not null and not exists(select 1 from atomic_validation_requests q join operational_subjects s on s.id=q.id where q.id=p_retest and q.reference_id=p_reference and s.status in ('completed','execution_failed','rejected','cancelled')) then raise exception 'Reteste exige uma solicitação anterior encerrada ou com falha';end if;
 next_status=case when p_submit then 'pending' else 'draft' end;
 if p_id is null then
  insert into operational_subjects(kind,title,status,created_by) values('validation',trim(p_title),next_status,auth.uid()) returning id into rid;
  insert into atomic_validation_requests(id,reference_id,reference_sha256,technique_id,rule_version_id,responsible_id,environment,objective,justification,priority,scheduled_at,retest_of)
  values(rid,p_reference,ref.sha256,tech,p_rule_version,p_responsible,trim(p_environment),trim(p_objective),trim(p_justification),p_priority,p_scheduled,p_retest);
 else
  select * into subject from operational_subjects where id=p_id and kind='validation' and not archived for update;
  if subject.id is null or subject.status<>'draft' or (subject.created_by<>auth.uid() and not is_platform_admin()) then raise exception 'Apenas o autor ou administrador pode editar um rascunho';end if;
  if p_expected_updated is distinct from subject.updated_at then raise exception 'A solicitação mudou. Atualize antes de salvar';end if;
  if exists(select 1 from atomic_validation_requests where id=p_id and (reference_id<>p_reference or retest_of is distinct from p_retest)) then raise exception 'Referência e origem do reteste são imutáveis';end if;
  rid=p_id;update operational_subjects set title=trim(p_title),status=next_status,updated_at=now() where id=rid;
  update atomic_validation_requests set responsible_id=p_responsible,environment=trim(p_environment),objective=trim(p_objective),justification=trim(p_justification),priority=p_priority,scheduled_at=p_scheduled,rule_version_id=p_rule_version where id=rid;
 end if;
 insert into attack_subject_links(technique_id,subject_id,subject_kind,created_by) values(tech,rid,'validation',auth.uid()) on conflict do nothing;
 if p_rule_version is not null then insert into attack_rule_links(technique_id,rule_id,created_by) select tech,rule_id,auth.uid() from rule_versions where id=p_rule_version on conflict do nothing;end if;
 insert into atomic_validation_history(request_id,from_status,to_status,note,actor_id) values(rid,subject.status,next_status,'Solicitação salva; execução exclusivamente manual.',auth.uid());
 perform audit('atomic.request_saved',rid::text,jsonb_build_object('status',next_status,'reference_id',ref.id,'technique',tech));return rid;
end $$;
create function public.transition_atomic_request(p_request uuid,p_status text,p_note text) returns void language plpgsql security definer set search_path=public as $$
declare subject operational_subjects;request atomic_validation_requests;result atomic_execution_results;
begin
 select * into subject from operational_subjects where id=p_request and kind='validation' and not archived for update;
 select * into request from atomic_validation_requests where id=p_request;
 if subject.id is null or request.id is null then raise exception 'Solicitação indisponível';end if;
 if p_note is null or length(trim(p_note)) not between 5 and 4000 then raise exception 'Registre uma justificativa de 5 a 4000 caracteres';end if;
 if p_status in ('approved','rejected','completed') then
  if not has_permission('validation.approve') then raise exception 'Sem permissão para aprovar ou revisar testes';end if;
  if subject.created_by=auth.uid() and not is_platform_admin() then raise exception 'Esta decisão exige outro revisor; administradores podem decidir independentemente';end if;
 elsif p_status='pending' then
  if not has_permission('validation.request') or (subject.created_by<>auth.uid() and not is_platform_admin()) then raise exception 'Sem permissão para enviar esta solicitação';end if;
 elsif p_status='cancelled' then
  if not has_permission('validation.approve') and not (has_permission('validation.request') and subject.created_by=auth.uid()) then raise exception 'Sem permissão para cancelar';end if;
 else
  if not has_permission('validation.record') or (request.responsible_id<>auth.uid() and not is_platform_admin()) then raise exception 'Apenas o responsável ou administrador pode registrar execução';end if;
 end if;
 if not ((subject.status='draft' and p_status in ('pending','cancelled')) or (subject.status='pending' and p_status in ('approved','rejected','cancelled')) or (subject.status='approved' and p_status in ('running','cancelled')) or (subject.status='running' and p_status='cancelled') or (subject.status='awaiting_validation' and p_status in ('completed','running','cancelled')) or (subject.status='execution_failed' and p_status in ('running','cancelled'))) then raise exception 'Transição de teste não permitida';end if;
 if p_status='completed' then
  select * into result from atomic_execution_results where request_id=p_request order by created_at desc,id desc limit 1;
  if result.id is null or result.execution<>'success' or not exists(select 1 from atomic_result_evidence l join operational_evidence e on e.id=l.evidence_id where l.result_id=result.id and e.status='ready' and e.subject_id=p_request) then raise exception 'Concluir exige execução documentada com evidência verificada';end if;
 end if;
 update operational_subjects set status=p_status,updated_at=now() where id=p_request;
 insert into atomic_validation_history(request_id,from_status,to_status,note,actor_id) values(p_request,subject.status,p_status,trim(p_note),auth.uid());
 perform audit('atomic.request_transition',p_request::text,jsonb_build_object('from',subject.status,'to',p_status));
end $$;
create function public.record_atomic_execution(p_request uuid,p_executed timestamptz,p_execution text,p_detected text,p_notes text,p_evidence uuid[]) returns uuid language plpgsql security definer set search_path=public as $$
declare subject operational_subjects;request atomic_validation_requests;rid uuid;next_status text;
begin
 if not has_permission('validation.record') then raise exception 'Sem permissão para registrar execução';end if;
 select * into subject from operational_subjects where id=p_request and kind='validation' and not archived for update;select * into request from atomic_validation_requests where id=p_request;
 if subject.id is null or subject.status<>'running' then raise exception 'Inicie a execução antes de registrar o resultado';end if;
 if request.responsible_id<>auth.uid() and not is_platform_admin() then raise exception 'Apenas o responsável ou administrador pode registrar o resultado';end if;
 if coalesce(array_length(p_evidence,1),0) not between 1 and 20 or exists(select 1 from unnest(p_evidence) as selected(evidence_id) where not exists(select 1 from operational_evidence e where e.id=selected.evidence_id and e.subject_id=p_request and e.status='ready')) then raise exception 'Selecione de 1 a 20 evidências verificadas desta solicitação';end if;
 if p_executed is null or p_executed>now()+interval '5 minutes' then raise exception 'Informe a data real da execução manual';end if;
 insert into atomic_execution_results(request_id,executed_at,execution,detected,notes,created_by) values(p_request,p_executed,p_execution,p_detected,trim(p_notes),auth.uid()) returning id into rid;
 insert into atomic_result_evidence(result_id,evidence_id) select distinct rid,selected.evidence_id from unnest(p_evidence) as selected(evidence_id);
 next_status=case when p_execution='success' then 'awaiting_validation' else 'execution_failed' end;
 update operational_subjects set status=next_status,updated_at=now() where id=p_request;
 insert into atomic_validation_history(request_id,from_status,to_status,note,actor_id) values(p_request,subject.status,next_status,'Resultado manual documentado com evidências verificadas.',auth.uid());
 perform audit('atomic.execution_recorded',rid::text,jsonb_build_object('request_id',p_request,'execution',p_execution,'detected',p_detected));return rid;
end $$;
do $$declare t text;begin
 foreach t in array array['atomic_validation_requests','atomic_execution_results','atomic_result_evidence','atomic_validation_history'] loop
 execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);
 execute format('create policy coverage_read on public.%I for select to authenticated using(public.has_permission(''coverage.read''))',t);
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.is_platform_admin(),public.save_atomic_request(uuid,text,text,uuid,text,text,text,text,timestamptz,uuid,boolean,uuid,timestamptz),public.transition_atomic_request(uuid,text,text),public.record_atomic_execution(uuid,timestamptz,text,text,text,uuid[]) from public,anon,authenticated;
grant execute on function public.is_platform_admin(),public.save_atomic_request(uuid,text,text,uuid,text,text,text,text,timestamptz,uuid,boolean,uuid,timestamptz),public.transition_atomic_request(uuid,text,text),public.record_atomic_execution(uuid,timestamptz,text,text,text,uuid[]) to authenticated;
commit;
