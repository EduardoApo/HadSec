begin;
insert into public.permission_definitions(key,label,description) values
 ('hunting.read','Consultar operações de hunting','Consultar hipóteses, campanhas, achados e evidências autorizadas.'),
 ('hunting.write','Registrar investigações de hunting','Criar hipóteses, importar evidências e documentar resultados.');
update public.roles set permissions=permissions||array['hunting.read','hunting.write'] where system and name in ('Administrador','Engenheiro','Revisor');
update public.roles set permissions=permissions||array['hunting.read'] where system and name='Leitor';
create policy hunting_subject_read on public.operational_subjects for select to authenticated using(public.has_permission('hunting.read') and kind in ('hypothesis','campaign'));
create policy hunting_mapping_read on public.attack_subject_links for select to authenticated using(public.has_permission('hunting.read') and subject_kind in ('hypothesis','campaign'));
create policy hunting_technique_read on public.attack_techniques for select to authenticated using(public.has_permission('hunting.read'));
create policy hunting_tactic_read on public.attack_tactics for select to authenticated using(public.has_permission('hunting.read'));
create table public.hunting_hypotheses(
 id uuid primary key references public.operational_subjects,subject_kind text not null default 'hypothesis' check(subject_kind='hypothesis'),
 description text not null check(length(trim(description)) between 10 and 8000),behavior text not null check(length(trim(behavior)) between 10 and 4000),
 justification text not null check(length(trim(justification)) between 10 and 4000),scope text not null check(length(trim(scope)) between 3 and 4000),
 methodology text not null default '' check(length(methodology)<=8000),log_sources text[] not null default '{}' check(array_length(log_sources,1)<=50),
 expected_results text not null default '' check(length(expected_results)<=4000),conclusion text not null default '' check(length(conclusion)<=8000),recommendations text not null default '' check(length(recommendations)<=8000),
 priority text not null check(priority in ('Baixa','Média','Alta','Crítica')),responsible_id uuid not null references public.profiles,
 campaign_id uuid,campaign_kind text not null default 'campaign' check(campaign_kind='campaign'),
 foreign key(id,subject_kind) references public.operational_subjects(id,kind),foreign key(campaign_id,campaign_kind) references public.operational_subjects(id,kind)
);
create table public.hunting_findings(
 id uuid primary key default gen_random_uuid(),hypothesis_id uuid not null references public.hunting_hypotheses,
 title text not null check(length(trim(title)) between 3 and 200),description text not null check(length(trim(description)) between 10 and 8000),
 recommendation text not null check(length(trim(recommendation)) between 5 and 4000),priority text not null check(priority in ('Baixa','Média','Alta','Crítica')),
 rule_id uuid references public.rules,created_by uuid not null references public.profiles,created_at timestamptz not null default now(),updated_at timestamptz not null default now()
);
create table public.hunting_finding_requests(
 finding_id uuid not null references public.hunting_findings,request_id uuid not null references public.change_requests,
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),primary key(finding_id,request_id)
);
create function public.save_hunting_hypothesis(p_id uuid,p_title text,p_description text,p_behavior text,p_justification text,p_scope text,p_methodology text,p_log_sources text[],p_expected_results text,p_conclusion text,p_recommendations text,p_priority text,p_responsible uuid,p_status text,p_campaign uuid,p_techniques text[],p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;subject operational_subjects;
begin
 if not has_permission('hunting.read') or not has_permission('hunting.write') then raise exception 'Sem permissão para registrar investigações';end if;
 if p_status is null or p_status not in ('draft','active','review','completed','cancelled') then raise exception 'Estado da hipótese inválido';end if;
 if p_status='completed' and length(trim(coalesce(p_conclusion,'')))<10 then raise exception 'Documente a conclusão antes de encerrar a hipótese';end if;
 if not exists(select 1 from profiles where id=p_responsible and active and deleted_at is null and not must_change_password) then raise exception 'Responsável indisponível';end if;
 if p_campaign is not null and not exists(select 1 from operational_subjects where id=p_campaign and kind='campaign' and not archived) then raise exception 'Campanha indisponível';end if;
 if coalesce(array_length(p_techniques,1),0)>50 or exists(select 1 from unnest(p_techniques) t where not exists(select 1 from attack_techniques a where a.id=t and a.active and not a.revoked and not a.deprecated)) then raise exception 'Técnica MITRE não encontrada no catálogo ativo';end if;
 if exists(select 1 from unnest(p_log_sources) s where length(s)>200) then raise exception 'Uma fonte de logs excede 200 caracteres';end if;
 if p_id is null then insert into operational_subjects(kind,title,status,created_by) values('hypothesis',trim(p_title),p_status,auth.uid()) returning id into rid;
 else
  select * into subject from operational_subjects where id=p_id and kind='hypothesis' and not archived for update;
  if subject.id is null then raise exception 'Hipótese indisponível';end if;
  if p_expected_updated is distinct from subject.updated_at then raise exception 'A hipótese mudou. Atualize antes de salvar';end if;
  rid=p_id;update operational_subjects set title=trim(p_title),status=p_status,updated_at=now() where id=rid;
 end if;
 insert into hunting_hypotheses(id,description,behavior,justification,scope,methodology,log_sources,expected_results,conclusion,recommendations,priority,responsible_id,campaign_id)
 values(rid,trim(p_description),trim(p_behavior),trim(p_justification),trim(p_scope),coalesce(p_methodology,''),coalesce(p_log_sources,'{}'),coalesce(p_expected_results,''),coalesce(p_conclusion,''),coalesce(p_recommendations,''),p_priority,p_responsible,p_campaign)
 on conflict(id) do update set description=excluded.description,behavior=excluded.behavior,justification=excluded.justification,scope=excluded.scope,methodology=excluded.methodology,log_sources=excluded.log_sources,expected_results=excluded.expected_results,conclusion=excluded.conclusion,recommendations=excluded.recommendations,priority=excluded.priority,responsible_id=excluded.responsible_id,campaign_id=excluded.campaign_id;
 delete from attack_subject_links where subject_id=rid;
 insert into attack_subject_links(technique_id,subject_id,subject_kind,created_by) select distinct t,rid,'hypothesis',auth.uid() from unnest(p_techniques) t;
 perform audit('hunting.hypothesis_saved',rid::text,jsonb_build_object('status',p_status,'campaign_id',p_campaign,'techniques',p_techniques));return rid;
end $$;
create function public.save_hunting_finding(p_id uuid,p_hypothesis uuid,p_title text,p_description text,p_recommendation text,p_priority text,p_rule uuid default null,p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;previous hunting_findings;
begin
 if not has_permission('hunting.read') or not has_permission('hunting.write') then raise exception 'Sem permissão para registrar achados';end if;
 if not exists(select 1 from hunting_hypotheses h join operational_subjects s on s.id=h.id where h.id=p_hypothesis and not s.archived) then raise exception 'Hipótese indisponível';end if;
 if p_rule is not null and not exists(select 1 from rules where id=p_rule and not archived) then raise exception 'Regra indisponível';end if;
 if p_id is null then
  insert into hunting_findings(hypothesis_id,title,description,recommendation,priority,rule_id,created_by) values(p_hypothesis,trim(p_title),trim(p_description),trim(p_recommendation),p_priority,p_rule,auth.uid()) returning id into rid;
 else
  select * into previous from hunting_findings where id=p_id and hypothesis_id=p_hypothesis for update;
  if previous.id is null or p_expected_updated is distinct from previous.updated_at then raise exception 'O achado mudou ou está indisponível';end if;
  rid=p_id;update hunting_findings set title=trim(p_title),description=trim(p_description),recommendation=trim(p_recommendation),priority=p_priority,rule_id=p_rule,updated_at=now() where id=rid;
 end if;
 perform audit('hunting.finding_saved',rid::text,jsonb_build_object('hypothesis_id',p_hypothesis,'rule_id',p_rule));return rid;
end $$;
create function public.request_from_hunting_finding(p_finding uuid,p_title text,p_context text,p_kind text,p_rule uuid default null,p_format text default 'sigma',p_mode text default 'Native') returns uuid language plpgsql security definer set search_path=public as $$
declare finding hunting_findings;subject operational_subjects;rule rules;rid uuid;description text;
begin
 if not has_permission('hunting.read') or not has_permission('hunting.write') or not has_permission('requests.create') then raise exception 'Sem permissão para encaminhar achados';end if;
 select * into finding from hunting_findings where id=p_finding;select * into subject from operational_subjects where id=finding.hypothesis_id and not archived;
 if finding.id is null or subject.id is null then raise exception 'Achado indisponível';end if;
 if p_context is null or length(trim(p_context))<10 then raise exception 'Descreva o objetivo da solicitação';end if;
 if p_kind='change' then select * into rule from rules where id=p_rule and not archived;if rule.id is null then raise exception 'Selecione a regra a ajustar';end if;end if;
 description=left(p_context||E'\n\nHipótese: '||subject.title||E'\nAchado: '||finding.title||E'\n'||left(finding.description,1500)||E'\nRecomendação: '||left(finding.recommendation,1000)||E'\nReferência de investigação: '||finding.hypothesis_id::text||' / '||finding.id::text,8000);
 rid=submit_change_request(p_kind,p_title,description,case when p_kind='change' then rule.format else p_format end,case when p_kind='change' then rule.mode else p_mode end,case when p_kind='change' then rule.id else null end,null);
 insert into hunting_finding_requests(finding_id,request_id,created_by) values(p_finding,rid,auth.uid());
 perform audit('hunting.finding_requested',rid::text,jsonb_build_object('finding_id',p_finding,'hypothesis_id',finding.hypothesis_id,'kind',p_kind));return rid;
end $$;
create function public.audit_operational_export(p_subject uuid,p_format text) returns void language plpgsql security definer set search_path=public as $$
begin
 if not can_read_subject(p_subject) then raise exception 'Sem permissão para exportar este registro';end if;
 if p_format not in ('pdf','json','csv') then raise exception 'Formato de exportação inválido';end if;
 perform audit('hunting.report_exported',p_subject::text,jsonb_build_object('format',p_format));
end $$;
create function public.actor_has_permission(p_actor uuid,p_permission text) returns boolean language sql stable security definer set search_path=public as $$
 select exists(select 1 from profiles p join roles r on r.id=p.role_id left join user_permission_overrides o on o.user_id=p.id and o.permission=p_permission where p.id=p_actor and p.active and p.deleted_at is null and not p.must_change_password and coalesce(o.granted,p_permission=any(r.permissions)))
$$;
do $$declare t text;begin
 foreach t in array array['hunting_hypotheses','hunting_findings','hunting_finding_requests'] loop
 execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);
 execute format('create policy hunting_read on public.%I for select to authenticated using(public.has_permission(''hunting.read''))',t);
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.save_hunting_hypothesis(uuid,text,text,text,text,text,text,text[],text,text,text,text,uuid,text,uuid,text[],timestamptz),public.save_hunting_finding(uuid,uuid,text,text,text,text,uuid,timestamptz),public.request_from_hunting_finding(uuid,text,text,text,uuid,text,text),public.audit_operational_export(uuid,text),public.actor_has_permission(uuid,text) from public,anon,authenticated;
grant execute on function public.save_hunting_hypothesis(uuid,text,text,text,text,text,text,text[],text,text,text,text,uuid,text,uuid,text[],timestamptz),public.save_hunting_finding(uuid,uuid,text,text,text,text,uuid,timestamptz),public.request_from_hunting_finding(uuid,text,text,text,uuid,text,text),public.audit_operational_export(uuid,text) to authenticated;
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant execute on function public.actor_has_permission(uuid,text) to service_role;end if;end $$;
commit;
