begin;
-- Preserve existing historical links when a rule is archived; new archived links remain forbidden.
create or replace function save_hunting_campaign(p_id uuid,p_title text,p_objective text,p_scope text,p_responsible uuid,p_priority text,p_deadline date,p_status text,p_conclusion text,p_members uuid[],p_techniques text[],p_rules uuid[],p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;s operational_subjects;
begin
 if not has_permission('hunting.read') or not has_permission('campaigns.manage') then raise exception 'Sem permissão para gerenciar campanhas';end if;
 if p_status is null or p_status not in ('draft','active','review','completed','cancelled') then raise exception 'Estado da campanha inválido';end if;
 if not exists(select 1 from profiles where id=p_responsible and active and deleted_at is null and not must_change_password) then raise exception 'Responsável indisponível';end if;
 if coalesce(cardinality(p_members),0)>100 or exists(select 1 from unnest(p_members) u where not exists(select 1 from profiles where id=u and active and deleted_at is null and not must_change_password)) then raise exception 'Participante indisponível';end if;
 if coalesce(cardinality(p_techniques),0)>100 or exists(select 1 from unnest(p_techniques) t where not exists(select 1 from attack_techniques where id=t and active and not revoked and not deprecated)) then raise exception 'Técnica MITRE indisponível';end if;
 if coalesce(cardinality(p_rules),0)>100 or exists(select 1 from unnest(p_rules) r where not exists(select 1 from rules where id=r and (not archived or exists(select 1 from campaign_rule_links old_link where old_link.campaign_id=p_id and old_link.rule_id=r)))) then raise exception 'Regra indisponível';end if;
 if p_id is null then insert into operational_subjects(kind,title,status,created_by) values('campaign',trim(p_title),p_status,auth.uid()) returning id into rid;
 else select * into s from operational_subjects where id=p_id and kind='campaign' and not archived for update;if s.id is null or s.updated_at is distinct from p_expected_updated then raise exception 'A campanha mudou. Atualize antes de salvar';end if;rid=p_id;end if;
 if p_status='completed' and (length(trim(coalesce(p_conclusion,'')))<10 or exists(select 1 from campaign_tasks where campaign_id=rid and status not in ('completed','cancelled'))) then raise exception 'Conclua ou cancele as tarefas e documente a conclusão antes de encerrar';end if;
 update operational_subjects set title=trim(p_title),status=p_status,updated_at=now() where id=rid;
 insert into hunting_campaigns(id,objective,scope,responsible_id,priority,deadline,conclusion) values(rid,trim(p_objective),trim(p_scope),p_responsible,p_priority,p_deadline,coalesce(p_conclusion,'')) on conflict(id) do update set objective=excluded.objective,scope=excluded.scope,responsible_id=excluded.responsible_id,priority=excluded.priority,deadline=excluded.deadline,conclusion=excluded.conclusion;
 delete from campaign_members where campaign_id=rid;insert into campaign_members select distinct rid,u from unnest(coalesce(p_members,'{}')||array[p_responsible]) u;
 delete from attack_subject_links where subject_id=rid;insert into attack_subject_links(technique_id,subject_id,subject_kind,created_by) select distinct t,rid,'campaign',auth.uid() from unnest(p_techniques) t;
 delete from campaign_rule_links where campaign_id=rid;insert into campaign_rule_links(campaign_id,rule_id,created_by) select distinct rid,r,auth.uid() from unnest(p_rules) r;
 perform audit('hunting.campaign_saved',rid::text,jsonb_build_object('status',p_status,'participants',p_members,'techniques',p_techniques,'rules',p_rules));return rid;
end $$;
create or replace function public.save_hunting_finding(p_id uuid,p_hypothesis uuid,p_title text,p_description text,p_recommendation text,p_priority text,p_rule uuid default null,p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;previous hunting_findings;
begin
 if not has_permission('hunting.read') or not has_permission('hunting.write') then raise exception 'Sem permissão para registrar achados';end if;
 if not exists(select 1 from hunting_hypotheses h join operational_subjects s on s.id=h.id where h.id=p_hypothesis and not s.archived) then raise exception 'Hipótese indisponível';end if;
 if p_rule is not null and not exists(select 1 from rules where id=p_rule and (not archived or exists(select 1 from hunting_findings old_finding where old_finding.id=p_id and old_finding.hypothesis_id=p_hypothesis and old_finding.rule_id=p_rule))) then raise exception 'Regra indisponível';end if;
 if p_id is null then
  insert into hunting_findings(hypothesis_id,title,description,recommendation,priority,rule_id,created_by) values(p_hypothesis,trim(p_title),trim(p_description),trim(p_recommendation),p_priority,p_rule,auth.uid()) returning id into rid;
 else
  select * into previous from hunting_findings where id=p_id and hypothesis_id=p_hypothesis for update;
  if previous.id is null or p_expected_updated is distinct from previous.updated_at then raise exception 'O achado mudou ou está indisponível';end if;
  rid=p_id;update hunting_findings set title=trim(p_title),description=trim(p_description),recommendation=trim(p_recommendation),priority=p_priority,rule_id=p_rule,updated_at=now() where id=rid;
 end if;
 perform audit('hunting.finding_saved',rid::text,jsonb_build_object('hypothesis_id',p_hypothesis,'rule_id',p_rule));return rid;
end $$;
commit;
