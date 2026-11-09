begin;
create index hunting_hypotheses_campaign on hunting_hypotheses(campaign_id);
create index campaign_tasks_campaign on campaign_tasks(campaign_id,status);
create index campaign_history_task on campaign_task_history(task_id,created_at);
create index fp_occurrences_case_time on fp_occurrences(case_id,occurred_at);
create index fp_tuning_results_case on fp_tuning_results(case_id,created_at);
create index query_subject_links_subject on query_subject_links(subject_id);
create index operational_evidence_subject on operational_evidence(subject_id,status);
create function operational_overview() returns jsonb language plpgsql stable security definer set search_path=public as $$
declare result jsonb;
begin
 if not exists(select 1 from profiles where id=auth.uid() and active and deleted_at is null and not must_change_password) then raise exception 'Entre com uma conta ativa para consultar o resumo';end if;
 result=jsonb_build_object('checked_at',now(),'coverage',null,'investigations',null,'campaigns',null,'false-positives',null,'query-library',null);
 if has_permission('coverage.read') then result=result||jsonb_build_object('coverage',jsonb_build_object('techniques',(select count(*) from attack_techniques where active and not revoked and not deprecated),'sigma',(select count(*) from reference_rules where source='sigma' and active),'atomic',(select count(*) from reference_rules where source='atomic' and active)));end if;
 if has_permission('hunting.read') then result=result||jsonb_build_object('investigations',jsonb_build_object('total',(select count(*) from hunting_hypotheses h join operational_subjects s on s.id=h.id where not s.archived),'active',(select count(*) from hunting_hypotheses h join operational_subjects s on s.id=h.id where not s.archived and s.status in ('active','review')),'events',(select count(*) from hunting_events e join hunting_imports i on i.id=e.import_id join operational_subjects s on s.id=i.hypothesis_id where i.status='ready' and i.active and not s.archived)),'campaigns',jsonb_build_object('total',(select count(*) from hunting_campaigns c join operational_subjects s on s.id=c.id where not s.archived),'active',(select count(*) from hunting_campaigns c join operational_subjects s on s.id=c.id where not s.archived and s.status in ('active','review')),'tasks',(select count(*) from campaign_tasks),'completed',(select count(*) from campaign_tasks where status='completed')));end if;
 if has_permission('fp.read') then result=result||jsonb_build_object('false-positives',jsonb_build_object('total',(select count(*) from false_positive_cases c join operational_subjects s on s.id=c.id where not s.archived),'occurrences',(select count(*) from fp_occurrences),'recurrences',(select coalesce(sum(n-1),0) from (select count(*) n from fp_occurrences group by case_id having count(*)>1) counts)));end if;
 if has_permission('queries.read') then result=result||jsonb_build_object('query-library',jsonb_build_object('total',(select count(*) from hunting_queries where deleted_at is null),'versions',(select count(*) from hunting_query_versions v join hunting_queries q on q.id=v.query_id where q.deleted_at is null)));end if;
 return result;
end $$;
revoke all on function operational_overview() from public,anon;grant execute on function operational_overview() to authenticated;
commit;
