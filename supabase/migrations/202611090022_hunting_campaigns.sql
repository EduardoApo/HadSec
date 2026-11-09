begin;
insert into permission_definitions(key,label,description) values('campaigns.manage','Gerenciar campanhas','Criar campanhas, participantes, tarefas e encerramentos.');
update roles set permissions=permissions||array['campaigns.manage'] where system and name in ('Administrador','Engenheiro','Revisor');
create table hunting_campaigns(
 id uuid primary key references operational_subjects,subject_kind text not null default 'campaign' check(subject_kind='campaign'),
 objective text not null check(length(trim(objective)) between 10 and 8000),scope text not null check(length(trim(scope)) between 3 and 4000),
 responsible_id uuid not null references profiles,priority text not null check(priority in ('Baixa','Média','Alta','Crítica')),deadline date not null,
 conclusion text not null default '' check(length(conclusion)<=12000),foreign key(id,subject_kind) references operational_subjects(id,kind)
);
create table campaign_members(campaign_id uuid not null references hunting_campaigns,user_id uuid not null references profiles,primary key(campaign_id,user_id));
create table campaign_rule_links(campaign_id uuid not null references hunting_campaigns,rule_id uuid not null references rules,created_by uuid not null references profiles,created_at timestamptz not null default now(),primary key(campaign_id,rule_id));
create table campaign_tasks(
 id uuid primary key default gen_random_uuid(),campaign_id uuid not null references hunting_campaigns,title text not null check(length(trim(title)) between 3 and 200),
 description text not null check(length(trim(description)) between 3 and 8000),responsible_id uuid not null references profiles,
 priority text not null check(priority in ('Baixa','Média','Alta','Crítica')),deadline date,
 status text not null default 'pending' check(status in ('pending','in_progress','review','completed','blocked','cancelled')),
 result text not null default '' check(length(result)<=8000),created_by uuid not null references profiles,created_at timestamptz not null default now(),updated_at timestamptz not null default now()
);
create table campaign_task_history(id uuid primary key default gen_random_uuid(),task_id uuid not null references campaign_tasks,actor_id uuid not null references profiles,previous_status text,next_status text not null,note text not null,created_at timestamptz not null default now());
create function save_hunting_campaign(p_id uuid,p_title text,p_objective text,p_scope text,p_responsible uuid,p_priority text,p_deadline date,p_status text,p_conclusion text,p_members uuid[],p_techniques text[],p_rules uuid[],p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;s operational_subjects;
begin
 if not has_permission('hunting.read') or not has_permission('campaigns.manage') then raise exception 'Sem permissão para gerenciar campanhas';end if;
 if p_status is null or p_status not in ('draft','active','review','completed','cancelled') then raise exception 'Estado da campanha inválido';end if;
 if not exists(select 1 from profiles where id=p_responsible and active and deleted_at is null and not must_change_password) then raise exception 'Responsável indisponível';end if;
 if coalesce(cardinality(p_members),0)>100 or exists(select 1 from unnest(p_members) u where not exists(select 1 from profiles where id=u and active and deleted_at is null and not must_change_password)) then raise exception 'Participante indisponível';end if;
 if coalesce(cardinality(p_techniques),0)>100 or exists(select 1 from unnest(p_techniques) t where not exists(select 1 from attack_techniques where id=t and active and not revoked and not deprecated)) then raise exception 'Técnica MITRE indisponível';end if;
 if coalesce(cardinality(p_rules),0)>100 or exists(select 1 from unnest(p_rules) r where not exists(select 1 from rules where id=r and not archived)) then raise exception 'Regra indisponível';end if;
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
create function save_campaign_task(p_id uuid,p_campaign uuid,p_title text,p_description text,p_responsible uuid,p_priority text,p_deadline date,p_status text,p_result text,p_expected_updated timestamptz default null) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;s operational_subjects;t campaign_tasks;
begin
 if not has_permission('hunting.read') or not has_permission('campaigns.manage') then raise exception 'Sem permissão para gerenciar tarefas';end if;
 select * into s from operational_subjects where id=p_campaign and kind='campaign' and not archived for update;
 if s.id is null or s.status in ('completed','cancelled') or not exists(select 1 from hunting_campaigns where id=p_campaign) then raise exception 'Campanha indisponível para tarefas';end if;
 if not exists(select 1 from campaign_members m join profiles p on p.id=m.user_id where m.campaign_id=p_campaign and m.user_id=p_responsible and p.active and p.deleted_at is null and not p.must_change_password) then raise exception 'O responsável precisa participar da campanha';end if;
 if p_status in ('completed','blocked','cancelled') and length(trim(coalesce(p_result,'')))<5 then raise exception 'Documente o resultado ou motivo da tarefa';end if;
 if p_id is null then insert into campaign_tasks(campaign_id,title,description,responsible_id,priority,deadline,status,result,created_by) values(p_campaign,trim(p_title),trim(p_description),p_responsible,p_priority,p_deadline,p_status,coalesce(p_result,''),auth.uid()) returning id into rid;
 else select * into t from campaign_tasks where id=p_id and campaign_id=p_campaign for update;if t.id is null or t.updated_at is distinct from p_expected_updated then raise exception 'A tarefa mudou. Atualize antes de salvar';end if;rid=p_id;update campaign_tasks set title=trim(p_title),description=trim(p_description),responsible_id=p_responsible,priority=p_priority,deadline=p_deadline,status=p_status,result=coalesce(p_result,''),updated_at=now() where id=rid;end if;
 insert into campaign_task_history(task_id,actor_id,previous_status,next_status,note) values(rid,auth.uid(),t.status,p_status,coalesce(p_result,''));
 perform audit('hunting.task_saved',rid::text,jsonb_build_object('campaign_id',p_campaign,'previous_status',t.status,'status',p_status));return rid;
end $$;
do $$declare t text;begin foreach t in array array['hunting_campaigns','campaign_members','campaign_rule_links','campaign_tasks','campaign_task_history'] loop
 execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);execute format('create policy hunting_read on public.%I for select to authenticated using(public.has_permission(''hunting.read''))',t);
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;end loop;end $$;
revoke all on function save_hunting_campaign(uuid,text,text,text,uuid,text,date,text,text,uuid[],text[],uuid[],timestamptz),save_campaign_task(uuid,uuid,text,text,uuid,text,date,text,text,timestamptz) from public,anon;
grant execute on function save_hunting_campaign(uuid,text,text,text,uuid,text,date,text,text,uuid[],text[],uuid[],timestamptz),save_campaign_task(uuid,uuid,text,text,uuid,text,date,text,text,timestamptz) to authenticated;
commit;
