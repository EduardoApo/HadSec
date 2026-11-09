begin;
-- Stable typed identities shared by campaigns, hypotheses and test requests.
-- Module-specific data and write RPCs are added in their own migrations.
create table public.operational_subjects(
 id uuid primary key default gen_random_uuid(),kind text not null check(kind in ('campaign','hypothesis','validation')),
 title text not null check(length(trim(title)) between 3 and 200),status text not null default 'draft',
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),updated_at timestamptz not null default now(),
 archived boolean not null default false,unique(id,kind)
);
create table public.attack_subject_links(
 technique_id text not null references public.attack_techniques,subject_id uuid not null,subject_kind text not null,
 created_by uuid not null references public.profiles,created_at timestamptz not null default now(),
 primary key(technique_id,subject_id),foreign key(subject_id,subject_kind) references public.operational_subjects(id,kind)
);
create function public.link_attack_subject(p_technique text,p_subject uuid,p_remove boolean default false) returns void language plpgsql security definer set search_path=public as $$
declare target operational_subjects;
begin
 if not has_permission('coverage.write') then raise exception 'Sem permissão para mapear cobertura'; end if;
 if not exists(select 1 from attack_techniques where id=p_technique and active and not revoked and not deprecated) then raise exception 'Técnica indisponível';end if;
 select * into target from operational_subjects where id=p_subject and not archived;
 if target.id is null then raise exception 'Campanha, hipótese ou teste indisponível';end if;
 if p_remove then delete from attack_subject_links where technique_id=p_technique and subject_id=p_subject;
 else insert into attack_subject_links(technique_id,subject_id,subject_kind,created_by) values(p_technique,p_subject,target.kind,auth.uid()) on conflict do nothing;end if;
 perform audit(case when p_remove then 'attack.subject_unlinked' else 'attack.subject_linked' end,p_technique,jsonb_build_object('subject_id',p_subject,'kind',target.kind));
end $$;
do $$declare t text;begin
 foreach t in array array['operational_subjects','attack_subject_links'] loop
 execute format('alter table public.%I enable row level security',t);
 execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);
 execute format('create policy coverage_read on public.%I for select to authenticated using(public.has_permission(''coverage.read''))',t);
 if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;
 end loop;
end $$;
revoke all on function public.link_attack_subject(text,uuid,boolean) from public,anon;
grant execute on function public.link_attack_subject(text,uuid,boolean) to authenticated;
commit;
