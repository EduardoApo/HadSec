begin;
insert into permission_definitions(key,label,description) values('queries.read','Consultar biblioteca de hunting','Consultar consultas, versões e uso autorizado.'),('queries.write','Gerenciar consultas de hunting','Criar, versionar, importar, excluir e relacionar consultas.');
update roles set permissions=permissions||array['queries.read','queries.write'] where system and name in ('Administrador','Engenheiro','Revisor');update roles set permissions=permissions||array['queries.read'] where system and name='Leitor';
create policy query_technique_read on attack_techniques for select to authenticated using(has_permission('queries.read'));
create table hunting_queries(
 id uuid primary key default gen_random_uuid(),title text not null check(length(trim(title)) between 3 and 200),description text not null check(length(trim(description)) between 10 and 8000),
 technology text not null check(technology in ('fortisiem','splunk','elastic','wazuh','kusto','qradar','velociraptor','other')),
 language text not null check(language in ('sql','xml','sigma','kusto','aql','eql','kibana_kql','spl','yara','lucene','vql','json','other')),
 data_source text not null check(length(trim(data_source)) between 2 and 2000),tags text[] not null default '{}' check(cardinality(tags)<=30),
 current_version integer not null default 0,created_by uuid not null references profiles,created_at timestamptz not null default now(),updated_at timestamptz not null default now(),deleted_at timestamptz
);
create table hunting_query_versions(
 id uuid primary key default gen_random_uuid(),query_id uuid not null references hunting_queries,number integer not null check(number>0),
 content text not null check(length(trim(content)) between 1 and 100000 and octet_length(content)<=200000),snapshot jsonb not null check(jsonb_typeof(snapshot)='object' and octet_length(snapshot::text)<=40000),
 note text not null check(length(trim(note)) between 5 and 2000),created_by uuid not null references profiles,created_at timestamptz not null default now(),unique(query_id,number),unique(query_id,id)
);
create table query_favorites(query_id uuid not null references hunting_queries,user_id uuid not null references profiles,created_at timestamptz not null default now(),primary key(query_id,user_id));
create table query_subject_links(
 id uuid primary key default gen_random_uuid(),query_id uuid not null references hunting_queries,version_id uuid not null,
 subject_id uuid not null,subject_kind text not null check(subject_kind in ('hypothesis','campaign')),notes text not null check(length(trim(notes)) between 5 and 4000),
 created_by uuid not null references profiles,created_at timestamptz not null default now(),foreign key(subject_id,subject_kind) references operational_subjects(id,kind),foreign key(query_id,version_id) references hunting_query_versions(query_id,id),unique(version_id,subject_id)
);
create function save_hunting_query(p_id uuid,p_title text,p_description text,p_technology text,p_language text,p_source text,p_tags text[],p_required_fields text[],p_techniques text[],p_limitations text,p_content text,p_note text,p_expected_version integer default 0) returns uuid language plpgsql security definer set search_path=public as $$
declare rid uuid;q hunting_queries;meta jsonb;n integer;
begin
 if not has_permission('queries.read') or not has_permission('queries.write') then raise exception 'Sem permissão para gerenciar consultas';end if;
 if coalesce(cardinality(p_tags),0)>30 or exists(select 1 from unnest(p_tags) t where t is null or length(trim(t)) not between 1 and 80) or coalesce(cardinality(p_required_fields),0)>100 or exists(select 1 from unnest(p_required_fields) t where t is null or length(trim(t)) not between 1 and 200) or length(coalesce(p_limitations,''))>8000 then raise exception 'Tags, campos ou limitações inválidos';end if;
 if coalesce(cardinality(p_techniques),0)>50 or exists(select 1 from unnest(p_techniques) t where not exists(select 1 from attack_techniques where id=t and active and not revoked and not deprecated)) then raise exception 'Técnica MITRE indisponível no catálogo ativo';end if;
 if p_id is null then insert into hunting_queries(title,description,technology,language,data_source,tags,created_by) values(trim(p_title),trim(p_description),p_technology,p_language,trim(p_source),coalesce(p_tags,'{}'),auth.uid()) returning id into rid;n=1;
 else select * into q from hunting_queries where id=p_id and deleted_at is null for update;if q.id is null or q.current_version is distinct from p_expected_version then raise exception 'A consulta mudou ou foi excluída. Atualize antes de salvar';end if;rid=p_id;n=q.current_version+1;end if;
 meta=jsonb_build_object('title',trim(p_title),'description',trim(p_description),'technology',p_technology,'language',p_language,'data_source',trim(p_source),'tags',coalesce(p_tags,'{}'),'required_fields',coalesce(p_required_fields,'{}'),'techniques',coalesce(p_techniques,'{}'),'limitations',coalesce(p_limitations,''));
 insert into hunting_query_versions(query_id,number,content,snapshot,note,created_by) values(rid,n,p_content,meta,trim(p_note),auth.uid());
 update hunting_queries set title=trim(p_title),description=trim(p_description),technology=p_technology,language=p_language,data_source=trim(p_source),tags=coalesce(p_tags,'{}'),current_version=n,updated_at=now() where id=rid;
 perform audit('hunting.query_saved',rid::text,jsonb_build_object('version',n,'technology',p_technology,'language',p_language));return rid;
end $$;
create function duplicate_hunting_query(p_query uuid) returns uuid language plpgsql security definer set search_path=public as $$
declare q hunting_queries;v hunting_query_versions;rid uuid;
begin
 if not has_permission('queries.read') or not has_permission('queries.write') then raise exception 'Sem permissão para duplicar consultas';end if;
 select * into q from hunting_queries where id=p_query and deleted_at is null;select * into v from hunting_query_versions where query_id=q.id and number=q.current_version;if v.id is null then raise exception 'Consulta indisponível';end if;
 rid=save_hunting_query(null,left(q.title,190)||' (cópia)',q.description,q.technology,q.language,q.data_source,q.tags,array(select jsonb_array_elements_text(v.snapshot->'required_fields')),array(select jsonb_array_elements_text(v.snapshot->'techniques')),v.snapshot->>'limitations',v.content,'Duplicada da consulta '||q.id||' versão '||v.number,0);
 perform audit('hunting.query_duplicated',rid::text,jsonb_build_object('source',q.id,'source_version',v.id));return rid;
end $$;
create function delete_hunting_query(p_query uuid,p_expected_version integer) returns void language plpgsql security definer set search_path=public as $$
declare q hunting_queries;
begin
 if not has_permission('queries.read') or not has_permission('queries.write') then raise exception 'Sem permissão para excluir consultas';end if;
 select * into q from hunting_queries where id=p_query and deleted_at is null for update;if q.id is null or q.current_version is distinct from p_expected_version then raise exception 'A consulta mudou ou foi excluída';end if;
 update hunting_queries set deleted_at=now(),updated_at=now() where id=p_query;delete from query_favorites where query_id=p_query;
 perform audit('hunting.query_deleted',p_query::text,jsonb_build_object('last_version',q.current_version,'history_preserved',true));
end $$;
create function favorite_hunting_query(p_query uuid,p_favorite boolean) returns void language plpgsql security definer set search_path=public as $$
begin
 if not has_permission('queries.read') or not exists(select 1 from hunting_queries where id=p_query and deleted_at is null) then raise exception 'Consulta indisponível';end if;
 if p_favorite then insert into query_favorites(query_id,user_id) values(p_query,auth.uid()) on conflict do nothing;else delete from query_favorites where query_id=p_query and user_id=auth.uid();end if;
end $$;
create function link_hunting_query(p_version uuid,p_subject uuid,p_notes text,p_remove boolean default false) returns void language plpgsql security definer set search_path=public as $$
declare s operational_subjects;v hunting_query_versions;
begin
 if not has_permission('queries.read') or not has_permission('queries.write') or not can_read_subject(p_subject) or not can_write_subject(p_subject) then raise exception 'Sem permissão para relacionar a consulta';end if;
 select * into s from operational_subjects where id=p_subject and kind in ('campaign','hypothesis') and not archived;select * into v from hunting_query_versions where id=p_version;
 if s.id is null or v.id is null then raise exception 'Consulta ou registro indisponível';end if;
 if p_remove then delete from query_subject_links where version_id=p_version and subject_id=p_subject;
 else
  if not exists(select 1 from hunting_queries where id=v.query_id and deleted_at is null) then raise exception 'Consulta excluída';end if;
  insert into query_subject_links(query_id,version_id,subject_id,subject_kind,notes,created_by) values(v.query_id,v.id,s.id,s.kind,trim(p_notes),auth.uid());
 end if;
 perform audit(case when p_remove then 'hunting.query_unlinked' else 'hunting.query_linked' end,v.query_id::text,jsonb_build_object('version_id',v.id,'subject_id',s.id,'notes',p_notes));
end $$;
create function import_hunting_queries(p_document jsonb) returns uuid[] language plpgsql security definer set search_path=public as $$
declare entry jsonb;meta jsonb;ids uuid[]='{}';rid uuid;
begin
 if not has_permission('queries.read') or not has_permission('queries.write') then raise exception 'Sem permissão para importar consultas';end if;
 if octet_length(p_document::text)>2000000 or p_document->>'schema' is distinct from 'hadsec.hunting-queries.v1' or jsonb_typeof(p_document->'queries') is distinct from 'array' then raise exception 'Documento de consultas inválido';end if;
 if jsonb_array_length(p_document->'queries') not between 1 and 20 then raise exception 'Importe de 1 a 20 consultas por arquivo';end if;
 if exists(select 1 from jsonb_object_keys(p_document) k where k not in ('schema','queries','exported_at')) then raise exception 'Propriedade inesperada no documento de consultas';end if;
 for entry in select jsonb_array_elements(p_document->'queries') loop
  meta=entry->'metadata';if jsonb_typeof(meta) is distinct from 'object' or jsonb_typeof(entry->'content') is distinct from 'string' then raise exception 'Consulta sem conteúdo ou metadados';end if;
  if exists(select 1 from jsonb_object_keys(meta) k where k not in ('title','description','technology','language','data_source','tags','required_fields','techniques','limitations')) or exists(select 1 from jsonb_object_keys(entry) k where k not in ('metadata','content')) then raise exception 'Propriedade inesperada no documento de consultas';end if;
  if exists(select 1 from jsonb_each(meta) e where e.key in ('title','description','technology','language','data_source','limitations') and jsonb_typeof(e.value)<>'string') or exists(select 1 from jsonb_each(meta) e where e.key in ('tags','required_fields','techniques') and jsonb_typeof(e.value)<>'array') then raise exception 'Tipo de metadado inválido';end if;
  if exists(select 1 from jsonb_each(meta) e cross join lateral jsonb_array_elements(case when e.key in ('tags','required_fields','techniques') then e.value else '[]'::jsonb end) x where jsonb_typeof(x)<>'string') then raise exception 'As listas de metadados aceitam somente texto';end if;
  rid=save_hunting_query(null,meta->>'title',meta->>'description',meta->>'technology',meta->>'language',meta->>'data_source',array(select jsonb_array_elements_text(meta->'tags')),array(select jsonb_array_elements_text(meta->'required_fields')),array(select jsonb_array_elements_text(meta->'techniques')),meta->>'limitations',entry->>'content','Importada de JSON; identidade e autoria de origem não são herdadas',0);ids=array_append(ids,rid);
 end loop;
 perform audit('hunting.queries_imported',auth.uid()::text,jsonb_build_object('query_ids',ids,'count',cardinality(ids)));return ids;
end $$;
create function audit_query_export(p_query uuid,p_version uuid) returns void language plpgsql security definer set search_path=public as $$begin if not has_permission('queries.read') or not exists(select 1 from hunting_query_versions where id=p_version and query_id=p_query) then raise exception 'Consulta indisponível';end if;perform audit('hunting.query_exported',p_query::text,jsonb_build_object('version_id',p_version));end $$;
do $$declare t text;begin foreach t in array array['hunting_queries','hunting_query_versions'] loop execute format('alter table public.%I enable row level security',t);execute format('revoke all on public.%I from anon,authenticated',t);execute format('grant select on public.%I to authenticated',t);execute format('create policy query_read on public.%I for select to authenticated using(public.has_permission(''queries.read''))',t);if exists(select 1 from pg_roles where rolname='service_role') then execute format('grant all on public.%I to service_role',t);end if;end loop;end $$;
alter table query_favorites enable row level security;revoke all on query_favorites from anon,authenticated;grant select on query_favorites to authenticated;create policy own_favorites on query_favorites for select to authenticated using(user_id=auth.uid() and has_permission('queries.read'));
alter table query_subject_links enable row level security;revoke all on query_subject_links from anon,authenticated;grant select on query_subject_links to authenticated;create policy subject_read on query_subject_links for select to authenticated using(has_permission('queries.read') and can_read_subject(subject_id));
do $$begin if exists(select 1 from pg_roles where rolname='service_role') then grant all on query_favorites,query_subject_links to service_role;end if;end $$;
revoke all on function save_hunting_query(uuid,text,text,text,text,text,text[],text[],text[],text,text,text,integer),duplicate_hunting_query(uuid),delete_hunting_query(uuid,integer),favorite_hunting_query(uuid,boolean),link_hunting_query(uuid,uuid,text,boolean),import_hunting_queries(jsonb),audit_query_export(uuid,uuid) from public,anon;
grant execute on function save_hunting_query(uuid,text,text,text,text,text,text[],text[],text[],text,text,text,integer),duplicate_hunting_query(uuid),delete_hunting_query(uuid,integer),favorite_hunting_query(uuid,boolean),link_hunting_query(uuid,uuid,text,boolean),import_hunting_queries(jsonb),audit_query_export(uuid,uuid) to authenticated;
commit;
