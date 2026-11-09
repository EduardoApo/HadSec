begin;
create or replace function public.search_reference_rules(p_source text,p_query text default '',p_level text default '',p_status text default '',p_category text default '',p_offset integer default 0,p_limit integer default 30) returns jsonb language plpgsql security definer set search_path=public as $$
declare result jsonb;
begin
 if not has_permission('coverage.read') then raise exception 'Sem permissão para consultar catálogos';end if;
 if p_source not in ('sigma','atomic') or p_source is null or p_offset<0 or p_offset>100000 or p_limit not between 1 and 100 or length(p_query)>200 then raise exception 'Filtro inválido';end if;
 with filtered as (select * from reference_rules where source=p_source and active
  and (p_query='' or position(lower(p_query) in lower(title||' '||description||' '||array_to_string(tags,' ')||' '||logsource::text||' '||array_to_string(techniques,' ')))>0)
  and (p_level='' or level=p_level) and (p_status='' or status=p_status) and (p_category='' or category=p_category or (p_source='atomic' and logsource->'platforms' ? p_category))),
 items as (select source,id,title,left(description,240) description,level,status,category,logsource,tags,techniques,sha256,path from filtered order by title,id offset p_offset limit p_limit)
 select jsonb_build_object('total',(select count(*) from filtered),'items',coalesce((select jsonb_agg(to_jsonb(items)) from items),'[]'::jsonb),
 'facets',jsonb_build_object('levels',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct level v from reference_rules where source=p_source and active order by level)a),'statuses',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct status v from reference_rules where source=p_source and active order by status)a),'categories',(select coalesce(jsonb_agg(v),'[]'::jsonb) from(select distinct v from reference_rules r cross join lateral unnest(case when p_source='atomic' then array(select jsonb_array_elements_text(r.logsource->'platforms')) else array[r.category] end) as valueset(v) where r.source=p_source and r.active order by v)a))) into result;
 return result;
end $$;
commit;
