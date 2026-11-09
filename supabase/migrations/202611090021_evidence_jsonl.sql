begin;
create or replace function public.begin_operational_evidence(p_subject uuid,p_name text,p_size integer,p_mime text,p_sha256 text) returns public.operational_evidence language plpgsql security definer set search_path=public as $$
declare row operational_evidence;fid uuid=gen_random_uuid();ext text;
begin
 if not can_write_subject(p_subject) or not can_read_subject(p_subject) then raise exception 'Sem permissão para anexar evidências neste registro';end if;
 perform id from operational_subjects where id=p_subject for update;
 if (select count(*) from operational_evidence where subject_id=p_subject)>=50 or (select coalesce(sum(size_bytes),0) from operational_evidence where subject_id=p_subject)+p_size>100000000 then raise exception 'O registro atingiu o limite de 50 arquivos ou 100 MB';end if;
 if p_name is null or p_name~'[[:cntrl:]/\\]' or lower(p_name)!~'\.(png|jpe?g|pdf|json|jsonl|ndjson|csv|txt|log)$' then raise exception 'Formato de evidência não permitido';end if;
 ext=lower(substring(p_name from '\.([^.]+)$'));
 insert into operational_evidence(id,subject_id,original_name,size_bytes,mime,sha256,storage_path,created_by)
 values(fid,p_subject,p_name,p_size,p_mime,p_sha256,p_subject::text||'/'||fid::text||'.'||ext,auth.uid()) returning * into row;
 perform audit('evidence.upload_started',fid::text,jsonb_build_object('subject_id',p_subject,'size',p_size,'sha256',p_sha256));return row;
end $$;
commit;
