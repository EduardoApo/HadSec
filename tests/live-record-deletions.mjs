// Explicit integration test. Fixtures and audit entries exist only inside a rolled-back transaction.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {createClient} from '@supabase/supabase-js';

const url=process.env.SUPABASE_URL,token=process.env.SUPABASE_ACCESS_TOKEN;
if(!url||!token)throw Error('Supabase management configuration required.');
async function query(sql){
 const response=await fetch(`https://api.supabase.com/v1/projects/${new URL(url).hostname.split('.')[0]}/database/query`,{
  method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({query:sql}),signal:AbortSignal.timeout(20000)
 });
 const body=await response.json();if(!response.ok)throw Error('Database verification failed: '+JSON.stringify(body));return body;
}
const [state]=await query(`select o.user_id,p.username,p.active,
 exists(select 1 from public.hadsec_schema_migrations where version='202611060008') as migrated
 from public.workspace_owner o join public.profiles p on p.id=o.user_id`);
assert.equal(state.username,'Admin');assert.equal(state.active,true);assert.equal(state.migrated,true);
const request=randomUUID(),sent=randomUUID(),other=randomUUID(),rule=randomUUID(),version=randomUUID(),linked=randomUUID();
// All UUIDs come from randomUUID() or the verified owner row; no user input is interpolated.
await query(`begin;
 insert into auth.users(id) values('${other}');
 insert into public.profiles(id,username,display_name,role_id,must_change_password)
 select '${other}','qa_delete_${other.slice(0,8)}','Temporary deletion authorization fixture',id,false from public.roles where name='Administrador' and system;
 insert into public.change_requests(id,title,description,created_by,status,github_url,exported_sha)
 values('${request}','QA request deletion','Transactional fixture, always rolled back','${other}','requested',null,null),
 ('${sent}','QA submission deletion','Transactional fixture, no real GitHub request','${other}','published','https://github.com/example/rules/pull/42','unchanged-sha');
 insert into public.rules(id,name,description,severity,mode,format,created_by)
 values('${rule}','QA linked deletion','Transactional fixture','Baixa','Scheduled via SQL','sql','${other}');
 insert into public.rule_versions(id,rule_id,number,content,change_note,created_by,content_sha256,validated)
 values('${version}','${rule}',1,'SELECT eventType FROM fsiem.events','Transactional fixture','${other}',repeat('a',64),true);
 insert into public.change_requests(id,rule_id,version_id,title,description,created_by,status,github_url)
 values('${linked}','${rule}','${version}','QA linked submission','Transactional fixture','${other}','published','https://github.com/example/rules/pull/43');
 select set_config('request.jwt.claim.sub','${other}',true);
 set local role authenticated;
 do $$begin
  if (public.record_capabilities()->>'owner')::boolean then raise exception 'Another administrator received ownership'; end if;
  begin perform public.delete_request('${request}','QA request deletion');raise exception 'Non-owner deleted request';
  exception when others then if sqlerrm not like 'Somente o proprietário%' then raise; end if;end;
  begin perform public.hide_github_submission('${sent}','QA submission deletion');raise exception 'Non-owner deleted submission';
  exception when others then if sqlerrm not like 'Somente o proprietário%' then raise; end if;end;
  begin perform public.archive_rule('${rule}','QA linked deletion');raise exception 'Non-owner deleted linked rule';
  exception when others then if sqlerrm not like 'Somente o proprietário%' then raise; end if;end;
 end$$;
 reset role;
 select set_config('request.jwt.claim.sub','${state.user_id}',true);
 set local role authenticated;
 do $$begin
  if not (public.record_capabilities()->>'owner')::boolean then raise exception 'HadSec owner capability missing'; end if;
  perform public.delete_request('${request}','QA request deletion');
  perform public.hide_github_submission('${sent}','QA submission deletion');
  if not exists(select 1 from public.change_requests where id='${request}' and deleted_at is not null and deleted_by='${state.user_id}') then raise exception 'Request deletion failed';end if;
  if not exists(select 1 from public.change_requests where id='${sent}' and github_hidden_at is not null and github_hidden_by='${state.user_id}' and deleted_at is null and status='published' and exported_sha='unchanged-sha' and github_url='https://github.com/example/rules/pull/42') then raise exception 'Submission preservation failed';end if;
  if (select count(*) from public.audit_events where entity_id in ('${request}','${sent}') and action in ('request.deleted','github.submission_hidden') and actor_id='${state.user_id}')<>2 then raise exception 'Audit verification failed';end if;
  begin perform public.add_comment('${request}','Stale tab comment');raise exception 'Deleted request accepted comment';
  exception when others then if sqlerrm not like '%indisponível%' then raise;end if;end;
  perform public.archive_rule('${rule}','QA linked deletion');
  if not exists(select 1 from public.rules where id='${rule}' and archived) then raise exception 'Linked rule exclusion failed';end if;
  if not exists(select 1 from public.change_requests where id='${linked}' and deleted_by='${state.user_id}' and github_hidden_at is not null and status='published' and github_url='https://github.com/example/rules/pull/43') then raise exception 'Linked submission not preserved';end if;
  if not exists(select 1 from public.rule_versions where id='${version}' and content='SELECT eventType FROM fsiem.events') then raise exception 'Historical version missing';end if;
  begin perform public.create_request('QA stale tab','Must reject a removed rule','${rule}',null);raise exception 'Archived rule accepted new request';
  exception when others then if sqlerrm not like '%excluída%' then raise;end if;end;
 end$$;
 reset role;
 rollback;`);
const [cleanup]=await query(`select
 (select count(*) from public.change_requests where id in ('${request}','${sent}','${linked}')) as requests,
 (select count(*) from public.audit_events where entity_id in ('${request}','${sent}','${linked}','${rule}')) as events,
 (select count(*) from public.rules where id='${rule}') as rules,
 (select count(*) from public.profiles where id='${other}') as profiles`);
assert.equal(cleanup.requests,0);assert.equal(cleanup.events,0);assert.equal(cleanup.profiles,0);assert.equal(cleanup.rules,0);
// Check the public HTTP RPC route also rejects anonymous callers.
const publicKey=process.env.SUPABASE_ANON_KEY||process.env.VITE_SUPABASE_ANON_KEY;
const anonymous=createClient(url,publicKey,{auth:{persistSession:false,autoRefreshToken:false}});
for(const name of ['delete_request','hide_github_submission']){
 const result=await anonymous.rpc(name,{p_request:request,p_confirmation:'QA request deletion'});assert.ok(result.error,'Anonymous mutation must be denied');
}
console.log(JSON.stringify({realSupabase:true,ownerIdentityPinned:true,ownerRequestDeletion:true,ownerSubmissionDeletion:true,linkedRuleDeletion:true,staleRequestBlocked:true,otherAdministratorDenied:true,anonymousDenied:true,githubRecordsPreserved:true,auditVerified:true,fixturesRolledBack:true,existingRecordsUnchanged:true}));
