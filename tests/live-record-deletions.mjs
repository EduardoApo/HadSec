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
 exists(select 1 from public.hadsec_schema_migrations where version='202611060007') as migrated
 from public.workspace_owner o join public.profiles p on p.id=o.user_id`);
assert.equal(state.username,'HadSec');assert.equal(state.active,true);assert.equal(state.migrated,true);
const request=randomUUID(),sent=randomUUID(),other=randomUUID();
// All UUIDs come from randomUUID() or the verified owner row; no user input is interpolated.
await query(`begin;
 insert into auth.users(id) values('${other}');
 insert into public.profiles(id,username,display_name,role_id,must_change_password)
 select '${other}','qa_delete_${other.slice(0,8)}','Temporary deletion authorization fixture',id,false from public.roles where name='Administrador' and system;
 insert into public.change_requests(id,title,description,created_by,status,github_url,exported_sha)
 values('${request}','QA request deletion','Transactional fixture, always rolled back','${other}','requested',null,null),
 ('${sent}','QA submission deletion','Transactional fixture, no real GitHub request','${other}','published','https://github.com/example/rules/pull/42','unchanged-sha');
 select set_config('request.jwt.claim.sub','${other}',true);
 set local role authenticated;
 do $$begin
  if (public.record_capabilities()->>'owner')::boolean then raise exception 'Another administrator received ownership'; end if;
  begin perform public.delete_request('${request}','QA request deletion');raise exception 'Non-owner deleted request';
  exception when others then if sqlerrm not like 'Somente o proprietário%' then raise; end if;end;
  begin perform public.hide_github_submission('${sent}','QA submission deletion');raise exception 'Non-owner deleted submission';
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
 end$$;
 reset role;
 rollback;`);
const [cleanup]=await query(`select
 (select count(*) from public.change_requests where id in ('${request}','${sent}')) as requests,
 (select count(*) from public.audit_events where entity_id in ('${request}','${sent}')) as events,
 (select count(*) from public.profiles where id='${other}') as profiles`);
assert.equal(cleanup.requests,0);assert.equal(cleanup.events,0);assert.equal(cleanup.profiles,0);
// Check the public HTTP RPC route also rejects anonymous callers.
const publicKey=process.env.SUPABASE_ANON_KEY||process.env.VITE_SUPABASE_ANON_KEY;
const anonymous=createClient(url,publicKey,{auth:{persistSession:false,autoRefreshToken:false}});
for(const name of ['delete_request','hide_github_submission']){
 const result=await anonymous.rpc(name,{p_request:request,p_confirmation:'QA request deletion'});assert.ok(result.error,'Anonymous mutation must be denied');
}
console.log(JSON.stringify({realSupabase:true,ownerIdentityPinned:true,ownerRequestDeletion:true,ownerSubmissionDeletion:true,otherAdministratorDenied:true,anonymousDenied:true,githubRecordsPreserved:true,auditVerified:true,fixturesRolledBack:true,existingRecordsUnchanged:true}));
