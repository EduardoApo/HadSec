// Explicit, isolated integration fixtures. No existing account or request is changed.
import {createClient} from '@supabase/supabase-js';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
import {createGateway} from '../server/gateway.mjs';

const url=process.env.SUPABASE_URL||process.env.VITE_SUPABASE_URL,serviceKey=process.env.SUPABASE_SERVICE_ROLE_KEY||process.env.SUPABASE_SECRET_KEY;
const publicKey=process.env.SUPABASE_ANON_KEY||process.env.VITE_SUPABASE_ANON_KEY;
if(!url||!serviceKey||!publicKey)throw Error('Server configuration required for explicit integration test.');
const service=createClient(url,serviceKey,{auth:{persistSession:false,autoRefreshToken:false}}),handler=createGateway({env:process.env});
const check=({data,error})=>{if(error)throw Error(error.message);return data;};
const suffix=randomUUID().replaceAll('-','').slice(0,14),accounts=[];let ruleId;
async function account(roleName,label){
 const role=check(await service.from('roles').select('id').eq('name',roleName).eq('system',true).single());
 const username='qa_'+label+'_'+suffix,password=randomUUID(),email=username+'@hadsec.local';
 const created=check(await service.auth.admin.createUser({email,password,email_confirm:true}));const id=created.user.id;accounts.push(id);
 check(await service.from('profiles').insert({id,username,display_name:'QA temporário '+label,role_id:role.id,active:true,must_change_password:false}));
 const client=createClient(url,publicKey,{auth:{persistSession:false,autoRefreshToken:false}});const {session}=check(await client.auth.signInWithPassword({email,password}));return {id,client,token:session.access_token};
}
try{
 const administrator=await account('Administrador','admin'),reviewer=await account('Revisor','reviewer');let lastVersion;
 for(const [index,decision]of ['approved','changes','rejected'].entries()){
  const version=check(await administrator.client.rpc('save_rule',{p_rule_id:ruleId||null,p_name:'QA decisão administrativa '+suffix,p_description:'Fixture temporária de autorização administrativa.',p_severity:'Baixa',p_technique:'',p_mode:'Scheduled via SQL',p_format:'sql',p_content:'SELECT eventType FROM fsiem.events LIMIT 10',p_note:'Fixture temporária '+decision,p_expected_version:index}));lastVersion=version;
  ruleId=check(await service.from('rule_versions').select('rule_id').eq('id',version).single()).rule_id;
  const response=await handler(new Request('http://127.0.0.1/api/gateway',{method:'POST',headers:{Authorization:'Bearer '+administrator.token,'Content-Type':'application/json'},body:JSON.stringify({action:'validate',version_id:version})}));assert.equal(response.status,200);assert.equal((await response.json()).ok,true);
  const request=check(await administrator.client.rpc('create_request',{p_title:'QA decisão '+decision+' '+suffix,p_description:'Solicitação temporária para verificar a decisão própria do administrador.',p_rule_id:ruleId,p_version_id:version}));
  if(decision==='approved'){
   const blocked=await administrator.client.rpc('decide_request',{p_request:request,p_decision:decision,p_note:'Teste temporário sem evidência.'});assert.match(blocked.error?.message||'',/teste aprovado/);
   check(await administrator.client.rpc('record_evidence',{p_version:version,p_method:'FortiSIEM SQL',p_result:'pass',p_notes:'FIXTURE SINTÉTICA TEMPORÁRIA: usada apenas para testar o controle de autorização. Não representa execução real no FortiSIEM e será removida ao final.'}));
  }
  check(await administrator.client.rpc('decide_request',{p_request:request,p_decision:decision,p_note:'Decisão administrativa temporária de teste: '+decision}));
  const row=check(await service.from('change_requests').select('status,reviewed_by').eq('id',request).single());assert.equal(row.status,decision);assert.equal(row.reviewed_by,administrator.id);
  const events=check(await service.from('audit_events').select('detail').eq('entity_id',request).eq('action','request.'+decision));assert.equal(events[0].detail.administrator_self_decision,true);
 }
 const ownRequest=check(await reviewer.client.rpc('create_request',{p_title:'QA revisor comum '+suffix,p_description:'Verifica que o perfil comum permanece impedido de decidir sua própria solicitação.',p_rule_id:ruleId,p_version_id:lastVersion}));
 for(const decision of ['approved','changes','rejected']){const result=await reviewer.client.rpc('decide_request',{p_request:ownRequest,p_decision:decision,p_note:'Tentativa própria do revisor comum.'});assert.match(result.error?.message||'',/outro revisor/);}
 console.log(JSON.stringify({realDatabase:true,administratorDecisions:['approved','changes','rejected'],secondReviewerNotRequired:true,auditVerified:true,approvalEvidenceStillRequired:true,ordinaryReviewerBlockedForAllThree:true,existingAccountsAndRequestsPreserved:true}));
}finally{
 if(accounts.length){
  const rules=check(await service.from('rules').select('id').eq('created_by',accounts[0]));
  for(const rule of rules){const versions=check(await service.from('rule_versions').select('id').eq('rule_id',rule.id));const ids=versions.map(v=>v.id);const requests=check(await service.from('change_requests').select('id').eq('rule_id',rule.id));if(requests.length)check(await service.from('comments').delete().in('request_id',requests.map(r=>r.id)));check(await service.from('change_requests').delete().eq('rule_id',rule.id));if(ids.length)check(await service.from('test_evidence').delete().in('version_id',ids));check(await service.from('rule_versions').delete().eq('rule_id',rule.id));check(await service.from('rules').delete().eq('id',rule.id));}
  check(await service.from('audit_events').delete().in('actor_id',accounts));check(await service.from('user_permission_overrides').delete().in('user_id',accounts));check(await service.from('profiles').delete().in('id',accounts));for(const id of accounts)check(await service.auth.admin.deleteUser(id));
  console.log('Temporary accounts, rules, requests, synthetic evidence and audit events removed.');
 }
}
