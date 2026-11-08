// Explicit temporary integration fixtures. No original account, rule, PR or request is changed.
import {createClient} from '@supabase/supabase-js';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
import {formats} from '../supabase/functions/_shared/formats.mjs';
const base=process.env.TEST_APP_URL||'http://127.0.0.1:4173',url=process.env.SUPABASE_URL;
const service=createClient(url,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const check=({data,error})=>{if(error)throw Error(error.message);return data;};
const accounts=[],requests=[],rules=new Set(),suffix=randomUUID().replaceAll('-','').slice(0,12);
async function account(roleName,label){
 const role=check(await service.from('roles').select('id').eq('name',roleName).single());
 const username='qa_formats_'+label+'_'+suffix,password=randomUUID(),email=username+'@hadsec.local';
 const id=check(await service.auth.admin.createUser({email,password,email_confirm:true})).user.id;accounts.push(id);
 check(await service.from('profiles').insert({id,username,display_name:'QA temporário '+label,role_id:role.id,must_change_password:false}));
 const client=createClient(url,process.env.VITE_SUPABASE_ANON_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
 const {session}=check(await client.auth.signInWithPassword({email,password}));return {id,client,token:session.access_token};
}
try{
 const requester=await account('Leitor','requester'),engineer=await account('Engenheiro','engineer');
 const creation=check(await requester.client.rpc('submit_change_request',{p_kind:'create',p_title:'QA nova regra '+suffix,p_description:'Fixture temporária de criação de regra.',p_format:'kusto',p_mode:'Native'}));requests.push(creation);
 assert.equal(check(await requester.client.from('change_requests').select('request_kind').eq('id',creation).single()).request_kind,'create');
 const verified=[];
 for(const format of formats.filter(f=>['sigma','kusto','yara'].includes(f.id))){
  const original=format.sample,request=check(await requester.client.rpc('submit_change_request',{p_kind:'change',p_title:'QA original '+format.id+' '+suffix,p_description:'Fixture temporária de preservação de regra original.',p_format:format.id,p_mode:format.mode,p_baseline_content:original}));requests.push(request);
  const row=check(await requester.client.from('change_requests').select('*').eq('id',request).single());rules.add(row.rule_id);
  const baseline=check(await requester.client.from('rule_versions').select('*').eq('id',row.baseline_version_id).single());assert.equal(baseline.content,original);assert.equal(baseline.number,1);
  const blocked=await requester.client.rpc('save_rule',{p_rule_id:row.rule_id,p_name:'Blocked',p_description:'Blocked',p_severity:'Baixa',p_technique:'',p_mode:format.mode,p_format:format.id,p_content:original,p_note:'Blocked',p_expected_version:1});assert.ok(blocked.error);
  const version=check(await engineer.client.rpc('save_rule',{p_rule_id:row.rule_id,p_name:'QA',p_description:'Fixture temporária',p_severity:'Baixa',p_technique:'',p_mode:format.mode,p_format:format.id,p_content:original.replace('malware.exe','changed.exe'),p_note:'Alteração temporária para testar a revisão.',p_expected_version:1}));
  const response=await fetch(base+'/api/gateway',{method:'POST',headers:{Authorization:'Bearer '+engineer.token,'Content-Type':'application/json'},body:JSON.stringify({action:'validate',version_id:version}),signal:AbortSignal.timeout(30000)});const report=await response.json();assert.equal(response.status,200,JSON.stringify(report));assert.equal(report.ok,true);assert.equal(report.format,format.id);
  check(await engineer.client.rpc('attach_version',{p_request:request,p_version:version}));
  const attached=check(await requester.client.from('change_requests').select('*').eq('id',request).single());assert.equal(attached.baseline_version_id,baseline.id);assert.equal(attached.version_id,version);assert.equal(attached.status,'review');
  assert.equal(check(await requester.client.from('rule_versions').select('content').eq('id',baseline.id).single()).content,original);
  const validated=check(await requester.client.from('rule_versions').select('validation_report').eq('id',version).single());assert.equal(validated.validation_report.engine,'hadsec-multiformat-1');verified.push(format.id);
 }
 console.log(JSON.stringify({realSupabase:true,createIntake:true,changeIntake:true,baselineImmutable:true,requesterCannotAuthorVersions:true,gatewayFormatsValidated:verified,revisionAttached:true,noExistingAccountsChanged:true,noGithubWrites:true}));
}finally{
 if(requests.length){check(await service.from('comments').delete().in('request_id',requests));check(await service.from('change_requests').delete().in('id',requests));}
 for(const id of rules){const versions=check(await service.from('rule_versions').select('id').eq('rule_id',id)).map(v=>v.id);if(versions.length)check(await service.from('test_evidence').delete().in('version_id',versions));check(await service.from('rule_versions').delete().eq('rule_id',id));check(await service.from('rules').delete().eq('id',id));}
 if(accounts.length){check(await service.from('audit_events').delete().in('actor_id',accounts));check(await service.from('user_permission_overrides').delete().in('user_id',accounts));check(await service.from('profiles').delete().in('id',accounts));for(const id of accounts)check(await service.auth.admin.deleteUser(id));}
 console.log('Temporary multiformat accounts, originals, revisions, requests and audit events removed.');
}
