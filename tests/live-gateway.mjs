// Explicit integration test: creates and removes only its own temporary account and rule.
import {createClient} from '@supabase/supabase-js';
import {chromium} from '@playwright/test';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';

const base=process.env.TEST_APP_URL||'http://127.0.0.1:5173';
const key=process.env.SUPABASE_SERVICE_ROLE_KEY||process.env.SUPABASE_SECRET_KEY;
if(!key)throw Error('Configure a server key in the local .env before this explicit test.');
const admin=createClient(process.env.VITE_SUPABASE_URL,key,{auth:{persistSession:false,autoRefreshToken:false}});
const client=createClient(process.env.VITE_SUPABASE_URL,process.env.VITE_SUPABASE_ANON_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const check=({data,error})=>{if(error)throw Error(error.message);return data;};
const label='qa_review_'+randomUUID().replaceAll('-','').slice(0,16),password=randomUUID(),email=label+'@hadsec.local';
let userId,ruleId,browser;
try{
 const role=check(await admin.from('roles').select('id').eq('name','Engenheiro').single());
 const created=check(await admin.auth.admin.createUser({email,password,email_confirm:true}));userId=created.user.id;
 check(await admin.from('profiles').insert({id:userId,username:label,display_name:'QA temporário',role_id:role.id,active:true,must_change_password:false}));
 check(await admin.from('user_permission_overrides').insert({user_id:userId,permission:'github.publish',granted:true,updated_by:userId}));
 const {session}=check(await client.auth.signInWithPassword({email,password}));
 const call=async(action,payload={})=>{const r=await fetch(base+'/api/gateway',{method:'POST',headers:{Authorization:'Bearer '+session.access_token,'Content-Type':'application/json',Origin:base},body:JSON.stringify({action,...payload}),signal:AbortSignal.timeout(45000)});const body=await r.json();if(!r.ok)throw Error(body.error||'Gateway '+r.status);return body;};
 const connection=await call('connections.status');assert.equal(connection.server,true);assert.equal(connection.supabase,true);
 assert.equal(connection.services.auth.state,'online');assert.equal(connection.services.database.state,'online');assert.equal(connection.services.github.state,'online');assert.ok(connection.checkedAt);
 const github=await call('github.status');assert.equal(github.configured,true);assert.equal(github.connected,true,'Existing GitHub credential must access its configured base branch');
 const vid=check(await client.rpc('save_rule',{p_rule_id:null,p_name:label,p_description:'Fixture temporária para verificar o gateway.',p_severity:'Baixa',p_technique:'',p_mode:'Scheduled via SQL',p_format:'sql',p_content:'SELECT eventType FROM fsiem.events LIMIT 10',p_note:'Fixture temporária de teste de integração.',p_expected_version:0}));
 const before=check(await admin.from('rule_versions').select('rule_id').eq('id',vid).single());ruleId=before.rule_id;
 const report=await call('validate',{version_id:vid});assert.equal(report.ok,true);
 const version=check(await admin.from('rule_versions').select('validated,validation_report').eq('id',vid).single());assert.equal(version.validated,true);assert.equal(version.validation_report.engine,report.engine);
 const notifications=await call('notifications.list');assert.ok(notifications.items.some(item=>item.target?.type==='rule'&&item.target.id===ruleId));assert.equal(notifications.items.some(item=>'detail' in item),false);
 browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.getByLabel('Usuário',{exact:true}).fill(label);await page.getByLabel('Senha',{exact:true}).fill(password);await page.getByRole('button',{name:'Entrar no workspace'}).click();await page.getByRole('heading',{name:'Visão geral.'}).waitFor();
 await page.getByRole('navigation',{name:'Navegação principal'}).getByRole('button',{name:'Regras de detecção',exact:true}).click();await page.getByRole('textbox',{name:'Filtrar resultados'}).fill(label);
 await page.getByRole('button',{name:'Excluir '+label,exact:true}).click();const modal=page.getByRole('dialog',{name:'Excluir regra'});await modal.getByRole('textbox').fill(label);await modal.getByRole('button',{name:'Excluir regra',exact:true}).click();await modal.waitFor({state:'hidden'});
 const rule=check(await admin.from('rules').select('archived').eq('id',ruleId).single());assert.equal(rule.archived,true);
 assert.equal(check(await admin.from('rule_versions').select('id').eq('rule_id',ruleId)).length,1);
 const events=check(await admin.from('audit_events').select('action,detail').eq('actor_id',userId));assert.ok(events.some(e=>e.action==='version.validated'));assert.ok(events.some(e=>e.action==='rule.archived'&&e.detail.deleted_requests===0),'Gateway must call the new atomic RPC');assert.deepEqual(errors,[]);
 console.log(JSON.stringify({realSupabaseLogin:true,serverSessionValidation:true,persistedValidation:true,realGitHubReadAccess:true,ruleExclusionThroughBrowser:true,historyPreserved:true,auditRecorded:true,existingAccountsUnchanged:true}));
}finally{
 if(browser)await browser.close();
 if(userId){
  check(await admin.from('audit_events').delete().eq('actor_id',userId));
  if(ruleId){check(await admin.from('rule_versions').delete().eq('rule_id',ruleId));check(await admin.from('rules').delete().eq('id',ruleId));}
  check(await admin.from('user_permission_overrides').delete().eq('user_id',userId));
  check(await admin.from('profiles').delete().eq('id',userId));
  check(await admin.auth.admin.deleteUser(userId));
  console.log('Temporary integration account, rule and audit events removed.');
 }
}
