// Test-only service fixtures. The application itself always requires Supabase login.
import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {validateRule} from '../supabase/functions/_shared/validator.mjs';
import {sampleSQL} from '../src/rule-templates.js';

const base='http://127.0.0.1:5173',date='2026-11-06T12:30:00Z';
const admin='00000000-0000-4000-8000-000000000001',reader='00000000-0000-4000-8000-000000000002';
const draftId='00000000-0000-4000-8000-000000000003',versionId='00000000-0000-4000-8000-000000000004',requestId='00000000-0000-4000-8000-000000000005';
const data={
 roles:[{id:'admin-role',name:'Administrador',system:true,permissions:['rules.write','requests.create','requests.review','tests.record','github.publish','users.manage','roles.manage','audit.read']}],
 profiles:[{id:admin,username:'HadSec',display_name:'HadSec',active:true,role_id:'admin-role',must_change_password:false},{id:reader,username:'analista',display_name:'João Analista',active:true,role_id:'admin-role',must_change_password:false}],
 rules:[{id:draftId,name:'Detecção temporária',description:'Regra criada para testar a exclusão.',format:'sql',mode:'Scheduled via SQL',severity:'Alta',technique:'T1110',created_by:admin,created_at:date,archived:false}],
 rule_versions:[{id:versionId,rule_id:draftId,number:1,content:sampleSQL,change_note:'Primeira versão',created_by:admin,created_at:date,validated:false,validation_report:null,content_sha256:'a'.repeat(64)}],
 change_requests:[{id:requestId,title:'Investigar autenticação incomum',description:'Criar uma regra para investigar tentativas de autenticação fora do padrão.',status:'requested',created_by:reader,created_at:date,updated_at:date,rule_id:null,version_id:null}],
 test_evidence:[],comments:[],audit_events:[{id:1,actor_id:reader,action:'request.created',entity_id:requestId,created_at:date,detail:{}}],permission_definitions:[],user_permission_overrides:[]
};
let githubFailure=false,validationFailure=false;
const calls=[];
const browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
await mkdir('artifacts/review',{recursive:true});
try{
 const login=await browser.newPage({viewport:{width:1440,height:1000}});
 await login.goto(base);await login.getByLabel('Usuário',{exact:true}).waitFor();
 assert.equal(await login.locator('.login-card img').count(),0);assert.equal(await login.locator('.login-brand img').count(),1);
 await login.screenshot({path:'artifacts/review/login-desktop.png',fullPage:true});
 await login.setViewportSize({width:390,height:844});await login.screenshot({path:'artifacts/review/login-mobile.png',fullPage:true});await login.close();
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const expires=Math.floor(Date.now()/1000)+3600;
 const token=[btoa(JSON.stringify({alg:'HS256',typ:'JWT'})),btoa(JSON.stringify({sub:admin,role:'authenticated',exp:expires})),'fixture-signature'].join('.');
 await context.addInitScript(({token,expires,admin})=>localStorage.setItem('sb-nsigspmrqqfpcihmixer-auth-token',JSON.stringify({access_token:token,refresh_token:'fixture-refresh',token_type:'bearer',expires_in:3600,expires_at:expires,user:{id:admin,email:'hadsec@hadsec.local',aud:'authenticated',role:'authenticated',app_metadata:{provider:'email'},user_metadata:{},created_at:'2026-11-06T12:00:00Z'}})),{token,expires,admin});
 const respond=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',headers:{'Access-Control-Allow-Origin':'*'},body:JSON.stringify(body)});
 const audit=(action,entity)=>data.audit_events.push({id:data.audit_events.length+1,actor_id:admin,action,entity_id:entity,created_at:date,detail:{}});
 await context.route('https://nsigspmrqqfpcihmixer.supabase.co/**',async route=>{
  const req=route.request(),url=new URL(req.url());calls.push(url.pathname);
  if(url.pathname.startsWith('/auth/v1/'))return respond(route,{user:{id:admin,email:'hadsec@hadsec.local'}});
  const name=url.pathname.split('/').at(-1);
  if(url.pathname.includes('/rpc/')){
   const p=req.postDataJSON();
   if(name==='save_rule'){
    const rid=p.p_rule_id||randomUUID(),vid=randomUUID();
    if(!p.p_rule_id)data.rules.push({id:rid,name:p.p_name,description:p.p_description,severity:p.p_severity,technique:p.p_technique,format:p.p_format,mode:p.p_mode,created_by:admin,created_at:date,archived:false});
    data.rule_versions.push({id:vid,rule_id:rid,number:p.p_expected_version+1,content:p.p_content,change_note:p.p_note,created_by:admin,created_at:date,validated:false,validation_report:null,content_sha256:'b'.repeat(64)});audit('version.created',vid);return respond(route,vid);
   }
   if(name==='attach_version'){const q=data.change_requests.find(q=>q.id===p.p_request),v=data.rule_versions.find(v=>v.id===p.p_version);assert.equal(v.validated,true);Object.assign(q,{rule_id:v.rule_id,version_id:v.id,status:'review'});audit('request.version_attached',q.id);return respond(route,null);}
   throw Error('Unexpected RPC '+name);
  }
  assert.ok(name in data,'Unexpected table '+name);return respond(route,data[name]);
 });
 await context.route('**/api/gateway',async route=>{
  const p=route.request().postDataJSON();calls.push('gateway:'+p.action);
  if(p.action==='validate'){
   if(validationFailure)return respond(route,{error:'Serviço temporariamente indisponível.'},503);
   const v=data.rule_versions.find(v=>v.id===p.version_id),r=data.rules.find(r=>r.id===v.rule_id),report=validateRule(v.content,r.format,r.mode);Object.assign(v,{validated:report.ok,validation_report:report});audit('version.validated',v.id);return respond(route,report);
  }
  if(p.action==='rule.archive'){const r=data.rules.find(r=>r.id===p.rule_id);assert.equal(p.confirmation,r.name);r.archived=true;audit('rule.archived',r.id);return respond(route,{ok:true});}
  if(p.action==='connections.status')return respond(route,{server:true,supabase:true,github:true,repository:'HadSec/regras'});
  if(p.action==='github.status')return githubFailure?respond(route,{error:'Não foi possível conectar ao serviço.'},503):respond(route,{configured:true,connected:true,repository:'HadSec/regras',branch:'main'});
  throw Error('Unexpected gateway action '+p.action);
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.getByRole('heading',{name:'Visão geral.'}).waitFor();
 assert.equal(await page.locator('.sidebar-compact').count(),1);
 assert.equal(await page.locator('.workspace,.version-card,.global-search').count(),0);
 assert.equal(await page.getByLabel('Buscar regras',{exact:true}).count(),0);
 await page.getByRole('button',{name:/^Notificações/}).click();await page.getByRole('dialog',{name:'Novas solicitações'}).waitFor();
 await page.getByRole('dialog',{name:'Novas solicitações'}).getByRole('button',{name:/Investigar autenticação/}).click();
 await page.getByRole('dialog',{name:'Revisar solicitação'}).waitFor();assert.equal(new URL(page.url()).hash,'#requests');
 await page.screenshot({path:'artifacts/review/request-flow.png',fullPage:true});
 await page.getByRole('button',{name:'Criar regra',exact:true}).click();
 await page.getByRole('dialog',{name:'Nova regra de detecção'}).waitFor();
 assert.equal(await page.getByLabel('Nome da regra',{exact:true}).inputValue(),data.change_requests[0].title);
 assert.equal(await page.getByLabel('Objetivo da detecção',{exact:true}).inputValue(),data.change_requests[0].description);
 await page.getByLabel('O que mudou nesta versão?',{exact:true}).fill('Detecção criada a partir da solicitação recebida.');
 await page.getByRole('button',{name:'Salvar, validar e enviar'}).click();
 await page.getByRole('heading',{name:'Investigar autenticação incomum.'}).waitFor();
 assert.equal(data.change_requests[0].status,'review');assert.ok(data.change_requests[0].version_id);assert.equal(data.rule_versions.find(v=>v.id===data.change_requests[0].version_id).validated,true);
 await page.screenshot({path:'artifacts/review/rule-editor.png',fullPage:true});
 const nav=page.getByRole('navigation',{name:'Navegação principal'});
 // A transport failure after saving must not leave a form that resubmits v1.
 await nav.getByRole('button',{name:'Regras de detecção',exact:true}).click();
 await page.getByRole('button',{name:'Nova regra',exact:true}).click();
 await page.getByLabel('Nome da regra',{exact:true}).fill('Rascunho salvo com falha de conexão');
 await page.getByLabel('Objetivo da detecção',{exact:true}).fill('Verificar que a versão salva não será duplicada.');
 await page.getByLabel('O que mudou nesta versão?',{exact:true}).fill('Primeira versão para verificar a recuperação.');
 const beforeSave=data.rule_versions.length;validationFailure=true;
 await page.getByRole('button',{name:'Salvar e validar',exact:true}).click();
 await page.getByRole('heading',{name:'Rascunho salvo com falha de conexão.'}).waitFor();
 assert.equal(data.rule_versions.length,beforeSave+1);assert.equal(await page.getByRole('dialog').count(),0);
 validationFailure=false;await page.getByRole('button',{name:'Validar versão',exact:true}).click();await page.getByText('Verificações estáticas concluídas',{exact:true}).waitFor();assert.equal(data.rule_versions.length,beforeSave+1);
 await nav.getByRole('button',{name:'Regras de detecção',exact:true}).click();
 await page.getByRole('button',{name:'Excluir Detecção temporária',exact:true}).click();
 const dialog=page.getByRole('dialog',{name:'Excluir regra'});await dialog.waitFor();assert.equal(await dialog.getByRole('button',{name:'Excluir regra',exact:true}).isDisabled(),true);
 await dialog.getByRole('textbox').fill('Detecção temporária');await dialog.getByRole('button',{name:'Excluir regra',exact:true}).click();await dialog.waitFor({state:'hidden'});
 assert.equal(await page.getByRole('button',{name:'Excluir Detecção temporária',exact:true}).count(),0);assert.equal(data.rule_versions.some(v=>v.rule_id===draftId),true);
 if(await page.getByRole('button',{name:'Fechar aviso',exact:true}).count())await page.getByRole('button',{name:'Fechar aviso',exact:true}).click();
 await page.screenshot({path:'artifacts/review/rules-desktop.png',fullPage:true});
 await nav.getByRole('button',{name:'GitHub',exact:true}).click();await page.getByText('Conectado',{exact:true}).waitFor();assert.equal(await page.getByRole('alert').count(),0);
 githubFailure=true;await page.getByRole('button',{name:'Verificar conexão'}).click();await page.getByRole('alert').waitFor();githubFailure=false;await page.getByRole('button',{name:'Tentar novamente'}).click();await page.getByText('Conectado',{exact:true}).waitFor();
 await nav.getByRole('button',{name:'Auditoria',exact:true}).click();const search=page.getByRole('searchbox',{name:'Pesquisar auditoria'});await search.fill('joao solicitacao 2026-11-06');assert.equal(await page.locator('tbody tr').count(),1);await search.fill('temporaria');assert.equal(await page.locator('tbody tr').count(),1);await search.fill('sem-resultados');assert.equal(await page.locator('tbody tr').count(),0);await page.getByRole('button',{name:'Limpar pesquisa de auditoria'}).click();await page.screenshot({path:'artifacts/review/audit-desktop.png',fullPage:true});
 await page.getByRole('button',{name:'Abrir menu da conta'}).click();await page.getByRole('menuitem',{name:'Alterar senha',exact:true}).click();await page.getByRole('tab',{name:/Alterar senha/}).waitFor();assert.equal(await page.getByRole('tab',{name:/Alterar senha/}).getAttribute('aria-selected'),'true');await page.getByLabel('Senha atual',{exact:true}).waitFor();
 await page.getByRole('tab',{name:/Sobre a ferramenta/}).click();await page.getByRole('heading',{name:'HadSec Detect',exact:true}).waitFor();assert.equal(await page.getByLabel('Senha atual',{exact:true}).count(),0);
 await page.getByRole('tab',{name:/Conexões/}).click();await page.getByText('Serviço da aplicação',{exact:true}).waitFor();await page.screenshot({path:'artifacts/review/settings-desktop.png',fullPage:true});
 await page.getByRole('button',{name:/^Notificações/}).click();await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog',{name:'Novas solicitações'}).count(),0);
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'artifacts/review/settings-mobile.png',fullPage:true});
 await page.getByRole('button',{name:/^Notificações/}).click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'artifacts/review/notifications-mobile.png',fullPage:true});
 assert.equal(calls.some(path=>path.includes('/functions/v1/')),false,'No Edge Function requests remain');assert.deepEqual(errors,[]);
 console.log(JSON.stringify({loginOwl:true,cleanSidebar:true,topSearchRemoved:true,notificationNavigation:true,requestToRuleAndReview:true,archiveConfirmation:true,historyPreserved:true,githubStatusAndRetry:true,auditSearch:true,settingsTabs:true,accountMenu:true,mobile:true,noEdgeFunctionRequests:true,pageErrors:errors,screenshots:'artifacts/review/'}));
 await context.close();
}finally{await browser.close();}
