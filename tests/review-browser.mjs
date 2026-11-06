// Test-only service fixtures. The application itself always requires Supabase login.
import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {validateRule} from '../supabase/functions/_shared/validator.mjs';
import {sampleSQL} from '../src/rule-templates.js';
import {buildNotifications} from '../server/notifications.mjs';

const base='http://127.0.0.1:5173',date=new Date(Date.now()-3600000).toISOString();
const admin='00000000-0000-4000-8000-000000000001',reader='00000000-0000-4000-8000-000000000002';
const draftId='00000000-0000-4000-8000-000000000003',versionId='00000000-0000-4000-8000-000000000004',requestId='00000000-0000-4000-8000-000000000005';
const data={
 roles:[{id:'admin-role',name:'Administrador',system:true,permissions:['rules.write','requests.create','requests.review','tests.record','github.publish','users.manage','roles.manage','audit.read']}],
 profiles:[{id:admin,username:'Admin',display_name:'Admin',active:true,role_id:'admin-role',must_change_password:false},{id:reader,username:'analista',display_name:'João Analista',active:true,role_id:'admin-role',must_change_password:false}],
 rules:[{id:draftId,name:'Detecção temporária',description:'Regra criada para testar a exclusão.',format:'sql',mode:'Scheduled via SQL',severity:'Alta',technique:'T1110',created_by:admin,created_at:date,archived:false}],
 rule_versions:[{id:versionId,rule_id:draftId,number:1,content:sampleSQL,change_note:'Primeira versão',created_by:admin,created_at:date,validated:false,validation_report:null,content_sha256:'a'.repeat(64)}],
 change_requests:[{id:requestId,title:'Investigar autenticação incomum',description:'Criar uma regra para investigar tentativas de autenticação fora do padrão.',status:'requested',created_by:reader,created_at:date,updated_at:date,rule_id:null,version_id:null}],
 test_evidence:[],comments:[],audit_events:[{id:1,actor_id:reader,action:'request.created',entity_id:requestId,created_at:date,detail:{}}],permission_definitions:[],user_permission_overrides:[]
};
// Reporting fixtures exist only in intercepted test responses.
for(let day=1;day<42;day++){
 const created_at=new Date(Date.now()-day*86400000).toISOString(),rid=randomUUID();
 data.rules.push({...data.rules[0],id:rid,name:'Correlação de autenticação '+day,severity:['Alta','Média','Baixa','Crítica'][day%4],created_at});
 for(let i=0;i<2+(day*7)%5;i++)data.rule_versions.push({...data.rule_versions[0],id:randomUUID(),rule_id:rid,number:i+1,created_at,validated:true,created_by:day%2?admin:reader});
 for(let i=0;i<(day*3)%4;i++)data.change_requests.push({id:randomUUID(),title:'Ajustar correlação de autenticação '+day+'-'+i,description:'Revisão da lógica e do limiar de detecção.',status:['requested','review','approved','published','changes','rejected'][(day+i)%6],created_by:reader,created_at,updated_at:created_at,rule_id:rid,version_id:null});
}
let githubFailure=false,validationFailure=false,connectionFailure=false,ownerSession=true;
const calls=[];
const browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
await mkdir('artifacts/review',{recursive:true});
try{
 const login=await browser.newPage({viewport:{width:1440,height:1000}});
 await login.goto(base);await login.getByLabel('Usuário',{exact:true}).waitFor();
 assert.equal(await login.locator('.login-card .login-logo img').count(),1);assert.equal(await login.locator('.login-brand').count(),0);assert.equal(await login.getByText(/Sua próxima/).count(),0);
 await login.screenshot({path:'artifacts/review/login-desktop.png',fullPage:true,animations:'disabled'});
 await login.setViewportSize({width:390,height:844});await login.screenshot({path:'artifacts/review/login-mobile.png',fullPage:true,animations:'disabled'});await login.close();
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const expires=Math.floor(Date.now()/1000)+3600;
 const token=[btoa(JSON.stringify({alg:'HS256',typ:'JWT'})),btoa(JSON.stringify({sub:admin,role:'authenticated',exp:expires})),'fixture-signature'].join('.');
 await context.addInitScript(({token,expires,admin})=>localStorage.setItem('sb-nsigspmrqqfpcihmixer-auth-token',JSON.stringify({access_token:token,refresh_token:'fixture-refresh',token_type:'bearer',expires_in:3600,expires_at:expires,user:{id:admin,email:'admin@hadsec.local',aud:'authenticated',role:'authenticated',app_metadata:{provider:'email'},user_metadata:{},created_at:'2026-11-06T12:00:00Z'}})),{token,expires,admin});
 const respond=(route,body,status=200)=>route.fulfill({status,contentType:'application/json',headers:{'Access-Control-Allow-Origin':'*'},body:JSON.stringify(body)});
 const audit=(action,entity)=>data.audit_events.push({id:data.audit_events.length+1,actor_id:admin,action,entity_id:entity,created_at:date,detail:{}});
 let releaseRoles;const rolesGate=new Promise(resolve=>{releaseRoles=resolve;});
 await context.route('https://nsigspmrqqfpcihmixer.supabase.co/**',async route=>{
  const req=route.request(),url=new URL(req.url());calls.push(url.pathname);
  if(url.pathname.startsWith('/auth/v1/'))return respond(route,{user:{id:admin,email:'admin@hadsec.local'}});
  const name=url.pathname.split('/').at(-1);
  if(url.pathname.includes('/rpc/')){
   if(name==='record_capabilities')return respond(route,{owner:ownerSession});
   const p=req.postDataJSON();
   if(['delete_request','hide_github_submission'].includes(name)){
    if(!ownerSession)return respond(route,{message:'Somente o proprietário pode excluir.'},403);
    const q=data.change_requests.find(q=>q.id===p.p_request);assert.equal(p.p_confirmation,q.title);
    if(name==='delete_request'){q.deleted_at=new Date().toISOString();q.deleted_by=admin;if(q.status==='published')q.github_hidden_at=q.deleted_at;}
    else{assert.equal(q.status,'published');q.github_hidden_at=new Date().toISOString();q.github_hidden_by=admin;}
    audit(name==='delete_request'?'request.deleted':'github.submission_hidden',q.id);return respond(route,null);
   }
   if(name==='save_rule'){
    const rid=p.p_rule_id||randomUUID(),vid=randomUUID();
    if(!p.p_rule_id)data.rules.push({id:rid,name:p.p_name,description:p.p_description,severity:p.p_severity,technique:p.p_technique,format:p.p_format,mode:p.p_mode,created_by:admin,created_at:date,archived:false});
    data.rule_versions.push({id:vid,rule_id:rid,number:p.p_expected_version+1,content:p.p_content,change_note:p.p_note,created_by:admin,created_at:date,validated:false,validation_report:null,content_sha256:'b'.repeat(64)});audit('version.created',vid);return respond(route,vid);
   }
   if(name==='attach_version'){const q=data.change_requests.find(q=>q.id===p.p_request),v=data.rule_versions.find(v=>v.id===p.p_version);assert.equal(v.validated,true);Object.assign(q,{rule_id:v.rule_id,version_id:v.id,status:'review'});audit('request.version_attached',q.id);return respond(route,null);}
   if(name==='decide_request'){const q=data.change_requests.find(q=>q.id===p.p_request);Object.assign(q,{status:p.p_decision,reviewed_by:admin,review_note:p.p_note});audit('request.'+p.p_decision,q.id);data.audit_events.at(-1).detail.administrator_self_decision=q.created_by===admin;data.audit_events.at(-1).detail.administrator_self_approval=q.created_by===admin&&p.p_decision==='approved';return respond(route,null);}
   throw Error('Unexpected RPC '+name);
  }
  assert.ok(name in data,'Unexpected table '+name);if(name==='roles')await rolesGate;return respond(route,data[name]);
 });
 await context.route('**/api/gateway',async route=>{
  const p=route.request().postDataJSON();calls.push('gateway:'+p.action);
  if(p.action==='validate'){
   if(validationFailure)return respond(route,{error:'Serviço temporariamente indisponível.'},503);
   const v=data.rule_versions.find(v=>v.id===p.version_id),r=data.rules.find(r=>r.id===v.rule_id),report=validateRule(v.content,r.format,r.mode);Object.assign(v,{validated:report.ok,validation_report:report});audit('version.validated',v.id);return respond(route,report);
  }
  if(p.action==='rule.archive'){const r=data.rules.find(r=>r.id===p.rule_id);assert.equal(p.confirmation,r.name);const linked=data.change_requests.filter(q=>q.rule_id===r.id&&!q.deleted_at);if(linked.length&&!ownerSession)return respond(route,{error:'Somente o proprietário pode excluir esta regra.'},403);for(const q of linked){q.deleted_at=new Date().toISOString();q.deleted_by=admin;if(q.status==='published')q.github_hidden_at=q.deleted_at;audit('request.deleted',q.id);}r.archived=true;audit('rule.archived',r.id);return respond(route,{ok:true,deleted_requests:linked.length});}
  if(p.action==='notifications.list')return respond(route,{items:buildNotifications({events:[...data.audit_events].reverse(),profiles:data.profiles,versions:data.rule_versions,rules:data.rules,requests:data.change_requests})});
  if(p.action==='connections.status')return respond(route,{server:true,supabase:!connectionFailure,github:true,repository:'EduardoApo/hadsec-detect-rules',checkedAt:new Date().toISOString(),services:{auth:{state:'online',latencyMs:43},database:{state:connectionFailure?'offline':'online',latencyMs:24},server:{state:'online',latencyMs:null},github:{state:'online',latencyMs:76}}});
  if(p.action==='github.status')return githubFailure?respond(route,{error:'Não foi possível conectar ao serviço.'},503):respond(route,{configured:true,connected:true,repository:'HadSec/regras',branch:'main'});
  throw Error('Unexpected gateway action '+p.action);
 });
 const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.getByRole('progressbar',{name:'Progresso do carregamento'}).waitFor();await page.waitForFunction(()=>{const bar=document.querySelector('[role=progressbar]');const value=Number(bar?.getAttribute('aria-valuenow'));return value>20&&value<100;});await page.screenshot({path:'artifacts/review/owl-splash.png',fullPage:true,animations:'disabled'});releaseRoles();await page.getByRole('heading',{name:'Visão geral.'}).waitFor();
 assert.equal(await page.locator('.sidebar-compact').count(),1);
 assert.equal(await page.locator('.workspace,.version-card,.global-search,.breadcrumb,.topbar').count(),0);
 assert.equal(await page.getByLabel('Buscar regras',{exact:true}).count(),0);
 await page.getByRole('button',{name:/^Notificações/}).click();await page.getByRole('dialog',{name:'Notificações do sistema'}).waitFor();
 await page.getByRole('dialog',{name:'Notificações do sistema'}).getByRole('button',{name:/Investigar autenticação/}).click();
 await page.getByRole('dialog',{name:'Revisar solicitação'}).waitFor();assert.equal(new URL(page.url()).hash,'#requests');
 await page.screenshot({path:'artifacts/review/request-flow.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:'Criar regra',exact:true}).click();
 await page.getByRole('dialog',{name:'Nova regra de detecção'}).waitFor();
 assert.equal(await page.getByLabel('Nome da regra',{exact:true}).inputValue(),data.change_requests[0].title);
 assert.equal(await page.getByLabel('Objetivo da detecção',{exact:true}).inputValue(),data.change_requests[0].description);
 await page.getByLabel('O que mudou nesta versão?',{exact:true}).fill('Detecção criada a partir da solicitação recebida.');
 await page.getByRole('button',{name:'Salvar, validar e enviar'}).click();
 await page.getByRole('heading',{name:'Investigar autenticação incomum.'}).waitFor();
 assert.equal(data.change_requests[0].status,'review');assert.ok(data.change_requests[0].version_id);assert.equal(data.rule_versions.find(v=>v.id===data.change_requests[0].version_id).validated,true);
 await page.screenshot({path:'artifacts/review/rule-editor.png',fullPage:true,animations:'disabled'});
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
 await page.screenshot({path:'artifacts/review/rules-desktop.png',fullPage:true,animations:'disabled'});
 await nav.getByRole('button',{name:'GitHub',exact:true}).click();await page.getByText('Conectado',{exact:true}).waitFor();assert.equal(await page.getByRole('alert').count(),0);
 githubFailure=true;await page.getByRole('button',{name:'Verificar conexão'}).click();await page.getByRole('alert').waitFor();githubFailure=false;await page.getByRole('button',{name:'Tentar novamente'}).click();await page.getByText('Conectado',{exact:true}).waitFor();
 await nav.getByRole('button',{name:'Auditoria',exact:true}).click();const search=page.getByRole('searchbox',{name:'Pesquisar auditoria'});await search.fill('joao solicitacao 2026-11-06');assert.equal(await page.locator('tbody tr').count(),1);await search.fill('temporaria');assert.equal(await page.locator('tbody tr').count(),1);await search.fill('sem-resultados');assert.equal(await page.locator('tbody tr').count(),0);await page.getByRole('button',{name:'Limpar pesquisa de auditoria'}).click();await page.screenshot({path:'artifacts/review/audit-desktop.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:'Abrir menu da conta'}).click();await page.getByRole('menuitem',{name:'Alterar senha',exact:true}).click();await page.getByRole('tab',{name:/Alterar senha/}).waitFor();assert.equal(await page.getByRole('tab',{name:/Alterar senha/}).getAttribute('aria-selected'),'true');await page.getByLabel('Senha atual',{exact:true}).waitFor();
 assert.equal(new URL(page.url()).hash,'#profile');await page.screenshot({path:'artifacts/review/profile-desktop.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:'Configurações',exact:true}).click();assert.equal(await page.getByRole('tab',{name:/Alterar senha/}).count(),0);
 await page.getByRole('tab',{name:/Sobre a ferramenta/}).click();await page.getByRole('heading',{name:'HadSec Detect',exact:true}).waitFor();assert.equal(await page.getByLabel('Senha atual',{exact:true}).count(),0);
 await page.getByRole('tab',{name:/Conexões/}).click();await page.getByText('Serviço da aplicação',{exact:true}).waitFor();
 const database=page.locator('[data-service=database]');await database.getByText('Conectado',{exact:true}).waitFor();connectionFailure=true;await page.getByRole('button',{name:'Verificar',exact:true}).click();await database.getByText('Indisponível',{exact:true}).waitFor();connectionFailure=false;await page.getByRole('button',{name:'Verificar',exact:true}).click();await database.getByText('Conectado',{exact:true}).waitFor();
 assert.ok(await page.evaluate(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=document.querySelector('.app-main').getBoundingClientRect().left+1));await page.screenshot({path:'artifacts/review/settings-desktop.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:/^Notificações/}).click();await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog',{name:'Notificações do sistema'}).count(),0);
 await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'artifacts/review/settings-mobile.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:/^Notificações/}).click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'artifacts/review/notifications-mobile.png',fullPage:true,animations:'disabled'});
 await page.getByRole('dialog',{name:'Notificações do sistema'}).getByRole('button',{name:/Admin criou uma regra/}).first().click();await page.waitForURL('**/#rules');assert.equal(new URL(page.url()).hash,'#rules');await page.waitForFunction(()=>document.querySelector('.detail-grid'));assert.equal(await page.getByRole('dialog').count(),0);
 await page.setViewportSize({width:1440,height:1000});
 const own={id:randomUUID(),title:'Revisão própria do administrador',description:'Aprovação administrativa com evidência de teste.',status:'review',created_by:admin,created_at:date,updated_at:date,rule_id:data.rule_versions.at(-1).rule_id,version_id:data.rule_versions.at(-1).id};data.change_requests.push(own);data.test_evidence.push({id:randomUUID(),version_id:own.version_id,result:'pass',method:'FortiSIEM SQL',notes:'Consulta validada no FortiSIEM.',created_by:admin,created_at:date});
 await page.reload();await page.getByRole('navigation',{name:'Navegação principal'}).waitFor();await nav.getByRole('button',{name:'Solicitações',exact:true}).click();await page.locator('.request-row').filter({hasText:'Revisão própria do administrador'}).click();const ownDialog=page.getByRole('dialog',{name:'Revisar solicitação'});await ownDialog.getByRole('button',{name:'Aprovar como administrador'}).waitFor();await ownDialog.getByLabel('Justificativa',{exact:true}).fill('Aprovação administrativa após teste de homologação.');await page.screenshot({path:'artifacts/review/admin-approval.png',fullPage:true,animations:'disabled'});await ownDialog.getByRole('button',{name:'Aprovar como administrador'}).click();await ownDialog.getByText('Parecer de Admin',{exact:true}).waitFor();assert.equal(own.status,'approved');await ownDialog.getByRole('button',{name:'Fechar',exact:true}).click();
 for(const [decision,label]of [['changes','Solicitar ajustes como administrador'],['rejected','Rejeitar como administrador']]){
  own.status='review';await page.reload();await nav.getByRole('button',{name:'Solicitações',exact:true}).waitFor();await page.locator('.request-row').filter({hasText:'Revisão própria do administrador'}).click();await ownDialog.getByLabel('Resultado',{exact:true}).selectOption(decision);const note='Decisão administrativa de teste: '+decision;await ownDialog.getByLabel('Justificativa',{exact:true}).fill(note);await ownDialog.getByRole('button',{name:label,exact:true}).click();await ownDialog.getByText(note,{exact:true}).waitFor();assert.equal(own.status,decision);await ownDialog.getByRole('button',{name:'Fechar',exact:true}).click();
 }
 data.roles[0].system=false;data.roles[0].name='Revisor';own.status='review';await page.reload();await nav.getByRole('button',{name:'Solicitações',exact:true}).waitFor();await page.locator('.request-row').filter({hasText:'Revisão própria do administrador'}).click();await page.getByText('Esta versão precisa ser revisada por outra pessoa.',{exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'Aprovar como administrador'}).count(),0);data.roles[0].system=true;data.roles[0].name='Administrador';await page.reload();await nav.getByRole('button',{name:'Relatórios',exact:true}).waitFor();
 await nav.getByRole('button',{name:'Relatórios',exact:true}).click();await page.getByRole('heading',{name:'Relatórios.'}).waitFor();assert.equal(await page.locator('.report-kpi').count(),4);await page.waitForTimeout(1300);assert.ok(await page.evaluate(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=document.querySelector('.app-main').getBoundingClientRect().left+1));await page.mouse.move(1350,70);await page.screenshot({path:'artifacts/review/reports-desktop.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:'7 dias',exact:true}).click();assert.equal(await page.getByRole('button',{name:'7 dias',exact:true}).getAttribute('aria-pressed'),'true');await page.getByRole('button',{name:'90 dias',exact:true}).click();assert.equal(await page.getByRole('button',{name:'90 dias',exact:true}).getAttribute('aria-pressed'),'true');const series=page.getByRole('button',{name:'Versões',exact:true});await series.click();assert.equal(await series.getAttribute('aria-pressed'),'false');await series.click();
 const download=page.waitForEvent('download');await page.getByRole('button',{name:'CSV',exact:true}).click();assert.equal((await download).suggestedFilename(),'hadsec-relatorio.csv');
 const pdfDownload=page.waitForEvent('download');await page.getByRole('button',{name:'Exportar PDF',exact:true}).click();const pdf=await pdfDownload;assert.match(pdf.suggestedFilename(),/\.pdf$/);await pdf.saveAs('artifacts/review/hadsec-relatorio.pdf');const pdfBytes=await readFile('artifacts/review/hadsec-relatorio.pdf');assert.equal(pdfBytes.subarray(0,5).toString(),'%PDF-');assert.ok(pdfBytes.length>10000);await page.getByText(/PDF gerado com \d+ páginas/).waitFor();
 await page.getByRole('button',{name:'30 dias',exact:true}).click();await page.setViewportSize({width:390,height:844});await page.waitForTimeout(1300);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.screenshot({path:'artifacts/review/reports-mobile.png',fullPage:true,animations:'disabled'});
 await page.setViewportSize({width:1440,height:1000});
 const removable={id:randomUUID(),title:'Solicitação temporária para excluir',description:'Registro de teste sem vínculo com uma regra.',status:'requested',created_by:reader,created_at:date,updated_at:date};
 const sent={...removable,id:randomUUID(),title:'Envio temporário para excluir',status:'published',github_url:'https://github.com/example/rules/pull/42'};
 data.change_requests.splice(0,data.change_requests.length,...data.change_requests.filter(q=>q.id===own.id||q.id===requestId),removable,sent);await page.reload();await nav.getByRole('button',{name:'Solicitações',exact:true}).waitFor();await nav.getByRole('button',{name:'Solicitações',exact:true}).click();
 assert.equal(await page.locator('button button').count(),0);
 await page.getByRole('button',{name:'Excluir solicitação '+removable.title,exact:true}).click();
 const deletion=page.getByRole('dialog',{name:'Excluir solicitação',exact:true});await deletion.waitFor();
 assert.equal(await deletion.getByRole('button',{name:'Excluir solicitação',exact:true}).isDisabled(),true);
 await deletion.getByLabel('Digite o título para confirmar').fill('título incorreto');assert.equal(await deletion.getByRole('button',{name:'Excluir solicitação',exact:true}).isDisabled(),true);
 await deletion.getByRole('button',{name:'Cancelar',exact:true}).click();assert.equal(removable.deleted_at,undefined);
 await page.locator('.request-row').filter({hasText:removable.title}).click();await page.getByRole('dialog',{name:'Revisar solicitação'}).getByRole('button',{name:'Excluir solicitação',exact:true}).click();
 await deletion.getByLabel('Digite o título para confirmar').fill(removable.title);await page.screenshot({path:'artifacts/review/delete-request-desktop.png',fullPage:false,animations:'disabled'});
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:'artifacts/review/delete-request-mobile.png',fullPage:false,animations:'disabled'});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.setViewportSize({width:1440,height:1000});
 await deletion.getByRole('button',{name:'Excluir solicitação',exact:true}).click();await deletion.waitFor({state:'hidden'});assert.ok(removable.deleted_at);assert.equal(await page.locator('.request-row').filter({hasText:removable.title}).count(),0);assert.ok(data.audit_events.some(e=>e.entity_id===removable.id&&e.action==='request.deleted'));
 await page.screenshot({path:'artifacts/review/requests-desktop.png',fullPage:true,animations:'disabled'});await page.setViewportSize({width:390,height:844});await page.screenshot({path:'artifacts/review/requests-mobile.png',fullPage:true,animations:'disabled'});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await page.setViewportSize({width:1440,height:1000});
 await nav.getByRole('button',{name:'GitHub',exact:true}).click();await page.getByRole('button',{name:'Excluir envio '+sent.title,exact:true}).waitFor();await page.screenshot({path:'artifacts/review/github-deletion.png',fullPage:true,animations:'disabled'});
 await page.getByRole('button',{name:'Excluir envio '+sent.title,exact:true}).click();const exportDeletion=page.getByRole('dialog',{name:'Excluir envio',exact:true});await exportDeletion.getByText(/pull request e os arquivos no GitHub serão preservados/).waitFor();await exportDeletion.getByLabel('Digite o título para confirmar').fill(sent.title);await page.screenshot({path:'artifacts/review/delete-submission.png',fullPage:false,animations:'disabled'});await exportDeletion.getByRole('button',{name:'Excluir envio',exact:true}).click();await exportDeletion.waitFor({state:'hidden'});assert.ok(sent.github_hidden_at);assert.equal(sent.status,'published');assert.equal(sent.github_url,'https://github.com/example/rules/pull/42');assert.equal(sent.deleted_at,undefined);assert.equal(await page.getByRole('button',{name:'Excluir envio '+sent.title,exact:true}).count(),0);
 // A separate administrator still sees the records, but receives no deletion controls.
 data.change_requests.push({...sent,id:randomUUID(),title:'Envio visível para outro administrador',github_hidden_at:null});ownerSession=false;await page.reload();await nav.getByRole('button',{name:'GitHub',exact:true}).waitFor();assert.equal(data.roles[0].name,'Administrador');assert.equal(await page.getByRole('button',{name:/^Excluir envio /}).count(),0);
 await nav.getByRole('button',{name:'Solicitações',exact:true}).click();assert.equal(await page.getByRole('button',{name:/^Excluir solicitação /}).count(),0);await page.locator('.request-row').filter({hasText:sent.title}).click();assert.equal(await page.getByRole('button',{name:'Excluir solicitação',exact:true}).count(),0);ownerSession=true;
 const linkedRule={...data.rules[0],id:randomUUID(),name:'Regra de teste com solicitações',archived:false};
 const linkedVersion={...data.rule_versions[0],id:randomUUID(),rule_id:linkedRule.id,validated:true};
 const linkedRequest={...sent,id:randomUUID(),rule_id:linkedRule.id,version_id:linkedVersion.id,github_hidden_at:null};
 const linkedPending={...removable,id:randomUUID(),rule_id:linkedRule.id,deleted_at:null};
 data.rules.push(linkedRule);data.rule_versions.push(linkedVersion);data.change_requests.push(linkedRequest,linkedPending);
 await page.reload();await nav.getByRole('button',{name:'Regras de detecção',exact:true}).waitFor();await nav.getByRole('button',{name:'Regras de detecção',exact:true}).click();
 await page.getByRole('textbox',{name:'Filtrar resultados'}).fill(linkedRule.name);await page.getByRole('button',{name:'Excluir '+linkedRule.name,exact:true}).click();
 const linkedDialog=page.getByRole('dialog',{name:'Excluir regra',exact:true});await linkedDialog.getByText(/2 solicitações vinculadas sairão das listas/).waitFor();await linkedDialog.getByRole('textbox').fill(linkedRule.name);await page.screenshot({path:'artifacts/review/delete-linked-rule.png',fullPage:false,animations:'disabled'});
 await linkedDialog.getByRole('button',{name:'Excluir regra',exact:true}).click();await linkedDialog.waitFor({state:'hidden'});
 assert.equal(linkedRule.archived,true);assert.ok(linkedRequest.deleted_at);assert.ok(linkedPending.deleted_at);assert.equal(linkedRequest.github_url,sent.github_url);assert.equal(data.rule_versions.some(v=>v.id===linkedVersion.id),true);
 assert.equal(calls.some(path=>path.includes('/functions/v1/')),false,'No Edge Function requests remain');assert.deepEqual(errors,[]);
 console.log(JSON.stringify({loginOwl:true,realLoadProgress:true,topNavigationRemoved:true,generalNotificationLinks:true,requestToRuleAndReview:true,archiveConfirmation:true,historyPreserved:true,githubStatusAndRetry:true,auditSearch:true,realConnectionStatuses:true,passwordInProfile:true,systemSettingsSeparated:true,adminSelfApprovalUI:true,ordinaryReviewerBlocked:true,animatedReports:true,reportPeriods:true,csvExport:true,actualPdfDownload:true,mobile:true,noEdgeFunctionRequests:true,ownerOnlyDeletion:true,requestDeletionFromListAndDetails:true,submissionDeletionPreservesGitHub:true,nonOwnerAdministratorHasNoDeletionControls:true,pageErrors:errors,screenshots:'artifacts/review/'}));
 await context.close();
}finally{await browser.close();}
