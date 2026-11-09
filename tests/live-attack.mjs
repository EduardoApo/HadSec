// Explicit integration: official catalog persists; only this script's temporary rule is removed.
import {createClient} from '@supabase/supabase-js';
import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
const base=process.env.TEST_APP_URL||'http://127.0.0.1:5173';
const client=createClient(process.env.SUPABASE_URL,process.env.VITE_SUPABASE_ANON_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const admin=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const check=({data,error})=>{if(error)throw Error(error.message);return data;};
let browser,ruleId,versionId,testUser;const subjectIds=[];
try{
 const username='qa_catalog_'+randomUUID().replaceAll('-','').slice(0,12),email=username+'@hadsec.local',password=randomUUID();
 const role=check(await admin.from('roles').select('id').eq('name','Engenheiro').single());
 testUser=check(await admin.auth.admin.createUser({email,password,email_confirm:true})).user.id;
 check(await admin.from('profiles').insert({id:testUser,username,display_name:'QA catálogo temporário',role_id:role.id,must_change_password:false}));
 check(await admin.from('user_permission_overrides').insert({user_id:testUser,permission:'catalogs.manage',granted:true,updated_by:testUser}));
 check(await client.auth.signInWithPassword({email,password}));
 versionId=check(await client.rpc('save_rule',{p_rule_id:null,p_name:'QA MITRE '+randomUUID().slice(0,8),p_description:'Temporary integration fixture only.',p_severity:'Baixa',p_technique:'',p_mode:'Scheduled via SQL',p_format:'sql',p_content:'SELECT * FROM events LIMIT 10',p_note:'Temporary MITRE mapping test.',p_expected_version:0}));
 ruleId=check(await client.from('rule_versions').select('rule_id').eq('id',versionId).single()).rule_id;
 for(const kind of ['campaign','hypothesis','validation']){const id=randomUUID();check(await admin.from('operational_subjects').insert({id,kind,title:'QA MITRE subject '+kind,created_by:testUser}));subjectIds.push(id);}
 browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base+'/#coverage');await page.getByLabel('Usuário',{exact:true}).fill(username);await page.getByLabel('Senha',{exact:true}).fill(password);await page.getByRole('button',{name:'Entrar no workspace',exact:true}).click();
 await page.getByRole('button',{name:'Sincronizar MITRE',exact:true}).waitFor();const syncResponse=page.waitForResponse(r=>r.url().endsWith('/api/gateway')&&r.request().postDataJSON()?.action==='attack.sync',{timeout:180000});await page.getByRole('button',{name:'Sincronizar MITRE',exact:true}).click();const syncHttp=await syncResponse;const syncResult=await syncHttp.json();assert.equal(syncHttp.status(),200,JSON.stringify(syncResult));await page.getByText('Catálogo MITRE sincronizado e persistido.',{exact:true}).waitFor();
 const sync=check(await client.from('attack_sync_runs').select('*').eq('status','success').order('started_at',{ascending:false}).limit(1).single());
 const count=await client.from('attack_techniques').select('id',{head:true,count:'exact'}).eq('active',true);if(count.error)throw count.error;assert.equal(count.count,sync.technique_count);assert.ok(count.count>500);assert.match(sync.source_commit,/^[a-f0-9]{40}$/);
 await page.getByRole('textbox',{name:'Buscar técnica',exact:true}).fill('T1059.001');await page.locator('.attack-tactic>button').first().click();const dialog=page.getByRole('dialog');await dialog.getByLabel('Relacionar regra',{exact:true}).selectOption(ruleId);await dialog.getByRole('button',{name:'Vincular',exact:true}).click();await dialog.getByText('Regra vinculada à técnica.',{exact:true}).waitFor();await dialog.getByRole('button',{name:'Fechar',exact:true}).click();
 assert.equal(check(await client.from('attack_rule_links').select('*').eq('technique_id','T1059.001').eq('rule_id',ruleId)).length,1);
 await page.locator('.attack-tactic>button').first().click();for(const id of subjectIds){await dialog.getByLabel('Campanha, hipótese ou solicitação de teste',{exact:true}).selectOption(id);await dialog.getByRole('button',{name:'Relacionar registro',exact:true}).click();await dialog.getByRole('button',{name:'Desvincular QA MITRE subject '+['campaign','hypothesis','validation'][subjectIds.indexOf(id)],exact:true}).waitFor();}await dialog.getByRole('button',{name:'Fechar',exact:true}).click();assert.equal(check(await client.from('attack_subject_links').select('*').in('subject_id',subjectIds)).length,3);
 await page.reload();await page.getByRole('textbox',{name:'Buscar técnica',exact:true}).fill('T1059.001');await page.getByRole('tab',{name:'Técnicas',exact:true}).click();await page.getByText('Regra sem validação',{exact:true}).last().waitFor();
 const downloadPromise=page.waitForEvent('download');await page.getByRole('button',{name:'Navigator JSON',exact:true}).click();const download=await downloadPromise;const stream=await download.createReadStream();const chunks=[];for await(const c of stream)chunks.push(c);const layer=JSON.parse(Buffer.concat(chunks).toString('utf8'));assert.equal(layer.versions.layer,'4.5');assert.equal(layer.domain,'enterprise-attack');assert.equal(layer.techniques[0].techniqueID,'T1059.001');assert.ok(!layer.techniques.some(t=>t.color==='#b5ed59'));
 await page.screenshot({path:'artifacts/review/mitre-functional.png',fullPage:true});await page.setViewportSize({width:390,height:844});await page.screenshot({path:'artifacts/review/mitre-functional-mobile.png',fullPage:true});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);assert.deepEqual(errors,[]);
 console.log(JSON.stringify({officialCatalogSync:true,version:sync.version,techniques:sync.technique_count,tactics:sync.tactic_count,relationships:sync.relationship_count,realRuleMapping:true,persistsAfterReload:true,noFalseValidatedCoverage:true,navigatorLayer:'4.5',desktopMobile:true,pageErrors:errors}));
}finally{
 if(browser)await browser.close();
 if(subjectIds.length){check(await admin.from('attack_subject_links').delete().in('subject_id',subjectIds));check(await admin.from('operational_subjects').delete().in('id',subjectIds));}
 if(ruleId){check(await admin.from('attack_rule_links').delete().eq('rule_id',ruleId));check(await admin.from('rule_versions').delete().eq('rule_id',ruleId));check(await admin.from('rules').delete().eq('id',ruleId));}
 await client.auth.signOut({scope:'local'});
 if(testUser){check(await admin.from('user_permission_overrides').delete().eq('user_id',testUser));check(await admin.from('profiles').update({active:false,deleted_at:new Date().toISOString(),username:'deleted.'+testUser.replaceAll('-',''),display_name:'Teste de sincronização removido'}).eq('id',testUser));check(await admin.auth.admin.deleteUser(testUser,true));}
 console.log('Temporary rule removed and test account soft-deleted. Official catalog and sync attribution retained. Existing accounts unchanged.');
}
