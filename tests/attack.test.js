import test from 'node:test';
import assert from 'node:assert/strict';
import {PGlite} from '@electric-sql/pglite';
import {readFile,readdir} from 'node:fs/promises';
import {parseAttackBundle} from '../server/attack-catalog.mjs';
import {fetchSource} from '../server/catalog-fetch.mjs';
import {techniqueCoverage,navigatorLayer} from '../src/attack-model.mjs';

export function attackFixture(){return {version:'20.1',commit:'a'.repeat(40),sha256:'b'.repeat(64),url:'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/'+ 'a'.repeat(40)+'/enterprise-attack/enterprise-attack-20.1.json',techniques:Array.from({length:100},(_,i)=>({id:'T'+(1000+i),stix_id:'attack-pattern--'+i,name:'Technique '+i,description:'Description',platforms:['Windows'],tactics:['execution'],parent_id:null,url:'https://attack.mitre.org/techniques/T'+(1000+i)+'/',modified:'2026-01-01T00:00:00Z',revoked:false,deprecated:false})),tactics:Array.from({length:5},(_,i)=>({id:'TA000'+i,stix_id:'x-mitre-tactic--'+i,shortname:i===0?'execution':'phase'+i,name:'Phase '+i,description:'Description',ordinal:i})),relationships:[]};}
test('Coverage requires explicit current native test evidence and never infers coverage from metadata/static/local success',()=>{
 const data={rules:[{id:'r'}],versions:[{id:'v1',rule_id:'r',number:1},{id:'v2',rule_id:'r',number:2}],ruleLinks:[],testLinks:[],evidence:[]};
 assert.equal(techniqueCoverage('T1000',data).status,'unmapped');data.ruleLinks.push({technique_id:'T1000',rule_id:'r'});
 assert.equal(techniqueCoverage('T1000',data).status,'unvalidated');
 data.evidence.push({id:'old',version_id:'v1',method:'Teste no motor de destino',result:'pass',created_at:'2026-01-01'});data.testLinks.push({technique_id:'T1000',evidence_id:'old',environment:'prod'});assert.equal(techniqueCoverage('T1000',data).status,'unvalidated');
 data.evidence.push({id:'local',version_id:'v2',method:'Simulação local',result:'pass',created_at:'2026-02-01'});data.testLinks.push({technique_id:'T1000',evidence_id:'local',environment:'prod'});assert.equal(techniqueCoverage('T1000',data).status,'unknown');
 data.evidence.push({id:'native',version_id:'v2',method:'Teste no motor de destino',result:'pass',created_at:'2026-03-01'});data.testLinks.push({technique_id:'T1000',evidence_id:'native',environment:'prod'});assert.equal(techniqueCoverage('T1000',data).status,'validated');
 data.evidence.push({id:'fail',version_id:'v2',method:'Teste no motor de destino',result:'fail',created_at:'2026-04-01'});data.testLinks.push({technique_id:'T1000',evidence_id:'fail',environment:'homolog'});assert.equal(techniqueCoverage('T1000',data).status,'unknown');assert.equal(techniqueCoverage('T1000',data,'homolog').status,'missed');
 const layer=navigatorLayer([{id:'T1000',platforms:['Windows']}],data,{version:'20.1',source_url:attackFixture().url,source_commit:'a'.repeat(40)},{environment:'prod'});assert.equal(layer.versions.layer,'4.5');assert.equal(layer.versions.navigator,'4.9.0');assert.equal(layer.domain,'enterprise-attack');assert.equal(layer.techniques[0].techniqueID,'T1000');assert.equal(layer.techniques[0].score,undefined);assert.match(layer.description,/versão atual/);
});
test('Catalog fetching bounds bytes, rejects redirects/invalid JSON and validates STIX structure',async()=>{
 await assert.rejects(fetchSource('https://official.example',{fetchImpl:async()=>new Response('x'.repeat(50)),maxBytes:10}),/limite/);
 await assert.rejects(fetchSource('https://official.example',{fetchImpl:async()=>new Response('{invalid')}),/JSON inválido/);
 await assert.rejects(fetchSource('https://official.example',{fetchImpl:async()=>new Response('',{status:429})}),/429/);
 assert.throws(()=>parseAttackBundle({type:'bundle',objects:[]},attackFixture()),/Matriz Enterprise/);
});
test('PostgreSQL MITRE: permission, service-only publication, atomic validation, no forged direct writes and audited links',async()=>{
 const db=new PGlite();try{
 await db.exec(`create role anon;create role authenticated;create role service_role bypassrls;create schema auth;create table auth.users(id uuid primary key,encrypted_password text);create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;grant usage on schema public,auth to authenticated,anon,service_role;grant execute on function auth.uid() to authenticated,anon,service_role;`);
 const dir=new URL('../supabase/migrations/',import.meta.url);for(const f of (await readdir(dir)).filter(f=>f.endsWith('.sql')).sort())await db.exec(await readFile(new URL(f,dir),'utf8'));
 const admin='40000000-0000-4000-8000-000000000001',reader='40000000-0000-4000-8000-000000000002';
 for(const [id,name,role] of [[admin,'adminqa','Administrador'],[reader,'readerqa','Leitor']]){await db.query('insert into auth.users(id) values($1)',[id]);await db.query('insert into profiles(id,username,display_name,role_id,must_change_password) select $1,$2,$2,id,false from roles where name=$3',[id,name,role]);}
 const as=async(id,role='authenticated')=>{await db.exec('reset role');await db.query("select set_config('request.jwt.claim.sub',$1,false)",[id]);await db.exec('set role '+role);};
 await as(reader);await assert.rejects(db.query('select begin_attack_sync()'),/Sem permissão/);await assert.rejects(db.query('select publish_attack_sync(null,$1)',[attackFixture()]),/permission denied/);
 await as(admin);const run=(await db.query('select begin_attack_sync() as id')).rows[0].id;await assert.rejects(db.query('select begin_attack_sync()'),/em andamento/);
 await as(admin,'service_role');await assert.rejects(db.query('select publish_attack_sync($1,$2)',[run,{}]),/Snapshot MITRE inválido/);assert.equal((await db.query('select count(*)::int n from attack_techniques')).rows[0].n,0);
 await db.query('select publish_attack_sync($1,$2)',[run,attackFixture()]);assert.equal((await db.query('select count(*)::int n from attack_techniques')).rows[0].n,100);
 await as(admin);const second=(await db.query('select begin_attack_sync() as id')).rows[0].id;await as(admin,'service_role');assert.equal((await db.query('select publish_attack_sync($1,$2) result',[second,attackFixture()])).rows[0].result.unchanged,true);
 await as(admin);await assert.rejects(db.query("update attack_techniques set name='Forged'"),/permission denied/);
 const v=(await db.query("select save_rule(null,'MITRE test','Test','Baixa','','Scheduled via SQL','sql','SELECT * FROM events LIMIT 10','Primeira versão',0) id")).rows[0].id;const r=(await db.query('select rule_id from rule_versions where id=$1',[v])).rows[0].rule_id;
 await db.query("select link_attack_rule('T1000',$1)",[r]);await db.query("select link_attack_rule('T1000',$1)",[r]);assert.equal((await db.query('select count(*)::int n from attack_rule_links')).rows[0].n,1);
 const subject='40000000-0000-4000-8000-000000000010';await db.exec('reset role');await db.query("insert into operational_subjects(id,kind,title,created_by) values($1,'hypothesis','Hypothesis for link test',$2)",[subject,admin]);await as(admin);await db.query("select link_attack_subject('T1000',$1)",[subject]);assert.equal((await db.query('select subject_kind from attack_subject_links')).rows[0].subject_kind,'hypothesis');await assert.rejects(db.query("select link_attack_subject('T1000','40000000-0000-4000-8000-000000000099')"),/indisponível/);
 await as(reader);await assert.rejects(db.query("select link_attack_subject('T1000',$1)",[subject]),/Sem permissão/);await assert.rejects(db.query("select link_attack_rule('T1000',$1)",[r]),/Sem permissão/);assert.equal((await db.query('select count(*)::int n from attack_techniques')).rows[0].n,100);
 await as(admin);await db.query("select record_evidence($1,'FortiSIEM SQL','pass','Documented external test result')",[v]);const e=(await db.query('select id from test_evidence where version_id=$1',[v])).rows[0].id;
 await db.query("select link_attack_test('T1000',$1,'lab','Observed test for this technique')",[e]);assert.equal((await db.query('select count(*)::int n from attack_test_links')).rows[0].n,1);assert.ok((await db.query("select * from audit_events where action='attack.test_linked'")).rows.length);
 await as('','anon');await assert.rejects(db.query('select count(*)::int n from attack_techniques'),/permission denied/);await assert.rejects(db.query('select begin_attack_sync()'),/permission denied/);
 }finally{await db.close();}
});
