import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {PGlite} from '@electric-sql/pglite';
import {requestVisible,submissionVisible,versionRequestActive} from '../src/record-visibility.mjs';
import {buildNotifications} from '../server/notifications.mjs';
import {buildReport} from '../src/reporting.mjs';

test('PostgreSQL: only the pinned owner can delete requests and GitHub records; workflows and history remain protected',async()=>{
 const pg=new PGlite();
 const owner='10000000-0000-4000-8000-000000000001',administrator='10000000-0000-4000-8000-000000000002',author='10000000-0000-4000-8000-000000000003';
 try{
  await pg.exec(`create role anon;create role authenticated;create schema auth;
   create table auth.users(id uuid primary key,encrypted_password text);
   create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
   grant usage on schema public,auth to anon,authenticated;grant execute on function auth.uid() to anon,authenticated;`);
  const dir=new URL('../supabase/migrations/',import.meta.url);
  for(const file of (await readdir(dir)).filter(file=>file.endsWith('.sql')).sort())await pg.exec(await readFile(new URL(file,dir),'utf8'));
  for(const [id,username,role]of [[owner,'HadSec','Administrador'],[administrator,'outroAdmin','Administrador'],[author,'autor','Engenheiro']]){
   await pg.query('insert into auth.users(id) values($1)',[id]);
   await pg.query('insert into profiles(id,username,display_name,role_id,must_change_password) select $1,$2,$2,id,false from roles where name=$3',[id,username,role]);
  }
  const as=async id=>{await pg.exec('reset role');await pg.query("select set_config('request.jwt.claim.sub',$1,false)",[id]);await pg.exec('set role authenticated');};
  const capabilities=async()=> (await pg.query('select record_capabilities() as value')).rows[0].value;
  const create=async(title,rule=null,version=null)=>(await pg.query('select create_request($1,$2,$3,$4) as id',[title,'Contexto da solicitação',rule,version])).rows[0].id;
  await as(author);const request=await create('Solicitação de teste');
  await pg.query("select add_comment($1,'Comentário preservado')",[request]);
  for(const caller of [author,administrator]){
   await as(caller);assert.equal((await capabilities()).owner,false);
   await assert.rejects(pg.query("select delete_request($1,'Solicitação de teste')",[request]),/Somente o proprietário/);
   await assert.rejects(pg.query("select hide_github_submission($1,'Solicitação de teste')",[request]),/Somente o proprietário/);
   await assert.rejects(pg.query('update change_requests set deleted_at=now(),deleted_by=$1 where id=$2',[caller,request]),/permission denied/);
   await assert.rejects(pg.query('update workspace_owner set user_id=$1',[caller]),/permission denied/);
  }
  await as(owner);assert.equal((await capabilities()).owner,true);
  await assert.rejects(pg.query("select delete_request($1,'errado')",[request]),/título exato/);
  await assert.rejects(pg.query('select delete_request($1,null)',[request]),/título exato/);
  await pg.query("select delete_request($1,'Solicitação de teste')",[request]);
  await pg.query("select delete_request($1,'Solicitação de teste')",[request]);
  const deleted=(await pg.query('select * from change_requests where id=$1',[request])).rows[0];assert.ok(deleted.deleted_at);assert.equal(deleted.deleted_by,owner);
  assert.equal((await pg.query('select * from comments where request_id=$1',[request])).rows.length,1);
  assert.equal((await pg.query("select * from audit_events where entity_id=$1 and action='request.deleted'",[request])).rows.length,1);
  await assert.rejects(pg.query("select add_comment($1,'Tentativa em aba antiga')",[request]),/indisponível/);
  const vid=(await pg.query("select save_rule(null,'Regra preservada','Teste de exclusão','Alta','T1110','Scheduled via SQL','sql','SELECT eventType FROM fsiem.events','Inicial',0) as id")).rows[0].id;
  const rid=(await pg.query('select rule_id from rule_versions where id=$1',[vid])).rows[0].rule_id;
  await pg.exec('reset role');await pg.query('update rule_versions set validated=true where id=$1',[vid]);await as(owner);
  await assert.rejects(pg.query('select attach_version($1,$2)',[request,vid]),/excluída/);
  const review=await create('Revisão excluída',rid,vid);await pg.query("select delete_request($1,'Revisão excluída')",[review]);
  for(const decision of ['approved','changes','rejected'])await assert.rejects(pg.query('select decide_request($1,$2,$3)',[review,decision,'Decisão em aba antiga']),/excluída|teste aprovado/);
  // Deleting an unpublished request releases its version for a fresh review.
  const published=await create('Envio preservado',rid,vid);
  await pg.exec('reset role');await pg.query("update change_requests set status='approved',export_lease_until=now()+interval '2 minutes' where id=$1",[published]);await as(owner);
  await assert.rejects(pg.query("select delete_request($1,'Envio preservado')",[published]),/Aguarde/);
  await pg.exec('reset role');await pg.query("update change_requests set status='published',export_lease_until=null,github_url='https://github.com/example/rules/pull/1',exported_sha='immutable-sha' where id=$1",[published]);await as(owner);
  await assert.rejects(pg.query("select hide_github_submission($1,'errado')",[published]),/título exato/);
  await pg.query("select hide_github_submission($1,'Envio preservado')",[published]);
  await pg.query("select hide_github_submission($1,'Envio preservado')",[published]);
  const hidden=(await pg.query('select * from change_requests where id=$1',[published])).rows[0];
  assert.equal(hidden.status,'published');assert.equal(hidden.github_hidden_by,owner);assert.equal(hidden.deleted_at,null);assert.equal(hidden.exported_sha,'immutable-sha');assert.match(hidden.github_url,/pull\/1$/);
  assert.equal((await pg.query("select * from audit_events where entity_id=$1 and action='github.submission_hidden'",[published])).rows.length,1);
  await assert.rejects(create('Não duplicar envio',rid,vid),/unique constraint/);
  await pg.query("select delete_request($1,'Envio preservado')",[published]);
  await assert.rejects(create('Publicado continua protegido',rid,vid),/unique constraint/);
  assert.equal((await pg.query('select content from rule_versions where id=$1',[vid])).rows[0].content,'SELECT eventType FROM fsiem.events');
  const draft=await create('Proteger ações após exclusão');
  await pg.exec('reset role');await pg.query("update change_requests set status='approved' where id=$1",[draft]);await as(owner);
  await pg.query("select delete_request($1,'Proteger ações após exclusão')",[draft]);
  await assert.rejects(pg.query('select claim_export($1)',[draft]),/excluída/);
  // Renaming the owner does not hand ownership to another administrator.
  await pg.exec('reset role');await pg.query("update profiles set username='HadSecRenomeado' where id=$1",[owner]);await pg.query("update profiles set username='HadSec' where id=$1",[administrator]);await as(administrator);assert.equal((await capabilities()).owner,false);await as(owner);assert.equal((await capabilities()).owner,true);
  for(const column of ['active','must_change_password']){
   await pg.exec('reset role');await pg.query(`update profiles set ${column}=$1 where id=$2`,[column==='must_change_password',owner]);await as(owner);assert.equal((await capabilities()).owner,false);await assert.rejects(pg.query("select delete_request($1,'Solicitação de teste')",[request]),/Somente/);
   await pg.exec('reset role');await pg.query(`update profiles set ${column}=$1 where id=$2`,[column==='active',owner]);
  }
  await pg.exec("reset role;select set_config('request.jwt.claim.sub','',false);set role anon");
  await assert.rejects(pg.query('select record_capabilities()'),/permission denied/);
  await assert.rejects(pg.query("select delete_request($1,'Solicitação de teste')",[request]),/permission denied/);
 }finally{await pg.close();}
});

test('Deleted requests leave lists, reports and notifications; hiding an export never permits republishing',()=>{
 const active={id:'active',status:'review',title:'Ativa',created_at:'2026-11-06T10:00:00Z'},deleted={...active,id:'deleted',deleted_at:'2026-11-06T11:00:00Z'},hidden={...active,id:'hidden',status:'published',github_hidden_at:'2026-11-06T11:00:00Z'},publishedDeleted={...deleted,status:'published'};
 assert.equal(requestVisible(deleted),false);assert.equal(requestVisible(hidden),true);assert.equal(submissionVisible(hidden),false);assert.equal(versionRequestActive(hidden),true);assert.equal(versionRequestActive(publishedDeleted),true);assert.equal(versionRequestActive(deleted),false);
 const requests=[active,deleted,hidden];
 const items=buildNotifications({events:[{id:1,action:'request.created',entity_id:deleted.id},{id:2,action:'github.pr_created',entity_id:hidden.id},{id:3,action:'request.approved',entity_id:hidden.id}],profiles:[],rules:[],versions:[],requests});assert.equal(items.length,1);assert.equal(items[0].target.id,hidden.id);
 const report=buildReport({rules:[],versions:[],requests,evidence:[],profiles:[]},7,new Date('2026-11-06T12:00:00Z'));assert.equal(report.metrics.requests,2);assert.equal(report.pending.length,1);assert.equal(report.pending[0].id,active.id);
});
