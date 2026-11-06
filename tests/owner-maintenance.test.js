import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,readdir} from 'node:fs/promises';
import {PGlite} from '@electric-sql/pglite';
import {ownerRenameSQL} from '../scripts/owner-rename-sql.mjs';

test('PostgreSQL: owner removes rules at every workflow stage atomically; Admin rename preserves authentication and ownership',async()=>{
 const pg=new PGlite(),owner='20000000-0000-4000-8000-000000000001',other='20000000-0000-4000-8000-000000000002';
 try{
  await pg.exec(`create role anon;create role authenticated;create schema auth;
   create table auth.users(id uuid primary key,email text,encrypted_password text,raw_user_meta_data jsonb,updated_at timestamptz);
   create table auth.identities(user_id uuid,provider text,identity_data jsonb,updated_at timestamptz);
   create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
   grant usage on schema public,auth to anon,authenticated;grant execute on function auth.uid() to anon,authenticated;`);
  const dir=new URL('../supabase/migrations/',import.meta.url);
  for(const file of (await readdir(dir)).filter(file=>file.endsWith('.sql')).sort())await pg.exec(await readFile(new URL(file,dir),'utf8'));
  for(const [id,username]of [[owner,'Admin'],[other,'outroAdmin']]){
   await pg.query("insert into auth.users(id,email,encrypted_password,raw_user_meta_data) values($1,$2,'unchanged-password-hash','{}')",[id,username.toLowerCase()+'@hadsec.local']);
   await pg.query("insert into auth.identities(user_id,provider,identity_data) values($1,'email',jsonb_build_object('email',$2::text))",[id,username.toLowerCase()+'@hadsec.local']);
   await pg.query("insert into profiles(id,username,display_name,role_id,must_change_password) select $1,$2,$2,id,false from roles where name='Administrador' and system",[id,username]);
  }
  const as=async id=>{await pg.exec('reset role');await pg.query("select set_config('request.jwt.claim.sub',$1,false)",[id]);await pg.exec('set role authenticated');};
  await as(owner);assert.equal((await pg.query('select record_capabilities() as c')).rows[0].c.owner,true);
  let ruleId;const ids=[],versions=[];
  for(const [index,status]of ['requested','review','changes','approved','published','rejected'].entries()){
   const v=(await pg.query("select save_rule($1,'Regra vinculada','Fixture de exclusão','Alta','T1110','Scheduled via SQL','sql','SELECT eventType FROM fsiem.events','Versão de teste',$2) as id",[ruleId||null,index])).rows[0].id;versions.push(v);
   ruleId=(await pg.query('select rule_id from rule_versions where id=$1',[v])).rows[0].rule_id;
   await pg.exec('reset role');await pg.query('update rule_versions set validated=true where id=$1',[v]);await as(owner);
   const q=(await pg.query("select create_request($1,'Contexto de teste',$2,$3) as id",['Solicitação '+status,ruleId,status==='requested'?null:v])).rows[0].id;ids.push(q);
   await pg.exec('reset role');await pg.query("update change_requests set status=$1,github_url=case when $1='published' then 'https://github.com/example/rules/pull/42' end where id=$2",[status,q]);await as(owner);
  }
  await pg.query("select add_comment($1,'Comentário que deve ser preservado')",[ids[0]]);
  await pg.query("select record_evidence($1,'Revisão manual','pass','Evidência de teste que deve permanecer')",[versions[0]]);
  await as(other);await assert.rejects(pg.query("select archive_rule($1,'Regra vinculada')",[ruleId]),/Somente o proprietário/);
  await as(owner);await assert.rejects(pg.query("select archive_rule($1,'nome incorreto')",[ruleId]),/nome exato/);
  await pg.exec('reset role');await pg.query("update change_requests set export_lease_until=now()+interval '2 minutes' where id=$1",[ids[3]]);await as(owner);
  await assert.rejects(pg.query("select archive_rule($1,'Regra vinculada')",[ruleId]),/Aguarde/);
  assert.equal((await pg.query('select archived from rules where id=$1',[ruleId])).rows[0].archived,false);
  assert.equal((await pg.query('select count(*)::integer as n from change_requests where rule_id=$1 and deleted_at is not null',[ruleId])).rows[0].n,0,'All deletions roll back when an export is in progress');
  await pg.exec('reset role');await pg.query('update change_requests set export_lease_until=null where id=$1',[ids[3]]);await as(owner);
  const result=(await pg.query("select archive_rule($1,'Regra vinculada') as result",[ruleId])).rows[0].result;assert.equal(result.deleted_requests,6);assert.equal(result.archived,true);
  assert.equal((await pg.query('select count(*)::integer as n from change_requests where rule_id=$1 and deleted_by=$2',[ruleId,owner])).rows[0].n,6);
  assert.equal((await pg.query('select count(*)::integer as n from rule_versions where rule_id=$1',[ruleId])).rows[0].n,6);
  assert.equal((await pg.query('select count(*)::integer as n from comments where request_id=$1',[ids[0]])).rows[0].n,1);
  assert.equal((await pg.query('select count(*)::integer as n from test_evidence where version_id=$1',[versions[0]])).rows[0].n,1);
  const sent=(await pg.query('select * from change_requests where id=$1',[ids[4]])).rows[0];assert.equal(sent.status,'published');assert.ok(sent.github_hidden_at);assert.match(sent.github_url,/pull\/42$/);
  assert.equal((await pg.query("select archive_rule($1,'Regra vinculada') as result",[ruleId])).rows[0].result.deleted_requests,0);
  assert.equal((await pg.query("select count(*)::integer as n from audit_events where action='rule.archived' and entity_id=$1",[ruleId])).rows[0].n,1);
  await assert.rejects(pg.query("select create_request('Aba antiga','Tentativa após exclusão',$1,null)",[ruleId]),/excluída/);
  const unlinked=(await pg.query("select create_request('Solicitação independente','Não deve ser alterada',null,null) as id")).rows[0].id;
  await assert.rejects(pg.query('select attach_version($1,$2)',[unlinked,versions[0]]),/excluída/);
  assert.equal((await pg.query('select status from change_requests where id=$1',[unlinked])).rows[0].status,'requested');
  await as(other);const ownV=(await pg.query("select save_rule(null,'Rascunho sem vínculos','Exclusão comum','Baixa','','Scheduled via SQL','sql','SELECT eventType FROM fsiem.events','Teste',0) as id")).rows[0].id;
  const ownRule=(await pg.query('select rule_id from rule_versions where id=$1',[ownV])).rows[0].rule_id;await pg.query("select archive_rule($1,'Rascunho sem vínculos')",[ownRule]);
  // Reproduce the former username without changing the account or its pinned ownership.
  await pg.exec('reset role');await pg.query("update profiles set username='HadSec',display_name='HadSec' where id=$1",[owner]);await pg.query("update auth.users set email='hadsec@hadsec.local' where id=$1",[owner]);
  await pg.exec(ownerRenameSQL('Admin'));
  assert.equal((await pg.query('select username from profiles where id=$1',[owner])).rows[0].username,'Admin');
  const auth=(await pg.query('select * from auth.users where id=$1',[owner])).rows[0];assert.equal(auth.email,'admin@hadsec.local');assert.equal(auth.encrypted_password,'unchanged-password-hash');assert.equal(auth.raw_user_meta_data.username,'Admin');
  assert.equal((await pg.query('select identity_data from auth.identities where user_id=$1',[owner])).rows[0].identity_data.email,'admin@hadsec.local');
  await pg.exec(ownerRenameSQL('Admin'));assert.equal((await pg.query("select count(*)::integer as n from audit_events where action='user.renamed'")).rows[0].n,1);
  await assert.rejects(pg.exec(ownerRenameSQL('outroAdmin')),/já está em uso/);await pg.exec('rollback');
  assert.equal((await pg.query('select username from profiles where id=$1',[owner])).rows[0].username,'Admin');
  await as(owner);assert.equal((await pg.query('select record_capabilities() as c')).rows[0].c.owner,true);await as(other);assert.equal((await pg.query('select record_capabilities() as c')).rows[0].c.owner,false);
  await pg.exec("reset role;select set_config('request.jwt.claim.sub','',false);set role anon");await assert.rejects(pg.query("select archive_rule($1,'Regra vinculada')",[ruleId]),/permission denied/);
 }finally{await pg.close();}
});
