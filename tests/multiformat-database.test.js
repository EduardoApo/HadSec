import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PGlite} from '@electric-sql/pglite';
import {readFile,readdir} from 'node:fs/promises';
import {formats} from '../supabase/functions/_shared/formats.mjs';
import {validateDetectionRule} from '../supabase/functions/_shared/detection-engine.mjs';

test('PostgreSQL: create/change intake preserves immutable originals, permissions, new formats and native approval evidence',async()=>{
 const pg=new PGlite(),author='30000000-0000-4000-8000-000000000001',engineer='30000000-0000-4000-8000-000000000002',reviewer='30000000-0000-4000-8000-000000000003';
 try{
  await pg.exec(`create role anon;create role authenticated;create schema auth;create table auth.users(id uuid primary key,encrypted_password text);
   create function auth.uid() returns uuid language sql stable as $$select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;
   grant usage on schema public,auth to authenticated,anon;grant execute on function auth.uid() to authenticated,anon;`);
  const dir=new URL('../supabase/migrations/',import.meta.url);for(const file of (await readdir(dir)).filter(file=>file.endsWith('.sql')).sort())await pg.exec(await readFile(new URL(file,dir),'utf8'));
  for(const [id,name,role]of [[author,'solicitante','Leitor'],[engineer,'engenheiro','Engenheiro'],[reviewer,'revisor','Revisor']]){await pg.query('insert into auth.users(id) values($1)',[id]);await pg.query('insert into profiles(id,username,display_name,role_id,must_change_password) select $1,$2,$2,id,false from roles where name=$3',[id,name,role]);}
  const as=async id=>{await pg.exec('reset role');await pg.query("select set_config('request.jwt.claim.sub',$1,false)",[id]);await pg.exec('set role authenticated');};
  const submit=async(kind,format,rule=null,content=null)=>(await pg.query("select submit_change_request($1,'Regra para investigar','Contexto da solicitação',$2,$3,$4,$5) as id",[kind,format,formats.find(f=>f.id===format)?.mode||'Native',rule,content])).rows[0].id;
  await as(author);const creation=await submit('create','kusto');const request=(await pg.query('select * from change_requests where id=$1',[creation])).rows[0];assert.equal(request.request_kind,'create');assert.equal(request.requested_format,'kusto');assert.equal(request.rule_id,null);assert.equal(request.baseline_version_id,null);
  await assert.rejects(submit('change','sigma'),/regra original/);await assert.rejects(submit('invalid','sigma'),/Escolha/);
  const original=formats.find(f=>f.id==='sigma').sample,change=await submit('change','sigma',null,original);
  const intake=(await pg.query('select * from change_requests where id=$1',[change])).rows[0],baseline=(await pg.query('select * from rule_versions where id=$1',[intake.baseline_version_id])).rows[0];
  assert.equal(intake.request_kind,'change');assert.equal(baseline.content,original);assert.equal(baseline.number,1);assert.equal(baseline.created_by,author);assert.equal(baseline.content_sha256.length,64);
  await assert.rejects(pg.query("update rule_versions set content='altered' where id=$1",[baseline.id]),/permission denied/);
  await assert.rejects(pg.query("select save_rule($1,'Regra','Alteração','Alta','','Native','sigma',$2,'Nova versão',1)",[intake.rule_id,original+'\n# ajuste']),/Permission/);
  await pg.exec('reset role');await assert.rejects(pg.query('update rule_versions set validated=true where id=$1',[baseline.id]),/Atualize/);
  await pg.query('update rule_versions set validated=true,validation_report=$2 where id=$1',[baseline.id,validateDetectionRule(original,'sigma','Native')]);await as(engineer);
  await assert.rejects(pg.query('select attach_version($1,$2)',[change,baseline.id]),/regra original/);
  const revised=original.replace('malware.exe','other.exe');const vid=(await pg.query("select save_rule($1,'Regra','Alteração','Alta','','Native','sigma',$2,'Ajuste solicitado',1) as id",[intake.rule_id,revised])).rows[0].id;
  await pg.exec('reset role');await pg.query('update rule_versions set validated=true,validation_report=$2 where id=$1',[vid,validateDetectionRule(revised,'sigma','Native')]);await as(engineer);await pg.query('select attach_version($1,$2)',[change,vid]);
  const submitted=(await pg.query('select * from change_requests where id=$1',[change])).rows[0];assert.equal(submitted.version_id,vid);assert.equal(submitted.baseline_version_id,baseline.id);assert.equal(submitted.status,'review');
  assert.equal((await pg.query('select content from rule_versions where id=$1',[baseline.id])).rows[0].content,original);
  await as(reviewer);await assert.rejects(pg.query("select decide_request($1,'approved','Critérios atendidos')",[change]),/teste aprovado/);
  await pg.query("select record_evidence($1,'Simulação local','pass','Teste local sobre o evento inserido')",[vid]);await assert.rejects(pg.query("select decide_request($1,'approved','Critérios atendidos')",[change]),/motor de destino/);
  await assert.rejects(pg.query("select record_evidence($1,'FortiSIEM SQL','pass','Método incompatível com Sigma')",[vid]),/incompatível/);
  await pg.query("select record_evidence($1,'Teste no motor de destino','pass','Teste no backend Sigma do ambiente de homologação')",[vid]);await pg.query("select decide_request($1,'approved','Critérios atendidos com evidência nativa')",[change]);
  await as(author);const further=await submit('change','sigma',intake.rule_id,revised);assert.equal((await pg.query('select baseline_version_id from change_requests where id=$1',[further])).rows[0].baseline_version_id,vid);
  assert.equal((await pg.query('select count(*)::int as n from rule_versions where rule_id=$1',[intake.rule_id])).rows[0].n,2);
  await assert.rejects(submit('change','sigma',intake.rule_id,original),/A regra mudou/);await assert.rejects(submit('create','sigma',intake.rule_id),/Nova regra/);
  await pg.exec('reset role');await assert.rejects(pg.query("update change_requests set request_kind='create' where id=$1",[change]),/imutáveis/);await assert.rejects(pg.query('update change_requests set baseline_version_id=null where id=$1',[change]),/imutáveis/);
  await as(engineer);for(const f of formats.filter(f=>!['sql','xml'].includes(f.id))){const version=(await pg.query("select save_rule(null,$1,'Formato adicional','Média','','Native',$2,$3,'Primeira versão',0) as id",['Regra '+f.id,f.id,f.sample])).rows[0].id;assert.ok(version);}
  await pg.exec("reset role;select set_config('request.jwt.claim.sub','',false);set role anon");await assert.rejects(submit('create','sigma'),/permission denied/);
 }finally{await pg.close();}
});
