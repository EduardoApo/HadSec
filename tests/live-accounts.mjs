import {chromium} from '@playwright/test';
import {createClient} from '@supabase/supabase-js';
import pg from 'pg';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';

// Isolated live account-management test. All generated accounts are removed in finally.
const connection=new pg.Client({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:true,ca:await readFile(new URL('../certs/supabase-root.crt',import.meta.url),'utf8')},connectionTimeoutMillis:15000});
const managerId=randomUUID(),suffix=managerId.replaceAll('-','').slice(0,12),managerName=`qa_mgr_${suffix}`,childName=`qa_child_${suffix}`;
const managerEmail=`${managerName}@hadsec.local`,childEmail=`${childName}@hadsec.local`,managerPassword=randomUUID(),childPassword=randomUUID(),changedPassword=randomUUID();
const authClient=key=>createClient(process.env.SUPABASE_URL,process.env.VITE_SUPABASE_ANON_KEY,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,storageKey:`qa-accounts-${key}-${suffix}`}});
const manager=authClient('manager'),child=authClient('child'),anonymous=authClient('anon');
let browser,childId;
await connection.connect();
try{
 const {rows:[readerRole]}=await connection.query("select id from public.roles where name<>'Administrador' order by cardinality(permissions),id limit 1");
 assert.ok(readerRole);
 await connection.query('begin');
 await connection.query(`insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,confirmation_token,recovery_token,email_change_token_new,email_change_token_current,email_change,reauthentication_token,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,is_sso_user,is_anonymous)
 values('00000000-0000-0000-0000-000000000000',$1::uuid,'authenticated','authenticated',$2,extensions.crypt($3,extensions.gen_salt('bf',10)),now(),'','','','','','','{"provider":"email","providers":["email"]}','{}',now(),now(),false,false)`,[managerId,managerEmail,managerPassword]);
 await connection.query(`insert into auth.identities(id,provider_id,user_id,identity_data,provider,created_at,updated_at) values(gen_random_uuid(),$1::text,$1::uuid,jsonb_build_object('sub',$1::text,'email',$2::text,'email_verified',true),'email',now(),now())`,[managerId,managerEmail]);
 await connection.query("insert into public.profiles(id,username,display_name,role_id,must_change_password) select $1::uuid,$2,$2,id,false from public.roles where name='Administrador' and system",[managerId,managerName]);
 await connection.query('commit');
 const args={p_username:childName,p_display_name:'QA Account Flow',p_password:childPassword,p_role_id:readerRole.id};
 assert.ok((await anonymous.rpc('create_managed_user',args)).error,'Anônimos não podem criar contas');
 const logged=await manager.auth.signInWithPassword({email:managerEmail,password:managerPassword});assert.equal(logged.error,null);
 browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
 const page=await browser.newPage();let edgeRequests=0;const errors=[];
 page.on('request',request=>{if(request.url().includes('/functions/v1/'))edgeRequests++;});page.on('pageerror',error=>errors.push(error.message));
 await page.goto('http://127.0.0.1:5173');await page.getByLabel('Usuário',{exact:true}).fill(managerName);await page.getByLabel('Senha',{exact:true}).fill(managerPassword);await page.getByRole('button',{name:'Entrar no workspace'}).click();await page.getByRole('heading',{name:'Visão geral.'}).waitFor();
 await page.getByRole('button',{name:'Equipe e acessos',exact:true}).click();await page.getByRole('button',{name:'Criar conta',exact:true}).click();
 const dialog=page.getByRole('dialog',{name:'Criar conta'});await dialog.getByLabel('Nome',{exact:true}).fill('QA Account Flow');await dialog.getByLabel('Usuário',{exact:true}).fill(childName);await dialog.getByLabel('Senha inicial',{exact:true}).fill(childPassword);await dialog.getByLabel('Perfil de acesso').selectOption(readerRole.id);
 await dialog.getByRole('button',{name:'Mostrar senha',exact:true}).click();assert.equal(await dialog.getByLabel('Senha inicial',{exact:true}).getAttribute('type'),'text');await dialog.getByRole('button',{name:'Ocultar senha',exact:true}).click();
 await dialog.getByRole('button',{name:'Criar conta',exact:true}).click();await dialog.waitFor({state:'hidden'});await page.locator('.member').filter({hasText:childName}).waitFor();
 const {rows:[profile]}=await connection.query('select id,must_change_password from public.profiles where username=$1',[childName]);childId=profile.id;assert.equal(profile.must_change_password,true);
 assert.equal((await child.auth.signInWithPassword({email:childEmail,password:childPassword})).error,null,'A conta criada precisa autenticar no Supabase');
 assert.equal((await child.auth.updateUser({password:changedPassword})).error,null);
 await connection.query("insert into public.user_permission_overrides(user_id,permission,granted,updated_by) values($1,'users.manage',false,$2)",[childId,managerId]);
 const denied=await child.rpc('create_managed_user',{...args,p_username:`qa_denied_${suffix}`});assert.ok(denied.error);assert.match(denied.error.message,/Sem permissão/);
 assert.match((await manager.rpc('create_managed_user',{...args,p_username:childName.toUpperCase()})).error.message,/já está cadastrado/);
 assert.match((await manager.rpc('create_managed_user',{...args,p_username:`qa_short_${suffix}`,p_password:'short'})).error.message,/senha/);
 assert.ok((await manager.rpc('update_managed_user',{p_user:managerId,p_role_id:readerRole.id,p_active:false})).error,'Não pode alterar a própria conta');
 assert.equal((await manager.rpc('update_managed_user',{p_user:childId,p_role_id:readerRole.id,p_active:false})).error,null);
 assert.equal((await child.rpc('is_member')).data,false,'Desativação bloqueia acesso mesmo com JWT anterior');
 assert.equal((await manager.rpc('update_managed_user',{p_user:childId,p_role_id:readerRole.id,p_active:true})).error,null);
 assert.equal((await child.auth.signInWithPassword({email:childEmail,password:changedPassword})).error,null);
 assert.ok((await manager.rpc('delete_managed_user',{p_user:childId,p_confirmation:'wrong-user'})).error);
 await page.getByRole('button',{name:'Visão geral',exact:true}).click();await page.getByRole('button',{name:'Equipe e acessos',exact:true}).click();
 await page.locator('.member').filter({hasText:childName}).getByRole('button',{name:'Gerenciar',exact:true}).click();await page.getByRole('button',{name:'Excluir usuário',exact:true}).click();await page.getByLabel(`Digite ${childName} para confirmar`).fill(childName);await page.getByRole('dialog').getByRole('button',{name:'Excluir usuário',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
 const removed=(await connection.query('select active,deleted_at from public.profiles where id=$1',[childId])).rows[0];assert.equal(removed.active,false);assert.ok(removed.deleted_at);
 assert.ok((await child.auth.signInWithPassword({email:childEmail,password:changedPassword})).error,'Conta excluída não pode autenticar');
 assert.equal(edgeRequests,0,'Operações de contas não dependem de Edge Functions');assert.deepEqual(errors,[]);
 console.log('Contas: criação pela UI, login real, senha inicial visível/oculta, duplicidade, bloqueio de anônimos/leitores, desativação, reativação e exclusão validados sem Edge Function.');
}finally{
 if(browser)await browser.close();await manager.auth.signOut({scope:'local'}).catch(()=>{});await child.auth.signOut({scope:'local'}).catch(()=>{});
 await connection.query('rollback').catch(()=>{});
 const fixtureIds=(await connection.query('select id from auth.users where id=$1::uuid or email=$2 or email=$3',[managerId,managerEmail,childEmail])).rows.map(row=>row.id);if(childId&&!fixtureIds.includes(childId))fixtureIds.push(childId);
 if(fixtureIds.length){await connection.query('begin');await connection.query('delete from public.user_permission_overrides where user_id=any($1::uuid[]) or updated_by=any($1::uuid[])',[fixtureIds]);await connection.query('delete from public.audit_events where actor_id=any($1::uuid[]) or entity_id=any($2::text[])',[fixtureIds,fixtureIds]);await connection.query('delete from public.profiles where id=any($1::uuid[])',[fixtureIds]);await connection.query('delete from auth.users where id=any($1::uuid[])',[fixtureIds]);await connection.query('commit');}
 await connection.end();
}
