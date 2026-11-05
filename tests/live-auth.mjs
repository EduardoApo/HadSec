import {chromium} from '@playwright/test';
import pg from 'pg';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';

// Explicit live integration test. Creates only its own short-lived Reader fixture.
// Existing accounts and their passwords are never changed.
const sql=new pg.Client({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:true,ca:await readFile(new URL('../certs/supabase-root.crt',import.meta.url),'utf8')},connectionTimeoutMillis:15000});
const id=randomUUID(),username=`qa_auth_${id.replaceAll('-','').slice(0,12)}`,email=`${username}@hadsec.local`;
const firstPassword=randomUUID(),newPassword=randomUUID();
let browser,fixtureCreated=false;
await sql.connect();
try{
 await sql.query('begin');
 await sql.query(`insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,confirmation_token,recovery_token,email_change_token_new,email_change_token_current,email_change,reauthentication_token,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,is_sso_user,is_anonymous)
 values('00000000-0000-0000-0000-000000000000',$1::uuid,'authenticated','authenticated',$2,extensions.crypt($3,extensions.gen_salt('bf',10)),now(),'','','','','','','{"provider":"email","providers":["email"]}','{}',now(),now(),false,false)`,[id,email,firstPassword]);
 await sql.query(`insert into auth.identities(id,provider_id,user_id,identity_data,provider,created_at,updated_at) values(gen_random_uuid(),$1::text,$1::uuid,jsonb_build_object('sub',$1::text,'email',$2::text,'email_verified',true),'email',now(),now())`,[id,email]);
 await sql.query("insert into public.profiles(id,username,display_name,role_id,must_change_password) select $1::uuid,$2,$2,id,true from public.roles where name<>'Administrador' order by cardinality(permissions),id limit 1",[id,username]);
 await sql.query('commit');fixtureCreated=true;
 browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:900}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://127.0.0.1:5173');
 await page.getByLabel('Usuário',{exact:true}).fill(username);await page.getByLabel('Senha',{exact:true}).fill(firstPassword);await page.getByRole('button',{name:'Entrar no workspace'}).click();
 await page.getByRole('dialog',{name:'Defina sua nova senha'}).waitFor();
 await page.getByLabel('Senha atual',{exact:true}).fill('incorrect-current-password');await page.getByLabel('Nova senha',{exact:true}).fill(newPassword);await page.getByLabel('Confirmar nova senha',{exact:true}).fill(newPassword);
 for(const [field,label] of [['Senha atual','senha atual'],['Nova senha','nova senha'],['Confirmar nova senha','confirmação de senha']]){const input=page.getByLabel(field,{exact:true}),before=await input.inputValue();await page.getByRole('button',{name:`Mostrar ${label}`,exact:true}).click();assert.equal(await input.getAttribute('type'),'text');assert.equal(await input.inputValue(),before);await page.getByRole('button',{name:`Ocultar ${label}`,exact:true}).click();assert.equal(await input.getAttribute('type'),'password');}
 await page.getByRole('button',{name:'Alterar senha',exact:true}).click();
 await page.getByRole('status').waitFor();
 assert.equal((await sql.query('select must_change_password from public.profiles where id=$1',[id])).rows[0].must_change_password,true,'Senha atual incorreta não pode liberar a conta');
 await page.getByLabel('Senha atual',{exact:true}).fill(firstPassword);await page.getByRole('button',{name:'Alterar senha',exact:true}).click();await page.getByRole('dialog').waitFor({state:'hidden'});
 await page.getByRole('heading',{name:'Visão geral.'}).waitFor();
 assert.equal((await sql.query('select must_change_password from public.profiles where id=$1',[id])).rows[0].must_change_password,false);
 assert.deepEqual(errors,[]);
 console.log('Supabase real: login obrigatório, mostrar/ocultar em todos os campos de troca, senha atual incorreta bloqueada e painel liberado após a troca. Conta temporária removida; contas existentes preservadas.');
}finally{
 if(browser)await browser.close();
 await sql.query('rollback').catch(()=>{});
 if(fixtureCreated){await sql.query('begin');await sql.query('delete from public.audit_events where actor_id=$1::uuid or entity_id=$1::text',[id]);await sql.query('delete from public.profiles where id=$1',[id]);await sql.query('delete from auth.users where id=$1',[id]);await sql.query('commit');}
 await sql.end();
}
