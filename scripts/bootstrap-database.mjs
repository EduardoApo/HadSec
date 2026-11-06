import pg from 'pg';
import {readFile} from 'node:fs/promises';
import {createClient} from '@supabase/supabase-js';

// One-time administrator provisioning using the explicitly supplied project database access.
// This is a setup script only, never a browser API or a replacement for the Auth Admin API.
export async function bootstrapDatabase(){
 const username=process.env.BOOTSTRAP_USERNAME||'Admin';
 const email=process.env.BOOTSTRAP_EMAIL||`${username.toLowerCase()}@hadsec.local`;
 const password=process.env.BOOTSTRAP_PASSWORD;
 if(!process.env.DATABASE_URL||!password)throw new Error('Preencha DATABASE_URL e BOOTSTRAP_PASSWORD no .env.');
 if(!/^[A-Za-z0-9_.-]{3,40}$/.test(username))throw new Error('BOOTSTRAP_USERNAME inválido.');
 const connection=new pg.Client({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:true,ca:await readFile(new URL('../certs/supabase-root.crt',import.meta.url),'utf8')},connectionTimeoutMillis:15000});
 let created=false;
 try{
  await connection.connect();await connection.query('begin');
  await connection.query("select pg_advisory_xact_lock(hashtext('hadsec.bootstrap.admin'))");
  const prior=await connection.query('select id from public.profiles where lower(username)=lower($1)',[username]);
  if(prior.rows.length){await connection.query('rollback');console.log('Administrador já existe. Nenhuma senha foi alterada.');return;}
  const orphan=await connection.query('select id from auth.users where lower(email)=lower($1)',[email]);
  if(orphan.rows.length)throw new Error('Já existe uma identidade com o e-mail do administrador. Nenhuma conta foi promovida ou alterada.');
  const role=await connection.query("select id from public.roles where name='Administrador' and system=true");
  if(role.rows.length!==1)throw new Error('Aplique as migrações do HadSec antes de criar o administrador.');
  const {rows:[user]}=await connection.query(`
   insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,
    confirmation_token,recovery_token,email_change_token_new,email_change_token_current,email_change,
    reauthentication_token,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,is_sso_user,is_anonymous)
   values('00000000-0000-0000-0000-000000000000',gen_random_uuid(),'authenticated','authenticated',$1,
    extensions.crypt($2,extensions.gen_salt('bf',10)),now(),'','','','','','',
    '{"provider":"email","providers":["email"]}'::jsonb,jsonb_build_object('username',$3::text),now(),now(),false,false)
   returning id`,[email,password,username]);
  await connection.query(`insert into auth.identities(id,provider_id,user_id,identity_data,provider,created_at,updated_at)
   values(gen_random_uuid(),$1::text,$1::uuid,jsonb_build_object('sub',$1::text,'email',$2::text,'email_verified',true,'phone_verified',false),'email',now(),now())`,[user.id,email]);
  await connection.query('insert into public.profiles(id,username,display_name,role_id,must_change_password) values($1,$2,$2,$3,true)',[user.id,username,role.rows[0].id]);
  await connection.query("insert into public.audit_events(actor_id,action,entity_id,detail) values($1::uuid,'user.bootstrap_created',$1::text,'{\"method\":\"database_setup\"}')",[user.id]);
  await connection.query('commit');created=true;
 }catch(error){await connection.query('rollback').catch(()=>{});throw error;}finally{await connection.end();}
 if(created){
  const auth=createClient(process.env.SUPABASE_URL,process.env.VITE_SUPABASE_ANON_KEY,{auth:{persistSession:false}});
  const {data,error}=await auth.auth.signInWithPassword({email,password});
  if(error)throw new Error(`Conta criada, mas o teste de autenticação falhou: ${error.message}`);
  if(!data.user)throw new Error('Conta criada, mas o teste de autenticação não retornou usuário.');
  await auth.auth.signOut({scope:'local'});console.log('Administrador criado e login validado pelo Supabase Auth. Troca de senha obrigatória no primeiro acesso.');
 }
}
