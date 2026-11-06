import {createClient} from '@supabase/supabase-js';
const {SUPABASE_URL,SUPABASE_SERVICE_ROLE_KEY,BOOTSTRAP_USERNAME,BOOTSTRAP_PASSWORD,BOOTSTRAP_EMAIL}=process.env;
if(!SUPABASE_URL||!BOOTSTRAP_PASSWORD)throw new Error('Preencha SUPABASE_URL e BOOTSTRAP_PASSWORD no .env.');
if(!SUPABASE_SERVICE_ROLE_KEY){const {bootstrapDatabase}=await import('./bootstrap-database.mjs');await bootstrapDatabase();process.exit(0);}
const db=createClient(SUPABASE_URL,SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false}});
const checked=async(p)=>{const {data,error}=await p;if(error)throw new Error(error.message);return data;};
const username=BOOTSTRAP_USERNAME||'Admin';
const role=await checked(db.from('roles').select('id').eq('name','Administrador').single());
const prior=await checked(db.from('profiles').select('id').eq('username',username).maybeSingle());
if(prior){console.log('Administrador já existe. Nenhuma senha foi alterada.');process.exit(0);}
const {user}=await checked(db.auth.admin.createUser({email:BOOTSTRAP_EMAIL||`${username.toLowerCase()}@hadsec.local`,password:BOOTSTRAP_PASSWORD,email_confirm:true}));
try{await checked(db.from('profiles').insert({id:user.id,username,display_name:username,role_id:role.id,must_change_password:true}));}
catch(e){await db.auth.admin.deleteUser(user.id);throw e;}
console.log('Administrador criado. A alteração de senha será exigida no primeiro acesso.');
