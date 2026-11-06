import {readFile,writeFile} from 'node:fs/promises';
import {ownerRenameSQL} from './owner-rename-sql.mjs';
const username=process.argv[2]||'Admin';
const sql=ownerRenameSQL(username),url=process.env.SUPABASE_URL,token=process.env.SUPABASE_ACCESS_TOKEN;
if(!url||!token)throw Error('Preencha SUPABASE_URL e SUPABASE_ACCESS_TOKEN no .env local.');
async function query(query){
 const response=await fetch(`https://api.supabase.com/v1/projects/${new URL(url).hostname.split('.')[0]}/database/query`,{
  method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({query}),signal:AbortSignal.timeout(20000)
 });
 const result=await response.json();if(!response.ok)throw Error(result.message||result.error||'Falha na alteração do usuário.');return result;
}
await query(sql);
const [state]=await query(`select p.username,p.display_name,p.active,
 u.email=lower(p.username)||'@hadsec.local' as auth_consistent,
 exists(select 1 from auth.identities i where i.user_id=p.id and i.provider='email' and i.identity_data->>'email'=u.email) as identity_consistent
 from public.workspace_owner o join public.profiles p on p.id=o.user_id join auth.users u on u.id=p.id`);
if(state?.username!==username||!state.active||!state.auth_consistent||!state.identity_consistent)throw Error('Confira a consistência do usuário proprietário.');
const path=new URL('../.env',import.meta.url);let env=await readFile(path,'utf8');
for(const [key,value]of [['BOOTSTRAP_USERNAME',username],['BOOTSTRAP_EMAIL',username.toLowerCase()+'@hadsec.local']]){
 const expression=new RegExp('^'+key+'=.*$','m');env=expression.test(env)?env.replace(expression,key+'='+value):env+'\n'+key+'='+value+'\n';
}
await writeFile(path,env);
console.log(JSON.stringify({username:state.username,authAndProfileConsistent:true,ownerIdentityPreserved:true,passwordUnchanged:true,bootstrapConfigurationUpdated:true}));
