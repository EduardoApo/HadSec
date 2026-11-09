import {createClient} from '@supabase/supabase-js';
import {readSupabaseConfig} from './supabase-config.mjs';

const {url,key,configured:validConfig}=readSupabaseConfig(import.meta.env);
export const configured=validConfig;
export const db=configured?createClient(url,key):null;
export const permissions={'rules.write':'Criar e versionar regras','requests.create':'Solicitar ajustes e revisão','requests.review':'Aprovar e devolver revisões','tests.record':'Registrar testes','github.publish':'Publicar no GitHub','users.manage':'Gerenciar contas','roles.manage':'Gerenciar perfis e permissões','audit.read':'Consultar auditoria'};

// Remove browser-only state from retired versions. It never authorizes access.
try{localStorage.removeItem('hadsec-mode');localStorage.removeItem('hadsec-demo-v1');}catch{}
const check=({data,error})=>{if(error)throw new Error(error.message);return data;};
const requireDatabase=()=>{if(!db)throw new Error('O acesso está indisponível. Contate o administrador.');};

async function changeOwnPassword(payload){
 const {data:{user},error}=await db.auth.getUser();
 if(error||!user?.email)throw new Error('Sua sessão expirou. Entre novamente.');
 if(typeof payload.password!=='string'||payload.password.length<10)throw new Error('A nova senha deve ter pelo menos 10 caracteres.');
 if(payload.password===payload.currentPassword)throw new Error('A nova senha precisa ser diferente da atual.');
 const verifier=createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false,detectSessionInUrl:false,storageKey:`hadsec-password-check-${crypto.randomUUID()}`}});
 const verified=await verifier.auth.signInWithPassword({email:user.email,password:payload.currentPassword});
 if(verified.error||verified.data.user?.id!==user.id)throw new Error('Senha atual incorreta.');
 try{const {error:changeError}=await db.auth.updateUser({password:payload.password,current_password:payload.currentPassword});if(changeError)throw new Error(changeError.message);return {ok:true};}
 finally{await verifier.auth.signOut({scope:'local'});}
}

async function all(table){
 let rows=[],offset=0;
 for(;;){
  const sort=table==='permission_definitions'?'key':table==='user_permission_overrides'?'user_id':table==='rule_versions'?'number':'id';
  let query=db.from(table).select('*').order(sort,{ascending:true});
  if(table==='user_permission_overrides')query=query.order('permission');else if(sort==='number')query=query.order('id');
  const page=check(await query.range(offset,offset+999));rows.push(...page);if(page.length<1000)return rows;offset+=1000;
 }
}
export async function loadData(onProgress){
 requireDatabase();
 let completed=0;const tables=['roles','profiles','rules','rule_versions','change_requests','test_evidence','comments','audit_events','permission_definitions','user_permission_overrides'];
 const reportProgress=()=>{if(typeof onProgress==='function')onProgress(++completed,tables.length+1);};
 const [[roles,profiles,rules,versions,requests,evidence,comments,audit,permissionDefinitions,overrides],capabilities]=await Promise.all([
  Promise.all(tables.map(async table=>{const rows=await all(table);reportProgress();return rows;})),
  rpc('record_capabilities').then(value=>{reportProgress();return value;})
 ]);
 audit.sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
 Object.assign(permissions,Object.fromEntries(permissionDefinitions.map(d=>[d.key,d.label])));
 return {roles,profiles,rules,versions,requests,evidence,comments,audit,permissionDefinitions,overrides,capabilities};
}
export async function loadRequests(){requireDatabase();return all('change_requests');}
export async function gateway(action,payload={}){
 requireDatabase();
 if(action==='password')return changeOwnPassword(payload);
 if(action==='user.create'){const id=await rpc('create_managed_user',{p_username:payload.username,p_display_name:payload.display_name,p_password:payload.password,p_role_id:payload.role_id});return {ok:true,id};}
 if(action==='user.update'){await rpc('update_managed_user',{p_user:payload.id,p_role_id:payload.role_id,p_active:payload.active});return {ok:true};}
 if(action==='user.delete'){await rpc('delete_managed_user',{p_user:payload.id,p_confirmation:payload.confirmation});return {ok:true};}
 const {data:{session},error}=await db.auth.getSession();
 if(error||!session?.access_token)throw new Error('Sua sessão expirou. Entre novamente.');
 let response;
 try{response=await fetch('/api/gateway',{method:'POST',headers:{Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},body:JSON.stringify({action,...payload}),signal:AbortSignal.timeout(action.endsWith('.sync')||action==='hunting.import'?240000:45000)});}
 catch(e){throw new Error(e.name==='TimeoutError'?'A operação demorou a responder. Tente novamente.':'Não foi possível conectar ao serviço. Verifique sua conexão e tente novamente.');}
 const data=await response.json().catch(()=>null);
 if(!data)throw new Error('O serviço da aplicação não está disponível nesta publicação.');
 if(!response.ok||data.error)throw new Error(data.error||'Não foi possível concluir a operação.');
 return data;
}
export async function rpc(name,parameters){requireDatabase();return check(await db.rpc(name,parameters));}
