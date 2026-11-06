import {createClient} from '@supabase/supabase-js';
import {validateRule} from '../supabase/functions/_shared/validator.mjs';
import {notificationActions,buildNotifications} from './notifications.mjs';

class GatewayError extends Error {
 constructor(message,status=400,code='REQUEST_FAILED'){super(message);this.status=status;this.code=code;}
}
const checked=async promise=>{const {data,error}=await promise;if(error)throw new GatewayError(error.message);return data;};
const uuid=value=>{if(typeof value!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value))throw new GatewayError('Registro inválido.');return value;};

// Both adapters use the same authorization, persisted content and export workflow.
export function createGateway({env={},clientFactory=createClient,fetchImpl=globalThis.fetch}={}) {
 const get=name=>String(typeof env==='function'?env(name)||'':env[name]||'').trim();
 const githubConfigured=()=>Boolean(get('GITHUB_TOKEN')&&get('GITHUB_OWNER')&&get('GITHUB_REPO'));
 async function github(path,method='GET',body){
  const r=await fetchImpl(`https://api.github.com/repos/${encodeURIComponent(get('GITHUB_OWNER'))}/${encodeURIComponent(get('GITHUB_REPO'))}${path}`,{
   method,headers:{Authorization:`Bearer ${get('GITHUB_TOKEN')}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},
   ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(12000)
  });
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new GatewayError(`GitHub ${r.status}: ${data.message||'Não foi possível concluir a operação.'}`,502,'GITHUB_UNAVAILABLE');
  return data;
 }
 return async function handle(request){
  const origin=new URL(request.url).origin,requestedOrigin=request.headers.get('origin');
  const allowed=new Set([origin,...[get('APP_ORIGIN'),get('APP_ORIGINS')].flatMap(x=>x.split(',')).map(x=>x.trim()).filter(Boolean)]);
  const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Vary':'Origin','Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info','Access-Control-Allow-Methods':'POST, OPTIONS'};
  if(requestedOrigin&&allowed.has(requestedOrigin))headers['Access-Control-Allow-Origin']=requestedOrigin;
  const reply=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
  try {
   if(requestedOrigin&&!allowed.has(requestedOrigin))throw new GatewayError('Origem não permitida.',403,'ORIGIN_NOT_ALLOWED');
   if(request.method==='OPTIONS')return new Response(null,{status:204,headers});
   if(request.method!=='POST')throw new GatewayError('Método não permitido.',405);
   const token=/^Bearer\s+(.+)$/i.exec(request.headers.get('authorization')||'')?.[1];
   if(!token)throw new GatewayError('Entre na sua conta para continuar.',401,'SESSION_REQUIRED');
   if(Number(request.headers.get('content-length')||0)>600000)throw new GatewayError('O envio excede 600 KB.',413);
   const text=await request.text();
   if(new TextEncoder().encode(text).length>600000)throw new GatewayError('O envio excede 600 KB.',413);
   let body;try{body=JSON.parse(text);}catch{throw new GatewayError('Envie um JSON válido.');}
   if(!body||typeof body!=='object'||Array.isArray(body))throw new GatewayError('Requisição inválida.');
   const url=get('SUPABASE_URL')||get('VITE_SUPABASE_URL');
   const serviceKey=get('SUPABASE_SERVICE_ROLE_KEY')||get('SUPABASE_SECRET_KEY');
   const publicKey=get('SUPABASE_ANON_KEY')||get('SUPABASE_PUBLISHABLE_KEY')||get('VITE_SUPABASE_ANON_KEY')||get('VITE_SUPABASE_PUBLISHABLE_KEY');
   if(!url||!serviceKey||!publicKey)throw new GatewayError('A conexão do servidor com o Supabase está pendente. Consulte Conexões.',503,'SERVER_NOT_CONFIGURED');
   const admin=clientFactory(url,serviceKey,{auth:{persistSession:false,autoRefreshToken:false}});
   const authStarted=Date.now();
   const {data:{user}={},error}=await admin.auth.getUser(token);
   const authLatency=Date.now()-authStarted;
   if(error?.name==='AuthRetryableFetchError'||error?.status>=500)throw new GatewayError('O Supabase Auth não respondeu. Tente novamente.',503,'AUTH_UNAVAILABLE');
   if(error||!user)throw new GatewayError('Sua sessão expirou. Entre novamente.',401,'SESSION_EXPIRED');
   const profile=await checked(admin.from('profiles').select('*,roles(*)').eq('id',user.id).maybeSingle());
   if(!profile?.active||profile.deleted_at)throw new GatewayError('Sua conta não tem acesso ao workspace.',403,'ACCOUNT_INACTIVE');
   if(profile.must_change_password)throw new GatewayError('Altere sua senha inicial antes de continuar.',403,'PASSWORD_CHANGE_REQUIRED');
   const overrides=await checked(admin.from('user_permission_overrides').select('permission,granted').eq('user_id',user.id));
   const has=permission=>overrides.find(o=>o.permission===permission)?.granted??profile.roles?.permissions?.includes(permission);
   const permit=permission=>{if(!has(permission))throw new GatewayError('Seu perfil não tem permissão para esta ação.',403,'PERMISSION_DENIED');};
   const audit=(action,entity,detail={})=>checked(admin.from('audit_events').insert({actor_id:user.id,action,entity_id:entity,detail}));
   const client=clientFactory(url,publicKey,{global:{headers:{Authorization:`Bearer ${token}`}},auth:{persistSession:false,autoRefreshToken:false}});

   if(body.action==='connections.status'){
    const checkedAt=new Date().toISOString();
    async function probe(operation){const started=Date.now();try{await operation();return {state:'online',latencyMs:Date.now()-started};}catch{return {state:'offline',latencyMs:Date.now()-started};}}
    const [database,git]=await Promise.all([
     probe(()=>checked(client.from('roles').select('id').limit(1))),
     githubConfigured()?probe(()=>github('/git/ref/heads/'+encodeURIComponent(get('GITHUB_BASE_BRANCH')||'main'))):Promise.resolve({state:'not_configured',latencyMs:null})
    ]);
    return reply({server:true,supabase:database.state==='online',github:git.state==='online',githubConfigured:githubConfigured(),repository:has('github.publish')&&githubConfigured()?`${get('GITHUB_OWNER')}/${get('GITHUB_REPO')}`:null,checkedAt,services:{auth:{state:'online',latencyMs:authLatency},database,server:{state:'online',latencyMs:null},github:git}});
   }
   if(body.action==='notifications.list'){
    // Safe event summaries for members; detailed audit access remains audit.read.
    const events=await checked(admin.from('audit_events').select('id,action,actor_id,entity_id,created_at').in('action',notificationActions).order('id',{ascending:false}).limit(50));
    const validIds=values=>[...new Set(values.filter(value=>typeof value==='string'&&/^[0-9a-f-]{36}$/i.test(value)))];
    const fetchRows=(table,columns,ids)=>ids.length?checked(admin.from(table).select(columns).in('id',ids)):Promise.resolve([]);
    const [profiles,versions,requests]=await Promise.all([
     fetchRows('profiles','id,display_name',validIds(events.map(e=>e.actor_id))),
     fetchRows('rule_versions','id,rule_id,number',validIds(events.filter(e=>e.action.startsWith('version.')||e.action==='evidence.recorded').map(e=>e.entity_id))),
     fetchRows('change_requests','id,title,deleted_at,github_hidden_at',validIds(events.filter(e=>e.action.startsWith('request.')||e.action==='github.pr_created').map(e=>e.entity_id)))
    ]);
    const rules=await fetchRows('rules','id,name',validIds([...versions.map(v=>v.rule_id),...events.filter(e=>e.action==='rule.archived').map(e=>e.entity_id)]));
    return reply({items:buildNotifications({events,profiles,versions,requests,rules}),checkedAt:new Date().toISOString()});
   }
   if(body.action==='validate'){
    permit('rules.write');
    const v=await checked(admin.from('rule_versions').select('*,rules(format,mode,archived)').eq('id',uuid(body.version_id)).maybeSingle());
    if(!v||v.rules.archived)throw new GatewayError('Esta versão não está disponível para validação.',404);
    // Never accept a client-supplied validation result or replacement content.
    const report=validateRule(v.content,v.rules.format,v.rules.mode);
    await checked(admin.from('rule_versions').update({validated:report.ok,validation_report:report}).eq('id',v.id));
    await audit('version.validated',v.id,{ok:report.ok,engine:report.engine});
    return reply(report);
   }
   if(body.action==='rule.archive'){
    permit('rules.write');
    const rule=await checked(admin.from('rules').select('id,name,archived').eq('id',uuid(body.rule_id)).maybeSingle());
    if(!rule)throw new GatewayError('Regra não encontrada.',404);
    if(body.confirmation!==rule.name)throw new GatewayError('Digite o nome exato da regra para confirmar.');
    if(rule.archived)return reply({ok:true,archived:true});
    const linked=await checked(admin.from('change_requests').select('id').eq('rule_id',rule.id).in('status',['requested','review','changes','approved','published']).or('status.eq.published,deleted_at.is.null').limit(1));
    if(linked.length)throw new GatewayError('Esta regra está vinculada a uma solicitação em andamento ou publicada. Preserve o fluxo antes de excluí-la.',409,'RULE_IN_USE');
    await checked(admin.from('rules').update({archived:true}).eq('id',rule.id).eq('archived',false));
    await audit('rule.archived',rule.id,{name:rule.name});
    return reply({ok:true,archived:true});
   }
   if(body.action==='github.status'){
    permit('github.publish');
    const status={configured:githubConfigured(),connected:false,repository:githubConfigured()?`${get('GITHUB_OWNER')}/${get('GITHUB_REPO')}`:null,branch:get('GITHUB_BASE_BRANCH')||'main'};
    if(status.configured){try{await github('/git/ref/heads/'+encodeURIComponent(status.branch));status.connected=true;}catch{status.error='Não foi possível acessar o repositório. Confira a credencial e a branch nas conexões do servidor.';}}
    return reply(status);
   }
   if(body.action==='github.publish'){
    permit('github.publish');
    if(!githubConfigured())throw new GatewayError('A integração GitHub ainda não está configurada.',503,'GITHUB_NOT_CONFIGURED');
    const r=await checked(client.from('change_requests').select('*,rule_versions(*),rules(*)').eq('id',uuid(body.request_id)).maybeSingle());
    if(!r||r.deleted_at||r.rules?.archived)throw new GatewayError('Solicitação indisponível.',404);
    if(r.status==='published')return reply({ok:true,url:r.github_url});
    // Database RPC checks approval, evidence, caller and exclusive export lease.
    await checked(client.rpc('claim_export',{p_request:r.id}));
    try {
     const branch=`hadsec/${r.id}`,base=get('GITHUB_BASE_BRANCH')||'main';
     const ref=await github('/git/ref/heads/'+encodeURIComponent(base));
     try{await github('/git/ref/heads/'+encodeURIComponent(branch));}
     catch(e){if(!e.message.includes('GitHub 404:'))throw e;await github('/git/refs','POST',{ref:'refs/heads/'+branch,sha:ref.object.sha});}
     const v=r.rule_versions,path=`rules/${r.rules.id}/v${v.number}.${r.rules.format}`;
     const bytes=new TextEncoder().encode(v.content);let binary='';
     for(let offset=0;offset<bytes.length;offset+=8192)binary+=String.fromCharCode(...bytes.subarray(offset,offset+8192));
     const content=btoa(binary);let existing;
     try{existing=await github(`/contents/${path}?ref=${encodeURIComponent(branch)}`);}catch(e){if(!e.message.includes('GitHub 404:'))throw e;}
     if(existing&&existing.content.replace(/\s/g,'')!==content)throw new GatewayError('O conteúdo do branch diverge da versão aprovada.');
     if(!existing)await github('/contents/'+path,'PUT',{message:`feat(detection): ${r.rules.name} v${v.number}`,content,branch});
     const prs=await github('/pulls?state=all&head='+encodeURIComponent(get('GITHUB_OWNER')+':'+branch));
     let pr=prs.find(p=>p.head.ref===branch);
     if(pr?.state==='closed'&&!pr.merged_at)throw new GatewayError('O pull request foi fechado sem merge. Reabra-o no GitHub antes de reenviar.');
     if(!pr)pr=await github('/pulls','POST',{title:`${r.rules.name} · v${v.number}`,head:branch,base,body:`Aprovado no HadSec Detect.\n\nFortiSIEM: 7.5.1.0620\nVersão: ${v.id}\nSHA-256: ${v.content_sha256}\nRevisor: ${r.reviewed_by}\n\n${r.review_note}\n\nA importação e ativação no FortiSIEM continuam manuais.`});
     await checked(admin.from('change_requests').update({status:'published',github_url:pr.html_url,exported_sha:v.content_sha256,export_lease_until:null,updated_at:new Date().toISOString()}).eq('id',r.id).eq('status','approved'));
     await audit('github.pr_created',r.id,{url:pr.html_url,sha256:v.content_sha256});
     return reply({ok:true,url:pr.html_url});
    }catch(e){await admin.from('change_requests').update({export_lease_until:null}).eq('id',r.id);throw e;}
   }
   throw new GatewayError('Ação desconhecida.',400,'UNKNOWN_ACTION');
  } catch(error){
   if(error instanceof GatewayError)return reply({error:error.message,code:error.code},error.status);
   if(error?.name==='TimeoutError'||error?.name==='AbortError')return reply({error:'A conexão demorou a responder. Tente novamente.',code:'UPSTREAM_TIMEOUT'},504);
   return reply({error:'Não foi possível concluir a operação. Tente novamente.',code:'SERVER_ERROR'},500);
  }
 };
}
