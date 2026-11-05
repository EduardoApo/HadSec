import {createClient} from '@supabase/supabase-js';
import {validateRule} from '../_shared/validator.mjs';
const env=(k:string)=>Deno.env.get(k)||'';
const admin=createClient(env('SUPABASE_URL'),env('SUPABASE_SERVICE_ROLE_KEY'),{auth:{persistSession:false,autoRefreshToken:false}});
const checked=async (p:any)=>{const {data,error}=await p;if(error)throw new Error(error.message);return data;};
const requireText=(s:any,min=1,max=8000)=>{if(typeof s!=='string'||s.trim().length<min||s.length>max)throw new Error('Campo inválido');return s.trim();};
const github=async(path:string,method='GET',body?:any)=>{
 const res=await fetch(`https://api.github.com/repos/${encodeURIComponent(env('GITHUB_OWNER'))}/${encodeURIComponent(env('GITHUB_REPO'))}${path}`,{method,headers:{Authorization:`Bearer ${env('GITHUB_TOKEN')}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
 const data=await res.json();if(!res.ok)throw new Error(`GitHub ${res.status}: ${data.message||'Falha na operação'}`);return data;
};
Deno.serve(async(req:Request)=>{
 const origin=env('APP_ORIGIN');const headers={'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin','Content-Type':'application/json','Cache-Control':'no-store'};
 const respond=(data:any,status=200)=>new Response(JSON.stringify(data),{status,headers});
 if(req.headers.get('origin')&&req.headers.get('origin')!==origin)return respond({error:'Origem não permitida'},403);
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return respond({error:'Método não permitido'},405);
 try {
  if(Number(req.headers.get('content-length')||0)>600000)return respond({error:'Payload excede 600 KB'},413);
  const text=await req.text();if(text.length>600000)return respond({error:'Payload excede 600 KB'},413);
  const body=JSON.parse(text);const token=req.headers.get('Authorization')?.replace(/^Bearer /i,'');
  if(!token)return respond({error:'Sessão necessária'},401);
  const {data:{user},error}=await admin.auth.getUser(token);if(error||!user)return respond({error:'Sessão inválida'},401);
  const profile=await checked(admin.from('profiles').select('*,roles(*)').eq('id',user.id).single());
  if(!profile.active)return respond({error:'Conta desativada'},403);
  const overrides=await checked(admin.from('user_permission_overrides').select('permission,granted').eq('user_id',user.id));
  const permit=(p:string)=>{if(!(overrides.find((o:any)=>o.permission===p)?.granted??profile.roles.permissions.includes(p)))throw new Error('Sem permissão para esta ação');};
  const client=createClient(env('SUPABASE_URL'),env('SUPABASE_ANON_KEY'),{global:{headers:{Authorization:`Bearer ${token}`}},auth:{persistSession:false}});
  if(profile.must_change_password)return respond({error:'Altere sua senha inicial antes de continuar'},403);
  if(body.action==='user.create') {
   const id=await checked(client.rpc('create_managed_user',{p_username:body.username,p_display_name:body.display_name,p_password:body.password,p_role_id:body.role_id}));return respond({ok:true,id});
  }
  if(body.action==='user.update') {
   await checked(client.rpc('update_managed_user',{p_user:body.id,p_role_id:body.role_id,p_active:body.active}));return respond({ok:true});
  }
  if(body.action==='user.delete') {
   await checked(client.rpc('delete_managed_user',{p_user:body.id,p_confirmation:body.confirmation}));return respond({ok:true});
  }
  if(body.action==='validate') {
   permit('rules.write');const v=await checked(admin.from('rule_versions').select('*,rules(format,mode)').eq('id',body.version_id).single());
   const report=validateRule(v.content,v.rules.format,v.rules.mode);
   await checked(admin.from('rule_versions').update({validated:report.ok,validation_report:report}).eq('id',v.id));
   await checked(admin.from('audit_events').insert({actor_id:user.id,action:'version.validated',entity_id:v.id,detail:{ok:report.ok,engine:report.engine}}));
   return respond(report);
  }
  if(body.action==='github.status'){permit('github.publish');return respond({configured:!!(env('GITHUB_TOKEN')&&env('GITHUB_OWNER')&&env('GITHUB_REPO')),repository:env('GITHUB_OWNER')&&env('GITHUB_REPO')?`${env('GITHUB_OWNER')}/${env('GITHUB_REPO')}`:null,branch:env('GITHUB_BASE_BRANCH')||'main'});}
  if(body.action==='github.publish') {
   permit('github.publish');if(!env('GITHUB_TOKEN')||!env('GITHUB_OWNER')||!env('GITHUB_REPO'))throw new Error('Configure os secrets GitHub no Supabase');
   const r=await checked(client.from('change_requests').select('*,rule_versions(*),rules(*)').eq('id',body.request_id).single());
   if(r.status==='published')return respond({ok:true,url:r.github_url});
   await checked(client.rpc('claim_export',{p_request:r.id}));
   try {
    const branch=`hadsec/${r.id}`,base=env('GITHUB_BASE_BRANCH')||'main';
    const ref=await github(`/git/ref/heads/${encodeURIComponent(base)}`);
    try{await github(`/git/ref/heads/${encodeURIComponent(branch)}`);}catch(e){if(!String(e).includes('404'))throw e;await github('/git/refs','POST',{ref:`refs/heads/${branch}`,sha:ref.object.sha});}
    const v=r.rule_versions;const path=`rules/${r.rules.id}/v${v.number}.${r.rules.format}`;
    const bytes=new TextEncoder().encode(v.content);let binary='';
    for(let offset=0;offset<bytes.length;offset+=8192)binary+=String.fromCharCode(...bytes.subarray(offset,offset+8192));
    const encoded=btoa(binary);
    let existing:any=null;try{existing=await github(`/contents/${path}?ref=${encodeURIComponent(branch)}`);}catch(e){if(!String(e).includes('404'))throw e;}
    if(existing){if(existing.content.replace(/\s/g,'')!==encoded)throw new Error('Conteúdo do branch diverge da versão aprovada');}
    else await github(`/contents/${path}`,'PUT',{message:`feat(detection): ${r.rules.name} v${v.number}`,content:encoded,branch});
    const prs=await github(`/pulls?state=all&head=${encodeURIComponent(env('GITHUB_OWNER')+':'+branch)}`);
    let pr=prs.find((p:any)=>p.head.ref===branch);
    if(pr?.state==='closed'&&!pr.merged_at)throw new Error('Pull request fechado sem merge; reabra-o no GitHub antes de reenviar');
    if(!pr)pr=await github('/pulls','POST',{title:`${r.rules.name} · v${v.number}`,head:branch,base,body:`Aprovado no HadSec Detect.\n\nFortiSIEM: 7.5.1.0620\nVersão: ${v.id}\nSHA-256: ${v.content_sha256}\nRevisor: ${r.reviewed_by}\n\n${r.review_note}\n\nA importação e ativação no FortiSIEM continuam manuais.`});
    await checked(admin.from('change_requests').update({status:'published',github_url:pr.html_url,exported_sha:v.content_sha256,export_lease_until:null,updated_at:new Date().toISOString()}).eq('id',r.id).eq('status','approved'));
    await checked(admin.from('audit_events').insert({actor_id:user.id,action:'github.pr_created',entity_id:r.id,detail:{url:pr.html_url,sha256:v.content_sha256}}));
    return respond({ok:true,url:pr.html_url});
   }catch(e){await admin.from('change_requests').update({export_lease_until:null}).eq('id',r.id);throw e;}
  }
  return respond({error:'Ação desconhecida'},400);
 }catch(e){return respond({error:e instanceof Error?e.message:'Falha na operação'},400);}
});
