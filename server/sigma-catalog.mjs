import {parseDocument} from 'yaml';
import {officialCommit} from './catalog-fetch.mjs';
import {officialTar} from './official-tar.mjs';
export const digest=async text=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)))].map(n=>n.toString(16).padStart(2,'0')).join('');
export function safeYAML(text){
 if(typeof text!=='string'||new TextEncoder().encode(text).length>500000)throw Error('YAML excede 500 KB.');
 const doc=parseDocument(text,{uniqueKeys:true,customTags:[],maxAliasCount:20});if(doc.errors.length)throw Error('YAML inválido: '+doc.errors[0].message.split('\n')[0]);if(doc.warnings.some(w=>w.code==='TAG_RESOLVE_FAILED'))throw Error('Tag YAML não permitida.');
 const data=doc.toJS({maxAliasCount:20});let fields=0;
 function visit(v,depth=0){if(depth>30||++fields>30000)throw Error('YAML excede limites de estrutura.');if(v&&typeof v==='object'){for(const k of Object.keys(v)){if(['__proto__','constructor','prototype'].includes(k))throw Error('Chave YAML não permitida.');visit(v[k],depth+1);}}}visit(data);return data;
}
export async function sigmaEntry(path,text){
 const d=safeYAML(text);if(!d||typeof d!=='object'||!/^[a-f0-9-]{36}$/i.test(d.id)||typeof d.title!=='string'||!d.logsource||!d.detection)throw Error('Regra Sigma incompleta: '+path);
 return {id:d.id.toLowerCase(),title:d.title.slice(0,300),description:String(d.description||'').slice(0,15000),level:String(d.level||'unspecified'),status:String(d.status||'unspecified'),category:String(d.logsource.category||d.logsource.product||'other'),logsource:d.logsource,tags:Array.isArray(d.tags)?d.tags.map(String):[],techniques:(d.tags||[]).filter(t=>/^attack\.t\d{4}(\.\d{3})?$/i.test(t)).map(t=>t.slice(7).toUpperCase()),details:{detection:d.detection,condition:d.detection.condition,falsepositives:d.falsepositives||[],author:d.author||'',references:d.references||[],date:d.date,modified:d.modified,license:d.license||'DRL-1.1'},original:text,path,sha256:await digest(text)};
}
export async function synchronizeSigma({client,admin,fetchImpl=fetch}){
 const check=async p=>{const {data,error}=await p;if(error)throw Error(error.message);return data;};const run=await check(client.rpc('begin_reference_sync',{p_source:'sigma'}));
 try{
  const commit=await officialCommit('SigmaHQ/sigma','master',fetchImpl);
  const last=await check(admin.from('reference_sync_runs').select('id,commit,total').eq('source','sigma').eq('status','success').eq('commit',commit).order('started_at',{ascending:false}).limit(1));
  if(last.length)return await check(admin.rpc('finish_reference_sync',{p_run:run,p_commit:commit,p_unchanged:true}));
  const accept=path=>/^(rules|rules-emerging-threats|rules-threat-hunting|rules-dfir|rules-compliance)\/.*\.ya?ml$/.test(path);
  let batch=[],count=0;const ids=new Set();
  for await(const file of officialTar('https://codeload.github.com/SigmaHQ/sigma/tar.gz/'+commit,accept,{fetchImpl})){
   const entry=await sigmaEntry(file.path,file.text);if(ids.has(entry.id))throw Error('UUID Sigma duplicado: '+entry.id);ids.add(entry.id);batch.push({run_id:run,source:'sigma',id:entry.id,entry});count++;
   if(batch.length===75){await check(admin.from('reference_staging').insert(batch));batch=[];}
  }
  if(batch.length)await check(admin.from('reference_staging').insert(batch));if(count<100)throw Error('Catálogo Sigma incompleto: menos de 100 regras.');
  return await check(admin.rpc('finish_reference_sync',{p_run:run,p_commit:commit,p_unchanged:false}));
 }catch(e){await check(admin.from('reference_sync_runs').update({status:'failed',error:String(e.message).slice(0,1500),finished_at:new Date().toISOString()}).eq('id',run));await check(admin.from('reference_staging').delete().eq('run_id',run));throw e;}
}
