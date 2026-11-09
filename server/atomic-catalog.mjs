import {safeYAML,digest} from './sigma-catalog.mjs';
import {officialCommit} from './catalog-fetch.mjs';
import {officialTar} from './official-tar.mjs';
export async function atomicEntries(path,text){
 const doc=safeYAML(text);if(!/^T\d{4}(\.\d{3})?$/.test(doc?.attack_technique)||!Array.isArray(doc.atomic_tests))throw Error('Arquivo Atomic incompleto: '+path);
 const fileSha=await digest(text),entries=[];
 for(const test of doc.atomic_tests){
  if(!/^[a-f0-9-]{36}$/i.test(test.auto_generated_guid)||typeof test.name!=='string'||!test.executor||!Array.isArray(test.supported_platforms))throw Error('Teste Atomic incompleto: '+path);
  entries.push({id:test.auto_generated_guid.toLowerCase(),title:test.name.slice(0,300),description:String(test.description||'').slice(0,15000),level:'not_applicable',status:'reference',category:test.supported_platforms[0]||'other',logsource:{platforms:test.supported_platforms},tags:[doc.attack_technique],techniques:[doc.attack_technique],details:{name:test.name,description:test.description||'',technique:doc.attack_technique,technique_name:doc.display_name,executor:test.executor,input_arguments:test.input_arguments||{},dependencies:test.dependencies||[],dependency_executor_name:test.dependency_executor_name||'',supported_platforms:test.supported_platforms},original:'',file_sha256:fileSha,path,sha256:await digest(JSON.stringify({technique:doc.attack_technique,test}))});
 }
 return {entries,file:{source:'atomic',sha256:fileSha,original:text,path}};
}
export async function synchronizeAtomic({client,admin,fetchImpl=fetch}){
 const check=async p=>{const {data,error}=await p;if(error)throw Error(error.message);return data;};const run=await check(client.rpc('begin_reference_sync',{p_source:'atomic'}));
 try{
  const commit=await officialCommit('redcanaryco/atomic-red-team','master',fetchImpl);
  const last=await check(admin.from('reference_sync_runs').select('id').eq('source','atomic').eq('status','success').eq('commit',commit).limit(1));if(last.length)return await check(admin.rpc('finish_reference_sync',{p_run:run,p_commit:commit,p_unchanged:true}));
  let files=[],entries=[],count=0;const seen=new Set();
  const flush=async()=>{if(files.length){await check(admin.from('reference_source_files').upsert(files,{onConflict:'source,sha256',ignoreDuplicates:true}));files=[];}if(entries.length){await check(admin.from('reference_staging').insert(entries));entries=[];}};
  for await(const item of officialTar('https://codeload.github.com/redcanaryco/atomic-red-team/tar.gz/'+commit,p=>/^atomics\/T\d{4}(\.\d{3})?\/T\d{4}(\.\d{3})?\.ya?ml$/.test(p),{fetchImpl,maxExpanded:350000000})){
   const parsed=await atomicEntries(item.path,item.text);files.push({...parsed.file,sync_id:run});for(const entry of parsed.entries){if(seen.has(entry.id))throw Error('GUID Atomic duplicado: '+entry.id);seen.add(entry.id);entries.push({run_id:run,source:'atomic',id:entry.id,entry});count++;}if(files.length>=25||entries.length>=75)await flush();
  }await flush();if(count<100)throw Error('Catálogo Atomic incompleto: menos de 100 testes.');return await check(admin.rpc('finish_reference_sync',{p_run:run,p_commit:commit,p_unchanged:false}));
 }catch(e){await check(admin.from('reference_sync_runs').update({status:'failed',error:String(e.message).slice(0,1500),finished_at:new Date().toISOString()}).eq('id',run));await check(admin.from('reference_staging').delete().eq('run_id',run));throw e;}
}
