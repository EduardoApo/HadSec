import {normalizeHunting} from './hunting-normalizer.mjs';
import {evidenceBucket,verifyEvidence} from './evidence.mjs';
export async function huntingImportAction({body,client,admin,user}){
 const check=async p=>{const {data,error}=await p;if(error)throw Error(error.message);return data;};
 if(!['chainsaw','hayabusa','velociraptor','structured'].includes(body.source))throw Error('Informe a origem do arquivo estruturado.');
 const file=await check(client.from('operational_evidence').select('*').eq('id',body.file_id).eq('subject_id',body.hypothesis_id).eq('status','ready').maybeSingle());
 if(!file||!['application/json','text/csv','text/plain'].includes(file.mime))throw Error('Selecione uma evidência estruturada e verificada desta hipótese.');
 const hypothesis=await check(client.from('hunting_hypotheses').select('id').eq('id',body.hypothesis_id).maybeSingle());if(!hypothesis)throw Error('Hipótese indisponível.');
 const blob=await check(admin.storage.from(evidenceBucket).download(file.storage_path));const bytes=await blob.arrayBuffer();await verifyEvidence(bytes,file);
 const config=body.mapping||{},prepared=normalizeHunting(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{...config,source:body.source,format:config.format||(file.original_name.toLowerCase().endsWith('.csv')?'csv':'json')});
 if(body.action==='hunting.import-preview')return {total:prepared.total,missingDates:prepared.missingDates,fields:prepared.fields,mapping:prepared.mapping,adapterVersion:prepared.adapterVersion,sample:prepared.rows.slice(0,10)};
 if(body.action!=='hunting.import')throw Error('Ação de importação desconhecida.');
 if(!Object.values(prepared.mapping.fields).some(Boolean))throw Error('Mapeie pelo menos um campo antes de importar.');
 if(prepared.missingDates&&body.allow_missing_dates!==true)throw Error(prepared.missingDates+' eventos não têm data normalizada. Revise o mapeamento ou confirme essa condição antes de importar.');
 const run=await check(admin.rpc('begin_hunting_import',{p_actor:user.id,p_hypothesis:body.hypothesis_id,p_file:file.id,p_source:body.source,p_adapter:prepared.adapterVersion,p_mapping:prepared.mapping,p_count:prepared.total,p_missing_dates:prepared.missingDates,p_rule:body.rule_id||null}));
 if(run.unchanged)return {ok:true,id:run.id,total:run.total,missingDates:prepared.missingDates,unchanged:true};
 try{let batch=[],size=0;const flush=async()=>{if(batch.length){await check(admin.from('hunting_event_staging').insert(batch));batch=[];size=0;}};
  for(const row of prepared.rows){const entry={import_id:run.id,record_index:row.record_index,entry:row},bytes=new TextEncoder().encode(JSON.stringify(entry)).length;if(size+bytes>300000||batch.length>=75)await flush();batch.push(entry);size+=bytes;}await flush();
  return await check(admin.rpc('publish_hunting_import',{p_import:run.id,p_actor:user.id}));
 }catch(e){await check(admin.from('hunting_imports').update({status:'failed',active:false,finished_at:new Date().toISOString(),error:String(e.message).slice(0,1500)}).eq('id',run.id));await check(admin.from('hunting_event_staging').delete().eq('import_id',run.id));throw e;}
}
