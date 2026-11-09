import {fetchSource,officialCommit} from './catalog-fetch.mjs';
const ref=obj=>obj.external_references?.find(r=>r.source_name==='mitre-attack');
const value=(v,max=100000)=>typeof v==='string'?v.slice(0,max):'';
export function parseAttackBundle(bundle,{version,commit,url,sha256}){
 if(bundle?.type!=='bundle'||!Array.isArray(bundle.objects)||bundle.objects.length>100000)throw Error('Bundle STIX Enterprise inválido.');
 const objects=bundle.objects,techs=objects.filter(o=>o.type==='attack-pattern'&&/^T\d{4}(\.\d{3})?$/.test(ref(o)?.external_id));
 const byStix=new Map(techs.map(t=>[t.id,ref(t).external_id]));
 const matrix=objects.find(o=>o.type==='x-mitre-matrix'&&!o.revoked&&!o.x_mitre_deprecated&&o.name==='Enterprise ATT&CK');
 if(!matrix?.tactic_refs?.length)throw Error('Matriz Enterprise ausente no STIX.');
 const tactics=matrix.tactic_refs.map((id,ordinal)=>{const t=objects.find(o=>o.id===id);if(!t||!/^TA\d{4}$/.test(ref(t)?.external_id))throw Error('Tática inválida.');return {id:ref(t).external_id,stix_id:id,shortname:t.x_mitre_shortname,name:value(t.name,300),description:value(t.description),ordinal};});
 const relationships=objects.filter(o=>o.type==='relationship'&&!o.revoked&&(byStix.has(o.source_ref)||byStix.has(o.target_ref))).map(r=>({stix_id:r.id,source_ref:r.source_ref,target_ref:r.target_ref,relationship_type:r.relationship_type,description:value(r.description,15000)}));
 const parents=new Map(relationships.filter(r=>r.relationship_type==='subtechnique-of').map(r=>[r.source_ref,byStix.get(r.target_ref)]));
 const techniques=techs.map(t=>({id:ref(t).external_id,stix_id:t.id,name:value(t.name,300),description:value(t.description),platforms:(t.x_mitre_platforms||[]).filter(x=>typeof x==='string'),tactics:(t.kill_chain_phases||[]).filter(p=>p.kill_chain_name==='mitre-attack').map(p=>p.phase_name),parent_id:parents.get(t.id)||null,url:'https://attack.mitre.org/techniques/'+ref(t).external_id.replace('.','/')+'/',modified:t.modified||null,revoked:!!t.revoked,deprecated:!!t.x_mitre_deprecated}));
 const ids=new Set();for(const t of techniques){if(ids.has(t.id))throw Error('ID de técnica duplicado no STIX: '+t.id);ids.add(t.id);if(t.parent_id&&!byStix.has(techs.find(x=>ref(x).external_id===t.parent_id)?.id))throw Error('Técnica pai ausente.');}
 if(techniques.length<100||techniques.length>5000||tactics.length<5||tactics.length>30)throw Error('Totais MITRE fora dos limites esperados.');
 return {version,commit,url,sha256,techniques,tactics,relationships};
}
export async function downloadAttackCatalog(fetchImpl=fetch){
 const commit=await officialCommit('mitre-attack/attack-stix-data','master',fetchImpl);
 const base='https://raw.githubusercontent.com/mitre-attack/attack-stix-data/'+commit;
 const {data:index}=await fetchSource(base+'/index.json',{fetchImpl,maxBytes:2000000});
 const versions=index.collections?.find(c=>c.name==='Enterprise ATT&CK')?.versions;
 if(!versions?.length)throw Error('Índice Enterprise ATT&CK ausente.');
 const version=versions.filter(v=>/^\d+\.\d+$/.test(v.version)).sort((a,b)=>b.version.localeCompare(a.version,undefined,{numeric:true}))[0]?.version;
 if(!version)throw Error('Versão Enterprise inválida.');
 const url=base+'/enterprise-attack/enterprise-attack-'+version+'.json';
 const {data,sha256}=await fetchSource(url,{fetchImpl});return parseAttackBundle(data,{version,commit,url,sha256});
}
export async function synchronizeAttack({client,admin,fetchImpl=fetch}){
 const checked=async p=>{const {data,error}=await p;if(error)throw Error(error.message);return data;};
 const run=await checked(client.rpc('begin_attack_sync'));
 try{const catalog=await downloadAttackCatalog(fetchImpl);return await checked(admin.rpc('publish_attack_sync',{p_run:run,p_catalog:catalog}));}
 catch(error){const message=error.name==='TimeoutError'?'A fonte oficial demorou a responder. O catálogo anterior foi preservado.':String(error.message).slice(0,1500);await checked(admin.from('attack_sync_runs').update({status:'failed',finished_at:new Date().toISOString(),error:message}).eq('id',run));throw Error(message);}
}
