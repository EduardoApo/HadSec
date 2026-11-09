export const coverageStates=[
 ['unmapped','Sem regra','#75839a'],['unvalidated','Regra sem validação','#86b7ee'],['requested','Teste solicitado','#c8b3f2'],
 ['missed','Executado sem detecção','#ef8791'],['validated','Detecção validada','#b5ed59'],['unknown','Desconhecida / insuficiente','#e7bb6a']
];
const native=method=>['FortiSIEM Streaming','FortiSIEM SQL','Teste no motor de destino'].includes(method);
export function techniqueCoverage(id,{ruleLinks=[],testLinks=[],rules=[],versions=[],evidence=[],subjects=[],atomicRequests=[],atomicResults=[],resultEvidence=[]},environment=''){
 const associated=rules.filter(r=>!r.archived&&ruleLinks.some(l=>l.technique_id===id&&l.rule_id===r.id));
 const requests=atomicRequests.filter(r=>r.technique_id===id&&(!environment||r.environment===environment)&&subjects.some(s=>s.id===r.id&&!s.archived));
 const pending=requests.some(r=>subjects.some(s=>s.id===r.id&&['pending','approved','running','awaiting_validation'].includes(s.status)));
 if(!associated.length)return {status:pending?'requested':'unmapped',rules:[],tests:[]};
 const current=associated.map(rule=>versions.filter(v=>v.rule_id===rule.id).sort((a,b)=>b.number-a.number)[0]?.id);
 const tests=testLinks.filter(l=>l.technique_id===id&&(!environment||l.environment===environment)).map(l=>({...l,evidence:evidence.find(e=>e.id===l.evidence_id)})).filter(l=>l.evidence&&current.includes(l.evidence.version_id));
 for(const request of requests.filter(r=>current.includes(r.rule_version_id)&&subjects.some(s=>s.id===r.id&&s.status==='completed'))){
  const result=atomicResults.filter(r=>r.request_id===request.id).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)||b.id.localeCompare(a.id))[0];
  if(result?.execution==='success'&&resultEvidence.some(e=>e.result_id===result.id))tests.push({environment:request.environment,kind:'atomic',evidence:{id:result.id,version_id:request.rule_version_id,method:'Atomic manual aprovado',result:result.detected==='yes'?'pass':result.detected==='no'?'fail':'unknown',created_at:result.executed_at}});
 }
 if(!tests.length)return {status:pending?'requested':'unvalidated',rules:associated,tests};
 const latest=new Map();
 for(const link of tests){const key=link.evidence.version_id+'|'+link.environment;const prior=latest.get(key);if(!prior||new Date(link.evidence.created_at)>new Date(prior.evidence.created_at))latest.set(key,link);}
 const results=[...latest.values()].map(l=>(!native(l.evidence.method)&&l.kind!=='atomic')||l.evidence.result==='unknown'?'unknown':l.evidence.result==='pass'?'validated':'missed');
 // Results with conflicting environments/versions remain explicitly uncertain.
 const status=new Set(results).size===1?results[0]:'unknown';return {status,rules:associated,tests};
}
export function navigatorLayer(techniques,context,sync,{environment='',platform='',tactic=''}={}){
 if(!sync?.version)throw Error('Sincronize o catálogo MITRE antes de exportar.');
 return {name:'HadSec Detect — cobertura de detecção',description:'Estados baseados em vínculos explícitos e evidências da versão atual. Ambiente: '+(environment||'todos; resultados divergentes são insuficientes')+'. Associação ou validação estática não comprova detecção.',domain:'enterprise-attack',versions:{attack:sync.version,navigator:'4.9.0',layer:'4.5'},customDataURL:sync.source_url,filters:{platforms:platform?[platform]:[...new Set(techniques.flatMap(t=>t.platforms))]},sorting:0,layout:{layout:'side',aggregateFunction:'average',showID:true,showName:true,showAggregateScores:false,countUnscored:false,expandedSubtechniques:'all'},hideDisabled:false,techniques:techniques.map(t=>{const coverage=techniqueCoverage(t.id,context,environment),state=coverageStates.find(s=>s[0]===coverage.status);return {techniqueID:t.id,...(tactic?{tactic}:{}),enabled:true,color:state[2],comment:state[1]+'; '+coverage.rules.length+' regra(s); '+coverage.tests.length+' evidência(s) da versão atual.',showSubtechniques:true,metadata:[{name:'Estado',value:state[1]},{name:'Ambiente',value:environment||'Todos'},{name:'Versão ATT&CK',value:sync.version}]};}),legendItems:coverageStates.map(([,label,color])=>({label,color})),metadata:[{name:'Fonte',value:sync.source_url||''},{name:'Commit',value:sync.source_commit||''},{name:'Sincronização',value:sync.finished_at||''}],selectTechniquesAcrossTactics:true,selectSubtechniquesWithParent:false};
}
