import {requestVisible,submissionVisible} from './record-visibility.mjs';

export const operationModules=[
 {id:'coverage',label:'Detection Coverage',description:'Técnicas, regras e evidências de detecção.',stage:2},
 {id:'investigations',label:'Hunting Investigation',description:'Hipóteses, evidências e linhas de investigação.',stage:5},
 {id:'campaigns',label:'Hunting Campaigns',description:'Escopo, responsáveis e atividades da equipe.',stage:3},
 {id:'false-positives',label:'False Positive Intelligence',description:'Ocorrências, causas e recomendações de tuning.',stage:4},
 {id:'query-library',label:'Hunting Query Library',description:'Consultas, versões e conhecimento compartilhado.',stage:3}
];
export const rulePages=['overview','requests','rules','reports','lab'];
export const workspacePages=['dashboard',...rulePages,...operationModules.map(m=>m.id),'settings','github','team','audit','documentation','profile'];
export function resolveWorkspacePage(hash){const page=String(hash||'').replace(/^#/,'');return workspacePages.includes(page)?page:'dashboard';}

// References from internal metadata are not an official ATT&CK catalog or proof of coverage.
export function internalTechniqueReferences(rules=[]){
 const refs=new Map();
 for(const rule of rules.filter(r=>!r.archived)){
  const ids=new Set((rule.technique||'').toUpperCase().match(/\bT\d{4}(?:\.\d{3})?\b/g)||[]);
  for(const id of ids){if(!refs.has(id))refs.set(id,{id,rules:[],coverage:'unknown'});refs.get(id).rules.push(rule);}
 }
 return [...refs.values()].sort((a,b)=>a.id.localeCompare(b.id));
}
export function buildOperationsOverview(data){
 const rules=(data.rules||[]).filter(r=>!r.archived),requests=(data.requests||[]).filter(requestVisible);
 const queue=requests.filter(r=>['requested','review','changes'].includes(r.status)).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at));
 return {rules:rules.length,versions:(data.versions||[]).filter(v=>rules.some(r=>r.id===v.rule_id)).length,pending:queue.length,approved:requests.filter(r=>r.status==='approved').length,sent:(data.requests||[]).filter(submissionVisible).length,techniques:internalTechniqueReferences(rules).length,queue:queue.slice(0,5)};
}
