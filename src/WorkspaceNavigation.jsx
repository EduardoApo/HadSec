import React,{useEffect,useState} from 'react';
import {GitBranch,ChevronDown,ChevronRight,LayoutDashboard,GitPullRequest,ScanLine,BarChart3,FlaskConical,Plug,Send,Users,ScrollText,BookOpen,Info} from 'lucide-react';
import {formats} from '../supabase/functions/_shared/formats.mjs';
import {operationModules,rulePages} from './operations-model.mjs';
import {moduleIcons} from './operation-icons';

export const settingsPages=['settings','github','team','audit','documentation'];
export function WorkflowNavigation({page,pending,compact,onNavigate,onExpand}){
 const [open,setOpen]=useState(()=>rulePages.includes(page));
 const items=[['overview','Visão geral',LayoutDashboard],['requests','Solicitações',GitPullRequest],['rules','Regras de detecção',ScanLine],['reports','Relatórios',BarChart3],['lab','Laboratório',FlaskConical]];
 useEffect(()=>{if(rulePages.includes(page))setOpen(true);},[page]);
 const navigateItem=(id,label,Icon)=><button key={id} className={'nav-item '+(page===id?'active':'')} aria-label={label} aria-current={page===id?'page':undefined} title={compact?label:undefined} onClick={()=>onNavigate(id)}><Icon size={20}/><span>{label}</span></button>;
 return <nav aria-label="Navegação principal">{navigateItem('dashboard','Dashboard',LayoutDashboard)}<button className={'nav-item nav-flow '+(rulePages.includes(page)?'active':'')} aria-label="Rule Management" title={compact?'Rule Management':undefined} aria-expanded={open&&!compact} aria-controls="rule-management-pages" onClick={()=>{if(compact){onExpand();setOpen(true);}else setOpen(!open);}}><GitBranch size={20}/><span>Rule Management</span>{!compact&&(open?<ChevronDown size={17}/>:<ChevronRight size={17}/>)}</button>{open&&!compact&&<div className="nav-flow-items" id="rule-management-pages">{items.map(([id,label,Icon])=><button key={id} className={'nav-item nav-subitem '+(page===id?'active':'')} aria-label={label} aria-current={page===id?'page':undefined} onClick={()=>onNavigate(id)}><Icon size={18}/><span>{label}</span>{id==='requests'&&pending>0&&<b>{pending}</b>}</button>)}</div>}{operationModules.map(module=>navigateItem(module.id,module.label,moduleIcons[module.id]))}</nav>;
}
export function SettingsNavigation({page,section,onNavigate,onSection}){
 const entries=[['connections','Conexões',Plug],['github','Envio',Send],['team','Equipe e acessos',Users],['audit','Auditoria',ScrollText],['documentation','Documentação de regras',BookOpen],['about','Sobre a ferramenta',Info]];
 return <div className="settings-navigation" role="tablist" aria-label="Seções das configurações">{entries.map(([id,label,Icon])=>{const selected=id===page||page==='settings'&&id===section;return <button key={id} id={'system-tab-'+id} role="tab" aria-selected={selected} className={'settings-navigation-item '+(selected?'active':'')} onClick={()=>['connections','about'].includes(id)?onSection(id):onNavigate(id)}><Icon size={18}/>{label}</button>;})}</div>;
}
export function RuleDocumentation(){
 return <><div className="page-heading"><div><h1>Documentação de regras<span className="title-dot">.</span></h1><p>Referências oficiais de sintaxe, criação e testes.</p></div></div><div className="documentation-grid">{formats.filter(f=>f.id!=='xml').map(format=><a className="panel documentation-card" key={format.id} href={format.docs} target="_blank" rel="noreferrer"><BookOpen size={26}/><h2>{format.id==='sql'?'FortiSIEM':format.label}</h2>{format.reference&&<p>{format.reference}</p>}<ChevronRight size={20}/></a>)}</div><section className="panel detail-padding documentation-note"><h2>Escopo do laboratório</h2><p>A simulação verifica eventos isolados e os operadores implementados. Agregações, correlações, mappings, módulos e dependências do ambiente precisam ser confirmados no motor de destino. O resultado local não é uma compilação oficial.</p><p>Os guias Kusto e Elastic acompanham referências contínuas. YARA usa a referência estável publicada no repositório oficial; a documentação IBM mantém sua árvore de referência QRadar.</p></section></>;
}
