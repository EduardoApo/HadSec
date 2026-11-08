import React,{useEffect,useState} from 'react';
import {GitBranch,ChevronDown,ChevronRight,LayoutDashboard,GitPullRequest,ScanLine,BarChart3,FlaskConical,Plug,Send,Users,ScrollText,BookOpen,Info} from 'lucide-react';
import {formats} from '../supabase/functions/_shared/formats.mjs';

export const settingsPages=['settings','github','team','audit','documentation'];
export function WorkflowNavigation({page,pending,compact,onNavigate,onExpand}){
 const [open,setOpen]=useState(true);
 const items=[['overview','Visão geral',LayoutDashboard],['requests','Solicitações',GitPullRequest],['rules','Regras de detecção',ScanLine],['reports','Relatórios',BarChart3]];
 useEffect(()=>{if(items.some(([id])=>id===page))setOpen(true);},[page]);
 return <nav aria-label="Navegação principal"><button className={'nav-item nav-flow '+(items.some(([id])=>id===page)?'active':'')} aria-label="Fluxo de regras" title={compact?'Fluxo de regras':undefined} aria-expanded={open&&!compact} onClick={()=>{if(compact){onExpand();setOpen(true);}else setOpen(!open);}}><GitBranch size={20}/><span>Fluxo de regras</span>{!compact&&(open?<ChevronDown size={17}/>:<ChevronRight size={17}/>)}</button>{open&&!compact&&<div className="nav-flow-items">{items.map(([id,label,Icon])=><button key={id} className={'nav-item nav-subitem '+(page===id?'active':'')} aria-label={label} onClick={()=>onNavigate(id)}><Icon size={18}/><span>{label}</span>{id==='requests'&&pending>0&&<b>{pending}</b>}</button>)}</div>}<button className={'nav-item '+(page==='lab'?'active':'')} aria-label="Laboratório" title={compact?'Laboratório':undefined} onClick={()=>onNavigate('lab')}><FlaskConical size={20}/><span>Laboratório</span></button></nav>;
}
export function SettingsNavigation({page,section,onNavigate,onSection}){
 const entries=[['connections','Conexões',Plug],['github','Envio',Send],['team','Equipe e acessos',Users],['audit','Auditoria',ScrollText],['documentation','Documentação de regras',BookOpen],['about','Sobre a ferramenta',Info]];
 return <div className="settings-navigation" role="tablist" aria-label="Seções das configurações">{entries.map(([id,label,Icon])=>{const selected=id===page||page==='settings'&&id===section;return <button key={id} id={'system-tab-'+id} role="tab" aria-selected={selected} className={'settings-navigation-item '+(selected?'active':'')} onClick={()=>['connections','about'].includes(id)?onSection(id):onNavigate(id)}><Icon size={18}/>{label}</button>;})}</div>;
}
export function RuleDocumentation(){
 return <><div className="page-heading"><div><h1>Documentação de regras<span className="title-dot">.</span></h1><p>Referências oficiais de sintaxe, criação e testes.</p></div></div><div className="documentation-grid">{formats.filter(f=>f.id!=='xml').map(format=><a className="panel documentation-card" key={format.id} href={format.docs} target="_blank" rel="noreferrer"><BookOpen size={26}/><h2>{format.id==='sql'?'FortiSIEM':format.label}</h2>{format.reference&&<p>{format.reference}</p>}<ChevronRight size={20}/></a>)}</div><section className="panel detail-padding documentation-note"><h2>Escopo do laboratório</h2><p>A simulação verifica eventos isolados e os operadores implementados. Agregações, correlações, mappings, módulos e dependências do ambiente precisam ser confirmados no motor de destino. O resultado local não é uma compilação oficial.</p><p>Os guias Kusto e Elastic acompanham referências contínuas. YARA usa a referência estável publicada no repositório oficial; a documentação IBM mantém sua árvore de referência QRadar.</p></section></>;
}
