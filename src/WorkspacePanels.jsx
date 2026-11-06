import React,{useEffect,useState} from 'react';
import {Plug,KeyRound,Info,Database,ShieldCheck,Github,Server,RotateCcw,Loader2,ArrowUpRight,ExternalLink,Search,X,Download,ScrollText,GitPullRequest,AlertTriangle,LogOut} from 'lucide-react';
import {gateway} from './api';
import {actionLabel,auditEntityLabel,filterAuditEvents} from './audit-search.mjs';

const Pill=({ok,children})=><span className={`badge ${ok?'green':'amber'}`}><span className="dot"/>{children}</span>;

export function AuditPage({data,name,Avatar,onExport}){
 const [query,setQuery]=useState('');
 const rows=filterAuditEvents(data.audit,query,data);
 return <><div className="page-heading"><div><h1>Auditoria<span className="title-dot">.</span></h1><p>Ações e responsáveis em cada etapa.</p></div><button className="btn" onClick={()=>onExport(rows)}><Download size={17}/>{query?'Exportar resultados':'Exportar auditoria'}</button></div>
  <div className="section-toolbar audit-toolbar"><div className="search-box audit-search"><Search size={18}/><input type="search" aria-label="Pesquisar auditoria" placeholder="Responsável, ação, registro ou data…" value={query} onChange={e=>setQuery(e.target.value)}/>{query&&<button className="icon-btn" aria-label="Limpar pesquisa de auditoria" onClick={()=>setQuery('')}><X size={16}/></button>}</div><span className="results-count" role="status">{rows.length} {rows.length===1?'evento':'eventos'}</span></div>
  <section className="panel"><div className="table-scroll"><table><thead><tr><th>Responsável</th><th>Ação</th><th>Registro</th><th>Data e hora</th></tr></thead><tbody>{rows.map(event=><tr key={event.id}><td><span className="inline-person"><Avatar small name={event.actor_id?name(event.actor_id):'Sistema'}/>{event.actor_id?name(event.actor_id):'Sistema'}</span></td><td>{actionLabel(event.action)}{event.detail?.administrator_self_approval&&<small className="audit-admin-note">Aprovação administrativa</small>}</td><td><div className="audit-record"><span>{auditEntityLabel(event,data)}</span><code title={event.entity_id||''}>{event.entity_id?.slice(0,16)||'—'}</code></div></td><td><time dateTime={event.created_at}>{new Date(event.created_at).toLocaleString('pt-BR')}</time></td></tr>)}</tbody></table></div>{!rows.length&&<div className="empty"><ScrollText size={34}/><h3>{query?'Nenhum evento encontrado':'Nenhuma ação registrada'}</h3><p>{query?'Tente outro nome, ação, registro ou data.':'As ações da equipe aparecerão aqui.'}</p></div>}</section>
 </>;
}

export function GitHubWorkspace({data,allowed,busy,run}){
 const [status,setStatus]=useState(null),[error,setError]=useState(''),[loading,setLoading]=useState(false);
 const check=async()=>{if(!allowed)return;setLoading(true);setError('');try{setStatus(await gateway('github.status'));}catch(e){setStatus(null);setError(e.message);}finally{setLoading(false);}};
 useEffect(()=>{check();},[allowed]);
 const ready=status?.connected,approved=data.requests.filter(q=>q.status==='approved'),sent=data.requests.filter(q=>q.status==='published');
 return <><div className="page-heading"><div><h1>GitHub<span className="title-dot">.</span></h1><p>Versões aprovadas, encaminhadas como pull requests.</p></div>{allowed&&<button className="btn" disabled={loading} onClick={check}>{loading?<Loader2 className="spin" size={17}/>:<RotateCcw size={17}/>}Verificar conexão</button>}</div>
  <section className="panel github-connect"><span className="github-large"><Github size={35}/></span><div><h2>{status?.repository||'Integração GitHub'}</h2><p>{!allowed?'Seu perfil permite acompanhar o histórico de envios.':loading?'Verificando acesso ao repositório…':ready?`Branch base: ${status.branch}`:status?.configured?'Confira o acesso à branch e ao repositório.':'Configure o repositório e a credencial no servidor.'}</p></div><Pill ok={ready}>{!allowed?'Consulta':loading?'Verificando':ready?'Conectado':error?'Indisponível':'Pendente'}</Pill></section>
  {(error||status?.error)&&<div className="inline-alert error-text" role="alert"><AlertTriangle size={19}/><span>{error||status.error}</span><button className="text-btn" disabled={loading} onClick={check}>Tentar novamente</button></div>}
  <div className="inline-alert"><GitPullRequest size={20}/><span>O envio abre um pull request com a versão aprovada. O merge e a ativação no FortiSIEM continuam com a equipe.</span></div>
  <div className="subheading"><h2>Prontas para envio</h2><span className="count-badge">{approved.length}</span></div><section className="panel">{approved.map(q=><div className="publish-row" key={q.id}><span className="request-icon green"><ShieldCheck size={22}/></span><div><h3>{q.title}</h3><small>v{data.versions.find(v=>v.id===q.version_id)?.number} · Revisão aprovada</small></div><button className="btn primary" disabled={busy||!allowed||!ready} onClick={()=>run(()=>gateway('github.publish',{request_id:q.id}),'Pull request enviado ao GitHub.',false)}><Github size={17}/>Enviar ao GitHub</button></div>)}{!approved.length&&<div className="empty"><ShieldCheck size={32}/><h3>Nenhuma versão aguardando envio</h3><p>As versões aprovadas aparecem aqui.</p></div>}</section>
  <div className="subheading"><h2>Envios registrados</h2></div><section className="panel">{sent.map(q=><div className="publish-row" key={q.id}><span className="request-icon purple"><GitPullRequest size={22}/></span><div><h3>{q.title}</h3><small>{new Date(q.updated_at).toLocaleDateString('pt-BR')}</small></div>{q.github_url?<a className="btn" href={q.github_url} target="_blank" rel="noreferrer">Pull request<ExternalLink size={16}/></a>:<Pill>Link indisponível</Pill>}</div>)}{!sent.length&&<div className="empty"><Github size={32}/><h3>Nenhum envio registrado</h3></div>}</section>
 </>;
}
