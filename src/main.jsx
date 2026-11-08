import {CodeEditor} from './CodeEditor';
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import { Shield, ShieldCheck, LayoutDashboard, ScanLine, GitPullRequest, FlaskConical, Github, Users, ScrollText, Settings, Search, Plus, PanelLeftOpen, PanelLeftClose, ArrowUpRight, ArrowRight, ChevronRight, ChevronDown, ChevronLeft, Check, CheckCheck, CheckCircle2, Clock, GitBranch, GitCommitHorizontal, Code2, FileCode2, MoreHorizontal, Menu, X, LogOut, LockKeyhole, ExternalLink, Download, Upload, AlertTriangle, Loader2, Command, BookOpen, Activity, Send, RotateCcw, Filter, Copy, Eye, EyeOff, KeyRound, Bell } from 'lucide-react';
import { db, configured, loadData, loadRequests, gateway, rpc, permissions } from './api';
import { sampleSQL } from './rule-templates';
import { validateDetectionRule as validateRule } from '../supabase/functions/_shared/detection-engine.mjs';
import { parseFortiSIEM } from '../supabase/functions/_shared/fortisiem.mjs';
import {Trash2,BarChart3} from 'lucide-react';
import {WorkspaceMenus} from './WorkspaceMenus';
import {AuditPage,GitHubWorkspace} from './WorkspacePanels';
import {WorkspaceSettings,ProfilePage} from './SystemSettings';
import {ReportsPage} from './ReportsPage';
import {LoadingSplash} from './LoadingSplash';
import {actionLabel} from './audit-search.mjs';
import {DeleteRecordForm} from './DeleteRecordForm';
import {requestVisible,submissionVisible,versionRequestActive} from './record-visibility.mjs';
import {WorkflowNavigation,SettingsNavigation,RuleDocumentation,settingsPages} from './WorkspaceNavigation';
import {DetectionLab} from './DetectionLab';
import {ChangeRequestForm} from './ChangeRequestForm';
import {FormatSelect} from './DetectionFields';
import {formatInfo,modeForFormat} from '../supabase/functions/_shared/formats.mjs';
import './styles.css';
const statusMap = { requested: ['Solicitado', 'blue'], review: ['Em revisão', 'amber'], changes: ['Ajustes pedidos', 'orange'], approved: ['Aprovado', 'green'], published: ['Enviado', 'purple'], rejected: ['Rejeitado', 'red'], draft: ['Rascunho', 'muted'] };
const date = s => new Date(s).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short' });
const ago = s => { const m = Math.max(0, Math.floor((Date.now() - new Date(s)) / 60000)); return m < 60 ? `${m} min atrás` : m < 1440 ? `${Math.floor(m / 60)} h atrás` : date(s); };
const Badge = ({ status, children, tone }) => <span className={`badge ${tone || statusMap[status]?.[1] || 'muted'}`}><span className="dot"/>{children || statusMap[status]?.[0] || status}</span>;
const Avatar = ({ name = 'HadSec', small = false }) => <span className={`avatar ${small ? 'small' : ''}`}>{name.split(/[ .]/).filter(Boolean).slice(0, 2).map(x => x[0]).join('').toUpperCase()}</span>;
const OwlLogo = ({ className = "" }) => <img className={`owl-logo ${className}`} src="/hadsec-owl-front.png" alt=""/>;
function Empty({ icon: Icon = ScanLine, title = 'Nenhum resultado', text = 'Altere os filtros ou crie o primeiro registro.', action }) { return <div className="empty"><Icon size={34}/><h3>{title}</h3><p>{text}</p>{action}</div>; }
function Field({ label, children, hint }) { const id = React.useId(); return <div className="field"><label htmlFor={id}>{label}</label>{React.cloneElement(children, { id, ...(hint ? { 'aria-describedby': `${id}-hint` } : {}) })}{hint && <small id={`${id}-hint`}>{hint}</small>}</div>; }
function PasswordInput({ label = 'senha', ...props }) {
    const [visible, setVisible] = useState(false);
    return <div className="password-input"><input {...props} type={visible ? 'text' : 'password'}/><button type="button" className="password-toggle icon-btn" aria-label={`${visible ? 'Ocultar' : 'Mostrar'} ${label}`} aria-pressed={visible} aria-controls={props.id} title={`${visible ? 'Ocultar' : 'Mostrar'} ${label}`} disabled={props.disabled} onClick={() => setVisible(!visible)}>{visible ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div>;
}
function Modal({ title, children, onClose, wide = false }) {
    useEffect(() => { const original = document.activeElement, old = document.body.style.overflow; document.body.style.overflow = 'hidden'; const close = e => { if (e.key === 'Escape')
        onClose(); if (e.key === 'Tab') {
        const items = [...document.querySelectorAll('.modal button,.modal input,.modal select,.modal textarea,.modal a[href]')].filter(x => !x.disabled), first = items[0], last = items.at(-1);
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last?.focus();
        }
        else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first?.focus();
        }
    } }; document.addEventListener('keydown', close); setTimeout(() => document.querySelector('.modal input,.modal textarea,.modal button')?.focus(), 0); return () => { document.body.style.overflow = old; document.removeEventListener('keydown', close); original?.focus(); }; }, []);
    return <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget)
        onClose(); }}><section className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}><div className="modal-head"><h2>{title}</h2><button className="icon-btn" onClick={onClose} aria-label="Fechar"><X /></button></div>{children}</section></div>;
}
function App() {
    const [compact, setCompact] = useState(() => localStorage.getItem('hadsec-sidebar') !== 'expanded');
    const [session, setSession] = useState(undefined), [data, setData] = useState(null), [page, setPage] = useState(location.hash.slice(1) || 'overview'), [menu, setMenu] = useState(false), [modal, setModal] = useState(null), [selected, setSelected] = useState(null), [query, setQuery] = useState(''), [filter, setFilter] = useState('all'), [toast, setToast] = useState(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
    const [ruleContext,setRuleContext]=useState(null),[settingsSection,setSettingsSection]=useState('connections'),[profileSection,setProfileSection]=useState('account');
    const [bootProgress,setBootProgress]=useState(5),[splashFinished,setSplashFinished]=useState(false);
    const completeSplash=React.useCallback(()=>setSplashFinished(true),[]);
    const notify = (text, kind = 'success') => setToast({ text, kind });
    const refresh = async (onProgress) => { try {
        const snapshot=await loadData(onProgress);setData(snapshot);setError('');return snapshot;
    }
    catch (e) {
        setError(e.message);
        throw e;
    } };
    useEffect(()=>{
     if(!configured){setSession(null);setBootProgress(100);return;}
     db.auth.getSession().then(({data})=>{setSession(data.session);setBootProgress(data.session?20:100);}).catch(()=>{setSession(null);setBootProgress(100);});
     const {data:{subscription}}=db.auth.onAuthStateChange((event,next)=>{setSession(next);if(!next){setData(null);setBootProgress(100);}});
     return()=>subscription.unsubscribe();
    },[]);
    useEffect(()=>{
     if(!session)return;
     let cancelled=false;setSplashFinished(false);setBootProgress(20);setError('');
     loadData((done,total)=>{if(!cancelled)setBootProgress(20+Math.round(done/total*75));}).then(snapshot=>{if(cancelled)return;setData(snapshot);setBootProgress(100);}).catch(e=>{if(!cancelled){setError(e.message);setSplashFinished(true);}});
     return()=>{cancelled=true;};
    },[session?.user.id]);
    useEffect(()=>{
     if(!session||busy)return;
     let cancelled=false;
     const update=async()=>{if(document.hidden)return;try{const requests=await loadRequests();if(!cancelled)setData(current=>current?{...current,requests}:current);}catch{/* Keep the current list during transient network failures. */}};
     const timer=setInterval(update,45000);window.addEventListener('focus',update);
     return()=>{cancelled=true;clearInterval(timer);window.removeEventListener('focus',update);};
    },[session?.user.id,busy]);
    useEffect(() => { const fn = () => { const next = location.hash.slice(1) || 'overview'; setPage(next); if (next !== 'rules')
        setSelected(null); }; window.addEventListener('hashchange', fn); return () => window.removeEventListener('hashchange', fn); }, []);
    useEffect(() => { if (!toast)
        return; const t = setTimeout(() => setToast(null), 5500); return () => clearTimeout(t); }, [toast]);
    const go = p => { setPage(p); location.hash = p; setMenu(false); setSelected(null); setRuleContext(null); setQuery(''); setFilter('all'); };
    const user = data?.profiles.find(u => u.id === session?.user.id), role = data?.roles.find(r => r.id === user?.role_id), can = p => (data?.overrides?.find(o => o.user_id === user?.id && o.permission === p)?.granted ?? role?.permissions.includes(p)) && user?.active;
    const name = id => data?.profiles.find(p => p.id === id)?.display_name || 'Usuário';
    const latest = r => data?.versions.filter(v => v.rule_id === r.id).sort((a, b) => b.number - a.number)[0];
    const state = r => data?.requests.filter(q => q.version_id === latest(r)?.id && (requestVisible(q)||q.status==='published')).sort((a, b) => new Date(b.updated_at) - new Date(a.updated_at))[0]?.status || 'draft';
    const run = async (fn, message, close = true) => { setBusy(true); try {
        const out = await fn();
        await refresh();
        if (message)
            notify(typeof message==='function'?message(out):message,out?.ok===false?'error':'success');
        if (close)
            setModal(null);
        return out;
    }
    catch (e) {
        notify(e.message, 'error');
    }
    finally {
        setBusy(false);
    } };
    const openRule = (id,requestId=null) => { setSelected(id);setRuleContext(requestId);setPage('rules');location.hash='rules';setQuery(''); };
    const saveRule=async(parameters,requestId)=>{
     setBusy(true);let savedId=null;
     try{
      savedId=await rpc('save_rule',parameters);
      let report,problem='';
      try{report=await gateway('validate',{version_id:savedId});}catch(e){problem=e.message;}
      let linked=false;
      if(report?.ok&&requestId){try{await rpc('attach_version',{p_request:requestId,p_version:savedId});linked=true;}catch(e){problem=e.message;}}
      const snapshot=await refresh();
      const version=snapshot.versions.find(v=>v.id===savedId);
      setModal(null);if(version)openRule(version.rule_id,requestId);
      if(problem)notify('Versão salva. '+problem,'error');
      else if(report?.ok===false)notify('Versão salva. Corrija os problemas exibidos na validação.','error');
      else notify(linked?'Versão validada e vinculada à solicitação para revisão.':'Versão salva e validação registrada.');
     }catch(e){notify(savedId?'Versão salva. Atualize a página para consultar o resultado.':e.message,'error');if(savedId)setModal(null);}
     finally{setBusy(false);}
    };
    const pending = data?.requests.filter(q => requestVisible(q)&&['requested', 'review', 'changes'].includes(q.status)).length || 0;
    if(session===undefined||(!splashFinished&&!error))return <LoadingSplash progress={bootProgress} onComplete={completeSplash}/>;
    if(!session)return <Login notify={notify}/>;
    if(!data)return error?<div className="loading"><OwlLogo/><h2>HadSec Detect</h2><p className="error-text">{error}</p><button className="btn primary" onClick={async()=>{setError('');setSplashFinished(false);setBootProgress(20);try{await refresh((done,total)=>setBootProgress(20+Math.round(done/total*75)));setBootProgress(100);}catch{setSplashFinished(true);}}}>Tentar novamente</button><button className="btn" onClick={()=>db.auth.signOut({scope:'local'})}>Sair</button></div>:<LoadingSplash progress={bootProgress} onComplete={completeSplash}/>;
    const filteredRules = data.rules.filter(r => !r.archived && `${r.name} ${r.technique} ${r.description}`.toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || state(r) === filter));
    const filteredRequests = data.requests.filter(q => requestVisible(q)&&`${q.title} ${q.description}`.toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || q.status === filter));
    const pageTitle = { overview: 'Visão geral', rules: 'Regras de detecção', requests: 'Solicitações', lab: 'Laboratório', github: 'GitHub', team: 'Equipe e acessos', audit: 'Auditoria', reports:'Relatórios', profile:'Meu perfil', settings: 'Configurações' }[page] || 'Visão geral';
    const canDeleteRecords=Boolean(data.capabilities?.owner);
    const deleteRequest=q=>setModal({type:'delete-request',id:q.id});
    const newRule = () => setModal({ type: 'rule' });
    const newRequest = () => setModal({ type: 'request' });
    const ruleTable = (rows, compact = false) => <div className="table-scroll"><table><thead><tr><th>Regra de detecção</th><th>Severidade</th><th>Status</th><th>Versão</th>{!compact && <th>Atualizada</th>}<th aria-label="Ações"/></tr></thead><tbody>{rows.map(r => <tr key={r.id} onClick={() => openRule(r.id)}><td><button className="rule-cell" onClick={() => openRule(r.id)}><span className="file-icon"><FileCode2 size={19}/></span><span><strong>{r.name}</strong><small>{r.technique || 'Sem técnica'}<span>·</span>{formatInfo(r.format).label}</small></span></button></td><td><span className={`severity ${r.severity === 'Crítica' ? 'red' : r.severity === 'Alta' ? 'orange' : r.severity === 'Média' ? 'amber' : 'blue'}`}><span className="dot"/>{r.severity}</span></td><td><Badge status={state(r)}/></td><td><code className="version">v{latest(r)?.number || 1}</code></td>{!compact && <td className="subtle">{ago(latest(r)?.created_at || r.created_at)}</td>}<td><div className="rule-row-actions"><button className="icon-btn" aria-label={"Abrir "+r.name} onClick={e=>{e.stopPropagation();openRule(r.id);}}><ChevronRight size={18}/></button>{can('rules.write')&&<button className="icon-btn delete-rule-button" aria-label={"Excluir "+r.name} title="Excluir regra" onClick={e=>{e.stopPropagation();setModal({type:'delete-rule',id:r.id});}}><Trash2 size={17}/></button>}</div></td></tr>)}</tbody></table>{!rows.length && <Empty />}</div>;
    return <div className={`app ${compact ? 'sidebar-compact' : ''}`}>
  {menu && <div className="sidebar-scrim" onClick={() => setMenu(false)}/>}
  <aside className={`sidebar ${menu ? 'open' : ''}`}><a href="#overview" aria-label="HadSec Detect" className="brand" onClick={() => go('overview')}><span className="brand-mark"><OwlLogo /></span><span>HadSec<span className="brand-detect">Detect<span className="brand-dot">.</span></span></span></a><button className="sidebar-toggle icon-btn" aria-label={compact ? 'Expandir menu' : 'Compactar menu'} title={compact ? 'Expandir menu' : 'Compactar menu'} onClick={() => { setCompact(!compact); localStorage.setItem('hadsec-sidebar', compact ? 'expanded' : 'compact'); }}>{compact ? <ChevronRight size={18}/> : <ChevronLeft size={18}/>}</button><WorkflowNavigation page={page} pending={pending} compact={compact} onNavigate={go} onExpand={()=>{setCompact(false);localStorage.setItem('hadsec-sidebar','expanded');}}/><div className="sidebar-bottom"><button aria-label="Configurações" title={compact ? 'Configurações' : undefined} className={`nav-item ${settingsPages.includes(page) ? 'active' : ''}`} onClick={() => go('settings')}><Settings size={20}/><span>Configurações</span></button><button className="profile" title={compact ? 'Minha conta' : undefined} aria-label="Minha conta" onClick={() => {setProfileSection('account');go('profile');}}><Avatar name={user?.display_name}/><span><strong>{user?.display_name || 'Sem perfil'}</strong><small>{role?.name || 'Acesso pendente'}</small></span><ChevronRight size={17}/></button></div></aside>
  <div className="app-main"><header className="workspace-actions"><button className="icon-btn mobile-menu" onClick={()=>setMenu(true)} aria-label="Abrir menu"><Menu/></button>{user&&<WorkspaceMenus key={user.id} user={user} role={role} revision={data} onNotification={async item=>{try{const snapshot=await refresh();if(item.target?.type==='request'&&snapshot.requests.some(request=>request.id===item.target.id&&requestVisible(request))){go('requests');setModal({type:'request-detail',id:item.target.id});}else if(item.target?.type==='rule'&&snapshot.rules.some(rule=>rule.id===item.target.id)){setModal(null);openRule(item.target.id);}else notify('Este registro não está mais disponível.','error');}catch(e){notify(e.message,'error');}}} onProfile={section=>{setProfileSection(section);go('profile');}} onLogout={()=>db.auth.signOut({scope:'local'})}/>} </header>
   {error && <div className="inline-alert error-text">{error}</div>}
   {!user?.active ? <main><Empty icon={LockKeyhole} title="Acesso pendente" text="Solicite ao administrador a criação ou ativação do seu perfil." action={<button className="btn" onClick={() => db?.auth.signOut({ scope: 'local' })}>Sair</button>}/></main> : <main>{settingsPages.includes(page)&&<SettingsNavigation page={page} section={settingsSection} onNavigate={go} onSection={id=>{setSettingsSection(id);go('settings');}}/>}
   {page === 'overview' && <>
    <div className="page-heading"><div><h1>Visão geral<span className="title-dot">.</span></h1><p>Acompanhe versões, revisões e envios ao GitHub.</p></div><button className="btn primary" onClick={can('rules.write') ? newRule : newRequest}><Plus size={18}/>{can('rules.write') ? 'Nova regra' : 'Nova solicitação'}</button></div>
    <section className="welcome-card"><div className="welcome-content"><h2>Da regra à revisão.<br />Cada versão no seu controle.</h2><p>Valide uma versão, reúna evidências<br />e encaminhe a mudança para revisão.</p><div className="welcome-actions"><button className="btn light-green" onClick={() => go('rules')}>Explorar regras <ArrowRight size={17}/></button><button className="text-btn" onClick={() => go('lab')}><FlaskConical size={17}/>Abrir laboratório</button></div></div><div className="radar-art" aria-hidden="true"><div className="radar-grid"/><div className="orbit o1"/><div className="orbit o2"/><div className="orbit o3"/><div className="radar-cross horizontal"/><div className="radar-cross vertical"/><span className="radar-node n1"><Code2 /></span><span className="radar-node n2"><GitBranch /></span><span className="radar-node n3"><Check size={18}/></span><span className="radar-center"><OwlLogo /></span><div className="floating-code"><span className="dot"/> detection.status = <b>protected</b></div></div></section>
    <div className="stats-grid">{[[ScanLine, 'Regras versionadas', data.rules.filter(r=>!r.archived).length, 'Todas as regras do workspace', 'lime'], [GitPullRequest, 'Aguardando ação', pending, 'Solicitações e revisões pendentes', 'amber'], [ShieldCheck, 'Versões aprovadas', data.requests.filter(q => requestVisible(q)&&q.status === 'approved').length, 'Prontas para envio ao GitHub', 'green'], [GitBranch, 'Enviadas', data.requests.filter(submissionVisible).length, 'Pull requests encaminhados', 'purple']].map(([Icon, label, value, note, color]) => <button className="stat-card" key={label} onClick={() => { go(label === 'Regras versionadas' ? 'rules' : label === 'Enviadas' ? 'github' : 'requests'); if (label === 'Versões aprovadas')
                setFilter('approved'); }}><div className="stat-top"><span>{label}</span><span className={`stat-icon ${color}`}><Icon size={19}/></span></div><strong className="stat-value">{String(value).padStart(2, '0')}</strong><small>{note}</small></button>)}</div>
    <div className="dashboard-grid"><div className="dashboard-left"><section className="panel"><div className="panel-heading"><div><h2>Regras recentes</h2><p>As últimas mudanças na sua base de detecção.</p></div><button className="text-btn lime-text" onClick={() => go('rules')}>Ver todas <ArrowUpRight size={16}/></button></div>{ruleTable(data.rules.filter(r=>!r.archived).sort((a, b) => new Date(latest(b)?.created_at) - new Date(latest(a)?.created_at)).slice(0, 5), true)}</section><section className="collaboration"><span className="collaboration-icon"><GitPullRequest size={25}/></span><div><h3>Uma regra melhor começa com uma solicitação.</h3><p>Abra uma solicitação e vincule a regra afetada.</p></div><button className="btn" onClick={newRequest}>Solicitar ajuste <ArrowUpRight size={16}/></button></section></div><aside className="dashboard-right"><section className="panel flow-panel"><div className="panel-heading"><h2>Fluxo de revisão</h2><GitBranch size={18}/></div><div className="flow-list">{[['Rascunho', 'Desenvolva a lógica', 'draft', Code2], ['Validação', 'Verifique a estrutura', 'validation', FlaskConical], ['Revisão', 'Outro olhar sobre a regra', 'review', Eye], ['Envio', 'Histórico no repositório', 'published', Github]].map(([label, desc, status, Icon], i) => <div className="flow-step" key={label}><span className={`flow-icon step-${i}`}><Icon size={18}/></span><div><strong>{label}</strong><small>{desc}</small></div><span className="flow-number">0{i + 1}</span></div>)}</div><div className="flow-footer"><ShieldCheck size={15}/>Aprovação antes da publicação</div></section><section className="panel activity-panel"><div className="panel-heading"><h2>Atividade recente</h2><Activity size={18}/></div>{data.audit.slice(0, 3).map((a, i) => <div className="activity-item" key={a.id}><span className={`activity-point point-${i}`}/><div><p><strong>{name(a.actor_id)}</strong> {actionLabel(a.action)}</p><small>{ago(a.created_at)}</small></div></div>)}{!data.audit.length && <p className="muted padded">As ações da equipe aparecerão aqui.</p>}<button className="activity-link" onClick={() => go('audit')}>Abrir auditoria <ArrowRight size={15}/></button></section></aside></div>
   </>}
   {page === 'rules' && !selected && <><PageHeading title="Regras de detecção" text="Cada regra, suas versões e o contexto de cada mudança." action={can('rules.write') && <button className="btn primary" onClick={newRule}><Plus size={18}/>Nova regra</button>}/><div className="section-toolbar"><Tabs value={filter} onChange={setFilter} items={['all', 'draft', 'review', 'approved', 'published']}/><SearchBox value={query} onChange={setQuery}/></div><section className="panel">{ruleTable(filteredRules)}</section><p className="results-count">{filteredRules.length} de {data.rules.filter(r=>!r.archived).length} regras</p></>}
   {page === 'rules' && selected && <RuleDetail requestContext={data.requests.find(q=>q.id===ruleContext&&requestVisible(q))} onRequest={q=>{go('requests');setModal({type:'request-detail',id:q.id});}} rule={data.rules.find(r => r.id === selected)} data={data} latest={latest} name={name} can={can} busy={busy} run={run} notify={notify} back={() => setSelected(null)} setModal={setModal}/>}
   {page === 'requests' && <><PageHeading title="Solicitações" text="Do primeiro pedido à aprovação da versão." action={can('requests.create') && <button className="btn primary" onClick={newRequest}><Plus size={18}/>Nova solicitação</button>}/><div className="section-toolbar"><Tabs value={filter} onChange={setFilter} items={['all', 'requested', 'review', 'approved', 'changes']}/><SearchBox value={query} onChange={setQuery}/></div><section className="panel request-list"><RequestsList rows={filteredRequests} data={data} name={name} busy={busy} onOpen={q=>setModal({type:'request-detail',id:q.id})} onDelete={canDeleteRecords?deleteRequest:null}/>{!filteredRequests.length && <Empty icon={GitPullRequest} title="Nenhuma solicitação"/>}</section></>}
   {page === 'lab' && <DetectionLab data={data} can={can} setModal={setModal} Report={Report} onDocs={()=>go('documentation')}/>}
   {page === 'github' && <GitHubWorkspace data={data} allowed={!!can('github.publish')} busy={busy} run={run} onDelete={canDeleteRecords?q=>setModal({type:'delete-submission',id:q.id}):null}/>}
   {page === 'team' && <><PageHeading title="Equipe e acessos" text="As pessoas certas, com as permissões certas." action={can('users.manage') && <button className="btn primary" onClick={() => setModal({ type: 'user' })}><Plus size={18}/>Criar conta</button>}/><section className="panel"><div className="panel-heading"><h2>Membros do workspace</h2><span className="count-badge">{data.profiles.filter(p => !p.deleted_at).length}</span></div><div className="members">{data.profiles.filter(p => !p.deleted_at).map(p => <div className="member" key={p.id}><Avatar name={p.display_name}/><div><strong>{p.display_name}{p.id === user.id && <small className="you">Você</small>}</strong><small>@{p.username}</small></div><Badge tone={p.active ? 'green' : 'muted'}>{p.active ? 'Ativo' : 'Desativado'}</Badge><span className="member-role">{data.roles.find(r => r.id === p.role_id)?.name}</span>{can('users.manage') && <button className="btn small-btn" onClick={() => setModal({ type: 'edit-user', id: p.id })}>Gerenciar</button>}</div>)}</div></section><div className="subheading"><div><h2>Perfis de acesso</h2><p>Permissões atribuídas a cada função.</p></div>{can('roles.manage') && <button className="btn" onClick={() => setModal({ type: 'role' })}><Plus size={17}/>Novo perfil</button>}</div><div className="roles-grid">{data.roles.map(r => <section className="panel role-card" key={r.id}><div className="role-card-head"><span className="role-shield"><ShieldCheck size={23}/></span>{r.system && <span className="system-label">Sistema</span>}</div><h3>{r.name}</h3><p>{data.profiles.filter(p => p.role_id === r.id && !p.deleted_at).length} membros · {r.permissions.length} permissões</p><ul>{r.permissions.map(p => <li key={p}><Check size={14}/>{permissions[p]}</li>)}</ul>{can('roles.manage') && <button className="text-btn lime-text" onClick={() => setModal({ type: 'role', id: r.id, duplicate: r.system && r.name === 'Administrador' })}>{r.system && r.name === 'Administrador' ? 'Duplicar perfil' : 'Editar permissões'}<ArrowUpRight size={15}/></button>}</section>)}</div>{can('roles.manage') && <PermissionLabels definitions={data.permissionDefinitions} busy={busy} onSave={p => run(() => rpc('save_permission_labels', p), 'Nomes das permissões atualizados.', false)}/>}</>}
   {page==='reports'&&<ReportsPage data={data} onRequest={q=>{go('requests');setModal({type:'request-detail',id:q.id});}} onExport={csv=>download('hadsec-relatorio.csv',csv,'text/csv;charset=utf-8')}/>}
   {page==='profile'&&<ProfilePage user={user} role={role} section={profileSection} onSectionChange={setProfileSection} onLogout={()=>db.auth.signOut({scope:'local'})} passwordForm={<PasswordForm busy={busy} onSubmit={p=>run(()=>gateway('password',p),'Senha alterada.',false)}/>}/>}
   {page==='audit'&&(can('audit.read')?<AuditPage data={data} name={name} Avatar={Avatar} onExport={rows=>download('hadsec-auditoria.json',JSON.stringify(rows,null,2),'application/json')}/>:<Empty icon={LockKeyhole} title="Acesso restrito" text="Seu perfil não tem permissão para consultar a auditoria."/>)}
   {page==='documentation'&&<RuleDocumentation/>}
   {page === 'settings' && <WorkspaceSettings section={settingsSection} onSectionChange={setSettingsSection} onGitHub={()=>go('github')} onDocs={()=>go('documentation')}/>}
   <footer className="footer"><span><span className="brand-mini"><OwlLogo /></span>HadSec Detect <span>·</span>Engenharia de detecção</span></footer>
   </main>}
  </div>
  {(modal || user?.must_change_password) && <Modal title={user?.must_change_password ? 'Defina sua nova senha' : modalTitle(modal)} wide={['rule', 'request-detail'].includes(modal?.type)} onClose={() => { if (!user?.must_change_password)
            setModal(null); }}>
   {user?.must_change_password ? <div className="modal-body"><p className="muted">Atualize a senha inicial para liberar o workspace.</p><PasswordForm busy={busy} onSubmit={v => run(() => gateway('password', v), 'Senha alterada. Seu workspace está pronto.')}/><button className="text-btn" onClick={() => db.auth.signOut({ scope: 'local' })}>Sair da conta</button></div> : <>
   {modal.type==='rule'&&<RuleForm rule={data.rules.find(r=>r.id===modal.id)} version={modal.id?latest(data.rules.find(r=>r.id===modal.id)):null} request={data.requests.find(q=>q.id===modal.requestId)} onBack={()=>setModal({type:'request-detail',id:modal.requestId})} busy={busy} onSubmit={p=>saveRule(p,modal.requestId)}/>}
   {modal.type==='delete-rule'&&<DeleteRuleForm rule={data.rules.find(r=>r.id===modal.id)} requests={data.requests} owner={canDeleteRecords} busy={busy} onSubmit={p=>run(async()=>{await gateway('rule.archive',p);setSelected(null);setRuleContext(null);},'Regra excluída da lista. Histórico preservado.')}/>}
   {modal.type === 'request' && <ChangeRequestForm rules={data.rules.filter(r=>!r.archived)} versions={data.versions} busy={busy} onSubmit={p=>run(()=>rpc('submit_change_request',p),'Solicitação criada.')}/>}
   {modal.type === 'request-detail' && <RequestDetail onDelete={canDeleteRecords?deleteRequest:null} isAdmin={role?.system&&role.name==='Administrador'} q={data.requests.find(q => q.id === modal.id)} data={data} name={name} can={can} user={user} busy={busy} run={run} notify={notify} createRule={q=>setModal({type:'rule',id:q.rule_id||undefined,requestId:q.id})} openRule={id => { setModal(null); openRule(id,modal.id); }}/>}
   {['delete-request','delete-submission'].includes(modal.type)&&<DeleteRecordForm request={data.requests.find(q=>q.id===modal.id)} submission={modal.type==='delete-submission'} busy={busy} onCancel={()=>setModal(null)} onSubmit={p=>run(()=>rpc(modal.type==='delete-submission'?'hide_github_submission':'delete_request',p),modal.type==='delete-submission'?'Envio excluído da lista.':'Solicitação excluída.')}/>}
   {modal.type === 'evidence' && <EvidenceForm simulation={modal.simulation} version={data.versions.find(v => v.id === modal.id)} rule={data.rules.find(r => r.id === data.versions.find(v => v.id === modal.id)?.rule_id)} busy={busy} onSubmit={p => run(() => rpc('record_evidence', p), 'Evidência registrada para esta versão.')}/>}
   {modal.type === 'delete-user' && <DeleteUserForm profile={data.profiles.find(p => p.id === modal.id)} busy={busy} onSubmit={p => run(() => gateway('user.delete', p), 'Conta excluída. Histórico preservado.')}/>}{['user', 'edit-user'].includes(modal.type) && <UserForm profile={data.profiles.find(p => p.id === modal.id)} roles={data.roles} busy={busy} onDelete={modal.id && modal.id !== user.id && data.roles.find(r => r.id === data.profiles.find(p => p.id === modal.id)?.role_id)?.name !== 'Administrador' ? () => setModal({ type: 'delete-user', id: modal.id }) : null} onSubmit={p => run(() => gateway(modal.type === 'user' ? 'user.create' : 'user.update', p), 'Conta atualizada.')}/>}
   {modal.type === 'edit-user' && can('roles.manage') && <IndividualPermissions profile={data.profiles.find(p => p.id === modal.id)} role={data.roles.find(r => r.id === data.profiles.find(p => p.id === modal.id)?.role_id)} definitions={data.permissionDefinitions} overrides={data.overrides} currentUserId={user.id} busy={busy} onSave={p => run(() => rpc('set_user_permissions', p), 'Permissões individuais atualizadas.', false)}/>}{modal.type === 'role' && <RoleForm role={data.roles.find(r => r.id === modal.id)} duplicate={modal.duplicate} busy={busy} onSubmit={p => run(() => rpc('save_role', p), 'Perfil salvo.')}/>}
   </>}
  </Modal>}
  {toast && <div role="status" className={`toast ${toast.kind}`}>{toast.kind === 'error' ? <AlertTriangle size={20}/> : <CheckCircle2 size={20}/>}<span>{toast.text}</span><button className="icon-btn" onClick={() => setToast(null)} aria-label="Fechar aviso"><X size={16}/></button></div>}
 </div>;
}
function PageHeading({ title, text, action }) { return <div className="page-heading"><div><h1>{title}<span className="title-dot">.</span></h1><p>{text}</p></div>{action}</div>; }
function SearchBox({ value, onChange }) { return <div className="search-box"><Search size={17}/><input aria-label="Filtrar resultados" value={value} placeholder="Buscar…" onChange={e => onChange(e.target.value)}/>{value && <button className="icon-btn" onClick={() => onChange('')} aria-label="Limpar busca"><X size={15}/></button>}</div>; }
function Tabs({ items, value, onChange }) { return <div className="tabs" role="tablist" aria-label="Filtrar por status">{items.map(i => <button role="tab" aria-selected={value === i} className={value === i ? 'active' : ''} onClick={() => onChange(i)} key={i}>{i === 'all' ? 'Todas' : statusMap[i]?.[0] || i}</button>)}</div>; }
function modalTitle(m) { return ({ rule: m?.id ? 'Criar nova versão' : 'Nova regra de detecção', request: 'Nova solicitação', 'request-detail': 'Revisar solicitação', 'delete-request':'Excluir solicitação','delete-submission':'Excluir envio', evidence: 'Registrar evidência', user: 'Criar conta', 'delete-rule': 'Excluir regra', 'delete-user': 'Excluir usuário', 'edit-user': 'Gerenciar conta', role: 'Perfil de acesso' })[m?.type] || ''; }
function download(name, text, type = 'text/plain') { const url = URL.createObjectURL(new Blob([text], { type })); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
function Login({ notify }) {
    const [busy, setBusy] = useState(false), [error, setError] = useState('');
    return <div className="login-page"><section className="panel login-card"><div className="login-logo" role="img" aria-label="HadSec Detect"><OwlLogo/><span aria-hidden="true">HadSec<span className="login-logo-detect">Detect<span className="lime-text">.</span></span></span></div><h1 className="sr-only">Entrar no HadSec Detect</h1>{!configured && <p className="error-text" role="alert">A conexão de autenticação não foi configurada nesta publicação. Avise o administrador.</p>}<form onSubmit={async (e) => { e.preventDefault(); setBusy(true); setError(''); const f = new FormData(e.currentTarget); try {
        if (!configured)
            throw new Error('A conexão de autenticação não foi configurada nesta publicação. Avise o administrador.');
        const login = String(f.get('username')).trim().toLowerCase();
        const { error } = await db.auth.signInWithPassword({ email: login.includes('@') ? login : `${login}@hadsec.local`, password: String(f.get('password')) });
        if (error)
            throw new Error('Usuário ou senha incorretos.');
    }
    catch (err) {
        setError(err.message);
    }
    finally {
        setBusy(false);
    } }}><Field label="Usuário"><input name="username" autoComplete="username" placeholder="Seu usuário" required/></Field><Field label="Senha"><PasswordInput name="password" autoComplete="current-password" placeholder="Sua senha" required/></Field>{error && <p className="error-text" role="alert">{error}</p>}<button className="btn primary full" disabled={busy || !configured}>{busy ? <Loader2 className="spin" size={18}/> : <ArrowRight size={18}/>}Entrar no workspace</button></form></section></div>;
}
function NativeSummary({ content }) {
    const meta = useMemo(() => { if (!content)
        return null; try {
        const definitions = parseFortiSIEM(content);
        return definitions.length === 1 ? definitions[0] : null;
    }
    catch {
        return null;
    } }, [content]);
    if (!meta)
        return null;
    return <section className="native-summary"><h3><ShieldCheck size={18}/>Definição FortiSIEM</h3><dl>{[['Evento do incidente', meta.eventType], ['Fonte de dados', meta.dataSource], ['Tecnologia', meta.technology], ['Severidade nativa', meta.nativeSeverity ? `${meta.nativeSeverity} / 10` : null], ['Táticas MITRE', meta.tactics], ['Técnica MITRE', meta.technique], ['Janela de correlação', meta.window ? `${meta.window} segundos` : null], ['Frequência de notificação', meta.notificationFrequency ? `${meta.notificationFrequency} segundos` : null], ['Tags de incidente', meta.tags.join(', ')], ['Watch lists', meta.watchLists.map(w => `${w.name} (${w.attribute})`).join(', ')]].filter(([, value]) => value).map(([label, value]) => <React.Fragment key={label}><dt>{label}</dt><dd>{value}</dd></React.Fragment>)}</dl><details><summary>Ver condições e atributos</summary>{meta.patterns.map(p => <div className="native-pattern" key={p.name}><strong>{p.name}</strong><p>Filtro <code>{p.filter}</code></p><p>Agregação <code>{p.aggregate || '—'}</code></p><p>Agrupamento <code>{p.groupBy || '—'}</code></p></div>)}{meta.incidentMapping && <div className="native-pattern"><strong>Mapeamento do incidente</strong><pre>{meta.incidentMapping}</pre></div>}<p className="native-attributes">Atributos disparadores: {meta.triggeredAttributes.join(', ') || 'Não informados'}</p></details></section>;
}
function Report({ report }) { return report && <div className="validation-report"><div className={`report-result ${report.ok ? 'green' : 'red'}`}>{report.ok ? <CheckCircle2 size={20}/> : <AlertTriangle size={20}/>}<strong>{report.ok ? 'Verificações estáticas concluídas' : 'Corrija os problemas encontrados'}</strong><Badge tone="muted">Parcial</Badge></div>{report.errors.map((e, i) => <p className="report-error" key={i}><X size={15}/>{String(e).replace(/FortiSIEM\s+v?\d+(?:\.\d+)+/gi,'FortiSIEM')}</p>)}{report.warnings.map((w, i) => <p key={i}><AlertTriangle size={15}/>{String(w).replace(/FortiSIEM\s+v?\d+(?:\.\d+)+/gi,'FortiSIEM')}</p>)}</div>; }
function RuleForm({ rule, version, request, onBack, busy, onSubmit }) {
    const formRef = useRef(null);
    const initialFormat=rule?.format||request?.requested_format||'sql';
    const [format, setFormat] = useState(initialFormat), [content, setContent] = useState(version?.content || formatInfo(initialFormat).sample || ''), [report, setReport] = useState(null), [mode, setMode] = useState(rule?.mode || 'Scheduled via SQL');
    return <form ref={formRef} className="modal-body" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); onSubmit({ p_rule_id: rule?.id || null, p_name: rule?.name || f.get('name'), p_description: rule?.description || f.get('description'), p_severity: rule?.severity || f.get('severity'), p_technique: rule?.technique || f.get('technique'), p_mode: modeForFormat(format,content,rule?.mode), p_format: format, p_content: content, p_note: f.get('note'), p_expected_version: version?.number || 0 }); }}>
  {request&&<div className="request-context"><span><GitPullRequest size={18}/><strong>{request.title}</strong></span><button type="button" className="text-btn" onClick={onBack}>Voltar à solicitação<ArrowUpRight size={15}/></button></div>}
  {!rule && <><Field label="Nome da regra"><input name="name" defaultValue={request?.title||''} minLength={3} maxLength={160} required placeholder="Ex.: Múltiplas falhas de autenticação"/></Field><Field label="Objetivo da detecção"><textarea name="description" defaultValue={request?.description||''} rows={2} placeholder="Descreva o comportamento que a regra detecta." required/></Field><div className="form-grid"><Field label="Severidade"><select name="severity"><option>Alta</option><option>Crítica</option><option>Média</option><option>Baixa</option></select></Field><Field label="Técnica MITRE ATT&CK"><input name="technique" placeholder="T1110" pattern="T[0-9]{4}(\.[0-9]{3})?"/></Field></div></>}
  <FormatSelect value={format} disabled={!!rule} onChange={id=>{setFormat(id);setMode(modeForFormat(id));setContent(formatInfo(id).sample||'');setReport(null);}}/>
  <label className="import-button"><Upload size={16}/>Importar arquivo .{formatInfo(format).extension}<input type="file" accept={`.${formatInfo(format).extension}${format==='sigma'?',.yaml':''}${format==='yara'?',.yara':''}`} onChange={async (e) => { const file = e.target.files[0]; if (file) {
        if (file.size > 500000) {
            e.target.setCustomValidity('Arquivo maior que 500 KB');
            e.target.reportValidity();
            return;
        }
        const imported = await file.text();
        setContent(imported);
        setReport(null);
        if (format === 'xml') {
            try {
                const [meta] = parseFortiSIEM(imported);
                if (!rule) {
                    for (const [key, value] of Object.entries({ name: meta.name, description: meta.description, severity: meta.severity, technique: meta.technique })) {
                        const field = formRef.current?.elements.namedItem(key);
                        if (field)
                            field.value = value;
                    }
                    if (['Streaming', 'Scheduled'].includes(meta.mode))
                        setMode(meta.mode);
                }
            }
            catch { }
        }
    } }}/></label>
  {format === 'xml' && !content && <div className="inline-alert">Exporte a regra em Resources → Rules → Export e importe o XML aqui. A plataforma preserva a definição original.</div>}
  <CodeEditor value={content} onChange={v => { setContent(v); setReport(null); }} format={format}/><NativeSummary content={format === 'xml' ? content : null}/><Report report={report}/><Field label="O que mudou nesta versão?"><textarea name="note" minLength={3} maxLength={4000} rows={2} required placeholder="Informe o ajuste e o motivo da mudança."/></Field><div className="form-actions"><button type="button" className="btn" onClick={() => setReport(validateRule(content, format, modeForFormat(format,content,rule?.mode)))}><FlaskConical size={17}/>Verificar estrutura</button><button className="btn primary" disabled={busy || !content.trim()}>{busy ? <Loader2 size={17} className="spin"/> : <GitCommitHorizontal size={17}/>}{request?'Salvar, validar e enviar':version?'Salvar v'+(version.number+1):'Salvar e validar'}</button></div>
 </form>;
}
function RuleDetail({ rule, data, latest, name, can, busy, run, notify, back, setModal, requestContext, onRequest }) {
    const versions = data.versions.filter(v => v.rule_id === rule?.id).sort((a, b) => b.number - a.number);
    const [id, setId] = useState(null), [tab, setTab] = useState('code');
    const v = versions.find(x => x.id === id) || versions[0], previous = versions.find(x => x.number === v?.number - 1);
    const requests = data.requests.filter(q => q.version_id === v?.id && (requestVisible(q)||q.status==='published'));
    const draftRequest=requestContext&&['requested','changes'].includes(requestContext.status)?requestContext:null;
    if (!rule || !v)
        return <Empty />;
    return <><button className="back-link" onClick={back}><ChevronLeft size={17}/>Todas as regras</button><PageHeading title={rule.name} text={`${rule.technique || 'Sem técnica MITRE'} · ${formatInfo(rule.format).label}`} action={can('rules.write')&&!rule.archived&&<div className="rule-heading-actions"><button className="btn danger" onClick={()=>setModal({type:'delete-rule',id:rule.id})}><Trash2 size={17}/>Excluir regra</button><button className="btn primary" onClick={()=>setModal({type:'rule',id:rule.id,requestId:draftRequest?.id})}><Plus size={18}/>Nova versão</button></div>}/>{rule.archived&&<div className="inline-alert">Esta regra foi excluída da lista. O histórico permanece disponível para consulta.</div>}{requestContext&&<div className="request-context"><span><GitPullRequest size={18}/><strong>{requestContext.title}</strong></span><button className="text-btn" onClick={()=>onRequest(requestContext)}>Abrir solicitação<ArrowUpRight size={16}/></button></div>}<div className="detail-grid"><section className="panel"><div className="panel-heading"><div className="tabs"><button className={tab === 'code' ? 'active' : ''} onClick={() => setTab('code')}>Definição</button><button className={tab === 'diff' ? 'active' : ''} onClick={() => setTab('diff')}>Comparar versões</button><button className={tab === 'tests' ? 'active' : ''} onClick={() => setTab('tests')}>Evidências</button></div><button className="icon-btn" aria-label="Baixar versão" onClick={() => download(`regra-v${v.number}.${rule.format}`, v.content)}><Download size={18}/></button></div>{tab === 'code' && <><NativeSummary content={rule.format === 'xml' ? v.content : null}/><CodeEditor value={v.content} readOnly format={rule.format}/><div className="detail-padding"><Report report={v.validation_report}/>{!v.validation_report && <p className="muted">{v.validated ? 'Validação estática registrada.' : 'Esta versão ainda não passou pela validação estática.'}</p>}<div className="button-row">{can('rules.write')&&!rule.archived && <button className="btn" disabled={busy} onClick={() => run(() => gateway('validate', { version_id: v.id }), report=>report.ok?'Validação registrada. Versão pronta para revisão.':'A validação encontrou problemas. Consulte os detalhes abaixo.', false)}><FlaskConical size={17}/>Validar versão</button>}{(draftRequest?can('rules.write'):can('requests.create'))&&!rule.archived && <button className="btn primary" disabled={busy || !v.validated || requests.some(versionRequestActive)} onClick={() => run(() => draftRequest?rpc('attach_version',{p_request:draftRequest.id,p_version:v.id}):rpc('create_request', { p_title: `Revisar ${rule.name} · v${v.number}`, p_description: v.change_note, p_rule_id: rule.id, p_version_id: v.id }), 'Versão enviada para revisão.', false)}><Send size={17}/>{draftRequest?'Vincular à solicitação':'Solicitar revisão'}</button>}</div></div></>}{tab === 'diff' && <div className="detail-padding"><p className="muted">{previous ? `v${previous.number} → v${v.number}` : 'Primeira versão: todo o conteúdo foi adicionado.'}</p><div className="diff-code">{diffLines(previous?.content || '', v.content).map((l, i) => <pre className={l.type} key={i}><span>{l.type === 'added' ? '+' : l.type === 'removed' ? '−' : ' '}</span>{l.text || ' '}</pre>)}</div></div>}{tab === 'tests' && <div className="detail-padding">{can('tests.record') && <button className="btn primary" onClick={() => setModal({ type: 'evidence', id: v.id })}><Plus size={17}/>Registrar evidência</button>}{data.evidence.filter(e => e.version_id === v.id).map(e => <div className="evidence-card" key={e.id}><Badge tone={e.result === 'pass' ? 'green' : 'red'}>{e.result === 'pass' ? 'Aprovado' : 'Falhou'}</Badge><strong>{e.method}</strong><p>{e.notes}</p><small>{name(e.created_by)} · {new Date(e.created_at).toLocaleString('pt-BR')}</small></div>)}{!data.evidence.some(e => e.version_id === v.id) && <Empty icon={FlaskConical} title="Nenhum teste registrado" text="As evidências devem corresponder exatamente ao conteúdo desta versão."/>}</div>}</section><aside><section className="panel detail-padding metadata"><h2>Sobre a regra</h2><p>{rule.description}</p><dl><dt>Severidade</dt><dd><Badge tone={rule.severity === 'Crítica' ? 'red' : 'orange'}>{rule.severity}</Badge></dd><dt>Autor da versão</dt><dd>{name(v.created_by)}</dd><dt>Verificação estática</dt><dd>{v.validated ? 'Concluída · parcial' : 'Pendente'}</dd></dl><h3>Histórico de versões</h3>{versions.map(x => <button className={`version-item ${x.id === v.id ? 'active' : ''}`} key={x.id} onClick={() => setId(x.id)}><GitCommitHorizontal size={20}/><div><strong>v{x.number}{data.requests.some(q=>q.baseline_version_id===x.id)&&' · Original'}</strong><small>{x.change_note}</small><small>{name(x.created_by)} · {date(x.created_at)}</small></div>{x.id === v.id && <Check size={16}/>}</button>)}<small className="hash">SHA-256<br />{v.content_sha256}</small></section></aside></div></>;
}
function diffLines(oldText, newText) { const a = oldText.split('\n'), b = newText.split('\n'); if (!oldText)
    return b.map(text => ({ text, type: 'added' })); if (a.length * b.length > 1000000)
    return [...a.map(text => ({ text, type: 'removed' })), ...b.map(text => ({ text, type: 'added' }))]; const dp = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1)); for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
        dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]); let i = 0, j = 0, out = []; while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j])
        out.push({ text: a[i++], type: 'same' }), j++;
    else if (j < b.length && (i === a.length || dp[i][j + 1] >= dp[i + 1][j]))
        out.push({ text: b[j++], type: 'added' });
    else
        out.push({ text: a[i++], type: 'removed' });
} return out; }
function RequestsList({rows,data,name,busy,onOpen,onDelete}){
 return [...rows].sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at)).map(q=><div className="request-row-shell" key={q.id}>
  <button className="request-row" onClick={()=>onOpen(q)}><span className={`request-icon ${statusMap[q.status]?.[1]}`}><GitPullRequest size={22}/></span><div className="request-title"><h3>{q.title}</h3><p>{q.request_kind==='change'?'Alteração':'Criação'}<span>·</span>{name(q.created_by)}<span>·</span>{ago(q.created_at)}<span>·</span>{q.version_id?`v${data.versions.find(v=>v.id===q.version_id)?.number}`:'Aguardando versão'}</p></div><Badge status={q.status}/><ChevronRight size={18}/></button>
  {onDelete&&<button className="icon-btn delete-rule-button request-row-delete" aria-label={'Excluir solicitação '+q.title} title="Excluir solicitação" disabled={busy} onClick={()=>onDelete(q)}><Trash2 size={18}/></button>}
 </div>);
}
function RequestDetail({ q, data, name, can, user, busy, run, notify, openRule, createRule, isAdmin, onDelete }) {
    const v = data.versions.find(v => v.id === q?.version_id), rule = data.rules.find(r => r.id === q?.rule_id), [decision, setDecision] = useState('approved');
    if(!q||!requestVisible(q))return <div className="modal-body"><Empty title="Solicitação indisponível" text="Este registro foi excluído da lista."/></div>;
    const baseline=data.versions.find(item=>item.id===q.baseline_version_id);
    const eligible = data.versions.filter(v => (!q.rule_id || v.rule_id === q.rule_id) && v.validated && (!baseline||v.number>baseline.number&&v.content_sha256!==baseline.content_sha256) && !data.rules.find(r=>r.id===v.rule_id)?.archived && !data.requests.some(other=>other.id!==q.id&&other.version_id===v.id&&versionRequestActive(other)));
    const evidence = data.evidence.filter(e => e.version_id === v?.id);
    return <div className="modal-body"><div className="request-detail-title"><Badge status={q.status}/><h2>{q.title}</h2><p>{name(q.created_by)} · {new Date(q.created_at).toLocaleString('pt-BR')}</p></div><p className="request-description">{q.description}</p><p className="request-kind-label">{q.request_kind==='change'?'Alterar regra':'Criar nova regra'}</p>{baseline&&<details className="baseline-card"><summary>Versão original · v{baseline.number}</summary><CodeEditor value={baseline.content} readOnly format={rule?.format}/><small>SHA-256: {baseline.content_sha256}</small></details>}{can('rules.write')&&['requested','changes'].includes(q.status)&&!rule?.archived&&<div className="request-next-step"><div><strong>{rule?'Desenvolver o ajuste':'Criar a detecção'}</strong><p>{rule?'Abra o editor para preparar uma nova versão.':'O contexto desta solicitação será levado ao editor.'}</p></div><button className="btn primary" onClick={()=>createRule(q)}><Code2 size={18}/>{rule?'Editar regra':'Criar regra'}</button></div>}{rule && <button className="linked-rule" onClick={() => openRule(rule.id)}><FileCode2 size={19}/><span>{rule.name}<small>{v ? `v${v.number} · ${v.content_sha256.slice(0, 16)}` : 'Sem versão vinculada'}</small></span><ArrowUpRight size={18}/></button>}{v && <><CodeEditor value={v.content} readOnly format={rule?.format}/><div className="review-checks"><span className={v.validated ? 'green' : 'amber'}>{v.validated ? <CheckCircle2 size={17}/> : <Clock size={17}/>}Validação estática {v.validated ? 'concluída' : 'pendente'}</span><span className={evidence.some(e => e.result === 'pass' && ['FortiSIEM SQL','FortiSIEM Streaming','Teste no motor de destino'].includes(e.method)) ? 'green' : 'amber'}><FlaskConical size={17}/>{evidence.length} evidência(s) de teste</span></div>{evidence.map(e => <div className="evidence-card" key={e.id}><Badge tone={e.result === 'pass' ? 'green' : 'red'}>{e.result === 'pass' ? 'Aprovado' : 'Falhou'}</Badge><strong>{e.method}</strong><p>{e.notes}</p></div>)}</>}
  {can('rules.write') && ['requested', 'changes'].includes(q.status) && <form className="subform" onSubmit={e => { e.preventDefault(); const id = new FormData(e.currentTarget).get('version'); run(() => rpc('attach_version', { p_request: q.id, p_version: id }), 'Versão vinculada para revisão.', false); }}><h3>Encaminhar para revisão</h3><Field label="Versão validada"><select name="version" required defaultValue=""><option value="" disabled>Selecione uma versão</option>{eligible.map(v => <option value={v.id} key={v.id}>{data.rules.find(r => r.id === v.rule_id)?.name} · v{v.number}</option>)}</select></Field><button className="btn primary" disabled={busy || !eligible.length}><Send size={16}/>Vincular e enviar</button></form>}
  {can('requests.review') && q.status === 'review' && ((q.created_by === user.id || v?.created_by === user.id)&&!isAdmin ? <div className="inline-alert"><LockKeyhole size={18}/>Esta versão precisa ser revisada por outra pessoa.</div> : <form className="subform" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); run(() => rpc('decide_request', { p_request: q.id, p_decision: decision, p_note: f.get('note') }), 'Decisão registrada.', false); }}><h3>Decisão de revisão</h3>{isAdmin&&(q.created_by===user.id||v?.created_by===user.id)&&<div className="inline-alert admin-approval-note"><ShieldCheck size={19}/><span>Como administrador, você pode aprovar, solicitar ajustes ou rejeitar sem outro revisor. Para aprovar, a validação e a evidência de teste continuam obrigatórias.</span></div>}<Field label="Resultado"><select value={decision} onChange={e => setDecision(e.target.value)}><option value="approved">Aprovar versão</option><option value="changes">Solicitar ajustes</option><option value="rejected">Rejeitar</option></select></Field><Field label="Justificativa"><textarea name="note" minLength={5} maxLength={8000} required rows={3} placeholder="Registre os critérios da sua decisão."/></Field><button className="btn primary" disabled={busy}><ShieldCheck size={17}/>{isAdmin&&(q.created_by===user.id||v?.created_by===user.id)?{approved:'Aprovar como administrador',changes:'Solicitar ajustes como administrador',rejected:'Rejeitar como administrador'}[decision]:'Registrar decisão'}</button></form>)}
  {q.review_note && <div className="review-note"><strong>Parecer de {name(q.reviewed_by)}</strong><p>{q.review_note}</p></div>}{q.github_url && <a className="btn" href={q.github_url} target="_blank" rel="noreferrer"><Github size={17}/>Abrir pull request <ExternalLink size={15}/></a>}
  {onDelete&&<div className="request-delete-action"><button className="btn danger" disabled={busy} onClick={()=>onDelete(q)}><Trash2 size={17}/>Excluir solicitação</button></div>}
  <div className="subform"><h3>Discussão</h3>{data.comments.filter(c => c.request_id === q.id).map(c => <div className="comment" key={c.id}><Avatar small name={name(c.created_by)}/><div><strong>{name(c.created_by)} <small>{ago(c.created_at)}</small></strong><p>{c.body}</p></div></div>)}<form onSubmit={e => { e.preventDefault(); const form = e.currentTarget, body = new FormData(form).get('body'); run(async () => { await rpc('add_comment', { p_request: q.id, p_body: body }); form.reset(); }, 'Comentário adicionado.', false); }}><Field label="Adicionar comentário"><textarea name="body" required maxLength={8000} rows={2} placeholder="Compartilhe detalhes com a equipe."/></Field><button className="btn" disabled={busy}><Send size={16}/>Comentar</button></form></div>
 </div>;
}
function EvidenceForm({version,rule,busy,onSubmit,simulation}){
 return <form className="modal-body" onSubmit={event=>{event.preventDefault();const data=new FormData(event.currentTarget);onSubmit({p_version:version.id,p_method:data.get('method'),p_result:data.get('result'),p_notes:data.get('notes')});}}><p className="muted">{rule.name} · v{version.number}</p><div className="inline-alert">A evidência corresponde a esta versão. Simulação local e revisão manual não substituem o teste no motor de destino para aprovação.</div><Field label="Método de teste"><select name="method" defaultValue={simulation?'Simulação local':'Teste no motor de destino'}><option>Teste no motor de destino</option><option>Simulação local</option><option>Revisão manual</option></select></Field><Field label="Resultado"><select name="result" defaultValue={simulation?.status==='no-match'?'fail':'pass'}><option value="pass">Aprovado</option><option value="fail">Falhou</option></select></Field><Field label="Ambiente, passos e resultado observado"><textarea name="notes" rows={5} minLength={10} maxLength={8000} required defaultValue={simulation?'Simulação local: '+simulation.matched+' de '+simulation.total+' eventos corresponderam à regra. Escopo: evento isolado.':''}/></Field><button className="btn primary" disabled={busy}><CheckCheck size={17}/>Registrar evidência</button></form>;
}
function UserForm({ profile, roles, busy, onSubmit, onDelete }) { return <form className="modal-body" onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); onSubmit(profile ? { id: profile.id, role_id: f.get('role'), active: f.get('active') === 'true' } : { username: f.get('username'), display_name: f.get('name'), password: f.get('password'), role_id: f.get('role') }); }}>{!configured && <div className="inline-alert">A criação de contas exige a conexão real com Supabase Auth.</div>}{profile ? <p className="muted">{profile.display_name} · @{profile.username}</p> : <><Field label="Nome"><input name="name" required minLength={2} maxLength={80}/></Field><Field label="Usuário" hint="Letras, números, pontos, hífens e sublinhado."><input name="username" autoComplete="off" required minLength={3} maxLength={40} pattern="[A-Za-z0-9_.\-]+"/></Field><Field label="Senha inicial" hint="A conta deverá alterar a senha no primeiro acesso."><PasswordInput name="password" required minLength={10} maxLength={128} autoComplete="new-password"/></Field></>}<Field label="Perfil de acesso"><select name="role" defaultValue={profile?.role_id || [...roles].filter(r => !(r.system && r.name === 'Administrador')).sort((a, b) => a.permissions.length - b.permissions.length)[0]?.id}>{roles.map(r => <option value={r.id} key={r.id}>{r.name}</option>)}</select></Field>{profile && <Field label="Status da conta"><select name="active" defaultValue={String(profile.active)}><option value="true">Ativa</option><option value="false">Desativada</option></select></Field>}<button className="btn primary" disabled={busy || !configured}><Users size={17}/>{profile ? 'Salvar alterações' : 'Criar conta'}</button>{onDelete && <button type="button" className="btn danger delete-account" onClick={onDelete}>Excluir usuário</button>}</form>; }
function IndividualPermissions({ profile, role, definitions, overrides, currentUserId, busy, onSave }) {
    const initial = Object.fromEntries(definitions.map(d => { const o = overrides.find(o => o.user_id === profile.id && o.permission === d.key); return [d.key, o ? o.granted ? 'allow' : 'deny' : 'inherit']; }));
    const [values, setValues] = useState(initial), protectedUser = profile.id === currentUserId || (role?.system && role.name === 'Administrador');
    return <form className="modal-body individual-permissions" onSubmit={e => { e.preventDefault(); onSave({ p_user: profile.id, p_overrides: Object.fromEntries(Object.entries(values).filter(([, value]) => value !== 'inherit').map(([key, value]) => [key, value === 'allow'])) }); }}>
  <h3>Permissões individuais</h3><p className="muted">Perfil global: {role?.name}. Exceções individuais prevalecem sobre o perfil.</p>
  {protectedUser ? <div className="inline-alert"><LockKeyhole size={17}/>{profile.id === currentUserId ? 'Outro administrador deve alterar suas permissões.' : 'O administrador do sistema mantém as permissões protegidas.'}</div> : <>
  <div className="individual-list">{definitions.map(d => <div className="individual-row" key={d.key}><div><strong>{d.label}</strong><small>{d.key} · Perfil: {role?.permissions.includes(d.key) ? 'permitido' : 'bloqueado'}</small></div><select aria-label={`${d.label} para ${profile.username}`} value={values[d.key]} onChange={e => setValues({ ...values, [d.key]: e.target.value })}><option value="inherit">Herdar perfil</option><option value="allow">Permitir</option><option value="deny">Bloquear</option></select></div>)}</div>
  <button className="btn primary" disabled={busy}><ShieldCheck size={17}/>Salvar permissões individuais</button></>}
 </form>;
}
function PermissionLabels({ definitions, busy, onSave }) {
    const [rows, setRows] = useState(definitions.map(d => ({ ...d })));
    return <section className="panel permission-label-panel"><div className="panel-heading"><div><h2>Nomes das permissões</h2><p>Os nomes exibidos mudam em todo o painel. Os identificadores internos permanecem os mesmos.</p></div></div><form className="detail-padding" onSubmit={e => { e.preventDefault(); onSave({ p_definitions: rows }); }}><div className="permission-label-grid">{rows.map((d, i) => <div className="permission-label-item" key={d.key}><code>{d.key}</code><Field label={`Nome de ${d.key}`}><input value={d.label} minLength={3} maxLength={100} required onChange={e => setRows(rows.map((r, j) => i === j ? { ...r, label: e.target.value } : r))}/></Field><Field label={`Descrição de ${d.key}`}><input value={d.description || ''} maxLength={500} onChange={e => setRows(rows.map((r, j) => i === j ? { ...r, description: e.target.value } : r))}/></Field></div>)}</div><div className="form-actions"><button className="btn primary" disabled={busy}><Check size={17}/>Salvar nomes das permissões</button></div></form></section>;
}
function DeleteRuleForm({rule,requests,owner,busy,onSubmit}){
 const [confirmation,setConfirmation]=useState('');
 const linked=requests.filter(q=>q.rule_id===rule.id&&!q.deleted_at),restricted=!owner&&(linked.length>0||requests.some(q=>q.rule_id===rule.id&&q.status==='published'));
 return <form className="modal-body" onSubmit={e=>{e.preventDefault();if(confirmation===rule.name)onSubmit({rule_id:rule.id,confirmation});}}>
 <div className="inline-alert"><AlertTriangle size={21}/><span>{restricted?'Somente o proprietário pode excluir esta regra e suas solicitações vinculadas.':linked.length?`A regra e ${linked.length} ${linked.length===1?'solicitação vinculada sairão':'solicitações vinculadas sairão'} das listas. Versões, evidências e auditoria serão preservadas. Pull requests e arquivos no GitHub permanecem.`:'A regra sairá das listas de detecção. Versões, evidências e auditoria serão preservadas.'}</span></div>
 <Field label={'Digite '+rule.name+' para confirmar'}><input value={confirmation} onChange={e=>setConfirmation(e.target.value)} autoComplete="off" placeholder={rule.name} required/></Field>
 <button className="btn danger full" disabled={busy||restricted||confirmation!==rule.name}>{busy?<Loader2 size={18} className="spin"/>:<Trash2 size={18}/>}Excluir regra</button></form>;
}
function DeleteUserForm({ profile, busy, onSubmit }) {
    const [confirmation, setConfirmation] = useState('');
    return <form className="modal-body" onSubmit={e => { e.preventDefault(); if (confirmation === profile.username)
        onSubmit({ id: profile.id, confirmation }); }}>
  <div className="inline-alert error-text"><AlertTriangle size={20}/><span>A conta de <strong>{profile.display_name}</strong> perderá o acesso. Versões, solicitações e auditoria serão preservadas.</span></div>
  
  <Field label={`Digite ${profile.username} para confirmar`}><input value={confirmation} onChange={e => setConfirmation(e.target.value)} autoComplete="off" required placeholder={profile.username}/></Field>
  <button className="btn danger full" disabled={busy || !configured || confirmation !== profile.username}>{busy ? <Loader2 className="spin" size={17}/> : <X size={17}/>}Excluir usuário</button>
 </form>;
}
function RoleForm({ role, duplicate, busy, onSubmit }) { const [selected, setSelected] = useState(role?.permissions || []); return <form className="modal-body" onSubmit={e => { e.preventDefault(); onSubmit({ p_id: duplicate ? null : role?.id || null, p_name: new FormData(e.currentTarget).get('name'), p_permissions: selected }); }}><Field label="Nome do perfil"><input name="name" required minLength={3} maxLength={80} defaultValue={duplicate ? `${role.name} personalizado` : role?.name}/></Field><div className="permission-list">{Object.entries(permissions).map(([key, label]) => <label key={key}><input type="checkbox" checked={selected.includes(key)} onChange={e => setSelected(e.target.checked ? [...selected, key] : selected.filter(p => p !== key))}/><span>{label}<small>{key}</small></span></label>)}</div><button className="btn primary" disabled={busy}><ShieldCheck size={17}/>Salvar perfil</button></form>; }
function PasswordForm({ busy, onSubmit }) { const [error, setError] = useState(''); return <form onSubmit={e => { e.preventDefault(); const f = new FormData(e.currentTarget); if (f.get('password') !== f.get('confirm')) {
    setError('As senhas não coincidem.');
    return;
} if (f.get('password') === f.get('current')) {
    setError('A nova senha precisa ser diferente.');
    return;
} setError(''); onSubmit({ currentPassword: f.get('current'), password: f.get('password') }); }}><Field label="Senha atual"><PasswordInput label="senha atual" name="current" required autoComplete="current-password"/></Field><Field label="Nova senha" hint="Use pelo menos 10 caracteres."><PasswordInput label="nova senha" name="password" required minLength={10} maxLength={128} autoComplete="new-password"/></Field><Field label="Confirmar nova senha"><PasswordInput label="confirmação de senha" name="confirm" required minLength={10} maxLength={128} autoComplete="new-password"/></Field>{error && <p className="error-text">{error}</p>}<button className="btn primary" disabled={busy || !configured}><KeyRound size={17}/>Alterar senha</button></form>; }
createRoot(document.getElementById('root')).render(<App />);
