import React,{useEffect,useRef,useState} from 'react';
import {Bell,CheckCheck,ChevronRight,GitPullRequest,KeyRound,Plug,Info,Settings,LogOut,X} from 'lucide-react';

export function WorkspaceMenus({user,role,requests,onRequest,onRequests,onSettings,onLogout}){
 const [open,setOpen]=useState(null),[seen,setSeen]=useState(()=>{
  try{return JSON.parse(localStorage.getItem(`hadsec-seen-${user.id}`)||'{}');}catch{return {};}
 });
 const root=useRef(null),trigger=useRef(null);
 const items=requests.filter(q=>['requested','review','changes'].includes(q.status)).sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at));
 const unread=q=>seen[q.id]!==q.updated_at;
 const count=items.filter(unread).length;
 const mark=rows=>setSeen(old=>{const next={...old,...Object.fromEntries(rows.map(q=>[q.id,q.updated_at]))};try{localStorage.setItem(`hadsec-seen-${user.id}`,JSON.stringify(next));}catch{}return next;});
 useEffect(()=>{
  if(!open)return;
  const close=e=>{if(e.type==='keydown'&&e.key==='Escape'){setOpen(null);trigger.current?.focus();}else if(e.type==='pointerdown'&&!root.current?.contains(e.target))setOpen(null);};
  document.addEventListener('pointerdown',close);document.addEventListener('keydown',close);
  return()=>{document.removeEventListener('pointerdown',close);document.removeEventListener('keydown',close);};
 },[open]);
 const toggle=(name,event)=>{trigger.current=event.currentTarget;setOpen(old=>old===name?null:name);};
 const navigate=section=>{setOpen(null);onSettings(section);};
 return <div className="topbar-actions workspace-menus" ref={root}>
  <button className="icon-btn notification" aria-label={`Notificações${count?`, ${count} novas`:''}`} aria-expanded={open==='notifications'} aria-controls="request-notifications" aria-haspopup="dialog" onClick={e=>toggle('notifications',e)}><Bell size={21}/>{count>0&&<b className="notification-count">{count>99?'99+':count}</b>}</button>
  <button className="account-trigger" aria-label="Abrir menu da conta" aria-expanded={open==='profile'} aria-controls="account-menu" aria-haspopup="menu" onClick={e=>toggle('profile',e)}><span className="avatar small">{(user.display_name||user.username).split(/\s+/).slice(0,2).map(n=>n[0]).join('').toUpperCase()}</span></button>
  {open==='notifications'&&<section className="header-popover notification-popover" id="request-notifications" role="dialog" aria-label="Novas solicitações">
   <div className="popover-heading"><div><h2>Solicitações</h2><p>{count?`${count} novas atualizações`:'Você está em dia'}</p></div><button className="icon-btn" aria-label="Fechar notificações" onClick={()=>{setOpen(null);trigger.current?.focus();}}><X size={18}/></button></div>
   {count>0&&<button className="text-btn mark-read" onClick={()=>mark(items)}><CheckCheck size={16}/>Marcar todas como lidas</button>}
   <div className="notification-list">{items.slice(0,20).map(q=><button key={q.id} className={`notification-item ${unread(q)?'unread':''}`} onClick={()=>{mark([q]);setOpen(null);onRequest(q);}}><span className="notification-symbol"><GitPullRequest size={18}/></span><span><strong>{q.title}</strong><small>{{requested:'Nova solicitação',review:'Aguardando revisão',changes:'Ajustes solicitados'}[q.status]} · {new Date(q.updated_at).toLocaleDateString('pt-BR')}</small></span><ChevronRight size={16}/></button>)}</div>
   {!items.length&&<div className="popover-empty"><Bell size={25}/><p>Nenhuma solicitação pendente.</p></div>}
   <button className="popover-footer" onClick={()=>{setOpen(null);onRequests();}}>Ver todas as solicitações<ChevronRight size={17}/></button>
  </section>}
  {open==='profile'&&<div className="header-popover account-popover" id="account-menu" role="menu" aria-label="Menu da conta"><div className="account-summary"><strong>{user.display_name}</strong><small>@{user.username} · {role?.name}</small></div><button role="menuitem" onClick={()=>navigate('connections')}><Plug size={18}/>Conexões</button><button role="menuitem" onClick={()=>navigate('password')}><KeyRound size={18}/>Alterar senha</button><button role="menuitem" onClick={()=>navigate('about')}><Info size={18}/>Sobre a ferramenta</button><button role="menuitem" onClick={()=>navigate('connections')}><Settings size={18}/>Configurações</button><button role="menuitem" className="account-logout" onClick={()=>{setOpen(null);onLogout();}}><LogOut size={18}/>Sair da conta</button></div>}
 </div>;
}
