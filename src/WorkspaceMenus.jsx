import React,{useEffect,useRef,useState} from 'react';
import {Bell,CheckCheck,ChevronRight,GitPullRequest,FileCode2,KeyRound,UserRound,LogOut,X,RotateCcw,Loader2} from 'lucide-react';
import {gateway} from './api';

export function WorkspaceMenus({user,role,revision,onNotification,onProfile,onLogout}){
 const [open,setOpen]=useState(null),[items,setItems]=useState([]),[loading,setLoading]=useState(false),[error,setError]=useState('');
 const [seen,setSeen]=useState(()=>{try{const stored=JSON.parse(localStorage.getItem(`hadsec-event-seen-${user.id}`)||'{}');return stored&&typeof stored==='object'&&!Array.isArray(stored)?stored:{};}catch{return {};}});
 const root=useRef(null),trigger=useRef(null),generation=useRef(0);
 const check=async()=>{const attempt=++generation.current;setLoading(true);setError('');try{const result=await gateway('notifications.list');if(attempt===generation.current)setItems(result.items);}catch(e){if(attempt===generation.current)setError(e.message);}finally{if(attempt===generation.current)setLoading(false);}};
 useEffect(()=>{check();const update=()=>{if(!document.hidden)check();};const timer=setInterval(update,45000);window.addEventListener('focus',update);return()=>{generation.current++;clearInterval(timer);window.removeEventListener('focus',update);};},[user.id,revision]);
 const unread=item=>seen[item.id]!==item.createdAt,count=items.filter(unread).length;
 const mark=rows=>setSeen(old=>{const next=Object.fromEntries(Object.entries({...old,...Object.fromEntries(rows.map(item=>[item.id,item.createdAt]))}).slice(-300));try{localStorage.setItem(`hadsec-event-seen-${user.id}`,JSON.stringify(next));}catch{}return next;});
 useEffect(()=>{
  if(!open)return;
  const close=e=>{if(e.type==='keydown'&&e.key==='Escape'){setOpen(null);trigger.current?.focus();}else if(e.type==='pointerdown'&&!root.current?.contains(e.target))setOpen(null);};
  document.addEventListener('pointerdown',close);document.addEventListener('keydown',close);return()=>{document.removeEventListener('pointerdown',close);document.removeEventListener('keydown',close);};
 },[open]);
 const toggle=(name,event)=>{trigger.current=event.currentTarget;setOpen(current=>current===name?null:name);if(name==='notifications')check();};
 const profile=section=>{setOpen(null);onProfile(section);};
 return <div className="topbar-actions workspace-menus" ref={root}>
  <button className="icon-btn notification" aria-label={`Notificações${count?`, ${count} novas`:''}`} aria-expanded={open==='notifications'} aria-controls="system-notifications" aria-haspopup="dialog" onClick={e=>toggle('notifications',e)}><Bell size={21}/>{count>0&&<b className="notification-count">{count>99?'99+':count}</b>}</button>
  <button className="account-trigger" aria-label="Abrir menu da conta" aria-expanded={open==='profile'} aria-controls="account-menu" aria-haspopup="menu" onClick={e=>toggle('profile',e)}><span className="avatar small">{(user.display_name||user.username).split(/\s+/).slice(0,2).map(n=>n[0]).join('').toUpperCase()}</span></button>
  {open==='notifications'&&<section className="header-popover notification-popover" id="system-notifications" role="dialog" aria-label="Notificações do sistema"><div className="popover-heading"><div><h2>Notificações</h2><p>{count?`${count} atualizações não lidas`:'Atualizações do workspace'}</p></div><button className="icon-btn" aria-label="Fechar notificações" onClick={()=>{setOpen(null);trigger.current?.focus();}}><X size={18}/></button></div>
   {count>0&&<button className="text-btn mark-read" onClick={()=>mark(items)}><CheckCheck size={16}/>Marcar todas como lidas</button>}
   {error&&<div className="notification-error" role="alert">{error}<button className="text-btn" onClick={check}>Tentar novamente</button></div>}
   <div className="notification-list">{items.map(item=>{const Icon=item.target?.type==='request'?GitPullRequest:FileCode2;return <button key={item.id} className={`notification-item ${unread(item)?'unread':''}`} disabled={!item.target} onClick={()=>{mark([item]);setOpen(null);onNotification(item);}}><span className="notification-symbol"><Icon size={18}/></span><span><strong>{item.title}</strong><span className="notification-description">{item.description}</span><small>{new Date(item.createdAt).toLocaleString('pt-BR',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'})}</small></span><ChevronRight size={16}/></button>;})}</div>
   {!items.length&&!error&&<div className="popover-empty">{loading?<Loader2 size={25} className="spin"/>:<Bell size={25}/>}<p>{loading?'Buscando atualizações…':'Nenhuma atualização registrada.'}</p></div>}
   <button className="popover-footer" disabled={loading} onClick={check}><span>{loading?'Atualizando…':'Atualizar notificações'}</span><RotateCcw size={16} className={loading?'spin':''}/></button>
  </section>}
  {open==='profile'&&<div className="header-popover account-popover" id="account-menu" role="menu" aria-label="Menu da conta"><div className="account-summary"><strong>{user.display_name}</strong><small>@{user.username} · {role?.name}</small></div><button role="menuitem" onClick={()=>profile('account')}><UserRound size={18}/>Meu perfil</button><button role="menuitem" onClick={()=>profile('password')}><KeyRound size={18}/>Alterar senha</button><button role="menuitem" className="account-logout" onClick={()=>{setOpen(null);onLogout();}}><LogOut size={18}/>Sair da conta</button></div>}
 </div>;
}
