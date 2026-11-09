import React,{useEffect,useState} from 'react';
import {AlertTriangle,CheckCircle2,Loader2,RefreshCw} from 'lucide-react';
export function useOperationalData(loader,allowed){
 const [rows,setRows]=useState(null),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState(''),[feedback,setFeedback]=useState(''),[revision,setRevision]=useState(0);
 useEffect(()=>{let current=true;if(!allowed){setLoading(false);return;}setLoading(true);loader().then(r=>{if(current){setRows(r);setError('');}}).catch(e=>{if(current)setError(e.message);}).finally(()=>{if(current)setLoading(false);});return()=>{current=false;};},[loader,allowed,revision]);
 const perform=async(fn,message)=>{setBusy(true);setError('');setFeedback('');try{const result=await fn();setFeedback(message);setRevision(v=>v+1);return result??true;}catch(e){setError(e.message);return null;}finally{setBusy(false);}};
 return {rows,loading,busy,error,feedback,perform,refresh:()=>setRevision(v=>v+1),setError,setFeedback};
}
export function OperationMessages({state}){return <>{state.error&&<div className="inline-alert error-text" role="alert"><AlertTriangle size={17}/>{state.error}</div>}{state.feedback&&<p className="operations-feedback" role="status"><CheckCircle2 size={17}/>{state.feedback}</p>}</>;}
export function OperationGate({allowed,state,children}){if(!allowed)return <div className="inline-alert">Seu perfil não tem permissão para consultar este módulo.</div>;if(!state.rows)return <><OperationMessages state={state}/>{state.loading?<div className="operations-loading"><Loader2 className="spin"/>Carregando registros…</div>:<button className="btn" onClick={state.refresh}><RefreshCw size={17}/>Tentar novamente</button>}</>;return children;}
export function RecordPicker({label,options,value,onChange}){const [query,setQuery]=useState('');return <fieldset className="record-picker"><legend>{label}</legend><input aria-label={'Buscar '+label.toLowerCase()} placeholder="Filtrar opções" value={query} maxLength={200} onChange={e=>setQuery(e.target.value)}/><div>{options.filter(o=>o.label.toLowerCase().includes(query.toLowerCase())||value.includes(o.id)).map(o=><label key={o.id}><input type="checkbox" checked={value.includes(o.id)} onChange={()=>onChange(value.includes(o.id)?value.filter(v=>v!==o.id):[...value,o.id])}/><span>{o.label}</span></label>)}</div>{!options.length&&<p className="muted">Nenhum registro disponível.</p>}</fieldset>;}
export const personName=(data,id)=>data.profiles.find(p=>p.id===id)?.display_name||'Usuário indisponível';
export const activePeople=data=>data.profiles.filter(p=>p.active&&!p.deleted_at&&!p.must_change_password);
export const priorities=['Baixa','Média','Alta','Crítica'];
