import React,{useState} from 'react';
import {AlertTriangle,Trash2} from 'lucide-react';

export function DeleteRecordForm({request,submission=false,busy,onSubmit,onCancel}){
 const [confirmation,setConfirmation]=useState('');
 if(!request||request.deleted_at)return <div className="modal-body"><p>Este registro não está mais disponível.</p><button className="btn" onClick={onCancel}>Fechar</button></div>;
 return <form className="modal-body" onSubmit={event=>{event.preventDefault();if(!busy&&confirmation===request.title)onSubmit({p_request:request.id,p_confirmation:confirmation});}}>
  <p className="delete-record-title">{request.title}</p>
  <div className="inline-alert"><AlertTriangle size={20}/><span>{submission?'O envio será removido da lista do HadSec. A solicitação, o pull request e os arquivos no GitHub serão preservados.':request.status==='published'?'A solicitação e seu envio sairão das listas do HadSec. O pull request e os arquivos no GitHub serão preservados.':'A solicitação sairá das listas e não poderá receber novas ações. A regra e suas versões serão preservadas.'} A exclusão fica registrada na auditoria.</span></div>
  <div className="field"><label htmlFor="record-deletion-confirmation">Digite o título para confirmar</label><input id="record-deletion-confirmation" autoComplete="off" value={confirmation} onChange={event=>setConfirmation(event.target.value)} disabled={busy} required/></div>
  <div className="form-actions"><button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancelar</button><button className="btn danger" disabled={busy||confirmation!==request.title}><Trash2 size={17}/>{submission?'Excluir envio':'Excluir solicitação'}</button></div>
 </form>;
}
