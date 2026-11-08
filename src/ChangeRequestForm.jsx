import React,{useState} from 'react';
import {Send,Upload,Plus,GitPullRequest} from 'lucide-react';
import {Field,FormatSelect} from './DetectionFields';
import {CodeEditor} from './CodeEditor';
import {formatInfo,modeForFormat} from '../supabase/functions/_shared/formats.mjs';
import {parseFortiSIEM} from '../supabase/functions/_shared/fortisiem.mjs';

export function ChangeRequestForm({rules,versions,busy,onSubmit}){
 const [kind,setKind]=useState('create'),[ruleId,setRuleId]=useState(''),[format,setFormat]=useState('sigma'),[original,setOriginal]=useState(''),[error,setError]=useState('');
 const rule=rules.find(r=>r.id===ruleId),baseline=versions.filter(v=>v.rule_id===ruleId).sort((a,b)=>b.number-a.number)[0],selectedFormat=rule?.format||format;
 const changeKind=value=>{setKind(value);setRuleId('');setOriginal('');setError('');};
 return <form className="modal-body" onSubmit={event=>{event.preventDefault();setError('');if(kind==='change'&&!ruleId&&!original.trim()){setError('Insira a regra original.');return;}const data=new FormData(event.currentTarget);let mode=rule?.mode||modeForFormat(selectedFormat,original);if(selectedFormat==='xml'&&!rule){try{mode=parseFortiSIEM(original)[0]?.mode||mode;}catch{}}
  onSubmit({p_kind:kind,p_title:data.get('title'),p_description:data.get('description'),p_format:selectedFormat,p_mode:mode,p_rule_id:kind==='change'?(ruleId||null):null,p_baseline_content:kind==='change'?(rule?baseline?.content:original):null});}}>
  <div className="request-kind-options" role="group" aria-label="Tipo da solicitação"><button type="button" aria-pressed={kind==='create'} className={'request-kind '+(kind==='create'?'active':'')} onClick={()=>changeKind('create')}><Plus size={22}/><span>Criar nova regra</span></button><button type="button" aria-pressed={kind==='change'} className={'request-kind '+(kind==='change'?'active':'')} onClick={()=>changeKind('change')}><GitPullRequest size={22}/><span>Alterar regra</span></button></div>
  <Field label="Título da solicitação"><input name="title" required minLength={3} maxLength={160} placeholder={kind==='create'?'Nome da nova detecção':'Qual regra precisa de ajuste?'}/></Field>
  <Field label="Contexto e resultado esperado"><textarea name="description" required minLength={3} maxLength={8000} rows={4} placeholder="Descreva o comportamento esperado e os dados envolvidos."/></Field>
  {kind==='change'&&<Field label="Regra original"><select value={ruleId} onChange={event=>setRuleId(event.target.value)}><option value="">Importar ou colar a regra antiga</option>{rules.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></Field>}
  <FormatSelect value={selectedFormat} disabled={!!rule} onChange={value=>{setFormat(value);setOriginal('');}}/>
  {kind==='change'&&<><div className="baseline-note"><strong>Versão original{baseline?' · v'+baseline.number:''}</strong><p>Será preservada no histórico e vinculada a esta solicitação.</p></div>{!rule&&<label className="import-button"><Upload size={16}/>Importar regra original<input type="file" accept={'.'+formatInfo(format).extension+(format==='sigma'?',.yaml':'')+(format==='yara'?',.yara':'')} onChange={async event=>{const file=event.target.files[0];if(!file)return;if(file.size>500000){setError('O arquivo excede 500 KB.');return;}setOriginal(await file.text());setError('');}}/></label>}<CodeEditor value={rule?baseline?.content||'':original} format={selectedFormat} readOnly={!!rule} onChange={setOriginal}/></>}
  {error&&<p className="error-text" role="alert">{error}</p>}<div className="form-actions"><button className="btn primary" disabled={busy||kind==='change'&&!!rule&&!baseline}><Send size={17}/>Criar solicitação</button></div>
 </form>;
}
