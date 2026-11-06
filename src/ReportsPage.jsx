import React,{useEffect,useId,useMemo,useRef,useState} from 'react';
import {BarChart3,GitPullRequest,GitBranch,ShieldCheck,Download,ArrowUpRight,Activity,CalendarDays,Users,ChevronRight,FileDown,Loader2,AlertTriangle} from 'lucide-react';
import {buildReport,reportCSV} from './reporting.mjs';

function Count({value,suffix=''}){
 const [display,setDisplay]=useState(0),previous=useRef(0);
 useEffect(()=>{
  if(value===null)return;
  if(matchMedia('(prefers-reduced-motion: reduce)').matches){setDisplay(value);previous.current=value;return;}
  const start=performance.now(),from=previous.current;let frame;
  const tick=time=>{const t=Math.min((time-start)/650,1);setDisplay(Math.round(from+(value-from)*(1-Math.pow(1-t,3))));if(t<1)frame=requestAnimationFrame(tick);else previous.current=value;};
  frame=requestAnimationFrame(tick);return()=>cancelAnimationFrame(frame);
 },[value]);
 return <span aria-label={value===null?'Sem dados':String(value)+suffix}><span aria-hidden="true">{value===null?'—':display.toLocaleString('pt-BR')+suffix}</span></span>;
}
function ActivityChart({rows}){
 const [hover,setHover]=useState(null),[visible,setVisible]=useState({versions:true,requests:true});
 const rawId=useId().replaceAll(':',''),width=760,height=240,pad=22;
 const max=Math.max(1,...rows.flatMap(d=>[visible.versions?d.versions:0,visible.requests?d.requests:0]));
 const point=(row,index,key)=>({x:pad+index/Math.max(1,rows.length-1)*(width-pad*2),y:height-pad-row[key]/max*(height-pad*2)});
 const path=key=>rows.map((row,i)=>{const p=point(row,i,key);return (i?'L':'M')+p.x+','+p.y;}).join(' ');
 const active=rows[hover];
 const select=e=>{const bounds=e.currentTarget.getBoundingClientRect();const x=(e.clientX-bounds.left)/bounds.width*width;setHover(Math.max(0,Math.min(rows.length-1,Math.round((x-pad)/(width-pad*2)*(rows.length-1)))));};
 return <><div className="report-chart-legend">{[['versions','Versões','#b5ed59'],['requests','Solicitações','#70b9e8']].map(([key,label,color])=><button key={key} aria-pressed={visible[key]} onClick={()=>setVisible(current=>({...current,[key]:!current[key]}))}><i style={{background:color,opacity:visible[key]?1:.25}}/>{label}</button>)}</div>
  <div className="activity-chart" onPointerMove={select} onPointerLeave={()=>setHover(null)} onPointerDown={select}>
   <svg viewBox={'0 0 '+width+' '+height} role="img" aria-label="Evolução diária de versões e solicitações" preserveAspectRatio="none"><defs><linearGradient id={'fill-'+rawId} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#b5ed59" stopOpacity=".25"/><stop offset="1" stopColor="#b5ed59" stopOpacity="0"/></linearGradient></defs>
    {[0,.25,.5,.75,1].map(t=><g key={t}><line x1={pad} x2={width-pad} y1={pad+t*(height-pad*2)} y2={pad+t*(height-pad*2)} stroke="#34404a" strokeDasharray="3 7"/><text x={width-pad} y={pad+t*(height-pad*2)-6} fill="#7e90a3" fontSize="10" textAnchor="end">{Math.round(max*(1-t))}</text></g>)}
    {visible.versions&&<path key={'area-'+rows.length} className="chart-area" d={path('versions')+' L'+(width-pad)+','+(height-pad)+' L'+pad+','+(height-pad)+' Z'} fill={'url(#fill-'+rawId+')'}/>}
    {[['versions','#b5ed59'],['requests','#70b9e8']].map(([key,color])=>visible[key]&&<path key={key+rows.length} className="chart-line" d={path(key)} pathLength="1" fill="none" stroke={color} strokeWidth="2.8" strokeLinejoin="round" strokeLinecap="round"/>)}
    {active&&<g><line x1={point(active,hover,'versions').x} x2={point(active,hover,'versions').x} y1={pad} y2={height-pad} stroke="#81919b" strokeDasharray="3 5"/>{[['versions','#b5ed59'],['requests','#70b9e8']].map(([key,color])=>visible[key]&&<circle key={key} cx={point(active,hover,key).x} cy={point(active,hover,key).y} r="4.5" fill={color} stroke="#182029" strokeWidth="2"/>)}</g>}
   </svg>
   {active&&<div className="chart-tooltip" role="status"><strong>{active.label}</strong><span>{active.versions} versões · {active.requests} solicitações</span></div>}
  </div><div className="chart-axis">{[0,Math.floor(rows.length/2),rows.length-1].map(i=><span key={i}>{rows[i].label}</span>)}</div>
 </>;
}
function Distribution({items}){
 const total=items.reduce((sum,item)=>sum+item.count,0),radius=61,circumference=2*Math.PI*radius;let offset=0;
 return <div className="distribution"><div className="report-donut"><svg viewBox="0 0 160 160" role="img" aria-label={items.map(item=>item.label+': '+item.count).join(', ')}><circle cx="80" cy="80" r={radius} fill="none" stroke="#293440" strokeWidth="15"/>{items.filter(item=>item.count).map(item=>{const length=item.count/total*circumference;const segment=<circle key={item.key} className="donut-segment" cx="80" cy="80" r={radius} fill="none" stroke={item.color} strokeWidth="15" strokeDasharray={length+' '+circumference} strokeDashoffset={-offset} transform="rotate(-90 80 80)"/>;offset+=length;return segment;})}</svg><div><strong><Count value={total}/></strong><span>solicitações</span></div></div><ul className="distribution-legend">{items.map(item=><li key={item.key}><i style={{background:item.color}}/><span>{item.label}</span><strong>{item.count}</strong></li>)}</ul></div>;
}
export function ReportsPage({data,onRequest,onExport}){
 const [days,setDays]=useState(30);
 const [exporting,setExporting]=useState(false),[exportError,setExportError]=useState(''),[exportResult,setExportResult]=useState('');
 const report=useMemo(()=>buildReport(data,days),[data,days]);
 const exportPDF=async()=>{setExporting(true);setExportError('');setExportResult('');try{const {downloadReportPDF}=await import('./report-pdf.mjs');const result=await downloadReportPDF(report);setExportResult('PDF gerado com '+result.pages+' páginas.');}catch{setExportError('Não foi possível gerar o PDF. Tente novamente.');}finally{setExporting(false);}};
 const maxSeverity=Math.max(1,...report.severity.map(item=>item.count)),maxPeople=Math.max(1,...report.collaborators.map(item=>item.count));
 const cards=[[GitBranch,'Versões criadas',report.metrics.versions,'Versões no período','lime'],[GitPullRequest,'Solicitações',report.metrics.requests,'Pedidos criados no período','blue'],[ShieldCheck,'Aprovações',report.metrics.approved,'Aprovadas ou publicadas','purple'],[Activity,'Taxa de aprovação',report.metrics.approvalRate,'Entre decisões concluídas','amber']];
 return <div className="reports-page"><div className="page-heading"><div><h1>Relatórios<span className="title-dot">.</span></h1><p>Da criação à aprovação, acompanhe a evolução da equipe.</p></div><div className="report-export-actions"><button className="btn" onClick={()=>onExport(reportCSV(report))}><Download size={17}/>CSV</button><button className="btn primary" disabled={exporting} onClick={exportPDF}>{exporting?<Loader2 className="spin" size={17}/>:<FileDown size={17}/>} {exporting?'Gerando PDF…':'Exportar PDF'}</button></div></div>
  {exportError&&<div className="inline-alert error-text" role="alert"><AlertTriangle size={18}/>{exportError}</div>}{exportResult&&<p className="report-export-feedback" role="status">{exportResult}</p>}
  <div className="report-period"><div><CalendarDays size={18}/><span>{new Date(report.start).toLocaleDateString('pt-BR')} — {new Date(report.end).toLocaleDateString('pt-BR')}</span></div><div className="period-options" role="group" aria-label="Período do relatório">{[7,30,90].map(value=><button key={value} aria-pressed={days===value} className={days===value?'active':''} onClick={()=>setDays(value)}>{value} dias</button>)}</div></div>
  <div className="report-kpis">{cards.map(([Icon,label,value,note,color],index)=><section className={'report-kpi '+color} key={label} style={{'--enter-delay':index*65+'ms'}}><div><span>{label}</span><Icon size={21}/></div><strong><Count value={value} suffix={label==='Taxa de aprovação'?'%':''}/></strong><p>{note}</p></section>)}</div>
  <div className="report-primary-grid"><section className="panel report-panel"><div className="report-panel-heading"><div><h2>Atividade da equipe</h2><p>Versões e solicitações por dia.</p></div><BarChart3 size={21}/></div><ActivityChart rows={report.daily}/></section><section className="panel report-panel"><div className="report-panel-heading"><div><h2>Fluxo de solicitações</h2><p>Distribuição por etapa.</p></div><GitPullRequest size={21}/></div><Distribution items={report.statuses}/></section></div>
  <div className="report-secondary-grid"><section className="panel report-panel"><div className="report-panel-heading"><div><h2>Severidade das regras</h2><p>Regras ativas criadas no período.</p></div><ShieldCheck size={21}/></div><div className="report-bars">{report.severity.map(item=><div className="report-bar" key={item.label}><div><span>{item.label}</span><strong>{item.count}</strong></div><div className="report-bar-track"><span style={{width:item.count/maxSeverity*100+'%',background:item.color}}/></div></div>)}</div></section><section className="panel report-panel"><div className="report-panel-heading"><div><h2>Colaboração</h2><p>Versões, solicitações e evidências por pessoa.</p></div><Users size={21}/></div>{report.collaborators.length?<div className="report-bars">{report.collaborators.map(item=><div className="report-bar" key={item.id}><div><span>{item.name}</span><strong>{item.count}</strong></div><div className="report-bar-track"><span style={{width:item.count/maxPeople*100+'%',background:'#b5ed59'}}/></div></div>)}</div>:<p className="report-empty">Nenhuma atividade neste período.</p>}</section></div>
  <section className="panel report-queue"><div className="report-panel-heading"><div><h2>Solicitações em andamento</h2><p>As mais antigas aparecem primeiro.</p></div><span className="count-badge">{report.pending.length}</span></div>{report.pending.slice(0,5).map(request=><button className="report-queue-item" key={request.id} onClick={()=>onRequest(request)}><span><strong>{request.title}</strong><small>{data.profiles.find(person=>person.id===request.created_by)?.display_name||'Usuário'} · {new Date(request.created_at).toLocaleDateString('pt-BR')}</small></span><span className={'badge '+(request.status==='review'?'amber':'blue')}>{{requested:'Solicitada',review:'Em revisão',changes:'Ajustes pedidos'}[request.status]}</span><ChevronRight size={18}/></button>)}{!report.pending.length&&<p className="report-empty">Nenhuma solicitação em andamento neste período.</p>}</section>
  <p className="report-scope">{report.scope}</p>
 </div>;
}
