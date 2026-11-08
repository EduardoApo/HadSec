import {requestVisible} from './record-visibility.mjs';
const dayKey=date=>[date.getFullYear(),String(date.getMonth()+1).padStart(2,'0'),String(date.getDate()).padStart(2,'0')].join('-');
export function buildReport(data,days=30,now=new Date()){
 days=[7,30,90].includes(Number(days))?Number(days):30;
 const start=new Date(now);start.setHours(0,0,0,0);start.setDate(start.getDate()-days+1);
 const within=row=>{const time=new Date(row.created_at).getTime();return Number.isFinite(time)&&time>=start.getTime()&&time<=now.getTime();};
 const rules=data.rules.filter(row=>!row.archived&&within(row)),versions=data.versions.filter(within),requests=data.requests.filter(row=>requestVisible(row)&&within(row)),evidence=data.evidence.filter(within);
 const daily=Array.from({length:days},(_,i)=>{const date=new Date(start);date.setDate(date.getDate()+i);return {date:dayKey(date),label:date.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'}),versions:0,requests:0};});
 for(const [rows,key]of [[versions,'versions'],[requests,'requests']])for(const row of rows){const bucket=daily.find(day=>day.date===dayKey(new Date(row.created_at)));if(bucket)bucket[key]++;}
 const statuses=[['requested','Solicitadas','#72aaf0'],['review','Em revisão','#f3c76c'],['changes','Em ajuste','#ed9b60'],['approved','Aprovadas','#b5ed59'],['published','Enviadas','#b39aee'],['rejected','Rejeitadas','#ed8792']].map(([key,label,color])=>({key,label,color,count:requests.filter(r=>r.status===key).length}));
 const completed=requests.filter(r=>['approved','published','rejected'].includes(r.status));
 const approved=completed.filter(r=>r.status!=='rejected').length;
 const severity=[['Crítica','#ed8792'],['Alta','#ed9b60'],['Média','#f3c76c'],['Baixa','#72aaf0']].map(([label,color])=>({label,color,count:rules.filter(r=>r.severity===label).length}));
 const people=new Map();for(const row of [...versions,...requests,...evidence]){const person=data.profiles.find(p=>p.id===row.created_by);const entry=people.get(row.created_by)||{id:row.created_by,name:person?.display_name||'Usuário',count:0};entry.count++;people.set(row.created_by,entry);}
 const collaborators=[...people.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name)).slice(0,5);
 const pending=requests.filter(r=>['requested','review','changes'].includes(r.status)).sort((a,b)=>new Date(a.created_at)-new Date(b.created_at)).map(request=>({...request,author:data.profiles.find(person=>person.id===request.created_by)?.display_name||'Usuário'}));
 return {days,start:start.toISOString(),end:now.toISOString(),daily,statuses,severity,collaborators,pending,metrics:{versions:versions.length,requests:requests.length,approved,approvalRate:completed.length?Math.round(approved/completed.length*100):null,evidencePassed:evidence.filter(e=>e.result==='pass').length},scope:'Solicitações e registros criados no período; resultados refletem o estado atual.'};
}
export function reportCSV(report){
 const rows=[['Data','Versões criadas','Solicitações criadas'],...report.daily.map(d=>[d.date,d.versions,d.requests])];
 return '\uFEFF'+rows.map(row=>row.map(value=>'"'+String(value).replaceAll('"','""')+'"').join(';')).join('\r\n');
}
