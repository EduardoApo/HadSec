export async function createOperationalPDF({title,subtitle='',sections=[]}){
 const {jsPDF}=await import('jspdf');const pdf=new jsPDF({format:'a4',unit:'mm',compress:true,putOnlyUsedFonts:true});pdf.setProperties({title,author:'HadSec Detect',creator:'HadSec Detect'});
 let y=25;const margin=16,width=178,bottom=276;
 const header=()=>{pdf.setFont('helvetica','bold');pdf.setFontSize(12);pdf.setTextColor('#254029');pdf.text('HadSec Detect',margin,15);pdf.setDrawColor('#CFD9D0');pdf.line(margin,19,194,19);y=29;};
 const page=()=>{pdf.addPage();header();};
 const text=(value,{size=9,bold=false,color='#23303D'}={})=>{pdf.setFont('helvetica',bold?'bold':'normal');pdf.setFontSize(size);pdf.setTextColor(color);const lines=pdf.splitTextToSize(String(value??'—').replaceAll('\t','  '),width);for(const line of lines){if(y+size*.5>bottom)page();pdf.setFont('helvetica',bold?'bold':'normal');pdf.setFontSize(size);pdf.setTextColor(color);pdf.text(String(line),margin,y);y+=size*.43;}y+=3;};
 header();text(title,{size:20,bold:true});if(subtitle)text(subtitle,{size:9,color:'#667563'});
 for(const section of sections){if(y+18>bottom)page();y+=4;text(section.title,{size:13,bold:true,color:'#315334'});for(const paragraph of section.paragraphs||[])text(paragraph);for(const [label,value]of section.fields||[]){text(label,{size:9,bold:true,color:'#4B6352'});text(value);}for(const entry of section.entries||[]){text(entry.title,{size:10,bold:true});for(const paragraph of entry.paragraphs||[])text(paragraph);y+=3;}}
 const pages=pdf.getNumberOfPages();for(let n=1;n<=pages;n++){pdf.setPage(n);pdf.setFont('helvetica','normal');pdf.setFontSize(8);pdf.setTextColor('#738078');pdf.text('HadSec Detect · '+n+'/'+pages,194,288,{align:'right'});}return {bytes:new Uint8Array(pdf.output('arraybuffer')),pages};
}
export function hypothesisReport(hypothesis,{findings,files,events,imports},data,campaignTitle=''){
 const subject=hypothesis.operational_subjects;
 return {title:subject.title,subtitle:'Relatório de investigação · '+new Date().toLocaleString('pt-BR'),sections:[
 {title:'Hipótese e escopo',fields:[['Hipótese',hypothesis.description],['Comportamento investigado',hypothesis.behavior],['Justificativa',hypothesis.justification],['Escopo',hypothesis.scope],['Campanha',campaignTitle||'Sem campanha'],['Responsável',data.profiles.find(p=>p.id===hypothesis.responsible_id)?.display_name||'Usuário'],['Prioridade / estado',hypothesis.priority+' / '+subject.status]]},
 {title:'Metodologia',fields:[['Metodologia',hypothesis.methodology||'Não registrada'],['Fontes de logs',hypothesis.log_sources.join(', ')||'Não registradas'],['Resultado esperado',hypothesis.expected_results||'Não registrado']]},
 {title:'Evidências e integridade',paragraphs:[files.length+' arquivos privados confirmados. '+events.total+' eventos normalizados ativos; '+events.missingDates+' sem data normalizada.'],entries:files.map(f=>({title:f.original_name,paragraphs:['SHA-256: '+f.sha256,'Tamanho: '+f.size_bytes+' bytes; confirmado em '+f.verified_at]}))},
 {title:'Importações',entries:imports.filter(i=>i.status==='ready'&&i.active).map(i=>({title:i.source+' · '+i.expected_count+' registros',paragraphs:['Adaptador: '+i.adapter_version+'; arquivo SHA-256: '+i.file_sha256,'Mapeamento e datas: '+JSON.stringify(i.mapping)]}))},
 {title:'Eventos iniciais em UTC',paragraphs:['Recorte explícito: '+events.items.length+' de '+events.total+' eventos ativos, em ordem temporal. Datas ausentes permanecem sem data; proximidade não comprova relação maliciosa.'],entries:events.items.map(e=>({title:(e.event_at||'Sem data normalizada')+' · '+(e.summary||e.event_identifier||'Registro '+e.record_index),paragraphs:['Host: '+(e.host||'—')+'; usuário: '+(e.user_name||'—')+'; IPs: '+(e.source_ip||'—')+' → '+(e.destination_ip||'—'),'Fonte: '+e.source+'; técnicas declaradas: '+e.techniques.join(', '),'Original SHA-256: '+e.file_sha256+'; registro '+e.record_index]}))},
 {title:'Achados',entries:findings.map(f=>({title:f.title+' · '+f.priority,paragraphs:[f.description,'Recomendação: '+f.recommendation]}))},
 {title:'Conclusão e recomendações',fields:[['Conclusão',hypothesis.conclusion||'Ainda não registrada'],['Recomendações',hypothesis.recommendations||'Ainda não registradas']]}
 ]};
}
