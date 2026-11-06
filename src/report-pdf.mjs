const colors={ink:'#172431',muted:'#637385',line:'#DCE3E8',paper:'#F4F7F9',green:'#517B23',blue:'#337DB0'};
const shortDate=value=>{const date=new Date(value);return Number.isNaN(date.getTime())?'—':date.toLocaleDateString('pt-BR');};
const dayDate=value=>value.slice(8,10)+'/'+value.slice(5,7)+'/'+value.slice(0,4);
const statusLabel={requested:'Solicitada',review:'Em revisão',changes:'Ajustes pedidos',approved:'Aprovada',published:'Publicada',rejected:'Rejeitada'};

export function reportPdfFilename(report){return 'hadsec-relatorio-'+(report.daily[0]?.date||report.start.slice(0,10))+'-a-'+(report.daily.at(-1)?.date||report.end.slice(0,10))+'.pdf';}

export async function createReportPDF(report,{logo,compress=true}={}){
 const {jsPDF}=await import('jspdf');
 const pdf=new jsPDF({unit:'mm',format:'a4',orientation:'portrait',compress,putOnlyUsedFonts:true});
 pdf.setProperties({title:'HadSec Detect - Relatório',subject:'Indicadores e fluxo de regras de detecção',author:'HadSec Detect',creator:'HadSec Detect'});
 const margin=15,width=180,bottom=275;
 const period=shortDate(report.start)+' a '+shortDate(report.end);
 let cursor=0;
 const font=(size=9,bold=false,color=colors.ink)=>{pdf.setFont('helvetica',bold?'bold':'normal');pdf.setFontSize(size);pdf.setTextColor(color);};
 const text=(value,x,y,{size=9,bold=false,color=colors.ink,maxWidth,align}={})=>{
  font(size,bold,color);const lines=maxWidth?pdf.splitTextToSize(String(value),maxWidth):String(value);
  pdf.text(lines,x,y,{...(align?{align}:{})});return Array.isArray(lines)?lines.length*size*.41:size*.41;
 };
 const header=first=>{
  if(logo)pdf.addImage(logo,'PNG',margin,10,10,15,'hadsec-owl');
  text('HadSec Detect',logo?30:margin,17,{size:15,bold:true});
  text('Engenharia de detecção',logo?30:margin,23,{size:8,color:colors.muted});
  text(period,195,17,{size:8,align:'right',color:colors.muted});
  pdf.setDrawColor(colors.line);pdf.setLineWidth(.25);pdf.line(margin,29,195,29);
  cursor=39;
  if(first){text('Relatório de detecção',margin,40,{size:20,bold:true});text('Período: '+period,margin,48,{size:9,color:colors.muted});cursor=57;}
 };
 const page=()=>{pdf.addPage();header(false);};
 const space=height=>{if(cursor+height>bottom)page();};
 const section=title=>{space(17);text(title,margin,cursor,{size:13,bold:true});cursor+=9;};
 const table=(headers,rows,widths,title)=>{
  const drawHeader=()=>{pdf.setFillColor(colors.paper);pdf.rect(margin,cursor,width,9,'F');let x=margin;headers.forEach((value,i)=>{text(value,x+3,cursor+6,{size:8,bold:true});x+=widths[i];});cursor+=9;};
  space(17);drawHeader();
  if(!rows.length){text('Nenhum registro neste período.',margin+3,cursor+7,{size:9,color:colors.muted});cursor+=15;return;}
  for(let index=0;index<rows.length;index++){
   font(9);const cells=rows[index].map((value,i)=>pdf.splitTextToSize(String(value??'—'),widths[i]-6));
   const height=Math.max(9,...cells.map(lines=>lines.length*4+5));
   if(cursor+height>bottom){page();section(title+' (continuação)');drawHeader();}
   if(index%2===0){pdf.setFillColor('#FAFBFC');pdf.rect(margin,cursor,width,height,'F');}
   let x=margin;cells.forEach((lines,i)=>{font(9,false,i===0?colors.ink:colors.muted);pdf.text(lines,x+3,cursor+5.8);x+=widths[i];});
   pdf.setDrawColor(colors.line);pdf.setLineWidth(.12);pdf.line(margin,cursor+height,195,cursor+height);cursor+=height;
  }
  cursor+=12;
 };

 header(true);
 const metrics=[['Versões criadas',report.metrics.versions],['Solicitações',report.metrics.requests],['Aprovações',report.metrics.approved],['Taxa de aprovação',report.metrics.approvalRate===null?'—':report.metrics.approvalRate+'%']];
 metrics.forEach(([label,value],i)=>{const x=margin+i*46;pdf.setFillColor(colors.paper);pdf.setDrawColor(colors.line);pdf.roundedRect(x,cursor,42,25,2,2,'FD');text(label,x+3,cursor+7,{size:8,color:colors.muted});text(value,x+3,cursor+19,{size:21,bold:true,color:i===0?colors.green:colors.ink});});
 cursor+=38;section('Atividade da equipe');
 const chart={x:22,y:cursor+10,w:167,h:48};
 const peak=Math.max(1,...report.daily.flatMap(day=>[day.versions,day.requests]));
 const steps=4,maximum=Math.ceil(peak/steps)*steps;
 for(let i=0;i<=steps;i++){const value=maximum*i/steps,y=chart.y+chart.h-value/maximum*chart.h;pdf.setDrawColor(colors.line);pdf.setLineWidth(.15);pdf.line(chart.x,y,chart.x+chart.w,y);text(Math.round(value),chart.x-3,y+1,{size:7,color:colors.muted,align:'right'});}
 [['versions',colors.green,'Versões'],['requests',colors.blue,'Solicitações']].forEach(([key,color,label],series)=>{
  pdf.setDrawColor(color);pdf.setLineWidth(.65);
  for(let i=1;i<report.daily.length;i++){const a=report.daily[i-1],b=report.daily[i];pdf.line(chart.x+(i-1)/(report.daily.length-1)*chart.w,chart.y+chart.h-a[key]/maximum*chart.h,chart.x+i/(report.daily.length-1)*chart.w,chart.y+chart.h-b[key]/maximum*chart.h);}
  const x=margin+series*37;pdf.setDrawColor(color);pdf.setLineWidth(.7);pdf.line(x,cursor+3,x+5,cursor+3);text(label,x+7,cursor+4,{size:8,color:colors.muted});
 });
 [0,Math.floor(report.daily.length/2),report.daily.length-1].forEach((index,i)=>text(report.daily[index].label,chart.x+index/(report.daily.length-1)*chart.w,chart.y+chart.h+7,{size:7,color:colors.muted,align:i===0?'left':i===2?'right':'center'}));
 cursor=chart.y+chart.h+19;

 const boxY=cursor;
 pdf.setDrawColor(colors.line);pdf.setLineWidth(.25);pdf.roundedRect(15,boxY,87,76,2,2);pdf.roundedRect(108,boxY,87,76,2,2);
 text('Fluxo de solicitações',20,boxY+9,{size:11,bold:true});text('Severidade das regras',113,boxY+9,{size:11,bold:true});
 const total=report.statuses.reduce((sum,item)=>sum+item.count,0),cx=36,cy=boxY+39,radius=13;
 pdf.setDrawColor(colors.line);pdf.setLineWidth(4);pdf.circle(cx,cy,radius);
 let angle=-Math.PI/2;
 for(const item of report.statuses){
  const length=total?item.count/total*Math.PI*2:0,count=Math.max(1,Math.ceil(length*25));pdf.setDrawColor(item.color);pdf.setLineWidth(4);
  for(let i=0;i<count&&length>0;i++){const a=angle+i/count*length,b=angle+(i+1)/count*length;pdf.line(cx+Math.cos(a)*radius,cy+Math.sin(a)*radius,cx+Math.cos(b)*radius,cy+Math.sin(b)*radius);}angle+=length;
 }
 text(total,cx,cy+1,{size:16,bold:true,align:'center'});text('pedidos',cx,cy+7,{size:7,color:colors.muted,align:'center'});
 report.statuses.forEach((item,i)=>{const y=boxY+20+i*8;pdf.setFillColor(item.color);pdf.circle(56,y-1,1,'F');text(item.label,59,y,{size:7.5,color:colors.muted});text(item.count,97,y,{size:8,bold:true,align:'right'});});
 const maxSeverity=Math.max(1,...report.severity.map(item=>item.count));
 report.severity.forEach((item,i)=>{const y=boxY+21+i*12;text(item.label,113,y,{size:8,color:colors.muted});text(item.count,190,y,{size:8,bold:true,align:'right'});pdf.setFillColor(colors.line);pdf.roundedRect(113,y+3,77,2,1,1,'F');if(item.count){pdf.setFillColor(item.color);pdf.roundedRect(113,y+3,77*item.count/maxSeverity,2,1,1,'F');}});
 page();section('Colaboração no período');
 table(['Pessoa','Registros'],report.collaborators.map(person=>[person.name,person.count]),[145,35],'Colaboração no período');
 section('Solicitações em andamento');
 table(['Solicitação','Responsável','Situação','Criada em'],report.pending.map(request=>[request.title,request.author||'—',statusLabel[request.status]||request.status,shortDate(request.created_at)]),[80,47,28,25],'Solicitações em andamento');
 section('Evolução diária');
 table(['Data','Versões criadas','Solicitações criadas'],report.daily.map(day=>[dayDate(day.date),day.versions,day.requests]),[60,60,60],'Evolução diária');
 space(18);text('Base dos indicadores',margin,cursor,{size:8,bold:true});text(report.scope,margin,cursor+5,{size:7.5,color:colors.muted,maxWidth:width});

 const pages=pdf.getNumberOfPages();
 for(let number=1;number<=pages;number++){pdf.setPage(number);pdf.setDrawColor(colors.line);pdf.setLineWidth(.2);pdf.line(margin,282,195,282);text('HadSec Detect - '+period,margin,288,{size:7,color:colors.muted});text(number+' / '+pages,195,288,{size:7,color:colors.muted,align:'right'});}
 return pdf;
}

export async function downloadReportPDF(report){
 let logo;
 try{const response=await fetch('/hadsec-owl-front.png',{signal:AbortSignal.timeout(12000)});if(response.ok)logo=new Uint8Array(await response.arrayBuffer());}catch{/* Text branding is retained if the image is unavailable. */}
 const pdf=await createReportPDF(report,{logo});pdf.save(reportPdfFilename(report));return {pages:pdf.getNumberOfPages()};
}
