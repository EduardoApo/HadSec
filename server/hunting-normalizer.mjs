export const adapterVersion='hadsec-structured-1';
export const normalizedFields=[['time','Data e hora'],['host','Host'],['user','Usuário'],['source_ip','IP de origem'],['destination_ip','IP de destino'],['event_id','Identificador do evento'],['technique','Técnicas MITRE declaradas'],['summary','Descrição do evento']];
const sources=new Set(['chainsaw','hayabusa','velociraptor','structured']);
const enc=s=>s.replaceAll('~','~0').replaceAll('/','~1');
export function pointer(row,path){if(!path)return undefined;let value=row;for(const part of path.split('/').slice(1).map(p=>p.replaceAll('~1','/').replaceAll('~0','~'))){if(['__proto__','constructor','prototype'].includes(part)||!value||typeof value!=='object'||!Object.hasOwn(value,part))return undefined;value=value[part];}return value;}
export function parseCSV(text,delimiter=','){
 if(![',',';','\t'].includes(delimiter))throw Error('Delimitador CSV inválido.');
 const rows=[];let row=[],cell='',quoted=false,closed=false;
 const finishCell=()=>{row.push(cell);cell='';closed=false;if(row.length>200)throw Error('O CSV excede 200 colunas.');};
 const finishRow=()=>{const present=row.length>0||cell!==''||closed;finishCell();if(present)rows.push(row);row=[];if(rows.length>5001)throw Error('O CSV excede 5.000 registros.');};
 for(let i=0;i<text.length;i++){const c=text[i];if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;}
 else if(c==='"'){if(cell||closed)throw Error('Aspas CSV fora de posição.');quoted=true;}
 else if(c===delimiter)finishCell();else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;finishRow();}
 else{if(closed&&c!==' '&&c!=='\t')throw Error('Conteúdo após o fechamento de aspas CSV.');if(!closed)cell+=c;}
 if(cell.length>100000)throw Error('Uma célula CSV excede 100 KB.');}
 if(quoted)throw Error('Aspas CSV não foram fechadas.');if(cell||row.length||closed)finishRow();
 const headers=rows.shift();if(!headers||headers.length<1||headers.some(h=>!h.trim()||['__proto__','constructor','prototype'].includes(h))||new Set(headers).size!==headers.length)throw Error('Cabeçalhos CSV vazios, repetidos ou não permitidos.');
 return rows.map((values,i)=>{if(values.length!==headers.length)throw Error('Quantidade de colunas divergente no registro '+(i+1)+'.');return Object.fromEntries(headers.map((h,j)=>[h,values[j]]));});
}
function protect(value,depth=0,state={nodes:0}){if(depth>25||++state.nodes>1000000)throw Error('A estrutura excede os limites de complexidade.');if(value&&typeof value==='object'){const keys=Object.keys(value);if(!Array.isArray(value)&&keys.length>200)throw Error('Um registro excede 200 campos.');for(const key of keys){if(['__proto__','constructor','prototype'].includes(key))throw Error('Chave de dados não permitida.');protect(value[key],depth+1,state);}}}
export function structuredRows(text,{format='json',delimiter=',',source='structured'}={}){
 if(!sources.has(source))throw Error('Origem de importação inválida.');if(new TextEncoder().encode(text).length>10000000)throw Error('A importação excede 10 MB.');text=text.replace(/^\uFEFF/,'');let rows;
 if(format==='csv')rows=parseCSV(text,delimiter);else if(format==='json'){
  let value;try{value=JSON.parse(text);}catch{const lines=text.trim().split(/\r?\n/);if(lines.length>5000)throw Error('O JSONL excede 5.000 registros.');try{value=lines.map(line=>JSON.parse(line));}catch{throw Error('JSON/JSONL inválido. Exporte registros estruturados da ferramenta.');}}
  rows=Array.isArray(value)?value:['results','events','detections','rows'].map(key=>value?.[key]).find(Array.isArray)||(value&&typeof value==='object'?[value]:null);
 }else throw Error('Formato não suportado. Use JSON/JSONL ou CSV; EVTX exige um parser externo adequado.');
 if(!rows?.length||rows.length>5000)throw Error('Use entre 1 e 5.000 registros estruturados.');protect(rows);
 if(source==='chainsaw')rows=rows.flatMap((row,i)=>Array.isArray(row.documents)?row.documents.map((document,j)=>{const metadata={...row};delete metadata.documents;return {aggregate_metadata:metadata,document,aggregate_index:i+1,document_index:j+1};}):[row]);
 if(rows.length>5000)throw Error('A expansão de grupos excede 5.000 eventos.');
 for(let i=0;i<rows.length;i++)if(!rows[i]||typeof rows[i]!=='object'||Array.isArray(rows[i])||new TextEncoder().encode(JSON.stringify(rows[i])).length>100000)throw Error('O registro '+(i+1)+' é inválido ou excede 100 KB.');return rows;
}
export function availableFields(rows){const fields=new Set();const visit=(value,path='')=>{if(path.length>500)throw Error('Um caminho de campo excede 500 caracteres.');if(value&&typeof value==='object'&&!Array.isArray(value)){for(const [key,v]of Object.entries(value))visit(v,path+'/'+enc(key));}else if(path)fields.add(path);};for(const row of rows)visit(row);if(fields.size>2000)throw Error('O arquivo excede 2.000 caminhos de campos. Separe os formatos de evento.');return [...fields].sort();}
export function suggestMapping(fields,source){
 const win={time:['/Event/System/TimeCreated_attributes/SystemTime','/Event/System/TimeCreated/@SystemTime','/Event/System/TimeCreated/SystemTime'],host:['/Event/System/Computer'],user:['/Event/EventData/TargetUserName','/Event/EventData/SubjectUserName','/Event/EventData/User'],source_ip:['/Event/EventData/IpAddress','/Event/EventData/SourceIp'],destination_ip:['/Event/EventData/DestinationIp'],event_id:['/Event/System/EventID','/Event/System/EventID/#text']};
 const aliases={time:['/Timestamp','/@timestamp','/timestamp','/TimeCreated','/time','/aggregate_metadata/timestamp'],host:['/Computer','/Hostname','/HostName','/host/name','/host/hostname','/hostname','/host'],user:['/User','/UserName','/username','/user/name','/TargetUserName'],source_ip:['/SrcIP','/SourceIP','/SourceIp','/source/ip'],destination_ip:['/TgtIP','/DestinationIP','/DestinationIp','/destination/ip'],event_id:['/EventID','/EventId','/event_id','/event/code','/event/id'],technique:['/MitreTags','/techniques','/technique','/rule/tags'],summary:['/RuleTitle','/title','/message','/Message','/Details','/description','/rule/name']};
 return Object.fromEntries(normalizedFields.map(([name])=>{const windows=(win[name]||[]).flatMap(path=>['','/data','/document','/document/data'].map(prefix=>prefix+path));const candidates=source==='chainsaw'?[...windows,...aliases[name]]:[...aliases[name],...windows];return [name,candidates.find(p=>fields.includes(p))||''];}));
}
export function normalizeTimestamp(raw,{time_unit='iso',timezone=''}={}){
 const warnings=[];if(raw===undefined||raw===null||raw==='')return {value:null,warnings:['Campo de data ausente.']};const text=String(raw).trim();
 if(time_unit!=='iso'){
  const digits={seconds:6,milliseconds:3,microseconds:0}[time_unit];if(digits===undefined)throw Error('Unidade de tempo inválida.');const match=/^(-?)(\d+)(?:\.(\d+))?$/.exec(text);if(!match||text.length>35||typeof raw==='number'&&Number.isInteger(raw)&&!Number.isSafeInteger(raw))return {value:null,warnings:['Timestamp numérico inválido ou fora da precisão segura.']};
  const fraction=match[3]||'';if(fraction.length>digits)warnings.push('Precisão limitada a microssegundos; valor original preservado.');const sign=match[1]?-1n:1n;const micros=sign*(BigInt(match[2])*10n**BigInt(digits)+BigInt(fraction.slice(0,digits).padEnd(digits,'0')||'0'));
  const ms=micros>=0n?micros/1000n:(micros-999n)/1000n;if(ms>8640000000000000n||ms< -8640000000000000n)return {value:null,warnings:['Timestamp fora do intervalo de datas.']};const remainder=(micros-ms*1000n).toString().padStart(3,'0');return {value:new Date(Number(ms)).toISOString().replace(/Z$/,remainder+'Z'),warnings};
 }
 const clean=text.replace(/\s+UTC$/i,'Z').replace(/([+-]\d{2})(\d{2})$/,'$1:$2');const parts=/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?(?:\.(\d{1,9}))?\s*(Z|[+-]\d{2}:\d{2})?$/i.exec(clean);
 if(!parts)return {value:null,warnings:['Data fora dos formatos ISO suportados.']};let offset=parts[5]||timezone;if(!offset)return {value:null,warnings:['Data sem fuso: confirme um offset na prévia ou mantenha sem data normalizada.']};if(offset==='Z'||offset==='z')offset='+00:00';
 if(!/^[+-]\d{2}:\d{2}$/.test(offset)||Number(offset.slice(1,3))>14||Number(offset.slice(4))>59||offset.slice(1,3)==='14'&&offset.slice(4)!=='00')return {value:null,warnings:['Offset de data inválido.']};
 const fraction=(parts[4]||'').padEnd(6,'0'),local=parts[1]+'T'+parts[2]+':'+(parts[3]||'00')+'.'+fraction.slice(0,3),date=new Date(local+offset);if(!Number.isFinite(date.getTime()))return {value:null,warnings:['Data inválida.']};
 const minutes=(Number(offset.slice(1,3))*60+Number(offset.slice(4)))*(offset[0]==='-'?-1:1);if(new Date(date.getTime()+minutes*60000).toISOString().slice(0,23)!==local)return {value:null,warnings:['Data de calendário inválida.']};
 if((parts[4]||'').length>6)warnings.push('Precisão limitada a microssegundos; valor original preservado.');return {value:date.toISOString().replace(/\.\d{3}Z$/,'.'+fraction.slice(0,6)+'Z'),warnings};
}
const scalar=(value,max)=>value==null?'':(Array.isArray(value)?value.map(v=>typeof v==='object'?JSON.stringify(v):String(v)).join(' · '):typeof value==='object'?JSON.stringify(value):String(value)).slice(0,max);
export function normalizeHunting(text,options={}){
 const source=options.source||'structured',rows=structuredRows(text,options),fields=availableFields(rows),mapping=options.fields||suggestMapping(fields,source);
 for(const [key,path]of Object.entries(mapping)){if(!normalizedFields.some(f=>f[0]===key)||typeof path!=='string'||path&&!fields.includes(path))throw Error('Mapeamento de campo inválido: '+key);}
 const time_unit=options.time_unit||'iso',timezone=options.timezone||'';if(!['iso','seconds','milliseconds','microseconds'].includes(time_unit)||!['','+00:00','-03:00'].includes(timezone))throw Error('Configuração de datas inválida.');
 const normalized=rows.map((row,index)=>{const get=name=>pointer(row,mapping[name]),timestamp=get('time'),parsed=normalizeTimestamp(timestamp,{time_unit,timezone});return {record_index:index+1,event_at:parsed.value,original_timestamp:scalar(timestamp,300),host:scalar(get('host'),300),user_name:scalar(get('user'),300),source_ip:scalar(get('source_ip'),200),destination_ip:scalar(get('destination_ip'),200),event_identifier:scalar(get('event_id'),300),techniques:[...new Set(scalar(get('technique'),3000).toUpperCase().match(/\bT\d{4}(\.\d{3})?\b/g)||[])].slice(0,50),summary:scalar(get('summary'),4000),normalization_warnings:parsed.warnings,raw_event:row};});
 return {rows:normalized,total:normalized.length,missingDates:normalized.filter(r=>!r.event_at).length,fields,mapping:{source,format:options.format||'json',delimiter:options.delimiter||',',fields:Object.fromEntries(normalizedFields.map(([key])=>[key,mapping[key]||''])),time_unit,timezone,tool_version:String(options.tool_version||'').slice(0,80),adapter_version:adapterVersion},adapterVersion};
}
