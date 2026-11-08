import {parseDocument} from 'yaml';
import {parseExpression,evaluateExpression,tokens,wildcard,lookup,Unsupported} from './filter-expression.mjs';
import {validateRule as validateFortiSIEM,scanSql} from './validator.mjs';
import {parseFortiSIEM} from './fortisiem.mjs';
import {formats,formatInfo} from './formats.mjs';

function maskCode(source,{strings=false,sql=false}={}){
 let output='',quote=null;
 for(let i=0;i<source.length;i++){
  const c=source[i],next=source[i+1];
  if(quote){output+=strings?' ':c;if(c==='\\'&&next){output+=strings?' ':next;i++;}else if(c===quote){if(next===quote){output+=strings?' ':next;i++;}else quote=null;}continue;}
  if(c==='"'||c==="'"){quote=c;output+=strings?' ':c;continue;}
  if(c==='/'&&next==='/'||sql&&c==='-'&&next==='-'){while(i<source.length&&source[i]!=='\n'){output+=' ';i++;}if(i<source.length)output+='\n';continue;}
  if(c==='/'&&next==='*'){const end=source.indexOf('*/',i+2);if(end<0)throw new Error('Comentário não terminado.');output+=' '.repeat(end+2-i);i=end+1;continue;}
  output+=c;
 }
 if(quote)throw new Error('String não terminada.');return output;
}

function sigmaDocument(content){
 const document=parseDocument(content,{uniqueKeys:true,schema:'core'});
 if(document.errors.length)throw new Error(document.errors.map(e=>e.message).join('\n'));
 if(document.warnings.length)throw new Unsupported('O YAML contém tags ou construções não suportadas.');
 const rule=document.toJS({maxAliasCount:20});
 if(!rule||typeof rule!=='object'||Array.isArray(rule))throw new Error('Informe um documento YAML de regra.');
 if(!rule.title||typeof rule.title!=='string')throw new Error('Sigma exige title.');
 if(!rule.logsource||typeof rule.logsource!=='object')throw new Error('Sigma exige logsource.');
 if(!rule.detection||typeof rule.detection!=='object'||typeof rule.detection.condition!=='string')throw new Error('Sigma exige detection e condition.');
 return rule;
}
function condition(input,names,test,{nativeUnknown=false}={}){
 if(input.length>8192||names.length>200||names.some(name=>name.length>128))throw new Unsupported('Condição acima do limite de complexidade local.');
 let source=input.replace(/\b(1|any|all)\s+of\s+([\w*?]+)(?![\w*?])/gi,(_,count,pattern)=>{
  const selected=names.filter(name=>pattern.toLowerCase()==='them'?!name.startsWith('_'):wildcard(name,pattern));
  if(!selected.length)throw new Error('A condição não encontra seletores para '+pattern+'.');
  return '('+selected.join(count.toLowerCase()==='all'?' and ':' or ')+')';
 });
 const list=tokens(source);let i=0,depth=0;
 const atom=()=>{if(++depth>64)throw new Unsupported('Condição muito profunda.');let result;const t=list[i++];if(!t)throw new Error('Condição incompleta.');if(t.value.toLowerCase()==='not')result=!atom();else if(t.value==='('){result=or();if(list[i++]?.value!==')')throw new Error('Parêntese ausente.');}else{if(!names.includes(t.value)){if(nativeUnknown&&!t.value.startsWith('$'))throw new Unsupported('A condição YARA exige o motor nativo.');throw new Error('Seletor não definido: '+t.value);}result=test(t.value);}depth--;return result;};
 const and=()=>{let result=atom();while(list[i]?.value.toLowerCase()==='and'){i++;const right=atom();result=result&&right;}return result;};
 const or=()=>{let result=and();while(list[i]?.value.toLowerCase()==='or'){i++;const right=and();result=result||right;}return result;};
 const result=or();if(i!==list.length)throw new Unsupported('A condição usa recursos que exigem o motor nativo.');return result;
}
function sigmaMatch(rule,event,missing){
 const selectors=Object.fromEntries(Object.entries(rule.detection).filter(([key])=>!['condition','timeframe'].includes(key)));
 const matchSelector=selection=>{
  if(Array.isArray(selection))return selection.map(matchSelector).some(Boolean);
  if(!selection||typeof selection!=='object')throw new Unsupported('Seletores de palavras-chave exigem o tratamento de campos do SIEM.');
  return Object.entries(selection).map(([key,expected])=>{
   const [field,...modifiers]=key.split('|'),entry=lookup(event,field);if(!entry.found){missing?.add(field);if(Object.hasOwn(event,'_raw')&&Object.keys(event).length===1)throw new Unsupported('O backend Sigma precisa normalizar este texto bruto. Use JSON ou campos chave=valor.');}
   const allowed=['contains','startswith','endswith','all','cased','exists'];
   if(modifiers.some(modifier=>!allowed.includes(modifier)))throw new Unsupported('Modificador Sigma não suportado localmente: '+key);
   if(modifiers.filter(m=>['contains','startswith','endswith'].includes(m)).length>1)throw new Unsupported('Combinação de modificadores não suportada localmente.');
   if(modifiers.includes('exists')){if(typeof expected!=='boolean')throw new Error('exists exige true ou false.');return entry.found===expected;}
   if(expected===null)return !entry.found||entry.value===null;
   if(!entry.found)return false;
   const expectedValues=Array.isArray(expected)?expected:[expected];if(!expectedValues.length)throw new Error('Lista Sigma vazia.');
   if(modifiers.includes('all')&&!Array.isArray(expected))throw new Error('O modificador all exige uma lista.');
   const actuals=Array.isArray(entry.value)?entry.value:[entry.value];
   const matches=expectedValue=>actuals.some(actual=>{
    if(expectedValue===null)throw new Error('Não use null dentro de lista Sigma.');
    if(actual===null)return false;
    if(typeof expectedValue!=='string')return actual===expectedValue;
    const sensitive=modifiers.includes('cased'),a=sensitive?String(actual):String(actual).toLowerCase(),b=sensitive?expectedValue:expectedValue.toLowerCase();
    if(modifiers.includes('contains'))return a.includes(b);if(modifiers.includes('startswith'))return a.startsWith(b);if(modifiers.includes('endswith'))return a.endsWith(b);
    return wildcard(actual,expectedValue,{sensitive});
   });
   return modifiers.includes('all')?expectedValues.every(matches):expectedValues.some(matches);
  }).every(Boolean);
 };
 if(rule.detection.timeframe)throw new Unsupported('timeframe exige correlação no backend Sigma.');
 // Evaluate all selectors first so an unsupported branch never becomes a false negative.
 const results=Object.fromEntries(Object.entries(selectors).map(([name,value])=>[name,matchSelector(value)]));
 return condition(rule.detection.condition,Object.keys(selectors),name=>results[name]);
}
function splitPipes(source){
 let quote=null,depth=0,start=0;const parts=[];
 for(let i=0;i<source.length;i++){const c=source[i];if(quote){if(c==='\\')i++;else if(c===quote){if(source[i+1]===quote)i++;else quote=null;}continue;}if(c==='"'||c==="'"){quote=c;continue;}if(c==='(')depth++;if(c===')')depth--;if(c==='|'&&depth===0){parts.push(source.slice(start,i).trim());start=i+1;}}
 parts.push(source.slice(start).trim());return parts;
}
function queryFilters(content,format){
 content=maskCode(content,{sql:['sql','aql'].includes(format)}).trim();
 if(format==='kusto'){
  const [table,...parts]=splitPipes(content);if(!/^[\w.]+$/.test(table))throw new Unsupported('let, funções e tabelas dinâmicas exigem o motor Kusto.');
  const filters=[];for(const part of parts){if(/^where\s+/i.test(part))filters.push({expression:part.replace(/^where\s+/i,''),dialect:'kusto'});else if(!/^project(?:-away|-keep)?\s+[\w.,\s]+$/i.test(part))throw new Unsupported('Comando Kusto fora da simulação: '+part.split(/\s/)[0]);}if(!filters.length)throw new Unsupported('Informe ao menos uma condição where.');return filters;
 }
 if(format==='sql'||format==='aql'){
  const scan=scanSql(content);if(scan.errors.length)throw new Error(scan.errors.join(' '));
  if(/\b(group\s+by|having|join|union|count\s*\(|sum\s*\(|last\s+\d+|start\s+'|stop\s+')/i.test(scan.sql))throw new Unsupported('Agregações, joins e janelas temporais exigem o SIEM.');
  const mask=maskCode(content,{strings:true,sql:true});if(/\(\s*select\b/i.test(mask))throw new Unsupported('Subconsultas exigem o motor de destino.');
  const start=/\bwhere\s+/i.exec(mask);if(!start)throw new Unsupported('A simulação SQL/AQL exige uma condição WHERE.');
  const offset=start.index+start[0].length,tail=mask.slice(offset),end=/\border\s+by\b|\blimit\b|;\s*$/i.exec(tail);
  return [{expression:content.slice(offset,end?offset+end.index:undefined).trim().replace(/;$/,''),dialect:format}];
 }
 if(format==='eql'){
  const match=/^\s*(\w+)\s+where\s+([\s\S]+)$/i.exec(content);if(!match)throw new Unsupported('sequence, join e funções de correlação exigem Elasticsearch.');
  if(match[1].toLowerCase()!=='any')return [{category:match[1]}, {expression:match[2],dialect:'eql'}];return [{expression:match[2],dialect:'eql'}];
 }
 if(format==='kibana_kql')return [{expression:content,dialect:'kibana_kql'}];
 if(format==='spl'){
  const parts=splitPipes(content),filters=[];
  for(let i=0;i<parts.length;i++){
   const part=parts[i];if(!part&&i===0)continue;
   if(/^where\s+/i.test(part))filters.push({expression:part.replace(/^where\s+/i,''),dialect:'spl_where'});
   else if(/^search\s+/i.test(part)||i===0)filters.push({expression:part.replace(/^search\s+/i,''),dialect:'spl_search',search:true,spl:true});
   else if(!/^fields\s+[\w.,\s]+$/i.test(part))throw new Unsupported('Comando SPL fora da simulação: '+part.split(/\s/)[0]);
  }
  return filters;
 }
 if(format==='xml'){
  const rules=parseFortiSIEM(content);if(rules.length!==1||rules[0].patterns.length!==1)throw new Unsupported('A simulação XML exige um único subpadrão.');
  const pattern=rules[0].patterns[0];if(pattern.aggregate)throw new Unsupported('Agregações XML exigem o FortiSIEM.');return [{expression:pattern.filter,dialect:'sql'}];
 }
 throw new Unsupported('Formato não suportado.');
}
function yaraParts(content){
 content=maskCode(content);const code=maskCode(content,{strings:true});
 if(/\b(import|include)\b/.test(code))throw new Unsupported('Módulos e includes YARA exigem o motor nativo.');
 const match=/^\s*(?:private\s+|global\s+)?rule\s+\w+(?:\s*:\s*[\w\s]+)?\s*\{([\s\S]*)\}\s*$/.exec(content);if(!match)throw new Error('Estrutura YARA inválida: use rule nome { ... condition: ... }.');
 const body=match[1],bodyMask=maskCode(body,{strings:true});
 const conditionStart=/\bcondition\s*:\s*/.exec(bodyMask);if(!conditionStart)throw new Error('YARA exige condition.');
 const before=body.slice(0,conditionStart.index),stringsStart=/\bstrings\s*:\s*/.exec(bodyMask.slice(0,conditionStart.index));
 const stringsSection=stringsStart?before.slice(stringsStart.index+stringsStart[0].length):'';
 const strings=[];let rest=stringsSection;
 const pattern=/\s*(\$\w+)\s*=\s*"((?:\\.|[^"\\])*)"\s*((?:(?:nocase|ascii|fullword)\b\s*)*)/y;let offset=0;
 while(offset<rest.length){pattern.lastIndex=offset;const item=pattern.exec(rest);if(!item){if(!rest.slice(offset).trim())break;throw new Unsupported('A simulação YARA cobre strings ASCII literais, nocase, ascii e fullword. Regex, hex e wide exigem motor nativo.');}let value=item[2].replace(/\\(x[0-9a-fA-F]{2}|[nrt"\\])/g,(_,escape)=>escape[0]==='x'?String.fromCharCode(parseInt(escape.slice(1),16)):({n:'\n',r:'\r',t:'\t','"':'"','\\':'\\'})[escape]);if(!value.length)throw new Error('String YARA vazia.');if(/[^\x00-\x7f]/.test(value))throw new Unsupported('A simulação YARA aceita strings ASCII.');strings.push({id:item[1],value,modifiers:item[3]});offset=pattern.lastIndex;}
 if(new Set(strings.map(item=>item.id)).size!==strings.length)throw new Error('Identificador YARA duplicado.');
 return {strings,condition:body.slice(conditionStart.index+conditionStart[0].length).trim()};
}
export function validateDetectionRule(content,format,mode){
 if(['sql','xml'].includes(format))return validateFortiSIEM(content,format,mode);
 const errors=[],warnings=['Análise estática parcial. A compilação completa deve ser confirmada no motor de destino.'];
 try{
  if(!formats.some(item=>item.id===format))throw new Error('Formato não suportado.');
  if(typeof content!=='string'||!content.trim())throw new Error('O conteúdo está vazio.');if(content.length>500000)throw new Error('A regra excede 500 KB.');
  if(format==='sigma'){const r=sigmaDocument(content);const selectors=Object.keys(r.detection).filter(k=>!['condition','timeframe'].includes(k));if(!selectors.length)throw new Error('Defina um seletor em detection.');condition(r.detection.condition,selectors,()=>false);}
  else if(format==='yara'){const r=yaraParts(content);if(!r.condition)throw new Error('Condição YARA vazia.');condition(r.condition,r.strings.map(item=>item.id),()=>false,{nativeUnknown:true});}
  else{
   const scan=scanSql(content);if(scan.errors.length)throw new Error(scan.errors.join(' '));
   if(format==='aql'&&(!/^\s*select\b/i.test(content)||!/\bfrom\s+(events|flows)\b/i.test(content)))throw new Error('AQL exige SELECT e FROM events ou flows.');
   if(format==='eql'&&!/^\s*(?:\w+\s+where\b|sequence\b|join\b)/i.test(content))throw new Error('EQL exige categoria where condição ou uma correlação válida.');
   if(format==='kusto'&&(!/\bwhere\b|\blet\b/i.test(content)||!/\|/.test(content)))throw new Error('Informe uma consulta Kusto com origem e pipeline.');
   if(/\|\s*$|\b(?:where|and|or)\s*$/i.test(content))throw new Error('Consulta incompleta.');
   try{for(const f of queryFilters(content,format))if(f.expression)parseExpression(f.expression,f);}catch(e){if(e instanceof Unsupported)warnings.push(e.message);else throw e;}
  }
 }catch(e){if(e instanceof Unsupported)warnings.push(e.message);else errors.push(e.message);}
 return {ok:!errors.length,errors,warnings,engine:'hadsec-multiformat-1',scope:'static-partial',format,language:formatInfo(format).label};
}
export function parseEvents(input){
 if(typeof input!=='string'||!input.trim())throw new Error('Insira um evento JSON ou texto de log.');if(input.length>250000)throw new Error('O log excede 250 KB.');
 let values;
 try{const parsed=JSON.parse(input);values=Array.isArray(parsed)?parsed:[parsed];}catch{
  if(input.trim().startsWith('{')||input.trim().startsWith('[')){try{values=input.split(/\r?\n/).filter(line=>line.trim()).map(line=>JSON.parse(line));}catch{throw new Error('JSON inválido. Use objeto, lista ou um objeto por linha.');}}
  else values=input.split(/\r?\n/).filter(line=>line.trim()).map(line=>{const event={_raw:line};for(const m of line.matchAll(/([\w.]+)=(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s]+))/g))Object.defineProperty(event,m[1],{value:m[2]??m[3]??m[4],enumerable:true});return event;});
 }
 if(!values.length||values.length>200)throw new Error('Use entre 1 e 200 eventos.');
 if(values.some(value=>!value||typeof value!=='object'||Array.isArray(value)))throw new Error('Cada evento precisa ser um objeto JSON.');return values;
}
export function simulateDetection(content,format,mode,log){
 const report=validateDetectionRule(content,format,mode);if(!report.ok)return {status:'invalid',reason:report.errors.join(' '),events:[]};
 try{
  const events=parseEvents(log);let match;
  const assumptions=[];
  if(format==='sigma'){const rule=sigmaDocument(content);assumptions.push('Campos e nomes já devem estar normalizados conforme o backend Sigma.');match=(event,missing)=>sigmaMatch(rule,event,missing);}
  else if(format==='yara'){
   const rule=yaraParts(content);assumptions.push('YARA analisa os bytes UTF-8 do texto inserido; não substitui análise de executáveis.');
   match=event=>{const raw=typeof event._raw==='string'?event._raw:JSON.stringify(event);const results=Object.fromEntries(rule.strings.map(s=>{const a=s.modifiers.includes('nocase')?raw.toLowerCase():raw,b=s.modifiers.includes('nocase')?s.value.toLowerCase():s.value;let found=a.includes(b);if(s.modifiers.includes('fullword')){found=false;for(let at=a.indexOf(b);at>=0;at=a.indexOf(b,at+1)){if(!/[A-Za-z0-9]/.test(a[at-1]||'')&&!/[A-Za-z0-9]/.test(a[at+b.length]||'')){found=true;break;}}}return [s.id,found];}));return condition(rule.condition,Object.keys(results),id=>results[id],{nativeUnknown:true});};
  }else{
   const filters=queryFilters(content,format).map(f=>f.expression?{...f,ast:parseExpression(f.expression,f)}:f);
   if(format==='kibana_kql')assumptions.push('Sem mapping Elasticsearch: os campos são tratados como keyword, sem analyzer ou normalizer.');
   match=(event,missing)=>filters.map(f=>{if(!f.category)return evaluateExpression(f.ast,event,f.dialect,missing);const entry=lookup(event,'event.category');if(!entry.found)missing.add('event.category');return Array.isArray(entry.value)?entry.value.includes(f.category):entry.value===f.category;}).every(Boolean);
  }
  const rows=events.map((event,index)=>{const missing=new Set();return {index:index+1,matched:match(event,missing),missing:[...missing]};});
  return {status:rows.some(row=>row.matched)?'match':'no-match',matched:rows.filter(row=>row.matched).length,total:rows.length,events:rows,assumptions,scope:'single-event-local'};
 }catch(e){return {status:e instanceof Unsupported?'unsupported':'invalid',reason:e.message,events:[]};}
}
