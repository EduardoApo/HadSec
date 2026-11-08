export class Unsupported extends Error{}
export function tokens(input){
 const out=[];let i=0;
 while(i<input.length){
  if(/\s/.test(input[i])){i++;continue;}
  const start=i,c=input[i];
  if(c==='"'||c==="'"){
   const quote=c;let value='',closed=false;i++;
   while(i<input.length){
    if(input[i]===quote){if(input[i+1]===quote){value+=quote;i+=2;continue;}closed=true;i++;break;}
    if(input[i]==='\\'&&[quote,'\\'].includes(input[i+1])){value+=input[i+1];i+=2;}else value+=input[i++];
   }
   if(!closed)throw new Error('String não terminada.');out.push({kind:'string',value,quote});continue;
  }
  const operator=/^(==|!=|<>|>=|<=|=~|!~|&&|\|\||[():,=><!])/.exec(input.slice(i));
  if(operator){out.push({kind:'operator',value:operator[0]});i+=operator[0].length;continue;}
  const word=/^[\p{L}_$@][\p{L}\p{N}_.$@*?~-]*|^[+-]?\d+(?:\.\d+)?|^[*?][\w.*?-]*/u.exec(input.slice(i));
  if(!word)throw new Unsupported('Expressão fora do subconjunto local perto de: '+input.slice(start,start+30));
  out.push({kind:/^[+-]?\d/.test(word[0])?'number':'word',value:word[0]});i+=word[0].length;
  if(out.length>3000)throw new Unsupported('A expressão excede o limite de complexidade local.');
 }
 return out;
}
export function parseExpression(input,{search=false,spl=false,dialect}={}){
 const list=tokens(input);let position=0,depth=0;
 const at=()=>list[position],is=value=>at()?.kind!=='string'&&at()?.value.toLowerCase()===value,take=()=>list[position++];
 const expect=value=>{if(!is(value))throw new Error('Esperado '+value+'.');return take();};
 const atom=()=>{
  if(++depth>64)throw new Unsupported('Expressão muito profunda.');
  let node;
  if(is('not')||is('!')){take();node={type:'not',value:atom()};}
  else if(is('(')){take();node=expression(0);expect(')');}
  else{
   const field=take();if(!field)throw new Error('Condição incompleta.');
   if(field.kind!=='word'&&!(field.kind==='string'&&field.quote==='"'))throw new Unsupported('Campo ou função não suportado.');
   if(field.kind==='string'&&dialect&&!['sql','aql'].includes(dialect))throw new Unsupported('Expressões de literais ou campos entre aspas exigem o parser nativo neste formato.');
   if(field.kind==='word'&&/[*?]/.test(field.value))throw new Unsupported('Campos com curingas exigem o mapping do motor de destino.');
   let operator=take()?.value.toLowerCase();
   if(operator==='not'){if(!is('in'))throw new Unsupported('Operador não suportado.');take();operator='not in';}
   const allowed=['=','==','!=','<>','=~','!~','>', '>=','<','<=',':','contains','contains_cs','has','has_cs','startswith','startswith_cs','endswith','endswith_cs','like','ilike','in','in~','not in'];
   if(!allowed.includes(operator))throw new Unsupported('Operador ou busca textual não suportado: '+(operator||field.value));
   const nativeOperators={kusto:['==','!=','=~','!~','>','>=','<','<=','contains','contains_cs','has','has_cs','startswith','startswith_cs','endswith','endswith_cs','in','in~'],sql:['=','==','!=','<>','>','>=','<','<=','like','ilike','in','not in'],aql:['=','!=','<>','>','>=','<','<=','like','ilike','in','not in'],eql:['==','!=','>','>=','<','<=',':','in','in~'],spl_search:['=','!=','>','>=','<','<='],spl_where:['=','==','!=','<>','>','>=','<','<=','in'],kibana_kql:[':','>','>=','<','<=']};
   if(dialect==='kibana_kql'&&![':','>','>=','<','<='].includes(operator))throw new Error('Kibana KQL usa : para igualdade e os operadores de intervalo.');
   if(dialect==='kusto'&&operator==='=')throw new Error('Kusto exige == para igualdade.');
   if(nativeOperators[dialect]&&!nativeOperators[dialect].includes(operator))throw new Unsupported('Operador fora do subconjunto deste formato: '+operator);
   let values=[];
   if(is('(')){take();if(!['in','in~','not in',':'].includes(operator))throw new Unsupported('Função não suportada.');do{const t=take();if(!t||t.kind!=='string'&&[')',','].includes(t.value))throw new Error('Lista incompleta.');values.push(t);if(!is(','))break;take();}while(at());expect(')');}
   else {const t=take();if(!t||t.kind!=='string'&&['and','or','&&','||',')',','].includes(t.value.toLowerCase()))throw new Error('Valor de comparação ausente.');values=[t];}
   if(values.some(t=>t.kind==='operator'))throw new Error('Use um valor literal depois do operador.');
   if(!['kibana_kql','spl_search'].includes(dialect)&&dialect&&values.some(t=>t.kind==='word'&&!['true','false','null'].includes(t.value.toLowerCase())))throw new Unsupported('Comparações com colunas ou valores sem aspas exigem o motor nativo.');
   node={type:'comparison',field:field.value,operator,values};
  }
  depth--;return node;
 };
 const precedence=op=>search?(op==='and'||op==='&&'?1:op==='or'||op==='||'?2:0):(op==='or'||op==='||'?1:op==='and'||op==='&&'?2:0);
 const expression=min=>{
  let left=atom();
  while(at()&&!is(')')&&!is(',')){
   let op=at().value.toLowerCase(),rank=precedence(op),implicit=false;
   if(!rank&&spl&&search){op='and';rank=1;implicit=true;}
   if(!rank||rank<min)break;if(!implicit)take();
   left={type:op==='and'||op==='&&'?'and':'or',left,right:expression(rank+1)};
  }
  return left;
 };
 const ast=expression(0);if(position!==list.length)throw new Unsupported('Parte da condição não é suportada localmente.');return ast;
}
export function lookup(event,field){
 if(Object.hasOwn(event,field))return {found:true,value:event[field]};
 let value=event;for(const key of field.split('.')){if(!value||typeof value!=='object'||!Object.hasOwn(value,key))return {found:false};value=value[key];}
 return {found:true,value};
}
export function wildcard(value,pattern,{sensitive=true,sql=false,singleWildcard=true}={}){
 if(pattern.length>2048)throw new Unsupported('Padrão curinga acima do limite local.');
 const parts=[],characters=Array.from(sensitive?pattern:pattern.toLowerCase());
 for(let i=0;i<characters.length;i++){
  const c=characters[i];
  if(c==='\\'&&['*','?','\\','%','_'].includes(characters[i+1]))parts.push({literal:characters[++i]});
  else if(c===(sql?'%':'*')){if(parts.at(-1)?.type!=='star')parts.push({type:'star'});}
  else if(singleWildcard&&c===(sql?'_':'?'))parts.push({type:'any'});else parts.push({literal:c});
 }
 const input=sensitive?String(value):String(value).toLowerCase();if(input.length*parts.length>250000)throw new Unsupported('O padrão excede o orçamento da simulação local.');
 let prior=new Uint8Array(parts.length+1);prior[0]=1;for(let j=1;j<=parts.length;j++)prior[j]=parts[j-1].type==='star'?prior[j-1]:0;
 for(const c of input){const next=new Uint8Array(parts.length+1);for(let j=1;j<=parts.length;j++){const part=parts[j-1];next[j]=part.type==='star'?(next[j-1]||prior[j]):prior[j-1]&&(part.type==='any'||c===part.literal)?1:0;}prior=next;}
 return !!prior[parts.length];
}
export function evaluateExpression(ast,event,dialect,missing=new Set()){
 const run=node=>{
  if(node.type==='not')return !run(node.value);
  if(node.type==='and')return run(node.left)&&run(node.right);
  if(node.type==='or')return run(node.left)||run(node.right);
  const {field,operator:op,values}=node,entry=lookup(event,field);if(!entry.found)missing.add(field);
  if(dialect==='eql'&&values.some(v=>v.quote==="'"))throw new Unsupported('EQL exige strings com aspas duplas.');
  if(dialect==='kibana_kql'&&op===':'&&values[0]?.value==='*'&&values[0].kind!=='string')return entry.found&&entry.value!==null;
  if(!entry.found){if(Object.hasOwn(event,'_raw')&&Object.keys(event).length===1)throw new Unsupported('Texto bruto sem campos normalizados: use JSON ou campos chave=valor para este filtro.');return false;}
  if(['sql','aql','spl_search','spl_where'].includes(dialect)&&(entry.value===null||values.some(t=>t.kind==='word'&&t.value.toLowerCase()==='null')))return false;
  if(entry.value===null)throw new Unsupported('A comparação com null depende dos tipos e do mapping nativo.');
  const compare=(actual,token)=>{
   let expected=token.kind==='number'?Number(token.value):token.value;
   if(token.kind==='word'&&['true','false','null'].includes(expected.toLowerCase()))expected=JSON.parse(expected.toLowerCase());
   const insensitive=['=~','!~','contains','has','startswith','endswith','ilike','in~'].includes(op)||(dialect==='spl_search')||(dialect==='eql'&&op===':');
   if(dialect!=='spl_search'&&typeof actual!==typeof expected)throw new Unsupported('Os tipos do evento e da comparação diferem. Use JSON com os tipos do destino ou confirme no motor nativo.');
   const a=insensitive?String(actual).toLowerCase():actual,b=insensitive?String(expected).toLowerCase():expected;
   if(['in','in~','not in','==','=','=~','!=','<>','!~'].includes(op)){
    if(dialect==='spl_search'&&typeof expected==='string')return wildcard(actual,expected,{sensitive:false,singleWildcard:false});
    return a===b;
   }
   if(op===':'){const glob=dialect!=='kibana_kql'||token.kind!=='string';return glob?wildcard(actual,String(expected),{sensitive:!insensitive,singleWildcard:dialect!=='kibana_kql'}):a===b;}
   if(['like','ilike'].includes(op))return wildcard(actual,String(expected),{sql:true,sensitive:op==='like'});
   if(op.startsWith('contains'))return String(a).includes(String(b));
   if(op.startsWith('startswith'))return String(a).startsWith(String(b));
   if(op.startsWith('endswith'))return String(a).endsWith(String(b));
   if(op==='has'||op==='has_cs')return String(a).split(/[^\p{L}\p{N}]+/u).includes(String(b));
   if(typeof actual!=='number'||typeof expected!=='number')throw new Unsupported('Comparação de intervalo exige números no evento e na regra.');
   if(op==='>')return actual>expected;if(op==='>=')return actual>=expected;if(op==='<')return actual<expected;if(op==='<=')return actual<=expected;
   throw new Unsupported('Operador não suportado.');
  };
  const negative=['!=','<>','!~','not in'].includes(op),actuals=Array.isArray(entry.value)?entry.value:[entry.value];
  const matches=actuals.some(actual=>values.some(value=>compare(actual,value)));return negative?!matches:matches;
 };
 return run(ast);
}
