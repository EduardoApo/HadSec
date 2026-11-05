import { XMLValidator } from 'fast-xml-parser';
import {parseFortiSIEM} from './fortisiem.mjs';
export const VALIDATOR_VERSION = 'hadsec-static-2';
// Conservative checks. This is deliberately not a replacement for the FortiSIEM compiler.
export function validateRule(content, format, mode) {
 const errors=[], warnings=[];
 if(typeof content!=='string'||!content.trim()) return {ok:false,errors:['O conteúdo está vazio.'],warnings,engine:VALIDATOR_VERSION};
 if(content.length>500000) return {ok:false,errors:['Limite de 500 KB excedido.'],warnings,engine:VALIDATOR_VERSION};
 if(!['xml','sql'].includes(format)) errors.push('Formato desconhecido.');
 if(!['Streaming','Scheduled','Scheduled via SQL'].includes(mode)) errors.push('Modo de avaliação desconhecido.');
 if((format==='sql')!==(mode==='Scheduled via SQL')) errors.push('SQL exige Scheduled via SQL; correlação XML exige Streaming ou Scheduled.');
 if(format==='xml') {
  if(/<!DOCTYPE|<!ENTITY/i.test(content)) errors.push('DOCTYPE e declarações de entidades não são permitidos.');
  const check=XMLValidator.validate(content,{allowBooleanAttributes:false});
  if(check!==true) errors.push(`XML: ${check.err.msg} (linha ${check.err.line}).`);
  if(check===true&&!errors.length) try {
   const definitions=parseFortiSIEM(content);
   if(definitions.length!==1)errors.push('Selecione e exporte uma única regra por arquivo para manter o histórico individual.');
   for(const rule of definitions){
    if(!rule.name.trim())errors.push('A definição deve conter Name preenchido.');
    if(rule.mode!==mode)errors.push(`O XML declara modo ${rule.mode||'ausente'}, diferente do modo selecionado ${mode}.`);
    if(!rule.eventType)errors.push('IncidentDef deve informar o eventType do incidente.');
    if(!Number.isInteger(rule.nativeSeverity)||rule.nativeSeverity<1||rule.nativeSeverity>10)errors.push('IncidentDef severity deve ser um inteiro entre 1 e 10.');
    if(mode==='Streaming'){
     if(!rule.patterns.length)errors.push('Uma regra Streaming deve conter SubPattern dentro de PatternClause.');
     if(!Number.isInteger(rule.window)||rule.window<=0)errors.push('PatternClause window deve informar uma janela positiva em segundos.');
    }
    const names=rule.patterns.map(p=>p.name);
    if(names.some(n=>!n))errors.push('Todos os subpadrões devem ter nome.');
    if(new Set(names).size!==names.length)errors.push('Os nomes dos subpadrões devem ser únicos.');
    if(names.some(n=>n.toLowerCase()==='regexp'))errors.push('regexp é um nome reservado para subpadrões.');
    for(const pattern of rule.patterns){
     if(!pattern.filter)warnings.push(`O subpadrão ${pattern.name} não possui filtro SingleEvtConstr. Confira o comportamento no FortiSIEM.`);
     for(const constraint of [pattern.filter,pattern.aggregate])errors.push(...scanSql(constraint).errors.map(e=>`${pattern.name}: ${e}`));
    }
    const protectedTargets=['eventType','phRecvTime','reptDevIpAddr','reptDevName','rawEventMsg'];
    for(const match of rule.incidentMapping.matchAll(/(?:^|,)\s*(\w+)\s*=/g))if(protectedTargets.includes(match[1]))errors.push(`O atributo reservado ${match[1]} não deve ser atribuído no ArgList do incidente.`);
    for(const match of rule.incidentMapping.matchAll(/=\s*([A-Za-z][\w]*)\./g))if(!names.includes(match[1]))errors.push(`O incidente referencia o subpadrão inexistente ${match[1]}.`);
    if(/Group@|Lookup|WatchList/.test(content))warnings.push('A definição depende de grupos, lookup tables ou watch lists do ambiente. Confirme essas dependências no destino.');
   }
  }catch(e){errors.push(e.message);}
  warnings.push('XML bem formado não certifica o schema ou a lógica de correlação. Preserve a estrutura exportada e valide a importação no FortiSIEM.');
 } else if(format==='sql') {
  const scan=scanSql(content);errors.push(...scan.errors);const sql=scan.sql;
  if(!/^\s*(SELECT|WITH)\b/i.test(sql)) errors.push('A consulta deve iniciar com SELECT ou WITH.');
  if(!/\bFROM\s+fsiem\s*\.\s*events\b/i.test(sql)) errors.push('A consulta deve referenciar FROM fsiem.events.');
  if(/\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|ATTACH|DETACH|SYSTEM|INTO\s+OUTFILE)\b/i.test(sql)) errors.push('Somente consultas de leitura são aceitas.');
  if(/\bSELECT\s+FROM\b|\bWHERE\s*(GROUP|ORDER|LIMIT|$)|\b(AND|OR)\s*($|GROUP|ORDER|LIMIT)/i.test(sql)) errors.push('Cláusula SQL incompleta.');
  for(const match of sql.matchAll(/\bAS\s+([\w]+)/gi)) {
   const token=match[1],quoted=/^__quoted_(\d+)__$/.exec(token),alias=quoted?scan.quoted[Number(quoted[1])]?.value:token;
   if(!/^[A-Za-z][A-Za-z0-9]*$/.test(alias||''))errors.push('Aliases de regras SQL devem começar com letra e conter somente letras e números (FortiSIEM 7.5.1).');
  }
  if(!/\bWHERE\b[\s\S]*\bphRecvTime\b/i.test(sql)) warnings.push('Inclua restrição temporal com phRecvTime no WHERE.');
  if(!/\bLIMIT\s+\d+/i.test(sql)) warnings.push('Use LIMIT durante a investigação para limitar resultados.');
  warnings.push('Análise estática parcial: funções ClickHouse, tipos e atributos precisam ser confirmados em Analytics > Advanced Search. Selecione também Attributes used.');
 }
 if(mode==='Scheduled'||mode==='Scheduled via SQL') warnings.push('O botão Test Rule do FortiSIEM não suporta regras Scheduled. Registre a verificação da consulta e execução agendada.');
 return {ok:errors.length===0,errors:[...new Set(errors)],warnings:[...new Set(warnings)],engine:VALIDATOR_VERSION,target:'7.5.1.0620',scope:'static-partial'};
}
export function scanSql(input) {
 let sql='',depth=0;const errors=[],quoted=[];
 for(let i=0;i<input.length;i++) {
  const c=input[i],next=input[i+1];
  if(c==='-'&&next==='-'){while(i<input.length&&input[i]!=='\n')i++;sql+=' ';continue;}
  if(c==='/'&&next==='*'){const end=input.indexOf('*/',i+2);if(end<0){errors.push('Comentário SQL não terminado.');break;}i=end+1;sql+=' ';continue;}
  if(c==="'"||c==='"'||c==='`') {
   const quote=c,start=i;let closed=false;
   for(i++;i<input.length;i++){if(input[i]==='\\'){i++;continue;}if(input[i]===quote){if(input[i+1]===quote){i++;continue;}closed=true;break;}}
   if(!closed)errors.push('String ou identificador SQL não terminado.');sql+=` __quoted_${quoted.length}__ `;quoted.push({quote,value:input.slice(start+1,i)});continue;
  }
  if(c==='(')depth++;if(c===')'&&--depth<0){errors.push('Parêntese de fechamento sem abertura.');depth=0;}
  sql+=c;
 }
 if(depth)errors.push('Parênteses desbalanceados.');
 const trimmed=sql.trim().replace(/;\s*$/,'');if(trimmed.includes(';'))errors.push('Apenas uma instrução SQL é permitida.');
 return {sql:trimmed,errors,quoted};
}
