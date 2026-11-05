import {XMLParser,XMLValidator} from 'fast-xml-parser';
const array=v=>v===undefined?[]:Array.isArray(v)?v:[v];
const text=v=>typeof v==='object'?String(v?.['#text']??''):String(v??'');
export function parseFortiSIEM(content){
 const valid=XMLValidator.validate(content);
 if(valid!==true)throw new Error(`XML: ${valid.err.msg} (linha ${valid.err.line}).`);
 if(/<!DOCTYPE|<!ENTITY/i.test(content))throw new Error('DOCTYPE e declarações de entidades não são permitidos.');
 const parsed=new XMLParser({ignoreAttributes:false,processEntities:true,parseTagValue:false,parseAttributeValue:false,trimValues:true}).parse(content);
 const roots=Object.keys(parsed).filter(k=>!k.startsWith('?'));
 if(roots.length!==1||roots[0]!=='rules'||!parsed.rules?.DataRequest)throw new Error('O XML nativo do FortiSIEM deve conter <rules><DataRequest>…</DataRequest></rules>.');
 const definitions=array(parsed.rules.DataRequest);
 return definitions.map(rule=>({
  native:rule,name:text(rule.Name),description:text(rule.Description),mode:rule['@_mode']||'',
  technique:rule['@_technique']||'',techniqueName:rule['@_techniqueName']||'',tactics:rule['@_tactic']||'',
  category:rule['@_functionCategory']||'',eventType:rule.IncidentDef?.['@_eventType']||'',
  nativeSeverity:Number(rule.IncidentDef?.['@_severity']||0),
  severity:Number(rule.IncidentDef?.['@_severity'])>=9?'Crítica':Number(rule.IncidentDef?.['@_severity'])>=8?'Alta':Number(rule.IncidentDef?.['@_severity'])>=5?'Média':'Baixa',
  dataSource:text(rule.DataSource),technology:text(rule.DetectionTechnology),tags:array(rule.Tag).map(text),
  window:Number(rule.PatternClause?.['@_window']||0),patterns:array(rule.PatternClause?.SubPattern).map(p=>({name:p['@_name']||'',filter:text(p.SingleEvtConstr),aggregate:text(p.GroupEvtConstr),groupBy:text(p.GroupByAttr)})),
  incidentTitle:text(rule.IncidentTitle),incidentMapping:text(rule.IncidentDef?.ArgList),notificationFrequency:Number(rule.IncidentDef?.['@_fireFreq']||0),
  triggeredAttributes:text(rule.TriggerEventDisplay?.AttrList).split(',').map(s=>s.trim()).filter(Boolean),
  watchLists:array(rule.DynWatchLists?.DynWatchListDef).map(d=>({attribute:d['@_attr'],name:text(d.WatchList)})),
  remediation:text(rule.Remediation)
 }));
}
