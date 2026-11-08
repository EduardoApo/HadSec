import {parseFortiSIEM} from './fortisiem.mjs';
export const formats=[
 {id:'sql',label:'FortiSIEM SQL',extension:'sql',mode:'Scheduled via SQL',docs:'https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/903877/creating-rules',sample:"SELECT Image FROM fsiem.events WHERE Image LIKE '%malware.exe'"},
 {id:'xml',label:'FortiSIEM XML',extension:'xml',mode:'Streaming',docs:'https://docs.fortinet.com/document/fortisiem/7.5.1/user-guide/903877/creating-rules',sample:''},
 {id:'sigma',label:'Sigma',extension:'yml',mode:'Native',docs:'https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html',reference:'Especificação 2.1.0',sample:"title: Executável suspeito\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\malware.exe'\n  condition: selection\nlevel: high"},
 {id:'kusto',label:'KQL · Microsoft Kusto',extension:'kql',mode:'Native',docs:'https://learn.microsoft.com/en-us/kusto/query/',sample:'DeviceProcessEvents\n| where FileName =~ "malware.exe"'},
 {id:'aql',label:'AQL · IBM QRadar',extension:'aql',mode:'Native',docs:'https://www.ibm.com/docs/en/qsip/7.5.0?topic=aql-ariel-query-language',sample:"SELECT * FROM events WHERE Image ILIKE '%malware.exe'"},
 {id:'eql',label:'EQL · Elastic',extension:'eql',mode:'Native',docs:'https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax',sample:'process where process.name == "malware.exe"'},
 {id:'kibana_kql',label:'KQL · Kibana',extension:'kql',mode:'Native',docs:'https://www.elastic.co/docs/reference/query-languages/kql',sample:'process.name: "malware.exe"'},
 {id:'spl',label:'SPL · Splunk',extension:'spl',mode:'Native',docs:'https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.6/search-commands/search',reference:'Referência 10.6',sample:'search Image="*malware.exe"'},
 {id:'yara',label:'YARA',extension:'yar',mode:'Native',docs:'https://github.com/VirusTotal/yara/blob/v4.6.0/docs/writingrules.rst',reference:'YARA clássico 4.6.0',sample:'rule ExecutavelSuspeito {\n  strings:\n    $exe = "malware.exe" nocase\n  condition:\n    $exe\n}'}
];
export const formatInfo=id=>formats.find(format=>format.id===id)||{id,label:id,extension:id,mode:'Native'};
export const sampleEvent=JSON.stringify({Image:'C:\\Temp\\malware.exe',FileName:'malware.exe',process:{name:'malware.exe',executable:'C:\\Temp\\malware.exe'},event:{category:'process'},message:'Process started: malware.exe'},null,2);
export const modeForFormat=(format,content='',prior)=>{if(format!=='xml')return formatInfo(format).mode;if(prior)return prior;try{return parseFortiSIEM(content)[0]?.mode||'Streaming';}catch{return 'Streaming';}};
