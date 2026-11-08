import {test} from 'node:test';
import assert from 'node:assert/strict';
import {formats,sampleEvent} from '../supabase/functions/_shared/formats.mjs';
import {validateDetectionRule,simulateDetection,parseEvents} from '../supabase/functions/_shared/detection-engine.mjs';
import {parseExpression,evaluateExpression,wildcard,Unsupported} from '../supabase/functions/_shared/filter-expression.mjs';

test('Every new format validates its example and distinguishes executable matches from negatives',()=>{
 for(const format of formats.filter(f=>f.sample)){
  assert.equal(validateDetectionRule(format.sample,format.id,format.mode).ok,true,format.id);
  assert.equal(simulateDetection(format.sample,format.id,format.mode,sampleEvent).status,'match',format.id);
  assert.equal(simulateDetection(format.sample,format.id,format.mode,sampleEvent.replaceAll('malware.exe','notepad.exe')).status,'no-match',format.id);
 }
});
test('Kusto operators preserve case sensitivity and term semantics',()=>{
 const run=(expression,value)=>simulateDetection('Events | where '+expression,'kusto','Native',JSON.stringify({Name:value}));
 assert.equal(run('Name == "malware.exe"','MALWARE.EXE').status,'no-match');assert.equal(run('Name =~ "malware.exe"','MALWARE.EXE').status,'match');
 assert.equal(run('Name contains "Explorer"','KustoExplorerQueryRun').status,'match');assert.equal(run('Name has "Explorer"','KustoExplorerQueryRun').status,'no-match');assert.equal(run('Name has "Explorer"','Kusto Explorer QueryRun').status,'match');
 assert.equal(run('Name in ("a", "b")','B').status,'no-match');assert.equal(run('Name in~ ("a", "b")','B').status,'match');
});
test('AQL and FortiSIEM SQL LIKE have SQL wildcards, and ILIKE ignores case',()=>{
 const log=JSON.stringify({Image:'MALWARE.EXE'});
 assert.equal(simulateDetection("SELECT * FROM events WHERE Image LIKE '%malware.exe'",'aql','Native',log).status,'no-match');
 assert.equal(simulateDetection("SELECT * FROM events WHERE Image ILIKE '%malware.exe'",'aql','Native',log).status,'match');
 assert.equal(simulateDetection("SELECT * FROM events WHERE Image LIKE '*MALWARE.EXE'",'aql','Native',log).status,'no-match');
});
test('Elastic EQL distinguishes == and wildcard :, while Kibana quoted wildcards are literal',()=>{
 const log=JSON.stringify({event:{category:'process'},process:{name:'MALWARE.EXE'}});
 assert.equal(simulateDetection('process where process.name == "malware.exe"','eql','Native',log).status,'no-match');
 assert.equal(simulateDetection('process where process.name : "*malware.exe"','eql','Native',log).status,'match');
 assert.equal(simulateDetection('process where process.name : "*malware.exe"','eql','Native',JSON.stringify({event:{category:['process']},process:{name:'MALWARE.EXE'}})).status,'match');
 assert.equal(simulateDetection('any where process.name == "*MALWARE.EXE"','eql','Native',log).status,'no-match');
 assert.equal(simulateDetection('process.name: *EXE','kibana_kql','Native',log).status,'match');
 assert.equal(simulateDetection('process.name: "*EXE"','kibana_kql','Native',log).status,'no-match');
 assert.equal(simulateDetection('process.name: *','kibana_kql','Native','{"process":{"name":""}}').status,'match');
 assert.equal(simulateDetection('process.name: *','kibana_kql','Native','{"process":{"name":null}}').status,'no-match');
 assert.equal(simulateDetection('process.name: m?lware.exe','kibana_kql','Native','{"process":{"name":"malware.exe"}}').status,'no-match');
});
test('Splunk search and where preserve their different boolean precedence and missing-field semantics',()=>{
 const log='{"a":"yes","b":"no","c":"yes"}';
 assert.equal(simulateDetection('search a="no" AND b="yes" OR c="yes"','spl','Native',log).status,'no-match');
 assert.equal(simulateDetection('| where a="no" AND b="yes" OR c="yes"','spl','Native',log).status,'match');
 assert.equal(simulateDetection('search a="YES"','spl','Native',log).status,'match');
 assert.equal(simulateDetection('| where a="YES"','spl','Native',log).status,'no-match');
 assert.equal(simulateDetection('search missing!="x"','spl','Native',log).status,'no-match');
 assert.equal(simulateDetection('search NOT missing="x"','spl','Native',log).status,'match');
 assert.equal(simulateDetection('search a="yes" c="yes"','spl','Native',log).status,'match');
});
test('Sigma maps, lists, all, cased, exists and selector expansion are evaluated without ignoring unknown branches',()=>{
 const header='title: Test\nlogsource:\n  product: windows\ndetection:\n';
 const sigma=(selection,condition='selection')=>header+selection+'  condition: '+condition;
 assert.equal(simulateDetection(sigma("  selection:\n    Image|endswith: '.exe'\n"),'sigma','Native','{"Image":"CMD.EXE"}').status,'match');
 assert.equal(simulateDetection(sigma("  selection:\n    Image|endswith|cased: '.exe'\n"),'sigma','Native','{"Image":"CMD.EXE"}').status,'no-match');
 assert.equal(simulateDetection(sigma("  selection:\n    CommandLine|contains|all: ['one', 'two']\n"),'sigma','Native','{"CommandLine":"ONE TWO"}').status,'match');
 assert.equal(simulateDetection(sigma("  selection:\n    Image|exists: true\n"),'sigma','Native','{"Image":null}').status,'match');
 const selectors="  selection_one:\n    Image: 'cmd.exe'\n  selection_two:\n    Image: 'powershell.exe'\n";
 assert.equal(simulateDetection(sigma(selectors,'1 of selection*'),'sigma','Native','{"Image":"cmd.exe"}').status,'match');
 assert.equal(simulateDetection(sigma("  selection:\n    Image: 'unmatched'\n    Field|unknown: 'value'\n"),'sigma','Native','{"Image":"other"}').status,'unsupported');
 assert.equal(validateDetectionRule(sigma(selectors,'not_defined'),'sigma','Native').ok,false);
 assert.equal(validateDetectionRule('title: a\ntitle: b','sigma','Native').ok,false);
});
test('YARA literal string matching honors nocase, fullword and string conditions',()=>{
 const rule=(modifiers,condition='$a')=>'rule R { strings: $a = "malware.exe" '+modifiers+' condition: '+condition+' }';
 assert.equal(simulateDetection(rule(''),'yara','Native','MALWARE.EXE').status,'no-match');
 assert.equal(simulateDetection(rule('nocase'),'yara','Native','MALWARE.EXE').status,'match');
 assert.equal(simulateDetection(rule('fullword'),'yara','Native','xmalware.exe').status,'no-match');
 assert.equal(simulateDetection(rule('fullword','any of them'),'yara','Native',' malware.exe ').status,'match');
 assert.equal(simulateDetection(rule('','filesize > 10'),'yara','Native','malware.exe').status,'unsupported');
 assert.equal(simulateDetection('import "pe" rule R { condition: pe.is_pe }','yara','Native','malware.exe').status,'unsupported');
});
test('Native correlations and unsupported functions never return a fabricated negative',()=>{
 for(const [format,query]of [['sql','SELECT COUNT(*) FROM fsiem.events WHERE Image = \'malware.exe\' HAVING COUNT(*) > 2'],['kusto','Events | where Name == "a" | summarize count()'],['eql','sequence [process where true] [process where true]'],['spl','search a="x" | stats count']])assert.equal(simulateDetection(query,format,format==='sql'?'Scheduled via SQL':'Native','{"a":"no","Name":"other"}').status,'unsupported',format);
});
test('Input formats and complexity limits keep logs local and bounded',()=>{
 assert.equal(parseEvents('[{"x":1},{"x":2}]').length,2);assert.equal(parseEvents('{"x":1}\n{"x":2}').length,2);
 assert.equal(parseEvents('Image="C:\\Temp\\malware.exe" action=started')[0].Image,'C:\\Temp\\malware.exe');
 assert.throws(()=>parseEvents('{invalid'),/JSON inválido/);assert.throws(()=>parseEvents(JSON.stringify(Array(201).fill({x:1}))),/200/);
 assert.throws(()=>wildcard('a'.repeat(1000),'a'.repeat(1000)),Unsupported);
 assert.equal(wildcard('C:\\Temp\\malware.exe','*\\malware.exe'),true);
 assert.equal(wildcard('😃.exe','*.exe'),true);assert.equal(wildcard('😃.exe','😃.exe'),true);
 assert.throws(()=>parseExpression('runMaliciousCode()'),Unsupported);
 assert.equal(evaluateExpression(parseExpression('x == "value"'),{x:'value'},'kusto'),true);
});
test('Quoted keywords, escaped SQL strings and comments cannot change clause boundaries',()=>{
 assert.equal(simulateDetection("SELECT * FROM events WHERE Name = 'O''Brien'",'aql','Native',JSON.stringify({Name:"O'Brien"})).status,'match');
 assert.equal(simulateDetection('Events | where Name == "AND"','kusto','Native','{"Name":"AND"}').status,'match');
 assert.equal(simulateDetection("SELECT 'WHERE hidden' FROM events WHERE Name = 'LIMIT text' LIMIT 1",'aql','Native','{"Name":"LIMIT text"}').status,'match');
 assert.equal(simulateDetection('// comment\nrule R { strings: $a = "condition: sample" condition: $a }','yara','Native','condition: sample').status,'match');
});
test('Unknown mappings and unparsed raw logs are not reported as false negatives',()=>{
 const sigma=formats.find(f=>f.id==='sigma');assert.equal(simulateDetection(sigma.sample,'sigma','Native','malware.exe was started').status,'unsupported');
 assert.equal(simulateDetection('search _raw="*malware.exe*"','spl','Native','malware.exe was started').status,'match');
 assert.equal(simulateDetection('process.*: "value"','kibana_kql','Native','{}').status,'unsupported');
 assert.equal(simulateDetection('Events | where a == b','kusto','Native','{"a":"x","b":"x"}').status,'unsupported');
 assert.equal(simulateDetection("SELECT * FROM events WHERE a != 'value'",'aql','Native','{"a":null}').status,'no-match');
 assert.equal(validateDetectionRule('Events | where a = "value"','kusto','Native').ok,false);
 assert.equal(validateDetectionRule('a == "value"','kibana_kql','Native').ok,false);
 assert.equal(simulateDetection('Events | where Name : "value"','kusto','Native','{"Name":"value"}').status,'unsupported');
 assert.equal(simulateDetection('search Name contains "value"','spl','Native','{"Name":"value"}').status,'unsupported');
 assert.equal(simulateDetection('Events | where EventID == 42','kusto','Native','EventID=42').status,'unsupported');
 assert.equal(simulateDetection('Events | where EventID == 42','kusto','Native','{"EventID":42}').status,'match');
});
