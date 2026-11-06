import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildReport,reportCSV} from '../src/reporting.mjs';
import {buildNotifications} from '../server/notifications.mjs';
const now=new Date('2026-11-06T18:00:00Z');
const date='2026-11-06T15:00:00Z';
const empty={rules:[],versions:[],requests:[],evidence:[],profiles:[]};
test('Reports: periods exclude old, future and invalid records without fabricated percentages',()=>{
 const data={...empty,versions:[{created_at:date},{created_at:'2020-01-01'},{created_at:'2030-01-01'},{created_at:'invalid'}]};
 const report=buildReport(data,7,now);assert.equal(report.daily.length,7);assert.equal(report.metrics.versions,1);assert.equal(report.metrics.approvalRate,null);assert.equal(report.daily.reduce((sum,row)=>sum+row.versions,0),1);
 assert.equal(buildReport(empty,90,now).daily.length,90);assert.equal(buildReport(empty,999,now).days,30);
});
test('Reports: cohort metrics, severity and collaboration use visible persisted records',()=>{
 const data={...empty,profiles:[{id:'user',display_name:'Analista'}],rules:[{created_at:date,severity:'Alta'},{created_at:date,severity:'Alta',archived:true}],versions:[{created_at:date,created_by:'user'}],requests:[{id:'a',created_at:date,status:'approved',created_by:'user'},{id:'b',created_at:date,status:'rejected',created_by:'user'},{id:'c',created_at:date,status:'review',created_by:'user'}],evidence:[{created_at:date,result:'pass',created_by:'user'}]};
 const report=buildReport(data,30,now);assert.equal(report.metrics.approvalRate,50);assert.equal(report.metrics.requests,3);assert.equal(report.metrics.approved,1);assert.equal(report.severity.find(x=>x.label==='Alta').count,1);assert.equal(report.pending[0].id,'c');assert.equal(report.collaborators[0].count,5);assert.equal(report.metrics.evidencePassed,1);
 assert.match(reportCSV(report),/Versões criadas/);assert.equal(reportCSV(report).split('\r\n').length,31);
});
test('Notifications: summaries point to the real rule or request and expose no audit detail',()=>{
 const fixture={profiles:[{id:'user',display_name:'João'}],rules:[{id:'rule',name:'Regra de acesso'}],versions:[{id:'version',rule_id:'rule',number:1}],requests:[{id:'request',title:'Ajustar regra'}],events:[{id:1,actor_id:'user',action:'version.created',entity_id:'version',created_at:date,detail:{secret:'never return'}},{id:2,actor_id:'user',action:'request.created',entity_id:'request',created_at:date}]};
 const rows=buildNotifications(fixture);assert.equal(rows[0].title,'João criou uma regra');assert.deepEqual(rows[0].target,{type:'rule',id:'rule'});assert.deepEqual(rows[1].target,{type:'request',id:'request'});assert.equal(JSON.stringify(rows).includes('never return'),false);
});
