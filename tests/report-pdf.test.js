import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {buildReport} from '../src/reporting.mjs';
import {createReportPDF,reportPdfFilename} from '../src/report-pdf.mjs';

const now=new Date('2026-11-06T18:00:00Z'),empty={rules:[],versions:[],requests:[],evidence:[],profiles:[]};
test('PDF: generates a real A4 document with the selected period and daily records',async()=>{
 const report=buildReport(empty,7,now),pdf=await createReportPDF(report,{compress:false});
 const bytes=new Uint8Array(pdf.output('arraybuffer'));assert.equal(Buffer.from(bytes.subarray(0,5)).toString(),'%PDF-');
 assert.ok(pdf.getNumberOfPages()>=2);assert.ok(Math.abs(pdf.internal.pageSize.getWidth()-210)<.1);assert.ok(Math.abs(pdf.internal.pageSize.getHeight()-297)<.1);
 const content=Buffer.from(bytes).toString('latin1');assert.ok(content.includes('HadSec Detect'));assert.ok(content.includes('06/11/2026'));assert.ok(content.includes('31/10/2026'));assert.match(reportPdfFilename(report),/^hadsec-relatorio-.*\.pdf$/);
});
test('PDF: preserves long names, paginates pending requests and includes all 90 days',async()=>{
 const date='2026-11-06T12:00:00Z';const data={...empty,profiles:[{id:'user',display_name:'Analista de Segurança'}],requests:Array.from({length:65},(_,i)=>({id:'q'+i,title:'Revisar a lógica de autenticação e a correlação dos eventos de acesso '+i,status:'review',created_by:'user',created_at:date}))};
 const report=buildReport(data,90,now),logo=new Uint8Array(await readFile(new URL('../public/hadsec-owl-front.png',import.meta.url)));
 const pdf=await createReportPDF(report,{logo,compress:false}),content=Buffer.from(pdf.output('arraybuffer')).toString('latin1');
 assert.ok(pdf.getNumberOfPages()>=6);assert.ok(content.includes('08/09/2026'));assert.ok(content.includes('06/11/2026'));assert.ok(content.includes('64)'));assert.equal(report.pending.length,65);
});
