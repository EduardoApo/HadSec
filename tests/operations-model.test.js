import test from 'node:test';
import assert from 'node:assert/strict';
import {internalTechniqueReferences,buildOperationsOverview,resolveWorkspacePage,operationModules} from '../src/operations-model.mjs';

test('New navigation preserves legacy deep links and safely defaults to Dashboard',()=>{
 assert.equal(resolveWorkspacePage(''),'dashboard');assert.equal(resolveWorkspacePage('#unknown'),'dashboard');
 for(const route of ['overview','requests','rules','lab','github','reports','coverage','investigations','campaigns','false-positives','query-library'])assert.equal(resolveWorkspacePage('#'+route),route);
 assert.deepEqual(operationModules.map(m=>m.id),['coverage','investigations','campaigns','false-positives','query-library']);
});
test('Internal mappings deduplicate IDs and rules, exclude archived rules and never infer validated coverage',()=>{
 const refs=internalTechniqueReferences([{id:'a',technique:'T1059.001, t1059.001; T1059'},{id:'b',technique:'T1059.001'},{id:'c',archived:true,technique:'T1003'},{id:'d',technique:'No technique'}]);
 assert.deepEqual(refs.map(r=>r.id),['T1059','T1059.001']);assert.deepEqual(refs[1].rules.map(r=>r.id),['a','b']);assert.ok(refs.every(r=>r.coverage==='unknown'));
});
test('Consolidated Dashboard counts active rules and visible requests without treating evidence as validated coverage',()=>{
 const overview=buildOperationsOverview({rules:[{id:'a',technique:'T1059'},{id:'b',archived:true}],versions:[{id:'v1',rule_id:'a'},{id:'v2',rule_id:'b'}],requests:[{id:'new',status:'requested',created_at:'2026-11-09'},{id:'old',status:'review',created_at:'2026-11-08'},{id:'deleted',status:'review',deleted_at:'2026-11-09'},{id:'approved',status:'approved'},{id:'sent',status:'published'},{id:'hidden',status:'published',github_hidden_at:'2026-11-09'}],evidence:[{result:'pass'}]});
 assert.equal(overview.rules,1);assert.equal(overview.versions,1);assert.equal(overview.pending,2);assert.equal(overview.approved,1);assert.equal(overview.sent,1);assert.equal(overview.techniques,1);assert.deepEqual(overview.queue.map(r=>r.id),['old','new']);assert.equal(overview.validatedCoverage,undefined);
});
