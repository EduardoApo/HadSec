import {test} from 'node:test';
import assert from 'node:assert/strict';
import {filterAuditEvents,auditEntityLabel} from '../src/audit-search.mjs';

test('Audit search combines responsible user, action, full record and localized date',()=>{
 const data={profiles:[{id:'user-1',display_name:'João Apolinário',username:'hadsec'}],rules:[{id:'rule-1',name:'Falhas de autenticação'}],versions:[{id:'version-full-uuid',rule_id:'rule-1',number:2}],requests:[]};
 const events=[{id:1,actor_id:'user-1',action:'version.validated',entity_id:'version-full-uuid',created_at:'2026-11-06T15:30:00Z'}];
 for(const query of ['joao','apolinario','hadsec','validou uma versao','version.validated','version-full-uuid','autenticacao','06/11/2026','2026-11-06','joao validou 2026-11-06'])assert.equal(filterAuditEvents(events,query,data).length,1,query);
 assert.equal(filterAuditEvents(events,'outro usuario',data).length,0);assert.equal(auditEntityLabel(events[0],data),'Falhas de autenticação · v2');
});
