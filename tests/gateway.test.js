import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createGateway} from '../server/gateway.mjs';
import {nodeGateway} from '../api/gateway.js';
import {Readable} from 'node:stream';

const userId='00000000-0000-4000-8000-000000000001',ruleId='00000000-0000-4000-8000-000000000002',versionId='00000000-0000-4000-8000-000000000003',requestId='00000000-0000-4000-8000-000000000004';
function setup({permissions=['rules.write','github.publish'],overrides=[],content='SELECT eventType FROM fsiem.events LIMIT 10',requestStatus,archived=false,mustChange=false,active=true,github=true,fetchImpl}={}){
 const rule={id:ruleId,name:'Regra de teste',format:'sql',mode:'Scheduled via SQL',archived};
 const version={id:versionId,rule_id:ruleId,number:1,content,content_sha256:'version-hash',rules:rule};
 const tables={roles:[{id:'role',permissions}],profiles:[{id:userId,active,must_change_password:mustChange,roles:{permissions}}],user_permission_overrides:overrides.map(o=>({...o,user_id:userId})),rules:[rule],rule_versions:[version],change_requests:requestStatus?[{id:requestId,rule_id:ruleId,version_id:versionId,status:requestStatus,rules:rule,rule_versions:version,reviewed_by:'another-user',review_note:'Aprovada com evidência',github_url:requestStatus==='published'?'https://github.com/example/rules/pull/1':null}]:[],audit_events:[]};
 const calls=[];
 function from(table){
  const filters=[];let mutation=null,values,single=false,limit=Infinity;
  const query={select(){return query;},order(){return query;},eq(key,value){filters.push(row=>row[key]===value);return query;},in(key,values){filters.push(row=>values.includes(row[key]));return query;},or(expression){assert.equal(expression,'status.eq.published,deleted_at.is.null');filters.push(row=>row.status==='published'||!row.deleted_at);return query;},limit(value){limit=value;return query;},maybeSingle(){single=true;return query;},update(value){mutation='update';values=value;return query;},insert(value){mutation='insert';values=value;return query;},then(resolve,reject){return Promise.resolve().then(()=>{calls.push({table,mutation});let rows=tables[table].filter(row=>filters.every(fn=>fn(row))).slice(0,limit);if(mutation==='update')for(const row of rows)Object.assign(row,values);if(mutation==='insert'){tables[table].push(values);rows=[values];}return {data:single?rows[0]||null:rows,error:null};}).then(resolve,reject);}};return query;
 }
 const api={auth:{async getUser(token){calls.push({auth:true});return token==='valid'?{data:{user:{id:userId}},error:null}:{data:{user:null},error:{message:'invalid token'}};}},from,async rpc(name){calls.push({rpc:name});const request=tables.change_requests[0];if(name==='claim_export'&&request?.status!=='approved')return {data:null,error:{message:'Aprovação pendente'}};return {data:null,error:null};}};
 const env={SUPABASE_URL:'https://example.supabase.co',SUPABASE_SERVICE_ROLE_KEY:'server-service-key',SUPABASE_ANON_KEY:'public-key',...(github?{GITHUB_TOKEN:'private-github-token',GITHUB_OWNER:'example',GITHUB_REPO:'rules'}:{})};
 const outbound=[];
 const handle=createGateway({env,clientFactory:()=>api,fetchImpl:async(url,options)=>{outbound.push({url,options});return fetchImpl?fetchImpl(url,options):Response.json({object:{sha:'base-sha'}});}});
 async function request(action,payload={},headers={Authorization:'Bearer valid'},origin='https://had-sec.vercel.app'){const response=await handle(new Request(origin+'/api/gateway',{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify({action,...payload})}));return {status:response.status,body:await response.json()};}
 return {handle,request,tables,calls,outbound,env};
}

test('Gateway: requires a valid session, active account and current permissions',async()=>{
 const anon=setup();assert.equal((await anon.request('validate',{version_id:versionId},{})).status,401);assert.equal(anon.calls.length,0);
 assert.equal((await setup().request('validate',{version_id:versionId},{Authorization:'Bearer invalid'})).status,401);
 for(const options of [{active:false},{mustChange:true},{permissions:[]},{overrides:[{permission:'rules.write',granted:false}]}]){const f=setup(options);assert.equal((await f.request('validate',{version_id:versionId})).status,403);assert.equal(f.tables.audit_events.length,0);assert.equal(f.tables.rule_versions[0].validated,undefined);}
 const granted=setup({permissions:[],overrides:[{permission:'rules.write',granted:true}]});assert.equal((await granted.request('validate',{version_id:versionId})).status,200);
});
test('Gateway: connection status probes the caller database access and GitHub branch',async()=>{
 const f=setup();const r=await f.request('connections.status');assert.equal(r.status,200);assert.equal(r.body.services.database.state,'online');assert.equal(r.body.services.github.state,'online');assert.ok(r.body.checkedAt);assert.ok(f.calls.some(call=>call.table==='roles'));assert.equal(JSON.stringify(r.body).includes('private-github-token'),false);
 f.tables.roles=null;const failed=await f.request('connections.status');assert.equal(failed.status,200);assert.equal(failed.body.services.database.state,'offline');assert.equal(failed.body.supabase,false);
 const unconfigured=await setup({github:false}).request('connections.status');assert.equal(unconfigured.body.services.github.state,'not_configured');assert.equal(unconfigured.body.github,false);
});
test('Gateway: general notifications expose allowed summaries without granting audit access',async()=>{
 const f=setup({permissions:[],requestStatus:'requested'});f.tables.profiles[0].display_name='Analista';f.tables.change_requests[0].title='Solicitação de ajuste';
 f.tables.audit_events.push({id:1,action:'version.created',actor_id:userId,entity_id:versionId,created_at:'2026-11-06T12:00:00Z',detail:{private:'not returned'}},{id:2,action:'request.created',actor_id:userId,entity_id:requestId,created_at:'2026-11-06T12:01:00Z'},{id:3,action:'user.created',actor_id:userId,entity_id:userId,detail:{private:'not returned'}});
 const r=await f.request('notifications.list');assert.equal(r.status,200);assert.equal(r.body.items.length,2);assert.equal(r.body.items[0].target.type,'rule');assert.equal(r.body.items[1].target.type,'request');assert.equal(JSON.stringify(r.body).includes('not returned'),false);
});
test('Gateway: validates persisted content and records the report and responsible user',async()=>{
 const f=setup({content:'DROP TABLE fsiem.events'});
 const r=await f.request('validate',{version_id:versionId,content:'SELECT eventType FROM fsiem.events',report:{ok:true}});
 assert.equal(r.status,200);assert.equal(r.body.ok,false);assert.ok(r.body.errors.length>0);
 assert.equal(f.tables.rule_versions[0].validated,false);assert.deepEqual(f.tables.rule_versions[0].validation_report,r.body);
 assert.equal(f.tables.audit_events[0].actor_id,userId);assert.equal(f.tables.audit_events[0].action,'version.validated');
 assert.equal((await setup({archived:true}).request('validate',{version_id:versionId})).status,404);
});
test('Gateway: rule exclusion preserves versions and requires confirmation',async()=>{
 const f=setup();assert.equal((await f.request('rule.archive',{rule_id:ruleId,confirmation:'wrong'})).status,400);assert.equal(f.tables.rules[0].archived,false);
 const r=await f.request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'});assert.equal(r.status,200);assert.equal(f.tables.rules[0].archived,true);assert.equal(f.tables.rule_versions.length,1);assert.equal(f.tables.audit_events[0].action,'rule.archived');
 assert.equal((await f.request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'})).status,200);
 for(const requestStatus of ['requested','review','changes','approved','published']){const blocked=setup({requestStatus});assert.equal((await blocked.request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'})).status,409);assert.equal(blocked.tables.rules[0].archived,false);}
 assert.equal((await setup({permissions:[]}).request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'})).status,403);
});
test('Gateway: GitHub status checks real access without exposing credentials',async()=>{
 const f=setup();const r=await f.request('github.status');assert.equal(r.body.connected,true);assert.ok(f.outbound[0].url.endsWith('/git/ref/heads/main'));assert.equal(f.outbound[0].options.headers.Authorization,'Bearer private-github-token');assert.equal(JSON.stringify(r.body).includes('private-github-token'),false);
 const pending=setup({github:false});assert.equal((await pending.request('github.status')).body.configured,false);assert.equal(pending.outbound.length,0);
 const unavailable=setup({fetchImpl:async()=>Response.json({message:'Not Found'},{status:404})});const status=await unavailable.request('github.status');assert.equal(status.status,200);assert.equal(status.body.connected,false);assert.ok(status.body.error);
 assert.equal((await setup({permissions:[]}).request('github.status')).status,403);
});

test('Gateway: deleted requests cannot publish; deleted unpublished reviews release rule exclusion',async()=>{
 for(const requestStatus of ['approved','published']){
  const f=setup({requestStatus});Object.assign(f.tables.change_requests[0],{deleted_at:'2026-11-06T12:00:00Z',github_hidden_at:'2026-11-06T12:00:00Z'});
  assert.equal((await f.request('github.publish',{request_id:requestId,status:'approved',deleted_at:null})).status,404);assert.equal(f.outbound.length,0);assert.equal(f.calls.some(call=>call.rpc==='claim_export'),false);
 }
 for(const requestStatus of ['requested','review','changes','approved']){
  const f=setup({requestStatus});f.tables.change_requests[0].deleted_at='2026-11-06T12:00:00Z';
  assert.equal((await f.request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'})).status,200);
 }
 const published=setup({requestStatus:'published'});published.tables.change_requests[0].deleted_at='2026-11-06T12:00:00Z';
 assert.equal((await published.request('rule.archive',{rule_id:ruleId,confirmation:'Regra de teste'})).status,409);
 const notifications=setup({requestStatus:'published'});Object.assign(notifications.tables.change_requests[0],{deleted_at:'2026-11-06T12:00:00Z'});notifications.tables.audit_events.push({id:1,action:'request.created',entity_id:requestId},{id:2,action:'github.pr_created',entity_id:requestId});assert.deepEqual((await notifications.request('notifications.list')).body.items,[]);
});
test('Gateway: export requires the database approval before any GitHub operation',async()=>{
 const f=setup({requestStatus:'review'});const r=await f.request('github.publish',{request_id:requestId,status:'approved'});assert.equal(r.status,400);assert.equal(f.outbound.length,0);assert.equal(f.tables.change_requests[0].status,'review');
 const published=setup({requestStatus:'published'});assert.equal((await published.request('github.publish',{request_id:requestId})).body.url,'https://github.com/example/rules/pull/1');assert.equal(published.outbound.length,0);
});
test('Gateway: approved export publishes persisted content and records the pull request',async()=>{
 const f=setup({requestStatus:'approved',fetchImpl:async(url,options)=>{
  if(url.includes('/git/ref/heads/main'))return Response.json({object:{sha:'base-sha'}});
  if(url.includes('/git/ref/heads/hadsec'))return Response.json({message:'Not Found'},{status:404});
  if(url.endsWith('/git/refs'))return Response.json({ref:'created'});
  if(url.includes('/contents/')&&options.method==='GET')return Response.json({message:'Not Found'},{status:404});
  if(url.includes('/contents/')&&options.method==='PUT')return Response.json({content:{sha:'new-sha'}});
  if(url.includes('/pulls?'))return Response.json([]);
  if(url.endsWith('/pulls')&&options.method==='POST')return Response.json({html_url:'https://github.com/example/rules/pull/2'});
  throw Error('Unexpected GitHub endpoint');
 }});
 const r=await f.request('github.publish',{request_id:requestId,content:'untrusted'});assert.equal(r.status,200);assert.equal(r.body.url,'https://github.com/example/rules/pull/2');
 const uploaded=JSON.parse(f.outbound.find(x=>x.options.method==='PUT').options.body);assert.equal(atob(uploaded.content),f.tables.rule_versions[0].content);assert.equal(f.tables.change_requests[0].status,'published');assert.equal(f.tables.audit_events[0].action,'github.pr_created');
});
test('Gateway: rejects unexpected origins, malformed JSON and missing server secrets',async()=>{
 const f=setup();const blocked=await f.handle(new Request('https://had-sec.vercel.app/api/gateway',{method:'POST',headers:{Origin:'https://other.example'},body:'{}'}));assert.equal(blocked.status,403);
 const malformed=await f.handle(new Request('https://had-sec.vercel.app/api/gateway',{method:'POST',headers:{Authorization:'Bearer valid'},body:'invalid'}));assert.equal(malformed.status,400);
 const pending=createGateway();const response=await pending(new Request('https://had-sec.vercel.app/api/gateway',{method:'POST',headers:{Authorization:'Bearer valid'},body:'{}'}));assert.equal(response.status,503);assert.equal((await response.json()).code,'SERVER_NOT_CONFIGURED');
 const preflight=await f.handle(new Request('https://had-sec.vercel.app/api/gateway',{method:'OPTIONS',headers:{Origin:'https://had-sec.vercel.app'}}));assert.equal(preflight.status,204);assert.equal(preflight.headers.get('Access-Control-Allow-Origin'),'https://had-sec.vercel.app');
});
test('Node adapter: local preview and Vercel return JSON errors without exposing secrets',async()=>{
 for(const [body,authorization,expected]of [['{}',undefined,401],['invalid','Bearer valid',400],['{}','Bearer valid',503],[JSON.stringify({text:'é'.repeat(310000)}),'Bearer valid',413]]){
  const req=Readable.from([body]);req.method='POST';req.url='/api/gateway';req.headers={host:'localhost:5173',...(authorization?{authorization}:{})};
  let status,headers,result;const res={writeHead(s,h){status=s;headers=h;},end(text){result=text;}};
  await nodeGateway({})(req,res);assert.equal(status,expected);assert.match(headers['content-type']||headers['Content-Type'],/^application\/json/);assert.ok(JSON.parse(result).error);
 }
});
