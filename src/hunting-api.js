import {db,rpc} from './api';import {check,readAll} from './operations-api';
export async function loadHunting(){
 const [hypotheses,campaigns,techniques,links,events,findings]=await Promise.all([
 readAll('hunting_hypotheses','*,operational_subjects!hunting_hypotheses_id_fkey(*)'),
 readAll('operational_subjects','id,title,status',q=>q.eq('kind','campaign').eq('archived',false)),
 readAll('attack_techniques','id,name,parent_id',q=>q.eq('active',true).eq('revoked',false).eq('deprecated',false)),
 readAll('attack_subject_links','*',q=>q.eq('subject_kind','hypothesis')),
 rpc('search_hunting_events',{p_limit:1}),db.from('hunting_findings').select('id',{head:true,count:'exact'})
 ]);if(findings.error)throw Error(findings.error.message);return {hypotheses:hypotheses.filter(h=>h.operational_subjects&&!h.operational_subjects.archived),campaigns,techniques,links,eventCount:events.total,missingDates:events.missingDates,findingCount:findings.count};
}
export async function loadHuntingCase(id){
 const [findings,requestLinks,files,imports,eventSummary]=await Promise.all([
 db.from('hunting_findings').select('*').eq('hypothesis_id',id).order('created_at').then(check),
 readAll('hunting_finding_requests','*,change_requests(id,title,status,deleted_at)'),db.from('operational_evidence').select('*').eq('subject_id',id).eq('status','ready').order('created_at').then(check),
 db.from('hunting_imports').select('*').eq('hypothesis_id',id).order('created_at',{ascending:false}).then(check),
 rpc('search_hunting_events',{p_hypothesis:id,p_limit:100})
 ]);return {findings,requestLinks,files,imports,events:eventSummary};
}
