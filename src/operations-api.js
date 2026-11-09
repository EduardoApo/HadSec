import {db,rpc,gateway} from './api';
export const check=({data,error})=>{if(error)throw Error(error.message);return data;};
export async function readAll(table,columns='*',configure=q=>q){
 const keys={attack_rule_links:['technique_id','rule_id'],attack_test_links:['technique_id','evidence_id'],attack_subject_links:['technique_id','subject_id'],atomic_result_evidence:['result_id','evidence_id'],hunting_finding_requests:['finding_id','request_id'],query_favorites:['query_id','user_id'],fp_tuning_requests:['case_id','request_id'],campaign_members:['campaign_id','user_id'],campaign_rule_links:['campaign_id','rule_id']};const order=keys[table]||['id'];
 const rows=[];for(let offset=0;;offset+=1000){let query=configure(db.from(table).select(columns));for(const key of order)query=query.order(key);const page=check(await query.range(offset,offset+999));rows.push(...page);if(page.length<1000)return rows;}
}
export async function loadAttack(){
 const [techniques,tactics,ruleLinks,testLinks,runs,subjects,subjectLinks,atomicRequests,atomicResults,resultEvidence]=await Promise.all([
 readAll('attack_techniques','id,stix_id,name,platforms,tactics,parent_id,revoked,deprecated,active',q=>q.eq('active',true).eq('revoked',false).eq('deprecated',false)),
 readAll('attack_tactics','*',q=>q.eq('active',true)),readAll('attack_rule_links'),readAll('attack_test_links'),
 db.from('attack_sync_runs').select('*').order('started_at',{ascending:false}).limit(30).then(check),readAll('operational_subjects','*',q=>q.eq('archived',false).in('kind',['campaign','hypothesis','validation'])),readAll('attack_subject_links'),
 readAll('atomic_validation_requests','id,technique_id,rule_version_id,environment'),readAll('atomic_execution_results','id,request_id,executed_at,execution,detected,created_at'),readAll('atomic_result_evidence')
 ]);return {techniques,tactics:tactics.sort((a,b)=>a.ordinal-b.ordinal),ruleLinks,testLinks,runs,subjects,subjectLinks,atomicRequests,atomicResults,resultEvidence};
}
export async function attackDetail(id){return check(await db.from('attack_techniques').select('*').eq('id',id).single());}
export const syncAttack=()=>gateway('attack.sync');
export const linkAttackRule=(technique,rule,remove=false)=>rpc('link_attack_rule',{p_technique:technique,p_rule:rule,p_remove:remove});
export const linkAttackTest=(technique,evidence,environment,notes,remove=false)=>rpc('link_attack_test',{p_technique:technique,p_evidence:evidence,p_environment:environment,p_notes:notes,p_remove:remove});
export const linkAttackSubject=(technique,subject,remove=false)=>rpc('link_attack_subject',{p_technique:technique,p_subject:subject,p_remove:remove});
