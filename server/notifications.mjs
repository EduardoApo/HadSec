export const notificationActions=['version.baseline_imported','version.created','version.validated','rule.archived','request.created','request.version_attached','request.approved','request.changes','request.rejected','evidence.recorded','github.pr_created'];

export function buildNotifications({events,profiles,versions,rules,requests}){
 return events.filter(event=>{
  const request=requests.find(q=>q.id===event.entity_id);
  return !request?.deleted_at&&!(event.action==='github.pr_created'&&request?.github_hidden_at);
 }).map(event=>{
  const actor=profiles.find(p=>p.id===event.actor_id)?.display_name||'Sistema';
  const version=versions.find(v=>v.id===event.entity_id);
  const request=requests.find(q=>q.id===event.entity_id);
  const rule=rules.find(r=>r.id===(version?.rule_id||event.entity_id));
  const verbs={'version.baseline_imported':'anexou uma regra original','version.created':version?.number===1?'criou uma regra':'criou uma nova versão','version.validated':'validou uma versão','rule.archived':'excluiu uma regra da lista','request.created':'criou uma solicitação','request.version_attached':'enviou uma versão para revisão','request.approved':'aprovou uma solicitação','request.changes':'solicitou ajustes','request.rejected':'rejeitou uma solicitação','evidence.recorded':'registrou uma evidência','github.pr_created':'enviou uma regra ao GitHub'};
  return {id:String(event.id),action:event.action,title:actor+' '+(verbs[event.action]||'atualizou o sistema'),description:request?.title||(rule?rule.name+(version?' · v'+version.number:''):'Registro indisponível'),createdAt:event.created_at,target:request?{type:'request',id:request.id}:rule?{type:'rule',id:rule.id}:null};
 });
}
