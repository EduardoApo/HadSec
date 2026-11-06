const labels={'request.deleted':'excluiu uma solicitação','github.submission_hidden':'excluiu um envio da lista','version.created':'criou uma versão','version.validated':'validou uma versão','rule.archived':'excluiu uma regra da lista','request.created':'abriu uma solicitação','request.approved':'aprovou uma revisão','request.changes':'solicitou ajustes','request.rejected':'rejeitou uma revisão','evidence.recorded':'registrou uma evidência','github.pr_created':'enviou uma versão ao GitHub','github.export_started':'iniciou envio ao GitHub','user.created':'criou uma conta','user.updated':'alterou acessos','user.deleted':'excluiu uma conta','permissions.user_updated':'alterou permissões individuais','permissions.labels_updated':'renomeou permissões','role.saved':'salvou um perfil','password.changed':'alterou a senha','comment.created':'adicionou um comentário','request.version_attached':'vinculou uma versão','set_user_permissions':'alterou permissões individuais','save_permission_labels':'renomeou permissões','save_rule':'criou uma versão','create_request':'abriu uma solicitação','decide_request':'revisou uma solicitação','record_evidence':'registrou uma evidência','add_comment':'comentou uma solicitação','save_role':'salvou um perfil'};
export const actionLabel=action=>labels[action]||action;
const normalize=value=>String(value||'').normalize('NFD').replace(/\p{Diacritic}/gu,'').toLowerCase();
export function auditEntityLabel(event,data){
 const id=event.entity_id;
 const version=data.versions.find(v=>v.id===id);
 if(version)return `${data.rules.find(r=>r.id===version.rule_id)?.name||'Regra'} · v${version.number}`;
 return data.rules.find(r=>r.id===id)?.name||data.requests.find(q=>q.id===id)?.title||data.profiles.find(p=>p.id===id)?.display_name||id||'—';
}
export function filterAuditEvents(events,query,data){
 const terms=normalize(query).trim().split(/\s+/).filter(Boolean);
 return events.filter(event=>{
  const actor=data.profiles.find(p=>p.id===event.actor_id);
  const date=new Date(event.created_at);
  const text=normalize([actor?.display_name,actor?.username,event.actor_id,event.action,actionLabel(event.action),event.entity_id,auditEntityLabel(event,data),date.toLocaleString('pt-BR'),date.toLocaleDateString('pt-BR',{dateStyle:'long'}),event.created_at].join(' '));
  return terms.every(term=>text.includes(term));
 }).sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
}
