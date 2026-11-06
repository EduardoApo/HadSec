export const requestVisible=request=>!request.deleted_at;
export const submissionVisible=request=>request.status==='published'&&!request.deleted_at&&!request.github_hidden_at;
// Keep a published version protected even after its record is removed from the lists.
export const versionRequestActive=request=>request.status==='published'||(!request.deleted_at&&['review','approved'].includes(request.status));
