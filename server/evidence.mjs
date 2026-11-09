export const evidenceBucket='hadsec-evidence';
const mimes={txt:'text/plain',log:'text/plain',csv:'text/csv',json:'application/json',jsonl:'application/json',ndjson:'application/json',pdf:'application/pdf',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg'};
export function evidenceMime(name){if(typeof name!=='string'||name.length>200||/[\x00-\x1f/\\]/.test(name))throw Error('Nome de arquivo inválido.');const ext=name.split('.').at(-1).toLowerCase();if(!mimes[ext])throw Error('Use JSON, CSV, TXT, LOG, PDF, PNG ou JPEG.');return mimes[ext];}
export async function verifyEvidence(bytes,row){
 if(bytes.byteLength!==row.size_bytes||bytes.byteLength>10000000)throw Error('O tamanho recebido não corresponde ao arquivo declarado.');
 const sha=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');if(sha!==row.sha256)throw Error('O hash recebido não corresponde ao arquivo original.');
 const u=new Uint8Array(bytes),starts=values=>values.every((v,i)=>u[i]===v);
 if(row.mime==='image/png'&&!starts([137,80,78,71,13,10,26,10])||row.mime==='image/jpeg'&&!starts([255,216,255])||row.mime==='application/pdf'&&!starts([37,80,68,70,45]))throw Error('O conteúdo não corresponde ao formato do arquivo.');
 if(row.mime.startsWith('text/')||row.mime==='application/json'){try{const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(text.includes('\0'))throw Error();}catch{throw Error('A evidência de texto precisa usar UTF-8 sem bytes nulos.');}}
 return sha;
}
export async function evidenceAction({body,client,admin,user,audit}){
 const check=async p=>{const {data,error}=await p;if(error)throw Error(error.message);return data;};
 if(body.action==='evidence.upload-url'){
  const result=await check(client.rpc('begin_operational_evidence',{p_subject:body.subject_id,p_name:body.name,p_size:body.size,p_mime:evidenceMime(body.name),p_sha256:body.sha256}));
  const row=Array.isArray(result)?result[0]:result;if(!row?.id||!row.storage_path)throw Error('O registro do envio não foi retornado pelo banco.');
  try{const signed=await check(admin.storage.from(evidenceBucket).createSignedUploadUrl(row.storage_path,{upsert:false}));return {id:row.id,path:row.storage_path,token:signed.token,mime:row.mime};}catch(e){await admin.from('operational_evidence').delete().eq('id',row.id).eq('status','pending');throw e;}
 }
 const row=await check(client.from('operational_evidence').select('*').eq('id',body.file_id).maybeSingle());if(!row)throw Error('Evidência indisponível ou sem permissão de acesso.');
 if(body.action==='evidence.finalize'){
  if(row.created_by!==user.id)throw Error('Somente o autor pode finalizar este envio.');if(row.status==='ready')return {ok:true,id:row.id,sha256:row.sha256};
  const allowed=await check(client.rpc('can_write_subject',{p_subject:row.subject_id}));if(!allowed)throw Error('Sem permissão para finalizar este envio.');
  const blob=await check(admin.storage.from(evidenceBucket).download(row.storage_path));const hash=await verifyEvidence(await blob.arrayBuffer(),row);
  await check(admin.rpc('finalize_operational_evidence',{p_file:row.id,p_actor:user.id,p_sha256:hash}));return {ok:true,id:row.id,sha256:hash};
 }
 if(body.action==='evidence.cancel'){
  if(row.created_by!==user.id||row.status!=='pending')throw Error('Apenas envios pendentes do próprio autor podem ser cancelados.');
  await check(admin.storage.from(evidenceBucket).remove([row.storage_path]));await check(admin.from('operational_evidence').delete().eq('id',row.id).eq('status','pending'));await audit('evidence.upload_cancelled',row.id,{subject_id:row.subject_id});return {ok:true};
 }
 if(body.action==='evidence.download'){
  if(row.status!=='ready')throw Error('A integridade do arquivo ainda não foi confirmada.');
  const signed=await check(admin.storage.from(evidenceBucket).createSignedUrl(row.storage_path,60,{download:row.original_name}));await audit('evidence.downloaded',row.id,{subject_id:row.subject_id});return {url:signed.signedUrl,expiresIn:60};
 }
 throw Error('Ação de evidência desconhecida.');
}
