// Only callers with fixed official source URLs use this helper. Never forward private repository tokens.
export async function fetchSource(url,{fetchImpl=fetch,maxBytes=100000000,asJson=true}={}){
 const response=await fetchImpl(url,{headers:{Accept:'application/json','User-Agent':'HadSec-Detect-Catalogs'},redirect:'error',signal:AbortSignal.timeout(90000)});
 if(!response.ok)throw Error('A fonte oficial respondeu HTTP '+response.status+'.');
 if(Number(response.headers.get('content-length')||0)>maxBytes)throw Error('A fonte oficial excedeu o limite de tamanho.');
 const reader=response.body?.getReader();if(!reader)throw Error('A fonte oficial retornou uma resposta vazia.');
 const chunks=[];let total=0;
 for(;;){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>maxBytes){await reader.cancel();throw Error('A fonte oficial excedeu o limite de tamanho.');}chunks.push(value);}
 const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const sha256=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
 if(!asJson)return {text,sha256,bytes:total};
 let data;try{data=JSON.parse(text);}catch{throw Error('JSON inválido retornado pela fonte oficial.');}return {data,sha256,bytes:total};
}
export async function officialCommit(repo,branch,fetchImpl=fetch){
 const {data}=await fetchSource('https://api.github.com/repos/'+repo+'/commits/'+branch,{fetchImpl,maxBytes:2000000});
 if(!/^[a-f0-9]{40}$/.test(data.sha))throw Error('Commit da fonte oficial inválido.');return data.sha;
}
