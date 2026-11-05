// Only public browser configuration belongs here. Service credentials stay on the server.
export function readSupabaseConfig(env={}) {
 const url=String(env.VITE_SUPABASE_URL||'').trim().replace(/\/+$/,'');
 const key=String(env.VITE_SUPABASE_ANON_KEY||'').trim()||String(env.VITE_SUPABASE_PUBLISHABLE_KEY||'').trim();
 const problems=[];
 if(!url)problems.push('Defina VITE_SUPABASE_URL.');
 else {
  try {
   const parsed=new URL(url);
   const local=['localhost','127.0.0.1','[::1]'].includes(parsed.hostname);
   if((parsed.protocol!=='https:'&&!(local&&parsed.protocol==='http:'))||parsed.username||parsed.password||parsed.pathname!=='/'||parsed.search||parsed.hash)throw new Error();
  } catch {problems.push('VITE_SUPABASE_URL deve ser a URL raiz do projeto Supabase.');}
 }
 if(!key)problems.push('Defina VITE_SUPABASE_ANON_KEY ou VITE_SUPABASE_PUBLISHABLE_KEY com a chave pública.');
 else if(!/^sb_publishable_[A-Za-z0-9_-]+$/.test(key)) {
  try {
   const payload=JSON.parse(atob(key.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
   if(key.split('.').length!==3||payload.role!=='anon')throw new Error();
  } catch {problems.push('Use somente uma chave publishable ou anon. Credenciais secretas não podem ir para o navegador.');}
 }
 return {url,key,configured:problems.length===0,problems};
}
