import {readFile,readdir} from 'node:fs/promises';
import pg from 'pg';
const action=process.argv[2]||'inspect';
const token=process.env.SUPABASE_ACCESS_TOKEN;
const ref=new URL(process.env.SUPABASE_URL).hostname.split('.')[0];
async function management(path,method='GET',body){
 if(!token)throw new Error('SUPABASE_ACCESS_TOKEN ausente no .env');
 const r=await fetch(`https://api.supabase.com/v1/projects/${ref}${path}`,{method,headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
 const data=await r.json();if(!r.ok)throw new Error(`Supabase Management ${r.status}: ${data.message||data.error||'erro'}`);return data;
}
async function query(sql,params=[]){
 if(token&&!params.length){const r=await management('/database/query','POST',{query:sql});return {rows:r};}
 const ca=await readFile(new URL('../certs/supabase-root.crt',import.meta.url),'utf8');
 const client=new pg.Client({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:true,ca},connectionTimeoutMillis:15000});
 try{await client.connect();return await client.query(sql,params);}finally{await client.end();}
}
if(action==='inspect'){
 console.log(JSON.stringify({accessTokenConfigured:!!token,databaseConfigured:!!process.env.DATABASE_URL}));
 const r=await query("select current_database() as database, to_regclass('public.profiles')::text as profiles, to_regclass('public.rules')::text as rules, to_regclass('public.hadsec_schema_migrations')::text as migrations");
 console.log(JSON.stringify(r.rows));
}else if(action==='migrate'){
 const {rows:[state]}=await query("select to_regclass('public.profiles')::text as profiles,to_regclass('public.hadsec_schema_migrations')::text as migrations");
 if(state.profiles&&!state.migrations)throw new Error('O projeto já contém profiles. Use um projeto dedicado ou revise a migração para evitar conflito.');
 await query('create table if not exists public.hadsec_schema_migrations(version text primary key, applied_at timestamptz default now());revoke all on public.hadsec_schema_migrations from anon,authenticated;');
 const files=(await readdir(new URL('../supabase/migrations/',import.meta.url))).filter(f=>/^\d+_.+\.sql$/.test(f)).sort();
 for(const file of files){const version=file.split('_')[0];const applied=await query(`select version from public.hadsec_schema_migrations where version='${version}'`);
 if(applied.rows.length){console.log(`Migração ${version} já aplicada.`);continue;}
 const sql=await readFile(new URL(`../supabase/migrations/${file}`,import.meta.url),'utf8');await query(sql.replace(/commit;\s*$/i,`insert into public.hadsec_schema_migrations(version) values('${version}');commit;`));console.log(`Migração ${version} aplicada.`);}
}else if(action==='configure'){
 const keys=await management('/api-keys');
 const service=keys.find(k=>k.name==='service_role')?.api_key;
 if(!service)throw new Error('Service role key não retornada pela API de gerenciamento.');
 // Write only to ignored .env. Never print keys.
 const {writeFile}=await import('node:fs/promises');const path=new URL('../.env',import.meta.url);let contents=await readFile(path,'utf8');
 contents=contents.replace(/^SUPABASE_SERVICE_ROLE_KEY=.*$/m,`SUPABASE_SERVICE_ROLE_KEY=${service}`);await writeFile(path,contents);
 console.log('Chave de serviço configurada no .env ignorado.');
}else if(action==='deploy'){
 // Management API supports multipart function deployments. Bundle the shared validator using esbuild first.
 const {bundleGateway}=await import('./bundle-gateway.mjs');const code=await bundleGateway();
 const form=new FormData();form.set('metadata',JSON.stringify({name:'gateway',entrypoint_path:'index.ts',verify_jwt:false}));form.set('file',new Blob([code],{type:'application/typescript'}),'index.ts');
 const response=await fetch(`https://api.supabase.com/v1/projects/${ref}/functions/deploy?slug=gateway`,{method:'POST',headers:{Authorization:`Bearer ${token}`},body:form});
 if(!response.ok)throw new Error(`Falha ao publicar função: ${response.status} ${await response.text()}`);
 console.log(JSON.stringify({deployed:true,name:'gateway'}));
 const secrets=['APP_ORIGIN','GITHUB_TOKEN','GITHUB_OWNER','GITHUB_REPO','GITHUB_BASE_BRANCH'].filter(k=>process.env[k]).map(name=>({name,value:process.env[name]}));
 await management('/secrets','POST',secrets);console.log('Secrets de execução configurados.');
}else throw new Error('Ação desconhecida');
