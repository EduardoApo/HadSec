import {spawnSync} from 'node:child_process';
import {readFile,writeFile} from 'node:fs/promises';
const file=new URL('../.env',import.meta.url);
let token=process.env.GITHUB_TOKEN;
if(!token){
 const result=spawnSync('git',['-c','credential.interactive=never','credential','fill'],{input:'protocol=https\nhost=github.com\n\n',encoding:'utf8',env:{...process.env,GIT_TERMINAL_PROMPT:'0',GCM_INTERACTIVE:'Never'},windowsHide:true,timeout:20000});
 const lines=(result.stdout||'').split(/\r?\n/);token=lines.find(s=>s.startsWith('password='))?.slice(9);
 if(!token){console.log('Nenhuma credencial GitHub autenticada disponível no ambiente local.');process.exit(2);}
}
const api=async(path,method='GET',body)=>{
 const r=await fetch(`https://api.github.com${path}`,{method,headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
 const data=await r.json();if(!r.ok){const e=new Error(`GitHub ${r.status}: ${data.message}`);e.status=r.status;throw e;}return data;
};
const user=await api('/user');
if(process.argv.includes('--inspect')){console.log(JSON.stringify({authenticated:true,account:user.login}));process.exit(0);}
const owner=process.env.GITHUB_OWNER||user.login;const name=process.env.GITHUB_REPO||'hadsec-detect-rules';let repo;
try{repo=await api(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`);}catch(e){if(e.status!==404)throw e;if(owner!==user.login)throw new Error('Configure um repositório existente ou um owner correspondente à conta autenticada.');repo=await api('/user/repos','POST',{name,private:true,auto_init:true,description:'Regras FortiSIEM 7.5.1.0620 revisadas no HadSec Detect'});}
if(!repo.permissions?.push)throw new Error('A conta autenticada não tem permissão de escrita no repositório.');
let content=await readFile(file,'utf8');for(const [k,v] of Object.entries({GITHUB_TOKEN:token,GITHUB_OWNER:owner,GITHUB_REPO:name,GITHUB_BASE_BRANCH:repo.default_branch})){
 const regex=new RegExp(`^${k}=.*$`,'m');content=regex.test(content)?content.replace(regex,()=>`${k}=${v}`):content+`\n${k}=${v}`;
}await writeFile(file,content);
console.log(JSON.stringify({configured:true,repository:repo.full_name,private:repo.private,url:repo.html_url,branch:repo.default_branch}));
