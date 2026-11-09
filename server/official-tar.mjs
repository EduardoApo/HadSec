// Read selected regular text entries from an official tar.gz stream. Nothing is extracted to disk.
export async function* officialTar(url,accept,{fetchImpl=fetch,maxExpanded=180000000,maxEntry=500000}={}){
 const r=await fetchImpl(url,{redirect:'error',signal:AbortSignal.timeout(120000),headers:{'User-Agent':'HadSec-Detect-Catalogs'}});
 if(!r.ok)throw Error('Arquivo oficial respondeu HTTP '+r.status+'.');if(!r.body)throw Error('Arquivo oficial vazio.');
 const reader=r.body.pipeThrough(new DecompressionStream('gzip')).getReader(),decoder=new TextDecoder('utf-8',{fatal:true});let buffer=new Uint8Array(),total=0,remaining=0,padding=0,current=null,ended=false;
 const str=bytes=>decoder.decode(bytes).replace(/\0.*$/s,'');
 try{for(;;){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>maxExpanded)throw Error('O catálogo expandido excede o limite.');const joined=new Uint8Array(buffer.length+value.length);joined.set(buffer);joined.set(value,buffer.length);buffer=joined;
  for(;;){
   if(remaining){const take=Math.min(remaining,buffer.length);if(current)current.parts.push(buffer.slice(0,take));buffer=buffer.slice(take);remaining-=take;if(remaining)break;if(current){const bytes=new Uint8Array(current.size);let at=0;for(const part of current.parts){bytes.set(part,at);at+=part.length;}yield {path:current.path,text:decoder.decode(bytes)};current=null;}}
   if(padding){const take=Math.min(padding,buffer.length);buffer=buffer.slice(take);padding-=take;if(padding)break;}
   if(buffer.length<512)break;
   const header=buffer.slice(0,512);buffer=buffer.slice(512);if(header.every(b=>b===0)){ended=true;return;}
   const octal=field=>{const text=str(field).trim();if(!/^[0-7]*$/.test(text))throw Error('Cabeçalho TAR inválido.');return parseInt(text||'0',8);};
   const sum=header.reduce((n,b,i)=>n+(i>=148&&i<156?32:b),0);if(sum!==octal(header.slice(148,156)))throw Error('Checksum TAR inválido.');
   const name=str(header.slice(0,100)),prefix=str(header.slice(345,500));const full=(prefix?prefix+'/':'')+name;const path=full.split('/').slice(1).join('/');
   remaining=octal(header.slice(124,136));if(!Number.isSafeInteger(remaining)||remaining>maxExpanded)throw Error('Tamanho TAR inválido.');padding=(512-remaining%512)%512;
   if((header[156]===0||header[156]===48)&&accept(path)){
    if(path.split('/').some(p=>p==='..')||path.startsWith('/')||path.includes('\\')||remaining>maxEntry)throw Error('Entrada de catálogo inválida ou excessiva.');
    current={path,size:remaining,parts:[]};if(!remaining){yield {path,text:''};current=null;}
   }
  }
 }if(!ended)throw Error('Arquivo TAR incompleto.');}finally{await reader.cancel().catch(()=>{});}
}
