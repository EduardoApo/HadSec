import {createGateway} from '../server/gateway.mjs';

// Node adapter used by Vercel Functions and the local Vite preview middleware.
export function nodeGateway(env=process.env){
 const handler=createGateway({env});
 return async(req,res)=>{
  try{
   const headers=new Headers();
   for(const [key,value]of Object.entries(req.headers||{}))if(value)headers.set(key,Array.isArray(value)?value.join(','):value);
   let body;
   if(!['GET','HEAD'].includes(req.method)){
    if(req.body!==undefined)body=typeof req.body==='string'?req.body:JSON.stringify(req.body);
    else{const chunks=[];let size=0;for await(const chunk of req){size+=Buffer.byteLength(chunk);if(size>600000){res.writeHead(413,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:'O envio excede 600 KB.'}));return;}chunks.push(Buffer.from(chunk));}body=Buffer.concat(chunks).toString('utf8');}
   }
   const protocol=req.headers['x-forwarded-proto']||'http';
   const host=req.headers.host||'localhost';
   const request=new Request(`${protocol}://${host}${req.url}`,{method:req.method,headers,...(body!==undefined?{body}:{})});
   const response=await handler(request);
   res.writeHead(response.status,Object.fromEntries(response.headers));
   res.end(await response.text());
  }catch{res.writeHead(500,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:'O serviço não conseguiu processar a requisição.'}));}
 };
}
export default nodeGateway();
