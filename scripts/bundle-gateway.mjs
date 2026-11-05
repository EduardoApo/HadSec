import {build} from 'esbuild';
import {readFile} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';
import path from 'node:path';
export async function bundleGateway(){
 const result=await build({entryPoints:[fileURLToPath(new URL('../supabase/functions/gateway/index.ts',import.meta.url))],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],target:'es2022',external:['@supabase/supabase-js'],packages:'bundle'});
 const imports=JSON.parse(await readFile(new URL('../supabase/functions/gateway/deno.json',import.meta.url),'utf8')).imports;
 const code=result.outputFiles[0].text.replace('from "@supabase/supabase-js"',`from "${imports['@supabase/supabase-js']}"`);
 if(!code.includes(`from "${imports['@supabase/supabase-js']}"`))throw new Error('Import do SDK Supabase não foi preparado para Deno');
 return code;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){const code=await bundleGateway();console.log(`Gateway compilado: ${new TextEncoder().encode(code).length} bytes.`);}
