import { defineConfig,loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import {readSupabaseConfig} from './src/supabase-config.mjs';
import {nodeGateway} from './api/gateway.js';
export default defineConfig(({command,mode})=>{
 if(command==='build'&&process.env.VERCEL==='1'){
  const {problems}=readSupabaseConfig(loadEnv(mode,process.cwd(),'VITE_'));
  if(problems.length)throw new Error(`Configuração Supabase ausente ou inválida. ${problems.join(' ')} No Vercel, configure em Settings → Environment Variables para este ambiente e faça Redeploy.`);
 }
 const runtimeEnv={...loadEnv(mode,process.cwd(),''),...process.env};
 const localApi={name:'hadsec-local-api',configureServer(server){server.middlewares.use('/api/gateway',nodeGateway(runtimeEnv));},configurePreviewServer(server){server.middlewares.use('/api/gateway',nodeGateway(runtimeEnv));}};
 return {plugins:[react(),localApi],optimizeDeps:{include:['jspdf']},build:{target:'es2022',sourcemap:false,rollupOptions:{output:{manualChunks:{react:['react','react-dom'],supabase:['@supabase/supabase-js'],xml:['fast-xml-parser']}}}}};
});
