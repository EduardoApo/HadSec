import { defineConfig,loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import {readSupabaseConfig} from './src/supabase-config.mjs';
export default defineConfig(({command,mode})=>{
 if(command==='build'&&process.env.VERCEL==='1'){
  const {problems}=readSupabaseConfig(loadEnv(mode,process.cwd(),'VITE_'));
  if(problems.length)throw new Error(`Configuração Supabase ausente ou inválida. ${problems.join(' ')} No Vercel, configure em Settings → Environment Variables para este ambiente e faça Redeploy.`);
 }
 return {plugins:[react()],build:{target:'es2022',sourcemap:false,rollupOptions:{output:{manualChunks:{react:['react','react-dom'],supabase:['@supabase/supabase-js'],xml:['fast-xml-parser']}}}}};
});
