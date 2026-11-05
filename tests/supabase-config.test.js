import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readSupabaseConfig} from '../src/supabase-config.mjs';

const env={VITE_SUPABASE_URL:'https://example.supabase.co',VITE_SUPABASE_ANON_KEY:'sb_publishable_example'};
const jwt=role=>`eyJhbGciOiJIUzI1NiJ9.${btoa(JSON.stringify({role})).replace(/=/g,'')}.signature`;

test('Supabase: deployment without public configuration keeps authentication unavailable',()=>{
 assert.equal(readSupabaseConfig({}).configured,false);
 assert.equal(readSupabaseConfig({SUPABASE_URL:env.VITE_SUPABASE_URL,SUPABASE_SERVICE_ROLE_KEY:jwt('service_role')}).configured,false);
 assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_ANON_KEY:'   '}).configured,false);
});
test('Supabase: accepts publishable alias and legacy anon keys',()=>{
 const config=readSupabaseConfig({VITE_SUPABASE_URL:` ${env.VITE_SUPABASE_URL}/ `,VITE_SUPABASE_ANON_KEY:' ',VITE_SUPABASE_PUBLISHABLE_KEY:env.VITE_SUPABASE_ANON_KEY});
 assert.equal(config.configured,true);assert.equal(config.url,env.VITE_SUPABASE_URL);assert.equal(config.key,env.VITE_SUPABASE_ANON_KEY);
 assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_ANON_KEY:jwt('anon')}).configured,true);
 assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_PUBLISHABLE_KEY:'sb_publishable_other'}).key,env.VITE_SUPABASE_ANON_KEY);
});
test('Supabase: rejects private credentials and incorrect endpoints',()=>{
 for(const key of [jwt('service_role'),'sb_secret_example','not-a-key'])assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_ANON_KEY:key}).configured,false);
 for(const url of ['not-a-url','http://example.supabase.co','https://user:password@example.supabase.co','https://example.supabase.co/rest/v1'])assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_URL:url}).configured,false);
 assert.equal(readSupabaseConfig({...env,VITE_SUPABASE_URL:'http://127.0.0.1:54321'}).configured,true);
});
