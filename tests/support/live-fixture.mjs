import {createClient} from '@supabase/supabase-js';import {randomUUID} from 'node:crypto';
export const check=({data,error})=>{if(error)throw Error(error.message);return data;};
export async function liveFixture(label,overrides=[]){
 const url=process.env.SUPABASE_URL,key=process.env.VITE_SUPABASE_ANON_KEY;
 const options={auth:{persistSession:false,autoRefreshToken:false}},admin=createClient(url,process.env.SUPABASE_SERVICE_ROLE_KEY,options),client=createClient(url,key,options);
 const username='qa_'+label+'_'+randomUUID().replaceAll('-','').slice(0,12),email=username+'@hadsec.local',password=randomUUID();
 const role=check(await admin.from('roles').select('id').eq('name','Engenheiro').single());const id=check(await admin.auth.admin.createUser({email,password,email_confirm:true})).user.id;
 try{check(await admin.from('profiles').insert({id,username,display_name:'QA temporário '+label,role_id:role.id,must_change_password:false}));if(overrides.length)check(await admin.from('user_permission_overrides').insert(overrides.map(permission=>({user_id:id,permission,granted:true,updated_by:id}))));const {session}=check(await client.auth.signInWithPassword({email,password}));
 return {admin,client,id,username,password,token:session.access_token,async cleanup(){await client.auth.signOut({scope:'local'});check(await admin.from('user_permission_overrides').delete().eq('user_id',id));check(await admin.from('profiles').update({active:false,deleted_at:new Date().toISOString(),username:'deleted.'+id.replaceAll('-',''),display_name:'Teste operacional removido'}).eq('id',id));check(await admin.auth.admin.deleteUser(id,true));}};
 }catch(e){await admin.auth.admin.deleteUser(id).catch(()=>{});throw e;}
}
