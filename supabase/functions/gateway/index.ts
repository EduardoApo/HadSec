// Optional Edge adapter. Vercel deployments use /api/gateway directly.
import {createGateway} from '../../../server/gateway.mjs';
Deno.serve(createGateway({env:(name:string)=>Deno.env.get(name)||''}));
