import {simulateDetection} from '../supabase/functions/_shared/detection-engine.mjs';
self.onmessage=event=>{try{const {content,format,mode,log}=event.data;self.postMessage(simulateDetection(content,format,mode,log));}catch(error){self.postMessage({status:'invalid',reason:error.message,events:[]});}};
