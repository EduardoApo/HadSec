import React,{useEffect} from 'react';

export function LoadingSplash({progress=0,onComplete}){
 const percent=Math.max(0,Math.min(100,Math.round(progress)));
 useEffect(()=>{if(percent!==100||!onComplete)return;const timer=setTimeout(onComplete,260);return()=>clearTimeout(timer);},[percent,onComplete]);
 return <div className="owl-splash" role="status" aria-live="polite" aria-label="Carregando HadSec Detect"><div className="splash-art" aria-hidden="true"><img className="splash-owl-base" src="/hadsec-owl-front.png" alt=""/><img className="splash-owl-fill" style={{clipPath:'inset('+(100-percent)+'% 0 0 0)'}} src="/hadsec-owl-front.png" alt=""/></div><h1>HadSec Detect<span>.</span></h1><p>{percent<25?'Preparando seu acesso':percent<100?'Carregando o workspace':'Workspace pronto'}</p><div className="splash-progress" role="progressbar" aria-label="Progresso do carregamento" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}><span>{percent}%</span></div></div>;
}
