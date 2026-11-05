import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
await mkdir('artifacts',{recursive:true});
const browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
const page=await browser.newPage({viewport:{width:1440,height:900}});const errors=[];let loginRequests=0;
page.on('pageerror',e=>errors.push(e.message));
page.on('request',r=>{if(r.url().includes('/auth/v1/token'))loginRequests++;});
try{
 await page.addInitScript(()=>{localStorage.setItem('hadsec-mode','demo');localStorage.setItem('hadsec-demo-v1',JSON.stringify({profiles:[{id:'me',username:'HadSec',active:true}],rules:[{name:'Retired local data'}]}));});
 await page.goto('http://127.0.0.1:5173/#overview');await page.getByLabel('Usuário',{exact:true}).waitFor();
 assert.equal(await page.locator('.app').count(),0,'Nenhum painel sem autenticação');
 assert.equal(await page.getByRole('button',{name:/demonstração/i}).count(),0,'Nenhum atalho de demonstração');
 assert.deepEqual(await page.evaluate(()=>[localStorage.getItem('hadsec-mode'),localStorage.getItem('hadsec-demo-v1')]),[null,null]);
 const password=page.getByLabel('Senha',{exact:true});await password.fill('Senha QA 123');assert.equal(await password.getAttribute('type'),'password');
 await page.getByRole('button',{name:'Mostrar senha',exact:true}).click();assert.equal(await password.getAttribute('type'),'text');assert.equal(await password.inputValue(),'Senha QA 123');
 const hide=page.getByRole('button',{name:'Ocultar senha',exact:true});assert.equal(await hide.getAttribute('aria-pressed'),'true');await hide.focus();await hide.press('Enter');assert.equal(await password.getAttribute('type'),'password');assert.equal(await password.inputValue(),'Senha QA 123');
 assert.equal(loginRequests,0,'O botão de visualizar não pode enviar o formulário');
 for(const route of ['rules','requests','team','lab']){await page.evaluate(route=>{location.hash=route;},route);await page.getByLabel('Usuário',{exact:true}).waitFor();assert.equal(await page.locator('.app').count(),0);}
 for(const width of [1440,390]){await page.setViewportSize({width,height:900});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`Overflow em ${width}px`);await page.screenshot({path:`artifacts/login-${width}.png`,fullPage:true});}
 await page.reload();await page.getByLabel('Usuário',{exact:true}).waitFor();assert.equal(await page.locator('.app').count(),0);
 assert.deepEqual(errors,[]);
 console.log('Navegador: demonstração e dados antigos não liberam acesso; rotas exigem login; mostrar/ocultar senha funciona por mouse e teclado em desktop e celular.');
}finally{await browser.close();}
