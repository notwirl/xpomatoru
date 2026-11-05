import {derive,validateVersion} from './crypto.mjs';
const base=new URL('./',location.href);
let unlocked=null,controller=null;
const error=document.querySelector('#error'),input=document.querySelector('#password'),frame=document.querySelector('#workspace');
function message(data) {
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();
    const timer=setTimeout(()=>reject(new Error('Не удалось открыть защищённую сборку. Обновите страницу.')),30000);
    channel.port1.onmessage=({data})=>{clearTimeout(timer);
  channel.port1.close();
  data.ok?resolve(data):reject(new Error(data.error))};
    controller.postMessage(data,[channel.port2]);
  });
}
const ready=(async()=>{
  if(!isSecureContext||!navigator.serviceWorker||!crypto.subtle)throw new Error('Откройте сайт по HTTPS в современном браузере.');
  await navigator.serviceWorker.register(new URL('vault-sw.js',base),{scope:base.pathname,type:'module',updateViaCache:'none'});
  await navigator.serviceWorker.ready;
  if(!navigator.serviceWorker.controller)await new Promise(resolve=>navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
  controller=navigator.serviceWorker.controller;
})();
ready.catch(e=>{error.textContent=e.message});
navigator.serviceWorker?.addEventListener('message',event=>{
  if(event.data?.type==='restore'&&unlocked?.session===event.data.session)event.source.postMessage({type:'unlock',...unlocked});
});
navigator.serviceWorker?.addEventListener('controllerchange',()=>{controller=navigator.serviceWorker.controller});
document.querySelector('#unlock').addEventListener('submit',async event=>{
  event.preventDefault();
  error.textContent='';
  document.querySelector('#submit').disabled=true;
  try{
    await ready;
    const response=await fetch(new URL('version.json',base),{cache:'no-store'});
    if(!response.ok)throw new Error('Сборка недоступна.');
    const version=validateVersion(await response.json());
    const pending=derive(input.value,version.salt);
  input.value='';
    const key=await pending;
    const session=[...crypto.getRandomValues(new Uint8Array(16))].map(n=>n.toString(16).padStart(2,'0')).join('');
    await message({type:'unlock',session,version,key});
    unlocked={session,version,key};
    const localTest = base.hostname === '127.0.0.1' && location.hash.startsWith('#selftest=');
    const target = localTest ? 'selftest.html#' + location.hash.slice(10) : 'index.html';
    frame.src=new URL(`run/${session}/${target}`,base).href;
    frame.hidden=false;
  document.querySelector('#login').hidden=true;
  document.querySelector('#bar').hidden=false;
  }catch{error.textContent='Пароль неверен или сборка повреждена. Проверьте пароль и повторите.';
  }
  finally{input.value='';
  document.querySelector('#submit').disabled=false;
  }
});
document.querySelector('#lock').addEventListener('click',async()=>{
  const session=unlocked?.session;
  unlocked=null;
  frame.src='about:blank';
  frame.hidden=true;
  if(session)await message({type:'lock',session}).catch(()=>{});
  document.querySelector('#login').hidden=false;
  document.querySelector('#bar').hidden=true;
  input.focus();
});
export async function checkUpdate(){
  if(!unlocked)return;
  try{
    const current=validateVersion(await (await fetch(new URL('version.json',base),{cache:'no-store'})).json());
    if(current.release!==unlocked.version.release){document.querySelector('#update').hidden=false;
  document.querySelector('#refresh').hidden=false;
  }
  }catch{/* Keep the running, authenticated release when the network is unavailable. */}
}
setInterval(checkUpdate,60000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)checkUpdate()});
document.querySelector('#refresh').addEventListener('click',()=>{
  if(confirm('Сохраните проект перед обновлением. Обновить страницу?'))location.reload();
});
