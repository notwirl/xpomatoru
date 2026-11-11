import {decrypt,validateVersion,validateManifest,sha256} from './crypto.mjs';
const base=new URL('./',self.location.href),sessions=new Map(),restoring=new Map();
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
async function unlock(data,source){
  if(!source||![base.href,new URL('index.html',base).href].includes(source.url.split('#')[0].split('?')[0]))throw new Error('Вход доступен только со страницы пароля.');
  if(!/^[a-f0-9]{32}$/.test(data.session))throw new Error('Неверная сессия.');
  const version=validateVersion(data.version);
  const response=await fetch(new URL(`releases/${version.release}/${version.manifest.blob}`,base));
  if(!response.ok)throw new Error('Сборка недоступна.');
  const raw=await decrypt(data.key,version.release,'manifest',version.manifest.iv,await response.arrayBuffer());
  const manifest=validateManifest(JSON.parse(new TextDecoder().decode(raw)),version);
  sessions.set(data.session,{key:data.key,version,manifest,owner:source.id});
  restoring.get(data.session)?.();
}
self.addEventListener('message',event=>{
  event.waitUntil((async()=>{
    try{
      if(event.data?.type==='unlock')await unlock(event.data,event.source);
      else if(event.data?.type==='lock'){
        if(sessions.get(event.data.session)?.owner===event.source?.id)sessions.delete(event.data.session);
      }else throw new Error('Неизвестная команда.');
      event.ports[0]?.postMessage({ok:true});
    }catch{event.ports[0]?.postMessage({ok:false,error:'Пароль неверен или сборка повреждена.'});
  }
  })());
});
async function sessionFor(id){
  if(!sessions.has(id)){
    await new Promise(async resolve=>{
      const timer=setTimeout(()=>{restoring.delete(id);
  resolve()},1500);
      restoring.set(id,()=>{clearTimeout(timer);
  restoring.delete(id);
  resolve()});
      for(const client of await self.clients.matchAll({type:'window'}))client.postMessage({type:'restore',session:id});
    });
  }
  const session=sessions.get(id);
  if(session&&!await self.clients.get(session.owner)){sessions.delete(id);
  return null;
  }
  return session;
}
const denied=()=>new Response('Доступ закрыт. Вернитесь на страницу ввода пароля.',{status:403,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(url.origin!==base.origin||!url.pathname.startsWith(base.pathname+'run/'))return;
  event.respondWith((async()=>{
    const relative=url.pathname.slice((base.pathname+'run/').length),slash=relative.indexOf('/');
    const id=relative.slice(0,slash),name=relative.slice(slash+1);
    if(!/^[a-f0-9]{32}$/.test(id))return denied();
    const session=await sessionFor(id);
    if(!session)return denied();
    // Local acceptance only: authenticated fixture gateway stays outside encrypted/public data.
    if(name.startsWith('__local/')&&base.hostname==='127.0.0.1')return fetch(new URL(name,base),{method:event.request.method,headers:event.request.headers,body:event.request.method==='POST'?await event.request.arrayBuffer():undefined});
    if(event.request.method!=='GET')return denied();
    const file=session.manifest.files[name];
    if(!file)return new Response('Нет файла',{status:404});
    try{
      const response=await fetch(new URL(`releases/${session.version.release}/${file.blob}`,base));
      if(!response.ok)throw new Error('Missing encrypted resource');
      const data=await decrypt(session.key,session.version.release,name,file.iv,await response.arrayBuffer());
      if(await sha256(data)!==file.sha256||data.byteLength!==file.size)throw new Error('Corrupt resource');
      // GitHub API открыт только сборке, в которую при выпуске зашифрован ключ «Базы LST».
      const connect=session.manifest.files['lst-base.json']?"connect-src 'self' https://api.github.com":"connect-src 'self'";
      const headers={'Content-Type':file.mime,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
        'Content-Security-Policy':"default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'unsafe-eval'; worker-src 'self' blob:; "+connect+"; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'"};
      return new Response(data,{headers});
    }catch{return new Response('Сборка повреждена. Загрузка остановлена.',{status:502});
  }
  })());
});
