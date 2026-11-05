// Native Web Crypto only. Shared by the gate, service worker, and Node build tests.
export const ITERATIONS = 600000;
export const bytes = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
export const base64 = data => btoa(String.fromCharCode(...new Uint8Array(data)));
export const aad = (release, name) => new TextEncoder().encode(`xpomatoru-v1/${release}/${name}`);
export async function derive(password, salt, usages = ['decrypt']) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(salt),iterations:ITERATIONS,hash:'SHA-256'},raw,
    {name:'AES-GCM',length:256},false,usages);
}
export async function decrypt(key, release, name, iv, data) {
  return crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(iv),additionalData:aad(release,name),tagLength:128},key,data);
}
export function validateVersion(value) {
  if (value.schema !== 1 || value.iterations !== ITERATIONS || !/^[a-f0-9]{32}$/.test(value.release)
      || !/^[a-f0-9]{64}$/.test(value.build_id) || bytes(value.salt).length !== 16
      || !/^[a-f0-9]{64}\.bin$/.test(value.manifest?.blob) || bytes(value.manifest.iv).length !== 12) {
    throw new Error('Неподдерживаемая или повреждённая сборка.');
  }
  return value;
}
export function validateManifest(value, version) {
  if (value.build_id !== version.build_id || !value.files?.['index.html']) throw new Error('Повреждён состав сборки.');
  for (const [name,file] of Object.entries(value.files)) {
    if (!/^[a-zA-Z0-9_./-]+$/.test(name) || name.startsWith('/') || name.split('/').some(p=>!p||p==='.'||p==='..')
        || !/^[a-f0-9]{64}\.bin$/.test(file.blob) || bytes(file.iv).length !== 12
        || !/^[a-f0-9]{64}$/.test(file.sha256) || typeof file.mime !== 'string') throw new Error('Повреждён путь сборки.');
  }
  return value;
}
export async function sha256(data) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256',data))].map(n=>n.toString(16).padStart(2,'0')).join('');
}
