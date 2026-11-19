// Source identities cover every build input, including bundled icons.
import {readFile,readdir,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';

export const DESKTOP_SOURCE_ROOTS=['.node-version','.gitignore','LICENSE','packaging','src','src-tauri/Cargo.toml','src-tauri/Cargo.lock','src-tauri/build.rs','src-tauri/src','src-tauri/icons','src-tauri/capabilities','src-tauri/linux','src-tauri/tauri.conf.json','src-tauri/tauri.v2.conf.json','src-tauri/tauri.v2.package.conf.json','src-tauri/tauri.v2.linux.conf.json','scripts','vendor','package.json','package-lock.json','tsconfig.json','index.html','v2.html','vite.config.ts','vite.v2.config.ts','vitest.v2.config.ts'];
const ignored=new Set(['node_modules','.git','target','.omd-build','artifacts','dist','dist-v2','.venv','.local','__pycache__']);
export async function fingerprintSources(directory,roots){
 const files=[];
 async function visit(relative){
  if(relative.split('/').some(part=>ignored.has(part)))return;
  const file=path.join(directory,relative),info=await lstat(file);
  if(info.isSymbolicLink())throw new Error(`Source fingerprint contains a symlink: ${relative}`);
  if(info.isDirectory()){for(const child of (await readdir(file)).sort())await visit(relative?relative+'/'+child:child);}
  else if(info.isFile())files.push({path:relative,sha256:createHash('sha256').update(await readFile(file)).digest('hex')});
  else throw new Error('Unsupported source input');
 }
 for(const relative of roots)await visit(relative);
 files.sort((a,b)=>a.path.localeCompare(b.path));
 const sha256=createHash('sha256').update(JSON.stringify(files)).digest('hex');
 return {sha256,files};
}
