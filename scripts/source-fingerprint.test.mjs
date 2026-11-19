import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fingerprintSources,DESKTOP_SOURCE_ROOTS} from './source-fingerprint.mjs';

test('desktop build identities change when bundled icons change',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'omd-source-identity-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 const directories=new Set(['packaging','src','src-tauri/src','src-tauri/icons','src-tauri/capabilities','src-tauri/linux','scripts','vendor']);
 for(const relative of DESKTOP_SOURCE_ROOTS){
  const file=path.join(root,relative);
  if(directories.has(relative))await mkdir(file,{recursive:true});
  else{await mkdir(path.dirname(file),{recursive:true});await writeFile(file,relative);}
 }
 const icon=path.join(root,'src-tauri/icons/icon.png');
 await writeFile(icon,'first icon');
 const before=await fingerprintSources(root,DESKTOP_SOURCE_ROOTS);
 assert.ok(before.files.some(file=>file.path==='src-tauri/icons/icon.png'));
 await writeFile(icon,'second icon');
 const after=await fingerprintSources(root,DESKTOP_SOURCE_ROOTS);
 assert.notEqual(after.sha256,before.sha256);
 assert.notDeepEqual(after.files,before.files);
 // Generated dependencies do not change the source identity.
 await mkdir(path.join(root,'src/node_modules'),{recursive:true});
 await writeFile(path.join(root,'src/node_modules/generated'),'generated output');
 assert.deepEqual(await fingerprintSources(root,DESKTOP_SOURCE_ROOTS),after);
});
