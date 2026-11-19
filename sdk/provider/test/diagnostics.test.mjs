import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {diagnosticsFor} from '../bin/diagnostics.mjs';
const hash=value=>createHash('sha256').update(value).digest('hex');
test('author maps are bound to exact component bytes and omit external paths',async()=>{
 const root=await mkdtemp(join(tmpdir(),'omd-diagnostic-'));
 try{
  const component=join(root,'plugin.wasm');await writeFile(component,'component');
  const map=JSON.stringify({version:3,file:'component.mjs',sources:['src/index.ts','../../PRIVATE/file.ts'],names:[],mappings:'AAAA;ACAA'});
  await writeFile(join(root,'component.mjs.map'),map);
  await writeFile(join(root,'build.json'),JSON.stringify({sha256:hash('component'),source_map_sha256:hash(map)}));
  const locate=await diagnosticsFor(component);
  assert.deepEqual(locate({diagnostics:{frames:[{line:1,column:1},{line:2,column:1},{line:-1,column:1},{line:1,column:1}]}}),[{source:'src/index.ts',line:1,column:1}]);
  await writeFile(component,'different component');assert.deepEqual((await diagnosticsFor(component))({diagnostics:{frames:[{line:1,column:1}]}}),[]);
  await writeFile(component,'component');await writeFile(join(root,'component.mjs.map'),map+' ');
  assert.deepEqual((await diagnosticsFor(component))({diagnostics:{frames:[{line:1,column:1}]}}),[]);
 }finally{await rm(root,{recursive:true});}
});
