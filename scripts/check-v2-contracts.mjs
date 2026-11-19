// The same contract check runs locally and in CI without requiring a Git checkout.
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';
import {cargoTargetDirectory} from './cargo-paths.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const target=await cargoTargetDirectory(root);
function run(command,args,cwd=root){const result=spawnSync(command,args,{cwd,encoding:'utf8',maxBuffer:8*1024*1024});if(result.error)throw result.error;if(result.status!==0)throw new Error(`${command} failed (${result.status})\n${result.stderr}`);return result.stdout;}
for(const [name,file] of [['omd-schema','domain'],['omd-openapi','openapi']]){
 const actual=run(path.join(target,'debug',name+(process.platform==='win32'?'.exe':'')),[]);
 assert.deepEqual(JSON.parse(actual),JSON.parse(await readFile(path.join(root,`schemas/v2/${file}.json`),'utf8')),`${file} contract differs from Rust`);
}
const files=['sdk/provider/src/contracts.ts','sdk/client/src/models.ts','sdk/client/src/http.generated.ts','sdk/client/src/scopes.generated.ts','sdk/client/openapi.json'];
const before=await Promise.all(files.map(file=>readFile(path.join(root,file),'utf8')));
run('vp',['exec','node','bin/generate-contracts.mjs'],path.join(root,'sdk/provider'));
run('vp',['exec','node','bin/generate.mjs'],path.join(root,'sdk/client'));
for(let i=0;i<files.length;i++)assert.equal(await readFile(path.join(root,files[i]),'utf8'),before[i],`${files[i]} differs from the published contract; regenerate and version the SDK`);
console.log('Rust domain, OpenAPI, generated SDK models, HTTP types and operation scopes agree.');
