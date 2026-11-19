import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,access,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {planIntegration,RUNTIME_BINARIES,STANDALONE_BINARIES} from './integration-config.mjs';

const engineRoot=fileURLToPath(new URL('../',import.meta.url));
const pinned=(await readFile(path.join(engineRoot,'.node-version'),'utf8')).trim();
const node=`v${pinned}`;

// Synthetic desktop and plugin checkouts; no private checkout or live site.
async function fixture(t,{plugins=[],desktopPin=pinned}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'omd-integration-config-')));
 t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(path.join(root,'desktop/packaging'),{recursive:true});
 await writeFile(path.join(root,'desktop/.node-version'),desktopPin+'\n');
 await writeFile(path.join(root,'desktop/packaging/public-plugins.json'),JSON.stringify({format:1,plugins,reserved_private_ids:['org.example.private']}));
 const checkout=async(name,manifest)=>{await mkdir(path.join(root,name));await writeFile(path.join(root,name,'omd-plugin.json'),JSON.stringify(manifest));};
 const config=async value=>{const file=path.join(root,'integration.json');await writeFile(file,JSON.stringify({desktop:'desktop',tools:'tools.json',browser_tools:'browser.json',output:'run',...value}));return file;};
 return {root,checkout,config};
}

test('the default public integration needs no plugin checkout and packages a release runtime',async t=>{
 const f=await fixture(t);
 const plan=await planIntegration(await f.config({}),{engineRoot,nodeVersion:node});
 assert.deepEqual(STANDALONE_BINARIES,[...RUNTIME_BINARIES,'omd-mcp']);
 assert.equal(plan.mode,'public');assert.equal(plan.publishable,true);assert.deepEqual(plan.sources,[]);
 assert.equal(plan.bundle,true);assert.equal(plan.output,path.join(f.root,'run'));assert.equal(plan.rustTestTimeoutSeconds,3600);
 assert.deepEqual(RUNTIME_BINARIES,['omd-engine','omd-plugin-worker-v2','omd-helper-guardian','omd-notify','omd-signin','omd']);
 const explicit=await planIntegration(await f.config({plugins:{mode:'public',sources:[]}}),{engineRoot,nodeVersion:node});
 assert.deepEqual(explicit.sources,[]);
});

test('public integrations reject plugins outside the reviewed desktop allowlist',async t=>{
 const f=await fixture(t,{plugins:[{name:'starter',id:'org.example.starter',version:'1.0.0',sha256:'a'.repeat(64),license:'MIT',review:'synthetic'}]});
 await f.checkout('private-source',{id:'org.example.private',version:'1.0.0'});
 await assert.rejects(planIntegration(await f.config({plugins:{mode:'public',sources:[{name:'private-source',path:'private-source'}]}}),{engineRoot,nodeVersion:node}),/not in the reviewed public allowlist/);
 await f.checkout('starter',{id:'org.example.starter',version:'1.0.1'});
 await assert.rejects(planIntegration(await f.config({plugins:{mode:'public',sources:[{name:'starter',path:'starter'}]}}),{engineRoot,nodeVersion:node}),/allowlist reviewed org\.example\.starter 1\.0\.0/);
 await writeFile(path.join(f.root,'starter/omd-plugin.json'),JSON.stringify({id:'org.example.starter',version:'1.0.0'}));
 const plan=await planIntegration(await f.config({plugins:{mode:'public',sources:[{name:'starter',path:'starter'}]}}),{engineRoot,nodeVersion:node});
 assert.equal(plan.sources[0].allowlisted_sha256,'a'.repeat(64));
});

test('private plugin integration is explicit, generic and never publishable',async t=>{
 const f=await fixture(t);
 for(const name of ['site-a','site-b'])await f.checkout(name,{id:`org.example.${name}`,version:'1.0.0'});
 const plan=await planIntegration(await f.config({plugins:{mode:'private',sources:[{name:'site-a',path:'site-a'},{name:'site-b',path:'site-b'}]}}),{engineRoot,nodeVersion:node});
 assert.equal(plan.mode,'private');assert.equal(plan.publishable,false);assert.deepEqual(plan.sources.map(s=>s.name),['site-a','site-b']);
 await assert.rejects(planIntegration(await f.config({plugins:{mode:'private'}}),{engineRoot,nodeVersion:node}),/at least one plugin source/);
 await assert.rejects(planIntegration(await f.config({plugins:{mode:'private',sources:[{name:'site-a',path:'site-a'},{name:'site-a',path:'site-b'}]}}),{engineRoot,nodeVersion:node}),/Duplicate plugin source/);
 await assert.rejects(planIntegration(await f.config({providers:[{name:'site-a',path:'site-a'}]}),{engineRoot,nodeVersion:node}),/"providers" was replaced by "plugins"/);
 await assert.rejects(planIntegration(await f.config({plugins:{mode:'everything'}}),{engineRoot,nodeVersion:node}),/plugins\.mode/);
});

test('integrations require the pinned Node in both roots',async t=>{
 const f=await fixture(t);
 await assert.rejects(planIntegration(await f.config({}),{engineRoot,nodeVersion:'v26.13.0'}),/pinned Node/);
 const g=await fixture(t,{desktopPin:'22.0.0'});
 await assert.rejects(planIntegration(await g.config({}),{engineRoot,nodeVersion:node}),/desktop pins Node 22\.0\.0/);
});

test('the runner rejects an unlisted public plugin before creating its output',{skip:process.version!==node&&`requires Node ${pinned}`},async t=>{
 const f=await fixture(t);await f.checkout('private-source',{id:'org.example.private',version:'1.0.0'});
 const config=await f.config({plugins:{mode:'public',sources:[{name:'private-source',path:'private-source'}]}});
 const result=spawnSync(process.execPath,[path.join(engineRoot,'scripts/integrate-v2.mjs'),'--config',config],{encoding:'utf8'});
 assert.notEqual(result.status,0);assert.match(result.stderr,/not in the reviewed public allowlist/);
 await assert.rejects(access(path.join(f.root,'run')),{code:'ENOENT'});
});
