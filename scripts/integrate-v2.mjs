// Build an integration from explicit repositories and verified tool inputs.
// No repository layout, sibling checkout, global npm installation or engine API
// internals are part of the desktop/provider contract. The default is a public
// integration with no plugin checkouts; private plugin testing is opt-in.
import {readFile,writeFile,mkdir,cp} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawn,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {cargoTargetDirectory} from './cargo-paths.mjs';
import {verifyBrowserSource} from './browser-source.mjs';
import {planIntegration,RUNTIME_BINARIES} from './integration-config.mjs';
import {fingerprintSources,DESKTOP_SOURCE_ROOTS} from './source-fingerprint.mjs';
const args=process.argv.slice(2);
if(args.length!==2||args[0]!=='--config')throw new Error('Use: vp exec node scripts/integrate-v2.mjs --config /absolute/integration.json');
const root=fileURLToPath(new URL('../',import.meta.url));
// All plugin, Node-pin and path validation happens before the output exists.
const plan=await planIntegration(args[1],{engineRoot:root});
const {desktop,output,bundle,sources:providers,tools,browser}=plan;
const engineTarget=await cargoTargetDirectory(root);
const desktopTarget=await cargoTargetDirectory(path.join(desktop,'src-tauri'));
await mkdir(output,{recursive:false});
const report={format:2,targets:{engine:engineTarget,desktop:desktopTarget},platform:process.platform,architecture:process.arch,node:process.version,started_at:new Date().toISOString(),status:'running',bundle,
 plugins:{mode:plan.mode,publishable:plan.publishable,sources:providers.map(p=>p.name)},
 // Developer regressions use debug binaries; packaged resources use release ones.
 profiles:{developer_binaries:'debug',packaged_runtime:bundle?'release':null,desktop_shell:bundle?'debug':null},
 steps:[],sources:[],packages:[]};
const reportFile=path.join(output,'integration.json');
async function save(){await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');}
let active=null;
for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{stop(active,'SIGKILL');report.status='interrupted';report.failure=`Interrupted by ${signal}`;report.completed_at=new Date().toISOString();save().finally(()=>process.exit(130));});
function stop(child,signal){if(!child?.pid)return;try{process.platform==='win32'?execFileSync('taskkill',['/pid',String(child.pid),'/T','/F'],{stdio:'ignore'}):process.kill(-child.pid,signal);}catch{}}
async function run(label,program,args,cwd=root,extra={},timeoutSeconds=null){
 console.log(label);const began=Date.now();let timedOut=false;
 const code=await new Promise((yes,no)=>{
  // A separate process group lets a bounded step stop its test binaries too.
  const child=active=spawn(program,args,{cwd,stdio:'inherit',detached:process.platform!=='win32',env:{...process.env,CARGO_INCREMENTAL:'0',...extra}});
  let timer=null,kill=null;
  if(timeoutSeconds)timer=setTimeout(()=>{timedOut=true;stop(child,'SIGTERM');kill=setTimeout(()=>stop(child,'SIGKILL'),10000);},timeoutSeconds*1000);
  child.once('error',error=>{clearTimeout(timer);clearTimeout(kill);active=null;no(error);});child.once('close',status=>{if(timedOut)stop(child,'SIGKILL');clearTimeout(timer);clearTimeout(kill);active=null;yes(status);});
 });
 report.steps.push({label,exit_code:code,seconds:(Date.now()-began)/1000,...(timeoutSeconds?{timeout_seconds:timeoutSeconds,timed_out:timedOut}:{})});await save();
 if(timedOut)throw new Error(`${label} exceeded ${timeoutSeconds}s and was stopped; retained evidence in ${output}`);
 if(code!==0)throw new Error(`${label} failed (${code}); retained evidence in ${output}`);
}
async function fingerprint(name,directory,roots,verify=false){
 const {sha256,files}=await fingerprintSources(directory,roots);
 if(verify){if(report.sources.find(source=>source.name===name)?.sha256!==sha256)throw new Error(`${name} sources changed during integration; rerun with stable inputs`);return;}
 report.sources.push({name,directory,roots,sha256,files});await save();
}
const exe=process.platform==='win32'?'.exe':'';
try{
 if(bundle){report.browser_adapter=await verifyBrowserSource(browser,path.join(root,'adapters/browser'));await save();}
 await fingerprint('engine',root,['Cargo.toml','Cargo.lock','rust-toolchain.toml','.node-version','LICENSE','package.json','crates','schemas','sdk/provider','sdk/client','adapters/browser','distribution','scripts','tests/v2-provider','tests/v2-acquisition-provider','tests/support']);
 await fingerprint('desktop',desktop,DESKTOP_SOURCE_ROOTS);
 for(const source of providers)await fingerprint(`plugin:${source.name}`,source.root,['src','test','vendor','package.json','package-lock.json','omd-plugin.json']);
 for(const sdk of ['provider','client'])await run(`Install locked ${sdk} SDK`,'vp',['install','--frozen-lockfile'],path.join(root,'sdk',sdk));
 for(const fixture of ['v2-provider','v2-acquisition-provider'])await run(`Build ${fixture}`,'vp',['exec','node','bin/omd-plugin.mjs','build',`../../tests/${fixture}`],path.join(root,'sdk/provider'));
 await run('Build developer Rust binaries (debug)','cargo',['build','--workspace','--bins','--locked']);
 await run('Integration script regressions','vp',['exec','node','--test','scripts/browser-source.test.mjs','scripts/integration-config.test.mjs','scripts/source-fingerprint.test.mjs','scripts/cargo-paths.test.mjs']);
 await run('Verify published contracts','vp',['exec','node','scripts/check-v2-contracts.mjs']);
 await run('Rust acceptance fixtures','cargo',['test','--workspace','--all-targets','--locked'],root,{},plan.rustTestTimeoutSeconds);
 const worker=path.join(engineTarget,'debug/omd-plugin-worker-v2'+exe);
 await run('Native MCP stdio protocol and HTTP boundary regressions','uv',['run','scripts/test-mcp.py'],root,{OMD_MCP_BINARY:path.join(engineTarget,'debug/omd-mcp'+exe)});
 await run('Check provider SDK types','vp',['run','check'],path.join(root,'sdk/provider'));
 await run('Provider SDK authoring and CLI regressions','vp',['run','test'],path.join(root,'sdk/provider'),{OMD_PLUGIN_WORKER:worker});
 await run('Check independent client SDK types','vp',['run','check'],path.join(root,'sdk/client'));
 await run('Independent client transport regressions','vp',['exec','node','--test','test/http.test.mjs'],path.join(root,'sdk/client'));
 let pluginManifest=null;
 if(providers.length){
  await mkdir(path.join(output,'plugins'));
  for(const source of providers){
   await run(`Install locked ${source.name} author tools`,'vp',['install','--frozen-lockfile'],source.root);
   await run(`Check ${source.name}`,'vp',['run','check'],source.root);
   await run(`Test ${source.name}`,'vp',['run','test'],source.root,{OMD_PLUGIN_WORKER:worker});
   await run(`Package ${source.name}`,'vp',['run','pack'],source.root);
   const bytes=await readFile(path.join(source.root,'.omd-build/provider.omdp')),sha256=createHash('sha256').update(bytes).digest('hex');
   if(source.allowlisted_sha256&&source.allowlisted_sha256!==sha256)throw new Error(`Plugin ${source.name} packaged as ${sha256}, not its reviewed public digest`);
   const packagePath=path.join(output,'plugins',source.name+'.omdp');await writeFile(packagePath,bytes,{flag:'wx'});
   report.packages.push({name:source.name,path:packagePath,sha256});
  }
  pluginManifest=path.join(output,'plugins.json');await writeFile(pluginManifest,JSON.stringify(report.packages,null,2)+'\n',{flag:'wx'});
 }
 await run('Install locked desktop dependencies','vp',['install','--frozen-lockfile'],desktop);
 await run('Check Svelte','vp',['run','check'],desktop);
 await run('Desktop regressions','vp',['exec','vitest','run','--config','vitest.v2.config.ts'],desktop);
 await run('Native shell error regressions','cargo',['test','--manifest-path','src-tauri/Cargo.toml','--lib','--locked'],desktop);
 await run('Packaging recovery tests','vp',['exec','node','--test','scripts/stage-v2.test.mjs'],desktop);
 if(bundle){
  // Staging requires an optimized worker; build the packaged runtime as release.
  await run('Build packaged runtime binaries (release)','cargo',['build','--release','--locked','--workspace',...RUNTIME_BINARIES.flatMap(name=>['--bin',name])]);
  const engineBin=path.join(engineTarget,'release');
  report.runtime_binaries=await Promise.all(RUNTIME_BINARIES.map(async name=>({name:name+exe,sha256:createHash('sha256').update(await readFile(path.join(engineBin,name+exe))).digest('hex')})));await save();
  await run('Stage verified desktop resources','vp',['exec','node','scripts/stage-v2.mjs','--engine-bin',engineBin,'--tools',tools,'--browser-tools',browser,'--plugin-mode',plan.mode,...(pluginManifest?['--providers',pluginManifest]:[]),...(plan.supplements?['--supplements',plan.supplements]:[])],desktop);
  const staged=path.join(desktop,'src-tauri/resources/v2');
  if(plan.publishable)await run('Check public resource inventory','vp',['exec','node','scripts/plugin-policy.mjs','--check-public',staged],desktop);
  const inventory=await readFile(path.join(staged,'build-inventory.json'));
  await writeFile(path.join(output,'build-inventory.json'),inventory,{flag:'wx'});
  const targets=process.platform==='darwin'?['app']:process.platform==='win32'?['nsis']:['deb'];
  const override=path.join(output,'bundle-targets.json');await writeFile(override,JSON.stringify({bundle:{targets}}),{flag:'wx'});
  await run('Build native development bundle (debug shell, release runtime)','vp',['exec','tauri','build','--debug','--features','v2','--config','src-tauri/tauri.v2.package.conf.json',...(process.platform==='linux'?['--config','src-tauri/tauri.v2.linux.conf.json']:[]),'--config',override],desktop);
  await cp(path.join(desktopTarget,'debug/bundle'),path.join(output,'bundle'),{recursive:true,errorOnExist:true});
 }else await run('Build independent frontend','vp',['build','--config','vite.v2.config.ts'],desktop);
 for(const source of report.sources)await fingerprint(source.name,source.directory,source.roots,true);
 report.status='passed';report.completed_at=new Date().toISOString();
 report.release_acceptance=plan.publishable?'Separate packaged platform evidence is required.':'Private plugin integration; never publish this output or its bundle.';await save();
 console.log(`Integration passed (${plan.mode} plugins). Evidence: ${reportFile}`);
}catch(error){report.status='failed';report.completed_at=new Date().toISOString();report.failure=error.message;await save();throw error;}
