// Fixture conformance executes the actual pure component in OMD's Wasmtime
// worker. No source code is imported into Node and no live broker fallback exists.
import {readFile,writeFile,mkdir,realpath,readdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import assert from 'node:assert/strict';
import {ownedProcess} from './process.mjs';
import {build} from './omd-plugin.mjs';
import {diagnosticsFor} from './diagnostics.mjs';
const frameLimit=16*1024*1024;
/** Explicit engine failure for conformance; ordinary callback errors remain test failures. */
export class BrokerFailure extends Error {
  constructor(problem){super(problem.message);assert.equal(typeof problem.code,'string');assert.equal(typeof problem.message,'string');this.problem={code:problem.code,message:problem.message,retryable:problem.retryable===true,actions:problem.actions??[]};}
}
export async function harness(project,{worker=process.env.OMD_PLUGIN_WORKER??'omd-plugin-worker-v2',component}={}) {
  project=await realpath(project);
  component??=(await build(project)).output;
  const sourceLocations=await diagnosticsFor(component);
  const cache=join(project,'.omd-build','fixture-cache');await mkdir(cache,{recursive:true});
  const config=join(project,'.omd-build','fixture-cache.toml');await writeFile(config,`[cache]\ndirectory = ${JSON.stringify(cache)}\n`);
  const manifest=JSON.parse(await readFile(join(project,'omd-plugin.json'),'utf8'));
  return {
    async invoke(input,broker=()=>{throw new Error('Unexpected broker operation')}) {
      const {child,stop}=ownedProcess(worker,[],{env:{}});
      let buffered=Buffer.alloc(0),settled=false;let frames=Promise.resolve();
      const trace=[];
      const payload={reference:null,query:null,url:null,cursor:null,page_size:100,policy:{},now:'2026-01-01T00:00:00.000Z',credential_profile:null,...input};
      function write(value){const bytes=Buffer.from(JSON.stringify(value));assert.ok(bytes.length<=frameLimit);const header=Buffer.alloc(4);header.writeUInt32LE(bytes.length);child.stdin.write(Buffer.concat([header,bytes]));}
      let timer;const interrupted=()=>void stop();process.once('SIGINT',interrupted);process.once('SIGTERM',interrupted);
      try {
        return await new Promise((resolveResult,reject)=>{
          const finish=(error,result)=>{if(settled)return;settled=true;if(error)reject(error);else resolveResult({result,trace,diagnostics:sourceLocations(result)});};
          timer=setTimeout(()=>{finish(new Error('Fixture execution exceeded its 60-second budget.'));void stop();},60000);
          child.once('error',()=>finish(new Error('OMD plugin worker is unavailable. Set OMD_PLUGIN_WORKER to the worker from your OMD installation.')));
          child.stdin.on('error',()=>{});child.stderr.resume();
          child.once('close',()=>{void frames.finally(()=>{if(!settled)finish(new Error('The fixture worker stopped before returning a result.'));});});
          child.stdout.on('data',chunk=>{
            buffered=Buffer.concat([buffered,chunk]);
            while(buffered.length>=4){const size=buffered.readUInt32LE();if(size>frameLimit){finish(new Error('Fixture frame exceeds its limit.'));void stop();return;}if(buffered.length<size+4)break;
              let message;try{message=JSON.parse(buffered.subarray(4,size+4));}catch{finish(new Error('Invalid worker frame'));void stop();return;}buffered=buffered.subarray(size+4);
              frames=frames.then(async()=>{
                if(settled)return;
                if(message.broker){
                  assert.ok(trace.length<128,'Fixture broker call limit exceeded');
                  const {operation}=message.broker;const request=JSON.parse(message.broker.payload);
                  validateBroker(manifest,operation,request);
                  try {
                    const response=await broker(operation,request,trace.length);trace.push({operation,request,response});
                    write({result:JSON.stringify(response)});
                  }catch(error){
                    if(!(error instanceof BrokerFailure))throw error;
                    trace.push({operation,request,error:error.problem});write({error:JSON.stringify(error.problem)});
                  }
                }else if(message.result)finish(null,message.result);
                else finish(new Error(message.error??'Invalid fixture response'));
              }).catch(error=>{finish(error);void stop();});
            }
          });
          write({component:resolve(component),manifest,cache_config:config,payload:JSON.stringify(payload)});
        });
      } finally {clearTimeout(timer);process.removeListener('SIGINT',interrupted);process.removeListener('SIGTERM',interrupted);await stop();child.stdin.destroy();child.stdout.destroy();child.stderr.destroy();}
    }
  };
}
function validateBroker(manifest,operation,input){
  if(operation==='log')return;
  if(operation==='media.inspect'){assert.ok(manifest.media_tools,'Undeclared media capability');return;}
  if(operation.startsWith('browser.')){
    assert.ok(manifest.browser,'Undeclared browser capability');
    assert.ok(['browser.open','browser.action','browser.close'].includes(operation),'Unknown browser operation');
    if(operation==='browser.action')assert.ok(['navigate','wait','click','fill','select','press','snapshot','pointer','type','scroll'].includes(input.op),'Unavailable source browser operation');
    if(operation==='browser.open'||input.op==='navigate'){
      const url=new URL(input.url);assert.equal(url.protocol,'https:');assert.ok(!url.username&&!url.password&&!url.hash&&(!url.port||url.port==='443'),'Invalid browser URL');
      assert.ok(manifest.grants.some(grant=>grant.methods.includes('GET')&&grant.hosts.some(host=>host===url.hostname||host.startsWith('*.')&&url.hostname.endsWith(host.slice(1)))),'Undeclared source browser host');
    }
    return;
  }
  assert.equal(operation,'http','Unknown or ambient broker operation');
  const grant=manifest.grants.find(g=>g.id===input.permission);assert.ok(grant,'Undeclared network permission');
  const url=new URL(input.url);assert.equal(url.protocol,'https:');assert.ok(!url.username&&!url.password&&!url.hash&&(!url.port||url.port==='443'),'Invalid source URL');
  assert.ok(grant.hosts.some(h=>h===url.hostname||h.startsWith('*.')&&url.hostname.endsWith(h.slice(1))),'Undeclared source host');
  assert.ok(grant.methods.includes(input.method??'GET'),'Undeclared source method');
  assert.ok(!Object.keys(input.headers??{}).some(h=>['authorization','cookie','proxy-authorization'].includes(h.toLowerCase())),'Source supplied a raw credential');
}
export async function testFixtures(project,options={}) {
  const directory=join(resolve(project),'fixtures');
  const names=(await readdir(directory)).filter(name=>name.endsWith('.json')).sort();assert.ok(names.length,'Add at least one JSON fixture under fixtures/');
  const runtime=await harness(project,options);const results=[];
  for(const name of names){
    const fixture=JSON.parse(await readFile(join(directory,name),'utf8'));let index=0;
    const {result,trace,diagnostics}=await runtime.invoke(fixture.input,(operation,request)=>{
      const expected=fixture.exchanges[index++];assert.ok(expected,`${name}: unexpected broker call ${operation}`);
      assert.equal(operation,expected.operation,`${name}: broker operation changed`);
      assert.deepEqual(request,expected.request,`${name}: broker request changed`);if(expected.error)throw new BrokerFailure(expected.error);return expected.response;
    });
    assert.equal(index,fixture.exchanges.length,`${name}: unused fixture responses`);
    if(fixture.error){assert.equal(result.ok,false,name);assert.equal(result.error.code,fixture.error,name);}
    else assert.deepEqual(result,{ok:true,result:fixture.result},`${name}${diagnostics.map(p=>`\n  ${p.source}:${p.line}:${p.column}`).join('')}`);
    results.push({fixture:name,status:'passed',broker_calls:trace.length});
  }
  return results;
}

const secretKey=/^(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|client_secret|access_token|refresh_token|id_token|token|api[_-]?key|signature|sig|session[_-]?(?:id|token))$/i;
/** Defense in depth for a fixture already collected through a broker. Supply
 * every known source-specific secret; arbitrary HTML cannot be classified safely. */
export function redactFixture(value,secrets=[]){
  const variants=[...new Set(secrets.filter(s=>typeof s==='string'&&s).flatMap(s=>[s,encodeURIComponent(s)]))].sort((a,b)=>b.length-a.length);
  const text=raw=>{
    let result=raw;for(const secret of variants)result=result.split(secret).join('[redacted]');
    return result.replace(/https?:\/\/[^\s<>"']+/g,raw=>{
      try {const url=new URL(raw);let changed=false;if(url.username||url.password){url.username='redacted';url.password='';changed=true;}
        for(const key of [...url.searchParams.keys()])if(secretKey.test(key)){url.searchParams.set(key,'[redacted]');changed=true;}
        return changed?url.href:raw;
      }catch{return raw;}
    });
  };
  const visit=value=>{
    if(typeof value==='string'){
      if(/^\s*[\[{]/.test(value)){try{return JSON.stringify(visit(JSON.parse(value)));}catch{}}
      return text(value);
    }
    if(Array.isArray(value))return value.map(visit);
    if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([key,value])=>[text(key),secretKey.test(key)?'[redacted]':visit(value)]));
    return value;
  };
  return visit(value);
}
export async function recordFixture(runtime,input,broker,output,{secrets=[]}={}){
  const {result,trace}=await runtime.invoke(input,broker);
  const fixture=redactFixture({input,exchanges:trace,...(result.ok?{result:result.result}:{error:result.error.code})},secrets);
  const bytes=JSON.stringify(fixture,null,2)+'\n';assert.ok(Buffer.byteLength(bytes)<=16*1024*1024,'Recorded fixture exceeds its byte budget');
  await writeFile(output,bytes,{flag:'wx',mode:0o600});
  return {output,broker_calls:trace.length};
}
