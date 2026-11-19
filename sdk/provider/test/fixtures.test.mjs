import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,cp,rm,readFile,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {harness,BrokerFailure,recordFixture,redactFixture} from '../bin/testing.mjs';
import {runOwned} from '../bin/process.mjs';
test('author CLI executes JSON fixtures and reports mismatches with a failing exit code',{timeout:180000},async()=>{
  const temp=await mkdtemp(join(tmpdir(),'omd-fixture-cli-'));
  try {
    const fixture=fileURLToPath(new URL('../../../tests/v2-provider/',import.meta.url));
    await cp(join(fixture,'src'),join(temp,'src'),{recursive:true});
    await cp(join(fixture,'omd-plugin.json'),join(temp,'omd-plugin.json'));
    await mkdir(join(temp,'fixtures'));
    const output=join(temp,'fixtures','identify.json');
    const expected={input:{operation:'identify',url:'https://example.com/one'},exchanges:[],result:{kind:'collection',reference:{provider:'org.example.conformance',id:'https://example.com/one'}}};
    await writeFile(output,JSON.stringify(expected));
    const command=fileURLToPath(new URL('../bin/omd-plugin.mjs',import.meta.url));
    const options={timeout:60000,maxBuffer:1024*1024,env:{...process.env,OMD_PLUGIN_WORKER:process.env.OMD_PLUGIN_WORKER??fileURLToPath(new URL('../../../target/debug/omd-plugin-worker-v2',import.meta.url))}};
    const result=await runOwned(process.execPath,[command,'test',temp],options);
    assert.deepEqual(JSON.parse(result.stdout),[{fixture:'identify.json',status:'passed',broker_calls:0}]);
    expected.result.reference.id='wrong';await writeFile(output,JSON.stringify(expected));
    await assert.rejects(runOwned(process.execPath,[command,'test',temp],options),/identify.json/);
  } finally {await rm(temp,{recursive:true,force:true});}
});
test('fixture authoring executes a pure component and enforces the engine contract',{timeout:180000},async()=>{
  const temp=await mkdtemp(join(tmpdir(),'omd-fixture-author-'));
  try {
    const fixture=fileURLToPath(new URL('../../../tests/v2-provider/',import.meta.url));
    await cp(join(fixture,'src'),join(temp,'src'),{recursive:true});await cp(join(fixture,'omd-plugin.json'),join(temp,'omd-plugin.json'));
    const runtime=await harness(temp,{worker:process.env.OMD_PLUGIN_WORKER??fileURLToPath(new URL('../../../target/debug/omd-plugin-worker-v2',import.meta.url))});
    const {result,trace}=await runtime.invoke({operation:'search',query:'fixture'},(operation,request)=>{
      assert.equal(operation,'http');assert.equal(request.url,'https://example.com/catalog');
      return {status:200,body:'<article data-id="one"><h2>Fixture title</h2><a href="/one">Details</a></article>'};
    });
    assert.equal(result.ok,true);assert.equal(result.result.items[0].title,'Fixture title');assert.equal(trace.length,1);
    await assert.rejects(runtime.invoke({operation:'search'},()=>({status:200,body:'<article data-id="one"><h2>Title</h2><a href="https://undeclared.test/">Details</a></article>'})),/normalized provider contract/);
    const denied=await runtime.invoke({operation:'search'},()=>{throw new BrokerFailure({code:'permission_denied',message:'Network permission was denied.',retryable:false,actions:['review_permissions']});});
    assert.equal(denied.result.error.code,'permission_denied');assert.equal(denied.trace[0].error.code,'permission_denied');
    const output=join(temp,'recorded.json');
    await recordFixture(runtime,{operation:'search'},()=>({status:200,body:'<article data-id="one"><h2>Title PRIVATE-SESSION</h2><a href="/one">Details</a></article>'}),output,{secrets:['PRIVATE-SESSION']});
    const recorded=await readFile(output,'utf8');assert.ok(!recorded.includes('PRIVATE-SESSION'));assert.equal(JSON.parse(recorded).result.items[0].title,'Title [redacted]');
    const optional=await runtime.invoke({operation:'collection'});assert.equal(optional.result.error.code,'unsupported');
    const trapped=await runtime.invoke({operation:'search',query:'trap'});
    assert.equal(trapped.result.error.code,'source_error');
    assert.ok(!JSON.stringify(trapped).includes('An intentional author error'));
    const trapLine=(await readFile(join(temp,'src/index.ts'),'utf8')).split(/\r?\n/).findIndex(line=>line.includes('An intentional author error'))+1;
    assert.ok(trapLine>0,'The intentional error must be present in the fixture');
    assert.ok(trapped.diagnostics.some(frame=>frame.source==='src/index.ts'&&frame.line===trapLine),JSON.stringify(trapped));
    await assert.rejects(runtime.invoke({operation:'search'}),/Unexpected broker operation/);
  } finally {await rm(temp,{recursive:true,force:true});}
});

test('fixture redaction covers nested JSON, headers, URL credentials and known HTML secrets',()=>{
 const original={headers:{Authorization:'Bearer abc','Set-Cookie':'SID=xyz'},url:'https://user:pass@example.com/?token=xyz&q=title',body:JSON.stringify({access_token:'hidden',title:'hello'}),html:'<p>source-specific-secret</p>'};
 const redacted=redactFixture(original,['source-specific-secret']);const text=JSON.stringify(redacted);
 for(const secret of ['Bearer abc','SID=xyz','user:pass','hidden','source-specific-secret'])assert.ok(!text.includes(secret));
 assert.equal(JSON.parse(redacted.body).title,'hello');assert.equal(new URL(redacted.url).searchParams.get('q'),'title');assert.equal(original.headers.Authorization,'Bearer abc');
});
