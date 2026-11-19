import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,cp,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {harness,BrokerFailure} from '../bin/testing.mjs';
test('browser scope runs in the pure component, closes on error, and rejects undeclared origins',{timeout:180000},async()=>{
  const root=await mkdtemp(join(tmpdir(),'omd-browser-author-'));
  try{
    const fixture=fileURLToPath(new URL('../../../tests/v2-browser-provider/',import.meta.url));
    await cp(join(fixture,'src'),join(root,'src'),{recursive:true});await cp(join(fixture,'omd-plugin.json'),join(root,'omd-plugin.json'));
    const runtime=await harness(root,{worker:process.env.OMD_PLUGIN_WORKER??fileURLToPath(new URL('../../../target/debug/omd-plugin-worker-v2',import.meta.url))});
    const result=await runtime.invoke({operation:'search'},(operation,input)=>operation==='browser.action'&&input.op==='snapshot'?{url:'https://fixture.example/',title:'Fixture',text:'Browser fixture',links:[],truncated:false}:{ready:true});
    assert.equal(result.result.ok,true);assert.equal(result.result.result.items[0].title,'Browser fixture');assert.deepEqual(result.trace.map(call=>call.operation),['browser.open','browser.action','browser.action','browser.close']);
    const denied=await runtime.invoke({operation:'search'},(operation,input)=>{if(operation==='browser.action'&&input.op==='wait')throw new BrokerFailure({code:'browser_budget',message:'Browser budget exceeded.'});return{ready:true};});
    assert.equal(denied.result.error.code,'browser_budget');assert.equal(denied.trace.at(-1).operation,'browser.close');
    await assert.rejects(runtime.invoke({operation:'search',query:'identity'}),/Undeclared source browser host/);
  }finally{await rm(root,{recursive:true,force:true});}
});
