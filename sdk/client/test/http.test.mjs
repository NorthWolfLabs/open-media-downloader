import {test} from 'node:test';import assert from 'node:assert/strict';
import {createApi,createAdministrativeApi,EngineError,EngineClient} from '../.test-build/src/index.js';
const connection={endpoint:'http://127.0.0.1:18181',token:'normal-test-token',admin_token:'admin-test-token'};
test('generated client uses scoped bearer tokens and preserves engine errors',async()=>{
 const seen=[];const fetcher=async request=>{seen.push(request);return new Response(JSON.stringify({active_jobs:2,acquired:3,following:4,attention:0}),{headers:{'content-type':'application/json'}});};
 const client=createApi(connection,fetcher);const result=await client.GET('/v2/summary');assert.equal(result.data.acquired,3);assert.equal(seen[0].headers.get('authorization'),'Bearer normal-test-token');assert.equal(seen[0].redirect,'error');
 await createAdministrativeApi(connection,fetcher).POST('/v2/service/shutdown');assert.equal(seen[1].headers.get('authorization'),'Bearer admin-test-token');
 const failure={code:'destination_unavailable',message:'Reconnect this destination.',retryable:true,actions:['reconnect_destination']};
 const denied=createApi(connection,async()=>new Response(JSON.stringify(failure),{status:409,headers:{'content-type':'application/json'}}));
 await assert.rejects(denied.GET('/v2/destinations/{id}',{params:{path:{id:'disconnected'}}}),error=>error instanceof EngineError&&error.status===409&&error.problem.actions[0]==='reconnect_destination');
 assert.throws(()=>createAdministrativeApi({...connection,admin_token:undefined}),/administration token/);
 for(const endpoint of ['https://example.com','http://localhost:18181','http://127.0.0.1:18181/path','http://user:pass@127.0.0.1:18181'])assert.throws(()=>createApi({...connection,endpoint}),/loopback endpoint/);
});
test('workflow helpers enforce the same endpoint and redirect boundary',async()=>{
 const previous=globalThis.fetch,seen=[];
 globalThis.fetch=async(url,options)=>{seen.push({url,options});return new Response(JSON.stringify({items:[],next_cursor:null}));};
 try{
  const client=new EngineClient(connection);
  await client.request('/v2/jobs');
  assert.equal(seen[0].options.redirect,'error');
  for(const path of ['https://example.com','//example.com/v2/jobs','/v2/../../admin','/v2/\\example.com','/v2/jobs#fragment'])await assert.rejects(client.request(path),/API path/);
  assert.equal(seen.length,1);
  await assert.rejects(new EngineClient({...connection,admin_token:undefined}).request('/v2/service/shutdown',{admin:true}),/administration token/);
  globalThis.fetch=async()=>new Response('SECRET invalid server diagnostics',{status:500});
  await assert.rejects(client.request('/v2/jobs'),e=>e instanceof EngineError&&e.problem.code==='invalid_engine_response'&&!e.message.includes('SECRET'));
 }finally{globalThis.fetch=previous;}
});
test('connection capabilities are captured once and cannot be redirected by callers',async()=>{
 const original={...connection},client=new EngineClient(original),previous=globalThis.fetch,seen=[];
 original.endpoint='https://example.com';original.token='changed';
 globalThis.fetch=async(url,options)=>{seen.push({url,options});return new Response('{}');};
 try{
  assert.throws(()=>{client.connection.endpoint='https://example.com';},TypeError);
  await client.request('/v2/service');
  assert.equal(seen[0].url,'http://127.0.0.1:18181/v2/service');
  assert.equal(seen[0].options.headers.Authorization,'Bearer normal-test-token');
 }finally{globalThis.fetch=previous;}
});
