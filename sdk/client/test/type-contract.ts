import {createApi,createAdministrativeApi} from '../src/http.js';
async function compilerContract(api:ReturnType<typeof createApi>,admin:ReturnType<typeof createAdministrativeApi>){
 const result=await api.GET('/v2/groups/{id}',{params:{path:{id:'group'}}});
 const count:number|undefined=result.data?.total;void count;
 await api.POST('/v2/groups/{id}/{action}',{params:{path:{id:'group',action:'pause'}}});
 // @ts-expect-error Normal clients do not expose administrative installation.
 await api.POST('/v2/sources/install',{body:{package_path:'source.omdp'}});
 // @ts-expect-error Destructive action names outside the public contract are rejected.
 await api.POST('/v2/groups/{id}/{action}',{params:{path:{id:'group',action:'erase'}}});
 // @ts-expect-error Idempotent submission requires a request key header.
 await api.POST('/v2/jobs',{body:{preparation_id:'batch'}});
 await admin.POST('/v2/sources/install',{body:{package_path:'source.omdp'}});
}
void compilerContract;

// Both generated domain models and HTTP responses retain the additive preference.
import type {AccountMode, ProviderManifest, components} from '../src/index.js';
const accountMode: AccountMode = 'cookies';
const domainMode: ProviderManifest['account_mode'] = accountMode;
const httpMode: components['schemas']['ProviderManifest']['account_mode'] = domainMode;
// @ts-expect-error Plugin-specific verification protocols are not connection modes.
const invalidMode: AccountMode = 'org.example.account-check';
void httpMode; void invalidMode;

// The engine sets the collection hint itself, only when it resolves a listed
// release again; the public source operation does not accept it.
import {EngineClient} from '../src/index.js';
async function sourceOperation(engine:EngineClient){
 await engine.operation('org.example.source',{operation:'resolve',reference:{provider:'org.example.source',id:'item'}});
 // @ts-expect-error Clients cannot send the engine-owned collection hint.
 await engine.operation('org.example.source',{operation:'resolve',collection_hint:{provider:'org.example.source',id:'results:demo'}});
}
void sourceOperation;

// Attaching keeps its earlier form; finishing downloads after leaving is opt-in.
async function leases(engine:EngineClient){
 const lease=await engine.attach();
 const finishing=await engine.attach({finish_downloads:true});
 const recorded:boolean|null|undefined=finishing.finish_downloads;
 void lease.lease_seconds; void recorded;
}
void leases;
