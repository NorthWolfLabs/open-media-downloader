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
