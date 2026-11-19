import createClient from 'openapi-fetch';
import type {Client} from 'openapi-fetch';
import type {paths} from './http.generated.js';
import type {NormalPaths} from './scopes.generated.js';
import {EngineError} from './errors.js';
export type Attachment={endpoint:string;token:string;admin_token?:string};
function endpoint(value:string):string {
  const url=new URL(value);
  if(url.protocol!=='http:'||!['127.0.0.1','[::1]'].includes(url.hostname)||url.username||url.password||url.search||url.hash||url.pathname!=='/')throw new Error('Attach to the loopback endpoint in the engine profile descriptor.');
  return url.origin;
}
function transport<P extends {}>(connection:Attachment,token:string,fetcher?:typeof fetch):Client<P>{
  if(!token)throw new Error('This operation requires a profile authorization token.');
  const client=createClient<P>({baseUrl:endpoint(connection.endpoint),fetch:fetcher,redirect:'error'});
  client.use({
    onRequest({request}){request.headers.set('Authorization',`Bearer ${token}`);return request;},
    async onResponse({response}){
      if(!response.ok){
        let problem;try{problem=await response.json();}catch{}
        if(!problem||typeof problem.code!=='string'||typeof problem.message!=='string')problem={code:'invalid_engine_response',message:'The engine returned an invalid error response.',retryable:true,actions:['reconnect']};
        throw new EngineError(problem,response.status);
      }
      return response;
    },
  });
  return client;
}
/** Typed normal-client operations, generated from the published scope matrix. */
export function createApi(connection:Attachment,fetcher?:typeof fetch):Client<NormalPaths>{return transport<NormalPaths>(connection,connection.token,fetcher);}
/** Deliberate administration boundary; no normal-token fallback. */
export function createAdministrativeApi(connection:Attachment,fetcher?:typeof fetch):Client<paths>{
  if(!connection.admin_token)throw new Error('This client has no administration token.');
  return transport<paths>(connection,connection.admin_token,fetcher);
}
