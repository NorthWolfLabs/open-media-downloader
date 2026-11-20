import {createApi,createAdministrativeApi} from "./http.js";
import {EngineError} from "./errors.js";
export {EngineError} from "./errors.js";
export {createApi,createAdministrativeApi} from "./http.js";
export type {paths,components,operations} from "./http.generated.js";
export type {NormalPaths} from "./scopes.generated.js";
import type {Event,Problem,ProviderRequest,Collection,Release,SourceRef,IdentifiedSource,Job,Destination,Subscription,SubscribeRequest} from "./models.js";
export type * from "./models.js";
export type Page<T>={items:T[];next_cursor:string|null};
export type Connection={endpoint:string;token:string;admin_token?:string};
export class EngineClient {
  readonly api:ReturnType<typeof createApi>;
  readonly connection:Readonly<Connection>;
  constructor(connection:Connection){this.connection=Object.freeze({...connection});this.api=createApi(this.connection);}
  administrativeApi(){return createAdministrativeApi(this.connection);}
  private url(path:string):string{
    if(!path.startsWith('/v2/')||path.startsWith('//')||path.includes('\\')||path.includes('#'))throw new Error('Use an engine /v2/ API path.');
    const base=new URL(this.connection.endpoint), url=new URL(path,base);
    if(url.origin!==base.origin||!url.pathname.startsWith('/v2/'))throw new Error('Use an engine /v2/ API path.');
    return url.href;
  }
  async request<T>(path:string,options:{method?:string;body?:unknown;admin?:boolean;key?:string;signal?:AbortSignal}={}):Promise<T>{
    if(options.admin&&!this.connection.admin_token)throw new Error('This client has no administration token.');
    const headers:Record<string,string>={Authorization:`Bearer ${options.admin?this.connection.admin_token:this.connection.token}`};
    if(options.body!==undefined)headers["Content-Type"]="application/json";if(options.key)headers["Idempotency-Key"]=options.key;
    const response=await fetch(this.url(path),{redirect:"error",method:options.method??"GET",headers,body:options.body===undefined?undefined:JSON.stringify(options.body),signal:options.signal});
    let value;try{value=await response.json();}catch{throw new EngineError({code:'invalid_engine_response',message:'The engine returned an invalid response.',retryable:true,actions:['reconnect']},response.status);}
    if(!response.ok){if(!value||typeof value.code!=='string'||typeof value.message!=='string')value={code:'invalid_engine_response',message:'The engine returned an invalid error response.',retryable:true,actions:['reconnect']};throw new EngineError(value,response.status);}return value as T;
  }
  async artwork(provider:string,url:string,signal?:AbortSignal):Promise<Blob>{
    const response=await fetch(this.url(`/v2/sources/${encodeURIComponent(provider)}/artwork?${new URLSearchParams({url})}`),{redirect:"error",headers:{Authorization:`Bearer ${this.connection.token}`},signal});
    if(!response.ok)throw new EngineError(await response.json(),response.status);
    const blob=await response.blob();
    if(blob.size>4*1024*1024||!/^image\/(jpeg|png|webp|gif|avif)$/.test(blob.type))throw new Error("Unsupported artwork response.");
    return blob;
  }
  /** Attach a client lease. `finish_downloads` asks the engine, when this is the last
   * client to leave and background operation is off, to finish queued and running
   * downloads before it stops; leave it unset when closing your client should stop them. */
  async attach(options:{finish_downloads?:boolean}={}){return this.request<{id:string;heartbeat_seconds:number;lease_seconds:number;finish_downloads?:boolean|null}>(options.finish_downloads?"/v2/clients?finish_downloads=true":"/v2/clients",{method:"POST"});}
  async heartbeat(id:string){return this.request(`/v2/clients/${encodeURIComponent(id)}`,{method:"POST"});}
  async detach(id:string){return this.request(`/v2/clients/${encodeURIComponent(id)}`,{method:"DELETE"});}
  async operation<T=Page<Collection>|Page<Release>|Collection|IdentifiedSource>(provider:string,input:Partial<Omit<ProviderRequest,"now"|"collection_hint">>&Pick<ProviderRequest,"operation">){return this.request<T>(`/v2/sources/${encodeURIComponent(provider)}/invoke`,{method:"POST",body:{reference:null,query:null,url:null,cursor:null,page_size:100,policy:{},...input}});}
  async jobs(query="",cursor:string|null=null,state?:string){const params=new URLSearchParams({q:query,limit:"100"});if(cursor)params.set("cursor",cursor);if(state)params.set("state",state);return this.request<Page<Job>>(`/v2/jobs?${params}`);}
  async destinations(){return this.request<Page<Destination>>("/v2/destinations");}
  /** Enumerate small configuration lists without silently dropping later pages. */
  async listAll<T>(path:string):Promise<T[]>{
    const items:T[]=[];let cursor:string|null=null;const seen=new Set<string>();
    do {
      const separator=path.includes("?")?"&":"?";
      const page:Page<T>=await this.request<Page<T>>(path+(cursor?`${separator}cursor=${encodeURIComponent(cursor)}`:""));
      items.push(...page.items);cursor=page.next_cursor;
      if(cursor){if(seen.has(cursor))throw new Error("The engine repeated a pagination cursor.");seen.add(cursor);}
    }while(cursor);
    return items;
  }
  async subscribe(request:SubscribeRequest){return this.request<Subscription>("/v2/subscriptions",{method:"POST",body:request});}
  /** Fetch-based SSE supports bearer headers and Last-Event-ID in every shell. */
  async events(cursor:number,onEvent:(event:Event)=>void,onResync:()=>void,signal:AbortSignal):Promise<void>{
    let failures=0;
    while(!signal.aborted){
      try{
        const response=await fetch(this.url("/v2/events"),{redirect:"error",headers:{Authorization:`Bearer ${this.connection.token}`,"Last-Event-ID":String(cursor)},signal});
        if(response.status===409){onResync();return;}
        if(!response.ok||!response.body)throw new Error("The engine event stream is unavailable.");
        failures=0;const reader=response.body.pipeThrough(new TextDecoderStream()).getReader();let buffered="";
        try{for(;;){const{done,value}=await reader.read();if(done)break;buffered+=value.replace(/\r\n/g,"\n");if(buffered.length>1024*1024)throw new Error("The engine event frame exceeded its limit.");let index;while((index=buffered.indexOf("\n\n"))>=0){const frame=buffered.slice(0,index);buffered=buffered.slice(index+2);const lines=frame.split("\n");const name=lines.find(line=>line.startsWith("event:"))?.slice(6).trim();if(name==="resync_required"){onResync();return;}const data=lines.filter(line=>line.startsWith("data:")).map(line=>line.slice(5).trimStart()).join("\n");if(!data)continue;const event=JSON.parse(data) as Event;if(event.id>cursor){onEvent(event);cursor=event.id;}}}}finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
      }catch(error){if(signal.aborted)return;failures++;if(failures===3){onResync();return;}}
      await new Promise<void>(resolve=>{if(signal.aborted){resolve();return;}const timer=setTimeout(done,Math.min(1000*2**Math.min(failures,5),30000));function done(){clearTimeout(timer);signal.removeEventListener("abort",done);resolve();}signal.addEventListener("abort",done,{once:true});});
    }
  }
}
