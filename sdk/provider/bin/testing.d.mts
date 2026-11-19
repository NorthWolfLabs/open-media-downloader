import type {ProviderRequest, Problem} from '../src/contracts.js';
export type BrokerRequest = {url?:string;permission?:string;method?:string;headers?:Record<string,string>;body?:string;[key:string]:unknown};
export type BrokerTrace = {operation:string;request:BrokerRequest;response?:unknown;error?:Problem};
export type SourceResult<T> = {ok:true;result:T}|{ok:false;error:Problem};
export type SourceLocation = {source:string;line:number;column:number};
export function harness(project:string,options?:{worker?:string;component?:string}):Promise<{
  invoke<T=unknown>(input:Partial<ProviderRequest>&Pick<ProviderRequest,'operation'>,broker?:(operation:string,request:BrokerRequest,index:number)=>unknown|Promise<unknown>):Promise<{result:SourceResult<T>;trace:BrokerTrace[];diagnostics:SourceLocation[]}>;
}>;
export function testFixtures(project:string,options?:{worker?:string;component?:string}):Promise<{fixture:string;status:'passed';broker_calls:number}[]>;

export class BrokerFailure extends Error {constructor(problem:Problem);problem:Problem;}
export function redactFixture<T>(value:T,secrets?:string[]):T;
export function recordFixture(runtime:Awaited<ReturnType<typeof harness>>,input:Partial<ProviderRequest>&Pick<ProviderRequest,"operation">,broker:(operation:string,request:BrokerRequest,index:number)=>unknown|Promise<unknown>,output:string,options?:{secrets?:string[]}):Promise<{output:string;broker_calls:number}>;
