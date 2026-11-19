import { request } from "omd:provider/broker@2.0.0";
import { parseDocument } from "htmlparser2";
import { selectAll, selectOne } from "css-select";
import { textContent, getAttributeValue } from "domutils";
import { isTag, type AnyNode, type Element } from "domhandler";

import type { SourceRef as Reference, Collection, Release, ProviderRequest as Input, ResolvedRelease as Resolved } from "./contracts.js";
export type * from "./contracts.js";
export type { SourceRef as Reference, SelectionPolicy as Policy, ProviderRequest as Input, ResolvedRelease as Resolved } from "./contracts.js";
export interface Page<T> { items: T[]; next_cursor: string | null }
export interface Source {
  discovery?(input: Input): import("./contracts.js").DiscoverySchema | Promise<import("./contracts.js").DiscoverySchema>;
  details?(input: Input): import("./contracts.js").CollectionDetails | Promise<import("./contracts.js").CollectionDetails>;
  artwork?(input: Input): Page<import("./contracts.js").Artwork> | Promise<Page<import("./contracts.js").Artwork>>;
  related?(input: Input): Page<Collection> | Promise<Page<Collection>>;
  recommendations?(input: Input): Page<Collection> | Promise<Page<Collection>>;
  search?(input: Input): Page<Collection> | Promise<Page<Collection>>;
  browse?(input: Input): Page<Collection> | Promise<Page<Collection>>;
  collection?(input: Input): Collection | Promise<Collection>;
  releases?(input: Input): Page<Release> | Promise<Page<Release>>;
  resolve?(input: Input): Resolved | Promise<Resolved>;
  identify?(input: Input): import("./contracts.js").IdentifiedSource | Promise<import("./contracts.js").IdentifiedSource>;
}

export class SourceError extends Error {
  constructor(public code: string, message: string, public retryable = false, public actions: string[] = []) { super(message); }
}
function broker<T>(operation: string, payload: unknown): T {
  try { return JSON.parse(request(operation, JSON.stringify(payload))) as T; }
  catch (error) {
    if (error instanceof SourceError) throw error;
    // ComponentizeJS lifts WIT result errors as ComponentError.payload.
    const payload=typeof error==="string"?error:error&&typeof error==="object"&&"payload" in error?error.payload:null;
    if (typeof payload === "string") {
      let problem: {code?:string;message?:string;retryable?:boolean;actions?:string[]}|null=null;
      try {problem=JSON.parse(payload);}catch{}
      if(problem && typeof problem.code==="string" && typeof problem.message==="string")throw new SourceError(problem.code,problem.message,problem.retryable===true,Array.isArray(problem.actions)?problem.actions:[]);
    }
    throw new SourceError("broker_failed", "The source request failed.", true, ["retry"]);
  }
}
export const http = {
  text(url: string, permission: string, options: {method?:string;headers?:Record<string,string>;body?:string} = {}): string {
    const result = broker<{status:number;body:string}>("http", {url,permission,method:options.method??"GET",headers:options.headers??{},body:options.body??""});
    if (result.status < 200 || result.status >= 300) throw new SourceError(result.status===429?"rate_limited":result.status===401||result.status===403?"authentication_required":"source_http_error", `Source returned HTTP ${result.status}.`,result.status===429||result.status>=500);
    return result.body;
  },
  json<T>(url: string, permission: string, options: {method?:string;headers?:Record<string,string>;body?:string} = {}): T {
    try { return JSON.parse(this.text(url,permission,options)) as T; }
    catch(error) { if(error instanceof SourceError) throw error; throw new SourceError("invalid_json", "The source returned malformed JSON."); }
  },
  html(url: string, permission: string): Html { return new Html(this.text(url,permission),url); },
};
export class Html {
  private nodes: AnyNode[];
  constructor(html: string, public baseUrl: string) { this.nodes = parseDocument(html).children; }
  all(selector: string): HtmlElement[] { return selectAll(selector,this.nodes).filter(isTag).map(e=>new HtmlElement(e,this.baseUrl)); }
  one(selector: string): HtmlElement | null { const element=selectOne(selector,this.nodes);return element&&isTag(element)?new HtmlElement(element,this.baseUrl):null; }
}
export class HtmlElement {
  constructor(private element: Element, private baseUrl: string) {}
  text(): string { return textContent(this.element).replace(/\s+/g," ").trim(); }
  attr(name: string): string | null { return getAttributeValue(this.element,name)?.trim()??null; }
  url(name="href"): string | null { const value=this.attr(name); return value?new URL(value,this.baseUrl).href:null; }
  one(selector:string):HtmlElement|null {const e=selectOne(selector,this.element.children);return e&&isTag(e)?new HtmlElement(e,this.baseUrl):null;}
  all(selector:string):HtmlElement[]{return selectAll(selector,this.element.children).filter(isTag).map(e=>new HtmlElement(e,this.baseUrl));}
}
export interface MediaItem { /** Full extraction proved playable media for the current session. Absent for flat entries. */ accessible?:boolean; id?:string;title?:string;description?:string;duration?:number;view_count?:number;channel_follower_count?:number;timestamp?:number;upload_date?:string;channel?:string;channel_id?:string;uploader?:string;uploader_id?:string;availability?:string|null;live_status?:string;playlist_count?:number;channel_url?:string;webpage_url?:string;thumbnail?:string }
export interface MediaInfo extends MediaItem {kind:"video"|"collection";entries?:MediaItem[];next_cursor?:string|null}
export const media = { inspect(url:string,cursor:string|null=null,pageSize=100):MediaInfo { return broker("media.inspect",{url,cursor,page_size:pageSize}); } };
export interface BrowserSnapshot { url:string;title:string;text:string;links:{text:string;url:string}[];truncated:boolean }
export interface BrowserPage {
  navigate(url:string):void;
  wait(selector:string):void;
  click(selector:string):void;
  fill(selector:string,text:string):void;
  select(selector:string,value:string):void;
  press(key:'Tab'|'Shift+Tab'|'Enter'|'Escape'|'Backspace'|'Delete'|'ArrowUp'|'ArrowDown'|'ArrowLeft'|'ArrowRight'|'Home'|'End'):void;
  snapshot():BrowserSnapshot;
}
/** One bounded browser per source operation. Every request and subresource uses
 * declared source grants. Sign-in authority and cookie export are engine-only. */
export async function withBrowser<T>(url:string,operation:(page:BrowserPage)=>T|Promise<T>):Promise<T> {
  broker('browser.open',{url});
  let closed=false,failed=false;
  const action=<R>(op:string,input:Record<string,unknown>={}):R=>{
    if(closed)throw new SourceError('browser_closed','This browser scope has ended.');
    return broker<R>('browser.action',{op,...input});
  };
  const page:BrowserPage={navigate:url=>action('navigate',{url}),wait:selector=>action('wait',{selector}),click:selector=>action('click',{selector}),fill:(selector,text)=>action('fill',{selector,text}),select:(selector,value)=>action('select',{selector,value}),press:key=>action('press',{key}),snapshot:()=>action<BrowserSnapshot>('snapshot')};
  try{return await operation(page);}catch(error){failed=true;throw error;}
  finally{closed=true;try{broker('browser.close',{});}catch(error){if(!failed)throw error;}}
}
export const log = { info(message:string,fields:Record<string,unknown>={}):void {broker("log",{level:"info",message,fields});} };
export function page<T>(items:T[],nextCursor:string|null=null):Page<T>{return {items,next_cursor:nextCursor};}
export function offset(cursor:string|null):number { const n=Number(cursor??0); if(!Number.isSafeInteger(n)||n<0)throw new SourceError("invalid_cursor","Invalid source cursor.");return n; }
export function defineSource(source:Source):Source{return source;}

// The generated component entrypoint catches author exceptions before a WASM trap
// can erase the actionable error. No raw host credentials or ambient API is exposed.
export async function dispatch(source:Source,payload:string):Promise<string>{
  try {
    const input=JSON.parse(payload) as Input;
    const operation=input.operation;
    if(!["discovery","details","artwork","related","recommendations","search","browse","collection","releases","resolve","identify"].includes(operation))throw new SourceError("unsupported","Unknown source operation.");
    const fn=source[operation as keyof Source];
    if(!fn)throw new SourceError("unsupported","This source does not provide that operation.");
    return JSON.stringify({ok:true,result:await fn(input)});
  } catch (error) {
    const expected = error instanceof SourceError;
    const e = expected ? error : new SourceError("source_error", "The source encountered an unexpected error.", false, ["update_source"]);
    // Only generated coordinates cross the diagnostic boundary. Error messages,
    // function names and stack text can contain source responses or credentials.
    const frames: {line:number;column:number}[] = [];
    if (!expected && error instanceof Error && typeof error.stack === "string") {
      for (const line of error.stack.slice(0, 8192).split("\n").slice(0, 32)) {
        const location = /(?:^|[@(/])provider\.js:(\d+):(\d+)\)?$/.exec(line);
        if (location) {
          const [row,column] = location.slice(1).map(Number);
          if (Number.isSafeInteger(row) && row > 0 && Number.isSafeInteger(column) && column > 0) frames.push({line:row,column});
        }
        if (frames.length === 8) break;
      }
    }
    return JSON.stringify({ok:false,error:{code:e.code,message:e.message,retryable:e.retryable,actions:e.actions},...(frames.length?{diagnostics:{frames}}:{})});
  }
}
