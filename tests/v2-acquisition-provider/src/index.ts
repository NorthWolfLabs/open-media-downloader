import {defineSource, type Collection, type Reference, type Release} from '@northwolf/omd-provider';
const provider='org.example.acquisition';
const reference={provider,id:'fixture-series'};
const collection:Collection={reference,title:'Durable collection fixture',kind:'manga',canonical_url:'https://example.com/fixture-series',description:'401 deterministic releases; two English chapters and 399 Japanese chapters.',artwork_url:null};
// Search-results and playlist collections (`results:<n>`, `playlist:<n>`) list
// chapters n and n+1, which this source files under its one canonical series.
// When the engine resolves a listed chapter again, `results:` collections keep it
// where it was listed by returning the engine's collection hint (the manifest
// declares the `collection_hint` capability); `playlist:` collections ignore the
// hint, as a source written before the hint existed does.
const listed=(id:string|undefined)=>!!id&&(id.startsWith('results:')||id.startsWith('playlist:'));
function listing(reference:Reference):Collection{return {reference,title:reference.id.startsWith('results:')?'Search results fixture':'Playlist fixture',kind:'playlist',canonical_url:'https://example.com/list/'+encodeURIComponent(reference.id),description:null,artwork_url:null};}
function release(n:number):Release{return {reference:{provider,id:`release-${n}`},collection:reference,title:`Chapter ${n}`,canonical_url:`https://example.com/chapter/${n}`,chapter:String(n),volume:null,language:n<2?'en':'ja',group:'Fixture group',published_at:'2026-01-01T00:00:00Z',revision:'1',availability:'available',unavailable_reason:null,position:n};}
export default defineSource({
  identify(){return {kind:'collection',reference};},
  collection(input){if(listed(input.reference?.id))return listing(input.reference!);if(input.reference?.id.startsWith("artist:"))return {...collection,reference:input.reference,kind:"channel",title:"Fixture artist",summary:{profile:"artist"}};return collection;},
  search(){return {items:[collection],next_cursor:null};},
  releases(input){if(listed(input.reference?.id)){const first=Number(input.reference!.id.split(':')[1]);return {items:[first,first+1].map(n=>({...release(n),collection:input.reference!})),next_cursor:null};}if(input.reference?.id.startsWith("artist:"))return {items:[{...release(0),reference:{provider,id:"image-multipage"},collection:input.reference,title:"Multi-image post",language:null,group:null,chapter:null}],next_cursor:null};const start=Number(input.cursor??0);const end=Math.min(start+input.page_size,401);return {items:Array.from({length:end-start},(_,i)=>release(start+i)),next_cursor:end<401?String(end):null};},
  resolve(input){
    if(input.reference!.id.startsWith('image-')) {
      const reference=input.reference!, c:Collection={reference,title:reference.id,kind:'item',canonical_url:'https://example.com/'+reference.id,summary:{image:{release_id:reference.id,count:reference.id === "image-multipage" ? 2 : 1,width:1200,height:900}}};
      const r:Release={...release(0),reference,collection:reference,title:reference.id,language:null,chapter:null,group:null};
      return {collection:c,release:r,expires_at:null,resources:Array.from({length:reference.id === 'image-multipage' ? 2 : 1},(_,i)=>({id:`original-${i}`,position:i,role:'page',media_type:'image/png',expected_size:null,expected_sha256:null,locator:{kind:'http' as const,url:'https://example.com/image.png',permission:'images',headers:{},credential_profile:null}}))};
    }
    const n=Number(input.reference!.id.slice(8));
    const hint=input.collection_hint, parent=hint?.id.startsWith('results:')?listing(hint):collection;
    return {release:{...release(n),collection:parent.reference},collection:parent,expires_at:null,resources:[{id:'page-1',position:0,role:'image',media_type:'image/png',expected_size:null,expected_sha256:null,locator:{kind:'http',url:'https://example.com/fixture.png',permission:'images',headers:{},credential_profile:null}}]};}
});
