import { defineSource, http, page } from "@northwolf/omd-provider";
let invocations=0;
export default defineSource({
  search(input) {
    invocations++;
    if(input.query==='state')return page([{reference:{provider:'org.example.conformance',id:'state'},title:String(invocations),kind:'manga',canonical_url:'https://example.com/state',description:null,artwork_url:null}]);
    if(input.query==="trap") throw new Error("An intentional author error");
    if(input.query==="loop") { for(;;){} }
    const html=http.html("https://example.com/catalog","metadata");
    return page(html.all("article").map(el=>({reference:{provider:"org.example.conformance",id:el.attr("data-id")!},title:el.one("h2")!.text(),kind:"manga" as const,canonical_url:el.one("a")!.url()!,description:null,artwork_url:null})));
  },
  identify(input){return {kind:"collection",reference:{provider:"org.example.conformance",id:input.url!}};}
});
