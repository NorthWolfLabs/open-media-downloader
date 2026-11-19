import {defineSource,withBrowser,page} from '@northwolf/omd-provider';
export default defineSource({
  async search(input) {
    return withBrowser(input.query==='identity'?'https://identity.example/':'https://fixture.example/',browser=>{
      browser.wait('h1');
      const snapshot=browser.snapshot();
      return page([{reference:{provider:'fixture.browser',id:'one'},kind:'manga' as const,title:snapshot.text,canonical_url:'https://fixture.example/one',description:null,artwork_url:null}]);
    });
  }
});
