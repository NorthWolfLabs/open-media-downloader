import {readFile,writeFile} from 'node:fs/promises';
import openapiTS,{astToString} from 'openapi-typescript';
const source=new URL('../../../schemas/v2/openapi.json',import.meta.url);
const document=JSON.parse(await readFile(source,'utf8'));
const types=astToString(await openapiTS(document));
await writeFile(new URL('../src/http.generated.ts',import.meta.url),types);
const methods=new Set(['get','post','put','patch','delete','options','head','trace']);
const entries=Object.entries(document.paths).map(([path,value])=>{
 const denied=Object.entries(value).filter(([method,operation])=>methods.has(method)&&operation['x-omd-scope']==='admin').map(([method])=>JSON.stringify(method));
 const allowed=Object.entries(value).some(([method,operation])=>methods.has(method)&&operation['x-omd-scope']!=='admin');
 if(!allowed)return null;
 return `  ${JSON.stringify(path)}: ${denied.length?`Omit<paths[${JSON.stringify(path)}], ${denied.join(' | ')}>`:`paths[${JSON.stringify(path)}]`};`;
}).filter(Boolean);
await writeFile(new URL('../src/scopes.generated.ts',import.meta.url),'/* Generated from operation authorization. Do not edit. */\nimport type {paths} from "./http.generated.js";\nexport type NormalPaths = {\n'+entries.join('\n')+'\n};\n');
await writeFile(new URL('../openapi.json',import.meta.url),JSON.stringify(document,null,2)+'\n');
