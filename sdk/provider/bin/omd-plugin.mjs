#!/usr/bin/env node
import { readFile, writeFile, mkdir, realpath } from "node:fs/promises";
import { resolve, dirname, join, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { rolldown } from "rolldown";
import { runOwned } from "./process.mjs";
import {bundleSdk} from "./sdk-package.mjs";
import ts from "typescript";
import {watch as watchFiles} from "node:fs";

const sdkRoot=resolve(dirname(fileURLToPath(import.meta.url)),"..");
export function check(project){
  const source=resolve(project,"src/index.ts");
  const program=ts.createProgram([source,join(sdkRoot,"src/broker.d.ts")],{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,moduleResolution:ts.ModuleResolutionKind.Bundler,strict:true,noEmit:true,skipLibCheck:true,types:[],baseUrl:sdkRoot,paths:{"@northwolf/omd-provider":["src/index.ts"]}});
  const diagnostics=ts.getPreEmitDiagnostics(program);
  if(diagnostics.length)throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics,{getCurrentDirectory:()=>project,getCanonicalFileName:name=>name,getNewLine:()=>"\n"}));
  const checker=program.getTypeChecker();const errors=[];
  const banned=new Set(["fetch","WebSocket","setTimeout","setInterval","process","Buffer","Deno","Bun","window","document","localStorage","navigator","console"]);
  for(const file of program.getSourceFiles()){
    // TypeScript normalizes source paths to forward slashes on Windows, while
    // node:path.resolve uses native separators. Compare path components, not a
    // raw prefix (which also incorrectly includes a sibling named project-old).
    const within=relative(resolve(project),resolve(file.fileName));
    if(file.isDeclarationFile||isAbsolute(within)||within==='..'||within.replaceAll('\\','/').startsWith('../'))continue;
    const visit=node=>{
      if(ts.isIdentifier(node)&&banned.has(node.text)){
        const symbol=checker.getSymbolAtLocation(node);const declarations=symbol?.declarations??[];
        if(!declarations.length||declarations.every(d=>d.getSourceFile().isDeclarationFile)){
          const pos=file.getLineAndCharacterOfPosition(node.getStart());errors.push(`${file.fileName}:${pos.line+1}:${pos.character+1}: ${node.text} is ambient host access. Use the OMD SDK broker.`);
        }
      }
      if(ts.isPropertyAccessExpression(node)&&((node.expression.getText()==="Math"&&node.name.text==="random")||(node.expression.getText()==="Date"&&node.name.text==="now")))errors.push(`${file.fileName}: Ambient randomness and clocks are unavailable. Use the operation's provided context.`);
      ts.forEachChild(node,visit);
    };visit(file);
  }
  if(errors.length)throw new Error(errors.join("\n"));
}
export async function build(project){
  const root=await realpath(resolve(project));
  check(root);
  const manifest=JSON.parse(await readFile(join(root,"omd-plugin.json"),"utf8"));
  if(manifest.api!=="omd:provider@2.0.0")throw new Error("Expected a v2 TypeScript provider manifest.");
  const cache=join(root,".omd-build");await mkdir(cache,{recursive:true});
  const entry=join(cache,"entry.mjs");
  await writeFile(entry,`import source from ${JSON.stringify(join(root,"src/index.ts"))};\nimport { dispatch } from ${JSON.stringify(join(sdkRoot,"src/index.ts"))};\nexport function invoke(payload){return dispatch(source,payload);}\n`);
  const bundle=await rolldown({input:entry,external:["omd:provider/broker@2.0.0"],platform:"browser",resolve:{alias:{"@northwolf/omd-provider":join(sdkRoot,"src/index.ts")}},plugins:[{name:"no-ambient-apis",resolveId(id){if(id.startsWith("node:")||["fs","path","net","http","https","child_process","os","worker_threads"].includes(id))throw new Error(`Unsupported ambient dependency ${id}. Use OMD broker APIs.`);}}]});
  const bundled=join(cache,"component.mjs");await bundle.write({file:bundled,format:"esm",sourcemap:true,minify:true});await bundle.close();
  // Keep local diagnostic maps independent of checkout location. Never include
  // source text, external absolute paths or dependency source in the author map.
  const map=JSON.parse(await readFile(`${bundled}.map`,"utf8"));
  map.sources=map.sources.map(source=>{
    const path=relative(root,resolve(cache,source)).replaceAll('\\','/');
    return !isAbsolute(path)&&path.startsWith('src/')&&!path.split('/').includes('..')?path:'<dependency>';
  });
  delete map.sourcesContent;delete map.sourceRoot;map.names=map.names.map(()=>'');
  const sourceMap=JSON.stringify(map);await writeFile(`${bundled}.map`,sourceMap);
  const output=join(cache,"plugin.wasm");
  await runOwned(process.execPath,["--experimental-import-meta-resolve","--disable-warning=ExperimentalWarning",join(sdkRoot,"bin/componentize-deterministic.mjs"),bundled,output],{timeout:180000,maxBuffer:4*1024*1024});
  const component=await readFile(output);
  const sha256=createHash("sha256").update(component).digest("hex");
  await writeFile(join(cache,"build.json"),JSON.stringify({api:manifest.api,id:manifest.id,sha256,bytes:component.length,source_map_sha256:createHash("sha256").update(sourceMap).digest("hex")},null,2)+"\n");
  return {output,sha256,bytes:component.length};
}

export async function pack(project){
  const result=await build(project);const root=await realpath(resolve(project));
  const manifest=await readFile(join(root,"omd-plugin.json"));
  const header=Buffer.alloc(10);header.write("OMDP2\0");header.writeUInt32LE(manifest.length,6);
  const output=join(root,".omd-build","provider.omdp");
  await writeFile(output,Buffer.concat([header,manifest,await readFile(result.output)]));
  return {...result,package:output};
}

export async function scaffold(project,id,host){
  if(!/^[a-z0-9]+(?:[.-][a-z0-9]+)+$/.test(id??""))throw new Error("Choose a namespaced provider ID such as org.example.source.");
  const origin=new URL(host);if(origin.protocol!=="https:"||origin.username||origin.password||origin.pathname!=="/"||origin.search)throw new Error("Supply the source's HTTPS origin, such as https://example.com.");
  const root=resolve(project);await mkdir(root);await mkdir(join(root,"src"));
  await writeFile(join(root,"omd-plugin.json"),JSON.stringify({api:"omd:provider@2.0.0",id,name:origin.hostname,version:"0.1.0",description:"A source adapter for "+origin.hostname,source_hosts:[origin.hostname],capabilities:["identify"],grants:[],media_tools:false,browser:false},null,2)+"\n");
  await writeFile(join(root,"src/index.ts"),`import {defineSource,SourceError} from "@northwolf/omd-provider";\n\nexport default defineSource({\n  identify(input) {\n    const url=new URL(input.url??"");\n    if(url.origin!==${JSON.stringify(origin.origin)})throw new SourceError("invalid_url","This URL belongs to another source.");\n    return {kind:"collection",reference:{provider:${JSON.stringify(id)},id:url.pathname}};\n  }\n});\n`);
  const version=JSON.parse(await readFile(join(sdkRoot,"package.json"),"utf8")).version;
  const archive=`northwolf-omd-provider-${version}.tgz`;
  await mkdir(join(root,"vendor"));await bundleSdk(sdkRoot,join(root,"vendor",archive));
  await writeFile(join(root,"package.json"),JSON.stringify({name:id,version:"0.1.0",private:true,type:"module",scripts:{check:"omd-plugin check .",build:"omd-plugin build .",watch:"omd-plugin watch .",pack:"omd-plugin pack ."},devDependencies:{"@northwolf/omd-provider":`file:vendor/${archive}`}},null,2)+"\n");
  await writeFile(join(root,".gitignore"),"node_modules/\n.omd-build/\n");
  return {root,operations:["identify"],next:"Run vp install, then implement the source operations you need and declare each capability and network grant in omd-plugin.json."};
}
export async function watch(project){
  const root=await realpath(resolve(project));let timer;let building=false;let again=false;
  const rebuild=async()=>{if(building){again=true;return;}building=true;try{console.log(JSON.stringify(await build(root)));}catch(error){console.error(error.message);}finally{building=false;if(again){again=false;void rebuild();}}};
  const watcher=watchFiles(join(root,"src"),{recursive:true},()=>{clearTimeout(timer);timer=setTimeout(rebuild,150);});
  const manifest=watchFiles(join(root,"omd-plugin.json"),()=>{clearTimeout(timer);timer=setTimeout(rebuild,150);});
  await rebuild();console.log("Watching provider source and manifest. Press Ctrl+C to stop.");
  await new Promise(resolve=>process.once("SIGINT",resolve));watcher.close();manifest.close();clearTimeout(timer);
}

// Do not await the command at module scope: the fixture runner imports build
// from this module. Awaiting its dynamic import during evaluation deadlocks
// `omd-plugin test` while direct imports of the runner appear to work.
async function main(){
  try{
    if(!process.argv[1]||await realpath(process.argv[1]).catch(()=>resolve(process.argv[1]))!==fileURLToPath(import.meta.url))return;
    const [command,project=".",id,host]=process.argv.slice(2);
    if(!["new","watch","check","build","pack","test"].includes(command))throw new Error("Usage: omd-plugin new <directory> <provider-id> <https-origin> | <check|build|watch|pack|test> <directory>");
    if(command==="new")console.log(JSON.stringify(await scaffold(project,id,host),null,2));
    else if(command==="test"){const {testFixtures}=await import("./testing.mjs");console.log(JSON.stringify(await testFixtures(project),null,2));}
    else if(command==="watch")await watch(project);
    else if(command==="check"){check(project);console.log("Provider types and ambient-API checks passed.");}
    else console.log(JSON.stringify(await (command==="pack"?pack:build)(project),null,2));
  }catch(error){console.error(error.message);process.exitCode=1;}
}
void main();
