// Runs in a separate build process. None of these build-time shims enter OMD's
// engine or a source worker. Author code is still compiled into a pure component.
import {readFile,writeFile,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {dirname,basename,join} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {WASI} from 'node:wasi';

const upstream=fileURLToPath(import.meta.resolve('@bytecodealliance/componentize-js'));
const source=await readFile(upstream,'utf8');
const toolchain=JSON.parse(await readFile(new URL('../build-tool/toolchain.json',import.meta.url),'utf8'));
if(createHash('sha256').update(source).digest('hex')!==toolchain.componentizer_sha256)throw new Error('The pinned ComponentizeJS compiler changed. Review and rebuild the OMD toolchain.');
const resolveCompiler=specifier=>import.meta.resolve(specifier,pathToFileURL(upstream).href);
const {wallClock,monotonicClock}=await import(resolveCompiler('@bytecodealliance/preview2-shim/clocks'));
const {random}=await import(resolveCompiler('@bytecodealliance/preview2-shim/random'));
wallClock.now=()=>({seconds:0n,nanoseconds:0});
monotonicClock.now=()=>0n;
random.getRandomBytes=len=>new Uint8Array(Number(len));

function replaceOnce(text,from,to){if(text.split(from).length!==2)throw new Error('ComponentizeJS patch no longer applies exactly.');return text.replace(from,to);}
let adapted=replaceOnce(source,
  'let args = `--initializer-script-path ${initializerPath} --strip-path-prefix ${workspacePrefix}/ ${sourcePath}`;',
  'let args = `--initializer-script-path /omd-internal/initializer.js --strip-path-prefix / ${sourcePath}`;');
adapted=replaceOnce(adapted,'let preopens = [`--dir=${sourcesDir}`];','let preopens = [`--mapdir=/omd-internal::${sourcesDir}`];');
adapted=replaceOnce(adapted,'const wizerBin = opts.wizerBin ?? wizer;','await opts.beforeWizer(inputWasmPath);\n  const wizerBin = opts.wizerBin ?? wizer;');
adapted=adapted.replace(/import\.meta\.url/g,JSON.stringify(pathToFileURL(upstream).href));
adapted=adapted.replace(/from (['"])([^'"]+)\1/g,(match,quote,specifier)=>{
  const url=specifier.startsWith('node:')?specifier:specifier.startsWith('.')?new URL(specifier,pathToFileURL(upstream)).href:resolveCompiler(specifier);
  return `from ${JSON.stringify(url)}`;
});
const {componentize}=await import(`data:text/javascript;base64,${Buffer.from(adapted).toString('base64')}`);
const transformer=await readFile(new URL('../build-tool/omd-component-snapshot.wasm',import.meta.url));
if(createHash('sha256').update(transformer).digest('hex')!==toolchain.snapshot_sha256)throw new Error('The OMD snapshot build tool failed integrity verification.');
const module=await WebAssembly.compile(transformer);
const beforeWizer=async path=>{
  const output=path+'.deterministic';
  const wasi=new WASI({version:'preview1',args:['omd-component-snapshot',`/build/${basename(path)}`,`/build/${basename(output)}`],env:{},preopens:{'/build':dirname(path)},returnOnExit:true});
  const instance=await WebAssembly.instantiate(module,{wasi_snapshot_preview1:wasi.wasiImport});
  if(wasi.start(instance)!==0)throw new Error('The deterministic snapshot transform failed.');
  await rename(output,path);
};
const [input,output]=process.argv.slice(2);
if(!input||!output)throw new Error('Expected a bundled module and output component path.');
const {component}=await componentize(await readFile(input,'utf8'),{
  sourceName:'provider.js',witPath:fileURLToPath(new URL('../wit',import.meta.url)),worldName:'provider',
  disableFeatures:['random','stdio','clocks','http','fetch-event'],env:{},beforeWizer,
});
await writeFile(output,component);
