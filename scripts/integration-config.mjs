// Validates an integration config into an execution plan before any output,
// build or staging work. Public runs need no private checkout; private plugin
// integration is a separate explicit mode.
import {readFile,realpath} from 'node:fs/promises';
import path from 'node:path';

const NAME=/^[a-z0-9][a-z0-9-]{0,63}$/;
const KEYS=new Set(['desktop','plugins','tools','browser_tools','supplements','output','bundle','rust_test_timeout_minutes']);
// Release runtime binaries staged into a bundle. The desktop shell may still be a
// debug development build; these are the packaged engine-side inputs.
// Desktop staging intentionally retains five binaries; standalone includes MCP.
export const RUNTIME_BINARIES=['omd-engine','omd-plugin-worker-v2','omd-helper-guardian','omd-notify','omd-signin','omd'];
export const STANDALONE_BINARIES=[...RUNTIME_BINARIES,'omd-mcp'];

const pin=async directory=>(await readFile(path.join(directory,'.node-version'),'utf8')).trim();

export async function planIntegration(configFile,{engineRoot,nodeVersion=process.version}){
 configFile=await realpath(configFile);
 const base=path.dirname(configFile),config=JSON.parse(await readFile(configFile,'utf8'));
 if(!config||typeof config!=='object'||Array.isArray(config))throw new Error('The integration config must be an object');
 if('providers' in config)throw new Error('"providers" was replaced by "plugins": omit it for a public integration, or use {"mode":"private","sources":[...]} for owner testing');
 for(const key of Object.keys(config))if(!KEYS.has(key))throw new Error(`Unknown integration setting: ${key}`);
 const resolve=value=>{if(typeof value!=='string'||!value)throw new Error('Supply explicit integration paths');return path.resolve(base,value);};
 const enginePin=await pin(engineRoot);
 if(nodeVersion!==`v${enginePin}`)throw new Error(`Run the integration with the pinned Node ${enginePin} (vp exec node), not ${nodeVersion}`);
 const desktop=await realpath(resolve(config.desktop));
 const desktopPin=await pin(desktop);
 if(desktopPin!==enginePin)throw new Error(`The desktop pins Node ${desktopPin}; the engine pins ${enginePin}`);
 const bundle=config.bundle??true;if(typeof bundle!=='boolean')throw new Error('bundle must be true or false');
 const timeout=config.rust_test_timeout_minutes??60;
 if(!Number.isInteger(timeout)||timeout<1||timeout>600)throw new Error('rust_test_timeout_minutes must be an integer from 1 to 600');
 const plugins=config.plugins??{mode:'public'};
 if(!plugins||typeof plugins!=='object'||Object.keys(plugins).some(key=>!['mode','sources'].includes(key)))throw new Error('Invalid plugins setting');
 const mode=plugins.mode;
 if(!['public','private'].includes(mode))throw new Error('plugins.mode must be "public" or "private"');
 const declared=plugins.sources??[];
 if(!Array.isArray(declared)||declared.length>32)throw new Error('plugins.sources must be an array of at most 32 checkouts');
 if(mode==='private'&&!declared.length)throw new Error('A private integration needs at least one plugin source checkout');
 const sources=[],names=new Set;
 for(const source of declared){
  if(!source||typeof source!=='object'||Object.keys(source).some(key=>!['name','path'].includes(key))||!NAME.test(source.name))throw new Error('Each plugin source needs a lowercase name and a path');
  if(names.has(source.name))throw new Error(`Duplicate plugin source: ${source.name}`);
  names.add(source.name);sources.push({name:source.name,root:await realpath(resolve(source.path))});
 }
 // Public plugins must already be reviewed in the desktop's tracked allowlist.
 // The config only selects checkouts; it never authorizes them. Staging verifies
 // the final package digest against the same entry.
 const policy=JSON.parse(await readFile(path.join(desktop,'packaging/public-plugins.json'),'utf8'));
 if(policy?.format!==1||!Array.isArray(policy.plugins)||!Array.isArray(policy.reserved_private_ids))throw new Error('Invalid desktop public plugin policy');
 if(mode==='public')for(const source of sources){
  const entry=policy.plugins.find(item=>item.name===source.name);
  if(!entry)throw new Error(`Plugin ${source.name} is not in the reviewed public allowlist; use plugins.mode "private" for owner testing`);
  const manifest=JSON.parse(await readFile(path.join(source.root,'omd-plugin.json'),'utf8'));
  if(policy.reserved_private_ids.includes(manifest.id))throw new Error(`Private plugin ${manifest.id} cannot join a public integration`);
  if(manifest.id!==entry.id||manifest.version!==entry.version)throw new Error(`Plugin ${source.name} is ${manifest.id} ${manifest.version}; the allowlist reviewed ${entry.id} ${entry.version}`);
  source.allowlisted_sha256=entry.sha256;
 }
 return {
  configFile,desktop,bundle,mode,sources,
  publishable:mode==='public',
  rustTestTimeoutSeconds:timeout*60,
  tools:resolve(config.tools),
  browser:resolve(config.browser_tools),
  supplements:config.supplements===undefined?null:resolve(config.supplements),
  output:resolve(config.output),
 };
}
