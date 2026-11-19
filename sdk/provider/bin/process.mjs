// Build-time process ownership. Provider execution remains in the Rust worker.
import { spawn } from 'node:child_process';
import {resolve,join,delimiter,isAbsolute} from 'node:path';
import {accessSync,constants} from 'node:fs';
import {fileURLToPath} from 'node:url';
function executable(program,cwd){
  if(isAbsolute(program)||program.includes('/')||program.includes('\\'))return resolve(cwd??process.cwd(),program);
  const suffixes=process.platform==='win32'&&!program.toLowerCase().endsWith('.exe')?['.exe','']:[''];
  for(const directory of (process.env.PATH??process.env.Path??'').split(delimiter))for(const suffix of suffixes){
    const candidate=resolve(directory,program+suffix);try{accessSync(candidate,constants.X_OK);return candidate;}catch{}
  }
  throw new Error('The requested build tool is unavailable. Set its absolute path or add it to PATH.');
}
export function ownedProcess(program,args,options={}) {
  program=executable(program,options.cwd);
  let command=program,parameters=args,environment=options.env??process.env;
  if(process.platform==='win32'){
    const systemRoot=process.env.SystemRoot??process.env.SYSTEMROOT;
    if(!systemRoot)throw new Error('Windows process ownership requires SystemRoot and Windows PowerShell.');
    command=join(systemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
    parameters=['-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',fileURLToPath(new URL('./windows-job.ps1',import.meta.url))];
    environment={...process.env,OMD_BUILD_REQUEST:JSON.stringify({program:resolve(program),arguments:args,directory:resolve(options.cwd??process.cwd()),environment:options.env??null,parent_process_id:process.pid})};
  }
  const child=spawn(command,parameters,{cwd:options.cwd,env:environment,stdio:['pipe','pipe','pipe'],detached:process.platform!=='win32',windowsHide:true});
  let cleaning;
  function stop() {
    if(cleaning)return cleaning;
    cleaning=new Promise(resolve=>{
      if(!child.pid){resolve();return;}
      if(process.platform==='win32'){child.kill('SIGKILL');resolve();}
      else {try{process.kill(-child.pid,'SIGKILL');}catch{}resolve();}
    });
    return cleaning;
  }
  return {child,stop};
}
export async function runOwned(program,args,{timeout=180000,maxBuffer=4*1024*1024,...options}={}) {
  const {child,stop}=ownedProcess(program,args,options);let stdout='',stderr='',size=0;
  let timedOut=false,overBudget=false;
  const timer=setTimeout(()=>{timedOut=true;void stop();},timeout);
  const abort=()=>void stop();process.once('SIGINT',abort);process.once('SIGTERM',abort);
  child.stdout.setEncoding('utf8');child.stderr.setEncoding('utf8');
  const capture=(kind,chunk)=>{size+=Buffer.byteLength(chunk,'utf8');if(size>maxBuffer){overBudget=true;void stop();return;}if(kind==='stdout')stdout+=chunk;else stderr+=chunk;};
  child.stdout.on('data',chunk=>capture('stdout',chunk));child.stderr.on('data',chunk=>capture('stderr',chunk));child.stdin.end();
  try {
    const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',resolve);});
    if(timedOut)throw new Error('The provider compiler exceeded its time limit. Its process tree was stopped.');
    if(overBudget)throw new Error('The provider compiler exceeded its diagnostic limit.');
    if(code!==0)throw new Error(stderr||'The provider compiler was interrupted.');
    return {stdout,stderr};
  } finally {clearTimeout(timer);process.removeListener('SIGINT',abort);process.removeListener('SIGTERM',abort);await stop();child.stdout.destroy();child.stderr.destroy();}
}
