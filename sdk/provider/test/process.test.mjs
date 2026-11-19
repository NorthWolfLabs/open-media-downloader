import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runOwned} from '../bin/process.mjs';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function alive(pid){try{process.kill(pid,0);return true;}catch{return false;}}
test('compiler capture drains UTF-8 split across writes and enforces byte limits',async()=>{
  const text='日本語 🌱';
  const result=await runOwned(process.execPath,['-e',`const b=Buffer.from(${JSON.stringify(text)});let i=0;const t=setInterval(()=>{process.stdout.write(b.subarray(i,i+1));if(++i===b.length)clearInterval(t)},1);`]);assert.equal(result.stdout,text);
  await assert.rejects(runOwned(process.execPath,['-e',`process.stdout.write('界'.repeat(10000));`],{maxBuffer:20000}),/diagnostic limit/);
});
test('compiler timeout owns descendants even after their parent exits',{timeout:20000},async()=>{
  const root=await mkdtemp(join(tmpdir(),'omd-compiler-tree-'));const pidfile=join(root,'child.pid');let pid;
  try{
    const childCode=`require('node:fs').writeFileSync(${JSON.stringify(pidfile)},String(process.pid));setInterval(()=>{},1000);`;
    const parentCode=`require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(childCode)}],{stdio:['ignore','inherit','inherit']}).unref();const ready=setInterval(()=>{if(require('node:fs').existsSync(${JSON.stringify(pidfile)})){clearInterval(ready);process.exit(0)}},5);`;
    try{await runOwned(process.execPath,['-e',parentCode],{timeout:process.platform==='win32'?10000:1000});}catch(error){assert.match(error.message,/time limit/);}
    pid=Number(await readFile(pidfile,'utf8'));
    for(let attempt=0;attempt<100&&alive(pid);attempt++)await pause(20);
    assert.equal(alive(pid),false,'compiler grandchild survived its operation');
  }finally{if(pid&&alive(pid))process.kill(pid,'SIGKILL');await rm(root,{recursive:true});}
});
