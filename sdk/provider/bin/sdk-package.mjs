// A scaffold carries the exact installed SDK, including offline compiler assets.
// npm-compatible deterministic USTAR avoids a registry/sibling-directory dependency.
import {readFile,writeFile,readdir,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
export async function bundleSdk(root,output){
  const manifest=JSON.parse(await readFile(join(root,'package.json'),'utf8'));
  const paths=new Set(['package.json','README.md']);
  async function visit(path){
    if(path.startsWith('/')||path.split('/').some(part=>part==='..'||part==='.'||!part))throw new Error('Invalid SDK package path');
    const info=await lstat(join(root,path));if(info.isSymbolicLink())throw new Error('SDK package assets must not be symlinks');
    if(info.isDirectory()){for(const name of (await readdir(join(root,path))).sort())await visit(`${path}/${name}`);}
    else if(info.isFile())paths.add(path);else throw new Error('SDK package contains an unsupported file');
  }
  for(const path of manifest.files??[])await visit(path);
  const chunks=[];let total=0;
  for(const path of [...paths].sort()){
    const name=`package/${path}`,bytes=await readFile(join(root,path));total+=bytes.length;
    if(Buffer.byteLength(name)>100||total>32*1024*1024)throw new Error('SDK package exceeds its archive budget');
    const header=Buffer.alloc(512);header.write(name);header.write('0000644\0',100);header.write('0000000\0',108);header.write('0000000\0',116);header.write(bytes.length.toString(8).padStart(11,'0')+'\0',124);header.write('00000000000\0',136);header.fill(32,148,156);header.write('0',156);header.write('ustar\0',257);header.write('00',263);
    const checksum=header.reduce((sum,value)=>sum+value,0);header.write(checksum.toString(8).padStart(6,'0')+'\0 ',148);
    chunks.push(header,bytes,Buffer.alloc((512-bytes.length%512)%512));
  }
  chunks.push(Buffer.alloc(1024));await writeFile(output,gzipSync(Buffer.concat(chunks),{level:9}),{flag:'wx'});
  return manifest.version;
}
