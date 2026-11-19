import {readFile,stat} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {SourceMap} from 'node:module';
import {createHash} from 'node:crypto';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');

/** Maps only the exact local build. Installed packages need no map or source. */
export async function diagnosticsFor(component){
  let map;
  try{
    const directory=dirname(component),path=join(directory,'component.mjs.map');
    if((await stat(path)).size>16*1024*1024||(await stat(component)).size>64*1024*1024)return ()=>[];
    const build=JSON.parse(await readFile(join(directory,'build.json'),'utf8'));
    const bytes=await readFile(path);
    if(hash(bytes)!==build.source_map_sha256||hash(await readFile(component))!==build.sha256)return ()=>[];
    map=new SourceMap(JSON.parse(bytes));
  }catch{return ()=>[];}
  return result=>{
    const mapped=[];
    for(const frame of (Array.isArray(result?.diagnostics?.frames)?result.diagnostics.frames:[]).slice(0,8)){
      if(!Number.isSafeInteger(frame.line)||frame.line<1||!Number.isSafeInteger(frame.column)||frame.column<1)continue;
      const origin=map.findOrigin(frame.line,frame.column);
      const source=origin.fileName;
      if(typeof source!=='string'||!/^src\/[A-Za-z0-9_./ -]+\.(?:[cm]?[jt]sx?)$/.test(source)||source.split('/').includes('..'))continue;
      if(!Number.isSafeInteger(origin.lineNumber)||origin.lineNumber<1||!Number.isSafeInteger(origin.columnNumber)||origin.columnNumber<1)continue;
      const location={source,line:origin.lineNumber,column:origin.columnNumber};
      if(!mapped.some(previous=>JSON.stringify(previous)===JSON.stringify(location)))mapped.push(location);
    }
    return mapped;
  };
}
