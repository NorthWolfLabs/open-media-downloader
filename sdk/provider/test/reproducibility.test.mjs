import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,cp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {pack} from '../bin/omd-plugin.mjs';

test('pure components and packages reproduce byte-for-byte in different directories', {timeout:180000}, async()=>{
  const temp=await mkdtemp(join(tmpdir(),'omd-reproducibility-'));
  const fixture=fileURLToPath(new URL('../../../tests/v2-provider/',import.meta.url));
  try {
    const builds=[];
    for(const name of ['checkout-one','another checkout']){
      const root=join(temp,name);
      await cp(join(fixture,'src'),join(root,'src'),{recursive:true});
      await cp(join(fixture,'omd-plugin.json'),join(root,'omd-plugin.json'));
      builds.push(await pack(root));
    }
    assert.equal(builds[0].sha256,builds[1].sha256);
    assert.deepEqual(await readFile(builds[0].package),await readFile(builds[1].package));
    assert.deepEqual(await readFile(join(dirname(builds[0].output),'component.mjs.map')),await readFile(join(dirname(builds[1].output),'component.mjs.map')));
  } finally {await rm(temp,{recursive:true,force:true});}
});
