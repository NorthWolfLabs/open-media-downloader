import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

test('the shipped snapshot transformer has no builder home/volume paths', async()=>{
  const wasm=await readFile(new URL('../build-tool/omd-component-snapshot.wasm',import.meta.url));
  assert.equal(WebAssembly.validate(wasm),true);
  assert.equal(/\/(?:Users|home|Volumes)\/|[A-Z]:[\\/]Users[\\/]/i.test(wasm.toString('latin1')),false);
  const pins=JSON.parse(await readFile(new URL('../build-tool/toolchain.json',import.meta.url),'utf8'));
  assert.equal(createHash('sha256').update(wasm).digest('hex'),pins.snapshot_sha256);
});
