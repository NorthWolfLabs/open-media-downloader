import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {cargoTargetDirectory} from './cargo-paths.mjs';

test('Cargo paths honor config and an external target directory',async t=>{
  const root=await realpath(await mkdtemp(path.join(tmpdir(),'omd-cargo-paths-')));
  t.after(()=>rm(root,{recursive:true,force:true}));
  await mkdir(path.join(root,'src'));
  await mkdir(path.join(root,'.cargo'));
  await writeFile(path.join(root,'Cargo.toml'),'[package]\nname="org-example-fixture"\nversion="0.1.0"\nedition="2024"\n[workspace]\n');
  await writeFile(path.join(root,'Cargo.lock'),'version=4\n[[package]]\nname="org-example-fixture"\nversion="0.1.0"\n');
  await writeFile(path.join(root,'src/lib.rs'),'');
  await writeFile(path.join(root,'.cargo/config.toml'),'[build]\ntarget-dir="configured-output"\n');
  const env={...process.env};delete env.CARGO_TARGET_DIR;
  assert.equal(await cargoTargetDirectory(root,env),path.join(root,'configured-output'));
  const external=path.join(root,'external-output');
  assert.equal(await cargoTargetDirectory(root,{...env,CARGO_TARGET_DIR:external}),external);
});
