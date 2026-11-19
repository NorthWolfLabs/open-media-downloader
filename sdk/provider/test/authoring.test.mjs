import {test} from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm,symlink} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {scaffold,check} from "../bin/omd-plugin.mjs";
test("a scaffold has only its implemented capability and type checks",async()=>{
  const root=await mkdtemp(join(tmpdir(),"omd-author-test-"));const project=join(root,"source");
  try{await scaffold(project,"org.example.source","https://example.com");assert.deepEqual(JSON.parse(await readFile(join(project,"omd-plugin.json"),"utf8")).capabilities,["identify"]);const packageJson=JSON.parse(await readFile(join(project,'package.json'),'utf8'));assert.match(packageJson.devDependencies['@northwolf/omd-provider'],/^file:vendor\//);assert.ok((await readFile(join(project,packageJson.devDependencies['@northwolf/omd-provider'].slice(5)))).length>1000);assert.doesNotThrow(()=>check(project));await assert.rejects(scaffold(project,"org.example.source","https://example.com"));}finally{await rm(root,{recursive:true});}
});
test("ambient network access fails at build time",async()=>{
  const root=await mkdtemp(join(tmpdir(),"omd-author-test-"));const project=join(root,"source");
  try{await scaffold(project,"org.example.source","https://example.com");await writeFile(join(project,"src/index.ts"),'import {defineSource} from "@northwolf/omd-provider"; export default defineSource({async identify(){await fetch("https://example.com");return {kind:"collection",reference:{provider:"org.example.source",id:"a"}};}});');assert.throws(()=>check(project),/ambient host access/);}finally{await rm(root,{recursive:true});}
});
test("installed binary symlinks execute the authoring command",async()=>{
  const root=await mkdtemp(join(tmpdir(),"omd-author-bin-"));const project=join(root,"source");
  try {
    await scaffold(project,"org.example.source","https://example.com");
    const bin=join(root,"omd-plugin");await symlink(fileURLToPath(new URL("../bin/omd-plugin.mjs",import.meta.url)),bin);
    const result=spawnSync(process.execPath,[bin,"check",project],{encoding:"utf8"});
    assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/Provider types and ambient-API checks passed/);
  }finally{await rm(root,{recursive:true});}
});
