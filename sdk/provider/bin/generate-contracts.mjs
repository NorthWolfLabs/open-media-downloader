import { readFile, writeFile } from "node:fs/promises";
import { compile } from "json-schema-to-typescript";
const schema = JSON.parse(await readFile(new URL("../../../schemas/v2/domain.json", import.meta.url), "utf8"));
const types=await compile(schema,"Contracts",{additionalProperties:false,unreachableDefinitions:true,bannerComment:"/* Generated from the Rust domain schema. Do not edit by hand. */"});
await writeFile(new URL("../src/contracts.ts", import.meta.url),types);
await writeFile(new URL("../../client/src/models.ts", import.meta.url),types);
