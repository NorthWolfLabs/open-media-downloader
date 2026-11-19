import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { verifyBrowserSource } from './browser-source.mjs';

for (const state of ['current', 'old-but-self-consistent', 'inventory-does-not-match-bytes', 'old-package-lock']) {
  test(`source integration checks browser kit: ${state}`, async t => {
    const root = await mkdtemp(path.join(tmpdir(), 'omd-browser-source-'));
    t.after(() => rm(root, {recursive: true, force: true}));
    await mkdir(path.join(root, 'source'));
    await mkdir(path.join(root, 'kit/adapter'), {recursive: true});
    const manifest = {root: 'kit', adapter: 'adapter/adapter.mjs', files: {}};
    for (const name of ['adapter.mjs', 'protocol.mjs', 'package.json', 'package-lock.json', 'LICENSE']) {
      const current = `// current ${name}\n`;
      const packaged = (state === 'old-but-self-consistent' && name === 'adapter.mjs') || (state === 'old-package-lock' && name === 'package-lock.json') ? '// old source\n' : current;
      const bytes = state === 'inventory-does-not-match-bytes' && name === 'protocol.mjs' ? '// changed protocol\n' : packaged;
      await writeFile(path.join(root, 'source', name), current);
      await writeFile(path.join(root, 'kit/adapter', name), bytes);
      manifest.files[`adapter/${name}`] = {sha256: createHash('sha256').update(packaged).digest('hex'), bytes: Buffer.byteLength(packaged)};
    }
    const input = path.join(root, 'manifest.json');
    await writeFile(input, JSON.stringify(manifest));
    if (state === 'current') assert.equal((await verifyBrowserSource(input, path.join(root, 'source'))).length, 5);
    else await assert.rejects(verifyBrowserSource(input, path.join(root, 'source')), /stale or mismatched/);
  });
}
