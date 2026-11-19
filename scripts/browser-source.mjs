import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

// Staging checks an artifact against its inventory. A source integration must
// additionally reject a self-consistent kit built from an older OMD adapter.
export async function verifyBrowserSource(manifestFile, sourceDirectory) {
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  if (typeof manifest.adapter !== 'string' || path.isAbsolute(manifest.adapter) ||
      manifest.adapter.split(/[\\/]/).some(part => part === '..'))
    throw new Error('Invalid browser adapter path');
  const root = path.resolve(path.dirname(manifestFile), manifest.root);
  const protocol = path.posix.join(path.posix.dirname(manifest.adapter), 'protocol.mjs');
  const verified = [];
  const directory = path.posix.dirname(manifest.adapter);
  const inputs = [[manifest.adapter, 'adapter.mjs'], [protocol, 'protocol.mjs'], ...['package.json', 'package-lock.json', 'LICENSE'].map(name => [path.posix.join(directory, name), name])];
  for (const [packaged, source] of inputs) {
    const expected = digest(await readFile(path.join(sourceDirectory, source)));
    const actual = await readFile(path.resolve(root, packaged));
    if (digest(actual) !== expected || manifest.files?.[packaged]?.sha256 !== expected ||
        manifest.files?.[packaged]?.bytes !== actual.length)
      throw new Error(`Browser kit has stale or mismatched ${source}; rebuild its immutable inventory from the current adapters/browser sources`);
    verified.push({path: packaged, sha256: expected});
  }
  return verified;
}
