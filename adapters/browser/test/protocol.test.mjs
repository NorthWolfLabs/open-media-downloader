import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { frames, validateCommand, MAX_FRAME } from '../protocol.mjs';
test('rejects host execution, ambient navigation, and invalid interactions', () => {
  for (const value of [
    { op: 'evaluate', script: 'process.env' }, { op: 'navigate', url: 'file:///secret' },
    { op: 'navigate', url: 'https://secret@example.com' }, { op: 'pointer', x: 960, y: 2 },
    { op: 'press', key: 'Meta+L' }, { op: 'click', selector: 'a >> internal:control=enter-frame' },
    { op: 'snapshot', path: '/secret' }, { op: 'type', text: 'x'.repeat(16385) },
  ]) assert.throws(() => validateCommand({ id: 1, ...value }));
});
test('preserves UTF-8 across chunks and ordered frames', async () => {
  const input = Buffer.from(JSON.stringify({ id: 1, op: 'type', text: '日本語' }) + '\n' + JSON.stringify({ id: 2, op: 'snapshot' }) + '\n');
  const result = [];
  for await (const value of frames(Readable.from([...input].map(byte => Buffer.from([byte]))))) result.push(value);
  assert.equal(result[0].text, '日本語'); assert.equal(result[1].id, 2);
});
test('bounds input before parsing and rejects unterminated frames', async () => {
  for (const input of [Buffer.alloc(MAX_FRAME + 1, 120), Buffer.from('{"id":1'), Buffer.from([255, 10])]) {
    await assert.rejects(async () => { for await (const _ of frames(Readable.from([input]))) {} });
  }
});
test('accepts bounded origin storage only for exact HTTPS origins', () => {
  const start = { id: 1, op: 'start', executable: '/kit/browser', proxy: 'http://127.0.0.1:9', username: 'a'.repeat(64), spki: 'A'.repeat(43) + '=', url: 'https://fixture.example/', cookies: [] };
  assert.equal(validateCommand({ ...start, origins: [{ origin: 'https://fixture.example', localStorage: [{ name: 'session', value: '{"user":1}' }] }] }).origins.length, 1);
  for (const origins of [
    [], [{ origin: 'http://fixture.example', localStorage: [] }], [{ origin: 'https://fixture.example/path', localStorage: [] }],
    [{ origin: 'https://fixture.example', localStorage: [{ name: '', value: 'x' }] }],
    [{ origin: 'https://fixture.example', localStorage: [{ name: 'a', value: 1 }] }],
    [{ origin: 'https://fixture.example', localStorage: [], script: 'x' }],
    [{ origin: 'https://fixture.example', localStorage: [] }, { origin: 'https://fixture.example', localStorage: [] }],
    Array.from({ length: 17 }, (_, i) => ({ origin: `https://h${i}.example`, localStorage: [] })),
  ]) assert.throws(() => validateCommand({ ...start, origins }));
  assert.deepEqual(validateCommand({ id: 2, op: 'storage' }), { id: 2, op: 'storage' });
  assert.throws(() => validateCommand({ id: 2, op: 'storage', origin: 'https://fixture.example' }));
});
