/**
 * Regression test atomic JSON write di Windows:
 * - rename sementara EPERM/EACCES/EBUSY di-retry lalu berhasil
 * - error permanen langsung dilempar tanpa retry
 * - kegagalan total tidak menghapus file tujuan dan membersihkan temp
 * - writer registry memakai jalur retry yang sama
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { writeJsonAtomicSync } from '../src/atomicWrite.ts';
import { writeEndpointRecords } from '../src/endpointStore.ts';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-atomic-'));
const target = path.join(dir, 'state.json');
const results = [];

function check(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`PASS  ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`FAIL  ${name} — ${error?.message || error}`);
  }
}

function tempFiles() {
  return fs.readdirSync(dir).filter(name => name.endsWith('.tmp'));
}

const realRename = fs.renameSync;
function failRename(times, code) {
  let calls = 0;
  fs.renameSync = (source, destination) => {
    calls += 1;
    if (calls <= times) throw Object.assign(new Error(`${code}: simulasi`), { code });
    return realRename(source, destination);
  };
  return () => { fs.renameSync = realRename; return calls; };
}

fs.writeFileSync(target, JSON.stringify({ value: 'lama' }));

let restore = failRename(2, 'EPERM');
check('rename EPERM sementara di-retry sampai berhasil', () => {
  writeJsonAtomicSync(target, { value: 'baru' });
  assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf-8')), { value: 'baru' });
  assert.equal(tempFiles().length, 0);
});
let calls = restore();
check('retry berhenti setelah berhasil', () => assert.equal(calls, 3));

fs.writeFileSync(target, JSON.stringify({ value: 'stabil' }));
restore = failRename(99, 'ENOENT');
check('error permanen ENOENT dilempar tanpa retry dan file tujuan tetap', () => {
  assert.throws(() => writeJsonAtomicSync(target, { value: 'gagal' }), /ENOENT/);
  assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf-8')), { value: 'stabil' });
  assert.equal(tempFiles().length, 0);
});
calls = restore();
check('ENOENT hanya satu percobaan', () => assert.equal(calls, 1));

restore = failRename(99, 'EBUSY');
check('seluruh retry EBUSY habis: gagal, tujuan utuh, temp bersih', () => {
  assert.throws(() => writeJsonAtomicSync(target, { value: 'gagal-total' }), /EBUSY/);
  assert.deepEqual(JSON.parse(fs.readFileSync(target, 'utf-8')), { value: 'stabil' });
  assert.equal(tempFiles().length, 0);
});
restore();

restore = failRename(2, 'EACCES');
check('writer registry memakai retry rename yang sama', () => {
  const registry = path.join(dir, 'endpoint_inventory.json');
  fs.writeFileSync(registry, '[]');
  const record = {
    id: 'uji', name: 'uji', hostname: 'uji.local', role: 'x', os: 'Linux', platformType: 'linux',
    ip: '', mac: '', user: '', openPorts: [], checks: [], source: 'operator',
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    revision: 1, changeHistory: []
  };
  writeEndpointRecords(registry, [record]);
  assert.equal(JSON.parse(fs.readFileSync(registry, 'utf-8'))[0].id, 'uji');
  assert.equal(tempFiles().length, 0);
});
restore();

fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
const failed = results.filter(ok => !ok).length;
console.log(`\n${results.length - failed}/${results.length} atomic write checks passed`);
if (failed) process.exit(1);
