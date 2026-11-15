/**
 * Uji runner Python: virtualenv proyek harus dipilih lebih dulu, fallback tetap
 * berfungsi, argumen diteruskan, dan exit code dipropagasikan.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { buildCandidates, venvPythonFor } from '../scripts/run-python.mjs';

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

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-runner-'));
const emptyRoot = path.join(tmp, 'kosong');
fs.mkdirSync(emptyRoot, { recursive: true });
const venvRoot = path.join(tmp, 'venv');
const platform = process.platform;
const expectedVenv = venvPythonFor(venvRoot, platform);
fs.mkdirSync(path.dirname(expectedVenv), { recursive: true });
fs.writeFileSync(expectedVenv, '');

check('kandidat pertama adalah .venv sesuai platform', () => {
  const candidates = buildCandidates(venvRoot, platform);
  assert.equal(candidates[0][0], expectedVenv);
});

check('tanpa .venv, kandidat tidak berisi folder venv', () => {
  const candidates = buildCandidates(emptyRoot, platform);
  assert.equal(candidates[0][0].startsWith(path.join(emptyRoot, '.venv')), false);
  assert.ok(candidates.length >= 1);
});

function findSystemPython() {
  const options = platform === 'win32' ? [['py', ['-3']], ['python', []], ['python3', []]] : [['python3', []], ['python', []]];
  for (const [bin, prefix] of options) {
    if (spawnSync(bin, [...prefix, '--version'], { stdio: 'ignore' }).status === 0) return [bin, ...prefix];
  }
  return null;
}

const python = findSystemPython();
if (!python) {
  check('interpreter sistem tersedia untuk membuat venv', () => { throw new Error('python tidak ditemukan'); });
} else {
  const venvCreateRoot = path.join(tmp, 'proyek');
  const venvCreate = path.join(venvCreateRoot, '.venv');
  fs.mkdirSync(venvCreateRoot, { recursive: true });
  const created = spawnSync(python[0], [...python.slice(1), '-m', 'venv', venvCreate], { stdio: 'ignore' });
  check('venv uji berhasil dibuat', () => assert.equal(created.status, 0));

  if (created.status === 0) {
    const run = (root, args) => spawnSync(process.execPath, [path.resolve('scripts/run-python.mjs'), ...args], {
      env: { ...process.env, PASOPATI_PYTHON_ROOT: root, PASOPATI_PYTHON_TRACE: '1' },
      encoding: 'utf-8'
    });

    const venvRun = run(venvCreateRoot, ['-c', 'print("RUNNER_VENV_OK")']);
    check('runner memilih .venv lebih dulu', () => {
      assert.equal(venvRun.status, 0, venvRun.stderr);
      assert.match(venvRun.stdout, /RUNNER_VENV_OK/);
      assert.match(venvRun.stderr, /chosen=.*\.venv/);
    });

    const fallbackRun = run(emptyRoot, ['-c', 'print("RUNNER_FALLBACK_OK")']);
    check('runner memakai fallback sistem tanpa .venv', () => {
      assert.equal(fallbackRun.status, 0, fallbackRun.stderr);
      assert.match(fallbackRun.stdout, /RUNNER_FALLBACK_OK/);
      assert.doesNotMatch(fallbackRun.stderr, /chosen=.*\.venv/);
    });

    const argRun = run(venvCreate, ['-c', 'import sys; print(sys.argv[1])', 'argumen-uji']);
    check('argumen diteruskan utuh ke Python', () => assert.equal(argRun.stdout.trim(), 'argumen-uji'));

    const exitRun = run(venvCreate, ['-c', 'import sys; sys.exit(7)']);
    check('exit code Python dipropagasikan', () => assert.equal(exitRun.status, 7));
  }
}

fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
const failed = results.filter(ok => !ok).length;
console.log(`\n${results.length - failed}/${results.length} runner checks passed`);
if (failed) process.exit(1);
