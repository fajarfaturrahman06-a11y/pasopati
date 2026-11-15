/**
 * Jalankan skrip Python dengan binary yang tersedia di platform ini.
 * Windows tidak punya `python3`, Linux/macOS tidak selalu punya `py`.
 *
 * Urutan: virtual environment proyek lebih dulu (`.venv/Scripts/python.exe`
 * di Windows, `.venv/bin/python` di POSIX), lalu fallback interpreter sistem.
 * `PASOPATI_PYTHON_ROOT` hanya dipakai pengujian untuk menunjuk root lain.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FALLBACKS = process.platform === 'win32'
  ? [['py', ['-3']], ['python', []], ['python3', []]]
  : [['python3', []], ['python', []]];

function projectRoot() {
  return process.env.PASOPATI_PYTHON_ROOT
    ? path.resolve(process.env.PASOPATI_PYTHON_ROOT)
    : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
}

export function venvPythonFor(root, platform = process.platform) {
  return platform === 'win32'
    ? path.join(root, '.venv', 'Scripts', 'python.exe')
    : path.join(root, '.venv', 'bin', 'python');
}

/** Kandidat interpreter: venv hanya bila filenya ada, lalu fallback platform. */
export function buildCandidates(root = projectRoot(), platform = process.platform) {
  const candidates = [];
  const venv = venvPythonFor(root, platform);
  if (fs.existsSync(venv)) candidates.push([venv, []]);
  candidates.push(...FALLBACKS);
  return candidates;
}

function main() {
  const candidates = buildCandidates();
  for (const [bin, prefix] of candidates) {
    const probe = spawnSync(bin, [...prefix, '--version'], { stdio: 'ignore' });
    if (probe.status === 0) {
      if (process.env.PASOPATI_PYTHON_TRACE) console.error(`[runner] chosen=${bin}`);
      const run = spawnSync(bin, [...prefix, ...process.argv.slice(2)], { stdio: 'inherit' });
      process.exit(typeof run.status === 'number' ? run.status : 1);
    }
  }
  console.error('[test] Python tidak ditemukan (venv, py -3, python, python3).');
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
