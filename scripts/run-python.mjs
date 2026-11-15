/**
 * Jalankan skrip Python dengan binary yang tersedia di platform ini.
 * Windows tidak punya `python3`, Linux/macOS tidak selalu punya `py`.
 */
import { spawnSync } from 'node:child_process';

const candidates = process.platform === 'win32'
  ? [['py', ['-3']], ['python', []], ['python3', []]]
  : [['python3', []], ['python', []]];

for (const [bin, prefix] of candidates) {
  const probe = spawnSync(bin, [...prefix, '--version'], { stdio: 'ignore' });
  if (probe.status === 0) {
    const run = spawnSync(bin, [...prefix, ...process.argv.slice(2)], { stdio: 'inherit' });
    process.exit(run.status ?? 1);
  }
}

console.error('[test] Python tidak ditemukan (coba py -3 / python / python3).');
process.exit(1);
