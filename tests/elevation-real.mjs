#!/usr/bin/env node
/**
 * UJI NYATA elevasi otomatis.
 *
 * Karena sudo interaktif tidak punya TTY di CI, test ini memakai shim `sudo`
 * yang mencatat pemanggilan lalu mengeksekusi perintah di user-namespace root
 * (`unshare -r`). Ini membuktikan: agent & script benar-benar mengelevasi diri,
 * tidak terjadi loop, argumen dipertahankan, dan audit.json berisi blok
 * eksekusi + riwayat yang bertambah pada run berikutnya.
 *
 * Jalankan: node tests/elevation-real.mjs
 */
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pasopati-elev-'));
const shimDir = path.join(tmp, 'bin');
const logFile = path.join(tmp, 'sudo.log');
fs.mkdirSync(shimDir);
fs.writeFileSync(
  path.join(shimDir, 'sudo'),
  `#!/bin/bash
echo "$*" >> ${JSON.stringify(logFile)}
args=("$@")
if [ "\${args[0]}" = "-E" ] || [ "\${args[0]}" = "-n" ]; then args=("\${args[@]:1}"); fi
exec unshare -r "\${args[@]}"
`,
  { mode: 0o755 }
);

const homeDir = path.join(tmp, 'home');
fs.mkdirSync(homeDir);
const env = { ...process.env, PATH: `${shimDir}:${process.env.PATH}`, HOME: homeDir };
const results = [];
function check(name, ok, detail = '') {
  results.push(ok);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}
const calls = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean) : []);

const audit1 = path.join(tmp, 'audit.json');
const audit2 = path.join(tmp, 'audit2.json');

try {
  if (spawnSync('unshare', ['-r', 'true']).status !== 0) {
    console.log('SKIP: unshare -r tidak tersedia');
    process.exit(0);
  }

  // ---------- 1. Agent audit: elevasi otomatis + audit.json ----------
  const run1 = spawnSync('python3', ['pasopati_audit.py', '-q', '-u', 'ELEV-TEST', '-o', audit1], { cwd: root, env, encoding: 'utf8' });
  check('Run audit sebagai non-root berhasil (exit 0)', run1.status === 0, (run1.stderr || '').slice(-300));
  check('Agent memanggil sudo tepat sekali (tanpa loop)', calls().length === 1, `call=${calls().length}`);
  check('Argumen agent dipertahankan saat elevasi', (calls()[0] || '').includes('pasopati_audit.py') && (calls()[0] || '').includes('ELEV-TEST'));

  const json1 = fs.existsSync(audit1) ? JSON.parse(fs.readFileSync(audit1, 'utf8')) : null;
  check('audit.json dibuat', Boolean(json1));
  if (json1) {
    check('audit.json mencatat elevated=true', json1.execution?.elevated === true, String(json1.execution?.elevated));
    check('audit.json mencatat metode elevasi', json1.execution?.elevation_method === 'sudo', String(json1.execution?.elevation_method));
    check('audit.json berisi matriks kerentanan', Array.isArray(json1.compliance_matrix) && json1.compliance_matrix.length > 0, `n=${json1.compliance_matrix?.length}`);
    check('audit.json berisi riwayat eksekusi', Array.isArray(json1.execution?.history) && json1.execution.history.length >= 1);
    const last = json1.execution.history[json1.execution.history.length - 1];
    check('Entri riwayat berisi unit + skor + status elevasi', last?.unit === 'ELEV-TEST' && typeof last?.score === 'number' && last?.elevated === true);
    check('Riwayat menunjuk file history persisten', typeof json1.execution?.history_file === 'string' && json1.execution.history_file.includes('history.json'));
  }

  // ---------- 2. Run kedua: riwayat bertambah & elevasi tetap otomatis ----------
  const before = calls().length;
  const run2 = spawnSync('python3', ['pasopati_audit.py', '-q', '-u', 'ELEV-TEST', '-o', audit2], { cwd: root, env, encoding: 'utf8' });
  check('Run kedua berhasil', run2.status === 0, (run2.stderr || '').slice(-300));
  check('Run kedua mengelevasi lagi tepat sekali', calls().length === before + 1, `delta=${calls().length - before}`);
  const json2 = fs.existsSync(audit2) ? JSON.parse(fs.readFileSync(audit2, 'utf8')) : null;
  check('Riwayat run sebelumnya terbawa ke run kedua', Array.isArray(json2?.execution?.history) && json2.execution.history.length >= 2, `n=${json2?.execution?.history?.length}`);

  // ---------- 2b. --no-elevate tidak memanggil sudo ----------
  const beforeNo = calls().length;
  const audit3 = path.join(tmp, 'audit3.json');
  const run3 = spawnSync('python3', ['pasopati_audit.py', '-q', '-u', 'NO-ELEV', '-o', audit3, '--no-elevate'], { cwd: root, env, encoding: 'utf8' });
  const json3 = fs.existsSync(audit3) ? JSON.parse(fs.readFileSync(audit3, 'utf8')) : null;
  check('--no-elevate tidak memanggil sudo', run3.status === 0 && calls().length === beforeNo, `call=${calls().length - beforeNo}`);
  check('--no-elevate mencatat elevated=false', json3?.execution?.elevated === false);

  // ---------- 2c. Script PERBAIKAN mengelevasi dirinya sendiri (bukan audit) ----------
  const beforeRem = calls().length;
  const remRun = spawnSync('python3', ['pasopati_remediate.py', '--demo', '--no-exec', '-q'], { cwd: root, env, encoding: 'utf8' });
  check('Script perbaikan berjalan sebagai non-root (exit 0)', remRun.status === 0, (remRun.stderr || '').slice(-300));
  check('Script perbaikan memanggil sudo tepat sekali', calls().length === beforeRem + 1, `delta=${calls().length - beforeRem}`);
  const remLog = calls()[calls().length - 1] || '';
  check('Elevasi menjalankan ulang pasopati_remediate.py (bukan audit)', remLog.includes('pasopati_remediate.py') && !remLog.includes('pasopati_audit.py'));

  // ---------- 3. Script hardening hasil generator ikut mengelevasi ----------
  const gen = execFileSync('npx', ['tsx', 'tests/gen-sample-script.ts', path.join(tmp, 'hardening.sh')], { cwd: root, encoding: 'utf8' });
  check('Script contoh tergenerate', fs.existsSync(path.join(tmp, 'hardening.sh')), gen.trim());
  const beforeScript = calls().length;
  const scriptRun = spawnSync('bash', [path.join(tmp, 'hardening.sh'), '--dry-run'], { cwd: tmp, env, encoding: 'utf8' });
  check('Script mengelevasi otomatis lalu jalan sebagai root', calls().length === beforeScript + 1, `delta=${calls().length - beforeScript}`);
  check('Script lolos ke mode DRY-RUN setelah elevasi', scriptRun.status === 0 && /MODE DRY-RUN/.test(scriptRun.stdout), (scriptRun.stderr || '').slice(-300));

  // ---------- 4. Rollback script juga mengelevasi ----------
  execFileSync('npx', ['tsx', 'tests/gen-sample-script.ts', path.join(tmp, 'rollback.sh'), 'roll'], { cwd: root, encoding: 'utf8' });
  const beforeRoll = calls().length;
  const rollRun = spawnSync('bash', [path.join(tmp, 'rollback.sh')], { cwd: tmp, env, encoding: 'utf8' });
  check('Rollback mengelevasi otomatis', calls().length === beforeRoll + 1, `delta=${calls().length - beforeRoll}`);
  check('Rollback berjalan (tanpa loop)', !/Butuh root/.test(rollRun.stdout + rollRun.stderr), (rollRun.stderr || '').slice(-200));
} catch (err) {
  check('Uji elevasi selesai tanpa exception', false, err?.message || String(err));
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

const failed = results.filter(r => !r).length;
console.log(`\n${results.length - failed}/${results.length} pengujian lolos`);
if (failed) process.exit(1);
