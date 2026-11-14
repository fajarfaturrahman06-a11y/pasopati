/**
 * Uji unit redaksi OPSEC: seluruh bentuk indikator sensitif harus tersensor,
 * sedangkan angka/istilah non-indikator tidak boleh ikut tersensor.
 *
 * Jalankan: npm run test:redaction
 */
import assert from 'node:assert/strict';
import { redactSensitive } from '../src/redaction';

let passed = 0;
function check(name: string, actual: string, expected: string) {
  assert.equal(actual, expected, name);
  passed += 1;
  console.log(`PASS  ${name}`);
}

check('IPv4 disensor', redactSensitive('host 10.14.2.10 aktif'), 'host [REDACTED_MIL_IP] aktif');
check('IPv6 terkompresi disensor', redactSensitive('link fe80::1 dan 2001:db8::5'), 'link [REDACTED_MIL_IP] dan [REDACTED_MIL_IP]');
check('IPv6 loopback disensor', redactSensitive('bind ::1'), 'bind [REDACTED_MIL_IP]');
check('MAC titik dua disensor', redactSensitive('mac 00:11:22:33:44:55'), 'mac [REDACTED_MAC]');
check('MAC titik disensor', redactSensitive('mac 0011.2233.4455'), 'mac [REDACTED_MAC]');
check('FQDN disensor', redactSensitive('srv-data.yonif.mil.id'), '[REDACTED_HOST]');
check('Hostname satu label disensor', redactSensitive('node PUSKODAL-SRV-01 down'), 'node [REDACTED_HOST] down');
check('Jam tidak disensor', redactSensitive('pukul 12:03:45'), 'pukul 12:03:45');
check('ID CIS tidak disensor', redactSensitive('sesuai CIS 5.2.10 dan STIG V-214878'), 'sesuai CIS 5.2.10 dan STIG V-214878');
check('Istilah teknis huruf kecil tetap', redactSensitive('usb-storage dan auditd'), 'usb-storage dan auditd');
check('null aman', redactSensitive(null), '');

console.log(`\n${passed}/${passed} pengujian lolos`);
