import fs from 'node:fs';
import { buildRemediationScripts } from '../src/remediationScripts';
import type { DeviceInfo, SecurityCheck } from '../src/types';

const out = process.argv[2];
const mode = process.argv[3] === 'roll' ? 'roll' : 'hard';
if (!out) {
  console.error('usage: tsx tests/gen-sample-script.ts <output> [roll]');
  process.exit(1);
}

const checks: SecurityCheck[] = [
  {
    id: 'c1',
    parameter: 'Host-Based Local Firewall Active',
    category: 'Endpoint Protection',
    cis_id: 'CIS 3.5.1',
    status: 'FAIL',
    details: 'UFW inactive',
    mitigation: 'Aktifkan UFW default deny incoming'
  },
  {
    id: 'c2',
    parameter: 'SSH Root Login & Auth',
    category: 'Access Control',
    cis_id: 'CIS 5.2.10',
    status: 'FAIL',
    details: 'PermitRootLogin yes',
    mitigation: 'Set PermitRootLogin no'
  }
];

const device: DeviceInfo = {
  id: 'ELEV-SCRIPT',
  name: 'ELEV-SCRIPT',
  hostname: 'elev-script.test',
  role: 'Server Uji Elevasi',
  os: 'Ubuntu 22.04',
  platformType: 'linux',
  ip: '10.0.0.2',
  mac: '00:00:00:00:00:02',
  user: 'tester',
  openPorts: [],
  checks
};

const scripts = buildRemediationScripts(device, true);
fs.writeFileSync(out, mode === 'roll' ? scripts.roll : scripts.hard);
