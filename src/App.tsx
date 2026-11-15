/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef } from 'react';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { TabCommandCenter } from './components/TabCommandCenter';
import { TabDeepAudit } from './components/TabDeepAudit';
import { TabAIHardening } from './components/TabAIHardening';
import { TabLiveAgent } from './components/TabLiveAgent';
import { TabAuditLog } from './components/TabAuditLog';
import { TabEndpointHealthAudit } from './components/TabEndpointHealthAudit';
import { LoginGate, type PrincipalIdentity } from './components/LoginGate';
import { OperatorTestAccess } from './components/OperatorTestAccess';
import { INITIAL_MOCK_DEVICES, calculateFleetScore, calculateDeviceScore } from './data/mockDevices';
import { DeviceInfo, AuditLogEntry } from './types';
import { normalizeAuditAction } from './auditActions';
import { sfx } from './utils/audio';
import { FileText, Download, Copy, Check, X, ShieldAlert } from 'lucide-react';
import type { EndpointSyncStatus, EndpointDraftPayload } from './components/EndpointRegistryPanel';

// Audit trail starts empty — entries are recorded only from real actions
// (remediation, quarantine, telemetry ingestion) during this session.
const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [];

function cloneDemoDevices(): DeviceInfo[] {
  return JSON.parse(JSON.stringify(INITIAL_MOCK_DEVICES)) as DeviceInfo[];
}

function normalizeEndpointDevice(raw: any): DeviceInfo {
  const checks = Array.isArray(raw?.checks) ? raw.checks : [];
  const platform = ['linux', 'windows', 'embedded'].includes(String(raw?.platformType)) ? raw.platformType : 'linux';
  return {
    id: String(raw?.id || ''),
    revision: Number.isSafeInteger(raw?.revision) && raw.revision > 0 ? raw.revision : 1,
    ...(typeof raw?.agentId === 'string' ? { agentId: raw.agentId } : {}),
    name: String(raw?.name || raw?.hostname || 'Endpoint'),
    hostname: String(raw?.hostname || ''),
    role: String(raw?.role || 'Endpoint'),
    os: String(raw?.os || 'Unknown'),
    platformType: platform,
    ip: String(raw?.ip || ''),
    mac: String(raw?.mac || ''),
    user: String(raw?.user || ''),
    openPorts: Array.isArray(raw?.openPorts) ? raw.openPorts.filter((port: unknown) => Number.isInteger(Number(port))).map(Number) : [],
    checks: checks.map((check: any, index: number) => ({
      id: String(check?.id || `check-${index + 1}`),
      parameter: String(check?.parameter || 'Security control'),
      category: String(check?.category || 'Network & Port') as DeviceInfo['checks'][number]['category'],
      cis_id: String(check?.cis_id || ''),
      status: (['PASS', 'WARNING', 'FAIL', 'N/A', 'WAIVED'].includes(String(check?.status)) ? String(check.status) : 'N/A') as DeviceInfo['checks'][number]['status'],
      details: String(check?.details || ''),
      mitigation: String(check?.mitigation || '')
    })),
    isQuarantined: raw?.isQuarantined === true,
    history: Array.isArray(raw?.history) ? raw.history.map((point: any) => ({
      timestamp: String(point?.timestamp || ''),
      score: Number(point?.score) || 0,
      passCount: Number(point?.passCount) || 0,
      warnCount: Number(point?.warnCount) || 0,
      failCount: Number(point?.failCount) || 0,
      event: String(point?.event || '')
    })) : []
  };
}

export default function App() {
  const [devices, setDevices] = useState<DeviceInfo[]>(cloneDemoDevices);
  const [centralEndpointData, setCentralEndpointData] = useState(false);
  const [endpointSyncStatus, setEndpointSyncStatus] = useState<EndpointSyncStatus>('demo');
  const [lastEndpointSync, setLastEndpointSync] = useState<string | null>(null);
  const [principalRole, setPrincipalRole] = useState<string | null>(null);
  const [principalName, setPrincipalName] = useState<string | null>(null);
  const [loginNotice, setLoginNotice] = useState<string | null>(null);
  const [showOperatorTestAccess, setShowOperatorTestAccess] = useState(false);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string>('SRV-DATA-YONIF');
  const [activeTab, setActiveTab] = useState<number>(0);
  const [mobileOpen, setMobileOpen] = useState<boolean>(false);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const [sessionActive, setSessionActive] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const [geminiKey, setGeminiKey] = useState<string>('');
  const [lastScanTime, setLastScanTime] = useState<string>(() => {
    const now = new Date();
    return now.toISOString().replace('T', ' ').substring(0, 19);
  });
  const [notification, setNotification] = useState<{ message: string; type: 'success' | 'info' } | null>(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(INITIAL_AUDIT_LOGS);
  const toastTimerRef = useRef<number | null>(null);
  const endpointSyncRef = useRef<() => Promise<void>>(async () => undefined);
  const centralEndpointDataRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' })
      .then(response => response.ok ? response.json() : { authenticated: false })
      .then(identity => {
        if (cancelled) return;
        if (identity?.authenticated && typeof identity.name === 'string' && typeof identity.role === 'string') {
          setPrincipalName(identity.name);
          setPrincipalRole(identity.role);
          setSessionActive(true);
        }
      })
      .catch(() => {})
      .finally(() => { if (!cancelled) setAuthReady(true); });
    return () => { cancelled = true; };
  }, []);

  const handleDirectDownload = async (fileName: string, url: string) => {
    sfx.playSuccess();
    const protectedDownload = url.includes('/api/download/project-zip');
    showToast(`Menyiapkan unduhan ${fileName}... (Akses Langsung Evaluasi Juri)`, 'info');
    try {
      const response = await fetch(url, { credentials: 'same-origin' });
      if (!response.ok) {
        if (protectedDownload && (response.status === 401 || response.status === 503)) {
          showToast('Sesi login tidak lagi berlaku. Masuk kembali dengan username dan password.', 'info');
          return;
        }
        throw new Error(`HTTP ${response.status}`);
      }
      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const tempLink = document.createElement('a');
      tempLink.href = blobUrl;
      tempLink.setAttribute('download', fileName);
      document.body.appendChild(tempLink);
      tempLink.click();
      document.body.removeChild(tempLink);
      setTimeout(() => window.URL.revokeObjectURL(blobUrl), 10000);
      showToast(`Berkas ${fileName} berhasil diunduh.`, 'success');
    } catch (err) {
      if (protectedDownload) {
        showToast(`Gagal mengunduh ${fileName}. Periksa koneksi server.`, 'info');
        return;
      }
      console.warn('Fetch blob download fallback to native navigation:', err);
      const fallbackLink = document.createElement('a');
      fallbackLink.href = url;
      fallbackLink.setAttribute('download', fileName);
      fallbackLink.setAttribute('target', '_blank');
      document.body.appendChild(fallbackLink);
      fallbackLink.click();
      document.body.removeChild(fallbackLink);
    }
  };

  useEffect(() => {
    let cancelled = false;
    if (!sessionActive) return () => { cancelled = true; };
    fetch('/api/audit-logs', { credentials: 'same-origin', cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : { logs: [] }))
      .then((d) => {
        if (cancelled) return;
        const logs = Array.isArray(d?.logs) ? d.logs : [];
        setAuditLogs(
          logs
            .filter((l: any) => l && l.id)
            .map((l: any) => ({
              id: String(l.id),
              timestamp: String(l.timestamp || ''),
              deviceId: String(l.deviceId || 'UNKNOWN'),
              deviceName: String(l.deviceName || 'UNKNOWN'),
              deviceRole: String(l.deviceRole || 'UNKNOWN'),
              action: normalizeAuditAction(l.action),
              operator: String(l.operator || 'operator'),
              preScore: Number(l.preScore) || 0,
              postScore: Number(l.postScore) || 0,
              changesSummary: String(l.changesSummary || ''),
              changesDetails: Array.isArray(l.changesDetails) ? l.changesDetails.filter((x: any) => typeof x === 'string').map((x: any) => String(x)) : [],
              status: (['SUCCESS', 'WARNING', 'FAILED'].includes(String(l.status)) ? String(l.status) : 'SUCCESS') as AuditLogEntry['status'],
              storedInDb: true,
              ...(typeof l.deletedAt === 'string' ? { deletedAt: l.deletedAt } : {})
            }))
        );
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [sessionActive]);

  // Satu sumber data endpoint untuk seluruh halaman: server VPS. Mock hanya
  // ditampilkan dalam mode demo sampai browser berhasil terautentikasi.
  useEffect(() => {
    let cancelled = false;
    let inFlight = false;
    let pollTimer: number | null = null;
    let startTimer: number | null = null;

    if (!sessionActive) {
      centralEndpointDataRef.current = false;
      setCentralEndpointData(false);
      setEndpointSyncStatus('demo');
      setLastEndpointSync(null);
      setPrincipalRole(null);
      setPrincipalName(null);
      setDevices(cloneDemoDevices());
      setSelectedDeviceId('SRV-DATA-YONIF');
      endpointSyncRef.current = async () => undefined;
      return () => { cancelled = true; };
    }

    setEndpointSyncStatus('connecting');
    const sync = async () => {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        const response = await fetch('/api/endpoints', { credentials: 'same-origin', cache: 'no-store' });
        if (response.status === 401 || response.status === 403) {
          centralEndpointDataRef.current = false;
          setCentralEndpointData(false);
          setDevices(cloneDemoDevices());
          setSelectedDeviceId('SRV-DATA-YONIF');
          setPrincipalRole(null);
          setPrincipalName(null);
          setEndpointSyncStatus('unauthenticated');
          setLoginNotice('Sesi login berakhir. Masuk kembali dengan username dan password.');
          setSessionActive(false);
          return;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!Array.isArray(data?.endpoints)) throw new Error('Response endpoint tidak valid.');
        const latest: DeviceInfo[] = data.endpoints.map(normalizeEndpointDevice) as DeviceInfo[];
        if (cancelled) return;
        centralEndpointDataRef.current = true;
        setCentralEndpointData(true);
        setDevices(latest);
        setSelectedDeviceId(current => latest.some(device => device.id === current) ? current : (latest[0]?.id || ''));
        setEndpointSyncStatus('connected');
        setLastEndpointSync(new Date().toLocaleTimeString());
      } catch {
        if (!cancelled) setEndpointSyncStatus('offline');
      } finally {
        inFlight = false;
      }
    };
    endpointSyncRef.current = sync;
    startTimer = window.setTimeout(() => {
      void sync();
      pollTimer = window.setInterval(() => void sync(), 5000);
    }, 350);
    return () => {
      cancelled = true;
      if (startTimer !== null) window.clearTimeout(startTimer);
      if (pollTimer !== null) window.clearInterval(pollTimer);
    };
  }, [sessionActive]);

  // Pulihkan status karantina dari registry server setelah pemulihan sesi.
  useEffect(() => {
    if (!sessionActive) return;
    let cancelled = false;
    fetch('/api/quarantine', { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (cancelled || !d?.units) return;
        setDevices(prev => prev.map(dev => {
          const entry = d.units[dev.id];
          return entry ? { ...dev, isQuarantined: entry.quarantined === true } : dev;
        }));
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [sessionActive]);

  const persistAuditLogs = (entries: AuditLogEntry[]) => {
    if (entries.length === 0) return;
    fetch('/api/audit-logs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs: entries })
    }).catch(() => {});
  };

  const showToast = (message: string, type: 'success' | 'info' = 'success') => {
    setNotification({ message, type });
    if (toastTimerRef.current !== null) window.clearTimeout(toastTimerRef.current);
    toastTimerRef.current = window.setTimeout(() => {
      setNotification(null);
      toastTimerRef.current = null;
    }, 4500);
  };

  // Switch device and navigate
  const handleSelectDevice = (deviceId: string) => {
    setSelectedDeviceId(deviceId);
    setActiveTab(1); // Jump to Tab 2: Deep Endpoint Audit
  };

  const handleNavigateToHardening = (deviceId: string) => {
    setSelectedDeviceId(deviceId);
    setActiveTab(2); // Jump to Tab 3: AI Hardening
  };

  // Emergency Network Quarantine Toggle (DEFCON 1 Kill-Switch)
  const handleToggleQuarantine = async (deviceId: string) => {
    const targetDev = devices.find(d => d.id === deviceId);
    if (!targetDev) return;

    const nextQuarantine = !targetDev.isQuarantined;

    setDevices(prev =>
      prev.map(d => {
        if (d.id === deviceId) {
          return {
            ...d,
            isQuarantined: nextQuarantine
          };
        }
        return d;
      })
    );

    try {
      const res = await fetch('/api/quarantine', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ unitId: deviceId, action: nextQuarantine ? 'LOCK' : 'RELEASE' })
      });
      const quarantineAck = await res.json().catch(() => null);
      if (!res.ok || !quarantineAck?.status) {
        setDevices(prev => prev.map(d => (d.id === deviceId ? { ...d, isQuarantined: !nextQuarantine } : d)));
        showToast('Karantina gagal diterima server. Status tidak diubah.', 'info');
        return;
      }
    } catch {
      setDevices(prev => prev.map(d => (d.id === deviceId ? { ...d, isQuarantined: !nextQuarantine } : d)));
      showToast('Koneksi ke server karantina gagal. Status tidak diubah.', 'info');
      return;
    }

    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    const newLog: AuditLogEntry = {
      id: `LOG-KILL-${Date.now()}`,
      timestamp: nowStr,
      deviceId: targetDev.id,
      deviceName: targetDev.name,
      deviceRole: targetDev.role,
      action: 'QUARANTINE KILL-SWITCH',
        operator: 'puskodal_commander',
      preScore: calculateDeviceScore(targetDev.checks),
      postScore: calculateDeviceScore(targetDev.checks),
      changesSummary: nextQuarantine
        ? `SIMULASI/STATUS: Host ditandai terisolasi di registry Puskodal. Pemblokiran firewall nyata menunggu eksekusi agen host.`
        : `ISOLASI DITANDAI DICABUT: Host dikembalikan ke status perimeter normal di registry.`,
      changesDetails: nextQuarantine
        ? ['[SIMULASI] Status karantina dicatat, bukan eksekusi IPTables', '[SIMULASI] Block lateral SMB/RPC belum dijalankan server', 'Eksekusi nyata: pasopati_remediate.py di host target']
        : ['[SIMULASI] Status karantina dicabut di registry'],
      status: nextQuarantine ? 'WARNING' : 'SUCCESS',
        storedInDb: true
    };
      setAuditLogs(prev => [newLog, ...prev]);
      persistAuditLogs([newLog]);

      if (nextQuarantine) {
      sfx.playPing();
      showToast(`Status karantina DICATAT untuk ${deviceId}. Pemblokiran jaringan nyata dieksekusi oleh agen host.`, 'info');
    } else {
      sfx.playSuccess();
      showToast(`Status isolasi pada ${deviceId} dicabut di registry Puskodal.`);
    }
  };

  // Terapkan/lepas waiver aktif ke daftar temuan perangkat.
  const refreshWaivers = async (deviceId: string) => {
    if (!sessionActive) return;
    try {
      const res = await fetch('/api/waivers/' + encodeURIComponent(deviceId), {
        credentials: 'same-origin'
      });
      if (!res.ok) return;
      const data = await res.json().catch(() => null);
      const list: any[] = Array.isArray(data?.waivers) ? data.waivers : [];
      setDevices(prev => prev.map(dev => {
        if (dev.id !== deviceId) return dev;
        return {
          ...dev,
          checks: dev.checks.map(c => {
            const waiver = list.find((w: any) => w?.parameter === c.parameter);
            if (waiver) {
              return { ...c, baseStatus: c.baseStatus ?? c.status, status: 'WAIVED' as const, waiver };
            }
            if (c.waiver) {
              return { ...c, status: (c.baseStatus ?? 'WARNING') as typeof c.status, waiver: undefined, baseStatus: undefined };
            }
            return c;
          })
        };
      }));
    } catch {
      /* abaikan */
    }
  };

  const saveEndpoint = async (payload: EndpointDraftPayload, id?: string, expectedRevision?: number) => {
    if (!sessionActive || !centralEndpointDataRef.current) throw new Error('Sesi login atau koneksi registry VPS tidak tersedia.');
    const response = await fetch(id ? `/api/endpoints/${encodeURIComponent(id)}` : '/api/endpoints', {
      method: id ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(id ? { ...payload, expected_revision: expectedRevision } : payload)
    });
    const result = await response.json().catch(() => null);
    if (response.status === 409 && id) {
      await endpointSyncRef.current();
      throw new Error(`${String(result?.reason || 'Konflik perubahan endpoint.')} Daftar sudah diperbarui; tutup dan buka kembali formulir edit sebelum menyimpan lagi.`);
    }
    if (!response.ok) throw new Error(String(result?.reason || `HTTP ${response.status}`));
    await endpointSyncRef.current();
    if (result?.endpoint?.id) setSelectedDeviceId(String(result.endpoint.id));
    showToast(id ? 'Perubahan endpoint tersimpan di registry VPS.' : (result?.created ? 'Endpoint tersimpan di registry VPS.' : 'Endpoint cocok diperbarui di registry VPS.'));
  };

  const deleteEndpoint = async (id: string) => {
    if (!sessionActive || !centralEndpointDataRef.current) throw new Error('Koneksi registry VPS tidak tersedia.');
    const response = await fetch(`/api/endpoints/${encodeURIComponent(id)}`, {
      method: 'DELETE', credentials: 'same-origin'
    });
    const result = await response.json().catch(() => null);
    if (!response.ok) throw new Error(String(result?.reason || `HTTP ${response.status}`));
    await endpointSyncRef.current();
    showToast('Endpoint diarsipkan; rekam jejak tetap tersimpan.');
  };

  // Sample stays local/demo; operational scan or JSON upload must be saved at VPS.
  const handleAddUploadedDevice = async (newDevice: DeviceInfo, source: 'agent' | 'demo' = 'agent') => {
    if (source === 'demo') {
      if (centralEndpointDataRef.current) {
        showToast('Contoh demo tidak ditambahkan ke inventaris VPS.', 'info');
        return;
      }
      setDevices(prev => [newDevice, ...prev.filter(device => device.id !== newDevice.id)]);
      setSelectedDeviceId(newDevice.id);
      showToast(`Contoh ${newDevice.name} hanya dimuat dalam sesi demo.`, 'info');
      return;
    }
    if (!sessionActive || !centralEndpointDataRef.current) throw new Error('Sesi login dan koneksi registry VPS diperlukan untuk menyimpan ke VPS.');
    const response = await fetch('/api/endpoints', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...newDevice, agentId: newDevice.agentId || newDevice.id, source: undefined })
    });
    const result = await response.json().catch(() => null);
    if (!response.ok) throw new Error(String(result?.reason || `HTTP ${response.status}`));
    await endpointSyncRef.current();
    if (result?.endpoint?.id) {
      setSelectedDeviceId(String(result.endpoint.id));
      void refreshWaivers(String(result.endpoint.id));
    }
    showToast(`Hasil audit ${newDevice.name} tersimpan di registry VPS (upload/import, bukan bukti scan langsung).`, 'info');
  };

  // Build official military commander briefing report text
  const buildCommanderReportText = () => {
    const fleetScore = calculateFleetScore(devices);
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);

    let doc = `================================================================================\n`;
    doc += `         SIMULASI EVALUASI KESIAPAN SIBER // TACTICAL CYBER DEFENSE BLUEPRINT   \n`;
    doc += `             PASOPATI: PROTOKOL AUDIT SISTEM & OPERASI PENGAMANAN AGEN TI        \n`;
    doc += `================================================================================\n\n`;
    doc += `KLASIFIKASI : SIMULASI / PROTOTYPE EVALUATION REPORT\n`;
    doc += `ACUAN       : CIS BENCHMARK v8.0, DISA STIG, ISA/IEC 62443\n`;
    doc += `PERIHAL     : LAPORAN SIMULASI KESIAPAN DAN AUDIT KEPATUHAN INFRASTRUKTUR\n`;
    doc += `WAKTU AUDIT : ${nowStr} UTC\n`;
    doc += `SKOR ARMADA : ${fleetScore}/100 [${fleetScore >= 80 ? 'DEFCON 4 - SIAP OPERASI' : fleetScore >= 60 ? 'DEFCON 3 - WASPADA' : 'DEFCON 2 - PERLU MITIGASI'}]\n\n`;
    doc += `--------------------------------------------------------------------------------\n`;
    doc += `1. RINGKASAN EKSEKUTIF SIMULASI\n`;
    doc += `--------------------------------------------------------------------------------\n`;
    doc += `Telah dilaksanakan simulasi audit kepatuhan siber berbasis standar internasional\n`;
    doc += `DISA STIG, CIS Benchmark v8.0, dan ISA/IEC 62443 terhadap ${devices.length} aset infrastruktur inti\n`;
    doc += `dan perangkat operasional taktis (OT/BMS). Purwarupa ini dirancang sebagai sistem\n`;
    doc += `evaluasi kepatuhan pertahanan mandiri. Kondisi kesiapan siber saat ini: ${fleetScore}/100.\n\n`;

    doc += `--------------------------------------------------------------------------------\n`;
    doc += `2. STATUS DAN INVENTARISASI PERANGKAT\n`;
    doc += `--------------------------------------------------------------------------------\n`;
    devices.forEach((d, idx) => {
      const failCount = d.checks.filter(c => c.status === 'FAIL').length;
      const warnCount = d.checks.filter(c => c.status === 'WARNING').length;
      doc += `[${idx + 1}] ${d.name} (${d.role})\n`;
      doc += `    - OS / Platform : ${d.os} [${d.platformType.toUpperCase()}]\n`;
      doc += `    - IP / MAC      : ${d.ip} / ${d.mac}\n`;
      doc += `    - Port Terbuka  : ${d.openPorts.join(', ') || 'None'}\n`;
      doc += `    - Status Celah  : ${failCount} FAIL (Kritis), ${warnCount} WARNING\n`;
      if (failCount > 0) {
        doc += `    - Temuan Kritis :\n`;
        d.checks.filter(c => c.status === 'FAIL').forEach(fc => {
          doc += `      * [${fc.cis_id}] ${fc.parameter}: ${fc.details}\n`;
        });
      }
      doc += `\n`;
    });

    doc += `--------------------------------------------------------------------------------\n`;
    doc += `3. REKOMENDASI TAKTIS BERBASIS STANDAR PERTAHANAN\n`;
    doc += `--------------------------------------------------------------------------------\n`;
    doc += `a. Segera terapkan Assisted Hardening Runbook (pasopati-hardening.sh/.ps1)\n`;
    doc += `   pada workstation dan gateway komunikasi yang masih berstatus FAIL.\n`;
    doc += `b. Isolasi port listener berbahaya (SMB 445, Telnet 23, Backdoor 4444).\n`;
    doc += `c. Distribusikan pasopati_audit.py mandiri dengan --push-url untuk telemetri berkala.\n\n`;
    doc += `================================================================================\n`;
    doc += `TIM INOVASI PASOPATI // TACTICAL READINESS PROTOTYPE\n`;
    doc += `================================================================================\n`;
    return doc;
  };

  // Open modal when 'Buat Laporan' is clicked
  const handleExportCommanderReport = () => {
    setIsReportModalOpen(true);
  };

  // Download plain text report
  const handleDownloadTextReport = () => {
    const doc = buildCommanderReportText();
    const blob = new Blob([doc], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `LAPORAN_KESIAPAN_SIBER_SIMULASI_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Laporan Simulasi (.txt) Berhasil Diunduh!');
  };

  // Download markdown report
  const handleDownloadMarkdownReport = () => {
    const fleetScore = calculateFleetScore(devices);
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    let md = `# SIMULASI LAPORAN KESIAPAN SIBER (TACTICAL DEFENSE BLUEPRINT)\n\n`;
    md += `**Klasifikasi:** SIMULASI / PROTOTYPE EVALUATION REPORT  \n`;
    md += `**Acuan Standar:** DISA STIG, CIS Benchmark v8.0, ISA/IEC 62443  \n`;
    md += `**Waktu Audit:** ${nowStr} UTC  \n`;
    md += `**Indeks Kesiapan Siber:** ${fleetScore}/100  \n\n`;
    md += `## 1. Ringkasan Eksekutif Simulasi\n\n`;
    md += `Telah dilaksanakan simulasi audit kepatuhan siber berbasis standar internasional DISA STIG, CIS Benchmark v8.0, dan ISA/IEC 62443 pada ${devices.length} aset siber taktis. Indeks kesiapan armada saat ini adalah **${fleetScore}/100**.\n\n`;
    md += `## 2. Inventarisasi Aset & Temuan Celah\n\n`;
    devices.forEach((d, idx) => {
      const fails = d.checks.filter(c => c.status === 'FAIL');
      const warns = d.checks.filter(c => c.status === 'WARNING');
      md += `### ${idx + 1}. ${d.name} (${d.role})\n`;
      md += `- **OS**: ${d.os} (${d.platformType.toUpperCase()})\n`;
      md += `- **IP / MAC**: \`${d.ip}\` / \`${d.mac}\`\n`;
      md += `- **Open Ports**: \`${d.openPorts.join(', ') || 'None'}\`\n`;
      md += `- **Status**: ${fails.length} FAIL, ${warns.length} WARNING\n\n`;
      if (fails.length > 0) {
        md += `**Temuan Kritis:**\n`;
        fails.forEach(f => {
          md += `- \`[${f.cis_id}]\` **${f.parameter}**: ${f.details}\n`;
        });
        md += `\n`;
      }
    });
    md += `## 3. Rekomendasi Taktis Komandan\n\n`;
    md += `1. Jalankan runbook hardening dinamis pada aset berstatus FAIL untuk memblokir port listener berbahaya.\n`;
    md += `2. Pastikan segmentasi conduit radio taktis mematuhi klausul ISA/IEC 62443.\n`;
    md += `3. Sinkronisasikan telemetri agen berkala untuk pemantauan berkelanjutan.\n`;

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `LAPORAN_KESIAPAN_SIBER_PUSKODAL_${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Laporan Resmi (.md) Berhasil Diunduh!');
  };

  const handleAuthenticated = (identity: PrincipalIdentity) => {
    setLoginNotice(null);
    setPrincipalName(identity.name);
    setPrincipalRole(identity.role);
    setActiveTab(0);
    setSessionActive(true);
    setAuthReady(true);
  };

  const handleLogout = () => {
    void fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    setSessionActive(false);
    setPrincipalName(null);
    setPrincipalRole(null);
    setShowOperatorTestAccess(false);
    setActiveTab(0);
  };

  if (!authReady) {
    return <main className="hud-grid flex min-h-screen items-center justify-center text-sm text-slate-400">Memeriksa sesi PASOPATI…</main>;
  }

  if (!sessionActive) {
    return <LoginGate onAuthenticated={handleAuthenticated} notice={loginNotice} />;
  }

  return (
    <div className="min-h-screen bg-[#12151c] text-slate-100 selection:bg-rose-500 selection:text-white">

      {showOperatorTestAccess && principalRole === 'admin' && (
        <OperatorTestAccess onClose={() => setShowOperatorTestAccess(false)} />
      )}

      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        fleetScore={calculateFleetScore(devices)}
        soundEnabled={soundEnabled}
        setSoundEnabled={setSoundEnabled}
        onExportCommanderReport={handleExportCommanderReport}
        onDownloadProjectZip={() => handleDirectDownload('pasopati-project.zip', '/api/download/project-zip')}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
        principalRole={principalRole}
        principalName={principalName}
        onLogout={handleLogout}
        onCreateTestUser={() => setShowOperatorTestAccess(true)}
      />

      <div className="flex min-h-screen flex-col lg:pl-[268px]">
        <Topbar
          activeTab={activeTab}
          devices={devices}
          auditLogCount={auditLogs.length}
          onOpenMobile={() => setMobileOpen(true)}
          onSelectDevice={handleSelectDevice}
          onNavigate={setActiveTab}
          principalName={principalName}
          principalRole={principalRole}
        />

        {/* Demo-vs-live honesty banner */}
        <div className={`border-b ${centralEndpointData ? 'border-emerald-900/40 bg-emerald-950/15' : 'border-amber-900/40 bg-amber-950/20'}`}>
          <div className={`mx-auto flex max-w-[1600px] items-start gap-2 px-4 py-1.5 font-mono text-[10.5px] sm:items-center sm:px-6 ${centralEndpointData ? 'text-emerald-200/90' : 'text-amber-300/90'}`}>
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 sm:mt-0" />
            <span>
              {centralEndpointData
                ? `MODE VPS: inventaris endpoint berasal dari server pusat${endpointSyncStatus === 'offline' ? ' (data terakhir tersimpan; VPS sedang tidak terjangkau)' : ''} dan dipoll tiap 5 detik. Audit/Hardening visual tidak menjalankan host; eksekusi nyata hanya melalui agen remediation di host target.`
                : 'MODE DEMO: data armada awal adalah mock lokal, bukan inventaris VPS. Masuk dengan akun terdaftar untuk memuat registry pusat. Audit/Hardening visual tidak menjalankan host.'}
            </span>
          </div>
        </div>

      {/* Toast Notification */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 bg-emerald-950 border border-emerald-500 text-emerald-200 px-4 py-3 rounded-lg shadow-[0_0_20px_rgba(16,185,129,0.3)] font-mono text-xs flex items-center gap-2 animate-bounce">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span>{notification.message}</span>
        </div>
      )}

      {/* Main Workspace Viewport */}
      <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-6 sm:px-6">
        {activeTab === 0 && (
          <TabCommandCenter
            devices={devices}
            lastScanTime={lastScanTime}
            auditLogs={auditLogs}
            onSelectDevice={handleSelectDevice}
            onAuditFinished={() => {
              const now = new Date();
              setLastScanTime(now.toISOString().replace('T', ' ').substring(0, 19));
              showToast('Audit Taktis Armada Selesai.');
            }}
            onNavigate={setActiveTab}
            endpointSyncStatus={endpointSyncStatus}
            centralEndpointData={centralEndpointData}
            canManageEndpoints={principalRole === 'admin' || principalRole === 'planner'}
            canDeleteEndpoints={principalRole === 'admin'}
            lastEndpointSync={lastEndpointSync}
            onSaveEndpoint={saveEndpoint}
            onDeleteEndpoint={deleteEndpoint}
          />
        )}

        {activeTab === 1 && (
          <TabDeepAudit
            devices={devices}
            selectedDeviceId={selectedDeviceId}
            onSelectDevice={setSelectedDeviceId}
            onNavigateToHardening={handleNavigateToHardening}
            onToggleQuarantine={handleToggleQuarantine}
            principalRole={principalRole}
            onWaiversChanged={refreshWaivers}
          />
        )}

        {activeTab === 2 && (
          <TabAIHardening
            devices={devices}
            selectedDeviceId={selectedDeviceId}
            onSelectDevice={setSelectedDeviceId}
            principalName={principalName}
            principalRole={principalRole}
            geminiKey={geminiKey}
            setGeminiKey={setGeminiKey}
            onShowToast={showToast}
          />
        )}

        {activeTab === 3 && (
          <TabLiveAgent
            onAddUploadedDevice={handleAddUploadedDevice}
            onNavigateToAudit={(devId) => {
              setSelectedDeviceId(devId);
              setActiveTab(1);
            }}
            onDownloadFile={handleDirectDownload}
          />
        )}

        {activeTab === 4 && (
          <TabAuditLog
            logs={auditLogs}
            onLogsUpdated={setAuditLogs}
            onShowToast={showToast}
          />
        )}

        {activeTab === 5 && principalRole === 'admin' && (
          <TabEndpointHealthAudit devices={devices} />
        )}
        {activeTab === 5 && principalRole !== 'admin' && (
          <div className="rounded-xl border border-rose-900/50 bg-rose-950/20 p-5 text-sm text-rose-200">
            Fitur Audit Endpoint &amp; Kondisi hanya tersedia untuk administrator.
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-[#232936] bg-[#0f131a] py-4 text-center font-mono text-[11px] text-slate-500">
        <div className="mx-auto flex max-w-[1600px] flex-col items-center justify-between gap-1.5 px-4 sm:flex-row sm:px-6">
          <span>PASOPATI v2.6 · Protokol Audit Sistem &amp; Operasi Pengamanan Agen TI</span>
          <span className="text-slate-600">Remediasi Taktis · Akurat · Aman</span>
        </div>
      </footer>

      </div>

      {/* Commander Briefing Report Modal (Rata Kiri-Kanan / Justified Text) */}
      {isReportModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-md flex items-center justify-center p-3 sm:p-6 animate-fadeIn">
          <div className="max-w-4xl w-full max-h-[92vh] bg-[#080d16] border border-slate-800 rounded-lg shadow-2xl flex flex-col overflow-hidden">
            
            {/* Modal Header */}
            <div className="px-5 py-4 border-b border-slate-800 bg-[#0c1220] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-sky-950/60 border border-sky-800/60 text-sky-400">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-sm font-bold font-mono text-slate-100 tracking-wide">
                    SIMULASI KESIAPAN SIBER // DOKUMEN AUDIT STANDAR PERTAHANAN
                  </div>
                  <div className="text-xs text-slate-400 font-mono">
                    Klasifikasi: SIMULASI · Acuan: DISA STIG, CIS Benchmark v8.0, ISA/IEC 62443
                  </div>
                </div>
              </div>
              <button
                onClick={() => setIsReportModalOpen(false)}
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
                title="Tutup Modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body: Justified text (Rata Kiri dan Kanan) */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-slate-200 font-sans text-sm">
              
              {/* Defense Labs Letterhead */}
              <div className="text-center border-b border-slate-800 pb-5">
                <div className="font-mono text-xs font-bold text-sky-400 tracking-widest uppercase">
                  PASOPATI CYBER DEFENSE LABS
                </div>
                <div className="text-lg font-black font-mono tracking-wider text-slate-100 mt-1">
                  TACTICAL READINESS & DEFENSE-GRADE COMPLIANCE SIMULATION
                </div>
                <div className="inline-block mt-2 px-3 py-0.5 rounded text-[11px] font-mono font-bold bg-sky-950/70 border border-sky-800/80 text-sky-300">
                  KLASIFIKASI: SIMULASI // PROTOTYPE EVALUATION REPORT
                </div>
                <div className="text-xs text-slate-500 font-mono mt-2">
                  Nomor: SIM/LAP-SIBER/PASOPATI/{new Date().getFullYear()} · Waktu Audit: {new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC
                </div>
              </div>

              {/* 1. Ringkasan Eksekutif (Justified) */}
              <div className="space-y-2">
                <div className="text-xs font-bold font-mono tracking-wider text-sky-400 uppercase">
                  1. Ringkasan Eksekutif Simulasi Kesiapan
                </div>
                <p 
                  className="text-slate-300 leading-relaxed text-justify"
                  style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                >
                  Telah dilaksanakan simulasi audit kepatuhan dan inspeksi siber otomatis terhadap aset infrastruktur inti (Core Infrastructure) dan perangkat operasional taktis (OT/BMS) menggunakan arsitektur PASOPATI. Purwarupa ini dirancang sebagai sistem evaluasi kepatuhan mandiri berbasis standar internasional CIS Benchmark v8.0, DISA STIG, dan ISA/IEC 62443 guna memvalidasi postur keamanan endpoint dari risiko lateral movement dan celah konfigurasi.
                </p>
                <p 
                  className="text-slate-300 leading-relaxed text-justify"
                  style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                >
                  Indeks kesiapan siber agregat armada saat ini berada pada tingkat <strong>{calculateFleetScore(devices)}/100</strong>. Kondisi ini mencerminkan postur operasional yang memerlukan tindakan mitigasi terarah pada perangkat yang masih membuka celah port berbahaya dan protokol komunikasi tanpa enkripsi.
                </p>
              </div>

              {/* 2. Inventarisasi dan Status Aset (Justified) */}
              <div className="space-y-3">
                <div className="text-xs font-bold font-mono tracking-wider text-sky-400 uppercase">
                  2. Inventarisasi Aset & Rekapitulasi Kepatuhan
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {devices.map((d, idx) => {
                    const fails = d.checks.filter(c => c.status === 'FAIL');
                    return (
                      <div key={d.id} className="p-3.5 rounded-lg bg-[#0c1322] border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-xs text-slate-100">
                            [{idx + 1}] {d.name}
                          </span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                            fails.length === 0 ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'
                          }`}>
                            {fails.length === 0 ? '100% COMPLIANT' : `${fails.length} VIOLATIONS`}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 font-mono">
                          {d.role} · {d.os}
                        </div>
                        <div className="text-xs text-slate-500 font-mono">
                          IP: {d.ip} · Ports: [{d.openPorts.join(', ') || 'Isolated'}]
                        </div>
                        {fails.length > 0 && (
                          <div 
                            className="text-xs text-rose-300/90 pt-1 border-t border-slate-800/80 text-justify"
                            style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                          >
                            <strong>Temuan Kritis:</strong> {fails.map(f => f.parameter).join(', ')}.
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* 3. Rekomendasi Mitigasi Taktis (Justified) */}
              <div className="space-y-2">
                <div className="text-xs font-bold font-mono tracking-wider text-sky-400 uppercase">
                  3. Rekomendasi Mitigasi Taktis Berbasis Standar CIS / DISA STIG
                </div>
                <div className="space-y-2 text-slate-300 text-xs">
                  <div 
                    className="p-3 rounded-lg bg-[#0c1322] border border-slate-800 text-justify leading-relaxed"
                    style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                  >
                    <strong className="text-sky-300">A. Otomasi Remediasi & Hardening:</strong> Eksekusi prosedur Assisted Hardening (Dry-Run) pada seluruh workstation dan pangkalan data yang masih berstatus FAIL untuk menutup port listener berisiko (SMB 445, Telnet 23, Backdoor 4444) serta menegakkan isolasi firewall host.
                  </div>
                  <div 
                    className="p-3 rounded-lg bg-[#0c1322] border border-slate-800 text-justify leading-relaxed"
                    style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                  >
                    <strong className="text-sky-300">B. Penegakan Kepatuhan Zona & Conduit Radio Taktis (ISA/IEC 62443):</strong> Hentikan penggunaan protokol plaintext tanpa otentikasi kuat pada simpul radio lapangan (GW-RADIO-TAKTIS-OT). Wajibkan penerapan tunneling terenkripsi (SSH/TLS) guna melindungi pertukaran data dari bahaya intersepsi.
                  </div>
                  <div 
                    className="p-3 rounded-lg bg-[#0c1322] border border-slate-800 text-justify leading-relaxed"
                    style={{ textAlign: 'justify', textJustify: 'inter-word' }}
                  >
                    <strong className="text-sky-300">C. Distribusi Telemetri Terpusat Melalui Agen Mandiri:</strong> Kerahkan skrip audit mandiri pasopati_audit.py ke seluruh sub-satuan dengan parameter --push-url untuk pelaporan telemetri berkala ke Puskodal Command Center.
                  </div>
                </div>
              </div>

              {/* Signature Block */}
              <div className="pt-4 border-t border-slate-800 flex justify-end">
                <div className="text-right text-xs font-mono space-y-1">
                  <div className="text-slate-400">TIM PENGEMBANG PASOPATI</div>
                  <div className="text-slate-100 font-bold">DEFENSE-GRADE CYBER READINESS PROTOTYPE</div>
                  <div className="text-emerald-400 font-semibold">[VERIFIKASI DIGITAL PASOPATI ENGINE]</div>
                </div>
              </div>

            </div>

            {/* Modal Actions */}
            <div className="px-5 py-3.5 border-t border-slate-800 bg-[#0c1220] flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <button
                  onClick={handleDownloadTextReport}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-sky-400" />
                  <span>Unduh Dokumen (.txt)</span>
                </button>
                <button
                  onClick={handleDownloadMarkdownReport}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Unduh Dokumen (.md)</span>
                </button>
                <button
                  onClick={() => {
                    const text = buildCommanderReportText();
                    navigator.clipboard.writeText(text);
                    setCopiedReport(true);
                    setTimeout(() => setCopiedReport(false), 2000);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedReport ? 'Tersalin' : 'Salin Teks'}</span>
                </button>
              </div>

              <button
                onClick={() => setIsReportModalOpen(false)}
                className="px-4 py-1.5 rounded-md text-xs font-mono font-bold bg-slate-700 hover:bg-slate-600 text-white transition-colors"
              >
                Tutup
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
