import React, { useState } from 'react';
import { DeviceInfo, AuditAgentResult } from '../types';
import { sfx } from '../utils/audio';
import { Download, Upload, Terminal, CheckCircle2, AlertCircle, FileCode, Server } from 'lucide-react';

interface TabLiveAgentProps {
  onAddUploadedDevice: (device: DeviceInfo, source?: 'agent' | 'demo') => Promise<void>;
  onNavigateToAudit: (deviceId: string) => void;
  onDownloadFile?: (fileName: string, downloadUrl: string) => void;
  onRequestSecureDownload?: (fileName: string, downloadUrl: string) => void;
}

export const TabLiveAgent: React.FC<TabLiveAgentProps> = ({
  onAddUploadedDevice,
  onNavigateToAudit,
  onDownloadFile,
  onRequestSecureDownload
}) => {
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadedResult, setUploadedResult] = useState<AuditAgentResult | null>(null);
  const [savingResult, setSavingResult] = useState(false);
  const [isScanningHost, setIsScanningHost] = useState(false);

  // Live real scan of current server container
  const handleLiveHostScan = async () => {
    setIsScanningHost(true);
    setUploadError(null);
    sfx.playPing();
    try {
      const res = await fetch('/api/scan-host', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ unitName: 'PASOPATI-LIVE-RUNTIME-NODE' })
      });
      if (!res.ok) throw new Error('Gagal mengeksekusi pemindaian mesin host.');
      const json = await res.json();
      await processAuditData(json);
    } catch (err: any) {
      setUploadError(err.message || 'Gagal memindai mesin server.');
    } finally {
      setIsScanningHost(false);
    }
  };

  // Direct Download helper
  const triggerDownload = (fileName: string, url: string) => {
    sfx.playClick();
    if (onDownloadFile) {
      onDownloadFile(fileName, url);
    } else if (onRequestSecureDownload) {
      onRequestSecureDownload(fileName, url);
    } else {
      window.location.href = url;
    }
  };

  // Download pasopati_audit.py
  const handleDownloadAgent = () => {
    triggerDownload('pasopati_audit.py', '/api/download/pasopati_audit.py');
  };

  // Download app.py
  const handleDownloadApp = () => {
    triggerDownload('app.py', '/api/download/app.py');
  };

  // Download requirements.txt
  const handleDownloadRequirements = () => {
    triggerDownload('requirements.txt', '/api/download/requirements.txt');
  };

  // Download README.md
  const handleDownloadReadme = () => {
    triggerDownload('README.md', '/api/download/README.md');
  };

  // Download Project ZIP
  const handleDownloadZip = () => {
    triggerDownload('pasopati-project.zip', '/api/download/project-zip');
  };

  // File Upload handler
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 5 * 1024 * 1024) {
      setUploadError('Ukuran file JSON melebihi batas aman 5 MB. File ditolak.');
      return;
    }

    setUploadError(null);
    sfx.playClick();

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target?.result as string);
        if (!json.metadata || !json.device_info || !json.compliance_matrix) {
          throw new Error('Format JSON tidak sesuai dengan skema PASOPATI Agent.');
        }

        void processAuditData(json).catch((err: any) => setUploadError(err?.message || 'Gagal menyimpan endpoint ke VPS.'));
      } catch (err: any) {
        setUploadError(err.message || 'Gagal memproses file JSON.');
      }
    };
    reader.readAsText(file);
  };

  // Process and ingest into session devices
  const processAuditData = async (json: AuditAgentResult, source: 'agent' | 'demo' = 'agent') => {
    setUploadError(null);
    setSavingResult(true);
    const rawUnitName = String(json.metadata?.tactical_unit || 'UPLOADED-JURI-NODE');
    const unitName = /^[A-Z0-9][A-Z0-9-_]{0,31}$/.test(rawUnitName.toUpperCase()) ? rawUnitName.toUpperCase() : 'UPLOADED-JURI-NODE';
    const deviceInfo = json.device_info || ({} as any);
    const matrix = Array.isArray(json.compliance_matrix) ? json.compliance_matrix : [];
    const rawPorts = deviceInfo.ports_list;

    const newDevice: DeviceInfo = {
      id: unitName,
      agentId: unitName,
      name: unitName,
      hostname: String(deviceInfo.hostname || 'Unknown Host'),
      role: 'Perangkat Uji Nyata (Hasil Scan CLI Agent)',
      os: String(deviceInfo.os || 'unknown'),
      platformType: String(deviceInfo.os || '').toLowerCase().includes('windows') ? 'windows' : 'linux',
      ip: String(deviceInfo.primary_ip || '127.0.0.1'),
      mac: String(deviceInfo.mac_address || '00:00:00:00:00:00'),
      user: String(deviceInfo.active_user || 'operator'),
      openPorts: Array.isArray(rawPorts) ? rawPorts.map(Number).filter(n => Number.isFinite(n)) : [],
      checks: matrix.map((c, i) => {
        const rawStatus = String(c?.status || 'WARNING').toUpperCase();
        const status = (['PASS', 'WARNING', 'FAIL', 'N/A'].includes(rawStatus) ? rawStatus : 'WARNING') as DeviceInfo['checks'][number]['status'];
        return {
          id: `up-${i}`,
          parameter: String(c?.parameter || 'Security Parameter'),
          category: (c?.category as any) || 'Network & Port',
          cis_id: String(c?.cis_id || 'CIS 1.0'),
          status,
          details: String((c as any)?.detail || c?.details || ''),
          mitigation: 'Terapkan perbaikan otomatis via Tab AI Hardening.'
        };
      })
    };

    try {
      await onAddUploadedDevice(newDevice, source);
      setUploadedResult(json);
      sfx.playSuccess();
    } catch (err: any) {
      setUploadedResult(null);
      setUploadError(err?.message || 'Gagal menyimpan endpoint ke registry pusat.');
    } finally {
      setSavingResult(false);
    }
  };

  // 1-Click Sample Preloader for jury convenience
  const handleLoadSample = () => {
    sfx.playPing();
    const sample: AuditAgentResult = {
      metadata: {
        scanner: 'PASOPATI Autonomous Agent v1.0',
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
        tactical_unit: 'LAPTOP-DEWAN-JURI',
        standard_baseline: 'CIS Benchmark v8.0 & DISA STIG Core Infra'
      },
      device_info: {
        hostname: 'evaluator-jury-workstation',
        os: 'Windows 11 Pro (Build 22631.3296)',
        platform_type: 'Windows Workstation',
        primary_ip: '192.168.1.105',
        mac_address: '88:66:5A:21:99:FF',
        active_user: 'dewan_juri',
        listening_ports_count: 7,
        critical_ports_detected: 1,
        ports_list: [135, 445, 5357, 8080]
      },
      scoring: {
        cyber_readiness_score: 60,
        passed_checks: 3,
        warning_checks: 1,
        failed_checks: 1,
        total_checks: 5
      },
      compliance_matrix: [
        {
          parameter: 'Network & Dangerous Ports Filtering',
          category: 'Network & Port',
          cis_id: 'CIS 3.4',
          status: 'FAIL',
          details: 'Port SMB 445 terbuka di antarmuka Wi-Fi lokal tanpa isolasi subnet.'
        },
        {
          parameter: 'Host-Based Local Firewall Active',
          category: 'Endpoint Protection',
          cis_id: 'CIS 3.5.1',
          status: 'PASS',
          details: 'Windows Defender Firewall aktif di seluruh profil jaringan.'
        },
        {
          parameter: 'Guest Account Lockdown',
          category: 'Access Control',
          cis_id: 'DISA STIG WN11-00-000010',
          status: 'PASS',
          details: 'Akun bawaan Guest telah dinonaktifkan.'
        },
        {
          parameter: 'USB Storage Device Control',
          category: 'Endpoint Protection',
          cis_id: 'DISA STIG WN11-CC-000180',
          status: 'WARNING',
          details: 'USB Mass Storage belum dibatasi via GPO atau registry Start=4.'
        },
        {
          parameter: 'Windows Event Log & Auditing',
          category: 'System Logging',
          cis_id: 'DISA STIG WN11-AU-000050',
          status: 'PASS',
          details: 'Security auditing service aktif merekam event log.'
        }
      ]
    };

    void processAuditData(sample, 'demo').catch((err: any) => setUploadError(err?.message || 'Gagal memuat contoh demo.'));
  };

  return (
    <div className="space-y-6">
      
      {/* Title */}
      <div className="bg-slate-900/60 p-5 rounded-lg border border-slate-800">
        <h2 className="text-xl font-bold tracking-tight text-rose-400 font-mono">
          LIVE AGENT SCANNER & CUSTOM JSON INGESTION
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Fasilitas Pengujian Nyata untuk Dewan Juri: Jalankan CLI Agent di Laptop/VM Anda Sendiri & Unggah File Audit
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column: Download CLI Agent & Run Instructions */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
              <Terminal className="w-5 h-5 text-rose-400" />
              <h3 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
                1. Unduh Script Pemeriksaan (`pasopati_audit.py`)
              </h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Script Python mandiri tanpa dependensi rumit yang memindai host nyata (Linux / Windows) untuk socket port liar, firewall lokal, kontrol akses root/guest, dan log audit sesuai standar <strong>CIS Benchmark & DISA STIG</strong>.
            </p>

            <button
              onClick={handleDownloadAgent}
              className="w-full py-2.5 px-4 rounded-md bg-rose-600 hover:bg-rose-500 text-white font-bold font-mono text-xs flex items-center justify-center gap-2 transition-all shadow-[0_0_15px_rgba(239,68,68,0.25)]"
            >
              <Download className="w-4 h-4" />
              <span>DOWNLOAD PASOPATI_AUDIT.PY (CLI)</span>
            </button>

            {/* CLI Execution Guide */}
            <div className="mt-5 space-y-2">
              <span className="text-xs font-mono text-slate-400 block font-semibold">
                Panduan Menjalankan di Terminal Dewan Juri:
              </span>
              <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[11px] text-rose-400/90 space-y-2">
                <div>
                  <span className="text-slate-500"># 1. Jalankan audit lokal di Linux/Windows:</span>
                  <div className="text-slate-200">python pasopati_audit.py -u "LAPTOP-JURI-TEST"</div>
                </div>
                <div>
                  <span className="text-slate-500"># 2. File hasil scan otomatis tersimpan:</span>
                  <div className="text-slate-300">audit_result.json</div>
                </div>
              </div>
            </div>
          </div>

          {/* Repository Packages Downloader */}
          <div className="pt-4 border-t border-slate-800 space-y-3">
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-600/40 flex items-center justify-between gap-3">
              <div>
                <div className="text-xs font-bold font-mono text-rose-300">
                  PAKET LENGKAP PROYEK (1-KLIK PINDAH KE LAPTOP)
                </div>
                <div className="text-[11px] text-slate-400">
                  Semua berkas (src, app.py, agent, requirements, configs) dalam 1 arsip ZIP.
                </div>
              </div>
              <button
                onClick={handleDownloadZip}
                className="shrink-0 px-3 py-2 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold font-mono text-xs flex items-center gap-1.5 transition-all shadow-[0_0_12px_rgba(239,68,68,0.3)]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Project (.ZIP)</span>
              </button>
            </div>

            <div>
              <span className="text-[11px] font-mono text-slate-400 block mb-1.5 font-semibold">
                Atau Unduh Berkas Individual (Bypass IDM / Direct Access):
              </span>
              <div className="text-[10px] text-slate-500 font-mono mb-2">
                *Jika software download manager (seperti IDM) memblokir arsip ZIP, gunakan tombol di bawah untuk mengunduh modul secara mandiri:
              </div>
              <div className="grid grid-cols-3 gap-2">
                <button
                  onClick={handleDownloadApp}
                  className="px-2 py-1.5 rounded bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-rose-400 text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors"
                >
                  <FileCode className="w-3.5 h-3.5 text-rose-400" />
                  <span>app.py</span>
                </button>
                <button
                  onClick={handleDownloadRequirements}
                  className="px-2 py-1.5 rounded bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-rose-400 text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors"
                >
                  <FileCode className="w-3.5 h-3.5 text-rose-400" />
                  <span>requirements.txt</span>
                </button>
                <button
                  onClick={handleDownloadReadme}
                  className="px-2 py-1.5 rounded bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-300 hover:text-rose-400 text-[11px] font-mono flex items-center justify-center gap-1.5 transition-colors"
                >
                  <FileCode className="w-3.5 h-3.5 text-rose-400" />
                  <span>README.md</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Upload JSON or 1-Click Sample Preloader */}
        <div className="lg:col-span-6 bg-slate-900/80 border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
              <Upload className="w-5 h-5 text-sky-400" />
              <h3 className="text-sm font-bold font-mono text-slate-100 uppercase tracking-wider">
                2. Unggah File `audit_result.json`
              </h3>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Unggah file JSON keluaran dari <code>pasopati_audit.py</code> untuk memvisualisasikan spesifikasi endpoint nyata dan mengeksekusi auto-remediasi berbasis AI.
            </p>

            {/* File Dropzone */}
            <label className="border-2 border-dashed border-slate-700 hover:border-rose-500 rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer transition-colors bg-slate-950/50">
              <Upload className="w-8 h-8 text-slate-500 mb-2" />
              <span className="text-xs font-mono text-slate-300 font-semibold">
                Klik untuk memilih file audit_result.json
              </span>
              <span className="text-[10px] font-mono text-slate-500 mt-1">
                Format: .json yang dihasilkan dari pasopati_audit.py
              </span>
              <input
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>

            {savingResult && (
              <div className="mt-3 p-3 rounded bg-sky-950/60 border border-sky-800 text-sky-200 text-xs font-mono flex items-center gap-2" role="status">
                <Server className="w-4 h-4 text-sky-300 shrink-0 animate-pulse" />
                <span>Menyimpan ke registry pusat… endpoint belum ditampilkan sampai server mengonfirmasi.</span>
              </div>
            )}

            {uploadError && (
              <div className="mt-3 p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2" role="alert">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{uploadError}</span>
              </div>
            )}

            {/* Live Real Host Scan Button */}
            <div className="mb-4 p-3.5 rounded-lg bg-rose-950/40 border border-rose-500/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-bold text-rose-400 flex items-center gap-1.5">
                  <Terminal className="w-4 h-4 text-rose-400" />
                  UJI NYATA LANGSUNG (REAL HOST CONTAINER SCAN)
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-900/60 text-rose-300">
                  LIVE CLI EXECUTION
                </span>
              </div>
              <p className="text-[11px] text-slate-300 mb-3 leading-relaxed">
                Ingin uji langsung tanpa terminal? Klik tombol di bawah untuk mengeksekusi <code>pasopati_audit.py</code> secara nyata pada mesin server ini sekarang!
              </p>
              <button
                disabled={isScanningHost || savingResult}
                onClick={handleLiveHostScan}
                className="w-full py-2.5 px-3 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(239,68,68,0.3)] flex items-center justify-center gap-2 disabled:opacity-50"
              >
                <Server className={`w-4 h-4 ${isScanningHost ? 'animate-spin' : ''}`} />
                <span>{isScanningHost ? 'SEDANG MEMINDAI MESIN HOST NYATA...' : '⚡ SCAN MESIN HOST INI SEKARANG SECARA REAL-TIME'}</span>
              </button>
            </div>

            {/* Quick 1-Click Sample Load Button */}
            <div className="mt-4 pt-4 border-t border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block mb-2 font-semibold">
                Opsi Simulasi Laptop Dewan Juri:
              </span>
              <button
                onClick={handleLoadSample}
                className="w-full py-2 px-3 rounded bg-sky-950/80 hover:bg-sky-900 border border-sky-600/60 text-sky-200 text-xs font-mono font-semibold transition-all flex items-center justify-center gap-2"
              >
                <Server className="w-4 h-4 text-sky-400" />
                <span>🧪 Muat Contoh Hasil Scan Agent (Sample Juri Laptop)</span>
              </button>
            </div>
          </div>

          {/* Uploaded Node Confirmation Card */}
          {uploadedResult && (
            <div className="bg-rose-950/30 border border-rose-700/60 p-4 rounded-lg space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-rose-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  PERANGKAT BERHASIL DIINTEGRASIKAN
                </span>
                <span className="text-xs font-mono text-slate-300 font-bold">
                  {uploadedResult.metadata?.tactical_unit || 'UPLOADED'}
                </span>
              </div>
              <div className="text-[11px] font-mono text-slate-300">
                OS: {uploadedResult.device_info?.os || 'unknown'} · IP: {uploadedResult.device_info?.primary_ip || '—'}
              </div>
              <div className="flex items-center justify-between pt-1">
                <span className="text-xs font-mono text-rose-400">
                  Skor Awal: <strong>{uploadedResult.scoring?.cyber_readiness_score ?? '—'}/100</strong>
                </span>
                <button
                  onClick={() => onNavigateToAudit((uploadedResult.metadata?.tactical_unit || 'UPLOADED').toUpperCase())}
                  className="px-2.5 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-[11px] font-mono font-bold transition-all"
                >
                  Periksa di Tab Deep Audit &rarr;
                </button>
              </div>
            </div>
          )}
        </div>

      </div>

    </div>
  );
};
