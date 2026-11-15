import React from 'react';
import { DeviceInfo } from '../types';
import { calculateDeviceScore } from '../data/mockDevices';
import { ShieldCheck, AlertTriangle, XCircle, ArrowRight, Server, Network, UserCheck, HardDrive, Cpu, ShieldAlert, Activity, Lock, Unlock, MinusCircle } from 'lucide-react';
import { sfx } from '../utils/audio';

interface TabDeepAuditProps {
  devices: DeviceInfo[];
  selectedDeviceId: string;
  onSelectDevice: (deviceId: string) => void;
  onNavigateToHardening: (deviceId: string) => void;
  onToggleQuarantine?: (deviceId: string) => void;
  principalRole?: string | null;
  onWaiversChanged?: (deviceId: string) => void;
}

export const TabDeepAudit: React.FC<TabDeepAuditProps> = ({
  devices,
  selectedDeviceId,
  onSelectDevice,
  onNavigateToHardening,
  onToggleQuarantine,
  principalRole,
  onWaiversChanged
}) => {
  const currentDevice = devices.find(d => d.id === selectedDeviceId) || devices[0];
  const [waiverBusy, setWaiverBusy] = React.useState<string | null>(null);
  const waiversEnabled = principalRole === 'admin' || principalRole === 'planner';
  if (!currentDevice) {
    return <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-8 text-center text-sm text-slate-400">Belum ada endpoint pusat. Tambahkan endpoint dari Dashboard atau kirim telemetry agen.</div>;
  }
  const deviceScore = calculateDeviceScore(currentDevice.checks || []);

  const handleWaive = async (parameter: string) => {
    if (!waiversEnabled) return;
    const reason = window.prompt(`Alasan waiver untuk:\n${parameter}`)?.trim();
    if (!reason) return;
    const days = Math.min(Math.max(Number(window.prompt('Berlaku berapa hari? (1-365)', '30')) || 30, 1), 365);
    setWaiverBusy(parameter);
    try {
      const res = await fetch('/api/waivers', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceId: currentDevice.id, parameter, reason, days })
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        window.alert(data?.reason || 'Gagal membuat waiver.');
        return;
      }
      await onWaiversChanged?.(currentDevice.id);
    } finally {
      setWaiverBusy(null);
    }
  };

  const handleRemoveWaiver = async (waiverId: string) => {
    if (!waiversEnabled) return;
    setWaiverBusy(waiverId);
    try {
      await fetch(`/api/waivers/${encodeURIComponent(currentDevice.id)}/${encodeURIComponent(waiverId)}`, {
        method: 'DELETE',
        credentials: 'same-origin'
      });
      await onWaiversChanged?.(currentDevice.id);
    } finally {
      setWaiverBusy(null);
    }
  };

  const criticalPorts = [445, 3389, 23, 21, 4444];

  return (
    <div className="space-y-6">
      
      {/* Header & Device Selector */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-lg border border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-rose-400 font-mono">
            DEEP ENDPOINT AUDIT & CIS/STIG MATRIX
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Verifikasi Kepatuhan Mendalam Terhadap Parameter CIS Benchmark & DISA STIG Core Infra
          </p>
        </div>

        {/* Device Switcher Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
          {devices.map(d => {
            const isSelected = d.id === currentDevice.id;
            const score = calculateDeviceScore(d.checks);
            return (
              <button
                key={d.id}
                onClick={() => {
                  sfx.playClick();
                  onSelectDevice(d.id);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap transition-all border ${
                  isSelected
                    ? 'bg-rose-950 text-rose-300 border-rose-600/70 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                    : 'bg-slate-900/70 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <span>{d.name}</span>
                <span className="ml-1.5 text-[10px] opacity-75 tabular-nums">({score}%)</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Endpoint Specifications Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4 mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-rose-950/80 border border-rose-700/50 text-rose-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold font-mono text-slate-100">
                  {currentDevice.name}
                </h3>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  {currentDevice.platformType}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">{currentDevice.role}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[11px] font-mono text-slate-400 block">Kesiapan Endpoint</span>
              <span
                className={`text-2xl font-bold font-mono tabular-nums ${
                  deviceScore >= 75 ? 'text-emerald-400' : deviceScore >= 50 ? 'text-amber-400' : 'text-rose-400'
                }`}
              >
                {deviceScore}/100
              </span>
            </div>

            {/* Emergency Network Quarantine Switch (DEFCON 1 Kill-Switch) */}
            <button
              onClick={() => {
                sfx.playPing();
                if (onToggleQuarantine) onToggleQuarantine(currentDevice.id);
              }}
              title={currentDevice.isQuarantined ? "Cabut Status Karantina di Registry" : "Tandai Karantina di Registry (eksekusi firewall oleh agen host)"}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-md text-xs font-bold font-mono transition-all border whitespace-nowrap ${
                currentDevice.isQuarantined
                  ? 'bg-rose-950 text-rose-300 border-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.4)] animate-pulse'
                  : 'bg-slate-900 hover:bg-rose-950/70 text-slate-300 hover:text-rose-300 border-slate-700 hover:border-rose-700'
              }`}
            >
              {currentDevice.isQuarantined ? <Unlock className="w-3.5 h-3.5 text-rose-400" /> : <Lock className="w-3.5 h-3.5 text-rose-400" />}
              <span>{currentDevice.isQuarantined ? 'ISOLASI DITANDAI (LEPAS)' : 'TANDAI KARANTINA'}</span>
            </button>

            <button
              onClick={() => {
                sfx.playClick();
                onNavigateToHardening(currentDevice.id);
              }}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold font-mono transition-all shadow-[0_0_12px_rgba(239,68,68,0.25)] whitespace-nowrap"
            >
              <span>Remediasi AI</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Quarantine Active Notice Banner */}
        {currentDevice.isQuarantined && (
          <div className="mb-4 p-3 rounded bg-rose-950/60 border border-rose-600/70 text-xs font-mono text-rose-200 flex items-center justify-between gap-3 animate-pulse">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
              <span>
                <strong>STATUS KARANTINA DICATAT:</strong> Penandaan isolasi tersimpan di PUSKODAL untuk {currentDevice.name}. Server tidak memutus jaringan; eksekusi firewall lokal wajib dilakukan oleh operator/agen host (pasopati_remediate.py).
              </span>
            </div>
            <span className="text-[10px] bg-rose-900/80 px-2 py-0.5 rounded text-white font-bold">
              DEFCON 1 FLAGGED
            </span>
          </div>
        )}

        {/* Tech Specs 4-Column Strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
          <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
            <span className="text-slate-500 block mb-1 flex items-center gap-1">
              <Cpu className="w-3 h-3 text-slate-400" />
              SISTEM OPERASI
            </span>
            <span className="text-slate-200 block truncate" title={currentDevice.os}>
              {currentDevice.os}
            </span>
          </div>

          <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
            <span className="text-slate-500 block mb-1 flex items-center gap-1">
              <Network className="w-3 h-3 text-slate-400" />
              JARINGAN & IP
            </span>
            <span className="text-sky-400 block tabular-nums">{currentDevice.ip}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">{currentDevice.mac}</span>
          </div>

          <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
            <span className="text-slate-500 block mb-1 flex items-center gap-1">
              <UserCheck className="w-3 h-3 text-slate-400" />
              PENGGUNA AKTIF
            </span>
            <span className="text-rose-400 block">{currentDevice.user}</span>
            <span className="text-[10px] text-slate-500 block mt-0.5">{currentDevice.hostname}</span>
          </div>

          <div className="bg-slate-950 p-3 rounded border border-slate-800/80">
            <span className="text-slate-500 block mb-1 flex items-center gap-1">
              <HardDrive className="w-3 h-3 text-slate-400" />
              OPEN PORTS
            </span>
            <div className="flex flex-wrap gap-1 mt-1">
              {currentDevice.openPorts.map(p => {
                const isCrit = criticalPorts.includes(p);
                return (
                  <span
                    key={p}
                    className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      isCrit
                        ? 'bg-rose-950 text-rose-300 border border-rose-700/60 font-bold'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    TCP/{p}
                  </span>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Matrix Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg overflow-hidden">
        {/* Category Filter Pills & Compliance Matrix */}
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-semibold text-rose-400 uppercase tracking-wider">
              Matriks Kepatuhan Parameter Keamanan (CIS v8.0 / DISA STIG / ISA 62443)
            </span>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {currentDevice.checks.length} Parameter Terinspeksi Mendalam
          </span>
        </div>

        {/* Stateful Compliance Drift Timeline Card */}
        {currentDevice.history && currentDevice.history.length > 0 && (
          <div className="p-4 bg-slate-950/90 border-b border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-300 font-bold flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-sky-400" />
                HISTORI COMPLIANCE DRIFT OVER TIME (PELACAKAN DEGRADASI POSTUR)
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Log Database Histori Lokal
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {currentDevice.history.map((h, idx) => (
                <div key={idx} className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-slate-800 pb-1 mb-1.5">
                    <span>{h.timestamp}</span>
                    <span className={`font-bold tabular-nums ${h.score >= 70 ? 'text-emerald-400' : h.score >= 50 ? 'text-amber-400' : 'text-rose-400'}`}>
                      {h.score}/100
                    </span>
                  </div>
                  <div className="text-slate-200 font-semibold truncate">{h.event}</div>
                  <div className="flex items-center gap-2 text-[10px] text-slate-400 mt-1">
                    <span className="text-emerald-400">{h.passCount} PASS</span> · 
                    <span className="text-amber-400">{h.warnCount} WARN</span> · 
                    <span className="text-rose-400">{h.failCount} FAIL</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="divide-y divide-slate-800/80">
          {currentDevice.checks.map(check => {
            const isPass = check.status === 'PASS';
            const isWarn = check.status === 'WARNING';
            const isFail = check.status === 'FAIL';
            const isNa = check.status === 'N/A';
            const isWaived = check.status === 'WAIVED';

            return (
              <div key={check.id} className="p-4 hover:bg-slate-800/30 transition-colors">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono font-bold text-sm text-slate-200">
                      {check.parameter}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                      {check.category}
                    </span>
                    <span className="text-[10px] font-mono text-rose-400/90 hidden md:inline">
                      [{check.cis_id}]
                    </span>
                  </div>

                  <div className="shrink-0">
                    {isPass && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-700/60 shadow-[0_0_8px_rgba(16,185,129,0.2)]">
                        <ShieldCheck className="w-3.5 h-3.5" />
                        PASS
                      </span>
                    )}
                    {isWarn && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/60 shadow-[0_0_8px_rgba(245,158,11,0.2)]">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        WARNING
                      </span>
                    )}
                    {isNa && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-600">
                        <MinusCircle className="w-3.5 h-3.5" />
                        N/A
                      </span>
                    )}
                    {isFail && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold bg-rose-950/80 text-rose-400 border border-rose-700/60 shadow-[0_0_8px_rgba(239,68,68,0.2)]">
                        <XCircle className="w-3.5 h-3.5" />
                        FAIL
                      </span>
                    )}
                    {isWaived && (
                      <span
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-mono font-bold bg-violet-950/80 text-violet-300 border border-violet-700/60"
                        title={check.waiver ? `${check.waiver.reason} — ${check.waiver.owner}, s/d ${check.waiver.expiresAt}` : ''}
                      >
                        <MinusCircle className="w-3.5 h-3.5" />
                        WAIVED
                      </span>
                    )}
                    {waiversEnabled && (isFail || isWarn) && (
                      <button
                        onClick={() => handleWaive(check.parameter)}
                        disabled={waiverBusy === check.parameter}
                        className="ml-2 text-[10px] font-mono px-2 py-0.5 rounded bg-violet-950/60 text-violet-300 border border-violet-800 hover:bg-violet-900 disabled:opacity-50"
                      >
                        waive
                      </button>
                    )}
                    {waiversEnabled && isWaived && check.waiver && (
                      <button
                        onClick={() => handleRemoveWaiver(check.waiver!.id)}
                        disabled={waiverBusy === check.waiver.id}
                        className="ml-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700 hover:bg-slate-800 disabled:opacity-50"
                      >
                        lepas
                      </button>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-12 gap-3 text-xs mt-2">
                  <div className="md:col-span-7 text-slate-300 bg-slate-950/60 p-2.5 rounded border border-slate-800/60">
                    <span className="text-slate-500 font-mono text-[11px] block mb-0.5">KONDISI TEMUAN:</span>
                    {check.details}
                  </div>
                  <div className="md:col-span-5 text-rose-300/90 bg-rose-950/20 p-2.5 rounded border border-rose-900/40">
                    <span className="text-rose-500 font-mono text-[11px] block mb-0.5">PANDUAN MITIGASI:</span>
                    {check.mitigation}
                  </div>
                  {check.waiver && (
                    <div className="md:col-span-12 text-[11px] font-mono text-violet-300 bg-violet-950/20 p-2.5 rounded border border-violet-900/40">
                      WAIVER: {check.waiver.reason} — {check.waiver.owner} · berlaku s/d{' '}
                      {new Date(check.waiver.expiresAt).toLocaleDateString()}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
