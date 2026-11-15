import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Play,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Terminal,
  MonitorSmartphone,
  Gauge,
  ScrollText,
  ArrowUpRight,
  Clock
} from 'lucide-react';
import { AuditLogEntry, DeviceInfo } from '../types';
import { calculateDeviceScore, calculateFleetScore } from '../data/mockDevices';
import { sfx } from '../utils/audio';
import { EndpointRegistryPanel, type EndpointDraftPayload, type EndpointSyncStatus } from './EndpointRegistryPanel';

interface TabCommandCenterProps {
  devices: DeviceInfo[];
  lastScanTime: string;
  auditLogs: AuditLogEntry[];
  onSelectDevice: (deviceId: string) => void;
  onAuditFinished: () => void;
  onNavigate: (tab: number) => void;
  endpointSyncStatus: EndpointSyncStatus;
  centralEndpointData: boolean;
  canManageEndpoints: boolean;
  canDeleteEndpoints: boolean;
  canViewAuditLog?: boolean;
  lastEndpointSync: string | null;
  onSaveEndpoint: (payload: EndpointDraftPayload, id?: string, expectedRevision?: number) => Promise<void>;
  onDeleteEndpoint: (id: string) => Promise<void>;
}

const ACTION_LABEL: Record<AuditLogEntry['action'], string> = {
  'HARDENING REMEDIATION': 'Remediasi',
  'ROLLBACK RESTORATION': 'Rollback',
  'BASELINE RECON': 'Baseline',
  'TELEMETRY INGESTION': 'Telemetri',
  'QUARANTINE KILL-SWITCH': 'Karantina'
};

export const TabCommandCenter: React.FC<TabCommandCenterProps> = ({
  devices,
  lastScanTime,
  auditLogs,
  onSelectDevice,
  onAuditFinished,
  onNavigate,
  endpointSyncStatus,
  centralEndpointData,
  canManageEndpoints,
  canDeleteEndpoints,
  canViewAuditLog = true,
  lastEndpointSync,
  onSaveEndpoint,
  onDeleteEndpoint
}) => {
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditProgress, setAuditProgress] = useState(0);
  const [auditTrace, setAuditTrace] = useState<string[]>([]);
  const timerRef = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timerRef.current !== null) window.clearInterval(timerRef.current);
    },
    []
  );

  const fleetScore = calculateFleetScore(devices);

  const totals = useMemo(() => {
    let passed = 0;
    let warning = 0;
    let failed = 0;
    devices.forEach(d => {
      d.checks.forEach(c => {
        if (c.status === 'PASS') passed += 1;
        else if (c.status === 'WARNING') warning += 1;
        else if (c.status === 'FAIL') failed += 1;
      });
    });
    return { passed, warning, failed, total: passed + warning + failed };
  }, [devices]);

  // Bar chart: temuan per endpoint (FAIL + WARNING)
  const barData = useMemo(
    () =>
      devices.slice(0, 8).map(d => ({
        id: d.id,
        name: d.name,
        fail: d.checks.filter(c => c.status === 'FAIL').length,
        warn: d.checks.filter(c => c.status === 'WARNING').length,
        score: calculateDeviceScore(d.checks)
      })),
    [devices]
  );
  const barMax = Math.max(4, ...barData.map(d => d.fail + d.warn));

  // Area chart: tren skor agregat dari riwayat endpoint.
  const trend = useMemo(() => {
    const buckets = new Map<string, number[]>();
    devices.forEach(d => {
      (d.history || []).forEach(h => {
        const key = String(h.timestamp || '').slice(0, 10) || 'n/a';
        const arr = buckets.get(key) || [];
        arr.push(Number(h.score) || 0);
        buckets.set(key, arr);
      });
    });
    const points = Array.from(buckets.entries())
      .map(([label, scores]) => ({ label, score: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) }))
      .slice(-7);
    if (points.length === 0) {
      const now = new Date();
      for (let i = 5; i >= 0; i -= 1) {
        const dt = new Date(now.getTime() - i * 86400000);
        points.push({ label: dt.toISOString().slice(5, 10), score: fleetScore });
      }
    }
    return points;
  }, [devices, fleetScore]);

  const trendPoints = useMemo(() => {
    const width = 620;
    const height = 240;
    const padX = 24;
    const padY = 22;
    const step = trend.length > 1 ? (width - padX * 2) / (trend.length - 1) : 0;
    const coords = trend.map((p, i) => ({
      ...p,
      x: padX + step * i,
      y: padY + (height - padY * 2) * (1 - Math.min(100, Math.max(0, p.score)) / 100)
    }));
    const line = coords.map((c, i) => `${i === 0 ? 'M' : 'L'} ${c.x.toFixed(1)} ${c.y.toFixed(1)}`).join(' ');
    const area = `${line} L ${coords[coords.length - 1]?.x.toFixed(1) ?? padX} ${height - padY} L ${coords[0]?.x.toFixed(1) ?? padX} ${height - padY} Z`;
    return { coords, line, area, width, height };
  }, [trend]);

  const recentLogs = auditLogs.slice(0, 6);

  const handleRunAudit = () => {
    sfx.playPing();
    setIsAuditing(true);
    setAuditProgress(0);
    setAuditTrace([
      '[SIMULASI] Inisialisasi evaluasi contoh terhadap data armada di dashboard (bukan scan jaringan).',
      '[SIMULASI] Tidak ada paket SYN/probing yang dikirim ke alamat mana pun.'
    ]);

    const steps = [
      '[SIMULASI] Evaluasi SMB 445 pada SRV-DATA-YONIF (data mock)... [FAIL]',
      '[SIMULASI] Evaluasi listener C2 4444 pada PC-STAF-INTEL-01 (data mock)... [CRITICAL]',
      '[SIMULASI] Evaluasi DISA STIG WN10-00-000015 pada PC-STAF-OPS-02 (data mock)... [PASS]',
      '[SIMULASI] Evaluasi Telnet 23 pada GW-RADIO-TAKTIS-OT (data mock)... [FAIL]',
      '[SIMULASI] Evaluasi auditd daemon pada SRV-LOGISTIK-KODIM (data mock)... [PASS]',
      '[SIMULASI] Agregasi skor selesai. Untuk hasil host nyata: jalankan pasopati_audit.py lalu impor JSON-nya.'
    ];

    let current = 0;
    if (timerRef.current !== null) window.clearInterval(timerRef.current);
    timerRef.current = window.setInterval(() => {
      if (current < steps.length) {
        setAuditTrace(prev => [...prev, steps[current]]);
        setAuditProgress(Math.round(((current + 1) / steps.length) * 100));
        current += 1;
      } else {
        if (timerRef.current !== null) window.clearInterval(timerRef.current);
        timerRef.current = null;
        setIsAuditing(false);
        sfx.playSuccess();
        onAuditFinished();
      }
    }, 430);
  };

  return (
    <div className="pasopati-fade-up space-y-6">
      {/* Page heading */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-[22px] font-black tracking-tight text-slate-100">Dashboard</h1>
          <p className="mt-0.5 text-[12.5px] text-slate-500">
            Ringkasan kesiapan siber, temuan kritis, dan aktivitas remediasi armada.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="hidden text-right sm:block">
            <div className="text-[9px] font-mono uppercase tracking-wider text-slate-600">Sinkronisasi terakhir</div>
            <div className="font-mono text-[11px] text-rose-300">{lastScanTime}</div>
          </div>
          <button
            disabled={isAuditing}
            onClick={handleRunAudit}
            className={`inline-flex items-center gap-2 rounded-lg px-4 py-2.5 text-[12px] font-bold tracking-wide transition-all ${
              isAuditing
                ? 'cursor-not-allowed border border-[#2a3140] bg-[#1b202a] text-slate-500'
                : 'bg-rose-600 text-white shadow-[0_8px_24px_rgba(239,68,68,0.35)] hover:bg-rose-500'
            }`}
          >
            <Play className={`h-4 w-4 ${isAuditing ? 'animate-spin' : ''}`} />
            {isAuditing ? 'SIMULASI BERJALAN...' : 'JALANKAN AUDIT'}
          </button>
        </div>
      </div>

      {/* Audit trace */}
      {isAuditing && (
        <div className="pasopati-panel p-4">
          <div className="mb-2 flex items-center justify-between font-mono text-[11px]">
            <span className="flex items-center gap-2 text-rose-300">
              <Terminal className="h-4 w-4 animate-pulse" /> SIMULASI AUDIT (DATA DASHBOARD): {auditProgress}%
            </span>
            <span className="tabular-nums text-slate-500">{auditProgress}/100</span>
          </div>
          <div className="mb-3 h-2 overflow-hidden rounded-full bg-[#0d1016]">
            <div
              className="h-full rounded-full bg-gradient-to-r from-rose-600 to-rose-400 transition-all duration-300"
              style={{ width: `${auditProgress}%` }}
            />
          </div>
          <div className="max-h-32 space-y-1 overflow-y-auto rounded-md border border-[#232936] bg-[#0d1016] p-3 font-mono text-[11px] text-slate-400">
            {auditTrace.map((line, i) => (
              <div key={i} className="leading-relaxed">{line}</div>
            ))}
          </div>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <div className="kpi-card">
          <div className="kpi-icon"><MonitorSmartphone className="h-7 w-7" /></div>
          <div>
            <div className="text-[11.5px] font-semibold text-slate-400">Endpoint Terpantau</div>
            <div className="mt-1 text-[26px] font-black leading-none tabular-nums text-slate-100">{devices.length}</div>
            <div className="mt-1.5 text-[10px] font-mono text-slate-500">ASET IT / OT TERDAFTAR</div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon"><Gauge className="h-7 w-7" /></div>
          <div>
            <div className="text-[11.5px] font-semibold text-slate-400">Skor Kesiapan</div>
            <div className="mt-1 flex items-baseline gap-1.5">
              <span className="text-[26px] font-black leading-none tabular-nums text-slate-100">{fleetScore}</span>
              <span className="text-[11px] font-mono text-slate-500">/ 100</span>
            </div>
            <div className="mt-1.5 text-[10px] font-mono text-rose-300">
              {fleetScore >= 75 ? 'DEFCON 4 · SIAP OPERASI' : fleetScore >= 50 ? 'DEFCON 3 · WASPADA' : 'DEFCON 1 · SIAGA MERAH'}
            </div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon"><AlertTriangle className="h-7 w-7" /></div>
          <div>
            <div className="text-[11.5px] font-semibold text-slate-400">Temuan Kritis</div>
            <div className="mt-1 text-[26px] font-black leading-none tabular-nums text-rose-400">{totals.failed}</div>
            <div className="mt-1.5 text-[10px] font-mono text-slate-500">
              {totals.warning} WARNING · {totals.passed}/{totals.total} PASS
            </div>
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-icon"><ScrollText className="h-7 w-7" /></div>
          <div>
            <div className="text-[11.5px] font-semibold text-slate-400">Aktivitas Tercatat</div>
            <div className="mt-1 text-[26px] font-black leading-none tabular-nums text-slate-100">{auditLogs.length}</div>
            <div className="mt-1.5 text-[10px] font-mono text-slate-500">AUDIT TRAIL PERSISTEN</div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Findings per endpoint */}
        <div className="pasopati-panel">
          <div className="pasopati-panel-header">
            <div>
              <h2 className="text-[14px] font-bold text-slate-100">Temuan per Endpoint</h2>
              <p className="mt-0.5 text-[10.5px] font-mono text-slate-500">FAIL vs WARNING · 8 endpoint pertama</p>
            </div>
            <button onClick={() => onNavigate(1)} className="pasopati-link inline-flex items-center gap-1">
              Lihat Semua <ArrowUpRight className="h-3 w-3" />
            </button>
          </div>
          <div className="p-4">
            <div className="mb-3 flex items-center gap-4 text-[10px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-rose-500" /> FAIL</span>
              <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm bg-amber-500" /> WARNING</span>
            </div>
            <svg viewBox="0 0 640 280" className="h-[260px] w-full" role="img" aria-label="Temuan per endpoint">
              {[0, 0.25, 0.5, 0.75, 1].map(f => {
                const y = 24 + f * 216;
                return (
                  <g key={f}>
                    <line x1="34" y1={y} x2="628" y2={y} stroke="#2a3140" strokeDasharray="3 6" />
                    <text x="8" y={y + 4} fill="#64748b" fontSize="10" fontFamily="monospace">
                      {Math.round(barMax * (1 - f))}
                    </text>
                  </g>
                );
              })}
              {barData.map((d, i) => {
                const slot = 594 / barData.length;
                const x = 34 + slot * i + slot * 0.18;
                const barW = Math.max(10, slot * 0.26);
                const hFail = (d.fail / barMax) * 216;
                const hWarn = (d.warn / barMax) * 216;
                return (
                  <g key={d.id}>
                    <rect x={x} y={240 - hFail} width={barW} height={hFail} rx="3" fill="#ef4444" />
                    <rect x={x + barW + 3} y={240 - hWarn} width={barW} height={hWarn} rx="3" fill="#f59e0b" opacity="0.85" />
                    <text
                      x={x + barW}
                      y="262"
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize="8.5"
                      fontFamily="monospace"
                    >
                      {d.name.replace(/^(SRV|PC|GW)-/, '').slice(0, 10)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Readiness trend */}
        <div className="pasopati-panel">
          <div className="pasopati-panel-header">
            <div>
              <h2 className="text-[14px] font-bold text-slate-100">Tren Kesiapan Armada</h2>
              <p className="mt-0.5 text-[10.5px] font-mono text-slate-500">Skor agregat dari riwayat telemetri</p>
            </div>
            <span className="rounded-md border border-rose-500/25 bg-rose-500/10 px-2 py-1 font-mono text-[10px] font-bold text-rose-300">
              {fleetScore}/100
            </span>
          </div>
          <div className="p-4">
            <svg viewBox="0 0 640 280" className="h-[260px] w-full" role="img" aria-label="Tren kesiapan armada">
              <defs>
                <linearGradient id="pasopatiArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.55" />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity="0.02" />
                </linearGradient>
              </defs>
              {[0, 0.25, 0.5, 0.75, 1].map(f => {
                const y = 24 + f * 216;
                return (
                  <g key={f}>
                    <line x1="34" y1={y} x2="628" y2={y} stroke="#2a3140" strokeDasharray="3 6" />
                    <text x="8" y={y + 4} fill="#64748b" fontSize="10" fontFamily="monospace">
                      {100 - f * 100}
                    </text>
                  </g>
                );
              })}
              <g transform="translate(18,0)">
                <path d={trendPoints.area} fill="url(#pasopatiArea)" />
                <path d={trendPoints.line} fill="none" stroke="#ef4444" strokeWidth="2.5" strokeLinejoin="round" />
                {trendPoints.coords.map((c, i) => (
                  <g key={i}>
                    <circle cx={c.x} cy={c.y} r="4" fill="#171b23" stroke="#ef4444" strokeWidth="2.5" />
                    <text x={c.x} y="262" textAnchor="middle" fill="#94a3b8" fontSize="9" fontFamily="monospace">
                      {c.label.slice(5)}
                    </text>
                    <text x={c.x} y={c.y - 10} textAnchor="middle" fill="#fca5a5" fontSize="9" fontFamily="monospace">
                      {c.score}
                    </text>
                  </g>
                ))}
              </g>
            </svg>
          </div>
        </div>
      </div>

      {/* Recent activity */}
      <div className="pasopati-panel">
        <div className="pasopati-panel-header">
          <div>
            <h2 className="text-[14px] font-bold text-slate-100">Aktivitas Terbaru</h2>
            <p className="mt-0.5 text-[10.5px] font-mono text-slate-500">
              Audit trail dari server · {auditLogs.length} entri
            </p>
          </div>
          {canViewAuditLog && (
            <button onClick={() => onNavigate(4)} className="pasopati-link inline-flex items-center gap-1">
              Lihat Semua <ArrowUpRight className="h-3 w-3" />
            </button>
          )}
        </div>

        {recentLogs.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
            <ScrollText className="h-7 w-7 text-slate-600" />
            <div className="text-[12px] font-semibold text-slate-400">Belum ada aktivitas tercatat</div>
            <p className="max-w-md text-[11px] text-slate-600">
              Aksi remediasi, karantina, dan ingest telemetri akan muncul di sini setelah dijalankan.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left">
              <thead>
                <tr className="border-b border-[#232936] text-[9.5px] font-mono uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-3 font-semibold">Endpoint</th>
                  <th className="px-3 py-3 font-semibold">Aksi</th>
                  <th className="px-3 py-3 font-semibold">Operator</th>
                  <th className="px-3 py-3 font-semibold">Waktu</th>
                  <th className="px-5 py-3 text-right font-semibold">Status</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.map(log => (
                  <tr key={log.id} className="border-b border-[#232936]/70 last:border-0 hover:bg-white/[0.02]">
                    <td className="px-5 py-3">
                      <div className="text-[12px] font-semibold text-slate-200">{log.deviceName}</div>
                      <div className="font-mono text-[10px] text-slate-500">{log.deviceRole}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className="rounded-md border border-[#2a3140] bg-[#12161e] px-2 py-1 font-mono text-[10px] text-slate-300">
                        {ACTION_LABEL[log.action] || log.action}
                      </span>
                    </td>
                    <td className="px-3 py-3 font-mono text-[11px] text-slate-400">{log.operator}</td>
                    <td className="px-3 py-3 font-mono text-[10.5px] text-slate-500">
                      <span className="inline-flex items-center gap-1">
                        <Clock className="h-3 w-3" /> {log.timestamp}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <span
                        className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-mono text-[10px] font-bold ${
                          log.status === 'SUCCESS'
                            ? 'border-emerald-800/60 bg-emerald-950/40 text-emerald-300'
                            : log.status === 'WARNING'
                              ? 'border-amber-800/60 bg-amber-950/40 text-amber-300'
                              : 'border-rose-800/60 bg-rose-950/40 text-rose-300'
                        }`}
                      >
                        {log.status === 'SUCCESS' ? (
                          <CheckCircle className="h-3 w-3" />
                        ) : log.status === 'WARNING' ? (
                          <AlertTriangle className="h-3 w-3" />
                        ) : (
                          <XCircle className="h-3 w-3" />
                        )}
                        {log.status}
                      </span>
                      <div className="mt-1 font-mono text-[9px] text-slate-600">
                        {log.preScore}% → {log.postScore}%
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Fleet list */}
      <EndpointRegistryPanel
        devices={devices}
        status={endpointSyncStatus}
        centralData={centralEndpointData}
        canManage={canManageEndpoints}
        canDelete={canDeleteEndpoints}
        lastSyncTime={lastEndpointSync}
        onSelectDevice={deviceId => {
          sfx.playClick();
          onSelectDevice(deviceId);
        }}
        onSave={onSaveEndpoint}
        onDelete={onDeleteEndpoint}
      />
    </div>
  );
};
