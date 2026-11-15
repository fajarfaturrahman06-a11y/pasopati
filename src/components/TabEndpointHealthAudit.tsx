import React, { useEffect, useState } from 'react';
import { Activity, Database, Eye, RefreshCw, ShieldCheck, UserRound } from 'lucide-react';
import type { DeviceInfo } from '../types';
import type { EndpointHealthAuditRecord } from '../endpointHealthAuditStore';

interface TabEndpointHealthAuditProps {
  devices: DeviceInfo[];
}

function headers(json = false): Record<string, string> {
  return {
    ...(json ? { 'Content-Type': 'application/json' } : {})
  };
}

function formatTime(value: string | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('id-ID');
}

function healthTone(score: number | undefined): string {
  if (score === undefined) return 'text-slate-400';
  return score >= 75 ? 'text-emerald-300' : score >= 50 ? 'text-amber-300' : 'text-rose-300';
}

export const TabEndpointHealthAudit: React.FC<TabEndpointHealthAuditProps> = ({ devices }) => {
  const [selectedEndpointId, setSelectedEndpointId] = useState('');
  const [records, setRecords] = useState<EndpointHealthAuditRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const selectedEndpoint = devices.find(device => device.id === selectedEndpointId) || devices[0];
  const latestCondition = selectedEndpoint?.history?.at(-1);
  const failures = selectedEndpoint?.checks.filter(check => check.status === 'FAIL').length || 0;
  const warnings = selectedEndpoint?.checks.filter(check => check.status === 'WARNING').length || 0;

  useEffect(() => {
    if (!devices.length) {
      setSelectedEndpointId('');
      return;
    }
    if (!devices.some(device => device.id === selectedEndpointId)) {
      setSelectedEndpointId(devices[0].id);
    }
  }, [devices, selectedEndpointId]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    fetch('/api/admin/endpoint-health-audit?limit=200', { credentials: 'same-origin', cache: 'no-store' })
      .then(async response => {
        const data = await response.json().catch(() => null);
        if (!response.ok) throw new Error(String(data?.reason || `HTTP ${response.status}`));
        return data;
      })
      .then(data => {
        if (!cancelled) setRecords(Array.isArray(data?.records) ? data.records : []);
      })
      .catch(err => {
        if (!cancelled) {
          setRecords([]);
          setError(err instanceof Error ? err.message : 'Gagal memuat rekaman audit endpoint.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [refreshKey]);

  const recordAccess = async () => {
    if (!selectedEndpoint) return;
    setSaving(true);
    setError('');
    try {
      const response = await fetch('/api/admin/endpoint-health-audit/access', {
        method: 'POST',
        credentials: 'same-origin',
        headers: headers(true),
        body: JSON.stringify({ endpointId: selectedEndpoint.id })
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) throw new Error(String(data?.reason || `HTTP ${response.status}`));
      setRefreshKey(value => value + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Gagal menyimpan rekaman akses endpoint.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-3 border-b border-[#252b37] pb-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-[0.18em] text-cyan-300">
            <ShieldCheck className="h-4 w-4" /> Fitur terpisah · Admin saja
          </div>
          <h1 className="mt-1 text-xl font-black text-slate-100 sm:text-2xl">Audit Akses & Kondisi Endpoint</h1>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-slate-400">
            Catat siapa yang membuka snapshot endpoint, siapa yang menyetujui remediasi, pengguna endpoint, dan kondisi komputer saat dicatat. Data tersimpan di database terpisah dan tidak bercampur dengan Audit Log.
          </p>
        </div>
        <button
          onClick={() => setRefreshKey(value => value + 1)}
          disabled={loading}
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#344151] bg-[#151a22] px-3 py-2 text-xs font-semibold text-slate-200 hover:border-cyan-700/70 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Muat ulang
        </button>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(300px,0.8fr)]">
        <section className="rounded-xl border border-[#27303d] bg-[#10151d] p-4 sm:p-5">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <Eye className="h-4 w-4 text-cyan-300" /> Catat akses dan snapshot kondisi
          </div>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">
            Pilih perangkat lalu catat akses secara eksplisit. Sinkronisasi daftar endpoint biasa tidak dicatat berulang kali.
          </p>
          <label className="mt-4 block text-[10px] font-mono uppercase tracking-wider text-slate-500" htmlFor="health-audit-endpoint">Endpoint</label>
          <select
            id="health-audit-endpoint"
            value={selectedEndpoint?.id || ''}
            onChange={event => setSelectedEndpointId(event.target.value)}
            disabled={!devices.length || saving}
            className="mt-1 h-10 w-full rounded-lg border border-[#303a49] bg-[#0b0f15] px-3 text-sm text-slate-200 outline-none focus:border-cyan-700"
          >
            {devices.length ? devices.map(device => (
              <option key={device.id} value={device.id}>{device.name} · {device.hostname || device.id}</option>
            )) : <option value="">Belum ada endpoint di registry</option>}
          </select>

          {selectedEndpoint && (
            <div className="mt-4 grid gap-2 rounded-lg border border-[#252d39] bg-[#0b1017] p-3 text-xs sm:grid-cols-2">
              <div><span className="text-slate-500">Pengguna endpoint</span><div className="mt-0.5 flex items-center gap-1.5 text-slate-200"><UserRound className="h-3.5 w-3.5 text-slate-500" />{selectedEndpoint.user || 'Tidak tercatat'}</div></div>
              <div><span className="text-slate-500">Sistem operasi</span><div className="mt-0.5 text-slate-200">{selectedEndpoint.os || 'Tidak diketahui'}</div></div>
              <div><span className="text-slate-500">Snapshot audit terakhir</span><div className={`mt-0.5 font-mono font-bold ${healthTone(latestCondition?.score)}`}>{latestCondition ? `${latestCondition.score}/100` : 'Belum ada skor'}</div></div>
              <div><span className="text-slate-500">Kondisi cek</span><div className="mt-0.5 text-slate-200">{failures} FAIL · {warnings} WARNING · {selectedEndpoint.openPorts.length} port</div></div>
              <div className="sm:col-span-2"><span className="text-slate-500">Nama / IP</span><div className="mt-0.5 break-all text-slate-200">{selectedEndpoint.hostname || selectedEndpoint.name} · {selectedEndpoint.ip || 'IP tidak tercatat'}</div></div>
            </div>
          )}
          <button
            onClick={recordAccess}
            disabled={!selectedEndpoint || saving}
            className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-lg border border-cyan-700/70 bg-cyan-950/40 px-4 py-2.5 text-xs font-bold text-cyan-200 hover:bg-cyan-900/40 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
          >
            <Activity className="h-4 w-4" /> {saving ? 'Menyimpan…' : 'Rekam akses & kondisi'}
          </button>
        </section>

        <section className="rounded-xl border border-[#27303d] bg-[#10151d] p-4 sm:p-5">
          <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
            <Database className="h-4 w-4 text-cyan-300" /> Penyimpanan terpisah
          </div>
          <p className="mt-2 text-xs leading-relaxed text-slate-400">
            Database SQLite <code className="rounded bg-black/30 px-1.5 py-0.5 text-cyan-200">data/endpoint_health_audit.sqlite</code> hanya dipakai fitur ini. Data JSON versi lama diimpor sekali dan dibiarkan sebagai cadangan; rekaman baru ditulis ke SQLite.
          </p>
          <div className="mt-4 flex items-center justify-between rounded-lg border border-[#252d39] bg-[#0b1017] px-3 py-2.5">
            <span className="text-xs text-slate-400">Rekaman terbaru dimuat</span>
            <span className="font-mono text-lg font-black text-cyan-200">{records.length}</span>
          </div>
          <p className="mt-2 text-[10px] leading-relaxed text-slate-500">Tampilan memuat maksimal 200 rekaman terbaru. Rekaman bersifat tambah-saja dari API ini; tidak ada tombol hapus.</p>
        </section>
      </div>

      {error && <div role="alert" className="rounded-lg border border-rose-900/60 bg-rose-950/20 px-4 py-3 text-xs text-rose-200">{error}</div>}

      <section className="overflow-hidden rounded-xl border border-[#27303d] bg-[#10151d]">
        <div className="flex items-center justify-between border-b border-[#252d39] px-4 py-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100">Riwayat akses & persetujuan</h2>
            <p className="mt-0.5 text-[10px] font-mono text-slate-500">{loading ? 'Memuat…' : `${records.length} rekaman ditampilkan`}</p>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-xs">
            <thead className="bg-[#0b1017] font-mono text-[9px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3">Waktu / Jenis</th>
                <th className="px-4 py-3">Endpoint / Pengguna</th>
                <th className="px-4 py-3">Diakses oleh</th>
                <th className="px-4 py-3">Disetujui oleh</th>
                <th className="px-4 py-3">Kondisi tertangkap</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#232936]">
              {records.map(record => (
                <tr key={record.id} className="align-top hover:bg-white/[0.02]">
                  <td className="whitespace-nowrap px-4 py-3">
                    <div className="text-slate-200">{formatTime(record.occurredAt)}</div>
                    <div className={`mt-1 font-mono text-[9px] font-bold ${record.eventType === 'REMEDIATION_APPROVED' ? 'text-amber-300' : 'text-cyan-300'}`}>
                      {record.eventType === 'REMEDIATION_APPROVED' ? 'PERSETUJUAN' : 'AKSES ENDPOINT'}
                      {record.planId ? ` · ${record.planId}` : ''}
                    </div>
                  </td>
                  <td className="max-w-[240px] px-4 py-3">
                    <div className="truncate font-semibold text-slate-200">{record.target.name || record.target.endpointId}</div>
                    <div className="mt-0.5 truncate font-mono text-[10px] text-slate-500">{record.target.hostname || record.target.endpointId}</div>
                    <div className="mt-1 text-[10px] text-slate-400">User: {record.target.endpointUser || 'Tidak tercatat'}</div>
                  </td>
                  <td className="px-4 py-3 text-slate-200">{record.accessedBy || '—'}{record.accessIp ? <div className="mt-1 font-mono text-[10px] text-slate-500">{record.accessIp}</div> : null}</td>
                  <td className="px-4 py-3 text-slate-200">{record.approvedBy || '—'}{record.approvedAt ? <div className="mt-1 text-[10px] text-slate-500">{formatTime(record.approvedAt)}</div> : null}</td>
                  <td className="px-4 py-3">
                    {record.computerCondition.captureStatus === 'CAPTURED' ? (
                      <>
                        <div className={`font-mono font-bold ${healthTone(record.computerCondition.score ?? undefined)}`}>{record.computerCondition.score === null ? 'Skor —' : `Skor ${record.computerCondition.score}/100`}</div>
                        <div className="mt-1 text-[10px] text-slate-400">{record.computerCondition.failCount} FAIL · {record.computerCondition.warningCount} WARNING · {record.computerCondition.openPorts.length} port · {record.computerCondition.quarantined ? 'Karantina' : 'Normal'}</div>
                      </>
                    ) : <span className="text-amber-300">Snapshot endpoint tidak tersedia</span>}
                    <div className="mt-1 text-[9px] text-slate-600">Ditangkap {formatTime(record.computerCondition.capturedAt)}</div>
                  </td>
                </tr>
              ))}
              {!loading && records.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-10 text-center text-xs text-slate-500">Belum ada rekaman. Catat akses endpoint di atas; persetujuan remediasi yang berhasil akan tercatat otomatis.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
