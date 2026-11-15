import React, { useEffect, useMemo, useState } from 'react';
import { Activity, Download, RefreshCw, ScanLine, ShieldAlert } from 'lucide-react';
import type { DeviceInfo } from '../types';
import { TabEndpointHealthAudit } from './TabEndpointHealthAudit';

interface EndpointActivityViewProps {
  devices: DeviceInfo[];
}

type ActivityFilter = 'ALL' | 'FILE_DOWNLOADED' | 'REALTIME_SCAN';

interface ActivityRecord {
  id: string;
  eventType: 'FILE_DOWNLOADED' | 'REALTIME_SCAN';
  occurredAt: string;
  actor: string;
  actorRole: string;
  sourceIp?: string;
  subject: string;
  detail: string;
  status: 'SUCCESS' | 'FAILED';
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('id-ID');
}

const FILTERS: Array<{ id: ActivityFilter; label: string }> = [
  { id: 'ALL', label: 'Semua aktivitas' },
  { id: 'FILE_DOWNLOADED', label: 'Unduhan berkas' },
  { id: 'REALTIME_SCAN', label: 'Scan realtime' }
];

/**
 * Panel aktivitas admin: rekaman akses/kondisi endpoint, unduhan berkas, dan
 * pemindaian realtime dari tab Agent & Upload. Hanya dirender untuk admin.
 */
export const EndpointActivityView: React.FC<EndpointActivityViewProps> = ({ devices }) => {
  const [filter, setFilter] = useState<ActivityFilter>('ALL');
  const [records, setRecords] = useState<ActivityRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError('');
    const query = new URLSearchParams({ limit: '150' });
    if (filter !== 'ALL') query.set('type', filter);
    fetch(`/api/admin/activity-audit?${query.toString()}`, { credentials: 'same-origin', cache: 'no-store' })
      .then(async response => {
        const data = await response.json().catch(() => null);
        if (!response.ok) throw new Error(String(data?.reason || `HTTP ${response.status}`));
        return data;
      })
      .then(data => {
        if (cancelled) return;
        setRecords(Array.isArray(data?.records) ? data.records : []);
        setTotal(Number(data?.total) || 0);
      })
      .catch(err => {
        if (cancelled) return;
        setRecords([]);
        setTotal(0);
        setError(err instanceof Error ? err.message : 'Gagal memuat aktivitas.');
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [filter, refreshKey]);

  const downloadCount = useMemo(() => records.filter(record => record.eventType === 'FILE_DOWNLOADED').length, [records]);
  const scanCount = useMemo(() => records.filter(record => record.eventType === 'REALTIME_SCAN').length, [records]);

  return (
    <div className="space-y-6">
      <TabEndpointHealthAudit devices={devices} />

      <section className="overflow-hidden rounded-xl border border-[#27303d] bg-[#10151d]">
        <div className="flex flex-col gap-3 border-b border-[#252d39] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-[10px] font-mono font-bold uppercase tracking-[0.18em] text-cyan-300">
              <ShieldAlert className="h-3.5 w-3.5" /> Admin saja
            </div>
            <h2 className="mt-1 flex items-center gap-2 text-sm font-bold text-slate-100">
              <Activity className="h-4 w-4 text-cyan-300" /> Aktivitas unduhan &amp; scan realtime
            </h2>
            <p className="mt-1 text-[11px] text-slate-500">
              Siapa mengunduh berkas agent/audit dan siapa menjalankan pemindaian realtime dari tab Agent &amp; Upload.
              Unduhan tanpa sesi tercatat sebagai <span className="font-mono text-slate-400">anonim</span>.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setRefreshKey(value => value + 1)}
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-[#344151] bg-[#151a22] px-3 py-2 text-xs font-semibold text-slate-200 hover:border-cyan-700/70 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Muat ulang
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[#232936] px-4 py-2.5">
          {FILTERS.map(item => (
            <button
              key={item.id}
              type="button"
              onClick={() => setFilter(item.id)}
              className={`rounded-md border px-2.5 py-1 text-[11px] font-mono font-bold transition-colors ${
                filter === item.id
                  ? 'border-cyan-700/70 bg-cyan-950/50 text-cyan-200'
                  : 'border-[#2a3140] bg-[#12161e] text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
          <span className="ml-auto font-mono text-[10px] text-slate-500">
            {loading ? 'Memuat…' : `${records.length} tampil · ${total} total · ${downloadCount} unduhan · ${scanCount} scan`}
          </span>
        </div>

        {error && <div role="alert" className="border-b border-rose-900/60 bg-rose-950/20 px-4 py-2.5 text-xs text-rose-200">{error}</div>}

        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-xs">
            <thead className="bg-[#0b1017] font-mono text-[9px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3">Waktu / Jenis</th>
                <th className="px-4 py-3">Pelaku</th>
                <th className="px-4 py-3">Berkas / Unit</th>
                <th className="px-4 py-3">Keterangan</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#232936]">
              {records.map(record => (
                <tr key={record.id} className="align-top hover:bg-white/[0.02]">
                  <td className="whitespace-nowrap px-4 py-3">
                    <div className="text-slate-200">{formatTime(record.occurredAt)}</div>
                    <div className={`mt-1 inline-flex items-center gap-1 font-mono text-[9px] font-bold ${record.eventType === 'REALTIME_SCAN' ? 'text-amber-300' : 'text-cyan-300'}`}>
                      {record.eventType === 'REALTIME_SCAN' ? <ScanLine className="h-3 w-3" /> : <Download className="h-3 w-3" />}
                      {record.eventType === 'REALTIME_SCAN' ? 'SCAN REALTIME' : 'UNDUH BERKAS'}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-semibold text-slate-200">{record.actor}</div>
                    <div className="mt-0.5 font-mono text-[10px] text-slate-500">{record.actorRole}{record.sourceIp ? ` · ${record.sourceIp}` : ''}</div>
                  </td>
                  <td className="max-w-[240px] truncate px-4 py-3 font-mono text-[11px] text-slate-300" title={record.subject}>{record.subject}</td>
                  <td className="px-4 py-3 text-[11px] text-slate-400">{record.detail}</td>
                  <td className="px-4 py-3">
                    <span className={`rounded px-2 py-0.5 font-mono text-[9px] font-bold ${record.status === 'SUCCESS' ? 'bg-emerald-950/70 text-emerald-300' : 'bg-rose-950/70 text-rose-300'}`}>
                      {record.status}
                    </span>
                  </td>
                </tr>
              ))}
              {!loading && records.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-xs text-slate-500">
                    Belum ada aktivitas. Unduhan dari tab Agent &amp; Upload dan scan realtime akan tercatat di sini.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};
