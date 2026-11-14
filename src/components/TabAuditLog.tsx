import React, { useState } from 'react';
import { AuditLogEntry } from '../types';
import { normalizeAuditAction } from '../auditActions';
import {
  Database,
  RefreshCw,
  Trash2,
  CheckCircle2,
  AlertCircle,
  History,
  Layers,
  Search,
  Filter
} from 'lucide-react';

interface TabAuditLogProps {
  logs: AuditLogEntry[];
  onLogsUpdated: (updatedLogs: AuditLogEntry[]) => void;
  onShowToast: (message: string, type?: 'success' | 'info') => void;
  apiKey: string;
}

const AUDIT_DB_PATH = 'data/audit_logs.json';

function auditHeaders(apiKey: string): Record<string, string> {
  const k = (apiKey || '').trim();
  return k ? { 'Content-Type': 'application/json', 'X-Pasopati-API-Key': k } : { 'Content-Type': 'application/json' };
}

export const TabAuditLog: React.FC<TabAuditLogProps> = ({
  logs,
  onLogsUpdated,
  onShowToast,
  apiKey
}) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterAction, setFilterAction] = useState<string>('ALL');
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isClearing, setIsClearing] = useState(false);

  const storedCount = logs.filter((l) => l.storedInDb).length;
  const pendingCount = logs.length - storedCount;

  const handleLoadFromDb = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/audit-logs', { headers: auditHeaders(apiKey) });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.reason || `HTTP ${res.status}`);
      const loaded = Array.isArray(data?.logs) ? data.logs : [];
      const mapped = loaded
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
          storedInDb: true
        }));
      onLogsUpdated(mapped);
      onShowToast(`Riwayat audit dimuat dari database lokal (${mapped.length} entri).`);
    } catch (err: any) {
      onShowToast(`Gagal memuat dari database lokal: ${err?.message || ''}`, 'info');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSaveToDb = async () => {
    setIsSaving(true);
    try {
      const res = await fetch('/api/audit-logs', {
        method: 'POST',
        headers: auditHeaders(apiKey),
        body: JSON.stringify({ logs })
      });
      const data = await res.json().catch(() => null);
      if (res.ok) {
        // Server membatasi 200 entri per request; tandai hanya yang benar-benar diterima.
        const accepted = Number(data?.added ?? logs.length);
        const updated = logs.map((l, i) => ({ ...l, storedInDb: i < accepted }));
        onLogsUpdated(updated);
        const rejected = Number(data?.rejected ?? 0);
        onShowToast(
          rejected > 0
            ? `Tersimpan ${accepted} entri; ${rejected} entri melebihi batas 200/request — tekan Simpan lagi untuk sisanya.`
            : `Berhasil menyimpan ${accepted} entri ke database lokal.`,
          rejected > 0 ? 'info' : 'success'
        );
      } else {
        onShowToast(`Gagal menyimpan ke database lokal: ${data?.reason || 'unknown'}`, 'info');
      }
    } catch (err: any) {
      onShowToast(`Gagal menyimpan ke database lokal: ${err?.message || ''}`, 'info');
    } finally {
      setIsSaving(false);
    }
  };

  const handleClearDb = async () => {
    if (!window.confirm('Kosongkan seluruh database audit lokal? Tindakan ini tidak dapat dibatalkan.')) return;
    setIsClearing(true);
    try {
      const res = await fetch('/api/audit-logs', { method: 'DELETE', headers: auditHeaders(apiKey) });
      if (res.ok) {
        onLogsUpdated([]);
        onShowToast('Database audit lokal telah dikosongkan.');
      } else {
        onShowToast('Gagal membersihkan database lokal.', 'info');
      }
    } catch (err: any) {
      onShowToast(`Gagal membersihkan database lokal: ${err?.message || ''}`, 'info');
    } finally {
      setIsClearing(false);
    }
  };

  const filteredLogs = logs.filter((l) => {
    if (filterAction !== 'ALL' && !l.action.toUpperCase().includes(filterAction)) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        l.deviceName.toLowerCase().includes(q) ||
        l.deviceRole.toLowerCase().includes(q) ||
        l.changesSummary.toLowerCase().includes(q) ||
        l.operator.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="p-5 rounded-lg bg-[#1b202a] border border-[#2a3140] shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-32 bg-rose-500/5 blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="p-2.5 rounded-lg bg-rose-950/60 border border-rose-700/60 text-rose-400 shrink-0">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold font-mono text-slate-100 tracking-wide">
                  LOCAL AUDIT DATABASE PERSISTENCE
                </h2>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 border border-rose-700/80 text-rose-300">
                  <CheckCircle2 className="w-3 h-3" />
                  LOCAL DB
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
                Mencatat setiap aksi remediator (nama perangkat, waktu operasi, konfigurasi diubah, delta skor) ke database lokal JSON pada server PASOPATI untuk akuntabilitas inspeksi puskodal.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={handleLoadFromDb}
              disabled={isLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-bold bg-[#232936] hover:bg-slate-700 text-slate-100 border border-[#333b4b] transition-all disabled:opacity-50"
              title="Muat riwayat audit dari database lokal"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isLoading ? 'Memuat...' : 'Muat dari DB'}</span>
            </button>

            <button
              onClick={handleSaveToDb}
              disabled={isSaving || logs.length === 0}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-mono font-bold bg-rose-600 hover:bg-rose-500 text-white transition-all shadow-[0_0_12px_rgba(239,68,68,0.3)] disabled:opacity-50"
              title="Simpan seluruh entri audit log ke database lokal"
            >
              <Database className="w-3.5 h-3.5" />
              <span>{isSaving ? 'Menyimpan...' : 'Simpan ke DB'}</span>
            </button>

            <button
              onClick={handleClearDb}
              disabled={isClearing || logs.length === 0}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-mono text-slate-300 bg-[#171b23] hover:bg-[#232936] border border-[#333b4b] transition-colors disabled:opacity-50"
              title="Kosongkan database audit lokal"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Kosongkan</span>
            </button>
          </div>
        </div>

        <div className="mt-4 pt-3 border-t border-[#2a3140]/80 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-4 text-slate-400">
            <span>TOTAL AKTIVITAS: <strong className="text-slate-200">{logs.length}</strong></span>
            <span>TERSIMPAN DI DB: <strong className="text-emerald-400">{storedCount}</strong></span>
            <span>BELUM DISIMPAN: <strong className={pendingCount > 0 ? 'text-amber-400' : 'text-emerald-400'}>{pendingCount}</strong></span>
            <span className="text-slate-500 truncate max-w-xs" title={AUDIT_DB_PATH}>
              DB: <strong className="text-rose-300">{AUDIT_DB_PATH}</strong>
            </span>
          </div>
          <span className="text-[11px] text-slate-500">
            Standard: DISA STIG V-214875 Audit Logging & ISA/IEC 62443 Event Persistence
          </span>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Cari perangkat / aksi / perub..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-[#1b202a] border border-[#2a3140] rounded-md text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-rose-500"
            />
          </div>

          <div className="flex items-center gap-1.5 bg-[#1b202a] border border-[#2a3140] rounded-md px-2 py-1">
            <Filter className="w-3 h-3 text-slate-500" />
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="bg-transparent text-xs font-mono text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="ALL" className="bg-[#1b202a]">SEMUA AKSI</option>
              <option value="HARDENING" className="bg-[#1b202a]">HARDENING</option>
              <option value="ROLLBACK" className="bg-[#1b202a]">ROLLBACK</option>
              <option value="TELEMETRY" className="bg-[#1b202a]">TELEMETRI INGEST</option>
            </select>
          </div>
        </div>

        <div className="text-xs font-mono text-slate-400 flex items-center gap-2">
          <Layers className="w-3.5 h-3.5 text-slate-500" />
          <span>MENAMPILKAN {filteredLogs.length} DARI {logs.length} AUDIT LOG</span>
        </div>
      </div>

      {filteredLogs.length === 0 ? (
        <div className="p-12 text-center rounded-lg bg-[#1b202a] border border-[#2a3140] space-y-3">
          <History className="w-10 h-10 text-slate-600 mx-auto" />
          <div className="text-sm font-mono font-bold text-slate-300">
            BELUM ADA RIWAYAT AKSI REMEDIATOR
          </div>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Setiap kali Anda menekan tombol <strong>Execute Hardening</strong> atau <strong>Rollback</strong> pada tab AI Hardening, seluruh detail perubahan konfigurasi dan delta skor akan otomatis terekam di sini dan disimpan ke database lokal.
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-[#2a3140] bg-[#1b202a] overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#171b23] border-b border-[#2a3140] text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-3 px-4">WAKTU (UTC)</th>
                  <th className="py-3 px-4">TARGET PERANGKAT</th>
                  <th className="py-3 px-4">AKSI REMEDIATOR</th>
                  <th className="py-3 px-4">DELTA KEPATUHAN</th>
                  <th className="py-3 px-4">PERUBAHAN KONFIGURASI</th>
                  <th className="py-3 px-4">OPERATOR</th>
                  <th className="py-3 px-4 text-center">PENYIMPANAN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a3140]/80">
                {filteredLogs.map(log => {
                  const isHardening = log.action.includes('HARDENING');
                  const isRollback = log.action.includes('ROLLBACK');
                  const scoreDiff = log.postScore - log.preScore;

                  return (
                    <tr key={log.id} className="hover:bg-[#171b23]/50 transition-colors">
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                        {log.timestamp}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="font-bold text-slate-200">{log.deviceName}</div>
                        <div className="text-[10px] text-slate-500">{log.deviceRole}</div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold ${
                          isHardening
                            ? 'bg-rose-950/80 border border-rose-700/80 text-rose-300'
                            : isRollback
                            ? 'bg-sky-950/80 border border-sky-700/80 text-sky-300'
                            : 'bg-purple-950/80 border border-purple-700/80 text-purple-300'
                        }`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-bold">
                          <span className="text-slate-400">{log.preScore}%</span>
                          <span className="text-slate-600">➔</span>
                          <span className={log.postScore >= 80 ? "text-emerald-400" : "text-amber-400"}>
                            {log.postScore}%
                          </span>
                          <span className={`text-[10px] ml-1 ${scoreDiff > 0 ? "text-emerald-400" : scoreDiff < 0 ? "text-rose-400" : "text-slate-500"}`}>
                            ({scoreDiff > 0 ? `+${scoreDiff}` : scoreDiff}%)
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-slate-200 font-semibold">{log.changesSummary}</div>
                        {log.changesDetails.length > 0 && (
                          <div className="text-[10px] text-slate-400 mt-0.5 line-clamp-1" title={log.changesDetails.join(', ')}>
                            {log.changesDetails.slice(0, 3).join(' · ')}
                            {log.changesDetails.length > 3 && ` (+${log.changesDetails.length - 3} lainnya)`}
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                        {log.operator}
                      </td>
                      <td className="py-3 px-4 text-center whitespace-nowrap">
                        {log.storedInDb ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/60 border border-emerald-800/80 text-emerald-400">
                            <CheckCircle2 className="w-3 h-3" />
                            DISK
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/60 border border-amber-800/80 text-amber-300">
                            <AlertCircle className="w-3 h-3" />
                            PENDING
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
