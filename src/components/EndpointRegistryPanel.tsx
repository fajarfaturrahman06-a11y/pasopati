import React, { useState } from 'react';
import { Clock3, Pencil, Plus, Save, Server, Trash2, Wifi, WifiOff, X } from 'lucide-react';
import type { DeviceInfo } from '../types';

export type EndpointSyncStatus = 'demo' | 'connecting' | 'connected' | 'offline' | 'unauthenticated';

interface EndpointDraft {
  name: string;
  hostname: string;
  role: string;
  os: string;
  platformType: DeviceInfo['platformType'];
  ip: string;
  mac: string;
  user: string;
  openPorts: string;
  agentId: string;
}

export type EndpointDraftPayload = Omit<EndpointDraft, 'openPorts'> & { openPorts: number[] };

interface Props {
  devices: DeviceInfo[];
  status: EndpointSyncStatus;
  centralData: boolean;
  canManage: boolean;
  canDelete: boolean;
  lastSyncTime: string | null;
  onSelectDevice: (id: string) => void;
  onSave: (payload: EndpointDraftPayload, id?: string, expectedRevision?: number) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}

const EMPTY_DRAFT: EndpointDraft = {
  name: '', hostname: '', role: '', os: '', platformType: 'linux',
  ip: '', mac: '', user: '', openPorts: '', agentId: ''
};

const STATUS_LABEL: Record<EndpointSyncStatus, string> = {
  demo: 'DEMO · BELUM TERHUBUNG',
  connecting: 'MENYAMBUNG…',
  connected: 'TERHUBUNG · DATA VPS',
  offline: 'VPS TIDAK TERSEDIA',
  unauthenticated: 'KUNCI / IZIN DIBUTUHKAN'
};

export const EndpointRegistryPanel: React.FC<Props> = ({
  devices, status, centralData, canManage, canDelete, lastSyncTime,
  onSelectDevice, onSave, onDelete
}) => {
  const [editingId, setEditingId] = useState<string | undefined>();
  const [editingRevision, setEditingRevision] = useState<number | undefined>();
  const [draft, setDraft] = useState<EndpointDraft>(EMPTY_DRAFT);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);

  const openCreate = () => {
    setEditingId(undefined);
    setEditingRevision(undefined);
    setDraft(EMPTY_DRAFT);
    setError(null);
    setFormOpen(true);
  };

  const openEdit = (device: DeviceInfo) => {
    setEditingId(device.id);
    setEditingRevision(device.revision || 1);
    setDraft({
      name: device.name || '', hostname: device.hostname || '', role: device.role || '',
      os: device.os || '', platformType: device.platformType || 'linux', ip: device.ip || '',
      mac: device.mac || '', user: device.user || '', openPorts: (device.openPorts || []).join(', '),
      agentId: device.agentId || ''
    });
    setError(null);
    setFormOpen(true);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const ports = draft.openPorts.trim()
        ? draft.openPorts.split(',').map(value => Number(value.trim())).filter(value => Number.isFinite(value))
        : [];
      await onSave({ ...draft, openPorts: ports }, editingId, editingRevision);
      setFormOpen(false);
      setDraft(EMPTY_DRAFT);
      setEditingId(undefined);
      setEditingRevision(undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Gagal menyimpan endpoint.');
    } finally {
      setBusy(false);
    }
  };

  const remove = async (device: DeviceInfo) => {
    if (!window.confirm(`Arsipkan endpoint ${device.name}? Endpoint tidak lagi tampil di daftar aktif, tetapi riwayatnya tetap disimpan.`)) return;
    setBusy(true);
    setError(null);
    try {
      await onDelete(device.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Gagal mengarsipkan endpoint.');
    } finally {
      setBusy(false);
    }
  };

  const statusStyle = status === 'connected'
    ? 'border-emerald-800/60 bg-emerald-950/40 text-emerald-300'
    : status === 'connecting'
      ? 'border-sky-800/60 bg-sky-950/40 text-sky-300'
      : 'border-amber-800/60 bg-amber-950/40 text-amber-300';

  return (
    <section className="pasopati-panel">
      <div className="pasopati-panel-header flex-wrap gap-3">
        <div>
          <h2 className="text-[14px] font-bold text-slate-100">Registri Endpoint Pusat</h2>
          <p className="mt-0.5 text-[10.5px] font-mono text-slate-500">
            {centralData ? 'Daftar dari VPS; perubahan tersimpan di server.' : 'Fixture contoh read-only; bukan inventaris operasional.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {lastSyncTime && (
            <span className="hidden items-center gap-1 font-mono text-[10px] text-slate-500 sm:inline-flex">
              <Clock3 className="h-3 w-3" /> Sinkronisasi {lastSyncTime}
            </span>
          )}
          <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[9px] font-bold ${statusStyle}`}>
            {status === 'connected' ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
            {STATUS_LABEL[status]}
          </span>
          <button
            type="button"
            onClick={openCreate}
            disabled={!centralData || !canManage || busy}
            title={!centralData ? 'Menunggu sesi terautentikasi dan koneksi registri pusat.' : !canManage ? 'Role planner/admin diperlukan.' : 'Tambah endpoint'}
            className="inline-flex items-center gap-1 rounded-md border border-rose-700/70 bg-rose-950/50 px-2.5 py-1.5 font-mono text-[10px] font-bold text-rose-200 hover:bg-rose-900/60 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Plus className="h-3.5 w-3.5" /> Tambah
          </button>
        </div>
      </div>

      {!centralData && (
        <div className="mx-4 mb-3 rounded-md border border-amber-900/50 bg-amber-950/20 px-3 py-2 text-[11px] text-amber-200/90">
          Data operasional hanya dibuka setelah login. Masuk dengan username/password terdaftar; daftar pusat akan dimuat dan disinkronkan tiap 5 detik.
        </div>
      )}

      {error && <div className="mx-4 mb-3 rounded-md border border-rose-800/60 bg-rose-950/30 px-3 py-2 text-[11px] text-rose-200">{error}</div>}

      {devices.length === 0 ? (
        <div className="px-6 py-10 text-center text-[12px] text-slate-500">
          {centralData ? 'Belum ada endpoint di VPS. Tambahkan endpoint atau kirim telemetry agen.' : 'Fixture demo tidak tersedia.'}
        </div>
      ) : (
        <div className="divide-y divide-[#232936]">
          {devices.map(device => {
            const fails = device.checks.filter(check => check.status === 'FAIL').length;
            return (
              <div key={device.id} className="flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02]">
                <button
                  type="button"
                  onClick={() => onSelectDevice(device.id)}
                  className="flex min-w-0 flex-1 items-center gap-3 text-left"
                >
                  <span className="rounded-lg border border-[#2a3140] bg-[#0f131a] p-2 text-slate-400"><Server className="h-4 w-4" /></span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-2">
                      <span className="truncate text-[12.5px] font-bold text-slate-200">{device.name}</span>
                      <span className="rounded border border-[#2a3140] bg-[#0d1016] px-1.5 py-0.5 font-mono text-[8.5px] uppercase text-slate-500">{device.platformType}</span>
                    </span>
                    <span className="mt-0.5 block truncate font-mono text-[10px] text-slate-500">{device.hostname} · {device.ip || 'IP —'} · {device.role}</span>
                  </span>
                  <span className={`hidden font-mono text-[10px] sm:block ${fails ? 'text-rose-400' : 'text-emerald-400'}`}>{fails ? `${fails} FAIL` : 'COMPLIANT'}</span>
                </button>
                {centralData && canManage && (
                  <button type="button" onClick={() => openEdit(device)} disabled={busy} title="Ubah endpoint" className="rounded p-2 text-slate-500 hover:bg-slate-800 hover:text-sky-300 disabled:opacity-40"><Pencil className="h-3.5 w-3.5" /></button>
                )}
                {centralData && canDelete && (
                  <button type="button" onClick={() => void remove(device)} disabled={busy} title="Arsipkan endpoint" className="rounded p-2 text-slate-500 hover:bg-rose-950/60 hover:text-rose-300 disabled:opacity-40"><Trash2 className="h-3.5 w-3.5" /></button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {formOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-3">
          <form onSubmit={submit} className="max-h-[92vh] w-full max-w-2xl overflow-y-auto rounded-lg border border-slate-700 bg-[#10151e] p-5 shadow-2xl">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h3 className="font-mono text-sm font-bold text-slate-100">{editingId ? 'Ubah endpoint' : 'Tambah endpoint'}</h3>
                <p className="mt-1 text-[10px] text-slate-500">Perubahan dikirim ke registry VPS; tidak disimpan di browser.</p>
              </div>
              <button type="button" onClick={() => setFormOpen(false)} aria-label="Tutup" className="rounded p-1.5 text-slate-400 hover:bg-slate-800"><X className="h-4 w-4" /></button>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Nama *" value={draft.name} onChange={name => setDraft(current => ({ ...current, name }))} required />
              <Field label="Hostname" value={draft.hostname} onChange={hostname => setDraft(current => ({ ...current, hostname }))} />
              <Field label="Peran" value={draft.role} onChange={role => setDraft(current => ({ ...current, role }))} />
              <Field label="Sistem operasi" value={draft.os} onChange={os => setDraft(current => ({ ...current, os }))} />
              <Field label="Alamat IP" value={draft.ip} onChange={ip => setDraft(current => ({ ...current, ip }))} />
              <Field label="MAC (00:11:22:33:44:55)" value={draft.mac} onChange={mac => setDraft(current => ({ ...current, mac }))} />
              <Field label="Pengguna" value={draft.user} onChange={user => setDraft(current => ({ ...current, user }))} />
              <Field label="ID agen (opsional)" value={draft.agentId} onChange={agentId => setDraft(current => ({ ...current, agentId }))} />
              <label className="space-y-1 text-[10px] font-mono text-slate-400">
                Platform
                <select value={draft.platformType} onChange={event => setDraft(current => ({ ...current, platformType: event.target.value as EndpointDraft['platformType'] }))} className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-2 text-[12px] text-slate-200">
                  <option value="linux">Linux</option><option value="windows">Windows</option><option value="embedded">Embedded</option>
                </select>
              </label>
              <Field label="Port terbuka (pisahkan koma)" value={draft.openPorts} onChange={openPorts => setDraft(current => ({ ...current, openPorts }))} placeholder="22, 443" />
            </div>
            {error && <p className="mt-3 rounded border border-rose-800/60 bg-rose-950/30 px-3 py-2 text-[11px] text-rose-200">{error}</p>}
            <div className="mt-5 flex justify-end gap-2">
              <button type="button" onClick={() => setFormOpen(false)} className="rounded border border-slate-700 px-3 py-2 text-[11px] text-slate-300 hover:bg-slate-800">Batal</button>
              <button type="submit" disabled={busy} className="inline-flex items-center gap-1.5 rounded bg-rose-600 px-3 py-2 text-[11px] font-bold text-white hover:bg-rose-500 disabled:opacity-50"><Save className="h-3.5 w-3.5" />{busy ? 'Menyimpan…' : 'Simpan ke VPS'}</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
};

function Field({ label, value, onChange, required, placeholder }: {
  label: string; value: string; onChange: (value: string) => void; required?: boolean; placeholder?: string;
}) {
  return (
    <label className="space-y-1 text-[10px] font-mono text-slate-400">
      {label}
      <input required={required} value={value} placeholder={placeholder} onChange={event => onChange(event.target.value)} className="w-full rounded border border-slate-700 bg-slate-950 px-2.5 py-2 text-[12px] text-slate-200 placeholder:text-slate-600 focus:border-rose-500 focus:outline-none" />
    </label>
  );
}
