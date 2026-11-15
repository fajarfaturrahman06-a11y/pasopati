import React, { useMemo, useState } from 'react';
import { DeviceInfo, RemediationPlan, RemediationPlanItem } from '../types';
import { approvePlan, createPlan, getPlan, getWhoAmI, wslCommandText, agentCommandText, reportManualEvidence, WhoAmI } from '../remediationApi';
import { VerificationBadge } from './VerificationBadges';
import { sfx } from '../utils/audio';
import { buildRemediationItems } from '../remediationMapping';
import { buildRemediationScripts } from '../remediationScripts';
import { ShieldCheck, Copy, Check, RefreshCw, FileJson, Terminal, KeyRound, ListChecks, Download, AlertTriangle } from 'lucide-react';

interface RemediationPanelProps {
  currentDevice: DeviceInfo | null;
  onShowToast: (message: string, type?: 'success' | 'info') => void;
}

export const RemediationPanel: React.FC<RemediationPanelProps> = ({
  currentDevice,
  onShowToast
}) => {
  const [isBusy, setIsBusy] = useState(false);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [token, setToken] = useState<string>('');
  const [hmacKey, setHmacKey] = useState<string>('');
  const [serverUrl, setServerUrl] = useState<string>(() =>
    typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'
  );
  const [copied, setCopied] = useState<'plan' | 'cmd' | 'hard' | 'roll' | null>(null);
  const [dryRunNotice, setDryRunNotice] = useState<string | null>(null);
  const [keyStatus, setKeyStatus] = useState<'empty' | 'checking' | 'ok' | 'bad' | 'offline'>('empty');
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [whoami, setWhoami] = useState<WhoAmI | null>(null);
  const [selfApprove, setSelfApprove] = useState(false);
  const [hosts, setHosts] = useState<Array<{ hostId: string; name: string; revokedAt?: string }>>([]);
  const [hostId, setHostId] = useState('');
  const [executionMode, setExecutionMode] = useState<'agent' | 'manual'>('agent');
  const [manualDone, setManualDone] = useState<Record<string, boolean>>({});

  // Jam lokal untuk menghitung kedaluwarsa token (tanpa perlu refresh manual).
  React.useEffect(() => {
    if (!plan || plan.status !== 'APPROVED') return;
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [plan]);

  const tokenExpiresAt = plan?.expiresAt ?? 0;
  const tokenExpired = Boolean(tokenExpiresAt) && nowMs >= tokenExpiresAt;
  const tokenRemainingSec = tokenExpiresAt ? Math.max(0, Math.ceil((tokenExpiresAt - nowMs) / 1000)) : 0;

  // Preflight sesi login; setiap operasi plan/approve tetap divalidasi RBAC di backend.
  const checkKey = React.useCallback(async () => {
    setKeyStatus('checking');
    try {
      const res = await fetch('/api/quarantine', { credentials: 'same-origin' });
      setKeyStatus(res.ok ? 'ok' : 'bad');
    } catch {
      setKeyStatus('offline');
    }
  }, []);

  React.useEffect(() => {
    checkKey();
  }, [checkKey]);

  // Identitas pemanggil + daftar host ter-enrol (untuk empat mata & pengikatan plan).
  React.useEffect(() => {
    if (keyStatus !== 'ok') {
      setWhoami(null);
      return;
    }
    let cancelled = false;
    getWhoAmI()
      .then(w => { if (!cancelled) setWhoami(w); })
      .catch(() => {});
    fetch('/api/hosts', { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null))
      .then(d => {
        if (!cancelled && Array.isArray(d?.hosts)) {
          setHosts(d.hosts.filter((h: { revokedAt?: string }) => !h.revokedAt));
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [keyStatus]);

  // Parameter remediasi diturunkan langsung dari temuan hardening (FAIL/WARNING).
  const draftItems = useMemo<RemediationPlanItem[]>(() => buildRemediationItems(currentDevice), [currentDevice]);

  const [selectedAliases, setSelectedAliases] = useState<Record<string, boolean>>({});
  const [ackConsole, setAckConsole] = useState(false);
  const toggleAlias = (alias: string) =>
    setSelectedAliases(prev => ({ ...prev, [alias]: prev[alias] === false ? true : false }));

  const isSelected = (item: RemediationPlanItem) => selectedAliases[item.alias] !== false;
  const selectedItems = draftItems.filter(isSelected);
  const selectedEnforce = selectedItems.filter(i => i.kind !== 'advisory');
  const selectedAliasSet = useMemo(() => new Set(selectedItems.map(i => i.alias)), [selectedItems]);
  const isLinux = currentDevice?.platformType === 'linux' || currentDevice?.platformType === 'embedded';
  const scripts = useMemo(
    () => (currentDevice ? buildRemediationScripts(currentDevice, isLinux, selectedAliasSet) : { hard: '', roll: '' }),
    [currentDevice, isLinux, selectedAliasSet]
  );

  // Ganti perangkat dari selector hardening → buang plan lama agar tidak salah target.
  React.useEffect(() => {
    setPlan(null);
    setToken('');
    setSelectedAliases({});
    setAckConsole(false);
  }, [currentDevice?.id]);

  const handleCreatePlan = async () => {
    if (!currentDevice || selectedItems.length === 0) return;
    setIsBusy(true);
    sfx.playPing();
    try {
      const created = await createPlan(currentDevice.id, selectedItems, hostId || undefined, {
        executionMode,
        artifacts: { hardening: scripts.hard, rollback: scripts.roll }
      });
      setPlan(created);
      setToken('');
      setAckConsole(false);
      setSelfApprove(false);
      setManualDone({});
      onShowToast('Plan remediasi ' + created.planId + ' dibuat (PLANNED, mode ' + executionMode + ').');
    } catch (err: any) {
      onShowToast(err?.message || 'Gagal membuat plan.', 'info');
    } finally {
      setIsBusy(false);
    }
  };

  const handleApprovePlan = async () => {
    if (!plan) return;
    setIsBusy(true);
    sfx.playPing();
    try {
      // approved.plan = plan LENGKAP sekali (berisi nonce/signature) — simpan langsung
      // untuk plan.json agent. JANGAN ambil dari GET (sudah diredaksi).
      const approved = await approvePlan(plan.planId, ackConsole, selfApprove);
      setToken(approved.token);
      setPlan(approved.plan);
      setNowMs(Date.now());
      onShowToast(
        tokenExpired
          ? 'Token baru diterbitkan. Token lama tidak berlaku lagi — salin plan.json yang baru.'
          : 'Plan disetujui. Token berlaku 10 menit — simpan plan.json sekarang (sekali tampil).'
      );
    } catch (err: any) {
      onShowToast(err?.message || 'Gagal approve plan.', 'info');
    } finally {
      setIsBusy(false);
    }
  };

  const handleRefresh = async () => {
    if (!plan) return;
    setIsBusy(true);
    try {
      const refreshed = await getPlan(plan.planId);
      // GET meredaksi nonce/signature. Pertahankan nilai yang sudah dimiliki agar
      // plan.json tetap valid untuk agent setelah refresh.
      setPlan(prev => prev ? {
        ...refreshed,
        nonce: prev.nonce ?? refreshed.nonce,
        signature: prev.signature ?? refreshed.signature,
        expiresAt: prev.expiresAt ?? refreshed.expiresAt,
        evidenceDeadline: prev.evidenceDeadline ?? refreshed.evidenceDeadline
      } : refreshed);
      onShowToast('Status plan diperbarui: ' + refreshed.status);
    } catch (err: any) {
      onShowToast(err?.message || 'Gagal refresh plan.', 'info');
    } finally {
      setIsBusy(false);
    }
  };

  const handleManualReport = async () => {
    if (!plan || !token) return;
    if (!plan.items.every(item => manualDone[item.alias])) {
      onShowToast('Tandai semua langkah selesai sebelum mengirim laporan manual.', 'info');
      return;
    }
    setIsBusy(true);
    try {
      const stamp = new Date().toISOString();
      const evidence = await Promise.all(plan.items.map(async (item, index) => {
        const raw = `${plan.planId}|${item.alias}|${stamp}`;
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
        const hash = 'sha256:' + Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        return { stepIndex: index, alias: item.alias, exitCode: 0, outputHash: hash, source: 'manual' as const };
      }));
      await reportManualEvidence(plan.planId, token.split('.')[0], evidence);
      await handleRefresh();
      onShowToast('Laporan manual tercatat. Jalankan audit ulang lalu kirim untuk status VERIFIED.');
    } catch (err: any) {
      onShowToast(err?.message || 'Gagal mengirim laporan manual.', 'info');
    } finally {
      setIsBusy(false);
    }
  };

  const downloadScript = (content: string, filename: string) => {
    const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    sfx.playClick();
  };

  const copyText = (text: string, kind: 'plan' | 'cmd' | 'hard' | 'roll') => {
    navigator.clipboard.writeText(text);
    setCopied(kind);
    sfx.playClick();
    setTimeout(() => setCopied(null), 2000);
  };

  if (!currentDevice) {
    return (
      <div className="p-5 rounded-lg bg-slate-900/80 border border-slate-800 text-sm font-mono text-slate-400">
        Tidak ada perangkat tersedia.
      </div>
    );
  }

  const planJsonText = plan ? JSON.stringify(plan, null, 2) : '';
  const cmdText = plan ? agentCommandText(serverUrl, plan.planId, '', hmacKey, Boolean(plan.requiresConsoleAck)) : '';
  const fallbackCmdText = plan ? wslCommandText(serverUrl, 'plan.json', token, '', Boolean(plan.requiresConsoleAck)) : '';

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-lg border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-bold tracking-tight text-rose-400 font-mono">
              2. PAKET EKSEKUSI &amp; PERSETUJUAN — {currentDevice?.name}
            </h3>
            <VerificationBadge planStatus={plan ? plan.status : undefined} />
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Satu alur dalam satu panel: pilih perubahan → tinjau runbook → buat plan → setujui → eksekusi. Tanpa token valid, agent tetap read-only.
          </p>
        </div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <ListChecks className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
              Langkah 1 · Pilih perubahan (parameter diturunkan dari temuan hardening)
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {selectedItems.length}/{draftItems.length} item dipilih (per-item approval)
          </span>
        </div>

        {draftItems.length === 0 ? (
          <div className="p-4 rounded bg-slate-950/60 border border-slate-800 text-xs font-mono text-slate-400">
            Tidak ada temuan FAIL/WARNING yang terpetakan ke allowlist agent
            (fw-enable-defender · guest-account-disable · usb-storage-block · fw-enable-ufw
            · ssh-disable-root · auditd-enable · usb-block-linux
            · rdp-nla-enable · uac-enable · bitlocker-enable
            · grub-config-perms · sudoers-remove-nopasswd · suid-strip-critical
            · win-auditpol-process).
          </div>
        ) : (
          <div className="space-y-2">
            {draftItems.map(item => {
              const check = currentDevice.checks.find(c => c.id === item.findingId);
              return (
                <label key={item.alias} className="flex items-center gap-3 p-3 rounded bg-slate-950 border border-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isSelected(item)}
                    onChange={() => toggleAlias(item.alias)}
                    className="rounded bg-slate-950 border-slate-700 text-rose-600 focus:ring-0"
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-slate-100 truncate">
                      {item.alias} <span className="text-slate-500">· risiko {item.risk} · reversibel</span>
                      {item.alias === 'ports-block-windows' && (currentDevice.openPorts || []).includes(3389) && (
                        <span className="ml-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800">
                          PUTUS RDP
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] font-mono text-slate-500 truncate">
                      {check ? `[${check.cis_id}] ${check.parameter} — ${check.details}` : item.preState}
                    </div>
                    <div className="text-[11px] font-mono text-rose-500/80 truncate">
                      target: {item.postStateExpected || '—'}
                    </div>
                  </div>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    check?.status === 'FAIL'
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : 'bg-amber-950 text-amber-300 border-amber-800'
                  }`}>
                    {check?.status || ''}
                  </span>
                </label>
              );
            })}
          </div>
        )}

        <div className={`p-3 rounded border text-[11px] font-mono flex flex-wrap items-center gap-2 ${
          keyStatus === 'ok'
            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
            : keyStatus === 'checking'
            ? 'bg-slate-900 border-slate-700 text-slate-300'
            : 'bg-amber-950/40 border-amber-800 text-amber-300'
        }`}>
          {keyStatus === 'ok' && <span>✓ Sesi login valid{whoami?.role ? ` · role ${whoami.role}` : ''}. Izin membuat/menyetujui plan mengikuti RBAC server.</span>}
          {keyStatus === 'checking' && <span>Memeriksa sesi login…</span>}
          {keyStatus === 'empty' && <span>Belum ada sesi aktif. Masuk melalui layar login PASOPATI.</span>}
          {keyStatus === 'bad' && <span>Sesi ditolak server. Keluar lalu masuk kembali dengan username dan password.</span>}
          {keyStatus === 'offline' && <span>Server tidak terjangkau. Jalankan <code>npm run dev</code> lalu muat ulang.</span>}
          <button onClick={checkKey} className="ml-auto px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-rose-300">
            tes ulang
          </button>
        </div>

        {draftItems.length > 0 && selectedEnforce.length === 0 && (
          <div className="p-3 rounded bg-amber-950/40 border border-amber-800 text-amber-300 text-[11px] font-mono flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5" />
            Pilih minimal satu langkah AUTO (enforce) — langkah advisory saja tidak cukup untuk membuat plan.
          </div>
        )}

        <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
          <div className="p-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between flex-wrap gap-2">
            <span className="text-xs font-mono font-semibold text-rose-400 flex items-center gap-1.5">
              <FileJson className="w-3.5 h-3.5" />
              {plan ? `Langkah 2 · Runbook resmi plan ${plan.planId}` : 'Langkah 2 · Pratinjau runbook — belum tercatat'}
              {!plan && <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">PRATINJAU</span>}
            </span>
            <div className="flex items-center gap-2">
              {plan?.artifacts ? (
                <>
                  <a
                    href={`/api/remediation-plans/${encodeURIComponent(plan.planId)}/artifacts/hardening`}
                    className="flex items-center gap-1 text-[11px] font-mono text-rose-400 hover:text-rose-300 px-2 py-0.5 rounded bg-rose-950/70 border border-rose-700/60"
                  >
                    <Download className="w-3 h-3" /> unduh hardening resmi
                  </a>
                  <a
                    href={`/api/remediation-plans/${encodeURIComponent(plan.planId)}/artifacts/rollback`}
                    className="flex items-center gap-1 text-[11px] font-mono text-sky-400 hover:text-sky-300 px-2 py-0.5 rounded bg-sky-950/70 border border-sky-700/60"
                  >
                    <Download className="w-3 h-3" /> unduh rollback resmi
                  </a>
                </>
              ) : (
                <>
                  <button
                    onClick={() => downloadScript(scripts.hard, isLinux ? 'pratinjau-hardening.sh' : 'pratinjau-hardening.ps1')}
                    className="flex items-center gap-1 text-[11px] font-mono text-rose-400 hover:text-rose-300 px-2 py-0.5 rounded bg-rose-950/70 border border-rose-700/60"
                  >
                    <Download className="w-3 h-3" /> unduh pratinjau
                  </button>
                  <button
                    onClick={() => downloadScript(scripts.roll, isLinux ? 'pratinjau-rollback.sh' : 'pratinjau-rollback.ps1')}
                    className="flex items-center gap-1 text-[11px] font-mono text-sky-400 hover:text-sky-300 px-2 py-0.5 rounded bg-sky-950/70 border border-sky-700/60"
                  >
                    <Download className="w-3 h-3" /> unduh rollback pratinjau
                  </button>
                </>
              )}
            </div>
          </div>
          {plan?.artifacts && (
            <div className="px-3 py-2 border-b border-slate-800 text-[10px] font-mono text-slate-400 break-all">
              hash hardening: <span className="text-slate-300">{plan.artifacts.hardeningHash}</span>
              <br />hash rollback: <span className="text-slate-300">{plan.artifacts.rollbackHash}</span>
            </div>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 divide-y lg:divide-y-0 lg:divide-x divide-slate-800">
            <div>
              <div className="px-3 py-2 text-[11px] font-mono text-rose-400 border-b border-slate-800 flex items-center justify-between">
                <span>hardening</span>
                <button onClick={() => copyText(scripts.hard, 'hard')} className="text-slate-400 hover:text-rose-400">
                  {copied === 'hard' ? 'tersalin' : 'salin'}
                </button>
              </div>
              <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-auto max-h-56 leading-relaxed">{scripts.hard}</pre>
            </div>
            <div>
              <div className="px-3 py-2 text-[11px] font-mono text-sky-400 border-b border-slate-800 flex items-center justify-between">
                <span>rollback</span>
                <button onClick={() => copyText(scripts.roll, 'roll')} className="text-slate-400 hover:text-sky-400">
                  {copied === 'roll' ? 'tersalin' : 'salin'}
                </button>
              </div>
              <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-auto max-h-56 leading-relaxed">{scripts.roll}</pre>
            </div>
          </div>
          <div className="p-3 border-t border-slate-800 flex flex-wrap items-center gap-2">
            <button
              onClick={() => { setDryRunNotice('Runbook ini selalu diawali mode aman. Jalankan dengan --dry-run (Linux) atau -DryRun (Windows) sebelum eksekusi nyata.'); sfx.playClick(); }}
              className="text-[11px] font-mono px-2 py-1 rounded bg-slate-900 border border-slate-700 text-slate-300 hover:text-amber-300"
            >
              cara uji aman
            </button>
            {dryRunNotice && <span className="text-[11px] font-mono text-amber-300">{dryRunNotice}</span>}
          </div>
        </div>

        <div className="flex items-center gap-2 pt-1 flex-wrap">
          <ShieldCheck className="w-4 h-4 text-rose-400" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">Langkah 3 · Setujui &amp; eksekusi</span>
          {whoami && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300">
              operator: {whoami.name} · {whoami.role}
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono text-slate-400">
          <label className="flex items-center gap-2">
            ikat ke host (opsional):
            <select
              value={hostId}
              onChange={(e) => setHostId(e.target.value)}
              className="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-slate-200"
            >
              <option value="">— tidak diikat —</option>
              {hosts.map(h => (
                <option key={h.hostId} value={h.hostId}>{h.name} ({h.hostId})</option>
              ))}
            </select>
          </label>
          <span className="text-slate-600">host terikat hanya boleh mengeksekusi plan miliknya.</span>
        </div>

        {plan?.requiresConsoleAck && (
          <div className="p-3 rounded border border-rose-800 bg-rose-950/40 space-y-2">
            <div className="text-[11px] font-mono font-bold text-rose-300 uppercase tracking-wide">
              Plan ini menyentuh jalur akses host
            </div>
            <ul className="text-[11px] font-mono text-rose-200/90 space-y-1 list-disc pl-4">
              {(plan.accessNotes || []).map(note => <li key={note}>{note}</li>)}
            </ul>
            <label className="flex items-start gap-2 text-[11px] font-mono text-rose-100 cursor-pointer">
              <input
                type="checkbox"
                checked={ackConsole}
                onChange={(e) => setAckConsole(e.target.checked)}
                className="mt-0.5 rounded bg-slate-950 border-rose-700 text-rose-500 focus:ring-0"
              />
              Saya sudah punya konsol/KVM atau siap rollback — lanjutkan approve.
            </label>
          </div>
        )}

        {whoami && plan && plan.createdBy === whoami.name && (
          <div className="p-3 rounded border border-amber-800 bg-amber-950/30 text-[11px] font-mono text-amber-200 flex flex-wrap items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5" />
            Plan dibuat oleh Anda sendiri ({whoami.name}). Empat mata: minta operator lain approve, atau
            <label className="flex items-center gap-1.5 cursor-pointer text-amber-100">
              <input
                type="checkbox"
                checked={selfApprove}
                onChange={(e) => setSelfApprove(e.target.checked)}
                className="rounded bg-slate-950 border-amber-700 text-amber-500 focus:ring-0"
              />
              setujui sendiri
            </label>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
          <span className="text-slate-500">mode eksekusi:</span>
          {(['agent', 'manual'] as const).map(mode => (
            <label key={mode} className={`flex items-center gap-1.5 px-2 py-1 rounded border cursor-pointer ${
              executionMode === mode ? 'border-rose-700 bg-rose-950/40 text-rose-200' : 'border-slate-700 bg-slate-900'
            }`}>
              <input
                type="radio"
                name="execution-mode"
                checked={executionMode === mode}
                disabled={Boolean(plan && plan.status !== 'PLANNED')}
                onChange={() => setExecutionMode(mode)}
                className="accent-rose-600"
              />
              {mode === 'agent' ? 'agent (token)' : 'manual (laporan)'}
            </label>
          ))}
          {executionMode === 'manual' && <span className="text-amber-300/90">mode manual bersifat self-reported; VERIFIED butuh audit ulang.</span>}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 pt-1">
          <button
            disabled={isBusy || selectedEnforce.length === 0 || keyStatus !== 'ok'}
            onClick={handleCreatePlan}
            className="flex-1 py-2.5 px-4 rounded-lg text-xs font-bold font-mono bg-rose-600 hover:bg-rose-500 text-white disabled:opacity-50 transition-all"
          >
            {isBusy ? 'MEMPROSES…' : 'BUAT PLAN'}
          </button>
          <button
            disabled={isBusy || keyStatus !== 'ok' || !plan || (Boolean(plan.requiresConsoleAck) && !ackConsole) || (Boolean(whoami) && plan.createdBy === whoami?.name && !selfApprove) || !(plan.status === 'PLANNED' || (plan.status === 'APPROVED' && tokenExpired))}
            onClick={handleApprovePlan}
            className="flex-1 py-2.5 px-4 rounded-lg text-xs font-bold font-mono bg-sky-600 hover:bg-sky-500 text-white disabled:opacity-50 transition-all"
          >
            {isBusy ? 'MEMPROSES…' : plan?.status === 'APPROVED' && tokenExpired ? 'TERBITKAN ULANG TOKEN' : 'APPROVE PLAN'}
          </button>
          <button
            disabled={isBusy || !plan}
            onClick={handleRefresh}
            className="py-2.5 px-4 rounded-lg text-xs font-bold font-mono bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 disabled:opacity-50 flex items-center justify-center gap-2 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isBusy ? 'animate-spin' : ''}`} />
            REFRESH
          </button>
        </div>
      </div>

      {plan && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
                Status Plan — {plan.planId}
              </h3>
            </div>
            <VerificationBadge planStatus={plan.status} />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">Status</span>
              <span className="text-slate-100 font-bold">{plan.status}</span>
            </div>
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">Perangkat</span>
              <span className="text-slate-100 font-bold">{plan.deviceId}</span>
            </div>
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">Dibuat oleh</span>
              <span className="text-slate-100 font-bold">{plan.createdBy}</span>
            </div>
            <div className="p-3 rounded bg-slate-950 border border-slate-800">
              <span className="text-slate-500 block">Disetujui</span>
              <span className="text-slate-100 font-bold">{plan.approvedBy || '—'}</span>
            </div>
          </div>

          {plan.status === 'APPROVED' && (
            <div className={`p-3 rounded border text-[11px] font-mono ${
              tokenExpired
                ? 'bg-amber-950/50 border-amber-700 text-amber-300'
                : 'bg-sky-950/40 border-sky-800 text-sky-300'
            }`}>
              {tokenExpired
                ? 'Token kedaluwarsa. Tekan “TERBITKAN ULANG TOKEN”, lalu salin plan.json + perintah yang baru (token lama tidak berlaku).'
                : `Token masih berlaku ${Math.floor(tokenRemainingSec / 60)}m ${tokenRemainingSec % 60}s. Salin plan.json SEKARANG — refresh halaman menghapus token dari layar.`}
              {plan.evidenceDeadline && (
                <span className="block text-slate-400 mt-1">
                  Batas kirim evidence: {new Date(plan.evidenceDeadline).toLocaleString('id-ID')}
                </span>
              )}
            </div>
          )}

          {plan.executionMode === 'manual' && plan.status === 'APPROVED' && !tokenExpired && (
            <div className="space-y-2 rounded border border-amber-800 bg-amber-950/25 p-3">
              <div className="text-[11px] font-mono font-bold text-amber-200 uppercase">Laporan manual — tandai langkah yang sudah dijalankan</div>
              <p className="text-[11px] font-mono text-amber-100/80">
                Unduh artefak resmi di 2b, jalankan, lalu tandai semua langkah. Server mencatat laporan sebagai MANUAL_REPORTED.
              </p>
              {plan.items.map((item, index) => (
                <label key={item.alias} className="flex items-center gap-2 text-[11px] font-mono text-amber-100">
                  <input
                    type="checkbox"
                    checked={Boolean(manualDone[item.alias])}
                    onChange={e => setManualDone(prev => ({ ...prev, [item.alias]: e.target.checked }))}
                    className="accent-amber-500"
                  />
                  step {index + 1} · {item.alias} {item.kind === 'advisory' && <span className="text-slate-400">(advisory)</span>}
                </label>
              ))}
              <button
                onClick={handleManualReport}
                disabled={isBusy || !plan.items.every(item => manualDone[item.alias])}
                className="w-full sm:w-auto px-4 py-2 rounded-lg text-xs font-bold font-mono bg-amber-600 hover:bg-amber-500 text-white disabled:opacity-50"
              >
                {isBusy ? 'MENGIRIM…' : 'KIRIM LAPORAN MANUAL'}
              </button>
            </div>
          )}

          {plan.status === 'MANUAL_REPORTED' && (
            <div className="p-3 rounded border border-amber-800 bg-amber-950/30 text-[11px] font-mono text-amber-200">
              Laporan manual sudah tercatat. Status <strong>VERIFIED</strong> baru diberikan setelah audit ulang host; sertakan hasilnya pada pengiriman evidence berikutnya.
            </div>
          )}
          {plan.evidence && plan.evidence.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-mono text-slate-400 font-semibold block">Evidence dari agent:</span>
              {plan.evidence.map((ev, i) => (
                <div key={i} className="p-3 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono flex flex-wrap gap-x-4 gap-y-1">
                  <span className="text-slate-300">step {ev.stepIndex}</span>
                  <span className="text-slate-100">{ev.alias}</span>
                  <span className="text-slate-400">exitCode: {ev.exitCode}</span>
                  {ev.advisory ? (
                    <span className="text-sky-400">advisory: {ev.verified ? 'SESUAI' : 'PERLU MANUAL'}</span>
                  ) : (
                    <span className={ev.verified ? 'text-emerald-400' : 'text-rose-400'}>
                      verified: {ev.verified ? 'PASS' : 'FAIL'}
                    </span>
                  )}
                  <span className="text-slate-500 truncate max-w-full">outputHash: {ev.outputHash}</span>
                  {ev.output && <span className="text-slate-400 truncate max-w-full basis-full">output: {ev.output}</span>}
                  {ev.rollback && (
                    <span className={ev.rollback.verified ? 'text-emerald-400' : 'text-amber-400'}>
                      rollback: {ev.rollback.verified ? 'PULIH' : 'TIDAK BERSIH'} (exit {ev.rollback.exitCode})
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden flex flex-col">
              <div className="p-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-mono font-semibold text-rose-400 flex items-center gap-1.5">
                  <FileJson className="w-3.5 h-3.5" />
                  plan.json (fallback offline)
                </span>
                <button
                  onClick={() => copyText(planJsonText, 'plan')}
                  className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-rose-400"
                >
                  {copied === 'plan' ? <Check className="w-3.5 h-3.5 text-rose-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied === 'plan' ? 'Tersalin' : 'Salin'}</span>
                </button>
              </div>
              <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-auto max-h-56 leading-relaxed">{planJsonText}</pre>
            </div>
            <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden flex flex-col">
              <div className="p-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                <span className="text-xs font-mono font-semibold text-sky-400 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  Perintah untuk Agent (host target)
                </span>
                <button
                  onClick={() => copyText(cmdText, 'cmd')}
                  className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-sky-400"
                >
                  {copied === 'cmd' ? <Check className="w-3.5 h-3.5 text-sky-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied === 'cmd' ? 'Tersalin' : 'Salin'}</span>
                </button>
              </div>
              <div className="p-3 space-y-2">
                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                  <KeyRound className="w-3.5 h-3.5 text-sky-400" />
                  Server URL:
                  <input
                    type="text"
                    value={serverUrl}
                    onChange={e => setServerUrl(e.target.value)}
                    className="flex-1 min-w-0 px-2 py-1 text-[11px] font-mono bg-slate-900 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-sky-500"
                  />
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                  <KeyRound className="w-3.5 h-3.5 text-rose-400" />
                  HMAC key (HMAC_SECRET):
                  <input
                    type="password"
                    value={hmacKey}
                    onChange={e => setHmacKey(e.target.value)}
                    placeholder="dari .env server"
                    className="flex-1 min-w-0 px-2 py-1 text-[11px] font-mono bg-slate-900 border border-slate-700 rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-rose-500"
                  />
                </div>
                <pre className="text-[11px] font-mono text-rose-300 overflow-auto max-h-40 leading-relaxed whitespace-pre-wrap">{cmdText || 'Approve plan untuk mendapatkan perintah…'}</pre>
                <p className="text-[11px] font-mono text-slate-500">
                  Jalankan di host target. Agent mengambil plan langsung dari server — target hanya butuh <code>pasopati_remediate.py</code> + <code>pasopati_audit.py</code>.
                  Tambahkan <code>--no-exec</code> untuk uji aman.
                </p>
                <p className="text-[11px] font-mono text-amber-400/90">
                  Dead-man: bila hasil tidak dikonfirmasi, host rollback otomatis setelah 10 menit
                  (<code>--deadman-seconds 0</code> untuk mematikan). Kunci BitLocker di-escrow ke server.
                </p>
                {token && (
                  <details className="text-[11px] font-mono text-slate-500">
                    <summary className="cursor-pointer">Fallback manual (plan.json + token)</summary>
                    <pre className="mt-1 text-slate-400 overflow-auto max-h-32 leading-relaxed whitespace-pre-wrap">{fallbackCmdText}</pre>
                  </details>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
