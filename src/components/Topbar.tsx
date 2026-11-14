import React, { useMemo, useState } from 'react';
import { Menu, Search, MessageCircle, Bell, ChevronDown, ShieldCheck, Server } from 'lucide-react';
import { DeviceInfo } from '../types';
import { calculateDeviceScore } from '../data/mockDevices';
import { sfx } from '../utils/audio';

interface TopbarProps {
  activeTab: number;
  devices: DeviceInfo[];
  auditLogCount: number;
  onOpenMobile: () => void;
  onSelectDevice: (deviceId: string) => void;
  onNavigate: (tab: number) => void;
}

const TAB_TITLES = ['Dashboard', 'Endpoint Audit', 'Hardening & Remediation', 'Agent & Upload', 'Audit Log'];

export const Topbar: React.FC<TopbarProps> = ({
  activeTab,
  devices,
  auditLogCount,
  onOpenMobile,
  onSelectDevice,
  onNavigate
}) => {
  const [query, setQuery] = useState('');
  const [focused, setFocused] = useState(false);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return devices
      .filter(d =>
        [d.id, d.name, d.ip, d.role, d.os].some(v => String(v || '').toLowerCase().includes(q))
      )
      .slice(0, 6);
  }, [devices, query]);

  const failCount = useMemo(
    () => devices.reduce((acc, d) => acc + d.checks.filter(c => c.status === 'FAIL').length, 0),
    [devices]
  );

  const selectResult = (id: string) => {
    sfx.playClick();
    onSelectDevice(id);
    setQuery('');
    setFocused(false);
  };

  return (
    <header className="sticky top-0 z-30 border-b border-[#2a3140] bg-[#171b23]/95 backdrop-blur">
      <div className="flex h-[68px] items-center gap-3 px-4 sm:px-6">
        <button
          onClick={onOpenMobile}
          className="rounded-lg border border-[#2a3140] bg-[#12161e] p-2 text-slate-400 hover:text-slate-100 lg:hidden"
          aria-label="Buka menu"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div className="hidden min-w-[130px] md:block">
          <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-slate-500">Halaman</div>
          <div className="text-[13px] font-bold text-slate-200">{TAB_TITLES[activeTab] || 'Dashboard'}</div>
        </div>

        {/* Search */}
        <div className="relative w-full max-w-[460px]">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onFocus={() => setFocused(true)}
            onBlur={() => window.setTimeout(() => setFocused(false), 120)}
            placeholder="Cari endpoint, IP, atau peran..."
            className="h-10 w-full rounded-lg border border-[#2a3140] bg-[#0f131a] pl-9 pr-3 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-rose-500/60 focus:outline-none focus:ring-2 focus:ring-rose-500/15"
          />
          {focused && query.trim() && (
            <div className="absolute left-0 right-0 top-11 overflow-hidden rounded-xl border border-[#2a3140] bg-[#151a22] shadow-2xl">
              {results.length === 0 ? (
                <div className="px-4 py-3 text-[12px] text-slate-500">Tidak ada endpoint yang cocok.</div>
              ) : (
                results.map(d => {
                  const score = calculateDeviceScore(d.checks);
                  return (
                    <button
                      key={d.id}
                      onMouseDown={e => e.preventDefault()}
                      onClick={() => selectResult(d.id)}
                      className="flex w-full items-center gap-3 border-b border-[#232936] px-4 py-2.5 text-left last:border-0 hover:bg-[#1c222c]"
                    >
                      <span className="rounded-md bg-[#0f131a] p-1.5 text-slate-400">
                        <Server className="h-3.5 w-3.5" />
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[12px] font-semibold text-slate-200">{d.name}</span>
                        <span className="block truncate font-mono text-[10px] text-slate-500">
                          {d.ip} · {d.role}
                        </span>
                      </span>
                      <span
                        className={`text-[11px] font-mono font-bold ${
                          score >= 75 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-rose-400'
                        }`}
                      >
                        {score}%
                      </span>
                    </button>
                  );
                })
              )}
            </div>
          )}
        </div>

        <div className="ml-auto flex items-center gap-1.5 sm:gap-3">
          <button
            onClick={() => {
              sfx.playClick();
              onNavigate(4);
            }}
            title="Pesan & aktivitas audit"
            className="relative rounded-full p-2 text-slate-400 hover:bg-white/5 hover:text-slate-100"
          >
            <MessageCircle className="h-5 w-5" />
            {auditLogCount > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[9px] font-bold text-white">
                {Math.min(auditLogCount, 99)}
              </span>
            )}
          </button>

          <button
            onClick={() => {
              sfx.playClick();
              onNavigate(1);
            }}
            title={`${failCount} temuan kritis`}
            className="relative rounded-full p-2 text-slate-400 hover:bg-white/5 hover:text-slate-100"
          >
            <Bell className="h-5 w-5" />
            {failCount > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[9px] font-bold text-white">
                {Math.min(failCount, 99)}
              </span>
            )}
          </button>

          <div className="hidden h-8 w-px bg-[#2a3140] sm:block" />

          <button
            onClick={() => onNavigate(0)}
            className="flex items-center gap-2 rounded-full py-1 pl-1 pr-2 hover:bg-white/5"
            title="Puskodal Operator — Administrator"
          >
            <span className="flex h-9 w-9 items-center justify-center overflow-hidden rounded-full border border-[#343b49] bg-[#0b0e14]">
              <img src="/pasopati-mark.png" alt="Operator" className="h-9 w-9 object-cover" />
            </span>
            <span className="hidden text-left sm:block">
              <span className="block text-[12px] font-bold leading-tight text-slate-200">Puskodal Operator</span>
              <span className="block text-[10px] font-mono text-slate-500">Administrator</span>
            </span>
            <ChevronDown className="hidden h-3.5 w-3.5 text-slate-500 sm:block" />
          </button>

          <span className="hidden items-center gap-1 rounded-md border border-emerald-800/50 bg-emerald-950/40 px-2 py-1 text-[9px] font-mono font-bold text-emerald-300 xl:flex">
            <ShieldCheck className="h-3 w-3" /> TERVERIFIKASI
          </span>
        </div>
      </div>
    </header>
  );
};
