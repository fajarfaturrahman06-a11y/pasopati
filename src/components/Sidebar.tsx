import React from 'react';
import {
  LayoutDashboard,
  MonitorSmartphone,
  Wrench,
  UploadCloud,
  ScrollText,
  FileText,
  Download,
  Volume2,
  VolumeX,
  X,
  ShieldCheck,
  Radio
} from 'lucide-react';
import { sfx } from '../utils/audio';

interface SidebarProps {
  activeTab: number;
  setActiveTab: (tab: number) => void;
  fleetScore: number;
  soundEnabled: boolean;
  setSoundEnabled: (enabled: boolean) => void;
  onExportCommanderReport: () => void;
  onDownloadProjectZip?: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

const MENU = [
  { id: 0, label: 'Dashboard', icon: LayoutDashboard },
  { id: 1, label: 'Endpoint Audit', icon: MonitorSmartphone },
  { id: 2, label: 'Hardening & Remediation', icon: Wrench },
  { id: 3, label: 'Agent & Upload', icon: UploadCloud },
  { id: 4, label: 'Audit Log', icon: ScrollText }
];

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  fleetScore,
  soundEnabled,
  setSoundEnabled,
  onExportCommanderReport,
  onDownloadProjectZip,
  mobileOpen,
  onCloseMobile
}) => {
  const defcon =
    fleetScore >= 80
      ? { label: 'DEFCON 4', status: 'SIAP OPERASI', color: 'text-emerald-400' }
      : fleetScore >= 60
        ? { label: 'DEFCON 3', status: 'WASPADA', color: 'text-amber-400' }
        : fleetScore >= 50
          ? { label: 'DEFCON 2', status: 'PERLU MITIGASI', color: 'text-orange-400' }
          : { label: 'DEFCON 1', status: 'SIAGA MERAH', color: 'text-rose-400' };

  const navigate = (id: number) => {
    sfx.playClick();
    setActiveTab(id);
    onCloseMobile();
  };

  return (
    <>
      {mobileOpen && (
        <button
          aria-label="Tutup menu"
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-[268px] flex-col bg-[#0b0e14] border-r border-[#20242e] transition-transform duration-200 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand */}
        <div className="flex items-center gap-3 px-5 pt-5 pb-4">
          <img
            src="/pasopati-mark.png"
            alt="Logo PASOPATI"
            className="w-11 h-11 rounded-xl object-cover border border-[#2a3140] shadow-[0_0_22px_rgba(239,68,68,0.18)]"
          />
          <div className="min-w-0">
            <div className="text-[19px] font-black tracking-[0.14em] text-rose-500 leading-none">
              PASOPATI
            </div>
            <div className="mt-1 text-[9px] font-mono uppercase tracking-[0.16em] text-slate-500 leading-tight">
              Audit Sistem &amp; Operasi Pengamanan Agen TI
            </div>
          </div>
          <button
            onClick={onCloseMobile}
            className="ml-auto rounded-md p-1 text-slate-500 hover:bg-white/5 hover:text-slate-200 lg:hidden"
            aria-label="Tutup sidebar"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Operator identity */}
        <div className="mx-4 mb-5 flex items-center gap-3 rounded-xl border border-[#252b37] bg-[#12161e] px-3 py-3">
          <div className="relative">
            <span className="flex h-10 w-10 items-center justify-center overflow-hidden rounded-full border border-[#343b49] bg-[#0b0e14]">
              <img src="/pasopati-mark.png" alt="" className="h-10 w-10 object-cover" />
            </span>
            <span className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-[#12161e] bg-emerald-400" />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[13px] font-bold text-slate-100">Puskodal Operator</div>
            <div className="text-[10px] font-mono text-slate-500">Administrator</div>
          </div>
          <ShieldCheck className="ml-auto h-4 w-4 text-emerald-400/80" />
        </div>

        {/* Navigation */}
        <div className="px-4 text-[9px] font-mono font-bold uppercase tracking-[0.18em] text-slate-600">
          Menu Utama
        </div>
        <nav className="mt-2 flex-1 space-y-1 overflow-y-auto px-3 pb-4">
          {MENU.map(item => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => navigate(item.id)}
                className={`pasopati-nav-item w-full text-left ${isActive ? 'active' : ''}`}
              >
                <span className="pasopati-nav-icon">
                  <Icon className="h-[17px] w-[17px]" />
                </span>
                <span className="truncate">{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Fleet status */}
        <div className="mx-4 mb-4 rounded-xl border border-[#252b37] bg-[#12161e] p-3">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-slate-500">
            <span className="flex items-center gap-1.5">
              <Radio className="h-3 w-3 text-rose-400" /> Status Armada
            </span>
            <span className={defcon.color}>{defcon.label}</span>
          </div>
          <div className="mt-2 flex items-end gap-2">
            <span className="text-2xl font-black tabular-nums text-slate-100">{fleetScore}</span>
            <span className="pb-0.5 text-[10px] font-mono text-slate-500">/ 100</span>
            <span className={`ml-auto pb-0.5 text-[10px] font-mono font-bold ${defcon.color}`}>
              {defcon.status}
            </span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[#232936]">
            <div
              className={`h-full rounded-full ${fleetScore >= 75 ? 'bg-emerald-500' : fleetScore >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`}
              style={{ width: `${Math.max(4, fleetScore)}%` }}
            />
          </div>
        </div>

        {/* Actions */}
        <div className="border-t border-[#20242e] px-4 py-3">
          <div className="grid grid-cols-3 gap-2">
            <button
              onClick={() => {
                sfx.playPing();
                onExportCommanderReport();
              }}
              title="Buat laporan kesiapan siber"
              className="flex flex-col items-center gap-1 rounded-lg border border-[#2a3140] bg-[#151a22] py-2 text-[9px] font-mono font-bold text-slate-400 hover:border-rose-500/50 hover:text-rose-300"
            >
              <FileText className="h-4 w-4" />
              LAPORAN
            </button>
            <button
              onClick={() => {
                sfx.playClick();
                onDownloadProjectZip?.();
              }}
              title="Unduh ZIP proyek (butuh API key)"
              className="flex flex-col items-center gap-1 rounded-lg border border-[#2a3140] bg-[#151a22] py-2 text-[9px] font-mono font-bold text-slate-400 hover:border-rose-500/50 hover:text-rose-300"
            >
              <Download className="h-4 w-4" />
              ZIP
            </button>
            <button
              onClick={() => {
                const next = !soundEnabled;
                setSoundEnabled(next);
                sfx.enabled = next;
                if (next) sfx.playClick();
              }}
              title={soundEnabled ? 'Matikan efek suara' : 'Aktifkan efek suara'}
              className="flex flex-col items-center gap-1 rounded-lg border border-[#2a3140] bg-[#151a22] py-2 text-[9px] font-mono font-bold text-slate-400 hover:border-rose-500/50 hover:text-rose-300"
            >
              {soundEnabled ? <Volume2 className="h-4 w-4" /> : <VolumeX className="h-4 w-4" />}
              SUARA
            </button>
          </div>
          <div className="mt-3 text-center text-[9px] font-mono text-slate-600">
            PASOPATI v2.6 · COMMAND CENTER
          </div>
        </div>
      </aside>
    </>
  );
};
