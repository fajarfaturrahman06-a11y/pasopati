import React from 'react';
import { CheckCircle2, Clock, XCircle, MinusCircle } from 'lucide-react';
import type { PlanStatus } from '../types';

export interface VerificationBadgeProps {
  planStatus?: PlanStatus | null;
}

export const VerificationBadge: React.FC<VerificationBadgeProps> = ({ planStatus }) => {
  if (planStatus === 'VERIFIED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-600 font-mono text-[11px] font-bold">
        <CheckCircle2 className="w-3.5 h-3.5" />
        TERVERIFIKASI NYATA
      </span>
    );
  }
  if (planStatus === 'EXECUTING') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-sky-950 text-sky-300 border border-sky-700 font-mono text-[11px] font-bold">
        <Clock className="w-3.5 h-3.5 animate-pulse" />
        MENUNGGU EVIDENCE AGENT…
      </span>
    );
  }
  if (planStatus === 'MANUAL_REPORTED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950 text-amber-200 border border-amber-700 font-mono text-[11px] font-bold">
        <Clock className="w-3.5 h-3.5" />
        LAPORAN MANUAL · BELUM AUDIT ULANG
      </span>
    );
  }
  if (planStatus === 'ROLLED_BACK' || planStatus === 'FAILED') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-700 font-mono text-[11px] font-bold">
        <XCircle className="w-3.5 h-3.5" />
        {planStatus === 'ROLLED_BACK' ? 'ROLLED BACK' : 'GAGAL'}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-700 font-mono text-[11px] font-bold">
      <MinusCircle className="w-3.5 h-3.5" />
      SIMULASI
    </span>
  );
};
