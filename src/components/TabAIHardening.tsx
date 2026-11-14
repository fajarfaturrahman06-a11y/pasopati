import React, { useEffect, useState } from 'react';
import { DeviceInfo, RemediationPlan } from '../types';
import { calculateDeviceScore } from '../data/mockDevices';
import { listPlans } from '../remediationApi';
import { VerificationBadge } from './VerificationBadges';
import { RemediationPanel } from './TabRemediation';
import { sfx } from '../utils/audio';
import { Sparkles, Shield, AlertOctagon, Key } from 'lucide-react';

interface TabAIHardeningProps {
  devices: DeviceInfo[];
  selectedDeviceId: string;
  onSelectDevice: (deviceId: string) => void;
  userApiKey: string;
  setUserApiKey: (key: string) => void;
  geminiKey: string;
  setGeminiKey: (key: string) => void;
  onShowToast: (message: string, type?: 'success' | 'info') => void;
}

export const TabAIHardening: React.FC<TabAIHardeningProps> = ({
  devices,
  selectedDeviceId,
  onSelectDevice,
  userApiKey,
  setUserApiKey,
  geminiKey,
  setGeminiKey,
  onShowToast
}) => {
  const currentDevice = devices.find(d => d.id === selectedDeviceId) || devices[0];
  const failChecks = currentDevice.checks.filter(c => c.status === 'FAIL');
  const warnChecks = currentDevice.checks.filter(c => c.status === 'WARNING');
  const deviceScore = calculateDeviceScore(currentDevice.checks);

  const [isGeneratingAI, setIsGeneratingAI] = useState(false);
  const [aiAnalysisText, setAiAnalysisText] = useState<string | null>(null);
  const [aiSource, setAiSource] = useState<'gemini' | 'rule-based' | null>(null);
  const [aiModel, setAiModel] = useState<string>('');
  const [opsecActive, setOpsecActive] = useState(true);
  const [verifiedPlan, setVerifiedPlan] = useState<RemediationPlan | null>(null);

  useEffect(() => {
    let cancelled = false;
    listPlans(userApiKey)
      .then(plans => {
        if (cancelled) return;
        const match = plans.find(p => p.deviceId === currentDevice.id && p.status === 'VERIFIED') || null;
        setVerifiedPlan(match);
      })
      .catch(() => {
        if (!cancelled) setVerifiedPlan(null);
      });
    return () => {
      cancelled = true;
    };
  }, [userApiKey, currentDevice.id]);


  // Run AI Contextual Risk Analysis
  const handleAnalyzeThreats = async () => {
    sfx.playPing();
    setIsGeneratingAI(true);
    setAiAnalysisText(null);

    try {
      const res = await fetch('/api/analyze-threats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(userApiKey.trim() ? { 'X-Pasopati-API-Key': userApiKey.trim() } : {}) },
        body: JSON.stringify({
          deviceName: currentDevice.name,
          deviceRole: currentDevice.role,
          os: currentDevice.os,
          checks: currentDevice.checks,
          userApiKey: geminiKey.trim() || undefined,
          opsecActive: opsecActive
        })
      });

      if (!res.ok) throw new Error('API request failed');
      const data = await res.json();
      setAiAnalysisText(data.analysis);
      setAiSource(data.engine === 'cloud' ? 'gemini' : 'rule-based');
      setAiModel(data.engine === 'cloud' ? String(data.source || '') : '');
      sfx.playClick();
    } catch {
      // Direct client fallback
      const failItems = currentDevice.checks.filter(c => c.status === 'FAIL');
      let fallbackText = `TELAAH INTELIJEN SIBER PERTAHANAN (PASOPATI THREAT INTEL):\n\n`;
      fallbackText += `Inspeksi pada ${currentDevice.name} (${currentDevice.role}) mengidentifikasi ${failItems.length} celah FAIL kritis yang membahayakan operasi satgas:\n\n`;
      failItems.forEach((f, idx) => {
        fallbackText += `${idx + 1}. [RISIKO TINGGI] ${f.parameter}:\n   Dampak: ${f.details}\n   Mitigasi Taktis: ${f.mitigation}\n\n`;
      });
      setAiAnalysisText(fallbackText);
      setAiSource('rule-based');
    } finally {
      setIsGeneratingAI(false);
    }
  };


  return (
    <div className="space-y-6">
      
      {/* Title & Device Switcher */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-[#171b23] p-5 rounded-lg border border-[#2a3140]">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold tracking-tight text-rose-400 font-mono">
              UNIFIED HARDENING & REMEDIATION
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700/60 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-rose-400" />
              Fitur Inovasi Utama
            </span>
          </div>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Satu jalur: analisis risiko → change set → runbook → eksekusi agent terverifikasi
          </p>
        </div>

        {/* Target Device Selector */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
          {devices.map(d => {
            const isSelected = d.id === currentDevice.id;
            const hasFail = d.checks.some(c => c.status === 'FAIL');
            return (
              <button
                key={d.id}
                onClick={() => {
                  sfx.playClick();
                  onSelectDevice(d.id);
                  setAiAnalysisText(null);
                }}
                className={`px-3 py-1.5 rounded-md text-xs font-mono whitespace-nowrap transition-all border flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-rose-950 text-rose-300 border-rose-600 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                    : 'bg-[#171b23] text-slate-400 border-[#2a3140] hover:text-slate-200'
                }`}
              >
                <span>{d.name}</span>
                {hasFail ? (
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                ) : (
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Target Device Status Summary Card */}
      <div className="bg-[#1b202a] border border-[#2a3140] rounded-lg p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold font-mono text-slate-100">{currentDevice.name}</span>
            <span className="text-xs font-mono text-slate-400">({currentDevice.role})</span>
            <VerificationBadge planStatus={verifiedPlan ? verifiedPlan.status : undefined} />
          </div>
          <div className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-3">
            <span>OS: <strong className="text-slate-200">{currentDevice.os}</strong></span>
            <span>IP: <strong className="text-slate-200">{currentDevice.ip}</strong></span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-[11px] font-mono text-slate-400 block">Kondisi Celah</span>
            <span className="text-sm font-mono font-bold">
              <span className="text-rose-400">{failChecks.length} FAIL</span> · <span className="text-amber-400">{warnChecks.length} WARN</span>
            </span>
          </div>
          <div className="text-right pl-3 border-l border-[#2a3140]">
            <span className="text-[11px] font-mono text-slate-400 block">Skor Saat Ini</span>
            <span
              className={`text-xl font-bold font-mono tabular-nums ${
                deviceScore >= 75 ? 'text-emerald-400' : deviceScore >= 50 ? 'text-amber-400' : 'text-rose-400'
              }`}
            >
              {deviceScore}/100
            </span>
          </div>
        </div>
      </div>

      {/* API Key Configuration Card */}
      <div className="bg-[#171b23] border border-[#2a3140] rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Key className="w-4 h-4 text-rose-400 shrink-0" />
          <div className="text-xs font-mono">
            <span className="text-slate-300 font-semibold block">Kunci Operasional &amp; AI:</span>
            <span className="text-slate-500 text-[11px]">
              <b className="text-rose-400">PASOPATI_API_KEY wajib</b> untuk Buat Plan / Approve / unduh ZIP.
              Kunci AI opsional; bila kosong dipakai Rule-Based Engine.
            </span>
          </div>
        </div>
        <div className="w-full sm:w-80 flex flex-col gap-2">
          <input
            type="password"
            placeholder="1) AI key (opsional) — bukan untuk plan..."
            value={geminiKey}
            onChange={(e) => setGeminiKey(e.target.value)}
            className="w-full px-3 py-1.5 text-xs font-mono bg-[#0d1016] border border-[#333b4b] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-rose-500"
          />
          <input
            type="password"
            placeholder="2) PASOPATI_API_KEY (wajib untuk plan/approve)..."
            value={userApiKey}
            onChange={(e) => setUserApiKey(e.target.value)}
            className="w-full px-3 py-1.5 text-xs font-mono bg-[#0d1016] border border-[#333b4b] rounded text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-rose-500"
          />
          <label className="flex items-center gap-2 cursor-pointer text-[11px] text-slate-400 select-none">
            <input
              type="checkbox"
              checked={opsecActive}
              onChange={(e) => setOpsecActive(e.target.checked)}
              className="rounded bg-[#0d1016] border-[#333b4b] text-rose-600 focus:ring-0"
            />
            <span className="text-rose-400 font-mono">🔒 OPSEC Data Sanitization</span>
          </label>
        </div>
      </div>

      {/* OPSEC Active Banner */}
      {opsecActive && (
        <div className="px-4 py-2.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center gap-2">
          <Shield className="w-4 h-4 text-rose-400 shrink-0" />
          <span><strong>OPSEC Sanitization Active:</strong> Parameter IP taktis, MAC, dan Hostname disensor menjadi <code className="text-rose-200 bg-rose-900/60 px-1 py-0.5 rounded">[REDACTED]</code> sebelum diproses AI.</span>
        </div>
      )}

      {/* FITUR 1: Analisis Risiko Kontekstual Taktis */}
      <div className="bg-[#1b202a] border border-[#2a3140] rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#2a3140] pb-3">
          <div className="flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">
              1. Analisis Risiko Kontekstual Taktis (Military Threat Intel)
            </h3>
          </div>
          <button
            disabled={isGeneratingAI}
            onClick={handleAnalyzeThreats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold font-mono transition-all shadow-[0_0_10px_rgba(239,68,68,0.2)] disabled:opacity-50"
          >
            <Sparkles className={`w-3.5 h-3.5 ${isGeneratingAI ? 'animate-spin' : ''}`} />
            <span>{isGeneratingAI ? 'MENGANALISIS INTEL...' : 'Generate AI Threat Analysis'}</span>
          </button>
        </div>

        {/* AI Output Box */}
        {aiAnalysisText ? (
          <div className="bg-[#0d1016] p-4 rounded-lg border border-[#2a3140] text-xs font-mono space-y-2">
            <div className="flex items-center justify-between text-[11px] text-slate-400 border-b border-[#2a3140] pb-2">
              <span className="text-rose-400 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" />
                TELAAH INTELIJEN SIBER PASOPATI
              </span>
              <span className="px-2 py-0.5 rounded bg-[#171b23] text-slate-400 border border-[#2a3140] text-[10px]">
                {aiSource === 'gemini' ? `Model: ${aiModel || 'cloud AI'}` : 'Engine: Rule-Based Defense Baseline'}
              </span>
            </div>
            <div className="text-slate-300 leading-relaxed whitespace-pre-line pt-2">
              {aiAnalysisText}
            </div>
          </div>
        ) : (
          <div className="p-4 rounded bg-[#0d1016]/60 border border-[#2a3140]/80 text-xs font-mono text-slate-400 flex flex-col items-center justify-center py-6 text-center">
            <Sparkles className="w-6 h-6 text-rose-400/60 mb-2" />
            <span>Klik tombol <strong>"Generate AI Threat Analysis"</strong> untuk menghasilkan telaah risiko militer dalam Bahasa Indonesia.</span>
          </div>
        )}
      </div>

      {/* Panel remediasi: parameter diturunkan dari temuan hardening di atas */}
      <RemediationPanel currentDevice={currentDevice} apiKey={userApiKey} onShowToast={onShowToast} />

    </div>
  );
};
