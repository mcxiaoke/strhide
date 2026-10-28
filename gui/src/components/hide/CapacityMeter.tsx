import React from "react";
import { ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";
import type { SafetyLevel, StegoCapacityInfo } from "../../types/strhide";

interface CapacityMeterProps {
  capacity: StegoCapacityInfo | null;
  payloadBytes: number;
  selectedSafety: SafetyLevel;
  onSelectSafety: (level: SafetyLevel) => void;
  enforceSafety: boolean;
  onToggleEnforceSafety: (enforce: boolean) => void;
  isLoading?: boolean;
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const CapacityMeter: React.FC<CapacityMeterProps> = ({
  capacity,
  payloadBytes,
  selectedSafety,
  onSelectSafety,
  enforceSafety,
  onToggleEnforceSafety,
  isLoading,
}) => {
  const maxBytes = capacity?.recommended_max_bytes || 1;
  const rawMaxBytes = capacity?.max_raw_payload_bytes || 1;

  const usageRatio = Math.min((payloadBytes / maxBytes) * 100, 100);
  const isOverRecommended = payloadBytes > maxBytes;
  const isOverRawLimit = payloadBytes > rawMaxBytes;

  const tiers: Array<{
    id: SafetyLevel;
    label: string;
    bpp: string;
    desc: string;
    color: string;
  }> = [
    {
      id: "paranoid",
      label: "Paranoid (偏执)",
      bpp: "≤0.06 bpp",
      desc: "极低检测风险，抗高级特征分析",
      color: "border-emerald-500/60 text-emerald-400 bg-emerald-950/30",
    },
    {
      id: "high",
      label: "High (推荐)",
      bpp: "≤0.10 bpp",
      desc: "默认安全线，抵抗常用取证工具",
      color: "border-cyan-500/60 text-cyan-400 bg-cyan-950/30",
    },
    {
      id: "balanced",
      label: "Balanced (均衡)",
      bpp: "≤0.15 bpp",
      desc: "传统隐写容量上限，适合纹理复杂图",
      color: "border-amber-500/60 text-amber-400 bg-amber-950/30",
    },
  ];

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          {isOverRecommended ? (
            <ShieldAlert className={`h-5 w-5 ${enforceSafety ? "text-rose-400" : "text-amber-400"}`} />
          ) : (
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
          )}
          <h4 className="font-semibold text-slate-200 text-sm">自适应容量安全水位尺</h4>
          {isLoading && <span className="text-[11px] text-cyan-400 animate-pulse">(探测中...)</span>}
        </div>

        {/* Safety enforcement toggle */}
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
            <input
              type="checkbox"
              checked={enforceSafety}
              onChange={(e) => onToggleEnforceSafety(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
            />
            <span>超限强制阻断 (Enforced)</span>
          </label>
        </div>
      </div>

      {/* Safety Tiers Selection */}
      <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-3">
        {tiers.map((t) => {
          const isSelected = selectedSafety === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => onSelectSafety(t.id)}
              className={`rounded-xl border p-3 text-left transition-all ${
                isSelected
                  ? `${t.color} shadow-md`
                  : "border-slate-800 bg-slate-950/60 text-slate-400 hover:border-slate-700 hover:text-slate-200"
              }`}
            >
              <div className="flex items-center justify-between font-semibold text-xs">
                <span>{t.label}</span>
                <span className="font-mono text-[10px] opacity-80">{t.bpp}</span>
              </div>
              <p className="mt-1 text-[11px] opacity-75">{t.desc}</p>
            </button>
          );
        })}
      </div>

      {/* Visual Capacity Meter Bar */}
      <div className="mt-5 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">
            当前载荷: <strong className="text-slate-100">{formatBytes(payloadBytes)}</strong>
          </span>
          <span className="text-slate-400">
            推荐上限: <strong className="text-cyan-300">{formatBytes(capacity?.recommended_max_bytes)}</strong>{" "}
            (极限: {formatBytes(capacity?.max_raw_payload_bytes)})
          </span>
        </div>

        {/* Progress Bar Track */}
        <div className="relative h-3 w-full overflow-hidden rounded-full bg-slate-950 border border-slate-800">
          <div
            className={`h-full transition-all duration-300 ease-out ${
              isOverRawLimit
                ? "bg-rose-600"
                : isOverRecommended
                ? enforceSafety
                  ? "bg-rose-500"
                  : "bg-amber-500"
                : "bg-gradient-to-r from-cyan-500 to-emerald-400"
            }`}
            style={{ width: `${usageRatio}%` }}
          />
        </div>

        {/* Over-capacity warning badge */}
        {isOverRecommended && (
          <div
            className={`mt-2.5 flex items-start gap-2 rounded-xl border p-3 text-xs ${
              enforceSafety
                ? "border-rose-800/80 bg-rose-950/50 text-rose-200"
                : "border-amber-800/80 bg-amber-950/50 text-amber-200"
            }`}
          >
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold">
                {enforceSafety ? "载荷超限（已阻断嵌入）" : "载荷超限安全告警（建议模式）"}
              </div>
              <p className="mt-0.5 text-[11px] opacity-90 leading-relaxed">
                当前载荷 ({formatBytes(payloadBytes)}) 超出 {selectedSafety} 档位安全上限 (
                {formatBytes(capacity?.recommended_max_bytes)})。
                {enforceSafety
                  ? "当前处于严格阻断模式，请删减载荷或切换至 Balanced 档位后继续。"
                  : "当前处于仅告警不阻断模式，可继续嵌入，但会削弱抗统计分析隐蔽性。"}
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
