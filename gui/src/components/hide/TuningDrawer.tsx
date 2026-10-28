import React from "react";
import { SlidersHorizontal, Shield, Clock, HardDrive, Cpu } from "lucide-react";
import type { StrategyCapacity } from "../../types/strhide";

interface TuningDrawerProps {
  domain: "structure" | "content";
  carrierFormat?: string;
  strategies: StrategyCapacity[];
  selectedStrategy: string;
  onSelectStrategy: (strat: string) => void;
  selectedAlgorithm: string;
  onSelectAlgorithm: (algo: string) => void;
  stealth: boolean;
  onToggleStealth: (stealth: boolean) => void;
  backup: boolean;
  onToggleBackup: (backup: boolean) => void;
  preserveTime: boolean;
  onTogglePreserveTime: (preserve: boolean) => void;
  hasPassword: boolean;
}

export const TuningDrawer: React.FC<TuningDrawerProps> = ({
  domain,
  carrierFormat,
  strategies,
  selectedStrategy,
  onSelectStrategy,
  selectedAlgorithm,
  onSelectAlgorithm,
  stealth,
  onToggleStealth,
  backup,
  onToggleBackup,
  preserveTime,
  onTogglePreserveTime,
  hasPassword,
}) => {
  const isPng = carrierFormat?.toUpperCase() === "PNG";
  const isJpeg = carrierFormat?.toUpperCase() === "JPEG";

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3 text-slate-300 font-semibold text-xs">
        <SlidersHorizontal className="h-4 w-4 text-cyan-400" />
        <span>高级参数微调 (Tuning & Safety Policy)</span>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {/* Strategy selection for structure domain */}
        {domain === "structure" ? (
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5 text-cyan-400" />
              注入策略 (Strategy)
            </label>
            <select
              value={selectedStrategy}
              onChange={(e) => onSelectStrategy(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="auto">自动选择最佳策略 (Auto)</option>
              {strategies.map((s) => (
                <option key={s.strategy} value={s.strategy} disabled={!s.available}>
                  {s.strategy} - {s.limit} {s.available ? "" : "(不可用)"}
                </option>
              ))}
            </select>
            <p className="mt-1 text-[11px] text-slate-500">
              默认 auto 自动根据载体结构选择最高隐蔽性或最大容量注入槽位
            </p>
          </div>
        ) : (
          /* Algorithm selection for content domain */
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Cpu className="h-3.5 w-3.5 text-indigo-400" />
              代价图模型 (Cost Model)
            </label>
            <select
              value={selectedAlgorithm}
              onChange={(e) => onSelectAlgorithm(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              <option value="auto">自动最优算法 (Auto)</option>
              {isPng && (
                <>
                  <option value="hill">HILL (高通残差滤波 - 推荐)</option>
                  <option value="suniward">S-UNIWARD (小波方向小波基)</option>
                </>
              )}
              {isJpeg && (
                <>
                  <option value="uerd">UERD (均匀能量自适应 - 推荐)</option>
                  <option value="juniward">J-UNIWARD (DCT 块内敏感加权)</option>
                </>
              )}
            </select>
            <p className="mt-1 text-[11px] text-slate-500">
              结合 STC 矩阵编码寻找最小嵌入失真路径，抗卡方分析与 RS 检测
            </p>
          </div>
        )}

        {/* Checkbox Options */}
        <div className="space-y-2.5 pt-1">
          {domain === "structure" && (
            <label
              className={`flex items-start gap-2.5 text-xs ${
                hasPassword ? "text-slate-300 cursor-pointer" : "text-slate-600 cursor-not-allowed"
              }`}
            >
              <input
                type="checkbox"
                checked={stealth}
                disabled={!hasPassword}
                onChange={(e) => onToggleStealth(e.target.checked)}
                className="mt-0.5 h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 disabled:opacity-40"
              />
              <div>
                <span className="font-medium flex items-center gap-1">
                  <Shield className="h-3.5 w-3.5 text-purple-400" />
                  Stealth 隐身信封（消除固定 Magic 标记）
                </span>
                <p className="text-[11px] text-slate-500">
                  擦除 UBE 头部明文特征，信封仅能通过正确密码进行位置推算（需先输入密码）
                </p>
              </div>
            </label>
          )}

          <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={backup}
              onChange={(e) => onToggleBackup(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
            />
            <div>
              <span className="font-medium flex items-center gap-1">
                <HardDrive className="h-3.5 w-3.5 text-emerald-400" />
                保留原文件备份 (.bak)
              </span>
              <p className="text-[11px] text-slate-500">原地覆盖前自动生成 `carrier.bak`，防止数据丢失</p>
            </div>
          </label>

          <label className="flex items-start gap-2.5 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={preserveTime}
              onChange={(e) => onTogglePreserveTime(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
            />
            <div>
              <span className="font-medium flex items-center gap-1">
                <Clock className="h-3.5 w-3.5 text-cyan-400" />
                克隆原文件修改时间 (Preserve Timestamp)
              </span>
              <p className="text-[11px] text-slate-500">保持 mtime/atime 不变，防止时间戳篡改暴露隐写痕迹</p>
            </div>
          </label>
        </div>
      </div>
    </div>
  );
};
