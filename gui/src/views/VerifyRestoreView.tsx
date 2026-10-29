import React, { useState } from "react";
import {
  CheckCircle2,
  XCircle,
  MinusCircle,
  RotateCcw,
  ShieldCheck,
  Key,
  FolderOpen,
  ExternalLink,
  AlertTriangle,
  Sparkles,
} from "lucide-react";
import { useWorkspaceStore } from "../store/workspaceStore";
import { useTaskStore } from "../store/taskStore";
import { verifyCarrier, restoreStructureFile } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { openCarrier, revealCarrier } from "../lib/openActions";
import type { DualVerifyDto, LevelStatus, RemoveResult } from "../types/strhide";

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const VerifyRestoreView: React.FC = () => {
  const { carrierPath, inspection, inspectError } = useWorkspaceStore();
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [password, setPassword] = useState("");
  const [verifyResult, setVerifyResult] = useState<DualVerifyDto | null>(null);
  const [restoreResult, setRestoreResult] = useState<RemoveResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isRestoring, setIsRestoring] = useState(false);

  if (!carrierPath) {
    return (
      <div className="flex h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 text-center text-slate-500">
        <ShieldCheck className="h-8 w-8 text-slate-600 mb-2" />
        <p className="text-sm font-medium">请先在上方拖入或选择载体文件</p>
      </div>
    );
  }

  if (inspectError) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-rose-800/80 bg-rose-950/20 p-8 text-center text-rose-300 space-y-3">
        <AlertTriangle className="h-10 w-10 text-rose-400" />
        <div>
          <h3 className="text-base font-bold text-rose-200">无法校验不受支持的文件格式</h3>
          <p className="mt-1 text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            {inspectError.detail || "该文件格式不受支持或文件已损坏。"}
          </p>
        </div>
      </div>
    );
  }

  const handleVerify = async () => {
    if (!carrierPath) return;
    setErrorMessage(null);
    setIsVerifying(true);
    const taskId = `verify-${Date.now()}`;
    startTask(taskId, "正在执行深度三级校验...");

    try {
      const res = await verifyCarrier(carrierPath, password || undefined);
      setVerifyResult(res);
    } catch (err) {
      const parsed = parseStrHideError(err);
      setErrorMessage(parsed.message);
    } finally {
      setIsVerifying(false);
      finishTask();
    }
  };

  const handleRestore = async () => {
    if (!carrierPath) return;
    setErrorMessage(null);
    setIsRestoring(true);
    const taskId = `restore-${Date.now()}`;
    startTask(taskId, "正在剥离信封并无损还原原始载体...");

    try {
      const res = await restoreStructureFile(
        taskId,
        carrierPath,
        undefined, // in-place restore
        password || undefined,
        true, // auto backup
        true, // overwrite in-place
        updateProgress,
      );
      setRestoreResult(res);
    } catch (err) {
      const parsed = parseStrHideError(err);
      setErrorMessage(parsed.message);
    } finally {
      setIsRestoring(false);
      finishTask();
    }
  };

  const renderLevelStatus = (level: number, title: string, status?: LevelStatus) => {
    if (!status) {
      return (
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 opacity-50 flex items-start gap-3">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-slate-400 text-xs font-bold font-mono">
            L{level}
          </div>
          <div>
            <div className="font-semibold text-slate-300 text-xs">{title}</div>
            <div className="text-[11px] text-slate-500 mt-0.5">未执行校验</div>
          </div>
        </div>
      );
    }

    const isOk = status.ok;
    const isSkipped = status.skipped;

    return (
      <div
        className={`rounded-xl border p-4 transition-all flex items-start gap-3.5 ${
          isSkipped
            ? "border-slate-800 bg-slate-950/60 text-slate-400"
            : isOk
            ? "border-emerald-800/80 bg-emerald-950/20 text-emerald-300"
            : "border-rose-800/80 bg-rose-950/30 text-rose-300"
        }`}
      >
        <div
          className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-xs font-bold font-mono ${
            isSkipped
              ? "bg-slate-800 text-slate-400"
              : isOk
              ? "bg-emerald-900/60 text-emerald-400 border border-emerald-700/50"
              : "bg-rose-900/60 text-rose-400 border border-rose-700/50"
          }`}
        >
          {isSkipped ? (
            <MinusCircle className="h-4 w-4" />
          ) : isOk ? (
            <CheckCircle2 className="h-4 w-4" />
          ) : (
            <XCircle className="h-4 w-4" />
          )}
        </div>

        <div className="flex-1">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-xs text-slate-200">
              Level {level} · {title}
            </span>
            <span
              className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase font-mono ${
                isSkipped
                  ? "bg-slate-800 text-slate-400"
                  : isOk
                  ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                  : "bg-rose-950 text-rose-400 border border-rose-800"
              }`}
            >
              {isSkipped ? "SKIPPED" : isOk ? "PASS" : "FAIL"}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-300 leading-relaxed font-mono">
            {status.detail}
          </p>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* 3-Tier Verification Section */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" />
              三级深度完整性校验 (3-Tier Verification)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              逐层执行容器结构、信封边界一致性与 AEAD 密码学完整性检查
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="relative">
              <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-500" />
              <input
                type="password"
                placeholder="Level 3 解密密码..."
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-48 rounded-xl border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-700 px-4 py-1.5 text-xs font-semibold text-white shadow-md hover:brightness-110 active:scale-95 disabled:opacity-50"
            >
              <ShieldCheck className="h-4 w-4" />
              运行三级校验
            </button>
          </div>
        </div>

        {/* Level 1, 2, 3 Stepper */}
        <div className="space-y-2.5">
          {renderLevelStatus(1, "宿主容器结构校验 (Host Container Syntax)", verifyResult?.level1_host)}
          {renderLevelStatus(2, "隐写信封边界校验 (Envelope & Trailer Consistency)", verifyResult?.level2_envelope)}
          {renderLevelStatus(3, "密码学认证与哈希校验 (AEAD Tag & Payload SHA-256)", verifyResult?.level3_crypto)}
        </div>

        {/* Content stego verification levels */}
        {verifyResult?.content_stego && (
          <div className="mt-4 pt-3 border-t border-slate-800 space-y-2">
            <div className="text-xs font-semibold text-indigo-300 flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5" />
              <span>内容域隐写诊断指标 ({verifyResult.content_stego.format})</span>
            </div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {verifyResult.content_stego.levels.map((lvl) => (
                <div
                  key={lvl.level}
                  className={`rounded-lg border p-2.5 text-xs flex items-center justify-between ${
                    lvl.ok
                      ? "border-emerald-800/60 bg-emerald-950/20 text-emerald-300"
                      : "border-rose-800/60 bg-rose-950/20 text-rose-300"
                  }`}
                >
                  <span className="font-medium">
                    Level {lvl.level}: {lvl.name}
                  </span>
                  <span className="font-mono text-[10px] font-bold">
                    {lvl.ok ? "PASS" : lvl.message || "FAIL"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 100% Lossless Restore Panel */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
              <RotateCcw className="h-4 w-4 text-emerald-400" />
              100% 字节级无损还原 (Lossless Restore)
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              一键精确剥离隐藏信封，使载体恢复到写入前的原始二进制字节流 (SHA-256 吻合)
            </p>
          </div>

          <button
            onClick={handleRestore}
            disabled={isRestoring}
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-700 px-5 py-2 text-xs font-bold text-white shadow-lg hover:bg-emerald-600 active:scale-95 disabled:opacity-50"
          >
            <RotateCcw className="h-4 w-4" />
            一键剥离并还原
          </button>
        </div>

        {/* Carrier Original Record */}
        {inspection?.orig_host_sha256 && (
          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3.5 text-xs font-mono space-y-1.5">
            <div className="text-slate-400 font-sans font-medium">信封记录的原始载体指标:</div>
            <div className="flex justify-between">
              <span className="text-slate-400">原始字节数:</span>
              <span className="text-slate-200">{formatBytes(inspection.orig_host_size)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">原始 SHA-256:</span>
              <span className="text-cyan-300 font-bold truncate max-w-sm" title={inspection.orig_host_sha256}>
                {inspection.orig_host_sha256}
              </span>
            </div>
          </div>
        )}

        {/* Restore Result Card */}
        {restoreResult && (
          <div className="rounded-xl border border-emerald-800/80 bg-emerald-950/30 p-4 space-y-3 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <CheckCircle2 className="h-5 w-5" />
                <span>载体无损还原成功！</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => openCarrier(restoreResult.carrier)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  打开文件
                </button>
                <button
                  onClick={() => revealCarrier(restoreResult.carrier)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                >
                  <FolderOpen className="h-3.5 w-3.5 text-cyan-400" />
                  定位目录
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 text-xs font-mono">
              <div>
                <span className="text-slate-400 font-sans">还原后文件大小: </span>
                <span className="text-slate-200">{formatBytes(restoreResult.restored_size)}</span>
              </div>
              <div>
                <span className="text-slate-400 font-sans">SHA-256 比对状态: </span>
                <span className="text-emerald-400 font-bold">100% 原始字节级吻合 (Bit-Exact)</span>
              </div>
            </div>

            {restoreResult.backup_file && (
              <p className="text-[11px] text-slate-400 font-mono">
                已生成原始隐写备份文件: {restoreResult.backup_file}
              </p>
            )}
          </div>
        )}

        {errorMessage && (
          <div className="rounded-xl border border-rose-800/80 bg-rose-950/50 p-4 text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
};
