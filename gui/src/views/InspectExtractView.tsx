import React, { useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import {
  ShieldAlert,
  Key,
  Download,
  Copy,
  Check,
  AlertTriangle,
  FolderOpen,
  FileText,
  Lock,
  Layers,
  Sparkles,
  Info,
} from "lucide-react";
import { useWorkspaceStore } from "../store/workspaceStore";
import { useTaskStore } from "../store/taskStore";
import { smartExtract } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { openCarrier, revealCarrier } from "../lib/openActions";
import type { Domain, ReadSummary } from "../types/strhide";

function formatBytes(bytes?: number | null): string {
  if (bytes === undefined || bytes === null) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const InspectExtractView: React.FC = () => {
  const { carrierPath, inspection, isInspecting, inspectCurrentCarrier } = useWorkspaceStore();
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [password, setPassword] = useState("");
  const [preferDomain, setPreferDomain] = useState<Domain | undefined>(undefined);
  const [extractedResult, setExtractedResult] = useState<{
    source: Domain;
    alsoPresent?: Domain;
    summary: ReadSummary;
  } | null>(null);
  const [copied, setCopied] = useState(false);
  const [extractError, setExtractError] = useState<string | null>(null);

  if (!carrierPath) {
    return (
      <div className="flex h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 text-center text-slate-500">
        <Info className="h-8 w-8 text-slate-600 mb-2" />
        <p className="text-sm font-medium">请先在上方拖入或选择载体文件</p>
      </div>
    );
  }

  const struct = inspection;
  const content = inspection?.content_stego;
  const passwordHint = struct?.password_hint;
  const hasSuspicious =
    struct?.has_hidden_data === false && struct.suspicious_hints && struct.suspicious_hints.length > 0;

  const handleSmartExtract = async (forcedDomain?: Domain) => {
    if (!carrierPath) return;
    setExtractError(null);
    const taskId = `extract-${Date.now()}`;
    startTask(taskId, "正在提取载荷...");

    try {
      const res = await smartExtract(
        taskId,
        carrierPath,
        undefined, // in-memory extract first for instant preview
        password || undefined,
        undefined,
        forcedDomain || preferDomain,
        false,
        updateProgress,
      );
      setExtractedResult({
        source: res.source,
        alsoPresent: res.also_present,
        summary: res.summary,
      });
    } catch (err) {
      const parsed = parseStrHideError(err);
      setExtractError(parsed.message);
    } finally {
      finishTask();
    }
  };

  const handleSavePayloadToFile = async () => {
    if (!extractedResult) return;
    try {
      const defaultName = extractedResult.summary.filename || "payload.bin";
      const targetPath = await save({
        defaultPath: defaultName,
        title: "另存载荷文件到本地",
      });
      if (targetPath && typeof targetPath === "string") {
        const taskId = `extract-save-${Date.now()}`;
        startTask(taskId, "正在另存载荷文件...");
        await smartExtract(
          taskId,
          carrierPath,
          targetPath,
          password || undefined,
          undefined,
          extractedResult.source,
          true,
          updateProgress,
        );
        finishTask();
        // Update written_file in UI
        setExtractedResult((prev) =>
          prev
            ? {
                ...prev,
                summary: { ...prev.summary, written_file: targetPath },
              }
            : null,
        );
      }
    } catch (err) {
      const parsed = parseStrHideError(err);
      setExtractError(parsed.message);
      finishTask();
    }
  };

  const handleCopyText = () => {
    if (extractedResult?.summary.text_preview) {
      navigator.clipboard.writeText(extractedResult.summary.text_preview);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Dual domain diagnosis cards */}
      <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
        {/* Left: Structure Domain Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg backdrop-blur-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="h-5 w-5 text-cyan-400" />
              <h3 className="font-semibold text-slate-200">结构域容器检视 (Structure)</h3>
            </div>
            {struct?.has_hidden_data ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-950 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-800/80">
                <Check className="h-3 w-3" />
                已检测到信封
              </span>
            ) : (
              <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-400">
                未检测到信封
              </span>
            )}
          </div>

          <div className="mt-4 space-y-3 text-xs">
            {struct?.strategy && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">注入策略:</span>
                <span className="font-mono font-semibold text-cyan-300">
                  {struct.strategy.name} (ID: {struct.strategy.id})
                </span>
              </div>
            )}
            {struct?.ube_total_size !== undefined && struct.ube_total_size !== null && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">信封总尺寸:</span>
                <span className="font-mono text-slate-200">{formatBytes(struct.ube_total_size)}</span>
              </div>
            )}
            {struct?.ube_offset !== undefined && struct.ube_offset !== null && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">信封偏移量:</span>
                <span className="font-mono text-slate-300">0x{struct.ube_offset.toString(16)}</span>
              </div>
            )}

            <div className="flex flex-wrap gap-1.5 pt-1">
              {struct?.is_encrypted && (
                <span className="rounded bg-indigo-950 px-2 py-0.5 text-indigo-300 border border-indigo-800/50">
                  AES-256-GCM 加密
                </span>
              )}
              {struct?.is_compressed && (
                <span className="rounded bg-blue-950 px-2 py-0.5 text-blue-300 border border-blue-800/50">
                  Zstd 压缩
                </span>
              )}
              {struct?.is_stealth && (
                <span className="rounded bg-purple-950 px-2 py-0.5 text-purple-300 border border-purple-800/50">
                  Stealth 隐身模式
                </span>
              )}
            </div>

            {/* Suspicious stealth hints alert */}
            {hasSuspicious && (
              <div className="mt-3 rounded-xl border border-amber-800/80 bg-amber-950/40 p-3 text-amber-200">
                <div className="flex items-start gap-2">
                  <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
                  <div>
                    <div className="font-semibold">疑似隐身信封特征</div>
                    <div className="mt-1 text-slate-300 text-xs leading-relaxed">
                      检出特征：{struct.suspicious_hints?.join(", ")}。该载体可能包含加密的 Stealth 信封，请在下方输入密码后重新检视。
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Decrypted metadata block */}
            {struct?.metadata && !("error" in struct.metadata) && (
              <div className="mt-3 rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-slate-300 space-y-1.5">
                <div className="font-semibold text-slate-200 text-xs">解密载荷元数据</div>
                <div className="flex justify-between">
                  <span className="text-slate-400">原文件名:</span>
                  <span className="font-mono text-slate-100">{struct.metadata.filename}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">原文件大小:</span>
                  <span className="font-mono text-slate-100">{formatBytes(struct.metadata.raw_size)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SHA-256:</span>
                  <span className="font-mono text-slate-400 truncate max-w-[200px]" title={struct.metadata.raw_sha256}>
                    {struct.metadata.raw_sha256}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Right: Content Domain Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-lg backdrop-blur-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-indigo-400" />
              <h3 className="font-semibold text-slate-200">内容域自适应隐写 (Content Stego)</h3>
            </div>
            {content?.has_hidden_data ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-950 px-2.5 py-0.5 text-xs font-semibold text-emerald-400 border border-emerald-800/80">
                <Check className="h-3 w-3" />
                已检测到隐写
              </span>
            ) : (
              <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs font-medium text-slate-400">
                未检测到隐写
              </span>
            )}
          </div>

          <div className="mt-4 space-y-3 text-xs">
            {content?.algorithm && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">隐写算法模型:</span>
                <span className="font-mono font-semibold text-indigo-300">{content.algorithm}</span>
              </div>
            )}
            {content?.codec && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">矩阵编码层:</span>
                <span className="font-mono text-slate-200">{content.codec}</span>
              </div>
            )}
            {content?.payload_len !== undefined && content.payload_len !== null && (
              <div className="flex items-center justify-between">
                <span className="text-slate-400">有效载荷长度:</span>
                <span className="font-mono text-emerald-400 font-bold">{formatBytes(content.payload_len)}</span>
              </div>
            )}
            {content?.note && (
              <div className="rounded-lg bg-slate-800/60 p-2 text-slate-300">{content.note}</div>
            )}
            {inspection?.content_error && (
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-2 text-slate-400">
                <span className="text-rose-400 font-medium">内容域提示: </span>
                {inspection.content_error.detail}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Double Carrier Warning Alert */}
      {extractedResult?.alsoPresent && (
        <div className="rounded-2xl border border-cyan-800/90 bg-cyan-950/50 p-4 text-cyan-200 shadow-lg flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-cyan-400 shrink-0" />
            <div>
              <div className="font-semibold text-sm">双域独立载荷提示</div>
              <div className="text-xs text-cyan-300/80">
                该载体同时包含【{extractedResult.alsoPresent === "structure" ? "结构域" : "内容域"}】独立载荷！当前展示的是【
                {extractedResult.source === "structure" ? "结构域" : "内容域"}】提取结果。
              </div>
            </div>
          </div>
          <button
            onClick={() => handleSmartExtract(extractedResult.alsoPresent)}
            className="shrink-0 rounded-xl bg-cyan-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-cyan-400"
          >
            提取另一载荷
          </button>
        </div>
      )}

      {/* Smart Extract Control Bar */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl">
        <h4 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Key className="h-4 w-4 text-cyan-400" />
          一键智能提取 (Smart Extract)
        </h4>

        {passwordHint && (
          <div className="mb-3 inline-flex items-center gap-1.5 rounded-lg bg-amber-950/60 px-3 py-1 text-xs text-amber-300 border border-amber-800/40">
            <Info className="h-3.5 w-3.5" />
            <span>密码提示 (Hint): <strong className="text-white font-mono">{passwordHint}</strong></span>
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[260px]">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <input
              type="password"
              placeholder="如载荷已加密，请输入解密密码..."
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950 py-2.5 pl-9 pr-3 text-xs text-slate-100 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <select
            value={preferDomain || ""}
            onChange={(e) => setPreferDomain((e.target.value as Domain) || undefined)}
            className="rounded-xl border border-slate-800 bg-slate-950 px-3 py-2.5 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none"
          >
            <option value="">优先域: 自动检测 (Auto)</option>
            <option value="structure">优先结构域 (Structure)</option>
            <option value="content">优先内容域 (Content)</option>
          </select>

          <button
            onClick={() => handleSmartExtract()}
            disabled={isInspecting}
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-5 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-950/50 hover:brightness-110 active:scale-95 disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            开始提取
          </button>

          {password && (
            <button
              onClick={() => inspectCurrentCarrier(password)}
              className="rounded-xl border border-slate-700 bg-slate-800 px-3.5 py-2.5 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white"
            >
              带密码重新检视
            </button>
          )}
        </div>

        {extractError && (
          <div className="mt-3 rounded-xl border border-rose-800/80 bg-rose-950/40 p-3 text-xs text-rose-300 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{extractError}</span>
          </div>
        )}
      </div>

      {/* Extracted Payload Result Display */}
      {extractedResult && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-2xl animate-in fade-in duration-200">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <FileText className="h-5 w-5 text-cyan-400" />
              <h4 className="font-semibold text-slate-100">
                提取结果: {extractedResult.summary.filename}
              </h4>
              <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300 font-mono">
                {formatBytes(extractedResult.summary.raw_size)}
              </span>
              <span className="rounded bg-cyan-950 px-2 py-0.5 text-xs text-cyan-300 border border-cyan-800/40 font-mono">
                来自: {extractedResult.source === "structure" ? "结构域" : "内容域"}
              </span>
            </div>

            <div className="flex items-center gap-2">
              {extractedResult.summary.text_preview && (
                <button
                  onClick={handleCopyText}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied ? "已复制" : "复制文本"}
                </button>
              )}
              <button
                onClick={handleSavePayloadToFile}
                className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-500 shadow-sm"
              >
                <Download className="h-3.5 w-3.5" />
                另存为文件...
              </button>
              {extractedResult.summary.written_file && (
                <button
                  onClick={() => revealCarrier(extractedResult.summary.written_file!)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
                >
                  <FolderOpen className="h-3.5 w-3.5 text-cyan-400" />
                  打开所在目录
                </button>
              )}
            </div>
          </div>

          {/* Pure text rendering to prevent XSS */}
          {extractedResult.summary.text_preview ? (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
              <pre
                style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}
                className="font-mono text-xs text-slate-200 leading-relaxed max-h-96 overflow-y-auto selection:bg-cyan-900"
              >
                {extractedResult.summary.text_preview}
              </pre>
            </div>
          ) : (
            <div className="mt-4 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-400">
              <span>二进制载荷文件，未在内存中渲染纯文本预览。可点击上方“另存为文件”落盘保存。</span>
              {extractedResult.summary.written_file && (
                <button
                  onClick={() => openCarrier(extractedResult.summary.written_file!)}
                  className="text-cyan-400 hover:underline"
                >
                  系统程序打开
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
