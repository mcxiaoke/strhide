import React, { useState, useEffect, useRef } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import {
  Shield,
  Layers,
  Sparkles,
  FileText,
  Upload,
  Lock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  FolderOpen,
  ExternalLink,
  SlidersHorizontal,
} from "lucide-react";
import { useWorkspaceStore } from "../store/workspaceStore";
import { useTaskStore } from "../store/taskStore";
import { useSettingsStore } from "../store/settingsStore";
import { writeStructureFile, embedStegoFile, probeStegoCapacity, getFileMetadata } from "../api/commands";
import { CapacityMeter } from "../components/hide/CapacityMeter";
import { TuningDrawer } from "../components/hide/TuningDrawer";
import { OverwriteDialog } from "../components/common/OverwriteDialog";
import { openCarrier, revealCarrier } from "../lib/openActions";
import { parseStrHideError } from "../lib/errorHandler";
import type {
  Domain,
  SafetyLevel,
  StegoCapacityFullDto,
  PayloadInputDto,
  EmbedStats,
} from "../types/strhide";

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const HideEmbedView: React.FC = () => {
  const { carrierPath, inspection, inspectError, capabilities } = useWorkspaceStore();
  const { startTask, updateProgress, finishTask } = useTaskStore();
  const { autoBackup } = useSettingsStore();

  const [domain, setDomain] = useState<Domain>("content");
  const [payloadType, setPayloadType] = useState<"text" | "file">("text");
  const [textContent, setTextContent] = useState("");
  const [payloadFilePath, setPayloadFilePath] = useState<string | null>(null);
  const [payloadFileSize, setPayloadFileSize] = useState<number>(0);

  // Security & tuning state
  const [password, setPassword] = useState("");
  const [passwordHint, setPasswordHint] = useState("");
  const [safetyLevel, setSafetyLevel] = useState<SafetyLevel>("high");
  const [enforceSafety, setEnforceSafety] = useState(false);
  const [selectedStrategy, setSelectedStrategy] = useState("auto");
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("auto");
  const [stealth, setStealth] = useState(false);
  const [backup, setBackup] = useState(autoBackup);
  const [preserveTime, setPreserveTime] = useState(true);
  const [showTuning, setShowTuning] = useState(false);

  // Capacity state with global carrier caching
  const [capacity, setCapacity] = useState<StegoCapacityFullDto | null>(null);
  const [isProbing, setIsProbing] = useState(false);
  const [probeError, setProbeError] = useState<string | null>(null);
  const capacityCacheRef = useRef<Map<string, StegoCapacityFullDto>>(new Map());

  // Outcome & dialogs
  const [result, setResult] = useState<{
    writtenTo: string;
    beforeBytes: number;
    afterBytes: number;
    stats?: EmbedStats;
    warnings?: string[];
  } | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [conflictTarget, setConflictTarget] = useState<string | null>(null);

  const format = inspection?.format;
  const currentCap = capabilities.find(
    (c) => c.format.toLowerCase() === format?.toLowerCase(),
  );
  const supportsStego = currentCap ? currentCap.stego.length > 0 : false;
  const supportsStructure = currentCap ? currentCap.structure.length > 0 : true;

  // Real carrier validation: an MP4 without HEVC stream does NOT support content stego
  const contentError = inspection?.content_error;
  const fileSupportsStego = supportsStego && !contentError;

  // Auto-select domain based on actual carrier capability
  useEffect(() => {
    if (fileSupportsStego) {
      setDomain("content");
    } else if (supportsStructure) {
      setDomain("structure");
    }
  }, [fileSupportsStego, supportsStructure]);

  // Compute live payload bytes
  const payloadBytes =
    payloadType === "text"
      ? new TextEncoder().encode(textContent).length
      : payloadFileSize;

  // Probe capacity on carrier or core tuning change (cached across safety tier switches)
  const probeTimerRef = useRef<number | null>(null);
  useEffect(() => {
    if (!carrierPath || !fileSupportsStego || domain !== "content") {
      setCapacity(null);
      setProbeError(null);
      return;
    }

    const cacheKey = `${carrierPath}:${password || ""}:${selectedAlgorithm}`;
    const cached = capacityCacheRef.current.get(cacheKey);
    if (cached) {
      setCapacity(cached);
      setProbeError(null);
      return;
    }

    if (probeTimerRef.current) {
      window.clearTimeout(probeTimerRef.current);
    }

    probeTimerRef.current = window.setTimeout(async () => {
      setIsProbing(true);
      try {
        const info = await probeStegoCapacity(
          `probe-${Date.now()}`,
          carrierPath,
          safetyLevel,
          password || undefined,
          undefined,
          selectedAlgorithm !== "auto" ? selectedAlgorithm : undefined,
          false,
        );
        capacityCacheRef.current.set(cacheKey, info);
        setCapacity(info);
        setProbeError(null);
      } catch (err) {
        const parsed = parseStrHideError(err);
        console.warn("Capacity probe error:", err);
        setProbeError(parsed.message || "该载体文件不支持内容域自适应隐写探测");
        setCapacity(null);
      } finally {
        setIsProbing(false);
      }
    }, 150);

    return () => {
      if (probeTimerRef.current) window.clearTimeout(probeTimerRef.current);
    };
  }, [carrierPath, fileSupportsStego, domain, password, selectedAlgorithm]);

  const handlePickPayloadFile = async () => {
    try {
      const selected = await open({
        multiple: false,
        title: "选择要隐藏的载荷文件",
      });
      if (selected && typeof selected === "string") {
        setPayloadFilePath(selected);
        try {
          const meta = await getFileMetadata(selected);
          setPayloadFileSize(meta.size_bytes);
        } catch (metaErr) {
          console.warn("Failed to get file metadata:", metaErr);
          setPayloadFileSize(0);
        }
      }
    } catch (err) {
      console.error("Payload pick error:", err);
    }
  };

  const handleStartHide = async (forcedOverwrite: boolean = false, customOutputPath?: string) => {
    if (!carrierPath) return;
    setErrorMessage(null);
    setResult(null);

    const payloadDto: PayloadInputDto =
      payloadType === "text"
        ? { kind: "text", content: textContent }
        : { kind: "file", path: payloadFilePath || "" };

    if (payloadType === "file" && !payloadFilePath) {
      setErrorMessage("请先选择要隐藏的文件载荷");
      return;
    }
    if (payloadType === "text" && !textContent.trim()) {
      setErrorMessage("请输入要隐藏的秘密文本内容");
      return;
    }

    const taskId = `embed-${Date.now()}`;
    startTask(taskId, "正在执行数据隐藏/自适应嵌入...");

    try {
      if (domain === "structure") {
        const res = await writeStructureFile(
          taskId,
          {
            carrier: carrierPath,
            payload: payloadDto,
            output_path: customOutputPath,
            password: password || undefined,
            password_hint: !stealth && passwordHint ? passwordHint : undefined,
            strategy: selectedStrategy !== "auto" ? selectedStrategy : undefined,
            stealth,
            preserve_time: preserveTime,
            backup,
            overwrite: forcedOverwrite,
          },
          updateProgress,
        );

        setResult({
          writtenTo: res.carrier,
          beforeBytes: inspection?.orig_host_size || 0,
          afterBytes: res.raw_size + res.ube_size,
          warnings: res.warnings.map((w) =>
            w.kind === "size_inflation"
              ? `信封膨胀率超标: ${w.ratio_pct.toFixed(1)}%`
              : "检出疑似重叠信封",
          ),
        });
      } else {
        const res = await embedStegoFile(
          taskId,
          {
            carrier: carrierPath,
            payload: payloadDto,
            output_path: customOutputPath,
            password: password || undefined,
            safety_level: safetyLevel,
            enforce_safety: enforceSafety,
            algorithm: selectedAlgorithm !== "auto" ? selectedAlgorithm : undefined,
            backup,
            overwrite: forcedOverwrite,
          },
          updateProgress,
        );

        setResult({
          writtenTo: res.written_to,
          beforeBytes: res.carrier_before_bytes,
          afterBytes: res.carrier_after_bytes,
          stats: res.stats,
          warnings: res.warnings.map(
            (w) => `超出安全上限: ${formatBytes(w.payload_bytes)} > ${formatBytes(w.recommended_max_bytes)}`,
          ),
        });
      }
    } catch (err) {
      const parsed = parseStrHideError(err);
      if (parsed.isAlreadyExists) {
        setConflictTarget(customOutputPath || carrierPath);
      } else {
        setErrorMessage(parsed.message);
      }
    } finally {
      finishTask();
    }
  };

  const handleSaveAs = async () => {
    try {
      const defaultName = carrierPath?.split(/[/\\]/).pop() || "stego_output";
      const target = await save({
        defaultPath: defaultName,
        title: "另存隐写产物为新文件",
      });
      if (target && typeof target === "string") {
        setConflictTarget(null);
        handleStartHide(true, target);
      }
    } catch (err) {
      console.error("Save as error:", err);
    }
  };

  if (!carrierPath) {
    return (
      <div className="flex h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 text-center text-slate-500">
        <Shield className="h-8 w-8 text-slate-600 mb-2" />
        <p className="text-sm font-medium">请先在上方拖入或选择载体文件</p>
      </div>
    );
  }

  // If carrier format itself is completely unsupported (neither structure nor stego available)
  if (inspectError || (!supportsStructure && !fileSupportsStego)) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-rose-800/80 bg-rose-950/20 p-8 text-center text-rose-300 space-y-3">
        <AlertTriangle className="h-10 w-10 text-rose-400" />
        <div>
          <h3 className="text-base font-bold text-rose-200">当前载体格式不支持隐藏写入</h3>
          <p className="mt-1 text-xs text-slate-400 max-w-md mx-auto">
            {inspectError?.detail || "该文件格式既不支持结构域注入，也不支持内容域自适应隐写。请更换支持的载体文件（如 PNG, JPEG, MP4/HEVC, HEIF, ZIP, PDF, PE 等）。"}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Domain Switcher */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 shadow-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="font-semibold text-slate-200 text-sm">隐藏技术域选择</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            根据载体格式特性智能分配最优隐藏通道
          </p>
        </div>

        <div className="flex items-center gap-2 rounded-xl bg-slate-950 p-1 border border-slate-800">
          <button
            type="button"
            disabled={!fileSupportsStego}
            onClick={() => setDomain("content")}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
              domain === "content"
                ? "bg-indigo-600 text-white shadow-md"
                : fileSupportsStego
                ? "text-slate-400 hover:text-slate-200"
                : "text-slate-500 cursor-not-allowed opacity-50 bg-slate-950/40"
            }`}
            title={contentError ? contentError.detail : undefined}
          >
            <Sparkles className="h-4 w-4" />
            内容域自适应隐写 {!fileSupportsStego ? "(此载体不支持)" : "(抗统计分析)"}
          </button>
          <button
            type="button"
            disabled={!supportsStructure}
            onClick={() => setDomain("structure")}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
              domain === "structure"
                ? "bg-cyan-600 text-white shadow-md"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Layers className="h-4 w-4" />
            结构域容器注入 (支持 100% 还原)
          </button>
        </div>
      </div>

      {/* Payload Input Block */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h4 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
            <FileText className="h-4 w-4 text-cyan-400" />
            秘密载荷输入 (Payload)
          </h4>

          {/* Type switcher */}
          <div className="flex rounded-lg bg-slate-950 p-0.5 border border-slate-800 text-xs">
            <button
              onClick={() => setPayloadType("text")}
              className={`rounded-md px-3 py-1 font-medium transition-colors ${
                payloadType === "text" ? "bg-slate-800 text-cyan-300" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              文本载荷
            </button>
            <button
              onClick={() => setPayloadType("file")}
              className={`rounded-md px-3 py-1 font-medium transition-colors ${
                payloadType === "file" ? "bg-slate-800 text-cyan-300" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              本地文件
            </button>
          </div>
        </div>

        {payloadType === "text" ? (
          <div>
            <textarea
              rows={4}
              placeholder="在此输入需要隐藏的秘密明文信息（自动统计 UTF-8 字节数）..."
              value={textContent}
              onChange={(e) => setTextContent(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 p-3 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none font-mono"
            />
            <div className="mt-1 flex justify-between text-[11px] text-slate-400 font-mono">
              <span>UTF-8 字节数: {payloadBytes} B</span>
              <span>字符数: {textContent.length}</span>
            </div>
          </div>
        ) : (
          <div>
            <div
              onClick={handlePickPayloadFile}
              className="cursor-pointer rounded-xl border border-dashed border-slate-700 bg-slate-950/60 p-5 text-center hover:border-cyan-500 hover:bg-slate-950"
            >
              <Upload className="h-6 w-6 text-slate-400 mx-auto mb-2" />
              <div className="text-xs font-semibold text-slate-200">
                {payloadFilePath ? (
                  <span className="text-cyan-400 font-mono break-all">{payloadFilePath}</span>
                ) : (
                  "点击选择要隐藏的本地文件（任意格式）"
                )}
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                Rust 后端按需流式读取，零 IPC 内存传输开销
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Unsupported Content Stego Alert Banner */}
      {domain === "content" && (contentError || probeError) && (
        <div className="rounded-2xl border border-amber-800/80 bg-amber-950/40 p-5 text-xs text-amber-200 shadow-xl space-y-3 animate-in fade-in">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-bold text-sm text-amber-300">
                当前载体不支持内容域自适应隐写
              </h4>
              <p className="mt-1 leading-relaxed text-slate-300 font-mono">
                {contentError?.detail || probeError || "该视频文件不包含支持的 HEVC (H.265) 视频流（如 H.264/AVC 编码暂不支持 CABAC 隐写）。"}
              </p>
            </div>
          </div>

          {supportsStructure && (
            <div className="pt-1 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => setDomain("structure")}
                className="inline-flex items-center gap-1.5 rounded-xl bg-cyan-700 hover:bg-cyan-600 px-4 py-2 font-bold text-white text-xs shadow-md transition-all active:scale-95"
              >
                <Layers className="h-4 w-4" />
                一键切换至【结构域容器注入】(支持 100% 无损还原)
              </button>
              <span className="text-slate-400">结构域支持所有 MP4 容器直接封装</span>
            </div>
          )}
        </div>
      )}

      {/* Capacity Meter (Content domain only) */}
      {domain === "content" && !contentError && !probeError && (
        <CapacityMeter
          capacity={capacity}
          payloadBytes={payloadBytes}
          selectedSafety={safetyLevel}
          onSelectSafety={setSafetyLevel}
          enforceSafety={enforceSafety}
          onToggleEnforceSafety={setEnforceSafety}
          isLoading={isProbing}
        />
      )}

      {/* Security Credentials Bar */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-3">
        <h4 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
          <Lock className="h-4 w-4 text-cyan-400" />
          加密密钥与密码提示
        </h4>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="block text-xs text-slate-400 mb-1">加密密码 (Password - 可选)</label>
            <input
              type="password"
              placeholder="留空则采用部署私有 Dialect 密钥..."
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {domain === "structure" && !stealth && (
            <div>
              <label className="block text-xs text-slate-400 mb-1">密码提示 (Password Hint - 可选)</label>
              <input
                type="text"
                placeholder="例如: 生日年份 / 常用绰号..."
                value={passwordHint}
                onChange={(e) => setPasswordHint(e.target.value)}
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>
          )}
        </div>
      </div>

      {/* Advanced Tuning Toggle */}
      <div>
        <button
          type="button"
          onClick={() => setShowTuning(!showTuning)}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-400 hover:underline"
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          {showTuning ? "收起高级参数设置" : "展开高级参数设置 (策略选择 / 隐身模式 / 备份)"}
        </button>

        {showTuning && (
          <div className="mt-3">
            <TuningDrawer
              domain={domain}
              carrierFormat={format}
              strategies={inspection?.strategies || []}
              selectedStrategy={selectedStrategy}
              onSelectStrategy={setSelectedStrategy}
              selectedAlgorithm={selectedAlgorithm}
              onSelectAlgorithm={setSelectedAlgorithm}
              stealth={stealth}
              onToggleStealth={setStealth}
              backup={backup}
              onToggleBackup={setBackup}
              preserveTime={preserveTime}
              onTogglePreserveTime={setPreserveTime}
              hasPassword={password.length > 0}
            />
          </div>
        )}
      </div>

      {/* Execute Button */}
      <div className="flex items-center justify-between gap-4 pt-2">
        <button
          onClick={() => handleSaveAs()}
          className="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white"
        >
          另存为新文件...
        </button>

        <button
          onClick={() => handleStartHide(false)}
          disabled={domain === "content" && (!capacity || !!probeError || !fileSupportsStego)}
          className={`inline-flex items-center gap-2 rounded-xl px-6 py-2.5 text-xs font-bold text-white shadow-xl transition-all active:scale-95 ${
            domain === "content" && (!capacity || !!probeError || !fileSupportsStego)
              ? "bg-slate-800 text-slate-500 cursor-not-allowed shadow-none"
              : "bg-gradient-to-r from-cyan-600 to-blue-700 shadow-cyan-950/60 hover:brightness-110"
          }`}
          title={
            domain === "content" && (!capacity || !!probeError || !fileSupportsStego)
              ? "当前载体不支持内容域隐写，请切换至结构域容器注入"
              : undefined
          }
        >
          <span>开始隐藏 / 嵌入</span>
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>

      {errorMessage && (
        <div className="rounded-xl border border-rose-800/80 bg-rose-950/50 p-4 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Embed Result Feedback Card */}
      {result && (
        <div className="rounded-2xl border border-emerald-800/80 bg-emerald-950/20 p-5 shadow-2xl animate-in fade-in duration-200 space-y-3">
          <div className="flex items-center justify-between border-b border-emerald-800/40 pb-3">
            <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
              <CheckCircle2 className="h-5 w-5" />
              <span>数据隐藏写入成功！</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => openCarrier(result.writtenTo)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                打开文件
              </button>
              <button
                onClick={() => revealCarrier(result.writtenTo)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700"
              >
                <FolderOpen className="h-3.5 w-3.5 text-cyan-400" />
                定位目录
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 text-xs">
            <div>
              <span className="text-slate-400">产物路径: </span>
              <p className="font-mono text-slate-200 truncate mt-0.5" title={result.writtenTo}>
                {result.writtenTo}
              </p>
            </div>
            <div>
              <span className="text-slate-400">体积变化: </span>
              <p className="font-mono text-slate-200 mt-0.5">
                {formatBytes(result.beforeBytes)} → {formatBytes(result.afterBytes)} (
                {result.afterBytes >= result.beforeBytes ? "+" : ""}
                {formatBytes(result.afterBytes - result.beforeBytes)})
              </p>
            </div>
            {result.stats && (
              <div>
                <span className="text-slate-400">精确修改率 (EmbedStats): </span>
                <p className="font-mono text-cyan-300 font-bold mt-0.5">
                  已微调 {result.stats.modified_slots.toLocaleString()} /{" "}
                  {result.stats.total_candidate_slots.toLocaleString()} 槽位 (
                  {((result.stats.modified_slots / result.stats.total_candidate_slots) * 100).toFixed(3)}
                  %)
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Overwrite Dialog Modal */}
      {conflictTarget && (
        <OverwriteDialog
          targetPath={conflictTarget}
          onConfirmOverwrite={() => {
            const target = conflictTarget;
            setConflictTarget(null);
            handleStartHide(true, target);
          }}
          onSaveAs={() => {
            setConflictTarget(null);
            handleSaveAs();
          }}
          onCancel={() => setConflictTarget(null)}
        />
      )}
    </div>
  );
};
