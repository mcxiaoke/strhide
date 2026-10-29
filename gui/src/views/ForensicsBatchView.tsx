import React, { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Microscope,
  Play,
  RotateCw,
  Plus,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Sliders,
} from "lucide-react";
import { useWorkspaceStore } from "../store/workspaceStore";
import { useTaskStore } from "../store/taskStore";
import { scanCarrier, runBatchJob } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import type { ScanReport, BatchOutcome } from "../types/strhide";

function getVerdictBadge(verdict: string) {
  switch (verdict) {
    case "clean":
      return "bg-emerald-950 text-emerald-400 border-emerald-800";
    case "low":
      return "bg-cyan-950 text-cyan-400 border-cyan-800";
    case "suspicious":
      return "bg-amber-950 text-amber-400 border-amber-800";
    default:
      return "bg-rose-950 text-rose-400 border-rose-800";
  }
}

export const ForensicsBatchView: React.FC = () => {
  const { carrierPath } = useWorkspaceStore();
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [activeSubTab, setActiveSubTab] = useState<"scan" | "batch">("scan");

  // Single file scan state
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Batch queue state
  const [batchItems, setBatchItems] = useState<string[]>([]);
  const [batchType, setBatchType] = useState<"inspect" | "verify" | "scan" | "restore">("inspect");
  const [concurrency, setConcurrency] = useState(2);
  const [continueOnError, setContinueOnError] = useState(true);
  const [batchPassword, setBatchPassword] = useState("");
  const [batchOutcome, setBatchOutcome] = useState<BatchOutcome<unknown> | null>(null);

  const handleScanSingle = async () => {
    if (!carrierPath) return;
    setScanError(null);
    setIsScanning(true);
    const taskId = `scan-${Date.now()}`;
    startTask(taskId, "正在执行黑盒反隐写扫描...");

    try {
      const rep = await scanCarrier(carrierPath);
      setScanReport(rep);
    } catch (err) {
      const parsed = parseStrHideError(err);
      setScanError(parsed.message);
    } finally {
      setIsScanning(false);
      finishTask();
    }
  };

  const handleAddBatchFiles = async () => {
    try {
      const selected = await open({
        multiple: true,
        title: "批量选择待处理文件",
      });
      if (selected) {
        const items = Array.isArray(selected) ? selected : [selected];
        const unique = Array.from(new Set([...batchItems, ...items]));
        setBatchItems(unique);
      }
    } catch (err) {
      console.error("Batch pick error:", err);
    }
  };

  const handleStartBatch = async () => {
    if (batchItems.length === 0) return;
    setBatchOutcome(null);
    const taskId = `batch-${Date.now()}`;
    startTask(taskId, `正在批量执行 ${batchType} (${batchItems.length} 个文件)...`);

    try {
      const res = await runBatchJob(
        taskId,
        batchItems,
        {
          job_type: batchType,
          password: batchPassword || undefined,
          continue_on_error: continueOnError,
          max_concurrency: concurrency,
        },
        updateProgress,
      );
      setBatchOutcome(res as BatchOutcome<unknown>);
    } catch (err) {
      console.error("Batch execution error:", err);
    } finally {
      finishTask();
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-tabs header */}
      <div className="flex rounded-xl bg-slate-900 p-1 border border-slate-800 w-fit">
        <button
          onClick={() => setActiveSubTab("scan")}
          className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
            activeSubTab === "scan"
              ? "bg-slate-800 text-cyan-400 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Microscope className="h-4 w-4" />
          黑盒反隐写取证 (Steganalysis)
        </button>
        <button
          onClick={() => setActiveSubTab("batch")}
          className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
            activeSubTab === "batch"
              ? "bg-slate-800 text-cyan-400 shadow-sm"
              : "text-slate-400 hover:text-slate-200"
          }`}
        >
          <Sliders className="h-4 w-4" />
          多文件批处理队列 (Batch Queue)
        </button>
      </div>

      {/* Subtab 1: Single file Steganalysis */}
      {activeSubTab === "scan" && (
        <div className="space-y-6">
          {!carrierPath ? (
            <div className="flex h-64 flex-col items-center justify-center rounded-2xl border border-dashed border-slate-800 text-center text-slate-500">
              <Microscope className="h-8 w-8 text-slate-600 mb-2" />
              <p className="text-sm font-medium">请先在上方拖入或选择载体文件</p>
            </div>
          ) : (
            <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div>
                  <h3 className="font-semibold text-slate-200 text-sm flex items-center gap-2">
                    <Microscope className="h-4 w-4 text-purple-400" />
                    统计学特征与结构盲盒扫描
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    综合评估空间像素残差、DCT 高频系数分布与容器尾部异常附加特征
                  </p>
                </div>

                <button
                  onClick={handleScanSingle}
                  disabled={isScanning}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-purple-700 to-indigo-700 px-4 py-2 text-xs font-bold text-white shadow-md hover:brightness-110 active:scale-95 disabled:opacity-50"
                >
                  <RotateCw className={`h-3.5 w-3.5 ${isScanning ? "animate-spin" : ""}`} />
                  开始反隐写扫描
                </button>
              </div>

              {/* Scan Overview Gauges */}
              {scanReport && (
                <div className="space-y-5 animate-in fade-in duration-200">
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                    {/* Risk Score Circle */}
                    <div className="flex flex-col items-center justify-center rounded-2xl border border-slate-800 bg-slate-950/80 p-5 text-center">
                      <span className="text-xs text-slate-400 font-medium">隐写风险指数 (0..100)</span>
                      <div className="mt-2 text-4xl font-extrabold font-mono text-cyan-400 tracking-tight">
                        {scanReport.risk_score}
                      </div>
                      <span
                        className={`mt-2 rounded-full px-3 py-0.5 text-xs font-bold uppercase border ${getVerdictBadge(
                          scanReport.verdict,
                        )}`}
                      >
                        {scanReport.verdict}
                      </span>
                    </div>

                    {/* Verdict description */}
                    <div className="sm:col-span-2 rounded-2xl border border-slate-800 bg-slate-950/60 p-5 flex flex-col justify-center text-xs space-y-2">
                      <div className="text-slate-300 font-medium">综合研判结论:</div>
                      <p className="text-slate-400 leading-relaxed">
                        当前文件扫描得分为 <strong className="text-slate-100">{scanReport.risk_score}</strong>
                        。判定档位为 <strong className="text-cyan-300 font-mono">[{scanReport.verdict}]</strong>
                        。检出异常命中项: {scanReport.findings.length} 处。
                      </p>
                      {scanReport.notes.length > 0 && (
                        <div className="rounded-lg bg-amber-950/30 border border-amber-800/40 p-2.5 text-amber-200">
                          <span className="font-semibold">检测盲区提示: </span>
                          {scanReport.notes.join("; ")}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Detectors Matrix Table */}
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-300">
                      量化检测器执行明细 ({scanReport.detectors.length} 项)
                    </h4>
                    <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">
                      <table className="w-full text-left text-xs">
                        <thead className="border-b border-slate-800 bg-slate-900/60 text-slate-400 font-medium font-mono text-[11px]">
                          <tr>
                            <th className="p-3">检测器名称</th>
                            <th className="p-3">技术域</th>
                            <th className="p-3">判定状态</th>
                            <th className="p-3">测量值</th>
                            <th className="p-3">参考阈值</th>
                            <th className="p-3">诊断详情</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300 text-xs">
                          {scanReport.detectors.map((d, i) => (
                            <tr key={i} className="hover:bg-slate-900/40">
                              <td className="p-3 font-semibold text-slate-200">{d.name}</td>
                              <td className="p-3 text-slate-400">{d.domain}</td>
                              <td className="p-3">
                                <span
                                  className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                                    d.status === "PASS"
                                      ? "bg-emerald-950 text-emerald-400 border border-emerald-800/50"
                                      : "bg-rose-950 text-rose-400 border border-rose-800/50"
                                  }`}
                                >
                                  {d.status}
                                </span>
                              </td>
                              <td className="p-3 text-cyan-300">{d.metric}</td>
                              <td className="p-3 text-slate-500">{d.threshold || "--"}</td>
                              <td className="p-3 font-sans text-slate-400 max-w-xs truncate" title={d.detail}>
                                {d.detail}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {scanError && (
                <div className="rounded-xl border border-rose-800/80 bg-rose-950/50 p-4 text-xs text-rose-300 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                  <span>{scanError}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Subtab 2: Multi-file Batch Queue */}
      {activeSubTab === "batch" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h3 className="font-semibold text-slate-200 text-sm">多文件批处理队列 (Batch Queue)</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                并行或单线程安全排队处理多个载体，支持单错继续与中途取消
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleAddBatchFiles}
                className="inline-flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-800 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700"
              >
                <Plus className="h-3.5 w-3.5" />
                添加文件...
              </button>
              {batchItems.length > 0 && (
                <button
                  onClick={() => setBatchItems([])}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-slate-800/60 p-2 text-xs text-slate-400 hover:text-rose-400"
                  title="清空队列"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>

          {/* Batch Options */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">批量作业类型</label>
              <select
                value={batchType}
                onChange={(e) => setBatchType(e.target.value as any)}
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus:outline-none"
              >
                <option value="inspect">批量双域检视 (Inspect)</option>
                <option value="verify">批量完整性校验 (Verify)</option>
                <option value="scan">批量黑盒反隐写 (Scan)</option>
                <option value="restore">批量信封还原 (Restore)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">最大并发工作线程</label>
              <input
                type="number"
                min={1}
                max={8}
                value={concurrency}
                onChange={(e) => setConcurrency(Math.max(1, parseInt(e.target.value) || 1))}
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">密码 (若包含加密信封)</label>
              <input
                type="password"
                placeholder="统一密码..."
                value={batchPassword}
                onChange={(e) => setBatchPassword(e.target.value)}
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-slate-200 focus:outline-none"
              />
            </div>

            <div className="flex items-center pt-5">
              <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={continueOnError}
                  onChange={(e) => setContinueOnError(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
                />
                <span>单文件出错仍继续</span>
              </label>
            </div>
          </div>

          {/* Batch Files List */}
          {batchItems.length === 0 ? (
            <div className="flex h-36 flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 text-center text-xs text-slate-500">
              <p>队列为空，请点击上方“添加文件...”或拖入多文件</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-300">
                  队列列表: 共 {batchItems.length} 个文件
                </span>
                <button
                  onClick={handleStartBatch}
                  className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-700 px-5 py-2 text-xs font-bold text-white shadow-lg hover:brightness-110 active:scale-95"
                >
                  <Play className="h-3.5 w-3.5" />
                  执行批量任务
                </button>
              </div>

              <div className="max-h-60 overflow-y-auto rounded-xl border border-slate-800 bg-slate-950 p-2 space-y-1">
                {batchItems.map((item, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between rounded-lg bg-slate-900/60 px-3 py-1.5 text-xs text-slate-300 font-mono"
                  >
                    <span className="truncate max-w-lg">{item}</span>
                    <button
                      onClick={() => setBatchItems(batchItems.filter((_, i) => i !== idx))}
                      className="text-slate-500 hover:text-rose-400"
                    >
                      移除
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Batch Outcome Summary */}
          {batchOutcome && (
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-3 animate-in fade-in duration-200">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-xs font-semibold">
                <span className="text-slate-200">批量任务执行汇报:</span>
                <div className="flex items-center gap-3">
                  <span className="text-emerald-400">成功: {batchOutcome.succeeded}</span>
                  <span className="text-rose-400">失败: {batchOutcome.failed}</span>
                  {batchOutcome.cancelled && <span className="text-amber-400">(任务已中途取消)</span>}
                </div>
              </div>

              <div className="max-h-72 overflow-y-auto space-y-1.5">
                {batchOutcome.items.map((item, idx) => {
                  const isSuccess = "Ok" in item.result;
                  return (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-2 text-xs flex items-center justify-between gap-3 font-mono"
                    >
                      <div className="flex items-center gap-2 truncate">
                        {isSuccess ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                        ) : (
                          <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
                        )}
                        <span className="truncate text-slate-300">{item.item}</span>
                      </div>
                      <div className="shrink-0 flex items-center gap-3 text-slate-400 text-[11px]">
                        <span>{item.elapsed_ms} ms</span>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                            isSuccess ? "bg-emerald-950 text-emerald-400" : "bg-rose-950 text-rose-400"
                          }`}
                        >
                          {isSuccess ? "OK" : "ERROR"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
