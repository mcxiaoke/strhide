import React from "react";
import {
  FileText,
  FolderOpen,
  ExternalLink,
  RefreshCw,
  X,
  Clock,
  Film,
  Maximize2,
  HardDrive,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";
import { openCarrier, revealCarrier } from "../../lib/openActions";

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null) return "--";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(ms?: number): string {
  if (!ms) return "";
  const totalSec = Math.floor(ms / 1000);
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  return `${min}:${sec.toString().padStart(2, "0")}`;
}

export const CarrierSummary: React.FC = () => {
  const { carrierPath, inspection, isInspecting, inspectCurrentCarrier, clearCarrier } =
    useWorkspaceStore();

  if (!carrierPath) return null;

  const fileName = carrierPath.split(/[/\\]/).pop() || carrierPath;
  const format = inspection?.format || "检测中...";
  const mediaInfo = inspection?.media_info || inspection?.content_stego?.media_info;

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-5 shadow-xl shadow-black/40 backdrop-blur-md">
      <div className="flex flex-wrap items-start justify-between gap-4">
        {/* Left info */}
        <div className="flex items-start gap-3.5">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-cyan-950/70 text-cyan-400 border border-cyan-800/40">
            <FileText className="h-6 w-6" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-base font-bold text-slate-100 tracking-tight">{fileName}</h2>
              <span className="rounded-md bg-cyan-900/40 px-2 py-0.5 text-xs font-semibold text-cyan-300 border border-cyan-700/50 uppercase">
                {format}
              </span>
              {inspection?.orig_host_size && (
                <span className="rounded-md bg-emerald-950/40 px-2 py-0.5 text-xs font-medium text-emerald-400 border border-emerald-800/50">
                  原载体: {formatBytes(inspection.orig_host_size)}
                </span>
              )}
            </div>
            <p className="mt-1 text-xs text-slate-400 font-mono break-all max-w-2xl">{carrierPath}</p>

            {/* Media Metadata Tags */}
            {mediaInfo && (
              <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs text-slate-300">
                {mediaInfo.width > 0 && mediaInfo.height > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/90 px-2 py-0.5 border border-slate-700/50">
                    <Maximize2 className="h-3 w-3 text-cyan-400" />
                    {mediaInfo.width} × {mediaInfo.height}
                  </span>
                )}
                {mediaInfo.duration_ms && mediaInfo.duration_ms > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/90 px-2 py-0.5 border border-slate-700/50">
                    <Clock className="h-3 w-3 text-amber-400" />
                    {formatDuration(mediaInfo.duration_ms)}
                  </span>
                )}
                {mediaInfo.fps && mediaInfo.fps > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/90 px-2 py-0.5 border border-slate-700/50">
                    <Film className="h-3 w-3 text-indigo-400" />
                    {mediaInfo.fps.toFixed(1)} fps
                  </span>
                )}
                {mediaInfo.bitrate_bps && mediaInfo.bitrate_bps > 0 && (
                  <span className="inline-flex items-center gap-1 rounded bg-slate-800/90 px-2 py-0.5 border border-slate-700/50">
                    <HardDrive className="h-3 w-3 text-purple-400" />
                    {(mediaInfo.bitrate_bps / 1_000_000).toFixed(2)} Mbps
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right actions */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => openCarrier(carrierPath)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-700 hover:text-white"
            title="调用系统默认软件打开文件"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            打开文件
          </button>
          <button
            onClick={() => revealCarrier(carrierPath)}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-700 hover:text-white"
            title="在系统文件管理器中定位"
          >
            <FolderOpen className="h-3.5 w-3.5" />
            定位目录
          </button>
          <button
            onClick={() => inspectCurrentCarrier()}
            disabled={isInspecting}
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-700 hover:text-white disabled:opacity-50"
            title="重新执行流式双域检视"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isInspecting ? "animate-spin text-cyan-400" : ""}`} />
            重新检视
          </button>
          <button
            onClick={clearCarrier}
            className="inline-flex items-center justify-center rounded-lg bg-slate-800/60 p-1.5 text-slate-400 transition-colors hover:bg-rose-950/60 hover:text-rose-400"
            title="关闭当前载体"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
