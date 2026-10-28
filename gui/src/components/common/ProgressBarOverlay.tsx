import React from "react";
import { Loader2, XCircle } from "lucide-react";
import { useTaskStore } from "../../store/taskStore";

export const ProgressBarOverlay: React.FC = () => {
  const { isRunning, statusText, progress, cancelActiveTask } = useTaskStore();

  if (!isRunning) return null;

  const percent = progress?.percent ?? null;
  const stage = progress?.stage ?? "processing";

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 w-full max-w-xl px-4 animate-in fade-in slide-in-from-bottom-4 duration-200">
      <div className="rounded-2xl border border-cyan-800/80 bg-slate-900/95 p-4 shadow-2xl shadow-cyan-950/60 backdrop-blur-xl">
        <div className="flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-cyan-400 font-medium">
            <Loader2 className="h-4 w-4 animate-spin shrink-0" />
            <span className="capitalize font-mono font-bold">[{stage}]</span>
            <span className="truncate text-slate-200 font-normal">{statusText}</span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {percent !== null && (
              <span className="font-mono font-bold text-cyan-300">{percent.toFixed(1)}%</span>
            )}
            <button
              onClick={cancelActiveTask}
              className="inline-flex items-center gap-1 rounded-lg bg-rose-950/80 px-2.5 py-1 text-xs font-semibold text-rose-300 border border-rose-800/60 transition-colors hover:bg-rose-900 hover:text-white"
            >
              <XCircle className="h-3.5 w-3.5" />
              取消
            </button>
          </div>
        </div>

        {/* Progress bar track */}
        <div className="mt-2.5 h-2 w-full overflow-hidden rounded-full bg-slate-800">
          {percent !== null ? (
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-150 ease-out"
              style={{ width: `${percent}%` }}
            />
          ) : (
            <div className="h-full w-1/3 bg-cyan-500 animate-pulse" />
          )}
        </div>
      </div>
    </div>
  );
};
