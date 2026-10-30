import React from "react";
import { Loader2, XCircle } from "lucide-react";
import { useTaskStore } from "../../store/taskStore";
import { useT } from "../../hooks/useT";
import { progressStageLabel } from "../../lib/i18n";

export const ProgressBarOverlay: React.FC = () => {
  const c = useT();
  const { isRunning, statusText, progress, cancelActiveTask } = useTaskStore();

  if (!isRunning) return null;

  const percent = progress?.percent ?? null;
  const stage = progress?.stage ?? "";

  return (
    <div className="fixed bottom-4 left-1/2 z-50 w-full max-w-xl -translate-x-1/2 px-4 duration-200 animate-in fade-in slide-in-from-bottom-4">
      <div className="rounded-xl border border-cyan-800/80 bg-slate-900/95 p-3 shadow-2xl shadow-cyan-950/60 backdrop-blur-xl">
        <div className="flex items-center justify-between gap-3 text-xs">
          <div className="flex min-w-0 items-center gap-2 text-slate-200">
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-cyan-400" />
            {stage && <span className="shrink-0 text-cyan-300">{progressStageLabel(c, stage)}</span>}
            <span className="truncate">{statusText}</span>
          </div>

          <div className="flex shrink-0 items-center gap-3">
            {percent !== null && <span className="font-mono text-cyan-300">{percent.toFixed(0)}%</span>}
            <button
              type="button"
              onClick={cancelActiveTask}
              className="inline-flex items-center gap-1 rounded-lg border border-rose-800/60 bg-rose-950/80 px-2.5 py-1 text-xs font-medium text-rose-300 hover:bg-rose-900 hover:text-white"
            >
              <XCircle className="h-3.5 w-3.5" />
              {c.common.cancel}
            </button>
          </div>
        </div>

        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          {percent !== null ? (
            <div
              className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-150 ease-out"
              style={{ width: `${percent}%` }}
            />
          ) : (
            <div className="h-full w-1/3 animate-pulse bg-cyan-500" />
          )}
        </div>
      </div>
    </div>
  );
};
