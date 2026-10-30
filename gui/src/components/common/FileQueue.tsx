import React from "react";
import { ExternalLink, FolderOpen, Files, Plus, Trash2, X } from "lucide-react";
import type { FileQueueApi } from "../../hooks/useFileQueue";
import { useT } from "../../hooks/useT";
import { fmt } from "../../lib/i18n";
import { formatBytes } from "../../lib/format";
import { openCarrier } from "../../lib/openActions";
import { StatusPill } from "./StatusPill";

interface FileQueueProps {
  api: FileQueueApi;
  hint?: string;
  disabled?: boolean;
  showCapacity?: boolean;
}

export const FileQueue: React.FC<FileQueueProps> = ({ api, hint, disabled, showCapacity }) => {
  const c = useT();
  const { items, skipped, pick, remove, clear, dismissSkipped } = api;
  const done = items.filter((it) => it.status === "ok").length;
  const failed = items.filter((it) => it.status === "error" || it.status === "skip").length;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-3 py-2">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Files className="h-4 w-4 text-cyan-400" />
          <span className="text-slate-300">
            {items.length > 0 ? fmt(c.common.files, { n: items.length }) : c.common.filesLabel}
          </span>
          {done > 0 && <span className="text-emerald-400">{fmt(c.common.doneCount, { n: done })}</span>}
          {failed > 0 && <span className="text-rose-400">{fmt(c.common.problemCount, { n: failed })}</span>}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={pick}
            disabled={disabled}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            {c.common.addFiles}
          </button>
          {items.length > 0 && (
            <button
              type="button"
              onClick={clear}
              disabled={disabled}
              className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs text-slate-400 hover:bg-rose-950/60 hover:text-rose-300 disabled:opacity-50"
            >
              <Trash2 className="h-3.5 w-3.5" />
              {c.common.clear}
            </button>
          )}
        </div>
      </div>

      {skipped.length > 0 && (
        <div className="flex items-start gap-2 border-b border-amber-800/50 bg-amber-950/30 px-3 py-2 text-[11px] text-amber-200">
          <span className="flex-1 leading-relaxed">
            {fmt(c.common.skipped, { n: skipped.length })}
            {skipped
              .map((item) =>
                fmt(c.common.skipItem, { name: item.name, reason: c.common.reasons[item.reason] }),
              )
              .join(c.common.listSeparator)}
          </span>
          <button type="button" onClick={dismissSkipped} className="shrink-0 text-amber-400 hover:text-amber-200">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {items.length === 0 ? (
        <button
          type="button"
          onClick={pick}
          disabled={disabled}
          className="flex w-full flex-col items-center gap-1 px-4 py-8 text-center text-xs text-slate-400 hover:bg-slate-800/40 disabled:opacity-50"
        >
          <FolderOpen className="h-5 w-5 text-slate-500" />
          <span className="text-slate-300">{c.common.empty}</span>
          {hint && <span className="text-[11px] text-slate-500">{hint}</span>}
        </button>
      ) : (
        <ul className="max-h-56 divide-y divide-slate-800/60 overflow-y-auto">
          {items.map((item) => (
            <li key={item.path} className="px-3 py-1.5 text-xs">
              <div className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate text-slate-200" title={item.path}>
                  {item.name}
                </span>
                <span className="w-16 shrink-0 text-right font-mono text-[11px] text-slate-500">
                  {formatBytes(item.size)}
                </span>
                {showCapacity && item.capacityBytes !== undefined && (
                  <span className="w-28 shrink-0 text-right font-mono text-[11px] text-slate-500">
                    {fmt(c.common.capacity, { size: formatBytes(item.capacityBytes) })}
                  </span>
                )}
                <StatusPill status={item.status} />
                {item.outputPath && (
                  <button
                    type="button"
                    onClick={() => openCarrier(item.outputPath!)}
                    title={c.common.open}
                    className="shrink-0 text-slate-500 hover:text-cyan-300"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => remove(item.path)}
                  disabled={disabled}
                  title={c.common.remove}
                  className="shrink-0 text-slate-500 hover:text-rose-400 disabled:opacity-40"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
              {(() => {
                const note = item.message ?? (item.reason ? c.common.reasons[item.reason] : undefined);
                if (!note || item.status === "idle") return null;
                return (
                  <p className="mt-0.5 truncate pl-0.5 text-[11px] text-slate-400" title={note}>
                    {note}
                  </p>
                );
              })()}
              {item.outputPath && (
                <p className="mt-0.5 truncate pl-0.5 font-mono text-[11px] text-slate-500" title={item.outputPath}>
                  → {item.outputPath}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};
