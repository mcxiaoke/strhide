import React, { useState } from "react";
import { Play, TriangleAlert } from "lucide-react";
import { useCapabilities } from "../hooks/useCapabilities";
import { useFileQueue } from "../hooks/useFileQueue";
import { useFileDrop } from "../hooks/useFileDrop";
import { useT } from "../hooks/useT";
import { useTaskStore } from "../store/taskStore";
import { inspectCarrier } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { formatBytes } from "../lib/format";
import { fmt } from "../lib/i18n";
import { FileQueue } from "../components/common/FileQueue";
import type { DualInspect } from "../types/strhide";

interface ScanRow {
  format: string | null;
  canEmbed: boolean;
  canAppend: boolean;
  capacityBytes?: number;
  appended: boolean;
  embedded: boolean;
  encrypted: boolean;
  payloadBytes?: number;
}

function toRow(info: DualInspect): ScanRow {
  const appended = !!info.has_hidden_data;
  const embedded = !!info.content_stego?.has_hidden_data;

  const capacities = (info.strategies ?? [])
    .filter((s) => s.available && s.capacity_bytes !== null)
    .map((s) => s.capacity_bytes as number);

  const payloadBytes =
    (info.content_stego?.payload_len ?? undefined) ||
    (typeof info.metadata === "object" && info.metadata && "raw_size" in info.metadata
      ? info.metadata.raw_size
      : undefined) ||
    (info.ube_total_size ?? undefined);

  return {
    format: info.format ?? null,
    canEmbed: !!info.content_stego,
    canAppend: (info.strategies?.length ?? 0) > 0,
    capacityBytes: capacities.length > 0 ? Math.max(...capacities) : undefined,
    appended,
    embedded,
    encrypted: !!info.is_encrypted,
    payloadBytes,
  };
}

export const ScanView: React.FC<{ active: boolean }> = ({ active }) => {
  const c = useT();
  const capabilities = useCapabilities();
  const queue = useFileQueue("any", capabilities);
  const { startTask, finishTask } = useTaskStore();

  const [rows, setRows] = useState<Record<string, ScanRow>>({});
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useFileDrop(active, queue.addPaths);

  const hiddenText = (row: ScanRow) => {
    if (row.appended && row.embedded) return c.scan.hiddenBoth;
    if (row.appended) return c.scan.writeAppend;
    if (row.embedded) return c.scan.writeEmbed;
    return c.scan.no;
  };

  const run = async () => {
    const targets = queue.items.filter((item) => item.supported);
    if (targets.length === 0) {
      setError(c.scan.emptyError);
      return;
    }

    setError(null);
    setRunning(true);
    setRows({});
    queue.resetStatus();

    try {
      for (let i = 0; i < targets.length; i += 1) {
        const item = targets[i];
        const taskId = `scan-${Date.now()}-${i}`;
        startTask(taskId, fmt(c.scan.progress, { i: i + 1, n: targets.length, name: item.name }));
        queue.update(item.path, { status: "running", message: c.scan.reading, outputPath: undefined });

        try {
          const info = await inspectCarrier(item.path);
          const row = toRow(info);
          setRows((prev) => ({ ...prev, [item.path]: row }));
          queue.update(item.path, {
            status: "ok",
            capacityBytes: row.capacityBytes,
            message: undefined,
          });
        } catch (err) {
          queue.update(item.path, { status: "error", message: parseStrHideError(err).message });
        }
      }
    } finally {
      finishTask();
      setRunning(false);
    }
  };

  const scanned = queue.items.filter((item) => rows[item.path]);

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">{c.scan.desc}</p>

      <FileQueue api={queue} disabled={running} hint={c.scan.fileHint} />

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-800/80 bg-rose-950/40 px-3 py-2 text-xs text-rose-300">
          <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[11px] text-slate-500">{c.scan.footnote}</p>
        <button
          type="button"
          onClick={run}
          disabled={running || queue.items.length === 0}
          className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-700 px-4 py-2 text-xs font-semibold text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Play className="h-3.5 w-3.5" />
          {c.scan.start}
        </button>
      </div>

      {scanned.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-900/60 text-[11px] text-slate-400">
              <tr>
                <th className="p-2.5 font-medium">{c.scan.colFile}</th>
                <th className="p-2.5 font-medium">{c.scan.colFormat}</th>
                <th className="p-2.5 font-medium">{c.scan.colWrite}</th>
                <th className="p-2.5 font-medium">{c.scan.colHidden}</th>
                <th className="p-2.5 font-medium">{c.scan.colEncrypted}</th>
                <th className="p-2.5 font-medium">{c.scan.colSize}</th>
                <th className="p-2.5 font-medium">{c.scan.colCapacity}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scanned.map((item) => {
                const row = rows[item.path];
                const hasHidden = row.appended || row.embedded;
                return (
                  <tr key={item.path}>
                    <td className="max-w-[16rem] truncate p-2.5 text-slate-200" title={item.path}>
                      {item.name}
                    </td>
                    <td className="p-2.5 font-mono text-slate-300">{row.format ?? "--"}</td>
                    <td className="space-x-1 p-2.5">
                      {row.canEmbed && (
                        <span className="rounded bg-indigo-950 px-1.5 py-0.5 text-[11px] text-indigo-300">
                          {c.scan.writeEmbed}
                        </span>
                      )}
                      {row.canAppend && (
                        <span className="rounded bg-cyan-950 px-1.5 py-0.5 text-[11px] text-cyan-300">
                          {c.scan.writeAppend}
                        </span>
                      )}
                      {!row.canEmbed && !row.canAppend && <span className="text-slate-500">{c.scan.writeNone}</span>}
                    </td>
                    <td className={`p-2.5 ${hasHidden ? "text-emerald-400" : "text-slate-400"}`}>
                      {hiddenText(row)}
                    </td>
                    <td className="p-2.5 text-slate-300">{row.encrypted ? c.scan.yes : c.scan.no}</td>
                    <td className="p-2.5 font-mono text-slate-300">{formatBytes(row.payloadBytes)}</td>
                    <td className="p-2.5 font-mono text-slate-400">{formatBytes(row.capacityBytes)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
