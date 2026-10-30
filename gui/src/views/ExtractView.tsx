import React, { useState } from "react";
import { Copy, Play, TriangleAlert } from "lucide-react";
import { useCapabilities } from "../hooks/useCapabilities";
import { useFileQueue } from "../hooks/useFileQueue";
import { useFileDrop } from "../hooks/useFileDrop";
import { useT } from "../hooks/useT";
import { useOutputDir } from "../hooks/useOutputDir";
import { useTaskStore } from "../store/taskStore";
import { smartExtract } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { baseName, formatBytes, withSuffix } from "../lib/format";
import { fmt } from "../lib/i18n";
import { uniqueOutputPath } from "../lib/queue";
import { FileQueue } from "../components/common/FileQueue";
import { PasswordRow } from "../components/common/PasswordRow";
import { DirRow } from "../components/common/DirRow";

interface TextResult {
  carrier: string;
  filename: string;
  text: string;
}

export const ExtractView: React.FC<{ active: boolean }> = ({ active }) => {
  const c = useT();
  const capabilities = useCapabilities();
  const queue = useFileQueue("any", capabilities);
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [password, setPassword] = useState("");
  const [outputDir, setOutputDir] = useOutputDir();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [textResults, setTextResults] = useState<TextResult[]>([]);

  useFileDrop(active, queue.addPaths);

  const sourceLabel = (domain: string) =>
    domain === "content" ? c.extract.fromContent : c.extract.fromStructure;

  const run = async () => {
    const targets = queue.items.filter((item) => item.supported);
    if (targets.length === 0) {
      setError(c.extract.emptyError);
      return;
    }

    setError(null);
    setRunning(true);
    setTextResults([]);
    queue.resetStatus();

    try {
      for (let i = 0; i < targets.length; i += 1) {
        const item = targets[i];
        const taskId = `extract-${Date.now()}-${i}`;
        startTask(taskId, fmt(c.extract.progress, { i: i + 1, n: targets.length, name: item.name }));
        queue.update(item.path, { status: "running", message: c.extract.reading, outputPath: undefined });

        try {
          const first = await smartExtract(
            taskId,
            item.path,
            undefined,
            password || undefined,
            undefined,
            undefined,
            false,
            updateProgress,
          );
          const summary = first.summary;
          const from = sourceLabel(first.source);
          const extra = first.also_present
            ? fmt(c.extract.alsoPresent, { from: sourceLabel(first.also_present) })
            : "";

          if (!summary.is_file && summary.text_preview) {
            setTextResults((prev) => [
              ...prev,
              { carrier: item.path, filename: summary.filename, text: summary.text_preview! },
            ]);
            queue.update(item.path, {
              status: "ok",
              message: fmt(c.extract.textDone, { from, size: formatBytes(summary.raw_size) }) + extra,
            });
            continue;
          }

          const target = await uniqueOutputPath(
            outputDir || item.dir,
            summary.filename || withSuffix(item.name, "_payload"),
          );
          const saved = await smartExtract(
            taskId,
            item.path,
            target,
            password || undefined,
            undefined,
            first.source,
            false,
            updateProgress,
          );
          queue.update(item.path, {
            status: "ok",
            message: fmt(c.extract.fileDone, { from, size: formatBytes(summary.raw_size) }) + extra,
            outputPath: saved.summary.written_file ?? target,
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

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">{c.extract.desc}</p>

      <FileQueue api={queue} disabled={running} hint={c.extract.fileHint} />

      <div className="space-y-2.5 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <PasswordRow
          value={password}
          onChange={setPassword}
          placeholder={c.extract.passwordPlaceholder}
          disabled={running}
        />
        <DirRow value={outputDir} onChange={setOutputDir} disabled={running} />
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-800/80 bg-rose-950/40 px-3 py-2 text-xs text-rose-300">
          <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[11px] text-slate-500">{c.extract.footnote}</p>
        <button
          type="button"
          onClick={run}
          disabled={running || queue.items.length === 0}
          className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-700 px-4 py-2 text-xs font-semibold text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Play className="h-3.5 w-3.5" />
          {c.extract.start}
        </button>
      </div>

      {textResults.length > 0 && (
        <div className="space-y-2">
          {textResults.map((res) => (
            <div key={res.carrier} className="rounded-xl border border-slate-800 bg-slate-900/60">
              <div className="flex items-center justify-between gap-3 border-b border-slate-800 px-3 py-2 text-xs">
                <span className="min-w-0 truncate text-slate-300" title={res.carrier}>
                  <span className="text-slate-400">{baseName(res.carrier)}</span>
                  <span className="px-1 text-slate-500">→</span>
                  {res.filename}
                </span>
                <button
                  type="button"
                  onClick={() => navigator.clipboard.writeText(res.text)}
                  className="inline-flex shrink-0 items-center gap-1 text-slate-400 hover:text-cyan-300"
                >
                  <Copy className="h-3.5 w-3.5" />
                  {c.common.copy}
                </button>
              </div>
              <pre
                style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}
                className="max-h-56 overflow-y-auto p-3 font-mono text-xs leading-relaxed text-slate-200"
              >
                {res.text}
              </pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
