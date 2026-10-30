import React, { useState } from "react";
import { Play, Settings2, TriangleAlert } from "lucide-react";
import { useCapabilities } from "../hooks/useCapabilities";
import { useFileQueue } from "../hooks/useFileQueue";
import { useFileDrop } from "../hooks/useFileDrop";
import { useT } from "../hooks/useT";
import { useOutputDir } from "../hooks/useOutputDir";
import { useTaskStore } from "../store/taskStore";
import { writeStructureFile } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { withSuffix } from "../lib/format";
import { fmt } from "../lib/i18n";
import { uniqueOutputPath } from "../lib/queue";
import { FileQueue } from "../components/common/FileQueue";
import { PasswordRow } from "../components/common/PasswordRow";
import { DirRow } from "../components/common/DirRow";
import { PayloadEditor, type PayloadKind } from "../components/common/PayloadEditor";
import type { PayloadInputDto } from "../types/strhide";

export const HideStructureView: React.FC<{ active: boolean }> = ({ active }) => {
  const c = useT();
  const capabilities = useCapabilities();
  const queue = useFileQueue("structure", capabilities);
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [payloadKind, setPayloadKind] = useState<PayloadKind>("text");
  const [text, setText] = useState("");
  const [payloadPath, setPayloadPath] = useState<string | null>(null);
  const [payloadSize, setPayloadSize] = useState<number | null>(null);

  const [password, setPassword] = useState("");
  const [passwordHint, setPasswordHint] = useState("");
  const [stealth, setStealth] = useState(false);
  const [outputDir, setOutputDir] = useOutputDir();
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useFileDrop(active, queue.addPaths);

  const payloadBytes =
    payloadKind === "text" ? new TextEncoder().encode(text).length : payloadSize ?? 0;

  const run = async () => {
    let payload: PayloadInputDto | null = null;
    if (payloadKind === "text") {
      payload = text ? { kind: "text", content: text } : null;
    } else {
      payload = payloadPath ? { kind: "file", path: payloadPath } : null;
    }
    if (!payload) {
      setError(payloadKind === "text" ? c.hide.textError : c.hide.fileError);
      return;
    }
    if (stealth && !password) {
      setError(c.hide.stealthError);
      return;
    }
    const targets = queue.items.filter((item) => item.supported);
    if (targets.length === 0) {
      setError(c.hide.emptyError);
      return;
    }

    setError(null);
    setRunning(true);
    queue.resetStatus();

    try {
      for (let i = 0; i < targets.length; i += 1) {
        const item = targets[i];
        const taskId = `hide-${Date.now()}-${i}`;
        startTask(taskId, fmt(c.hide.progress, { i: i + 1, n: targets.length, name: item.name }));
        queue.update(item.path, { status: "running", message: c.hide.working, outputPath: undefined });

        try {
          const target = await uniqueOutputPath(outputDir || item.dir, withSuffix(item.name, "_hidden"));
          const res = await writeStructureFile(
            taskId,
            {
              carrier: item.path,
              payload,
              output_path: target,
              password: password || undefined,
              password_hint: !stealth && password && passwordHint ? passwordHint : undefined,
              strategy: undefined,
              stealth,
              preserve_time: true,
              backup: false,
              overwrite: false,
            },
            updateProgress,
          );
          queue.update(item.path, {
            status: "ok",
            message: undefined,
            outputPath: res.carrier,
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
      <p className="text-xs text-slate-400">{c.hide.desc}</p>

      <FileQueue api={queue} disabled={running} hint={c.hide.fileHint} />

      <PayloadEditor
        label={c.hide.payloadLabel}
        placeholder={c.hide.textPlaceholder}
        kind={payloadKind}
        onKind={setPayloadKind}
        text={text}
        onText={setText}
        filePath={payloadPath}
        fileSize={payloadSize}
        onFilePath={(path, size) => {
          setPayloadPath(path);
          setPayloadSize(size);
        }}
        disabled={running}
      />

      <div className="space-y-2.5 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
        <PasswordRow
          value={password}
          onChange={setPassword}
          placeholder={c.hide.passwordPlaceholder}
          disabled={running}
          extra={
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300"
            >
              <Settings2 className="h-3.5 w-3.5" />
              {c.common.advanced}
            </button>
          }
        />

        {password && !stealth && (
          <PasswordRow
            label={c.common.hint}
            masked={false}
            value={passwordHint}
            onChange={setPasswordHint}
            placeholder={c.hide.hintPlaceholder}
            disabled={running}
          />
        )}

        {showAdvanced && (
          <label className="flex cursor-pointer items-center gap-1.5 pl-[3.5rem] text-xs text-slate-300">
            <input
              type="checkbox"
              checked={stealth}
              onChange={(e) => setStealth(e.target.checked)}
              disabled={running || !password}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 disabled:opacity-40"
            />
            {c.hide.stealth}
          </label>
        )}

        <DirRow value={outputDir} onChange={setOutputDir} disabled={running} />
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-rose-800/80 bg-rose-950/40 px-3 py-2 text-xs text-rose-300">
          <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-[11px] text-slate-500">{c.hide.footnote}</p>
        <button
          type="button"
          onClick={run}
          disabled={running || payloadBytes === 0 || queue.items.length === 0}
          className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-700 px-4 py-2 text-xs font-semibold text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Play className="h-3.5 w-3.5" />
          {c.hide.start}
        </button>
      </div>
    </div>
  );
};
