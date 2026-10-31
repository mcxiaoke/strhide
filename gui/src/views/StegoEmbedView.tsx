import React, { useRef, useState } from "react";
import { Play, Settings2, TriangleAlert } from "lucide-react";
import { useCapabilities } from "../hooks/useCapabilities";
import { useFileQueue } from "../hooks/useFileQueue";
import { useFileDrop } from "../hooks/useFileDrop";
import { useT } from "../hooks/useT";
import { useOutputDir } from "../hooks/useOutputDir";
import { useTaskStore } from "../store/taskStore";
import { embedStegoFile, probeStegoCapacity } from "../api/commands";
import { parseStrHideError } from "../lib/errorHandler";
import { formatBytes, withSuffix } from "../lib/format";
import { fmt } from "../lib/i18n";
import { uniqueOutputPath } from "../lib/queue";
import { ALGORITHMS, SAFETY_LEVELS, tierLimit } from "../lib/stego";
import { FileQueue } from "../components/common/FileQueue";
import { PasswordRow } from "../components/common/PasswordRow";
import { DirRow } from "../components/common/DirRow";
import { PayloadEditor, type PayloadKind } from "../components/common/PayloadEditor";
import type { PayloadInputDto, SafetyLevel, StegoCapacityFullDto } from "../types/strhide";

export const StegoEmbedView: React.FC<{ active: boolean }> = ({ active }) => {
  const c = useT();
  const capabilities = useCapabilities();
  const queue = useFileQueue("stego", capabilities);
  const { startTask, updateProgress, finishTask } = useTaskStore();

  const [payloadKind, setPayloadKind] = useState<PayloadKind>("text");
  const [text, setText] = useState("");
  const [payloadPath, setPayloadPath] = useState<string | null>(null);
  const [payloadSize, setPayloadSize] = useState<number | null>(null);

  const [password, setPassword] = useState("");
  const [safety, setSafety] = useState<SafetyLevel>("high");
  const [enforce, setEnforce] = useState(false);
  const [outputDir, setOutputDir] = useOutputDir();
  const [algorithm, setAlgorithm] = useState("auto");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const capacityCache = useRef(new Map<string, StegoCapacityFullDto>());

  useFileDrop(active, queue.addPaths);

  const safetyLabel: Record<SafetyLevel, string> = {
    paranoid: c.stego.safetyParanoid,
    high: c.stego.safetyHigh,
    balanced: c.stego.safetyBalanced,
  };

  const algorithmLabel: Record<string, string> = {
    auto: c.stego.algoAuto,
    hill: "HILL",
    suniward: "S-UNIWARD",
    uerd: "UERD",
    juniward: "J-UNIWARD",
  };

  const payloadBytes =
    payloadKind === "text" ? new TextEncoder().encode(text).length : payloadSize ?? 0;

  /** 密码 / 隐蔽程度 / 算法变化后，旧的容量数字不再成立，先清掉等下次执行重算 */
  const clearCapacities = () => {
    queue.items.forEach((item) => {
      if (item.capacityBytes !== undefined) queue.update(item.path, { capacityBytes: undefined });
    });
  };

  const buildPayload = (): PayloadInputDto | null => {
    if (payloadKind === "text") return text ? { kind: "text", content: text } : null;
    return payloadPath ? { kind: "file", path: payloadPath } : null;
  };

  const run = async () => {
    const payload = buildPayload();
    if (!payload) {
      setError(payloadKind === "text" ? c.stego.textError : c.stego.fileError);
      return;
    }
    const targets = queue.items.filter((item) => item.supported);
    if (targets.length === 0) {
      setError(c.stego.emptyError);
      return;
    }

    setError(null);
    setRunning(true);
    queue.resetStatus();

    try {
      for (let i = 0; i < targets.length; i += 1) {
        const item = targets[i];
        const taskId = `stego-${Date.now()}-${i}`;
        startTask(taskId, fmt(c.stego.progress, { i: i + 1, n: targets.length, name: item.name }));
        queue.update(item.path, { status: "running", message: c.stego.working, outputPath: undefined });

        let capacity: StegoCapacityFullDto;
        try {
          const cacheKey = `${item.path}|${password}|${algorithm}`;
          const cached = capacityCache.current.get(cacheKey);
          if (cached) {
            capacity = cached;
          } else {
            capacity = await probeStegoCapacity(
              taskId,
              item.path,
              safety,
              password || undefined,
              undefined,
              algorithm !== "auto" ? algorithm : undefined,
              false,
            );
            capacityCache.current.set(cacheKey, capacity);
          }
        } catch (err) {
          queue.update(item.path, { status: "skip", message: parseStrHideError(err, c).message });
          continue;
        }

        const limit = tierLimit(capacity, safety);
        queue.update(item.path, { capacityBytes: limit });

        if (payloadBytes > capacity.max_raw_payload_bytes) {
          queue.update(item.path, {
            status: "skip",
            message: fmt(c.stego.tooBig, {
              size: formatBytes(payloadBytes),
              cap: formatBytes(capacity.max_raw_payload_bytes),
            }),
          });
          continue;
        }
        if (enforce && payloadBytes > limit) {
          queue.update(item.path, {
            status: "skip",
            message: fmt(c.stego.overLimit, { cap: formatBytes(limit) }),
          });
          continue;
        }

        try {
          const target = await uniqueOutputPath(outputDir || item.dir, withSuffix(item.name, "_stego"));
          const res = await embedStegoFile(
            taskId,
            {
              carrier: item.path,
              payload,
              output_path: target,
              password: password || undefined,
              domain: "content",
              safety_level: safety,
              enforce_safety: enforce,
              algorithm: algorithm !== "auto" ? algorithm : undefined,
              backup: false,
              overwrite: false,
            },
            updateProgress,
          );
          queue.update(item.path, {
            status: "ok",
            message: undefined,
            outputPath: res.written_to,
          });
        } catch (err) {
          queue.update(item.path, { status: "error", message: parseStrHideError(err, c).message });
        }
      }
    } finally {
      finishTask();
      setRunning(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">{c.stego.desc}</p>

      <FileQueue api={queue} disabled={running} showCapacity hint={c.stego.fileHint} />

      <PayloadEditor
        label={c.stego.payloadLabel}
        placeholder={c.stego.textPlaceholder}
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
          onChange={(value) => {
            setPassword(value);
            clearCapacities();
          }}
          placeholder={c.stego.passwordPlaceholder}
          disabled={running}
        />

        <div className="flex flex-wrap items-center gap-3">
          <span className="w-[5.25rem] shrink-0 text-xs text-slate-400">{c.stego.safety}</span>
          <select
            value={safety}
            onChange={(e) => {
              setSafety(e.target.value as SafetyLevel);
              clearCapacities();
            }}
            disabled={running}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
          >
            {SAFETY_LEVELS.map((level) => (
              <option key={level} value={level}>
                {safetyLabel[level]}
              </option>
            ))}
          </select>
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={enforce}
              onChange={(e) => setEnforce(e.target.checked)}
              disabled={running}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0"
            />
            {c.stego.skipOver}
          </label>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="ml-auto inline-flex items-center gap-1 text-xs text-slate-400 hover:text-cyan-300"
          >
            <Settings2 className="h-3.5 w-3.5" />
            {c.common.advanced}
          </button>
        </div>

        {showAdvanced && (
          <div className="flex items-center gap-3">
            <span className="w-[5.25rem] shrink-0 text-xs text-slate-400">{c.stego.algorithm}</span>
            <select
              value={algorithm}
              onChange={(e) => {
                setAlgorithm(e.target.value);
                clearCapacities();
              }}
              disabled={running}
              className="rounded-lg border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
            >
              {ALGORITHMS.map((algo) => (
                <option key={algo} value={algo}>
                  {algorithmLabel[algo]}
                </option>
              ))}
            </select>
          </div>
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
        <p className="text-[11px] text-slate-500">{c.stego.footnote}</p>
        <button
          type="button"
          onClick={run}
          disabled={running || payloadBytes === 0 || queue.items.length === 0}
          className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-700 px-4 py-2 text-xs font-semibold text-white hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Play className="h-3.5 w-3.5" />
          {c.stego.start}
        </button>
      </div>
    </div>
  );
};
