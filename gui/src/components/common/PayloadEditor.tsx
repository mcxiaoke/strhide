import React from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { FileUp, X } from "lucide-react";
import { getFileMetadata } from "../../api/commands";
import { useT } from "../../hooks/useT";
import { baseName, formatBytes } from "../../lib/format";

export type PayloadKind = "text" | "file";

interface PayloadEditorProps {
  label: string;
  kind: PayloadKind;
  onKind: (kind: PayloadKind) => void;
  text: string;
  onText: (text: string) => void;
  filePath: string | null;
  fileSize: number | null;
  onFilePath: (path: string | null, size: number | null) => void;
  placeholder?: string;
  disabled?: boolean;
}

export const PayloadEditor: React.FC<PayloadEditorProps> = ({
  label,
  kind,
  onKind,
  text,
  onText,
  filePath,
  fileSize,
  onFilePath,
  placeholder,
  disabled,
}) => {
  const c = useT();

  const pickFile = async () => {
    try {
      const selected = await open({ multiple: false, title: c.common.chooseFile });
      if (!selected || typeof selected !== "string") return;
      try {
        const meta = await getFileMetadata(selected);
        onFilePath(selected, Number(meta.size_bytes));
      } catch {
        onFilePath(selected, null);
      }
    } catch (err) {
      console.error("Payload pick error:", err);
    }
  };

  const bytes = kind === "text" ? new TextEncoder().encode(text).length : fileSize ?? 0;

  return (
    <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-slate-400">{label}</span>
        <div className="flex rounded-lg border border-slate-800 bg-slate-950 p-0.5 text-[11px]">
          {(["text", "file"] as PayloadKind[]).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => onKind(k)}
              disabled={disabled}
              className={`rounded px-2.5 py-1 font-medium transition-colors disabled:opacity-50 ${
                kind === k ? "bg-slate-800 text-cyan-300" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {k === "text" ? c.stego.textTab : c.stego.fileTab}
            </button>
          ))}
        </div>
      </div>

      {kind === "text" ? (
        <textarea
          rows={3}
          value={text}
          onChange={(e) => onText(e.target.value)}
          disabled={disabled}
          placeholder={placeholder ?? c.stego.textPlaceholder}
          className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-2.5 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none disabled:opacity-50"
        />
      ) : (
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={pickFile}
            disabled={disabled}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
          >
            <FileUp className="h-3.5 w-3.5" />
            {c.common.chooseFile}
          </button>
          <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300" title={filePath ?? ""}>
            {filePath ? baseName(filePath) : c.common.notChosen}
          </span>
          {filePath && (
            <button
              type="button"
              onClick={() => onFilePath(null, null)}
              disabled={disabled}
              title={c.common.remove}
              className="shrink-0 text-slate-500 hover:text-rose-400 disabled:opacity-40"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      <div className="flex justify-between text-[11px] font-mono text-slate-500">
        <span>{formatBytes(bytes)}</span>
      </div>
    </div>
  );
};
