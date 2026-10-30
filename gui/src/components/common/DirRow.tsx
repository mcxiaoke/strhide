import React from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen, X } from "lucide-react";
import { useT } from "../../hooks/useT";

interface DirRowProps {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}

export const DirRow: React.FC<DirRowProps> = ({ value, onChange, disabled }) => {
  const c = useT();

  const pickDir = async () => {
    try {
      const selected = await open({ directory: true, multiple: false, title: c.common.saveTo });
      if (selected && typeof selected === "string") onChange(selected);
    } catch (err) {
      console.error("Directory pick error:", err);
    }
  };

  return (
    <div className="flex items-center gap-3">
      <span className="w-14 shrink-0 text-xs text-slate-400">{c.common.saveTo}</span>
      <span
        className={`min-w-0 flex-1 truncate font-mono text-xs ${value ? "text-slate-300" : "text-slate-500"}`}
        title={value || c.common.sameDir}
      >
        {value || c.common.sameDir}
      </span>
      <button
        type="button"
        onClick={pickDir}
        disabled={disabled}
        className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 disabled:opacity-50"
      >
        <FolderOpen className="h-3.5 w-3.5" />
        {c.common.choose}
      </button>
      {value && (
        <button
          type="button"
          onClick={() => onChange("")}
          disabled={disabled}
          title={c.common.sameDir}
          className="shrink-0 text-slate-500 hover:text-rose-400 disabled:opacity-40"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
};
