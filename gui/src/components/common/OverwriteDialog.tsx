import React from "react";
import { AlertCircle, FileCheck, Save } from "lucide-react";

interface OverwriteDialogProps {
  targetPath: string;
  onConfirmOverwrite: () => void;
  onSaveAs: () => void;
  onCancel: () => void;
}

export const OverwriteDialog: React.FC<OverwriteDialogProps> = ({
  targetPath,
  onConfirmOverwrite,
  onSaveAs,
  onCancel,
}) => {
  const fileName = targetPath.split(/[/\\]/).pop() || targetPath;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-amber-950/80 text-amber-400 border border-amber-800/60">
            <AlertCircle className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">目标文件已存在</h3>
            <p className="mt-1 text-xs text-slate-300 leading-relaxed">
              文件 <span className="font-mono font-semibold text-cyan-300">{fileName}</span> 已存在于磁盘。直接覆盖将不可逆地改写该文件。
            </p>
            <p className="mt-1 text-[11px] text-slate-500 font-mono break-all">{targetPath}</p>
          </div>
        </div>

        <div className="mt-6 flex flex-col gap-2">
          <button
            onClick={onConfirmOverwrite}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-rose-600 px-4 py-2.5 text-xs font-semibold text-white shadow-md hover:bg-rose-500 active:scale-95"
          >
            <FileCheck className="h-4 w-4" />
            确认覆盖现有文件
          </button>
          <button
            onClick={onSaveAs}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-slate-800 px-4 py-2.5 text-xs font-semibold text-slate-200 border border-slate-700 hover:bg-slate-700 active:scale-95"
          >
            <Save className="h-4 w-4 text-cyan-400" />
            另存为新路径...
          </button>
          <button
            onClick={onCancel}
            className="w-full py-1.5 text-xs text-slate-400 hover:text-slate-200"
          >
            取消操作
          </button>
        </div>
      </div>
    </div>
  );
};
