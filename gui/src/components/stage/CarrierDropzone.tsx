import React, { useEffect } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { UploadCloud, FileSearch } from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

export const CarrierDropzone: React.FC = () => {
  const { setCarrier, isInspecting } = useWorkspaceStore();

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    try {
      const webview = getCurrentWebview();
      if (webview && typeof webview.onDragDropEvent === "function") {
        webview
          .onDragDropEvent((event) => {
            if (event.payload.type === "drop") {
              const paths = event.payload.paths;
              if (paths && paths.length > 0) {
                setCarrier(paths[0]);
              }
            }
          })
          .then((fn) => {
            unlisten = fn;
          })
          .catch((err) => {
            console.warn("Drag & drop listener error:", err);
          });
      }
    } catch (err) {
      console.warn("Webview drag-drop initialization skipped in non-Tauri context:", err);
    }

    return () => {
      if (unlisten) unlisten();
    };
  }, [setCarrier]);

  const handlePickFile = async () => {
    try {
      const selected = await open({
        multiple: false,
        title: "选择载体文件 (PNG, JPEG, MP4, HEIF, ZIP, PDF, PE...)",
      });
      if (selected && typeof selected === "string") {
        setCarrier(selected);
      }
    } catch (err) {
      console.error("File pick error:", err);
    }
  };

  return (
    <div
      onClick={handlePickFile}
      className="group relative cursor-pointer rounded-2xl border-2 border-dashed border-slate-700 bg-slate-900/60 p-8 text-center transition-all duration-200 hover:border-cyan-500 hover:bg-slate-900/90 hover:shadow-lg hover:shadow-cyan-950/30"
    >
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-slate-800 text-cyan-400 shadow-inner transition-transform group-hover:scale-105 group-hover:bg-cyan-950/60 group-hover:text-cyan-300">
        <UploadCloud className="h-8 w-8" />
      </div>

      <h3 className="mt-4 text-base font-semibold text-slate-100">
        拖拽载体文件至此，或 <span className="text-cyan-400 underline underline-offset-4">点击浏览选择</span>
      </h3>
      <p className="mt-1.5 text-xs text-slate-400">
        支持 PNG, JPEG, MP4, HEVC, HEIF, ZIP, PDF, PE, WAV, MKV 等全格式载体
      </p>

      {isInspecting && (
        <div className="mt-4 inline-flex items-center gap-2 rounded-full bg-cyan-950/80 px-4 py-1 text-xs text-cyan-300 border border-cyan-800/60 animate-pulse">
          <FileSearch className="h-3.5 w-3.5 animate-spin" />
          正在流式检视载体双域结构...
        </div>
      )}
    </div>
  );
};
