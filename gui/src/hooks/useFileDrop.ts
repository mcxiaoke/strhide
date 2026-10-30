import { useEffect, useRef } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";

/** 只让当前页签接收拖入的文件 */
export function useFileDrop(active: boolean, onPaths: (paths: string[]) => void) {
  const handlerRef = useRef(onPaths);
  handlerRef.current = onPaths;
  const activeRef = useRef(active);
  activeRef.current = active;

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let disposed = false;

    try {
      const webview = getCurrentWebview();
      if (webview && typeof webview.onDragDropEvent === "function") {
        webview
          .onDragDropEvent((event) => {
            if (!activeRef.current) return;
            if (event.payload.type !== "drop") return;
            const paths = event.payload.paths;
            if (paths && paths.length > 0) handlerRef.current(paths);
          })
          .then((fn) => {
            if (disposed) {
              fn();
            } else {
              unlisten = fn;
            }
          })
          .catch((err) => {
            console.warn("Drag & drop listener error:", err);
          });
      }
    } catch (err) {
      console.warn("Drag & drop unavailable outside Tauri:", err);
    }

    return () => {
      disposed = true;
      if (unlisten) unlisten();
    };
  }, []);
}
