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

    const customListener = (event: Event) => {
      const custom = event as CustomEvent<{ paths?: string[] }>;
      if (!activeRef.current) return;
      const paths = custom.detail?.paths;
      if (paths && paths.length > 0) handlerRef.current(paths);
    };
    window.addEventListener("strhide:drop-files", customListener);

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
      window.removeEventListener("strhide:drop-files", customListener);
      if (unlisten) unlisten();
    };
  }, []);
}
