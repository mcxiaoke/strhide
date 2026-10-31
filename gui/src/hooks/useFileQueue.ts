import { useCallback, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import type { Capability } from "../types/strhide";
import { getFileMetadata } from "../api/commands";
import { t } from "../lib/i18n";
import { classifyFormat, makeItem, type QueueItem, type QueueNeed, type ReasonKey } from "../lib/queue";
import { useSettingsStore } from "../store/settingsStore";

export interface SkippedFile {
  name: string;
  reason: ReasonKey;
}

export interface FileQueueApi {
  items: QueueItem[];
  skipped: SkippedFile[];
  pick: () => Promise<void>;
  addPaths: (paths: string[]) => Promise<void>;
  update: (path: string, patch: Partial<QueueItem>) => void;
  remove: (path: string) => void;
  clear: () => void;
  resetStatus: () => void;
  dismissSkipped: () => void;
}

/** 单个页签自己的文件队列，不支持的文件当场提示并跳过 */
export function useFileQueue(need: QueueNeed, capabilities: Capability[]): FileQueueApi {
  const lang = useSettingsStore((s) => s.lang);
  const [items, setItems] = useState<QueueItem[]>([]);
  const [skipped, setSkipped] = useState<SkippedFile[]>([]);
  const itemsRef = useRef<QueueItem[]>([]);
  const capsRef = useRef<Capability[]>(capabilities);
  capsRef.current = capabilities;

  const commit = useCallback((next: QueueItem[]) => {
    itemsRef.current = next;
    setItems(next);
  }, []);

  const addPaths = useCallback(
    async (paths: string[]) => {
      const caps = capsRef.current;
      const known = new Set(itemsRef.current.map((it) => it.path));
      const fresh: QueueItem[] = [];
      const rejected: SkippedFile[] = [];

      for (const path of paths) {
        if (!path || known.has(path)) continue;
        known.add(path);
        const verdict = classifyFormat(path, caps, need);
        if (!verdict.supported) {
          rejected.push({
            name: path.split(/[\\/]/).pop() || path,
            reason: verdict.reason ?? "formatUnsupported",
          });
          continue;
        }
        fresh.push(makeItem(path, verdict));
      }

      if (rejected.length > 0) setSkipped((prev) => [...prev, ...rejected]);
      if (fresh.length === 0) return;
      commit([...itemsRef.current, ...fresh]);

      const metas = await Promise.all(
        fresh.map(async (item) => {
          try {
            const meta = await getFileMetadata(item.path);
            return { path: item.path, size: Number(meta.size_bytes) };
          } catch {
            return { path: item.path, size: null as number | null };
          }
        }),
      );
      commit(
        itemsRef.current.map((item) => {
          const hit = metas.find((m) => m.path === item.path);
          return hit && hit.size !== null ? { ...item, size: hit.size } : item;
        }),
      );
    },
    [commit, need],
  );

  const pick = useCallback(async () => {
    try {
      const selected = await open({ multiple: true, title: t(lang).common.pickFilesTitle });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];
      await addPaths(paths);
    } catch (err) {
      console.error("File pick error:", err);
    }
  }, [addPaths, lang]);

  const update = useCallback(
    (path: string, patch: Partial<QueueItem>) => {
      commit(itemsRef.current.map((item) => (item.path === path ? { ...item, ...patch } : item)));
    },
    [commit],
  );

  const remove = useCallback(
    (path: string) => {
      commit(itemsRef.current.filter((item) => item.path !== path));
    },
    [commit],
  );

  const clear = useCallback(() => {
    commit([]);
  }, [commit]);

  const resetStatus = useCallback(() => {
    commit(
      itemsRef.current.map((item) => ({
        ...item,
        status: item.supported ? "idle" : "skip",
        message: undefined,
        outputPath: undefined,
      })),
    );
  }, [commit]);

  const dismissSkipped = useCallback(() => setSkipped([]), []);

  return { items, skipped, pick, addPaths, update, remove, clear, resetStatus, dismissSkipped };
}
