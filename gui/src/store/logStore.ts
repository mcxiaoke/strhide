import { create } from "zustand";
import type { LogEntry, LogLevel, LogSource } from "../types/strhide";
import { clearLogs as clearBackendLogs } from "../api/commands";

export const MAX_STORE_LOGS = 2000;

interface LogState {
  entries: LogEntry[];
  filterSource: "all" | LogSource;
  filterLevel: "all" | LogLevel;
  searchQuery: string;
  isModalOpen: boolean;
  autoScroll: boolean;
  unreadErrorCount: number;

  addEntry: (entry: Omit<LogEntry, "id"> & { id?: string | number }) => void;
  addEntries: (entries: Array<Omit<LogEntry, "id"> & { id?: string | number }>) => void;
  setFilterSource: (source: "all" | LogSource) => void;
  setFilterLevel: (level: "all" | LogLevel) => void;
  setSearchQuery: (query: string) => void;
  setModalOpen: (open: boolean) => void;
  setAutoScroll: (autoScroll: boolean) => void;
  clear: () => Promise<void>;
  copyFormatted: (filteredOnly?: boolean) => Promise<boolean>;
}

let counter = 1;

function normalizeEntry(entry: Omit<LogEntry, "id"> & { id?: string | number }): LogEntry {
  const id = entry.id ? String(entry.id) : `log-${Date.now()}-${counter++}`;
  const level = (entry.level.toLowerCase() as LogLevel) || "info";
  const source = entry.source || "frontend";
  const timestamp = typeof entry.timestamp === "number" ? entry.timestamp : Date.now();
  return {
    id,
    timestamp,
    source,
    level,
    target: entry.target || "app",
    message: entry.message || "",
    data: entry.data,
  };
}

export const useLogStore = create<LogState>((set, get) => ({
  entries: [],
  filterSource: "all",
  filterLevel: "all",
  searchQuery: "",
  isModalOpen: false,
  autoScroll: true,
  unreadErrorCount: 0,

  addEntry: (raw) => {
    const entry = normalizeEntry(raw);
    const { isModalOpen, unreadErrorCount } = get();
    const isError = entry.level === "error";

    set((state) => {
      const nextEntries = [...state.entries, entry];
      if (nextEntries.length > MAX_STORE_LOGS) {
        nextEntries.splice(0, nextEntries.length - MAX_STORE_LOGS);
      }
      return {
        entries: nextEntries,
        unreadErrorCount: !isModalOpen && isError ? unreadErrorCount + 1 : unreadErrorCount,
      };
    });
  },

  addEntries: (rawList) => {
    if (!rawList || rawList.length === 0) return;
    const normalized = rawList.map(normalizeEntry);

    set((state) => {
      const existingIds = new Set(state.entries.map((e) => e.id));
      const deduplicated = normalized.filter((e) => !existingIds.has(e.id));
      const combined = [...state.entries, ...deduplicated];
      combined.sort((a, b) => a.timestamp - b.timestamp);
      if (combined.length > MAX_STORE_LOGS) {
        combined.splice(0, combined.length - MAX_STORE_LOGS);
      }
      return { entries: combined };
    });
  },

  setFilterSource: (filterSource) => set({ filterSource }),
  setFilterLevel: (filterLevel) => set({ filterLevel }),
  setSearchQuery: (searchQuery) => set({ searchQuery }),

  setModalOpen: (isModalOpen) => {
    set({
      isModalOpen,
      unreadErrorCount: isModalOpen ? 0 : get().unreadErrorCount,
    });
  },

  setAutoScroll: (autoScroll) => set({ autoScroll }),

  clear: async () => {
    try {
      await clearBackendLogs();
    } catch {
      // Backend clear may fail in unit test environments without mock
    }
    set({ entries: [], unreadErrorCount: 0 });
  },

  copyFormatted: async (filteredOnly = false) => {
    const state = get();
    let list = state.entries;

    if (filteredOnly) {
      const source = state.filterSource;
      const level = state.filterLevel;
      const query = state.searchQuery.trim().toLowerCase();

      list = list.filter((e) => {
        if (source !== "all" && e.source !== source) return false;
        if (level !== "all" && e.level !== level) return false;
        if (query) {
          const matchMsg = e.message.toLowerCase().includes(query);
          const matchTarget = e.target.toLowerCase().includes(query);
          const matchData = e.data ? JSON.stringify(e.data).toLowerCase().includes(query) : false;
          if (!matchMsg && !matchTarget && !matchData) return false;
        }
        return true;
      });
    }

    if (list.length === 0) return false;

    const formatted = list
      .map((e) => {
        const d = new Date(e.timestamp);
        const timeStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}.${String(d.getMilliseconds()).padStart(3, "0")}`;
        const src = e.source === "rust" ? "RUST" : "GUI ";
        const lvl = e.level.toUpperCase().padEnd(5, " ");
        let line = `[${timeStr}] [${src}] [${lvl}] [${e.target}] ${e.message}`;
        if (e.data !== undefined && e.data !== null) {
          try {
            line += `\n  Data: ${JSON.stringify(e.data, null, 2).replace(/\n/g, "\n  ")}`;
          } catch {
            line += `\n  Data: [Object]`;
          }
        }
        return line;
      })
      .join("\n");

    try {
      await navigator.clipboard.writeText(formatted);
      return true;
    } catch {
      return false;
    }
  },
}));
