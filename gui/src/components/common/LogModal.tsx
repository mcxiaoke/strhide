import React, { useState, useMemo, useRef, useEffect } from "react";
import {
  Terminal,
  X,
  Maximize2,
  Minimize2,
  Copy,
  Check,
  Trash2,
  ArrowDown,
  Search,
  ChevronDown,
  ChevronRight,
  FileCode,
} from "lucide-react";
import { useLogStore } from "../../store/logStore";
import { useT } from "../../hooks/useT";
import type { LogEntry } from "../../types/strhide";

export const LogModal: React.FC = () => {
  const c = useT();
  const {
    entries,
    filterSource,
    filterLevel,
    searchQuery,
    isModalOpen,
    autoScroll,
    setFilterSource,
    setFilterLevel,
    setSearchQuery,
    setModalOpen,
    setAutoScroll,
    clear,
    copyFormatted,
  } = useLogStore();

  const [isMaximized, setIsMaximized] = useState(false);
  const [copiedAll, setCopiedAll] = useState(false);
  const [copiedEntryId, setCopiedEntryId] = useState<string | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const isAutoScrollingRef = useRef(false);

  // Keyboard shortcut: Esc to close
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isModalOpen) {
        setModalOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isModalOpen, setModalOpen]);

  // Filtered log entries
  const filteredEntries = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return entries.filter((e) => {
      if (filterSource !== "all" && e.source !== filterSource) return false;
      if (filterLevel !== "all" && e.level !== filterLevel) return false;
      if (q) {
        const matchMsg = e.message.toLowerCase().includes(q);
        const matchTarget = e.target.toLowerCase().includes(q);
        const matchData = e.data ? JSON.stringify(e.data).toLowerCase().includes(q) : false;
        if (!matchMsg && !matchTarget && !matchData) return false;
      }
      return true;
    });
  }, [entries, filterSource, filterLevel, searchQuery]);

  // Level counts for badges
  const levelCounts = useMemo(() => {
    const counts = { debug: 0, info: 0, warn: 0, error: 0 };
    for (const e of entries) {
      if (e.level in counts) {
        counts[e.level]++;
      }
    }
    return counts;
  }, [entries]);

  // Auto-scroll logic
  useEffect(() => {
    if (!autoScroll || !isModalOpen) return;
    const el = scrollContainerRef.current;
    if (!el) return;

    isAutoScrollingRef.current = true;
    el.scrollTop = el.scrollHeight;
    setTimeout(() => {
      isAutoScrollingRef.current = false;
    }, 50);
  }, [filteredEntries.length, autoScroll, isModalOpen]);

  // Detect manual user scroll
  const handleScroll = () => {
    if (isAutoScrollingRef.current) return;
    const el = scrollContainerRef.current;
    if (!el) return;

    const isAtBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= 40;
    if (autoScroll !== isAtBottom) {
      setAutoScroll(isAtBottom);
    }
  };

  const handleCopyAll = async () => {
    const ok = await copyFormatted(true);
    if (ok) {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    }
  };

  const handleCopySingle = async (e: LogEntry) => {
    const d = new Date(e.timestamp);
    const timeStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}.${String(d.getMilliseconds()).padStart(3, "0")}`;
    let text = `[${timeStr}] [${e.source.toUpperCase()}] [${e.level.toUpperCase()}] [${e.target}] ${e.message}`;
    if (e.data !== undefined) {
      text += `\n${JSON.stringify(e.data, null, 2)}`;
    }

    try {
      await navigator.clipboard.writeText(text);
      setCopiedEntryId(e.id);
      setTimeout(() => setCopiedEntryId(null), 1500);
    } catch {
      // Ignore
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  if (!isModalOpen) return null;

  return (
    <div
      data-testid="log-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 sm:p-6"
      onClick={() => setModalOpen(false)}
    >
      <div
        data-testid="log-modal-container"
        className={`flex flex-col rounded-xl border border-slate-800 bg-slate-900 shadow-2xl transition-all duration-150 ${
          isMaximized
            ? "fixed inset-3 z-50 max-w-none"
            : "h-[85vh] w-full max-w-5xl"
        }`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex h-12 shrink-0 items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-6 w-6 items-center justify-center rounded-md bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              <Terminal className="h-3.5 w-3.5" />
            </div>
            <span className="text-sm font-semibold text-slate-100">
              {c.logs.title}
            </span>
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[11px] font-mono text-slate-400">
              {c.logs.entriesCount.replace("{n}", String(filteredEntries.length))}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setIsMaximized(!isMaximized)}
              title={isMaximized ? "Restore" : "Maximize"}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              {isMaximized ? (
                <Minimize2 className="h-4 w-4" />
              ) : (
                <Maximize2 className="h-4 w-4" />
              )}
            </button>
            <button
              type="button"
              data-testid="log-modal-close"
              onClick={() => setModalOpen(false)}
              title={c.logs.close}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-rose-400"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Control Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-slate-800 bg-slate-950/60 p-3 text-xs">
          {/* Source and Level filter buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Source group */}
            <div className="inline-flex rounded-lg border border-slate-800 bg-slate-900/90 p-0.5">
              {(["all", "rust", "frontend"] as const).map((src) => (
                <button
                  key={src}
                  type="button"
                  data-testid={`filter-source-${src}`}
                  onClick={() => setFilterSource(src)}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    filterSource === src
                      ? "bg-cyan-700 text-white font-semibold"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {src === "all"
                    ? c.logs.sourceAll
                    : src === "rust"
                    ? c.logs.sourceRust
                    : c.logs.sourceFrontend}
                </button>
              ))}
            </div>

            {/* Level group */}
            <div className="inline-flex rounded-lg border border-slate-800 bg-slate-900/90 p-0.5">
              {(["all", "error", "warn", "info", "debug"] as const).map((lvl) => {
                const isActive = filterLevel === lvl;
                return (
                  <button
                    key={lvl}
                    type="button"
                    data-testid={`filter-level-${lvl}`}
                    onClick={() => setFilterLevel(lvl)}
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium transition-colors ${
                      isActive
                        ? "bg-slate-700 text-slate-100 font-semibold"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <span>
                      {lvl === "all" ? c.logs.levelAll : lvl.toUpperCase()}
                    </span>
                    {lvl !== "all" && levelCounts[lvl] > 0 && (
                      <span
                        className={`rounded-full px-1 text-[9px] font-mono leading-tight ${
                          lvl === "error"
                            ? "bg-rose-500/30 text-rose-300"
                            : lvl === "warn"
                            ? "bg-amber-500/30 text-amber-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {levelCounts[lvl]}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Search box and action buttons */}
          <div className="flex flex-1 items-center justify-end gap-2 min-w-[280px]">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                data-testid="log-search-input"
                placeholder={c.logs.searchPlaceholder}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded-lg border border-slate-700 bg-slate-900 py-1 pl-8 pr-7 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>

            <button
              type="button"
              data-testid="copy-all-logs-btn"
              onClick={handleCopyAll}
              title={c.logs.copyAll}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                copiedAll
                  ? "border-emerald-600 bg-emerald-950/60 text-emerald-300"
                  : "border-slate-700 bg-slate-800/80 text-slate-300 hover:bg-slate-700 hover:text-slate-100"
              }`}
            >
              {copiedAll ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-cyan-400" />}
              {copiedAll ? c.logs.copied : c.logs.copyAll}
            </button>

            <button
              type="button"
              onClick={() => setAutoScroll(!autoScroll)}
              title={c.logs.autoScroll}
              className={`inline-flex items-center gap-1 rounded-lg border px-2 py-1 text-xs transition-colors ${
                autoScroll
                  ? "border-cyan-700 bg-cyan-950/60 text-cyan-300"
                  : "border-slate-700 bg-slate-800/80 text-slate-400 hover:text-slate-200"
              }`}
            >
              <ArrowDown className={`h-3.5 w-3.5 ${autoScroll ? "text-cyan-400" : ""}`} />
            </button>

            <button
              type="button"
              data-testid="clear-logs-btn"
              onClick={() => clear()}
              title={c.logs.clear}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2 py-1 text-xs text-slate-400 hover:bg-rose-950/50 hover:border-rose-800 hover:text-rose-300"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        {/* Log Stream Content Body (Explicitly selectable) */}
        <div
          ref={scrollContainerRef}
          onScroll={handleScroll}
          data-testid="log-stream-container"
          className="flex-1 overflow-y-auto bg-slate-950 p-3 font-mono text-xs select-text"
          style={{ userSelect: "text" }}
        >
          {filteredEntries.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-slate-500">
              <Terminal className="h-8 w-8 text-slate-600" />
              <span>{c.logs.empty}</span>
            </div>
          ) : (
            <div className="space-y-1">
              {filteredEntries.map((e) => {
                const d = new Date(e.timestamp);
                const timeStr = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}.${String(d.getMilliseconds()).padStart(3, "0")}`;
                const isExpanded = expandedIds.has(e.id);
                const hasData = e.data !== undefined && e.data !== null;

                const levelBadgeClass =
                  e.level === "error"
                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/30 font-semibold"
                    : e.level === "warn"
                    ? "bg-amber-500/20 text-amber-300 border border-amber-500/30 font-semibold"
                    : e.level === "debug"
                    ? "bg-slate-800 text-slate-400 border border-slate-700"
                    : "bg-cyan-950/80 text-cyan-300 border border-cyan-800/50";

                const sourceBadgeClass =
                  e.source === "rust"
                    ? "bg-cyan-900/40 text-cyan-300"
                    : "bg-indigo-900/40 text-indigo-300";

                return (
                  <div
                    key={e.id}
                    data-testid={`log-row-${e.id}`}
                    className="group flex flex-col rounded border border-transparent p-1.5 transition-colors hover:border-slate-800 hover:bg-slate-900/60"
                  >
                    <div className="flex items-start gap-2">
                      <span className="shrink-0 text-[11px] text-slate-500 select-text">
                        {timeStr}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.2 text-[10px] font-semibold uppercase ${sourceBadgeClass}`}
                      >
                        {e.source === "rust" ? "RUST" : "GUI"}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1.5 py-0.2 text-[10px] uppercase ${levelBadgeClass}`}
                      >
                        {e.level}
                      </span>
                      <span className="shrink-0 rounded bg-slate-900 px-1 text-[11px] text-slate-400 select-text border border-slate-800">
                        {e.target}
                      </span>
                      <span className="flex-1 break-all text-slate-200 select-text leading-relaxed">
                        {e.message}
                      </span>

                      {/* Action buttons on hover */}
                      <div className="flex shrink-0 items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        {hasData && (
                          <button
                            type="button"
                            onClick={() => toggleExpand(e.id)}
                            title={isExpanded ? c.logs.collapseData : c.logs.expandData}
                            className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[10px] text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 hover:bg-cyan-900/80"
                          >
                            <FileCode className="h-3 w-3" />
                            {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleCopySingle(e)}
                          title="Copy entry"
                          className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                        >
                          {copiedEntryId === e.id ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Expandable Data / JSON block */}
                    {hasData && isExpanded && (
                      <div className="mt-2 ml-16 mr-2 rounded-lg border border-slate-800 bg-slate-900/90 p-2.5">
                        <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-800 text-[11px] text-slate-400">
                          <span className="font-semibold text-cyan-300">
                            {c.logs.expandData} (JSON)
                          </span>
                          <button
                            type="button"
                            onClick={async () => {
                              try {
                                await navigator.clipboard.writeText(
                                  JSON.stringify(e.data, null, 2),
                                );
                                setCopiedEntryId(e.id);
                                setTimeout(() => setCopiedEntryId(null), 1500);
                              } catch {
                                // Ignore
                              }
                            }}
                            className="inline-flex items-center gap-1 rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700"
                          >
                            {copiedEntryId === e.id ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            {c.logs.copyJson}
                          </button>
                        </div>
                        <pre className="overflow-x-auto text-[11px] text-emerald-300 select-text leading-tight">
                          {JSON.stringify(e.data, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
