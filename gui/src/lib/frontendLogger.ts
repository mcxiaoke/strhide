import { listen } from "@tauri-apps/api/event";
import { useLogStore } from "../store/logStore";
import { getRecentLogs } from "../api/commands";
import type { LogLevel } from "../types/strhide";

let isInitialized = false;

function formatArgs(args: unknown[]): { message: string; data?: unknown } {
  if (args.length === 0) return { message: "" };

  const parts: string[] = [];
  let extraData: unknown = undefined;

  for (let i = 0; i < args.length; i++) {
    const item = args[i];
    if (typeof item === "string") {
      parts.push(item);
    } else if (item instanceof Error) {
      parts.push(`${item.name}: ${item.message}\n${item.stack || ""}`);
    } else if (typeof item === "object" && item !== null) {
      try {
        parts.push(JSON.stringify(item));
        if (extraData === undefined && i === args.length - 1) {
          extraData = item;
        }
      } catch {
        parts.push(String(item));
      }
    } else {
      parts.push(String(item));
    }
  }

  return { message: parts.join(" "), data: extraData };
}

export function initFrontendLogging() {
  if (isInitialized) return;
  isInitialized = true;

  // 1. Intercept console methods
  const origLog = console.log.bind(console);
  const origInfo = console.info.bind(console);
  const origWarn = console.warn.bind(console);
  const origError = console.error.bind(console);
  const origDebug = console.debug.bind(console);

  const wrapConsole = (level: LogLevel, orig: (...args: any[]) => void) => {
    return (...args: any[]) => {
      orig(...args);
      try {
        const { message, data } = formatArgs(args);
        useLogStore.getState().addEntry({
          source: "frontend",
          level,
          target: "console",
          message,
          data,
          timestamp: Date.now(),
        });
      } catch {
        // Ignore errors inside logger
      }
    };
  };

  console.log = wrapConsole("info", origLog);
  console.info = wrapConsole("info", origInfo);
  console.warn = wrapConsole("warn", origWarn);
  console.error = wrapConsole("error", origError);
  console.debug = wrapConsole("debug", origDebug);

  // 2. Global uncaught error listeners
  if (typeof window !== "undefined") {
    window.addEventListener("error", (event) => {
      useLogStore.getState().addEntry({
        source: "frontend",
        level: "error",
        target: "window.onerror",
        message: `${event.message} (${event.filename}:${event.lineno}:${event.colno})`,
        data: event.error ? { stack: event.error.stack } : undefined,
        timestamp: Date.now(),
      });
    });

    window.addEventListener("unhandledrejection", (event) => {
      const reason = event.reason;
      const msg = reason instanceof Error ? reason.message : String(reason);
      useLogStore.getState().addEntry({
        source: "frontend",
        level: "error",
        target: "unhandledrejection",
        message: `Unhandled promise rejection: ${msg}`,
        data: reason instanceof Error ? { stack: reason.stack } : reason,
        timestamp: Date.now(),
      });
    });

    // 3. Listen to Rust backend logs via Tauri event
    try {
      listen<any>("app:log", (event) => {
        if (event.payload) {
          useLogStore.getState().addEntry({
            ...event.payload,
            source: "rust",
          });
        }
      }).catch(() => {
        // Ignore if outside Tauri environment (e.g. browser unit tests)
      });

      // Synchronize historical backlog
      getRecentLogs()
        .then((backlog) => {
          if (Array.isArray(backlog) && backlog.length > 0) {
            useLogStore.getState().addEntries(
              backlog.map((item) => ({
                ...item,
                source: "rust",
              })),
            );
          }
        })
        .catch(() => {
          // Ignore if outside Tauri environment
        });
    } catch {
      // Non-tauri test environment
    }
  }
}
