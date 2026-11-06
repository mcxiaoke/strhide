import { useEffect, useState } from "react";
import { getCapabilities } from "../api/commands";
import type { Capability } from "../types/strhide";

let cached: Capability[] | null = null;
let pending: Promise<Capability[]> | null = null;

/** How long to wait before retrying a failed capability fetch, once. */
const RETRY_DELAY_MS = 1500;

export interface CapabilitiesState {
  /**
   * `null` means "not known yet", which callers must not treat as "no
   * capabilities": an empty table rejects every file as unsupported.
   */
  capabilities: Capability[] | null;
  error: string | null;
}

/**
 * 格式能力表，进程内只取一次；失败后自动重试一次，并允许下次挂载再取。
 *
 * 之前失败时返回空数组，`classifyFormat` 会把每个文件判成「格式不支持」，
 * 真实原因只留在 DevTools 里。
 */
export function useCapabilities(): CapabilitiesState {
  const [state, setState] = useState<CapabilitiesState>({
    capabilities: cached,
    error: null,
  });

  useEffect(() => {
    if (cached) {
      setState({ capabilities: cached, error: null });
      return;
    }

    let alive = true;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;

    const load = (): void => {
      if (!pending) {
        pending = getCapabilities().catch((err) => {
          // Release the rejected promise so the retry below (or the next
          // mount) issues a fresh request instead of replaying the failure.
          pending = null;
          throw err;
        });
      }
      const current = pending;
      current.then(
        (res) => {
          cached = res;
          if (alive) setState({ capabilities: res, error: null });
        },
        (err) => {
          if (!alive) return;
          const message = err instanceof Error ? err.message : String(err);
          console.error("Failed to load capabilities:", err);
          setState({ capabilities: null, error: message });
          if (retryTimer === undefined) {
            retryTimer = setTimeout(load, RETRY_DELAY_MS);
          }
        },
      );
    };

    load();

    return () => {
      alive = false;
      if (retryTimer !== undefined) clearTimeout(retryTimer);
    };
  }, []);

  return state;
}
