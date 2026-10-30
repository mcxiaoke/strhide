import { useEffect, useState } from "react";
import { getCapabilities } from "../api/commands";
import type { Capability } from "../types/strhide";

let cached: Capability[] | null = null;
let pending: Promise<Capability[]> | null = null;

/** 格式能力表，进程内只取一次 */
export function useCapabilities(): Capability[] {
  const [caps, setCaps] = useState<Capability[]>(cached ?? []);

  useEffect(() => {
    if (cached) {
      setCaps(cached);
      return;
    }
    if (!pending) {
      pending = getCapabilities().catch((err) => {
        console.error("Failed to load capabilities:", err);
        return [] as Capability[];
      });
    }
    let alive = true;
    pending.then((res) => {
      cached = res;
      if (alive) setCaps(res);
    });
    return () => {
      alive = false;
    };
  }, []);

  return caps;
}
