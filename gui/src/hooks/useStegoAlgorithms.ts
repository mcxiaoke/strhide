import { useEffect, useState } from "react";
import { getStegoAlgorithms } from "../api/commands";
import type { StegoAlgorithmInfo } from "../types/strhide";

let cached: StegoAlgorithmInfo[] | null = null;
let pending: Promise<StegoAlgorithmInfo[]> | null = null;

/** 隐写算法元数据列表，进程内单例缓存 */
export function useStegoAlgorithms(): StegoAlgorithmInfo[] {
  const [algos, setAlgos] = useState<StegoAlgorithmInfo[]>(cached ?? []);

  useEffect(() => {
    if (cached) {
      setAlgos(cached);
      return;
    }
    let alive = true;
    if (!pending) {
      pending = getStegoAlgorithms().catch((err) => {
        pending = null;
        console.error("Failed to load stego algorithms:", err);
        throw err;
      });
    }
    pending
      .then((res) => {
        const safeList = Array.isArray(res) ? res : [];
        if (safeList.length > 0) {
          cached = safeList;
        }
        if (alive) setAlgos(safeList);
      })
      .catch(() => {
        // Error already logged; keep cached null so next mount retries.
      });
    return () => {
      alive = false;
    };
  }, []);

  return algos;
}
