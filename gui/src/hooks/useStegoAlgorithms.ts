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
    if (!pending) {
      pending = getStegoAlgorithms().catch((err) => {
        console.error("Failed to load stego algorithms:", err);
        return [] as StegoAlgorithmInfo[];
      });
    }
    let alive = true;
    pending.then((res) => {
      const safeList = Array.isArray(res) ? res : [];
      cached = safeList;
      if (alive) setAlgos(safeList);
    });
    return () => {
      alive = false;
    };
  }, []);

  return algos;
}
