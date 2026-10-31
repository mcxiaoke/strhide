import type { Capability } from "../types/strhide";
import { getFileMetadata } from "../api/commands";
import { baseName, dirName, extOf, joinPath } from "./format";

/** 队列用途：stego=内容域隐写，structure=结构域隐藏，any=只检查格式 */
export type QueueNeed = "stego" | "structure" | "any";

export type ItemStatus = "idle" | "running" | "ok" | "skip" | "error";

export interface QueueItem {
  path: string;
  name: string;
  dir: string;
  ext: string;
  size: number | null;
  format: string | null;
  supported: boolean;
  reason?: ReasonKey;
  status: ItemStatus;
  message?: string;
  outputPath?: string;
  capacityBytes?: number;
}

export type ReasonKey = "formatUnsupported" | "noStego" | "noStructure";

export interface SupportVerdict {
  supported: boolean;
  format: string | null;
  reason?: ReasonKey;
}

export function classifyFormat(path: string, capabilities: Capability[], need: QueueNeed): SupportVerdict {
  const name = baseName(path);
  const ext = extOf(name);
  const cap = capabilities.find((c) => c.extensions.some((e) => e.toLowerCase() === ext));
  if (!cap) {
    return { supported: false, format: null, reason: "formatUnsupported" };
  }
  if (need === "stego" && cap.stego.length === 0) {
    return { supported: false, format: cap.format, reason: "noStego" };
  }
  if (need === "structure" && cap.structure.length === 0) {
    return { supported: false, format: cap.format, reason: "noStructure" };
  }
  return { supported: true, format: cap.format };
}

export function makeItem(path: string, verdict: SupportVerdict): QueueItem {
  const name = baseName(path);
  return {
    path,
    name,
    dir: dirName(path),
    ext: extOf(name),
    size: null,
    format: verdict.format,
    supported: verdict.supported,
    reason: verdict.reason,
    status: verdict.supported ? "idle" : "skip",
  };
}

export async function pathExists(path: string): Promise<boolean> {
  try {
    const meta = await getFileMetadata(path);
    return meta.is_file;
  } catch {
    return false;
  }
}

/** 目标目录内挑一个不冲突的文件名，重名时追加 (1)、(2)… */
export async function uniqueOutputPath(dir: string, fileName: string): Promise<string> {
  const idx = fileName.lastIndexOf(".");
  const stem = idx > 0 ? fileName.slice(0, idx) : fileName;
  const tail = idx > 0 ? fileName.slice(idx) : "";
  let candidate = joinPath(dir, fileName);
  let n = 1;
  while (await pathExists(candidate)) {
    candidate = joinPath(dir, `${stem} (${n})${tail}`);
    n += 1;
    if (n > 999) break;
  }
  return candidate;
}
