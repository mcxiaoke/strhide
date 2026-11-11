import type { Capability } from "../types/strhide";
import { baseName, dirName, extOf } from "./format";

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

export type ReasonKey =
  | "formatUnsupported"
  | "noStego"
  | "noStructure"
  | "capabilitiesUnavailable";

export interface SupportVerdict {
  supported: boolean;
  format: string | null;
  reason?: ReasonKey;
}

export function classifyFormat(
  path: string,
  capabilities: Capability[] | null,
  need: QueueNeed,
): SupportVerdict {
  // `null` means the capability table could not be loaded, which is not the
  // same answer as "this extension is unsupported". They used to be merged
  // (`getCapabilities()` failed → `[]` → every file rejected as
  // "unsupported format"), so an IPC hiccup told the user their files were
  // the problem.
  if (capabilities === null) {
    return { supported: false, format: null, reason: "capabilitiesUnavailable" };
  }
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

