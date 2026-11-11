import { invoke, Channel } from "@tauri-apps/api/core";
import type {
  Capability,
  StegoAlgorithmInfo,
  DualInspect,
  WriteResult,
  StegoCapacityFullDto,
  FileMetadataDto,
  StegoEmbedResult,
  SmartExtractSummaryDto,
  StructureWriteRequest,
  StegoEmbedRequest,
  ProgressEvent,
  Lang,
  SafetyLevel,
} from "../types/strhide";

export async function getCapabilities(): Promise<Capability[]> {
  return invoke<Capability[]>("get_capabilities_cmd");
}

export async function getStegoAlgorithms(): Promise<StegoAlgorithmInfo[]> {
  return invoke<StegoAlgorithmInfo[]>("get_stego_algorithms_cmd");
}

export async function getFileMetadata(path: string): Promise<FileMetadataDto> {
  return invoke<FileMetadataDto>("get_file_metadata_cmd", { path });
}

/**
 * Ask the backend for a non-colliding output path (`stem (n).ext`).
 *
 * The numbering rule and the existence checks live in one place so the GUI
 * views, smart-extract's directory mode and the CLI batch agree; doing it in
 * one IPC call also removes the per-candidate `getFileMetadata` round trips.
 */
export async function uniqueOutputPath(dir: string, filename: string): Promise<string> {
  return invoke<string>("unique_output_path_cmd", { dir, filename });
}

export async function inspectCarrier(
  path: string,
  password?: string,
  domain?: string,
  taskId?: string,
): Promise<DualInspect> {
  return invoke<DualInspect>("inspect_carrier_cmd", { path, password, domain, taskId });
}

export async function writeStructureFile(
  taskId: string,
  req: StructureWriteRequest,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<WriteResult> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<WriteResult>("write_structure_file_cmd", {
    taskId,
    req,
    onProgress: channel,
  });
}

export async function probeStegoCapacity(
  taskId: string,
  path: string,
  safetyLevel: SafetyLevel = "high",
  password?: string,
  domain?: string,
  algorithm?: string,
  exact: boolean = false,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<StegoCapacityFullDto> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<StegoCapacityFullDto>("probe_stego_capacity_cmd", {
    taskId,
    path,
    safetyLevel,
    password,
    domain,
    algorithm,
    exact,
    onProgress: channel,
  });
}

export async function embedStegoFile(
  taskId: string,
  req: StegoEmbedRequest,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<StegoEmbedResult> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<StegoEmbedResult>("embed_stego_file_cmd", {
    taskId,
    req,
    onProgress: channel,
  });
}

export async function smartExtract(
  taskId: string,
  path: string,
  outputPath?: string,
  password?: string,
  domain?: string,
  prefer?: "structure" | "content",
  overwrite: boolean = false,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<SmartExtractSummaryDto> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<SmartExtractSummaryDto>("smart_extract_cmd", {
    taskId,
    path,
    outputPath,
    password,
    domain,
    prefer,
    overwrite,
    onProgress: channel,
  });
}

export async function setUiLanguage(lang: Lang): Promise<Lang> {
  return invoke<Lang>("set_ui_language_cmd", { lang });
}

export async function cancelTask(taskId: string): Promise<boolean> {
  return invoke<boolean>("cancel_task_cmd", { taskId });
}

export async function getRecentLogs(): Promise<any[]> {
  return invoke<any[]>("get_recent_logs_cmd");
}

export async function clearLogs(): Promise<void> {
  return invoke<void>("clear_logs_cmd");
}
