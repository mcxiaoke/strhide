import { invoke, Channel } from "@tauri-apps/api/core";
import type {
  Capability,
  DualInspect,
  DualVerifyDto,
  ScanReport,
  WriteResult,
  ReadSummary,
  RemoveResult,
  StegoCapacityInfo,
  StegoEmbedResult,
  SmartExtractSummaryDto,
  StructureWriteRequest,
  StegoEmbedRequest,
  ProgressEvent,
  Lang,
  SafetyLevel,
  Domain,
  BatchJobSpec,
  BatchOutcome,
} from "../types/strhide";

export async function getCapabilities(): Promise<Capability[]> {
  return invoke<Capability[]>("get_capabilities_cmd");
}

export async function inspectCarrier(
  path: string,
  password?: string,
  domain?: string,
): Promise<DualInspect> {
  return invoke<DualInspect>("inspect_carrier_cmd", { path, password, domain });
}

export async function verifyCarrier(
  path: string,
  password?: string,
  domain?: string,
): Promise<DualVerifyDto> {
  return invoke<DualVerifyDto>("verify_carrier_cmd", { path, password, domain });
}

export async function scanCarrier(path: string): Promise<ScanReport> {
  return invoke<ScanReport>("scan_carrier_cmd", { path });
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

export async function readStructureFile(
  taskId: string,
  path: string,
  outputPath?: string,
  password?: string,
  overwrite: boolean = false,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<ReadSummary> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<ReadSummary>("read_structure_file_cmd", {
    taskId,
    path,
    outputPath,
    password,
    overwrite,
    onProgress: channel,
  });
}

export async function restoreStructureFile(
  taskId: string,
  path: string,
  outputPath?: string,
  password?: string,
  backup: boolean = true,
  overwrite: boolean = false,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<RemoveResult> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<RemoveResult>("restore_structure_file_cmd", {
    taskId,
    path,
    outputPath,
    password,
    backup,
    overwrite,
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
): Promise<StegoCapacityInfo> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<StegoCapacityInfo>("probe_stego_capacity_cmd", {
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

export async function extractStegoFile(
  taskId: string,
  path: string,
  outputPath?: string,
  password?: string,
  domain?: string,
  overwrite: boolean = false,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<ReadSummary> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<ReadSummary>("extract_stego_file_cmd", {
    taskId,
    path,
    outputPath,
    password,
    domain,
    overwrite,
    onProgress: channel,
  });
}

export async function smartExtract(
  taskId: string,
  path: string,
  outputPath?: string,
  password?: string,
  domain?: string,
  prefer?: Domain,
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

export async function runBatchJob(
  taskId: string,
  items: string[],
  job: BatchJobSpec,
  onProgress?: (ev: ProgressEvent) => void,
): Promise<BatchOutcome<unknown>> {
  const channel = new Channel<ProgressEvent>();
  if (onProgress) {
    channel.onmessage = onProgress;
  }
  return invoke<BatchOutcome<unknown>>("run_batch_job_cmd", {
    taskId,
    items,
    job,
    onProgress: channel,
  });
}
