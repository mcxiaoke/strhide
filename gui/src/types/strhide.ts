export type Lang = "en" | "zh";
export type Domain = "structure" | "content";
export type SafetyLevel = "paranoid" | "high" | "balanced";

export type ErrorKind =
  | "io"
  | "corrupted_data"
  | "password"
  | "password_with_hint"
  | "trellis_infeasible"
  | "rejection"
  | "already_exists"
  | "target_busy"
  | "safety_threshold"
  | "restore_mismatch"
  | "unsupported_format"
  | "no_hidden_data"
  | "unsupported_version"
  | "cancelled"
  | "general";

export interface ErrorDetail {
  kind: ErrorKind;
  category?: string;
  category_label?: string;
  detail: string;
  hint?: string;
}

export interface MediaInfo {
  width: number;
  height: number;
  fps?: number;
  duration_ms?: number;
  bitrate_bps?: number;
}

export interface StrategyCapacity {
  strategy: string;
  capacity_bytes: number | null;
  available: boolean;
  limit: string;
  note?: string;
}

export interface CarrierMetadata {
  filename: string;
  raw_size: number;
  raw_sha256: string;
  created_at: number;
}

export interface StegoHeaderInfo {
  format: string;
  has_hidden_data: boolean;
  algorithm?: string;
  codec?: string;
  envelope_len?: number;
  payload_len?: number;
  media_info?: MediaInfo;
  note?: string;
}

export interface StrategyId {
  id: number;
  name: string;
}

export interface DualInspect {
  carrier: string;
  format: string;
  has_hidden_data: boolean;
  strategy?: StrategyId;
  ube_offset?: number;
  ube_total_size?: number;
  is_encrypted?: boolean;
  is_compressed?: boolean;
  is_stealth?: boolean;
  password_hint?: string;
  orig_host_size?: number;
  orig_host_sha256?: string;
  metadata?: CarrierMetadata | { error: string };
  suspicious_hints?: string[];
  strategies: StrategyCapacity[];
  content_stego?: StegoHeaderInfo;
  content_error?: ErrorDetail;
  media_info?: MediaInfo;
}

export interface StegoCapacityInfo {
  format: string;
  algorithm: string;
  total_elements: number;
  available_slots: number;
  max_raw_payload_bytes: number;
  max_raw_is_grouped: boolean;
  recommended_max_bytes: number;
  estimated_change_rate: number;
  safety_level: SafetyLevel;
  safety_bpp_limit: number;
  is_estimated: boolean;
  media_info?: MediaInfo;
}

export interface StegoCapacityFullDto extends StegoCapacityInfo {
  paranoid_max_bytes: number;
  high_max_bytes: number;
  balanced_max_bytes: number;
}

export interface FileMetadataDto {
  path: string;
  filename: string;
  size_bytes: number;
  exists: boolean;
  is_file: boolean;
  is_dir: boolean;
  modified_ms?: number;
}

export interface EmbedStats {
  modified_slots: number;
  total_candidate_slots: number;
}

export interface StegoEmbedResult {
  carrier: string;
  written_to: string;
  format: string;
  payload_bytes: number;
  carrier_before_bytes: number;
  carrier_after_bytes: number;
  backup_file?: string;
  capacity?: StegoCapacityInfo;
  stats?: EmbedStats;
  warnings: Array<{
    kind: "safety_threshold_exceeded";
    payload_bytes: number;
    recommended_max_bytes: number;
    safety_level: string;
    actual_bpp: number;
    limit_bpp: number;
  }>;
}

export interface ReadSummary {
  carrier: string;
  is_file: boolean;
  is_encrypted: boolean;
  filename: string;
  raw_size: number;
  written_file?: string;
  text_preview?: string;
}

export interface ProgressEvent {
  taskId: string;
  stage: "read" | "decode" | "cost_map" | "solve" | "encode" | "write" | "verify";
  done: number;
  total: number | null;
  percent: number | null;
}



export type WriteWarning =
  | { kind: "size_inflation"; ube_size: number; host_size: number; ratio_pct: number }
  | { kind: "suspicious_structures"; hints: string[] };

export interface WriteResult {
  carrier: string;
  format: string;
  strategy: StrategyId;
  strategy_note?: string;
  raw_size: number;
  ube_size: number;
  is_encrypted: boolean;
  is_stealth: boolean;
  password_hint?: string;
  backup_file?: string;
  warnings: WriteWarning[];
}


export type FormatName = string;

export interface Capability {
  format: FormatName;
  structure: string[];
  stego: string[];
  extensions: string[];
  memory: "streaming" | "whole_file";
}



export type PayloadInputDto =
  | { kind: "text"; content: string }
  | { kind: "file"; path: string };

export interface StructureWriteRequest {
  carrier: string;
  payload: PayloadInputDto;
  output_path?: string;
  password?: string;
  password_hint?: string;
  strategy?: string;
  stealth: boolean;
  preserve_time: boolean;
  backup: boolean;
  overwrite: boolean;
}

export interface StegoEmbedRequest {
  carrier: string;
  payload: PayloadInputDto;
  output_path?: string;
  password?: string;
  domain?: string;
  safety_level: SafetyLevel;
  enforce_safety: boolean;
  algorithm?: string;
  backup: boolean;
  overwrite: boolean;
}

export interface SmartExtractSummaryDto {
  source: Domain;
  also_present?: Domain;
  summary: ReadSummary;
}



