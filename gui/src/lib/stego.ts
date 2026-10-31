import type { SafetyLevel, StegoCapacityFullDto } from "../types/strhide";

export const SAFETY_LEVELS: SafetyLevel[] = ["paranoid", "high", "balanced"];

export const ALGORITHMS = ["auto", "hill", "suniward", "uerd", "juniward"];

export function tierLimit(capacity: StegoCapacityFullDto, tier: SafetyLevel): number {
  if (tier === "paranoid") return capacity.paranoid_max_bytes;
  if (tier === "balanced") return capacity.balanced_max_bytes;
  return capacity.high_max_bytes;
}
