import { test as base, expect, Page } from "@playwright/test";

export interface MockDataOptions {
  carrierPath?: string;
  hasHiddenData?: boolean;
  passwordHint?: string;
  suspiciousHints?: string[];
  riskScore?: number;
  verdict?: "clean" | "low" | "suspicious" | "likely-hidden";
  alsoPresent?: "structure" | "content";
  conflictOnEmbed?: boolean;
  format?: string;
  contentError?: string;
  inspectError?: string;
}

export function createTauriMockScript(opts: MockDataOptions = {}) {
  return `
    window.__TAURI_INTERNALS__ = window.__TAURI_INTERNALS__ || {};
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = window.__TAURI_EVENT_PLUGIN_INTERNALS__ || {};
    
    window.__TAURI_INTERNALS__.metadata = {
      currentWindow: { label: "main" },
      currentWebview: { windowLabel: "main", label: "main" }
    };

    const callbacks = new Map();
    window.__TAURI_INTERNALS__.callbacks = callbacks;
    window.__TAURI_INTERNALS__.transformCallback = (cb, once) => {
      const id = Math.floor(Math.random() * 1000000);
      callbacks.set(id, (data) => {
        if (once) callbacks.delete(id);
        return cb && cb(data);
      });
      return id;
    };
    window.__TAURI_INTERNALS__.unregisterCallback = (id) => callbacks.delete(id);
    window.__TAURI_INTERNALS__.runCallback = (id, data) => {
      const cb = callbacks.get(id);
      if (cb) cb(data);
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener = () => {};

    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      // console.log("[MOCK IPC]", cmd, args);

      if (cmd === "plugin:event|listen") {
        return 1;
      }
      if (cmd === "plugin:dialog|open") {
        if (args && args.multiple) {
          return ["${opts.carrierPath || "C:\\\\Samples\\\\secret_image.png"}"];
        }
        return "${opts.carrierPath || "C:\\\\Samples\\\\secret_image.png"}";
      }
      if (cmd === "plugin:dialog|save") {
        return "C:\\\\Samples\\\\extracted_payload.txt";
      }
      if (cmd === "plugin:opener|open_path" || cmd === "plugin:opener|reveal_item_in_dir") {
        return null;
      }
      if (cmd === "set_ui_language_cmd") {
        return args.lang;
      }
      if (cmd === "cancel_task_cmd") {
        return true;
      }

      if (cmd === "get_capabilities_cmd") {
        return [
          {
            format: "PNG",
            structure: ["chunk", "eof"],
            stego: ["png_spatial"],
            extensions: ["png"],
            memory: "whole_file"
          },
          {
            format: "JPEG",
            structure: ["eof"],
            stego: ["jpeg_dct"],
            extensions: ["jpg", "jpeg"],
            memory: "whole_file"
          },
          {
            format: "MP4",
            structure: ["box", "eof"],
            stego: ["hevc_cabac"],
            extensions: ["mp4", "mov"],
            memory: "streaming"
          },
          {
            format: "ZIP",
            structure: ["central_dir", "eof"],
            stego: [],
            extensions: ["zip"],
            memory: "streaming"
          }
        ];
      }

      if (cmd === "inspect_carrier_cmd") {
        if (${opts.inspectError ? `true` : `false`}) {
          throw {
            kind: "unsupported_format",
            detail: "${opts.inspectError || "Unsupported format"}"
          };
        }
        return {
          carrier: args.path || "C:\\\\Samples\\\\secret_image.png",
          format: "${opts.format || "PNG"}",
          has_hidden_data: ${opts.hasHiddenData !== undefined ? opts.hasHiddenData : true},
          strategy: { id: 2, name: "chunk" },
          ube_offset: 1420,
          ube_total_size: 24576,
          is_encrypted: true,
          is_compressed: true,
          is_stealth: false,
          password_hint: "${opts.passwordHint || "my-safe-key"}",
          orig_host_size: 1428570,
          orig_host_sha256: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
          metadata: {
            filename: "secret_document.txt",
            raw_size: 18420,
            raw_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            created_at: 1730000000
          },
          suspicious_hints: ${JSON.stringify(opts.suspiciousHints || [])},
          strategies: [
            {
              strategy: "chunk",
              capacity_bytes: 2097152,
              available: true,
              limit: "≤ 2,097,152 B (2 MiB)"
            },
            {
              strategy: "eof",
              capacity_bytes: null,
              available: true,
              limit: "无上限 (文件增长)"
            }
          ],
          content_stego: ${opts.contentError ? `null` : `{
            format: "${opts.format || "PNG"}",
            has_hidden_data: ${opts.hasHiddenData !== undefined ? opts.hasHiddenData : true},
            algorithm: "HILL",
            codec: "STC (h=7, u=2)",
            payload_len: 18420,
            media_info: {
              width: 1920,
              height: 1080
            }
          }`},
          content_error: ${opts.contentError ? `{
            kind: "unsupported_format",
            detail: "${opts.contentError}"
          }` : `null`},
          media_info: {
            width: 1920,
            height: 1080
          }
        };
      }

      if (cmd === "get_file_metadata_cmd") {
        return {
          path: args.path || "C:\\\\Samples\\\\secret.txt",
          filename: "secret.txt",
          size_bytes: 4096,
          exists: true,
          is_file: true,
          is_dir: false,
          modified_ms: Date.now()
        };
      }

      if (cmd === "probe_stego_capacity_cmd") {
        if (${opts.contentError ? `true` : `false`}) {
          throw {
            kind: "unsupported_format",
            detail: "${opts.contentError || "Unsupported format"}"
          };
        }
        return {
          format: "PNG",
          algorithm: "HILL",
          total_elements: 2073600,
          available_slots: 1555200,
          max_raw_payload_bytes: 64000,
          max_raw_is_grouped: false,
          recommended_max_bytes: 25600,
          paranoid_max_bytes: 15360,
          high_max_bytes: 25600,
          balanced_max_bytes: 38400,
          estimated_change_rate: 0.08,
          safety_level: args.safety_level || "high",
          safety_bpp_limit: 0.10,
          is_estimated: false,
          media_info: { width: 1920, height: 1080 }
        };
      }

      if (cmd === "smart_extract_cmd") {
        return {
          source: "structure",
          also_present: ${opts.alsoPresent ? `"${opts.alsoPresent}"` : "undefined"},
          summary: {
            carrier: args.path || "C:\\\\Samples\\\\secret_image.png",
            is_file: false,
            is_encrypted: true,
            filename: "secret_document.txt",
            raw_size: 1420,
            text_preview: "Confidential Report 2026:\\nProject StrHide successfully implemented lossless format-preserving data hiding!\\nAll bytes verified bit-exact identical."
          }
        };
      }

      if (cmd === "embed_stego_file_cmd") {
        if (${opts.conflictOnEmbed === true}) {
          throw {
            kind: "already_exists",
            detail: args.req.carrier
          };
        }
        return {
          carrier: args.req.carrier,
          written_to: args.req.carrier,
          format: "PNG",
          payload_bytes: 1420,
          carrier_before_bytes: 1428570,
          carrier_after_bytes: 1428570,
          capacity: {
            format: "PNG",
            algorithm: "HILL",
            total_elements: 2073600,
            available_slots: 1555200,
            max_raw_payload_bytes: 64000,
            max_raw_is_grouped: false,
            recommended_max_bytes: 25600,
            estimated_change_rate: 0.08,
            safety_level: "high",
            safety_bpp_limit: 0.10,
            is_estimated: false
          },
          stats: {
            modified_slots: 1420,
            total_candidate_slots: 2073600
          },
          warnings: []
        };
      }

      if (cmd === "verify_carrier_cmd") {
        return {
          carrier: args.path || "C:\\\\Samples\\\\secret_image.png",
          format: "PNG",
          level1_host: { ok: true, detail: "PNG structure valid (IHDR, IDAT, IEND CRCs verified bit-exact)", skipped: false },
          level2_envelope: { ok: true, detail: "UBE Envelope Header & Trailer magic/CRC32 verified consistent", skipped: false },
          level3_crypto: { ok: true, detail: "AES-256-GCM authentication tag and payload SHA-256 100% verified", skipped: false },
          content_stego: {
            format: "PNG",
            levels: [
              { level: 1, name: "Header Signature", ok: true },
              { level: 2, name: "STC Syndrome Parity", ok: true }
            ]
          }
        };
      }

      if (cmd === "restore_structure_file_cmd") {
        return {
          carrier: args.path || "C:\\\\Samples\\\\secret_image.png",
          restored_size: 1428570,
          restored_sha256: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
          verified_identical: true,
          backup_file: (args.path || "C:\\\\Samples\\\\secret_image.png") + ".bak"
        };
      }

      if (cmd === "scan_carrier_cmd") {
        return {
          carrier: args.path || "C:\\\\Samples\\\\secret_image.png",
          format: "PNG",
          file_size: 1428570,
          risk_score: ${opts.riskScore !== undefined ? opts.riskScore : 18},
          verdict: "${opts.verdict || "low"}",
          findings: [
            { detector: "png:trailing-data", severity: "info", detail: "No appended data after IEND" }
          ],
          notes: [
            "Ternary +/-1 steganography (HILL/STC) produces minimal histogram distortion; RS analysis sensitivity is bounded."
          ],
          detectors: [
            { name: "png:trailing-data", domain: "structural", status: "PASS", metric: "0 B", threshold: "> 0 B", detail: "Clean IEND terminator" },
            { name: "png:known-signatures", domain: "signature", status: "PASS", metric: "0 hits", threshold: "0", detail: "No foreign tool signatures detected" },
            { name: "png:chi2-spatial", domain: "spatial", status: "PASS", metric: "p=0.482", threshold: "p < 0.05", detail: "Pair of values distribution is uniform" },
            { name: "png:rs-analysis", domain: "spatial", status: "PASS", metric: "alpha=0.012", threshold: "alpha > 0.05", detail: "Regular/Singular group smoothness variance is low" }
          ]
        };
      }

      if (cmd === "run_batch_job_cmd") {
        return {
          items: (args.items || []).map((it, idx) => ({
            index: idx,
            item: it,
            result: { Ok: { status: "processed", format: "PNG" } },
            elapsed_ms: 12 + idx * 8
          })),
          succeeded: (args.items || []).length,
          failed: 0,
          cancelled: false
        };
      }

      return null;
    };
  `;
}

export const test = base.extend<{
  appPage: Page;
}>({
  appPage: async ({ page }, use) => {
    await page.goto("http://localhost:1420");
    await use(page);
  },
});

export { expect };
