import { test as base, expect, Page } from "@playwright/test";

export interface MockDataOptions {
  /** dialog 返回的文件列表（多选时不支持的文件也会被前端跳过） */
  files?: string[];
  format?: string;
  hasHiddenData?: boolean;
  passwordHint?: string;
  /** probe_stego_capacity_cmd 失败，模拟不支持的视频流 */
  capacityError?: string;
  /** embed_stego_file_cmd / write_structure_file_cmd 失败 */
  embedError?: string;
  /** inspect_carrier_cmd 失败 */
  inspectError?: string;
  alsoPresent?: "structure" | "content";
  /** smart_extract 返回二进制文件而不是文本 */
  binaryPayload?: boolean;
}

export function createTauriMockScript(opts: MockDataOptions = {}) {
  const files = (opts.files ?? ["C:\\\\Samples\\\\photo.png"]).map((p) => p.replace(/\\\\/g, "\\"));

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

    const EXISTING = ${JSON.stringify(files)};

    window.__TAURI_INTERNALS__.invoke = async (cmd, args) => {
      if (cmd === "plugin:event|listen") return 1;

      if (cmd === "plugin:dialog|open") {
        const dialogOpts = (args && args.options) || args || {};
        if (dialogOpts.directory) return "C:\\\\Samples\\\\out";
        if (dialogOpts.multiple) return EXISTING;
        return EXISTING[0];
      }
      if (cmd === "plugin:dialog|save") return "C:\\\\Samples\\\\out\\\\payload.txt";
      if (cmd === "plugin:opener|open_path" || cmd === "plugin:opener|reveal_item_in_dir") return null;
      if (cmd === "set_ui_language_cmd") return args.lang;
      if (cmd === "cancel_task_cmd") return true;

      if (cmd === "get_capabilities_cmd") {
        return [
          { format: "PNG", structure: ["chunk", "eof"], stego: ["hill"], extensions: ["png"], memory: "whole_file" },
          { format: "JPEG", structure: ["eof"], stego: ["uerd"], extensions: ["jpg", "jpeg"], memory: "whole_file" },
          { format: "MP4", structure: ["box", "eof"], stego: ["hevc_cabac"], extensions: ["mp4", "mov"], memory: "streaming" },
          { format: "ZIP", structure: ["central_dir", "eof"], stego: [], extensions: ["zip"], memory: "streaming" },
          { format: "PDF", structure: ["eof"], stego: [], extensions: ["pdf"], memory: "streaming" }
        ];
      }

      if (cmd === "get_file_metadata_cmd") {
        if (EXISTING.includes(args.path)) {
          return {
            path: args.path,
            filename: args.path.split(/[\\\\/]/).pop(),
            size_bytes: 1234567,
            exists: true,
            is_file: true,
            is_dir: false,
            modified_ms: 1730000000000
          };
        }
        throw { kind: "io", detail: "No such file: " + args.path };
      }

      if (cmd === "probe_stego_capacity_cmd") {
        if (${opts.capacityError ? "true" : "false"}) {
          throw { kind: "unsupported_format", detail: "${opts.capacityError || ""}" };
        }
        return {
          format: "${opts.format || "PNG"}",
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
          safety_level: args.safetyLevel || "high",
          safety_bpp_limit: 0.1,
          is_estimated: false,
          media_info: { width: 1920, height: 1080 }
        };
      }

      if (cmd === "embed_stego_file_cmd") {
        if (${opts.embedError ? "true" : "false"}) {
          throw { kind: "rejection", detail: "${opts.embedError || ""}" };
        }
        return {
          carrier: args.req.carrier,
          written_to: args.req.output_path,
          format: "${opts.format || "PNG"}",
          payload_bytes: 1420,
          carrier_before_bytes: 1234567,
          carrier_after_bytes: 1234567,
          stats: { modified_slots: 1420, total_candidate_slots: 2073600 },
          warnings: []
        };
      }

      if (cmd === "write_structure_file_cmd") {
        if (${opts.embedError ? "true" : "false"}) {
          throw { kind: "rejection", detail: "${opts.embedError || ""}" };
        }
        return {
          carrier: args.req.output_path,
          format: "${opts.format || "PNG"}",
          strategy: { id: 2, name: "chunk" },
          raw_size: 18420,
          ube_size: 20480,
          is_encrypted: !!args.req.password,
          is_stealth: !!args.req.stealth,
          warnings: []
        };
      }

      if (cmd === "inspect_carrier_cmd") {
        if (${opts.inspectError ? "true" : "false"}) {
          throw { kind: "unsupported_format", detail: "${opts.inspectError || ""}" };
        }
        return {
          carrier: args.path,
          format: "${opts.format || "PNG"}",
          has_hidden_data: ${opts.hasHiddenData !== undefined ? opts.hasHiddenData : true},
          strategy: { id: 2, name: "chunk" },
          ube_offset: 1420,
          ube_total_size: 24576,
          is_encrypted: true,
          is_compressed: true,
          is_stealth: false,
          password_hint: "${opts.passwordHint || "year-1990"}",
          orig_host_size: 1234567,
          orig_host_sha256: "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
          metadata: {
            filename: "secret.txt",
            raw_size: 18420,
            raw_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            created_at: 1730000000
          },
          suspicious_hints: [],
          strategies: [
            { strategy: "chunk", capacity_bytes: 2097152, available: true, limit: "≤ 2 MiB" },
            { strategy: "eof", capacity_bytes: null, available: true, limit: "无上限" }
          ],
          content_stego: {
            format: "${opts.format || "PNG"}",
            has_hidden_data: ${opts.hasHiddenData !== undefined ? opts.hasHiddenData : true},
            algorithm: "HILL",
            codec: "STC",
            payload_len: 18420,
            media_info: { width: 1920, height: 1080 }
          },
          content_error: null,
          media_info: { width: 1920, height: 1080 }
        };
      }

      if (cmd === "smart_extract_cmd") {
        const isFile = ${opts.binaryPayload ? "true" : "false"} || !!args.outputPath;
        return {
          source: "structure",
          also_present: ${opts.alsoPresent ? `"${opts.alsoPresent}"` : "null"},
          summary: {
            carrier: args.path,
            is_file: isFile,
            is_encrypted: true,
            filename: "secret.txt",
            raw_size: 1420,
            written_file: args.outputPath || undefined,
            text_preview: isFile ? undefined : "会议纪要：本周完成隐写链路联调。"
          }
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
