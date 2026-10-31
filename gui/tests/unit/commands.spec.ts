import { test, expect } from "@playwright/test";

// Polyfill window for Node.js test environment (required by @tauri-apps/api)
(globalThis as any).window = globalThis;

import { mockIPC, clearMocks } from "@tauri-apps/api/mocks";
import {
  getCapabilities,
  getFileMetadata,
  inspectCarrier,
  writeStructureFile,
  probeStegoCapacity,
  embedStegoFile,
  smartExtract,
  setUiLanguage,
  cancelTask,
} from "../../src/api/commands";
import type {
  PayloadInputDto,
  StegoEmbedRequest,
  StructureWriteRequest,
  SafetyLevel,
} from "../../src/types/strhide";

test.describe("GUI Core Commands & Parameters Verification", () => {
  let capturedCmd = "";
  let capturedArgs: any = null;

  test.beforeEach(() => {
    capturedCmd = "";
    capturedArgs = null;
    mockIPC((cmd, args) => {
      capturedCmd = cmd;
      capturedArgs = args;

      if (cmd === "embed_stego_file_cmd") {
        return {
          carrier: args.req?.carrier,
          written_to: args.req?.output_path || args.req?.carrier,
          format: "JPEG",
          payload_bytes: 381,
          carrier_before_bytes: 45197,
          carrier_after_bytes: 46979,
          warnings: [],
        };
      }
      if (cmd === "smart_extract_cmd") {
        return {
          source: "content",
          also_present: undefined,
          summary: {
            carrier: args.path,
            is_file: false,
            is_encrypted: !!args.password,
            filename: "payload.txt",
            raw_size: 381,
            written_file: args.outputPath,
            text_preview: "测试公开信息内容",
          },
        };
      }
      if (cmd === "probe_stego_capacity_cmd") {
        return {
          format: "JPEG",
          algorithm: args.algorithm || "UERD",
          total_elements: 2420000,
          available_slots: 1200000,
          max_raw_payload_bytes: 300000,
          max_raw_is_grouped: false,
          recommended_max_bytes: 30000,
          paranoid_max_bytes: 18000,
          high_max_bytes: 30000,
          balanced_max_bytes: 45000,
          estimated_change_rate: 0.05,
          safety_level: args.safetyLevel || "high",
          safety_bpp_limit: 0.1,
          is_estimated: !args.exact,
        };
      }
      if (cmd === "write_structure_file_cmd") {
        return {
          carrier: args.req?.output_path || args.req?.carrier,
          format: "PNG",
          strategy: { id: 1, name: "chunk" },
          raw_size: 100,
          ube_size: 200,
          is_encrypted: !!args.req?.password,
          is_stealth: !!args.req?.stealth,
          warnings: [],
        };
      }
      if (cmd === "inspect_carrier_cmd") {
        return {
          carrier: args.path,
          format: "JPEG",
          has_hidden_data: true,
          strategies: [],
        };
      }
      if (cmd === "get_capabilities_cmd") {
        return [{ format: "JPEG", structure: ["eof"], stego: ["uerd"], extensions: ["jpg"], memory: "whole_file" }];
      }
      if (cmd === "get_file_metadata_cmd") {
        return { path: args.path, filename: "test.jpg", size_bytes: 50000, exists: true, is_file: true, is_dir: false };
      }
      if (cmd === "set_ui_language_cmd") {
        return args.lang;
      }
      if (cmd === "cancel_task_cmd") {
        return true;
      }
    });
  });

  test.afterEach(() => {
    clearMocks();
  });

  // =========================================================================
  // 1. embedStegoFile: 各种参数组合测试
  // =========================================================================
  test.describe("embedStegoFile parameter combinations", () => {
    test("组合 1：中文文本 + 中文密码（复现并验证本次修复的核心场景）", async () => {
      const chineseText = "根据目前公开信息，这项“禁止复刻特定现有游戏”的限制仅明确针对 Opus 5.5";
      const chinesePassword = "根据目前公开信息";

      const req: StegoEmbedRequest = {
        carrier: "C:\\Home\\Projects\\strhide\\temp\\jpgtest\\art002e004437~large.jpg",
        payload: { kind: "text", content: chineseText },
        output_path: "C:\\Home\\Projects\\strhide\\temp\\jpgtest\\art002e004437~large_stego.jpg",
        password: chinesePassword,
        domain: undefined, // 关键：必须为 undefined，绝不能是 "content"
        safety_level: "high",
        enforce_safety: false,
        algorithm: undefined, // auto 转换为 undefined
        backup: false,
        overwrite: false,
      };

      const res = await embedStegoFile("task-cn-stego", req);

      expect(capturedCmd).toBe("embed_stego_file_cmd");
      expect(capturedArgs.taskId).toBe("task-cn-stego");
      expect(capturedArgs.req.carrier).toBe(req.carrier);
      expect(capturedArgs.req.payload).toEqual({ kind: "text", content: chineseText });
      expect(capturedArgs.req.output_path).toBe(req.output_path);
      expect(capturedArgs.req.password).toBe("根据目前公开信息");

      // 核心断言：domain 必须为 undefined，防止再次引入密码学隔离域错误
      expect(capturedArgs.req.domain).toBeUndefined();
      expect(capturedArgs.req.domain).not.toBe("content");

      expect(capturedArgs.req.safety_level).toBe("high");
      expect(capturedArgs.req.enforce_safety).toBe(false);
      expect(capturedArgs.req.algorithm).toBeUndefined();
      expect(res.written_to).toBe(req.output_path);
    });

    test("组合 2：英文文本 + 英文密码 + 指定算法 uerd + 严格安全限制", async () => {
      const req: StegoEmbedRequest = {
        carrier: "F:\\Temp\\test2\\art002e004437~large.jpg",
        payload: { kind: "text", content: "English payload content" },
        output_path: "F:\\Temp\\test2\\art002e004437~large_stego.jpg",
        password: "pwd123456",
        domain: undefined,
        safety_level: "paranoid",
        enforce_safety: true,
        algorithm: "uerd",
        backup: false,
        overwrite: true,
      };

      await embedStegoFile("task-en-stego", req);

      expect(capturedArgs.req.password).toBe("pwd123456");
      expect(capturedArgs.req.domain).toBeUndefined();
      expect(capturedArgs.req.safety_level).toBe("paranoid");
      expect(capturedArgs.req.enforce_safety).toBe(true);
      expect(capturedArgs.req.algorithm).toBe("uerd");
      expect(capturedArgs.req.overwrite).toBe(true);
    });

    test("组合 3：文件 Payload + 无密码（password: undefined）+ 算法 hill", async () => {
      const req: StegoEmbedRequest = {
        carrier: "C:\\Images\\photo.png",
        payload: { kind: "file", path: "C:\\Secrets\\secret.zip" },
        output_path: "C:\\Images\\photo_stego.png",
        password: undefined,
        domain: undefined,
        safety_level: "balanced",
        enforce_safety: false,
        algorithm: "hill",
        backup: true,
        overwrite: false,
      };

      await embedStegoFile("task-file-stego", req);

      expect(capturedArgs.req.payload).toEqual({ kind: "file", path: "C:\\Secrets\\secret.zip" });
      expect(capturedArgs.req.password).toBeUndefined();
      expect(capturedArgs.req.domain).toBeUndefined();
      expect(capturedArgs.req.safety_level).toBe("balanced");
      expect(capturedArgs.req.algorithm).toBe("hill");
      expect(capturedArgs.req.backup).toBe(true);
    });

    test("组合 4：密码空字符串转 undefined 处理验证", async () => {
      // 模拟前端 UI 输入框逻辑：password || undefined
      const rawPasswordInput = "";
      const normalizedPassword = rawPasswordInput || undefined;

      const req: StegoEmbedRequest = {
        carrier: "test.jpg",
        payload: { kind: "text", content: "data" },
        password: normalizedPassword,
        domain: undefined,
        safety_level: "high",
        enforce_safety: false,
        algorithm: undefined,
        backup: false,
        overwrite: false,
      };

      await embedStegoFile("task-empty-pwd", req);
      expect(capturedArgs.req.password).toBeUndefined();
      expect(capturedArgs.req.domain).toBeUndefined();
    });
  });

  // =========================================================================
  // 2. smartExtract: 各种参数组合测试
  // =========================================================================
  test.describe("smartExtract parameter combinations", () => {
    test("组合 1：带中文密码 + 提取到文件 + domain 为 undefined", async () => {
      const res = await smartExtract(
        "task-extract-cn",
        "C:\\Home\\Projects\\strhide\\temp\\jpgtest\\art002e004437~large_stego.jpg",
        "C:\\Home\\Projects\\strhide\\temp\\jpgtest\\out_payload.txt",
        "根据目前公开信息",
        undefined, // domain 默认为 undefined
        undefined, // prefer 默认为 undefined
        true, // overwrite
      );

      expect(capturedCmd).toBe("smart_extract_cmd");
      expect(capturedArgs.taskId).toBe("task-extract-cn");
      expect(capturedArgs.path).toBe("C:\\Home\\Projects\\strhide\\temp\\jpgtest\\art002e004437~large_stego.jpg");
      expect(capturedArgs.outputPath).toBe("C:\\Home\\Projects\\strhide\\temp\\jpgtest\\out_payload.txt");
      expect(capturedArgs.password).toBe("根据目前公开信息");
      expect(capturedArgs.domain).toBeUndefined();
      expect(capturedArgs.prefer).toBeUndefined();
      expect(capturedArgs.overwrite).toBe(true);
      expect(res.source).toBe("content");
    });

    test("组合 2：无密码 + 无 outputPath（提取到内存预览）+ prefer content", async () => {
      const res = await smartExtract(
        "task-extract-preview",
        "photo_stego.jpg",
        undefined,
        undefined,
        undefined,
        "content",
        false,
      );

      expect(capturedArgs.outputPath).toBeUndefined();
      expect(capturedArgs.password).toBeUndefined();
      expect(capturedArgs.domain).toBeUndefined();
      expect(capturedArgs.prefer).toBe("content");
      expect(res.summary.text_preview).toBeDefined();
    });

    test("组合 3：英文密码 + prefer structure", async () => {
      await smartExtract(
        "task-extract-struct",
        "file_hidden.zip",
        "out.bin",
        "pwd123456",
        undefined,
        "structure",
        false,
      );

      expect(capturedArgs.password).toBe("pwd123456");
      expect(capturedArgs.domain).toBeUndefined();
      expect(capturedArgs.prefer).toBe("structure");
    });
  });

  // =========================================================================
  // 3. probeStegoCapacity: 各种参数组合测试
  // =========================================================================
  test.describe("probeStegoCapacity parameter combinations", () => {
    test("组合 1：默认参数（high, 无密码, auto 算法, exact: false）", async () => {
      const cap = await probeStegoCapacity("task-cap-1", "sample.jpg");

      expect(capturedCmd).toBe("probe_stego_capacity_cmd");
      expect(capturedArgs.path).toBe("sample.jpg");
      expect(capturedArgs.safetyLevel).toBe("high");
      expect(capturedArgs.password).toBeUndefined();
      expect(capturedArgs.domain).toBeUndefined();
      expect(capturedArgs.algorithm).toBeUndefined();
      expect(capturedArgs.exact).toBe(false);
      expect(cap.format).toBe("JPEG");
    });

    test("组合 2：带中文密码 + 指定算法 uerd + exact 扫描", async () => {
      await probeStegoCapacity(
        "task-cap-2",
        "sample.jpg",
        "paranoid",
        "根据目前公开信息",
        undefined,
        "uerd",
        true,
      );

      expect(capturedArgs.safetyLevel).toBe("paranoid");
      expect(capturedArgs.password).toBe("根据目前公开信息");
      expect(capturedArgs.domain).toBeUndefined();
      expect(capturedArgs.algorithm).toBe("uerd");
      expect(capturedArgs.exact).toBe(true);
    });
  });

  // =========================================================================
  // 4. writeStructureFile: 结构隐写参数组合测试
  // =========================================================================
  test.describe("writeStructureFile parameter combinations", () => {
    test("组合 1：文本 Payload + 密码 + password_hint（常规隐写）", async () => {
      const req: StructureWriteRequest = {
        carrier: "doc.pdf",
        payload: { kind: "text", content: "secret memo" },
        output_path: "doc_hidden.pdf",
        password: "my-password",
        password_hint: "birthday year",
        strategy: undefined,
        stealth: false,
        preserve_time: true,
        backup: false,
        overwrite: false,
      };

      const res = await writeStructureFile("task-struct-1", req);

      expect(capturedCmd).toBe("write_structure_file_cmd");
      expect(capturedArgs.req.carrier).toBe("doc.pdf");
      expect(capturedArgs.req.password).toBe("my-password");
      expect(capturedArgs.req.password_hint).toBe("birthday year");
      expect(capturedArgs.req.stealth).toBe(false);
      expect(capturedArgs.req.preserve_time).toBe(true);
      expect(res.carrier).toBe("doc_hidden.pdf");
    });

    test("组合 2：隐蔽模式（stealth: true，无 password_hint）", async () => {
      const req: StructureWriteRequest = {
        carrier: "doc.png",
        payload: { kind: "file", path: "secret.bin" },
        password: "secure-pwd",
        password_hint: undefined,
        stealth: true,
        preserve_time: true,
        backup: false,
        overwrite: true,
      };

      await writeStructureFile("task-struct-2", req);

      expect(capturedArgs.req.stealth).toBe(true);
      expect(capturedArgs.req.password_hint).toBeUndefined();
    });
  });

  // =========================================================================
  // 5. 辅助与诊断命令测试
  // =========================================================================
  test.describe("Auxiliary and Diagnostic Commands", () => {
    test("inspectCarrier 参数验证", async () => {
      await inspectCarrier("carrier.jpg", "test-pwd", undefined);
      expect(capturedCmd).toBe("inspect_carrier_cmd");
      expect(capturedArgs.path).toBe("carrier.jpg");
      expect(capturedArgs.password).toBe("test-pwd");
      expect(capturedArgs.domain).toBeUndefined();
    });

    test("getCapabilities / getFileMetadata / setUiLanguage / cancelTask 验证", async () => {
      const caps = await getCapabilities();
      expect(capturedCmd).toBe("get_capabilities_cmd");
      expect(caps.length).toBeGreaterThan(0);

      const meta = await getFileMetadata("test.jpg");
      expect(capturedCmd).toBe("get_file_metadata_cmd");
      expect(meta.filename).toBe("test.jpg");

      const lang = await setUiLanguage("zh");
      expect(capturedCmd).toBe("set_ui_language_cmd");
      expect(lang).toBe("zh");

      const cancelled = await cancelTask("task-123");
      expect(capturedCmd).toBe("cancel_task_cmd");
      expect(cancelled).toBe(true);
    });
  });
});
