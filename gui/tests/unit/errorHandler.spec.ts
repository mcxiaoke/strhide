import { test, expect } from "@playwright/test";
import { parseStrHideError } from "../../src/lib/errorHandler";
import { t } from "../../src/lib/i18n";
import type { ErrorDetail } from "../../src/types/strhide";

test.describe("GUI parseStrHideError & Structured Error Classification (I6)", () => {
  const dictZh = t("zh");
  const dictEn = t("en");

  test.describe("Capacity and Safety Threshold Errors (Skip Classification)", () => {
    test("safety_threshold maps to safety title and sets isCapacityOrSafety to true", () => {
      const err: ErrorDetail = {
        kind: "safety_threshold",
        detail: "payload cost 120 exceeds threshold 100",
      };

      const parsedZh = parseStrHideError(err, dictZh);
      expect(parsedZh.kind).toBe("safety_threshold");
      expect(parsedZh.isCapacityOrSafety).toBe(true);
      expect(parsedZh.title).toBe(dictZh.errors.safetyTitle);
      expect(parsedZh.message).toBe(dictZh.errors.safety);

      const parsedEn = parseStrHideError(err, dictEn);
      expect(parsedEn.isCapacityOrSafety).toBe(true);
      expect(parsedEn.title).toBe(dictEn.errors.safetyTitle);
      expect(parsedEn.message).toBe(dictEn.errors.safety);
    });

    test("payload_too_large maps to safety title and sets isCapacityOrSafety to true", () => {
      const err: ErrorDetail = {
        kind: "payload_too_large",
        detail: "Payload 500 bytes exceeds carrier capacity 260 bytes",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("payload_too_large");
      expect(parsed.isCapacityOrSafety).toBe(true);
      expect(parsed.title).toBe(dictZh.errors.safetyTitle);
      expect(parsed.message).toBe("Payload 500 bytes exceeds carrier capacity 260 bytes");
    });

    test("trellis_infeasible maps to safety title and sets isCapacityOrSafety to true", () => {
      const err: ErrorDetail = {
        kind: "trellis_infeasible",
        detail: "Trellis path not found within distortion budget",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("trellis_infeasible");
      expect(parsed.isCapacityOrSafety).toBe(true);
      expect(parsed.title).toBe(dictZh.errors.safetyTitle);
      expect(parsed.message).toBe("Trellis path not found within distortion budget");
    });
  });

  test.describe("Operational & Security Errors (Error Classification)", () => {
    test("already_exists formats target path and isCapacityOrSafety is false", () => {
      const err: ErrorDetail = {
        kind: "already_exists",
        detail: "C:/output/photo_stego.jpg",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("already_exists");
      expect(parsed.isAlreadyExists).toBe(true);
      expect(parsed.isCapacityOrSafety).toBe(false);
      expect(parsed.title).toBe(dictZh.errors.alreadyExistsTitle);
      expect(parsed.message).toContain("C:/output/photo_stego.jpg");
    });

    test("target_busy marks isTargetBusy and isCapacityOrSafety is false", () => {
      const err: ErrorDetail = {
        kind: "target_busy",
        detail: "Carrier file is locked by media player",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("target_busy");
      expect(parsed.isTargetBusy).toBe(true);
      expect(parsed.isCapacityOrSafety).toBe(false);
      expect(parsed.title).toBe(dictZh.errors.targetBusyTitle);
      expect(parsed.message).toBe(dictZh.errors.targetBusy);
    });

    test("password and password_with_hint preserve hints and mark isPasswordError", () => {
      const err1: ErrorDetail = {
        kind: "password",
        detail: "HMAC authentication failed",
      };
      const parsed1 = parseStrHideError(err1, dictZh);
      expect(parsed1.kind).toBe("password");
      expect(parsed1.isPasswordError).toBe(true);
      expect(parsed1.isCapacityOrSafety).toBe(false);
      expect(parsed1.title).toBe(dictZh.errors.passwordTitle);

      const err2: ErrorDetail = {
        kind: "password_with_hint",
        detail: "HMAC auth failed",
        hint: "My cat's birthday",
      };
      const parsed2 = parseStrHideError(err2, dictZh);
      expect(parsed2.kind).toBe("password_with_hint");
      expect(parsed2.isPasswordError).toBe(true);
      expect(parsed2.hint).toBe("My cat's birthday");
      expect(parsed2.isCapacityOrSafety).toBe(false);
    });

    test("cancelled marks isCancelled and isCapacityOrSafety is false", () => {
      const err: ErrorDetail = {
        kind: "cancelled",
        detail: "Task cancelled by user",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("cancelled");
      expect(parsed.isCancelled).toBe(true);
      expect(parsed.isCapacityOrSafety).toBe(false);
      expect(parsed.title).toBe(dictZh.errors.cancelledTitle);
      expect(parsed.message).toBe(dictZh.errors.cancelled);
    });

    test("io / corrupted_data uses category_label or failed fallback", () => {
      const err: ErrorDetail = {
        kind: "io",
        category_label: "文件读取失败",
        detail: "Permission denied (os error 5)",
      };

      const parsed = parseStrHideError(err, dictZh);
      expect(parsed.kind).toBe("io");
      expect(parsed.title).toBe("文件读取失败");
      expect(parsed.message).toBe("Permission denied (os error 5)");
      expect(parsed.isCapacityOrSafety).toBe(false);
    });
  });

  test.describe("Fallback / Non-structured Errors", () => {
    test("generic Error instance without capacity keywords", () => {
      const parsed = parseStrHideError(new Error("Network timeout"), dictZh);
      expect(parsed.kind).toBeUndefined();
      expect(parsed.title).toBe(dictZh.errors.unknownTitle);
      expect(parsed.message).toBe("Network timeout");
      expect(parsed.isCapacityOrSafety).toBe(false);
    });

    test("generic Error instance with capacity / threshold keywords triggers isCapacityOrSafety fallback", () => {
      const parsed = parseStrHideError(new Error("Carrier capacity exhausted"), dictZh);
      expect(parsed.isCapacityOrSafety).toBe(true);

      const parsedThreshold = parseStrHideError(new Error("Safety threshold limit reached"), dictZh);
      expect(parsedThreshold.isCapacityOrSafety).toBe(true);
    });
  });
});
