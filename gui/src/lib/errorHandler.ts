import type { ErrorDetail } from "../types/strhide";
import { fmt, type Dict } from "./i18n";

export interface ParsedError {
  title: string;
  message: string;
  hint?: string;
  isCancelled: boolean;
  isPasswordError: boolean;
  isAlreadyExists: boolean;
  isTargetBusy: boolean;
}

/**
 * 把后端返回的结构化错误翻译成面向用户的提示。
 * 文案统一走 `dict.errors`，两者都保持陈述句、只说后果和下一步，不解释内部机制。
 */
export function parseStrHideError(err: unknown, dict: Dict): ParsedError {
  const e = dict.errors;

  if (typeof err === "object" && err !== null && "kind" in err) {
    const detail = err as ErrorDetail;
    const isCancelled = detail.kind === "cancelled";
    const isPasswordError = detail.kind === "password" || detail.kind === "password_with_hint";
    const isAlreadyExists = detail.kind === "already_exists";
    const isTargetBusy = detail.kind === "target_busy";

    let title = detail.category_label || e.failed;
    let message = detail.detail;

    switch (detail.kind) {
      case "already_exists":
        title = e.alreadyExistsTitle;
        message = fmt(e.alreadyExists, { path: detail.detail });
        break;
      case "target_busy":
        title = e.targetBusyTitle;
        message = e.targetBusy;
        break;
      case "password":
      case "password_with_hint":
        title = e.passwordTitle;
        message = e.password;
        break;
      case "safety_threshold":
        title = e.safetyTitle;
        message = e.safety;
        break;
      case "restore_mismatch":
        title = e.restoreTitle;
        message = e.restore;
        break;
      case "no_hidden_data":
        title = e.noHiddenTitle;
        message = e.noHidden;
        break;
      case "cancelled":
        title = e.cancelledTitle;
        message = e.cancelled;
        break;
    }

    return {
      title,
      message,
      hint: detail.hint,
      isCancelled,
      isPasswordError,
      isAlreadyExists,
      isTargetBusy,
    };
  }

  const rawMsg = err instanceof Error ? err.message : String(err);
  return {
    title: e.unknownTitle,
    message: rawMsg,
    isCancelled: false,
    isPasswordError: false,
    isAlreadyExists: false,
    isTargetBusy: false,
  };
}
