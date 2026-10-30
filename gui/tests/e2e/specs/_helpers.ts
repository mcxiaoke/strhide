import { test, expect, createTauriMockScript } from "../fixtures";
import type { Page } from "@playwright/test";

export const panel = (page: Page, id: string) => page.locator(`[data-panel="${id}"]`);

export const MIXED_FILES = [
  "C:\\\\Samples\\\\photo.png",
  "C:\\\\Samples\\\\clip.mp4",
  "C:\\\\Samples\\\\notes.txt",
];

/** 默认 mock：1 个 PNG 载体，容量 25.0 KB（high 档） */
export async function openApp(page: Page, options: Parameters<typeof createTauriMockScript>[0] = {}) {
  await page.addInitScript(createTauriMockScript(options));
  await page.goto("http://localhost:1420");
}

export async function goTab(page: Page, id: "stego" | "hide" | "extract" | "scan") {
  await page.locator(`[data-testid=tab-${id}]`).click();
}
