import { test as base, expect, chromium, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(__dirname, "../../..");
export const exePath = path.resolve(projectRoot, "gui/src-tauri/target/release/StrHideStudio.exe");

export interface RealAppFixture {
  page: Page;
  proc: ChildProcess;
  scratchDir: string;
  dropFiles: (paths: string[]) => Promise<void>;
  goTab: (tab: "stego" | "hide" | "extract" | "scan") => Promise<void>;
  panel: (id: "stego" | "hide" | "extract" | "scan") => ReturnType<Page["locator"]>;
}

export const test = base.extend<{ realApp: RealAppFixture }>({
  realApp: async ({}, use) => {
    if (!fs.existsSync(exePath)) {
      throw new Error(`StrHideStudio.exe not found at ${exePath}. Run 'pnpm tauri build --no-bundle' first.`);
    }

    const testId = Date.now() + "_" + Math.floor(Math.random() * 10000);
    const scratchDir = path.resolve(projectRoot, `temp/real_e2e_${testId}`);
    fs.mkdirSync(scratchDir, { recursive: true });

    // Pick a free-ish debugging port to avoid collision
    const port = 9300 + Math.floor(Math.random() * 500);

    const proc = spawn(exePath, [], {
      env: {
        ...process.env,
        WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
      },
      stdio: "ignore",
    });

    // Wait for CDP readiness
    let connected = false;
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 400));
      try {
        const res = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (res.ok) {
          connected = true;
          break;
        }
      } catch (e) {
        // waiting
      }
    }

    if (!connected) {
      proc.kill();
      throw new Error(`Failed to connect to CDP port ${port} on StrHideStudio.exe`);
    }

    const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    const context = browser.contexts()[0];
    const page = context.pages()[0] || (await context.waitForEvent("page"));

    const dropFiles = async (paths: string[]) => {
      await page.evaluate((fileList) => {
        window.dispatchEvent(
          new CustomEvent("strhide:drop-files", { detail: { paths: fileList } }),
        );
      }, paths);
      await page.waitForTimeout(500);
    };

    const goTab = async (tab: "stego" | "hide" | "extract" | "scan") => {
      await page.locator(`[data-testid=tab-${tab}]`).click();
      await page.waitForTimeout(300);
    };

    const panel = (id: "stego" | "hide" | "extract" | "scan") => {
      return page.locator(`[data-panel="${id}"]`);
    };

    await use({
      page,
      proc,
      scratchDir,
      dropFiles,
      goTab,
      panel,
    });

    try {
      await browser.close();
    } catch (e) {}
    try {
      if (proc.pid) {
        // Windows 强杀整棵子进程树，避免残留后台 WebView2 实例
        const { execSync } = await import("node:child_process");
        try {
          execSync(`taskkill /pid ${proc.pid} /T /F`, { stdio: "ignore" });
        } catch (_) {
          proc.kill();
        }
      } else {
        proc.kill();
      }
    } catch (e) {}
    try {
      if (fs.existsSync(scratchDir)) {
        fs.rmSync(scratchDir, { recursive: true, force: true });
      }
    } catch (e) {}
  },
});

export { expect };
