import { defineConfig } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  testDir: "./specs",
  timeout: 45000,
  expect: {
    timeout: 15000,
  },
  fullyParallel: false,
  workers: 1, // 真实桌面单进程串行测试
  reporter: [["list"]],
  use: {
    headless: false,
    actionTimeout: 15000,
  },
  webServer: {
    command: "pnpm dev",
    port: 1420,
    reuseExistingServer: true,
    cwd: path.resolve(__dirname, "../../"),
  },
});
