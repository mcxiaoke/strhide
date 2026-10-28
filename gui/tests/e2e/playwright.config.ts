import { defineConfig } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  testDir: "./specs",
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: [
    ["list"],
  ],
  use: {
    headless: true,
    viewport: { width: 1240, height: 820 },
    actionTimeout: 10000,
  },
  webServer: {
    command: "pnpm dev",
    port: 1420,
    reuseExistingServer: true,
    cwd: path.resolve(__dirname, "../../"),
  },
});
