import { defineConfig } from "@playwright/test";

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
});
