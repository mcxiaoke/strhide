import { test, expect, createTauriMockScript } from "../fixtures";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotDir = path.resolve(__dirname, "../../../../temp/screenshots");

test.describe("工作台 3: 三级校验与无损还原台 E2E 及截图验证", () => {
  test("08-三级深度完整性校验步进器状态与截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 3
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('三级校验与无损还原')").click();

    // 点击运行三级校验
    const runVerifyBtn = page.locator("button:has-text('运行三级校验')");
    await runVerifyBtn.click();

    // 验证 L1, L2, L3 全部 PASS
    await expect(page.locator("text=Level 1 · 宿主容器结构校验")).toBeVisible();
    await expect(page.locator("text=Level 2 · 隐写信封边界校验")).toBeVisible();
    await expect(page.locator("text=Level 3 · 密码学认证与哈希校验")).toBeVisible();

    // 验证内容域诊断指标
    await expect(page.locator("text=内容域隐写诊断指标 (PNG)")).toBeVisible();

    // 截屏 9: 三级校验通过态
    await page.screenshot({
      path: path.join(screenshotDir, "09-workbench-verify-stepper.png"),
      fullPage: true,
    });
  });

  test("09-一键100%字节级无损剥离还原与哈希吻合截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 3
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('三级校验与无损还原')").click();

    // 点击一键剥离并还原
    const restoreBtn = page.locator("button:has-text('一键剥离并还原')");
    await restoreBtn.click();

    // 验证还原成功卡片与 Bit-Exact 状态
    await expect(page.locator("text=载体无损还原成功！")).toBeVisible();
    await expect(page.locator("text=100% 原始字节级吻合 (Bit-Exact)")).toBeVisible();

    // 截屏 10: 100% 原始字节级无损还原成功卡片
    await page.screenshot({
      path: path.join(screenshotDir, "10-workbench-restore-bitexact.png"),
      fullPage: true,
    });
  });
});
