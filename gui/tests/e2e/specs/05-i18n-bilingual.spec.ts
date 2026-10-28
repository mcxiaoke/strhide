import { test, expect, createTauriMockScript } from "../fixtures";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotDir = path.resolve(__dirname, "../../../../temp/screenshots");

test.describe("双语国际化与英文界面渲染截图", () => {
  test("12-切换英文界面与全导航本地化渲染截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体
    await page.locator("text=拖拽载体文件至此").click();

    // 点击右上角语言切换按钮
    const langBtn = page.locator("button:has-text('中文')");
    await langBtn.click();

    // 验证侧边导航转换为英文
    await expect(page.locator("button:has-text('Inspect & Extract')")).toBeVisible();
    await expect(page.locator("button:has-text('Hide & Embed')")).toBeVisible();
    await expect(page.locator("button:has-text('Verify & Restore')")).toBeVisible();
    await expect(page.locator("button:has-text('Steganalysis & Batch')")).toBeVisible();

    // 验证语言按钮变为 English
    await expect(page.locator("button:has-text('English')")).toBeVisible();

    // 截屏 13: 英文界面渲染
    await page.screenshot({
      path: path.join(screenshotDir, "13-workbench-english-i18n.png"),
      fullPage: true,
    });
  });
});
