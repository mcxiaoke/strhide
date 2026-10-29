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

  test("13-默认亮色模式与深色主题无缝切换截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 验证默认亮色主题生效
    const html = page.locator("html");
    await expect(html).toHaveAttribute("data-theme", "light");

    // 截屏 14: 默认浅色现代界面 (Light Mode)
    await page.screenshot({
      path: path.join(screenshotDir, "14-workbench-theme-light-default.png"),
      fullPage: true,
    });

    // 点击右上角深色模式切换按钮
    const themeBtn = page.locator("button:has-text('深色模式')");
    await themeBtn.click();

    // 验证主题变为 dark
    await expect(html).toHaveAttribute("data-theme", "dark");
    await expect(page.locator("button:has-text('浅色模式')")).toBeVisible();

    // 截屏 15: 一键切换至科技感暗黑界面 (Dark Mode)
    await page.screenshot({
      path: path.join(screenshotDir, "15-workbench-theme-dark-switch.png"),
      fullPage: true,
    });
  });
});
