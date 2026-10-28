import { test, expect, createTauriMockScript } from "../fixtures";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotDir = path.resolve(__dirname, "../../../../temp/screenshots");

test.describe("工作台 1: 检视与智能提取台 E2E 及截图验证", () => {
  test("01-初始未选载体态渲染与截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript());
    await page.goto("http://localhost:1420");

    // 验证 Dropzone 存在
    const dropzoneText = page.locator("text=拖拽载体文件至此");
    await expect(dropzoneText).toBeVisible();

    // 验证导航栏处于检视台
    const inspectTab = page.locator("button:has-text('检视与智能提取')");
    await expect(inspectTab).toBeVisible();

    // 高清截屏快照 1
    await page.screenshot({
      path: path.join(screenshotDir, "01-workbench-inspect-empty.png"),
      fullPage: true,
    });
  });

  test("02-载入载体文件后的双域检视卡片渲染与截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      hasHiddenData: true,
      passwordHint: "birthday-1990",
    }));
    await page.goto("http://localhost:1420");

    // 点击选择载体文件 (触发 mock 的 dialog|open)
    const dropzone = page.locator("text=拖拽载体文件至此");
    await dropzone.click();

    // 验证载体元数据卡片显示
    const carrierHeader = page.locator("h2:has-text('holiday_photo.png')");
    await expect(carrierHeader).toBeVisible();

    // 验证分辨率徽章
    const resBadge = page.locator("text=1920 × 1080");
    await expect(resBadge).toBeVisible();

    // 验证结构域卡片状态
    const structBadge = page.locator("text=已检测到信封");
    await expect(structBadge).toBeVisible();

    // 验证内容域算法模型卡片
    const contentAlgo = page.locator("text=HILL");
    await expect(contentAlgo).toBeVisible();

    // 验证密码提示徽章自动显示
    const hintBadge = page.locator("text=birthday-1990");
    await expect(hintBadge).toBeVisible();

    // 高清截屏快照 2
    await page.screenshot({
      path: path.join(screenshotDir, "02-workbench-inspect-carrier-loaded.png"),
      fullPage: true,
    });
  });

  test("03-一键智能解密提取纯文本载荷渲染与截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      hasHiddenData: true,
      passwordHint: "birthday-1990",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体
    await page.locator("text=拖拽载体文件至此").click();

    // 输入密码
    const pwdInput = page.locator("input[type='password']");
    await pwdInput.fill("birthday-1990");

    // 点击开始提取
    const extractBtn = page.locator("button:has-text('开始提取')");
    await extractBtn.click();

    // 验证提取结果标题显示
    const resultTitle = page.locator("h4:has-text('提取结果: secret_document.txt')");
    await expect(resultTitle).toBeVisible();

    // 验证纯文本 pre 预览内容正确渲染
    const previewContent = page.locator("pre:has-text('Confidential Report 2026')");
    await expect(previewContent).toBeVisible();

    // 验证复制文本与另存为文件按钮
    await expect(page.locator("button:has-text('复制文本')")).toBeVisible();
    await expect(page.locator("button:has-text('另存为文件...')")).toBeVisible();

    // 高清截屏快照 3
    await page.screenshot({
      path: path.join(screenshotDir, "03-workbench-inspect-text-extracted.png"),
      fullPage: true,
    });
  });
});
