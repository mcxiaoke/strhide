import { test, expect } from "../fixtures";
import { openApp } from "./_helpers";

test.describe("日志面板 (Log Modal)", () => {
  test("右上角图标可打开日志面板，展示控制栏与筛选按钮，按 Esc 或关闭按钮可退出", async ({ page }) => {
    await openApp(page);

    // 1. 验证右上角日志按钮存在
    const toggleBtn = page.locator("[data-testid=log-panel-toggle]");
    await expect(toggleBtn).toBeVisible();

    // 2. 点击打开日志面板
    await toggleBtn.click();
    const modal = page.locator("[data-testid=log-modal-container]");
    await expect(modal).toBeVisible();

    // 3. 验证工具栏组件
    await expect(page.locator("[data-testid=filter-source-all]")).toBeVisible();
    await expect(page.locator("[data-testid=filter-source-rust]")).toBeVisible();
    await expect(page.locator("[data-testid=filter-source-frontend]")).toBeVisible();
    await expect(page.locator("[data-testid=log-search-input]")).toBeVisible();
    await expect(page.locator("[data-testid=copy-all-logs-btn]")).toBeVisible();
    await expect(page.locator("[data-testid=clear-logs-btn]")).toBeVisible();
    await expect(page.locator("[data-testid=log-stream-container]")).toBeVisible();

    // 4. 验证文本框可自由选择与输入
    const searchInput = page.locator("[data-testid=log-search-input]");
    await searchInput.fill("test-search");
    await expect(searchInput).toHaveValue("test-search");

    // 5. 点击关闭按钮
    const closeBtn = page.locator("[data-testid=log-modal-close]");
    await closeBtn.click();
    await expect(modal).not.toBeVisible();

    // 6. 再次打开并按 Esc 退出
    await toggleBtn.click();
    await expect(modal).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });
});
