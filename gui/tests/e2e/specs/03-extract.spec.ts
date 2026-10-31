import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

test.describe("提取页", () => {
  test("文字内容直接显示并可复制", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });
    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");

    await expect(extract.locator("p").first()).toHaveText("检测文件中的隐藏内容，并将其提取出来。");

    await extract.locator("button:has-text('添加文件')").click();
    await extract.locator("button:has-text('开始提取')").click();

    await expect(extract.locator("pre:has-text('会议纪要')")).toBeVisible();
    await expect(extract.locator("text=嵌入内容 · 文字 1.4 KB")).toBeVisible();
    await expect(extract.locator("button:has-text('复制')")).toBeVisible();
  });

  test("文件内容保存到输出目录", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"], binaryPayload: true });
    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");

    await extract.locator("button:has-text('添加文件')").click();
    await extract.locator("button:has-text('开始提取')").click();

    await expect(extract.locator("text=C:\\Samples\\secret.txt")).toBeVisible();
    await expect(extract.locator("text=嵌入内容 · 文件 1.4 KB")).toBeVisible();
  });

  test("同时含有两份内容时给出提示", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"], alsoPresent: "content" });
    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");

    await extract.locator("button:has-text('添加文件')").click();
    await extract.locator("button:has-text('开始提取')").click();

    await expect(extract.locator("text=（另有隐写内容）")).toBeVisible();
  });

  test("没有文件时按钮不可点", async ({ page }) => {
    await openApp(page);
    await page.locator("[data-testid=tab-extract]").click();
    await expect(panel(page, "extract").locator("button:has-text('开始提取')")).toBeDisabled();
  });
});
