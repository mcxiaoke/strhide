import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

test.describe("扫描页", () => {
  test("批量扫描结果表", async ({ page }) => {
    await openApp(page, {
      files: ["C:\\\\Samples\\\\photo.png", "C:\\\\Samples\\\\archive.zip"],
      format: "PNG",
    });
    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");

    await expect(scan.locator("p").first()).toHaveText("检查文件里有没有藏内容，以及能不能往里写。");

    await scan.locator("button:has-text('添加文件')").click();
    await expect(scan.locator("text=2 个文件")).toBeVisible();

    await scan.locator("button:has-text('开始扫描')").click();

    await expect(scan.locator("table")).toBeVisible();
    await expect(scan.locator("th:has-text('能写入')")).toBeVisible();
    await expect(scan.locator("th:has-text('藏了内容')")).toBeVisible();
    await expect(scan.locator("td:has-text('附加 + 嵌入')").first()).toBeVisible();
    await expect(scan.locator("td:has-text('18.0 KB')").first()).toBeVisible();
    await expect(scan.locator("td:has-text('2.00 MB')").first()).toBeVisible();
  });

  test("不支持的文件直接跳过", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\notes.txt"] });
    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");

    await scan.locator("button:has-text('添加文件')").click();

    await expect(scan.locator("text=notes.txt（格式不支持）")).toBeVisible();
    await expect(scan.locator("button:has-text('开始扫描')")).toBeDisabled();
  });

  test("没有藏内容的文件显示为无", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"], hasHiddenData: false });
    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");

    await scan.locator("button:has-text('添加文件')").click();
    await scan.locator("button:has-text('开始扫描')").click();

    const row = scan.locator("tr:has-text('photo.png')").last();
    await expect(row.locator("td").nth(3)).toHaveText("—");
  });
});
