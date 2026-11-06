import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

/**
 * A failed capability fetch must not be reported as "unsupported format".
 *
 * `useCapabilities` used to answer `[]` on failure, and `classifyFormat` looks
 * up the extension in that table — so an IPC hiccup rejected every file with
 * the one message that blames the user's file.
 */
test.describe("格式能力加载失败", () => {
  test("文件按「能力未加载」跳过，而不是「格式不支持」", async ({ page }) => {
    await openApp(page, {
      files: ["C:\\\\Samples\\\\photo.png"],
      capabilitiesError: "ipc channel closed",
    });

    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");

    await scan.locator("button:has-text('添加文件')").click();

    await expect(scan.getByText("已跳过 1 个").first()).toBeVisible();
    await expect(scan.getByText("格式能力未加载，请稍后重试", { exact: false }).first()).toBeVisible();
    await expect(scan.getByText("格式不支持", { exact: false })).toHaveCount(0);
  });
});
