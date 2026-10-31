import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

test.describe("嵌入页", () => {
  test("多文件写入输出目录", async ({ page }) => {
    await openApp(page, {
      files: ["C:\\\\Samples\\\\report.pdf", "C:\\\\Samples\\\\archive.zip"],
    });
    await page.locator("[data-testid=tab-hide]").click();
    const hide = panel(page, "hide");

    await expect(hide.locator("p").first()).toHaveText("将文字或文件嵌入到任意文件内部。文件可正常打开，并能完整还原为原文件。");

    await hide.locator("button:has-text('添加文件')").click();
    await expect(hide.locator("text=2 个文件")).toBeVisible();

    await hide.locator("textarea").fill("internal memo");
    await hide.getByRole("button", { name: "浏览…", exact: true }).click();
    await expect(hide.locator("text=C:\\Samples\\out")).toBeVisible();

    await hide.locator("button:has-text('开始嵌入')").click();

    await expect(hide.getByText("完成", { exact: true }).first()).toBeVisible();
    await expect(hide.locator("p:has-text('report_hidden.pdf')").first()).toBeVisible();
  });

  test("设置密码后出现提示行，不留痕迹需要密码", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });
    await page.locator("[data-testid=tab-hide]").click();
    const hide = panel(page, "hide");

    await hide.locator("button:has-text('添加文件')").click();
    await hide.locator("textarea").fill("memo");
    await hide.locator("button:has-text('高级选项')").click();

    const stealth = hide.locator("label:has-text('无痕模式') input[type=checkbox]");
    await expect(stealth).toBeDisabled();
    await expect(hide.locator("input[type=text]")).toHaveCount(0);

    await hide.locator("input[type=password]").fill("pw123456");

    await expect(hide.locator("input[type=text]")).toHaveCount(1);
    await expect(stealth).toBeEnabled();
  });

  test("格式不支持的文件被跳过", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\notes.txt", "C:\\\\Samples\\\\photo.png"] });
    await page.locator("[data-testid=tab-hide]").click();
    const hide = panel(page, "hide");

    await hide.locator("button:has-text('添加文件')").click();

    await expect(hide.locator("text=1 个文件")).toBeVisible();
    await expect(hide.locator("text=notes.txt（格式不支持）")).toBeVisible();
  });
});
