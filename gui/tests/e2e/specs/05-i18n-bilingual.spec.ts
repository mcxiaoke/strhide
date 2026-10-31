import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

test.describe("语言与主题", () => {
  test("切换语言后页签与正文都变化", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });

    await expect(page.locator("[data-testid=tab-stego]")).toHaveText("隐写");
    await expect(page.locator("[data-testid=tab-scan]")).toHaveText("扫描");
    await expect(panel(page, "stego").locator("p").first()).toHaveText(
      "将文字或文件隐写进图片、视频的画面数据。文件外观不变，但无法还原为原文件。",
    );

    await page.locator("[data-testid=lang-toggle]").click();

    await expect(page.locator("[data-testid=tab-stego]")).toHaveText("Stego");
    await expect(page.locator("[data-testid=tab-hide]")).toHaveText("Embed");
    await expect(page.locator("[data-testid=tab-extract]")).toHaveText("Extract");
    await expect(page.locator("[data-testid=tab-scan]")).toHaveText("Scan");
    await expect(panel(page, "stego").locator("p").first()).toHaveText(
      "Writes text or files into the picture data of an image or video. The file looks unchanged, but cannot be restored.",
    );
    await expect(panel(page, "stego").locator("button:has-text('Add files')")).toBeVisible();
  });

  test("切换主题后按钮文案变化", async ({ page }) => {
    await openApp(page);

    const themeBtn = page.locator("[data-testid=theme-toggle]");
    await expect(themeBtn).toHaveText("深色");
    await themeBtn.click();
    await expect(themeBtn).toHaveText("浅色");
  });
});
