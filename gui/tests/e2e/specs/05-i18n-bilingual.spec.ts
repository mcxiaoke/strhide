import { test, expect } from "../fixtures";
import { openApp, panel } from "./_helpers";

test.describe("语言与主题", () => {
  test("切换语言后页签与正文都变化", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });

    await expect(page.locator("[data-testid=tab-stego]")).toHaveText("隐写");
    await expect(page.locator("[data-testid=tab-scan]")).toHaveText("扫描");
    await expect(panel(page, "stego").locator("p").first()).toHaveText(
      "把内容写进图片或视频，画面看不出变化。",
    );

    await page.locator("[data-testid=lang-toggle]").click();

    await expect(page.locator("[data-testid=tab-stego]")).toHaveText("Stego");
    await expect(page.locator("[data-testid=tab-hide]")).toHaveText("Hide");
    await expect(page.locator("[data-testid=tab-extract]")).toHaveText("Extract");
    await expect(page.locator("[data-testid=tab-scan]")).toHaveText("Scan");
    await expect(panel(page, "stego").locator("p").first()).toHaveText(
      "Writes your content into an image or video. The picture looks unchanged.",
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
