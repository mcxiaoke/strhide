import { test } from "../fixtures";
import type { Page } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { openApp, panel } from "./_helpers";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const shotDir = path.resolve(__dirname, "../../../../temp/screenshots");

const ALL_FILES = [
  "C:\\\\Samples\\\\photo.png",
  "C:\\\\Samples\\\\clip.mp4",
  "C:\\\\Samples\\\\report.pdf",
  "C:\\\\Samples\\\\notes.txt",
];

const shot = async (page: Page, name: string) => {
  await page.screenshot({ path: path.join(shotDir, `${name}.png`), fullPage: true });
};

const addFiles = async (page: Page, id: string, label = "添加文件") => {
  await panel(page, id).locator(`button:has-text('${label}')`).click();
};

test.describe("界面截图", () => {
  test("中文 · 浅色：四个页签各状态", async ({ page }) => {
    await openApp(page, { files: ALL_FILES });

    // 隐写：空态 / 已添加 / 完成 / 高级
    const stego = panel(page, "stego");
    await shot(page, "zh-light-01-stego-empty");
    await addFiles(page, "stego");
    await shot(page, "zh-light-02-stego-files");
    await stego.locator("textarea").fill("明天下午三点，老地方见。");
    await stego.locator("button:has-text('开始隐写')").click();
    await stego.locator("text=完成").first().waitFor();
    await shot(page, "zh-light-03-stego-done");
    await stego.locator("button:has-text('高级选项')").click();
    await shot(page, "zh-light-04-stego-advanced");

    // 嵌入：已添加 / 完成 / 高级（密码 + 提示 + 无痕模式）
    await page.locator("[data-testid=tab-hide]").click();
    const hide = panel(page, "hide");
    await shot(page, "zh-light-05-hide-empty");
    await addFiles(page, "hide");
    await hide.locator("textarea").fill("项目验收清单已放在共享盘。");
    await hide.locator("input[type=password]").fill("my-password");
    await hide.locator("button:has-text('高级选项')").click();
    await hide.locator("label:has-text('无痕模式') input[type=checkbox]").check();
    await shot(page, "zh-light-06-hide-advanced");
    await hide.locator("button:has-text('开始嵌入')").click();
    await hide.locator("text=完成").first().waitFor();
    await shot(page, "zh-light-07-hide-done");

    // 提取：空态 / 文字结果
    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");
    await shot(page, "zh-light-08-extract-empty");
    await addFiles(page, "extract");
    await extract.locator("button:has-text('开始提取')").click();
    await extract.locator("pre").first().waitFor();
    await shot(page, "zh-light-09-extract-text");

    // 扫描：空态 / 结果表
    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");
    await shot(page, "zh-light-10-scan-empty");
    await addFiles(page, "scan");
    await scan.locator("button:has-text('开始扫描')").click();
    await scan.locator("table").waitFor();
    await shot(page, "zh-light-11-scan-table");
  });

  test("中文 · 浅色：文件类内容提取到目录", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"], binaryPayload: true });
    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");
    await addFiles(page, "extract");
    await extract.locator("button:has-text('开始提取')").click();
    await extract.locator("text=完成").first().waitFor();
    await shot(page, "zh-light-12-extract-file");
  });

  test("中文 · 深色：四个页签", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("strhide_theme", "dark"));
    await openApp(page, { files: ALL_FILES });

    const stego = panel(page, "stego");
    await addFiles(page, "stego");
    await stego.locator("textarea").fill("明天下午三点，老地方见。");
    await stego.locator("button:has-text('开始隐写')").click();
    await stego.locator("text=完成").first().waitFor();
    await shot(page, "zh-dark-01-stego");

    await page.locator("[data-testid=tab-hide]").click();
    const hide = panel(page, "hide");
    await addFiles(page, "hide");
    await hide.locator("textarea").fill("项目验收清单已放在共享盘。");
    await hide.locator("button:has-text('开始嵌入')").click();
    await hide.locator("text=完成").first().waitFor();
    await shot(page, "zh-dark-02-hide");

    await page.locator("[data-testid=tab-extract]").click();
    const extract = panel(page, "extract");
    await addFiles(page, "extract");
    await extract.locator("button:has-text('开始提取')").click();
    await extract.locator("pre").first().waitFor();
    await shot(page, "zh-dark-03-extract");

    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");
    await addFiles(page, "scan");
    await scan.locator("button:has-text('开始扫描')").click();
    await scan.locator("table").waitFor();
    await shot(page, "zh-dark-04-scan");
  });

  test("英文界面：隐写与扫描", async ({ page }) => {
    await openApp(page, { files: ALL_FILES });
    await page.locator("[data-testid=lang-toggle]").click();

    const stego = panel(page, "stego");
    await addFiles(page, "stego", "Add files");
    await stego.locator("textarea").fill("Meet me at the usual place at 3pm.");
    await stego.locator("button:has-text('Start')").click();
    await stego.getByText("Done", { exact: true }).first().waitFor();
    await shot(page, "en-light-01-stego");

    await page.locator("[data-testid=tab-scan]").click();
    const scan = panel(page, "scan");
    await scan.locator("button:has-text('Add files')").click();
    await scan.locator("button:has-text('Start')").click();
    await scan.locator("table").waitFor();
    await shot(page, "en-light-02-scan");
  });
});
