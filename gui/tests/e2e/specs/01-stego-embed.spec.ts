import { test, expect } from "../fixtures";
import { MIXED_FILES, openApp, panel } from "./_helpers";

test.describe("隐写页", () => {
  test("空态与多选添加（不支持的文件被跳过）", async ({ page }) => {
    await openApp(page, { files: MIXED_FILES });
    const stego = panel(page, "stego");

    await expect(stego.locator("p").first()).toHaveText("把内容写进图片或视频，画面看不出变化。");
    await expect(stego.locator("text=拖入文件，或点击选择（可多选）")).toBeVisible();
    await expect(stego.locator("text=开始隐写")).toBeDisabled();

    await stego.locator("button:has-text('添加文件')").click();

    await expect(stego.locator("text=2 个文件")).toBeVisible();
    await expect(stego.locator("text=已跳过 1 个：notes.txt（格式不支持）")).toBeVisible();
  });

  test("写入成功后显示产物与容量", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });
    const stego = panel(page, "stego");

    await stego.locator("button:has-text('添加文件')").click();
    await stego.locator("textarea").fill("hello stego");
    await stego.locator("button:has-text('开始隐写')").click();

    await expect(stego.locator("text=可藏 25.0 KB")).toBeVisible();
    await expect(stego.locator("text=photo_stego.png")).toBeVisible();
    await expect(stego.getByText("完成", { exact: true })).toBeVisible();
  });

  test("内容超过容量时跳过该文件", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });
    const stego = panel(page, "stego");

    await stego.locator("button:has-text('添加文件')").click();
    await stego.getByRole("button", { name: "文件", exact: true }).click();
    await stego.locator("button:has-text('选择文件')").click();
    await expect(stego.locator("text=photo.png").first()).toBeVisible();

    await stego.locator("button:has-text('开始隐写')").click();

    await expect(stego.locator("text=内容太大，这份文件最多能藏 62.5 KB")).toBeVisible();
    await expect(stego.getByText("跳过", { exact: true })).toHaveCount(1);
  });

  test("视频不是 HEVC 时给出提示", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\clip.mp4"], capacityError: "该视频不是 HEVC 编码" });
    const stego = panel(page, "stego");

    await stego.locator("button:has-text('添加文件')").click();
    await stego.locator("textarea").fill("hello");
    await stego.locator("button:has-text('开始隐写')").click();

    await expect(stego.locator("text=该视频不是 HEVC 编码")).toBeVisible();
  });

  test("没有内容或文件时给出提示", async ({ page }) => {
    await openApp(page, { files: ["C:\\\\Samples\\\\photo.png"] });
    const stego = panel(page, "stego");

    await expect(stego.locator("button:has-text('开始隐写')")).toBeDisabled();

    await stego.locator("button:has-text('添加文件')").click();
    await expect(stego.locator("button:has-text('开始隐写')")).toBeDisabled();

    await stego.locator("textarea").fill("x");
    await expect(stego.locator("button:has-text('开始隐写')")).toBeEnabled();
  });
});
