import { test, expect, projectRoot } from "../fixtures";
import fs from "node:fs";
import path from "node:path";

test.describe("Real Process & Real Data E2E Test Suite", () => {
  test("1. 隐写嵌入与提取真实全链路闭环（中文长文本与中文密码）", async ({ realApp }) => {
    const { page, scratchDir, dropFiles, goTab, panel } = realApp;

    const carrierSrc = path.resolve(projectRoot, "temp/jpgtest/art002e004437~large.jpg");
    const testCarrier = path.join(scratchDir, "sample.jpg");
    fs.copyFileSync(carrierSrc, testCarrier);

    const chinesePayload =
      "根据目前公开信息，这项“禁止复刻特定现有游戏”的限制仅明确针对 Opus 5.5 模型中的 Claude Code。Anthropic 表示，他们在 Opus 5.5 的 Claude Code 提示词中加入了“两句引导内容”，让模型避免重现他人特定游戏。报道并未说明 Anthropic 已将同样规则推广到其他 Claude 模型或所有 Claude Code 版本。";
    const chinesePassword = "根据目前公开信息";

    // 1. 进入隐写页并录入
    await goTab("stego");
    const stego = panel("stego");

    await dropFiles([testCarrier]);
    await expect(stego.locator(`text=${path.basename(testCarrier)}`).first()).toBeVisible();

    await stego.locator("textarea").fill(chinesePayload);
    await stego.locator("input[type='password']").fill(chinesePassword);

    const startBtn = stego.locator("button:has-text('开始隐写')");
    await expect(startBtn).toBeEnabled();
    await startBtn.click();

    // 2. 等待真实 Rust 后端嵌入完成
    const doneBadge = stego.getByText("完成", { exact: true });
    await expect(doneBadge).toBeVisible({ timeout: 35000 });

    const expectedStegoPath = path.join(scratchDir, "sample_stego.jpg");
    expect(fs.existsSync(expectedStegoPath)).toBe(true);
    expect(fs.statSync(expectedStegoPath).size).toBeGreaterThan(40000);

    // 3. 进入提取页并验证真实提取
    await goTab("extract");
    const extract = panel("extract");

    await dropFiles([expectedStegoPath]);
    await expect(extract.locator(`text=${path.basename(expectedStegoPath)}`).first()).toBeVisible();

    await extract.locator("input[type='password']").fill(chinesePassword);
    const extractBtn = extract.locator("button:has-text('开始提取')");
    await expect(extractBtn).toBeEnabled();
    await extractBtn.click();

    // 4. 断言真实提取出来的中文长文本在页面呈现且一字不差
    const pre = extract.locator("pre").first();
    await expect(pre).toBeVisible({ timeout: 30000 });
    await expect(pre).toContainText(chinesePayload);
  });

  test("2. 结构嵌入与提取真实全链路闭环（PNG 结构域写入与提取）", async ({ realApp }) => {
    const { scratchDir, dropFiles, goTab, panel } = realApp;

    const carrierSrc = path.resolve(projectRoot, "rust/tests/fixtures/carrier.png");
    const testCarrier = path.join(scratchDir, "sample.png");
    fs.copyFileSync(carrierSrc, testCarrier);

    const structPayload = "Confidential real structure hidden memo 2026";
    const structPassword = "struct_real_pwd";

    // 1. 进入嵌入页并录入
    await goTab("hide");
    const hide = panel("hide");

    await dropFiles([testCarrier]);
    await expect(hide.locator(`text=${path.basename(testCarrier)}`).first()).toBeVisible();

    await hide.locator("textarea").fill(structPayload);
    await hide.locator("input[type='password']").fill(structPassword);

    const startBtn = hide.locator("button:has-text('开始嵌入')");
    await expect(startBtn).toBeEnabled();
    await startBtn.click();

    // 2. 等待完成
    const doneBadge = hide.getByText("完成", { exact: true });
    await expect(doneBadge).toBeVisible({ timeout: 25000 });

    const expectedHiddenPath = path.join(scratchDir, "sample_hidden.png");
    expect(fs.existsSync(expectedHiddenPath)).toBe(true);

    // 3. 进入提取页提取结构域内容
    await goTab("extract");
    const extract = panel("extract");

    await dropFiles([expectedHiddenPath]);
    await expect(extract.locator(`text=${path.basename(expectedHiddenPath)}`).first()).toBeVisible();

    await extract.locator("input[type='password']").fill(structPassword);
    const extractBtn = extract.locator("button:has-text('开始提取')");
    await expect(extractBtn).toBeEnabled();
    await extractBtn.click();

    // 4. 断言提取文本一致
    const pre = extract.locator("pre").first();
    await expect(pre).toBeVisible({ timeout: 25000 });
    await expect(pre).toContainText(structPayload);
  });

  test("3. 扫描检测真实双域识别（识别隐写和结构隐藏）", async ({ realApp }) => {
    const { scratchDir, dropFiles, goTab, panel } = realApp;

    // 先准备一个已经隐写写入的图片文件
    const stegoCarrierSrc = path.resolve(projectRoot, "temp/jpgtest/art002e004437~large_stego.jpg");
    const testStego = path.join(scratchDir, "test_stego.jpg");
    fs.copyFileSync(stegoCarrierSrc, testStego);

    await goTab("scan");
    const scan = panel("scan");

    await dropFiles([testStego]);
    await expect(scan.locator(`text=${path.basename(testStego)}`).first()).toBeVisible();

    const scanBtn = scan.locator("button:has-text('开始扫描')");
    await expect(scanBtn).toBeEnabled();
    await scanBtn.click();

    // 真实检测结果应渲染表格并识别出隐写
    await expect(scan.locator("table")).toBeVisible({ timeout: 25000 });
    await expect(scan.locator("table")).toContainText("test_stego.jpg");
    await expect(scan.locator("table")).toContainText("隐写");
  });

  test("4. 错误密码提取防御验证（密码错误时安全报错且应用稳定运行）", async ({ realApp }) => {
    const { scratchDir, dropFiles, goTab, panel } = realApp;

    // 使用带有密码的隐写载体
    const stegoCarrierSrc = path.resolve(projectRoot, "temp/jpgtest/art002e004437~large_stego.jpg");
    const testStego = path.join(scratchDir, "wrong_pwd_test.jpg");
    fs.copyFileSync(stegoCarrierSrc, testStego);

    await goTab("extract");
    const extract = panel("extract");

    await dropFiles([testStego]);
    await expect(extract.locator(`text=${path.basename(testStego)}`).first()).toBeVisible();

    // 输入完全错误的密码
    await extract.locator("input[type='password']").fill("DefinitelyWrongPassword123!");
    const extractBtn = extract.locator("button:has-text('开始提取')");
    await expect(extractBtn).toBeEnabled();
    await extractBtn.click();

    // 应该显示失败状态（如 StatusPill 显示“失败”或列表头部提示“跳过/失败”）
    const failBadge = extract.getByText("失败", { exact: true });
    await expect(failBadge).toBeVisible({ timeout: 25000 });

    // 确保没有误把内容提取出来
    await expect(extract.locator("pre")).toHaveCount(0);
  });
});
