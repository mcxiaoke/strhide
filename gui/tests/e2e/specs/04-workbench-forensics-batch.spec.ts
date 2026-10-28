import { test, expect, createTauriMockScript } from "../fixtures";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotDir = path.resolve(__dirname, "../../../../temp/screenshots");

test.describe("工作台 4: 反隐写取证与批处理中心 E2E 及截图验证", () => {
  test("10-黑盒反隐写风险评分盘与量化指标矩阵截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      riskScore: 18,
      verdict: "low",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 4
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('反隐写取证与批处理')").click();

    // 点击开始反隐写扫描
    const scanBtn = page.locator("button:has-text('开始反隐写扫描')");
    await scanBtn.click();

    // 验证风险评分盘与研判档位
    await expect(page.locator("text=隐写风险指数 (0..100)")).toBeVisible();
    await expect(page.locator(".text-4xl:has-text('18')")).toBeVisible();
    await expect(page.locator("span.uppercase:has-text('low')")).toBeVisible();

    // 验证量化指标表格存在
    await expect(page.locator("text=量化检测器执行明细")).toBeVisible();
    await expect(page.locator("text=png:chi2-spatial")).toBeVisible();

    // 截屏 11: 反隐写评分盘与检测器明细
    await page.screenshot({
      path: path.join(screenshotDir, "11-workbench-forensics-steganalysis.png"),
      fullPage: true,
    });
  });

  test("11-多文件批处理队列调度执行与进度汇总截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 进入工作台 4
    await page.locator("button:has-text('反隐写取证与批处理')").click();

    // 切换至多文件批处理队列子标签
    await page.locator("button:has-text('多文件批处理队列')").click();

    // 添加模拟队列文件
    await page.locator("button:has-text('添加文件...')").click();

    // 验证队列列表显示文件
    await expect(page.locator("text=队列列表: 共 1 个文件")).toBeVisible();

    // 点击执行批量任务
    const executeBatchBtn = page.locator("button:has-text('执行批量任务')");
    await executeBatchBtn.click();

    // 验证批量执行结果报告
    await expect(page.locator("text=批量任务执行汇报:")).toBeVisible();
    await expect(page.locator("text=成功: 1")).toBeVisible();

    // 截屏 12: 多文件批处理队列与汇总报告
    await page.screenshot({
      path: path.join(screenshotDir, "12-workbench-forensics-batch-queue.png"),
      fullPage: true,
    });
  });
});
