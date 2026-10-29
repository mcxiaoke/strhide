import { test, expect, createTauriMockScript } from "../fixtures";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const screenshotDir = path.resolve(__dirname, "../../../../temp/screenshots");

test.describe("工作台 2: 隐藏与自适应嵌入台 E2E 及截图验证", () => {
  test("04-内容域隐写与容量水位尺实时交互截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体
    await page.locator("text=拖拽载体文件至此").click();

    // 切换至工作台 2
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 验证技术域自动选中内容域自适应隐写
    const contentDomainBtn = page.locator("button:has-text('内容域自适应隐写')");
    await expect(contentDomainBtn).toBeVisible();

    // 在文本载荷框输入秘密文本
    const textarea = page.locator("textarea");
    await textarea.fill("Top secret mission payload: coordinates 39.9042, 116.4074.");

    // 验证字节计数更新
    await expect(page.locator("text=UTF-8 字节数:")).toBeVisible();

    // 验证容量水位尺渲染
    await expect(page.locator("text=自适应容量安全水位尺")).toBeVisible();
    await expect(page.locator("text=Paranoid (偏执)")).toBeVisible();
    await expect(page.locator("text=High (推荐)")).toBeVisible();

    // 高清截屏快照 4
    await page.screenshot({
      path: path.join(screenshotDir, "04-workbench-hide-content-domain.png"),
      fullPage: true,
    });
  });

  test("05-载荷超出安全上限动态警报与超限阻断截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 2
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 填入超长文本模拟超限 (30,000 字节 > 推荐上限 25,600 字节)
    const longPayload = "A".repeat(30000);
    const textarea = page.locator("textarea");
    await textarea.fill(longPayload);

    // 验证触发超限警告框
    const alertBox = page.locator("text=载荷超限安全告警（建议模式）");
    await expect(alertBox).toBeVisible();

    // 勾选强制阻断 (Enforced)
    const enforceCheckbox = page.locator("input[type='checkbox']").first();
    await enforceCheckbox.check();

    // 验证警告框切换为阻断模式
    await expect(page.locator("text=载荷超限（已阻断嵌入）")).toBeVisible();

    // 高清截屏快照 5
    await page.screenshot({
      path: path.join(screenshotDir, "05-workbench-hide-capacity-overlimit.png"),
      fullPage: true,
    });
  });

  test("06-高级参数微调面板与覆盖冲突拦截对话框截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      conflictOnEmbed: true, // 模拟目标文件已存在冲突
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 2
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 展开高级参数设置
    const toggleTuningBtn = page.locator("button:has-text('展开高级参数设置')");
    await toggleTuningBtn.click();

    // 验证算法选择器与时间戳保留选项
    await expect(page.locator("text=高级参数微调 (Tuning & Safety Policy)")).toBeVisible();
    await expect(page.locator("text=克隆原文件修改时间")).toBeVisible();

    // 截屏 6: 展开调优抽屉
    await page.screenshot({
      path: path.join(screenshotDir, "06-workbench-hide-tuning-drawer.png"),
      fullPage: true,
    });

    // 输入载荷并点击开始嵌入，触发覆盖冲突
    await page.locator("textarea").fill("Test confidential memo.");
    await page.locator("button:has-text('开始隐藏 / 嵌入')").click();

    // 验证弹出 OverwriteDialog 对话框
    const overwriteModalTitle = page.locator("h3:has-text('目标文件已存在')");
    await expect(overwriteModalTitle).toBeVisible();
    await expect(page.locator("button:has-text('确认覆盖现有文件')")).toBeVisible();
    await expect(page.locator("button:has-text('另存为新路径...')")).toBeVisible();

    // 截屏 7: 覆盖冲突弹窗
    await page.screenshot({
      path: path.join(screenshotDir, "07-workbench-hide-overwrite-dialog.png"),
      fullPage: true,
    });
  });

  test("07-嵌入成功与 EmbedStats 精确修改率统计报告截图", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      conflictOnEmbed: false,
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 2
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 输入载荷并执行嵌入
    await page.locator("textarea").fill("Secret message to embed.");
    await page.locator("button:has-text('开始隐藏 / 嵌入')").click();

    // 验证成功反馈卡片
    await expect(page.locator("text=数据隐藏写入成功！")).toBeVisible();

    // 验证 EmbedStats 修改率徽章 (1,420 / 2,073,600)
    const statsBadge = page.locator("text=精确修改率 (EmbedStats):");
    await expect(statsBadge).toBeVisible();
    await expect(page.locator("text=1,420 / 2,073,600")).toBeVisible();

    // 截屏 8: 写入成功反馈卡片
    await page.screenshot({
      path: path.join(screenshotDir, "08-workbench-hide-embed-success.png"),
      fullPage: true,
    });
  });

  test("08-选择本地载荷文件真实元数据与瞬时容量档位切换验证", async ({ page }) => {
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Samples\\holiday_photo.png",
      conflictOnEmbed: false,
    }));
    await page.goto("http://localhost:1420");

    // 载入载体并进入工作台 2
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 切换至“本地文件”
    await page.locator("button:has-text('本地文件')").click();

    // 点击选择要隐藏的载荷文件
    await page.locator("text=点击选择要隐藏的本地文件").click();

    // 验证真实文件大小被准确读取 (4.0 KB 真实元数据，而非旧的 1 KB 假数据)
    await expect(page.locator("text=4.0 KB").first()).toBeVisible();

    // 验证档位卡片中常态显示真实推荐上限
    await expect(page.locator("text=Paranoid (偏执)")).toBeVisible();
    await expect(page.locator("text=Balanced (均衡)")).toBeVisible();

    // 瞬时点击切换至 Paranoid 档位，验证推荐上限即时更新为 15.0 KB
    await page.locator("button:has-text('Paranoid (偏执)')").click();
    await expect(page.locator("text=15.0 KB").first()).toBeVisible();

    // 瞬时点击切换至 Balanced 档位，验证推荐上限即时更新为 37.5 KB
    await page.locator("button:has-text('Balanced (均衡)')").click();
    await expect(page.locator("text=37.5 KB").first()).toBeVisible();
  });

  test("09-不支持内容域隐写的载体(如H.264视频)智能降级结构域与显式警报提示", async ({ page }) => {
    // 模拟载入截图中的 file-00.mp4 (H.264视频流，缺少 HEVC CABAC 隐写流)
    await page.addInitScript(createTauriMockScript({
      carrierPath: "C:\\Home\\Projects\\strhide\\temp\\testfiles\\file-00.mp4",
      format: "MP4",
      contentError: "MP4/MOV parse error: unsupported HEVC feature: video track sample entry is not HEVC (hvc1/hev1)",
    }));
    await page.goto("http://localhost:1420");

    // 载入载体进入工作台 2
    await page.locator("text=拖拽载体文件至此").click();
    await page.locator("button:has-text('隐藏与自适应嵌入')").click();

    // 1. 验证载体头部信息栏准确提示内容隐写不支持
    await expect(page.locator("text=内容隐写不支持 (仅结构注入可用)")).toBeVisible();

    // 2. 验证前端智能自动选定“结构域容器注入 (支持 100% 还原)”，避免用户陷入全部为 -- 的空白状态
    const structBtn = page.locator("button:has-text('结构域容器注入 (支持 100% 还原)')");
    await expect(structBtn).toBeVisible();
    await expect(structBtn).toHaveClass(/bg-cyan-600/);

    // 3. 验证“内容域自适应隐写”按钮被标记为禁用态且提示不支持
    const contentBtn = page.locator("button:has-text('内容域自适应隐写 (此载体不支持)')");
    await expect(contentBtn).toBeVisible();
    await expect(contentBtn).toBeDisabled();
  });
});
