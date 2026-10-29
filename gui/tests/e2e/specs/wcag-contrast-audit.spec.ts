import { test, expect } from "@playwright/test";
import { createTauriMockScript } from "../fixtures";

interface ContrastViolation {
  theme: "light" | "dark";
  pageName: string;
  element: string;
  text: string;
  fg: string;
  bg: string;
  ratio: number;
  expected: number;
  type: "text" | "large-text" | "ui";
}

test.describe("WCAG 对比度与可访问性全面审查", () => {
  const themes: ("light" | "dark")[] = ["light", "dark"];

  for (const theme of themes) {
    test(`扫描未载入载体初始态对比度 - ${theme} 主题`, async ({ page }) => {
      await page.addInitScript(createTauriMockScript({
        carrierPath: "",
      }));
      await page.goto("http://localhost:1420");

      await page.evaluate((th) => {
        document.documentElement.setAttribute("data-theme", th);
        localStorage.setItem("strhide_theme", th);
      }, theme);

      await page.waitForTimeout(300);

      const navButtons = [
        { name: "检视与智能提取", selector: "button:has-text('检视与智能提取')" },
        { name: "隐藏与自适应嵌入", selector: "button:has-text('隐藏与自适应嵌入')" },
        { name: "三级校验与无损还原", selector: "button:has-text('三级校验与无损还原')" },
        { name: "反隐写取证与批处理", selector: "button:has-text('反隐写取证与批处理')" },
      ];

      const violations: ContrastViolation[] = [];

      for (const nav of navButtons) {
        await page.locator(nav.selector).click();
        await page.waitForTimeout(200);

        const results = await page.evaluate((pageName) => {
          function parseRgb(colorStr: string): [number, number, number, number] {
            const m = colorStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
            if (!m) return [0, 0, 0, 1];
            return [
              parseInt(m[1], 10),
              parseInt(m[2], 10),
              parseInt(m[3], 10),
              m[4] !== undefined ? parseFloat(m[4]) : 1,
            ];
          }

          function getLum(r: number, g: number, b: number): number {
            const [rs, gs, bs] = [r, g, b].map((c) => {
              const s = c / 255;
              return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
            });
            return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
          }

          function blend(fgRgba: [number, number, number, number], bgRgb: [number, number, number]): [number, number, number] {
            const a = fgRgba[3];
            return [
              Math.round(fgRgba[0] * a + bgRgb[0] * (1 - a)),
              Math.round(fgRgba[1] * a + bgRgb[1] * (1 - a)),
              Math.round(fgRgba[2] * a + bgRgb[2] * (1 - a)),
            ];
          }

          function getEffectiveBg(el: HTMLElement): [number, number, number] {
            let cur: HTMLElement | null = el;
            const layers: [number, number, number, number][] = [];

            while (cur && cur !== document.documentElement) {
              const style = window.getComputedStyle(cur);
              if (style.backgroundImage && style.backgroundImage.includes("linear-gradient")) {
                const matches = Array.from(style.backgroundImage.matchAll(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/g));
                if (matches.length > 0) {
                  let avgR = 0, avgG = 0, avgB = 0;
                  for (const m of matches) {
                    avgR += parseInt(m[1], 10);
                    avgG += parseInt(m[2], 10);
                    avgB += parseInt(m[3], 10);
                  }
                  layers.unshift([
                    Math.round(avgR / matches.length),
                    Math.round(avgG / matches.length),
                    Math.round(avgB / matches.length),
                    1,
                  ]);
                  break;
                }
              }

              const bg = parseRgb(style.backgroundColor);
              if (bg[3] > 0) {
                layers.unshift(bg);
                if (bg[3] >= 0.99) break;
              }
              cur = cur.parentElement;
            }

            const rootStyle = window.getComputedStyle(document.body);
            const rootBg = parseRgb(rootStyle.backgroundColor);
            let base: [number, number, number] = [rootBg[0], rootBg[1], rootBg[2]];

            for (const layer of layers) {
              base = blend(layer, base);
            }
            return base;
          }

          const elements = Array.from(document.querySelectorAll<HTMLElement>("p, span, h1, h2, h3, h4, h5, h6, button, a, label, input, textarea, td, th"));
          const issues: {
            element: string;
            text: string;
            fg: string;
            bg: string;
            ratio: number;
            expected: number;
            type: "text" | "large-text" | "ui";
          }[] = [];

          const seenTexts = new Set<string>();

          for (const el of elements) {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            const style = window.getComputedStyle(el);
            if (style.visibility === "hidden" || style.display === "none" || parseFloat(style.opacity) < 0.1) continue;

            const text = (el.innerText || (el as HTMLInputElement).value || (el as HTMLInputElement).placeholder || "").trim();
            if (!text || text.length > 60) continue;

            if (text.length === 1 && (text === "S" || text === "·" || text === "/" || text === "×")) continue;

            const textKey = `${el.tagName}:${text}`;
            if (seenTexts.has(textKey)) continue;
            seenTexts.add(textKey);

            const fgRgba = parseRgb(style.color);
            const bgRgb = getEffectiveBg(el);
            const actualFg = fgRgba[3] < 1 ? blend(fgRgba, bgRgb) : [fgRgba[0], fgRgba[1], fgRgba[2]];

            const l1 = getLum(actualFg[0], actualFg[1], actualFg[2]);
            const l2 = getLum(bgRgb[0], bgRgb[1], bgRgb[2]);
            const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

            const fontSize = parseFloat(style.fontSize);
            const isBold = parseInt(style.fontWeight, 10) >= 700 || style.fontWeight === "bold";
            const isLarge = fontSize >= 24 || (fontSize >= 18.66 && isBold);
            const expected = isLarge ? 3.0 : 4.5;

            if (ratio < expected) {
              issues.push({
                element: `${el.tagName.toLowerCase()}.${el.className.split(" ").slice(0, 3).join(".")}`,
                text: text.slice(0, 35),
                fg: `rgb(${actualFg.join(",")})`,
                bg: `rgb(${bgRgb.join(",")})`,
                ratio: Math.round(ratio * 100) / 100,
                expected,
                type: isLarge ? "large-text" : "text",
              });
            }
          }
          return issues;
        }, nav.name);

        for (const item of results) {
          violations.push({
            theme,
            pageName: nav.name,
            ...item,
          });
        }
      }

      console.log(`\n=== WCAG 初始态审查报告 [${theme.toUpperCase()}] 共有 ${violations.length} 处违规 ===`);
      for (const v of violations) {
        console.log(`[${v.pageName}] ${v.element} | 文本: "${v.text}" | 前景: ${v.fg} 背景: ${v.bg} | 对比度: ${v.ratio}:1 (期望 >= ${v.expected}:1)`);
      }

      expect(violations.length).toBe(0);
    });

    test(`扫描载入载体后全功能工作态对比度 - ${theme} 主题`, async ({ page }) => {
      await page.addInitScript(createTauriMockScript({
        carrierPath: "C:\\Samples\\holiday_photo.png",
        hasHiddenData: true,
        suspiciousHints: ["检测到隐写特征"],
      }));
      await page.goto("http://localhost:1420");

      await page.evaluate((th) => {
        document.documentElement.setAttribute("data-theme", th);
        localStorage.setItem("strhide_theme", th);
      }, theme);

      await page.locator("text=拖拽载体文件至此").click();
      await page.waitForTimeout(300);

      const navButtons = [
        { name: "检视与智能提取", selector: "button:has-text('检视与智能提取')" },
        { name: "隐藏与自适应嵌入", selector: "button:has-text('隐藏与自适应嵌入')" },
        { name: "三级校验与无损还原", selector: "button:has-text('三级校验与无损还原')" },
        { name: "反隐写取证与批处理", selector: "button:has-text('反隐写取证与批处理')" },
      ];

      const violations: ContrastViolation[] = [];

      for (const nav of navButtons) {
        await page.locator(nav.selector).click();
        await page.waitForTimeout(400);

        if (nav.name === "隐藏与自适应嵌入") {
          const fileBtn = page.locator("button:has-text('本地文件')");
          if (await fileBtn.isVisible()) {
            await fileBtn.click();
            await page.waitForTimeout(200);
          }
        }

        const results = await page.evaluate((pageName) => {
          function parseRgb(colorStr: string): [number, number, number, number] {
            const m = colorStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
            if (!m) return [0, 0, 0, 1];
            return [
              parseInt(m[1], 10),
              parseInt(m[2], 10),
              parseInt(m[3], 10),
              m[4] !== undefined ? parseFloat(m[4]) : 1,
            ];
          }

          function getLum(r: number, g: number, b: number): number {
            const [rs, gs, bs] = [r, g, b].map((c) => {
              const s = c / 255;
              return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
            });
            return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
          }

          function blend(fgRgba: [number, number, number, number], bgRgb: [number, number, number]): [number, number, number] {
            const a = fgRgba[3];
            return [
              Math.round(fgRgba[0] * a + bgRgb[0] * (1 - a)),
              Math.round(fgRgba[1] * a + bgRgb[1] * (1 - a)),
              Math.round(fgRgba[2] * a + bgRgb[2] * (1 - a)),
            ];
          }

          function getEffectiveBg(el: HTMLElement): [number, number, number] {
            let cur: HTMLElement | null = el;
            const layers: [number, number, number, number][] = [];

            while (cur && cur !== document.documentElement) {
              const style = window.getComputedStyle(cur);
              if (style.backgroundImage && style.backgroundImage.includes("linear-gradient")) {
                const matches = Array.from(style.backgroundImage.matchAll(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/g));
                if (matches.length > 0) {
                  let avgR = 0, avgG = 0, avgB = 0;
                  for (const m of matches) {
                    avgR += parseInt(m[1], 10);
                    avgG += parseInt(m[2], 10);
                    avgB += parseInt(m[3], 10);
                  }
                  layers.unshift([
                    Math.round(avgR / matches.length),
                    Math.round(avgG / matches.length),
                    Math.round(avgB / matches.length),
                    1,
                  ]);
                  break;
                }
              }

              const bg = parseRgb(style.backgroundColor);
              if (bg[3] > 0) {
                layers.unshift(bg);
                if (bg[3] >= 0.99) break;
              }
              cur = cur.parentElement;
            }

            const rootStyle = window.getComputedStyle(document.body);
            const rootBg = parseRgb(rootStyle.backgroundColor);
            let base: [number, number, number] = [rootBg[0], rootBg[1], rootBg[2]];

            for (const layer of layers) {
              base = blend(layer, base);
            }
            return base;
          }

          const elements = Array.from(document.querySelectorAll<HTMLElement>("p, span, h1, h2, h3, h4, h5, h6, button, a, label, input, textarea, td, th"));
          const issues: {
            element: string;
            text: string;
            fg: string;
            bg: string;
            ratio: number;
            expected: number;
            type: "text" | "large-text" | "ui";
          }[] = [];

          const seenTexts = new Set<string>();

          for (const el of elements) {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            const style = window.getComputedStyle(el);
            if (style.visibility === "hidden" || style.display === "none" || parseFloat(style.opacity) < 0.1) continue;

            const text = (el.innerText || (el as HTMLInputElement).value || (el as HTMLInputElement).placeholder || "").trim();
            if (!text || text.length > 60) continue;

            if (text.length === 1 && (text === "S" || text === "·" || text === "/" || text === "×")) continue;

            const textKey = `${el.tagName}:${text}`;
            if (seenTexts.has(textKey)) continue;
            seenTexts.add(textKey);

            const fgRgba = parseRgb(style.color);
            const bgRgb = getEffectiveBg(el);
            const actualFg = fgRgba[3] < 1 ? blend(fgRgba, bgRgb) : [fgRgba[0], fgRgba[1], fgRgba[2]];

            const l1 = getLum(actualFg[0], actualFg[1], actualFg[2]);
            const l2 = getLum(bgRgb[0], bgRgb[1], bgRgb[2]);
            const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

            const fontSize = parseFloat(style.fontSize);
            const isBold = parseInt(style.fontWeight, 10) >= 700 || style.fontWeight === "bold";
            const isLarge = fontSize >= 24 || (fontSize >= 18.66 && isBold);
            const expected = isLarge ? 3.0 : 4.5;

            if (ratio < expected) {
              issues.push({
                element: `${el.tagName.toLowerCase()}.${el.className.split(" ").slice(0, 3).join(".")}`,
                text: text.slice(0, 35),
                fg: `rgb(${actualFg.join(",")})`,
                bg: `rgb(${bgRgb.join(",")})`,
                ratio: Math.round(ratio * 100) / 100,
                expected,
                type: isLarge ? "large-text" : "text",
              });
            }
          }
          return issues;
        }, nav.name);

        for (const item of results) {
          violations.push({
            theme,
            pageName: nav.name,
            ...item,
          });
        }
      }

      console.log(`\n=== WCAG 全功能工作态审查报告 [${theme.toUpperCase()}] 共有 ${violations.length} 处违规 ===`);
      for (const v of violations) {
        console.log(`[${v.pageName}] ${v.element} | 文本: "${v.text}" | 前景: ${v.fg} 背景: ${v.bg} | 对比度: ${v.ratio}:1 (期望 >= ${v.expected}:1)`);
      }

      expect(violations.length).toBe(0);
    });
  }
});
