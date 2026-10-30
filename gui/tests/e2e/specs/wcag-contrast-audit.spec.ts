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
}

const TABS = ["stego", "hide", "extract", "scan"];

test.describe("WCAG 对比度审查", () => {
  for (const theme of ["light", "dark"] as const) {
    test(`四个页签工作态对比度 - ${theme}`, async ({ page }) => {
      await page.addInitScript((th) => {
        localStorage.setItem("strhide_theme", th);
      }, theme);
      await page.addInitScript(
        createTauriMockScript({
          files: ["C:\\\\Samples\\\\photo.png", "C:\\\\Samples\\\\archive.zip"],
        }),
      );
      await page.goto("http://localhost:1420");

      const violations: ContrastViolation[] = [];

      for (const tab of TABS) {
        await page.locator(`[data-testid=tab-${tab}]`).click();
        const addBtn = page.locator("button:has-text('添加文件'):visible");
        if (await addBtn.count()) await addBtn.click();
        await page.waitForTimeout(200);

        if (tab === "stego") {
          const textarea = page.locator("textarea:visible");
          if (await textarea.count()) await textarea.fill("hello");
          const runBtn = page.locator("button:has-text('开始隐写'):visible");
          if (await runBtn.count()) {
            await runBtn.click();
            await page.waitForTimeout(300);
          }
        }

        const issues = await page.evaluate(() => {
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

          function blend(
            fg: [number, number, number, number],
            bg: [number, number, number],
          ): [number, number, number] {
            const a = fg[3];
            return [
              Math.round(fg[0] * a + bg[0] * (1 - a)),
              Math.round(fg[1] * a + bg[1] * (1 - a)),
              Math.round(fg[2] * a + bg[2] * (1 - a)),
            ];
          }

          function effectiveBg(el: HTMLElement): [number, number, number] {
            let cur: HTMLElement | null = el;
            const layers: [number, number, number, number][] = [];
            while (cur && cur !== document.documentElement) {
              const style = window.getComputedStyle(cur);
              const bg = parseRgb(style.backgroundColor);
              if (bg[3] > 0) {
                layers.unshift(bg);
                if (bg[3] >= 0.99) break;
              }
              cur = cur.parentElement;
            }
            const rootBg = parseRgb(window.getComputedStyle(document.body).backgroundColor);
            let base: [number, number, number] = [rootBg[0], rootBg[1], rootBg[2]];
            for (const layer of layers) base = blend(layer, base);
            return base;
          }

          const issues: {
            element: string;
            text: string;
            fg: string;
            bg: string;
            ratio: number;
            expected: number;
          }[] = [];

          const seen = new Set<string>();
          const nodes = Array.from(
            document.querySelectorAll<HTMLElement>(
              "p, span, h1, h2, h3, h4, h5, h6, button, a, label, input, textarea, td, th, li",
            ),
          );

          for (const el of nodes) {
            const rect = el.getBoundingClientRect();
            if (rect.width === 0 || rect.height === 0) continue;
            const style = window.getComputedStyle(el);
            if (style.visibility === "hidden" || style.display === "none" || parseFloat(style.opacity) < 0.1)
              continue;

            const text = (
              el.innerText ||
              (el as HTMLInputElement).value ||
              (el as HTMLInputElement).placeholder ||
              ""
            ).trim();
            if (!text || text.length > 60) continue;
            if (text.length === 1 && (text === "S" || text === "·" || text === "/" || text === "×")) continue;

            const key = `${el.tagName}:${text}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const fgRgba = parseRgb(style.color);
            const bg = effectiveBg(el);
            const fg = fgRgba[3] < 1 ? blend(fgRgba, bg) : [fgRgba[0], fgRgba[1], fgRgba[2]];
            const l1 = getLum(fg[0], fg[1], fg[2]);
            const l2 = getLum(bg[0], bg[1], bg[2]);
            const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

            const fontSize = parseFloat(style.fontSize);
            const isBold = parseInt(style.fontWeight, 10) >= 700 || style.fontWeight === "bold";
            const isLarge = fontSize >= 24 || (fontSize >= 18.66 && isBold);
            const expected = isLarge ? 3.0 : 4.5;

            if (ratio < expected) {
              issues.push({
                element: `${el.tagName.toLowerCase()}.${el.className.split(" ").slice(0, 3).join(".")}`,
                text: text.slice(0, 35),
                fg: `rgb(${fg.join(",")})`,
                bg: `rgb(${bg.join(",")})`,
                ratio: Math.round(ratio * 100) / 100,
                expected,
              });
            }
          }
          return issues;
        });

        for (const issue of issues) {
          violations.push({ theme, pageName: tab, ...issue });
        }
      }

      console.log(`\n=== 对比度审查 [${theme}] 共 ${violations.length} 处 ===`);
      for (const v of violations) {
        console.log(
          `[${v.pageName}] ${v.element} | "${v.text}" | ${v.fg} on ${v.bg} | ${v.ratio}:1 (>= ${v.expected}:1)`,
        );
      }

      expect(violations.length).toBe(0);
    });
  }
});
