import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, waitFor } from "@testing-library/react";
import i18n from "@/i18n";
import { MarkdownView } from "./MarkdownView";

// 真实综合报告结构：多个同级 level-2 章节（各有 vuln 子条目）+ 攻击链。
// 用于复现 scroll-spy 自动展开累积 bug。
const MD = [
  "# 安全评估报告",
  "",
  "## 执行摘要",
  "",
  "- **目标：** demo",
  "",
  "## Injection Vulnerabilities",
  "",
  "### INJ-VULN-01: SQLi",
  "",
  "- **vulnerability_type:** SQLi",
  "",
  "## Cross-Site Scripting (XSS)",
  "",
  "### XSS-VULN-01: Stored",
  "",
  "- **vulnerability_type:** Stored",
  "",
  "## 攻击链（多步利用路径）",
  "",
  "### llm-chain-1: a -> b",
  "",
  "步骤1",
  "",
].join("\n");

// mock IntersectionObserver：记录 observe 的元素，提供 trigger 方法模拟进入视口。
class MockIO {
  static last: MockIO | null = null;
  cb: (entries: any[]) => void;
  targets: Map<HTMLElement, boolean> = new Map();
  constructor(cb: (entries: any[]) => void) {
    this.cb = cb;
    MockIO.last = this;
  }
  observe(el: HTMLElement) {
    this.targets.set(el, false);
  }
  unobserve() {}
  disconnect() {
    this.targets.clear();
  }
  // 模拟某元素进入/离开视口顶部窄带
  trigger(el: HTMLElement, isIntersecting: boolean) {
    this.cb([
      {
        target: el,
        isIntersecting,
        boundingClientRect: { top: isIntersecting ? 100 : 500 },
      },
    ]);
  }
}

describe("TOC scroll-spy 累积展开", () => {
  beforeEach(async () => {
    await i18n.changeLanguage("zh");
    MockIO.last = null;
    (globalThis as any).IntersectionObserver = MockIO as any;
  });
  afterEach(() => {
    delete (globalThis as any).IntersectionObserver;
    document.body.innerHTML = "";
  });

  /** 挂固定视口几何（2026-09-15 判定带对齐遮蔽带后 scrollspy 需真实 rect，
   *  jsdom 默认全 0 会被精确判定剔除）。 */
  function viewportRect(top: number, bottom: number): DOMRect {
    return { top, bottom, height: bottom - top, left: 0, right: 0, width: 0, x: 0, y: top, toJSON: () => ({}) } as DOMRect;
  }

  /** 挂 sticky 遮蔽带元素：TopBar(0→48) + scan sticky 头(48→stickyBottom)
   *  → stickyHeaderOffset() = stickyBottom + 8（jsdom 无样式走 rect.bottom 回落）。 */
  function mountStickyBand(stickyBottom: number) {
    const mk = (testid: string, top: number, bottom: number) => {
      const el = document.createElement("div");
      el.setAttribute("data-testid", testid);
      el.getBoundingClientRect = () => viewportRect(top, bottom);
      document.body.appendChild(el);
    };
    mk("topbar", 0, 48);
    mk("scan-sticky-header", 48, stickyBottom);
  }

  it("滚动到下方章节时，上方同级章节不应保持展开（复现联动 bug）", async () => {
    const { container } = render(<MarkdownView markdown={MD} />);

    // 等 TOC 渲染 + 默认折叠
    await waitFor(() => {
      expect(container.querySelector('[data-testid="toc"]')).not.toBeNull();
    });
    await waitFor(() => {
      expect(container.querySelectorAll('[data-testid="toc-toggle"]').length).toBe(3);
    });

    const toggles = () =>
      Array.from(container.querySelectorAll<HTMLElement>('[data-testid="toc-toggle"]'));

    // 默认全折叠
    expect(toggles().map((b) => b.getAttribute("aria-expanded"))).toEqual([
      "false",
      "false",
      "false",
    ]);

    const io = MockIO.last!;
    expect(io).not.toBeNull();

    // 找到各章节的 vuln/chain 子条目 DOM
    const inj = container.querySelector("#INJ-VULN-01") as HTMLElement;
    const xss = container.querySelector("#XSS-VULN-01") as HTMLElement;
    const chain = container.querySelector("#llm-chain-1") as HTMLElement;
    expect(inj).not.toBeNull();
    expect(xss).not.toBeNull();
    expect(chain).not.toBeNull();
    // 2026-09-15 判定带对齐遮蔽带后需真实几何（trigger 逐条进入视线带）
    inj.getBoundingClientRect = () => viewportRect(100, 500);
    xss.getBoundingClientRect = () => viewportRect(100, 500);
    chain.getBoundingClientRect = () => viewportRect(100, 500);

    // 1) 滚到 INJ-VULN-01（Injection 章节）-> 不自动展开，但 Injection 父标题高亮
    io.trigger(inj, true);
    await waitFor(() => expect(isActive(parentLink(container, 0))).toBe(true));
    // 所有章节保持折叠（不被动展开）
    expect(toggles().map((b) => b.getAttribute("aria-expanded"))).toEqual([
      "false",
      "false",
      "false",
    ]);

    // 2) 滚到 XSS-VULN-01（XSS 章节）-> XSS 父标题高亮，Injection 不再高亮
    io.trigger(xss, true);
    await waitFor(() => expect(isActive(parentLink(container, 1))).toBe(true));
    expect(isActive(parentLink(container, 0))).toBe(false);
    // 仍全折叠
    expect(toggles().map((b) => b.getAttribute("aria-expanded"))).toEqual([
      "false",
      "false",
      "false",
    ]);

    // 3) 滚到 llm-chain-1（攻击链章节）-> 攻击链父标题高亮，上方同级不再高亮
    io.trigger(chain, true);
    await waitFor(() => expect(isActive(parentLink(container, 2))).toBe(true));
    expect(isActive(parentLink(container, 0))).toBe(false);
    expect(isActive(parentLink(container, 1))).toBe(false);

    // ★ 核心回归：滚到下方后，上方同级章节从未被展开（不累积、不联动）
    expect(toggles().map((b) => b.getAttribute("aria-expanded"))).toEqual([
      "false",
      "false",
      "false",
    ]);
  });

  it("跳转落点与判定带同源（2026-09-15 修「高亮前一个」）：目标顶贴遮蔽带下沿、前章尾只在被遮蔽区 → 同批合并通知也高亮目标", async () => {
    mountStickyBand(191); // 遮蔽带 191 → stickyHeaderOffset=199；旧粗筛带 [-80px, 30%] 起点在被遮蔽区
    const { container } = render(<MarkdownView markdown={MD} />);
    await waitFor(() => {
      expect(container.querySelectorAll('[data-testid="toc-toggle"]').length).toBe(3);
    });
    const io = MockIO.last!;
    const inj = container.querySelector("#INJ-VULN-01") as HTMLElement;
    const xss = container.querySelector("#XSS-VULN-01") as HTMLElement;
    // 跳转完成几何：前章尾 = 目标顶 − gap = 183（落在遮蔽区内）；目标顶贴 199。
    inj.getBoundingClientRect = () => viewportRect(-600, 183);
    xss.getBoundingClientRect = () => viewportRect(199, 1099);
    // 快速 smooth 跳转的合并通知批次：两章同批 intersecting（旧实现 sort by top → 前章赢）
    io.cb([
      { target: inj, isIntersecting: true, boundingClientRect: { top: -600 } },
      { target: xss, isIntersecting: true, boundingClientRect: { top: 199 } },
    ]);
    // XSS 父标题高亮，Injection 不被抢
    await waitFor(() => expect(isActive(parentLink(container, 1))).toBe(true));
    expect(isActive(parentLink(container, 0))).toBe(false);
  });
});

// 取第 idx 个 TOC 章节的父标题 <a>（toggle 按钮所在 li 内的 a）。
function parentLink(container: HTMLElement, idx: number): HTMLElement {
  const toggles = container.querySelectorAll<HTMLElement>('[data-testid="toc-toggle"]');
  const li = toggles[idx].closest("li")!;
  return li.querySelector("a")!;
}

// active 父标题 class 含连续的 "bg-accent text-foreground"（非 active 是
// "text-muted-foreground hover:bg-accent/50 hover:text-foreground"，不含该连续串）。
function isActive(a: HTMLElement): boolean {
  return a.className.includes("bg-accent text-foreground");
}
