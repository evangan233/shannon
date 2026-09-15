import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, fireEvent, act } from "@testing-library/react";
import i18n from "@/i18n";
import { ReportToc, REPORT_EXEC_SUMMARY_ID, REPORT_CHAINS_ID } from "./ReportToc";
import type { ReportData, ReportVulnerability } from "@/api/types";

// ── fixture：与 ReportView.test 同形（只喂目录所需字段的最小合法集）──

const vuln = (id: string, title: string, severity: string): ReportVulnerability => ({
  id,
  type: "xss",
  vulnerability_type: "Stored",
  title,
  severity,
  confidence: "high",
  cwe_id: "CWE-79",
  externally_exploitable: true,
  merge_source: "both",
  merged_from: [],
  narrative: { cause: "c", impact: "i", remediation: "r" },
  endpoints: [],
  affected_entries: [],
  dataflow_steps: [],
  poc: null,
  evidence: null,
  attack_chain_refs: [],
});

const data: ReportData = {
  schema_version: 1,
  scan: { id: "scan-1", track: "whitebox", repo: "NodeGoat" },
  executive_summary: {
    narrative: "n",
    risk_level: "极高",
    top_risks: [],
    remediation_order: "r",
  },
  stats: null,
  vulnerabilities: [vuln("XSS-VULN-01", "备忘录存储型 XSS", "high"), vuln("INJ-VULN-02", "NoSQL 注入", "critical")],
  attack_chains: [{ id: "CHAIN-1", narrative: "链叙事" }],
  qa: null,
};

/** 挂目标锚点元素（目录点击定位的落点）。 */
function mountAnchor(id: string) {
  const el = document.createElement("section");
  el.id = id;
  document.body.appendChild(el);
  return el;
}

// —— IntersectionObserver stub（jsdom 无实现，scrollspy 需手动喂 entry），
//    对齐 TocSideBar.test 的 MockIO 模式 ——
class MockIO {
  static instances: MockIO[] = [];
  cb: IntersectionObserverCallback;
  observed: Element[] = [];
  constructor(cb: IntersectionObserverCallback) {
    this.cb = cb;
    MockIO.instances.push(this);
  }
  observe(el: Element) {
    this.observed.push(el);
  }
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}

/** 挂 sticky 遮蔽带元素并量出固定几何：TopBar(0→48) + scan sticky 头(48→stickyBottom)
 *  → stickyHeaderOffset() = stickyBottom + 8 呼吸（jsdom getComputedStyle 无样式，
 *  pinnedBottom 走 rect.bottom 回落分支，mock rect 即可控制量取值）。 */
function mountStickyBand(stickyBottom: number) {
  const mk = (testid: string, top: number, bottom: number) => {
    const el = document.createElement("div");
    el.setAttribute("data-testid", testid);
    el.getBoundingClientRect = () =>
      ({ top, bottom, height: bottom - top, left: 0, right: 0, width: 0, x: 0, y: top, toJSON: () => ({}) }) as DOMRect;
    document.body.appendChild(el);
  };
  mk("topbar", 0, 48);
  mk("scan-sticky-header", 48, stickyBottom);
}

/** 给锚点元素挂固定视口几何（复现「点击跳转完成后」的真实布局：
 *  前卡尾=目标顶−16px gap；目标顶=遮蔽带下沿 199px）。 */
function setViewportRect(el: Element, top: number, bottom: number) {
  el.getBoundingClientRect = () =>
    ({ top, bottom, height: bottom - top, left: 0, right: 0, width: 0, x: 0, y: top, toJSON: () => ({}) }) as DOMRect;
}

describe("ReportToc — 报告目录（2026-08-26 结构化路径新增）", () => {
  let scrollTo: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    i18n.changeLanguage("zh");
    scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
  });
  afterEach(() => {
    i18n.changeLanguage("zh");
    document.body.innerHTML = "";
  });

  it("分组镜像区块：执行摘要 + 漏洞 (N) + 攻击链 (N)，漏洞条目带 severity 点与标题小字", () => {
    const { container } = render(<ReportToc data={data} />);
    expect(container.textContent ?? "").toContain("漏洞 (2)");
    expect(container.textContent ?? "").toContain("攻击链 (1)");
    expect(container.querySelector(`[data-toc-id="${REPORT_EXEC_SUMMARY_ID}"]`)).toBeTruthy();
    const entry = container.querySelector('[data-toc-id="XSS-VULN-01"]');
    expect(entry?.getAttribute("data-severity")).toBe("high");
    expect(entry?.textContent ?? "").toContain("备忘录存储型 XSS");
    // severity 状态点：critical 条目用 --c-red（与卡 SEV_DOT 同源）
    const critEntry = container.querySelector('[data-toc-id="INJ-VULN-02"]');
    const dot = critEntry?.querySelector("span[style]") as HTMLElement | null;
    expect(dot?.getAttribute("style") ?? "").toContain("hsl(var(--c-red))");
  });

  it("点击漏洞条目 → focusAnchor 精准定位（scrollTo smooth）+ 目标卡描边闪烁 + 立即高亮", () => {
    const target = mountAnchor("XSS-VULN-01");
    const { container } = render(<ReportToc data={data} />);
    fireEvent.click(container.querySelector('[data-toc-id="XSS-VULN-01"]')!);
    expect(scrollTo).toHaveBeenCalledTimes(1);
    expect(scrollTo.mock.calls[0][0]).toEqual({ top: expect.any(Number), behavior: "smooth" });
    expect(target.classList.contains("dataflow-flash")).toBe(true);
    // 点击立即置 active（不等 scrollspy 回填）
    expect(
      container.querySelector('[data-toc-id="XSS-VULN-01"]')!.getAttribute("aria-current"),
    ).toBe("true");
  });

  it("点击攻击链分组条目 → 定位 report-chains 锚点", () => {
    const target = mountAnchor(REPORT_CHAINS_ID);
    const { container } = render(<ReportToc data={data} />);
    fireEvent.click(container.querySelector(`[data-toc-id="${REPORT_CHAINS_ID}"]`)!);
    expect(scrollTo).toHaveBeenCalled();
    expect(target.classList.contains("dataflow-flash")).toBe(true);
  });

  it("无执行摘要 / 无攻击链 → 对应条目与分组不渲染", () => {
    const { container } = render(
      <ReportToc data={{ ...data, executive_summary: null, attack_chains: [] }} />,
    );
    expect(container.querySelector(`[data-toc-id="${REPORT_EXEC_SUMMARY_ID}"]`)).toBeNull();
    expect(container.querySelector(`[data-toc-id="${REPORT_CHAINS_ID}"]`)).toBeNull();
    expect(container.textContent ?? "").not.toContain("攻击链");
  });

  it("jsdom 无 IntersectionObserver → 渲染与点击不受影响（scrollspy 跳过）", () => {
    const target = mountAnchor("INJ-VULN-02");
    const { container } = render(<ReportToc data={data} />);
    fireEvent.click(container.querySelector('[data-toc-id="INJ-VULN-02"]')!);
    expect(target.classList.contains("dataflow-flash")).toBe(true);
  });
});

describe("ReportToc — scrollspy 判定带与跳转落点同源（2026-09-15 修「高亮前一个」）", () => {
  beforeEach(() => {
    MockIO.instances = [];
    vi.stubGlobal("IntersectionObserver", MockIO);
    window.scrollTo = vi.fn();
  });
  afterEach(() => {
    // 顶层平级块（外层 describe 的 afterEach 不跨块生效）——必须自清 body，
    // 否则前条用例的锚点/几何 mock 残留，getElementById 取到旧元素污染后续用例。
    document.body.innerHTML = "";
    vi.unstubAllGlobals();
  });

  /** 渲染目录 + 挂锚点并复现「点击跳转完成后」几何，返回容器。
   *  前卡尾 bottom = 目标顶 − 16px(space-y-4 gap)；目标顶 = 遮蔽带下沿。 */
  function setupJumpGeometry(stickyBottom: number, gap = 16) {
    mountStickyBand(stickyBottom);
    const prev = mountAnchor("XSS-VULN-01");
    const target = mountAnchor("INJ-VULN-02");
    setViewportRect(prev, -600, stickyBottom + 8 - gap);
    setViewportRect(target, stickyBottom + 8, stickyBottom + 8 + 900);
    const view = render(<ReportToc data={data} />);
    return view;
  }

  it("点击跳转后：目标卡顶部贴遮蔽带下沿、前卡尾只在被遮蔽区 → 高亮目标卡（非前一个）", async () => {
    // 遮蔽带 191px → stickyHeaderOffset=199；jsdom 视口 768 → 旧观察带 [76.8, 307.2]
    const { container } = setupJumpGeometry(191);
    const io = MockIO.instances[0];
    expect(io).toBeTruthy();
    expect(io.observed.length).toBe(2); // 只挂了两张 vuln 卡锚点（exec/chains 未挂）
    // 旧观察带下前卡尾(183>76.8)与目标卡(199<307.2)都「相交」——这正是 bug 几何
    const prev = document.getElementById("XSS-VULN-01")!;
    const target = document.getElementById("INJ-VULN-02")!;
    await act(async () => {
      io.cb(
        [
          { isIntersecting: true, target: prev } as unknown as IntersectionObserverEntry,
          { isIntersecting: true, target } as unknown as IntersectionObserverEntry,
        ],
        io as unknown as IntersectionObserver,
      );
    });
    expect(container.querySelector('[data-toc-id="INJ-VULN-02"]')!.getAttribute("aria-current")).toBe("true");
    expect(container.querySelector('[data-toc-id="XSS-VULN-01"]')!.getAttribute("aria-current")).toBeNull();
  });

  it("普通滚动（前卡独占视线带）→ 仍高亮前卡（文档序第一可见者语义不变）", async () => {
    mountStickyBand(191);
    const prev = mountAnchor("XSS-VULN-01");
    const target = mountAnchor("INJ-VULN-02");
    setViewportRect(prev, 100, 500); // 完整在视线区
    setViewportRect(target, 520, 1400); // 在带下方不可见
    const { container } = render(<ReportToc data={data} />);
    const io = MockIO.instances[0];
    await act(async () => {
      io.cb(
        [
          { isIntersecting: true, target: prev } as unknown as IntersectionObserverEntry,
          { isIntersecting: false, target } as unknown as IntersectionObserverEntry,
        ],
        io as unknown as IntersectionObserver,
      );
    });
    expect(container.querySelector('[data-toc-id="XSS-VULN-01"]')!.getAttribute("aria-current")).toBe("true");
  });

  it("sticky 遮蔽带滚动中长高（SSE 进度概览）→ 回调内实时重量，前卡尾落入新遮蔽区仍被剔除", async () => {
    // IO 创建时遮蔽带 191；之后 sticky 长高到 232（+41），目标落点被 focusAnchor 校正下移
    const { container } = setupJumpGeometry(191);
    const io = MockIO.instances[0];
    const prev = document.getElementById("XSS-VULN-01")!;
    const target = document.getElementById("INJ-VULN-02")!;
    // 模拟校正后几何：遮蔽带 232+8=240；前卡尾 240-16=224；目标顶 240
    document.querySelector('[data-testid="scan-sticky-header"]')!.getBoundingClientRect = () =>
      ({ top: 48, bottom: 232, height: 184, left: 0, right: 0, width: 0, x: 0, y: 48, toJSON: () => ({}) }) as DOMRect;
    setViewportRect(prev, -600, 224);
    setViewportRect(target, 240, 1140);
    await act(async () => {
      io.cb(
        [
          { isIntersecting: true, target: prev } as unknown as IntersectionObserverEntry,
          { isIntersecting: true, target } as unknown as IntersectionObserverEntry,
        ],
        io as unknown as IntersectionObserver,
      );
    });
    expect(container.querySelector('[data-toc-id="INJ-VULN-02"]')!.getAttribute("aria-current")).toBe("true");
  });
});
