import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { focusAnchor, stickyHeaderOffset } from "./focusAnchor";

// ── jsdom 无布局：getBoundingClientRect 全 0，逐用例注入假 rect；scrollTo/scrollY stub ──

/** rect stub：height 由 top/bottom 推导（与真实布局一致），支持事后变高（ref 覆写）。 */
function stubRect(el: Element, top: number, bottom: number) {
  el.getBoundingClientRect = () => ({ top, bottom, height: bottom - top }) as DOMRect;
}

function stubScrollY(y: number) {
  Object.defineProperty(window, "scrollY", { value: y, configurable: true });
}

/** 造一个带 id 的目标元素（+可选高度感 rect）。 */
function mountTarget(id: string, top = 1000): HTMLElement {
  const el = document.createElement("section");
  el.id = id;
  document.body.appendChild(el);
  stubRect(el, top, top + 400);
  return el;
}

/** 造 sticky 头元素（topbar / scan-sticky-header）。stickyTop 模拟 CSS top（内联样式，
 *  jsdom computed 可解析；真实页面为 tailwind top-12/top-0 → "48px"/"0px"）。 */
function mountSticky(testid: string, bottom: number, stickyTop?: string) {
  const el = document.createElement("div");
  el.setAttribute("data-testid", testid);
  if (stickyTop !== undefined) el.style.top = stickyTop;
  document.body.appendChild(el);
  stubRect(el, 0, bottom);
  return el;
}

describe("stickyHeaderOffset — 运行时量 sticky 遮蔽带", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("TopBar + scan sticky 块都在 → 取 max(bottom) + 呼吸余量 8px", () => {
    mountSticky("topbar", 48);
    mountSticky("scan-sticky-header", 150);
    expect(stickyHeaderOffset()).toBe(158);
  });

  // ── 2026-09-11 修复：未贴顶量取偏差。报告页 sticky 头上方有 ~102px 页面内容，
  //    页面在顶部点击目录时 sticky 未贴顶（rect.bottom=自然位 293，比贴顶底 191
  //    大 102）→ 落点恒定过头。量「理论贴顶底」= computedTop + height（与滚动
  //    状态无关），未贴顶/贴顶两种时刻量取值一致。 ──
  it("sticky 未贴顶（自然位 bottom 293）→ 按理论贴顶底 computedTop+height 量取", () => {
    mountSticky("topbar", 48, "0px");
    // 未贴顶：rect top=150（自然位），height=143 → 理论贴顶底 48+143=191
    const st = mountSticky("scan-sticky-header", 293, "48px");
    st.getBoundingClientRect = () => ({ top: 150, bottom: 293, height: 143 }) as DOMRect;
    expect(stickyHeaderOffset()).toBe(191 + 8);
  });

  it("sticky 已贴顶 → 理论贴顶底与 rect.bottom 一致（不回归）", () => {
    mountSticky("topbar", 48, "0px");
    const st = mountSticky("scan-sticky-header", 191, "48px");
    st.getBoundingClientRect = () => ({ top: 48, bottom: 191, height: 143 }) as DOMRect;
    expect(stickyHeaderOffset()).toBe(191 + 8);
  });

  it("computedTop 解析失败（jsdom 无样式 / 旧环境）→ 回落 rect.bottom（旧语义）", () => {
    mountSticky("topbar", 48);
    mountSticky("scan-sticky-header", 150);
    expect(stickyHeaderOffset()).toBe(158);
  });

  it("只有 TopBar（非 scan 页）→ topbar.bottom + 8", () => {
    mountSticky("topbar", 48);
    expect(stickyHeaderOffset()).toBe(56);
  });

  it("sticky 元素缺席 → 只留呼吸余量", () => {
    expect(stickyHeaderOffset()).toBe(8);
  });
});

describe("focusAnchor — 目录/锚点精准定位 + 闪烁反馈", () => {
  let scrollTo: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    stubScrollY(0);
  });
  afterEach(() => {
    document.body.innerHTML = "";
    vi.restoreAllMocks();
  });

  it("目标缺席 → false 且不滚动不闪烁", () => {
    expect(focusAnchor("nope")).toBe(false);
    expect(scrollTo).not.toHaveBeenCalled();
  });

  it("命中 → scrollTo top = el.top + scrollY − 遮蔽带（behavior smooth）+ 目标加 flash 描边", () => {
    mountSticky("topbar", 48);
    mountSticky("scan-sticky-header", 150);
    stubScrollY(300);
    const el = mountTarget("VULN-1", 1000);
    expect(focusAnchor("VULN-1")).toBe(true);
    // 1000 + 300 − 158 = 1142：卡片顶落在遮蔽带下沿 +8px，而非 scroll-mt-20 的 80px
    expect(scrollTo).toHaveBeenCalledWith({ top: 1142, behavior: "smooth" });
    expect(el.classList.contains("dataflow-flash")).toBe(true);
  });

  it("计算值为负 → 钳到 0（目标本就在页首）", () => {
    mountSticky("topbar", 48);
    mountTarget("VULN-2", 20);
    focusAnchor("VULN-2");
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });
  });

  it("单一 active-target：连点第二个目标，旧目标描边被摘除", () => {
    const a = mountTarget("VULN-A", 500);
    const b = mountTarget("VULN-B", 1500);
    focusAnchor("VULN-A");
    focusAnchor("VULN-B");
    expect(a.classList.contains("dataflow-flash")).toBe(false);
    expect(b.classList.contains("dataflow-flash")).toBe(true);
  });

  it("闪烁 2s 后自动清理（timer 兜底，jsdom 无动画事件）", () => {
    vi.useFakeTimers();
    try {
      const el = mountTarget("VULN-C", 900);
      focusAnchor("VULN-C");
      expect(el.classList.contains("dataflow-flash")).toBe(true);
      vi.advanceTimersByTime(2000);
      expect(el.classList.contains("dataflow-flash")).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("自定义 resolve（dataflow 的 data-tree-id 查找）→ 同样精准定位", () => {
    const el = document.createElement("div");
    el.setAttribute("data-tree-id", "T-1");
    document.body.appendChild(el);
    stubRect(el, 800, 1200);
    const resolve = (id: string) => document.querySelector(`[data-tree-id="${id}"]`);
    expect(focusAnchor("T-1", resolve)).toBe(true);
    expect(scrollTo).toHaveBeenCalledWith({ top: 792, behavior: "smooth" });
    expect(el.classList.contains("dataflow-flash")).toBe(true);
  });
});

// ── 2026-09-11 修复：滚动后校正。smooth 滚动数百 ms 内 sticky 头可能长高
//    （报告页进度概览订阅 SSE 事件重放，打开页面后内容逐步增长）——点击时刻
//    量取的遮蔽带 < 滚动完成时真实遮蔽带 → 目标标题被遮。滚动结束
//    （scrollend，timeout 兜底）后重量一次，偏差 >1px 补一次 instant 微调。 ──
describe("focusAnchor — 滚动结束后校正（sticky 长高场景）", () => {
  let scrollTo: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    scrollTo = vi.fn();
    window.scrollTo = scrollTo as unknown as typeof window.scrollTo;
    stubScrollY(0);
  });
  afterEach(() => {
    document.body.innerHTML = "";
    window.dispatchEvent(new Event("scrollend")); // 清残留校正监听
    vi.restoreAllMocks();
  });

  /** 场景脚手架：topbar(48) + scan sticky（可变高）+ 目标 el。 */
  function scene() {
    const topbar = mountSticky("topbar", 48, "0px");
    const sticky = mountSticky("scan-sticky-header", 191, "48px");
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 191, height: 143 }) as DOMRect;
    const el = mountTarget("VULN-X", 1000);
    stubScrollY(800);
    return { topbar, sticky, el };
  }

  it("scrollend 后 sticky 长高 → 补一次 instant 微调让目标回到遮蔽带下", () => {
    const { sticky, el } = scene();
    focusAnchor("VULN-X");
    // 点击时刻：offset=199，落点 = 1000+800−199 = 1601（smooth）
    expect(scrollTo).toHaveBeenCalledWith({ top: 1601, behavior: "smooth" });
    // smooth 结束：页面滚到 1601；期间 sticky 长高 100（height 243）、目标相对视口被压到 191
    stubScrollY(1601);
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 291, height: 243 }) as DOMRect;
    el.getBoundingClientRect = () => ({ top: 191, bottom: 591, height: 400 }) as DOMRect;
    window.dispatchEvent(new Event("scrollend"));
    // 校正：期望 el.top=offset=291+8=299 → 新落点 = 191+1601−299 = 1493（instant）
    expect(scrollTo).toHaveBeenLastCalledWith({ top: 1493, behavior: "instant" });
  });

  it("scrollend 时用户已滚走（scrollY 与落点差 >5px）→ 放弃校正", () => {
    const { sticky, el } = scene();
    focusAnchor("VULN-X");
    stubScrollY(1750); // 用户接着滚了 149px
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 291, height: 243 }) as DOMRect;
    el.getBoundingClientRect = () => ({ top: 42, bottom: 442, height: 400 }) as DOMRect;
    window.dispatchEvent(new Event("scrollend"));
    expect(scrollTo).toHaveBeenCalledTimes(1); // 只有初始 smooth
  });

  it("校正目标物理不可达（超 maxScroll）→ 放弃", () => {
    const { sticky, el } = scene();
    focusAnchor("VULN-X");
    stubScrollY(1601);
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 291, height: 243 }) as DOMRect;
    el.getBoundingClientRect = () => ({ top: 191, bottom: 591, height: 400 }) as DOMRect;
    // 校正目标 1493，但页面只够滚到 1400（scrollHeight 2300 − innerHeight 900）
    Object.defineProperty(document.documentElement, "scrollHeight", {
      value: 2300, configurable: true,
    });
    Object.defineProperty(window, "innerHeight", { value: 900, configurable: true });
    window.dispatchEvent(new Event("scrollend"));
    expect(scrollTo).toHaveBeenCalledTimes(1); // 只有初始 smooth，不硬滚
    // 还原实例属性覆盖（回落原型 getter），防泄漏进后续用例把可分校正误判不可达
    delete (document.documentElement as { scrollHeight?: number }).scrollHeight;
    delete (window as { innerHeight?: number }).innerHeight;
  });

  it("连点第二个目标 → 旧校正作废，只校正新目标（单例语义）", () => {
    const { sticky } = scene();
    const b = mountTarget("VULN-B", 3000);
    focusAnchor("VULN-X"); // 落点 1601
    focusAnchor("VULN-B"); // 落点 = 3000+800−199 = 3601
    stubScrollY(3601);
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 291, height: 243 }) as DOMRect;
    b.getBoundingClientRect = () => ({ top: 191, bottom: 591, height: 400 }) as DOMRect;
    window.dispatchEvent(new Event("scrollend"));
    // 只校正 B：新落点 = 191+3601−299 = 3493
    expect(scrollTo).toHaveBeenLastCalledWith({ top: 3493, behavior: "instant" });
    expect(scrollTo).toHaveBeenCalledTimes(3); // X smooth + B smooth + B 校正
  });

  it("无偏差（sticky 未变）→ 不补滚", () => {
    const { sticky, el } = scene();
    focusAnchor("VULN-X");
    stubScrollY(1601);
    el.getBoundingClientRect = () => ({ top: 199, bottom: 599, height: 400 }) as DOMRect; // 恰在带下 8px
    sticky.getBoundingClientRect = () => ({ top: 48, bottom: 191, height: 143 }) as DOMRect;
    window.dispatchEvent(new Event("scrollend"));
    expect(scrollTo).toHaveBeenCalledTimes(1);
  });
});
