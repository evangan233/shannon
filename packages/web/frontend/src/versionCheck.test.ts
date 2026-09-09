import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installVersionCheck } from "./versionCheck";

// 生产语义：index.html(no-cache) 里 entry script 的 /assets/index-<hash>.js 就是版本指纹——
// 改前端 hash 必变、改后端不变。检测器在 visibilitychange 切回前台时拉首页比对，变了就 reload。
const OLD_HTML = '<html><head><script type="module" src="/assets/index-OLDHASH.js"></script></head></html>';
const NEW_HTML = '<html><head><script type="module" src="/assets/index-NEWHASH.js"></script></head></html>';

function makeFetch(html: string) {
  return vi.fn(async () => ({ ok: true, text: async () => html }));
}

function mountDocumentWith(html: string) {
  // 模拟「当前页面已被浏览器加载」：document 里带着旧 entry script
  document.body.innerHTML = html.replace(/<\/?html>|<\/?head>/g, "");
}

function becomeVisible() {
  Object.defineProperty(document, "visibilityState", {
    value: "visible",
    configurable: true,
  });
  document.dispatchEvent(new Event("visibilitychange"));
}

function becomeHidden() {
  Object.defineProperty(document, "visibilityState", {
    value: "hidden",
    configurable: true,
  });
  document.dispatchEvent(new Event("visibilitychange"));
}

// dispatch → handler → check() 内部 await fetch → await text() → 比对，整条 microtask 链冲干净
async function flushMicrotasks() {
  for (let i = 0; i < 6; i++) await Promise.resolve();
}

describe("installVersionCheck", () => {
  let unload: (() => void) | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    unload?.();
    unload = undefined;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("切回可见且服务端 entry hash 已变 → reload 一次", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = makeFetch(NEW_HTML);
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(fetchImpl).toHaveBeenCalledWith("/", expect.anything());
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("entry hash 未变（只改了后端）→ 不 reload", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = makeFetch(OLD_HTML);
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(reload).not.toHaveBeenCalled();
  });

  it("fetch 网络失败（rebuild 窗口连接拒绝）→ 静默跳过不抛不 reload", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(reload).not.toHaveBeenCalled();
  });

  it("响应非 ok（502 等）→ 不 reload", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = vi.fn(async () => ({ ok: false, text: async () => "" }));
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(reload).not.toHaveBeenCalled();
  });

  it("当前页面无 /assets/ entry（vite dev 模式）→ 不安装检测，切可见也不 fetch", async () => {
    document.body.innerHTML = '<script type="module" src="/src/main.tsx"></script>';
    const reload = vi.fn();
    const fetchImpl = makeFetch(NEW_HTML);
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it("tab 变 hidden 不触发检测（只有切回前台才查）", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = makeFetch(NEW_HTML);
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeHidden();
    await flushMicrotasks();

    expect(fetchImpl).not.toHaveBeenCalled();
    expect(reload).not.toHaveBeenCalled();
  });

  it("防抖：reload 后 10s 内再次检测到变化不重复 reload", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = makeFetch(NEW_HTML);
    let clock = 1_000;
    unload = installVersionCheck({ fetchImpl, reload, now: () => clock });

    becomeVisible();
    await flushMicrotasks();
    expect(reload).toHaveBeenCalledTimes(1);

    // 10s 内第二次切回（HTML 异常抖动/解析边界），不再 reload
    clock = 6_000;
    becomeVisible();
    await flushMicrotasks();
    expect(reload).toHaveBeenCalledTimes(1);

    // 防抖窗口过后恢复检测
    clock = 20_000;
    becomeVisible();
    await flushMicrotasks();
    expect(reload).toHaveBeenCalledTimes(2);
  });

  it("服务端 HTML 里解析不到 entry（后端起坏了/返回错误页）→ 静默不 reload", async () => {
    mountDocumentWith(OLD_HTML);
    const reload = vi.fn();
    const fetchImpl = makeFetch("<html><body>502 Bad Gateway</body></html>");
    unload = installVersionCheck({ fetchImpl, reload, now: () => 1_000 });

    becomeVisible();
    await flushMicrotasks();

    expect(reload).not.toHaveBeenCalled();
  });
});
