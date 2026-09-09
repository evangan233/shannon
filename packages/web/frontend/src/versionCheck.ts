// SPA 版本更新检测：治「up.sh --build 更新后，旧标签页一直跑旧 bundle 直到手动刷新」。
//
// 版本指纹 = index.html 里 entry script 的 /assets/index-<hash>.js src：改前端 hash 必变、
// 改后端不变（后端更新本就不需要刷前端），无需服务端任何配合（index.html 本身 no-cache）。
// 触发时机只挂 visibilitychange 切回前台——「rebuild 完切回浏览器」是内网部署的高频场景；
// 后台轮询发现更新时用户看不见 toast，而盯日志的前台 tab 被 reload 反而打断，等下次
// 切走切回自然吃到新版。
//
// vite dev 模式（script 是 /src/main.tsx 无 hash）自动禁用，零误报。

type FetchLike = (
  url: string,
  init?: RequestInit,
) => Promise<{ ok: boolean; text(): Promise<string> }>;

export interface VersionCheckOptions {
  fetchImpl?: FetchLike;
  reload?: () => void;
  now?: () => number;
  document?: Document;
}

const RELOAD_DEBOUNCE_MS = 10_000;
const ENTRY_SELECTOR = 'script[src^="/assets/"]';

function findEntrySrc(doc: Document): string | null {
  const el = doc.querySelector<HTMLScriptElement>(ENTRY_SELECTOR);
  return el?.getAttribute("src") ?? null;
}

export function installVersionCheck(opts: VersionCheckOptions = {}): () => void {
  const doc = opts.document ?? document;
  const fetchImpl: FetchLike =
    opts.fetchImpl ?? ((url, init) => fetch(url, init));
  const reload = opts.reload ?? (() => window.location.reload());
  const now = opts.now ?? Date.now;

  const currentSrc = findEntrySrc(doc);
  if (!currentSrc) {
    // dev 模式（无 hash entry）或异常 DOM：不安装检测
    return () => {};
  }

  let inFlight = false;
  let lastReloadAt = -Infinity;

  const check = async () => {
    if (inFlight) return;
    if (now() - lastReloadAt < RELOAD_DEBOUNCE_MS) return;
    inFlight = true;
    try {
      const res = await fetchImpl("/", { cache: "no-store" });
      if (!res.ok) return;
      const html = await res.text();
      const latestSrc = findEntrySrc(new DOMParser().parseFromString(html, "text/html"));
      // 服务端解析不出 entry（起坏/错误页）→ 视为无信号，不动当前页面
      if (latestSrc && latestSrc !== currentSrc) {
        lastReloadAt = now();
        reload();
      }
    } catch {
      // rebuild 窗口连接拒绝 / 网络抖动：静默，下次切回再试
    } finally {
      inFlight = false;
    }
  };

  const onVisibilityChange = () => {
    if (doc.visibilityState === "visible") void check();
  };
  doc.addEventListener("visibilitychange", onVisibilityChange);
  return () => doc.removeEventListener("visibilitychange", onVisibilityChange);
}
