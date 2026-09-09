import { afterEach, describe, expect, it, vi } from "vitest";
import { withChunkReload } from "./lazyWithRetry";

// 场景：旧标签页里 React.lazy 动态 import 的 chunk，服务端已 rebuild、旧 hash 文件被清 →
// 404 → 白屏。兜底：失败时 reload 一次进新 bundle；30s 内已 reload 过仍失败 = 新 bundle
// 真有问题，rethrow 给 ErrorBoundary，防 reload 死循环。

const STORAGE_KEY = "supernova:chunk-reload-at";

function makeLoad(impl: () => Promise<{ tag: string }>) {
  return vi.fn(impl);
}

describe("withChunkReload", () => {
  afterEach(() => {
    sessionStorage.clear();
    vi.restoreAllMocks();
  });

  it("加载成功 → 透传结果，不 reload 不写标记", async () => {
    const reload = vi.fn();
    const load = makeLoad(async () => ({ tag: "ok" }));

    const result = await withChunkRetryHarness(load, { reload });

    expect(result).toEqual({ tag: "ok" });
    expect(reload).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("chunk 404（首次失败）→ reload 一次并写时间戳标记", async () => {
    const reload = vi.fn();
    const load = makeLoad(async () => {
      throw new TypeError("Failed to fetch dynamically imported module");
    });

    await expect(withChunkRetryHarness(load, { reload })).rejects.toThrow();

    expect(reload).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem(STORAGE_KEY)).not.toBeNull();
  });

  it("30s 窗口内二次失败 → 不再 reload（防死循环），rethrow", async () => {
    const reload = vi.fn();
    sessionStorage.setItem(STORAGE_KEY, String(10_000));
    const load = makeLoad(async () => {
      throw new Error("Importing a module script failed");
    });

    await expect(
      withChunkRetryHarness(load, { reload, now: () => 20_000 }),
    ).rejects.toThrow("Importing a module script failed");

    expect(reload).not.toHaveBeenCalled();
  });

  it("标记超过 30s 窗口后失败 → 恢复 reload 一次", async () => {
    const reload = vi.fn();
    sessionStorage.setItem(STORAGE_KEY, String(10_000));
    const load = makeLoad(async () => {
      throw new Error("chunk missing");
    });

    await expect(
      withChunkRetryHarness(load, { reload, now: () => 60_000 }),
    ).rejects.toThrow();

    expect(reload).toHaveBeenCalledTimes(1);
  });
});

// 测试马具：默认依赖（sessionStorage / Date.now / window.location.reload）注入点
function withChunkRetryHarness<T>(
  load: () => Promise<T>,
  opts: { reload: ReturnType<typeof vi.fn>; now?: () => number },
): Promise<T> {
  return withChunkReload(load, {
    reload: opts.reload,
    // 基线取远离 30s 窗口的值，避免「无标记(last=0)」被误判为「刚 reload 过」
    now: opts.now ?? (() => 100_000),
  });
}
