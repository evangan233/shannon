import { lazy, type ComponentType } from "react";

// React.lazy chunk 加载失败兜底：旧标签页在服务端 rebuild 后，懒加载 chunk 的旧 hash
// 文件已被清（404 / "Failed to fetch dynamically imported module"）→ 白屏。
// 兜底动作：reload 一次让页面进新 bundle（versionCheck 会保证大多数场景根本走不到这里，
// 这是纯兜底层）。30s 窗口内已 reload 过仍失败 = 新 bundle 真有问题 → rethrow 给
// ErrorBoundary，防 reload 死循环。

const RELOAD_WINDOW_MS = 30_000;
const STORAGE_KEY = "supernova:chunk-reload-at";

export interface ChunkRetryOptions {
  reload?: () => void;
  now?: () => number;
  storage?: Pick<Storage, "getItem" | "setItem">;
}

export async function withChunkReload<T>(
  load: () => Promise<T>,
  opts: ChunkRetryOptions = {},
): Promise<T> {
  const reload = opts.reload ?? (() => window.location.reload());
  const now = opts.now ?? Date.now;
  const storage = opts.storage ?? sessionStorage;
  try {
    return await load();
  } catch (err) {
    const last = Number(storage.getItem(STORAGE_KEY) ?? 0);
    if (now() - last < RELOAD_WINDOW_MS) throw err;
    storage.setItem(STORAGE_KEY, String(now()));
    reload();
    // reload 非同步跳转；继续抛出终止当前渲染路径，避免 Suspense 吞掉错误后挂在 fallback
    throw err;
  }
}

export function lazyWithRetry<T extends ComponentType<any>>(
  load: () => Promise<{ default: T }>,
) {
  return lazy(() => withChunkReload(load));
}
