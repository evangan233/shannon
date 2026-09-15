import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, act } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useLocation, useNavigate } from "react-router-dom";

// setLastVisitedWorkspace mock：断言触发/去重的观察点。
const { mockSetLastVisited } = vi.hoisted(() => ({
  mockSetLastVisited: vi.fn(),
}));

vi.mock("@/api/client", () => ({
  setLastVisitedWorkspace: (...args: unknown[]) => mockSetLastVisited(...args),
}));

import { LastVisitedTracker } from "./LastVisitedTracker";

// 测试内驱导航：Harness 挂载时捕获 MemoryRouter 的 navigate（直推 window.history
// 不会通知 react-router 的 history 实例，useLocation 不更新）。
let nav: ((to: string) => void) | undefined;

/** 路由外壳：Tracker 挂顶层（同 AppShell 位置）。 */
function Harness() {
  const { pathname } = useLocation();
  nav = useNavigate();
  return (
    <>
      <LastVisitedTracker />
      <span data-testid="path">{pathname}</span>
    </>
  );
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="*" element={<Harness />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("LastVisitedTracker", () => {
  beforeEach(() => {
    mockSetLastVisited.mockReset().mockResolvedValue(undefined);
    nav = undefined;
  });

  it("reports when entering /p/:ws", () => {
    renderAt("/p/ws-a");
    expect(mockSetLastVisited).toHaveBeenCalledWith("ws-a");
  });

  it("reports scan deep pages too (ScanDetail bypasses WorkspaceDetail)", () => {
    renderAt("/p/ws-a/scans/20260911-100000");
    expect(mockSetLastVisited).toHaveBeenCalledWith("ws-a");
  });

  it("dedupes same-workspace navigation within /p/:ws/*", () => {
    renderAt("/p/ws-a");
    expect(mockSetLastVisited).toHaveBeenCalledTimes(1);
    // ws 首页 -> scan 深页 -> ws settings：同一 ws 不重复上报
    act(() => nav?.("/p/ws-a/scans/1"));
    act(() => nav?.("/p/ws-a/settings"));
    expect(mockSetLastVisited).toHaveBeenCalledTimes(1);
  });

  it("reports again when switching to another workspace", () => {
    renderAt("/p/ws-a");
    act(() => nav?.("/p/ws-b"));
    expect(mockSetLastVisited).toHaveBeenNthCalledWith(2, "ws-b");
  });

  it("does not report on non-workspace paths", () => {
    renderAt("/settings");
    expect(mockSetLastVisited).not.toHaveBeenCalled();
  });

  // 2026-09-15 现场「金融」ws：pathname 是 URL-encoded 形态，编码串直接上报后端
  // 按目录名找不到 404、last_visited 永不落库（「工作区」入口跳错 ws 的主根因）。
  it("decodes percent-encoded workspace names before reporting (中文 ws 名)", () => {
    renderAt("/p/%E9%87%91%E8%9E%8D");
    expect(mockSetLastVisited).toHaveBeenCalledWith("金融");
  });

  it("stays silent on malformed percent-encoding (decode throw 不上报)", () => {
    renderAt("/p/%E4%BD%");
    expect(mockSetLastVisited).not.toHaveBeenCalled();
  });

  it("stays silent on report failure (fire-and-forget)", async () => {
    mockSetLastVisited.mockRejectedValue(new Error("network down"));
    renderAt("/p/ws-a");
    // .catch 接住 rejection：静默即通过。await 一拍让 microtask 走完，
    // 若组件漏 .catch，unhandled rejection 会在此后冒出。
    await act(async () => { await Promise.resolve(); });
    expect(mockSetLastVisited).toHaveBeenCalledWith("ws-a");
  });
});
