import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { CloneProgress } from "./CloneProgress";
import { useEventSource } from "@/api/useEventSource";
import type { NdjsonEvent } from "@/api/types";

vi.mock("react-i18next", () => {
  const t = (k: string) => k;
  return { useTranslation: () => ({ t }) };
});

// SSE hook mock：CloneProgress 是纯展示组件，事件流/连接状态由 useEventSource
// 提供——测试注入 { events, status } 驱动各分支（i18n mock → key 字符串断言；
// clone 事件 shape 非 NdjsonEvent 联合成员，组件侧本就 as CloneEvt 消费）。
vi.mock("@/api/useEventSource", () => ({ useEventSource: vi.fn() }));
const mocked = vi.mocked(useEventSource);

function renderWith(events: unknown[] = [], status: "open" | "closed" | "error" = "open") {
  mocked.mockReturnValue({ events: events as NdjsonEvent[], status, lastEventId: undefined, hydrated: true });
  return render(<CloneProgress ws="ws1" name="r1" />);
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.clearAllMocks();
});
afterEach(() => vi.useRealTimers());

describe("CloneProgress 终态与进度（回归锚点）", () => {
  it("连接健康时显示 clone 中", () => {
    renderWith([], "open");
    expect(screen.getByText("repos.clone.cloning")).toBeTruthy();
  });

  it("有进度事件时显示百分比", () => {
    renderWith([{ progress: 42 }], "open");
    expect(screen.getByText("repos.clone.cloningProgress")).toBeTruthy();
  });

  it("busyLabelKey 覆盖进行中文案（上传解压复用）", () => {
    mocked.mockReturnValue({ events: [], status: "open", lastEventId: undefined, hydrated: true });
    render(<CloneProgress ws="ws1" name="r1" busyLabelKey="repos.states.extracting" />);
    expect(screen.getByText("repos.states.extracting")).toBeTruthy();
  });

  it("clone_end 成功 → 就绪", () => {
    renderWith([{ type: "clone_end" }], "closed");
    expect(screen.getByText("repos.clone.ready")).toBeTruthy();
  });

  it("clone_end failed → 失败文案", () => {
    renderWith([{ type: "clone_end", status: "failed", error: "boom" }], "closed");
    expect(screen.getByText("repos.clone.failed")).toBeTruthy();
  });
});

describe("CloneProgress SSE 瞬断宽限（2026-09-11 闪「中断」修复）", () => {
  it("瞬断（<5s 宽限内）不闪断连警示，继续显示 clone 中", () => {
    renderWith([{ progress: 42 }], "error");
    expect(screen.getByText("repos.clone.cloningProgress")).toBeTruthy();
    expect(screen.queryByText("repos.clone.reconnecting")).toBeNull();
    act(() => vi.advanceTimersByTime(4999));
    expect(screen.getByText("repos.clone.cloningProgress")).toBeTruthy();
    expect(screen.queryByText("repos.clone.reconnecting")).toBeNull();
  });

  it("持续断连 ≥5s 才升级为断连警示", () => {
    renderWith([], "error");
    expect(screen.queryByText("repos.clone.reconnecting")).toBeNull();
    act(() => vi.advanceTimersByTime(5000));
    expect(screen.getByText("repos.clone.reconnecting")).toBeTruthy();
  });

  it("宽限内断连恢复 → 不再升级（计时器清除）", () => {
      const { rerender } = renderWith([], "error");
    act(() => vi.advanceTimersByTime(3000));
    mocked.mockReturnValue({ events: [], status: "open", lastEventId: undefined, hydrated: true });
    rerender(<CloneProgress ws="ws1" name="r1" />);
    act(() => vi.advanceTimersByTime(9999));
    expect(screen.queryByText("repos.clone.reconnecting")).toBeNull();
    expect(screen.getByText("repos.clone.cloning")).toBeTruthy();
  });

  it("已升级警示后恢复连接 → 立即回退到 clone 中（恢复沿不去抖）", () => {
    const { rerender } = renderWith([], "error");
    act(() => vi.advanceTimersByTime(5000));
    expect(screen.getByText("repos.clone.reconnecting")).toBeTruthy();
    mocked.mockReturnValue({ events: [], status: "open", lastEventId: undefined, hydrated: true });
    rerender(<CloneProgress ws="ws1" name="r1" />);
    expect(screen.getByText("repos.clone.cloning")).toBeTruthy();
  });
});
