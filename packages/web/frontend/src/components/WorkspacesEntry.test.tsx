import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, waitFor, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route, useParams } from "react-router-dom";
import i18n from "@/i18n";

// vi.mock 工厂被 hoist 到所有 import 之前；用 vi.hoisted 暴露可变 mock 函数，
// 每个测试用 mockReturnValue 切换返回值驱动三段跳转不同分支。
// （brief 原 vi.doMock 写法对静态 import 无效--见 task-11-report.md）
const { mockUseAuth, mockUseWorkspaces } = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
  mockUseWorkspaces: vi.fn(),
}));

vi.mock("@/auth/AuthContext", () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock("@/api/useWorkspaces", () => ({
  useWorkspaces: () => mockUseWorkspaces(),
}));

import { WorkspacesEntry } from "./WorkspacesEntry";

function WsDetail() {
  const { workspace } = useParams();
  return <div data-testid="ws-detail" data-ws={workspace} />;
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/" element={<div data-testid="home" />} />
        <Route path="/p/:workspace" element={<WsDetail />} />
        <Route path="*" element={<WorkspacesEntry />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("WorkspacesEntry", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("redirects to last visited workspace when set and still a member", async () => {
    mockUseAuth.mockReturnValue({ user: { last_visited_workspace: "ws-recent" } });
    mockUseWorkspaces.mockReturnValue({
      data: [
        { name: "ws-recent", status: "completed", created_at: 1, latest_created_at: 1, scan_type: "whitebox" },
        { name: "ws-other", status: "completed", created_at: 5, latest_created_at: 5, scan_type: "whitebox" },
      ],
      loading: false,
    });
    const { container } = renderAt("/entry");
    await waitFor(() =>
      expect(container.querySelector("[data-testid='ws-detail']")).toBeInTheDocument(),
    );
    // last_visited 优先于最近活跃（ws-other 的 latest_created_at 更新也不抢）
    expect(screen.getByTestId("ws-detail")).toHaveAttribute("data-ws", "ws-recent");
  });

  it("falls back to most recent workspace when last visited is not in membership (deleted/removed)", async () => {
    mockUseAuth.mockReturnValue({ user: { last_visited_workspace: "ws-gone" } });
    mockUseWorkspaces.mockReturnValue({
      data: [
        { name: "ws-old", status: "completed", created_at: 1, latest_created_at: 1, scan_type: "whitebox" },
        { name: "ws-new", status: "completed", created_at: 2, latest_created_at: 2, scan_type: "whitebox" },
      ],
      loading: false,
    });
    const { container } = renderAt("/entry");
    await waitFor(() =>
      expect(container.querySelector("[data-testid='ws-detail']")).toBeInTheDocument(),
    );
    // last_visited 指向已删/被移出的 ws -> 不跳 404，回落最近活跃（latest_created_at 倒序首项）
    expect(screen.getByTestId("ws-detail")).toHaveAttribute("data-ws", "ws-new");
  });

  it("redirects to most recent workspace when never visited but has membership", async () => {
    mockUseAuth.mockReturnValue({ user: { last_visited_workspace: null } });
    mockUseWorkspaces.mockReturnValue({
      data: [
        { name: "ws-old", status: "completed", created_at: 1, latest_created_at: 1, scan_type: "whitebox" },
        { name: "ws-new", status: "completed", created_at: 2, latest_created_at: 2, scan_type: "whitebox" },
      ],
      loading: false,
    });
    const { container } = renderAt("/entry");
    await waitFor(() =>
      expect(container.querySelector("[data-testid='ws-detail']")).toBeInTheDocument(),
    );
    // 最近活跃 = latest_created_at 倒序首项 = ws-new（而非 ws-old）
    expect(screen.getByTestId("ws-detail")).toHaveAttribute("data-ws", "ws-new");
  });

  it("redirects to / (Dashboard) when no membership", async () => {
    mockUseAuth.mockReturnValue({ user: { last_visited_workspace: null } });
    mockUseWorkspaces.mockReturnValue({ data: [], loading: false });
    const { container } = renderAt("/entry");
    await waitFor(() =>
      expect(container.querySelector("[data-testid='home']")).toBeInTheDocument(),
    );
  });
});
