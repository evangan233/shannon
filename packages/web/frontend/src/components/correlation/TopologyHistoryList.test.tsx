import { render, screen, fireEvent } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TopologyHistoryList } from "./TopologyHistoryList";
import type { CorrelationTopologyAnalysis } from "@/api/types";

function entry(patch: Partial<CorrelationTopologyAnalysis>): CorrelationTopologyAnalysis {
  return {
    analysis_id: "a1",
    workspace: "ws",
    status: "completed",
    repos: ["api-gateway", "user-svc"],
    created_at: "2026-09-03T06:22:00Z",
    ...patch,
  };
}

describe("TopologyHistoryList", () => {
  it("renders nothing when history is empty", () => {
    const { container } = render(
      <TopologyHistoryList entries={[]} activeId={null} onSelect={() => {}} />,
    );
    expect(container.querySelector("[data-testid='topology-history']")).toBeNull();
  });

  it("lists repo combo, time and status per entry", () => {
    render(
      <TopologyHistoryList
        entries={[
          entry({ analysis_id: "a1", repos: ["api-gateway", "user-svc", "order-svc"] }),
          entry({ analysis_id: "a2", status: "failed", repos: ["web", "billing"] }),
        ]}
        activeId={null}
        onSelect={() => {}}
      />,
    );
    expect(screen.getByText("api-gateway, user-svc, order-svc")).toBeInTheDocument();
    expect(screen.getByText("web, billing")).toBeInTheDocument();
    // 时间与状态成对出现（每条一行次级信息；具体钟点随时区漂移，锁格式）
    expect(screen.getAllByText(/\d{2}-\d{2} \d{2}:\d{2}/).length).toBe(2);
  });

  it("marks the loaded entry with aria-current and calls onSelect with the entry", async () => {
    const onSelect = vi.fn();
    const a1 = entry({ analysis_id: "a1" });
    const a2 = entry({ analysis_id: "a2" });
    render(
      <TopologyHistoryList entries={[a1, a2]} activeId="a2" onSelect={onSelect} />,
    );
    const rows = screen.getAllByRole("button", { name: /api-gateway/ });
    expect(rows.find((r) => r.getAttribute("aria-current") === "true")).toBeDefined();
    fireEvent.click(rows[0]);
    expect(onSelect).toHaveBeenCalledWith(a1);
  });

  it("shows delete actions, forwards terminal entries, and blocks active deletion", () => {
    const onSelect = vi.fn();
    const onDelete = vi.fn();
    const a1 = entry({ analysis_id: "a1", status: "completed" });
    const a2 = entry({ analysis_id: "a2", status: "running" });
    render(
      <TopologyHistoryList
        entries={[a1, a2]} activeId={null} onSelect={onSelect} onDelete={onDelete}
      />,
    );
    fireEvent.click(screen.getByTestId("topology-history-delete-a1"));
    expect(onDelete).toHaveBeenCalledWith(a1);
    expect(onSelect).not.toHaveBeenCalled();
    expect(screen.getByTestId("topology-history-delete-a2")).toBeDisabled();
  });

  it("marks the deleting entry disabled while the request is in flight", () => {
    const entryA = entry({ analysis_id: "a1", status: "completed" });
    render(
      <TopologyHistoryList
        entries={[entryA]} activeId={null} onSelect={() => {}}
        onDelete={() => {}} deletingId="a1"
      />,
    );
    expect(screen.getByTestId("topology-history-delete-a1")).toBeDisabled();
  });

  it("flags cache-hit entries with the reuse chip", () => {
    render(
      <TopologyHistoryList
        entries={[entry({ analysis_id: "a1", cache_hit: true })]}
        activeId={null}
        onSelect={() => {}}
      />,
    );
    expect(screen.getByTestId("topology-history-cache-a1")).toBeInTheDocument();
  });
});
