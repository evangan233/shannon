// TreeList 交互锁（2026-09-14 信息架构重做）：收起行摘要 + 点击展开/收起 + 锚点稳定。
import { describe, it, expect, beforeAll, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import i18next from "i18next";
import type { DataflowTree } from "@/api/types";
import { TreeList } from "../TreeList";

beforeAll(() => i18next.changeLanguage("zh"));

function node(func: string, line: number) {
  return { func, line, has_code: false, code: null, file: "a.js", intermediate_vars: [] };
}
function branch(id: string, verdict: "vulnerable" | "safe", nodes: ReturnType<typeof node>[] = []) {
  return {
    branch_id: id,
    track: "gitnexus" as const,
    verdict,
    verdict_reason: null,
    source: { label: "req.q", type: "query", entry: "GET /a" },
    nodes,
    sanitizers: [],
  };
}
function tree(id: string, verdict: "vulnerable" | "safe"): DataflowTree {
  return {
    tree_id: id,
    vuln_class: "injection",
    sink: { label: `sink-${id}`, file: "s.js", line: 1, rule_id: "R", category: "c", code: null },
    findings: [],
    branches: [branch(`${id}-b`, verdict, [node("fn", 2)])],
  };
}

describe("TreeList（收起行 + 按需展开）", () => {
  it("收起态：每树一行摘要（data-tree-id 锚点 + 比例计数），不挂载 React Flow 树卡", () => {
    const { container } = render(
      <TreeList trees={[tree("T-1", "vulnerable"), tree("T-2", "safe")]} expandedIds={new Set()} onToggle={() => {}} />,
    );
    // 两行锚点都在 DOM（scrollspy/深链稳定）；无展开卡
    expect(container.querySelectorAll("[data-tree-id]").length).toBe(2);
    expect(container.querySelector('[data-testid="pruning-tree-card"]')).toBeNull();
    // 行摘要：sink 名 + 枝计数（zh 文案）
    expect(screen.getByText(/打通 1 \/ 剪断 0/)).toBeInTheDocument();
    expect(screen.getByText(/打通 0 \/ 剪断 1/)).toBeInTheDocument();
  });

  it("点击行 → 展开树卡（RF 画布 + 枝明细）；再点收起（卡卸载、行仍在）", () => {
    const onToggle = vi.fn();
    const { container } = render(
      <TreeList trees={[tree("T-1", "vulnerable")]} expandedIds={new Set()} onToggle={onToggle} />,
    );
    const row = container.querySelector('[data-tree-id="T-1"]') as HTMLElement;
    expect(row.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(row);
    expect(onToggle).toHaveBeenCalledWith("T-1");
  });

  it("展开态：行头 aria-expanded=true + 树卡渲染（源节点可见）", () => {
    const { container } = render(
      <TreeList trees={[tree("T-1", "vulnerable")]} expandedIds={new Set(["T-1"])} onToggle={() => {}} />,
    );
    const row = container.querySelector('[data-tree-id="T-1"]') as HTMLElement;
    expect(row.getAttribute("aria-expanded")).toBe("true");
    expect(container.querySelector('[data-testid="pruning-tree-card"]')).toBeTruthy();
    expect(container.querySelector("[data-source]")).toBeTruthy();
  });
});
