// 真实数据回归锁（T13）：NodeGoat-20260825-131517 全量 22 树（蒸馏 fixture 进 repo，
// 不依赖工作区路径）。每棵树过布局不变量（节点盒两两不相交）+ 渲染无错——本次迁移
// 要根治的「LLM 自然语言长 label 重叠」问题的真实数据级回归锁。
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { render } from "@testing-library/react";
import { beforeAll, describe, expect, it } from "vitest";
import i18next from "i18next";
import type { DataflowView } from "@/api/types";
import { PruningTreeFig } from "../PruningTreeFig";
import { buildPruneLayout } from "../prune/layout";

const view = JSON.parse(
  readFileSync(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/nodegoat-dataflow.json"),
    "utf8",
  ),
) as DataflowView;

function rectsOverlap(
  a: { x: number; y: number; w: number; h: number },
  b: { x: number; y: number; w: number; h: number },
): boolean {
  const eps = 0.5;
  return a.x < b.x + b.w - eps && b.x < a.x + a.w - eps && a.y < b.y + b.h - eps && b.y < a.y + a.h - eps;
}

beforeAll(() => {
  i18next.changeLanguage("zh");
});

describe("NodeGoat 真实数据回归（22 树全量）", () => {
  it("每棵树布局：任意两节点矩形不相交（折叠/展开两态）", () => {
    expect(view.trees.length).toBe(22);
    for (const tree of view.trees) {
      for (const foldExpanded of [false, true]) {
        const layout = buildPruneLayout(tree, { foldExpanded });
        const nodes = layout.nodes;
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            expect(
              rectsOverlap(nodes[i], nodes[j]),
              `${tree.tree_id} fold=${foldExpanded}: ${nodes[i].id} × ${nodes[j].id} 相交`,
            ).toBe(false);
          }
        }
      }
    }
  });

  it("真实长 label（LLM 自然语言 40-51 字符）节点高按行数撑开、布局包围盒包含全部", () => {
    for (const tree of view.trees) {
      const layout = buildPruneLayout(tree, { foldExpanded: true });
      for (const n of layout.nodes) {
        expect(n.x + n.w).toBeLessThanOrEqual(layout.width + 0.5);
        expect(n.y + n.h).toBeLessThanOrEqual(layout.height + 0.5);
      }
      // 长标签节点（≥3 行）高度显著高于单行节点基线
      const tall = layout.nodes.find((n) => n.data.kind === "step" && n.data.lines.length >= 2);
      if (tall) expect(tall.h).toBeGreaterThanOrEqual(44 + 2 * 13);
    }
  });

  it("全量渲染无错（React Flow jsdom 下 22 卡 + 边 + 折叠）", () => {
    const { container } = render(<PruningTreeFig trees={view.trees} />);
    expect(container.querySelectorAll("[data-tree-id]").length).toBe(22);
    expect(container.querySelectorAll("[data-source]").length).toBeGreaterThan(0);
    expect(container.querySelectorAll("path[data-branch]").length).toBeGreaterThan(0);
  });
});
