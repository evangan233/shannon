import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { DataFlowTab } from "../DataFlowTab";
import type { DataflowView } from "@/api/types";

// Task 14 fixture：3 棵树覆盖筛选两轴——vuln_class（injection×2 / xss×1）× 有无漏洞
// （T-INJ-VULN 有打通枝+findings；T-XSS-SAFE / T-INJ-SAFE 全剪断 safe-only）。
// 枝条叙事口径计数：3 条数据流 = 1 打通 + 2 剪断。
const mockView: DataflowView = {
  schema_version: 1,
  summary: { total_sinks: 3, vulnerable_sinks: 1, safe_only_sinks: 2 },
  trees: [
    {
      tree_id: "T-INJ-VULN",
      vuln_class: "injection",
      sink: { label: "cursor.execute", file: "app/db.py", line: 42, rule_id: "py-sql-execute-raw", category: "sql", code: null },
      findings: [{ id: "INJ-VULN-01", merge_source: "both", title: "SQL 注入", confidence: "high" }],
      branches: [
        {
          branch_id: "F-01",
          track: "gitnexus",
          verdict: "vulnerable",
          verdict_reason: null,
          source: { label: "req.query.name", type: "query", entry: "GET /api/users", file: "r.ts", line: 1 },
          nodes: [
            { func: "UserController.list", file: "r.ts", line: 25, transformation: "concat", intermediate_vars: ["q"], code: null, has_code: false },
          ],
          sanitizers: [],
        },
      ],
    },
    {
      tree_id: "T-XSS-SAFE",
      vuln_class: "xss",
      sink: { label: "element.innerHTML", file: "app/view.ts", line: 8, rule_id: "dom-innerhtml", category: "xss", code: null },
      findings: [],
      branches: [
        {
          branch_id: "F-02",
          track: "gitnexus",
          verdict: "safe",
          verdict_reason: "textContent 赋值覆盖拼接值",
          source: { label: "req.query.tag", type: "query", entry: "GET /api/tag", file: "r.ts", line: 2 },
          nodes: [],
          sanitizers: [{ name: "textContent", defense_type: "safe_dom", file: "v.ts", line: 3, effective: true }],
        },
      ],
    },
    {
      tree_id: "T-INJ-SAFE",
      vuln_class: "injection",
      sink: { label: "cursor.execute", file: "app/db.py", line: 99, rule_id: "py-sql-execute-raw", category: "sql", code: null },
      findings: [],
      branches: [
        {
          branch_id: "F-03",
          track: "gitnexus",
          verdict: "safe",
          verdict_reason: "shlex.quote 覆盖拼接值",
          source: { label: "req.query.id", type: "query", entry: "GET /api/x", file: "r.ts", line: 3 },
          nodes: [],
          sanitizers: [{ name: "shlex.quote", defense_type: "shlex_quote", file: "s.ts", line: 9, effective: true }],
        },
      ],
    },
  ],
  control_findings: [],
  safe_vectors: [],
};

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
// jsdom navigator.language 默认 en，LanguageDetector 会把 i18n 切到 en；现有断言依赖中文渲染，逐测试钉回 zh。
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// DataFlowTab 经 useParams 取 ws/scanId（对齐 DeliverablesTab 习惯）——MemoryRouter +
// 匹配 Route 让 params 解析；SWRConfig 独立 cache 防跨测试污染（DeliverablesTab.test 同款）。
function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SWRConfig value={{ provider: () => new Map() }}>
        <Routes>
          <Route path="/p/:workspace/scans/:scanId/dataflow" element={<DataFlowTab />} />
        </Routes>
      </SWRConfig>
    </MemoryRouter>,
  );
}

/** 挂 mock 数据并等摘要条出现（各用例共同前置）。 */
async function renderWithData() {
  server.use(
    http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () =>
      HttpResponse.json(mockView)),
  );
  renderAt("/p/w1/scans/s1/dataflow");
  await waitFor(() =>
    expect(screen.getByTestId("dataflow-summary-bar")).toBeInTheDocument());
}

describe("DataFlowTab", () => {
  it("渲染摘要条（枝条叙事口径：N 条数据流 / N 条打通 / N 条被剪断 / 认证风险计数）", async () => {
    await renderWithData();
    expect(screen.getByText("数据流")).toBeInTheDocument();
    // 枝条口径（spec §5 汇总条）：3 条数据流 = 1 打通 + 2 剪断（branch 单位，可加和）
    expect(screen.getByText(/3 条数据流/)).toBeInTheDocument();
    expect(screen.getByText(/1 条打通到危险点/)).toBeInTheDocument();
    expect(screen.getByText(/2 条被防护剪断/)).toBeInTheDocument();
    expect(screen.getByText(/0 个认证\/授权风险/)).toBeInTheDocument();
    // 汇总计数保持全量口径：默认无筛选，3 棵树卡全部渲染
    expect(document.querySelectorAll("[data-tree-id]").length).toBe(3);
  });

  it("后端 404（无 dataflow_view.json）显示空态「无数据流视图」+「需新版扫描」引导（spec §6）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () =>
        HttpResponse.json({ detail: "not found" }, { status: 404 })),
    );
    renderAt("/p/w1/scans/s1/dataflow");
    // 标题精确匹配（hint 也含「无数据流视图」子串，正则会双命中）
    await waitFor(() =>
      expect(screen.getByText("无数据流视图")).toBeInTheDocument());
    // spec §6：404 空态文案含「需新版扫描」引导
    expect(screen.getByText(/需新版扫描/)).toBeInTheDocument();
    // 守卫：404 空态不渲染摘要条
    expect(screen.queryByTestId("dataflow-summary-bar")).not.toBeInTheDocument();
  });

  it("筛选器 vuln_class=injection → 只渲染 injection 树（树区 + 目录同步过滤）", async () => {
    await renderWithData();
    // 初始：xss 树在树区与目录
    expect(document.querySelector('[data-tree-id="T-XSS-SAFE"]')).toBeTruthy();
    expect(document.querySelector('[data-toc-id="T-XSS-SAFE"]')).toBeTruthy();
    // 选 vuln_class=injection
    fireEvent.change(screen.getByTestId("dataflow-class-select"), {
      target: { value: "injection" },
    });
    // 树区：injection 树保留、xss 树消失
    expect(document.querySelector('[data-tree-id="T-INJ-VULN"]')).toBeTruthy();
    expect(document.querySelector('[data-tree-id="T-INJ-SAFE"]')).toBeTruthy();
    expect(document.querySelector('[data-tree-id="T-XSS-SAFE"]')).toBeNull();
    // 目录：与树区同步（TocSideBar 收过滤后的 trees）
    expect(document.querySelector('[data-toc-id="T-XSS-SAFE"]')).toBeNull();
    expect(document.querySelector('[data-toc-id="T-INJ-VULN"]')).toBeTruthy();
    // 汇总计数保持全量口径（3 条数据流不随筛选缩水——描述本次扫描整体）
    expect(screen.getByText(/3 条数据流/)).toBeInTheDocument();
  });

  it("toggle「只看有漏洞的」→ safe-only 树消失（树区 + 目录）", async () => {
    await renderWithData();
    expect(document.querySelector('[data-tree-id="T-INJ-SAFE"]')).toBeTruthy();
    fireEvent.click(screen.getByTestId("dataflow-toggle-vulnonly"));
    expect(
      screen.getByTestId("dataflow-toggle-vulnonly").getAttribute("aria-pressed"),
    ).toBe("true");
    // 只有带 findings/打通枝的 T-INJ-VULN 保留；两棵 safe-only 树消失
    expect(document.querySelector('[data-tree-id="T-INJ-VULN"]')).toBeTruthy();
    expect(document.querySelector('[data-tree-id="T-INJ-SAFE"]')).toBeNull();
    expect(document.querySelector('[data-tree-id="T-XSS-SAFE"]')).toBeNull();
    expect(document.querySelector('[data-toc-id="T-INJ-SAFE"]')).toBeNull();
    expect(document.querySelector('[data-toc-id="T-XSS-SAFE"]')).toBeNull();
    // 切回「全部」→ 三棵树恢复
    fireEvent.click(screen.getByTestId("dataflow-toggle-all"));
    expect(document.querySelectorAll("[data-tree-id]").length).toBe(3);
  });

  it("筛选后无匹配 → 空提示（不渲染树卡）", async () => {
    await renderWithData();
    // xss 类下只看有漏洞的：T-XSS-SAFE 是 safe-only → 无匹配
    fireEvent.change(screen.getByTestId("dataflow-class-select"), {
      target: { value: "xss" },
    });
    fireEvent.click(screen.getByTestId("dataflow-toggle-vulnonly"));
    expect(screen.getByTestId("dataflow-filter-empty")).toBeInTheDocument();
    expect(document.querySelector("[data-tree-id]")).toBeNull();
  });

  it("无树（仅 control/safe 区）→ 不渲染筛选器 / 图例条 / 空提示", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () =>
        HttpResponse.json({ ...mockView, trees: [] })),
    );
    renderAt("/p/w1/scans/s1/dataflow");
    await waitFor(() =>
      expect(screen.getByText(/0 条数据流/)).toBeInTheDocument());
    expect(screen.queryByTestId("dataflow-class-select")).not.toBeInTheDocument();
    expect(screen.queryByTestId("dataflow-legend-bar")).not.toBeInTheDocument();
    expect(screen.queryByTestId("dataflow-filter-empty")).not.toBeInTheDocument();
    expect(screen.queryByText("漏洞数据流树")).not.toBeInTheDocument(); // 区头也不渲染
  });

  it("图例条渲染于树区上方（spec §5：位于树区上方，教读图）", async () => {
    await renderWithData();
    const legend = screen.getByTestId("dataflow-legend-bar");
    expect(legend).toBeInTheDocument();
    expect(screen.getByText("图例")).toBeInTheDocument();
    // DOM 序：图例条在第一棵树卡之前
    const firstTree = document.querySelector("[data-tree-id]");
    expect(firstTree).toBeTruthy();
    expect(
      legend.compareDocumentPosition(firstTree!) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it("树区区头（spec §5 区 1）：标题「漏洞数据流树」+ 组织方式说明段", async () => {
    await renderWithData();
    // 标题 + 说明段关键词（每个危险点一棵树 / 打通 / 剪断 / 断得越靠右走得越远）
    expect(screen.getByRole("heading", { name: "漏洞数据流树" })).toBeInTheDocument();
    expect(screen.getByText(/每个危险点（sink）一棵树/)).toBeInTheDocument();
    expect(screen.getByText(/红色流动线=打通/)).toBeInTheDocument();
    expect(screen.getByText(/✂ 剪断=防护拦下/)).toBeInTheDocument();
    expect(screen.getByText(/断得越靠右说明输入走得越远/)).toBeInTheDocument();
    // DOM 序：标题 → 图例条 → 第一棵树卡（标题→说明段→图例条→树，说明段在标题后）
    const title = screen.getByRole("heading", { name: "漏洞数据流树" });
    const intro = screen.getByText(/每个危险点（sink）一棵树/);
    const legend = screen.getByTestId("dataflow-legend-bar");
    const firstTree = document.querySelector("[data-tree-id]")!;
    const follows = (a: Element, b: Element) =>
      (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    expect(follows(title, intro)).toBe(true);
    expect(follows(intro, legend)).toBe(true);
    expect(follows(legend, firstTree)).toBe(true);
  });

  it("信息架构重做：默认仅展开第一棵漏洞树（其余收起行），漏洞树置顶排序", async () => {
    await renderWithData();
    // mockView：T-INJ-VULN（有 findings）唯一漏洞树 → 默认展开它
    const expandedRow = document.querySelector('[data-tree-row="expanded"]');
    expect(expandedRow?.getAttribute("data-tree-id")).toBe("T-INJ-VULN");
    // 树卡只挂载一张（React Flow 画布仅展开态存在）
    expect(document.querySelectorAll('[data-testid="pruning-tree-card"]').length).toBe(1);
    // 收起行仍在 DOM（锚点/scrollspy 稳定）：3 行 = 1 展开 + 2 收起
    expect(document.querySelectorAll("[data-tree-id]").length).toBe(3);
    expect(document.querySelectorAll('[data-tree-row="collapsed"]').length).toBe(2);
    // 排序：漏洞树置顶（数据序 T-INJ-VULN 本在首位，用 DOM 序校验首行）
    expect(document.querySelector("[data-tree-id]")?.getAttribute("data-tree-id")).toBe("T-INJ-VULN");
  });

  it("信息架构重做：收起行点击展开/收起（受控交互）", async () => {
    await renderWithData();
    const safeRow = document.querySelector('[data-tree-id="T-XSS-SAFE"]') as HTMLElement;
    expect(safeRow.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(safeRow);
    await waitFor(() =>
      expect(document.querySelector('[data-tree-id="T-XSS-SAFE"]')?.getAttribute("aria-expanded")).toBe("true"));
    // 该树卡挂载（xss 树），且 T-INJ-VULN 仍展开 → 2 张卡
    expect(document.querySelectorAll('[data-testid="pruning-tree-card"]').length).toBe(2);
    // 再点收起
    fireEvent.click(document.querySelector('[data-tree-id="T-XSS-SAFE"]') as HTMLElement);
    await waitFor(() =>
      expect(document.querySelectorAll('[data-testid="pruning-tree-card"]').length).toBe(1));
  });

  it("信息架构重做：?tree= 深链展开目标树（VulnCard「查看数据流」落点）", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () =>
        HttpResponse.json(mockView)),
    );
    renderAt("/p/w1/scans/s1/dataflow?tree=T-INJ-SAFE");
    await waitFor(() =>
      expect(
        document.querySelector('[data-tree-id="T-INJ-SAFE"]')?.getAttribute("aria-expanded"),
      ).toBe("true"));
    // 深链目标展开；默认第一棵漏洞树也保持展开（互不挤占）
    expect(
      document.querySelector('[data-tree-id="T-INJ-VULN"]')?.getAttribute("aria-expanded"),
    ).toBe("true");
  });

  it("汇总条 unknown 枝计数：总数含未判定 + 独立「N 条未判定」项（无 unknown 时不显示该噪音）", async () => {
    // 无 unknown：不出现「未判定」段
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () => HttpResponse.json(mockView)),
    );
    renderAt("/p/w1/scans/s1/dataflow");
    await waitFor(() => expect(screen.getByTestId("dataflow-summary-bar")).toBeInTheDocument());
    expect(screen.queryByText(/未判定/)).toBeNull();

    // 加一棵 unknown 树：4 条数据流 = 1 打通 + 2 剪断 + 1 未判定（数字加得平）
    const unknownTree = {
      ...mockView.trees[0],
      tree_id: "T-SSRF-UNK",
      findings: [],
      branches: [
        {
          ...mockView.trees[0].branches[0],
          branch_id: "F-UNK",
          verdict: "unknown" as const,
          verdict_reason: "No URL scheme allowlist validation",
        },
      ],
    };
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/dataflow", () =>
        HttpResponse.json({ ...mockView, trees: [...mockView.trees, unknownTree] })),
    );
    cleanup(); // 同 it 两轮挂载：清第一轮 DOM，避免 getByText 命中两份
    renderAt("/p/w2/scans/s2/dataflow");
    await waitFor(() => expect(screen.getByText(/4 条数据流/)).toBeInTheDocument());
    expect(screen.getByText(/1 条打通到危险点/)).toBeInTheDocument();
    expect(screen.getByText(/2 条被防护剪断/)).toBeInTheDocument();
    expect(screen.getByText(/1 条未判定/)).toBeInTheDocument();
  });
});
