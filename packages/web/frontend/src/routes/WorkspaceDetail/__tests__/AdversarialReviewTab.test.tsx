import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { SWRConfig } from "swr";
import i18n from "@/i18n";
import { AdversarialReviewTab } from "../AdversarialReviewTab";

// Task 7 fixture：3 条审查记录覆盖三态（refuted/survived/unreviewed）+ failed_dimensions
// 两轴筛选（仅 INJ-01 带 defense_effective；INJ-01 展开含维度结果与 file:line 证据）。
const fixture = {
  summary: { total: 3, refuted: 1, survived: 1, unreviewed: 1 },
  records: [
    {
      vuln_class: "injection",
      finding_id: "INJ-01",
      review_verdict: "refuted",
      failed_dimensions: ["defense_effective"],
      before: { title: "SQLi", verdict: "vulnerable" },
      dimension_results: [
        {
          dimension: "defense_effective",
          rebutted: true,
          reason: "r",
          evidence: [{ location: "app.js:88", snippet: "escape(x)" }],
        },
      ],
      rebuttal_reason: "defense covers slot",
      survival_reason: null,
      after: { action: "dismissed" },
    },
    {
      vuln_class: "xss",
      finding_id: "XSS-01",
      review_verdict: "survived",
      failed_dimensions: [],
      before: { title: "t2", verdict: "vulnerable" },
      dimension_results: [],
      rebuttal_reason: null,
      survival_reason: "no refutation",
      after: { action: "kept" },
    },
    {
      vuln_class: "auth",
      finding_id: "AUTH-01",
      review_verdict: "unreviewed",
      failed_dimensions: [],
      before: { title: "t3", verdict: "vulnerable" },
      dimension_results: [],
      rebuttal_reason: null,
      survival_reason: null,
      after: { action: "kept" },
    },
  ],
};

const server = setupServer();

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
// jsdom navigator.language 默认 en，LanguageDetector 会把 i18n 切到 en；断言依赖中文渲染，逐测试钉回 zh。
beforeEach(() => i18n.changeLanguage("zh"));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// AdversarialReviewTab 经 useParams 取 ws/scanId（对齐 DataFlowTab 习惯）——
// MemoryRouter + 匹配 Route 让 params 解析；SWRConfig 独立 cache 防跨测试污染（DataFlowTab.test 同款）。
function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <SWRConfig value={{ provider: () => new Map() }}>
        <Routes>
          <Route
            path="/p/:workspace/scans/:scanId/adversarial"
            element={<AdversarialReviewTab />}
          />
        </Routes>
      </SWRConfig>
    </MemoryRouter>,
  );
}

/** 挂 mock 数据并等 summary 计数条出现（各用例共同前置）。 */
async function renderWithData() {
  server.use(
    http.get("/api/workspaces/:ws/scans/:scanId/adversarial-review", () =>
      HttpResponse.json(fixture),
    ),
  );
  renderAt("/p/w1/scans/s1/adversarial");
  await waitFor(() =>
    expect(screen.getByTestId("adv-summary")).toBeInTheDocument(),
  );
}

describe("AdversarialReviewTab", () => {
  it("渲染 summary 计数条（3 条 / 1 驳回 / 1 幸存 / 1 未审成），默认全量 3 张记录卡", async () => {
    await renderWithData();
    expect(screen.getByTestId("adv-summary")).toHaveTextContent("3");
    expect(screen.getByText(/已驳回/)).toBeInTheDocument();
    expect(screen.getByText(/无法反驳/)).toBeInTheDocument();
    expect(screen.getByText(/未审成/)).toBeInTheDocument();
    expect(screen.getAllByTestId("adv-record")).toHaveLength(3);
  });

  it("verdict 筛选 survived → 只剩 XSS-01（refuted/unreviewed 记录消失）", async () => {
    await renderWithData();
    await waitFor(() => screen.getByText("INJ-01"));
    fireEvent.change(screen.getByTestId("adv-verdict-select"), {
      target: { value: "survived" },
    });
    expect(screen.queryByText("INJ-01")).not.toBeInTheDocument();
    expect(screen.getByText("XSS-01")).toBeInTheDocument();
    expect(screen.queryByText("AUTH-01")).not.toBeInTheDocument();
  });

  it("failed dimension 筛选 defense_effective → 只剩 INJ-01（无该维度失败的不出现）", async () => {
    await renderWithData();
    await waitFor(() => screen.getByText("INJ-01"));
    fireEvent.change(screen.getByTestId("adv-dimension-select"), {
      target: { value: "defense_effective" },
    });
    expect(screen.getByText("INJ-01")).toBeInTheDocument();
    expect(screen.queryByText("XSS-01")).not.toBeInTheDocument();
    expect(screen.queryByText("AUTH-01")).not.toBeInTheDocument();
  });

  it("后端 404（未开启/未生成对抗审查）→ adv-empty 空态，不渲染计数条", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/adversarial-review", () =>
        HttpResponse.json({ detail: "not generated" }, { status: 404 })),
    );
    renderAt("/p/w1/scans/s1/adversarial");
    await waitFor(() =>
      expect(screen.getByTestId("adv-empty")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("adv-summary")).not.toBeInTheDocument();
  });

  it("畸形产物（summary/records 缺字段）→ ?? 兜底渲染 0/空，不炸整页", async () => {
    server.use(
      http.get("/api/workspaces/:ws/scans/:scanId/adversarial-review", () =>
        HttpResponse.json({
          records: [
            { vuln_class: "injection", finding_id: "INJ-01", review_verdict: "survived" },
          ],
        }),
      ),
    );
    renderAt("/p/w1/scans/s1/adversarial");
    await waitFor(() =>
      expect(screen.getByTestId("adv-summary")).toBeInTheDocument(),
    );
    // summary 缺失 → 全 0；记录缺 failed_dimensions/dimension_results → 兜底空数组
    expect(screen.getByTestId("adv-summary")).toHaveTextContent("0");
    expect(screen.getAllByTestId("adv-record")).toHaveLength(1);
  });
});
