import { describe, expect, it } from "vitest";
import yaml from "js-yaml";
import {
  addTopologyEdge,
  confirmTopologyDraft,
  corrFormToTopologyDraft,
  createTopologyDraft,
  deleteTopologyEdge,
  moveTopologyNode,
  resetTopologyLayout,
  setTopologyEdgeEnabled,
  setTopologyNodeSource,
  addTopologyNode,
  removeTopologyNode,
  updateTopologyRepositories,
  toggleTopologyRole,
  topologyDraftFingerprint,
  topologyDraftToCorrForm,
  undoTopology,
  redoTopology,
  validateTopologyDraft,
} from "./correlation-topology-draft";
import type { CorrelationTopologyAnalysis } from "@/api/types";

const analysis: CorrelationTopologyAnalysis = {
  analysis_id: "topology-test",
  workspace: "ws1",
  status: "completed",
  repos: ["web", "admin", "order", "user"],
  cache_hit: false,
  progress: 100,
  result: {
    nodes: [
      { repo: "web", roles: ["entrypoint", "backend"], capabilities: [] },
      { repo: "admin", roles: ["entrypoint"], capabilities: [] },
      { repo: "order", roles: ["backend"], capabilities: [] },
      { repo: "user", roles: ["backend"], capabilities: [] },
    ],
    edges: [
      {
        from: "web", to: "order", protocol: "grpc", confidence: "high",
        client_evidence: [{ repo: "web", file: "client.ts", line: 1, snippet: "stub" }],
        handler_evidence: [],
      },
      { from: "web", to: "user", protocol: "http", confidence: "medium", client_evidence: [], handler_evidence: [] },
      { from: "admin", to: "order", protocol: "graphql", confidence: "medium", client_evidence: [], handler_evidence: [] },
      { from: "order", to: "user", protocol: "grpc", confidence: "low", client_evidence: [], handler_evidence: [] },
    ],
    uncertain: [{ repo: "order", message: "possible thrift", protocol_hint: "thrift", evidence: [] }],
    coverage: analysisRepos().map((repo) => ({ repo, complete: true, reason: "fixture" })),
    invalid: [],
  },
};

function analysisRepos() { return ["web", "admin", "order", "user"]; }

describe("topology draft graph semantics", () => {
  it("imports all selected repos and retains M:N plus multi-hop edges", () => {
    const state = createTopologyDraft(analysis.repos, analysis, { web: "scan-web" });
    expect(state.draft.nodes.map((n) => n.repo)).toEqual(analysis.repos);
    expect(state.draft.edges.map((e) => `${e.from}-${e.to}-${e.protocol}`)).toEqual([
      "web-order-grpc", "web-user-http", "admin-order-graphql", "order-user-grpc",
    ]);
    expect(state.draft.nodes[0].roles).toEqual(["entrypoint", "backend"]);
    expect(state.draft.nodes[0].reuseScanId).toBe("scan-web");
    expect(state.draft.nodes[1].reuseScanId).toBeNull();
    expect(state.draft.uncertain).toHaveLength(1);
  });

  it("supports edits, undo/redo, source preservation, and confirmation invalidation", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    state = confirmTopologyDraft(state);
    expect(state.confirmation.status).toBe("confirmed");
    const confirmedFingerprint = state.confirmation.fingerprint;

    state = setTopologyEdgeEnabled(state, state.draft.edges[1].id, false);
    expect(state.confirmation.status).toBe("unconfirmed");
    expect(state.draft.edges[1].enabled).toBe(false);

    state = setTopologyNodeSource(state, "web", "scan-web");
    expect(state.draft.nodes[0].reuseScanId).toBe("scan-web");

    state = addTopologyEdge(state, { from: "admin", to: "user", protocol: "grpc" });
    expect(state.draft.edges.at(-1)?.origin).toBe("manual");

    const deletedId = state.draft.edges[0].id;
    state = deleteTopologyEdge(state, deletedId);
    expect(state.draft.edges.some((e) => e.id === deletedId)).toBe(false);
    state = undoTopology(state); state = undoTopology(state); state = undoTopology(state);
    expect(state.draft.edges[0].enabled).toBe(true);
    expect(state.draft.nodes[0].reuseScanId).toBeNull();
    state = redoTopology(state);
    expect(state.draft.nodes[0].reuseScanId).toBe("scan-web");

    state = confirmTopologyDraft(state);
    expect(state.confirmation.fingerprint).not.toBeNull();
    expect(topologyDraftFingerprint(state.draft)).toBe(state.confirmation.fingerprint);
    expect(confirmedFingerprint).not.toBeNull();
  });

  it("layout-only operations do not invalidate confirmation or enter undo history", () => {
    let state = confirmTopologyDraft(createTopologyDraft(analysis.repos, analysis, {}));
    const before = state.draft.nodes[0].position;
    state = moveTopologyNode(state, "web", 123, 456);
    expect(state.draft.nodes[0].position).toEqual({ x: 123, y: 456 });
    expect(state.confirmation.status).toBe("confirmed");
    state = resetTopologyLayout(state);
    expect(state.draft.nodes[0].position).toEqual(before);
    expect(undoTopology(state)).toBe(state);
  });

  it("defaultSource 只默认新进入的仓库：existingSources 原样保留（含显式 null=现扫）", () => {
    // order 未在 existingSources → 用 defaultSource；admin 在 existingSources 且显式 null（用户选了现扫）→ 不得被默认翻回复用
    const sources: Record<string, string | null> = { web: "scan-web", admin: null };
    const state = createTopologyDraft(
      analysis.repos, analysis, sources,
      (repo) => (repo === "order" ? "scan-order-latest" : null),
    );
    expect(state.draft.nodes.find((n) => n.repo === "web")?.reuseScanId).toBe("scan-web");
    expect(state.draft.nodes.find((n) => n.repo === "admin")?.reuseScanId).toBeNull();
    expect(state.draft.nodes.find((n) => n.repo === "order")?.reuseScanId).toBe("scan-order-latest");
    expect(state.draft.nodes.find((n) => n.repo === "user")?.reuseScanId).toBeNull();
  });

  it("updateTopologyRepositories：新进 selection 的仓库应用 defaultSource，已有节点原样保留", () => {
    let state = createTopologyDraft(analysis.repos, analysis, { web: "scan-web" });
    state = updateTopologyRepositories(
      state, ["web", "admin", "payment"],
      (repo) => (repo === "payment" ? "scan-pay" : "should-not-apply"),
    );
    expect(state.draft.nodes.find((n) => n.repo === "payment")?.reuseScanId).toBe("scan-pay");
    expect(state.draft.nodes.find((n) => n.repo === "web")?.reuseScanId).toBe("scan-web");
    expect(state.draft.nodes.find((n) => n.repo === "admin")?.reuseScanId).toBeNull();
  });

  it("preserves compatible draft state when repositories are added or removed", () => {
    let state = createTopologyDraft(analysis.repos, analysis, { web: "scan-web" });
    state = addTopologyNode(state, "payment");
    expect(state.draft.nodes.map((node) => node.repo)).toContain("payment");
    state = updateTopologyRepositories(state, ["web", "admin", "order", "payment"]);
    expect(state.draft.nodes.find((node) => node.repo === "user")).toBeUndefined();
    expect(state.draft.edges.every((edge) => edge.to !== "user" && edge.from !== "user")).toBe(true);
    expect(state.draft.nodes.find((node) => node.repo === "web")?.reuseScanId).toBe("scan-web");
    state = removeTopologyNode(state, "payment");
    expect(state.draft.nodes.map((node) => node.repo)).not.toContain("payment");
    expect(state.history.past.length).toBeGreaterThan(0);
  });

  it("converts only enabled edges, emits roles, and validates isolated/reference policy", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    state = setTopologyEdgeEnabled(state, state.draft.edges[1].id, false);
    const form = topologyDraftToCorrForm(state.draft);
    expect(form.relations).toHaveLength(3);
    expect(form.repos.find((r) => r.repo === "web")?.roles).toEqual(["entrypoint", "backend"]);
    expect(form.repos.find((r) => r.repo === "user")?.protocol).toBe("grpc");
    const parsed = yaml.load(confirmTopologyDraft(state).confirmation.yaml!) as any;
    expect(parsed.relations).toHaveLength(3);
    expect(parsed.repos.web.roles).toContain("backend");

    state = toggleTopologyRole(state, "web", "entrypoint");
    state = toggleTopologyRole(state, "admin", "entrypoint");
    expect(validateTopologyDraft(state.draft).map((i) => i.code)).toContain("missing_entrypoint");
    state = toggleTopologyRole(state, "web", "entrypoint");
    state = toggleTopologyRole(state, "admin", "entrypoint");
    state = setTopologyEdgeEnabled(state, state.draft.edges[3].id, false);
    const issues = validateTopologyDraft(state.draft);
    expect(issues.map((i) => i.code)).toContain("isolated_node");
    state.draft.nodes.find((n) => n.repo === "user")!.referenceOnly = true;
    expect(validateTopologyDraft(state.draft).filter((i) => i.code === "isolated_node")).toEqual([]);
  });
});

// === YAML→拓扑方向（2026-09-04 拓扑↔YAML 双向同步）：corrFormToTopologyDraft ===
// 文本侧（yamlToForm 产物）重建图侧草稿——贴 YAML 即长拓扑、编辑 YAML 即改图。
describe("corrFormToTopologyDraft (yaml -> topology)", () => {
  it("builds a full draft from a form with no previous state", () => {
    const state = corrFormToTopologyDraft({
      repos: [
        { repo: "web", role: "entrypoint", protocol: "grpc", reuseScanId: null },
        { repo: "order", role: "backend", protocol: "grpc", reuseScanId: "scan-1" },
      ],
      relations: [{ from: "web", to: "order", protocol: "http" }],
    }, null);
    expect(state.draft.nodes.map((n) => n.repo)).toEqual(["web", "order"]);
    expect(state.draft.nodes.find((n) => n.repo === "order")?.reuseScanId).toBe("scan-1");
    expect(state.draft.edges).toHaveLength(1);
    expect(state.draft.edges[0]).toMatchObject({ from: "web", to: "order", protocol: "http", enabled: true });
    // entrypoint 左列 / backend 右列的默认布局
    expect(state.draft.nodes.find((n) => n.repo === "web")!.position.x).toBeLessThan(
      state.draft.nodes.find((n) => n.repo === "order")!.position.x);
    expect(state.history).toEqual({ past: [], future: [] });
    expect(state.confirmation.status).toBe("unconfirmed");
  });

  it("returns the previous state untouched when the form is semantically identical (no confirmation reset)", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    state = confirmTopologyDraft(state);
    expect(state.confirmation.status).toBe("confirmed");
    // round-trip：草稿派生的 form 重建必须不惊动确认态（YAML 文本微调——注释/排版——
    // 不该要求重新确认）
    const roundTrip = corrFormToTopologyDraft(topologyDraftToCorrForm(state.draft), state);
    expect(roundTrip).toBe(state);
  });

  it("resets confirmation and pushes history when the form diverges semantically", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    state = confirmTopologyDraft(state);
    const form = topologyDraftToCorrForm(state.draft);
    const next = corrFormToTopologyDraft({
      ...form,
      relations: [...form.relations, { from: "admin", to: "user", protocol: "http" as const }],
    }, state);
    expect(next).not.toBe(state);
    expect(next.confirmation.status).toBe("unconfirmed");
    expect(next.draft.edges.map((e) => `${e.from}->${e.to}`)).toContain("admin->user");
    // 旧草稿进 undo 历史（改错可撤销回 YAML 编辑前的图）
    expect(next.history.past.at(-1)).toEqual(state.draft);
  });

  it("keeps node positions and AI edge evidence from the previous draft", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    state = moveTopologyNode(state, "order", 333, 222);
    const aiEdge = state.draft.edges.find((e) => e.from === "web" && e.to === "order")!;
    expect(aiEdge.origin).toBe("ai");
    // 语义变化（加一条边）强制走重建路径，验证非文本信息（位置/AI 证据/能力）继承
    const form = topologyDraftToCorrForm(state.draft);
    const diverged = { ...form, relations: [...form.relations, { from: "admin", to: "user", protocol: "http" as const }] };
    const next = corrFormToTopologyDraft(diverged, state);
    expect(next).not.toBe(state);
    expect(next.draft.nodes.find((n) => n.repo === "order")?.position).toEqual({ x: 333, y: 222 });
    // 同 identity 边保留 AI 证据（origin/confidence/evidence 不因文本重排而丢）
    const kept = next.draft.edges.find((e) => e.from === "web" && e.to === "order")!;
    expect(kept.origin).toBe("ai");
    expect(kept.confidence).toBe("high");
    expect(kept.client_evidence).toEqual(aiEdge.client_evidence);
    // 稳定 id：重复重建不换 id（React key / selectedEdge 不失效）
    expect(corrFormToTopologyDraft(diverged, state).draft.edges
      .find((e) => e.from === "web" && e.to === "order")!.id).toBe(kept.id);
    expect(next.draft.edges.find((e) => e.id.startsWith("yaml:"))?.id)
      .toBe("yaml:admin->user:http");
  });

  it("drops edges the form no longer declares (text is the source of truth)", () => {
    let state = createTopologyDraft(analysis.repos, analysis, {});
    const form = topologyDraftToCorrForm(state.draft);
    const next = corrFormToTopologyDraft({
      ...form,
      relations: form.relations.filter((e) => !(e.from === "web" && e.to === "user")),
    }, state);
    expect(next.draft.edges.some((e) => e.from === "web" && e.to === "user")).toBe(false);
  });
});
