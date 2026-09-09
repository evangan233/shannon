import {
  type CorrFormState,
  type CorrProtocol,
  type CorrRelation,
  type CorrRole,
  formToYaml,
} from "./correlation-yaml";
import type { CorrelationTopologyAnalysis, CorrelationTopologyEdge, CorrelationTopologyEvidence, CorrelationTopologyNode } from "@/api/types";

export interface TopologyNodeDraft {
  repo: string;
  roles: CorrRole[];
  reuseScanId: string | null;
  protoRoots?: string[];
  position: { x: number; y: number };
  referenceOnly?: boolean;
  capabilities?: CorrelationTopologyNode["capabilities"];
}

export type TopologyEdgeOrigin = "ai" | "manual";

export interface TopologyEdgeDraft {
  id: string;
  from: string;
  to: string;
  protocol: CorrProtocol;
  enabled: boolean;
  origin: TopologyEdgeOrigin;
  aiModified?: boolean;
  confidence?: "high" | "medium" | "low";
  service?: string | null;
  method?: string | null;
  client_evidence?: CorrelationTopologyEvidence[];
  handler_evidence?: CorrelationTopologyEvidence[];
}

export interface TopologyDraft {
  nodes: TopologyNodeDraft[];
  edges: TopologyEdgeDraft[];
  uncertain: NonNullable<CorrelationTopologyAnalysis["result"]>["uncertain"];
  coverage: NonNullable<CorrelationTopologyAnalysis["result"]>["coverage"];
}

export interface TopologyDraftState {
  selectedRepos: string[];
  analysis: CorrelationTopologyAnalysis | null;
  draft: TopologyDraft;
  history: { past: TopologyDraft[]; future: TopologyDraft[] };
  confirmation: {
    status: "unconfirmed" | "confirmed";
    fingerprint: string | null;
    yaml: string | null;
    issues: TopologyDraftIssue[];
  };
}

export interface TopologyDraftIssue {
  code:
    | "missing_repo" | "missing_entrypoint" | "missing_enabled_edge" | "dangling_relation"
    | "self_loop" | "invalid_protocol" | "duplicate_edge" | "missing_source" | "isolated_node";
  message: string;
}

type SourceMap = Record<string, string | null>;

const ROLE_ORDER: CorrRole[] = ["entrypoint", "backend"];
let manualEdgeSequence = 0;

function defaultPosition(roles: CorrRole[], index: number) {
  return { x: roles.includes("entrypoint") ? 80 : 480, y: 70 + index * 110 };
}

function defaultLayout(draft: TopologyDraft): TopologyDraft {
  return {
    ...draft,
    nodes: draft.nodes.map((node, index) => ({
      ...node,
      position: defaultPosition(node.roles, index),
    })),
  };
}

function edgeId(edge: Pick<TopologyEdgeDraft, "from" | "to" | "protocol">, origin: TopologyEdgeOrigin) {
  return `${origin}:${edge.from}->${edge.to}:${edge.protocol}${origin === "manual" ? `:${++manualEdgeSequence}` : ""}`;
}

function cloneDraft(draft: TopologyDraft): TopologyDraft {
  return structuredClone(draft);
}

function semantic(
  state: TopologyDraftState,
  update: (draft: TopologyDraft) => TopologyDraft,
): TopologyDraftState {
  const draft = update(cloneDraft(state.draft));
  return {
    ...state,
    draft,
    history: { past: [...state.history.past, cloneDraft(state.draft)].slice(-50), future: [] },
    confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues: [] },
  };
}

export function effectiveRoles(node: Pick<TopologyNodeDraft, "roles">): CorrRole[] {
  return ROLE_ORDER.filter((role) => node.roles.includes(role));
}

/** 新进入配置的仓库的来源智能默认解析器（2026-09-09）：返回复用 scan_id 或 null（现扫）。
 *  只对「不在 existingSources / 图里尚无节点」的仓库生效——用户已配过（含显式现扫）原样保留。 */
export type DefaultSourceResolver = (repo: string) => string | null;

export function createTopologyDraft(
  selectedRepos: string[],
  analysis: CorrelationTopologyAnalysis | null,
  existingSources: SourceMap = {},
  defaultSource?: DefaultSourceResolver,
): TopologyDraftState {
  const result = analysis?.result;
  const roleMap = new Map((result?.nodes ?? []).map((node) => [node.repo, node.roles] as const));
  const capabilityMap = new Map((result?.nodes ?? []).map((node) => [node.repo, node.capabilities ?? []] as const));
  const evidenceEdge = (edge: CorrelationTopologyEdge): TopologyEdgeDraft => ({
    id: edgeId(edge, "ai"),
    from: edge.from,
    to: edge.to,
    protocol: edge.protocol,
    enabled: true,
    origin: "ai",
    confidence: edge.confidence,
    service: edge.service ?? null,
    method: edge.method ?? null,
    client_evidence: edge.client_evidence ?? [],
    handler_evidence: edge.handler_evidence ?? [],
  });
  const draft = defaultLayout({
    nodes: selectedRepos.map((repo, index) => ({
      repo,
      roles: roleMap.get(repo) ?? [],
      capabilities: capabilityMap.get(repo) ?? [],
      reuseScanId: existingSources[repo] !== undefined
        ? existingSources[repo]
        : (defaultSource?.(repo) ?? null),
      position: defaultPosition(roleMap.get(repo) ?? [], index),
    })),
    edges: (result?.edges ?? []).filter(
      (edge) => selectedRepos.includes(edge.from) && selectedRepos.includes(edge.to),
    ).map(evidenceEdge),
    uncertain: result?.uncertain ?? [],
    coverage: result?.coverage ?? [],
  });
  return {
    selectedRepos,
    analysis,
    draft,
    history: { past: [], future: [] },
    confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues: [] },
  };
}

export function toggleTopologyRole(state: TopologyDraftState, repo: string, role: CorrRole) {
  return semantic(state, (draft) => ({
    ...draft,
    nodes: draft.nodes.map((node) => {
      if (node.repo !== repo) return node;
      const has = node.roles.includes(role);
      const roles = effectiveRoles({ roles: has ? node.roles.filter((r) => r !== role) : [...node.roles, role] });
      return {
        ...node,
        roles,
        capabilities: (node.capabilities ?? []).filter((capability) => roles.includes(capability.role)),
      };
    }),
  }));
}

export function setTopologyNodeSource(state: TopologyDraftState, repo: string, reuseScanId: string | null) {
  return semantic(state, (draft) => ({
    ...draft,
    nodes: draft.nodes.map((node) => node.repo === repo ? { ...node, reuseScanId } : node),
  }));
}

export function setTopologyReferenceOnly(state: TopologyDraftState, repo: string, referenceOnly: boolean) {
  return semantic(state, (draft) => ({
    ...draft,
    nodes: draft.nodes.map((node) => node.repo === repo ? { ...node, referenceOnly } : node),
  }));
}

export function addTopologyNode(state: TopologyDraftState, repo: string) {
  if (state.draft.nodes.some((node) => node.repo === repo)) return state;
  return semantic(state, (draft) => ({
    ...draft,
    nodes: [...draft.nodes, {
      repo,
      roles: [],
      capabilities: [],
      reuseScanId: null,
      position: defaultPosition([], draft.nodes.length),
    }],
  }));
}

export function removeTopologyNode(state: TopologyDraftState, repo: string) {
  return semantic(state, (draft) => ({
    ...draft,
    nodes: draft.nodes.filter((node) => node.repo !== repo),
    edges: draft.edges.filter((edge) => edge.from !== repo && edge.to !== repo),
  }));
}

export function updateTopologyRepositories(
  state: TopologyDraftState, repos: string[], defaultSource?: DefaultSourceResolver,
) {
  const selected = new Set(repos);
  const existing = new Map(state.draft.nodes.map((node) => [node.repo, node]));
  return semantic(state, (draft) => ({
    ...draft,
    nodes: repos.map((repo, index) => existing.get(repo) ?? {
      repo,
      roles: [],
      capabilities: [],
      reuseScanId: defaultSource?.(repo) ?? null,
      position: defaultPosition([], index),
    }),
    edges: draft.edges.filter((edge) => selected.has(edge.from) && selected.has(edge.to)),
  }));
}

export function moveTopologyNode(state: TopologyDraftState, repo: string, x: number, y: number) {
  return {
    ...state,
    draft: {
      ...state.draft,
      nodes: state.draft.nodes.map((node) =>
        node.repo === repo ? { ...node, position: { x, y } } : node),
    },
  };
}

export function resetTopologyLayout(state: TopologyDraftState) {
  return { ...state, draft: defaultLayout(cloneDraft(state.draft)) };
}

export function addTopologyEdge(
  state: TopologyDraftState,
  relation: CorrRelation & { enabled?: boolean },
) {
  return semantic(state, (draft) => ({
    ...draft,
    edges: [...draft.edges, {
      id: edgeId(relation, "manual"),
      from: relation.from,
      to: relation.to,
      protocol: relation.protocol,
      enabled: relation.enabled ?? true,
      origin: "manual",
      client_evidence: [],
      handler_evidence: [],
    }],
  }));
}

export function updateTopologyEdge(
  state: TopologyDraftState,
  edgeId: string,
  patch: Partial<Pick<TopologyEdgeDraft, "from" | "to" | "protocol" | "enabled">>,
) {
  return semantic(state, (draft) => ({
    ...draft,
    edges: draft.edges.map((edge) => edge.id === edgeId ? {
      ...edge,
      ...patch,
      aiModified: edge.origin === "ai" ? true : edge.aiModified,
    } : edge),
  }));
}

export function setTopologyEdgeEnabled(state: TopologyDraftState, edgeId: string, enabled: boolean) {
  return updateTopologyEdge(state, edgeId, { enabled });
}

export function restoreTopologyAiEdge(
  state: TopologyDraftState, edge: CorrelationTopologyEdge,
) {
  return semantic(state, (draft) => ({
    ...draft,
    edges: [...draft.edges, {
      id: edgeId(edge, "ai"),
      from: edge.from,
      to: edge.to,
      protocol: edge.protocol,
      enabled: true,
      origin: "ai",
      confidence: edge.confidence,
      service: edge.service ?? null,
      method: edge.method ?? null,
      client_evidence: edge.client_evidence ?? [],
      handler_evidence: edge.handler_evidence ?? [],
    }],
  }));
}

export function deleteTopologyEdge(state: TopologyDraftState, edgeId: string) {
  return semantic(state, (draft) => ({
    ...draft,
    edges: draft.edges.filter((edge) => edge.id !== edgeId),
  }));
}

export function undoTopology(state: TopologyDraftState): TopologyDraftState {
  const previous = state.history.past.at(-1);
  if (!previous) return state;
  return {
    ...state,
    draft: cloneDraft(previous),
    history: { past: state.history.past.slice(0, -1), future: [cloneDraft(state.draft), ...state.history.future] },
    confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues: [] },
  };
}

export function redoTopology(state: TopologyDraftState): TopologyDraftState {
  const next = state.history.future[0];
  if (!next) return state;
  return {
    ...state,
    draft: cloneDraft(next),
    history: { past: [...state.history.past, cloneDraft(state.draft)], future: state.history.future.slice(1) },
    confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues: [] },
  };
}

export function validateTopologyDraft(draft: TopologyDraft): TopologyDraftIssue[] {
  const issues: TopologyDraftIssue[] = [];
  const names = new Set(draft.nodes.map((node) => node.repo));
  const enabled = draft.edges.filter((edge) => edge.enabled);
  if (!draft.nodes.length) issues.push({ code: "missing_repo", message: "No repository selected" });
  if (!draft.nodes.some((node) => effectiveRoles(node).includes("entrypoint")))
    issues.push({ code: "missing_entrypoint", message: "At least one entrypoint is required" });
  if (!enabled.length) issues.push({ code: "missing_enabled_edge", message: "At least one enabled edge is required" });
  const seen = new Set<string>();
  for (const edge of enabled) {
    if (!names.has(edge.from) || !names.has(edge.to))
      issues.push({ code: "dangling_relation", message: `${edge.from} -> ${edge.to} references an unknown repository` });
    if (edge.from === edge.to) issues.push({ code: "self_loop", message: `${edge.from} cannot call itself` });
    if (!["grpc", "http", "graphql"].includes(edge.protocol))
      issues.push({ code: "invalid_protocol", message: `Unsupported protocol: ${edge.protocol}` });
    const identity = `${edge.from}\n${edge.to}\n${edge.protocol}`;
    if (seen.has(identity)) issues.push({ code: "duplicate_edge", message: `Duplicate edge: ${identity.replace(/\n/g, " / ")}` });
    seen.add(identity);
  }
  for (const node of draft.nodes) {
    if (node.reuseScanId === "") issues.push({ code: "missing_source", message: `Repository ${node.repo} has no selected source` });
    const connected = enabled.some((edge) => edge.from === node.repo || edge.to === node.repo);
    if (!connected && !node.referenceOnly)
      issues.push({ code: "isolated_node", message: `Repository ${node.repo} is isolated` });
  }
  return issues;
}

export function topologyDraftToCorrForm(draft: TopologyDraft): CorrFormState {
  const enabled = draft.edges.filter((edge) => edge.enabled);
  return {
    repos: draft.nodes.map((node) => {
      const incoming = enabled.find((edge) => edge.to === node.repo);
      return {
        repo: node.repo,
        role: effectiveRoles(node)[0] ?? "backend",
        roles: effectiveRoles(node),
        protocol: incoming?.protocol ?? "grpc",
        reuseScanId: node.reuseScanId,
        protoRoots: node.protoRoots,
      };
    }),
    relations: enabled.map((edge) => ({
      from: edge.from, to: edge.to, protocol: edge.protocol,
    })),
  };
}

/** CorrFormState（YAML 解析产物）→ TopologyDraftState：文本→图方向（2026-09-04 拓扑↔YAML
 *  双向同步）。YAML 文本是权威——form 未声明的节点/边不保留；文本不携带的图上下文
 *  （节点位置、referenceOnly、capabilities、同 identity 边的 AI 证据）从 prev 同名/同边
 *  继承，语义未变（fingerprint 相同，纯排版差异）时原样返回 prev——确认态与历史不受
 *  文本微调惊动。语义有变则推入 undo 历史并重置确认（改错可撤销回文本编辑前的图）。 */
export function corrFormToTopologyDraft(
  form: CorrFormState,
  prev: TopologyDraftState | null,
): TopologyDraftState {
  const prevNode = new Map((prev?.draft.nodes ?? []).map((node) => [node.repo, node] as const));
  const rolesOf = (repo: CorrFormState["repos"][number]) =>
    effectiveRoles({ roles: repo.roles?.length ? repo.roles : [repo.role] });
  const nodes: TopologyNodeDraft[] = form.repos.map((repo, index) => {
    const roles = rolesOf(repo);
    const kept = prevNode.get(repo.repo);
    return {
      repo: repo.repo,
      roles,
      reuseScanId: repo.reuseScanId,
      protoRoots: repo.protoRoots,
      position: kept?.position ?? defaultPosition(roles, index),
      referenceOnly: kept?.referenceOnly,
      capabilities: kept?.capabilities,
    };
  });
  const prevEdge = new Map(
    (prev?.draft.edges ?? []).map((edge) => [`${edge.from}\n${edge.to}\n${edge.protocol}`, edge] as const));
  const edges: TopologyEdgeDraft[] = form.relations.map((relation) => {
    const kept = prevEdge.get(`${relation.from}\n${relation.to}\n${relation.protocol}`);
    if (kept) return { ...kept, from: relation.from, to: relation.to, protocol: relation.protocol, enabled: true };
    return {
      id: `yaml:${relation.from}->${relation.to}:${relation.protocol}`,
      from: relation.from,
      to: relation.to,
      protocol: relation.protocol,
      enabled: true,
      origin: "manual",
      client_evidence: [],
      handler_evidence: [],
    };
  });
  const draft: TopologyDraft = {
    nodes,
    edges,
    uncertain: prev?.draft.uncertain ?? [],
    coverage: prev?.draft.coverage ?? [],
  };
  if (prev && topologyDraftFingerprint(draft) === topologyDraftFingerprint(prev.draft)) return prev;
  return {
    selectedRepos: prev?.selectedRepos ?? [],
    analysis: prev?.analysis ?? null,
    draft,
    history: prev
      ? { past: [...prev.history.past, cloneDraft(prev.draft)].slice(-50), future: [] }
      : { past: [], future: [] },
    confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues: [] },
  };
}

export function topologyDraftFingerprint(draft: TopologyDraft): string {
  const semanticView = {
    nodes: draft.nodes.map(({ repo, roles, reuseScanId, referenceOnly }) => ({
      repo, roles: effectiveRoles({ roles }), reuseScanId, referenceOnly: referenceOnly === true,
    })).sort((a, b) => a.repo.localeCompare(b.repo)),
    edges: draft.edges.filter((edge) => edge.enabled).map(({ from, to, protocol }) => ({
      from, to, protocol,
    })).sort((a, b) => `${a.from}${a.to}${a.protocol}`.localeCompare(`${b.from}${b.to}${b.protocol}`)),
  };
  return JSON.stringify(semanticView);
}

export function confirmTopologyDraft(state: TopologyDraftState): TopologyDraftState {
  const issues = validateTopologyDraft(state.draft);
  if (issues.length) {
    return { ...state, confirmation: { status: "unconfirmed", fingerprint: null, yaml: null, issues } };
  }
  const yaml = formToYaml(topologyDraftToCorrForm(state.draft));
  return {
    ...state,
    confirmation: {
      status: "confirmed", fingerprint: topologyDraftFingerprint(state.draft), yaml, issues: [],
    },
  };
}
