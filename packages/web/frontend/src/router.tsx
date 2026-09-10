import { lazyWithRetry } from "./lazyWithRetry";
import { createBrowserRouter, useNavigate, useParams, Navigate } from "react-router-dom";
import { useEffect } from "react";
import { DashboardPage } from "./pages/DashboardPage";
import { getScan, listScans } from "./api/client";
import { AppShell } from "./components/layout/AppShell";
import LoginPage from "./pages/LoginPage";
import { RequireAuth } from "./auth/RequireAuth";
import { RequireAdmin } from "./auth/RequireAdmin";

// 重页面按需加载（spec §B）：Login/Dashboard 是最高频首屏路径保持 eager；
// ReportTab → MarkdownView → react-markdown/micromark/highlight 栈随动态 import 独立成 chunk。
const ScanNewPage = lazyWithRetry(() => import("./pages/ScanNewPage").then(m => ({ default: m.ScanNewPage })));
const SettingsPage = lazyWithRetry(() => import("./pages/SettingsPage").then(m => ({ default: m.SettingsPage })));
const UsersPage = lazyWithRetry(() => import("./pages/UsersPage").then(m => ({ default: m.UsersPage })));
const WorkspaceDetail = lazyWithRetry(() => import("./routes/WorkspaceDetail"));
const ScanList = lazyWithRetry(() => import("./routes/WorkspaceDetail/ScanList").then(m => ({ default: m.ScanList })));
const ScanDetail = lazyWithRetry(() => import("./routes/WorkspaceDetail/ScanDetail"));
const OverviewTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/OverviewTab").then(m => ({ default: m.OverviewTab })));
const ReportTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/ReportTab").then(m => ({ default: m.ReportTab })));
const DeliverablesTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/DeliverablesTab").then(m => ({ default: m.DeliverablesTab })));
const DataFlowTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/DataFlowTab").then(m => ({ default: m.DataFlowTab })));
const EvidenceTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/EvidenceTab").then(m => ({ default: m.EvidenceTab })));
// 跨仓关联结果 tab（D5 组件收 {ws, scanId} props——与兄弟 tab 的 useParams 自取不同，
// 由 CorrelationTabRoute 包装注入；ReportTab 独立 chunk 同理，MarkdownView 栈不进主包）。
const CorrelationTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/CorrelationTab").then(m => ({ default: m.CorrelationTab })));
const LogsTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/LogsTab").then(m => ({ default: m.LogsTab })));
const LiveTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/LiveTab"));
const ReposTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/ReposTab").then(m => ({ default: m.ReposTab })));
const WsSettingsTab = lazyWithRetry(() => import("./routes/WorkspaceDetail/WsSettingsTab"));
const AuthProfilesPage = lazyWithRetry(() => import("./pages/AuthProfilesPage").then(m => ({ default: m.AuthProfilesPage })));
const AuthProfileTestPage = lazyWithRetry(() => import("./pages/AuthProfileTestPage").then(m => ({ default: m.AuthProfileTestPage })));
const VerifyProcessPage = lazyWithRetry(() => import("./pages/VerifyProcessPage").then(m => ({ default: m.VerifyProcessPage })));
const HostProfilesPage = lazyWithRetry(() => import("./pages/HostProfilesPage").then(m => ({ default: m.HostProfilesPage })));
const WorkspacesEntry = lazyWithRetry(() => import("./components/WorkspacesEntry").then(m => ({ default: m.WorkspacesEntry })));
const DevComponentsPage = lazyWithRetry(() => import("./pages/DevComponentsPage").then(m => ({ default: m.DevComponentsPage })));

// per-scan 默认 tab：进行中 -> live，完成 -> report。fetch scan status 后 navigate（replace 避免占历史栈）。
// correlation 主行（D6，spec 2026-08-24 §8；2026-09-10 tab 组增 live 后对齐该语义）：
// 进行中 -> live（段②编排 + 段③黑盒验证实时日志），完成 -> 跨仓关联（结果页替代 report）。
export function DefaultScanTab() {
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  const nav = useNavigate();
  useEffect(() => {
    if (!workspace || !scanId) return;
    getScan(workspace, scanId)
      .then((s) => {
        const st = s.status ?? s.session?.status ?? "running";
        const done = st === "completed" || st === "done";
        // correlation 完成态结果页 = 跨仓关联 tab（无 report）；其余完成态落 report。
        nav(s.scan_type === "correlation"
          ? (done ? "correlation" : "live")
          : (done ? "report" : "live"), { replace: true });
      })
      .catch(() => nav("live", { replace: true }));
  }, [workspace, scanId, nav]);
  return null;
}

// 跨仓关联 tab 路由包装（D6）：CorrelationTab 收 {ws, scanId} props（D5 契约，组件自身
// 无 router 依赖），此处从 useParams 注入。
function CorrelationTabRoute() {
  const { workspace, scanId } = useParams<{ workspace: string; scanId: string }>();
  return <CorrelationTab ws={workspace ?? ""} scanId={scanId ?? ""} />;
}

// 旧 ws-scoped tab 路由（/p/:ws/overview 等）过渡期 shim：redirect 到 latest scan 的对应 tab。
// spec §5.2 shim：旧端点操作 ws 内 latest scan。Phase 2 切完后此 redirect 移除（F6）。
function LegacyWsTabRedirect({ tab }: { tab: string }) {
  const { workspace } = useParams<{ workspace: string }>();
  const nav = useNavigate();
  useEffect(() => {
    if (!workspace) return;
    listScans(workspace)
      .then((scans) => {
        if (scans.length === 0) { nav(`/p/${workspace}`, { replace: true }); return; }
        // listScans 按 created_at 倒序，首项 = latest scan
        nav(`/p/${workspace}/scans/${scans[0].scan_id}/${tab}`, { replace: true });
      })
      .catch(() => nav(`/p/${workspace}`, { replace: true }));
  }, [workspace, tab, nav]);
  return null;
}

const devRoutes = import.meta.env.DEV
  ? [{ path: "/dev/components", element: <DevComponentsPage /> }]
  : [];

export const router = createBrowserRouter([
  // /login 公开路由（不进 AppShell；业务路由的 RequireAuth 包裹在 Task 16 加）
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireAuth><AppShell /></RequireAuth>,
    children: [
      { path: "/", element: <DashboardPage /> },
      // 顶栏「工作区」入口：三段跳转（pinned->最近->空态）。IA 重设计 §2.3
      { path: "/workspaces-entry", element: <WorkspacesEntry /> },
      // WorkspaceListPage 已下线（取消并入 Dashboard、删除并入切换器，spec 2026-07-27）。
      // 旧 /workspaces 链接/书签 redirect 到 Dashboard，不 404。
      { path: "/workspaces", element: <Navigate to="/" replace /> },
      { path: "/scan/new", element: <ScanNewPage /> },
      {
        // ws 概览（容器）：ws header + 扫描列表 + 仓库/settings 入口
        path: "/p/:workspace",
        element: <WorkspaceDetail />,
        children: [
          { index: true, element: <ScanList /> },
          // ws 级 tab（仓库/配置）保留在 ws 概览下
          { path: "repos", element: <ReposTab /> },
          { path: "settings", element: <WsSettingsTab /> },
          { path: "auth-profiles", element: <AuthProfilesPage /> },
          // HOST 档案（blackbox-host-profile）：domain→IP 映射管理，黑盒扫描时注入代理/DNS 覆盖。
          { path: "host-profiles", element: <HostProfilesPage /> },
          // 档案级认证测试页：多选角色 → 串行逐个独立验证。档案行「测试登录」按钮跳此路由。
          { path: "auth-profiles/:pid", element: <AuthProfileTestPage /> },
          // 认证过程页（新标签页打开）: 测试登录实时 + 最近一次回看。列表 chip 点击 window.open 此路由。
          { path: "auth-profiles/:pid/credentials/:cid", element: <VerifyProcessPage /> },
          // 旧 ws-scoped scan tab 路由 -> redirect 到 latest scan 对应 tab（过渡期 shim）
          { path: "overview", element: <LegacyWsTabRedirect tab="overview" /> },
          { path: "report", element: <LegacyWsTabRedirect tab="report" /> },
          { path: "deliverables", element: <LegacyWsTabRedirect tab="deliverables" /> },
          { path: "logs", element: <LegacyWsTabRedirect tab="logs" /> },
          { path: "live", element: <LegacyWsTabRedirect tab="live" /> },
        ],
      },
      {
        // per-scan 视图：scan header + scan tabs（overview/report/deliverables/logs/live；
        // correlation 主行 tab 组分支见 ScanDetail——概览/跨仓关联/产物/日志）
        path: "/p/:workspace/scans/:scanId",
        element: <ScanDetail />,
        children: [
          { index: true, element: <DefaultScanTab /> },
          { path: "overview", element: <OverviewTab /> },
          { path: "report", element: <ReportTab /> },
          { path: "evidence", element: <EvidenceTab /> },
          { path: "deliverables", element: <DeliverablesTab /> },
          { path: "dataflow", element: <DataFlowTab /> },
          // 跨仓关联结果视图（D6 路由接线；命名对齐兄弟 tab 的单词段约定）
          { path: "correlation", element: <CorrelationTabRoute /> },
          { path: "logs", element: <LogsTab /> },
          { path: "live", element: <LiveTab /> },
        ],
      },
      { path: "/settings", element: <SettingsPage /> },
      { path: "/users", element: <RequireAdmin><UsersPage /></RequireAdmin> },
      ...devRoutes,
    ],
  },
]);
