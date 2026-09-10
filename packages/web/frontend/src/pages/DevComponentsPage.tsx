import type { ReactNode } from "react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Spinner } from "@/components/Spinner";
import { Empty } from "@/components/Empty";
import { MergeSourceBadge, ReachableBadge } from "@/components/vuln-badges";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { FileSystemPicker } from "@/components/FileSystemPicker";
import { ErrorState } from "@/components/ErrorState";
import { StatusBadge } from "@/components/StatusBadge";
import { VulnCard } from "@/components/VulnCard";
import { DashboardPanel } from "@/components/DashboardPanel";
import { LogStream } from "@/components/LogStream";
import { emptyState, type DashboardState } from "@/state/dashboardReducer";
import type { NdjsonEvent, Vulnerability } from "@/api/types";

function FileSystemPickerDemo() {
  const [path, setPath] = useState("/");
  return (
    <div className="flex items-center gap-2">
      <FileSystemPicker value={path} onChange={setPath} />
      <span className="font-mono text-sm text-muted-foreground">已选：{path}</span>
    </div>
  );
}

// Task 15 mock：DashboardPanel 信息增强（current_phase + phase_units + unit_status +
// unit_intent + 1 running agent + completed_count + total_cost）。
const MOCK_DASHBOARD_STATE: DashboardState = {
  ...emptyState(),
  current_phase: "recon",
  phase_units: ["pre-recon", "recon", "vulnerability-analysis", "reporting"],
  unit_status: {
    "pre-recon": "done",
    "recon": "running",
    "vulnerability-analysis": "",
    "reporting": "",
  },
  unit_intent: {
    "pre-recon": "GitNexus 索引",
    "recon": "recon agent 情报收集",
    "vulnerability-analysis": "六类漏洞分析",
    "reporting": "中文综合报告",
  },
  agents: {
    "recon-agent": {
      name: "recon-agent",
      status: "running",
      attempt: 1,
      turn: 3,
      last_action: "Read",
      last_action_detail: "Read README.md",
      last_turn_text: "正在分析项目结构...",
      duration_ms: null,
      cost_usd: 0.12,
      error: null,
    },
  },
  completed_count: 0,
  total_cost: 0.12,
  total_units: 4,
  completed_units: 1,
  running_units: ["recon"],
};

// Task 15 mock：LogStream 事件流，覆盖 summarizer 各分支（phase/step/agent/tool/llm/info）。
const MOCK_EVENTS: NdjsonEvent[] = [
  { type: "WorkflowHeader", category: "HEADER", ts: "2026-07-04T01:00:00.000Z", workflow_id: "wf-demo", target_url: "https://example.git", repo_path: "/repo", mode: "whitebox", web_ui_url: "/p/demo/live", logs_cmd: "tail -f", workspace: "demo" },
  { type: "PhaseEvent", category: "PHASE", ts: "2026-07-04T01:00:01.000Z", phase: "recon", event: "start", steps: ["pre-recon", "recon"], step_intents: ["索引", "情报"] },
  { type: "StepEvent", category: "STEP", ts: "2026-07-04T01:00:05.000Z", name: "pre-recon", phase: "recon", event: "start" },
  { type: "StepEvent", category: "STEP", ts: "2026-07-04T01:00:10.000Z", name: "pre-recon", phase: "recon", event: "complete", duration_ms: 5000 },
  { type: "AgentEvent", category: "AGENT", ts: "2026-07-04T01:00:11.000Z", agent_name: "recon-agent", event: "start", attempt: 1 },
  { type: "ToolCallEvent", category: "TOOL", ts: "2026-07-04T01:00:12.000Z", agent_name: "recon-agent", tool_name: "Read", parameters: { path: "README.md" } },
  { type: "LlmTurnEvent", category: "LLM", ts: "2026-07-04T01:00:13.000Z", agent_name: "recon-agent", turn: 3, content: "正在分析项目结构..." },
  { type: "InfoEvent", category: "CONTROL", ts: "2026-07-04T01:00:14.000Z", message: "GitNexus 索引完成", level: "info" },
];

// Task 15 mock：VulnCard 一可达一不可达，分别带 merge_source。
const MOCK_VULNS: Vulnerability[] = [
  {
    ID: "INJ-001",
    vulnerability_type: "SQL Injection",
    externally_exploitable: true,
    confidence: "high",
    source_endpoint: "POST /api/login",
    vulnerable_code_location: "src/auth.ts:42",
    missing_defense: "未参数化查询",
    exploitation_hypothesis: "username 字段拼接 SQL",
    suggested_exploit_technique: "' OR 1=1--",
    merge_source: "both",
  },
  {
    ID: "INJ-002",
    vulnerability_type: "Command Injection",
    externally_exploitable: false,
    confidence: "medium",
    source_endpoint: "internal job",
    vulnerable_code_location: "internal/runner.py:88",
    notes: "仅内部触发，公网不可达",
    merge_source: "llm-only",
  },
];

export function DevComponentsPage() {
  return (
    <div className="space-y-8">
      <h1 className="font-semibold tracking-tight text-2xl">Component Preview (dev-only)</h1>

      <Section title="Theme">
        <ThemeToggle />
        <span className="text-sm text-muted-foreground">点切换深/浅，刷新验持久化</span>
      </Section>

      <Section title="子项目5 新页(Dashboard / Settings)">
        <span className="text-sm text-muted-foreground">访问 </span>
        <code className="font-mono text-cyan">/</code>
        <span className="text-sm text-muted-foreground"> 看 Dashboard 进站概览,</span>
        <code className="font-mono text-cyan">/settings</code>
        <span className="text-sm text-muted-foreground"> 看主题 + 系统状态 + 关于。ThemeToggle 切深/浅验对比度。</span>
      </Section>

      <Section title="Buttons">
        <Button>default</Button>
        <Button variant="secondary">secondary</Button>
        <Button variant="ghost">ghost</Button>
        <Button variant="outline">outline</Button>
        <Button variant="destructive">destructive</Button>
        <Button size="sm">small</Button>
        <Button size="icon" aria-label="op">⏵</Button>
      </Section>

      <Section title="Inputs">
        <Label htmlFor="i1">文本</Label>
        <Input id="i1" placeholder="type..." />
        <Textarea placeholder="多行" />
      </Section>

      <Section title="Selection">
        <Checkbox id="c1" defaultChecked />
        <Label htmlFor="c1">勾选</Label>
        <Switch defaultChecked aria-label="开关" />
      </Section>

      <Section title="Badges">
        <Badge>default</Badge>
        <MergeSourceBadge source="llm-only" />
        <MergeSourceBadge source="gitnexus-only" />
        <MergeSourceBadge source="both" />
        <ReachableBadge reachable={true} />
        <ReachableBadge reachable={false} />
      </Section>

      <Section title="StatusBadge（lucide 图标·状态语义色）">
        {["running", "completed", "failed", "killed", "crashed", "interrupted", "queued", "weird-state"].map((s) => (
          <StatusBadge key={s} status={s} />
        ))}
        <StatusBadge status="done" />
      </Section>

      <Section title="ErrorState（共享组件·红横幅）">
        <ErrorState message="示例错误信息（无重试）" />
        <ErrorState message="带重试按钮" onRetry={() => alert("retry clicked")} />
      </Section>

      <Section title="VulnCard（可点行键盘可展开·一可达一内部）">
        {MOCK_VULNS.map((v) => (
          <VulnCard key={v.ID} v={v} />
        ))}
      </Section>

      <Section title="DashboardPanel（mock state·信息增强）">
        <DashboardPanel state={MOCK_DASHBOARD_STATE} elapsedMs={123456} />
      </Section>

      <Section title="LogStream（aria-live·mock 事件流）">
        <LogStream events={MOCK_EVENTS} />
      </Section>

      <Section title="Spinner">
        <Spinner label="running" />
        <Spinner />
      </Section>

      <Section title="Empty">
        <div className="w-full">
          <Empty title="no workspaces" hint="新建一个扫描开始">
            <Button>+ new scan</Button>
          </Empty>
        </div>
      </Section>

      <Section title="Skeleton">
        <Skeleton className="h-4 w-48" />
        <Skeleton className="h-4 w-64" />
      </Section>

      <Section title="Tabs">
        <Tabs defaultValue="a">
          <TabsList>
            <TabsTrigger value="a">Tab A</TabsTrigger>
            <TabsTrigger value="b">Tab B</TabsTrigger>
          </TabsList>
          <TabsContent value="a">content a</TabsContent>
          <TabsContent value="b">content b</TabsContent>
        </Tabs>
      </Section>

      <Section title="Card">
        <Card className="max-w-sm">
          <CardHeader>
            <CardTitle>title</CardTitle>
          </CardHeader>
          <CardContent>content</CardContent>
        </Card>
      </Section>

      <Section title="FileSystemPicker">
        <FileSystemPickerDemo />
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="font-semibold tracking-tight text-lg text-muted-foreground">{title}</h2>
      <div className="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card p-4">
        {children}
      </div>
    </section>
  );
}
