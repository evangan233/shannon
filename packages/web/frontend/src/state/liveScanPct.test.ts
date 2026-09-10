// liveScanPct：SSE 归并流 events → 列表行实时进度（组合扫描三阶段加权，2026-08-28）。
// 根因背景：dashboardReducer 是「当前 phase」口径（PhaseEvent(start) 重置 units），
// 组合扫描白盒最后 phase 收尾后 fold=N/N=100%，黑盒段又从 0 爬——列表行把它当
// 全任务进度即误导。src 源标记（tailer 注入）判段后按 spec §9.2 三阶段映射。
import { describe, it, expect } from "vitest";
import { liveScanPct } from "./liveScanPct";
import type { NdjsonEvent } from "../api/types";

const COMBINED = { combined: true, scan_type: "whitebox" } as const;
const PURE_WB = { combined: false, scan_type: "whitebox" } as const;
const CORR = { combined: true, scan_type: "correlation" } as const;

function phase(src: string, phaseName: string, steps: string[]): NdjsonEvent {
  return {
    ts: "2026-08-28T10:00:00Z", category: "PHASE",
    type: "PhaseEvent", event: "start", phase: phaseName, steps, step_intents: [],
    src,
  };
}
function step(src: string, phaseName: string, name: string, ev: "complete" | "start" = "complete"): NdjsonEvent {
  return {
    ts: "2026-08-28T10:00:01Z", category: "STEP",
    type: "StepEvent", name, phase: phaseName, event: ev,
    src,
  };
}

describe("liveScanPct 组合扫描三阶段加权", () => {
  it("白盒段满格 → 55% 而非 100%（黑盒未开始/段间空窗不再谎报完成）", () => {
    const events = [
      phase("wb", "recon", ["a", "b"]),
      step("wb", "recon", "a"), step("wb", "recon", "b"),
    ];
    expect(liveScanPct(events, COMBINED)).toBe(55);
  });

  it("白盒段半程 → 30%（5 + 50×0.5）", () => {
    const events = [
      phase("wb", "recon", ["a", "b"]),
      step("wb", "recon", "a"),
    ];
    expect(liveScanPct(events, COMBINED)).toBe(30);
  });

  it("黑盒段开头（steps 0/2）→ 55%；半程 → 78%；满格 → 100%", () => {
    const head = [phase("run-1", "exploitation", ["x", "y"])];
    expect(liveScanPct(head, COMBINED)).toBe(55);
    expect(liveScanPct([...head, step("run-1", "exploitation", "x")], COMBINED)).toBe(78);
    expect(liveScanPct(
      [...head, step("run-1", "exploitation", "x"), step("run-1", "exploitation", "y")],
      COMBINED)).toBe(100);
  });

  it("黑盒 preflight 空窗（steps=[] total=0）→ 55% 起点，非回退非 0", () => {
    const events = [phase("run-1", "preflight", [])];
    expect(liveScanPct(events, COMBINED)).toBe(55);
  });

  it("认证预检段（ac）→ 0-5% 微加权：1/4 → 1%，满格 → 5%", () => {
    const head = [phase("ac", "auth-validation", ["navigate", "fill", "submit", "verify"])];
    expect(liveScanPct([...head, step("ac", "auth-validation", "navigate")], COMBINED)).toBe(1);
    expect(liveScanPct([
      ...head, step("ac", "auth-validation", "navigate"),
      step("ac", "auth-validation", "fill"), step("ac", "auth-validation", "submit"),
      step("ac", "auth-validation", "verify"),
    ], COMBINED)).toBe(5);
  });

  it("事件无 src（旧后端流/单文件流）→ null（判不了段，回退 progress_pct）", () => {
    const events = [
      { ...phase("wb", "recon", ["a", "b"]), src: undefined },
      { ...step("wb", "recon", "a"), src: undefined },
      { ...step("wb", "recon", "b"), src: undefined },
    ];
    expect(liveScanPct(events as NdjsonEvent[], COMBINED)).toBeNull();
  });
});

describe("liveScanPct 非组合行（口径不变）", () => {
  it("纯白盒满格 → 100%（一段即全部）；total=0 → null", () => {
    expect(liveScanPct([
      phase("wb", "recon", ["a"]), step("wb", "recon", "a"),
    ], PURE_WB)).toBe(100);
    expect(liveScanPct([], PURE_WB)).toBeNull();
    expect(liveScanPct([phase("wb", "recon", [])], PURE_WB)).toBeNull();
  });

  it("correlation 主行（combined=true 也不套三阶段）→ fold 直读", () => {
    // correlation_progress 累积网格（reducer 不重置 units）：2 网格行完成 1 → 50%
    const events: NdjsonEvent[] = [
      { ts: "t", category: "CONTROL", type: "correlation_progress", node: "repo", name: "svc-a", status: "completed", src: "wb" },
      { ts: "t", category: "CONTROL", type: "correlation_progress", node: "repo", name: "svc-b", status: "started", src: "wb" },
    ];
    expect(liveScanPct(events, CORR)).toBe(50);
  });
});

// ─── correlation 主行子仓源过滤（2026-09-10 归并流扩子仓）───
// 现扫子仓白盒日志（src=c-<scan_id>）并入主行归并流后，其 PhaseEvent(start) 的
// 网格重置语义会清掉 correlation_progress 累积网格——列表行进度必须挡在 fold 外。
describe("liveScanPct correlation 子仓源过滤", () => {
  it("子仓 PhaseEvent/StepEvent（src=c-*）不重置 correlation 网格", () => {
    const events: NdjsonEvent[] = [
      { ts: "2026-09-10T10:00:00Z", category: "CONTROL", type: "correlation_progress",
        node: "repo", name: "gateway", status: "completed", src: "wb" },
      { ts: "2026-09-10T10:00:01Z", category: "CONTROL", type: "correlation_progress",
        node: "repo", name: "order-svc", status: "completed", src: "wb" },
      phase("c-gw-123", "recon", ["a", "b"]),
      step("c-gw-123", "recon", "a"),
    ];
    expect(liveScanPct(events, CORR)).toBe(100); // 2/2 repo 完成——子仓重置则会低
  });

  it("纯子仓事件（主行尚无 correlation_progress）→ null 回退 progress_pct", () => {
    const events: NdjsonEvent[] = [
      phase("c-gw-123", "recon", ["a", "b"]),
      step("c-gw-123", "recon", "a"),
    ];
    expect(liveScanPct(events, CORR)).toBeNull();
  });
});
