// 跨仓来源智能默认（2026-09-09）：仓库进入配置时，有成功白盒 → 默认复用最新一次；
// 无成功/未扫过 → 现扫。本文件锁定取值口径：whitebox + completed + repo 精确匹配，
// created_at 最大者胜（更新的失败扫描不抢默认）。
import { describe, expect, it } from "vitest";
import { latestReusableScanId } from "./correlation-reuse";

const scan = (over: Record<string, unknown>) => ({
  scan_id: "s", repo: "order-svc", scan_type: "whitebox",
  status: "completed", created_at: 1000, ...over,
});

describe("latestReusableScanId", () => {
  it("多条成功白盒 → 取 created_at 最新一次", () => {
    const scans = [scan({ scan_id: "old", created_at: 1000 }), scan({ scan_id: "new", created_at: 2000 })];
    expect(latestReusableScanId(scans, "order-svc")).toBe("new");
  });

  it("更新的失败/运行中扫描不抢默认——只认 completed", () => {
    const scans = [
      scan({ scan_id: "done", created_at: 1000 }),
      scan({ scan_id: "failed-newer", status: "failed", created_at: 9000 }),
      scan({ scan_id: "running-newer", status: "running", created_at: 9500 }),
    ];
    expect(latestReusableScanId(scans, "order-svc")).toBe("done");
  });

  it("非白盒 / 别的仓库的扫描不参与", () => {
    const scans = [
      scan({ scan_id: "mr", scan_type: "mr", created_at: 9000 }),
      scan({ scan_id: "other-repo", repo: "pay-svc", created_at: 9000 }),
    ];
    expect(latestReusableScanId(scans, "order-svc")).toBeNull();
  });

  it("只有失败扫描或从未扫过 → null（默认现扫）", () => {
    expect(latestReusableScanId([scan({ status: "failed" })], "order-svc")).toBeNull();
    expect(latestReusableScanId([], "order-svc")).toBeNull();
  });
});
