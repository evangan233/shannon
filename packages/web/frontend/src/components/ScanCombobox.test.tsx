import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ScanCombobox } from "./ScanCombobox";
import type { ScanSummary } from "@/api/types";

// 任务单选可搜索下拉（2026-09-15）：黑盒表单选白盒任务用——候选多时按
// workflow_id / scan_id / repo 搜；单选语义（onSelect 替换 + 收起）。

function mk(partial: Partial<ScanSummary>): ScanSummary {
  return {
    scan_id: "s", scan_type: "whitebox", status: "completed",
    created_at: 0, vuln_count: 0, is_running: false, ...partial,
  };
}

const SCANS = [
  mk({ scan_id: "gw_trade-20260910", workflow_id: "ws1-gw_trade-20260910", repo: "gw_trade" }),
  mk({ scan_id: "stock-20260909", workflow_id: "ws1-stock-20260909", repo: "stock-svc" }),
  mk({ scan_id: "legacy-no-wf", repo: null }),
];

const baseProps = {
  scans: SCANS,
  value: "",
  onChange: vi.fn(),
  placeholder: "选择任务",
  searchPlaceholder: "搜索任务…",
  emptyText: "无匹配任务",
};

describe("ScanCombobox", () => {
  it("未选中时触发器显示 placeholder", () => {
    render(<ScanCombobox {...baseProps} />);
    expect(screen.getByText("选择任务")).toBeInTheDocument();
  });

  it("选中时触发器显示 workflow_id（缺省回落 scan_id）", () => {
    render(<ScanCombobox {...baseProps} value="gw_trade-20260910" onChange={vi.fn()} />);
    expect(screen.getByText("ws1-gw_trade-20260910")).toBeInTheDocument();
  });

  it("输入按 workflow_id / repo 过滤（子串、大小写不敏感）", async () => {
    render(<ScanCombobox {...baseProps} />);
    fireEvent.click(screen.getByText("选择任务"));
    const input = await screen.findByPlaceholderText("搜索任务…");
    // workflow_id 子串
    fireEvent.change(input, { target: { value: "STOCK" } });
    await waitFor(() => {
      expect(screen.getByText("ws1-stock-20260909")).toBeInTheDocument();
      expect(screen.queryByText("ws1-gw_trade-20260910")).not.toBeInTheDocument();
    });
    // repo 子串
    fireEvent.change(input, { target: { value: "gw_trade" } });
    await waitFor(() => {
      expect(screen.getByText("ws1-gw_trade-20260910")).toBeInTheDocument();
      expect(screen.queryByText("ws1-stock-20260909")).not.toBeInTheDocument();
    });
  });

  it("点击匹配项触发 onChange(scan_id) 并关闭（单选：选中即替换）", async () => {
    const onChange = vi.fn();
    render(<ScanCombobox {...baseProps} value="stock-20260909" onChange={onChange} />);
    fireEvent.click(screen.getByRole("combobox"));
    const opt = await screen.findByRole("option", { name: /gw_trade/ });
    fireEvent.click(opt);
    expect(onChange).toHaveBeenCalledWith("gw_trade-20260910");
    await waitFor(() =>
      expect(screen.queryByRole("option", { name: /gw_trade/ })).not.toBeInTheDocument());
  });

  it("无匹配时显示空文案；loading 优先于空态", async () => {
    render(<ScanCombobox {...baseProps} />);
    fireEvent.click(screen.getByText("选择任务"));
    const input = await screen.findByPlaceholderText("搜索任务…");
    fireEvent.change(input, { target: { value: "zzz不存在" } });
    expect(await screen.findByText("无匹配任务")).toBeInTheDocument();

    render(
      <ScanCombobox {...baseProps} scans={[]} loading loadingText="加载任务中…" />,
    );
    fireEvent.click(screen.getAllByText("选择任务")[1]);
    expect(await screen.findByText("加载任务中…")).toBeInTheDocument();
  });
});
