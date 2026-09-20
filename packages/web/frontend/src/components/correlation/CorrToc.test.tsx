// CorrToc 单测（2026-09-20 结论优先批次）：区块镜像 presence、漏洞条目按结论
// 分组 + severity 状态点、点击回调分流（区块 anchor / 漏洞 vulnId）。
// scrollspy 用 IntersectionObserver——jsdom 缺席，渲染与点击不受影响（ReportToc 同）。
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { CorrToc, CORR_SEC_VERDICT, CORR_SEC_FLOWS } from "./CorrToc";
import type { CorrTocVuln } from "./CorrToc";
import i18n from "@/i18n";

const vulns: CorrTocVuln[] = [
  { id: "INJ-1", anchorId: "corr-vuln-INJ-1", severity: "critical", service: "order-svc", group: "confirmed" },
  { id: "XSS-1", anchorId: "corr-vuln-XSS-1", severity: "high", service: "web", group: "refuted" },
  { id: "INJ-2", anchorId: "corr-vuln-INJ-2", severity: "low", service: "web", group: "unadjudicated" },
];

function renderToc(over: { onLocateSection?: (id: string) => void; onLocateVuln?: (id: string) => void } = {}) {
  return render(
    <CorrToc
      vulns={vulns}
      sections={{ flows: true, multihop: false, topology: true, dismissed: false, boundaries: true, report: true }}
      {...over}
    />,
  );
}

describe("CorrToc — 跨仓结果页目录", () => {
  it("镜像 presence 区块：multihop/dismissed 关闭不渲染，其余可见", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    expect(screen.getByText("跨仓结论")).toBeInTheDocument();
    expect(screen.getByText("漏洞（按跨仓结论）")).toBeInTheDocument();
    expect(screen.getByText("跨服务攻击链")).toBeInTheDocument();
    expect(screen.queryByText("多跳候选链")).not.toBeInTheDocument();
    expect(screen.queryByText("单仓已否决（跨仓重审）")).not.toBeInTheDocument();
    expect(screen.getByText("信任边界")).toBeInTheDocument();
    expect(screen.getByText("关联报告")).toBeInTheDocument();
  });

  it("漏洞条目按结论组分组（成立在前）+ 组计数", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    expect(screen.getByText("成立 (1)")).toBeInTheDocument();
    expect(screen.getByText("消掉 (1)")).toBeInTheDocument();
    expect(screen.getByText("未重审 (1)")).toBeInTheDocument();
    expect(screen.queryByText("存疑", { exact: false })).not.toBeInTheDocument(); // 存疑组空不渲染组头
  });

  it("点击分流：区块条目走 onLocateSection（anchor id），漏洞条目走 onLocateVuln（vuln id）", async () => {
    await i18n.changeLanguage("zh");
    const onSection = vi.fn();
    const onVuln = vi.fn();
    renderToc({ onLocateSection: onSection, onLocateVuln: onVuln });
    fireEvent.click(screen.getByText("跨服务攻击链"));
    expect(onSection).toHaveBeenCalledWith(CORR_SEC_FLOWS);
    fireEvent.click(screen.getByText("INJ-1"));
    expect(onVuln).toHaveBeenCalledWith("INJ-1");
  });

  it("无回调时缺省直接 focusAnchor（不抛错）", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    expect(() => fireEvent.click(screen.getByText("跨仓结论"))).not.toThrow();
    // 区块锚点元素缺席（未挂载对应 section）时 focusAnchor 静默返回
    expect(document.getElementById(CORR_SEC_VERDICT)).toBeNull();
  });
});
