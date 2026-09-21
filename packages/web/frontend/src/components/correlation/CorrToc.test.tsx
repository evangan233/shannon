// CorrToc 单测（2026-09-20 结论优先批次；09-20 去重 / 09-21 静默批次收窄区块；
// 09-21 修文档序——漏洞条目紧随「漏洞」区块条目，不再堆在全部区块后致点击回跳）：
// 区块镜像 presence、漏洞条目按结论分组 + severity 状态点、点击回调分流。
// scrollspy 用 IntersectionObserver——jsdom 缺席，渲染与点击不受影响（ReportToc 同）。
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, within } from "@testing-library/react";
import { CorrToc, CORR_SEC_TOPOLOGY } from "./CorrToc";
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
      sections={{ multihop: false, topology: true }}
      {...over}
    />,
  );
}

describe("CorrToc — 跨仓结果页目录", () => {
  it("镜像 presence 区块：multihop 关闭不渲染；撤除章节不再出现", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    expect(screen.getByText("漏洞（按跨仓结论）")).toBeInTheDocument();
    expect(screen.queryByText("多跳候选链")).not.toBeInTheDocument();
    expect(screen.getByText("服务拓扑")).toBeInTheDocument();
    // 信任边界/单仓已否决/关联报告章节已撤（信息落 md 附录/复核行/总览头下载）
    expect(screen.queryByText("信任边界")).not.toBeInTheDocument();
    expect(screen.queryByText("单仓已否决（跨仓重审）")).not.toBeInTheDocument();
    expect(screen.queryByText("关联报告")).not.toBeInTheDocument();
  });

  it("文档序：漏洞条目紧随「漏洞」区块条目，其余区块垫后（修复点击回跳）", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    const nav = screen.getByTestId("corr-toc");
    const ids = [...nav.querySelectorAll<HTMLElement>("[data-toc-id]")]
      .map((el) => el.getAttribute("data-toc-id"));
    // 漏洞区块 → 漏洞条目（INJ-1/XSS-1/INJ-2）→ 服务拓扑
    expect(ids).toEqual([
      "corr-sec-vulns",
      "corr-vuln-INJ-1", "corr-vuln-XSS-1", "corr-vuln-INJ-2",
      "corr-sec-topology",
    ]);
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
    fireEvent.click(within(screen.getByTestId("corr-toc")).getByText("服务拓扑"));
    expect(onSection).toHaveBeenCalledWith(CORR_SEC_TOPOLOGY);
    fireEvent.click(screen.getByText("INJ-1"));
    expect(onVuln).toHaveBeenCalledWith("INJ-1");
  });

  it("无回调时缺省直接 focusAnchor（不抛错）", async () => {
    await i18n.changeLanguage("zh");
    renderToc();
    expect(() => fireEvent.click(screen.getByText("服务拓扑"))).not.toThrow();
    // 区块锚点元素缺席（未挂载对应 section）时 focusAnchor 静默返回
    expect(document.getElementById(CORR_SEC_TOPOLOGY)).toBeNull();
  });
});
