import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import i18n from "@/i18n";
import { StatusBadge } from "./StatusBadge";

// jsdom navigator.language 默认 en,LanguageDetector 会把 i18n 切到 en;
// 现有断言依赖中文渲染,逐测试钉回 zh(同 ReposPage.test 模式)。
beforeEach(() => i18n.changeLanguage("zh"));

// 2026-09-10 状态图标语言统一：Unicode 字符/emoji → lucide svg（跨字体基线一致）。
// 断言口径：图标 = Badge 内自身带 aria-hidden 的 <svg>（lucide 把 aria-hidden 直接
// 落在 svg 上，无包裹 span）。
describe("StatusBadge", () => {
  it("running → spinner 图标 + 文案(Badge 渲染)", () => {
    const { container } = render(<StatusBadge status="running" />);
    expect(screen.getByText("运行中")).toBeInTheDocument();
    // shadcn Badge 渲染为外层 <div>(含 text-* 语义色),内含 aria-hidden svg 承载图标
    const badge = container.querySelector("[class*='text-cyan']");
    expect(badge).not.toBeNull();
    const icon = badge?.querySelector("svg[aria-hidden='true']");
    expect(icon).not.toBeNull();
    // running 是全表唯一动效：spin + motion-reduce 尊重减动效
    expect(icon?.getAttribute("class")).toMatch(/animate-spin/);
    expect(icon?.getAttribute("class")).toMatch(/motion-reduce:animate-none/);
  });
  it("completed 渲染 Badge + green 语义色（非 spinner）", () => {
    render(<StatusBadge status="completed" />);
    // 拒绝 weak `??` 兜底:直接断言承载 completed 文案的 Badge 带 text-green
    const node = screen.getByText("已完成").closest("[class*='text-green']");
    expect(node).not.toBeNull();
    expect(node).toBeInTheDocument();
    expect(node?.querySelector("svg[aria-hidden='true']")?.getAttribute("class") ?? "").not.toMatch(/animate-spin/);
  });
  it("徽标不换行（whitespace-nowrap）——112px 状态列任何 locale 不挤两行", () => {
    const { container } = render(<StatusBadge status="running" />);
    const badge = container.querySelector("[title='running']");
    expect(badge?.className).toMatch(/whitespace-nowrap/);
  });
  it("soft-tint 状态灯：胶囊形 + 同色系柔和底（2026-09-10 美观升级）", () => {
    const { container } = render(<StatusBadge status="completed" />);
    const badge = container.querySelector("[title='completed']");
    expect(badge?.className).toMatch(/rounded-full/);
    expect(badge?.className).toMatch(/bg-green\/10/);
    // 状态=语义层：不再用 mono（类型列 Badge 保持 mono 技术层，形状+字体双重分层）
    expect(badge?.className).not.toMatch(/font-mono/);
  });
  it("running 叠底色呼吸（status-breathe），其余状态静止", () => {
    const { container } = render(<><StatusBadge status="running" /><StatusBadge status="queued" /></>);
    expect(container.querySelector("[title='running']")?.className).toMatch(/status-breathe/);
    expect(container.querySelector("[title='queued']")?.className).not.toMatch(/status-breathe/);
  });
  it("a11y:title 属性 = status 字符串(图标不应是唯一信号)", () => {
    const { container } = render(<StatusBadge status="running" />);
    const badge = container.querySelector("[title='running']");
    expect(badge?.getAttribute("title")).toBe("running");
  });
  it("a11y:未知 status 也有 title", () => {
    const { container } = render(<StatusBadge status="weird-state" />);
    const badge = container.querySelector("[title='weird-state']");
    expect(badge?.getAttribute("title")).toBe("weird-state");
  });
  it("未知 status 走 warn 色 + help 图标", () => {
    const { container } = render(<StatusBadge status="weird" />);
    expect(screen.getByText(/weird/)).toBeInTheDocument();
    const badge = container.querySelector("[class*='text-yellow']");
    expect(badge?.className).toMatch(/text-yellow/);
    expect(badge?.querySelector("svg[aria-hidden='true']")).not.toBeNull();
  });
});

describe("StatusBadge i18n", () => {
  beforeEach(() => i18n.changeLanguage("zh"));

  it("已知状态中文映射", () => {
    render(<StatusBadge status="running" />);
    expect(screen.getByText("运行中")).toBeInTheDocument();
  });

  it("切英文映射", () => {
    i18n.changeLanguage("en");
    render(<StatusBadge status="running" />);
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("queued → 时钟图标 + 排队中", () => {
    render(<StatusBadge status="queued" />);
    expect(screen.getByText("排队中")).toBeInTheDocument();
  });

  it("reconnecting → 中性等待态，不伪装成已中断", () => {
    render(<StatusBadge status="reconnecting" />);
    expect(screen.getByText("重连中")).toBeInTheDocument();
  });

  it("未知状态 fallback 原值不空白", () => {
    render(<StatusBadge status="some-new-state" />);
    expect(screen.getByText("some-new-state")).toBeInTheDocument();
  });
});
