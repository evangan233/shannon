// prune/text.ts 纯函数测试（T1，TDD 先行）。
// 估宽沿用旧 PruningTreeFig.textWidthPx 口径（全角 1.0×fontSize / 半角 0.56×fontSize，
// 参数化字号）；wrapLabel 是新布局「网格迁就文字」的核心：行数决定节点高、行数封顶。
import { describe, expect, it } from "vitest";
import { estimateTextWidthPx, wrapLabel } from "../prune/text";

describe("estimateTextWidthPx", () => {
  it("全角按 1.0×fontSize、半角按 0.56×fontSize 估宽", () => {
    expect(estimateTextWidthPx("中文", 10)).toBeCloseTo(20);
    expect(estimateTextWidthPx("ab", 10)).toBeCloseTo(11.2);
    // 混排（半角+全角+半角）
    const w = estimateTextWidthPx("a中b", 10);
    expect(w).toBeCloseTo(5.6 + 10 + 5.6);
  });

  it("参数化字号（fontSize=11 等比放大）", () => {
    expect(estimateTextWidthPx("中", 11)).toBeCloseTo(11);
    expect(estimateTextWidthPx("a", 11)).toBeCloseTo(6.16);
  });
});

describe("wrapLabel", () => {
  it("单行装得下 → 原文一行", () => {
    expect(wrapLabel("short", 200, 3)).toEqual(["short"]);
    expect(wrapLabel("中文标签", 200, 3)).toEqual(["中文标签"]);
  });

  it("超预算贪心换行，行内不超预算", () => {
    // 预算 40px：全角 10px/字 → 每行 4 字
    const lines = wrapLabel("一二三四五六七八", 40, 3);
    expect(lines).toEqual(["一二三四", "五六七八"]);
  });

  it("行数封顶 maxLines：末行截断加「…」", () => {
    // 预算 40px 每行 4 全角字，maxLines=2 → 两行，第二行尾 …（预留省略号宽 10px → 3 字 + …）
    const lines = wrapLabel("一二三四五六七八九十一", 40, 2);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("一二三四");
    expect(lines[1].endsWith("…")).toBe(true);
    // 第二行内容不超过预算（… 按 10px 计）
    expect(estimateTextWidthPx(lines[1], 10)).toBeLessThanOrEqual(40);
    // 拼接（去 …）是原文前缀
    expect(lines[1].replace(/…$/, "")).toBe("五六七");
  });

  it("行数封顶内不丢内容（无 …）", () => {
    const lines = wrapLabel("一二三四五六七八", 40, 2);
    expect(lines.join("")).toBe("一二三四五六七八");
    expect(lines.some((l) => l.includes("…"))).toBe(false);
  });

  it("半角长串（函数名）按 5.6px/字贪心换行", () => {
    // 预算 28px → 5 半角字/行
    const lines = wrapLabel("abcdefgh", 28, 3);
    expect(lines).toEqual(["abcde", "fgh"]);
  });

  it("确定性：同输入两次调用结果一致", () => {
    const s = "AllocationsDAO.getByUserIdAndThreshold 直接模板字符串拼接进 $where:88";
    expect(wrapLabel(s, 140, 3)).toEqual(wrapLabel(s, 140, 3));
  });

  it("空串与恰好压线的串", () => {
    expect(wrapLabel("", 100, 3)).toEqual([""]);
    // 恰好等于预算 → 单行不拆
    expect(wrapLabel("一二三四", 40, 3)).toEqual(["一二三四"]);
  });
});
