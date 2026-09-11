/** 锚点精准定位（2026-08-26 报告目录跳转修复）：ScanDetail 页有**双层 sticky 头**——
 *  TopBar(h-12=48px) + 「进度概览 + scan tabs」sticky 块(top-12，高度随进度内容变，
 *  实测 ~100px+)，合计遮蔽带 ≈150px，远超旧锚点 scroll-mt-20(80px) 预留——
 *  scrollIntoView(block:"start") 把卡头 ID/标题行留在遮蔽带里，症状即「点目录跳转
 *  后定位到漏洞标题下方，看不到标题」。修复立场：**不猜固定值**（sticky 块高度随
 *  主题/语言/进度概览内容变化），点击时刻运行时量取各 sticky 块遮蔽带，window.scrollTo
 *  精确落点让目标完整露出在遮蔽带下方；并复用 .dataflow-flash
 *  coral 描边闪烁（tokens.css，与 dataflow 目录/?tree= 深链同一「定位确认」语言）。
 *
 *  2026-09-11 二修（时序误差，chromium 实测钉死）：点击时刻一次性量取有两处系统性偏差——
 *  (a) **未贴顶量取偏大**：报告页 sticky 头上方还有 ~102px 页面内容（工作区头/横幅位），
 *      页面在顶部时 sticky 未贴顶，rect.bottom=自然位(293) 比贴顶底(191) 大 102 →
 *      落点恒定「过头」最多 102px。修：量**理论贴顶底** = computedTop(px)+rect.height，
 *      与滚动状态无关，未贴顶/贴顶两种时刻量取值一致。
 *  (b) **滚动中 sticky 长高**：进度概览订阅 SSE 事件重放（打开页面后内容逐步增长），
 *      smooth 滚动数百 ms 内遮蔽带长高 → 点击时刻的预留 < 滚动完成时真实遮蔽带 →
 *      目标标题被遮（用户报告的症状方向）。修：滚动结束（scrollend，timeout 兜底）
 *      后重量一次，偏差 >1px 补一次 instant 微调；用户已滚走（scrollY 偏离落点 >5px）
 *      或目标物理不可达（> maxScroll）时放弃，不与用户抢滚动。 */
const FLASH_CLEANUP_MS = 2000;
/** 校正兜底定时器：scrollend 缺席（旧浏览器/jsdom）时等 smooth 长距离滚动（~600-800ms）结束后再校正。 */
const CORRECTION_TIMEOUT_MS = 900;
/** 闪烁清理定时器（单例：新定位自动接管，旧定时器不再对新目标生效）。 */
let flashTimer: number | undefined;

/** 遮蔽带量取选择器：TopBar + ScanDetail sticky 头（外层 sticky div，含进度概览+tabs）。
 *  元素缺席（非 scan 页 / TopBar 外测试环境）按 0 计，互不影响。 */
const STICKY_SELECTORS = ['[data-testid="topbar"]', '[data-testid="scan-sticky-header"]'];

/** sticky 块理论贴顶底：computedTop(px) + 高度。与当前滚动状态无关——未贴顶时
 *  rect.bottom 是自然位（偏大），贴顶后才是遮蔽真值；两者中只有「贴顶底」是定位
 *  完成时刻的真实遮蔽带。computedTop 解析失败（jsdom 无样式/非 sticky）回落 rect.bottom（旧语义）。 */
function pinnedBottom(el: Element): number {
  const rect = el.getBoundingClientRect();
  const topPx = parseFloat(getComputedStyle(el).top);
  return Number.isFinite(topPx) ? topPx + rect.height : rect.bottom;
}

/** 量取当前 sticky 头遮蔽带下沿（各块理论贴顶底最大值）+ 8px 呼吸余量。 */
export function stickyHeaderOffset(): number {
  let bottom = 0;
  for (const sel of STICKY_SELECTORS) {
    const el = document.querySelector(sel);
    if (el) bottom = Math.max(bottom, pinnedBottom(el));
  }
  return bottom + 8;
}

/** 在途校正（单例：新定位自动作废旧校正——settled 标志 + 摘 listener + 清 timer，
 *  防 timer 兜底消费后残留 listener 盗跑吞掉下一次校正）。 */
let correction: { cancel: () => void } | undefined;

/** 排程滚动结束后的一次性校正（根因 b）：scrollend 优先，CORRECTION_TIMEOUT_MS 兜底；
 *  先到先得（settled 标志），触发后另一路径失效。 */
function scheduleCorrection(el: Element, intendedTop: number) {
  correction?.cancel();
  let settled = false;
  let timer = 0;
  const run = () => {
    // 用户已接管滚动（smooth 被打断 / 校正时机已过）→ 不与用户抢
    if (Math.abs(window.scrollY - intendedTop) > 5) return;
    const offset = stickyHeaderOffset();
    const elTop = el.getBoundingClientRect().top;
    if (Math.abs(elTop - offset) <= 1) return; // 无偏差（sticky 没长高）
    const target = elTop + window.scrollY - offset;
    // 物理不可达（目标在页面尾部、滚不到位）→ 放弃，不硬滚。
    // maxScroll ≤ 0 视为无约束（jsdom 无布局 scrollHeight=0，负数不该挡校正）。
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
    if (maxScroll > 0 && target > maxScroll) return;
    window.scrollTo({ top: target, behavior: "instant" });
  };
  const settle = () => {
    if (settled) return;
    settled = true;
    window.clearTimeout(timer);
    window.removeEventListener("scrollend", settle);
    correction = undefined;
    run();
  };
  timer = window.setTimeout(settle, CORRECTION_TIMEOUT_MS);
  correction = {
    cancel: () => {
      settled = true;
      window.clearTimeout(timer);
      window.removeEventListener("scrollend", settle);
    },
  };
  window.addEventListener("scrollend", settle);
}

/**
 * 定位锚点：平滑滚动到目标（落点 = 目标顶 − sticky 遮蔽带）+ coral 描边闪烁后渐隐 +
 * 滚动结束后按最新遮蔽带校正一次（见文件头 2026-09-11 二修）。
 * 报告目录 / 执行摘要 top_risks / dataflow 目录与 ?tree= 深链共用。
 * 找不到目标（深链失效 / 数据未含该条目）返回 false，静默不报错。
 * 单一 active-target 语义：触发新定位前清掉所有旧目标描边（连点多目标不残留累积）。
 * @param resolve 查找器（默认按元素 id；dataflow 传 data-tree-id 等属性查询）
 */
export function focusAnchor(id: string, resolve?: (id: string) => Element | null): boolean {
  const el = resolve ? resolve(id) : document.getElementById(id);
  if (!el) return false;
  // 清旧：摘掉所有仍带描边的目标 + 作废旧清理定时器
  for (const prev of Array.from(document.querySelectorAll(".dataflow-flash"))) {
    prev.classList.remove("dataflow-flash");
  }
  if (flashTimer !== undefined) {
    window.clearTimeout(flashTimer);
    flashTimer = undefined;
  }
  const top = Math.max(0, el.getBoundingClientRect().top + window.scrollY - stickyHeaderOffset());
  window.scrollTo({ top, behavior: "smooth" });
  scheduleCorrection(el, top);
  // 重启动画：先摘 class 再强制 reflow 再加回（连续定位同一目标也能重新闪烁）
  el.classList.remove("dataflow-flash");
  void (el as HTMLElement).offsetWidth;
  el.classList.add("dataflow-flash");
  // 动画结束自清理（jsdom 无动画事件，用与动画时长对齐的 timer 兜底）
  flashTimer = window.setTimeout(() => {
    el.classList.remove("dataflow-flash");
    flashTimer = undefined;
  }, FLASH_CLEANUP_MS);
  return true;
}
