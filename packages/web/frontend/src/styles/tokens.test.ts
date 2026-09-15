import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const tokens = readFileSync(resolve(__dirname, "tokens.css"), "utf8");
const cfg = readFileSync(resolve(__dirname, "../../tailwind.config.ts"), "utf8");

const SHADCN_TOKENS = [
  "--background", "--foreground", "--card", "--card-foreground",
  "--popover", "--popover-foreground", "--primary", "--primary-foreground",
  "--secondary", "--secondary-foreground", "--muted", "--muted-foreground",
  "--accent", "--accent-foreground", "--destructive", "--destructive-foreground",
  "--border", "--input", "--ring",
];
const SEMANTIC = ["--c-cyan", "--c-magenta", "--c-green", "--c-red", "--c-orange", "--c-yellow", "--c-amber"];

describe("tokens.css 漂移护栏", () => {
  it("含全部 shadcn token", () => {
    for (const t of SHADCN_TOKENS) expect(tokens, `missing ${t}`).toContain(t);
  });
  it("含全部语义色 token（--c- 前缀避开 events.css hex 同名变量）", () => {
    for (const t of SEMANTIC) expect(tokens, `missing ${t}`).toContain(t);
  });
  it("含代码主题 token（层 G：代码块按代码主题渲染，与 web 主题解耦）", () => {
    for (const t of [
      "--code-bg", "--code-fg", "--code-muted", "--code-border",
      "--code-hl-keyword", "--code-hl-string", "--code-hl-number",
      "--code-hl-title", "--code-hl-meta",
    ]) expect(tokens, `missing ${t}`).toContain(t);
    // 深色区亮度差被 gamma 压扁，实色窗框是边界主载体——不得回退 alpha 发丝线
    expect(tokens).toMatch(/--code-border:\s*[\d.]+ [\d.]+% [\d.]+%;/);
  });
  it("含 :root（深）与 .light（浅）两组", () => {
    expect(tokens).toMatch(/:root\s*\{/);
    expect(tokens).toMatch(/\.light\s*\{/);
  });
  it("radius = 12px", () => {
    expect(tokens).toContain("--radius: 12px;");
  });
  it("字体角色位：基准 sans=Space Grotesk 自托管（2026-09-02 全库字体加强）/ 中文回落系统栈 / mono·serif=Plex 自托管", () => {
    expect(tokens).toContain("IBM Plex Mono");
    expect(tokens).toContain("IBM Plex Serif");
    // 2026-08-31 曾换纯系统栈（外链 webfont 断供跳变）；2026-09-02 字体全库加强：
    // 自托管 fontsource（内网零外链）+ 拉丁字体逐主题身份 + 中文回落 system-ui
    // （中文 webfont 单字重 5-8MB 不可打包），断供根因根治且保留混排平衡。
    expect(tokens).toMatch(/--font-sans:\s*"Space Grotesk", system-ui, sans-serif;/);
  });
});

describe("tailwind.config 消费 token", () => {
  it("darkMode = class", () => {
    expect(cfg).toMatch(/darkMode:\s*\["class"\]/);
  });
  it("colors 映射 shadcn token + 语义色（--c- 前缀）", () => {
    expect(cfg).toContain("hsl(var(--primary))");
    expect(cfg).toContain("hsl(var(--c-cyan) / <alpha-value>)");
  });
  it("fontFamily 注入 Plex", () => {
    expect(cfg).toContain("IBM Plex Mono");
  });
  it("plugins 含 typography + animate", () => {
    expect(cfg).toMatch(/@tailwindcss\/typography/);
    expect(cfg).toMatch(/tailwindcss-animate/);
  });
});

describe("amber 语义色（must_change 提醒用，对齐 --c-orange/yellow 暖梯度）", () => {
  it("tokens.css :root（深）定义 --c-amber（HSL channel）", () => {
    expect(tokens).toMatch(/:root[\s\S]*?--c-amber:\s*\d+\s+\d+%\s+\d+%/);
  });
  it("tokens.css .light（浅）定义 --c-amber（HSL channel）", () => {
    const lightBlock = tokens.match(/\.light\s*\{([\s\S]*?)\}/);
    expect(lightBlock, ".light 块应存在").not.toBeNull();
    expect(lightBlock![1]).toMatch(/--c-amber:\s*\d+\s+\d+%\s+\d+%/);
  });
  it("tailwind 映射 amber → hsl(var(--c-amber))，支持 alpha 修饰", () => {
    expect(cfg).toMatch(/amber:\s*"hsl\(var\(--c-amber\) \/ <alpha-value>\)"/);
  });
});

describe("扩展主题（2026-08-25 OpenDesign 六主题移植）", () => {
  // 断言均先提取主题块体（kami 式 [\s\S]*?\n\} 懒惰匹配止于本块闭合），
  // 再对块体断言——防止懒惰跨块匹配拿到后续主题的同名 token 掩盖本块笔误。

  it("sentry 块：紫黑双层表面 + Sentry 紫主色 + 玻璃浮层 token", () => {
    const m = tokens.match(/\.dark\.theme-sentry\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const sentryBlock = m![1];
    expect(sentryBlock).toMatch(/--background:\s*258 40% 10%;/);
    expect(sentryBlock).toMatch(/--primary:\s*247 44% 56%;/);
    expect(sentryBlock).toMatch(/--radius:\s*8px;/);
    expect(sentryBlock).toMatch(/--backdrop-float:\s*blur\(18px\) saturate\(180%\);/);
    // 浮层有玻璃但卡片不做玻璃：不定义 --backdrop-card
    expect(sentryBlock).not.toContain("--backdrop-card");
    // severity hue 锁定
    expect(sentryBlock).toMatch(/--c-red:\s*5\s/);
    expect(sentryBlock).toMatch(/--c-orange:\s*24\s/);
    expect(sentryBlock).toMatch(/--c-yellow:\s*38\s/);
  });

  it("arc 块：深色半透玻璃表面 + coral 主色 + 磨砂三件套 + 环境光层", () => {
    const m = tokens.match(/\.dark\.theme-arc\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const arcBlock = m![1];
    expect(arcBlock).toMatch(/--card:\s*240 10% 12% \/ 0\.6;/);
    expect(arcBlock).toMatch(/--primary:\s*15 60% 56%;/);
    expect(arcBlock).toMatch(/--radius:\s*16px;/);
    expect(arcBlock).toMatch(/--backdrop-card:\s*saturate\(180%\) blur\(24px\);/);
    expect(arcBlock).toMatch(/--backdrop-float:\s*saturate\(180%\) blur\(36px\);/);
    // 环境光层是独立选择器 .dark.theme-arc body，单独提取断言（勿并入块体）
    const mBody = tokens.match(/\.dark\.theme-arc body\s*\{([\s\S]*?)\n\}/);
    expect(mBody).not.toBeNull();
    const arcBody = mBody![1];
    expect(arcBody).toMatch(/background-attachment:\s*fixed;/);
  });

  it("mission 块：深空海军蓝 + 琥珀遥测主色 + 4px 硬朗圆角 + 深投影", () => {
    const m = tokens.match(/\.dark\.theme-mission\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const missionBlock = m![1];
    expect(missionBlock).toMatch(/--background:\s*223 49% 8%;/);
    expect(missionBlock).toMatch(/--primary:\s*43 100% 50%;/);
    expect(missionBlock).toMatch(/--radius:\s*4px;/);
    expect(missionBlock).toMatch(/--c-cyan:\s*190 100% 50%;/);
    expect(missionBlock).toMatch(/--c-red:\s*5\s/);
    expect(missionBlock).toMatch(/--c-orange:\s*24\s/);
    expect(missionBlock).toMatch(/--c-yellow:\s*38\s/);
    // 禁玻璃：mission 不定义 --backdrop-*
    expect(missionBlock).not.toContain("--backdrop-");
  });

  it("github 块：蓝白精准 + 实色细线边框 + Primer 蓝", () => {
    const m = tokens.match(/\.light\.theme-github\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const githubBlock = m![1];
    expect(githubBlock).toMatch(/--border:\s*210 18% 84%;/);
    // 2026-08-25 曾身份色归业务（coral 赤褐）；2026-09-02 回归 Primer 蓝 #0969DA
    // （系统对齐层本色纪律，mac 先例——与 notion 陶土 coral 撞款解）
    expect(githubBlock).toMatch(/--primary:\s*212 92% 44%;/);
    expect(githubBlock).toMatch(/--radius:\s*6px;/);
    expect(githubBlock).toMatch(/--c-red:\s*5\s/);
    expect(githubBlock).toMatch(/--c-yellow:\s*38\s/);
    // 2026-08-26 材质补课：TopBar 灰带（GitHub 全局头 #f6f8fa = subtle 灰，
    // 最强结构信号；TopBar 经 --topbar-bg 消费，其他主题未定义回落 popover）
    expect(githubBlock).toMatch(/--topbar-bg:\s*210 29% 97%;/);
    // 阴影再轻一档（Primer 靠线不靠影：边框类已画线，卡影只留微投影）
    expect(githubBlock).toMatch(/--shadow-card:\s*0 1px 0 hsl\(213 13% 14% \/ 0\.05\), 0 8px 24px hsl\(212 12% 32% \/ 0\.07\);/);
    // 禁玻璃：github 不定义 --backdrop-*
    expect(githubBlock).not.toContain("--backdrop-");
  });

  it("notion 块：暖灰交替面 + 无边软影卡（Notion 标志性多层影）+ coral 主色", () => {
    const m = tokens.match(/\.light\.theme-notion\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const notionBlock = m![1];
    expect(notionBlock).toMatch(/--secondary:\s*30 10% 96%;/);
    expect(notionBlock).toMatch(/--border:\s*0 0% 0% \/ 0\.1;/);
    // 2026-08-25 身份色归业务：Notion 蓝 → coral 陶土 14 58% 46%
    expect(notionBlock).toMatch(/--primary:\s*14 58% 46%;/);
    expect(notionBlock).toMatch(/--radius:\s*6px;/);
    expect(notionBlock).toMatch(/--c-orange:\s*24\s/);
    // 2026-08-26 材质补课：阴影对齐 Notion 真配方（ring + 0.07 中距 + 0.10 远距，
    // 比移植版 whisper 一档强——纯白画布上「层次弱」的主因），卡面去边框（类覆盖）
    expect(notionBlock).toMatch(/--shadow-card:\s*0 0 0 1px hsl\(0 0% 0% \/ 0\.05\), 0 3px 6px hsl\(0 0% 0% \/ 0\.07\), 0 9px 24px hsl\(0 0% 0% \/ 0\.10\);/);
    expect(tokens).toMatch(/\.light\.theme-notion :is\(div, section, article\)\.bg-card\.border\s*\{/);
    // 禁玻璃：notion 不定义 --backdrop-*
    expect(notionBlock).not.toContain("--backdrop-");
  });

  it("kami 块：羊皮纸底 + 朱砂主色 + 衬线字体覆盖（唯一例外）+ 层次拉开", () => {
    const m = tokens.match(/\.light\.theme-kami\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const kamiBlock = m![1];
    // 2026-08-26 材质补课：画布 95→93 拉开与 ivory 卡（97）的明度差，
    // 「纸上的卡」读得出（DESIGN.md 真值 #f5f4ed 在 97 卡旁层次发闷）
    expect(kamiBlock).toMatch(/--background:\s*52 30% 93%;/);
    expect(kamiBlock).toMatch(/--border:\s*50 22% 86%;/);
    // 2026-08-25 身份色归业务：墨蓝 → 铅印朱砂 10 52% 40%
    expect(kamiBlock).toMatch(/--primary:\s*10 52% 40%;/);
    expect(kamiBlock).toMatch(/--radius:\s*6px;/);
    expect(kamiBlock).toMatch(/--font-sans:\s*"Charter", Georgia, Palatino, "Songti SC", "Source Han Serif SC", serif;/);
    expect(kamiBlock).toMatch(/--c-red:\s*5\s/);
    // 禁玻璃：kami 不定义 --backdrop-*
    expect(kamiBlock).not.toContain("--backdrop-");
  });

  it("kami 块：羊皮纸颗粒画布材质（2026-08-26 亮色材质升级）", () => {
    const m = tokens.match(/\.light\.theme-kami\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const kamiBlock = m![1];
    // 粗频噪点（baseFrequency 0.55、3 octaves）——比 warm-paper 细纤维更明显的颗粒
    expect(kamiBlock).toMatch(/--canvas-material:\s*url\("data:image\/svg\+xml,[^"]*baseFrequency='0\.55'[^"]*"\)/);
  });

  it("mac 块：SF Pro 字体栈 + 胶囊 CTA + 玻璃减法（卡片实色、浮层留玻璃）+ coral 主色", () => {
    const m = tokens.match(/\.light\.theme-mac\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const macBlock = m![1];
    // 字体（2026-08-25 质感修订，kami 之外唯一覆盖 --font-sans 的主题）：
    // Apple 设备 -apple-system 解析 SF Pro/苹方；其他平台 Inter（OpenDesign 官方替代）
    expect(macBlock).toMatch(/--font-sans:\s*-apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Inter",/);
    expect(macBlock).toMatch(/--font-mono:\s*ui-monospace, "SF Mono", "IBM Plex Mono",/);
    // 胶囊主操作（macOS Big Sur+ 原生按钮几何；其他主题不定义该 token，组件回落）
    expect(macBlock).toMatch(/--radius-cta:\s*980px;/);
    // 玻璃减法：卡片实色（无 alpha）、不定义 --backdrop-card（card/磁贴回落 none），
    // 浮层玻璃保留（--popover 半透 + --backdrop-float）
    expect(macBlock).toMatch(/--card:\s*0 0% 100%;/);
    expect(macBlock).not.toContain("--backdrop-card");
    expect(macBlock).toMatch(/--popover:\s*0 0% 100% \/ 0\.72;/);
    expect(macBlock).toMatch(/--backdrop-float:/);
    // primary（2026-08-27 果味修订）：coral → apple.com CTA 蓝 #0071E3（系统对齐层
    // 用参考系统本色的分层纪律回归；品牌 coral 仍在 charcoal/warm-paper 基准主题）
    expect(macBlock).toMatch(/--primary:\s*211 100% 45%;/);
    // 2026-08-27 果味修订：中性阶梯蓝饱和回真值——#F2F2F7 精确换算是 240 24% 96%
    // （旧值 240 6% 96% 把蓝味降没了，全屏读作纯灰——「发灰」根因）
    expect(macBlock).toMatch(/--background:\s*240 24% 96%;/);
    // 天光渐变画布材质：极淡冷蓝自上而下渐隐，磨砂玻璃透出 macOS 桌面天光
    // （单方向单色温 ≤6% alpha，与 Arc 三团彩色光斑不同语言）；attachment fixed 钉视口
    expect(macBlock).toMatch(/--canvas-material:\s*linear-gradient\(180deg, hsl\(211[^)]*\) 0%,/);
    expect(macBlock).toMatch(/--canvas-material-attachment:\s*fixed;/);
    // CTA 光晕同步蓝（旧 coral 光晕在蓝按钮上是脏橙边）
    expect(macBlock).toMatch(/--shadow-cta:[^;]*hsl\(211 100% 45% \/ 0\.30\)/);
    // 2026-08-26 材质补课（macOS 系统设置语言）：卡片 whisper 影（无外描边环——
    // 白卡浮灰画布靠色调对比，ring 是 web 通用解法非 Apple 解法）
    expect(macBlock).toMatch(/--shadow-card:\s*0 1px 2px hsl\(240 6% 20% \/ 0\.03\), 0 8px 24px -12px hsl\(240 6% 20% \/ 0\.07\);/);
    // 平面卡：卡片面（div/section/article 上的 bg-card+border）隐去描边；
    // 卡内分隔线/输入框/TopBar hairline 走 --border 原值不受影响
    expect(tokens).toMatch(/\.light\.theme-mac :is\(div, section, article\)\.bg-card\.border\s*\{/);
    // 分段控件导航（2026-08-27 果味修订）：激活项 = 白片浮起在灰槽（macOS segmented
    // control 原生语言；旧灰胶囊是灰上灰），带小落影
    const seg = tokens.match(/\.light\.theme-mac \.topbar-nav-item\[data-active="true"\]\s*\{([\s\S]*?)\n\}/);
    expect(seg).not.toBeNull();
    expect(seg![1]).toMatch(/background:\s*hsl\(0 0% 100%\);/);
    expect(seg![1]).toMatch(/box-shadow:/);
    // 天光走 --canvas-material var 机制（html body 通用消费点 + attachment var），
    // 不写 .light.theme-mac body 规则
    expect(tokens).not.toMatch(/\.light\.theme-mac body\s*\{/);
  });

  it("openai 块：纯白画布 + 深青黑墨色 + OpenAI 青主色（DESIGN.md 真值）+ Söhne/Inter 字体覆盖", () => {
    const m = tokens.match(/\.light\.theme-openai\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const oaiBlock = m![1];
    // 层 A 真值：--bg #ffffff / --fg #0d0d0d / --border #e5e5e5 / 主按钮墨黑（DESIGN.md
    // 「主要按钮 #0d0d0d」真值档——teal 非主 CTA，仅焦点/链接/成功，反「绿太多」失真）
    expect(oaiBlock).toMatch(/--background:\s*0 0% 100%;/);
    expect(oaiBlock).toMatch(/--foreground:\s*0 0% 5%;/);
    expect(oaiBlock).toMatch(/--border:\s*0 0% 90%;/);
    expect(oaiBlock).toMatch(/--primary:\s*0 0% 5%;/);
    // teal 的真岗位：focus ring（--focus-ring 真值）——primary 黑 / ring 青分离
    expect(oaiBlock).toMatch(/--ring:\s*165 82% 35%;/);
    // 次级面：薄雾 #fafafa（secondary/muted）+ 珍珠 #f5f5f5（accent）
    expect(oaiBlock).toMatch(/--secondary:\s*0 0% 98%;/);
    expect(oaiBlock).toMatch(/--accent:\s*0 0% 96%;/);
    // 层 C：12px 软圆角 + Söhne/Inter 栈（真值置首、Inter webfont 兜底）+ Söhne Mono
    expect(oaiBlock).toMatch(/--radius:\s*12px;/);
    expect(oaiBlock).toMatch(/--font-sans:\s*"Söhne", "Inter", system-ui, -apple-system, "Segoe UI", sans-serif;/);
    expect(oaiBlock).toMatch(/--font-mono:\s*"Söhne Mono", ui-monospace, "JetBrains Mono", Menlo, Consolas, monospace;/);
    // 不覆盖衬线（DESIGN.md 约束：Signifier 仅限编辑展示层，产品控件无衬线）；
    // 不定义胶囊 CTA（OpenAI 行动按钮是 12px 矩形圆角，非 mac 全胶囊语言）
    expect(oaiBlock).not.toContain("--font-serif:");
    expect(oaiBlock).not.toContain("--radius-cta:");
    // 层 B：c-green 用深青 #0a7a5e（--accent-hover 真值档，白底 5.3:1 AA；
    // 品牌青 35% 档仅 3.2:1 只配按钮底/链接）。severity hue 锁定 5/24/38
    expect(oaiBlock).toMatch(/--c-green:\s*165 85% 26%;/);
    // red 归队家族亮度阶梯（green 26/yellow 30/orange 38/red 40）：40% 深砖红
    // 白底 6.3:1 AA 稳过；48% 档曾全场最亮、在纯白近单色画布上刺眼（2026-08-28 修）
    expect(oaiBlock).toMatch(/--c-red:\s*5 84% 40%;/);
    expect(oaiBlock).toMatch(/--destructive:\s*5 84% 40%;/);
    expect(oaiBlock).toMatch(/--c-orange:\s*24\s/);
    expect(oaiBlock).toMatch(/--c-yellow:\s*38\s/);
    // GitNexus cyan 与 teal 主色拉开（190° vs 165°）
    expect(oaiBlock).toMatch(/--c-cyan:\s*190 65% 30%;/);
    // 层 E：全库最轻——真值 hover 影 rgba(13,13,13,0.06) 压一档当静态 whisper，
    // 单层无 ring（卡 border 已画线，github「线不叠影」纪律）
    expect(oaiBlock).toMatch(/--shadow-card:\s*0 4px 16px hsl\(0 0% 5% \/ 0\.05\);/);
    // 黑 CTA 无光晕（DESIGN.md 主按钮近无影；teal 光晕在黑按钮上是脏边——同 mac
    // 果味修订「coral 光晕在蓝按钮上是脏橙边」教训）：cta 影为纯中性黑落影
    expect(oaiBlock).toMatch(/--shadow-cta:\s*0 1px 2px hsl\(0 0% 5% \/ 0\.18\);/);
    expect(oaiBlock).not.toMatch(/--shadow-cta:[^;]*hsl\(165/);
    // 禁玻璃 / 无画布材质 / 无 topbar 覆盖（留白即真值；顶栏回落 popover 白+hairline）
    expect(oaiBlock).not.toContain("--backdrop-");
    expect(oaiBlock).not.toContain("--canvas-material");
    expect(oaiBlock).not.toContain("--topbar-bg");
  });
});

describe("亮色材质升级（2026-08-26 纸纹×2 + 蓝图网格，spec 同名）", () => {
  it("通用画布材质消费点：html body 读 --canvas-material（(0,0,2) 压 events.css body shorthand）", () => {
    const m = tokens.match(/html body\s*\{([\s\S]*?)\n\}/);
    expect(m, "html body 规则应存在").not.toBeNull();
    expect(m![1]).toMatch(/background-image:\s*var\(--canvas-material, none\);/);
    expect(m![1]).toMatch(/background-size:\s*var\(--canvas-material-size, auto\);/);
    // 2026-08-27 mac 果味修订：attachment 第三 var（纸纹/网格默认 scroll 随内容，
    // mac 天光 fixed 钉视口顶部）
    expect(m![1]).toMatch(/background-attachment:\s*var\(--canvas-material-attachment, scroll\);/);
  });

  it("warm-paper 块：材质专用块（色 token 仍在 .light 基础块不重复）+ 细纸纹 feTurbulence", () => {
    const m = tokens.match(/\.light\.theme-warm-paper\s*\{([\s\S]*?)\n\}/);
    expect(m, ".light.theme-warm-paper 块应存在").not.toBeNull();
    const wpBlock = m![1];
    // 细纤维：高频 0.9、低透明度 0.04——比 kami 更淡的纸面
    expect(wpBlock).toMatch(/--canvas-material:\s*url\("data:image\/svg\+xml,[^"]*baseFrequency='0\.9'[^"]*"\)/);
    expect(wpBlock).toMatch(/opacity='0\.04'/);
    // 材质专用块：不重复定义颜色 token（.light 基础块仍是唯一色源）
    expect(wpBlock).not.toMatch(/--background:/);
    expect(wpBlock).not.toMatch(/--primary:/);
  });

  it("blueprint 块：冷白绘图纸 + 墨蓝主色 + 4px 圆角 + 实色 hairline + 网格画布", () => {
    const m = tokens.match(/\.light\.theme-blueprint\s*\{([\s\S]*?)\n\}/);
    expect(m).not.toBeNull();
    const bpBlock = m![1];
    expect(bpBlock).toMatch(/--background:\s*214 40% 97%;/);
    // 制图墨蓝（224°，与 GitNexus cyan 192° 拉开 32°）
    expect(bpBlock).toMatch(/--primary:\s*224 58% 34%;/);
    // 实色 crisp hairline（蓝图线是画出来的，非 alpha 透出）
    expect(bpBlock).toMatch(/--border:\s*215 25% 84%;/);
    expect(bpBlock).toMatch(/--radius:\s*4px;/);
    // TopBar 冷灰带（与 github 灰带同机制、冷调）
    expect(bpBlock).toMatch(/--topbar-bg:\s*214 35% 96%;/);
    // severity hue 锁定
    expect(bpBlock).toMatch(/--c-red:\s*5\s/);
    expect(bpBlock).toMatch(/--c-orange:\s*24\s/);
    expect(bpBlock).toMatch(/--c-yellow:\s*38\s/);
    // 网格画布：24px 小格 + 120px 大格双层 linear-gradient（图案材质非噪点）
    expect(bpBlock).toMatch(/--canvas-material:\s*\n?\s*linear-gradient\(hsl\(221[^)]*\) 1px, transparent 1px\),/);
    expect(bpBlock).toMatch(/--canvas-material-size:\s*24px 24px, 24px 24px, 120px 120px, 120px 120px;/);
    // 禁玻璃：blueprint 不定义 --backdrop-*（图纸是实底材质）
    expect(bpBlock).not.toContain("--backdrop-");
  });
});
