import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground shadow hover:bg-primary/90",
        destructive:
          "bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90",
        outline:
          "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
        secondary:
          "bg-secondary text-secondary-foreground shadow-sm hover:bg-secondary/80",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
        // cta · 主命令按钮：coral 实心 + sans 字体 + 柔和材质阴影 + hover 微浮。
        // 不再用 ❯ 提示符 / mono / neon 光晕（过重且与文案 + 号重复）。
        // 靠质感（阴影 + hover 浮起）区分主次，尺寸同 default(h-9)，不加大。
        // 2026-08-25 mac 质感修订：经 --radius-cta 消费胶囊几何（mac 980px）；
        // 未定义该 token 的主题回落 calc(var(--radius) - 2px) = rounded-md 等值，
        // 与 --backdrop-* 同一套「未定义即回落」idiom（tailwind 3.4 同 utility
        // 任意值输出在具名值之后，覆盖基类 rounded-md 生效）。
        cta:
          "bg-primary text-primary-foreground font-medium shadow-[var(--shadow-cta)] hover:shadow-[var(--shadow-cta-hover)] hover:-translate-y-px active:translate-y-0 transition-all [border-radius:var(--radius-cta,calc(var(--radius)_-_2px))]",
        // ai · AI 辅助动作按钮（扫描页三按钮家族 2026-09-09）：主命令（提交扫描）恒走
        // cta 实色胶囊，AI 辅助（自动关联分析等，产物是须确认的草稿）走 primary 轻染
        // 描边 + 同款 hover 微浮——层级编码在容器，动作语义在图标。不实色：与 cta 同为
        // bg-primary 会两个实色按钮争层级，用户可能把「分析」当「扫描」点。
        // 图标色放调用处染（primary / 取消态 destructive），不在 variant 里 [&_svg] 锁死：
        // 父级 arbitrary-variant 选择器 specificity 高于图标自身类，锁死会染不进语义色。
        ai:
          "border border-primary/35 bg-primary/5 text-foreground shadow-sm hover:-translate-y-px hover:border-primary/50 hover:bg-primary/10 active:translate-y-0",
        // toolbar · 工作区页操作条按钮（切换工作区/成员/仓库/认证/HOST/置顶）：card 表面
        // 浮于页面 + hover 上浮 -2px + 暖色柔阴影 + 图标染 coral（与 cta 同一浮动语言）。
        // 图标默认 muted，hover 跟随按钮整体上浮后点亮，给出可点击反馈。
        toolbar:
          "border border-input bg-card text-foreground shadow-[var(--shadow-toolbar)] hover:-translate-y-0.5 hover:border-primary/45 hover:shadow-[var(--shadow-toolbar-hover)] active:translate-y-0 [&_svg]:text-muted-foreground [&_svg]:transition-colors hover:[&_svg]:text-primary",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 rounded-md px-3 text-xs",
        lg: "h-10 rounded-md px-8",
        icon: "h-9 w-9",
        "icon-sm": "h-7 w-7",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps
  extends React.ComponentProps<"button">,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

function Button({ className, variant, size, asChild = false, ...props }: ButtonProps) {
  const Comp = asChild ? Slot : "button"
  return (
    <Comp
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
