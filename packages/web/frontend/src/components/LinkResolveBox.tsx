import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { resolveLink } from "@/api/client";
import type { ResolveLinkResult } from "@/api/types";
import { apiErrorMessage } from "@/lib/apiError";

interface Props {
  workspace: string;
  /** 限定接受的链接类别：MR 表单传 ["mr"]——收到仓库链接时行内提示切白盒，
   *  不回调不回填。 */
  accepts?: Array<"mr" | "repo">;
  /** 解析成功（且通过 accepts 过滤）回调——页面统一处理：回填 repo/refs，
   *  repo_state=cloning 时启动页面级下载提示（CloneWatch，不随表单切换卸载）。 */
  onResolved: (r: ResolveLinkResult) => void;
}

/** MR 表单粘贴框（2026-09-03 仓库入口整合 B 段；2026-09-08 收窄为 MR hero 专用——
 *  白盒侧链接框删除，新仓库走「+ 添加仓库」弹窗、已有仓库走下拉搜索）：粘贴
 *  GitLab MR 链接 → 解析回填仓库 + refs，大粘贴框 + 链接前缀图标 + 引导副文案，
 *  分组标题由父级 GroupLabel 承担。
 *
 *  解析失败行内报错（后端 detail 透传），不阻塞手填路径。下载进度不在本组件
 *  （表单切换会卸载实例丢轮询态）——cloning 提示由页面级 CloneWatch 承担。
 */
export function LinkResolveBox({ workspace, accepts, onResolved }: Props) {
  const { t } = useTranslation();
  const [url, setUrl] = useState("");
  const [resolving, setResolving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onResolve(urlOverride?: string) {
    const trimmed = (urlOverride ?? url).trim();
    if (!trimmed || resolving) return;
    setResolving(true);
    setError(null);
    try {
      const r = await resolveLink(workspace, trimmed);
      if (accepts && !accepts.includes(r.kind)) {
        setError(t("scan.link.repoInMrHint"));
        return;
      }
      onResolved(r);
    } catch (e) {
      setError(apiErrorMessage(e, t("scan.link.resolveFailed")));
    } finally {
      setResolving(false);
    }
  }

  /** 粘贴即解析（2026-09-04）：框文案承诺「贴入链接，自动填好」，但旧实现只在
   *  Enter/点「解析」时触发——用户贴完等回填、请求从未发出（web 日志零 resolve-link
   *  实证）。剪贴板是完整 http(s) 链接时立即解析；普通文本走默认粘贴不惊动。 */
  function onPaste(e: React.ClipboardEvent<HTMLInputElement>) {
    const text = e.clipboardData.getData("text").trim();
    if (!/^https?:\/\//i.test(text)) return;
    e.preventDefault();
    setUrl(text);
    void onResolve(text);
  }

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2">
        <div className="relative min-w-0 flex-1">
          <Link2
            className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            data-testid="link-url-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onPaste={onPaste}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); void onResolve(); } }}
            placeholder={t("scan.link.placeholder")}
            className="font-mono min-w-0 pl-8"
          />
        </div>
        <Button
          type="button"
          data-testid="link-resolve-btn"
          variant="outline"
          className="shrink-0"
          disabled={!url.trim() || resolving}
          onClick={() => void onResolve()}
        >
          {resolving ? t("scan.link.resolving") : t("scan.link.resolveBtn")}
        </Button>
      </div>
      {error && <div className="text-destructive text-xs">{error}</div>}
      <div className="text-[11px] text-muted-foreground">{t("scan.mr.importHint")}</div>
    </div>
  );
}
