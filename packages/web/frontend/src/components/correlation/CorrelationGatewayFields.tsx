import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronRight } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { GroupLabel } from "@/components/GroupLabel";
// 认证/HOST 块复用既有抽取组件（auth-profile-vault Task 14 / HOST Task 13），与白盒组合
// 扫描同款——correlation 三视图 tabs 外共用（2026-09-04 tabs 重组前散在两个模式容器里各一份）。
import { AuthFields, HostFields } from "@/components/ScanFormFields";
import type { AuthFormState, HostFormState } from "@/pages/ScanNewPage";

interface Props {
  workspace: string;
  /** 黑盒验证网关地址（复用页面 FormState.url 承载，避免新 state）。 */
  gatewayUrl: string;
  onGatewayUrl: (v: string) => void;
  gatewayErr?: string | null;
  auth: AuthFormState;
  setAuth: (patch: Partial<AuthFormState>) => void;
  authErr?: string | null;
  host: HostFormState;
  setHost: (patch: Partial<HostFormState>) => void;
  hostErr?: string | null;
}

/** 跨仓关联黑盒验证（可选，2026-09-04 工作台化改可折叠）：gateway URL + 认证/HOST——
 *  tabs 外共用，切视图不丢配置。可选项默认收起（主路径是拓扑→提交，黑盒验证是
 *  段③增强，恒展开会拖长页面）；已有任一配置（重跑预填/先前填写）则默认展开，
 *  配置可见性不因折叠丢失。展开态由用户掌控，不随字段清空自动收起。 */
export function CorrelationGatewayFields({
  workspace, gatewayUrl, onGatewayUrl, gatewayErr, auth, setAuth, authErr, host, setHost, hostErr,
}: Props) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(
    () => !!gatewayUrl.trim() || auth.enabled || host.enabled,
  );
  return (
    <section className="space-y-2.5 border-t border-border pt-4">
      <button
        type="button"
        data-testid="corr-gateway-toggle"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 text-left"
      >
        <GroupLabel hint={t("scan.correlation.gatewayOptional")} className="flex-1">
          {t("scan.correlation.gatewayTitle")}
        </GroupLabel>
        <ChevronRight
          className={`size-3.5 text-muted-foreground transition-transform ${open ? "rotate-90" : ""}`}
          aria-hidden
        />
      </button>
      {open && (
        <div className="space-y-2.5">
          <div className="space-y-1.5">
            <Label className="text-xs font-medium">{t("scan.correlation.gatewayLabel")}</Label>
            <Input
              value={gatewayUrl}
              onChange={(e) => onGatewayUrl(e.target.value)}
              placeholder={t("scan.correlation.gatewayPlaceholder")}
              size="sm"
              className="font-mono"
            />
            {gatewayErr && <div className="text-destructive text-xs">{gatewayErr}</div>}
            <div className="text-[11px] text-muted-foreground">{t("scan.correlation.gatewayHint")}</div>
          </div>
          <AuthFields value={auth} onChange={setAuth} workspace={workspace} authErr={authErr ?? null} refreshSignal={0} />
          <HostFields value={host} onChange={setHost} workspace={workspace} error={hostErr} />
        </div>
      )}
    </section>
  );
}
