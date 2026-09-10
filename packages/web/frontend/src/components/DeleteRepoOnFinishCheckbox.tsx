import { useTranslation } from "react-i18next";
import { Checkbox } from "@/components/ui/checkbox";

/**
 * 扫完即删（2026-09-10）：启动扫描可勾选，默认不勾——勾选后扫描到任意终态
 * （completed/failed/cancelled…）由 web 仓库级 sweep 删除对应仓库。
 *
 * 三处共用：白盒表单（ScanFormFields ② 仓库区）/ MR 表单（ScanNewPage ①b）/
 * 跨仓表单（CorrelationFormFields 底部，语义=删除本次新建扫描的子仓库）。
 * linked 仓（外部关联目录，源不归 ws 管）由调用方置 disabled + 换提示文案。
 */
export function DeleteRepoOnFinishCheckbox({ checked, onChange, disabled, hint }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  /** linked 仓不适用（后端 sweep 对 linked 完全不处理）——禁用 + linkedHint。 */
  disabled?: boolean;
  /** 覆盖默认说明文案（跨仓等语义不同场景；调用方传已翻译文本）。 */
  hint?: string;
}) {
  const { t } = useTranslation();
  return (
    <label data-testid="delete-repo-on-finish"
           className={`flex items-start gap-2.5 ${disabled ? "" : "cursor-pointer"}`}>
      <Checkbox
        checked={checked}
        disabled={disabled}
        onCheckedChange={(v) => onChange(v === true)}
        aria-label={t("scan.deleteRepo.toggle")}
        className="mt-0.5"
      />
      <div className="flex flex-col gap-0.5">
        <span className="text-[13px] font-medium leading-tight">{t("scan.deleteRepo.toggle")}</span>
        <span className="text-[11px] text-muted-foreground leading-relaxed">
          {disabled ? t("scan.deleteRepo.linkedHint") : (hint ?? t("scan.deleteRepo.hint"))}
        </span>
      </div>
    </label>
  );
}
