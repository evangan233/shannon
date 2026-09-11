import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useEventSource } from "@/api/useEventSource";
import { repoEventsUrl } from "@/api/client";

type CloneEvt = { progress?: number; type?: string; status?: string; error?: string };

/** SSE 瞬断宽限（2026-09-11 闪「中断」修复）：大仓 clone 期间事件间隔长，后端
 *  EventTailer 空闲时零字节无心跳，空闲连接易被中间层掐断——EventSource ~3s
 *  自动重连恢复。宽限 > 重连周期，瞬断不升级为用户可见的"连接断开"警示；
 *  持续断连超宽限才值得打扰（真断连）；恢复立即回退（恢复沿不去抖）。 */
const SSE_ERROR_GRACE_MS = 5000;

/** value 持续为 true 超过 ms 才返回 true（升级沿去抖）；恢复 false 立即返回 false。 */
function useSustained(value: boolean, ms: number): boolean {
  const [sustained, setSustained] = useState(false);
  useEffect(() => {
    if (!value) {
      setSustained(false);
      return;
    }
    const id = setTimeout(() => setSustained(true), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return sustained;
}

/** P2: clone 事件 SSE 走 ws 内路径 /api/workspaces/<ws>/repos/<name>/events。
 *  busyLabelKey：进行中文案的 i18n key 覆盖（上传解压的 extracting 复用此组件，
 *  事件管道同一条 clone.ndjson → SSE，仅文案不同；默认 "clone 中"）。 */
export function CloneProgress({ ws, name, busyLabelKey }: { ws: string; name: string; busyLabelKey?: string }) {
  const { t } = useTranslation();
  const { events, status } = useEventSource(repoEventsUrl(ws, name), "clone_end");
  const last = events[events.length - 1] as CloneEvt | undefined;
  const endEvent = [...events].reverse().find((e) => (e as CloneEvt).type === "clone_end") as CloneEvt | undefined;
  const failed = endEvent?.status === "failed";
  const progress = last?.progress ?? null;
  const sustainedError = useSustained(status === "error", SSE_ERROR_GRACE_MS);

  if (failed) {
    return <div className="text-xs text-destructive">{t("repos.clone.failed", { error: endEvent?.error ?? t("repos.clone.unknownError") })}</div>;
  }
  if (endEvent && !failed) {
    return <div className="text-xs text-green">{t("repos.clone.ready")}</div>;
  }
  if (sustainedError) {
    return <div className="text-xs text-yellow">{t("repos.clone.reconnecting")}</div>;
  }
  return (
    <div className="text-xs text-muted-foreground">
      {progress !== null
        ? t("repos.clone.cloningProgress", { progress })
        : t(busyLabelKey ?? "repos.clone.cloning")}
    </div>
  );
}
