// 时间/时长/地址 紧凑格式化（Dashboard / WorkspaceDetail / ScanList 共用口径）。
// 此前 fmtTime / fmtDur / fmtElapsed / compactUrl 在三处各持一份拷贝，口径易漂移，抽到 utils。

/** 紧凑时间 MM-DD HH:mm（列表「时间」列 / 指标「最近完成」用）。 */
export function fmtTime(unix?: number | null): string {
  if (!unix) return "-";
  const d = new Date(unix * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** ISO 8601 串 → 同口径紧凑 MM-DD HH:mm（HOST 档案「更新时间」列：后端 isoformat() 串 32 字符，
 *  直渲染会溢出固定列宽挤到相邻操作按钮；空/无效串兜底 "-"，完整串由调用方放 title）。 */
export function fmtIsoTime(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "-";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** 时长紧凑格式：45s / 12m / 3h 20m（total_duration_ms → 文本）。 */
export function fmtDur(ms?: number | null): string {
  if (!ms || ms < 0) return "";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h}h ${rem}m` : `${h}h`;
}

/** 运行时长紧凑格式（created_at unix 秒 → 现在）：45s / 12m / 3h 20m。 */
export function fmtElapsed(unix: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem ? `${h}h ${rem}m` : `${h}h`;
}

/** git 地址紧凑化：去协议头 / git@ 前缀 / .git 尾（表格仓库列两行格共用口径）。 */
export function compactUrl(u: string): string {
  return u.replace(/^https?:\/\//, "").replace(/^git@/, "").replace(/\.git$/, "");
}
