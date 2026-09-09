/** 跨仓来源智能默认（2026-09-09）：仓库首次进入配置时的默认复用解析。
 *  口径与图视图复用候选一致（TopologyEditor）：whitebox + completed + repo 精确匹配；
 *  created_at 最大者胜——更新的失败/运行中扫描不抢默认。 */

export interface ReusableScanLike {
  scan_id?: string | null;
  repo?: string | null;
  scan_type?: string | null;
  status?: string | null;
  created_at?: number | null;
}

/** 该仓库最新一次成功白盒扫描的 scan_id；无成功扫描/未扫过 → null（= 现扫）。 */
export function latestReusableScanId(scans: ReusableScanLike[], repo: string): string | null {
  let best: { scan_id: string; created_at: number } | null = null;
  for (const scan of scans) {
    if (scan.scan_type !== "whitebox" || scan.status !== "completed") continue;
    if (scan.repo !== repo || !scan.scan_id) continue;
    if (!best || (scan.created_at ?? 0) >= best.created_at) {
      best = { scan_id: scan.scan_id, created_at: scan.created_at ?? 0 };
    }
  }
  return best?.scan_id ?? null;
}
