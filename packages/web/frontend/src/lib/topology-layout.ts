/**
 * 服务拓扑分层布局（2026-09-21 自 TopologyGraph.tsx 迁出为 lib 单源）：调用层级
 * 分层——入口第 0 层，layer(to) ≥ layer(from)+1 长路径松弛；层间左→右、层内垂直
 * 均分。消费方：结果页只读画布（crossServiceTopologyToDraft 换算进编辑器世界
 * 坐标）；原 TopologyGraph 组件已由只读 TopologyEditor 取代。
 */

/** 布局节点（中心点坐标，viewBox 坐标系）。 */
export interface NodePos {
  name: string;
  x: number;
  y: number;
  role: string;
}

/**
 * 布局纯函数（同输入同输出，无 React 依赖）：入口初始化为 0，沿边反复抬高被调方
 * （最多 |services| 轮，环收敛）；无前驱的非入口（含孤立）服务落第 0 层，与入口
 * 并列。层间从左到右均分画布宽，层内垂直均分；单层居中。高度 =
 * max(各层节点数, 1) × heightPerNode + 40（空服务不塌缩，留呼吸边距）。
 */
export function layout(
  services: { name: string; role: string }[],
  edges: { from: string; to: string }[] = [],
  width = 560,
  heightPerNode = 90,
): { nodes: NodePos[]; height: number } {
  // 分层：入口初始化为 0，沿边反复抬高被调方（最多 |services| 轮，环收敛）
  const layer = new Map<string, number>();
  services.forEach((s) => { if (s.role === "entrypoint") layer.set(s.name, 0); });
  const known = new Set(services.map((s) => s.name));
  for (let round = 0; round < services.length; round++) {
    let changed = false;
    for (const e of edges) {
      if (!known.has(e.from) || !known.has(e.to)) continue;
      const lf = layer.get(e.from);
      if (lf === undefined) continue;
      if ((layer.get(e.to) ?? -1) < lf + 1) { layer.set(e.to, lf + 1); changed = true; }
    }
    if (!changed) break;
  }
  // 无前驱的非入口（含孤立）服务落第 0 层，与入口并列
  services.forEach((s) => { if (!layer.has(s.name)) layer.set(s.name, 0); });

  const maxLayer = Math.max(0, ...layer.values());
  const columns: { name: string; role: string }[][] = Array.from({ length: maxLayer + 1 }, () => []);
  services.forEach((s) => columns[layer.get(s.name)!].push(s));
  const height = Math.max(...columns.map((c) => c.length), 1) * heightPerNode + 40;

  const nodes: NodePos[] = [];
  const span = width - 40; // 左右各 20 边距
  columns.forEach((column, li) => {
    const x = maxLayer === 0 ? width / 2 : 20 + (span / (maxLayer + 1)) * (li + 0.5);
    column.forEach((s, i) => nodes.push({ name: s.name, role: s.role, x, y: 40 + i * heightPerNode + 20 }));
  });
  return { nodes, height };
}

/** 边 status → 语义色 token class（repo 既有语义色：green/amber/red/muted-foreground）。 */
export function statusClass(status: string): string {
  switch (status) {
    case "ok":
      return "text-green";
    case "low":
      return "text-amber";
    case "error":
      return "text-red";
    default:
      // unverified / declared-missing / 未知值：低调灰
      return "text-muted-foreground";
  }
}
