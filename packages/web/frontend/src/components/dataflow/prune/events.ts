// 图↔行联动事件 context（D6）：value 只装稳定回调（TreeCard useCallback 产物），
// 不承载高亮态——hover 态经 layout 纯函数注入 node/edge data，context 零订阅者
// 随 hover 重渲染。
import { createContext, useContext } from "react";

export interface BranchEvents {
  /** hover 枝条（null=离开）——图→行与行→图双向共用。 */
  onHover: (branchId: string | null) => void;
  /** 点枝条选中/再点取消（明细行展开首节点 code）。 */
  onSelect: (branchId: string) => void;
  /** 折叠行点击展开/收起。 */
  onFoldToggle: () => void;
}

export const BranchEventsContext = createContext<BranchEvents | null>(null);

/** 节点/边组件内取事件回调；无 provider（单测直渲染）时为 no-op。 */
export function useBranchEvents(): BranchEvents {
  return (
    useContext(BranchEventsContext) ?? {
      onHover: () => {},
      onSelect: () => {},
      onFoldToggle: () => {},
    }
  );
}
