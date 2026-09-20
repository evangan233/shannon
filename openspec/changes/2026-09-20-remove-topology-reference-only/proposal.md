## Why

跨仓拓扑编辑器的「参考仓库」勾选框名不副实且功能冗余。它的唯一功能是豁免孤立节点（无任何启用边的仓库）的 `isolated_node` 确认阻塞，但：

1. **不改变扫描行为**——勾选后仓库照样全量白盒扫描、照样进跨仓报告，"只作参考"的语义并不存在（标志不进 YAML / 后端无对应字段，角色缺省还回落 `backend`）；
2. **入口隐蔽、易误解**——要先点开节点属性面板才能找到，被阻塞的用户大概率不知道去哪勾；
3. **防错价值已被覆盖**——校验问题（含孤立节点）本就实时显示在编辑器底部（红色 alert 文本），「漏连边」的手滑保护不依赖阻塞确认。

而它支撑的真实用例——把一个拓扑上不与其他仓库通信的仓库搭车进本次跨仓扫描、并入同一份报告——应当保留。做法是把 `isolated_node` 从阻塞校验降级为非阻塞警告，勾选框随之删除。

## What Changes

- **web frontend**：删除拓扑节点属性面板的「参考仓库」勾选框及 `setTopologyReferenceOnly` / `TopologyNodeDraft.referenceOnly` 字段 / fingerprint 参与；`confirmTopologyDraft` 不再把 `isolated_node` 计入阻塞校验（警告保留在编辑器底部实时展示，amber 警告色区分于错误红）；`issues.isolated_node` 文案改为非阻塞语义。
- **spec**：`cross-repo-topology-discovery` 的「Isolated repository warning」场景从"必须移除或标记参考仓库后才能确认"改为"警告展示、可直接确认保留参与扫描"。
- **不变**：其余确认校验（entrypoint / 至少一条启用边 / 来源 / 协议 / self-loop / 悬空关系等）全部保持阻塞；确认后的 `MultiRepoConfig` 转换、扫描编排、报告链路零改动。

## Capabilities

### Modified Capabilities

- `cross-repo-topology-discovery`: 孤立仓库从"阻塞确认、需显式豁免"改为"非阻塞警告、可直接确认"；删除参考仓库标记能力。

## Impact

- **web frontend**：`TopologyEditor.tsx`（属性面板 + 底部校验展示）、`correlation-topology-draft.ts`（类型 / setter / 校验 / fingerprint / 确认门禁）、`correlation-topology-draft.test.ts`、`locales/{zh,en}.json`。
- **无后端改动**：`referenceOnly` 从未离开前端草稿态，YAML / `MultiRepoConfig` / 编排不受影响。
