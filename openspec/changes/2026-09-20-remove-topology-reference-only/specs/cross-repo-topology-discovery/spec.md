## MODIFIED Requirements

### Requirement: Multi-entry and many-to-many topologies are first-class
拓扑分析、编辑器和确认校验 SHALL 支持 generally useful directed service graphs，包括多个入口、一个入口调用多个后端、多个入口共享一个或多个后端、多跳、backend 互调和环。系统 MUST 以有序边身份保留 from/to/protocol，MUST NOT 将共享后端的多个 caller 合并、丢弃非第一个入口或把图限制为星型。

#### Scenario: Two entrypoints call different backends
- **WHEN** 候选图为 `web -> order-svc` 且 `admin -> user-svc`
- **THEN** `web` 与 `admin` 均可标记 entrypoint
- **AND** 两条边都被保留并可在确认后提交

#### Scenario: One entrypoint fans out to multiple services
- **WHEN** 候选图包含 `web -> order-svc`、`web -> user-svc` 和 `web -> payment-svc`
- **THEN** 编辑器和确认结果保留全部出边
- **AND** 每条边可单独查看证据、修改协议、禁用或删除

#### Scenario: Multiple entrypoints share multiple backends
- **WHEN** 候选图包含 `web -> order-svc`、`web -> user-svc`、`admin -> order-svc` 和 `admin -> payment-svc`
- **THEN** 系统保留四条 M:N 有向边
- **AND** `order-svc` 的可达性记录同时包含 `web` 和 `admin` 来源

#### Scenario: Mixed multi-hop and shared backend topology
- **WHEN** 候选图包含 `web -> order-svc`、`admin -> order-svc` 和 `order-svc -> user-svc`
- **THEN** `order-svc` 同时作为入边目标与出边来源渲染
- **AND** 确认后的 relations 保留三边且多跳可达性不被合并

#### Scenario: Isolated repository warning
- **WHEN** 选定仓库中存在没有任何启用边的节点
- **THEN** 确认界面显示孤立节点警告
- **AND** 该警告不阻塞确认，用户可直接确认并保留该仓库参与本次扫描
