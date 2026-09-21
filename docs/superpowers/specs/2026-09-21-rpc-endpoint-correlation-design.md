# RPC 接口关联（证据 → RPC endpoint）— 设计 spec

- 日期：2026-09-21
- 状态：设计完成，待实现（brainstorming 2026-09-21，用户拍板方案 A + 配套动 prompt）

## 0. 背景与调查结论

用户主诉：**后端仓库的扫描，证据经常未能关联到具体接口**——后端仓多为 RPC，证据页接口塌方。

2026-09-21 调查确认：证据 → 接口关联三环全是 **HTTP-only 语义**，RPC 完全缺席：

1. **底册提取**（`code_index/entry_points.py`）：Go 的 gRPC 入口（`context.Context` + 请求指针签名启发式）标 `entry_type="grpc_service"`，但 **`route=None`、`http_method=None`**（`entry_points.py:157`）；只有 HTTP 路由注册式（`r.GET("/x", h)`）才带 route+method（`:186`）。schema 解析只有 OpenAPI（`schema_entry_parser.py`）；`entry_point_fusion.py:2` docstring 声称支持 "Proto" 但实现里没有。
2. **finding 侧**：GN 轨 `http_route_label`（`chain_verdict.py:256`）要求 `route` **和** `http_method` 都有值才产 label（缺 method 返回 None）；LLM 轨 vuln prompt 的 endpoints schema 写死「全部接口（METHOD /path）」（`collectors/vuln.py:430`）。
3. **匹配侧**（`services/api_evidence_matrix.py`）：倒排索引 key = `(HTTP method, path shape)`（`:64`）；entry 收集只收 `route` 非空（`:320`，RPC 入口第一步被扔）；endpoint 提取正则只认 `METHOD /path` 与裸 `/path`。

**实测数据（金融平台-2026h2）**：

- `scans/ins_user_svr-20260920-100133`：`adjudicated_entry_points` 31 条（16 grpc_service + 12 gitnexus_process + 3 cli），**带 route 的 0 条** → 证据矩阵 `no-route-entries`，全部证据落 unmatched（即 spec 2026-09-10 §0 v2 记录的「Go/RPC 底册 route 匹配塌方」遗留项，本 spec 立项修复）。
- 目标仓 **2783 个 `.proto`**，1373 个含 `service` 块；其余约一半为纯 message 的 CMD 命令号风格（如 CMD2008.proto，无 service/rpc 块）。
- 自研 srpc 框架：`service X { option (srpc.service_option_id)=0x5002; rpc Y(...) { option (srpc.method_option_id)=0x1; } }`（命令字）；部分 method option 带 HTTP 注解（`HttpRouteOptions` get/post path）。
- **Go 实现与 proto 完全同名**：`func (S SetupOrder) SetupOrderCreate(ctx context.Context, request *pb.SetupOrderCreateReq)`——receiver 类型=service 名、方法名=rpc 名、签名正是现有 grpc_service 启发式命中的形态（实测定位于 `customer_profile_service/internal/app/client/web_account/setup_order.client.go:34`）。

## 1. 目标 / 非目标

**目标**

1. RPC 服务（标准 gRPC + 自研 srpc）的接口标识进入底册（`adjudicated_entry_points` 的 `route` 字段），证据矩阵、GN 轨 endpoint、LLM 轨 endpoints 三环全部可产出与匹配 RPC 标识。
2. 金融平台类 Go RPC 仓：grpc_service 入口大部分带 route，证据从「全 unmatched / no-route-entries」变为挂载到 `/Service/Method` 接口卡。
3. HTTP 语义零回归（HTTP 仓行为完全不变）。

**非目标**

- **CMD 命令号风格 proto 不覆盖**（1410 个无 service 块的纯 message）：接口标识只能靠代码注册点（命令号 ↔ handler 映射）分析，成本明显更高，用户拍板不做。
- **proto-only 候选不进底册**：proto 里约一半是「调下游」的客户端定义（如 `client/` 目录），直接当本仓入口会产生无 finding 的假接口卡 + 跨仓误报。只有 join 上本仓 Go 实现的 rpc 才算入口（宁缺勿错，对齐 GN 轨确定性 join 哲学）。
- 不动 LLM 轨 vuln-*.txt 主体 prompt（只动 shared schema 的 endpoints 字段 description，见 §4.4）。
- 前端零改动：`/Service/Method` 是普通路径串，卡片/矩阵渲染无额外假设。
- 黑盒侧无专项：匹配侧统一支持后黑盒 verdict join 自然受益；RPC 仓黑盒实测本就多不可达（网络边界），价值有限。

## 2. 关键决策

| # | 决策 | 理由 |
|---|---|---|
| D1 | RPC 标识统一形态 **`/Service/Method`**（如 `/SetupOrder/SetupOrderCreate`），存现有 `route` 字段、`http_method=None` | 以 `/` 开头，现有 `normalize_route`、`_BARE_PATH_RE`（`.` 已在字符类）、`match_entry` 的 `method=None` 跨桶分支**全部天然兼容**——匹配机器无需新维度；唯一命中保护/四态 unmatched reason/黑白盒 join 免费继承 |
| D2 | **同名 join**：方法名全仓唯一命中才填 route | `func_block_id` 只有方法名（`file:func:line`），无 receiver；方法名全局唯一时 join 零歧义。多 service 同名 method（如 `Get`/`List`）不 join——宁缺勿错 |
| D3 | proto 解析只产 `dict[(service, method)]` 查找表，**不产独立 entry** | 见非目标第 2 条；同时省掉 fusion 去重键（proto 无 func_block_id）的设计负担 |
| D4 | LLM 写 gRPC 全路径（带包名 `/pkg.Service/Method`）靠**尾两段回退**互认 | gRPC HTTP/JSON transcoding 惯例是 `/package.Service/Method`；LLM grep proto/pb.go 两种形态都可能写出 |
| D5 | srpc 命令字（`service_option_id`/`method_option_id`）、HTTP 注解（`HttpRouteOptions`）作为 evidence 附带记录，不参与 join 键 | 命令字与 Go 代码无直接文本关联，join 靠名字；option 是增强 evidence 不是路由本体 |

## 3. 设计

### 3.1 底册侧（两个单元）

**单元 1：`code_index/proto_entry_parser.py`（新文件，与 `schema_entry_parser.py` 并列）**

- `parse_proto_services(repo_path: str) -> dict[tuple[str, str], ProtoRouteInfo]`
  - key = `(service_name, method_name)`；value = `{route: "/Service/Method", proto_file: 相对路径, package: str|None, options: dict}`（options 含 srpc 命令字，进 evidence）
- 解析策略：抓 `service (\w+)\s*{...}` 花括号范围（proto service 块内只有 rpc/option，嵌套可控），块内抓 `rpc (\w+)\s*\(`；`package` 行独立提取
- 复用 `path_exclusions` 过滤；注释剔除（`//`、`/* */` → 等长空白，对齐 `_strip_js_comments` 先例）防注释伪 service 块
- 花括号失衡/解析失败 → 该文件跳过，log warning，不抛扫描级异常（对齐证据矩阵降级风格）
- 2783 个文件纯正则扫描，秒级；只扫 `repo_path` 存在时（与 OpenAPI schema 扫描同条件）

**单元 2：同名 join（挂 `code_index/__init__.py::merge_entry_points_from_deliverable` 内，fusion 之后、写回之前）**

- 对 `entry_type="grpc_service"` 且 `route=None` 的 entry：从 `func_block_id` 提方法名查 proto 表
- join 策略（D2）：方法名在 proto 表中**唯一命中**才填；若 FuncBlock 的 `class_name` 非空且等于某 service 名，优先 `(receiver, method)` 双键精确 join（实现时验证 Go 方法的 class_name 是否落 receiver，落空则双键自动退化为单键路径）
- 填法：`route="/Service/Method"`；`evidence` 追加 `; joined from proto: <proto_file>`（含 package/命令字时一并附注）；`confidence` 0.70 → **0.85**（签名启发式 + proto 双重印证，过 `save_adjudication` CONFIRMED 线 0.85，verdict 从 NEEDS_REVIEW 升 CONFIRMED）
- join 上的 entry 数量 log 一行汇总

### 3.2 GN 轨 label（`code_index/chain_verdict.py::http_route_label`）

- 现状：`route` 有值但 `http_method` 为空 → 返回 None（HTTP 时代的保守：缺 method 的 label 匹配不上 PoC derive_method_path 正则）
- 改动：`route` 非空、`http_method` 为空（= RPC entry）→ **返回裸 route**（`/Service/Method`，无 METHOD 前缀）。RPC label 不参与 PoC method 推导，原保守理由不适用
- 下游连锁（零改动）：builder `endpoint=route_label`（`injection_builder.py:96` 同型三 builder）随卡透传 → `_endpoint_rows` 字符串行走 `_BARE_PATH_RE` 解析（`/Service/Method` 已兼容）；`dataflow_view.py:840` 的 label 三元表达式 `route and method ? "METHOD path" : (route or entry_type)` 对 RPC 自动显示裸 route，连带受益
- `endpoint_backfill` 零改动：只认 `METHOD /path` 提名，RPC 卡天然不触发

### 3.3 匹配侧（`services/api_evidence_matrix.py`）

- **entry 收集（:320）零改动**：RPC entry 填 route 后自动过 `ep.get("route")` 过滤；`http_method` 为空 → `index_entries` 落 `("", shape)` 桶
- **尾两段回退（D4）**：`match_entry` / `match_entry_reason` miss 后，若 query route 是 RPC 两段式（段内含 `.`，如 `/pkg.Service/Method`）→ 归一为 `/Service/Method` 重查一次。HTTP path（段不含 `.`）不触发回退
- **unmatched reason 不变**：四态照旧；RPC 仓 `no-route-entries` 自然消失，残余 unmatched（LLM 未产出 RPC 标识的）继续落 v2 富卡兜底
- **`SCHEMA_VERSION = 2` 不 bump**：矩阵产物结构未变；旧扫描底册 route 仍全 null，重算矩阵无差异（见 §5 兼容性）

### 3.4 LLM 轨 prompt（`collectors/vuln.py` endpoints schema description）

在「该漏洞涉及的全部接口（METHOD /path）」后补方法论指引（大意）：

> 对 RPC/gRPC 服务（无 HTTP 路由），产出 RPC 接口标识 `/Service/Method`（可带 proto 包名，如 `/pkg.Service/Method`）——自行 grep `.proto` 的 service/rpc 定义或 Go 方法实现（receiver 类型=service 名、方法名=rpc 名）得出。

- **不违反双轨铁律**：这是方法论指引，源由 agent 自己 grep 派生，不注入任何确定性产物；`tests/prompts/test_static_dataflow_hints_decoupling.py` 锁定项（prompt 不得 `@include` 确定性产物）不涉及
- `vuln-*.txt` 主体不动；affected_parameters 等其他 schema 字段不动

## 4. 边界与降级

| 情况 | 行为 |
|---|---|
| 仓里没有 `.proto` / 无 service 块（CMD 纯 message） | proto 表为空，join 不发生——现状不变，unmatched 富卡兜底 |
| 多 service 同名 method | 唯一命中策略：不 join、不填 route |
| 同名 rpc 但实现函数不是 grpc_service 签名 | 不 join（底册没这个入口，proto 表无从挂靠） |
| LLM 写带包名/不带包名 | 尾两段回退互认 |
| RPC entry 与 HTTP entry 同 shape 撞桶 | method 维度天然隔离（`""` vs `"GET"`），唯一命中保护在 |
| proto 花括号失衡/注释伪块 | 解析失败该文件跳过 + warning，不抛扫描级异常 |
| join 后 confidence 0.85 边界 | `save_adjudication` 阈值 `>= 0.85` 为 CONFIRMED，实测取 0.85 恰过线；实现时以断言锁定 verdict=CONFIRMED |

## 5. 兼容性

- **HTTP 仓零回归**：join 只对 `entry_type="grpc_service" && route=None` 生效；尾两段回退只对段含 `.` 的 query route 生效；`http_route_label` 分支只在 `http_method` 为空时变化（HTTP entry 恒有 method）
- **旧扫描不自动回填底册**：`entry_points.json` 是扫描时产物，存量扫描 route 仍全 null、证据页照旧 unmatched（富卡兜底）；生产生效需新扫描。离线验收可对旧扫描目录重跑 `merge_entry_points_from_deliverable` + `save_adjudication` + `build_api_evidence_matrix` 三步对比
- **矩阵缓存**：`SCHEMA_VERSION` 不 bump（产物结构未变）；旧扫描聚合缓存重算无差异
- **correlation / dual_track / authz 轨不受影响**：`adjudicated_entry_points` 消费方仅 `api_evidence_matrix.py`（grep 实证）；`dataflow_view.py:840` 自动兼容且连带受益

## 6. 测试与验收

**单测（TDD，每环先红后绿）**

1. `proto_entry_parser`：标准 service/rpc 提取；srpc option 附带提取（命令字进 evidence）；注释伪 service 块不误配；花括号失衡跳过；CMD 纯 message 文件产空表；path_exclusions 生效
2. 同名 join：唯一命中填 route + evidence + confidence 0.85；歧义 method 不 join；class_name 双键优先（或确认退化路径）；非 grpc_service entry 不动
3. `http_route_label`：RPC entry（route 有 method 无）→ 裸 route；HTTP entry 行为不变；join miss → None 不变
4. `match_entry`/`match_entry_reason`：尾两段回退（带包名 ↔ 短形态互认）；HTTP path 不触发回退（回归）；RPC 桶与 HTTP 桶隔离；唯一命中/歧义语义不变
5. prompt：endpoints description 含 RPC 指引（collectors/vuln.py schema 快照断言）

**真实数据验收（金融平台-2026h2 离线重跑）**

- 对 `scans/ins_user_svr-20260920-100133` 重跑三步（§5 兼容性），对比 before/after：
  - `adjudicated_entry_points` 带 route 数：0 → 期望 16 个 grpc_service 大部分带上（proto 表覆盖度决定）
  - `api_evidence_matrix.json`：entries>0、`/Service/Method` 接口卡出现且有 finding 挂载、unmatched 占比显著下降
- 抽查 join 正确性：随机 N 条 join 结果人肉核对 proto 定义 ↔ Go 实现同名对应（防单键 join 误挂）
