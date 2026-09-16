"""单次扫描预算 scan_budget —— 从「获槽」起算的整个扫描 wall-clock 上限。

2026-09-16 语义重构（原 workflow_run_timeout：从提交起算 3h、排队计入）：闸门
排队发生在 workflow 内部轮询（scan_gate.acquire_gate_slot），旧口径下排队时间
全额吃掉预算——金融平台批量事故 37 个扫描排队 3h 未获槽被整点收割（一个 phase
都没跑）。新口径：

- **排队不限时**（对齐 scan-gate spec 原意「不做排队超时」）：排队阶段由
  acquire_gate_slot 周期性 continue-as-new 重开 run，事件历史清零防 temporal
  ~50k 上限，workflow_id 不变、闸门 FIFO 位置保持；获槽后也重开一次 run，
  预算精确从获槽起算（新 run 首次 try_acquire 走 held 幂等路径）。
- **预算只约束扫描本身**：token 防失控的最外层兜底目的不变——排队零 LLM 消耗，
  扫描段才烧 token，收口在获槽后即完整保留该目的。默认 5h 覆盖实测单扫中位
  109min（26-179min）的 ~2.7× 余量，只拦真失控。
- 触发即整个 workflow fail（temporal 服务端 TIMED_OUT，不可恢复）；web _watch
  既有 describe 轮询路径标 failed，无新消费点。
- 关联扫描（corr）activity 预算 4h，提交端必须 `max(budget, 4h30m)` 保下限
  （scan_manager._submit_correlation final-fix ④）。
- AuthValidationWorkflow（认证管理页"测试登录"，非扫描）不套此预算。
"""
import logging
import os
from datetime import timedelta

_DEFAULT_HOURS = 5
_log = logging.getLogger(__name__)


def scan_budget() -> timedelta:
    """单次扫描预算（获槽起算），默认 5h，env SUPERNOVA_SCAN_BUDGET_HOURS 可配。

    返回 env 值(int>=1)对应时长；未设 / 畸形 / <1 回退默认(5h)并 warning。
    畸形值绝不 crash 提交路径（对齐 concurrency.get_max_concurrent 容错契约）。
    """
    raw = os.environ.get("SUPERNOVA_SCAN_BUDGET_HOURS")
    if raw is None:
        return timedelta(hours=_DEFAULT_HOURS)
    try:
        val = int(raw)
    except ValueError:
        _log.warning("SUPERNOVA_SCAN_BUDGET_HOURS=%r not an int; falling back to %dh",
                     raw, _DEFAULT_HOURS)
        return timedelta(hours=_DEFAULT_HOURS)
    if val < 1:
        _log.warning("SUPERNOVA_SCAN_BUDGET_HOURS=%d must be >=1; falling back to %dh",
                     val, _DEFAULT_HOURS)
        return timedelta(hours=_DEFAULT_HOURS)
    return timedelta(hours=val)
