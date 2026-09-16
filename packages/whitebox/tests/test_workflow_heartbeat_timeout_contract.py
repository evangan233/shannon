"""契约锁：长 activity（start_to_close ≥ 600s）必须带 heartbeat_timeout。

背景（2026-09-16 worker 重启事故）：长 activity 无 heartbeat_timeout 时，server
不知道 worker 死了，要等 start_to_close 整段超时才重投（agent 类可达小时级），
期间心跳文件停写 → web 误显「已中断」。heartbeat_timeout 靠 activity 心跳判活
（temporalio 无自动心跳，实现侧须挂 ``@with_activity_heartbeat`` 泵，见
core ``temporal_heartbeat.with_activity_heartbeat``），worker 重启后 ~2min 判死
重投。≤ 600s 的短调用点 start_to_close 本身就是快速重投时钟，不强制。

新增长 activity 调用点漏配 heartbeat_timeout 会被本测试拦下。
"""
import ast
import pathlib

_WORKFLOWS = (pathlib.Path(__file__).resolve().parents[1]
              / "src" / "supernova_whitebox" / "pipeline" / "workflows.py")


def _td_seconds(node):
    """timedelta(...) 字面量 → 秒；含动态表达式（常量名/or 表达式）返回 None
    = 按长调用点保守处理（本仓动态项均为分钟级以上常量）。"""
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "timedelta":
        secs = 0.0
        for kw in node.keywords:
            mult = {"seconds": 1, "minutes": 60, "hours": 3600}.get(kw.arg)
            if not mult:
                return None
            try:
                secs += mult * ast.literal_eval(kw.value)
            except ValueError:
                return None
        return secs
    return None


def _long_calls_without_heartbeat():
    tree = ast.parse(_WORKFLOWS.read_text())
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute)
                and func.attr in ("execute_activity", "execute_local_activity")):
            continue
        stc = hbt = None
        for kw in node.keywords:
            if kw.arg == "start_to_close_timeout":
                stc = _td_seconds(kw.value)
            if kw.arg == "heartbeat_timeout":
                hbt = kw
        if stc is None or stc < 600:
            continue
        if hbt is None:
            bad.append(node.lineno)
    return bad


def test_long_activities_carry_heartbeat_timeout():
    bad = _long_calls_without_heartbeat()
    assert not bad, (
        "start_to_close>=600s 的 execute_activity 缺 heartbeat_timeout"
        f"（行号 {bad}）；同时确认对应 activity 实现已挂 "
        "@with_activity_heartbeat（否则 heartbeat_timeout 会误杀无心跳 activity）"
    )
