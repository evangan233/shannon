"""契约锁：长 activity（start_to_close ≥ 600s 或动态窗口）必须带 heartbeat_timeout，
且对应 activity 实现必须挂心跳泵。

背景（2026-09-16 worker 重启事故）：长 activity 无 heartbeat_timeout 时，server
不知道 worker 死了，要等 start_to_close 整段超时才重投（agent 类可达小时级），
期间心跳文件停写 → web 误显「已中断」。heartbeat_timeout 靠 activity 心跳判活
（temporalio 无自动心跳，实现侧须挂 ``@with_activity_heartbeat`` 泵，见
core ``temporal_heartbeat.with_activity_heartbeat``），worker 重启后 ~2min 判死
重投。≤ 600s 的短调用点 start_to_close 本身就是快速重投时钟，不强制。

两条规则（2026-09-16 复盘补严）：
1. 动态窗口（常量名 / 表达式，AST 解析不出秒数）→ **保守按长调用处理**，同样
   要求 heartbeat_timeout。旧版对 None 直接跳过，漏掉 run_code_index（20min）/
   run_gitnexus_chain_verdict（15min，MR 可配）——正是「重启后 15~20min 才被
   发现」的两个 GitNexus 长活动。
2. 配了 heartbeat_timeout 但实现没挂泵同样红：无泵 = server 在窗口内收不到
   任何心跳 → 误判死亡重投（maximum_attempts=1 时直接失败）。
"""
import ast
import pathlib

_PKG_SRC = (pathlib.Path(__file__).resolve().parents[1]
            / "src" / "supernova_multi")
_WORKFLOWS = _PKG_SRC / "pipeline" / "workflows.py"


def _td_seconds(node):
    """timedelta(...) 字面量 → 秒；含动态表达式（常量名/or 表达式）返回 None
    = 动态窗口，由调用方保守按长调用处理。"""
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


def _activity_ref_name(node):
    """execute_activity 的 activity 实参名（Name/Attribute 引用 → 函数名；
    动态表达式 → None，跳过实现侧校验）。"""
    v = node.args[0] if node.args else None
    for kw in node.keywords:
        if kw.arg == "activity":
            v = kw.value
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr
    return None


def _pumped_activity_names():
    """同包 src 里 @activity.defn 且挂了 with_activity_heartbeat 的函数名集合。"""
    names = set()
    for f in _PKG_SRC.rglob("*.py"):
        try:
            tree = ast.parse(f.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decs = node.decorator_list
            has_defn = any(
                isinstance(d, ast.Attribute) and d.attr == "defn"
                and isinstance(d.value, ast.Name) and d.value.id == "activity"
                for d in decs)
            has_pump = any(
                (isinstance(d, ast.Name) and d.id == "with_activity_heartbeat")
                or (isinstance(d, ast.Attribute)
                    and d.attr == "with_activity_heartbeat")
                for d in decs)
            if has_defn and has_pump:
                names.add(node.name)
    return names


def _violations():
    pumped = _pumped_activity_names()
    missing_hbt = []   # 长调用点缺 heartbeat_timeout
    missing_pump = []  # 配了 heartbeat_timeout 但实现没挂泵（误杀风险）
    for node in ast.walk(ast.parse(_WORKFLOWS.read_text())):
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
        if stc is not None and stc < 600:
            continue  # 短调用点：start_to_close 本身就是快速重投时钟
        name = _activity_ref_name(node)
        if hbt is None:
            missing_hbt.append((node.lineno, name or "<dynamic>"))
        elif name is not None and name not in pumped:
            missing_pump.append((node.lineno, name))
    return missing_hbt, missing_pump


def test_long_activities_carry_heartbeat_timeout():
    missing_hbt, missing_pump = _violations()
    assert not missing_hbt, (
        "start_to_close>=600s（或动态窗口）的 execute_activity 缺 "
        f"heartbeat_timeout（行号, activity: {missing_hbt}）"
    )
    assert not missing_pump, (
        "配了 heartbeat_timeout 但实现没挂 @with_activity_heartbeat——"
        "temporalio async activity 无自动心跳，无泵会被 heartbeat_timeout "
        f"误杀重投（行号, activity: {missing_pump}）"
    )
