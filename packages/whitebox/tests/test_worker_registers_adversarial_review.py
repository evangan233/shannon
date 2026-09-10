"""worker 注册契约（对齐 test_worker_registers_authz_judge 钉死模式）：
漏注册 = workflow 侧 ActivityNotRegistered fail-fast 或静默降级。

注：brief 底稿写的是 `worker.ACTIVITIES`，但 worker.py 的注册列表是
Worker(activities=[...]) 内联传参、并无模块级 ACTIVITIES（改成模块级常量会让
activities 关键字不再是字面 List，直接打断
test_worker_registers_authz_judge.py::test_all_worker_registered_activities_are_defn
的 AST 解析）。故此处按同一钉死模式用 AST 解析注册名 + import 块出现次数，
契约等价：import 区与 activities=[...] 列表两处都必须有 run_adversarial_review。
"""
import ast
from pathlib import Path

import supernova_whitebox.worker as worker_mod  # noqa: F401 – import 即验证模块可加载

WORKER_SRC = Path(worker_mod.__file__).read_text()


def _registered_activity_names() -> set[str]:
    """AST 解析 Worker(activities=[...]) 的注册名（同
    test_all_worker_registered_activities_are_defn 的解析方式）。"""
    tree = ast.parse(WORKER_SRC)
    names: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "activities"
            and isinstance(node.value, ast.List)
        ):
            names |= {elt.id for elt in node.value.elts if isinstance(elt, ast.Name)}
    return names


def test_adversarial_review_registered():
    assert "run_adversarial_review" in _registered_activity_names(), (
        "run_adversarial_review must be listed in worker.py activities=[...]"
    )


def test_adversarial_review_imported_and_listed():
    # import 块 + activities 列表两处 => 至少出现 2 次（对齐 authz judge 钉死断言）。
    assert WORKER_SRC.count("run_adversarial_review") >= 2, (
        "run_adversarial_review must be imported AND listed in worker.py activities"
    )
