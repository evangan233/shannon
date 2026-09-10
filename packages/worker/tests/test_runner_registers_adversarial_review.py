"""常驻 worker 注册契约（2026-09-11 NodeGoat 线上事故钉死）：

adversarial review（8d800bb9）只注册进了 CLI 内嵌 worker
（supernova_whitebox.worker），漏了本常驻 runner 的 wb activities 表——
web 提交的扫描跑在 WEB_TASK_QUEUE_WHITEBOX（supernova-wb-web），merge 完成后
调 run_adversarial_review 即 ActivityNotRegistered，重试耗尽 fail-fast
（NodeGoat-20260910-193720 双轨合并后无任何 adversarial 事件/日志）。
whitebox 侧 test_worker_registers_adversarial_review.py 只钉 CLI 那份，
盲区由此而来；本测试钉常驻这份（AST 解析，同款钉死模式）。
"""
import ast
from pathlib import Path

import supernova_worker.runner as runner_mod  # noqa: F401 – import 即验证模块可加载

RUNNER_SRC = Path(runner_mod.__file__).read_text()


def _registered_activity_names() -> set[str]:
    """AST 解析所有 Worker(activities=[...]) 的注册名（wb/bb/corr 三份聚合）。"""
    tree = ast.parse(RUNNER_SRC)
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
        "run_adversarial_review must be listed in runner.py wb activities=[...]"
    )


def test_adversarial_review_imported_and_listed():
    # import 块 + activities 列表两处 => 至少出现 2 次（对齐 CLI 侧钉死断言）。
    assert RUNNER_SRC.count("run_adversarial_review") >= 2, (
        "run_adversarial_review must be imported AND listed in runner.py"
    )
