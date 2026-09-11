import logging
from pathlib import Path

import pytest

from supernova_core.logging.temporalio_redirect import install_temporalio_log_redirect


_LOGGER_NAME = "temporalio.activity"
# install_temporalio_log_redirect 管理的 logger 集合(temporalio.activity 现有 +
# temporalio.worker 子树新增,后者覆盖 _activity :315/:521 执行边界 DEBUG)。
_MANAGED_LOGGERS = ("temporalio.activity", "temporalio.worker")


@pytest.fixture(autouse=True)
def _restore_temporalio_loggers():
    """Snapshot and restore every managed temporalio logger's state.

    ``logging.getLogger(name)`` returns the same global logger object across
    tests, so handlers attached by ``install_temporalio_log_redirect`` and the
    ``propagate=False`` toggle would leak into subsequent tests (both within
    this module and across the wider suite). We snapshot before and restore
    after so each test starts from a clean, propagation-on, handler-less
    state. Covers all managed loggers (temporalio.activity + temporalio.worker
    subtree) so the worker-coverage extension cannot leak either.
    """
    saved = {
        name: (
            list(logging.getLogger(name).handlers),
            logging.getLogger(name).propagate,
            logging.getLogger(name).level,
        )
        for name in _MANAGED_LOGGERS
    }
    try:
        yield
    finally:
        for name in _MANAGED_LOGGERS:
            logger = logging.getLogger(name)
            orig_handlers, orig_propagate, orig_level = saved[name]
            for h in list(logger.handlers):
                if h not in orig_handlers:
                    logger.removeHandler(h)
                    h.close()
            for h in orig_handlers:
                if h not in logger.handlers:
                    logger.addHandler(h)
            logger.propagate = orig_propagate
            logger.setLevel(orig_level)


def test_install_removes_stale_handler_on_other_path(tmp_path):
    """legacy 换代（无 workflow_id 双装）：旧 fallback 目标不再接收 record 且旧
    FileHandler 被 close——不摘则同一条 record 被双写（两个会话目录内容/md5 相同，
    2026-08-18 worker 容器实测）+ 句柄泄漏。路由架构（2026-09-11）下等价保证：
    record 只落新路径 + 旧 handler close；并发会话隔离见
    test_concurrent_sessions_route_by_workflow_id。"""
    old_path = tmp_path / "a" / "activity_failures.log"
    new_path = tmp_path / "b" / "activity_failures.log"
    install_temporalio_log_redirect(old_path)
    routing = logging.getLogger(_LOGGER_NAME).handlers[0]
    old_fh = routing._targets.get("_fallback")
    assert old_fh is not None, "预置：旧路径应已是 fallback 目标"

    install_temporalio_log_redirect(new_path)

    logging.getLogger(_LOGGER_NAME).warning("legacy no-id record")
    assert "legacy no-id record" in new_path.read_text()
    assert "legacy no-id record" not in old_path.read_text()
    assert old_fh.stream is None, \
        "旧 fallback FileHandler 应被 close（stream=None，释放句柄）"


def test_failure_record_goes_to_file_not_stderr(tmp_path, capsys):
    log_path = tmp_path / "activity_failures.log"
    install_temporalio_log_redirect(log_path)

    # Simulate a configured root logger with a stderr handler. With such a
    # handler present, a propagated record WOULD reach stderr; this test only
    # stays clean if ``propagate=False`` blocks the walk toward root. (Without
    # a root handler, Python's lastResort never fires because our WARNING-level
    # FileHandler already handled the record — so a bare assert on stderr would
    # pass regardless of the propagate setting and could not detect a
    # regression removing ``propagate=False``.)
    import sys
    root_stderr_handler = logging.StreamHandler(sys.stderr)
    root_logger = logging.getLogger()
    root_logger.addHandler(root_stderr_handler)
    try:
        logger = logging.getLogger(_LOGGER_NAME)
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logger.warning("Completing activity as failed", exc_info=True)

        captured = capsys.readouterr()
        assert "Traceback" not in captured.err              # not on terminal
        assert "Traceback" in log_path.read_text()          # into file
        assert "Completing activity as failed" in log_path.read_text()
    finally:
        root_logger.removeHandler(root_stderr_handler)


def test_debug_records_filtered_out_of_file(tmp_path):
    log_path = tmp_path / "activity_failures.log"
    install_temporalio_log_redirect(log_path)
    logging.getLogger(_LOGGER_NAME).debug("heartbeat noise")
    assert "heartbeat noise" not in log_path.read_text()   # handler level=WARNING


def test_install_is_idempotent(tmp_path):
    log_path = tmp_path / "activity_failures.log"
    install_temporalio_log_redirect(log_path)
    install_temporalio_log_redirect(log_path)
    # 路由架构：共享 routing handler 不重复挂（logger 上只有一个被管 handler），
    # 同路径重装 fallback FileHandler 换代（旧的 close，不堆叠）。
    routing = [h for h in logging.getLogger(_LOGGER_NAME).handlers
               if not isinstance(h, logging.FileHandler)]
    assert len(routing) == 1                               # not re-added
    fh = routing[0]._targets.get("_fallback")
    assert fh is not None
    assert Path(fh.baseFilename).resolve() == log_path.resolve()
    install_temporalio_log_redirect(log_path)
    fh2 = routing[0]._targets.get("_fallback")
    assert fh2 is not fh and fh.stream is None             # 换代关旧，不堆叠


def test_worker_activity_debug_goes_to_file_when_debug_env(tmp_path, monkeypatch):
    """temporalio.worker._activity 的执行边界 DEBUG(:315 Running / :521 Completing)
    在 SUPERNOVA_TEMPORALIO_LOG_LEVEL=DEBUG 时进入 per-workspace 文件。

    这是 '10min 无日志空窗' 可观测性的核心: 拿到 activity 被 worker 取走执行的
    时间戳序列, 判定 attempt=1 有无被执行。默认(env 未设)不进文件。
    """
    monkeypatch.setenv("SUPERNOVA_TEMPORALIO_LOG_LEVEL", "DEBUG")
    log_path = tmp_path / "temporalio-activity.log"
    install_temporalio_log_redirect(log_path)

    logging.getLogger("temporalio.worker._activity").debug(
        "Running activity run_framework_analysis (token xyz)")

    assert "Running activity run_framework_analysis" in log_path.read_text()


def test_worker_debug_does_not_leak_to_root_when_debug_env(tmp_path, monkeypatch, capsys):
    """propagate=False 截断(spec 不变量 I2): env=DEBUG 时 worker DEBUG record
    进文件, 但不向上传播到 root —— 不污染 display 流 / 终端。

    若有人误删 propagate=False, worker DEBUG 会经 LogBusHandler 刷屏 live display;
    本测试用一个 root stderr handler 探测传播是否被截断。
    """
    import sys
    monkeypatch.setenv("SUPERNOVA_TEMPORALIO_LOG_LEVEL", "DEBUG")
    log_path = tmp_path / "temporalio-activity.log"
    install_temporalio_log_redirect(log_path)

    root_stderr_handler = logging.StreamHandler(sys.stderr)
    root_logger = logging.getLogger()
    root_logger.addHandler(root_stderr_handler)
    try:
        logging.getLogger("temporalio.worker._activity").debug("Running activity leak_check")

        captured = capsys.readouterr()
        assert "leak_check" in log_path.read_text()        # 进文件
        assert "leak_check" not in captured.err            # 不进终端(截断到 root)
    finally:
        root_logger.removeHandler(root_stderr_handler)


def test_worker_activity_debug_filtered_when_env_unset(tmp_path, monkeypatch):
    """默认(env 未设)→ handler WARNING, temporalio.worker._activity 的 DEBUG 不进文件。

    零回归不变量 I1: env 未设时行为与改前完全一致(worker 子树默认也不泄 DEBUG)。
    """
    monkeypatch.delenv("SUPERNOVA_TEMPORALIO_LOG_LEVEL", raising=False)
    log_path = tmp_path / "temporalio-activity.log"
    install_temporalio_log_redirect(log_path)

    logging.getLogger("temporalio.worker._activity").debug("should_not_appear_default")

    assert "should_not_appear_default" not in log_path.read_text()


def test_invalid_env_level_falls_back_to_warning(tmp_path, monkeypatch):
    """env 非法值 → 回落 WARNING, 不抛(spec §7); handler 级别 == WARNING, DEBUG 被滤。"""
    monkeypatch.setenv("SUPERNOVA_TEMPORALIO_LOG_LEVEL", "BOGUS")
    log_path = tmp_path / "temporalio-activity.log"
    install_temporalio_log_redirect(log_path)              # 不抛

    logging.getLogger("temporalio.worker._activity").debug("should_not_appear_bogus")
    assert "should_not_appear_bogus" not in log_path.read_text()
    # 路由架构：level 过滤由共享 routing handler 承担（内部 FileHandler 恒不滤）。
    routing = [h for h in logging.getLogger("temporalio.worker").handlers
               if not isinstance(h, logging.FileHandler)]
    assert routing and routing[0].level == logging.WARNING


# ---------------------------------------------------------------------------
# 2026-09-11 日志串台修复：按 record 内 workflow_id 路由（共享 handler + registry）
# 回归背景：常驻 worker 单进程跑 wb/bb/corr 三 queue，「最后安装者赢」的重定向使
# corr 的崩溃 traceback 落进 wb 会话目录（NodeGoat-20260910-193720 实证），排查
# 方向被带偏。temporalio 的 failure record 消息里带 workflow_id（dict repr），
# 据此路由到所属会话目录。
# ---------------------------------------------------------------------------

def test_concurrent_sessions_route_by_workflow_id(tmp_path):
    """并发会话各自 install（带 workflow_id）后，record 按消息内 workflow_id
    路由到所属会话目录——不再互相抢。"""
    wb_log = tmp_path / "wb" / "activity_failures.log"
    corr_log = tmp_path / "corr" / "activity_failures.log"
    install_temporalio_log_redirect(wb_log, workflow_id="ws-nodegoat-1")
    install_temporalio_log_redirect(corr_log, workflow_id="ws-crossrepo-2")

    act = logging.getLogger(_LOGGER_NAME)
    # temporalio 实证形态：details dict repr 嵌在 message 里
    act.warning("Completing activity as failed ({'workflow_id': "
                "'ws-crossrepo-2-corr', 'activity_type': 'run_correlation_activity'})")
    act.warning("Completing activity as failed ({'workflow_id': "
                "'ws-nodegoat-1-resume-1', 'activity_type': 'run_adversarial_review'})")

    assert "run_correlation_activity" in corr_log.read_text()
    assert "run_correlation_activity" not in wb_log.read_text()
    assert "run_adversarial_review" in wb_log.read_text()
    assert "run_adversarial_review" not in corr_log.read_text()


def test_record_without_workflow_id_falls_back_to_latest(tmp_path):
    """无 workflow_id 的 record（worker 执行边界 DEBUG 等）→ fallback 到最近
    安装的目录——与原「最后安装者赢」行为对齐（legacy 调用零回归）。"""
    a_log = tmp_path / "a" / "activity_failures.log"
    b_log = tmp_path / "b" / "activity_failures.log"
    install_temporalio_log_redirect(a_log, workflow_id="ws-a")
    install_temporalio_log_redirect(b_log)          # 无 id → fallback 换代

    logging.getLogger("temporalio.worker._activity").warning("boundary record no id")
    assert "boundary record no id" in b_log.read_text()
    assert "boundary record no id" not in a_log.read_text()


def test_reinstall_same_workflow_id_replaces_target(tmp_path):
    """同 workflow_id 重装（同会话目录重跑）换代：record 只落新路径，旧路径
    不再接收（防双写/句柄泄漏，2026-08-18 同款隐患）。"""
    old_log = tmp_path / "old" / "f.log"
    new_log = tmp_path / "new" / "f.log"
    install_temporalio_log_redirect(old_log, workflow_id="ws-x")
    install_temporalio_log_redirect(new_log, workflow_id="ws-x")

    logging.getLogger(_LOGGER_NAME).warning(
        "Completing activity as failed ({'workflow_id': 'ws-x', 'x': 1})")
    assert "ws-x" in new_log.read_text()
    old_txt = old_log.read_text() if old_log.exists() else ""
    assert "'x': 1" not in old_txt
