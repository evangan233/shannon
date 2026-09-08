"""stale probe reaper：启动期清残留 probe 的明文凭据（worker/web 异常退出滞留）。
2026-08-17 收窄：只删明文 scan-config.yaml，保留 events.ndjson/auth-state.json 供回看
（对齐 get_auth_validation_result finally 的收窄清理）；running cred 的 probe 跳过
（重启时验证仍在跑，batch 后续 cred 尚未跑，删其 scan-config 会让 activity 读不到配置）。"""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from supernova_web.components.auth_profile_store import (
    AuthProfile, AuthProfileCredential, AuthProfileStore, VerifyStatus)
from supernova_web.components.credential_vault import CredentialVault
from supernova_web.components.scan_manager import ScanManager


def _store(tmp_path):
    vault = CredentialVault(tmp_path / ".master.key")
    return AuthProfileStore(tmp_path, vault)


def _mgr_with_store(tmp_path, store):
    return ScanManager(
        workspaces_dir=tmp_path, repos_dir=tmp_path / "repos", config_store=MagicMock(),
        scan_timeout=0.0, ws_config_store=MagicMock(),
        auth_profile_store=store,
    )


def test_reap_removes_plaintext_config_keeps_events(tmp_path):
    """残留 probe：删明文 scan-config.yaml；events.ndjson 保留供 verify-log 回看。"""
    ws = tmp_path / "ws1"
    probe = ws / "auth-probes" / "probe-stale"
    probe.mkdir(parents=True)
    (probe / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    (probe / "events.ndjson").write_text('{"i":1}\n', "utf-8")
    mgr = ScanManager(tmp_path, tmp_path / "repos", MagicMock())
    mgr.reap_stale_probes()
    assert not (probe / "scan-config.yaml").exists()
    assert (probe / "events.ndjson").exists()


def test_reap_removes_emptied_probe_dir(tmp_path):
    """只剩明文配置的 probe（无过程记录）→ 清空配置后目录一并移除，不堆积空壳。"""
    ws = tmp_path / "ws1"
    probe = ws / "auth-probes" / "probe-stale"
    probe.mkdir(parents=True)
    (probe / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    mgr = ScanManager(tmp_path, tmp_path / "repos", MagicMock())
    mgr.reap_stale_probes()
    assert not probe.exists()
    assert (ws / "auth-probes").exists() is False  # 空父目录一并清


def test_reap_skips_running_cred_probe(tmp_path):
    """running cred 的 probe（重启时验证仍在跑）→ scan-config 保留（batch 后续 cred 还要用）。"""
    ws = tmp_path / "ws1"
    probe = ws / "auth-probes" / "probe-live"
    probe.mkdir(parents=True)
    (probe / "scan-config.yaml").write_text("authentication: {}", "utf-8")
    store = _store(tmp_path)
    store.write("ws1", [AuthProfile(
        id="prof_1", name="NG", login_url="http://t/", login_type="form",
        credentials=[AuthProfileCredential(
            id="cred_a", role="admin", username="admin", password="pw",
            verify_status=VerifyStatus(
                state="running", workflow_id="authval-batch-ws1-x",
                probe_dir=str(probe)))])])
    mgr = _mgr_with_store(tmp_path, store)
    mgr.reap_stale_probes()
    assert (probe / "scan-config.yaml").exists()


def test_reap_stale_probes_no_dir_is_noop(tmp_path):
    mgr = ScanManager(tmp_path, tmp_path / "repos", MagicMock())
    mgr.reap_stale_probes()  # 无 auth-probes,不报错
