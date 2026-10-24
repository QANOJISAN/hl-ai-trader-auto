"""Audit Round 15: Tier-0 差分アドオン（HMACコード改ざんシール・L1出金遮断・CSRF Sec-Fetch-Site補強）単体テスト."""

from __future__ import annotations

from pathlib import Path
import sys
import pytest

PROJECT_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_DIR))

from src.exchange_wrapper import _install_exchange_l1_destination_guard
from src.utils import (
    DPAPI_APP_ENTROPY,
    DPAPI_CUSTOM_ENTROPY_SALT,
    can_decrypt_without_custom_entropy,
    dpapi_decrypt_str,
    dpapi_encrypt_str,
    get_dpapi_custom_entropy,
    seal_code_integrity_manifest,
    verify_code_integrity_seal,
    verify_pinned_hl_action_destination,
)
from src.web_server import SECURITY_HEADERS, validate_local_request_security


def test_dpapi_custom_entropy_rejects_null_entropy() -> None:
    """Layer 7 DPAPI カスタムEntropy維持および NULL Entropy 復号拒否の検証."""
    assert DPAPI_APP_ENTROPY == DPAPI_CUSTOM_ENTROPY_SALT
    assert len(get_dpapi_custom_entropy()) == 32
    plaintext = "hl_tier0_round15_secret_payload_998877"
    encrypted = dpapi_encrypt_str(plaintext, use_custom_entropy=True)
    assert encrypted.startswith("DPAPI:")

    # 正規のカスタムEntropyありでは復号成功
    assert dpapi_decrypt_str(encrypted, require_custom_entropy=True) == plaintext

    # カスタムEntropyなし（pOptionalEntropy=None）では復号失敗（False）
    assert can_decrypt_without_custom_entropy(encrypted) is False


def test_code_integrity_seal_and_tamper_detection(tmp_path: Path) -> None:
    """HMAC-SHA256 コード改ざんシールの生成・正常検証・1バイト改ざん検知の検証."""
    # 1. 実プロジェクトに対するシール生成（一時ファイル出力）と検証
    tmp_real_seal = tmp_path / "real_code_integrity.seal"
    manifest = seal_code_integrity_manifest(seal_path=tmp_real_seal, project_root=PROJECT_ROOT_DIR)
    assert "hmac_sha256" in manifest
    assert "files" in manifest
    assert len(manifest["files"]) >= 10
    assert verify_code_integrity_seal(
        seal_path=tmp_real_seal,
        raise_on_failure=True,
        project_root=PROJECT_ROOT_DIR,
    ) is True

    # 2. 模擬プロジェクトツリーでの1バイト改ざん検知テスト
    mock_root = tmp_path / "mock_proj"
    (mock_root / "src").mkdir(parents=True, exist_ok=True)
    (mock_root / "src" / "utils.py").write_text("# mock utils\nx = 1\n", encoding="utf-8")
    (mock_root / "src" / "main.py").write_text("# mock main\ny = 2\n", encoding="utf-8")
    (mock_root / "watchdog.py").write_text("# mock watchdog\nz = 3\n", encoding="utf-8")

    mock_seal = mock_root / "data" / "code_integrity.seal"
    seal_code_integrity_manifest(seal_path=mock_seal, project_root=mock_root)

    assert verify_code_integrity_seal(
        seal_path=mock_seal,
        raise_on_failure=True,
        project_root=mock_root,
    ) is True

    # src/utils.py に1バイト改ざんを加える
    target_py = mock_root / "src" / "utils.py"
    target_py.write_text(target_py.read_text(encoding="utf-8") + "#", encoding="utf-8")

    with pytest.raises(PermissionError, match="Code integrity seal"):
        verify_code_integrity_seal(
            seal_path=mock_seal,
            raise_on_failure=True,
            project_root=mock_root,
        )

    assert verify_code_integrity_seal(
        seal_path=mock_seal,
        raise_on_failure=False,
        project_root=mock_root,
    ) is False


def test_l1_destination_pinning_guard() -> None:
    """Hyperliquid L1 出金・権限委譲アクション遮断ガードの検証."""
    pinned = {"0x1234567890abcdef1234567890abcdef12345678"}

    # 通常の取引アクションは無条件で許可
    for trade_type in ("order", "cancel", "cancelByCloid", "batchModify", "modify", "scheduleCancel", "updateLeverage"):
        assert verify_pinned_hl_action_destination({"type": trade_type}, allowed_destinations=pinned) is True

    # approveAgent / approveBuilderFee は宛先に関わらず無条件遮断
    for forbidden_type in ("approveAgent", "approveBuilderFee"):
        with pytest.raises(PermissionError, match=forbidden_type):
            verify_pinned_hl_action_destination(
                {"type": forbidden_type, "agentAddress": "0x1234567890abcdef1234567890abcdef12345678"},
                allowed_destinations=pinned,
            )

    # 未知アドレスへの usdSend / withdraw3 / spotSend / vaultTransfer は即時遮断
    for transfer_type, key in (
        ("usdSend", "destination"),
        ("withdraw3", "destination"),
        ("spotSend", "destination"),
        ("sendAsset", "destination"),
        ("vaultTransfer", "vaultAddress"),
    ):
        with pytest.raises(PermissionError, match="Blocked unauthorized L1"):
            verify_pinned_hl_action_destination(
                {"type": transfer_type, key: "0xdeadbeef00000000000000000000000000000000"},
                allowed_destinations=pinned,
            )

    # ピン留めされた自身マスターアドレス宛ては許可（大文字小文字混在でも正規化一致）
    assert verify_pinned_hl_action_destination(
        {"type": "usdSend", "destination": "0x1234567890ABCDEF1234567890abcdef12345678"},
        allowed_destinations=pinned,
    ) is True

    # Exchange._post_action フックの動作確認
    class DummyExchange:
        def __init__(self) -> None:
            self.calls = []

        def _post_action(self, action, signature, nonce):
            self.calls.append((action, signature, nonce))
            return {"status": "ok"}

    dummy = DummyExchange()
    _install_exchange_l1_destination_guard(dummy)
    assert getattr(dummy, "_hl_l1_guard_installed", False) is True

    # order は通過
    res = dummy._post_action({"type": "order", "orders": []}, "sig", 123)
    assert res == {"status": "ok"}
    assert len(dummy.calls) == 1

    # approveAgent は遮断
    with pytest.raises(PermissionError):
        dummy._post_action({"type": "approveAgent"}, "sig", 124)
    assert len(dummy.calls) == 1


def test_validate_local_request_security_and_headers() -> None:
    """Host / Origin / Sec-Fetch-Site 検証および CSP / Cache-Control ヘッダー検証."""
    assert SECURITY_HEADERS.get("Cache-Control") == "no-store"
    assert "frame-ancestors 'none'" in SECURITY_HEADERS.get("Content-Security-Policy", "")

    # 正規ローカルリクエストは許可
    assert validate_local_request_security(
        {"Host": "127.0.0.1:8081"},
        method="GET",
        bound_port=8081,
    ) is True
    assert validate_local_request_security(
        {
            "Host": "127.0.0.1:8081",
            "Origin": "http://127.0.0.1:8081",
            "Sec-Fetch-Site": "same-origin",
        },
        method="POST",
        bound_port=8081,
    ) is True

    # Host 不正（DNS Rebinding）は拒否
    assert validate_local_request_security(
        {"Host": "evil.com"},
        method="GET",
        bound_port=8081,
    ) is False

    # Origin 不正（外部サイトからのリクエスト）は拒否
    assert validate_local_request_security(
        {"Host": "127.0.0.1:8081", "Origin": "https://evil.com"},
        method="POST",
        bound_port=8081,
    ) is False

    # Sec-Fetch-Site: cross-site は拒否
    assert validate_local_request_security(
        {"Host": "127.0.0.1:8081", "Sec-Fetch-Site": "cross-site"},
        method="POST",
        bound_port=8081,
    ) is False
    assert validate_local_request_security(
        {"Host": "127.0.0.1:8081", "Sec-Fetch-Site": "cross-site"},
        method="GET",
        bound_port=8081,
    ) is False
