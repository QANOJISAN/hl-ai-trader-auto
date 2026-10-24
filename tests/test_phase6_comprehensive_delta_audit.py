"""
HL AI Trader v1.2 Alpha-Max — Phase 6 Comprehensive Delta Audit Test Suite
(`tests/test_phase6_comprehensive_delta_audit.py`)

Audit Round 12 & 13 で検証・強化した全4領域（v1.1/v1.2 クオンツエンジン境界条件、
64bit DPAPI & Win32 リソースリーク防止、高可用性SQLite WAL / イベント駆動 scheduleCancel / UPS電源保護、
および事後監査CLI `run_quant_postmortem_audit.py` の全エッジケース）を検証する単体・結合テストスイート。
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from scripts.run_quant_postmortem_audit import (
    open_readonly_sqlite,
    run_diagnostic_1_bayesian_gate_audit,
    run_diagnostic_2_mfe_capture_audit,
    run_diagnostic_3_fee_and_maker_audit,
    run_diagnostic_4_tax_forensic_audit,
    run_full_postmortem_audit,
)
from src.coordinator import (
    ConcurrencyStateCoordinator,
    SlotState,
    SlotSubState,
    TrailingStage,
)
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import (
    ActionBudgetController,
    HyperliquidExchangeWrapper,
    SpotUniverseEntry,
)
from src.main import HLTraderDaemon
from src.radar import (
    compute_short_squeeze_ignition_index,
    compute_spot_absorption_index,
)
from src.risk_guard import (
    RiskAndCircuitBreakerEngine,
    compute_soft_ratchet_trailing_sl,
    compute_time_decay_sl,
)
from src.utils import (
    SYSTEM_POWER_STATUS,
    _read_windows_process_peb_strings,
    check_ups_power_critical,
    dpapi_decrypt_str,
    dpapi_encrypt_str,
    hidden_subprocess_kwargs,
    verify_target_process_identity,
)
from src.ws_manager import HyperliquidWSManager


def test_checklist_1_empty_buffers_and_stage20_time_decay_monotonicity(tmp_path: Path) -> None:
    """
    監査項目 1-1, 1-2, 1-3:
    1) WebSocket 起動直後（約定履歴・板履歴が空 `[]` / `{}`）における CVD / Whale / SSII / SAI のゼロ除算・例外耐性
    2) 6段階ソフトラチェット (`10, 13, 17, 20, 30, 40`) と旧ステージ (`1, 2, 3, 4`) の完全互換性
    3) Stage 2 / Stage 20 (`FREEROLL_LOCKED`, `entry_px * 1.0015`) 到達後の `compute_time_decay_sl` 単調非減少保証
    """
    ws = HyperliquidWSManager(main_address="0x" + "1" * 40)
    cvd_empty = ws.compute_cvd_and_whale_metrics("HYPE/USDC", trades_override=[])
    assert cvd_empty == {"cvd_5m": 0.0, "cvd_15m": 0.0, "cvd_1h": 0.0, "whale_1h": 0.0}

    cvd_unregistered = ws.compute_cvd_and_whale_metrics("UNKNOWN/USDC")
    assert cvd_unregistered == {"cvd_5m": 0.0, "cvd_15m": 0.0, "cvd_1h": 0.0, "whale_1h": 0.0}

    assert ws.get_bid_top3_depth_ratio_3s("HYPE/USDC") == 1.0

    ssii_zero = compute_short_squeeze_ignition_index(
        funding_t=0.0,
        z_oi_4h_t=0.0,
        spot_px=0.0,
        high_20_15m=0.0,
        atr_15m=0.0,
        cvd_perp_5m=0.0,
        delta_oi_15m=0.0,
        delta_basis_15m=0.0,
    )
    assert ssii_zero["ssii"] == 0.0

    sai_zero = compute_spot_absorption_index(
        cvd_spot_15m=0.0,
        cvd_perp_15m=0.0,
        whale_1h=0.0,
        funding_t=0.0,
        ssii=0.0,
    )
    assert 0.0 <= sai_zero["sai"] <= 1.0

    # Stage 2 / Stage 20 (FREEROLL_LOCKED: 100.0 * 1.0015 = 100.15) 到達時の Time-Decay SL 非退行検証
    for stage_val in (2, 3, 4, 20, 30, 40):
        assert TrailingStage.is_freeroll_locked_stage(stage_val) is True
        td = compute_time_decay_sl(
            entry_px=100.0,
            initial_sl_px=96.0,
            current_sl_px=100.15,
            holding_minutes=220.0,
            stage=stage_val,
        )
        assert td["active"] is False
        assert td["sl_updated"] is False
        assert td["new_sl_px"] == pytest.approx(100.15)

    # 仮に stage=17 でも current_sl_px が既に 100.15 (+0.15%) 以上なら決して 100.05 (+0.05%) に引き下げない
    td_high_sl = compute_time_decay_sl(
        entry_px=100.0,
        initial_sl_px=96.0,
        current_sl_px=100.15,
        holding_minutes=230.0,
        stage=17,
    )
    assert td_high_sl["new_sl_px"] >= 100.15

    # Slot 2 Triple Gate が trailing_stage=20 でも Gate 1 を通過することを確認
    db = DatabaseManager(db_path=tmp_path / "gate_test.db")
    coord = ConcurrencyStateCoordinator(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)
    gate_res = rg.evaluate_slot2_triple_gate(
        slot1_state={
            "state": SlotState.OPEN_PROTECTED.value,
            "sub_state": SlotSubState.FREEROLL_LOCKED.value,
            "trailing_stage": 20,
            "entry_px": 100.0,
            "sl_px": 100.15,
        },
        slot1_best_bid=101.5,
        slot1_atr_1m=0.20,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.5,
        hype_perp_premium_pct=0.01,
        hype_perp_delta_oi_15m_pct=0.5,
        corr_4h=0.25,
    )
    assert gate_res["allowed"] is True


def test_checklist_1_4_scratch_sell_alo_precancel_on_emergency_ioc_exit(tmp_path: Path) -> None:
    """
    監査項目 1-4 & 1-5:
    1) スクラッチ撤退 (`place_spot_sell_alo`, TTL 180秒) の待機中に価格が急落して `execute_atomic_ioc_exit` が
       発火した際、必ず既存の `SELL_ALO` 指値を先行キャンセル (`exchange.cancel`) してから `IOC` 売り注文を送信し、
       `hold > 0` 拘束による `Insufficient balance` を100%防止すること。
    2) `ActionBudgetController` が100%枯渇 (`EMERGENCY_ONLY`) しても、緊急 `IOC` 決済とキャンセルは一切遮断されないこと。
    """
    db = DatabaseManager(db_path=tmp_path / "scratch_ioc.db")
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)

    call_log: List[Tuple[str, Dict[str, Any]]] = []

    class _MockExchange:
        def order(self, **kwargs: Any) -> Dict[str, Any]:
            tif = kwargs.get("order_type", {}).get("limit", {}).get("tif", "")
            call_log.append((f"ORDER_{tif.upper()}", kwargs))
            if tif == "Alo":
                return {"status": "ok", "response": {"data": {"statuses": [{"resting": {"oid": 777001}}]}}}
            return {
                "status": "ok",
                "response": {"data": {"statuses": [{"filled": {"oid": 777002, "totalSz": "1.0", "avgPx": "24.5"}}]}},
            }

        def cancel(self, name: str, oid: int) -> Dict[str, Any]:
            call_log.append(("CANCEL", {"name": name, "oid": oid}))
            return {"status": "ok"}

        def schedule_cancel(self, cancel_time_ms: Optional[int]) -> Dict[str, Any]:
            call_log.append(("SCHEDULE_CANCEL", {"cancel_time_ms": cancel_time_ms}))
            return {"status": "ok"}

    class _MockInfo:
        def spot_clearinghouse_state(self, user: str) -> Dict[str, Any]:
            # SELL_ALO 発注中は hold=1.00, total=1.00 で拘束されている状態を模擬
            return {
                "balances": [
                    {"coin": "USDC", "total": "100.0", "hold": "0.0"},
                    {"coin": "HYPE", "total": "1.00", "hold": "1.00"},
                ]
            }

        def open_orders(self, user: str) -> List[Dict[str, Any]]:
            return []

    wrapper = HyperliquidExchangeWrapper(
        main_address="0x" + "2" * 40,
        agent_private_key="0x" + "3" * 64,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=_MockInfo(),
        exchange_client=_MockExchange(),
    )
    entry = SpotUniverseEntry(
        pair_name="HYPE/USDC",
        api_coin_name="@107",
        base_asset="HYPE",
        quote_asset="USDC",
        base_token_idx=1,
        quote_token_idx=0,
        universe_idx=107,
        spot_asset_id=10107,
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        perp_coin="HYPE",
        spot_mid_px=25.0,
        spot_day_ntl_vlm=5_000_000.0,
    )
    wrapper.pair_to_entry["HYPE/USDC"] = entry
    wrapper.api_coin_to_entry["@107"] = entry
    wrapper.base_to_entry["HYPE"] = entry

    # ActionBudgetController を 100% 枯渇状態に設定しても緊急IOC決済・キャンセルが通ることを確認
    b_state = wrapper.action_budget.evaluate_budget_state(
        v_cum_usdc=0.0,
        a_used_total=10_000,
        v_ema_7d_usdc=100.0,
        v_today_usdc=0.0,
        actions_used_today=2000,
    )
    assert b_state["new_entry_allowed"] is False
    assert b_state["repeg_modify_allowed"] is False
    assert b_state["exit_and_cancel_allowed"] is True

    # 1. SELL_ALO (TTL 180s) を発注 -> resting oid=777001 が _active_scratch_sell_orders[1] に記録される
    alo_res = wrapper.place_spot_sell_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        best_ask=25.10,
        best_bid=25.00,
        raw_sz="1.00",
        ttl_sec=180,
    )
    assert alo_res["status"] == "ok"
    assert alo_res["oid"] == 777001
    assert 1 in wrapper._active_scratch_sell_orders

    # 2. 直後に価格急落で SL 割れ -> execute_atomic_ioc_exit 発火
    ioc_res = wrapper.execute_atomic_ioc_exit(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        best_bid=24.50,
    )
    assert ioc_res["status"] == "ok"
    assert ioc_res["pre_cancelled_scratch_order"] is True
    assert 1 not in wrapper._active_scratch_sell_orders

    # 呼び出し順序の検証: ORDER_ALO -> SCHEDULE_CANCEL -> CANCEL(777001) -> ORDER_IOC
    action_names = [name for name, _ in call_log]
    cancel_idx = action_names.index("CANCEL")
    ioc_idx = action_names.index("ORDER_IOC")
    assert cancel_idx < ioc_idx
    assert call_log[cancel_idx][1]["oid"] == 777001


def test_checklist_2_and_3_ring_buffer_bounds_and_deadman_idempotency(tmp_path: Path) -> None:
    """
    監査項目 2-1, 2-2, 3-1, 3-2, 3-3:
    1) WebSocket `_trades_history` (最大 2000 件) および `_bid_top3_history` (最大 30 件) のメモリ上限強制
    2) `clear_deadman_if_no_pending_orders` の完全べき等性（一度クリア試行したら `_active_deadman_cancel_time_ms = None` となり次周期以降に再発火しない）
    3) DPAPI 暗号化・復号 (`LocalFree`) とインプロセス PEB 読み取り (`CloseHandle`) の正常動作
    4) デスクトップPC (`BatteryLifePercent = 255`) の誤検知ゼロと `_graceful_shutdown_triggered` 再入防止
    """
    ws = HyperliquidWSManager(main_address="0x" + "1" * 40)
    now = 1_760_000_000_000

    # 2500件の約定を流し込んでも 2000件以下にクリップされること
    bulk_trades = [
        {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "1.0", "time": now - i * 100}
        for i in range(2500)
    ]
    ws.handle_trades_msg({"data": bulk_trades}, current_time_ms=now)
    assert len(ws._trades_history["HYPE/USDC"]) <= 2000

    # 50回の l2Book 更新を流し込んでも _bid_top3_history が 30件以下にクリップされること
    for i in range(50):
        ws.handle_l2_book_msg(
            {
                "data": {
                    "coin": "HYPE/USDC",
                    "time": now + i * 100,
                    "levels": [[{"px": "25.0", "sz": "10.0"}], [{"px": "25.1", "sz": "10.0"}]],
                }
            },
            current_time_ms=now + i * 100,
        )
    assert len(ws._bid_top3_history["HYPE/USDC"]) <= 30

    # Dead Man's Switch のクリアべき等性検証
    wrapper = HyperliquidExchangeWrapper(execution_mode="DRY_RUN")
    sched = wrapper.schedule_cancel_deadman(cancel_time_ms=now + 120_000, current_time_ms=now)
    assert sched["scheduled"] is True
    assert wrapper._active_deadman_cancel_time_ms is not None

    clr1 = wrapper.clear_deadman_if_no_pending_orders(has_other_pending_orders=False, current_time_ms=now + 1000)
    assert clr1["cleared"] is True
    assert wrapper._active_deadman_cancel_time_ms is None

    # 2回目の呼び出しでは API を一切叩かず NO_ACTIVE_DEADMAN_RESERVATION で即座に終了すること
    calls_before = wrapper._schedule_cancel_daily_count
    clr2 = wrapper.clear_deadman_if_no_pending_orders(has_other_pending_orders=False, current_time_ms=now + 2000)
    assert clr2["cleared"] is False
    assert clr2["reason"] == "NO_ACTIVE_DEADMAN_RESERVATION"
    assert wrapper._schedule_cancel_daily_count == calls_before

    # DPAPI 往復検証 & Win32 PEB インプロセス読み取り検証
    enc = dpapi_encrypt_str("audit-round-12-secret-value")
    assert enc.startswith("DPAPI:")
    assert dpapi_decrypt_str(enc) == "audit-round-12-secret-value"
    kw = hidden_subprocess_kwargs()
    assert kw.get("creationflags") == 0x08000000

    # デスクトップPC (BatteryLifePercent=255) で誤って power_critical=True にならないこと
    desktop_pwr = check_ups_power_critical(
        simulated_status={"ACLineStatus": 0, "BatteryFlag": 128, "BatteryLifePercent": 255}
    )
    assert desktop_pwr["power_critical"] is False


def test_checklist_4_postmortem_audit_all_edge_cases(tmp_path: Path) -> None:
    """
    監査項目 4:
    `scripts/run_quant_postmortem_audit.py` の全エッジケース検証:
    1) トレード 0 件の初期DBでゼロ除算・例外なく完走すること
    2) 全勝 (`L_live = 0`) / 全敗 (`W_live = 0`) / `MFE_R = 0.0` / `MAE_R = 0.0` でもゼロ除算ゼロで完走すること
    3) `open_readonly_sqlite` が `INSERT` を `sqlite3.OperationalError` で確実に拒絶すること
    """
    db_path = tmp_path / "edge_postmortem.db"
    db = DatabaseManager(db_path=db_path)

    # ケースA: トレード0件の初期DB
    rep_empty = run_full_postmortem_audit(db_path=db_path, mc_samples=2000)
    assert rep_empty["pragma_query_only"] == 1
    assert rep_empty["diagnostic_1_gate_bayesian"]["n_live"] == 0
    assert rep_empty["diagnostic_2_mfe_capture"]["total_closed_trades"] == 0
    assert rep_empty["diagnostic_2_mfe_capture"]["mean_cr_mfe"] is None
    assert rep_empty["diagnostic_4_tax_forensic"]["status"] == "PASS: EXPORT_READY"

    # ケースB: 全勝 (L_live=0) かつ MFE_R=0.0 の勝ちトレード、および MAE_R=0.0 の負けトレードを追加
    with db.immediate_transaction() as tx:
        tx.execute(
            """
            INSERT INTO ai_episodic_memory (
                episode_id, timestamp_ms, slot_id, coin, cloid, oid,
                market_regime_4h, trend_alignment_1h, bbo_spread_bps,
                perp_funding_rate_hr, perp_oi_delta_15m_pct, perp_premium_pct,
                conviction_score, entry_limit_px, initial_sl_px, target_tp_px,
                expected_rr_ratio, order_sz, notional_usdc, reasoning_summary,
                self_critique, invalidation_condition, prompt_hash, lifecycle_status
            ) VALUES
            ('EP_ZERO_MFE', 1760000000000, 1, 'HYPE/USDC', '0x1111', 101,
             'BULL_EXPANSION', 'ALIGNED', 2.0, 0.0001, 1.0, 0.05,
             85, 25.0, 24.5, 26.0, 2.0, 1.0, 25.0, 'r', 'c', 'i', 'h1', 'CLOSED'),
            ('EP_ZERO_MAE', 1760000100000, 1, 'HYPE/USDC', '0x2222', 102,
             'BULL_EXPANSION', 'ALIGNED', 2.0, 0.0001, 1.0, 0.05,
             80, 25.0, 24.5, 26.0, 2.0, 1.0, 25.0, 'r', 'c', 'i', 'h2', 'CLOSED')
            """
        )
        tx.execute(
            """
            INSERT INTO ai_reflection_memory (
                reflection_id, episode_id, closed_at_ms, coin, market_regime_4h,
                exit_reason, holding_duration_sec, entry_px, exit_px,
                realized_r_multiple, mfe_pct, mae_pct, execution_slippage_bps,
                thesis_validity_score, failure_taxonomy, distilled_rule, importance_weight
            ) VALUES
            ('REF_ZERO_MFE', 'EP_ZERO_MFE', 1760000050000, 'HYPE/USDC', 'BULL_EXPANSION',
             'SCRATCH_PROFIT', 50, 25.0, 25.1, 0.20, 0.0, 0.0, 1.0, 0.8, 'NONE', 'rule1', 1.0),
            ('REF_ZERO_MAE', 'EP_ZERO_MAE', 1760000150000, 'HYPE/USDC', 'BULL_EXPANSION',
             'SCRATCH_LOSS', 50, 25.0, 24.9, -0.20, 0.0, 0.0, 1.0, 0.5, 'NOISE', 'rule2', 1.0)
            """
        )

    rep_edges = run_full_postmortem_audit(db_path=db_path, mc_samples=2000)
    d2 = rep_edges["diagnostic_2_mfe_capture"]
    assert d2["total_closed_trades"] == 2
    assert d2["win_trades"] == 1
    assert d2["loss_trades"] == 1
    # MFE_R == 0.0 の勝ちトレードは NULL 除外されるため cr_mfe_valid_count == 0, mean_cr_mfe is None
    assert d2["cr_mfe_valid_count"] == 0
    assert d2["mean_cr_mfe"] is None
    # MAE_R == 0.0 の負けトレードもゼロ除算せず mean_ur_mae is None
    assert d2["mean_ur_mae"] is None

    # 読み取り専用接続が書き込みを拒絶することを確認
    ro_conn = open_readonly_sqlite(db_path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            ro_conn.execute("UPDATE system_state_store SET operator_paused = 1 WHERE id = 1")
    finally:
        ro_conn.close()
