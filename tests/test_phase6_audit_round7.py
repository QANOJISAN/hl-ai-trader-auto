"""
HL AI Trader v1 — Phase 6 Audit Round 7 Test Suite (tests/test_phase6_audit_round7.py)

第7回 徹底総合監査（Audit Round 7：Round 6修正パッチの副作用監査・分割約定/連続決済の識別性・DB永続化完全性監査）の検証スイート:
1. `process_spot_fill` の60秒窓重複排除における「分割約定 (Partial Fills)」および「60秒以内の別注文 (`hl_oid` 違い / Top-Up & Dump)」の誤スキップ防止監査
2. `_finalize_position_exit` のべき等キー衝突防止監査（`episode_id` が `None`/`""`/`"0"` または `order_created_at_ms == 0` の場合でも過去トレードや後続トレードと衝突しないこと）
3. L2 / L3 / L4 クールダウン満了時の SQLite `system_state_store` 永続化監査（満了時に `in_quiescence=True` / `price_tainted=True` が重なった場合やプロセス再起動後も再ロックされないこと）
4. 全モジュール横断整合性・`exit_oid` 伝播・ロック解放完全性監査
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from src.ai_brain import DebiasedAIBrain, HLTraderExecutionDecision
from src.coordinator import ConcurrencyStateCoordinator, SlotState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.main import HLTraderDaemon
from src.risk_guard import RiskAndCircuitBreakerEngine
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo


# ==============================================================================
# 1. `process_spot_fill`: 分割約定 (Partial Fills) & 60秒以内の別注文誤スキップ防止監査
# ==============================================================================
def test_round7_item1_partial_fills_and_consecutive_distinct_orders_within_60s_not_skipped(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r7_item1.db", initial_equity_usdc=143.73)
    tax = HyperliquidTaxEngine(db=db)
    ts = 1_780_000_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )

    # --- Case 1A: 同一注文 (hl_oid=5000) が2回の実分割約定 (Partial Fill #1, #2) で約定した場合 ---
    # 同一サイズ (0.50 + 0.50 = 1.00) かつ 100ms 間隔であっても、異なる実 hl_tid (< 9e12) は両方記録されること
    pf1 = tax.process_spot_fill(
        hl_tid=1001,
        hl_oid=5000,
        timestamp_ms=ts + 1_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.50",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    pf2 = tax.process_spot_fill(
        hl_tid=1002,
        hl_oid=5000,
        timestamp_ms=ts + 1_100,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.50",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert pf1["duplicate"] is False
    assert pf2["duplicate"] is False

    # その後、同一 hl_oid=5000 に対する合成フォールバック (hl_tid >= 9e12) が到着した場合は重複としてスキップされること
    pf_syn_after = tax.process_spot_fill(
        hl_tid=9_000_000_005_000,
        hl_oid=5000,
        timestamp_ms=ts + 1_500,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="1.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert pf_syn_after["duplicate"] is True

    conn = db._get_connection()
    hype_inv = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    assert float(hype_inv["quantity"]) == pytest.approx(1.00)

    # --- Case 1B: 逆に REST 合成約定 (hl_oid=6000, sz=1.00) が先に記録され、後から WS 分割約定 (0.40 + 0.60) が到着した場合 ---
    syn_first = tax.process_spot_fill(
        hl_tid=9_000_000_006_000,
        hl_oid=6000,
        timestamp_ms=ts + 5_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="1.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert syn_first["duplicate"] is False

    ws_part1 = tax.process_spot_fill(
        hl_tid=2001,
        hl_oid=6000,
        timestamp_ms=ts + 5_100,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.40",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    ws_part2 = tax.process_spot_fill(
        hl_tid=2002,
        hl_oid=6000,
        timestamp_ms=ts + 5_200,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.60",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert ws_part1["duplicate"] is True
    assert ws_part2["duplicate"] is True

    hype_inv2 = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    # Case 1A (1.00) + Case 1B (1.00) = 厳密に 2.00 枚であり、1.00 + 0.60 のような過剰計上が起きないこと
    assert float(hype_inv2["quantity"]) == pytest.approx(2.00)

    # --- Case 1C: 60秒以内に「異なる hl_oid (7001 と 7002)」で同一銘柄・同一数量の売却が連続した場合 ---
    # Order 7001 (合成約定 1.00 枚売却)
    sell_1 = tax.process_spot_fill(
        hl_tid=9_000_000_007_001,
        hl_oid=7001,
        timestamp_ms=ts + 10_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc="26.00",
        exec_sz_base="1.00",
        raw_fee_amount="0.0182",
        raw_fee_token="USDC",
        usdc_jpy_rate=155.0,
    )
    # 5秒後 (60秒以内) に別注文 Order 7002 (1.00 枚売却) が到着 -> hl_oid が異なるため絶対にスキップされないこと!
    sell_2 = tax.process_spot_fill(
        hl_tid=9_000_000_007_002,
        hl_oid=7002,
        timestamp_ms=ts + 15_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc="26.00",
        exec_sz_base="1.00",
        raw_fee_amount="0.0182",
        raw_fee_token="USDC",
        usdc_jpy_rate=155.0,
    )
    assert sell_1["duplicate"] is False
    assert sell_2["duplicate"] is False

    hype_inv3 = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    assert float(hype_inv3["quantity"]) == pytest.approx(0.0)
    db.close()


# ==============================================================================
# 2. `_finalize_position_exit`: べき等キー衝突防止監査 (`ep_id` が None / "" / "0" / `created_ms == 0`)
# ==============================================================================
def test_round7_item2_finalize_position_exit_idempotency_key_no_collision_on_missing_or_zero_ep_id(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r7_item2.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    mock_info = MockHLInfo("0x0")
    mock_ex = MockHLExchange(mock_info)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=mock_info,
        exchange_client=mock_ex,
    )
    wrapper.refresh_universe_mapping()
    daemon = HLTraderDaemon(db=db, coordinator=coord, tax_engine=tax, exchange_wrapper=wrapper)
    ts = 1_780_100_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )
    # 3回分の売却在庫を事前用意
    tax.process_spot_fill(
        hl_tid=3001,
        hl_oid=8001,
        timestamp_ms=ts + 100,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="3.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )

    # --- Trade #1: 正規の episode_id="ep_trade_1" を持つトレード ---
    dec1 = HLTraderExecutionDecision(
        action="BUY_ALO",
        conviction_score=85,
        limit_px=25.00,
        sl_px=24.00,
        tp_px=27.00,
        expected_rr_ratio=2.5,
        market_regime_assessment="BULL_EXPANSION",
        reasoning="Trade 1 entry",
        self_critique="None",
        invalidation_trigger_desc="Below 24.00",
        memory_alignment_check="ALIGNED",
        prompt_hash="h1",
    )
    daemon.ai_brain.record_episodic_entry(
        slot_id=1,
        coin="HYPE/USDC",
        cloid="0xcloid1",
        oid=8001,
        market_regime_4h="BULL_TREND",
        trend_alignment_1h="BULLISH",
        bbo_spread_bps=2.0,
        perp_funding_rate_hr=0.0,
        perp_oi_delta_15m_pct=0.0,
        perp_premium_pct=0.0,
        decision=dec1,
        order_sz=1.0,
        notional_usdc=25.0,
        episode_id="ep_trade_1",
        timestamp_ms=ts + 1_000,
    )

    snap_trade1 = {
        "slot_id": 1,
        "state": SlotState.OPEN_PROTECTED.value,
        "coin": "HYPE/USDC",
        "base_asset": "HYPE",
        "entry_px": 25.0,
        "current_sz": 1.0,
        "sl_px": 24.0,
        "tp_px": 27.0,
        "active_cloid": "0xcloid1",
        "active_oid": 8001,
        "order_created_at_ms": ts + 1_000,
        "episode_id": "ep_trade_1",
        "mutation_epoch": 2,
    }
    res1 = daemon._finalize_position_exit(
        slot_id=1,
        slot_snapshot=snap_trade1,
        exit_px=26.0,
        exit_reason="TAKE_PROFIT_HIT",
        timestamp_ms=ts + 10_000,
        exit_oid=8101,
    )
    assert res1.get("already_finalized") is not True
    assert db.get_system_state()["daily_trade_count"] == 1

    # --- Trade #2: episode_id が None かつ order_created_at_ms が 0 の別トレード ---
    # 過去の ai_episodic_memory ("ep_trade_1") を誤って引き継いでスキップされることなく正常に決済処理されること
    snap_trade2 = {
        "slot_id": 1,
        "state": SlotState.OPEN_PROTECTED.value,
        "coin": "HYPE/USDC",
        "base_asset": "HYPE",
        "entry_px": 25.5,
        "current_sz": 1.0,
        "sl_px": 24.5,
        "tp_px": 27.5,
        "active_cloid": "0xcloid2",
        "active_oid": 8002,
        "order_created_at_ms": 0,
        "episode_id": None,
        "mutation_epoch": 5,
    }
    res2 = daemon._finalize_position_exit(
        slot_id=1,
        slot_snapshot=snap_trade2,
        exit_px=24.4,
        exit_reason="STOP_LOSS_HIT",
        timestamp_ms=ts + 20_000,
        exit_oid=8102,
    )
    assert res2.get("already_finalized") is not True
    assert db.get_system_state()["daily_trade_count"] == 2
    assert db.get_system_state()["consecutive_losses"] == 1

    # --- Trade #3: episode_id が "0" かつ active_cloid/active_oid/order_created_at_ms も 0/空 の極端ケース ---
    snap_trade3 = {
        "slot_id": 1,
        "state": SlotState.OPEN_PROTECTED.value,
        "coin": "HYPE/USDC",
        "base_asset": "HYPE",
        "entry_px": 25.0,
        "current_sz": 1.0,
        "sl_px": 24.0,
        "tp_px": 27.0,
        "active_cloid": "",
        "active_oid": 0,
        "order_created_at_ms": 0,
        "episode_id": "0",
        "mutation_epoch": 9,
    }
    res3 = daemon._finalize_position_exit(
        slot_id=1,
        slot_snapshot=snap_trade3,
        exit_px=26.5,
        exit_reason="TAKE_PROFIT_HIT",
        timestamp_ms=ts + 30_000,
        exit_oid=8103,
    )
    assert res3.get("already_finalized") is not True
    assert db.get_system_state()["daily_trade_count"] == 3
    assert db.get_system_state()["consecutive_losses"] == 0

    # 同一 Trade #3 が同一タイムスタンプ・エポックで再呼び出しされた場合は確実にべき等ブロックされること
    res3_dup = daemon._finalize_position_exit(
        slot_id=1,
        slot_snapshot=snap_trade3,
        exit_px=26.5,
        exit_reason="TAKE_PROFIT_HIT",
        timestamp_ms=ts + 30_000,
        exit_oid=8103,
    )
    assert res3_dup.get("already_finalized") is True
    assert db.get_system_state()["daily_trade_count"] == 3

    conn = db._get_connection()
    refl_cnt = conn.execute("SELECT COUNT(*) AS cnt FROM ai_reflection_memory").fetchone()["cnt"]
    assert int(refl_cnt) == 3
    db.close()


# ==============================================================================
# 3. L2 / L3 / L4 クールダウン満了時の SQLite 永続化 & プロセス再起動耐性監査
# ==============================================================================
def test_round7_item3_l2_l3_l4_cooldown_expiry_sqlite_persistence_across_engine_restarts(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r7_item3.db", initial_equity_usdc=143.73)
    rg1 = RiskAndCircuitBreakerEngine(db=db)
    base_ts = 1_780_200_000_000

    rg1.evaluate_circuit_breakers(
        equity_usdc=143.73,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=base_ts,
    )

    # --- 1) L2 が「2連敗 + 日次DD -2.0% (140.85 USDC)」の両方で発動したケース ---
    with db.immediate_transaction() as tx:
        tx.execute("UPDATE system_state_store SET consecutive_losses = 2 WHERE id = 1")

    cb_l2_on = rg1.evaluate_circuit_breakers(
        equity_usdc=140.85,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=base_ts + 15_000,
    )
    assert cb_l2_on["l2_active"] is True
    l2_until = int(db.get_system_state()["l2_active_until_ms"])
    assert l2_until == base_ts + 15_000 + 6 * 3_600_000

    # 6時間経過して L2 満了
    t_l2_exp = l2_until + 1_000
    cb_l2_exp = rg1.evaluate_circuit_breakers(
        equity_usdc=140.85,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=t_l2_exp,
    )
    assert cb_l2_exp["l2_active"] is False
    assert cb_l2_exp["consecutive_losses"] == 0
    assert cb_l2_exp["l2_active_until_ms"] == 0

    # SQLite DB 自体にリセット値 (l2_active_until_ms=0, consecutive_losses=0, sod_equity_usdc=140.85) が保存されているか確認
    sys_after_l2 = db.get_system_state()
    assert int(sys_after_l2["l2_active_until_ms"]) == 0
    assert int(sys_after_l2["consecutive_losses"]) == 0
    assert float(sys_after_l2["sod_equity_usdc"]) == pytest.approx(140.85)

    # プロセス再起動を模擬して「新しい RiskAndCircuitBreakerEngine インスタンス」を生成し、
    # 15秒後に同じ資産 140.85 USDC で評価しても L2 が再発火しないことを検証!
    rg_restarted = RiskAndCircuitBreakerEngine(db=db)
    cb_after_restart = rg_restarted.evaluate_circuit_breakers(
        equity_usdc=140.85,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=t_l2_exp + 15_000,
    )
    assert cb_after_restart["l2_active"] is False
    assert cb_after_restart["risk_per_trade_pct"] == pytest.approx(0.020)

    # --- 2) L3 (-3.2%) & L4 (-6.5%) 満了ティックに in_quiescence=True / price_tainted_flag=True が重なった場合 ---
    t_l3_base = t_l2_exp + 60_000
    for i in range(3):
        cb_l3 = rg_restarted.evaluate_circuit_breakers(
            equity_usdc=131.00,  # 140.85 比 -6.99%, 初期 143.73 比 -8.85% -> L3 & L4 発動
            price_tainted_flag=False,
            in_quiescence=False,
            current_time_ms=t_l3_base + i * 15_000,
        )
    assert cb_l3["l3_active"] is True
    assert cb_l3["l4_active"] is True

    sys_l34 = db.get_system_state()
    max_until = max(int(sys_l34["l3_active_until_ms"]), int(sys_l34["l4_active_until_ms"]))
    t_l34_exp = max_until + 5_000

    # 満了ティックでたまたま in_quiescence=True かつ price_tainted_flag=True だった場合
    cb_exp_quiescence = rg_restarted.evaluate_circuit_breakers(
        equity_usdc=131.00,
        price_tainted_flag=True,
        in_quiescence=True,
        current_time_ms=t_l34_exp,
    )
    assert cb_exp_quiescence["l3_active"] is False
    assert cb_exp_quiescence["l4_active"] is False

    # DB の sod_equity_usdc と sow_equity_usdc が 131.00 に更新されていること
    sys_reanchored = db.get_system_state()
    assert int(sys_reanchored["l3_active_until_ms"]) == 0
    assert int(sys_reanchored["l4_active_until_ms"]) == 0
    assert float(sys_reanchored["sod_equity_usdc"]) == pytest.approx(131.00)
    assert float(sys_reanchored["sow_equity_usdc"]) == pytest.approx(131.00)

    # さらに別インスタンス (再起動模擬) で通常ティックを3回連続実行しても L3 / L4 が再ロックされないこと
    rg_restarted2 = RiskAndCircuitBreakerEngine(db=db)
    for j in range(1, 4):
        cb_norm = rg_restarted2.evaluate_circuit_breakers(
            equity_usdc=131.00,
            price_tainted_flag=False,
            in_quiescence=False,
            current_time_ms=t_l34_exp + j * 15_000,
        )
        assert cb_norm["l3_active"] is False
        assert cb_norm["l4_active"] is False
        assert cb_norm["new_buy_allowed"] is True

    db.close()


# ==============================================================================
# 4. 200msガーディアン・15秒制御・15分AIレーダー・Webサーバーの横断整合性監査
# ==============================================================================
def test_round7_item4_cross_module_consistency_and_full_daemon_cycle(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r7_item4.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    mock_info = MockHLInfo("0x0")
    mock_ex = MockHLExchange(mock_info)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=mock_info,
        exchange_client=mock_ex,
    )
    wrapper.refresh_universe_mapping()
    ai_brain = DebiasedAIBrain(db=db, use_live_llm=False)
    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=wrapper,
        ai_brain=ai_brain,
    )

    ts = 1_780_300_000_000
    ctrl1 = daemon.run_15s_control_tick(current_time_ms=ts)
    assert ctrl1["fencing_valid"] is True
    assert coord._held_levels() == []

    guard1 = daemon.run_200ms_guardian_tick(current_time_ms=ts + 200)
    assert guard1["actions"] == []
    assert coord._held_levels() == []

    radar1 = daemon.run_15m_ai_radar_tick(candidate_pairs=["HYPE/USDC"], current_time_ms=ts + 1_000)
    assert radar1["status"] in ("ORDER_PLACED", "EVALUATED_NO_ORDER", "SKIPPED")
    assert coord._held_levels() == []

    db.close()
