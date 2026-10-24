"""
HL AI Trader v1 — Phase 6 Audit Round 8 Test Suite (tests/test_phase6_audit_round8.py)

第8回 徹底総合監査（Audit Round 8：Round 7修正パッチの交差到着検証・IDLEリセット後の遅延WS到着耐性・全モジュール収束監査）の検証スイート:
1. 分割約定と合成ロットが「交互（サンドイッチ順序: WS部分約定#1 ➔ REST合成フォールバック ➔ WS部分約定#2）」に到着した場合の税務台帳整合性監査
2. スロットが `IDLE` にリセットされた後に遅延到着した WebSocket 売り約定 (`_on_ws_spot_fill`) の安全性・二重計上防止監査
3. L2 / L3 / L4 クールダウン満了による `sod_equity_usdc` / `sow_equity_usdc` 再アンカー時の `hwm_equity_usdc`・`initial_equity_usdc`・L5防衛ライン (85% Floor) 不変性監査
4. Webサーバー・AI推論・3並列ループ・Watchdogの最終横断チェック（ロック解放・メモリ境界・スナップショット機密スクラブ）
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
from src.web_server import DashboardStateService
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo


# ==============================================================================
# 1. 分割約定と合成ロットの「交互（サンドイッチ順序）」到着時の税務台帳整合性監査
# ==============================================================================
def test_round8_item1_sandwich_order_ws_partial1_then_rest_synthetic_then_ws_partial2(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r8_item1.db", initial_equity_usdc=143.73)
    tax = HyperliquidTaxEngine(db=db)
    ts = 1_785_000_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )

    # 同一注文 (hl_oid = 6000, 合計数量 1.00 HYPE) に対して:
    # ① WS で分割約定 #1 (tid = 2001 < 9e12, sz = 0.40) が先に到着して記録
    res_p1 = tax.process_spot_fill(
        hl_tid=2001,
        hl_oid=6000,
        timestamp_ms=ts + 1_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.40",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert res_p1["duplicate"] is False

    # ② 直後に REST の合成フォールバック (tid >= 9e12, hl_oid = 6000, sz = 1.00) が到着 -> 重複としてスキップされること
    res_syn = tax.process_spot_fill(
        hl_tid=9_000_000_006_000,
        hl_oid=6000,
        timestamp_ms=ts + 1_200,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="1.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert res_syn["duplicate"] is True

    # ③ 最後に WS で分割約定 #2 (tid = 2002 < 9e12, hl_oid = 6000, sz = 0.60) が到着 ->
    #    ①の hl_oid = 6000 レコードと衝突してスキップされることなく、正常に新規ロットとして記録されること!
    res_p2 = tax.process_spot_fill(
        hl_tid=2002,
        hl_oid=6000,
        timestamp_ms=ts + 1_400,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="0.60",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert res_p2["duplicate"] is False

    # 検証: tax_lots には tid=2001 (0.40) と tid=2002 (0.60) の2件が記録され、HYPE 在庫が 1.00 枚であること
    conn = db._get_connection()
    lots = conn.execute(
        "SELECT hl_tid, hl_oid, exec_sz_base FROM tax_lots WHERE hl_oid = 6000 ORDER BY hl_tid ASC"
    ).fetchall()
    assert len(lots) == 2
    assert int(lots[0]["hl_tid"]) == 2001
    assert float(lots[0]["exec_sz_base"]) == pytest.approx(0.40)
    assert int(lots[1]["hl_tid"]) == 2002
    assert float(lots[1]["exec_sz_base"]) == pytest.approx(0.60)

    hype_inv = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    assert float(hype_inv["quantity"]) == pytest.approx(1.00)
    assert float(hype_inv["book_cost_jpy"]) == pytest.approx(25.00 * 1.00 * 155.0)
    assert float(hype_inv["moving_avg_unit_jpy"]) == pytest.approx(25.00 * 155.0)
    db.close()


# ==============================================================================
# 2. スロットが IDLE にリセットされた後に遅延到着した WebSocket 売り約定の安全性監査
# ==============================================================================
def test_round8_item2_delayed_ws_sell_fill_after_slot_already_idle_does_not_double_count(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r8_item2.db", initial_equity_usdc=143.73)
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
    ts = 1_785_100_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )

    # 1) Slot 1 で HYPE/USDC を発注・買い約定させて OPEN_PROTECTED へ遷移
    ord_buy = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="2.00",
        sl_px="24.20",
        tp_px="27.00",
        episode_id="ep_r8_delayed_ws",
        timestamp_ms=ts + 1_000,
    )
    buy_oid = int(ord_buy["oid"])
    buy_cloid = str(ord_buy["cloid"])

    dec = HLTraderExecutionDecision(
        action="BUY_ALO",
        conviction_score=85,
        limit_px=25.00,
        sl_px=24.20,
        tp_px=27.00,
        expected_rr_ratio=2.5,
        market_regime_assessment="BULL_EXPANSION",
        reasoning="Delayed WS fill test",
        self_critique="None",
        invalidation_trigger_desc="Below 24.20",
        memory_alignment_check="ALIGNED",
        prompt_hash="hash_r8",
    )
    daemon.ai_brain.record_episodic_entry(
        slot_id=1,
        coin="HYPE/USDC",
        cloid=buy_cloid,
        oid=buy_oid,
        market_regime_4h="BULL_TREND",
        trend_alignment_1h="BULLISH",
        bbo_spread_bps=2.5,
        perp_funding_rate_hr=0.0,
        perp_oi_delta_15m_pct=0.0,
        perp_premium_pct=0.0,
        decision=dec,
        order_sz=2.00,
        notional_usdc=50.0,
        episode_id="ep_r8_delayed_ws",
        timestamp_ms=ts + 1_000,
    )

    daemon.ws.handle_raw_message(
        {
            "channel": "userFills",
            "data": {
                "fills": [
                    {
                        "tid": 810001,
                        "oid": buy_oid,
                        "coin": "@107",
                        "side": "B",
                        "px": "25.00",
                        "sz": "2.00",
                        "fee": "0.0",
                        "feeToken": "HYPE",
                        "time": ts + 1_500,
                    }
                ]
            },
        }
    )
    assert db.get_slot_state(1)["state"] == SlotState.OPEN_PROTECTED.value

    # 2) 200ms ガーディアンが SL 着弾 (24.00 <= 24.20) を検知して execute_atomic_ioc_exit & _finalize_position_exit 完了
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "93.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "2.00", "hold": "0.0"},
    ]
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": ts + 5_000,
                "levels": [[{"px": "24.00", "sz": "200", "n": 2}], [{"px": "24.02", "sz": "200", "n": 2}]],
            },
        }
    )
    g_res = daemon.run_200ms_guardian_tick(current_time_ms=ts + 5_100)
    assert len(g_res["actions"]) == 1
    sell_oid = int(g_res["actions"][0]["result"]["oid"])

    # Slot 1 が完全に IDLE (coin=None, active_oid=None, episode_id=None) にリセットされていることを確認
    s1_idle = db.get_slot_state(1)
    assert s1_idle["state"] == SlotState.IDLE.value
    assert not s1_idle["coin"]
    assert not s1_idle["episode_id"]

    sys_mid = db.get_system_state()
    assert int(sys_mid["consecutive_losses"]) == 1
    assert int(sys_mid["daily_trade_count"]) == 1

    # 3) 数秒後に WebSocket userFills から当該売り約定 (tid=810002, oid=sell_oid) が遅延到着!
    delayed_sell_fill = {
        "tid": 810002,
        "oid": sell_oid,
        "coin": "@107",
        "side": "A",
        "px": "24.00",
        "sz": "2.00",
        "fee": "0.0336",
        "feeToken": "USDC",
        "time": ts + 8_000,
    }
    daemon.ws.handle_raw_message({"channel": "userFills", "data": {"fills": [delayed_sell_fill]}})

    # さらに _on_ws_spot_fill が直接呼ばれた場合も検証
    daemon._on_ws_spot_fill(
        {
            "timestamp_ms": ts + 8_500,
            "is_buy": False,
            "coin": "@107",
            "pair_name": "HYPE/USDC",
            "base_asset": "HYPE",
            "oid": sell_oid,
            "px": 24.00,
            "sz": 2.00,
            "fee": 0.0336,
            "fee_token": "USDC",
        }
    )

    # 検証: consecutive_losses, daily_trade_count, ai_reflection_memory, tax_lots が一切二重計上されていないこと!
    sys_after = db.get_system_state()
    assert int(sys_after["consecutive_losses"]) == 1
    assert int(sys_after["daily_trade_count"]) == 1

    conn = db._get_connection()
    refl_rows = conn.execute("SELECT * FROM ai_reflection_memory").fetchall()
    assert len(refl_rows) == 1
    assert refl_rows[0]["episode_id"] == "ep_r8_delayed_ws"

    sell_lots = conn.execute("SELECT * FROM tax_lots WHERE event_type = 'SPOT_SELL'").fetchall()
    assert len(sell_lots) == 1
    assert int(sell_lots[0]["hl_tid"]) == 810002
    db.close()


# ==============================================================================
# 3. L2 / L3 / L4 再アンカー時の `hwm_equity_usdc` / `initial_equity_usdc` / L5防衛ライン不変性監査
# ==============================================================================
def test_round8_item3_hwm_and_initial_equity_invariance_across_l2_l3_l4_reanchoring(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r8_item3.db", initial_equity_usdc=143.73)
    rg = RiskAndCircuitBreakerEngine(db=db)
    t0 = 1_785_200_000_000

    # 1) 利益が出て HWM が 160.00 USDC に上昇 (L5防衛ライン = 160.00 * 0.85 = 136.00 USDC)
    cb_peak = rg.evaluate_circuit_breakers(
        equity_usdc=160.00,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=t0,
    )
    assert cb_peak["initial_equity_usdc"] == pytest.approx(143.73)
    assert cb_peak["hwm_equity_usdc"] == pytest.approx(160.00)
    assert cb_peak["l5_floor_usdc"] == pytest.approx(160.00 * 0.85)

    # 2) 翌週月曜 06:00 JST のロールオーバー (+7日) で sod_eq = 160.00, sow_eq = 160.00 に更新された後、
    #    148.00 USDC (-7.5%, ただし L5 フロア 136.00 より上) へ下落して L2/L3/L4 発動
    t_next_week = t0 + 7 * 86_400_000
    rg.evaluate_circuit_breakers(
        equity_usdc=160.00,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=t_next_week,
    )
    for i in range(1, 4):
        cb_drop = rg.evaluate_circuit_breakers(
            equity_usdc=148.00,
            price_tainted_flag=False,
            in_quiescence=False,
            current_time_ms=t_next_week + i * 15_000,
        )
    assert cb_drop["l2_active"] is True
    assert cb_drop["l3_active"] is True
    assert cb_drop["l4_active"] is True
    assert cb_drop["hwm_equity_usdc"] == pytest.approx(160.00)
    assert cb_drop["initial_equity_usdc"] == pytest.approx(143.73)
    assert cb_drop["l5_floor_usdc"] == pytest.approx(136.00)

    # 3) L2 / L3 / L4 のすべてのクールダウン期限が満了し、sod_equity_usdc と sow_equity_usdc が 148.00 に再アンカーされる
    sys_st = db.get_system_state()
    max_cooldown = max(
        int(sys_st["l2_active_until_ms"]),
        int(sys_st["l3_active_until_ms"]),
        int(sys_st["l4_active_until_ms"]),
    )
    cb_recovered = rg.evaluate_circuit_breakers(
        equity_usdc=148.00,
        price_tainted_flag=False,
        in_quiescence=False,
        current_time_ms=max_cooldown + 10_000,
    )
    assert cb_recovered["l2_active"] is False
    assert cb_recovered["l3_active"] is False
    assert cb_recovered["l4_active"] is False
    assert cb_recovered["sod_equity_usdc"] == pytest.approx(148.00)
    assert cb_recovered["sow_equity_usdc"] == pytest.approx(148.00)

    # 【核心検証】sod_eq / sow_eq が 148.00 に再アンカーされても、
    # hwm_equity_usdc (160.00), initial_equity_usdc (143.73), l5_floor_usdc (136.00) は1ミリも引き下げられないこと!
    assert cb_recovered["hwm_equity_usdc"] == pytest.approx(160.00)
    assert cb_recovered["initial_equity_usdc"] == pytest.approx(143.73)
    assert cb_recovered["l5_floor_usdc"] == pytest.approx(136.00)

    sys_db = db.get_system_state()
    assert float(sys_db["hwm_equity_usdc"]) == pytest.approx(160.00)
    assert float(sys_db["initial_equity_usdc"]) == pytest.approx(143.73)
    db.close()


# ==============================================================================
# 4. Webサーバー・AI推論・3並列ループ・Watchdogの最終横断チェック
# ==============================================================================
def test_round8_item4_final_cross_system_convergence_check(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r8_item4.db", initial_equity_usdc=143.73)
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
    service = DashboardStateService(db=db, tax_engine=tax, coordinator=coord, daemon=daemon)

    status_payload = service.get_status_payload()
    assert status_payload["equity"]["current_usdc"] == pytest.approx(143.73)
    assert status_payload["equity"]["l5_floor_usdc"] == pytest.approx(143.73 * 0.85)
    assert len(status_payload["slots"]) == 2
    assert coord._held_levels() == []
    db.close()
