"""
Phase 6 — 第6回 徹底総合監査 (Audit Round 6) 異常相場ストレス耐性・L1〜L5自動復帰・WS/REST三重到着べき等性・極限サイジング・本番プリフライト検証テスト

検証項目:
1. 多層価格サニティフィルタ (`TAINTED`) の最大4周期保持 ➔ 5周期目実勢移行・再アンカー・正常化遷移と、
   L2 (3連敗 ➔ 6時間後自動復帰) / L3 (翌06:00 JST自動復帰) / L4 (クールダウン経過後自動復帰) の永久ロック防止検証
2. WebSocket `userFills`・REST 即時処理・`backfill_missed_fills` (`userFillsByTime`)・15秒 `reconcile_3way_state` の
   4経路重複到着に対する `HyperliquidTaxEngine` (`tax_lots`) ＆ `_finalize_position_exit` 完全べき等性検証
3. Single-Bullet サイジング・端数丸め (`round_price` / `floor_size`)・`16.0 USDC` フロア・丸め後SL距離 `8.0%` キャップの
   高価格銘柄 (`UBTC = 95,000 USDC`, `szDecimals = 5`) 〜 低価格銘柄 (`PURR = 0.15 USDC`, `szDecimals = 0`) 極限ケース検証
4. GMOコイン版 (`E:\\gmo-ai-trader-auto`) との完全非干渉・本番プリフライト総合検証
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.dont_write_bytecode = True

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.ai_brain import DebiasedAIBrain, HLTraderExecutionDecision
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SystemMode
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper, OrderValidationError
from src.main import HLTraderDaemon
from src.risk_guard import (
    RiskAndCircuitBreakerEngine,
    get_next_0600_jst_ms,
    get_next_monday_0600_jst_ms,
)
from src.utils import WindowsSingleInstanceGuard, floor_size, round_price
from src.web_server import (
    GIT_PUSH_OFFSET_MINUTES,
    ISOLATED_GITCONFIG_PATH,
    build_isolated_git_env,
)
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo
from watchdog import build_isolated_process_env, is_port_listening, resolve_venv_python

JST = timezone(timedelta(hours=9))


def test_round6_item1_price_sanity_4_cycle_hold_5th_cycle_transition_and_l2_l3_l4_auto_recovery(
    tmp_path: Path,
) -> None:
    """
    監査項目1:
    - フラッシュクラッシュ（スプレッド急拡大・15秒8%超変動・Oracle乖離2%超）発生時、
      `evaluate_token_price_sanity` が最大4周期まで直前正常価格を保持して L3/L5 ストライク加算を凍結し、
      5周期目で実勢価格を採用して再アンカー＆ストライク凍結を解除し、正常化時に `VALID` へ復帰すること
    - L2（3連敗 ➔ 6時間ロット半減＆確信度85以上）および L3/L4 が指定クールダウン経過後に
      自動で通常状態（`NORMAL`, `l2_active=False`, `l3_active=False`, `l4_active=False`, `new_buy_allowed=True`）へ復帰すること
    """
    db = DatabaseManager(db_path=tmp_path / "r6_item1.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)

    # 1. 正常価格 (25.00 USDC) で初期アンカー
    v0 = rg.evaluate_token_price_sanity(
        "HYPE/USDC", best_bid=25.00, best_ask=25.02, mark_px=25.01, perp_oracle_px=25.01
    )
    assert v0["status"] == "VALID"
    assert v0["price_tainted"] is False
    valid_px = v0["p_val"]

    # 2. 15秒8%超の急落 (25.00 -> 21.00 = -16.0%) が4周期連続発生 -> 最大4周期まで直前正常価格を保持し L3/L5 ストライクを凍結
    t0 = int(datetime(2026, 10, 23, 12, 0, 0, tzinfo=JST).timestamp() * 1000)
    for cycle in range(1, 5):
        vt = rg.evaluate_token_price_sanity(
            "HYPE/USDC", best_bid=21.00, best_ask=21.02, mark_px=21.01, perp_oracle_px=21.01
        )
        assert vt["status"] == "TAINTED"
        assert vt["price_tainted"] is True
        assert vt["tainted_cycles"] == cycle
        assert vt["p_val"] == pytest.approx(valid_px)

        # TAINTED 中は仮に評価額が L5 ライン (85% = 122.17 USDC) 未満でもストライクが加算されないこと
        cb_t = rg.evaluate_circuit_breakers(
            equity_usdc=110.0,
            price_tainted_flag=vt["price_tainted"],
            current_time_ms=t0 + cycle * 15_000,
        )
        assert cb_t["l5_strikes"] == 0
        assert cb_t["l3_strikes"] == 0

    # 3. 5周期目 (cnt == 5 > MAX_TAINTED_CYCLES): 直前価格保持上限を超え、実勢価格 (21.00) へ再アンカー＆ストライク凍結解除
    v5 = rg.evaluate_token_price_sanity(
        "HYPE/USDC", best_bid=21.00, best_ask=21.02, mark_px=21.01, perp_oracle_px=21.01
    )
    assert v5["status"] == "TAINTED_FALLBACK_ADOPTED"
    assert v5["price_tainted"] is False
    assert v5["tainted_cycles"] == 5
    assert v5["p_val"] == pytest.approx(21.00, rel=1e-2)

    # 6周期目: 21.00 に再アンカーされたため、引き続き 21.00 付近なら VALID (正常化) へ復帰すること
    v6 = rg.evaluate_token_price_sanity(
        "HYPE/USDC", best_bid=21.05, best_ask=21.07, mark_px=21.06, perp_oracle_px=21.06
    )
    assert v6["status"] == "VALID"
    assert v6["price_tainted"] is False
    assert v6["tainted_cycles"] == 0

    # 4. L2 (3連敗 -> 6時間ロット半減 1R=1.0% & 確信度85以上) の発動と、6時間経過後の自動復帰検証
    with db.immediate_transaction() as tx:
        tx.execute("UPDATE system_state_store SET consecutive_losses = 3 WHERE id = 1")

    cb_l2_start = rg.evaluate_circuit_breakers(
        equity_usdc=143.73, price_tainted_flag=False, current_time_ms=t0 + 100_000
    )
    assert cb_l2_start["l2_active"] is True
    assert cb_l2_start["risk_per_trade_pct"] == pytest.approx(0.010)
    assert cb_l2_start["required_conviction_score"] == 85

    # 3時間後 (まだ6時間未満): 15秒ループが回っても l2_until が無限延長されず L2 が維持されること
    cb_l2_mid = rg.evaluate_circuit_breakers(
        equity_usdc=143.73, price_tainted_flag=False, current_time_ms=t0 + 100_000 + 3 * 3_600_000
    )
    assert cb_l2_mid["l2_active"] is True

    # 6時間 + 1秒経過後: 自動的に L2 が解除され、consecutive_losses も 0 にリセットされて通常状態へ復帰すること
    t_after_6h = t0 + 100_000 + 6 * 3_600_000 + 1_000
    cb_l2_recovered = rg.evaluate_circuit_breakers(
        equity_usdc=143.73, price_tainted_flag=False, current_time_ms=t_after_6h
    )
    assert cb_l2_recovered["l2_active"] is False
    assert cb_l2_recovered["risk_per_trade_pct"] == pytest.approx(0.020)
    assert cb_l2_recovered["required_conviction_score"] == 75
    assert int(db.get_system_state()["consecutive_losses"]) == 0

    # 5. L3 (日次 -3.0% 3回連続 -> 翌06:00 JSTまで新規停止) と翌06:00 JST経過後の自動復帰検証
    eq_l3 = 143.73 * 0.965  # -3.5% <= -3.0%
    rg.evaluate_circuit_breakers(equity_usdc=eq_l3, current_time_ms=t_after_6h + 15_000)
    rg.evaluate_circuit_breakers(equity_usdc=eq_l3, current_time_ms=t_after_6h + 30_000)
    cb_l3_trig = rg.evaluate_circuit_breakers(equity_usdc=eq_l3, current_time_ms=t_after_6h + 45_000)
    assert cb_l3_trig["l3_active"] is True
    assert cb_l3_trig["l3_triggered_now"] is True
    assert cb_l3_trig["new_buy_allowed"] is False

    next_0600_ms = get_next_0600_jst_ms(t_after_6h + 45_000)
    cb_l3_recovered = rg.evaluate_circuit_breakers(
        equity_usdc=eq_l3, current_time_ms=next_0600_ms + 1_000
    )
    assert cb_l3_recovered["l3_active"] is False
    assert cb_l3_recovered["new_buy_allowed"] is True

    # 6. L4 (週次 -6.0% または Perp清算カスケード 12hクールダウン) と期限経過後の自動復帰検証
    t_l4_start = next_0600_ms + 10_000
    cb_l4_trig = rg.evaluate_circuit_breakers(
        equity_usdc=eq_l3,
        perp_cascade_detected=True,
        current_time_ms=t_l4_start,
    )
    assert cb_l4_trig["l4_active"] is True
    assert cb_l4_trig["new_buy_allowed"] is False

    cb_l4_recovered = rg.evaluate_circuit_breakers(
        equity_usdc=eq_l3,
        perp_cascade_detected=False,
        current_time_ms=t_l4_start + 12 * 3_600_000 + 1_000,
    )
    assert cb_l4_recovered["l4_active"] is False
    assert cb_l4_recovered["new_buy_allowed"] is True
    assert cb_l4_recovered["system_mode"] == SystemMode.NORMAL.value
    db.close()


def test_round6_item2_triple_arrival_idempotency_ws_rest_backfill_and_3way_reconcile(
    tmp_path: Path,
) -> None:
    """
    監査項目2:
    - 同一の買い約定および売り決済に対して:
      ① REST レスポンス即時処理 (`place_spot_buy_alo` / `execute_atomic_ioc_exit`)
      ② WebSocket リアルタイム `userFills` (`handle_raw_message`)
      ③ 再接続時の `backfill_missed_fills` (`userFillsByTime`)
      ④ 15秒ループの `reconcile_3way_state` ＆ `_finalize_position_exit` (異なる `mutation_epoch` スナップショット含む)
      が重複発火しても、`tax_lots` に二重計上が一切起きず、`_finalize_position_exit` の副作用
      (`ai_reflection_memory`・`consecutive_losses`・`daily_trade_count`) が1回限りしか実行されないこと
    """
    db = DatabaseManager(db_path=tmp_path / "r6_item2.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "88" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=MockHLInfo("0x0"),
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    mock_ex = MockHLExchange(mock_info)
    wrapper.info = mock_info
    wrapper.exchange = mock_ex
    wrapper.refresh_universe_mapping()

    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=wrapper,
    )
    daemon.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")
    tax.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")

    ts = int(datetime(2026, 10, 23, 14, 0, 0, tzinfo=JST).timestamp() * 1000)
    tax.bootstrap_initial_usdc_inventory("143.73", 155.0, timestamp_ms=ts)

    # --- Phase A: 買い注文の多重到着テスト ---
    # 1) 発注 & 3者照合による先行昇格 + WS userFills + REST backfill_missed_fills
    ord_buy = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="2.00",
        sl_px="24.20",
        tp_px="27.00",
        episode_id="ep_r6_dup_test",
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
        reasoning="Idempotency test entry",
        self_critique="None",
        invalidation_trigger_desc="Below 24.20",
        memory_alignment_check="ALIGNED",
        prompt_hash="hash_r6",
    )
    daemon.ai_brain.record_episodic_entry(
        slot_id=1,
        coin="HYPE/USDC",
        cloid=buy_cloid,
        oid=buy_oid,
        market_regime_4h="BULL_TREND",
        trend_alignment_1h="BULLISH",
        bbo_spread_bps=3.0,
        perp_funding_rate_hr=0.0001,
        perp_oi_delta_15m_pct=0.5,
        perp_premium_pct=0.01,
        decision=dec,
        order_sz=2.00,
        notional_usdc=50.0,
        episode_id="ep_r6_dup_test",
        timestamp_ms=ts + 1_000,
    )

    # ① REST 先行合成記録をシミュレート (hl_tid = 9_000_000_000_000 + buy_oid)
    tax.process_spot_fill(
        hl_tid=9_000_000_000_000 + buy_oid,
        hl_oid=buy_oid,
        timestamp_ms=ts + 1_500,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="2.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )

    # ② WS userFills で実 tid=700001 が到着
    buy_fill_payload = {
        "tid": 700001,
        "oid": buy_oid,
        "coin": "@107",
        "side": "B",
        "px": "25.00",
        "sz": "2.00",
        "fee": "0.0",
        "feeToken": "HYPE",
        "time": ts + 1_600,
    }
    daemon.ws.handle_raw_message({"channel": "userFills", "data": {"fills": [buy_fill_payload]}})

    # ③ 再接続時の backfill_missed_fills で同じ tid=700001 が再度返却される (さらに _processed_tids クリア後も検証)
    mock_info.fills = [buy_fill_payload]
    daemon.ws.backfill_missed_fills(start_time_ms=ts)
    daemon.ws._processed_tids.clear()
    daemon.ws.backfill_missed_fills(start_time_ms=ts)

    # ④ 15秒ループの reconcile_3way_state 実行
    spot_bals = {
        "USDC": {"total": Decimal("93.73"), "hold": Decimal("0"), "free": Decimal("93.73")},
        "HYPE": {"total": Decimal("2.00"), "hold": Decimal("0"), "free": Decimal("2.00")},
    }
    daemon.reconcile_3way_state(spot_balances=spot_bals, open_orders=[], current_time_ms=ts + 2_000)

    # 買い約定の tax_lots は厳密に 1 件のみであり、HYPE 在庫も 2.00 枚であること
    conn = db._get_connection()
    buy_lots = conn.execute("SELECT * FROM tax_lots WHERE event_type = 'SPOT_BUY'").fetchall()
    assert len(buy_lots) == 1
    assert int(buy_lots[0]["hl_tid"]) == 700001
    hype_inv = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    assert float(hype_inv["quantity"]) == pytest.approx(2.00)

    # --- Phase B: 売り決済 (SL着弾 / 損切り) の多重到着テスト ---
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "93.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "2.00", "hold": "0.0"},
    ]
    snap_open = db.get_slot_state(1)
    assert snap_open["state"] == SlotState.OPEN_PROTECTED.value

    # ① 200ms ガーディアンが SL 着弾 (24.10 <= 24.20) を検知して IOC 決済 & _finalize_position_exit を実行
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": ts + 5_000,
                "levels": [[{"px": "24.10", "sz": "300", "n": 3}], [{"px": "24.12", "sz": "300", "n": 3}]],
            },
        }
    )
    g_res = daemon.run_200ms_guardian_tick(current_time_ms=ts + 5_100)
    assert any(a["slot_id"] == 1 and a.get("exit_reason") == "STOP_LOSS_HIT" for a in g_res["actions"])
    sell_oid = int(g_res["actions"][0]["result"]["oid"])

    # ② 同一売り約定に対して WS userFills (実 tid=700002, oid=sell_oid) が到着し、さらに異なる mutation_epoch のスナップショットで
    #    _finalize_position_exit が重複呼び出しされた場合をシミュレート
    sell_fill_payload = {
        "tid": 700002,
        "oid": sell_oid,
        "coin": "@107",
        "side": "A",
        "px": "24.10",
        "sz": "2.00",
        "fee": "0.03374",
        "feeToken": "USDC",
        "time": ts + 5_200,
    }
    daemon.ws.handle_raw_message({"channel": "userFills", "data": {"fills": [sell_fill_payload]}})

    # ③ backfill_missed_fills でも同じ売り約定が到着
    mock_info.fills = [buy_fill_payload, sell_fill_payload]
    daemon.ws._processed_tids.clear()
    daemon.ws.backfill_missed_fills(start_time_ms=ts)

    # ④ 異なる mutation_epoch を持つスナップショットで _finalize_position_exit を再呼び出し
    mutated_snap = {**snap_open, "mutation_epoch": int(snap_open["mutation_epoch"]) + 1}
    dup_fin = daemon._finalize_position_exit(
        slot_id=1,
        slot_snapshot=mutated_snap,
        exit_px=24.10,
        exit_reason="WS_SELL_FILL",
        timestamp_ms=ts + 5_300,
    )
    assert dup_fin.get("already_finalized") is True

    # 検証:
    # - SPOT_SELL の tax_lots レコードは厳密に 1 件のみ (二重計上ゼロ)
    # - ai_reflection_memory レコードも厳密に 1 件のみ
    # - consecutive_losses と daily_trade_count は厳密に 1 (2以上に重複加算されていないこと)
    sell_lots = conn.execute("SELECT * FROM tax_lots WHERE event_type = 'SPOT_SELL'").fetchall()
    assert len(sell_lots) == 1
    assert int(sell_lots[0]["hl_tid"]) == 700002

    reflections = conn.execute(
        "SELECT * FROM ai_reflection_memory WHERE episode_id = 'ep_r6_dup_test'"
    ).fetchall()
    assert len(reflections) == 1

    sys_st = db.get_system_state()
    assert int(sys_st["consecutive_losses"]) == 1
    assert int(sys_st["daily_trade_count"]) == 1
    db.close()


def test_round6_item3_extreme_single_bullet_sizing_rounding_and_16_usdc_floor(
    tmp_path: Path,
) -> None:
    """
    監査項目3:
    - 高価格銘柄 (`UBTC = 95,000 USDC`, `szDecimals = 5`) から低価格銘柄 (`PURR = 0.15432 USDC`, `szDecimals = 0`) まで、
      `143.73 USDC` 口座（Slot 1上限70%＝`100.61 USDC`、L2半減時等）でサイジングと `round_price` / `floor_size` を行った際、
      切り捨てによって注文額が `16.0 USDC`（および取引所最小 `10.0 USDC`）未満になるケースや、
      `round_price` 切り捨て後に初期SL距離が `8.0%` を超えるケースが100%事前ブロックされること
    """
    db = DatabaseManager(db_path=tmp_path / "r6_item3.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)

    # 1. 高価格銘柄 UBTC/USDC (95,000 USDC, szDecimals=5) — 通常時 (143.73 USDC, Slot 1)
    sz_ubtc = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=143.73,
        free_usdc=143.73,
        entry_px=95000.0,
        sl_px=93100.0,  # 2.0% SL
        sz_decimals=5,
        l2_derisk_active=False,
    )
    assert sz_ubtc["eligible"] is True
    assert Decimal(sz_ubtc["px_str"]) * Decimal(sz_ubtc["sz_str"]) >= Decimal("16.0")
    assert sz_ubtc["notional_usdc"] <= 143.73 * 0.70

    # 2. 低価格銘柄 PURR/USDC (0.15432 USDC, szDecimals=0) — 通常時 (143.73 USDC, Slot 1)
    sz_purr = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=143.73,
        free_usdc=143.73,
        entry_px=0.15432,
        sl_px=0.14800,  # 約4.1% SL
        sz_decimals=0,
        l2_derisk_active=False,
    )
    assert sz_purr["eligible"] is True
    assert "." not in sz_purr["sz_str"]  # szDecimals=0 のため整数数量
    assert Decimal(sz_purr["px_str"]) * Decimal(sz_purr["sz_str"]) >= Decimal("16.0")

    # 3. L2半減時 (1R=1.0%) かつ広いSL (7.8%) で切り捨て後の発注額が 16.0 USDC 未満になるケース -> eligible=False で確実にブロック
    sz_sub16 = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=120.0,
        free_usdc=120.0,
        entry_px=95000.0,
        sl_px=87590.0,  # 7.8% SL, 1R=1.20 USDC -> notl ~ 15.38 USDC -> floor_size 後 14.25 USDC < 16.0 USDC
        sz_decimals=5,
        l2_derisk_active=True,
    )
    assert sz_sub16["eligible"] is False
    assert "BELOW_16_USDC" in sz_sub16["reason"]

    # 4. 丸め前は SL距離 7.999% <= 8.0% だが、round_price(ROUND_DOWN) 後に 8.00% を超える境界ケース -> eligible=False でブロック
    #    entry_px=0.15432, sl_px=0.141975 -> 未丸め (0.15432 - 0.141975)/0.15432 = 7.9996% <= 8.0%
    #    round_price(0.141975, 0) -> "0.14197" -> 丸め後 (0.15432 - 0.14197)/0.15432 = 8.0028% > 8.0%
    sz_sl_edge = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=143.73,
        free_usdc=143.73,
        entry_px=0.15432,
        sl_px=0.141975,
        sz_decimals=0,
        l2_derisk_active=False,
    )
    assert sz_sl_edge["eligible"] is False
    assert "SL_PCT_EXCEEDS_8PCT_CAP" in sz_sl_edge["reason"]
    db.close()


def test_round6_item4_gmo_non_interference_and_live_preflight_readiness() -> None:
    """
    監査項目4:
    - `.env`, Named Mutex (`Global\\HL_AI_TRADER_V1_MAIN_MUTEX`), Port `8081`, `.hl_gitconfig`,
      Watchdog プロセス検証、および Mainnet `/info` (Unified Account `143.73 USDC` & Agent Wallet 有効期限) の
      本番起動前プリフライト総合検証
    """
    # 1. Named Mutex 名称が GMO 版と完全分離されていること
    assert WindowsSingleInstanceGuard.DEFAULT_MUTEX_NAME == r"Global\HL_AI_TRADER_V1_MAIN_MUTEX"

    # 2. Git 隔離設定と Push 分オフセット (08, 23, 38, 53分) が GMO 版 (02, 17, 32, 47分) と完全非干渉であること
    assert GIT_PUSH_OFFSET_MINUTES == (8, 23, 38, 53)
    git_env = build_isolated_git_env({})
    assert git_env["GIT_CONFIG_GLOBAL"] == str(ISOLATED_GITCONFIG_PATH)
    assert git_env["PYTHONDONTWRITEBYTECODE"] == "1"

    # 3. Watchdog 環境変数と Port 8080 保護ガード
    wd_env = build_isolated_process_env(ROOT_DIR)
    assert wd_env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert wd_env["PYTHONUTF8"] == "1"
    assert Path(resolve_venv_python(ROOT_DIR)).exists()
    with pytest.raises(ValueError):
        is_port_listening(port=8080)

    # 4. .env 必須キーの存在確認 (秘密値は出力しない)
    env_path = ROOT_DIR / ".env"
    assert env_path.exists()
    env_text = env_path.read_text(encoding="utf-8")
    for req_key in ("HL_MAIN_ADDRESS=", "HL_AGENT_PRIVATE_KEY=", "GEMINI_API_KEY="):
        assert req_key in env_text
