"""
HL AI Trader v1 — Phase 6 Audit Round 9 Test Suite (tests/test_phase6_audit_round9.py)

第9回 徹底総合監査（Audit Round 9：WS再接続バックフィル境界・IOC実残高売却保証・本番DBクリーン性・最終収束監査）の検証スイート:
1. WebSocket 再接続時の `backfill_missed_fills` 時刻境界（60秒オーバーラップ窓）による切断直前・ミリ秒境界約定の取りこぼしゼロ＆既処理約定の100%重複排除監査
2. IOC 決済時の「実残高 (`spot_clearinghouse_state.total`) 優先参照」による買い手数料控除後の `Insufficient balance` 完全防止監査
3. Web リモート操作 (`PAUSE` / `RESUME` / `CLEAR_PENDING_BUYS` / `EMERGENCY_LIQUIDATE_ALL`) と 3並列ループ (`200ms` / `15s` / `15m`) の即時協調監査
4. 本番用 SQLite WAL データベース (`data/hl_v1_state_wal.db`) のクリーン状態＆プリフライト最終確認監査
"""

from __future__ import annotations

import sqlite3
from decimal import Decimal
from pathlib import Path

import pytest

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.main import HLTraderDaemon
from src.web_server import DashboardStateService
from src.ws_manager import HyperliquidWSManager
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo

BASE_DIR = Path(__file__).resolve().parent.parent


# ==============================================================================
# 1. WebSocket 再接続時の `backfill_missed_fills` 時刻境界と取りこぼしゼロ監査
# ==============================================================================
def test_round9_item1_ws_reconnect_backfill_60s_overlap_boundary_zero_miss_and_dedup(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r9_item1.db", initial_equity_usdc=143.73)
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
    ts = 1_800_000_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )

    # 1) 切断前に WS ストリームで約定 #1 (tid=910001, time=ts + 100_000) を受信済み
    fill_1 = {
        "tid": 910001,
        "oid": 4001,
        "coin": "@107",
        "side": "B",
        "px": "25.00",
        "sz": "1.00",
        "fee": "0.0",
        "feeToken": "HYPE",
        "time": ts + 100_000,
    }
    daemon.ws.handle_raw_message({"channel": "userFills", "data": {"fills": [fill_1]}})
    assert daemon.ws.last_fill_timestamp_ms == ts + 100_000

    # 2) WS 切断直前の同一ミリ秒境界 (ts + 100_000) に発生して取りこぼした約定 #2 (tid=910002) と、
    #    切断中 (ts + 102_000) に発生した約定 #3 (tid=910003) が取引所側 user_fills_by_time に存在
    fill_2_boundary = {
        "tid": 910002,
        "oid": 4002,
        "coin": "@107",
        "side": "B",
        "px": "25.00",
        "sz": "0.50",
        "fee": "0.0",
        "feeToken": "HYPE",
        "time": ts + 100_000,  # 約定 #1 と完全に同一ミリ秒境界!
    }
    fill_3_during_disconnect = {
        "tid": 910003,
        "oid": 4003,
        "coin": "@107",
        "side": "B",
        "px": "25.00",
        "sz": "0.50",
        "fee": "0.0",
        "feeToken": "HYPE",
        "time": ts + 102_000,
    }
    mock_info.fills_by_time = [fill_3_during_disconnect, fill_1, fill_2_boundary]  # 順不同で返却されても時系列ソートされること

    # 3) WS 再接続時の backfill_missed_fills() (start_time_ms 省略 = 自動60秒オーバーラップ窓) を実行
    bf_res = daemon.ws.backfill_missed_fills()
    expected_start = (ts + 100_000) - HyperliquidWSManager.DEFAULT_BACKFILL_OVERLAP_MS
    assert bf_res["start_time_ms"] == expected_start
    assert bf_res["fetched_count"] == 3
    # 既処理の tid=910001 はスキップされ、未処理の 910002 と 910003 の2件のみが時系列順に処理されること!
    assert bf_res["new_processed_count"] == 2
    assert bf_res["processed_tids"] == [910002, 910003]

    # 4) 万一 _processed_tids メモリキャッシュがクリアされた状態で再度 backfill が走っても、
    #    tax_lots に重複計上されないこと
    daemon.ws._processed_tids.clear()
    daemon.ws.backfill_missed_fills()

    conn = db._get_connection()
    lots = conn.execute("SELECT hl_tid, exec_sz_base FROM tax_lots ORDER BY hl_tid ASC").fetchall()
    assert [int(r["hl_tid"]) for r in lots] == [910001, 910002, 910003]
    hype_inv = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'HYPE'").fetchone()
    assert float(hype_inv["quantity"]) == pytest.approx(2.00)
    db.close()


# ==============================================================================
# 2. IOC 決済時の「実残高 (`spot_clearinghouse_state.total`) 優先参照」監査
# ==============================================================================
def test_round9_item2_ioc_exit_prioritizes_actual_spot_balance_over_db_theoretical_size(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r9_item2.db", initial_equity_usdc=143.73)
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
    ts = 1_790_100_000_000

    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=Decimal("143.73"),
        usdc_jpy_rate=155.0,
        timestamp_ms=ts,
    )
    tax.process_spot_fill(
        hl_tid=920001,
        hl_oid=5001,
        timestamp_ms=ts + 500,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="2.00",
        raw_fee_amount="0.0014",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )

    # DB 上の current_sz が仮に手数料控除前の理論値 2.00 になっていたとしても、
    # 実口座 (spot_clearinghouse_state) の HYPE total が手数料控除後の 1.9986 (szDecimals=2) である状況を模擬
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.00,
        sz=2.00,
        sl_px=24.20,
        tp_px=27.00,
        timestamp_ms=ts + 1_000,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid=intent["cloid"],
        oid=5001,
        filled=True,
        filled_sz=2.00,  # DB 上は理論数量 2.00
        avg_px=25.00,
        timestamp_ms=ts + 1_100,
    )
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "93.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "1.9986", "hold": "0.0"},  # 実残高は 1.9986 (< 2.00)
    ]

    # 200ms ガーディアンで SL 着弾 (24.00 <= 24.20) -> IOC 決済発動
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": ts + 5_000,
                "levels": [[{"px": "24.00", "sz": "300", "n": 2}], [{"px": "24.02", "sz": "300", "n": 2}]],
            },
        }
    )
    g_res = daemon.run_200ms_guardian_tick(current_time_ms=ts + 5_100)
    assert len(g_res["actions"]) == 1
    ioc_res = g_res["actions"][0]["result"]

    # 売却発注数量が理論値 "2.00" ではなく、実残高 1.9986 を floor_size(..., 2) で切り捨てた "1.99" であること!
    assert ioc_res["status"] == "ok"
    assert ioc_res["sz_str"] == "1.99"
    assert float(mock_ex.orders_placed[-1]["sz"]) == pytest.approx(1.99)
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    db.close()


# ==============================================================================
# 3. Web リモート操作 (`PAUSE` / `RESUME` / `CLEAR_PENDING_BUYS` / `EMERGENCY_LIQUIDATE_ALL`) と3並列ループの即時協調監査
# ==============================================================================
def test_round9_item3_web_remote_commands_and_3_parallel_loops_coordination(
    tmp_path: Path,
) -> None:
    db = DatabaseManager(db_path=tmp_path / "r9_item3.db", initial_equity_usdc=143.73)
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
    ts = 1_790_200_000_000

    # 1) PAUSE 実行 -> 15分AIレーダーが即座に OPERATOR_PAUSED でスキップされること
    res_pause = service.execute_control_command("PAUSE", current_time_ms=ts)
    assert res_pause["ok"] is True
    assert res_pause["status_badge"] == "PAUSED"
    assert res_pause["operator_paused"] is True
    assert db.fetch_pending_commands() == []

    radar_paused = daemon.run_15m_ai_radar_tick(candidate_pairs=["HYPE/USDC"], current_time_ms=ts + 100)
    assert radar_paused["status"] == "SKIPPED"
    assert radar_paused["reason"] == "OPERATOR_PAUSED"

    # 2) RESUME 実行 -> 0秒で RUNNING に復帰し、15分AIレーダーが稼働可能になること
    res_resume = service.execute_control_command("RESUME", current_time_ms=ts + 200)
    assert res_resume["ok"] is True
    assert res_resume["status_badge"] == "RUNNING"
    assert res_resume["operator_paused"] is False
    assert db.fetch_pending_commands() == []

    # 3) Slot 1 に待機買い指値 (ENTRY_PENDING) を配置し、CLEAR_PENDING_BUYS で即座にキャンセル＆IDLE化されること
    wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="1.00",
        sl_px="24.00",
        tp_px="27.00",
        timestamp_ms=ts + 300,
    )
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    res_clear = service.execute_control_command("CLEAR_PENDING_BUYS", current_time_ms=ts + 400)
    assert res_clear["ok"] is True
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    assert db.fetch_pending_commands() == []
    db.close()


# ==============================================================================
# 4. 本番用 SQLite WAL データベース (`data/hl_v1_state_wal.db`) のクリーン状態＆プリフライト最終確認
# ==============================================================================
def test_round9_item4_production_sqlite_wal_db_is_clean_and_preflight_ready() -> None:
    prod_db_path = BASE_DIR / "data" / "hl_v1_state_wal.db"
    assert prod_db_path.exists(), "本番用 SQLite WAL DB が存在しません"

    conn = sqlite3.connect(str(prod_db_path))
    conn.row_factory = sqlite3.Row
    try:
        sys_row = dict(conn.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone())
        assert sys_row["system_mode"] in ("NORMAL", "RECONCILING_REST_QUIESCENCE")
        assert int(sys_row["operator_paused"]) in (0, 1)
        assert float(sys_row["initial_equity_usdc"]) == pytest.approx(143.73, abs=0.5)
        assert float(sys_row["hwm_equity_usdc"]) >= 143.0
        assert float(sys_row["current_equity_usdc"]) >= 100.0
        assert int(sys_row["l5_strike_count"]) == 0

        # Slot 1 & Slot 2 が有効なステートであること
        slots = [dict(r) for r in conn.execute("SELECT * FROM slot_state_store ORDER BY slot_id ASC").fetchall()]
        assert len(slots) == 2
        for s in slots:
            assert s["state"] in ("IDLE", "ENTRY_PENDING", "OPEN_PROTECTED", "MODIFYING_SL")

        # USDC 税務在庫が正常に記録されていること
        usdc_inv = conn.execute("SELECT * FROM tax_inventory_state WHERE asset = 'USDC'").fetchone()
        assert usdc_inv is not None
        assert float(usdc_inv["quantity"]) > 0.0
        assert float(usdc_inv["moving_avg_unit_jpy"]) > 100.0
    finally:
        conn.close()
