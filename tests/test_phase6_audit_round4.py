"""
HL AI Trader v1 — Phase 6 Audit Round 4 Verification Suite (tests/test_phase6_audit_round4.py)

第4回徹底総合監査（Audit Round 4）の重点検査項目を網羅する単体・結合テストスイート:
1. プロセス再起動・クラッシュ時の過渡状態 (`MODIFYING_SL`, `EXITING_ATOMIC`, `CANCELLING`, `DUST_RECOVERY_IN_PROGRESS`) 自動自己修復監査
2. 待機買い指値 (`ENTRY_PENDING`) の逆選択ガード (`Adverse Selection Cancel`) 結線 ＆ `ai_episodic_memory.lifecycle_status` (`CANCELLED_ADVERSE` / `EXPIRED_4H`) 更新監査
3. `asyncio.to_thread` スレッドプール再利用時のロック階層・SQLiteトランザクション (`BaseException` / `CancelledError`) 安全性監査
4. 4段階トレーリングストップの単調増加（ラチェット）＆ DB即時永続化・Slot 2解放ゲート連動監査
5. 運用期限スケジューラ（Phase 1凍結/全決済 ➔ 24h休止 ➔ Phase 2再開/凍結/全決済）の実配線＆1回限り執行監査
"""

from __future__ import annotations

import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict

import pytest

sys.dont_write_bytecode = True

from src.ai_brain import DebiasedAIBrain, HLTraderExecutionDecision
from src.coordinator import (
    ConcurrencyStateCoordinator,
    SlotState,
    SlotSubState,
    SystemMode,
)
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.main import HLTraderDaemon
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo


def _setup_round4_env(tmp_path: Path, db_name: str = "audit_r4.db"):
    db = DatabaseManager(db_path=tmp_path / db_name, initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "66" * 32,
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
    daemon.rate_fetcher.get_rate = lambda force_refresh=False: (Decimal("156.81"), "MOCK")
    return db, coord, tax, wrapper, mock_info, mock_ex, daemon


# ==============================================================================
# 1. プロセス再起動・クラッシュ時の過渡状態リカバリ監査
# ==============================================================================
def test_audit_r4_1_crash_transient_state_recovery(tmp_path: Path) -> None:
    db, coord, tax, wrapper, mock_info, mock_ex, daemon = _setup_round4_env(tmp_path, "r4_crash.db")
    ts0 = 1_785_000_000_000

    # OS強制終了により system_mode='DUST_RECOVERY_IN_PROGRESS', Slot 1='MODIFYING_SL' (実残高 2.0 HYPE = 50 USDC),
    # Slot 2='EXITING_ATOMIC' (実残高 0 USOL) のまま残存した状態を模擬
    with db.immediate_transaction() as tx:
        tx.execute(
            """
            UPDATE system_state_store
            SET system_mode = 'DUST_RECOVERY_IN_PROGRESS', quiescence_until_ms = ?, updated_at_ms = ?
            WHERE id = 1
            """,
            (ts0 + 5000, ts0),
        )
        tx.execute(
            """
            UPDATE slot_state_store
            SET state = 'MODIFYING_SL', sub_state = 'FREEROLL_LOCKED',
                coin = 'HYPE/USDC', base_asset = 'HYPE', sz_decimals = 2,
                entry_px = 25.00, current_sz = 2.00, sl_px = 25.10, tp_px = 27.50,
                trailing_stage = 2, updated_at_ms = ?
            WHERE slot_id = 1
            """,
            (ts0,),
        )
        tx.execute(
            """
            UPDATE slot_state_store
            SET state = 'EXITING_ATOMIC', sub_state = 'INITIAL_RISK',
                coin = 'USOL/USDC', base_asset = 'USOL', sz_decimals = 2,
                entry_px = 180.00, current_sz = 0.20, sl_px = 175.00, tp_px = 195.00,
                trailing_stage = 1, updated_at_ms = ?
            WHERE slot_id = 2
            """,
            (ts0,),
        )

    mock_info.spot_balances = [
        {"coin": "USDC", "total": "93.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "2.00", "hold": "0.0"},
        {"coin": "USOL", "total": "0.0", "hold": "0.0"},
    ]

    # 1) 静止期間内 (ts0 + 1000 < ts0 + 5000) はまだ遷移を邪魔しないこと
    rec_early = daemon.recover_transient_states_if_expired(current_time_ms=ts0 + 1000)
    assert rec_early["reason"] == "IN_QUIESCENCE"
    assert db.get_slot_state(1)["state"] == SlotState.MODIFYING_SL.value

    # 2) 静止期間経過後 (ts0 + 6000) の 15秒ループで自動的にアンstickされ、Fencing 検証も通過すること
    ctrl_res = daemon.run_15s_control_tick(current_time_ms=ts0 + 6000)
    assert ctrl_res["fencing_valid"] is True
    assert db.get_system_state()["system_mode"] == SystemMode.NORMAL.value

    s1 = db.get_slot_state(1)
    assert s1["state"] == SlotState.OPEN_PROTECTED.value
    assert s1["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1["sl_px"]) == pytest.approx(25.10)
    assert float(s1["tp_px"]) == pytest.approx(27.50)
    assert float(s1["current_sz"]) == pytest.approx(2.00)

    s2 = db.get_slot_state(2)
    assert s2["state"] == SlotState.IDLE.value
    db.close()


# ==============================================================================
# 2. 待機買い指値 (`ENTRY_PENDING`) の逆選択ガード結線 ＆ `lifecycle_status` 更新監査
# ==============================================================================
def test_audit_r4_2_adverse_selection_cancel_and_episodic_lifecycle_status(tmp_path: Path) -> None:
    db, coord, tax, wrapper, mock_info, mock_ex, daemon = _setup_round4_env(tmp_path, "r4_adverse.db")
    ts0 = 1_785_100_000_000

    def _place_pending_with_episode(ep_id: str, created_ts: int) -> Dict[str, Any]:
        ord_res = wrapper.place_spot_buy_alo(
            slot_id=1,
            coin_or_pair="HYPE/USDC",
            raw_limit_px="25.00",
            raw_sz="1.00",
            sl_px="24.25",
            tp_px="27.00",
            episode_id=ep_id,
            timestamp_ms=created_ts,
        )
        dec = HLTraderExecutionDecision(
            action="BUY_ALO",
            conviction_score=82,
            limit_px=25.00,
            sl_px=24.25,
            tp_px=27.00,
            expected_rr_ratio=2.67,
            market_regime_assessment="BULL_EXPANSION",
            reasoning="Strong trend",
            self_critique="Risk acceptable",
            invalidation_trigger_desc="Break below 24.25",
            memory_alignment_check="ALIGNED",
            prompt_hash="hash_r4",
        )
        daemon.ai_brain.record_episodic_entry(
            slot_id=1,
            coin="HYPE/USDC",
            cloid=ord_res["cloid"],
            oid=ord_res["oid"],
            market_regime_4h="BULL_TREND",
            trend_alignment_1h="BULLISH",
            bbo_spread_bps=4.0,
            perp_funding_rate_hr=0.0001,
            perp_oi_delta_15m_pct=0.5,
            perp_premium_pct=0.02,
            decision=dec,
            order_sz=1.0,
            notional_usdc=25.0,
            episode_id=ep_id,
            timestamp_ms=created_ts,
        )
        return ord_res

    # Case A: 価格が初期 sl_px (24.25) の +0.30% 以内 (24.30 <= 24.25 * 1.003 = 24.32275) まで急接近 -> CANCELLED_ADVERSE
    _place_pending_with_episode("ep_adv_price", ts0)
    daemon.ws._bbo_cache["HYPE/USDC"] = {"best_bid": 24.30, "best_ask": 24.32, "mid_px": 24.31, "updated_at_ms": ts0 + 1000}
    res_a = daemon.run_15s_control_tick(current_time_ms=ts0 + 1000)
    assert len(res_a["adverse_selection_cancelled"]) == 1
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    ep_row_a = dict(db._get_connection().execute("SELECT * FROM ai_episodic_memory WHERE episode_id = 'ep_adv_price'").fetchone())
    assert ep_row_a["lifecycle_status"] == "CANCELLED_ADVERSE"

    # Case B: Perp Long-Flush Blocker (funding_1h_pct >= 0.025% & delta_oi_15m_pct <= -2.0%) -> CANCELLED_ADVERSE
    daemon.ws._bbo_cache["HYPE/USDC"] = {"best_bid": 25.05, "best_ask": 25.07, "mid_px": 25.06, "updated_at_ms": ts0 + 5000}
    _place_pending_with_episode("ep_adv_perp", ts0 + 5000)
    res_b = daemon.run_15s_control_tick(
        current_time_ms=ts0 + 6000,
        perp_signals_by_pair={
            "UBTC/USDC": {"funding_1h_pct": 0.032, "delta_oi_15m_pct": -2.4, "premium_pct": -0.05},
        },
    )
    assert len(res_b["adverse_selection_cancelled"]) == 1
    assert "PERP_LONG_FLUSH_BLOCKER" in res_b["adverse_selection_cancelled"][0]["reason"]
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    ep_row_b = dict(db._get_connection().execute("SELECT * FROM ai_episodic_memory WHERE episode_id = 'ep_adv_perp'").fetchone())
    assert ep_row_b["lifecycle_status"] == "CANCELLED_ADVERSE"

    # Case C: 4時間未約定タイムアウト (ORDER_EXPIRY_MS) -> EXPIRED_4H
    _place_pending_with_episode("ep_exp_4h", ts0 + 10_000)
    res_c = daemon.run_15s_control_tick(current_time_ms=ts0 + 10_000 + 4 * 3_600_000 + 100)
    assert 1 in res_c["expired_slots"]
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    ep_row_c = dict(db._get_connection().execute("SELECT * FROM ai_episodic_memory WHERE episode_id = 'ep_exp_4h'").fetchone())
    assert ep_row_c["lifecycle_status"] == "EXPIRED_4H"
    db.close()


# ==============================================================================
# 3. `asyncio.to_thread` スレッドプール再利用時のロック階層・SQLite トランザクション安全性監査
# ==============================================================================
def test_audit_r4_3_thread_pool_lock_hierarchy_and_cancelled_error_hygiene(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r4_thread_pool.db")
    coord = ConcurrencyStateCoordinator(db=db)

    # 1つのワーカースレッド (max_workers=1) を強制再利用させ、1回目で asyncio.CancelledError (BaseException) を発生させる
    with ThreadPoolExecutor(max_workers=1) as pool:
        def _faulty_task():
            with coord.acquire_hierarchy(use_global=False, slot_ids=(1,), use_db_tx=True) as tx:
                assert tx is not None
                tx.execute("UPDATE system_state_store SET daily_trade_count = 99 WHERE id = 1")
                raise asyncio.CancelledError("Simulated task cancellation inside SQLite tx & SlotLock(1)")

        with pytest.raises(asyncio.CancelledError):
            pool.submit(_faulty_task).result()

        # 同じワーカースレッドで上位ロック GlobalSystemLock(10) -> SlotLock(1)(20) -> SQLite(40) を取得しても
        # 前回の held_levels や tx_depth が一切汚染されておらず正常にコミットできること
        def _clean_task():
            with coord.acquire_hierarchy(use_global=True, slot_ids=(1, 2), use_db_tx=True) as tx:
                assert tx is not None
                row = tx.execute("SELECT daily_trade_count FROM system_state_store WHERE id = 1").fetchone()
                # 前回の CancelledError の 99 は確実に ROLLBACK されていること
                assert int(row["daily_trade_count"]) == 0
                tx.execute("UPDATE system_state_store SET daily_trade_count = 2 WHERE id = 1")
            return coord._held_levels()

        remaining_levels = pool.submit(_clean_task).result()
        assert remaining_levels == []
        assert int(db.get_system_state()["daily_trade_count"]) == 2
    db.close()


# ==============================================================================
# 4. 4段階トレーリングストップの単調増加（ラチェット）＆ DB永続化・Slot 2解放ゲート連動監査
# ==============================================================================
def test_audit_r4_4_4stage_trailing_sl_monotonic_ratchet_and_slot2_gate_sync(tmp_path: Path) -> None:
    db, coord, tax, wrapper, mock_info, mock_ex, daemon = _setup_round4_env(tmp_path, "r4_ratchet.db")
    ts0 = 1_785_200_000_000

    coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        cloid="0x" + "d4" * 16,
        entry_px=25.00,
        sz=2.00,
        sl_px=24.25,
        tp_px=28.00,
        timestamp_ms=ts0,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid="0x" + "d4" * 16,
        oid=91001,
        filled=True,
        filled_sz=2.00,
        avg_px=25.00,
        timestamp_ms=ts0 + 100,
    )

    # Tick 1: +2.00% (25.50 >= 25.00 * 1.018) -> Stage 2 (FREEROLL_LOCKED, sl_px >= 25.0375 -> 25.038)
    daemon.ws._bbo_cache["HYPE/USDC"] = {"best_bid": 25.50, "best_ask": 25.52, "mid_px": 25.51, "updated_at_ms": ts0 + 200}
    daemon.run_200ms_guardian_tick(current_time_ms=ts0 + 200)
    s1_st2 = db.get_slot_state(1)
    assert int(s1_st2["trailing_stage"]) == 2
    assert s1_st2["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_st2["sl_px"]) >= 25.0375

    # Tick 2: +3.20% (25.80 >= 25.00 * 1.028, atr_15m=0.20) -> Stage 3 (sl_px = 25.80 - 0.24 = 25.56)
    daemon.ws._bbo_cache["HYPE/USDC"] = {"best_bid": 25.80, "best_ask": 25.82, "mid_px": 25.81, "updated_at_ms": ts0 + 400}
    daemon.run_200ms_guardian_tick(atr_15m_by_slot={1: 0.20}, current_time_ms=ts0 + 400)
    s1_st3 = db.get_slot_state(1)
    assert int(s1_st3["trailing_stage"]) == 3
    assert s1_st3["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_st3["sl_px"]) == pytest.approx(25.56)

    # Tick 3 (押し目 25.60): SLもステージもFREEROLL_LOCKEDも絶対に引き下げられないこと
    daemon.ws._bbo_cache["HYPE/USDC"] = {"best_bid": 25.60, "best_ask": 25.62, "mid_px": 25.61, "updated_at_ms": ts0 + 600}
    daemon.run_200ms_guardian_tick(atr_15m_by_slot={1: 0.20}, current_time_ms=ts0 + 600)
    s1_pullback = db.get_slot_state(1)
    assert int(s1_pullback["trailing_stage"]) == 3
    assert s1_pullback["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_pullback["sl_px"]) == pytest.approx(25.56)

    # 直接 transition_to_modifying_sl に低い SL/Stage を渡しても単調増加ラチェットで保護されること
    coord.transition_to_modifying_sl(slot_id=1, new_sl_px=24.80, new_trailing_stage=1, timestamp_ms=ts0 + 700)
    s1_guarded = db.get_slot_state(1)
    assert int(s1_guarded["trailing_stage"]) == 3
    assert s1_guarded["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_guarded["sl_px"]) == pytest.approx(25.56)

    # Slot 2 解放3重ゲートが DB 永続化済みの Slot 1 (FREEROLL_LOCKED, sl_px=25.56) を即座に参照できること
    gate_res = daemon.risk_guard.evaluate_slot2_triple_gate(
        slot1_state=s1_guarded,
        slot1_best_bid=25.80,  # >= 25.56 + max(0, 0.15) = 25.71
        slot1_atr_1m=0.05,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.5,
        hype_perp_premium_pct=0.02,
        hype_perp_delta_oi_15m_pct=0.5,
    )
    assert gate_res["allowed"] is True
    db.close()


# ==============================================================================
# 5. 運用期限スケジューラ (Phase 1終了 ➔ 24h休止 ➔ Phase 2終了) の実配線＆1回限り執行監査
# ==============================================================================
def test_audit_r4_5_campaign_schedule_phase1_freeze_flatten_and_phase2_once_only(tmp_path: Path) -> None:
    db, coord, tax, wrapper, mock_info, mock_ex, daemon = _setup_round4_env(tmp_path, "r4_schedule.db")
    with db.immediate_transaction() as tx:
        tx.execute("UPDATE system_state_store SET operator_paused = 0 WHERE id = 1")

    # 1) 2027-07-08 22:30 JST (Phase 1 期限2時間前凍結期間) -> 15分AIレーダーは新規エントリーを凍結スキップ
    dt_p1_freeze = datetime.fromisoformat("2027-07-08T22:30:00+09:00")
    radar_freeze = daemon.run_15m_ai_radar_tick(
        candidate_pairs=["HYPE/USDC"],
        current_time_ms=1_815_000_000_000,
        now_dt=dt_p1_freeze,
    )
    assert radar_freeze["status"] == "SKIPPED"
    assert radar_freeze["reason"] == "CAMPAIGN_PHASE_PHASE1_PRE_DEADLINE_FREEZE"

    # Slot 1 に待機注文を置いた状態で 2027-07-09 00:01 JST (Phase 1 終了時刻到達) を迎える
    wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="1.00",
        sl_px="24.25",
        tp_px="27.00",
        timestamp_ms=1_815_000_010_000,
    )
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    dt_p1_end = datetime.fromisoformat("2027-07-09T00:01:00+09:00")
    ctrl_p1_first = daemon.run_15s_control_tick(current_time_ms=1_815_005_000_000, now_dt=dt_p1_end)
    assert ctrl_p1_first["campaign_schedule"]["phase"] == "INTER_PHASE_COOLING_WINDOW"
    assert ctrl_p1_first["campaign_schedule"]["should_flatten_all"] is True
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # 次の15秒ティック (2027-07-09 00:02 JST) では should_flatten_all が False となり重複決済されないこと
    ctrl_p1_second = daemon.run_15s_control_tick(
        current_time_ms=1_815_005_015_000,
        now_dt=datetime.fromisoformat("2027-07-09T00:02:00+09:00"),
    )
    assert ctrl_p1_second["campaign_schedule"]["should_flatten_all"] is False

    # 2) 2027-07-10 00:05 JST (Phase 2 開始) -> 新規エントリー再開
    sched_p2_active = daemon.evaluate_campaign_schedule(
        now_dt=datetime.fromisoformat("2027-07-10T00:05:00+09:00")
    )
    assert sched_p2_active["phase"] == "PHASE2_ACTIVE"
    assert sched_p2_active["new_entry_allowed"] is True

    # 3) 2027-12-10 00:01 JST (Phase 2 最終終了到達) -> 1回だけ全決済され、2回目以降は should_flatten_all == False
    ctrl_p2_first = daemon.run_15s_control_tick(
        current_time_ms=1_828_000_000_000,
        now_dt=datetime.fromisoformat("2027-12-10T00:01:00+09:00"),
    )
    assert ctrl_p2_first["campaign_schedule"]["phase"] == "CAMPAIGN_COMPLETED"
    assert ctrl_p2_first["campaign_schedule"]["should_flatten_all"] is True

    ctrl_p2_second = daemon.run_15s_control_tick(
        current_time_ms=1_828_000_015_000,
        now_dt=datetime.fromisoformat("2027-12-10T00:02:00+09:00"),
    )
    assert ctrl_p2_second["campaign_schedule"]["should_flatten_all"] is False
    db.close()
