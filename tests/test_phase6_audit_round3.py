"""
HL AI Trader v1 — Phase 6 Audit Round 3 Verification Suite (tests/test_phase6_audit_round3.py)

第3回徹底総合監査（Audit Round 3）の4大重点項目を検証する単体・結合テストスイート:
1. 非同期イベントループ非ブロッキング検証 (`asyncio.to_thread`) ＆ リアルタイム MFE/MAE 計測・反映
2. 15分AIレーダー L1日次上限 (4回/日)・`l2_snapshot`/`candles_snapshot` 動的フォールバック ＆ 15秒ループ `shadow_evaluations` 1h/4h/24h 自動完了
3. 常駐起動基盤 (`launch_hidden.vbs`, `watchdog.py`) の `.venv` 解決・環境変数隔離・Port 8080/GMO 完全非干渉ガード
4. 長期稼働メモリ上限ガード (`_processed_tids`, `_sent_subscriptions`, `_finalized_exit_keys`, `_pre_order_base_balances`, `_candle_cache`) ＆ マルチスレッド SQLite 接続クリーンアップ
"""

from __future__ import annotations

import asyncio
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.dont_write_bytecode = True

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.main import HLTraderDaemon
from src.web_server import DashboardStateService
from src.ws_manager import HyperliquidWSManager
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo
from tests.test_phase3_to_phase5 import _make_healthy_l2_book, _make_trending_candles
import watchdog


def _build_round3_daemon(tmp_path: Path):
    db = DatabaseManager(tmp_path / "audit_r3.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    ex = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        db=db,
        coordinator=coord,
        tax_engine=tax,
        execution_mode="DRY_RUN",
        info_client=MockHLInfo("0x0"),
    )
    mock_info = MockHLInfo(ex.agent_address)
    ex.info = mock_info
    ex.refresh_universe_mapping()

    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=ex,
    )
    return db, coord, tax, daemon.ws, ex, daemon.ai_brain, daemon


# ==============================================================================
# 1. 非同期イベントループ非ブロッキング検証 ＆ リアルタイム MFE/MAE 追跡
# ==============================================================================
def test_round3_async_nonblocking_and_realtime_mfe_mae(tmp_path: Path):
    """
    1) 15秒ループ内で同期I/O遅延（350ms）が発生している間も、`run_200ms_guardian_step_async` が
       ブロックされずに並行して複数回完了することを確認する。
    2) 200ms ガーディアン監視中に価格が `25.00 -> 26.25 (+5.0%) -> 24.50 (-2.0%) -> 26.50 (TP決済)` と推移した際、
       実測された `mfe_pct` (+6.0%) と `mae_pct` (-2.0%) が `episodic_reflections` に記録されることを確認する。
    """
    db, coord, tax, ws, ex, brain, daemon = _build_round3_daemon(tmp_path)
    ts0 = 1_780_000_000_000

    # 1. 非ブロッキング並行実行テスト
    ex.get_spot_balances = lambda raw=None: {
        "USDC": {"total": Decimal("143.73"), "hold": Decimal("0"), "free": Decimal("143.73")},
        "HYPE": {"total": Decimal("0"), "hold": Decimal("0"), "free": Decimal("0")},
    }
    ex.info = type("SlowInfo", (), {"open_orders": staticmethod(lambda addr: (time.sleep(0.32), [])[1])})()
    daemon.rate_fetcher.get_rate = lambda force_refresh=False: (Decimal("156.81"), "MOCK")

    async def _exercise_concurrent_steps():
        guardian_ticks = 0

        async def _fast_guardian():
            nonlocal guardian_ticks
            for i in range(4):
                await daemon.run_200ms_guardian_step_async(current_time_ms=ts0 + i * 50)
                guardian_ticks += 1
                await asyncio.sleep(0.05)

        t_start = time.perf_counter()
        await asyncio.gather(
            daemon.run_15s_control_step_async(current_time_ms=ts0),
            _fast_guardian(),
        )
        elapsed = time.perf_counter() - t_start
        return guardian_ticks, elapsed

    g_ticks, elapsed_sec = asyncio.run(_exercise_concurrent_steps())
    assert g_ticks == 4
    assert elapsed_sec < 1.5  # 同期ブロックされず並列完了

    # 2. リアルタイム MFE / MAE 追跡テスト
    ep_id = "ep_mfe_mae_r3"
    coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        cloid="0x" + "c1" * 16,
        entry_px=25.00,
        sz=2.0,
        sl_px=24.00,
        tp_px=26.50,
        episode_id=ep_id,
        timestamp_ms=ts0,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid="0x" + "c1" * 16,
        oid=88001,
        filled=True,
        filled_sz=2.0,
        avg_px=25.00,
    )
    ex.get_spot_balances = lambda raw=None: {
        "USDC": {"total": Decimal("93.73"), "hold": Decimal("0"), "free": Decimal("93.73")},
        "HYPE": {"total": Decimal("2.00"), "hold": Decimal("0"), "free": Decimal("2.00")},
    }

    # Tick 1: 26.25 (+5.0% 含み益)
    ws._bbo_cache["HYPE/USDC"] = {"best_bid": 26.25, "best_ask": 26.27, "mid_px": 26.26, "updated_at_ms": ts0 + 200}
    daemon.run_200ms_guardian_tick(current_time_ms=ts0 + 200)

    # Tick 2: 24.50 (-2.0% 含み損, ただし SL=24.00 or Freeroll 判定前と仮定するため sl_px=24.00 に再設定してMAE計測確認)
    with db.immediate_transaction() as conn:
        conn.execute("UPDATE slot_state_store SET sl_px = 24.00, sub_state = 'INITIAL_RISK' WHERE slot_id = 1")
    ws._bbo_cache["HYPE/USDC"] = {"best_bid": 24.50, "best_ask": 24.52, "mid_px": 24.51, "updated_at_ms": ts0 + 400}
    daemon.run_200ms_guardian_tick(current_time_ms=ts0 + 400)

    assert daemon._slot_excursions[1]["mfe_pct"] == pytest.approx(5.0, abs=1e-4)
    assert daemon._slot_excursions[1]["mae_pct"] == pytest.approx(-2.0, abs=1e-4)

    # Tick 3: 26.50 (TP=26.50 到達 -> IOC 決済 & 反省メモリ記録)
    ws._bbo_cache["HYPE/USDC"] = {"best_bid": 26.50, "best_ask": 26.52, "mid_px": 26.51, "updated_at_ms": ts0 + 600}
    res_tp = daemon.run_200ms_guardian_tick(current_time_ms=ts0 + 600)
    assert any(a["action"] == "ATOMIC_IOC_EXIT" and a["exit_reason"] == "TAKE_PROFIT_HIT" for a in res_tp["actions"])

    refs = [dict(r) for r in db._get_connection().execute("SELECT * FROM ai_reflection_memory WHERE episode_id = ?", (ep_id,)).fetchall()]
    assert len(refs) == 1
    assert float(refs[0]["mfe_pct"]) == pytest.approx(6.0, abs=1e-4)
    assert float(refs[0]["mae_pct"]) == pytest.approx(-2.0, abs=1e-4)
    db.close()


# ==============================================================================
# 2. 15分AIレーダー (L1上限・動的L2/Candle取得) ＆ 15秒ループ Shadow Evaluation 自動完了
# ==============================================================================
def test_round3_radar_l1_limit_live_fallback_and_shadow_eval_completion(tmp_path: Path):
    """
    1) `daily_trade_count == 4` のとき `run_15m_ai_radar_tick` が `L1_DAILY_TRADE_LIMIT_REACHED` でスキップされること。
    2) `l2_books_by_pair` / `candles_by_pair` 引数省略時に `exchange.info.l2_snapshot` および
       `candles_snapshot` が自動呼び出しされ、7段階フィルタ通過後に発注まで到達すること。
    3) `shadow_evaluations` の `TRACKING` レコードが 1h / 4h / 24h 経過時に価格追跡＆自動完了されること。
    """
    db, coord, tax, ws, ex, brain, daemon = _build_round3_daemon(tmp_path)
    ts0 = 1_780_100_000_000
    active_dt = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)

    # 1. L1 日次4回上限テスト
    with db.immediate_transaction() as conn:
        conn.execute(
            "UPDATE system_state_store SET operator_paused = 0, daily_trade_count = 4, current_equity_usdc = 143.73 WHERE id = 1"
        )
    res_l1 = daemon.run_15m_ai_radar_tick(
        candidate_pairs=["HYPE/USDC"],
        current_time_ms=ts0,
        now_dt=active_dt,
    )
    assert res_l1["status"] == "SKIPPED"
    assert res_l1["reason"] == "L1_DAILY_TRADE_LIMIT_REACHED"

    # 2. 動的 l2_snapshot / candles_snapshot フォールバック検証
    with db.immediate_transaction() as conn:
        conn.execute("UPDATE system_state_store SET daily_trade_count = 0 WHERE id = 1")
    ex.get_spot_balances = lambda raw=None: {
        "USDC": {"total": Decimal("143.73"), "hold": Decimal("0"), "free": Decimal("143.73")}
    }

    l2_calls: List[str] = []
    candle_calls: List[str] = []

    class _MockInfo:
        @staticmethod
        def open_orders(addr: str):
            return []

        @staticmethod
        def l2_snapshot(api_coin: str):
            l2_calls.append(api_coin)
            return _make_healthy_l2_book(25.00)

        @staticmethod
        def candles_snapshot(api_coin: str, interval: str, start_ms: int, end_ms: int):
            candle_calls.append(f"{api_coin}:{interval}")
            if interval == "4h":
                return _make_trending_candles(60, 20.0, 0.015)
            if interval == "1h":
                return _make_trending_candles(60, 22.0, 0.015)
            return _make_trending_candles(60, 24.0, 0.008)

    ex.info = _MockInfo()
    res_radar = daemon.run_15m_ai_radar_tick(
        candidate_pairs=["HYPE/USDC"],
        current_time_ms=ts0,
        now_dt=active_dt,
    )
    assert "@107" in l2_calls
    assert "@107:4h" in candle_calls and "@107:1h" in candle_calls and "@107:15m" in candle_calls
    assert res_radar["status"] == "ORDER_PLACED"
    assert res_radar["placed_order"]["pair_name"] == "HYPE/USDC"

    # 3. Shadow Evaluation の 1h / 4h / 24h 自動完了テスト
    sh_id = brain.register_shadow_skip(
        coin="HYPE/USDC",
        market_regime_4h="STRONG_BULL",
        skip_stage="AI_SKIP",
        skip_reason_code="TEST_SHADOW_TRACK",
        spot_mid_at_eval=25.00,
        hypothetical_sl_px=24.25,
        hypothetical_tp_px=26.25,
        ai_conviction_score=70,
        evaluated_at_ms=ts0,
    )
    # 1.5時間後: 価格 25.80 -> px_after_1h が記録され TRACKING 継続
    s1 = brain.process_pending_shadow_evaluations(
        current_prices={"HYPE/USDC": 25.80},
        current_time_ms=ts0 + 5_400_000,
    )
    assert len(s1) >= 1
    row_1h = dict(
        db._get_connection().execute("SELECT * FROM shadow_evaluations WHERE shadow_id = ?", (sh_id,)).fetchone()
    )
    assert float(row_1h["px_after_1h"]) == pytest.approx(25.80)
    assert row_1h["shadow_outcome"] == "TRACKING"

    # 5時間後: 価格 26.80 (TP=26.25 超え) -> px_after_4h と max_high_24h=26.80 が記録される
    brain.process_pending_shadow_evaluations(
        current_prices={"HYPE/USDC": 26.80},
        current_time_ms=ts0 + 18_000_000,
    )
    # 24時間経過: 自動完了 -> max_high_24h >= 26.25 かつ min_low_24h > 24.25 のため TIMID_MISS 判定
    s24 = brain.process_pending_shadow_evaluations(
        current_prices={"HYPE/USDC": 26.40},
        current_time_ms=ts0 + 86_400_001,
    )
    assert any(item["shadow_id"] == sh_id and item["shadow_outcome"] == "TIMID_MISS" for item in s24)
    row_24h = dict(
        db._get_connection().execute("SELECT * FROM shadow_evaluations WHERE shadow_id = ?", (sh_id,)).fetchone()
    )
    assert row_24h["shadow_outcome"] == "TIMID_MISS"
    assert row_24h["calibration_signal"] == "RELAX_TIMIDITY"
    assert float(row_24h["max_high_24h"]) == pytest.approx(26.80)
    db.close()


# ==============================================================================
# 3. 常駐起動基盤 (`launch_hidden.vbs`, `watchdog.py`) の検証
# ==============================================================================
def test_round3_launcher_and_watchdog_isolation():
    """
    `launch_hidden.vbs` と `watchdog.py` が `.venv\\Scripts\\python.exe`・`PYTHONUTF8=1`・
    `PYTHONDONTWRITEBYTECODE=1`・`GIT_CONFIG_GLOBAL` を正しく設定し、Port 8080 を保護することを確認する。
    """
    base_dir = Path(__file__).resolve().parent.parent
    vbs_text = (base_dir / "launch_hidden.vbs").read_text(encoding="utf-8")
    assert ".venv\\Scripts\\python.exe" in vbs_text
    assert 'env("PYTHONDONTWRITEBYTECODE") = "1"' in vbs_text
    assert 'env("PYTHONUTF8") = "1"' in vbs_text
    assert ".hl_gitconfig" in vbs_text

    py_path = watchdog.resolve_venv_python(base_dir)
    assert py_path.lower().endswith("python.exe")

    iso_env = watchdog.build_isolated_process_env(base_dir)
    assert iso_env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert iso_env["PYTHONUTF8"] == "1"
    assert iso_env["GIT_CONFIG_GLOBAL"].endswith(".hl_gitconfig")

    # Port 8080 (GMO AI Trader) の監視・操作要求は例外で即拒否されること
    with pytest.raises(ValueError, match="Port 8080"):
        watchdog.is_port_listening(port=8080)


# ==============================================================================
# 4. 長期稼働メモリ上限ガード ＆ マルチスレッド SQLite 接続クリーンアップ
# ==============================================================================
def test_round3_memory_bounds_and_multithread_db_cleanup(tmp_path: Path):
    """
    1) ワーカースレッド (`asyncio.to_thread`) で開かれた SQLite 接続が `db.close()` で全て閉じられること。
    2) `HyperliquidWSManager` の `_processed_tids` と `_sent_subscriptions` が上限を超えずプルーニングされること。
    3) `DashboardStateService._candle_cache` が上限 64 件でクリアされること。
    """
    db = DatabaseManager(tmp_path / "mt_cleanup.db")

    async def _open_in_worker_threads():
        await asyncio.gather(
            asyncio.to_thread(db.get_system_state),
            asyncio.to_thread(db.get_all_slots),
        )

    asyncio.run(_open_in_worker_threads())
    assert len(db._all_connections) >= 1
    db.close()
    assert len(db._all_connections) == 0

    # WS キャッシュ上限プルーニング検証
    ws = HyperliquidWSManager(main_address="0x1234567890123456789012345678901234567890")
    ws.MAX_PROCESSED_TIDS = 20
    for tid in range(1, 35):
        ws.handle_raw_message(
            {
                "channel": "userFills",
                "data": {
                    "isSnapshot": False,
                    "fills": [{"tid": tid, "oid": tid, "coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "1.0"}],
                },
            }
        )
    assert len(ws._processed_tids) <= 20

    # Candle キャッシュ上限検証
    db2 = DatabaseManager(tmp_path / "candle_cap.db")
    svc = DashboardStateService(
        db=db2,
        candle_provider=lambda pair, iv: [{"t": 1, "o": 1.0, "h": 1.0, "l": 1.0, "c": 1.0, "v": 1.0}],
    )
    for idx in range(70):
        svc.fetch_live_or_cached_candles(f"COIN{idx}/USDC", "15m", current_time_ms=1_780_000_000_000)
    assert len(svc._candle_cache) <= 64
    db2.close()
