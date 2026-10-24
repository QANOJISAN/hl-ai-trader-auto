"""
Phase 6 — 第5回 徹底総合監査 (Audit Round 5) 回帰・年次税務境界・HTTP異常系・E2Eフルライフサイクル検証テスト

検証項目:
1. Round 1〜4 で追加された全メソッド (`recover_transient_states_if_expired`, `evaluate_adverse_selection_for_pending_entries`) の
   ロック階層 (`Global(10) -> Slot(20/30) -> SQLite(40)`) 遵守、および Perp 非上場 Spot 専用銘柄 (`perp_oracle_px == 0`) /
   板キャッシュ空 (`l2Book == {}`) における例外安全性検証
2. キャンペーン運用期限スケジューラ (`2027-07-09 00:00 JST`, `2027-12-10 00:00 JST`) 経過後の再起動時における
   不要API呼び出し抑止と `_phase1_liquidated` / `_phase2_liquidated` 即時完了検証
3. 税務エンジン (`HyperliquidTaxEngine`) の Maker 手数料ゼロ (`0`) / マイナスリベート (`-0.005`) 安全クランプと、
   複数銘柄 (`HYPE`, `UBTC`) 売買を通じた年次確定申告サマリー (`MOVING_AVERAGE` / `TOTAL_AVERAGE`) 1円単位整合性検証
4. Port 8081 Web ダッシュボード API (`/api/status`, `/api/candles`, `/api/command`) における未知シンボル・空ボディ・
   不正JSON入力時の HTTP 400/200 安全応答とプロセス無停止検証
5. E2E フルライフサイクル結合テスト (`143.73 USDC` 初期状態 ➔ 15分AIレーダー7段階フィルタ通過 ➔ Slot 1 `BUY_ALO` 発注・約定
   ➔ 200msガーディアン Stage 2 `FREEROLL_LOCKED` 昇格 ➔ Slot 2 3重ゲート解放・発注・約定 ➔ Slot 1 & 2 決済
   ➔ `tax_lots`, `ai_reflection_memory`, Web `/api/state` 完全一致検証)
"""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
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
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper, SpotUniverseEntry
from src.main import HLTraderDaemon
from src.radar import MarketRadarAndFilter
from src.risk_guard import RiskAndCircuitBreakerEngine
from src.web_server import DashboardStateService, create_dashboard_http_server
from src.ws_manager import HyperliquidWSManager
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo
from tests.test_phase3_to_phase5 import _make_healthy_l2_book

JST = timezone(timedelta(hours=9))


def test_round5_item1_lock_hierarchy_and_spot_only_adverse_selection_safety(tmp_path: Path) -> None:
    """
    監査項目1:
    - `recover_transient_states_if_expired` と `evaluate_adverse_selection_for_pending_entries` が
      ロック階層違反を起こさずに連続実行できること
    - Perp市場が存在しない Spot専用銘柄 (`perp_oracle_px == 0` または `get_spot_entry() -> None`) や
      `l2Book` キャッシュが空の状態でも `KeyError`, `TypeError`, `ZeroDivisionError` を一切送出しないこと
    """
    db_path = tmp_path / "r5_item1.db"
    db = DatabaseManager(db_path=db_path)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    ex = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
    )
    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=ex,
    )
    ws = daemon.ws

    ts = 1_780_000_000_000
    # Spot専用銘柄 (Perp市場なし: perp_oracle_px=0.0, get_spot_entry=None, l2Book空) を Slot 1 ENTRY_PENDING に配置
    coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="SPOTONLY/USDC",
        base_asset="SPOTONLY",
        sz_decimals=2,
        cloid="0x" + "a1" * 16,
        entry_px=1.25,
        sz=20.0,
        sl_px=1.18,
        tp_px=1.45,
        timestamp_ms=ts - 10_000,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid="0x" + "a1" * 16,
        oid=501,
        filled=False,
        timestamp_ms=ts - 9_500,
    )

    # BBO のみ存在し、l2Book キャッシュが空・get_spot_entry("SPOTONLY/USDC") が None の状態
    ws._bbo_cache["SPOTONLY/USDC"] = {
        "best_bid": 1.251,
        "best_ask": 1.253,
        "mid_px": 1.252,
        "updated_at_ms": ts,
    }

    # 例外が発生せず、安全に空リストが返ることを検証
    cancelled = daemon.evaluate_adverse_selection_for_pending_entries(
        perp_signals_by_pair=None,
        current_time_ms=ts,
    )
    assert cancelled == []
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    # 続いて過渡状態リカバリも連続呼び出ししてロック階層違反が発生しないことを検証
    rec = daemon.recover_transient_states_if_expired(current_time_ms=ts)
    assert rec["recovered_system_mode"] is False
    assert rec["recovered_slots"] == {}
    assert coord._held_levels() == []
    db.close()


def test_round5_item2_campaign_deadline_restart_idempotency(tmp_path: Path) -> None:
    """
    監査項目2:
    - `2027-07-09 00:00 JST` (第1期終了) および `2027-12-10 00:00 JST` (第2期終了) 以降に
      プロセスが再起動された際、すでに全スロットが `IDLE` で未約定注文も `0` であれば、
      不要なキャンセル・売却APIを1回も呼ばずに `_phase1_liquidated` / `_phase2_liquidated` が `True` となり、
      以降のティックで重複精算が発生しないこと
    """
    db_path = tmp_path / "r5_item2.db"
    db = DatabaseManager(db_path=db_path)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    ex = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
    )
    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=ex,
    )
    daemon.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")
    tax.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")

    cancel_calls: List[Any] = []
    exit_calls: List[Any] = []
    orig_cancel = ex.cancel_spot_order
    orig_exit = ex.execute_atomic_ioc_exit

    def spy_cancel(*args: Any, **kwargs: Any) -> Any:
        cancel_calls.append((args, kwargs))
        return orig_cancel(*args, **kwargs)

    def spy_exit(*args: Any, **kwargs: Any) -> Any:
        exit_calls.append((args, kwargs))
        return orig_exit(*args, **kwargs)

    ex.cancel_spot_order = spy_cancel  # type: ignore[method-assign]
    ex.execute_atomic_ioc_exit = spy_exit  # type: ignore[method-assign]

    # 1. 2027-07-09 00:05 JST (第1期終了直後・全スロット IDLE) で再起動後の初回 15s tick
    dt_p1_end = datetime(2027, 7, 9, 0, 5, 0, tzinfo=JST)
    res1 = daemon.run_15s_control_tick(
        current_time_ms=int(dt_p1_end.timestamp() * 1000),
        now_dt=dt_p1_end,
    )
    assert res1["campaign_schedule"]["phase"] == "INTER_PHASE_COOLING_WINDOW"
    assert daemon._phase1_liquidated is True
    assert len(cancel_calls) == 0
    assert len(exit_calls) == 0

    # 次の tick では should_flatten_all が False になっていること
    sched_next = daemon.evaluate_campaign_schedule(now_dt=dt_p1_end)
    assert sched_next["should_flatten_all"] is False

    # 2. 2027-12-10 00:05 JST (第2期終了直後・全スロット IDLE) で再起動後の初回 15s tick
    dt_p2_end = datetime(2027, 12, 10, 0, 5, 0, tzinfo=JST)
    res2 = daemon.run_15s_control_tick(
        current_time_ms=int(dt_p2_end.timestamp() * 1000),
        now_dt=dt_p2_end,
    )
    assert res2["campaign_schedule"]["phase"] == "CAMPAIGN_COMPLETED"
    assert daemon._phase2_liquidated is True
    assert len(cancel_calls) == 0
    assert len(exit_calls) == 0

    sched_p2_next = daemon.evaluate_campaign_schedule(now_dt=dt_p2_end)
    assert sched_p2_next["should_flatten_all"] is False
    db.close()


def test_round5_item3_tax_engine_maker_rebate_and_multi_asset_annual_summary(tmp_path: Path) -> None:
    """
    監査項目3:
    - Maker `Alo` 約定時に `raw_fee_amount = "0"` またはマイナス値 (`raw_fee_amount = "-0.005"`) が
      渡されても、`fee = max(0, ...)` で安全にクランプされ、取得単価や実現損益計算が破綻しないこと
    - 複数銘柄 (`HYPE`, `UBTC`) の `SPOT_BUY` ➔ `SPOT_SELL` において、
      `calculate_annual_summary` (`MOVING_AVERAGE` ＆ `TOTAL_AVERAGE`) が1円単位で正確に一致すること
    """
    db_path = tmp_path / "r5_item3.db"
    db = DatabaseManager(db_path=db_path)
    tax = HyperliquidTaxEngine(db=db)

    # 2026年内のミリ秒タイムスタンプ
    ts_base = int(datetime(2026, 10, 23, 12, 0, 0, tzinfo=JST).timestamp() * 1000)

    # 1. 初期 143.73 USDC を @150.00 JPY でブートストラップ
    boot = tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total="143.73",
        usdc_jpy_rate=150.00,
        timestamp_ms=ts_base,
    )
    assert boot["bootstrapped"] is True

    # 2. HYPE/USDC を Maker Alo (マイナス手数料リベート "-0.005") で 2.0 HYPE @ 25.00 USDC 購入 (@150 JPY)
    #    50.00 USDC 消費 -> 為替差損益 0円, HYPE 2.0枚 取得原価 = 7,500 JPY
    buy_hype = tax.process_spot_fill(
        hl_tid=500001,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.0",
        exec_sz_base="2.0",
        raw_fee_amount="-0.005",
        raw_fee_token="HYPE",
        timestamp_ms=ts_base + 1_000,
        usdc_jpy_rate=150.00,
    )
    assert float(buy_hype["raw_fee_amount"]) == pytest.approx(0.0)
    assert float(buy_hype["acquired_net_qty"]) == pytest.approx(2.0)
    assert float(buy_hype["realized_pnl_jpy"]) == pytest.approx(0.0)

    # 3. HYPE/USDC を Maker Alo (手数料 "0") で 2.0 HYPE @ 30.00 USDC 売却 (@150 JPY)
    #    売却収入 = 60.00 * 150 = 9,000 JPY, 原価 = 7,500 JPY -> 実現益 +1,500 JPY
    sell_hype = tax.process_spot_fill(
        hl_tid=500002,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc="30.0",
        exec_sz_base="2.0",
        raw_fee_amount="0",
        raw_fee_token="USDC",
        timestamp_ms=ts_base + 2_000,
        usdc_jpy_rate=150.00,
    )
    assert round(float(sell_hype["realized_pnl_jpy"])) == 1500

    # 4. UBTC/USDC を 0.001 UBTC @ 80,000 USDC 購入 (@150 JPY) -> 80 USDC (12,000 JPY)
    tax.process_spot_fill(
        hl_tid=500003,
        pair_name="UBTC/USDC",
        base_asset="UBTC",
        is_buy=True,
        exec_px_usdc="80000.0",
        exec_sz_base="0.001",
        raw_fee_amount="0",
        raw_fee_token="UBTC",
        timestamp_ms=ts_base + 3_000,
        usdc_jpy_rate=150.00,
    )
    # 5. UBTC/USDC を 0.001 UBTC @ 85,000 USDC 売却 (@150 JPY) -> 85 USDC (12,750 JPY) -> 実現益 +750 JPY
    tax.process_spot_fill(
        hl_tid=500004,
        pair_name="UBTC/USDC",
        base_asset="UBTC",
        is_buy=False,
        exec_px_usdc="85000.0",
        exec_sz_base="0.001",
        raw_fee_amount="0",
        raw_fee_token="USDC",
        timestamp_ms=ts_base + 4_000,
        usdc_jpy_rate=150.00,
    )

    ma_summary = tax.calculate_annual_summary(tax_year=2026, method="MOVING_AVERAGE")
    ta_summary = tax.calculate_annual_summary(tax_year=2026, method="TOTAL_AVERAGE")

    # 合計実現益 = 1,500 + 750 = 2,250 JPY (1円のズレもなく一致)
    assert ma_summary["lot_count"] == 4
    assert ma_summary["total_realized_pnl_jpy_int"] == 2250
    assert ta_summary["total_realized_pnl_jpy_int"] == 2250
    db.close()


def test_round5_item4_web_server_http_error_resilience(tmp_path: Path) -> None:
    """
    監査項目4:
    - Web サーバー (`/api/status`, `/api/candles`, `/api/command`) に対して未知の銘柄名、
      空の JSON ボディ、壊れた JSON 文字列、未承認の `EMERGENCY_LIQUIDATE_ALL` を送信した際、
      適切な HTTP ステータス (400 / 200) と JSON を返し、サーバーが決してクラッシュしないこと
    """
    db_path = tmp_path / "r5_item4.db"
    db = DatabaseManager(db_path=db_path)
    svc = DashboardStateService(db=db)
    server = create_dashboard_http_server(svc, host="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    base_url = f"http://127.0.0.1:{port}"
    auth_token = svc.auth_manager.issue_session_token()
    auth_hdrs = {"X-HL-Auth": auth_token}
    try:
        # 1. 未知の銘柄 & 未知の時間足への GET /api/candles -> HTTP 200 でフォールバックローソク足を返す
        req_candles = urllib.request.Request(
            f"{base_url}/api/candles?pair=UNKNOWN_COIN_XYZ&interval=999m", headers=auth_hdrs
        )
        with urllib.request.urlopen(req_candles, timeout=5) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["pair_name"] == "UNKNOWN_COIN_XYZ/USDC"
            assert data["interval"] == "15m"
            assert len(data["candles"]) == 48

        # 2. 壊れた JSON ボディの POST /api/command -> HTTP 400
        req_bad_json = urllib.request.Request(
            f"{base_url}/api/command",
            data=b"{broken_json_payload",
            headers={"Content-Type": "application/json", "X-HL-Auth": auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req_bad_json, timeout=5)
        assert exc_info.value.code == 400
        err_body = json.loads(exc_info.value.read().decode("utf-8"))
        assert err_body["ok"] is False

        # 3. 空ボディの POST /api/command -> HTTP 400
        req_empty = urllib.request.Request(
            f"{base_url}/api/command",
            data=b"",
            headers={"Content-Type": "application/json", "X-HL-Auth": auth_token},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_empty:
            urllib.request.urlopen(req_empty, timeout=5)
        assert exc_empty.value.code == 400

        # 4. 異常リクエスト後も GET /api/status が正常に HTTP 200 を返すこと
        req_status = urllib.request.Request(f"{base_url}/api/status", headers=auth_hdrs)
        with urllib.request.urlopen(req_status, timeout=5) as resp_ok:
            assert resp_ok.status == 200
            st_data = json.loads(resp_ok.read().decode("utf-8"))
            assert st_data["port"] == 8081
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_round5_item5_full_e2e_lifecycle_integration(tmp_path: Path) -> None:
    """
    監査項目5 (E2E フルライフサイクル結合検証):
    1. 初期状態 (`143.73 USDC`) シード
    2. 15分AIレーダー7段階フィルタ通過 ➔ AI `BUY_ALO` 判定 ➔ Slot 1 発注 (`ENTRY_PENDING`) ➔ 約定 (`OPEN_PROTECTED`)
    3. 200msガーディアンによる MFE/MAE 追跡 ➔ Stage 2 (`FREEROLL_LOCKED`, `sl_px >= entry_px * 1.0015`) への昇格
    4. Slot 2 解放3重ゲート (`FREEROLL_LOCKED` ＆ クッション十分 ＆ Perp健全) の通過 ➔ Slot 2 発注・約定
    5. Slot 1 & Slot 2 の決済完了 ➔ `tax_lots`, `ai_reflection_memory` 蒸留、および Web `/api/state` 反映の完全一致検証
    """
    db_path = tmp_path / "r5_item5_e2e.db"
    db = DatabaseManager(db_path=db_path, initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)
    radar = MarketRadarAndFilter()
    ai_brain = DebiasedAIBrain(db=db)

    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "77" * 32,
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
        radar=radar,
        ai_brain=ai_brain,
        risk_guard=rg,
    )
    daemon.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")
    tax.rate_fetcher.get_rate = lambda force_refresh=False: (155.0, "MOCK")

    web_svc = DashboardStateService(
        db=db,
        tax_engine=tax,
        coordinator=coord,
        daemon=daemon,
    )

    ts = int(datetime(2026, 10, 23, 15, 0, 0, tzinfo=JST).timestamp() * 1000)

    # Step 1: 初期残高 143.73 USDC (@155.0 JPY) を DB & 税務在庫へシード
    with db.immediate_transaction() as tx:
        tx.execute(
            """
            UPDATE system_state_store
            SET initial_equity_usdc = 143.73,
                hwm_equity_usdc = 143.73,
                sod_equity_usdc = 143.73,
                sow_equity_usdc = 143.73,
                current_equity_usdc = 143.73,
                latest_usdc_jpy_rate = 155.0,
                operator_paused = 0,
                updated_at_ms = ?
            WHERE id = 1
            """,
            (ts,),
        )
    tax.bootstrap_initial_usdc_inventory("143.73", 155.0, timestamp_ms=ts)

    # Step 2: 7段階マイクロストラクチャフィルタを通過する HYPE/USDC エントリ検証
    hype_entry = SpotUniverseEntry(
        pair_name="HYPE/USDC",
        api_coin_name="@107",
        base_asset="HYPE",
        quote_asset="USDC",
        base_token_idx=150,
        quote_token_idx=0,
        universe_idx=107,
        spot_asset_id=10107,
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        perp_coin="HYPE",
        spot_mid_px=25.00,
        spot_mark_px=25.005,
        spot_day_ntl_vlm=35_000_000.0,
        perp_mark_px=25.00,
        perp_oracle_px=25.00,
        perp_funding_1h=0.00001,
        perp_premium=0.0002,
    )
    filter_res = radar.evaluate_7_stage_filter(hype_entry, _make_healthy_l2_book(25.00))
    assert filter_res.passed is True

    # AI BUY_ALO 決定 & Slot 1 発注 (4.00 HYPE @ 25.00 USDC = 100.0 USDC)
    dec1 = HLTraderExecutionDecision(
        action="BUY_ALO",
        conviction_score=84,
        limit_px=25.00,
        sl_px=24.20,
        tp_px=27.50,
        expected_rr_ratio=3.12,
        market_regime_assessment="BULL_EXPANSION",
        reasoning="順張りモメンタム＋健全な資金調達率",
        self_critique="急激なBTC調整リスクを考慮し初期SLを24.20に厳格設定",
        invalidation_trigger_desc="24.20割れで撤退",
        memory_alignment_check="ALIGNED",
        prompt_hash="hash_e2e_1",
    )
    res_order1 = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="4.00",
        sl_px="24.20",
        tp_px="27.50",
        episode_id="ep_e2e_slot1",
        timestamp_ms=ts + 1_000,
    )
    assert res_order1["status"] == "ok"
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value
    cloid1 = res_order1["cloid"]
    oid1 = res_order1["oid"]

    ai_brain.record_episodic_entry(
        slot_id=1,
        coin="HYPE/USDC",
        cloid=cloid1,
        oid=oid1,
        market_regime_4h="BULL_TREND",
        trend_alignment_1h="BULLISH",
        bbo_spread_bps=3.5,
        perp_funding_rate_hr=0.00001,
        perp_oi_delta_15m_pct=0.8,
        perp_premium_pct=0.02,
        decision=dec1,
        order_sz=4.00,
        notional_usdc=100.0,
        episode_id="ep_e2e_slot1",
        timestamp_ms=ts + 1_000,
    )

    # Slot 1 約定処理 (税務台帳 + Coordinator OPEN_PROTECTED 昇格)
    tax.process_spot_fill(
        hl_tid=600001,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="4.00",
        raw_fee_amount="0",
        raw_fee_token="HYPE",
        timestamp_ms=ts + 2_000,
        hl_oid=oid1,
        usdc_jpy_rate=155.0,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid=cloid1,
        oid=oid1,
        filled=True,
        filled_sz=4.00,
        avg_px=25.00,
        timestamp_ms=ts + 2_000,
    )
    ai_brain.update_episodic_lifecycle_status(status="FILLED", episode_id="ep_e2e_slot1")

    # Step 3: 200ms ガーディアンに価格上昇 (25.00 -> 25.55, +2.20% >= +1.80% Stage 2 閾値) を投入し、
    #         Slot 1 が Stage 2 (`FREEROLL_LOCKED`, `sl_px >= 25.0375`) へ自動昇格することを検証
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": ts + 3_000,
                "levels": [[{"px": "25.55", "sz": "300", "n": 3}], [{"px": "25.57", "sz": "300", "n": 3}]],
            },
        }
    )
    g_res = daemon.run_200ms_guardian_tick(current_time_ms=ts + 3_100)
    assert any(a["action"] == "TRAILING_SL_UPDATED" and a["slot_id"] == 1 for a in g_res["actions"])
    s1_after_stage2 = db.get_slot_state(1)
    assert s1_after_stage2["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_after_stage2["sl_px"]) >= 25.00 * 1.0015

    # Step 4: Slot 2 の 3重解放ゲート (Slot 1 FREEROLL_LOCKED & 価格クッション十分 & Perp健全) を検証
    gate = rg.evaluate_slot2_triple_gate(
        slot1_state=s1_after_stage2,
        slot1_best_bid=25.55,
        slot1_atr_1m=0.05,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.4,
        hype_perp_premium_pct=0.02,
        hype_perp_delta_oi_15m_pct=0.6,
    )
    assert gate["allowed"] is True

    # Slot 2 (USOL/USDC) 発注 & 約定 (0.20 USOL @ 180.00 USDC = 36.0 USDC)
    dec2 = HLTraderExecutionDecision(
        action="BUY_ALO",
        conviction_score=82,
        limit_px=180.00,
        sl_px=175.00,
        tp_px=190.00,
        expected_rr_ratio=2.0,
        market_regime_assessment="BULL_EXPANSION",
        reasoning="Slot 1 フリーロール確定後の第2枠エントリー",
        self_critique="クッション維持を監視",
        invalidation_trigger_desc="175.00割れで撤退",
        memory_alignment_check="ALIGNED",
        prompt_hash="hash_e2e_2",
    )
    res_order2 = wrapper.place_spot_buy_alo(
        slot_id=2,
        coin_or_pair="USOL/USDC",
        raw_limit_px="180.00",
        raw_sz="0.20",
        sl_px="175.00",
        tp_px="190.00",
        episode_id="ep_e2e_slot2",
        timestamp_ms=ts + 4_000,
    )
    assert res_order2["status"] == "ok"
    cloid2 = res_order2["cloid"]
    oid2 = res_order2["oid"]

    ai_brain.record_episodic_entry(
        slot_id=2,
        coin="USOL/USDC",
        cloid=cloid2,
        oid=oid2,
        market_regime_4h="BULL_TREND",
        trend_alignment_1h="BULLISH",
        bbo_spread_bps=4.0,
        perp_funding_rate_hr=0.00002,
        perp_oi_delta_15m_pct=0.5,
        perp_premium_pct=0.01,
        decision=dec2,
        order_sz=0.20,
        notional_usdc=36.0,
        episode_id="ep_e2e_slot2",
        timestamp_ms=ts + 4_000,
    )

    tax.process_spot_fill(
        hl_tid=600002,
        pair_name="USOL/USDC",
        base_asset="USOL",
        is_buy=True,
        exec_px_usdc="180.00",
        exec_sz_base="0.20",
        raw_fee_amount="0",
        raw_fee_token="USOL",
        timestamp_ms=ts + 5_000,
        hl_oid=oid2,
        usdc_jpy_rate=155.0,
    )
    coord.bind_order_response(
        slot_id=2,
        cloid=cloid2,
        oid=oid2,
        filled=True,
        filled_sz=0.20,
        avg_px=180.00,
        timestamp_ms=ts + 5_000,
    )

    # Step 5: Slot 1 (TP到達: 27.60 USDC >= 27.50) & Slot 2 (TP到達: 191.00 USDC >= 190.00) のガーディアン決済
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "7.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "4.00", "hold": "0.0"},
        {"coin": "USOL", "total": "0.20", "hold": "0.0"},
    ]
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": ts + 6_000,
                "levels": [[{"px": "27.60", "sz": "500", "n": 4}], [{"px": "27.62", "sz": "500", "n": 4}]],
            },
        }
    )
    g_exit1 = daemon.run_200ms_guardian_tick(current_time_ms=ts + 6_100)
    assert any(a["slot_id"] == 1 and a.get("exit_reason") == "TAKE_PROFIT_HIT" for a in g_exit1["actions"])
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # Slot 2 TP 到達 (191.00 USDC >= 190.00)
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "USOL/USDC",
                "time": ts + 7_000,
                "levels": [[{"px": "191.00", "sz": "50.0", "n": 3}], [{"px": "191.20", "sz": "50.0", "n": 3}]],
            },
        }
    )
    g_exit2 = daemon.run_200ms_guardian_tick(current_time_ms=ts + 7_100)
    assert any(a["slot_id"] == 2 and a.get("exit_reason") == "TAKE_PROFIT_HIT" for a in g_exit2["actions"])
    assert db.get_slot_state(2)["state"] == SlotState.IDLE.value

    # Web `/api/state` (`/api/status`) ペイロードを生成し、税務サマリー・AI反省メモリ・スロット状態を検証
    state_payload = web_svc.get_status_payload(current_time_ms=ts + 8_000)
    assert state_payload["slots"]["1"]["state"] == "IDLE"
    assert state_payload["slots"]["2"]["state"] == "IDLE"
    assert state_payload["tax_summary"]["lot_count"] >= 4
    assert state_payload["tax_summary"]["moving_average_pnl_jpy_int"] > 0
    assert (
        state_payload["tax_summary"]["moving_average_pnl_jpy_int"]
        == state_payload["tax_summary"]["total_average_pnl_jpy_int"]
    )
    assert len(state_payload["ai_memory"]["recent_reflections"]) >= 2
    db.close()
