"""
HL AI Trader v1 — Phase 6 Comprehensive Audit Round 1 Regression & Live Integration Test Suite
(tests/test_phase6_audit_round1.py)

重点検証項目 (Audit Round 1 全8領域):
1. Hyperliquid「Unified Account（統合口座: 143.73 USDC）」における残高認識・`spot_user_state` 互換・誤振替防止 (`auto_transfer_perp_to_spot_usdc`)
2. 実 Hyperliquid Mainnet `/info` API (`spot_meta_and_asset_ctxs`, `meta_and_asset_ctxs`, `l2_snapshot`, `candles_snapshot`) との実データ疎通および `@index` ペアの正規判定修正検証
3. 3並列ループと状態遷移・二重課税イベント台帳 (`_on_ws_spot_fill` による `ENTRY_PENDING` ➔ `OPEN_PROTECTED` 即時遷移・`sl_px`/`tp_px` 保持・`tax_lots` 二重計上)
4. `143.73 USDC` 実残高でのサイジング検証、および `< 10.0 USDC` 端数自己復旧における「アクティブスロット保護（`OPEN_PROTECTED` / `ENTRY_PENDING` 残高を絶対に端数誤認・売却しない）」排他制御検証
5. L1〜L5 サーキットブレーカーの `06:00 JST` 日次 (`sod_equity_usdc`, `daily_trade_count=0`)・月曜 `06:00 JST` 週次 (`sow_equity_usdc`) ロールオーバーと `initial_equity_usdc == 0.0` ゼロ除算/誤発動防止ガード
6. Gemini AI SDK (`google-genai`) による実API接続・未提供モデル (`gemini-3.8-flash`) からの自動フェイルオーバー (`gemini-2.5-flash`)・429/タイムアウト時の安全フォールバック検証
7. Webサーバー (`/`, `/api/status`, `/api/state`, `/api/chart`, `/api/candles`, `/api/command`) の実データ連携・PAUSED初期状態・0秒ボタン操作検証
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict

import pytest

from src.ai_brain import DebiasedAIBrain, HL_TRADER_DECISION_JSON_SCHEMA
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState, SystemMode
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HLSDKInfo, HyperliquidExchangeWrapper, MAINNET_API_URL
from src.main import HLTraderDaemon
from src.radar import MarketRadarAndFilter
from src.risk_guard import (
    RiskAndCircuitBreakerEngine,
    get_current_0600_jst_anchor_ms,
    get_current_monday_0600_jst_anchor_ms,
    get_next_0600_jst_ms,
    get_next_monday_0600_jst_ms,
)
from src.utils import ensure_windows_ca_bundle, get_secret, load_safe_dotenv
from src.web_server import (
    DashboardStateService,
    create_dashboard_http_server,
    sync_live_readonly_account_state,
)
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo

JST = timezone(timedelta(hours=9))
BASE_DIR = Path(__file__).resolve().parent.parent
load_safe_dotenv(BASE_DIR / ".env")


# ==============================================================================
# 1. Unified Account USDC Balance & No-Transfer Guard + Live Read-Only Probe
# ==============================================================================
def test_audit1_unified_account_balance_and_live_readonly_info(tmp_path: Path) -> None:
    ca_path = ensure_windows_ca_bundle()
    assert ca_path is not None and Path(ca_path).exists()

    db = DatabaseManager(db_path=tmp_path / "audit1.db")
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)

    main_addr = os.getenv("HL_MAIN_ADDRESS", "0xa226258389cf6ff2e3ddb92fc072f8b85fc48777")
    agent_pk = get_secret("HL_AGENT_PRIVATE_KEY")
    info_cli = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True)

    wrapper = HyperliquidExchangeWrapper(
        main_address=main_addr,
        agent_private_key=agent_pk,
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=info_cli,
    )

    # 1. Unified Account 判定が True になること
    spot_state = wrapper._fetch_spot_clearinghouse_state()
    assert wrapper.is_unified_account(spot_state) is True

    # 2. Spot USDC 残高および保有Spotトークン残高が正確に取得できること
    balances = wrapper.get_spot_balances(spot_state)
    assert "USDC" in balances
    assert float(balances["USDC"]["total"]) > 0.0
    assert float(balances["USDC"]["free"]) >= 0.0

    # 3. Unified Account 環境では auto_transfer_perp_to_spot_usdc が usd_class_transfer を呼ばず安全にスキップすること
    tr_res = wrapper.auto_transfer_perp_to_spot_usdc(only_when_spot_below_usdc=500.0)
    assert tr_res["transferred"] is False
    assert tr_res["unified_account"] is True
    assert tr_res["reason"] == "UNIFIED_ACCOUNT_NO_TRANSFER_NEEDED"

    # 4. Agent Wallet (0x3128...5c2) が extra_agents に登録済みで有効期限内であること
    validity = wrapper.check_agent_wallet_validity(raise_on_invalid=True)
    assert validity["valid"] is True
    assert validity["remaining_hours"] > 100.0
    db.close()


# ==============================================================================
# 2. Live Hyperliquid `/info` Universe Mapping (`@index` Canonical Fix) & Radar
# ==============================================================================
def test_audit2_live_universe_mapping_and_7stage_filter(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "audit2.db")
    info_cli = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True)
    wrapper = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        info_client=info_cli,
    )
    universe = wrapper.refresh_universe_mapping()

    # HYPE/USDC (@107), UBTC/USDC (@142), UETH/USDC (@151), USOL/USDC (@156), PURR/USDC がすべて正規ペアとして認識されること
    for pair_name, expected_perp in (
        ("HYPE/USDC", "HYPE"),
        ("UBTC/USDC", "BTC"),
        ("UETH/USDC", "ETH"),
        ("USOL/USDC", "SOL"),
        ("PURR/USDC", "PURR"),
    ):
        assert pair_name in universe, f"{pair_name} missing from universe"
        entry = universe[pair_name]
        assert entry.is_canonical is True, f"{pair_name} should be canonical"
        assert entry.quote_token_idx == 0
        assert entry.perp_coin == expected_perp
        assert entry.spot_mid_px > 0

    # 実 l2_snapshot と candles_snapshot を用いた 7段階フィルタ & MTF 指標算出検証
    radar = MarketRadarAndFilter()
    hype_entry = universe["HYPE/USDC"]
    live_l2 = info_cli.l2_snapshot(hype_entry.api_coin_name)
    filter_res = radar.evaluate_7_stage_filter(hype_entry, live_l2)
    assert filter_res.failed_stage != "GATE1_CANONICAL_USDC"
    assert filter_res.best_bid > 0 and filter_res.best_ask >= filter_res.best_bid

    now_ts = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    raw_15m = info_cli.candles_snapshot(hype_entry.api_coin_name, "15m", now_ts - 60 * 15 * 60_000, now_ts)
    raw_1h = info_cli.candles_snapshot(hype_entry.api_coin_name, "1h", now_ts - 60 * 60 * 60_000, now_ts)
    raw_4h = info_cli.candles_snapshot(hype_entry.api_coin_name, "4h", now_ts - 60 * 4 * 60 * 60_000, now_ts)
    assert len(raw_15m) >= 20 and len(raw_1h) >= 20 and len(raw_4h) >= 20

    mtf = radar.compute_mtf_indicators("HYPE/USDC", raw_4h, raw_1h, raw_15m)
    assert mtf["market_regime_4h"] in (
        "BULL_EXPANSION",
        "BULL_PULLBACK",
        "NEUTRAL_RANGE",
        "DISTRIBUTION_RISK",
        "BEAR_CASCADE_RISK",
    )
    assert mtf["atr_1h_pct"] > 0.0
    db.close()


# ==============================================================================
# 3. WS Fill Callback (`ENTRY_PENDING` -> `OPEN_PROTECTED` + `sl_px`/`tp_px` + Tax)
# ==============================================================================
def test_audit3_ws_fill_transitions_slot_and_preserves_sl_tp_and_records_tax(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "audit3.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    tax.seed_opening_or_deposit("USDC", "143.73", "158.0", tax_year=2026, timestamp_ms=1_775_000_000_000)

    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
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

    # 1. Alo 新規買い発注 -> Slot 1 が ENTRY_PENDING (sl_px=24.20, tp_px=27.50) になる
    order_res = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="2.00",
        sl_px="24.20",
        tp_px="27.50",
        timestamp_ms=1_775_000_010_000,
    )
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    # 2. WebSocket userFills イベント着弾 -> 自動的に OPEN_PROTECTED へ遷移し sl_px / tp_px が保持され、tax_lots にも計上されること
    daemon.ws.handle_raw_message(
        {
            "channel": "userFills",
            "data": {
                "isSnapshot": False,
                "user": wrapper.main_address,
                "fills": [
                    {
                        "coin": "@107",
                        "px": "25.00",
                        "sz": "2.00",
                        "side": "B",
                        "time": 1_775_000_012_000,
                        "fee": "0.002",
                        "feeToken": "HYPE",
                        "tid": 99001,
                        "oid": order_res["oid"],
                    }
                ],
            },
        }
    )

    s1 = db.get_slot_state(1)
    assert s1["state"] == SlotState.OPEN_PROTECTED.value
    assert s1["sub_state"] == SlotSubState.INITIAL_RISK.value
    assert float(s1["sl_px"]) == pytest.approx(24.20)
    assert float(s1["tp_px"]) == pytest.approx(27.50)
    assert float(s1["current_sz"]) == pytest.approx(1.998)  # 2.00 - 0.002 HYPE fee

    tax_sum = tax.calculate_annual_summary(tax_year=2026, method="MOVING_AVERAGE")
    assert tax_sum["lot_count"] == 1
    db.close()


# ==============================================================================
# 4. 143.73 USDC Sizing & Active-Slot Protection from Orphan Dust Recovery
# ==============================================================================
def test_audit4_sizing_with_143_73_usdc_and_active_slot_dust_protection(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "audit4.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
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

    daemon = HLTraderDaemon(db=db, coordinator=coord, tax_engine=tax, exchange_wrapper=wrapper)

    # 1. 143.73 USDC での Single-Bullet サイジング検証 (Slot 1 max 70% = 100.611 USDC, 1R = 2.8746 USDC)
    sz1 = daemon.risk_guard.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=143.73,
        free_usdc=143.73,
        entry_px=41.50,
        sl_px=39.90,  # SL距離 3.855% <= 8.0%
        sz_decimals=2,
    )
    assert sz1["eligible"] is True
    assert 16.0 <= sz1["notional_usdc"] <= 143.73 * 0.70

    # 2. アクティブスロット保護テスト:
    # Slot 1 が HYPE/USDC で OPEN_PROTECTED の間に、仮に HYPE 残高が 0.20 HYPE (5.0 USDC < 10.0 USDC) であっても、
    # アクティブスロットで管理中の銘柄は絶対に端数 (Orphan Dust) として売却されないこと!
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.00,
        sz=0.80,
        sl_px=24.00,
        tp_px=27.00,
    )
    coord.bind_order_response(slot_id=1, cloid=intent["cloid"], oid=555, filled=True, filled_sz=0.20, avg_px=25.00)

    mock_info.spot_balances = [
        {"coin": "USDC", "total": "138.73", "hold": "0.0"},
        {"coin": "USDE", "total": "0.0", "hold": "0.0"},
        {"coin": "HYPE", "total": "0.20", "hold": "0.0"},  # 5.0 USDC 相当だが Slot 1 が OPEN_PROTECTED
    ]

    # 直接 recover_dust_top_up_and_dump を呼んでも ACTIVE_SLOT_PROTECTED でブロックされること
    direct_res = wrapper.recover_dust_top_up_and_dump(
        coin_or_pair="HYPE/USDC",
        best_bid="25.00",
        best_ask="25.02",
    )
    assert direct_res["recovered"] is False
    assert "ACTIVE_SLOT_PROTECTED" in direct_res["reason"]

    # 15秒ループの scan_and_recover_orphan_dust でも HYPE がスキップされること
    ctrl_res = daemon.run_15s_control_tick(current_time_ms=2_000_000)
    assert len(ctrl_res["orphan_dust_actions"]) == 0
    assert db.get_slot_state(1)["state"] == SlotState.OPEN_PROTECTED.value
    db.close()


# ==============================================================================
# 5. 06:00 JST Daily/Weekly Rollover & Zero-Equity Initialization Guard
# ==============================================================================
def test_audit5_0600_jst_rollover_and_zero_equity_seed_guard(tmp_path: Path) -> None:
    # initial_equity_usdc = 0.0 で初期化されたDBでもゼロ除算や誤L5発動が起きないこと
    db = DatabaseManager(db_path=tmp_path / "audit5.db", initial_equity_usdc=0.0)
    coord = ConcurrencyStateCoordinator(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)

    # 1. equity_usdc = 0.0 の初期ティックで L5 が誤発動しないこと
    cb_zero = rg.evaluate_circuit_breakers(equity_usdc=0.0, current_time_ms=1_775_000_000_000)
    assert cb_zero["l5_strikes"] == 0
    assert cb_zero["system_mode"] == SystemMode.NORMAL.value

    # 2. 実残高 143.73 USDC が入った最初のティックで initial/hwm/sod/sow が 143.73 に自動シードされること
    # 2026-10-25 (日曜) 05:50 JST
    dt_sun_0550 = datetime(2026, 10, 25, 5, 50, 0, tzinfo=JST)
    ts_sun_0550 = int(dt_sun_0550.timestamp() * 1000)
    cb_seed = rg.evaluate_circuit_breakers(equity_usdc=143.73, current_time_ms=ts_sun_0550)
    assert cb_seed["initial_equity_usdc"] == pytest.approx(143.73)
    assert cb_seed["sod_equity_usdc"] == pytest.approx(143.73)
    assert cb_seed["sow_equity_usdc"] == pytest.approx(143.73)

    # 3. 日曜 06:05 JST を跨いだ瞬間に sod_equity_usdc が新残高 (148.50) にロールオーバーされ、sow_equity_usdc は維持されること
    dt_sun_0605 = datetime(2026, 10, 25, 6, 5, 0, tzinfo=JST)
    ts_sun_0605 = int(dt_sun_0605.timestamp() * 1000)
    cb_daily = rg.evaluate_circuit_breakers(equity_usdc=148.50, current_time_ms=ts_sun_0605)
    assert cb_daily["daily_rolled"] is True
    assert cb_daily["weekly_rolled"] is False
    assert cb_daily["sod_equity_usdc"] == pytest.approx(148.50)
    assert cb_daily["sow_equity_usdc"] == pytest.approx(143.73)

    # 4. 月曜 06:05 JST を跨いだ瞬間に sod_equity_usdc と sow_equity_usdc の両方が新残高 (152.00) にロールオーバーされること
    dt_mon_0605 = datetime(2026, 10, 26, 6, 5, 0, tzinfo=JST)
    ts_mon_0605 = int(dt_mon_0605.timestamp() * 1000)
    cb_weekly = rg.evaluate_circuit_breakers(equity_usdc=152.00, current_time_ms=ts_mon_0605)
    assert cb_weekly["daily_rolled"] is True
    assert cb_weekly["weekly_rolled"] is True
    assert cb_weekly["sod_equity_usdc"] == pytest.approx(152.00)
    assert cb_weekly["sow_equity_usdc"] == pytest.approx(152.00)
    db.close()


# ==============================================================================
# 6. Gemini AI SDK Model Failover & 429/Timeout Resilience
# ==============================================================================
def test_audit6_gemini_sdk_failover_and_exception_resilience(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "audit6.db")

    # 1. LLM caller が 429 Rate Limit や Timeout 例外を投げた場合でもクラッシュせずルールベースフォールバックへ移行すること
    def _failing_caller(prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        raise TimeoutError("Simulated Gemini 429 / Timeout error")

    brain_fail = DebiasedAIBrain(db=db, llm_caller=_failing_caller)
    dec_fb = brain_fail.evaluate_candidate(
        pair_name="HYPE/USDC",
        sz_decimals=2,
        best_bid=41.50,
        mtf_indicators={"market_regime_4h": "BULL_EXPANSION", "entry_eligible": True, "sl_init_pct": 2.0, "tp_target_pct": 4.5},
        perp_signals={"long_flush_blocked": False, "basis_blocked": False, "short_squeeze_boost": True},
        bbo_spread_bps=3.0,
    )
    assert dec_fb.action in ("BUY_ALO", "SKIP")
    assert brain_fail.last_fallback_reason is not None
    assert "TimeoutError" in brain_fail.last_fallback_reason

    # 2. 実 GEMINI_API_KEY が設定されている場合、gemini-3.8-flash (404) から gemini-2.5-flash へ自動フェイルオーバーして
    #    11フィールドの JSON Schema 応答を取得できること (または 429 時に None を返して安全フォールバックすること)
    if get_secret("GEMINI_API_KEY"):
        brain_live = DebiasedAIBrain(db=db, gemini_model="gemini-3.8-flash", use_live_llm=True)
        prompt, p_hash, _ = brain_live.compile_debiased_prompt(
            pair_name="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            market_features={"best_bid": 41.50, "rsi_15m": 55.0, "atr_1h_pct": 2.1},
        )
        live_dict = brain_live._call_gemini_structured_output(prompt, HL_TRADER_DECISION_JSON_SCHEMA)
        if live_dict is not None:
            assert brain_live.last_model_used in ("gemini-2.5-flash", "gemini-3-flash-preview", "gemini-3.8-flash")
            parsed_dec = brain_live.parse_and_validate_decision(
                raw_output=live_dict,
                best_bid=41.50,
                sz_decimals=2,
                prompt_hash=p_hash,
            )
            assert parsed_dec.action in ("BUY_ALO", "SKIP")
    db.close()


# ==============================================================================
# 7. Web Server Aliases (`/api/state`, `/api/candles`) & Live Readonly Sync
# ==============================================================================
def test_audit7_web_server_aliases_and_live_readonly_sync(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "audit7.db", initial_equity_usdc=0.0)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    info_cli = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True)
    wrapper = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=info_cli,
    )
    daemon = HLTraderDaemon(db=db, coordinator=coord, tax_engine=tax, exchange_wrapper=wrapper)
    service = DashboardStateService(db=db, tax_engine=tax, coordinator=coord, daemon=daemon)

    # 実アカウント残高 (143.73 USDC) と PAUSED 初期状態を同期
    st_init = sync_live_readonly_account_state(service, pause_on_init=True)
    assert st_init["status_badge"] == "PAUSED"
    assert st_init["operator_paused"] is True
    assert st_init["equity"]["current_usdc"] >= 100.0

    server = create_dashboard_http_server(service=service, host="127.0.0.1", port=0)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    base_url = f"http://127.0.0.1:{port}"
    auth_token = service.auth_manager.issue_session_token()
    auth_hdrs = {"X-HL-Auth": auth_token}
    try:
        # /api/state (alias of /api/status)
        req_state = urllib.request.Request(f"{base_url}/api/state", headers=auth_hdrs)
        with urllib.request.urlopen(req_state) as r:
            data = json.loads(r.read().decode("utf-8"))
            assert r.status == 200
            assert data["status_badge"] == "PAUSED"
            assert data["equity"]["current_usdc"] >= 100.0

        # /api/candles?coin=HYPE/USDC&interval=15m (alias of /api/chart)
        req_candles = urllib.request.Request(
            f"{base_url}/api/candles?coin=HYPE/USDC&interval=15m", headers=auth_hdrs
        )
        with urllib.request.urlopen(req_candles) as r:
            c_data = json.loads(r.read().decode("utf-8"))
            assert r.status == 200
            assert c_data["pair_name"] == "HYPE/USDC"
            assert len(c_data["candles"]) >= 20
            assert c_data["candles"][-1]["c"] > 0
    finally:
        server.shutdown()
        server.server_close()
        db.close()
