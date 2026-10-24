"""
HL AI Trader v1 — Phase 3, Phase 4 & Phase 5 Comprehensive Unit & Integration Test Suite
(tests/test_phase3_to_phase5.py)

検証対象:
- Phase 3 (`src/radar.py`, `src/ai_brain.py`):
  1. 7段階マイクロストラクチャ・フィルタ (Gate 1〜Gate 7) ＆ HIP-2 (0.30%等間隔・均一数量グリッド) 検知排除
  2. マルチタイムフレーム (4H/1H/15m) デカップリング指標 ＆ 大型/高ボラ銘柄別の最小1H/15m ATR%閾値
  3. Perp オンチェーン需給統合 (Long-Flush Blocker, Short-Squeeze Boost, Spot-Oracle Basis > +0.20%)
  4. 脱バイアス3層AI記憶プロンプトコンパイラ (口座残高・連敗数の完全秘匿、指数減衰重み上位3件の教訓、直近20件のShadow統計注入)
  5. Gemini Structured Output (`HLTraderExecutionDecision`) の検証・クランプ・ハードVeto・事後Shadow評価更新
- Phase 4 (`src/risk_guard.py`, `src/main.py`):
  6. Single-Bullet サイジング、第2枠 (Slot 2) 解放の3重ゲート、親子スロット連動インターロック、事後リスクバジェット再計算
  7. 多層価格サニティフィルタ (TAINTED時最大4周期保持)、`Total_USDC` (`hold` 含む) 総資産算出式、L1〜L5 サーキットブレーカー (L5の12秒以上間隔・3回連続確認ガード)
  8. 200ms高速ガーディアン (4段階トレーリング・Perp清算カスケード3ティック脱出)、15秒制御ループ (4h失効)、15分AIループ、Phase 1/2 運用期限スケジューラ
- Phase 5 (`src/web_server.py`, `watchdog.py`):
  9. Webダッシュボード API (`/`, `/api/status`, `/api/chart` の Entry/SL/TP 水平ライン描画データ)
  10. 0秒同期の操作ボタン (`PAUSE`, `RESUME`, `CLEAR_PENDING_BUYS`, `EMERGENCY_LIQUIDATE_ALL` 2段階確認) ＆ Git非干渉オフセット (`08, 23, 38, 53分`)・`.hl_gitconfig` 隔離
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState, SystemMode
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper, SpotUniverseEntry
from src.main import HLTraderDaemon
from src.radar import MarketRadarAndFilter
from src.risk_guard import RiskAndCircuitBreakerEngine
from src.web_server import (
    DashboardStateService,
    build_isolated_git_env,
    create_dashboard_http_server,
    should_run_git_push_at_minute,
)
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo

JST = timezone(timedelta(hours=9))


def _make_healthy_l2_book(mid: float = 25.00) -> Dict[str, Any]:
    """スプレッド <= 0.04% (4 bps)、±0.30% 板厚 >= 10,000 USDC、非均一ステップの健全な板データを生成"""
    return {
        "coin": "@107",
        "levels": [
            [
                {"px": f"{mid * 0.9998:.4f}", "sz": "120.0", "n": 4},
                {"px": f"{mid * 0.9992:.4f}", "sz": "250.0", "n": 6},
                {"px": f"{mid * 0.9985:.4f}", "sz": "85.0", "n": 3},
                {"px": f"{mid * 0.9979:.4f}", "sz": "310.0", "n": 7},
                {"px": f"{mid * 0.9972:.4f}", "sz": "190.0", "n": 5},
            ],
            [
                {"px": f"{mid * 1.0002:.4f}", "sz": "130.0", "n": 4},
                {"px": f"{mid * 1.0009:.4f}", "sz": "220.0", "n": 5},
                {"px": f"{mid * 1.0016:.4f}", "sz": "95.0", "n": 3},
                {"px": f"{mid * 1.0022:.4f}", "sz": "280.0", "n": 6},
                {"px": f"{mid * 1.0028:.4f}", "sz": "175.0", "n": 4},
            ],
        ],
    }


def _make_hip2_uniform_l2_book(mid: float = 25.00) -> Dict[str, Any]:
    """上位5レベルがすべて 0.30% 等間隔かつ均一サイズ (HIP-2 グリッドMM露出, ±0.30%内板厚 >= 5000 USDC) の板データを生成"""
    bids = []
    asks = []
    b_px = mid * (1.0 - 0.0002)
    a_px = mid * (1.0 + 0.0002)
    for _ in range(5):
        bids.append({"px": f"{b_px:.6f}", "sz": "300.0", "n": 1})
        asks.append({"px": f"{a_px:.6f}", "sz": "300.0", "n": 1})
        b_px *= (1.0 - 0.0030)
        a_px *= (1.0 + 0.0030)
    return {"coin": "@107", "levels": [bids, asks]}


def _make_trending_candles(count: int = 60, start_px: float = 20.0, step_pct: float = 0.012) -> List[Dict[str, Any]]:
    """上昇トレンドかつ十分なATR%を持つローソク足配列を生成"""
    candles: List[Dict[str, Any]] = []
    px = start_px
    for i in range(count):
        o = px
        c = px * (1.0 + step_pct * 0.35)
        h = max(o, c) * (1.0 + step_pct)
        l = min(o, c) * (1.0 - step_pct * 0.8)
        candles.append({"t": 1_775_000_000_000 + i * 3_600_000, "o": o, "h": h, "l": l, "c": c, "v": 5000.0})
        px = c
    return candles


# ==============================================================================
# 1. Phase 3: 7-Stage Filter, HIP-2 Guard, MTF & Perp Signals (`src/radar.py`)
# ==============================================================================
def test_radar_7_stage_filter_and_hip2_and_perp_signals() -> None:
    radar = MarketRadarAndFilter()

    entry = SpotUniverseEntry(
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
        spot_mark_px=25.005,  # 乖離 0.02% <= 0.08%
        spot_day_ntl_vlm=25_000_000.0,
        perp_mark_px=25.00,
        perp_oracle_px=25.00,
        perp_funding_1h=0.00001,
        perp_premium=0.0002,
    )

    healthy_book = _make_healthy_l2_book(25.00)

    # 1. 健全な板・出来高・Perp状態では全7ゲートを通過すること
    res_ok = radar.evaluate_7_stage_filter(entry, healthy_book)
    assert res_ok.passed is True
    assert res_ok.tier == 1

    # 2. Gate 1: Builder Fee > 0 または非正規ペアは除外
    res_g1 = radar.evaluate_7_stage_filter(entry, healthy_book, builder_fee_bps=1.0)
    assert res_g1.passed is False
    assert res_g1.failed_stage == "GATE1_CANONICAL_USDC"

    # 3. Gate 2: Tier 1 で 24h出来高 < 5,000,000 USDC は除外
    low_vlm_entry = SpotUniverseEntry(**{**entry.__dict__, "spot_day_ntl_vlm": 3_000_000.0})
    res_g2 = radar.evaluate_7_stage_filter(low_vlm_entry, healthy_book)
    assert res_g2.passed is False
    assert res_g2.failed_stage == "GATE2_VOLUME_24H"

    # 4. Gate 3: Mark-Mid 乖離 > 0.08% は除外
    div_entry = SpotUniverseEntry(**{**entry.__dict__, "spot_mark_px": 25.05})  # 0.20% > 0.08%
    res_g3 = radar.evaluate_7_stage_filter(div_entry, healthy_book)
    assert res_g3.passed is False
    assert res_g3.failed_stage == "GATE3_MARK_MID_DIVERGENCE"

    # 5. Gate 6: HIP-2 均一0.30%ステップ検知ガード
    hip2_book = _make_hip2_uniform_l2_book(25.00)
    res_g6 = radar.evaluate_7_stage_filter(entry, hip2_book)
    assert res_g6.passed is False
    assert res_g6.failed_stage == "GATE6_HIP2_UNIFORM_GRID_EXPOSED"
    assert res_g6.hip2_exposed is True

    # 6. Gate 7: Perp Long-Flush Blocker & Short-Squeeze Boost & Basis Guard
    p_flush = radar.evaluate_perp_signals(
        funding_1h_pct=0.0055,  # >= +0.0050%
        premium_pct=0.18,       # >= +0.15%
        delta_oi_4h_pct=6.5,    # >= +6.0%
        spot_mid_px=25.00,
        perp_oracle_px=25.00,
    )
    assert p_flush["long_flush_blocked"] is True
    res_g7_flush = radar.evaluate_7_stage_filter(entry, healthy_book, perp_signals=p_flush)
    assert res_g7_flush.passed is False
    assert res_g7_flush.failed_stage == "GATE7_PERP_LONG_FLUSH_BLOCKER"

    p_squeeze = radar.evaluate_perp_signals(
        funding_1h_pct=-0.0020,  # < 0.0000%
        premium_pct=-0.08,       # <= -0.05%
        delta_oi_1h_pct=3.2,     # >= +2.5%
        spot_mid_px=25.00,
        perp_oracle_px=25.00,
        regime_bullish=True,
    )
    assert p_squeeze["short_squeeze_boost"] is True
    res_squeeze = radar.evaluate_7_stage_filter(entry, healthy_book, perp_signals=p_squeeze)
    assert res_squeeze.passed is True
    assert res_squeeze.short_squeeze_boost is True

    # 7. マルチタイムフレーム (4H / 1H / 15m) デカップリング指標算出
    c4h = _make_trending_candles(60, 20.0, 0.015)
    c1h = _make_trending_candles(60, 22.0, 0.015)
    c15m = _make_trending_candles(60, 24.0, 0.008)
    mtf = radar.compute_mtf_indicators("HYPE/USDC", c4h, c1h, c15m)
    assert mtf["regime_4h_ok"] is True
    assert mtf["atr_gate_passed"] is True
    assert mtf["entry_eligible"] is True
    assert 2.00 <= mtf["sl_init_pct"] <= 5.00
    assert mtf["tp_target_pct"] >= 3.20


# ==============================================================================
# 2. Phase 3: Debiased 3-Tier AI Memory & Structured Output (`src/ai_brain.py`)
# ==============================================================================
def test_ai_brain_debiased_prompt_and_structured_output_veto(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "ai_brain_test.db")
    brain = DebiasedAIBrain(db=db)
    now = 1_775_500_000_000

    # Episodic & Reflection 記憶を4件投入し、指数減衰重み上位3件が選ばれるか検証
    for i in range(4):
        ep_id = brain.record_episodic_entry(
            slot_id=1,
            coin="HYPE/USDC",
            cloid=f"0x{i+1:032x}",
            oid=100 + i,
            market_regime_4h="BULL_EXPANSION",
            trend_alignment_1h="BULLISH",
            bbo_spread_bps=3.5,
            perp_funding_rate_hr=0.001,
            perp_oi_delta_15m_pct=0.5,
            perp_premium_pct=0.01,
            decision=brain.parse_and_validate_decision(
                {
                    "action": "BUY_ALO",
                    "conviction_score": 82,
                    "limit_px": 25.0,
                    "sl_px": 24.2,
                    "tp_px": 26.8,
                    "expected_rr_ratio": 2.25,
                    "market_regime_assessment": "BULL_EXPANSION",
                    "reasoning": "Test",
                    "self_critique": "Test",
                    "invalidation_trigger_desc": "Test",
                    "memory_alignment_check": "Test",
                },
                best_bid=25.0,
                sz_decimals=2,
            ),
            order_sz=2.0,
            notional_usdc=50.0,
            timestamp_ms=now - (i * 30 * 86_400_000),
        )
        brain.record_reflection_on_close(
            episode_id=ep_id,
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="TAKE_PROFIT_HIT",
            entry_px=25.0,
            exit_px=26.8,
            initial_sl_px=24.2,
            holding_duration_sec=3600,
            distilled_rule=f"RULE_NUMBER_{i+1}",
            importance_weight=1.5 if i < 3 else 0.5,
            closed_at_ms=now - (i * 30 * 86_400_000),
        )

    # Shadow Evaluation の見送り事後追跡テスト (TIMID_MISS と CORRECT_AVOIDANCE)
    sh1 = brain.register_shadow_skip(
        coin="HYPE/USDC",
        market_regime_4h="BULL_EXPANSION",
        skip_stage="AI_SKIP",
        skip_reason_code="LOW_CONVICTION",
        spot_mid_at_eval=25.0,
        hypothetical_sl_px=24.2,
        hypothetical_tp_px=26.6,
        evaluated_at_ms=now - 90_000_000,
    )
    res_sh1 = brain.complete_shadow_evaluation(
        shadow_id=sh1,
        px_after_1h=25.5,
        px_after_4h=26.2,
        px_after_24h=26.8,
        max_high_24h=27.0,
        min_low_24h=24.8,  # SL(24.2)を割らずにTP(26.6)到達 -> TIMID_MISS
    )
    assert res_sh1["shadow_outcome"] == "TIMID_MISS"

    # プロンプトコンパイル: 口座残高や連敗数を意図的に混ぜてもプロンプトから完全秘匿されること
    tainted_features = {
        "rsi_15m": 54.2,
        "atr_1h_pct": 1.85,
        "current_equity_usdc": 134.5678,
        "initial_equity_usdc": 130.0,
        "consecutive_losses": 4,
        "realized_pnl_jpy": -12345.0,
    }
    prompt, p_hash, meta = brain.compile_debiased_prompt(
        pair_name="HYPE/USDC",
        market_regime_4h="BULL_EXPANSION",
        market_features=tainted_features,
        current_time_ms=now,
    )
    assert "134.5678" not in prompt
    assert "consecutive_losses" not in prompt
    assert "-12345" not in prompt
    assert "RULE_NUMBER_1" in prompt
    assert "RULE_NUMBER_2" in prompt
    assert "RULE_NUMBER_3" in prompt
    assert len(meta["reflections_injected"]) == 3

    # Structured Output の検証: conviction < 75 や RR < 1.8 は SKIP に強制Vetoされること
    dec_veto = brain.parse_and_validate_decision(
        {
            "action": "BUY_ALO",
            "conviction_score": 68,  # < 75
            "limit_px": 25.50,       # best_bid(25.00)超え -> 25.00 にクランプ
            "sl_px": 24.50,
            "tp_px": 27.00,
            "expected_rr_ratio": 2.0,
            "market_regime_assessment": "BULL_EXPANSION",
            "reasoning": "Attempt buy",
            "self_critique": "Critique",
            "invalidation_trigger_desc": "Invalidation",
            "memory_alignment_check": "Aligned",
        },
        best_bid=25.00,
        sz_decimals=2,
        min_conviction_score=75,
    )
    assert dec_veto.limit_px == pytest.approx(25.00)
    assert dec_veto.vetoed is True
    assert dec_veto.action == "SKIP"
    db.close()


# ==============================================================================
# 3. Phase 4: Risk Guard, Slot 2 Gates, Interlock, Sanity & L1-L5 (`src/risk_guard.py`)
# ==============================================================================
def test_risk_guard_slot2_gates_interlock_post_loss_and_l5_strikes(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "risk_test.db", initial_equity_usdc=130.0)
    coord = ConcurrencyStateCoordinator(db=db)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)

    # 1. Single-Bullet サイジング (130 USDC, Slot 1 最大70%=91 USDC, 1R=2.60 USDC)
    sz_res = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=130.0,
        free_usdc=130.0,
        entry_px=25.00,
        sl_px=24.00,  # SL距離 4.0% <= 8.0%
        sz_decimals=2,
    )
    assert sz_res["eligible"] is True
    assert sz_res["notional_usdc"] >= 16.0
    assert sz_res["notional_usdc"] <= 91.0

    # 2. 第2枠 (Slot 2) 解放の3重ゲート検証
    slot1_locked = {
        "state": "OPEN_PROTECTED",
        "sub_state": "FREEROLL_LOCKED",
        "entry_px": 25.00,
        "sl_px": 25.05,  # >= 25.00 * 1.0015 (25.0375)
    }
    # クッション十分 (25.05 + 0.15 = 25.20 <= 25.30) & Perp健全 -> allowed=True
    gate_ok = rg.evaluate_slot2_triple_gate(
        slot1_state=slot1_locked,
        slot1_best_bid=25.30,
        slot1_atr_1m=0.05,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.5,
        hype_perp_premium_pct=0.02,
        hype_perp_delta_oi_15m_pct=0.8,
    )
    assert gate_ok["allowed"] is True

    # Perp悪化時 (BTC delta_OI_15m = -2.0% <= -1.5%) -> Gate 3 でブロック
    gate_fail3 = rg.evaluate_slot2_triple_gate(
        slot1_state=slot1_locked,
        slot1_best_bid=25.30,
        slot1_atr_1m=0.05,
        btc_perp_premium_pct=-0.08,
        btc_perp_delta_oi_15m_pct=-2.0,
        hype_perp_premium_pct=0.02,
        hype_perp_delta_oi_15m_pct=0.8,
    )
    assert gate_fail3["allowed"] is False
    assert gate_fail3["failed_gate"] == "GATE3_PERP_REGIME_DETERIORATING"

    # 3. 親子スロット連動インターロック (Slot 1 Bid <= SL_1 * 1.0025 で Slot 2 キャンセル)
    il_res = rg.check_parent_child_interlock(
        slot1_state=slot1_locked,
        slot2_state={"state": "ENTRY_PENDING"},
        slot1_best_bid=25.05 * 1.0010,  # <= 25.05 * 1.0025
    )
    assert il_res["should_cancel_slot2"] is True

    # 4. 事後リスクバジェット再計算 (0 < D_1 < 0.75 * R_max なら SL 引き上げ、>= 0.75 * R_max なら緊急IOC決済)
    # R_max = 130 * 0.02 = 2.60 USDC, 0.75 * R_max = 1.95 USDC
    slot2_open = {
        "state": "OPEN_PROTECTED",
        "entry_px": 180.0,
        "current_sz": 0.20,
        "sl_px": 175.0,
        "sz_decimals": 2,
    }
    post_tight = rg.recalculate_post_slot1_loss_budget(
        equity_usdc=130.0,
        slot1_realized_loss_usdc=1.20,  # < 1.95 USDC -> R_rem = 1.40 USDC -> new_sl = 180 - 1.40/0.20 = 173 -> max(175, 173)=175 or tighter
        slot2_state={**slot2_open, "sl_px": 170.0},
    )
    assert post_tight["action"] == "TIGHTEN_SLOT2_SL"
    assert post_tight["new_sl_px"] == pytest.approx(173.0)

    post_emerg = rg.recalculate_post_slot1_loss_budget(
        equity_usdc=130.0,
        slot1_realized_loss_usdc=2.10,  # >= 1.95 USDC
        slot2_state=slot2_open,
    )
    assert post_emerg["action"] == "EMERGENCY_IOC_FLATTEN_SLOT2"

    # 5. 多層価格サニティフィルタ (TAINTED 時に最大4周期まで直前正常価格を保持)
    v_ok = rg.evaluate_token_price_sanity("HYPE/USDC", best_bid=25.00, best_ask=25.02, mark_px=25.01, perp_oracle_px=25.01)
    assert v_ok["status"] == "VALID"
    assert v_ok["price_tainted"] is False

    # 瞬間的な異常スプレッド/ヒゲ (best_bid=15.0 -> 15秒変化率 > 8.0%)
    v_taint = rg.evaluate_token_price_sanity("HYPE/USDC", best_bid=15.00, best_ask=25.00, mark_px=20.00, perp_oracle_px=25.00)
    assert v_taint["status"] == "TAINTED"
    assert v_taint["price_tainted"] is True
    assert v_taint["p_val"] == pytest.approx(v_ok["p_val"])  # 直前の正常価格が保持されること

    # 6. L5 ハード・キルスイッチ (85% Floor = 110.5 USDC 未満を 12秒以上間隔・価格健全・静止期間外で3回連続確認)
    # TAINTED 中は 100 USDC でもストライクが増えないこと
    cb_tainted = rg.evaluate_circuit_breakers(equity_usdc=100.0, price_tainted_flag=True, current_time_ms=1_000_000)
    assert cb_tainted["l5_strikes"] == 0

    # 価格健全で1回目 (t=1,020,000)
    cb1 = rg.evaluate_circuit_breakers(equity_usdc=105.0, price_tainted_flag=False, current_time_ms=1_020_000)
    assert cb1["l5_strikes"] == 1
    assert cb1["l5_triggered_now"] is False

    # 5秒後 (t=1,025,000 < 12秒間隔) の呼び出しでは同一周期とみなされカウントが増えないこと
    cb_short = rg.evaluate_circuit_breakers(equity_usdc=105.0, price_tainted_flag=False, current_time_ms=1_025_000)
    assert cb_short["l5_strikes"] == 1

    # 15秒後 (t=1,035,000) で2回目
    cb2 = rg.evaluate_circuit_breakers(equity_usdc=105.0, price_tainted_flag=False, current_time_ms=1_035_000)
    assert cb2["l5_strikes"] == 2
    assert cb2["l5_triggered_now"] is False

    # さらに15秒後 (t=1,050,000) で3回目確定 -> HALTED 遷移!
    cb3 = rg.evaluate_circuit_breakers(equity_usdc=105.0, price_tainted_flag=False, current_time_ms=1_050_000)
    assert cb3["l5_strikes"] == 3
    assert cb3["l5_triggered_now"] is True
    assert cb3["system_mode"] == SystemMode.HALTED.value
    db.close()


# ==============================================================================
# 4. Phase 4: Main Daemon (200ms Guardian, 15s Control, Campaign Schedule)
# ==============================================================================
def test_main_daemon_guardian_cascade_trailing_and_campaign_schedule(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "daemon_test.db", initial_equity_usdc=130.0)
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

    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=wrapper,
    )

    # Slot 1 を HYPE/USDC @ 25.00 (SL=24.20, TP=27.50) で OPEN_PROTECTED にセット
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.00,
        sz=3.50,
        sl_px=24.20,
        tp_px=27.50,
        timestamp_ms=10_000,
    )
    coord.bind_order_response(slot_id=1, cloid=intent["cloid"], oid=701, filled=True, filled_sz=3.50, avg_px=25.00, timestamp_ms=10_100)

    # 1. 含み益 +2.0% (Best Bid = 25.50 >= +1.80% 閾値) を WS キャッシュへ投入 -> 200msガーディアンで FREEROLL_LOCKED 昇格
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": 20_000,
                "levels": [[{"px": "25.50", "sz": "100.0", "n": 2}], [{"px": "25.52", "sz": "100.0", "n": 2}]],
            },
        }
    )
    g_res1 = daemon.run_200ms_guardian_tick(current_time_ms=20_100)
    assert any(a["action"] == "TRAILING_SL_UPDATED" for a in g_res1["actions"])
    s1_after = db.get_slot_state(1)
    assert s1_after["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert float(s1_after["sl_px"]) >= 25.00 * 1.0015 - 0.01

    # 2. Perp 清算カスケード 3ティック連続検知で SL 到達前でも即時 IOC 全決済されること
    cascade_metrics = {1: {"delta_oi_15m_pct": -5.2, "premium_pct": -0.25, "perp_mark_px": 25.40}}
    daemon.run_200ms_guardian_tick(perp_metrics_by_slot=cascade_metrics, current_time_ms=30_000)
    daemon.run_200ms_guardian_tick(perp_metrics_by_slot=cascade_metrics, current_time_ms=30_200)
    g_res3 = daemon.run_200ms_guardian_tick(perp_metrics_by_slot=cascade_metrics, current_time_ms=30_400)
    assert any(a.get("exit_reason") == "PERP_CASCADE_CRASH_GUARD" for a in g_res3["actions"])
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # 3. 運用期限スケジューラ検証 (Phase 1 凍結 -> Phase 1 終了全決済 -> Phase 2)
    sc_freeze = daemon.evaluate_campaign_schedule(
        now_dt=datetime.fromisoformat("2027-07-08T22:30:00+09:00")
    )
    assert sc_freeze["phase"] == "PHASE1_PRE_DEADLINE_FREEZE"
    assert sc_freeze["new_entry_allowed"] is False

    sc_end1 = daemon.evaluate_campaign_schedule(
        now_dt=datetime.fromisoformat("2027-07-09T00:05:00+09:00")
    )
    assert sc_end1["phase"] == "INTER_PHASE_COOLING_WINDOW"
    assert sc_end1["should_flatten_all"] is True

    sc_p2 = daemon.evaluate_campaign_schedule(
        now_dt=datetime.fromisoformat("2027-07-15T12:00:00+09:00")
    )
    assert sc_p2["phase"] == "PHASE2_ACTIVE"
    assert sc_p2["new_entry_allowed"] is True
    db.close()


# ==============================================================================
# 5. Phase 5: Port 8081 Web Server, 0s Control Buttons & Non-Interfering Git Sync
# ==============================================================================
def test_web_server_endpoints_horizontal_lines_and_zero_sec_commands(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "web_test.db", initial_equity_usdc=135.0)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)

    # Slot 1 に HYPE/USDC の OPEN_PROTECTED ポジションをセットしてチャート水平ラインを検証
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.00,
        sz=2.0,
        sl_px=24.20,
        tp_px=27.50,
    )
    coord.bind_order_response(slot_id=1, cloid=intent["cloid"], oid=901, filled=True, filled_sz=2.0, avg_px=25.00)

    # Slot 2 に ENTRY_PENDING 指値をセットして CLEAR_PENDING_BUYS ボタン動作を検証
    coord.begin_order_intent(
        slot_id=2,
        target_state=SlotState.ENTRY_PENDING,
        coin="USOL/USDC",
        base_asset="USOL",
        sz_decimals=2,
        entry_px=180.00,
        sz=0.20,
        sl_px=175.00,
        tp_px=192.00,
    )

    service = DashboardStateService(db=db, tax_engine=tax, coordinator=coord)
    # テスト時は空きポート (port=0) にバインドして実HTTPリクエストで検証
    server = create_dashboard_http_server(service=service, host="127.0.0.1", port=0)
    actual_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    base_url = f"http://127.0.0.1:{actual_port}"
    auth_token = service.auth_manager.issue_session_token()
    auth_hdrs = {"X-HL-Auth": auth_token}
    try:
        # 1. GET / (HTML ダッシュボード)
        with urllib.request.urlopen(f"{base_url}/") as resp:
            html = resp.read().decode("utf-8")
            assert resp.status == 200
            assert "HL AI Trader v1" in html
            assert "EMERGENCY_LIQUIDATE_ALL" in html

        # 2. GET /api/status (USDC / JPY 併記、HWM、L5 85% ライン、税務サマリー)
        req_status = urllib.request.Request(f"{base_url}/api/status", headers=auth_hdrs)
        with urllib.request.urlopen(req_status) as resp:
            status_data = json.loads(resp.read().decode("utf-8"))
            assert status_data["status_badge"] == "RUNNING"
            assert status_data["equity"]["current_usdc"] == pytest.approx(135.0)
            assert status_data["equity"]["l5_floor_usdc"] == pytest.approx(135.0 * 0.85)
            assert "moving_average_pnl_jpy" in status_data["tax_summary"]
            assert "total_average_pnl_jpy" in status_data["tax_summary"]

        # 3. GET /api/chart (Entry / SL / TP の水平ラインが3本重なって返ること)
        req_chart = urllib.request.Request(
            f"{base_url}/api/chart?pair=HYPE/USDC&interval=15m", headers=auth_hdrs
        )
        with urllib.request.urlopen(req_chart) as resp:
            chart_data = json.loads(resp.read().decode("utf-8"))
            assert chart_data["pair_name"] == "HYPE/USDC"
            assert chart_data["interval"] == "15m"
            assert len(chart_data["candles"]) > 0
            line_types = {ln["type"]: ln["price"] for ln in chart_data["horizontal_lines"]}
            assert line_types["ENTRY"] == pytest.approx(25.00)
            assert line_types["SL"] == pytest.approx(24.20)
            assert line_types["TP"] == pytest.approx(27.50)

        def _post_cmd(payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
            req = urllib.request.Request(
                f"{base_url}/api/command",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-HL-Auth": auth_token},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req) as r:
                    return (r.status, json.loads(r.read().decode("utf-8")))
            except urllib.error.HTTPError as e:
                return (e.code, json.loads(e.read().decode("utf-8")))

        # 4. POST /api/command: PAUSE -> 0秒で status_badge が PAUSED になること
        code, pause_res = _post_cmd({"command": "PAUSE"})
        assert code == 200
        assert pause_res["status_badge"] == "PAUSED"
        assert pause_res["operator_paused"] is True

        # 5. POST /api/command: RESUME -> 0秒で RUNNING に復帰すること
        code, resume_res = _post_cmd({"command": "RESUME"})
        assert code == 200
        assert resume_res["status_badge"] == "RUNNING"
        assert resume_res["operator_paused"] is False

        # 6. POST /api/command: CLEAR_PENDING_BUYS -> Slot 2 の待機指値が IDLE にクリアされること
        code, clear_res = _post_cmd({"command": "CLEAR_PENDING_BUYS"})
        assert code == 200
        assert db.get_slot_state(2)["state"] == SlotState.IDLE.value
        assert db.get_slot_state(1)["state"] == SlotState.OPEN_PROTECTED.value

        # 7. POST /api/command: EMERGENCY_LIQUIDATE_ALL (confirmed=false は 400 で拒否、confirmed=true で全決済＋PAUSED)
        code_unconf, unconf_res = _post_cmd({"command": "EMERGENCY_LIQUIDATE_ALL", "confirmed": False})
        assert code_unconf == 400
        assert unconf_res["requires_confirmation"] is True
        assert db.get_slot_state(1)["state"] == SlotState.OPEN_PROTECTED.value

        code_conf, conf_res = _post_cmd({"command": "EMERGENCY_LIQUIDATE_ALL", "confirmed": True})
        assert code_conf == 200
        assert conf_res["status_badge"] == "PAUSED"
        assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

        # 8. 公開スナップショット出力 & Git Push 分離検証
        snap_file = service.export_public_snapshot(output_path=tmp_path / "public_snapshot.json")
        assert snap_file.exists()
        snap_text = snap_file.read_text(encoding="utf-8")
        assert "private_key" not in snap_text.lower()

        for m in (8, 23, 38, 53):
            assert should_run_git_push_at_minute(m) is True
        for gmo_m in (2, 17, 32, 47):
            assert should_run_git_push_at_minute(gmo_m) is False

        git_env = build_isolated_git_env({})
        assert git_env["GIT_CONFIG_GLOBAL"].endswith(".hl_gitconfig")
    finally:
        server.shutdown()
        server.server_close()
        db.close()


def test_15m_ai_radar_loop_and_15s_order_expiry_and_watchdog(tmp_path: Path) -> None:
    from watchdog import read_recorded_daemon_pid, terminate_only_verified_hl_pid

    db = DatabaseManager(db_path=tmp_path / "e2e_test.db", initial_equity_usdc=130.0)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "55" * 32,
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

    # 1. 15分AIレーダーループで HYPE/USDC が全7ゲート通過 -> AI BUY_ALO -> Slot 1 発注成功
    l2_books = {"HYPE/USDC": _make_healthy_l2_book(25.00)}
    candles = {
        "HYPE/USDC": {
            "4h": _make_trending_candles(60, 20.0, 0.015),
            "1h": _make_trending_candles(60, 22.0, 0.015),
            "15m": _make_trending_candles(60, 24.0, 0.008),
        }
    }
    radar_res = daemon.run_15m_ai_radar_tick(
        candidate_pairs=["HYPE/USDC"],
        l2_books_by_pair=l2_books,
        candles_by_pair=candles,
        current_time_ms=1_000_000,
        now_dt=datetime.fromisoformat("2026-10-23T06:00:00+09:00"),
    )
    assert radar_res["status"] == "ORDER_PLACED"
    assert radar_res["target_slot_id"] == 1
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    # 2. 4時間経過後の 15秒制御ループで未約定買い指値が自動キャンセルされること
    ctrl_res = daemon.run_15s_control_tick(
        current_time_ms=1_000_000 + 4 * 3_600_000 + 1000,
        now_dt=datetime.fromisoformat("2026-10-23T10:01:00+09:00"),
    )
    assert 1 in ctrl_res["expired_slots"]
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # 3. Watchdog の安全なPID検証 (存在しない/無関係なPIDは拒否されること)
    assert read_recorded_daemon_pid(tmp_path / "nonexistent.lock") is None
    assert terminate_only_verified_hl_pid(-1) is False
    db.close()

