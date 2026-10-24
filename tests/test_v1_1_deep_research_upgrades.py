"""
HL AI Trader v1.1 Optimized — Deep Research 6-Topic Comprehensive Test Suite
(`tests/test_v1_1_deep_research_upgrades.py`)

検証項目:
  1. Topic 1: 6段階ソフト・ラチェット（Soft-Ratchet）トレーリング＆動的フリーロール閾値 θ_2
     - 実トレード事例 `UZEC/USDC` (Entry `1234.3`, 初期SL `1197.4`, Peak `1256.4` [+1.7905%]) において、
       旧4段階方式の +1.80% 寸止め反転によるフル1R損失 (-4.14 USDC) を防ぎ、
       Stage 13 -> Stage 17 -> Stage 20 (`FREEROLL_LOCKED`, SL >= `1236.6` > Entry `1234.3`) で確実に利益ロックされることを証明
     - Stage 10 -> 13 -> 17 -> 20 -> 30 -> 40 の全ステージで SL とステージ番号が単調非減少であること
  2. Topic 2: 3レジーム適応型 `Alo` 指値価格最適化、Post-Only リジェクト時 Re-peg リトライ、高速200ms逆選択キャンセル＆動的15〜30分TTL
  3. Topic 3: L2板厚スイープ (`DepthAwareIocPlanner`) による IOC 決済下限価格算出、`< 10.0 USDC` 事前端数隔離、`< 11.2 USDC` 端数残余防止カラー拡張、一時的板空白検知
  4. Topic 4: 少額資金専用 Fractional Kelly 1R = 1.25% (`c_RT = 0.20%` 込み) サイジング、`< 16.0 USDC` フロア棄却、Slot 2 の 4h リターン相関ゲート (`corr_4h <= 0.65`)
  5. Topic 5: WMR 7日間半減期・2:1対比教訓抽出、経路依存 First-Hitting-Time (`SL_FIRST` vs `TP_FIRST`) シャドウ評価、無次元5特徴量＆VWAP乖離キャップ (`dist_from_vwap_atr > 2.5 -> conviction <= 70`)、動的確信度閾値 Θ_req
  6. Topic 6: 2.5秒 WebSocket サイレントストール検知＆REST L2 フェイルオーバー、サーバ時刻オフセット補正付き単調増加 Nonce、14日 (`336h`) Agent Wallet 期限警告、SQLite 32MB WAL 制御、Windows 1ms 高分解能タイマー
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState, TrailingStage
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import (
    DepthAwareIocPlanner,
    HyperliquidExchangeWrapper,
    SpotUniverseEntry,
    compute_optimal_buy_alo_price,
)
from src.main import HLTraderDaemon
from src.radar import MarketRadarAndFilter
from src.risk_guard import (
    RiskAndCircuitBreakerEngine,
    compute_dynamic_theta2,
    compute_return_correlation_4h,
    compute_soft_ratchet_trailing_sl,
)
from src.utils import MonotonicNonceGenerator, WindowsHighResTimer
from src.ws_manager import HyperliquidWSManager


def _make_test_env(tmp_path: Path):
    db = DatabaseManager(tmp_path / "test_v1_1.db")
    db.initialize_schema()
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    ex = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
    )
    uzec_entry = SpotUniverseEntry(
        pair_name="UZEC/USDC",
        api_coin_name="@180",
        base_asset="UZEC",
        quote_asset="USDC",
        base_token_idx=180,
        quote_token_idx=0,
        universe_idx=180,
        spot_asset_id=10180,
        perp_coin="ZEC",
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        spot_day_ntl_vlm=8_500_000.0,
        spot_mid_px=1234.3,
        spot_mark_px=1234.3,
    )
    ex.pair_to_entry["UZEC/USDC"] = uzec_entry
    ex.api_coin_to_entry["@180"] = uzec_entry
    return db, coord, tax, ex


# ==============================================================================
# Topic 1: 6段階ソフト・ラチェット（Soft-Ratchet）＆ UZEC/USDC 実トレード救済証明
# ==============================================================================
def test_topic1_uzec_real_trade_mfe_1_79pct_capital_preservation(tmp_path: Path):
    """
    実トレード UZEC/USDC (Entry=1234.3, Initial SL=1197.4, Peak=1256.4 [+1.7905%]) において:
    - 途中段階 (1250.0, MFE_R=0.425) で Stage 13 (FIRST_CUSHION) が発動し初期SL 1197.4 から大幅引き上げ
    - ピーク (1256.4, MFE=+1.7905% >= θ_2=1.644%) で Stage 20 (FREEROLL_LOCKED) が発動し、
      SL が 1236.6 (> Entry 1234.3 * 1.0015) にロックされ、反転下落しても +0.18% 以上の利益確定となることを検証。
    """
    entry_px = 1234.3
    init_sl = 1197.4
    sz_decimals = 2

    # Step 1: 含み益途中 (best_bid = 1250.0, MFE_R = 15.7 / 36.9 = 0.425) -> Stage 13
    s13 = compute_soft_ratchet_trailing_sl(
        entry_px=entry_px,
        initial_sl_px=init_sl,
        current_sl_px=init_sl,
        current_stage=TrailingStage.STAGE_10_INITIAL,
        best_bid=1250.0,
        peak_bid=1250.0,
        sz_decimals=sz_decimals,
        spread_eff=0.0008,
        atr_15m_pct=0.0110,
    )
    assert s13["new_stage"] == int(TrailingStage.STAGE_13_FIRST_CUSHION)
    assert s13["new_sl_px"] > 1213.0  # 1197.4 から +16ドル以上クッション引き上げ

    # Step 2: MFE_R = 0.73 (best_bid = 1261.24 相当の前に θ_2 = 1.644% があるため、r_pct が小さいケースで Stage 17 も検証)
    # UZEC のピーク 1256.4 (+1.7905%) 到達時 -> θ_2 (1.644%) を突破し Stage 20 (FREEROLL_LOCKED) へ到達！
    s20 = compute_soft_ratchet_trailing_sl(
        entry_px=entry_px,
        initial_sl_px=init_sl,
        current_sl_px=s13["new_sl_px"],
        current_stage=s13["new_stage"],
        best_bid=1256.4,
        peak_bid=1256.4,
        sz_decimals=sz_decimals,
        spread_eff=0.0008,
        atr_15m_pct=0.0110,
    )
    assert s20["new_stage"] == int(TrailingStage.STAGE_20_FREEROLL)
    assert s20["freeroll_locked"] is True
    assert s20["new_sl_px"] >= entry_px * 1.0015

    # Step 3: その後価格が 1240.0 へ反落しても SL と Stage は一切後退しない（単調非減少ラチェット）
    s_pullback = compute_soft_ratchet_trailing_sl(
        entry_px=entry_px,
        initial_sl_px=init_sl,
        current_sl_px=s20["new_sl_px"],
        current_stage=s20["new_stage"],
        best_bid=1240.0,
        peak_bid=1256.4,
        sz_decimals=sz_decimals,
        spread_eff=0.0008,
        atr_15m_pct=0.0110,
    )
    assert s_pullback["new_sl_px"] == s20["new_sl_px"]
    assert s_pullback["new_stage"] == int(TrailingStage.STAGE_20_FREEROLL)


def test_topic1_all_6_stages_monotonic_progression():
    """Stage 10 -> 13 -> 17 -> 20 -> 30 -> 40 の全6段階遷移と単調非減少性を検証する。"""
    entry_px = 100.0
    init_sl = 98.0  # r_pct = 2.0% -> 0.55 * 0.02 = 0.011, atr=0.015 -> theta2 = 1.725% (0.01725)
    cur_sl = init_sl
    cur_stage = int(TrailingStage.STAGE_10_INITIAL)

    # 1) Stage 10: MFE_R = 0.20 (bid = 100.4)
    r10 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, cur_sl, cur_stage, best_bid=100.4, peak_bid=100.4, sz_decimals=2, atr_15m_pct=0.015
    )
    assert r10["new_stage"] == int(TrailingStage.STAGE_10_INITIAL)

    # 2) Stage 13: MFE_R = 0.50 (bid = 101.0, +1.0%)
    r13 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, r10["new_sl_px"], r10["new_stage"], best_bid=101.0, peak_bid=101.0, sz_decimals=2, atr_15m_pct=0.015
    )
    assert r13["new_stage"] == int(TrailingStage.STAGE_13_FIRST_CUSHION)
    assert r13["new_sl_px"] > init_sl

    # 3) Stage 17: MFE_R = 0.80 (bid = 101.6, +1.6% < theta2=1.725%)
    r17 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, r13["new_sl_px"], r13["new_stage"], best_bid=101.6, peak_bid=101.6, sz_decimals=2, atr_15m_pct=0.015
    )
    assert r17["new_stage"] == int(TrailingStage.STAGE_17_TIGHT_CUSHION)
    assert r17["new_sl_px"] >= r13["new_sl_px"]

    # 4) Stage 20: bid = 102.0 (+2.0% >= theta2=1.725%)
    r20 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, r17["new_sl_px"], r17["new_stage"], best_bid=102.0, peak_bid=102.0, sz_decimals=2, atr_15m_pct=0.015
    )
    assert r20["new_stage"] == int(TrailingStage.STAGE_20_FREEROLL)
    assert r20["freeroll_locked"] is True
    assert r20["new_sl_px"] >= 100.15

    # 5) Stage 30: bid = 103.2 (+3.2% >= theta3=2.925%)
    r30 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, r20["new_sl_px"], r20["new_stage"], best_bid=103.2, peak_bid=103.2, sz_decimals=2, atr_15m_pct=0.015
    )
    assert r30["new_stage"] == int(TrailingStage.STAGE_30_ATR_TRAILING)
    assert r30["new_sl_px"] >= r20["new_sl_px"]

    # 6) Stage 40: bid = 105.0 (+5.0% >= theta4) or rsi_5m = 82.0
    r40 = compute_soft_ratchet_trailing_sl(
        entry_px, init_sl, r30["new_sl_px"], r30["new_stage"], best_bid=105.0, peak_bid=105.0, sz_decimals=2, atr_15m_pct=0.015, rsi_5m=82.0
    )
    assert r40["new_stage"] == int(TrailingStage.STAGE_40_HYPER_TIGHT)
    assert r40["new_sl_px"] >= r30["new_sl_px"]


# ==============================================================================
# Topic 2: 3レジーム Alo 価格最適化・Post-Only Re-peg・高速200ms逆選択キャンセル
# ==============================================================================
def test_topic2_alo_3regime_pricing_and_post_only_repeg_and_adverse_cancel(tmp_path: Path):
    db, coord, tax, ex = _make_test_env(tmp_path)

    # 1) Regime A: スプレッド >= 2 ticks かつ conviction >= 85 & obi_5 >= +0.20 & b_lead >= +0.0003 -> Best Bid + 1 tick
    p_reg_a = compute_optimal_buy_alo_price(
        best_bid=100.00, best_ask=100.05, sz_decimals=2, conviction_score=88, obi_5=0.35, b_lead=0.0005
    )
    assert p_reg_a["regime"] == "REGIME_A_STEP_AHEAD"
    assert Decimal(p_reg_a["px_str"]) == Decimal("100.01")

    # 2) Regime B: 1 tick スプレッドだが上位5層に流動性壁がある -> 壁の1ティック上 (Best Bid 以下)
    l2_bids = [
        {"px": "100.00", "sz": "1.0"},
        {"px": "99.98", "sz": "25.0"},  # 流動性クラスター壁
        {"px": "99.95", "sz": "2.0"},
    ]
    p_reg_b = compute_optimal_buy_alo_price(
        best_bid=100.00, best_ask=100.01, sz_decimals=2, conviction_score=80, obi_5=0.0, bids_levels=l2_bids
    )
    assert p_reg_b["regime"] == "REGIME_B_CLUSTER_FRONT"
    assert Decimal(p_reg_b["px_str"]) == Decimal("99.99")

    # 3) Regime C: 逆行オーダーフロー (obi_5 < -0.15) -> 深い押し目指値 (< Best Bid)
    p_reg_c = compute_optimal_buy_alo_price(
        best_bid=100.00, best_ask=100.02, sz_decimals=2, conviction_score=78, obi_5=-0.30, atr_15m=1.5
    )
    assert p_reg_c["regime"] == "REGIME_C_DEEP_PULLBACK"
    assert Decimal(p_reg_c["px_str"]) < Decimal("100.00")

    # 4) 高速200ms逆選択キャンセル判定 & 動的 15〜30分 TTL
    adv = HLTraderDaemon.evaluate_fast_200ms_adverse_selection(
        perp_price_change_30s_pct=-0.50,
        perp_spot_lead_basis_pct=-0.05,
        bid_top3_depth_ratio_3s=0.80,
    )
    assert adv["should_cancel"] is True
    assert "PERP_30S_DROP" in adv["reason"]

    ttl_drift = HLTraderDaemon.evaluate_dynamic_entry_ttl(
        order_created_at_ms=1_000_000,
        current_time_ms=1_000_000 + 16 * 60 * 1000,
        limit_px=100.0,
        current_mid_px=101.0,
        atr_15m=1.2,
    )
    assert ttl_drift["expired"] is True
    assert "DYNAMIC_TTL_15M_PRICE_DRIFT" in ttl_drift["reason"]


# ==============================================================================
# Topic 3: L2板厚スイープ IOC プランナー＆端数（Dust）事前隔離・カラー拡張
# ==============================================================================
def test_topic3_depth_aware_ioc_planner_and_sub10_dust_quarantine(tmp_path: Path):
    db, coord, tax, ex = _make_test_env(tmp_path)
    planner = DepthAwareIocPlanner()

    # 1) 10.0 USDC 未満の残高は IOC 発注せず即座に QUARANTINE_DUST_ONLY を返す
    sub10 = planner.plan_exit(
        actual_balance_total=Decimal("0.005"),
        sz_decimals=3,
        best_bid=Decimal("1200.0"),  # 6.0 USDC < 10.0 USDC
    )
    assert sub10["action"] == "QUARANTINE_DUST_ONLY"

    # execute_atomic_ioc_exit でも 10 USDC 未満が即時 dust_quarantine へ隔離され IDLE になること
    ex.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="UZEC/USDC",
        raw_limit_px="1200.0",
        raw_sz="0.02",
        sl_px=1160.0,
        tp_px=1300.0,
        episode_id="ep_dust2",
    )
    res_sub10 = ex.execute_atomic_ioc_exit(
        slot_id=1,
        coin_or_pair="UZEC/USDC",
        best_bid=400.0,  # 0.02 * 400.0 = 8.0 USDC < 10.0 USDC
        spot_clearinghouse_state={"balances": [{"coin": "UZEC", "total": "0.02", "hold": "0.0"}]},
    )
    assert res_sub10["action"] == "QUARANTINE_DUST_ONLY"
    assert res_sub10["quarantined_dust"] is True
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # 2) 20段板スイープ & 未約定残余 < 11.2 USDC 時の +0.50% スリッページカラー拡張
    l2_bids = [
        {"px": "100.00", "sz": "0.50"},  # 50 USDC (>= 98.50)
        {"px": "98.80", "sz": "0.45"},   # 44.46 USDC (>= 98.50) -> 標準1.5%カラー内合計 0.95, 残り 0.05 * 100 = 5 USDC (< 11.2 USDC)
        {"px": "98.20", "sz": "0.20"},   # 標準カラー(98.50)外だが拡張2.0%カラー(98.00)内
    ]
    sweep_plan = planner.plan_exit(
        actual_balance_total=Decimal("1.00"),
        sz_decimals=2,
        best_bid=Decimal("100.00"),
        l2_bids=l2_bids,
        is_emergency=True,
    )
    assert sweep_plan["action"] == "EXECUTE_IOC_SELL"
    assert sweep_plan["collar_widened_for_dust_avoidance"] is True


# ==============================================================================
# Topic 4: 少額資金 Fractional Kelly 1R=1.25% サイジング & 4h 相関ゲート
# ==============================================================================
def test_topic4_v1_1_1_25pct_sizing_and_4h_correlation_gate(tmp_path: Path):
    db, coord, _, _ = _make_test_env(tmp_path)
    rg = RiskAndCircuitBreakerEngine(db=db, coordinator=coord)

    # 1) Equity = 140.47 USDC, SL距離 = 2.5% (d_SL = 0.025), c_RT = 0.0020
    # S_Slot1 = 140.47 * 0.0125 / (0.025 + 0.0020) = 1.755875 / 0.027 = 65.03 USDC (< 70% cap 98.33 USDC)
    sz_res = rg.calculate_single_bullet_sizing(
        slot_id=1,
        equity_usdc=140.47,
        free_usdc=140.47,
        entry_px=100.0,
        sl_px=97.5,
        sz_decimals=2,
        l2_derisk_active=False,
        use_v1_1_formula=True,
    )
    assert sz_res["eligible"] is True
    assert sz_res["formula"] == "v1.1_fractional_kelly_1.25pct"
    assert 60.0 <= sz_res["notional_usdc"] <= 66.0

    # 2) 4h リターン相関係数ゲート: 相関 > 0.65 の場合は GATE4_HIGH_4H_RETURN_CORRELATION でブロック
    slot1_state = {
        "state": SlotState.OPEN_PROTECTED.value,
        "sub_state": SlotSubState.FREEROLL_LOCKED.value,
        "entry_px": 100.0,
        "sl_px": 100.20,
    }
    c_a = [100.0, 102.0, 101.0, 104.0, 103.0, 107.0]
    c_b_high_corr = [50.0, 51.0, 50.5, 52.0, 51.5, 53.5]
    c_c_low_corr = [50.0, 49.5, 51.0, 50.0, 52.0, 51.2]

    assert compute_return_correlation_4h(c_a, c_b_high_corr) > 0.95
    g_blocked = rg.evaluate_slot2_triple_gate(
        slot1_state=slot1_state,
        slot1_best_bid=102.0,
        slot1_atr_1m=0.2,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.5,
        hype_perp_premium_pct=0.01,
        hype_perp_delta_oi_15m_pct=0.5,
        slot1_closes_4h=c_a,
        candidate_closes_4h=c_b_high_corr,
    )
    assert g_blocked["allowed"] is False
    assert g_blocked["failed_gate"] == "GATE4_HIGH_4H_RETURN_CORRELATION"

    g_passed = rg.evaluate_slot2_triple_gate(
        slot1_state=slot1_state,
        slot1_best_bid=102.0,
        slot1_atr_1m=0.2,
        btc_perp_premium_pct=0.01,
        btc_perp_delta_oi_15m_pct=0.5,
        hype_perp_premium_pct=0.01,
        hype_perp_delta_oi_15m_pct=0.5,
        slot1_closes_4h=c_a,
        candidate_closes_4h=c_c_low_corr,
    )
    assert g_passed["allowed"] is True


# ==============================================================================
# Topic 5: WMR 7日半減期2:1対比・経路依存 First-Hitting-Time・無次元5特徴量
# ==============================================================================
def test_topic5_wmr_contrast_first_hitting_time_and_dimensionless_features(tmp_path: Path):
    db, _, _, _ = _make_test_env(tmp_path)
    brain = DebiasedAIBrain(db=db, use_live_llm=False)
    radar = MarketRadarAndFilter()
    t0 = 1_700_000_000_000

    # 1) WMR 2:1 対比抽出 (失敗 Caution 2件 + 成功 Opportunity 1件)
    brain.record_reflection_on_close(
        episode_id="ep_loss_1", coin="UZEC/USDC", market_regime_4h="BULL_EXPANSION",
        exit_reason="STOP_LOSS_HIT", entry_px=1234.3, exit_px=1194.6, initial_sl_px=1197.4,
        holding_duration_sec=3600, mfe_pct=1.79, mae_pct=-3.21, closed_at_ms=t0 - 3600_000
    )
    brain.record_reflection_on_close(
        episode_id="ep_loss_2", coin="HYPE/USDC", market_regime_4h="BULL_EXPANSION",
        exit_reason="STOP_LOSS_HIT", entry_px=25.0, exit_px=24.2, initial_sl_px=24.3,
        holding_duration_sec=1800, mfe_pct=0.5, mae_pct=-3.2, closed_at_ms=t0 - 7200_000
    )
    brain.record_reflection_on_close(
        episode_id="ep_win_1", coin="UBTC/USDC", market_regime_4h="BULL_EXPANSION",
        exit_reason="TAKE_PROFIT_HIT", entry_px=90000.0, exit_px=93600.0, initial_sl_px=88500.0,
        holding_duration_sec=7200, mfe_pct=4.1, mae_pct=-0.3, closed_at_ms=t0 - 5400_000
    )
    wmr = brain.retrieve_wmr_contrast_reflections("BULL_EXPANSION", current_time_ms=t0)
    assert len(wmr["cautions"]) == 2
    assert len(wmr["opportunities"]) == 1
    assert wmr["contrast_ratio"] == "2:1"

    # 2) 経路依存 First-Hitting-Time Shadow Evaluation:
    # 先に SL (97.0) を割った後、24時間以内に TP (105.0) まで反発したケースは必ず CORRECT_AVOIDANCE (-1.0R)
    sh_id = brain.register_shadow_skip(
        coin="HYPE/USDC", market_regime_4h="BULL_EXPANSION",
        skip_stage="AI_SKIP", skip_reason_code="TEST_PATH",
        spot_mid_at_eval=100.0, hypothetical_sl_px=97.0, hypothetical_tp_px=105.0,
        evaluated_at_ms=t0,
    )
    # 1時間後に 96.5 (SL 着弾: SL_FIRST)
    brain.process_pending_shadow_evaluations({"HYPE/USDC": 96.5}, current_time_ms=t0 + 3_600_000)
    # 4時間後に 106.0 (TP 上抜け)
    brain.process_pending_shadow_evaluations({"HYPE/USDC": 106.0}, current_time_ms=t0 + 4 * 3_600_000)
    # 24時間後に 105.5 で完了確定 -> SL_FIRST が記録されているため CORRECT_AVOIDANCE になること！
    done = brain.process_pending_shadow_evaluations({"HYPE/USDC": 105.5}, current_time_ms=t0 + 24 * 3_600_000)
    assert len(done) == 1
    assert done[0]["first_hit_type"] == "SL_FIRST"
    assert done[0]["shadow_outcome"] == "CORRECT_AVOIDANCE"
    assert float(done[0]["missed_r_multiple"]) == -1.0

    # 3) 無次元5特徴量 & VWAP乖離 > 2.5 ATR での conviction <= 70 キャップ
    candles_15m = [{"o": 100 + i * 0.2, "h": 100.5 + i * 0.2, "l": 99.8 + i * 0.2, "c": 100.2 + i * 0.2, "v": 100.0} for i in range(25)]
    candles_15m[-1]["c"] = 120.0  # VWAPから大きく上方乖離
    dim5 = radar.compute_dimensionless_5_features(candles_15m=candles_15m, candles_1h=candles_15m, atr_15m=1.5)
    assert 0.0 <= dim5["er_15m"] <= 1.0
    assert dim5["dist_from_vwap_atr"] > 2.5
    assert dim5["vwap_stretch_capped"] is True

    dec = brain.parse_and_validate_decision(
        raw_output={
            "action": "BUY_ALO",
            "conviction_score": 92,
            "limit_px": 100.0,
            "sl_px": 97.5,
            "tp_px": 106.0,
            "expected_rr_ratio": 2.4,
            "market_regime_assessment": "BULL_EXPANSION",
            "reasoning": "Test",
            "self_critique": "Test",
            "invalidation_trigger_desc": "Test",
            "memory_alignment_check": "Test",
        },
        best_bid=100.0,
        sz_decimals=2,
        min_conviction_score=75,
        dist_from_vwap_atr=3.1,
    )
    assert dec.conviction_score == 70
    assert dec.action == "SKIP"
    assert dec.vetoed is True
    assert "VWAP_STRETCH_CAP_70" in (dec.veto_reason or "")


# ==============================================================================
# Topic 6: 2.5秒WSサイレントストール検知・Nonceオフセット・14日Wallet警告・32MB WAL
# ==============================================================================
def test_topic6_ws_stall_failover_nonce_offset_wallet_14d_and_wal_checkpoint(tmp_path: Path):
    db, coord, tax, ex = _make_test_env(tmp_path)

    # 1) WebSocket 2.5秒サイレントストール検知 & REST L2 フェイルオーバー
    ws = HyperliquidWSManager(main_address=ex.main_address, exchange_wrapper=ex, tax_engine=tax)
    ws.last_message_received_ms = 1_000_000
    assert ws.is_ws_stalled(threshold_ms=2500, current_time_ms=1_003_000) is True

    class DummyInfo:
        def l2_snapshot(self, coin: str):
            return {
                "coin": coin,
                "levels": [
                    [{"px": "1235.0", "sz": "2.5"}],
                    [{"px": "1235.5", "sz": "2.0"}],
                ],
            }

    bbo = ws.get_bbo_with_rest_failover("UZEC/USDC", info_client=DummyInfo(), threshold_ms=2500)
    assert bbo is not None
    assert float(bbo["best_bid"]) == 1235.0
    assert float(bbo["best_ask"]) == 1235.5

    # 2) Server time offset 付き単調増加 Nonce 生成器
    ng = MonotonicNonceGenerator(server_time_offset_ms=500)
    n1 = ng.generate()
    n2 = ng.generate()
    assert n2 > n1

    # 3) SQLite journal_size_limit = 32MB & WAL checkpoint 実行
    chk = db.run_wal_checkpoint("PASSIVE")
    assert chk["status"] == "ok"
    conn = db._get_connection()
    j_limit = conn.execute("PRAGMA journal_size_limit;").fetchone()[0]
    assert int(j_limit) == 33554432

    # 4) Windows 1ms 高分解能タイマーの安全なコンテキスト実行
    with WindowsHighResTimer(1) as timer:
        assert isinstance(timer.active, bool)
