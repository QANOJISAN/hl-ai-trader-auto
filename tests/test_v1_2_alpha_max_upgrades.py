"""
HL AI Trader v1.2 Alpha-Max — 全5論点 単体・結合検証テストスイート (tests/test_v1_2_alpha_max_upgrades.py)

検証項目:
1. 論点1: Spot-Perp クロス需給アルファ (正規化CVD, 1hクジラ偏り W_whale_1h, SSII_t, SAI_t, ブルトラップ +8.0pt ペナルティ, SSII>=0.70 時の Regime A 昇格)
2. 論点2: OU過程半減期に基づく2層型・時間減衰イグジット (第1層 compute_time_decay_sl 単調増加ラチェット & 第2層 4重ゲート停滞スクラッチ撤退 + SELL_ALO 180s TTL)
3. 論点3: オンチェーン4指標による動的銘柄クラスタ分類 (複合ベータ B_i, USDT0/USDC 自動除外, 3クラスタ A/B/C と Stage 3/4 逆転 lambda_mfe)
4. 論点4: UTC時間帯・曜日レジーム適応 (6レジーム判定, WEEKEND_THIN における上ヒゲ比 0.30 遮断・リスク倍率 0.60x [1R=0.75%]・純粋ブレイクアウト抑制)
5. 論点5: 365日無枯渇の日次アクション・バジェット管理 B_daily(t) & 反証誘導型5次元AIルーブリック (Gate_valid & Theta_raw 決定論的ハードゲート)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.ai_brain import DebiasedAIBrain, evaluate_falsification_rubric
from src.coordinator import ConcurrencyStateCoordinator, TrailingStage
from src.db import DatabaseManager
from src.exchange_wrapper import (
    ActionBudgetController,
    HyperliquidExchangeWrapper,
    SpotUniverseEntry,
    compute_optimal_buy_alo_price,
)
from src.radar import (
    MarketRadarAndFilter,
    classify_asset_cluster,
    compute_short_squeeze_ignition_index,
    compute_spot_absorption_index,
    evaluate_time_of_day_regime,
)
from src.risk_guard import (
    RiskAndCircuitBreakerEngine,
    compute_soft_ratchet_trailing_sl,
    compute_time_decay_sl,
    evaluate_stagnant_scratch_exit,
)
from src.ws_manager import HyperliquidWSManager


def test_topic1_spot_perp_cross_alpha_ssii_sai_and_bull_trap(tmp_path: Path) -> None:
    """
    論点1: 正規化CVD (5m/15m/1h)・1hクジラ偏り W_whale_1h・Perpショートスクイーズ指数 SSII_t・
    Spot実需買い集め指数 SAI_t・ブルトラップ検知 (+8.0pt)・Regime A 自動昇格の検証。
    """
    ws = HyperliquidWSManager(main_address="0x" + "11" * 20)
    ts_now = 1_780_000_000_000

    # 12件の約定データ (うち上位大口 > 500 USDC が買い優勢)
    trades_msg = {
        "channel": "trades",
        "data": [
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "4.0", "time": ts_now - 2_000_000},   # 100 USDC
            {"coin": "HYPE/USDC", "side": "A", "px": "25.0", "sz": "3.0", "time": ts_now - 1_800_000},   # 75 USDC
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "5.0", "time": ts_now - 1_500_000},   # 125 USDC
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "6.0", "time": ts_now - 1_200_000},   # 150 USDC
            {"coin": "HYPE/USDC", "side": "A", "px": "25.0", "sz": "4.0", "time": ts_now - 1_000_000},   # 100 USDC
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "8.0", "time": ts_now - 700_000},     # 200 USDC (15m内)
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "10.0", "time": ts_now - 500_000},    # 250 USDC (15m内)
            {"coin": "HYPE/USDC", "side": "A", "px": "25.0", "sz": "4.0", "time": ts_now - 400_000},     # 100 USDC (15m内)
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "12.0", "time": ts_now - 200_000},    # 300 USDC (5m内)
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "16.0", "time": ts_now - 120_000},    # 400 USDC (5m内)
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "40.0", "time": ts_now - 60_000},     # 1000 USDC (Whale Buy)
            {"coin": "HYPE/USDC", "side": "B", "px": "25.0", "sz": "60.0", "time": ts_now - 30_000},     # 1500 USDC (Whale Buy)
        ],
    }
    ws.handle_raw_message(trades_msg)
    flow = ws.compute_cvd_and_whale_metrics("HYPE/USDC", current_time_ms=ts_now)
    assert 0.50 < flow["cvd_5m"] <= 1.0
    assert 0.50 < flow["cvd_15m"] <= 1.0
    assert 0.50 < flow["cvd_1h"] <= 1.0
    assert flow["whale_1h"] > 0.85

    # SSII_t: マイナスFunding + 高OI Zスコア + 20本高値ブレイク + Perp 5m買いCVD + ショートカバーOI減少
    ssii_res = compute_short_squeeze_ignition_index(
        funding_t=-0.0040,        # -0.0040% -> S_fund = clip((0.0005 - (-0.0040))/0.0040, 0, 1.5) = 1.125
        funding_4h_mean=-0.0035,
        z_oi_4h_t=2.60,           # S_oi_coil = sigma(1.25 * 1.80) = sigma(2.25) = 0.9046 -> Phi_fuel = 1.0
        spot_px=105.0,
        high_20_15m=104.8,
        atr_15m=1.2,
        cvd_perp_5m=0.55,         # >= 0.50 -> cvd_term = 1.0
        delta_oi_15m=-0.012,      # -1.2% OI drop (short liquidation/cover) -> sigma(3.6) = 0.9734
        delta_basis_15m=0.0020,
    )
    assert ssii_res["phi_fuel"] == pytest.approx(1.0, rel=1e-2)
    assert ssii_res["ssii"] >= 0.80
    assert ssii_res["is_squeeze_ignition"] is True
    assert ssii_res["is_super_squeeze"] is True
    assert ssii_res["promote_to_regime_a"] is True

    # SSII_t >= 0.70 時は conviction=78 (通常Regime B) でも自動的に REGIME_A_STEP_AHEAD (TTL 900s) へ昇格すること
    alo_plan = compute_optimal_buy_alo_price(
        best_bid="25.00",
        best_ask="25.05",
        sz_decimals=2,
        conviction_score=78,
        obi_5=0.05,
        b_lead=0.0,
        ssii=ssii_res["ssii"],
    )
    assert alo_plan["regime"] == "REGIME_A_STEP_AHEAD"
    assert alo_plan["recommended_ttl_sec"] == 900
    assert alo_plan["limit_px"] > 25.00

    # SAI_t: 現物主導の買い集め (強気需給 -> 要求確信度 -5.0pt 緩和)
    sai_bull = compute_spot_absorption_index(
        cvd_spot_15m=0.48,
        cvd_perp_15m=0.20,
        whale_1h=0.60,
        funding_t=0.0005,
        ssii=ssii_res["ssii"],
    )
    assert sai_bull["sai"] >= 0.85
    assert sai_bull["bull_trap_detected"] is False
    assert sai_bull["delta_theta_flow"] == pytest.approx(-5.0)

    # ブルトラップ検知: D_lead_15m < -0.25 かつ F_t > +0.003%/h かつ CVD_spot_15m <= 0 -> +8.0pt ペナルティ
    sai_trap = compute_spot_absorption_index(
        cvd_spot_15m=-0.05,
        cvd_perp_15m=0.50,   # D_lead = -0.05 - 0.35 = -0.40 < -0.25
        whale_1h=-0.20,
        funding_t=0.0045,    # +0.0045%/h > +0.003%/h
        ssii=0.10,
    )
    assert sai_trap["d_lead_15m"] < -0.25
    assert sai_trap["bull_trap_detected"] is True
    assert sai_trap["delta_theta_flow"] == pytest.approx(8.0)
    assert sai_trap["delta_theta_flow_norm"] == pytest.approx(0.08)


def test_topic2_ou_time_decay_sl_and_4gate_stagnant_scratch_exit(tmp_path: Path) -> None:
    """
    論点2: 第1層 連続時間減衰型SLタイトニング (compute_time_decay_sl) の単調増加ラチェットと
    第2層 4重ゲート停滞スクラッチ撤退 (evaluate_stagnant_scratch_exit) + SELL_ALO (TTL 180s) の検証。
    """
    # 第1層: Entry=100.0, Initial SL=96.0 (1R = 4.0 USDC), Stage 10 (FREEROLL未達)
    # 猶予 tau_grace=45分 経過前 (30分時点) は u(t)=0 のため初期SL 96.0 を維持
    td_early = compute_time_decay_sl(
        entry_px=100.0,
        initial_sl_px=96.0,
        current_sl_px=96.0,
        holding_minutes=30.0,
        tau_grace_min=45.0,
        tau_max_min=240.0,
        atr_5m_now=0.60,
        atr_5m_init=1.00,
        cvd_perp_15m=-0.10,
        cvd_spot_15m=-0.10,
        c_fric_r=0.08,
        sz_decimals=2,
        stage=int(TrailingStage.STAGE_10_INITIAL),
    )
    assert td_early["u_t"] == pytest.approx(0.0)
    assert td_early["new_sl_px"] == pytest.approx(96.0)

    # 150分経過時点: u(t) > 0 により L_time(t) が -1.0R から引き上がり、さらに 200分経過時点で単調増加すること
    td_mid = compute_time_decay_sl(
        entry_px=100.0,
        initial_sl_px=96.0,
        current_sl_px=td_early["new_sl_px"],
        holding_minutes=150.0,
        tau_grace_min=45.0,
        tau_max_min=240.0,
        atr_5m_now=0.60,
        atr_5m_init=1.00,
        cvd_perp_15m=-0.10,
        cvd_spot_15m=-0.10,
        c_fric_r=0.08,
        sz_decimals=2,
        stage=int(TrailingStage.STAGE_10_INITIAL),
    )
    td_late = compute_time_decay_sl(
        entry_px=100.0,
        initial_sl_px=96.0,
        current_sl_px=td_mid["new_sl_px"],
        holding_minutes=210.0,
        tau_grace_min=45.0,
        tau_max_min=240.0,
        atr_5m_now=0.55,
        atr_5m_init=1.00,
        cvd_perp_15m=-0.15,
        cvd_spot_15m=-0.15,
        c_fric_r=0.08,
        sz_decimals=2,
        stage=int(TrailingStage.STAGE_10_INITIAL),
    )
    assert td_mid["new_sl_px"] > 96.0
    assert td_late["new_sl_px"] > td_mid["new_sl_px"]
    assert td_late["l_eff_r"] >= td_mid["l_eff_r"] > -1.0

    # 第2層: 4重ゲート停滞スクラッチ撤退 (D1: 単独微益撤退 R_now = +0.18R in [+0.08R, +0.40R])
    scratch_d1 = evaluate_stagnant_scratch_exit(
        holding_minutes=135.0,
        tau_stagnant_min=120.0,
        tau_max_min=240.0,
        mfe_pct=0.0050,     # < 0.55 * 0.015 (= 0.00825)
        theta2=0.0150,
        mae_r=-0.30,        # > -0.65R
        rho_atr=0.62,       # <= 0.68
        cvd_spot_15m=-0.01, # <= +0.02
        delta_basis_15m=-0.0002,
        r_now=0.18,
    )
    assert scratch_d1["should_exit"] is True
    assert scratch_d1["d1_matched"] is True
    assert scratch_d1["preferred_order_type"] == "SELL_ALO"
    assert scratch_d1["sell_alo_ttl_sec"] == 180

    # D2: 機会費用置換 (R_now = -0.12R in [-0.25R, +0.40R] かつ 別銘柄期待純利得差 +0.95R >= +0.85R)
    scratch_d2 = evaluate_stagnant_scratch_exit(
        holding_minutes=140.0,
        tau_stagnant_min=120.0,
        tau_max_min=240.0,
        mfe_pct=0.0040,
        theta2=0.0150,
        mae_r=-0.25,
        rho_atr=0.65,
        cvd_spot_15m=0.01,
        delta_basis_15m=0.0,
        r_now=-0.12,
        alt_expected_net_gain_diff_r=0.95,
    )
    assert scratch_d2["should_exit"] is True
    assert scratch_d2["d2_matched"] is True

    # SELL_ALO 発注ヘルパー検証 (TTL 180秒, Best Ask 配置)
    db = DatabaseManager(db_path=tmp_path / "sell_alo.db")
    coord = ConcurrencyStateCoordinator(db=db)
    ex = HyperliquidExchangeWrapper(execution_mode="DRY_RUN", db=db, coordinator=coord)
    ex.pair_to_entry["HYPE/USDC"] = SpotUniverseEntry(
        pair_name="HYPE/USDC",
        api_coin_name="@107",
        base_asset="HYPE",
        quote_asset="USDC",
        base_token_idx=1,
        quote_token_idx=0,
        universe_idx=107,
        spot_asset_id=10107,
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        perp_coin="HYPE",
    )
    sell_res = ex.place_spot_sell_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        best_ask="25.05",
        best_bid="25.00",
        raw_sz="2.00",
        ttl_sec=180,
    )
    assert sell_res["status"] == "ok"
    assert sell_res["order_type"] == "SELL_ALO"
    assert sell_res["ttl_sec"] == 180
    assert sell_res["fallback_planner"] == "DepthAwareIocPlanner"
    db.close()


def test_topic3_dynamic_asset_cluster_beta_and_stage3_4_lambda_inversion() -> None:
    """
    論点3: オンチェーン4指標による複合ベータ B_i 算出・ステーブルペア自動除外・
    3クラスタ分類 (A/B/C) と Stage 3/4 逆転 lambda_mfe の検証。
    """
    # 0. USDT0/USDC 等のステーブルペアはスイング対象から自動除外されること
    stable_res = classify_asset_cluster(pair_or_coin="USDT0/USDC")
    assert stable_res["is_stablecoin"] is True
    assert stable_res["swing_eligible"] is False
    assert stable_res["cluster"] == "EXCLUDED_STABLE"

    # 1. Cluster A (UBTC/USDC: 低ATR%, 厚い板, 高Perp支配率 -> B_i < 0.35)
    cl_a = classify_asset_cluster(
        pair_or_coin="UBTC/USDC",
        atr_1h_pct=0.0095,
        spread_bps=1.5,
        depth_minus_50bps_usdc=150_000.0,
        depth_plus_50bps_usdc=150_000.0,
        perp_volume_24h_usdc=500_000_000.0,
        spot_volume_24h_usdc=30_000_000.0,
    )
    assert cl_a["cluster"] == "A"
    assert 0.0 <= cl_a["beta_score"] < 0.35

    # 2. Cluster B (HYPE/USDC: 中程度ATR%・流動性 -> 0.35 <= B_i < 0.65)
    cl_b = classify_asset_cluster(
        pair_or_coin="HYPE/USDC",
        atr_1h_pct=0.024,
        spread_bps=6.0,
        depth_minus_50bps_usdc=20_000.0,
        depth_plus_50bps_usdc=20_000.0,
        perp_volume_24h_usdc=80_000_000.0,
        spot_volume_24h_usdc=45_000_000.0,
    )
    assert cl_b["cluster"] == "B"
    assert 0.35 <= cl_b["beta_score"] < 0.65

    # 3. Cluster C (UZEC/USDC・PURR/USDC: 高ボラティリティ・薄板 -> 0.65 <= B_i <= 1.00)
    cl_c = classify_asset_cluster(
        pair_or_coin="UZEC/USDC",
        atr_1h_pct=0.038,
        spread_bps=14.0,
        depth_minus_50bps_usdc=8_000.0,
        depth_plus_50bps_usdc=8_000.0,
        perp_volume_24h_usdc=8_000_000.0,
        spot_volume_24h_usdc=12_000_000.0,
    )
    assert cl_c["cluster"] == "C"
    assert 0.65 <= cl_c["beta_score"] <= 1.00

    # Stage 3 と Stage 4 の減衰係数 lambda_mfe の逆転検証:
    # Stage 3 では高ベータ (Cluster C) の方が小さく (押し目を耐えて伸ばす)、
    # Stage 4 では高ベータ (Cluster C) の方が大きい (クライマックスで超タイトに利益固定する)
    assert cl_c["lambda_mfe_3"] < cl_b["lambda_mfe_3"] < cl_a["lambda_mfe_3"]
    assert cl_c["lambda_mfe_4"] > cl_b["lambda_mfe_4"] > cl_a["lambda_mfe_4"]
    assert cl_c["k_sl"] > cl_a["k_sl"]
    assert cl_c["r_tp"] > cl_a["r_tp"]
    assert cl_c["tau_grace_min"] < cl_a["tau_grace_min"]
    assert cl_c["tau_max_min"] < cl_a["tau_max_min"]

    # Stage 40 での実価格比較: 高ベータ (beta=0.90) は低ベータ (beta=0.10) よりもタイト (高いSL価格) に締め付けること
    sr_low_beta = compute_soft_ratchet_trailing_sl(
        entry_px=100.0,
        initial_sl_px=97.0,
        current_sl_px=101.0,
        current_stage=30,
        best_bid=106.0,
        peak_bid=106.0,
        sz_decimals=4,
        atr_15m_pct=0.015,
        beta_score=0.10,
    )
    sr_high_beta = compute_soft_ratchet_trailing_sl(
        entry_px=100.0,
        initial_sl_px=97.0,
        current_sl_px=101.0,
        current_stage=30,
        best_bid=106.0,
        peak_bid=106.0,
        sz_decimals=4,
        atr_15m_pct=0.015,
        beta_score=0.90,
    )
    assert sr_high_beta["new_stage"] == int(TrailingStage.STAGE_40_HYPER_TIGHT)
    assert sr_high_beta["new_sl_px"] > sr_low_beta["new_sl_px"]


def test_topic4_utc_time_of_day_and_weekend_thin_wick_and_risk_scaling(tmp_path: Path) -> None:
    """
    論点4: UTC時間帯・曜日 6レジーム判定、および週末薄商い WEEKEND_THIN における
    上ヒゲ比 > 0.30 遮断・ポジションリスク 0.60x 縮小 (1R = 0.75%)・純粋ブレイクアウト抑制の検証。
    """
    # 1. ASIA_SESSION (水曜 03:00 UTC)
    r_asia = evaluate_time_of_day_regime(datetime(2026, 10, 21, 3, 0, tzinfo=timezone.utc))
    assert r_asia["regime"] == "ASIA_SESSION"
    assert r_asia["kappa_risk"] == pytest.approx(0.85)
    assert r_asia["delta_theta_time"] == pytest.approx(1.0)

    # 2. EU_OPEN (水曜 08:00 UTC)
    r_eu = evaluate_time_of_day_regime(datetime(2026, 10, 21, 8, 0, tzinfo=timezone.utc))
    assert r_eu["regime"] == "EU_OPEN"
    assert r_eu["mu_depth"] == pytest.approx(1.05)
    assert r_eu["mu_spread"] == pytest.approx(1.15)
    assert r_eu["kappa_risk"] == pytest.approx(0.90)

    # 3. INST_PRE_US (水曜 11:00 UTC / JST 20:00)
    r_inst = evaluate_time_of_day_regime(datetime(2026, 10, 21, 11, 0, tzinfo=timezone.utc))
    assert r_inst["regime"] == "INST_PRE_US"
    assert r_inst["delta_theta_time"] == pytest.approx(-2.0)
    assert r_inst["kappa_risk"] == pytest.approx(1.00)

    # 4. US_PEAK (火曜 15:00 UTC vs 金曜 15:00 UTC)
    r_us_tue = evaluate_time_of_day_regime(datetime(2026, 10, 20, 15, 0, tzinfo=timezone.utc))
    r_us_fri = evaluate_time_of_day_regime(datetime(2026, 10, 23, 15, 0, tzinfo=timezone.utc))
    assert r_us_tue["regime"] == "US_PEAK"
    assert r_us_tue["delta_theta_time"] == pytest.approx(-2.0)
    assert r_us_tue["kappa_risk"] == pytest.approx(1.00)
    assert r_us_fri["regime"] == "US_PEAK"
    assert r_us_fri["delta_theta_time"] == pytest.approx(1.0)
    assert r_us_fri["kappa_risk"] == pytest.approx(0.90)

    # 5. WEEKEND_THIN (土曜 12:00 UTC): 上ヒゲ比 0.40 > W_max(0.30) のストップ狩りヒゲを厳格遮断
    stop_hunt_candle = {"o": 100.0, "h": 105.0, "l": 95.0, "c": 101.0}  # upper_wick = (105-101)/(105-95) = 0.40
    r_wknd = evaluate_time_of_day_regime(
        datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc),
        ssii=0.30,
        sai=0.40,
        candle_15m=stop_hunt_candle,
    )
    assert r_wknd["regime"] == "WEEKEND_THIN"
    assert r_wknd["mu_depth"] == pytest.approx(1.35)
    assert r_wknd["mu_spread"] == pytest.approx(0.90)
    assert r_wknd["w_max"] == pytest.approx(0.30)
    assert r_wknd["delta_theta_time"] == pytest.approx(6.0)
    assert r_wknd["kappa_risk"] == pytest.approx(0.60)
    assert r_wknd["effective_1r_pct"] == pytest.approx(0.0075)  # 1R = 0.75%
    assert r_wknd["upper_wick_ratio"] == pytest.approx(0.40)
    assert r_wknd["wick_rejected"] is True
    assert r_wknd["pure_breakout_allowed"] is False

    # SSII >= 0.70 の強根拠時は週末でもブレイクアウト許可
    r_wknd_strong = evaluate_time_of_day_regime(
        datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc),
        ssii=0.75,
        sai=0.50,
    )
    assert r_wknd_strong["pure_breakout_allowed"] is True

    # 6. SUN_MON_ACCUM (日曜 20:00 UTC, SAI >= 0.65 で -3.0pt 優遇)
    r_sun = evaluate_time_of_day_regime(
        datetime(2026, 10, 25, 20, 0, tzinfo=timezone.utc),
        sai=0.70,
    )
    assert r_sun["regime"] == "SUN_MON_ACCUM"
    assert r_sun["delta_theta_time"] == pytest.approx(-3.0)
    assert r_sun["kappa_risk"] == pytest.approx(0.95)

    # RiskGuard のサイジングで kappa_risk = 0.60 (1R = 0.75%) が正確に反映されること
    db = DatabaseManager(db_path=tmp_path / "wknd_risk.db")
    rg = RiskAndCircuitBreakerEngine(db=db)
    sz_normal = rg.calculate_v1_1_single_bullet_sizing(
        slot_id=1,
        equity_usdc=144.0,
        free_usdc=144.0,
        entry_px=100.0,
        sl_px=97.0,
        sz_decimals=3,
        kappa_risk=1.0,
    )
    sz_weekend = rg.calculate_v1_1_single_bullet_sizing(
        slot_id=1,
        equity_usdc=144.0,
        free_usdc=144.0,
        entry_px=100.0,
        sl_px=97.0,
        sz_decimals=3,
        kappa_risk=0.60,
    )
    assert sz_normal["eligible"] is True
    assert sz_weekend["eligible"] is True
    assert sz_weekend["risk_budget_usdc"] == pytest.approx(sz_normal["risk_budget_usdc"] * 0.60, rel=1e-3)
    db.close()


def test_topic5_daily_action_budget_and_5d_falsification_rubric_gate(tmp_path: Path) -> None:
    """
    論点5: 365日無枯渇の日次アクション・バジェット管理 B_daily(t) と
    反証誘導型5次元AIルーブリック (Gate_valid & Theta_raw) の検証。
    """
    ctrl = ActionBudgetController()

    # 1. 当日無約定 (V_today == 0) の間はハードキャップ B_zero_vol = 20 枠/日に制限されること
    b_zero = ctrl.compute_daily_budget(
        v_cum_usdc=5000.0,
        a_used_total=200,
        v_ema_7d_usdc=120.0,
        v_today_usdc=0.0,
    )
    assert b_zero == 20

    # 2. 当日約定あり (V_today = 100 USDC) の場合は理論式通りの枠が算出されること
    # floor((10000 + 5000 - 200 - 2500)/365 + 0.50 * min(120, 200)) = floor(33.698 + 60.0) = 93
    b_active = ctrl.compute_daily_budget(
        v_cum_usdc=5000.0,
        a_used_total=200,
        v_ema_7d_usdc=120.0,
        v_today_usdc=100.0,
    )
    assert b_active == 93

    # 3. 消費率 70% / 90% / 100% 段階制御 & オンチェーンSL modify 0回 & 決済/キャンセル常時許可の検証
    st_50 = ctrl.evaluate_budget_state(v_cum_usdc=5000.0, a_used_total=200, v_ema_7d_usdc=120.0, v_today_usdc=0.0, actions_used_today=10)
    assert st_50["onchain_sl_modify_allowed"] is False
    assert st_50["repeg_modify_allowed"] is True
    assert st_50["conviction_penalty"] == pytest.approx(0.0)
    assert st_50["new_entry_allowed"] is True

    st_75 = ctrl.evaluate_budget_state(v_cum_usdc=5000.0, a_used_total=200, v_ema_7d_usdc=120.0, v_today_usdc=0.0, actions_used_today=15)
    assert st_75["repeg_modify_allowed"] is False
    assert st_75["new_entry_allowed"] is True

    st_95 = ctrl.evaluate_budget_state(v_cum_usdc=5000.0, a_used_total=200, v_ema_7d_usdc=120.0, v_today_usdc=0.0, actions_used_today=19)
    assert st_95["repeg_modify_allowed"] is False
    assert st_95["conviction_penalty"] == pytest.approx(8.0)
    assert st_95["new_entry_allowed"] is True

    st_100 = ctrl.evaluate_budget_state(v_cum_usdc=5000.0, a_used_total=200, v_ema_7d_usdc=120.0, v_today_usdc=0.0, actions_used_today=20)
    assert st_100["new_entry_allowed"] is False
    assert st_100["exit_and_cancel_allowed"] is True

    # expiresAfter 検証 (>= now + 60,000 ms)
    ts_base = 1_780_000_000_000
    with pytest.raises(ValueError):
        ActionBudgetController.validate_expires_after(ts_base + 15_000, current_time_ms=ts_base, strict=True)
    assert ActionBudgetController.validate_expires_after(ts_base + 15_000, current_time_ms=ts_base, strict=False) == ts_base + 60_000

    # 4. 反証誘導型エビデンス行列 & 5次元ルーブリック採点 (Gate_valid & Theta_raw)
    db = DatabaseManager(db_path=tmp_path / "rubric_ai.db")
    brain = DebiasedAIBrain(db=db, use_live_llm=False)

    # ケースA: H2・H3ともに反証成功かつ R1=2, R2=2, R3=2, R4=2, R5=1 -> Gate_valid=1, Theta_raw = 94.0 -> BUY_ALO 通過
    valid_payload = {
        "action": "BUY_ALO",
        "conviction_score": 90,
        "limit_px": 25.00,
        "sl_px": 24.20,
        "tp_px": 27.00,
        "expected_rr_ratio": 2.50,
        "market_regime_assessment": "BULL_EXPANSION",
        "reasoning": "Strong Spot absorption with Perp short squeeze ignition.",
        "self_critique": "Monitored funding and basis closely.",
        "invalidation_trigger_desc": "Break below 24.20",
        "memory_alignment_check": "Aligned with WMR lessons.",
        "evidence_matrix": {
            "E1_spot_perp_flow_citation": "SAI=0.82, SSII=0.76, D_lead=+0.28",
            "E2_price_structure_citation": "Breakout above 20-bar high with wick ratio 0.12",
            "E3_wmr_memory_contrast_citation": "Avoided caution pattern, matches opportunity exemplar",
        },
        "hypothesis_falsification": {
            "H2_bull_trap_refuted": True,
            "H2_refutation_pointer": "Spot CVD +0.48 leads Perp CVD +0.20, Funding negative",
            "H3_stagnation_refuted": True,
            "H3_refutation_pointer": "Kaufman ER_15m=0.68 and ATR expanding",
        },
        "rubric_scores": {
            "R1_cross_market_alpha": 2,          # 1.4 * 2 = 2.8
            "R2_structure_and_wick_quality": 2,  # 1.0 * 2 = 2.0
            "R3_wmr_precedent_superiority": 2,   # 1.2 * 2 = 2.4
            "R4_microstructure_execution_safety": 2,  # 0.8 * 2 = 1.6
            "R5_thesis_invalidation_clarity": 1,      # 0.6 * 1 = 0.6 -> sum = 9.4 -> Theta_raw = 94.0
        },
    }
    dec_ok = brain.parse_and_validate_decision(
        raw_output=valid_payload,
        best_bid=25.00,
        sz_decimals=2,
        min_conviction_score=75,
    )
    assert dec_ok.action == "BUY_ALO"
    assert dec_ok.vetoed is False
    assert dec_ok.gate_valid == 1
    assert dec_ok.theta_raw == pytest.approx(94.0)
    assert dec_ok.conviction_score == 94

    # ケースB: H2 (Bull Trap) が反証できていない場合 (H2_bull_trap_refuted=False) -> Gate_valid=0 -> 即座に SKIP (FALSIFICATION_GATE_REJECTED)
    trap_payload = {
        **valid_payload,
        "hypothesis_falsification": {
            "H2_bull_trap_refuted": False,
            "H2_refutation_pointer": "Perp-only spike with negative Spot CVD",
            "H3_stagnation_refuted": True,
            "H3_refutation_pointer": "Volatility present",
        },
    }
    dec_trap = brain.parse_and_validate_decision(
        raw_output=trap_payload,
        best_bid=25.00,
        sz_decimals=2,
        min_conviction_score=75,
    )
    assert dec_trap.action == "SKIP"
    assert dec_trap.vetoed is True
    assert dec_trap.gate_valid == 0
    assert dec_trap.conviction_score == 0
    assert dec_trap.veto_reason is not None and "FALSIFICATION_GATE_REJECTED" in dec_trap.veto_reason

    # ケースC: R1=0 または R3=0 の場合も Gate_valid=0 で即座に SKIP (FALSIFICATION_GATE_REJECTED) へ落ちること
    r1_zero_payload = {
        **valid_payload,
        "rubric_scores": {
            "R1_cross_market_alpha": 0,
            "R2_structure_and_wick_quality": 2,
            "R3_wmr_precedent_superiority": 2,
            "R4_microstructure_execution_safety": 2,
            "R5_thesis_invalidation_clarity": 2,
        },
    }
    dec_r1_zero = brain.parse_and_validate_decision(
        raw_output=r1_zero_payload,
        best_bid=25.00,
        sz_decimals=2,
        min_conviction_score=75,
    )
    assert dec_r1_zero.action == "SKIP"
    assert dec_r1_zero.vetoed is True
    assert dec_r1_zero.gate_valid == 0
    assert dec_r1_zero.veto_reason is not None and "FALSIFICATION_GATE_REJECTED" in dec_r1_zero.veto_reason
    db.close()
