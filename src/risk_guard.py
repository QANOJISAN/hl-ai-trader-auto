"""
HL AI Trader v1 — Risk Allocation, Conditional Slot 2, Sanity Filter & L1-L5 Circuit Breakers (src/risk_guard.py)

実装機能 (ARCHITECTURE.md Section 5, 6 完全準拠):
1. Single-Bullet サイジング (`calculate_single_bullet_sizing`):
   - 総資産300 USDC未満は分割エントリー・分割利確を完全禁止 (100%一括決済)
   - Slot 1 最大投入 70%、1R = 2.0% (L2発動時は 1.0%)、最小発注額フロア 16.0 USDC、最大初期SL幅 8.0%
2. 第2枠 (Slot 2) 解放の3重ゲート判定 (`evaluate_slot2_triple_gate`):
   - ① Slot 1 が `OPEN_PROTECTED` かつ `FREEROLL_LOCKED` (`sl_px >= entry_px * 1.0015`)
   - ② 価格クッション条件: `P_bid_1 >= P_SL_1 + max(1.5 * ATR_1m_1, 0.0060 * P_entry_1)`
   - ③ Perpレジーム非悪化条件: BTCおよびHYPEの Perp `premium >= -0.05%` かつ `delta_OI_15m > -1.5%`
3. 親子スロット連動インターロック ＆ 事後リスクバジェット再計算:
   - Slot 2 が `ENTRY_PENDING` 中に Slot 1 の Best Bid が `P_SL_1 * 1.0025` 以下へ接近（または決済）したら即座に Slot 2 をキャンセル
   - Slot 1 がマイナス決済 (`D_1 > 0`) となった場合、`R_rem = max(0, 0.020 * Equity_USDC - D_1)` に基づき
     `0 < D_1 < 0.75 * R_max` なら Slot 2 の SL を `P_entry_2 - R_rem / sz_2` へ引き上げ、
     `D_1 >= 0.75 * R_max` なら Slot 2 も即座に IOC 100%緊急決済
4. 多層価格サニティフィルタ ＆ 総資産算出式 (`Equity_USDC`) ＆ L1〜L5 サーキットブレーカー:
   - 相対スプレッド・15秒変化率・Oracle乖離の3重サニティ検証と `TAINTED` 時の最大4周期価格保持＋ストライク凍結
   - `hold` 拘束分を含む `Total_USDC` を用いた総資産評価
   - L1〜L5 判定（特に L5 は「独立3周期・12秒以上間隔・静止状態・価格健全」で `Equity < 0.85 * max(Initial, HWM)` を3回連続確認時のみ発動）
"""

from __future__ import annotations

import logging
import math
import statistics
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState, SystemMode, TrailingStage
from src.db import DatabaseManager
from src.radar import (
    LARGE_CAP_PAIRS,
    TIER1_CORE_PAIRS,
    classify_asset_cluster,
    compute_short_squeeze_ignition_index,
    compute_spot_absorption_index,
    compute_upper_wick_ratio,
    evaluate_time_of_day_regime,
)
from src.utils import _to_clean_decimal, floor_size, now_jst, now_ms, round_price

logger = logging.getLogger(__name__)

JST = timezone(timedelta(hours=9))


def _norm_ratio(val: float, threshold: float = 0.20) -> float:
    """パーセント表記 (例: 2.99) と比率表記 (例: 0.0299) の両方を比率へ正規化する。"""
    v = float(val or 0.0)
    if v < 0:
        return 0.0
    return v / 100.0 if v > threshold else v


def compute_dynamic_theta2(
    r_pct: float,
    spread_eff: float = 0.0010,
    atr_15m_pct: float = 0.0100,
    fee_rt: float = 0.0011,
) -> float:
    """
    Topic 1: 銘柄ボラティリティ・初期SL距離・実効スプレッドに連動する動的フリーロール閾値 θ_2 を算出する。
    θ_2 = min(0.0180, max(0.0065, 0.55 * r_pct, 2.5 * spread_eff + 3.0 * fee_rt, 1.15 * atr_15m_pct))
    """
    r = _norm_ratio(r_pct, threshold=0.20)
    sp = _norm_ratio(spread_eff, threshold=0.10)
    atr = _norm_ratio(atr_15m_pct, threshold=0.15)
    fee = float(fee_rt)
    theta2 = min(
        0.0180,
        max(
            0.0065,
            0.55 * r,
            2.5 * sp + 3.0 * fee,
            1.15 * atr,
        ),
    )
    return float(theta2)


def compute_soft_ratchet_trailing_sl(
    entry_px: float,
    initial_sl_px: float,
    current_sl_px: float,
    current_stage: int,
    best_bid: float,
    peak_bid: float,
    sz_decimals: int = 2,
    spread_eff: float = 0.0010,
    atr_15m_pct: float = 0.0100,
    obi5: float = 0.0,
    rsi_5m: float = 50.0,
    fee_rt: float = 0.0011,
    c_lock: float = 0.0015,
    beta_score: Optional[float] = None,
    lambda_mfe_3: Optional[float] = None,
    lambda_mfe_4: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Topic 1 & v1.2 論点3: 6段階ソフト・ラチェット（Soft-Ratchet）適応型トレーリングストップ計算エンジン。
    Stage 10 (INITIAL_RISK) -> Stage 13 (FIRST_CUSHION) -> Stage 17 (TIGHT_CUSHION)
    -> Stage 20 (FREEROLL_LOCKED) -> Stage 30 (DYNAMIC_ATR_TRAIL) -> Stage 40 (CLIMAX_HYPER_TIGHT)
    すべてのステージで SL 価格とステージ番号の単調非減少 (new_sl = max(current_sl_px, cand_sl)) を保証する。
    beta_score (B_i in [0, 1]) 指定時は Stage 3 減衰係数 lambda_mfe^(3) = 0.40 - 0.28 * B_i、
    Stage 4 減衰係数 lambda_mfe^(4) = 0.48 + 0.22 * B_i (Stage 3と逆転) を適用する。
    """
    epx = float(entry_px)
    cur_sl = float(current_sl_px)
    init_sl = float(initial_sl_px) if float(initial_sl_px) > 0 else cur_sl
    bid = float(best_bid)
    peak = max(float(peak_bid), bid, epx)
    sp = _norm_ratio(spread_eff, threshold=0.10)
    atr = max(0.0010, _norm_ratio(atr_15m_pct, threshold=0.15))

    b_i = max(0.0, min(1.0, float(beta_score))) if beta_score is not None else 0.50
    lam3 = float(lambda_mfe_3) if lambda_mfe_3 is not None else (0.40 - 0.28 * b_i)
    lam4 = float(lambda_mfe_4) if lambda_mfe_4 is not None else (0.48 + 0.22 * b_i)

    # レガシーステージ番号 (0, 1, 2, 3, 4) を v1.1 ステージ番号 (10, 20, 30, 40) へ正規化
    raw_stage = int(current_stage or 10)
    if raw_stage <= 1:
        norm_cur_stage = int(TrailingStage.STAGE_10_INITIAL)
    elif raw_stage == 2:
        norm_cur_stage = int(TrailingStage.STAGE_20_FREEROLL)
    elif raw_stage == 3:
        norm_cur_stage = int(TrailingStage.STAGE_30_ATR_TRAILING)
    elif raw_stage == 4:
        norm_cur_stage = int(TrailingStage.STAGE_40_HYPER_TIGHT)
    else:
        norm_cur_stage = raw_stage

    if epx <= 0 or bid <= 0:
        return {
            "new_sl_px": cur_sl,
            "new_stage": norm_cur_stage,
            "stage_changed": False,
            "sl_updated": False,
            "freeroll_locked": norm_cur_stage >= int(TrailingStage.STAGE_20_FREEROLL),
            "theta2": 0.015,
            "mfe_pct": 0.0,
            "mfe_r": 0.0,
            "lambda_mfe_3": round(lam3, 4),
            "lambda_mfe_4": round(lam4, 4),
        }

    r_px = max(epx - init_sl, epx * 0.0050)
    r_pct = r_px / epx
    mfe_pct = max(0.0, (peak - epx) / epx)
    mfe_r = max(0.0, (peak - epx) / r_px)

    theta2 = compute_dynamic_theta2(r_pct=r_pct, spread_eff=sp, atr_15m_pct=atr, fee_rt=fee_rt)
    theta3 = max(1.35 * theta2, theta2 + 0.80 * atr)
    theta4 = max(2.10 * theta2, theta3 + 1.10 * atr)

    cand_stage = int(TrailingStage.STAGE_10_INITIAL)
    cand_sl = cur_sl

    if mfe_pct >= theta4 or (mfe_pct >= theta2 and float(rsi_5m) >= 78.0):
        cand_stage = int(TrailingStage.STAGE_40_HYPER_TIGHT)
        # Stage 4: 高ベータほど lam4 が大きく、クライマックスでよりタイトに利益固定する
        tight_scale = (1.0 - 0.55 * lam4) if (beta_score is not None or lambda_mfe_4 is not None) else 1.0
        d_40 = max(0.0025, 0.45 * atr * tight_scale, 2.0 * sp)
        floor_20 = epx * (1.0 + float(c_lock) + max(0.25, lam4) * max(0.0, mfe_pct - theta2))
        cand_sl = max(floor_20, peak * (1.0 - d_40))
    elif mfe_pct >= theta3:
        cand_stage = int(TrailingStage.STAGE_30_ATR_TRAILING)
        obi_clamped = max(-1.0, min(1.0, float(obi5)))
        # Stage 3: 高ベータほど lam3 が小さく、減衰を緩やかにして押し目を耐え大相場を伸ばす
        decay_rate = (45.0 * lam3) if (beta_score is not None or lambda_mfe_3 is not None) else 18.0
        k_trail = max(0.75, min(2.40, 2.2 * math.exp(-decay_rate * (mfe_pct - theta3)) * (1.0 + 0.25 * obi_clamped)))
        floor_20 = epx * (1.0 + float(c_lock) + 0.25 * max(0.0, mfe_pct - theta2))
        cand_sl = max(floor_20, peak * (1.0 - k_trail * atr))
    elif mfe_pct >= theta2:
        cand_stage = int(TrailingStage.STAGE_20_FREEROLL)
        cand_sl = epx * (1.0 + float(c_lock) + 0.25 * (mfe_pct - theta2))
    elif mfe_r >= 0.72:
        cand_stage = int(TrailingStage.STAGE_17_TIGHT_CUSHION)
        denom = max(1e-6, theta2 - 0.72 * r_pct)
        u2 = max(0.0, min(1.0, (mfe_pct - 0.72 * r_pct) / denom))
        sl_low = epx * (1.0 - 0.20 * r_pct)
        sl_high = epx * (1.0 + float(c_lock))
        sl_interp = sl_low + u2 * (sl_high - sl_low)
        bid_cap = bid * (1.0 - max(1.8 * sp, 0.0020))
        cand_sl = min(sl_interp, bid_cap)
    elif mfe_r >= 0.38:
        cand_stage = int(TrailingStage.STAGE_13_FIRST_CUSHION)
        u1 = max(0.0, min(1.0, (mfe_r - 0.38) / (0.72 - 0.38)))
        cand_sl = epx - (0.60 - 0.40 * u1) * r_px
    else:
        cand_stage = int(TrailingStage.STAGE_10_INITIAL)
        cand_sl = cur_sl

    rounded_cand_sl = float(round_price(cand_sl, int(sz_decimals)))
    new_sl = max(cur_sl, rounded_cand_sl)
    new_stage = max(norm_cur_stage, cand_stage)
    freeroll_locked = bool(
        new_stage >= int(TrailingStage.STAGE_20_FREEROLL)
        or new_sl >= epx * (1.0 + float(c_lock)) - 1e-9
    )

    return {
        "new_sl_px": float(new_sl),
        "new_stage": int(new_stage),
        "cand_stage": int(cand_stage),
        "stage_changed": bool(new_stage > norm_cur_stage),
        "sl_updated": bool(new_sl > cur_sl + 1e-9),
        "freeroll_locked": freeroll_locked,
        "theta2": round(float(theta2), 6),
        "theta3": round(float(theta3), 6),
        "theta4": round(float(theta4), 6),
        "mfe_pct": round(float(mfe_pct), 6),
        "mfe_r": round(float(mfe_r), 4),
        "r_pct": round(float(r_pct), 6),
        "lambda_mfe_3": round(float(lam3), 4),
        "lambda_mfe_4": round(float(lam4), 4),
    }


def compute_time_decay_sl(
    entry_px: float,
    initial_sl_px: float,
    current_sl_px: float,
    holding_minutes: float,
    tau_grace_min: float = 45.0,
    tau_max_min: float = 240.0,
    atr_5m_now: float = 1.0,
    atr_5m_init: float = 1.0,
    cvd_perp_15m: float = 0.0,
    cvd_spot_15m: float = 0.0,
    mfe_ratchet_sl_px: Optional[float] = None,
    l_ratchet_r: Optional[float] = None,
    c_fric_r: float = 0.08,
    sz_decimals: int = 2,
    stage: int = 10,
) -> Dict[str, Any]:
    """
    v1.2 論点2 (第1層): OU過程半減期に基づく連続時間減衰型SLタイトニング (compute_time_decay_sl)
    Stage 20 (FREEROLL_LOCKED) 未達のポジションに対し:
      rho_ATR(t) = ATR_5m(t) / ATR_5m(t_0)
      psi_mom(t) = clip(-(CVD_perp_15m + CVD_spot_15m) / 0.40, -0.30, +0.60)
      u(t) = clip((t_hold - tau_grace) / (tau_max - tau_grace), 0, 1)
      gamma(t) = clip(1.60 * rho_ATR(t) - psi_mom(t), 0.65, 2.20)
      L_time(t) = -1.0R + (1.0R - c_fric_R - 0.05R) * (u(t))^gamma(t)
      L_eff(t) = max(L_ratchet(MFE_t), L_time(t))
    を単調増加ラチェットで適用する。
    """
    epx = float(entry_px)
    init_sl = float(initial_sl_px)
    cur_sl = float(current_sl_px) if float(current_sl_px) > 0 else init_sl
    r_px = max(epx - init_sl, epx * 0.0050)

    # すでに Stage 2 / Stage 20 (FREEROLL_LOCKED, sl_px >= entry_px * 1.0015) 到達済みの場合は時間減衰を適用せず既存SLを維持
    if TrailingStage.is_freeroll_locked_stage(int(stage)) or (epx > 0 and cur_sl >= epx * 1.0015 - 1e-9):
        cur_r = (cur_sl - epx) / r_px
        return {
            "active": False,
            "u_t": 0.0,
            "rho_atr": 1.0,
            "psi_mom": 0.0,
            "gamma_t": 1.0,
            "l_time_r": round(cur_r, 6),
            "l_ratchet_r": round(cur_r, 6),
            "l_eff_r": round(cur_r, 6),
            "time_sl_px": cur_sl,
            "new_sl_px": cur_sl,
            "sl_updated": False,
        }

    rho_atr = float(atr_5m_now) / max(float(atr_5m_init), 1e-9) if float(atr_5m_init) > 0 else 1.0
    psi_mom = max(-0.30, min(0.60, -(float(cvd_perp_15m) + float(cvd_spot_15m)) / 0.40))
    denom_tau = max(1.0, float(tau_max_min) - float(tau_grace_min))
    u_t = max(0.0, min(1.0, (float(holding_minutes) - float(tau_grace_min)) / denom_tau))
    gamma_t = max(0.65, min(2.20, 1.60 * rho_atr - psi_mom))

    fric_r = max(0.0, min(0.60, float(c_fric_r)))
    l_time_r = -1.0 + (1.0 - fric_r - 0.05) * (u_t ** gamma_t) if u_t > 0.0 else -1.0

    ratchet_sl = float(mfe_ratchet_sl_px) if mfe_ratchet_sl_px is not None else cur_sl
    if l_ratchet_r is not None:
        ratchet_r = float(l_ratchet_r)
        ratchet_sl = max(ratchet_sl, epx + ratchet_r * r_px)
    else:
        ratchet_r = (ratchet_sl - epx) / r_px

    l_eff_r = max(ratchet_r, l_time_r)
    raw_time_sl_px = epx + l_time_r * r_px
    raw_eff_sl_px = max(cur_sl, ratchet_sl, raw_time_sl_px)
    rounded_eff_sl = float(round_price(raw_eff_sl_px, int(sz_decimals)))
    new_sl = max(cur_sl, rounded_eff_sl)

    return {
        "active": bool(u_t > 0.0),
        "u_t": round(float(u_t), 6),
        "rho_atr": round(float(rho_atr), 6),
        "psi_mom": round(float(psi_mom), 6),
        "gamma_t": round(float(gamma_t), 6),
        "l_time_r": round(float(l_time_r), 6),
        "l_ratchet_r": round(float(ratchet_r), 6),
        "l_eff_r": round(float(l_eff_r), 6),
        "time_sl_px": float(round_price(raw_time_sl_px, int(sz_decimals))),
        "new_sl_px": float(new_sl),
        "sl_updated": bool(new_sl > cur_sl + 1e-9),
    }


def evaluate_stagnant_scratch_exit(
    holding_minutes: float,
    tau_stagnant_min: float = 120.0,
    tau_max_min: float = 240.0,
    mfe_pct: float = 0.0,
    theta2: float = 0.015,
    mae_r: float = -0.20,
    rho_atr: float = 0.60,
    cvd_spot_15m: float = 0.0,
    delta_basis_15m: float = 0.0,
    r_now: float = 0.15,
    alt_expected_net_gain_diff_r: float = 0.0,
) -> Dict[str, Any]:
    """
    v1.2 論点2 (第2層): 4重ゲート停滞スクラッチ撤退 (evaluate_stagnant_scratch_exit)
      - Gate A: t_hold >= tau_stagnant (クラスタ別 90〜180分)
      - Gate B: MFE_t < 0.55 * theta_2 かつ MAE_t > -0.65R
      - Gate C: rho_ATR(t) <= 0.68 かつ CVD_spot_15m(t) <= +0.02 かつ dBasis_15m <= 0
      - Gate D:
          D1 (単独微益撤退): R_now in [+0.08R, +0.40R]
          D2 (機会費用置換 / 最大時間到達): (R_now in [-0.25R, +0.40R] かつ 別銘柄期待純利得差 >= +0.85R) または t_hold >= tau_max
      発火時は最良売り気配 (Best Ask) に SELL_ALO (TTL 180秒) を優先発注し、未約定または L_eff 割れ時に DepthAwareIocPlanner で決済。
    """
    t_hold = float(holding_minutes)
    mfe_norm = _norm_ratio(mfe_pct, threshold=0.20)
    th2_norm = _norm_ratio(theta2, threshold=0.20)
    mae_val = -abs(float(mae_r)) if float(mae_r) > 0 else float(mae_r)
    r_cur = float(r_now)

    gate_a = bool(t_hold >= float(tau_stagnant_min))
    gate_b = bool(mfe_norm < (0.55 * th2_norm) and mae_val > -0.65)
    gate_c = bool(
        float(rho_atr) <= 0.68
        and float(cvd_spot_15m) <= 0.02
        and float(delta_basis_15m) <= 0.0
    )

    d1_scratch_profit = bool(0.08 <= r_cur <= 0.40)
    d2_opportunity_or_max = bool(
        (-0.25 <= r_cur <= 0.40 and float(alt_expected_net_gain_diff_r) >= 0.85)
        or (t_hold >= float(tau_max_min))
    )
    gate_d = bool(d1_scratch_profit or d2_opportunity_or_max)

    should_exit = bool(gate_a and gate_b and gate_c and gate_d)
    if d1_scratch_profit:
        trigger_type = "D1_STANDALONE_SCRATCH_PROFIT"
    elif d2_opportunity_or_max:
        trigger_type = "D2_OPPORTUNITY_REPLACEMENT_OR_TAU_MAX"
    else:
        trigger_type = "NONE"

    return {
        "should_exit": should_exit,
        "exit_mode": "SELL_ALO_FIRST" if should_exit else "HOLD",
        "preferred_order_type": "SELL_ALO",
        "sell_alo_ttl_sec": 180,
        "fallback_order_type": "IOC_DEPTH_AWARE",
        "trigger_type": trigger_type,
        "gate_a": gate_a,
        "gate_b": gate_b,
        "gate_c": gate_c,
        "gate_d": gate_d,
        "d1_matched": d1_scratch_profit,
        "d2_matched": d2_opportunity_or_max,
        "r_now": round(r_cur, 4),
    }


def compute_return_correlation_4h(
    closes_1: Sequence[float],
    closes_2: Sequence[float],
) -> float:
    """
    Topic 4: Slot 1 保有銘柄と Slot 2 候補銘柄の 4h 足リターン相関係数 ρ_4h を算出する。
    """
    n = min(len(closes_1 or []), len(closes_2 or []))
    if n < 3:
        return 0.0
    c1 = [float(x) for x in list(closes_1)[-n:]]
    c2 = [float(x) for x in list(closes_2)[-n:]]
    r1: List[float] = []
    r2: List[float] = []
    for i in range(1, n):
        if c1[i - 1] > 0 and c2[i - 1] > 0:
            r1.append((c1[i] - c1[i - 1]) / c1[i - 1])
            r2.append((c2[i] - c2[i - 1]) / c2[i - 1])
    if len(r1) < 2:
        return 0.0
    m1 = sum(r1) / len(r1)
    m2 = sum(r2) / len(r2)
    num = sum((a - m1) * (b - m2) for a, b in zip(r1, r2))
    den1 = math.sqrt(sum((a - m1) ** 2 for a in r1))
    den2 = math.sqrt(sum((b - m2) ** 2 for b in r2))
    if den1 <= 1e-12 or den2 <= 1e-12:
        return 0.0
    return float(max(-1.0, min(1.0, num / (den1 * den2))))


def get_current_0600_jst_anchor_ms(current_time_ms: Optional[int] = None) -> int:
    """現在属している日次サイクルの開始時刻（直近の 06:00 JST）のミリ秒タイムスタンプを返す"""
    ts = int(current_time_ms) if current_time_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    anchor = dt.replace(hour=6, minute=0, second=0, microsecond=0)
    if dt < anchor:
        anchor -= timedelta(days=1)
    return int(anchor.timestamp() * 1000)


def get_next_0600_jst_ms(current_time_ms: Optional[int] = None) -> int:
    """翌朝 06:00 JST のミリ秒タイムスタンプを返す"""
    ts = int(current_time_ms) if current_time_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    target = dt.replace(hour=6, minute=0, second=0, microsecond=0)
    if dt >= target:
        target += timedelta(days=1)
    return int(target.timestamp() * 1000)


def get_current_monday_0600_jst_anchor_ms(current_time_ms: Optional[int] = None) -> int:
    """現在属している週次サイクルの開始時刻（直近の月曜 06:00 JST）のミリ秒タイムスタンプを返す"""
    ts = int(current_time_ms) if current_time_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    days_since_monday = dt.weekday()
    anchor = (dt - timedelta(days=days_since_monday)).replace(hour=6, minute=0, second=0, microsecond=0)
    if dt < anchor:
        anchor -= timedelta(days=7)
    return int(anchor.timestamp() * 1000)


def get_next_monday_0600_jst_ms(current_time_ms: Optional[int] = None) -> int:
    """翌週月曜 06:00 JST のミリ秒タイムスタンプを返す"""
    ts = int(current_time_ms) if current_time_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    days_ahead = (7 - dt.weekday()) % 7
    if days_ahead == 0 and dt.hour >= 6:
        days_ahead = 7
    target = (dt + timedelta(days=days_ahead)).replace(hour=6, minute=0, second=0, microsecond=0)
    return int(target.timestamp() * 1000)


class RiskAndCircuitBreakerEngine:
    """
    資金配分・条件付き第2枠・親子インターロック・事後リスク再計算・
    多層価格サニティフィルタ・L1〜L5サーキットブレーカーを統括するリスクエンジン。
    """

    TAKER_FEE_RATE = Decimal("0.0007")
    SLOT1_MAX_ALLOC_PCT = Decimal("0.70")
    SLOT2_MAX_ALLOC_PCT = Decimal("0.38")
    BASE_RISK_PCT = Decimal("0.020")
    DERISKED_RISK_PCT = Decimal("0.010")
    MIN_ORDER_NOTIONAL_USDC = Decimal("16.0")
    MAX_INITIAL_SL_PCT = Decimal("0.080")

    FREEROLL_LOCK_MULT = 1.0015
    SLOT1_DANGER_SL_MULT = 1.0025
    POST_LOSS_EMERGENCY_RATIO = 0.75

    L5_KILL_DRAWDOWN_RATIO = 0.85
    L5_MIN_STRIKE_INTERVAL_MS = 12_000  # 12秒以上間隔
    L5_REQUIRED_STRIKES = 3
    L3_REQUIRED_STRIKES = 3
    MAX_TAINTED_CYCLES = 4

    def __init__(
        self,
        db: DatabaseManager,
        coordinator: Optional[ConcurrencyStateCoordinator] = None,
    ) -> None:
        self.db = db
        self.coordinator = coordinator

        # トークン別の直前正常価格と連続TAINTED周期カウンタ
        self._last_valid_prices: Dict[str, float] = {}
        self._tainted_cycle_counts: Dict[str, int] = {}

        # L2 / L3 / L5 連続ストライク追跡 & 06:00 JST 日次/週次ロールオーバー追跡
        self._l2_perp_softness_strikes: int = 0
        self._l2_daily_dd_served_anchor_ms: int = 0
        self._l3_daily_dd_strikes: int = 0
        self._last_l5_strike_ts_ms: int = 0
        self._last_sod_anchor_ms: int = 0
        self._last_sow_anchor_ms: int = 0

    # ==========================================================================
    # 1. Single-Bullet サイジング (`calculate_single_bullet_sizing`) & v1.1 1.25% 1R 方式
    # ==========================================================================
    def compute_soft_ratchet_trailing_sl(
        self,
        entry_px: float,
        initial_sl_px: float,
        current_sl_px: float,
        current_stage: int,
        best_bid: float,
        peak_bid: float,
        sz_decimals: int = 2,
        spread_eff: float = 0.0010,
        atr_15m_pct: float = 0.0100,
        obi5: float = 0.0,
        rsi_5m: float = 50.0,
        fee_rt: float = 0.0011,
        c_lock: float = 0.0015,
        beta_score: Optional[float] = None,
        lambda_mfe_3: Optional[float] = None,
        lambda_mfe_4: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Topic 1 & v1.2 論点3: 6段階ソフト・ラチェット（Soft-Ratchet）適応型トレーリングストップ計算エンジン。"""
        return compute_soft_ratchet_trailing_sl(
            entry_px=entry_px,
            initial_sl_px=initial_sl_px,
            current_sl_px=current_sl_px,
            current_stage=current_stage,
            best_bid=best_bid,
            peak_bid=peak_bid,
            sz_decimals=sz_decimals,
            spread_eff=spread_eff,
            atr_15m_pct=atr_15m_pct,
            obi5=obi5,
            rsi_5m=rsi_5m,
            fee_rt=fee_rt,
            c_lock=c_lock,
            beta_score=beta_score,
            lambda_mfe_3=lambda_mfe_3,
            lambda_mfe_4=lambda_mfe_4,
        )

    def compute_time_decay_sl(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点2 (第1層): OU過程半減期に基づく連続時間減衰型SLタイトニング。"""
        return compute_time_decay_sl(*args, **kwargs)

    def evaluate_stagnant_scratch_exit(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点2 (第2層): 4重ゲート停滞スクラッチ撤退判定。"""
        return evaluate_stagnant_scratch_exit(*args, **kwargs)

    def classify_asset_cluster(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点3: 複合ベータ B_i に基づく銘柄3クラスタ分類。"""
        return classify_asset_cluster(*args, **kwargs)

    def evaluate_time_of_day_regime(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点4: UTC時間帯・曜日（WEEKEND_THIN 等）レジーム適応判定。"""
        return evaluate_time_of_day_regime(*args, **kwargs)

    def calculate_v1_1_single_bullet_sizing(
        self,
        slot_id: int,
        equity_usdc: float,
        free_usdc: float,
        entry_px: float,
        sl_px: float,
        sz_decimals: int,
        l2_derisk_active: bool = False,
        r_1r: float = 0.0125,
        c_rt: float = 0.0020,
        kappa_risk: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Topic 4 & v1.2 論点4: 少額資金 (140〜145 USDC) 専用 Fractional Kelly 1R = 1.25% * kappa_risk サイジング式:
        S_Slot1 = clip(E * 0.0125 * kappa_risk * m_CB / (d_SL + 0.0020), 16.0, 0.70 * E * m_CB)
        ※ リスクベースの理論サイズまたは利用可能上限が 16.0 USDC 未満の場合は発注を見送る。
        """
        eq = _to_clean_decimal(equity_usdc)
        free = _to_clean_decimal(free_usdc)
        epx = _to_clean_decimal(entry_px)
        spx = _to_clean_decimal(sl_px)

        if eq <= 0 or free <= 0:
            return {"eligible": False, "reason": "NON_POSITIVE_EQUITY_OR_FREE_USDC", "sz_str": "0", "notional_usdc": 0.0}
        if epx <= 0 or spx <= 0 or spx >= epx:
            return {"eligible": False, "reason": "INVALID_ENTRY_OR_SL_PRICE", "sz_str": "0", "notional_usdc": 0.0}

        px_str = round_price(epx, sz_decimals)
        sl_str = round_price(spx, sz_decimals)
        px_dec = _to_clean_decimal(px_str)
        sl_dec = _to_clean_decimal(sl_str)
        if px_dec <= 0 or sl_dec <= 0 or sl_dec >= px_dec:
            return {"eligible": False, "reason": "INVALID_ROUNDED_ENTRY_OR_SL_PRICE", "sz_str": "0", "notional_usdc": 0.0}

        raw_sl_dist_pct = (epx - spx) / epx
        rounded_sl_dist_pct = (px_dec - sl_dec) / px_dec
        sl_dist_pct = max(raw_sl_dist_pct, rounded_sl_dist_pct)
        if sl_dist_pct > self.MAX_INITIAL_SL_PCT:
            return {
                "eligible": False,
                "reason": f"SL_PCT_EXCEEDS_8PCT_CAP({float(sl_dist_pct)*100:.2f}%)",
                "sz_str": "0",
                "px_str": px_str,
                "sl_str": sl_str,
                "notional_usdc": 0.0,
            }

        m_cb = Decimal("0.50") if l2_derisk_active else Decimal("1.00")
        kappa_dec = _to_clean_decimal(kappa_risk)
        r_1r_dec = _to_clean_decimal(r_1r) * kappa_dec
        c_rt_dec = _to_clean_decimal(c_rt)
        risk_budget_usdc = eq * r_1r_dec * m_cb

        max_alloc_ratio = self.SLOT1_MAX_ALLOC_PCT if int(slot_id) == 1 else self.SLOT2_MAX_ALLOC_PCT
        max_notional_usdc = min(eq * max_alloc_ratio * m_cb, free * Decimal("0.995"))
        raw_risk_notional_usdc = risk_budget_usdc / (rounded_sl_dist_pct + c_rt_dec)
        target_notional_usdc = min(raw_risk_notional_usdc, max_notional_usdc)

        if target_notional_usdc < self.MIN_ORDER_NOTIONAL_USDC:
            return {
                "eligible": False,
                "reason": f"V1_1_NOTIONAL_BELOW_16_USDC({float(target_notional_usdc):.2f})",
                "sz_str": "0",
                "px_str": px_str,
                "sl_str": sl_str,
                "notional_usdc": float(target_notional_usdc),
            }

        raw_sz = target_notional_usdc / px_dec
        sz_str = floor_size(raw_sz, sz_decimals)
        sz_dec = _to_clean_decimal(sz_str)
        notional = px_dec * sz_dec
        if notional < self.MIN_ORDER_NOTIONAL_USDC:
            return {
                "eligible": False,
                "reason": f"ROUNDED_NOTIONAL_BELOW_16_USDC({float(notional):.2f})",
                "sz_str": sz_str,
                "px_str": px_str,
                "sl_str": sl_str,
                "notional_usdc": float(notional),
            }

        actual_risk_usdc = sz_dec * (px_dec - sl_dec) + (notional * c_rt_dec)
        return {
            "eligible": True,
            "reason": "OK",
            "formula": "v1.1_fractional_kelly_1.25pct",
            "slot_id": int(slot_id),
            "px_str": px_str,
            "sl_str": sl_str,
            "sz_str": sz_str,
            "notional_usdc": float(notional),
            "risk_budget_usdc": float(risk_budget_usdc),
            "actual_risk_usdc": float(actual_risk_usdc),
            "sl_distance_pct": round(float(rounded_sl_dist_pct) * 100.0, 4),
            "m_cb": float(m_cb),
        }

    def calculate_single_bullet_sizing(
        self,
        slot_id: int,
        equity_usdc: float,
        free_usdc: float,
        entry_px: float,
        sl_px: float,
        sz_decimals: int,
        l2_derisk_active: bool = False,
        use_v1_1_formula: bool = False,
    ) -> Dict[str, Any]:
        """
        Single-Bullet (100%一括発注・一括決済) 方式の注文数量・リスク額を算出する。
        - use_v1_1_formula=True の場合は v1.1 1R=1.25% (c_RT=0.20%込み) 方式を使用
        - Slot 1: 最大投入 = 総資産の 70%、1R = 総資産の 2.0% (L2発動時は 1.0%)
        - Slot 2: 最大投入 = 総資産の 38% (または残余 free_usdc の 98%)、1R = 総資産の 1.0%〜2.0%
        - 最小発注額フロア `16.0 USDC` 以上、初期SL距離 `8.0%` 以下（丸め前後とも）を厳密検証
        """
        if use_v1_1_formula:
            return self.calculate_v1_1_single_bullet_sizing(
                slot_id=slot_id,
                equity_usdc=equity_usdc,
                free_usdc=free_usdc,
                entry_px=entry_px,
                sl_px=sl_px,
                sz_decimals=sz_decimals,
                l2_derisk_active=l2_derisk_active,
            )
        eq = _to_clean_decimal(equity_usdc)
        free = _to_clean_decimal(free_usdc)
        epx = _to_clean_decimal(entry_px)
        spx = _to_clean_decimal(sl_px)

        if eq <= 0 or free <= 0:
            return {"eligible": False, "reason": "NON_POSITIVE_EQUITY_OR_FREE_USDC", "sz_str": "0", "notional_usdc": 0.0}
        if epx <= 0 or spx <= 0 or spx >= epx:
            return {"eligible": False, "reason": "INVALID_ENTRY_OR_SL_PRICE", "sz_str": "0", "notional_usdc": 0.0}

        px_str = round_price(epx, sz_decimals)
        sl_str = round_price(spx, sz_decimals)
        px_dec = _to_clean_decimal(px_str)
        sl_dec = _to_clean_decimal(sl_str)
        if px_dec <= 0 or sl_dec <= 0 or sl_dec >= px_dec:
            return {"eligible": False, "reason": "INVALID_ROUNDED_ENTRY_OR_SL_PRICE", "sz_str": "0", "notional_usdc": 0.0}

        raw_sl_dist_pct = (epx - spx) / epx
        rounded_sl_dist_pct = (px_dec - sl_dec) / px_dec
        sl_dist_pct = max(raw_sl_dist_pct, rounded_sl_dist_pct)
        if sl_dist_pct > self.MAX_INITIAL_SL_PCT:
            return {
                "eligible": False,
                "reason": f"SL_PCT_EXCEEDS_8PCT_CAP({float(sl_dist_pct)*100:.2f}%)",
                "sz_str": "0",
                "px_str": px_str,
                "sl_str": sl_str,
                "notional_usdc": 0.0,
            }

        risk_pct = self.DERISKED_RISK_PCT if l2_derisk_active else self.BASE_RISK_PCT
        risk_budget_usdc = eq * risk_pct

        max_alloc_ratio = self.SLOT1_MAX_ALLOC_PCT if int(slot_id) == 1 else self.SLOT2_MAX_ALLOC_PCT
        # 手数料余裕のため free_usdc の 99.5% を上限とする
        max_notional_usdc = min(eq * max_alloc_ratio, free * Decimal("0.995"))
        if max_notional_usdc < self.MIN_ORDER_NOTIONAL_USDC:
            return {
                "eligible": False,
                "reason": f"AVAILABLE_ALLOCATION_BELOW_16_USDC({float(max_notional_usdc):.2f})",
                "sz_str": "0",
                "notional_usdc": 0.0,
            }

        risk_per_unit = px_dec - sl_dec
        sz_by_risk = risk_budget_usdc / risk_per_unit
        sz_by_alloc = max_notional_usdc / px_dec
        raw_sz = min(sz_by_risk, sz_by_alloc)

        sz_str = floor_size(raw_sz, sz_decimals)
        sz_dec = _to_clean_decimal(sz_str)
        notional = px_dec * sz_dec

        if notional < self.MIN_ORDER_NOTIONAL_USDC:
            return {
                "eligible": False,
                "reason": f"ROUNDED_NOTIONAL_BELOW_16_USDC({float(notional):.2f})",
                "sz_str": sz_str,
                "px_str": px_str,
                "sl_str": sl_str,
                "notional_usdc": float(notional),
            }

        actual_risk_usdc = sz_dec * (px_dec - sl_dec)
        return {
            "eligible": True,
            "reason": "OK",
            "slot_id": int(slot_id),
            "px_str": px_str,
            "sl_str": sl_str,
            "sz_str": sz_str,
            "notional_usdc": float(notional),
            "risk_budget_usdc": float(risk_budget_usdc),
            "actual_risk_usdc": float(actual_risk_usdc),
            "sl_distance_pct": round(float(rounded_sl_dist_pct) * 100.0, 4),
        }

    # ==========================================================================
    # 2. 第2枠 (Slot 2) 解放の3重+相関ゲート判定 (`evaluate_slot2_triple_gate`)
    # ==========================================================================
    def evaluate_slot2_triple_gate(
        self,
        slot1_state: Dict[str, Any],
        slot1_best_bid: float,
        slot1_atr_1m: float,
        btc_perp_premium_pct: float,
        btc_perp_delta_oi_15m_pct: float,
        hype_perp_premium_pct: float,
        hype_perp_delta_oi_15m_pct: float,
        l2_active: bool = False,
        corr_4h: Optional[float] = None,
        slot1_closes_4h: Optional[Sequence[float]] = None,
        candidate_closes_4h: Optional[Sequence[float]] = None,
        max_corr_4h: float = 0.65,
    ) -> Dict[str, Any]:
        """
        ARCHITECTURE.md Section 5 + v1.1 Topic 4 に基づく第2枠 (Slot 2) 解放のゲート条件を検証する:
          1. Slot 1 が `OPEN_PROTECTED` かつサブ状態が `FREEROLL_LOCKED` (`P_SL_1 >= P_entry_1 * 1.0015`)
          2. 価格クッション条件: `P_bid_1 >= P_SL_1 + max(1.5 * ATR_1m_1, 0.0060 * P_entry_1)`
          3. Perpレジーム非悪化条件: BTCおよびHYPEの Perp `premium >= -0.05%` かつ `delta_OI_15m > -1.5%`
          4. (v1.1 Topic 4) 4h足リターン相関ゲート: `corr_4h <= 0.65`
        """
        if l2_active:
            return {"allowed": False, "failed_gate": "L2_DERISKING_ACTIVE", "reason": "Slot 2 frozen during L2 cooldown"}

        st1 = str(slot1_state.get("state", "IDLE"))
        sub1 = str(slot1_state.get("sub_state", "NONE"))
        stage1 = int(slot1_state.get("trailing_stage") or 1)
        entry_1 = float(slot1_state.get("entry_px") or 0.0)
        sl_1 = float(slot1_state.get("sl_px") or 0.0)

        # Gate 1: Slot 1 OPEN_PROTECTED & FREEROLL_LOCKED (Stage 2/3/4 または Stage 20/30/40 対応)
        is_freeroll_sub = (
            sub1 == SlotSubState.FREEROLL_LOCKED.value
            or TrailingStage.is_freeroll_locked_stage(stage1)
        )
        gate1_ok = bool(
            st1 == SlotState.OPEN_PROTECTED.value
            and is_freeroll_sub
            and entry_1 > 0
            and sl_1 >= entry_1 * self.FREEROLL_LOCK_MULT - 1e-9
        )
        if not gate1_ok:
            return {
                "allowed": False,
                "failed_gate": "GATE1_SLOT1_NOT_FREEROLL_LOCKED",
                "reason": f"state={st1}, sub_state={sub1}, sl_1={sl_1}, min_req={entry_1 * self.FREEROLL_LOCK_MULT:.6f}",
            }

        # Gate 2: 価格クッション条件
        required_cushion = max(1.5 * float(slot1_atr_1m), 0.0060 * entry_1)
        min_required_bid = sl_1 + required_cushion
        gate2_ok = bool(float(slot1_best_bid) >= min_required_bid - 1e-9)
        if not gate2_ok:
            return {
                "allowed": False,
                "failed_gate": "GATE2_INSUFFICIENT_PRICE_CUSHION",
                "reason": f"slot1_best_bid({slot1_best_bid:.6f}) < required({min_required_bid:.6f})",
                "min_required_bid": min_required_bid,
            }

        # Gate 3: BTC & HYPE Perp レジーム非悪化条件 (premium >= -0.05% かつ delta_OI_15m > -1.5%)
        btc_ok = float(btc_perp_premium_pct) >= -0.05 and float(btc_perp_delta_oi_15m_pct) > -1.5
        hype_ok = float(hype_perp_premium_pct) >= -0.05 and float(hype_perp_delta_oi_15m_pct) > -1.5
        gate3_ok = bool(btc_ok and hype_ok)
        if not gate3_ok:
            return {
                "allowed": False,
                "failed_gate": "GATE3_PERP_REGIME_DETERIORATING",
                "reason": (
                    f"BTC(prem={btc_perp_premium_pct:.3f}%, dOI15m={btc_perp_delta_oi_15m_pct:.2f}%), "
                    f"HYPE(prem={hype_perp_premium_pct:.3f}%, dOI15m={hype_perp_delta_oi_15m_pct:.2f}%)"
                ),
            }

        # Gate 4 (v1.1 Topic 4): 4h足リターン相関係数 corr_4h <= 0.65
        eff_corr = corr_4h
        if eff_corr is None and slot1_closes_4h is not None and candidate_closes_4h is not None:
            eff_corr = compute_return_correlation_4h(slot1_closes_4h, candidate_closes_4h)
        if eff_corr is not None and float(eff_corr) > float(max_corr_4h):
            return {
                "allowed": False,
                "failed_gate": "GATE4_HIGH_4H_RETURN_CORRELATION",
                "reason": f"corr_4h({float(eff_corr):.4f}) > max_corr_4h({float(max_corr_4h):.2f})",
                "corr_4h": round(float(eff_corr), 4),
            }

        return {
            "allowed": True,
            "failed_gate": None,
            "reason": "ALL_3_GATES_PASSED",
            "min_required_bid": min_required_bid,
            "corr_4h": round(float(eff_corr), 4) if eff_corr is not None else None,
        }

    # ==========================================================================
    # 3. 親子スロット連動インターロック ＆ 事後リスクバジェット再計算
    # ==========================================================================
    def check_parent_child_interlock(
        self,
        slot1_state: Dict[str, Any],
        slot2_state: Dict[str, Any],
        slot1_best_bid: float,
    ) -> Dict[str, Any]:
        """
        Slot 2 が `ENTRY_PENDING`（買い指値待機中）の間に、
        Slot 1 の Best Bid が `P_bid_1 <= P_SL_1 * 1.0025` の危険水域へ接近した瞬間、
        または Slot 1 が `OPEN_PROTECTED` でなくなった瞬間に `should_cancel_slot2 = True` を返す。
        """
        st2 = str(slot2_state.get("state", "IDLE"))
        if st2 != SlotState.ENTRY_PENDING.value:
            return {"should_cancel_slot2": False, "reason": "SLOT2_NOT_ENTRY_PENDING"}

        st1 = str(slot1_state.get("state", "IDLE"))
        if st1 != SlotState.OPEN_PROTECTED.value:
            return {
                "should_cancel_slot2": True,
                "reason": f"PARENT_SLOT1_NO_LONGER_OPEN_PROTECTED(state={st1})",
            }

        sl_1 = float(slot1_state.get("sl_px") or 0.0)
        danger_threshold = sl_1 * self.SLOT1_DANGER_SL_MULT
        if float(slot1_best_bid) <= danger_threshold:
            return {
                "should_cancel_slot2": True,
                "reason": f"SLOT1_BID_NEAR_SL({slot1_best_bid:.6f} <= {danger_threshold:.6f})",
                "danger_threshold": danger_threshold,
            }

        return {"should_cancel_slot2": False, "reason": "SAFE"}

    def recalculate_post_slot1_loss_budget(
        self,
        equity_usdc: float,
        slot1_realized_loss_usdc: float,
        slot2_state: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Slot 2 が `OPEN_PROTECTED` 保有中に、Slot 1 が急落時のスリッページ等で
        マイナス決済（損失額 `D_1 > 0`）となった場合の事後リスクバジェット再計算:
          - `R_max = 0.020 * Equity_USDC`
          - `R_rem = max(0, R_max - D_1)`
          - `0 < D_1 < 0.75 * R_max`: Slot 2 の `sl_px` を `P_entry_2 - R_rem / sz_2` へ引き上げ
          - `D_1 >= 0.75 * R_max`: Slot 2 も即座に `IOC` で100%緊急決済 (`EMERGENCY_IOC_FLATTEN_SLOT2`)
        """
        d1 = float(slot1_realized_loss_usdc)
        st2 = str(slot2_state.get("state", "IDLE"))
        if d1 <= 0.0 or st2 != SlotState.OPEN_PROTECTED.value:
            return {"action": "NONE", "reason": "NO_SLOT1_LOSS_OR_SLOT2_NOT_OPEN"}

        r_max = 0.020 * float(equity_usdc)
        r_rem = max(0.0, r_max - d1)

        if d1 >= self.POST_LOSS_EMERGENCY_RATIO * r_max:
            return {
                "action": "EMERGENCY_IOC_FLATTEN_SLOT2",
                "reason": f"Slot 1 loss D_1 ({d1:.2f} USDC) >= 0.75 * R_max ({0.75 * r_max:.2f} USDC)",
                "r_max_usdc": r_max,
                "r_rem_usdc": r_rem,
                "d1_loss_usdc": d1,
            }

        entry_2 = float(slot2_state.get("entry_px") or 0.0)
        sz_2 = float(slot2_state.get("current_sz") or 0.0)
        cur_sl_2 = float(slot2_state.get("sl_px") or 0.0)
        sz_dec_2 = int(slot2_state.get("sz_decimals") or 2)

        if entry_2 <= 0 or sz_2 <= 0:
            return {"action": "EMERGENCY_IOC_FLATTEN_SLOT2", "reason": "INVALID_SLOT2_POSITION_DATA"}

        tightened_raw = entry_2 - (r_rem / sz_2)
        new_sl_2 = float(round_price(max(cur_sl_2, tightened_raw), sz_dec_2))
        return {
            "action": "TIGHTEN_SLOT2_SL",
            "reason": f"0 < D_1 ({d1:.2f}) < 0.75 * R_max ({0.75 * r_max:.2f})",
            "r_max_usdc": r_max,
            "r_rem_usdc": r_rem,
            "d1_loss_usdc": d1,
            "old_sl_px": cur_sl_2,
            "new_sl_px": new_sl_2,
        }

    # ==========================================================================
    # 4. 多層価格サニティフィルタ ＆ 総資産算出式 (`Equity_USDC`)
    # ==========================================================================
    def evaluate_token_price_sanity(
        self,
        pair_name: str,
        best_bid: float,
        best_ask: float,
        mark_px: float,
        perp_oracle_px: float = 0.0,
    ) -> Dict[str, Any]:
        """
        ARCHITECTURE.md Section 6.1 に基づく3重価格サニティ検証:
          1. 相対スプレッド `(P_ask - P_bid) / P_mid` が Tier 1 で <= 1.5%、Tier 2 で <= 3.0%
          2. 前周期（15秒前）の正常価格からの変化率が <= 8.0%
          3. Tier 1 銘柄において、Spot仲値とPerpオラクル価格 (`oraclePx`) の乖離が <= 2.0%
        - 正常時 (`VALID`): `P_ref = median(P_mid, P_mark, P_bid)`, `P_val = max(P_bid, 0.995 * P_ref)`
        - 異常時 (`TAINTED`): 最大4周期（60秒間）まで直前の正常価格を保持し `price_tainted = True` を返す
        """
        pair = str(pair_name).strip().upper()
        is_tier1 = pair in TIER1_CORE_PAIRS
        bid = float(best_bid)
        ask = float(best_ask)
        mark = float(mark_px)
        oracle = float(perp_oracle_px)

        reasons: List[str] = []
        if bid <= 0 or ask <= 0 or ask < bid:
            reasons.append("NON_POSITIVE_OR_CROSSED_BBO")
            mid = max(bid, mark, 0.0)
        else:
            mid = (bid + ask) / 2.0
            rel_spread_pct = ((ask - bid) / mid) * 100.0 if mid > 0 else 999.0
            max_spread_pct = 1.5 if is_tier1 else 3.0
            if rel_spread_pct > max_spread_pct:
                reasons.append(f"SPREAD_EXCEEDED({rel_spread_pct:.2f}%>{max_spread_pct:.1f}%)")

        prev_valid = self._last_valid_prices.get(pair)
        if prev_valid is not None and prev_valid > 0 and mid > 0:
            step_change_pct = (abs(mid - prev_valid) / prev_valid) * 100.0
            if step_change_pct > 8.0:
                reasons.append(f"STEP_CHANGE_15S_EXCEEDED({step_change_pct:.2f}%>8.0%)")

        if is_tier1 and oracle > 0 and mid > 0:
            oracle_div_pct = (abs(mid - oracle) / oracle) * 100.0
            if oracle_div_pct > 2.0:
                reasons.append(f"ORACLE_DIVERGENCE_EXCEEDED({oracle_div_pct:.2f}%>2.0%)")

        eff_mark = mark if mark > 0 else mid
        p_ref = float(statistics.median([mid, eff_mark, bid])) if (mid > 0 and bid > 0) else max(bid, mid, eff_mark)
        raw_p_val = max(bid, 0.995 * p_ref)

        if not reasons:
            self._last_valid_prices[pair] = raw_p_val
            self._tainted_cycle_counts[pair] = 0
            return {
                "pair_name": pair,
                "status": "VALID",
                "price_tainted": False,
                "p_val": raw_p_val,
                "p_ref": p_ref,
                "tainted_cycles": 0,
                "reasons": [],
            }

        # TAINTED 発生時: 最大4周期まで直前の正常価格を保持し、5周期目以降は実勢価格へ移行してストライク凍結を解除
        cnt = self._tainted_cycle_counts.get(pair, 0) + 1
        self._tainted_cycle_counts[pair] = cnt
        if prev_valid is not None and cnt <= self.MAX_TAINTED_CYCLES:
            return {
                "pair_name": pair,
                "status": "TAINTED",
                "price_tainted": True,
                "p_val": float(prev_valid),
                "p_ref": p_ref,
                "tainted_cycles": cnt,
                "reasons": reasons,
            }

        # 5周期目以降 (cnt > MAX_TAINTED_CYCLES): 直前価格保持上限に達したため現在価格を採用し、基準価格を再アンカー
        if bid > 0 and ask >= bid:
            self._last_valid_prices[pair] = raw_p_val
        return {
            "pair_name": pair,
            "status": "TAINTED_FALLBACK_ADOPTED",
            "price_tainted": False,
            "p_val": float(raw_p_val),
            "p_ref": p_ref,
            "tainted_cycles": cnt,
            "reasons": reasons,
        }

    def compute_total_equity_usdc(
        self,
        spot_balances: Dict[str, Dict[str, Decimal]],
        token_valuations: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        ARCHITECTURE.md Section 6.2 の総資産算出式:
        `Equity_USDC(t) = Total_USDC(t) + sum(Total_i(t) * P_val_i(t) * (1 - 0.0007))`
        （※ 買い指値待機中に拘束されている `hold` 分も総資産に含めるため必ず `total` を使用する）
        """
        usdc_entry = spot_balances.get("USDC") or {}
        total_usdc = _to_clean_decimal(usdc_entry.get("total", Decimal("0")))
        hold_usdc = _to_clean_decimal(usdc_entry.get("hold", Decimal("0")))
        free_usdc = max(Decimal("0"), total_usdc - hold_usdc)

        tokens_net_usdc = Decimal("0")
        any_tainted = False
        token_breakdown: Dict[str, Dict[str, float]] = {}

        for asset, bal in spot_balances.items():
            coin = str(asset).strip().upper()
            if coin == "USDC":
                continue
            tot_i = _to_clean_decimal(bal.get("total", Decimal("0")))
            if tot_i <= 0:
                continue

            val_info = (
                token_valuations.get(coin)
                or token_valuations.get(f"{coin}/USDC")
                or {}
            )
            p_val_dec = _to_clean_decimal(val_info.get("p_val", 0.0))
            is_tainted = bool(val_info.get("price_tainted", False))
            if is_tainted:
                any_tainted = True

            net_val_i = tot_i * p_val_dec * (Decimal("1") - self.TAKER_FEE_RATE)
            tokens_net_usdc += net_val_i
            token_breakdown[coin] = {
                "total_qty": float(tot_i),
                "p_val": float(p_val_dec),
                "net_usdc_val": float(net_val_i),
                "price_tainted": is_tainted,
            }

        equity_dec = total_usdc + tokens_net_usdc
        return {
            "equity_usdc": float(equity_dec),
            "total_usdc": float(total_usdc),
            "hold_usdc": float(hold_usdc),
            "free_usdc": float(free_usdc),
            "tokens_net_usdc": float(tokens_net_usdc),
            "price_tainted_flag": any_tainted,
            "token_breakdown": token_breakdown,
        }

    # ==========================================================================
    # 5. L1〜L5 サーキットブレーカー統合マトリクス (`evaluate_circuit_breakers`)
    # ==========================================================================
    def rollover_daily_and_weekly_baselines(
        self,
        equity_usdc: float,
        current_time_ms: Optional[int] = None,
        force_daily: bool = False,
        force_weekly: bool = False,
    ) -> Dict[str, Any]:
        """
        日次基準時刻 (06:00 JST) および週次基準時刻 (月曜 06:00 JST) を跨いだ際に
        `sod_equity_usdc`, `sow_equity_usdc`, `daily_trade_count = 0` をアトミックにロールオーバーする。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        eq = float(equity_usdc)
        cur_sod_anchor = get_current_0600_jst_anchor_ms(ts)
        cur_sow_anchor = get_current_monday_0600_jst_anchor_ms(ts)

        daily_rolled = False
        weekly_rolled = False

        with self.db.immediate_transaction() as tx:
            row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            if not row:
                raise RuntimeError("system_state_store が未初期化です。")

            sod_eq = float(row["sod_equity_usdc"])
            sow_eq = float(row["sow_equity_usdc"])
            daily_cnt = int(row["daily_trade_count"])

            if force_daily or (self._last_sod_anchor_ms > 0 and cur_sod_anchor > self._last_sod_anchor_ms):
                if eq > 0:
                    sod_eq = eq
                daily_cnt = 0
                self._l3_daily_dd_strikes = 0
                daily_rolled = True

            if force_weekly or (self._last_sow_anchor_ms > 0 and cur_sow_anchor > self._last_sow_anchor_ms):
                if eq > 0:
                    sow_eq = eq
                weekly_rolled = True

            self._last_sod_anchor_ms = cur_sod_anchor
            self._last_sow_anchor_ms = cur_sow_anchor

            if daily_rolled or weekly_rolled:
                tx.execute(
                    """
                    UPDATE system_state_store
                    SET sod_equity_usdc = ?,
                        sow_equity_usdc = ?,
                        daily_trade_count = ?,
                        updated_at_ms = ?
                    WHERE id = 1
                    """,
                    (sod_eq, sow_eq, daily_cnt, ts),
                )

        return {
            "daily_rolled": daily_rolled,
            "weekly_rolled": weekly_rolled,
            "sod_equity_usdc": sod_eq,
            "sow_equity_usdc": sow_eq,
            "daily_trade_count": daily_cnt,
            "sod_anchor_ms": cur_sod_anchor,
            "sow_anchor_ms": cur_sow_anchor,
        }

    def evaluate_circuit_breakers(
        self,
        equity_usdc: float,
        price_tainted_flag: bool = False,
        in_quiescence: bool = False,
        btc_perp_delta_oi_1h_pct: float = 0.0,
        btc_perp_premium_pct: float = 0.0,
        perp_cascade_detected: bool = False,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        ARCHITECTURE.md Section 6.3 の L1〜L5 サーキットブレーカー統合評価を行い、
        `system_state_store` を更新して現在の制限状態と緊急アクション指示を返す。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        eq = float(equity_usdc)
        cur_sod_anchor = get_current_0600_jst_anchor_ms(ts)
        cur_sow_anchor = get_current_monday_0600_jst_anchor_ms(ts)

        daily_rolled = False
        weekly_rolled = False

        with self.db.immediate_transaction() as tx:
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            if not sys_row:
                raise RuntimeError("system_state_store が未初期化です。")

            init_eq = float(sys_row["initial_equity_usdc"])
            hwm_eq = float(sys_row["hwm_equity_usdc"])
            sod_eq = float(sys_row["sod_equity_usdc"])
            sow_eq = float(sys_row["sow_equity_usdc"])
            daily_cnt = int(sys_row["daily_trade_count"])
            consec_losses = int(sys_row["consecutive_losses"])
            l2_until = int(sys_row["l2_active_until_ms"])
            l3_until = int(sys_row["l3_active_until_ms"])
            l4_until = int(sys_row["l4_active_until_ms"])
            l5_strikes = int(sys_row["l5_strike_count"])
            cur_mode = str(sys_row["system_mode"])

            # 初期状態 (initial_equity_usdc == 0.0 等) のゼロ除算・誤L5発動防止シード処理
            if not price_tainted_flag and not in_quiescence and eq > 0:
                if init_eq <= 0.0:
                    init_eq = eq
                if hwm_eq <= 0.0:
                    hwm_eq = eq
                if sod_eq <= 0.0:
                    sod_eq = eq
                if sow_eq <= 0.0:
                    sow_eq = eq

            # 06:00 JST 日次ロールオーバー & 月曜 06:00 JST 週次ロールオーバー判定
            if not price_tainted_flag and not in_quiescence and eq > 0:
                if self._last_sod_anchor_ms == 0:
                    self._last_sod_anchor_ms = cur_sod_anchor
                elif cur_sod_anchor > self._last_sod_anchor_ms:
                    sod_eq = eq
                    daily_cnt = 0
                    self._l3_daily_dd_strikes = 0
                    self._last_sod_anchor_ms = cur_sod_anchor
                    daily_rolled = True

                if self._last_sow_anchor_ms == 0:
                    self._last_sow_anchor_ms = cur_sow_anchor
                elif cur_sow_anchor > self._last_sow_anchor_ms:
                    sow_eq = eq
                    self._last_sow_anchor_ms = cur_sow_anchor
                    weekly_rolled = True

            # 価格健全かつ静止期間外の場合のみ HWM を更新
            if not price_tainted_flag and not in_quiescence and eq > hwm_eq:
                hwm_eq = eq

            # ------------------------------------------------------------------
            # クールダウン期限切れ時の自動リセット・基準資産再アンカー処理 (DB永続化保証)
            # ------------------------------------------------------------------
            if 0 < l2_until <= ts:
                l2_until = 0
                consec_losses = 0
                self._l2_perp_softness_strikes = 0
                self._l2_daily_dd_served_anchor_ms = cur_sod_anchor
                if eq > 0 and sod_eq > 0 and ((eq - sod_eq) / sod_eq) * 100.0 <= -1.5:
                    sod_eq = eq

            if 0 < l3_until <= ts:
                l3_until = 0
                self._l3_daily_dd_strikes = 0
                if eq > 0 and sod_eq > 0 and ((eq - sod_eq) / sod_eq) * 100.0 <= -3.0:
                    sod_eq = eq
                    daily_cnt = 0
                    daily_rolled = True

            if 0 < l4_until <= ts:
                l4_until = 0
                if eq > 0 and sow_eq > 0 and ((eq - sow_eq) / sow_eq) * 100.0 <= -6.0:
                    sow_eq = eq
                    weekly_rolled = True

            daily_dd_pct = ((eq - sod_eq) / sod_eq) * 100.0 if sod_eq > 0 else 0.0
            weekly_dd_pct = ((eq - sow_eq) / sow_eq) * 100.0 if sow_eq > 0 else 0.0
            l5_ref_eq = max(init_eq, hwm_eq)
            l5_floor_eq = self.L5_KILL_DRAWDOWN_RATIO * l5_ref_eq if l5_ref_eq > 0 else 0.0

            # ------------------------------------------------------------------
            # L2: 2連敗、日次DD <= -1.5%、またはBTC Perp軟化2回連続 -> 6時間デリスキング
            # ------------------------------------------------------------------
            btc_soft = (float(btc_perp_delta_oi_1h_pct) <= -2.5 and float(btc_perp_premium_pct) <= -0.10)
            if btc_soft:
                self._l2_perp_softness_strikes += 1
            else:
                self._l2_perp_softness_strikes = 0

            daily_dd_l2_trig = (
                daily_dd_pct <= -1.5
                and self._l2_daily_dd_served_anchor_ms != cur_sod_anchor
            )
            if not price_tainted_flag and l2_until == 0:
                if (
                    consec_losses >= 2
                    or daily_dd_l2_trig
                    or self._l2_perp_softness_strikes >= 2
                ):
                    l2_until = ts + 6 * 3_600_000
                    self._l2_perp_softness_strikes = 0
                    if daily_dd_l2_trig:
                        self._l2_daily_dd_served_anchor_ms = cur_sod_anchor

            l2_active = bool(ts < l2_until)

            # ------------------------------------------------------------------
            # L3: 日次損失リミット (-3.0% を価格健全状態で3回連続確認 -> 翌06:00 JSTまで新規停止)
            # ------------------------------------------------------------------
            l3_triggered_now = False
            if not price_tainted_flag and not in_quiescence and sod_eq > 0 and l3_until == 0:
                if daily_dd_pct <= -3.0:
                    self._l3_daily_dd_strikes += 1
                    if self._l3_daily_dd_strikes >= self.L3_REQUIRED_STRIKES:
                        next_0600 = get_next_0600_jst_ms(ts)
                        if l3_until < next_0600:
                            l3_triggered_now = True
                        l3_until = max(l3_until, next_0600)
                else:
                    self._l3_daily_dd_strikes = 0

            l3_active = bool(ts < l3_until)

            # ------------------------------------------------------------------
            # L4: 週次損失リミット (-6.0%) または Perp清算カスケード検知
            # ------------------------------------------------------------------
            l4_cascade_flatten_now = False
            if perp_cascade_detected:
                l4_until = max(l4_until, ts + 12 * 3_600_000)
                l4_cascade_flatten_now = True
            elif not price_tainted_flag and not in_quiescence and sow_eq > 0 and l4_until == 0 and weekly_dd_pct <= -6.0:
                l4_until = max(l4_until, get_next_monday_0600_jst_ms(ts))

            l4_active = bool(ts < l4_until)

            # ------------------------------------------------------------------
            # L5: ハード・キルスイッチ (Equity < 0.85 * max(Initial, HWM) を
            #     独立3周期・12秒以上間隔・静止状態・価格異常なしで3回連続確認)
            # ------------------------------------------------------------------
            l5_triggered_now = False
            if (
                not price_tainted_flag
                and not in_quiescence
                and cur_mode != SystemMode.HALTED.value
                and l5_ref_eq > 0.0
                and eq > 0.0
            ):
                if eq < l5_floor_eq:
                    if self._last_l5_strike_ts_ms == 0 or (ts - self._last_l5_strike_ts_ms) >= self.L5_MIN_STRIKE_INTERVAL_MS:
                        l5_strikes += 1
                        self._last_l5_strike_ts_ms = ts
                        if l5_strikes >= self.L5_REQUIRED_STRIKES:
                            cur_mode = SystemMode.HALTED.value
                            l5_triggered_now = True
                            logger.critical(
                                "L5 ハード・キルスイッチ発動! Equity(%.2f) < 85%% Floor(%.2f) 3周期連続確定",
                                eq,
                                l5_floor_eq,
                            )
                else:
                    l5_strikes = 0
                    self._last_l5_strike_ts_ms = 0

            tx.execute(
                """
                UPDATE system_state_store
                SET system_mode = ?,
                    initial_equity_usdc = ?,
                    hwm_equity_usdc = ?,
                    sod_equity_usdc = ?,
                    sow_equity_usdc = ?,
                    current_equity_usdc = ?,
                    daily_trade_count = ?,
                    consecutive_losses = ?,
                    l2_active_until_ms = ?,
                    l3_active_until_ms = ?,
                    l4_active_until_ms = ?,
                    l5_strike_count = ?,
                    updated_at_ms = ?
                WHERE id = 1
                """,
                (
                    cur_mode,
                    init_eq,
                    hwm_eq,
                    sod_eq,
                    sow_eq,
                    eq,
                    daily_cnt,
                    consec_losses,
                    l2_until,
                    l3_until,
                    l4_until,
                    l5_strikes,
                    ts,
                ),
            )

        return {
            "system_mode": cur_mode,
            "equity_usdc": eq,
            "initial_equity_usdc": init_eq,
            "hwm_equity_usdc": hwm_eq,
            "sod_equity_usdc": sod_eq,
            "sow_equity_usdc": sow_eq,
            "daily_trade_count": daily_cnt,
            "consecutive_losses": consec_losses,
            "l2_active_until_ms": l2_until,
            "l3_active_until_ms": l3_until,
            "l4_active_until_ms": l4_until,
            "daily_rolled": daily_rolled,
            "weekly_rolled": weekly_rolled,
            "l5_floor_usdc": round(l5_floor_eq, 4),
            "daily_dd_pct": round(daily_dd_pct, 4),
            "weekly_dd_pct": round(weekly_dd_pct, 4),
            "price_tainted_flag": price_tainted_flag,
            "l2_active": l2_active,
            "l3_active": l3_active,
            "l3_strikes": self._l3_daily_dd_strikes,
            "l3_triggered_now": l3_triggered_now,
            "l4_active": l4_active,
            "l4_cascade_flatten_now": l4_cascade_flatten_now,
            "l5_strikes": l5_strikes,
            "l5_triggered_now": l5_triggered_now,
            "new_buy_allowed": bool(
                cur_mode == SystemMode.NORMAL.value and not l3_active and not l4_active
            ),
            "required_conviction_score": 85 if l2_active else 75,
            "risk_per_trade_pct": 0.010 if l2_active else 0.020,
        }
