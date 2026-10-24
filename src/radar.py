"""
HL AI Trader v1 — 7-Stage Microstructure Filter, MTF Decoupling & Perp Signal Radar (src/radar.py)

実装機能 (ARCHITECTURE.md Section 3 完全準拠):
1. 7段階マイクロストラクチャ・フィルタ (HIP-2 自動グリッドMM排除):
   - Gate 1: 正規USDCペア検証 (`quote_token_idx == 0`, `isCanonical`, `#` 予測市場・Builder Fee完全除外)
   - Gate 2: 24時間売買代金 (`dayNtlVlm`): Tier 1 >= 5,000,000 USDC / Tier 2 >= 2,000,000 USDC
   - Gate 3: Mark-Mid価格乖離率: `|markPx - midPx| / midPx <= 0.08%` (8 bps)
   - Gate 4: BBOスプレッド上限 (`l2Book`): Tier 1 <= 0.08% (8 bps) / Tier 2 <= 0.15% (15 bps)
   - Gate 5: 有効板厚 (Cumulative Depth): Mid価格から ±0.30% 以内のBid/Askそれぞれの累積板厚 >= 5,000 USDC
   - Gate 6: HIP-2均一ステップ検知ガード: 上位5レベルの価格差がすべて約0.30%かつ数量が均一な場合はMM撤退・HIP-2露出と判定し即時除外
   - Gate 7: Perp需給＆Spot-Oracle Basis統合ゲート
2. マルチタイムフレーム (4H / 1H / 15m) デカップリング指標＆ATR閾値算出:
   - 4H環境認識 (`EMA20 > EMA50` または `close > EMA50` かつ高値・安値切り上げ)
   - 大型銘柄 (`UBTC/USDC`, `UETH/USDC`) vs 主力高ボラ銘柄 (`HYPE/USDC`, `USOL/USDC`, `PURR/USDC`) の最小1H/15m ATR%検証と初期SL/目標TP算出
3. Perp側オンチェーン需給シグナル (`metaAndAssetCtxs`) 統合:
   - ① 逆選択ガード (`Long-Flush Blocker`)
   - ② ショートスクイーズ・ブースト (`Short-Squeeze Boost`)
   - ③ Spot-Oracle Basisガード (`Basis > +0.20%`)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

from src.exchange_wrapper import SpotUniverseEntry

logger = logging.getLogger(__name__)

TIER1_CORE_PAIRS = frozenset(
    {
        "UBTC/USDC",
        "HYPE/USDC",
        "UETH/USDC",
        "USOL/USDC",
    }
)

LARGE_CAP_PAIRS = frozenset(
    {
        "UBTC/USDC",
        "UETH/USDC",
    }
)


@dataclass
class FilterGateResult:
    """7段階マイクロストラクチャ・フィルタおよびPerp需給判定結果"""

    pair_name: str
    passed: bool
    tier: int
    failed_stage: Optional[str] = None
    fail_reason: Optional[str] = None
    day_ntl_vlm_usdc: float = 0.0
    mark_mid_divergence_pct: float = 0.0
    bbo_spread_pct: float = 0.0
    bbo_spread_bps: float = 0.0
    best_bid: float = 0.0
    best_ask: float = 0.0
    mid_px: float = 0.0
    bid_depth_030pct_usdc: float = 0.0
    ask_depth_030pct_usdc: float = 0.0
    hip2_exposed: bool = False
    spot_oracle_basis_pct: float = 0.0
    long_flush_blocked: bool = False
    short_squeeze_boost: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


def _compute_ema_series(values: Sequence[float], period: int) -> List[float]:
    if not values:
        return []
    alpha = 2.0 / (float(period) + 1.0)
    ema: List[float] = [float(values[0])]
    for v in values[1:]:
        ema.append(alpha * float(v) + (1.0 - alpha) * ema[-1])
    return ema


def _compute_atr_series(
    highs: Sequence[float],
    lows: Sequence[float],
    closes: Sequence[float],
    period: int = 14,
) -> float:
    n = min(len(highs), len(lows), len(closes))
    if n == 0:
        return 0.0
    if n == 1:
        return max(0.0, float(highs[0]) - float(lows[0]))

    trs: List[float] = [max(0.0, float(highs[0]) - float(lows[0]))]
    for i in range(1, n):
        h = float(highs[i])
        l = float(lows[i])
        prev_c = float(closes[i - 1])
        tr = max(h - l, abs(h - prev_c), abs(l - prev_c))
        trs.append(tr)

    if len(trs) <= period:
        return float(sum(trs) / len(trs))

    # Wilder's smoothing ATR
    atr = float(sum(trs[:period]) / period)
    for tr in trs[period:]:
        atr = (atr * (period - 1) + tr) / float(period)
    return atr


def _compute_rsi(closes: Sequence[float], period: int = 14) -> float:
    if len(closes) < 2:
        return 50.0
    gains: List[float] = []
    losses: List[float] = []
    for i in range(1, len(closes)):
        diff = float(closes[i]) - float(closes[i - 1])
        gains.append(max(0.0, diff))
        losses.append(max(0.0, -diff))

    window = min(period, len(gains))
    avg_gain = sum(gains[-window:]) / float(window)
    avg_loss = sum(losses[-window:]) / float(window)
    if avg_loss <= 1e-12:
        return 100.0 if avg_gain > 0 else 50.0
    rs = avg_gain / avg_loss
    return 100.0 - (100.0 / (1.0 + rs))


class MarketRadarAndFilter:
    """
    Hyperliquid Spot の7段階マイクロストラクチャ・フィルタ（HIP-2排除）、
    マルチタイムフレーム（4H / 1H / 15m）デカップリング指標、および Perp 需給シグナル統合エンジン。
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        cfg = config or {}
        u_cfg = cfg.get("universe", {})
        f_cfg = u_cfg.get("filters", {})
        p_cfg = cfg.get("perp_signals", {})

        self.tier1_pairs = set(u_cfg.get("tier1_core_pairs") or TIER1_CORE_PAIRS)
        self.large_cap_pairs = set(
            (cfg.get("timeframes_and_atr") or {}).get("large_cap_pairs") or LARGE_CAP_PAIRS
        )

        # 7段階フィルタ閾値 (ARCHITECTURE.md Section 3.1)
        self.tier1_min_vlm_usdc = float(f_cfg.get("tier1_min_day_ntl_vlm_usdc", 5_000_000.0))
        self.tier2_min_vlm_usdc = float(f_cfg.get("tier2_min_day_ntl_vlm_usdc", 2_000_000.0))
        self.max_mark_mid_div_pct = float(f_cfg.get("max_mark_mid_divergence_pct", 0.08))
        self.tier1_max_spread_pct = float(f_cfg.get("tier1_max_bbo_spread_pct", 0.08))
        self.tier2_max_spread_pct = float(f_cfg.get("tier2_max_bbo_spread_pct", 0.15))
        self.min_depth_030pct_usdc = float(f_cfg.get("min_cumulative_depth_030pct_usdc", 5_000.0))
        self.hip2_step_pct = float(f_cfg.get("hip2_uniform_step_pct", 0.30))
        self.hip2_step_tol_pct = float(f_cfg.get("hip2_step_tolerance_pct", 0.04))
        self.hip2_size_cv_threshold = float(f_cfg.get("hip2_size_cv_threshold", 0.05))

        # Perp シグナル閾値 (ARCHITECTURE.md Section 3.3)
        lfb = p_cfg.get("long_flush_blocker", {})
        self.lfb_funding_combined_pct = float(lfb.get("funding_1h_pct_combined", 0.0050))
        self.lfb_delta_oi_4h_pct = float(lfb.get("delta_oi_4h_pct_combined", 6.0))
        self.lfb_premium_pct = float(lfb.get("premium_pct_combined", 0.15))
        self.lfb_funding_solo_pct = float(lfb.get("funding_1h_pct_solo", 0.0080))

        ssb = p_cfg.get("short_squeeze_boost", {})
        self.ssb_max_funding_pct = float(ssb.get("max_funding_1h_pct", 0.0))
        self.ssb_min_delta_oi_1h_pct = float(ssb.get("min_delta_oi_1h_pct", 2.5))
        self.ssb_max_premium_pct = float(ssb.get("max_premium_pct", -0.05))

        self.max_spot_oracle_basis_pct = float(p_cfg.get("spot_oracle_basis_max_pct", 0.20))

    def get_pair_tier(self, pair_name: str) -> int:
        return 1 if str(pair_name).strip().upper() in self.tier1_pairs else 2

    def is_large_cap(self, pair_name: str) -> bool:
        return str(pair_name).strip().upper() in self.large_cap_pairs

    # ==========================================================================
    # HIP-2 均一グリッド露出検知 (Gate 6)
    # ==========================================================================
    def detect_hip2_uniform_grid(
        self,
        levels_side: Sequence[Dict[str, Any]],
        num_levels: int = 5,
    ) -> bool:
        """
        上位 `num_levels` (デフォルト5レベル) の板データ `[{"px": ..., "sz": ...}, ...]` を検査し、
        隣接価格ステップがすべて約 0.30% (`0.30% ± 0.04%`) であり、かつ数量 (またはUSDC額) が均一
        (変動係数 CV <= 0.05) な場合は HIP-2 自動グリッドMMの直接露出と判定して True を返す。
        """
        if len(levels_side) < num_levels:
            return False

        top = levels_side[:num_levels]
        try:
            pxs = [float(item["px"]) for item in top]
            szs = [float(item["sz"]) for item in top]
        except (KeyError, TypeError, ValueError):
            return False

        if any(p <= 0 or s <= 0 for p, s in zip(pxs, szs)):
            return False

        step_pcts: List[float] = []
        for i in range(len(pxs) - 1):
            step = abs(pxs[i + 1] - pxs[i]) / pxs[i] * 100.0
            step_pcts.append(step)

        low_bound = self.hip2_step_pct - self.hip2_step_tol_pct
        high_bound = self.hip2_step_pct + self.hip2_step_tol_pct
        all_steps_around_030 = all(low_bound <= st <= high_bound for st in step_pcts)
        if not all_steps_around_030:
            return False

        # 数量または名目額(px * sz)の均一性検査 (CV = std / mean)
        arr_sz = np.array(szs, dtype=float)
        arr_ntl = np.array([p * s for p, s in zip(pxs, szs)], dtype=float)
        cv_sz = float(np.std(arr_sz) / np.mean(arr_sz)) if np.mean(arr_sz) > 0 else 1.0
        cv_ntl = float(np.std(arr_ntl) / np.mean(arr_ntl)) if np.mean(arr_ntl) > 0 else 1.0

        return bool(min(cv_sz, cv_ntl) <= self.hip2_size_cv_threshold)

    # ==========================================================================
    # Perp オンチェーン需給シグナル評価 (Section 3.3)
    # ==========================================================================
    def evaluate_perp_signals(
        self,
        funding_1h_pct: float,
        premium_pct: float,
        delta_oi_4h_pct: float = 0.0,
        delta_oi_1h_pct: float = 0.0,
        delta_oi_15m_pct: float = 0.0,
        spot_mid_px: float = 0.0,
        perp_oracle_px: float = 0.0,
        perp_mark_px: float = 0.0,
        regime_bullish: bool = True,
    ) -> Dict[str, Any]:
        """
        Perp側の Funding Rate (%/h), OI変化率 (%), Premium (%), OraclePx を統合評価する。
        （※全パーセント引数は `%` 単位、例: `+0.0050%` は `0.0050`, `+6.0%` は `6.0`, `+0.15%` は `0.15`）
        """
        f_1h = float(funding_1h_pct)
        prem = float(premium_pct)
        doi_4h = float(delta_oi_4h_pct)
        doi_1h = float(delta_oi_1h_pct)
        doi_15m = float(delta_oi_15m_pct)

        # 1. Long-Flush Blocker (逆選択ガード)
        combined_crowded = (
            f_1h >= self.lfb_funding_combined_pct
            and doi_4h >= self.lfb_delta_oi_4h_pct
            and prem >= self.lfb_premium_pct
        )
        solo_extreme_funding = f_1h >= self.lfb_funding_solo_pct
        long_flush_blocked = bool(combined_crowded or solo_extreme_funding)

        # 2. Short-Squeeze Boost (ショートスクイーズ・ブースト)
        short_squeeze_boost = bool(
            regime_bullish
            and f_1h < self.ssb_max_funding_pct
            and doi_1h >= self.ssb_min_delta_oi_1h_pct
            and prem <= self.ssb_max_premium_pct
        )

        # 3. Spot-Oracle Basis ガード: (P_spot_mid - P_perp_oracle) / P_perp_oracle > +0.20%
        basis_pct = 0.0
        basis_blocked = False
        if spot_mid_px > 0 and perp_oracle_px > 0:
            basis_pct = ((float(spot_mid_px) - float(perp_oracle_px)) / float(perp_oracle_px)) * 100.0
            basis_blocked = bool(basis_pct > self.max_spot_oracle_basis_pct)

        # 4. 清算カスケード緊急脱出条件 (In-Position Crash Guard の単一ティック判定)
        cascade_tick_detected = bool(
            doi_15m <= -4.5
            and prem <= -0.20
            and (spot_mid_px > perp_mark_px if (spot_mid_px > 0 and perp_mark_px > 0) else True)
        )

        return {
            "funding_1h_pct": f_1h,
            "premium_pct": prem,
            "delta_oi_4h_pct": doi_4h,
            "delta_oi_1h_pct": doi_1h,
            "delta_oi_15m_pct": doi_15m,
            "spot_oracle_basis_pct": round(basis_pct, 4),
            "long_flush_blocked": long_flush_blocked,
            "long_flush_reason": (
                "SOLO_EXTREME_FUNDING"
                if solo_extreme_funding
                else ("COMBINED_CROWDED_LONG" if combined_crowded else "NONE")
            ),
            "short_squeeze_boost": short_squeeze_boost,
            "basis_blocked": basis_blocked,
            "cascade_tick_detected": cascade_tick_detected,
        }

    # ==========================================================================
    # 7段階マイクロストラクチャ・フィルタ一括検証 (`evaluate_7_stage_filter`)
    # ==========================================================================
    def evaluate_7_stage_filter(
        self,
        entry: SpotUniverseEntry,
        l2_book: Dict[str, Any],
        perp_signals: Optional[Dict[str, Any]] = None,
        builder_fee_bps: float = 0.0,
    ) -> FilterGateResult:
        """
        ARCHITECTURE.md Section 3.1 & 3.3 に基づき、対象Spotペアに対して
        7段階すべてのマイクロストラクチャ＆オンチェーン需給ゲートを適用する。
        """
        pair = entry.pair_name.upper()
        tier = self.get_pair_tier(pair)

        # Gate 1: 正規USDCペア検証 & HIP-4予測市場 / Builder Fee 排除
        if (
            entry.quote_token_idx != 0
            or entry.quote_asset.upper() != "USDC"
            or not entry.is_canonical
            or entry.pair_name.startswith("#")
            or entry.api_coin_name.startswith("#")
            or float(builder_fee_bps) > 0.0
        ):
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE1_CANONICAL_USDC",
                fail_reason="Non-canonical pair, prediction market (#), or non-zero builder fee",
            )

        # Gate 2: 24時間売買代金 (dayNtlVlm)
        vlm = float(entry.spot_day_ntl_vlm)
        min_vlm = self.tier1_min_vlm_usdc if tier == 1 else self.tier2_min_vlm_usdc
        if vlm < min_vlm:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE2_VOLUME_24H",
                fail_reason=f"dayNtlVlm ({vlm:.0f} USDC) < Tier {tier} min ({min_vlm:.0f} USDC)",
                day_ntl_vlm_usdc=vlm,
            )

        # l2Book から BBO を抽出
        levels = l2_book.get("levels") or []
        if len(levels) < 2 or not levels[0] or not levels[1]:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE4_BBO_SPREAD",
                fail_reason="Empty or incomplete l2Book levels",
                day_ntl_vlm_usdc=vlm,
            )

        bids = levels[0]
        asks = levels[1]
        best_bid = float(bids[0]["px"])
        best_ask = float(asks[0]["px"])
        if best_bid <= 0 or best_ask <= 0 or best_ask < best_bid:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE4_BBO_SPREAD",
                fail_reason=f"Invalid BBO bid={best_bid}, ask={best_ask}",
                day_ntl_vlm_usdc=vlm,
            )

        book_mid = (best_bid + best_ask) / 2.0
        eff_mid = float(entry.spot_mid_px) if entry.spot_mid_px > 0 else book_mid
        eff_mark = float(entry.spot_mark_px) if entry.spot_mark_px > 0 else eff_mid

        # Gate 3: Mark-Mid 価格乖離率 (<= 0.08%)
        mark_mid_div_pct = (abs(eff_mark - eff_mid) / eff_mid) * 100.0 if eff_mid > 0 else 999.0
        if mark_mid_div_pct > self.max_mark_mid_div_pct + 1e-9:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE3_MARK_MID_DIVERGENCE",
                fail_reason=f"Mark-Mid divergence ({mark_mid_div_pct:.4f}%) > {self.max_mark_mid_div_pct:.4f}%",
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
            )

        # Gate 4: BBO スプレッド上限 (Tier 1 <= 0.08%, Tier 2 <= 0.15%)
        spread_pct = ((best_ask - best_bid) / book_mid) * 100.0
        spread_bps = spread_pct * 100.0
        max_spread = self.tier1_max_spread_pct if tier == 1 else self.tier2_max_spread_pct
        if spread_pct > max_spread + 1e-9:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE4_BBO_SPREAD",
                fail_reason=f"BBO spread ({spread_pct:.4f}%) > Tier {tier} max ({max_spread:.4f}%)",
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
                bbo_spread_pct=spread_pct,
                bbo_spread_bps=spread_bps,
                best_bid=best_bid,
                best_ask=best_ask,
                mid_px=book_mid,
            )

        # Gate 5: 有効板厚 (Mid価格から ±0.30% 以内のBid/Ask累積板厚 >= 5,000 USDC)
        min_bid_px_030 = book_mid * (1.0 - 0.0030)
        max_ask_px_030 = book_mid * (1.0 + 0.0030)
        bid_depth_usdc = sum(
            float(b["px"]) * float(b["sz"])
            for b in bids
            if float(b["px"]) >= min_bid_px_030
        )
        ask_depth_usdc = sum(
            float(a["px"]) * float(a["sz"])
            for a in asks
            if float(a["px"]) <= max_ask_px_030
        )
        if bid_depth_usdc < self.min_depth_030pct_usdc or ask_depth_usdc < self.min_depth_030pct_usdc:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE5_CUMULATIVE_DEPTH",
                fail_reason=(
                    f"Cumulative ±0.30% depth insufficient (bid={bid_depth_usdc:.1f} USDC, "
                    f"ask={ask_depth_usdc:.1f} USDC, min={self.min_depth_030pct_usdc:.1f} USDC)"
                ),
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
                bbo_spread_pct=spread_pct,
                bbo_spread_bps=spread_bps,
                best_bid=best_bid,
                best_ask=best_ask,
                mid_px=book_mid,
                bid_depth_030pct_usdc=bid_depth_usdc,
                ask_depth_030pct_usdc=ask_depth_usdc,
            )

        # Gate 6: HIP-2 均一ステップ検知ガード (上位5レベルが0.30%等間隔＆均一数量)
        hip2_bid = self.detect_hip2_uniform_grid(bids, num_levels=5)
        hip2_ask = self.detect_hip2_uniform_grid(asks, num_levels=5)
        if hip2_bid or hip2_ask:
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE6_HIP2_UNIFORM_GRID_EXPOSED",
                fail_reason="Detected uniform 0.30% HIP-2 mechanical grid without organic MM quotes",
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
                bbo_spread_pct=spread_pct,
                bbo_spread_bps=spread_bps,
                best_bid=best_bid,
                best_ask=best_ask,
                mid_px=book_mid,
                bid_depth_030pct_usdc=bid_depth_usdc,
                ask_depth_030pct_usdc=ask_depth_usdc,
                hip2_exposed=True,
            )

        # Gate 7: Perp需給＆Spot-Oracle Basisガード
        if perp_signals is None:
            # entry の raw_perp_ctx (比率表現: funding=0.00005 -> 0.0050%, premium=0.0015 -> 0.15%) から自動計算
            perp_signals = self.evaluate_perp_signals(
                funding_1h_pct=float(entry.perp_funding_1h) * 100.0,
                premium_pct=float(entry.perp_premium) * 100.0,
                delta_oi_4h_pct=0.0,
                delta_oi_1h_pct=0.0,
                spot_mid_px=book_mid,
                perp_oracle_px=float(entry.perp_oracle_px),
                perp_mark_px=float(entry.perp_mark_px),
            )

        basis_pct = float(perp_signals.get("spot_oracle_basis_pct", 0.0))
        if perp_signals.get("basis_blocked"):
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE7_SPOT_ORACLE_BASIS_TOO_HIGH",
                fail_reason=f"Spot-Oracle basis ({basis_pct:.3f}%) > +{self.max_spot_oracle_basis_pct:.2f}%",
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
                bbo_spread_pct=spread_pct,
                bbo_spread_bps=spread_bps,
                best_bid=best_bid,
                best_ask=best_ask,
                mid_px=book_mid,
                bid_depth_030pct_usdc=bid_depth_usdc,
                ask_depth_030pct_usdc=ask_depth_usdc,
                spot_oracle_basis_pct=basis_pct,
            )

        if perp_signals.get("long_flush_blocked"):
            return FilterGateResult(
                pair_name=pair,
                passed=False,
                tier=tier,
                failed_stage="GATE7_PERP_LONG_FLUSH_BLOCKER",
                fail_reason=f"Perp Long-Flush Blocker triggered ({perp_signals.get('long_flush_reason')})",
                day_ntl_vlm_usdc=vlm,
                mark_mid_divergence_pct=mark_mid_div_pct,
                bbo_spread_pct=spread_pct,
                bbo_spread_bps=spread_bps,
                best_bid=best_bid,
                best_ask=best_ask,
                mid_px=book_mid,
                bid_depth_030pct_usdc=bid_depth_usdc,
                ask_depth_030pct_usdc=ask_depth_usdc,
                spot_oracle_basis_pct=basis_pct,
                long_flush_blocked=True,
            )

        return FilterGateResult(
            pair_name=pair,
            passed=True,
            tier=tier,
            failed_stage=None,
            fail_reason=None,
            day_ntl_vlm_usdc=vlm,
            mark_mid_divergence_pct=mark_mid_div_pct,
            bbo_spread_pct=spread_pct,
            bbo_spread_bps=spread_bps,
            best_bid=best_bid,
            best_ask=best_ask,
            mid_px=book_mid,
            bid_depth_030pct_usdc=bid_depth_usdc,
            ask_depth_030pct_usdc=ask_depth_usdc,
            hip2_exposed=False,
            spot_oracle_basis_pct=basis_pct,
            long_flush_blocked=False,
            short_squeeze_boost=bool(perp_signals.get("short_squeeze_boost", False)),
            details=perp_signals,
        )

    # ==========================================================================
    # マルチタイムフレーム (4H / 1H / 15m) デカップリング指標算出 & 無次元5特徴量 (Section 3.2 & Topic 5)
    # ==========================================================================
    @staticmethod
    def compute_kaufman_er(closes: Sequence[float], period: int = 10) -> float:
        """
        Topic 5 (1): Kaufman Efficiency Ratio (ER_N) = |C_t - C_{t-N}| / sum(|C_i - C_{i-1}|) in [0, 1].
        """
        c = [float(x) for x in closes if float(x) > 0]
        if len(c) < 2:
            return 0.5
        n = min(int(period), len(c) - 1)
        if n <= 0:
            return 0.5
        sub = c[-(n + 1):]
        direction = abs(sub[-1] - sub[0])
        volatility = sum(abs(sub[i] - sub[i - 1]) for i in range(1, len(sub)))
        if volatility <= 1e-12:
            return 0.0
        return float(max(0.0, min(1.0, direction / volatility)))

    def compute_dimensionless_5_features(
        self,
        candles_15m: Sequence[Dict[str, Any]],
        candles_1h: Sequence[Dict[str, Any]],
        atr_15m: float = 0.0,
        benchmark_ret_1h_pct: float = 0.0,
        benchmark_ret_4h_pct: float = 0.0,
        funding_zscore: float = 0.0,
        delta_oi_1h_zscore: float = 0.0,
        premium_zscore: float = 0.0,
        obi_3: float = 0.0,
        obi_15: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Topic 5: Flash-Lite 推論用の無次元化5特徴量 (Dimensionless Normalized Features) を算出する:
          1. Kaufman Efficiency Ratio (er_15m, er_1h)
          2. 対 BTC/HYPE ボラティリティ調整済み相対強度 Zスコア (rs_zscore_vs_btc_hype)
          3. Perp レバレッジ過熱指数 LCI = 0.45*z(funding) + 0.35*z(dOI_1h) + 0.20*z(premium)
          4. 板不均衡加速度 delta_obi = OBI_3 - OBI_15
          5. セッション VWAP 乖離の ATR 倍率 dist_from_vwap_atr = (P_mid - VWAP) / ATR_15m
             (dist_from_vwap_atr > +2.5 の場合は vwap_stretch_capped = True で conviction <= 70 に制限)
        """
        c15 = [float(c.get("c", c.get("close", 0.0))) for c in candles_15m]
        v15 = [float(c.get("v", c.get("volume", 1.0)) or 1.0) for c in candles_15m]
        c1 = [float(c.get("c", c.get("close", 0.0))) for c in candles_1h]

        er_15m = self.compute_kaufman_er(c15, period=10)
        er_1h = self.compute_kaufman_er(c1, period=10)

        # RS Z-score vs BTC/HYPE
        ret_1h = ((c1[-1] - c1[-2]) / c1[-2] * 100.0) if len(c1) >= 2 and c1[-2] > 0 else 0.0
        ret_4h = ((c1[-1] - c1[-5]) / c1[-5] * 100.0) if len(c1) >= 5 and c1[-5] > 0 else ret_1h
        rets_1h = [
            (c1[i] - c1[i - 1]) / c1[i - 1] * 100.0
            for i in range(1, len(c1))
            if c1[i - 1] > 0
        ]
        vol_1h = float(np.std(rets_1h)) if len(rets_1h) >= 2 else 1.0
        vol_1h = max(0.25, vol_1h)
        excess_1h = ret_1h - float(benchmark_ret_1h_pct)
        excess_4h = ret_4h - float(benchmark_ret_4h_pct)
        rs_zscore = (0.60 * excess_1h + 0.40 * excess_4h) / vol_1h

        # Leverage Crowding Index (LCI)
        lci = 0.45 * float(funding_zscore) + 0.35 * float(delta_oi_1h_zscore) + 0.20 * float(premium_zscore)

        # OBI acceleration
        delta_obi = float(obi_3) - float(obi_15)

        # Session VWAP distance in ATR_15m units (8-bar = 2h intraday rolling VWAP)
        cur_px = c15[-1] if c15 else (c1[-1] if c1 else 0.0)
        lookback = min(len(c15), 8)
        if lookback > 0:
            sub_c = c15[-lookback:]
            sub_v = [max(1e-9, v) for v in v15[-lookback:]]
            vwap_session = sum(p * v for p, v in zip(sub_c, sub_v)) / sum(sub_v)
        else:
            vwap_session = cur_px
        eff_atr_15m = float(atr_15m) if float(atr_15m) > 0 else max(cur_px * 0.005, 1e-9)
        dist_from_vwap_atr = (cur_px - vwap_session) / max(eff_atr_15m, 1e-9) if cur_px > 0 else 0.0
        vwap_stretch_capped = bool(dist_from_vwap_atr > 2.5)

        return {
            "er_15m": round(float(er_15m), 4),
            "er_1h": round(float(er_1h), 4),
            "rs_zscore_vs_btc_hype": round(float(rs_zscore), 4),
            "lci": round(float(lci), 4),
            "delta_obi": round(float(delta_obi), 4),
            "vwap_session": round(float(vwap_session), 6),
            "dist_from_vwap_atr": round(float(dist_from_vwap_atr), 4),
            "vwap_stretch_capped": vwap_stretch_capped,
        }

    def compute_mtf_indicators(
        self,
        pair_name: str,
        candles_4h: Sequence[Dict[str, Any]],
        candles_1h: Sequence[Dict[str, Any]],
        candles_15m: Sequence[Dict[str, Any]],
        benchmark_ret_1h_pct: float = 0.0,
        benchmark_ret_4h_pct: float = 0.0,
        funding_zscore: float = 0.0,
        delta_oi_1h_zscore: float = 0.0,
        premium_zscore: float = 0.0,
        obi_3: float = 0.0,
        obi_15: float = 0.0,
    ) -> Dict[str, Any]:
        """
        4H足（環境認識）・1H足（主軸トレンド＆TP/SL設計）・15m足（執行レーダー）の
        デカップリング指標とATR閾値・推奨SL/TP距離・無次元5特徴量を算出する。
        各ローソク足要素は `{"o": ..., "h": ..., "l": ..., "c": ..., "v": ...}` 形式。
        """
        pair = str(pair_name).strip().upper()
        is_large = self.is_large_cap(pair)

        def _extract_hlc(candles: Sequence[Dict[str, Any]]) -> Tuple[List[float], List[float], List[float]]:
            h_list = [float(c.get("h", c.get("high", 0.0))) for c in candles]
            l_list = [float(c.get("l", c.get("low", 0.0))) for c in candles]
            c_list = [float(c.get("c", c.get("close", 0.0))) for c in candles]
            return h_list, l_list, c_list

        h4, l4, c4 = _extract_hlc(candles_4h)
        h1, l1, c1 = _extract_hlc(candles_1h)
        h15, l15, c15 = _extract_hlc(candles_15m)

        # 1. 4H 環境認識: EMA20 > EMA50 または (Close > EMA50 かつ 高値・安値切り上げ)
        ema20_4h = _compute_ema_series(c4, 20)[-1] if c4 else 0.0
        ema50_4h = _compute_ema_series(c4, 50)[-1] if c4 else 0.0
        close_4h = c4[-1] if c4 else 0.0
        hh_hl_4h = bool(
            len(h4) >= 2 and len(l4) >= 2 and h4[-1] >= h4[-2] and l4[-1] >= l4[-2]
        )
        regime_4h_ok = bool(
            (ema20_4h > ema50_4h and close_4h > 0)
            or (close_4h > ema50_4h and hh_hl_4h and ema50_4h > 0)
        )
        if ema20_4h > ema50_4h and close_4h >= ema20_4h:
            market_regime_4h = "BULL_EXPANSION"
        elif regime_4h_ok:
            market_regime_4h = "BULL_PULLBACK"
        elif close_4h < ema50_4h and ema20_4h < ema50_4h:
            market_regime_4h = "BEAR_CASCADE_RISK"
        else:
            market_regime_4h = "NEUTRAL_RANGE"

        # 2. 1H 主軸トレンド & ATR14%
        ema20_1h = _compute_ema_series(c1, 20)[-1] if c1 else 0.0
        ema50_1h = _compute_ema_series(c1, 50)[-1] if c1 else 0.0
        close_1h = c1[-1] if c1 else (close_4h or 1.0)
        atr_1h = _compute_atr_series(h1, l1, c1, period=14)
        atr_1h_pct = (atr_1h / close_1h) * 100.0 if close_1h > 0 else 0.0
        trend_alignment_1h = "BULLISH" if ema20_1h >= ema50_1h else "PULLBACK"

        # 3. 15m 執行レーダー & ATR14%
        close_15m = c15[-1] if c15 else close_1h
        atr_15m = _compute_atr_series(h15, l15, c15, period=14)
        atr_15m_pct = (atr_15m / close_15m) * 100.0 if close_15m > 0 else 0.0
        rsi_15m = _compute_rsi(c15, period=14)

        # 4. 大型銘柄 vs 主力高ボラ銘柄の ATR% 閾値・SL/TPパラメータ (ARCHITECTURE.md Section 3.2 表)
        if is_large:
            min_1h_atr_pct = 0.85
            min_15m_atr_pct = 0.45
            raw_sl_pct = 1.8 * atr_1h_pct
            sl_init_pct = min(max(raw_sl_pct, 1.40), 3.30)
            tp_target_pct = max(2.20, 2.8 * atr_1h_pct, 1.85 * sl_init_pct)
            freeroll_trigger_gain_pct = 1.20
        else:
            min_1h_atr_pct = 1.35
            min_15m_atr_pct = 0.70
            raw_sl_pct = 1.6 * atr_1h_pct
            sl_init_pct = min(max(raw_sl_pct, 2.00), 5.00)
            tp_target_pct = max(3.20, 2.6 * atr_1h_pct, 1.85 * sl_init_pct)
            freeroll_trigger_gain_pct = 1.80

        atr_gate_passed = bool(
            atr_1h_pct >= min_1h_atr_pct and atr_15m_pct >= min_15m_atr_pct
        )
        recommended_sl_px = close_15m * (1.0 - sl_init_pct / 100.0)
        recommended_tp_px = close_15m * (1.0 + tp_target_pct / 100.0)
        expected_rr = tp_target_pct / sl_init_pct if sl_init_pct > 0 else 0.0

        dim5 = self.compute_dimensionless_5_features(
            candles_15m=candles_15m,
            candles_1h=candles_1h,
            atr_15m=atr_15m,
            benchmark_ret_1h_pct=benchmark_ret_1h_pct,
            benchmark_ret_4h_pct=benchmark_ret_4h_pct,
            funding_zscore=funding_zscore,
            delta_oi_1h_zscore=delta_oi_1h_zscore,
            premium_zscore=premium_zscore,
            obi_3=obi_3,
            obi_15=obi_15,
        )

        res = {
            "pair_name": pair,
            "is_large_cap": is_large,
            "market_regime_4h": market_regime_4h,
            "regime_4h_ok": regime_4h_ok,
            "trend_alignment_1h": trend_alignment_1h,
            "ema20_4h": round(ema20_4h, 6),
            "ema50_4h": round(ema50_4h, 6),
            "ema20_1h": round(ema20_1h, 6),
            "ema50_1h": round(ema50_1h, 6),
            "atr_1h": atr_1h,
            "atr_1h_pct": round(atr_1h_pct, 4),
            "atr_15m": atr_15m,
            "atr_15m_pct": round(atr_15m_pct, 4),
            "min_1h_atr_pct": min_1h_atr_pct,
            "min_15m_atr_pct": min_15m_atr_pct,
            "atr_gate_passed": atr_gate_passed,
            "rsi_15m": round(rsi_15m, 2),
            "sl_init_pct": round(sl_init_pct, 4),
            "tp_target_pct": round(tp_target_pct, 4),
            "freeroll_trigger_gain_pct": freeroll_trigger_gain_pct,
            "recommended_entry_px": close_15m,
            "recommended_sl_px": recommended_sl_px,
            "recommended_tp_px": recommended_tp_px,
            "expected_rr_ratio": round(expected_rr, 3),
            "entry_eligible": bool(regime_4h_ok and atr_gate_passed),
        }
        res.update(dim5)
        return res

    # ==========================================================================
    # v1.2 Alpha-Max 拡張メソッド群 (論点1, 論点3, 論点4)
    # ==========================================================================
    def compute_short_squeeze_ignition_index(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return compute_short_squeeze_ignition_index(*args, **kwargs)

    def compute_spot_absorption_index(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return compute_spot_absorption_index(*args, **kwargs)

    def classify_asset_cluster(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return classify_asset_cluster(*args, **kwargs)

    def evaluate_time_of_day_regime(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return evaluate_time_of_day_regime(*args, **kwargs)


# ==============================================================================
# v1.2 Alpha-Max 論点1: Spot-Perp クロス需給アルファ (SSII_t & SAI_t)
# ==============================================================================
def _sigmoid(x: float) -> float:
    clamped = max(-60.0, min(60.0, float(x)))
    return float(1.0 / (1.0 + math.exp(-clamped)))


def _normalize_funding_to_pct(val: float) -> float:
    """
    Funding Rate を `%` 単位（例: 0.0005% -> 0.0005, -0.0035% -> -0.0035）へ正規化する。
    比率表現（例: 5e-6 = 0.0005%, -3.5e-5 = -0.0035%）が渡された場合は * 100.0 で変換する。
    """
    v = float(val or 0.0)
    if 0.0 < abs(v) <= 0.00025:
        return v * 100.0
    return v


def compute_short_squeeze_ignition_index(
    funding_t: float = 0.0,
    funding_4h_mean: Optional[float] = None,
    z_oi_4h_t: float = 0.0,
    z_oi_4h_prev15m: Optional[float] = None,
    spot_px: float = 100.0,
    high_20_15m: float = 100.0,
    atr_15m: float = 1.0,
    cvd_perp_5m: float = 0.0,
    delta_oi_15m: float = 0.0,
    delta_basis_15m: float = 0.0,
) -> Dict[str, Any]:
    """
    v1.2 論点1: Perpショートスクイーズ初動指数 SSII_t in [0, 1]
      Phi_fuel(t) = min(1.0, S_fund(t) * S_oi_coil(t))
        S_fund(t) = clip((0.0005% - min(F_t, F_bar_4h(t))) / 0.0040%, 0, 1.5)
        S_oi_coil(t) = sigma(1.25 * (max(Z_OI_4h(t), Z_OI_4h(t-15m)) - 0.80))
      Psi_ignite(t) = I(P_spot >= H_20^(15m) - 0.10 * ATR_15m)
                      * clip((CVD_perp_5m - 0.15) / 0.35, 0, 1)
                      * max(sigma(-300 * dOI_15m), sigma(1500 * dBasis_15m))
      SSII_t = Phi_fuel(t) * Psi_ignite(t)
    """
    f_now = _normalize_funding_to_pct(funding_t)
    f_4h = _normalize_funding_to_pct(funding_4h_mean if funding_4h_mean is not None else funding_t)
    f_min = min(f_now, f_4h)

    s_fund = max(0.0, min(1.5, (0.0005 - f_min) / 0.0040))
    z_prev = float(z_oi_4h_prev15m) if z_oi_4h_prev15m is not None else float(z_oi_4h_t)
    z_max = max(float(z_oi_4h_t), z_prev)
    s_oi_coil = _sigmoid(1.25 * (z_max - 0.80))
    phi_fuel = min(1.0, s_fund * s_oi_coil)

    # 構造突破・点火項 Psi_ignite(t)
    breakout_thresh = float(high_20_15m) - 0.10 * float(atr_15m)
    is_breakout = 1.0 if float(spot_px) >= breakout_thresh - 1e-9 else 0.0
    cvd_term = max(0.0, min(1.0, (float(cvd_perp_5m) - 0.15) / 0.35))

    # dOI_15m と dBasis_15m の比率正規化 (%表記が渡された場合は / 100.0)
    doi_ratio = float(delta_oi_15m) / 100.0 if abs(float(delta_oi_15m)) > 0.15 else float(delta_oi_15m)
    dbasis_ratio = float(delta_basis_15m) / 100.0 if abs(float(delta_basis_15m)) > 0.02 else float(delta_basis_15m)
    short_cover_or_basis_term = max(_sigmoid(-300.0 * doi_ratio), _sigmoid(1500.0 * dbasis_ratio))

    psi_ignite = is_breakout * cvd_term * short_cover_or_basis_term
    ssii = max(0.0, min(1.0, phi_fuel * psi_ignite))

    return {
        "ssii": round(float(ssii), 6),
        "phi_fuel": round(float(phi_fuel), 6),
        "psi_ignite": round(float(psi_ignite), 6),
        "s_fund": round(float(s_fund), 6),
        "s_oi_coil": round(float(s_oi_coil), 6),
        "is_squeeze_ignition": bool(ssii >= 0.65),
        "is_super_squeeze": bool(ssii >= 0.80),
        "promote_to_regime_a": bool(ssii >= 0.70),
        "recommended_alo_regime": "REGIME_A_STEP_AHEAD" if ssii >= 0.70 else "STANDARD",
        "recommended_ttl_sec": 900 if ssii >= 0.70 else 1800,
    }


def compute_spot_absorption_index(
    cvd_spot_15m: float = 0.0,
    cvd_perp_15m: float = 0.0,
    whale_1h: float = 0.0,
    funding_t: float = 0.0,
    ssii: float = 0.0,
) -> Dict[str, Any]:
    """
    v1.2 論点1: Spot実需買い集め指数 SAI_t in [0, 1] と要求確信度補正 Delta_Theta_flow
      D_lead_15m(t) = CVD_spot_15m(t) - 0.7 * CVD_perp_15m(t)
      SAI_t = clip(0.45 * (CVD_spot_15m - 0.10)/0.35 + 0.30 * (D_lead_15m / 0.25) + 0.25 * (W_whale_1h - 0.15)/0.40, 0, 1)
      ブルトラップ検知: D_lead_15m < -0.25 かつ F_t > +0.003%/h かつ CVD_spot_15m <= 0 -> +8.0pt (+0.08) ペナルティ
      強気需給時: 最大 -5.0pt (-0.05) 緩和
    """
    c_spot = float(cvd_spot_15m)
    c_perp = float(cvd_perp_15m)
    w_1h = float(whale_1h)
    f_pct = _normalize_funding_to_pct(funding_t)
    ssii_v = float(ssii)

    d_lead_15m = c_spot - 0.70 * c_perp
    raw_sai = (
        0.45 * ((c_spot - 0.10) / 0.35)
        + 0.30 * (d_lead_15m / 0.25)
        + 0.25 * ((w_1h - 0.15) / 0.40)
    )
    sai = max(0.0, min(1.0, raw_sai))

    bull_trap = bool(d_lead_15m < -0.25 and f_pct > 0.003 and c_spot <= 0.0)
    if bull_trap:
        delta_theta_pts = 8.0
    elif ssii_v >= 0.80 or (ssii_v >= 0.65 and sai >= 0.65) or sai >= 0.85:
        delta_theta_pts = -5.0
    elif max(ssii_v, sai) >= 0.65:
        delta_theta_pts = -round(5.0 * max(ssii_v, sai), 2)
    else:
        delta_theta_pts = 0.0

    return {
        "sai": round(float(sai), 6),
        "d_lead_15m": round(float(d_lead_15m), 6),
        "bull_trap_detected": bull_trap,
        "delta_theta_flow": round(float(delta_theta_pts), 4),
        "delta_theta_flow_norm": round(float(delta_theta_pts) / 100.0, 6),
        "promote_to_regime_a": bool(ssii_v >= 0.70),
    }


# ==============================================================================
# v1.2 Alpha-Max 論点3: オンチェーン4指標による動的銘柄クラスタ分類 (B_i) & Stage 3/4 逆転 lambda_mfe
# ==============================================================================
STABLECOIN_BASES_EXCLUDED = frozenset(
    {"USDC", "USDT", "USDT0", "USDE", "USDH", "FEUSD", "DAI", "FDUSD"}
)


def classify_asset_cluster(
    pair_or_coin: str = "HYPE/USDC",
    atr_1h_pct: float = 0.015,
    spread_bps: float = 5.0,
    depth_minus_50bps_usdc: float = 25_000.0,
    depth_plus_50bps_usdc: float = 25_000.0,
    perp_volume_24h_usdc: float = 50_000_000.0,
    spot_volume_24h_usdc: float = 10_000_000.0,
    psr_override: Optional[float] = None,
    lfi_override: Optional[float] = None,
) -> Dict[str, Any]:
    """
    v1.2 論点3: 複合ベータ・非流動性スコア B_i in [0, 1] と3クラスタ連続適応パラメータ算出:
      LFI_i = Spread_bps / 10 + 50,000 / (min(D_-50bps, D_+50bps) + 1,000)
      PSR_i = V_perp_24h / (V_perp_24h + V_spot_24h)
      B_i = clip(0.45 * (ATR%_1h - 0.008)/0.032 + 0.30 * (LFI_i - 1.0)/5.0 + 0.25 * (1.0 - PSR_i), 0, 1)
    """
    sym = str(pair_or_coin or "").strip().upper()
    base = sym.split("/")[0].strip()
    if base in STABLECOIN_BASES_EXCLUDED or sym in STABLECOIN_BASES_EXCLUDED:
        return {
            "pair_name": sym,
            "base_asset": base,
            "is_stablecoin": True,
            "swing_eligible": False,
            "cluster": "EXCLUDED_STABLE",
            "cluster_label": "EXCLUDED_STABLE",
            "beta_score": 0.0,
            "lfi": 0.0,
            "psr": 0.0,
            "k_sl": 0.0,
            "r_tp": 0.0,
            "lambda_mfe_3": 0.40,
            "lambda_mfe_4": 0.48,
            "tau_grace_min": 60,
            "tau_stagnant_min": 180,
            "tau_max_min": 360,
        }

    # ATR%_1h: %表記 (例: 1.5 -> 0.015) と比率表記 (0.015) の両対応
    atr_ratio = float(atr_1h_pct) / 100.0 if float(atr_1h_pct) > 0.15 else float(atr_1h_pct)

    if lfi_override is not None:
        lfi = float(lfi_override)
    else:
        d_min = max(0.0, min(float(depth_minus_50bps_usdc), float(depth_plus_50bps_usdc)))
        lfi = (float(spread_bps) / 10.0) + (50_000.0 / (d_min + 1_000.0))

    if psr_override is not None:
        psr = max(0.0, min(1.0, float(psr_override)))
    else:
        v_tot = max(0.0, float(perp_volume_24h_usdc)) + max(0.0, float(spot_volume_24h_usdc))
        psr = (float(perp_volume_24h_usdc) / v_tot) if v_tot > 0 else 0.50

    raw_b = (
        0.45 * ((atr_ratio - 0.008) / 0.032)
        + 0.30 * ((lfi - 1.0) / 5.0)
        + 0.25 * (1.0 - psr)
    )
    b_i = max(0.0, min(1.0, raw_b))

    if b_i < 0.35:
        cluster = "A"
        cluster_label = "CLUSTER_A"
    elif b_i < 0.65:
        cluster = "B"
        cluster_label = "CLUSTER_B"
    else:
        cluster = "C"
        cluster_label = "CLUSTER_C"

    k_sl = 1.55 + 1.05 * b_i
    r_tp = 2.00 + 2.60 * b_i
    lambda_mfe_3 = 0.40 - 0.28 * b_i
    lambda_mfe_4 = 0.48 + 0.22 * b_i
    tau_grace = int(round(60.0 - 25.0 * b_i))
    tau_stagnant = int(round(180.0 - 90.0 * b_i))
    tau_max = int(round(360.0 - 210.0 * b_i))

    return {
        "pair_name": sym,
        "base_asset": base,
        "is_stablecoin": False,
        "swing_eligible": True,
        "cluster": cluster,
        "cluster_label": cluster_label,
        "beta_score": round(float(b_i), 6),
        "lfi": round(float(lfi), 4),
        "psr": round(float(psr), 4),
        "k_sl": round(float(k_sl), 4),
        "r_tp": round(float(r_tp), 4),
        "lambda_mfe_3": round(float(lambda_mfe_3), 4),
        "lambda_mfe_4": round(float(lambda_mfe_4), 4),
        "tau_grace_min": tau_grace,
        "tau_stagnant_min": tau_stagnant,
        "tau_max_min": tau_max,
    }


# ==============================================================================
# v1.2 Alpha-Max 論点4: UTC時間帯・曜日（週末薄商い WEEKEND_THIN）の動的マイクロストラクチャ適応
# ==============================================================================
def compute_upper_wick_ratio(
    open_px: float,
    high_px: float,
    low_px: float,
    close_px: float,
    eps: float = 1e-9,
) -> float:
    """
    15分足の上ヒゲ比 (P_high - max(P_open, P_close)) / (P_high - P_low + eps) を算出する。
    """
    h = float(high_px)
    l = float(low_px)
    o = float(open_px)
    c = float(close_px)
    if h <= l:
        return 0.0
    upper_wick = max(0.0, h - max(o, c))
    return float(max(0.0, min(1.0, upper_wick / (h - l + float(eps)))))


def evaluate_time_of_day_regime(
    utc_dt: Optional[Union[datetime, int, float]] = None,
    ssii: float = 0.0,
    sai: float = 0.0,
    candle_15m: Optional[Dict[str, Any]] = None,
    base_1r_pct: float = 0.0125,
) -> Dict[str, Any]:
    """
    v1.2 論点4: UTC時刻と曜日 (weekday(): 月=0〜日=6) から6つの時間レジーム s を判定し、
    要求板厚倍率 mu_depth(s)、許容スプレッド倍率 mu_spread(s)、15分足最大上ヒゲ比 W_max(s)、
    要求確信度補正 Delta_Theta_time(s)、ポジションリスク倍率 kappa_risk(s) を返す。
    """
    if utc_dt is None:
        dt = datetime.now(timezone.utc)
    elif isinstance(utc_dt, (int, float)):
        ts_sec = float(utc_dt) / 1000.0 if float(utc_dt) > 1e11 else float(utc_dt)
        dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
    else:
        dt = utc_dt.astimezone(timezone.utc) if utc_dt.tzinfo is not None else utc_dt.replace(tzinfo=timezone.utc)

    wd = dt.weekday()  # 0=Mon .. 5=Sat, 6=Sun
    hr = dt.hour + (dt.minute / 60.0) + (dt.second / 3600.0)
    ssii_v = float(ssii)
    sai_v = float(sai)

    # 1. WEEKEND_THIN (土曜 00:00 UTC 〜 日曜 18:00 UTC)
    if wd == 5 or (wd == 6 and hr < 18.0):
        regime = "WEEKEND_THIN"
        mu_depth = 1.35
        mu_spread = 0.90
        w_max = 0.30
        delta_theta = 6.0
        kappa_risk = 0.60
        pure_breakout_allowed = bool(ssii_v >= 0.70 or sai_v >= 0.72)
    # 2. SUN_MON_ACCUM (日曜 18:00 UTC 〜 月曜 03:00 UTC)
    elif (wd == 6 and hr >= 18.0) or (wd == 0 and hr < 3.0):
        regime = "SUN_MON_ACCUM"
        mu_depth = 1.10
        mu_spread = 1.00
        w_max = 0.40
        delta_theta = -3.0 if sai_v >= 0.65 else 0.0
        kappa_risk = 0.95
        pure_breakout_allowed = True
    # 3. ASIA_SESSION (平日 00:00〜07:00 UTC および 21:00〜24:00 UTC)
    elif hr < 7.0 or hr >= 21.0:
        regime = "ASIA_SESSION"
        mu_depth = 1.00
        mu_spread = 1.00
        w_max = 0.45
        delta_theta = 1.0
        kappa_risk = 0.85
        pure_breakout_allowed = True
    # 4. EU_OPEN (平日 07:00〜10:00 UTC)
    elif 7.0 <= hr < 10.0:
        regime = "EU_OPEN"
        mu_depth = 1.05
        mu_spread = 1.15
        w_max = 0.40
        delta_theta = 2.0
        kappa_risk = 0.90
        pure_breakout_allowed = True
    # 5. INST_PRE_US (平日 10:00〜13:00 UTC / JST 19:00〜22:00)
    elif 10.0 <= hr < 13.0:
        regime = "INST_PRE_US"
        mu_depth = 1.00
        mu_spread = 1.05
        w_max = 0.45
        delta_theta = -2.0
        kappa_risk = 1.00
        pure_breakout_allowed = True
    # 6. US_PEAK (平日 13:00〜21:00 UTC)
    else:
        regime = "US_PEAK"
        mu_depth = 0.95
        mu_spread = 0.85
        w_max = 0.50
        is_thu_fri = wd in (3, 4)
        delta_theta = 1.0 if is_thu_fri else -2.0
        kappa_risk = 0.90 if is_thu_fri else 1.00
        pure_breakout_allowed = True

    upper_wick_ratio = 0.0
    wick_rejected = False
    if isinstance(candle_15m, dict):
        o_px = float(candle_15m.get("o", candle_15m.get("open", 0.0)))
        h_px = float(candle_15m.get("h", candle_15m.get("high", 0.0)))
        l_px = float(candle_15m.get("l", candle_15m.get("low", 0.0)))
        c_px = float(candle_15m.get("c", candle_15m.get("close", 0.0)))
        upper_wick_ratio = compute_upper_wick_ratio(o_px, h_px, l_px, c_px)
        wick_rejected = bool(upper_wick_ratio > w_max)

    return {
        "regime": regime,
        "weekday": wd,
        "utc_hour": round(hr, 4),
        "mu_depth": round(float(mu_depth), 4),
        "mu_spread": round(float(mu_spread), 4),
        "w_max": round(float(w_max), 4),
        "delta_theta_time": round(float(delta_theta), 4),
        "delta_theta_time_norm": round(float(delta_theta) / 100.0, 6),
        "kappa_risk": round(float(kappa_risk), 4),
        "effective_1r_pct": round(float(base_1r_pct) * float(kappa_risk), 6),
        "pure_breakout_allowed": pure_breakout_allowed,
        "upper_wick_ratio": round(float(upper_wick_ratio), 4),
        "wick_rejected": wick_rejected,
    }
