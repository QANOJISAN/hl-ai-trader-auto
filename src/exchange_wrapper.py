"""
HL AI Trader v1 — Hyperliquid Spot Exchange Wrapper (src/exchange_wrapper.py)

実装機能 (ARCHITECTURE.md Section 1, 3.1, 4, 5 準拠):
1. Agent Wallet 権限分離初期化:
   - `Exchange(wallet=agent_account, base_url=MAINNET_API_URL, account_address=main_address)`
   - Agent Walletは外部出金権限を持たず、残高・注文照会はすべて `main_address` に対して行う
2. `extra_agents` 有効期限チェック (`check_agent_wallet_validity`):
   - `info.extra_agents(main_address)` の `validUntil` を監視し、期限切れ・期限接近を検知
3. Perps ➔ Spot 自動USDC振替 (`auto_transfer_perp_to_spot_usdc`):
   - `exchange.usd_class_transfer(amount, to_perp=False)` によりPerps口座の遊休USDCをSpot口座へ自動振替
4. Spot-Perp シンボル動的マッピング (`refresh_universe_mapping`):
   - `spot_meta_and_asset_ctxs` と `meta_and_asset_ctxs` から毎回動的に `@index` (`@107` 等) ⟷ 人間可読ペア名 (`HYPE/USDC` 等) ⟷ `szDecimals` を再構築
   - Spotベーストークン名から先頭 `U` を除去 (`UBTC`➔`BTC`, `UETH`➔`ETH`, `USOL`➔`SOL`, `UZEC`➔`ZEC`) してPerp銘柄と1対1紐付け
5. Perps発注遮断ガード (`assert_spot_only_coin`):
   - 正規USDC建てSpotペア以外のシンボル（Perp単体名 `BTC`, `HYPE` や `#` 予測市場など）での注文をコードレベルで即座に遮断 (`PerpsOrderForbiddenError`)
   - レート制限5倍ペナルティを受ける `expiresAfter` パラメータは一切使用しない
6. 1ステップ IOC 即時決済 (`execute_atomic_ioc_exit`):
   - 直前の `spot_clearinghouse_state` の `total` 実残高を `floor_size` で切り捨て、`best_bid * 0.985` の `round_price` 指値で1ステップ IOC 売却
7. 10 USDC未満端数の「Top-Up & Dump」自己復旧ルーチン (`recover_dust_top_up_and_dump`):
   - `DUST_RECOVERY_IN_PROGRESS` (静止期間 5000ms) 下で 11.0 USDC 相当を IOC 買い増し ➔ 600ms 待機 ➔ 合算実残高を全量 IOC 一括売却
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from eth_account import Account as EthAccount
    from eth_account.signers.local import LocalAccount
except ImportError:
    EthAccount = None  # type: ignore[assignment]
    LocalAccount = Any  # type: ignore[assignment,misc]


class FallbackLocalAccount:
    """eth_account 未導入環境またはモック検証用の互換 LocalAccount クラス"""

    def __init__(self, private_key_hex: str) -> None:
        norm = private_key_hex.strip()
        if not norm.startswith("0x"):
            norm = "0x" + norm
        raw_hex = norm[2:]
        if len(raw_hex) != 64:
            raise ValueError(f"秘密鍵は32バイト(64桁hex)である必要があります: length={len(raw_hex)}")
        int(raw_hex, 16)  # 16進数妥当性チェック
        self.key = bytes.fromhex(raw_hex)
        digest = hashlib.sha256(self.key).hexdigest()
        self.address = "0x" + digest[:40]

    @classmethod
    def from_key(cls, private_key_hex: str) -> "FallbackLocalAccount":
        return cls(private_key_hex)

from src.coordinator import ConcurrencyStateCoordinator, SlotState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.utils import (
    MonotonicHyperliquidNonceManager,
    PersistentHTTPSession,
    _to_clean_decimal,
    floor_size,
    format_decimal_plain,
    generate_cloid,
    dpapi_decrypt_str,
    get_secret,
    now_ms,
    round_price,
    verify_pinned_hl_action_destination,
)

try:
    from hyperliquid.exchange import Exchange as HLSDKExchange
    from hyperliquid.info import Info as HLSDKInfo
    from hyperliquid.utils import constants as hl_constants
    from hyperliquid.utils.types import Cloid as HLSDKCloid

    MAINNET_API_URL = getattr(hl_constants, "MAINNET_API_URL", "https://api.hyperliquid.xyz")
except ImportError:
    HLSDKExchange = None  # type: ignore[assignment]
    HLSDKInfo = None  # type: ignore[assignment]
    HLSDKCloid = None  # type: ignore[assignment]
    MAINNET_API_URL = "https://api.hyperliquid.xyz"

logger = logging.getLogger(__name__)


class FallbackCloid:
    """hyperliquid-python-sdk の Cloid 互換ラッパー"""

    def __init__(self, raw_cloid: str) -> None:
        norm = str(raw_cloid).strip().lower()
        if not norm.startswith("0x") or len(norm) != 34:
            raise ValueError(f"cloid は '0x' + 32桁hex である必要があります: {raw_cloid}")
        self.raw_cloid = norm

    @classmethod
    def from_str(cls, cloid_hex: str) -> Any:
        if HLSDKCloid is not None:
            return HLSDKCloid.from_str(cloid_hex)
        return cls(cloid_hex)

    def to_raw(self) -> str:
        return self.raw_cloid

    def __str__(self) -> str:
        return self.raw_cloid

    def __eq__(self, other: Any) -> bool:
        return str(self).lower() == str(other).lower()


def make_cloid(cloid_hex: str) -> Any:
    """SDK の `Cloid.from_str(cloid_hex)` オブジェクトを生成する"""
    return FallbackCloid.from_str(cloid_hex)


class PerpsOrderForbiddenError(PermissionError):
    """Spot専用システムにおいてPerps銘柄や非正規ペアへの発注が試行された際に送出される致命的ガード例外"""


class AgentWalletExpiredError(PermissionError):
    """Agent Walletが未登録または有効期限切れの場合に送出される例外"""


class OrderValidationError(ValueError):
    """最小発注額フロア (16.0 USDC) 未満や最大SL幅 (8.0%) 超過などの発注前検証エラー"""


@dataclass
class SpotUniverseEntry:
    """Spotペアと対応Perpコンテキストの動的マッピング情報"""

    pair_name: str               # 人間可読ペア名 (例: "HYPE/USDC", "UBTC/USDC", "PURR/USDC")
    api_coin_name: str           # SDK発注用コイン名 (例: "@107", "@142", "PURR/USDC")
    base_asset: str              # Spotベーストークン名 (例: "HYPE", "UBTC", "PURR")
    quote_asset: str             # クオートトークン名 ("USDC")
    base_token_idx: int          # spotMeta.tokens 内のベーストークンindex
    quote_token_idx: int         # spotMeta.tokens 内のクオートトークンindex (0)
    universe_idx: int            # spotMeta.universe 内のindex
    spot_asset_id: int           # 10000 + universe_idx
    sz_decimals: int             # ベーストークンの数量小数桁数
    wei_decimals: int            # ベーストークンのwei小数桁数
    is_canonical: bool           # 正規トークンフラグ
    perp_coin: Optional[str]     # 1対1対応するPerp銘柄名 (例: "BTC", "ETH", "SOL", "HYPE")
    spot_mid_px: float = 0.0
    spot_mark_px: float = 0.0
    spot_day_ntl_vlm: float = 0.0
    perp_mark_px: float = 0.0
    perp_oracle_px: float = 0.0
    perp_mid_px: float = 0.0
    perp_funding_1h: float = 0.0
    perp_open_interest: float = 0.0
    perp_premium: float = 0.0
    perp_day_ntl_vlm: float = 0.0
    raw_spot_ctx: Dict[str, Any] = field(default_factory=dict)
    raw_perp_ctx: Dict[str, Any] = field(default_factory=dict)


def map_spot_base_to_perp_symbol(base_asset: str, available_perp_coins: set[str]) -> Optional[str]:
    """
    Spotのベーストークン名から先頭の `U` を除去（`UBTC`➔`BTC`, `UETH`➔`ETH`, `USOL`➔`SOL`, `UZEC`➔`ZEC`）
    またはそのままの名前（`HYPE`➔`HYPE`, `PURR`➔`PURR`）でPerp銘柄と1対1で紐付ける。
    """
    b = str(base_asset).strip().upper()
    if not b:
        return None
    # 1. 先頭 'U' 除去後の名前がPerpユニバースに存在する場合 (UBTC->BTC, UETH->ETH, USOL->SOL 等)
    if b.startswith("U") and len(b) >= 4:
        stripped = b[1:]
        if stripped in available_perp_coins:
            return stripped
    # 2. そのままの名前がPerpユニバースに存在する場合 (HYPE, PURR 等)
    if b in available_perp_coins:
        return b
    # 3. 末尾 '1' 除去後の名前がPerpユニバースに存在する場合 (XMR1->XMR 等)
    if b.endswith("1") and len(b) >= 4:
        stripped_num = b[:-1]
        if stripped_num in available_perp_coins:
            return stripped_num
    return None


def compute_tick_size(px: Union[float, int, str, Decimal], sz_decimals: int) -> Decimal:
    """
    Hyperliquid Spot の価格規則（有効数字最大5桁 かつ 小数点以下最大 `8 - szDecimals` 桁）に準拠した
    対象価格水準での最小1ティック幅 `Delta p_tick` を `Decimal` で返す。
    """
    d = _to_clean_decimal(px)
    if d <= 0:
        return Decimal("0.0001")
    max_dec = max(0, 8 - int(sz_decimals))
    mag = d.adjusted()
    target_exp = max(mag - 4, -max_dec)
    return Decimal(f"1e{target_exp}")


def compute_optimal_buy_alo_price(
    best_bid: Union[float, str, Decimal],
    best_ask: Union[float, str, Decimal],
    sz_decimals: int,
    conviction_score: int = 80,
    obi_5: float = 0.0,
    b_lead: float = 0.0,
    atr_15m: float = 0.0,
    bids_levels: Optional[List[Dict[str, Any]]] = None,
    ssii: float = 0.0,
) -> Dict[str, Any]:
    """
    L2板不均衡 (`OBI_5`)・Perp先行シグナル (`B_lead`)・ショートスクイーズ指数 (`SSII_t`) に基づく
    3レジーム `Alo` 指値価格最適化エンジン (v1.1 Topic 2 & v1.2 論点1):
      - Regime A (`SSII_t >= 0.70` または `conviction >= 85` & `OBI_5 >= +0.20` & `B_lead >= +0.03% (0.0003)`):
        スプレッドが2ティック以上あれば `min(ask_1 - 1 tick, bid_1 + 1 tick)` の1ティック踏み込み、1ティックなら `bid_1` (TTL 15分 = 900秒)
      - Regime C (逆行オーダーフロー・押し目待ち: `OBI_5 < -0.15` または `-0.0012 < B_lead <= -0.0003`):
        `bid_1 - max(2 * tick, 0.20 * ATR_15m)` のディープ指値
      - Regime B (標準確信度 `75..84`):
        上位5ティック内の最大流動性クラスター `k* = argmax(p_k * v_k)` の1ティック前 `min(bid_1, p_{k*} + 1 tick)`
    常に Post-Only (`Alo`) が拒否されないよう `ask_1 - 1 tick` 以下にクランプし、`round_price` で丸めた文字列を返す。
    """
    bid_dec = _to_clean_decimal(best_bid)
    ask_dec = _to_clean_decimal(best_ask) if _to_clean_decimal(best_ask) > 0 else bid_dec
    tick = compute_tick_size(bid_dec, sz_decimals)
    score = int(conviction_score)
    obi = float(obi_5)
    blead = float(b_lead)
    ssii_v = float(ssii)
    atr_dec = _to_clean_decimal(max(0.0, float(atr_15m)))

    max_post_only_px = (ask_dec - tick) if ask_dec > bid_dec else bid_dec

    if ssii_v >= 0.70 or (score >= 85 and obi >= 0.20 and blead >= 0.0003):
        regime = "REGIME_A_STEP_AHEAD"
        if (ask_dec - bid_dec) >= (Decimal("2") * tick):
            cand_px = min(ask_dec - tick, bid_dec + tick)
        else:
            cand_px = bid_dec
    elif obi < -0.15 or (-0.0012 < blead <= -0.0003):
        regime = "REGIME_C_DEEP_PULLBACK"
        pullback_offset = max(Decimal("2") * tick, Decimal("0.20") * atr_dec)
        cand_px = max(tick, bid_dec - pullback_offset)
    else:
        regime = "REGIME_B_CLUSTER_FRONT"
        cluster_px = bid_dec
        if bids_levels and len(bids_levels) >= 1:
            top5 = bids_levels[:5]
            best_notional = Decimal("-1")
            for lv in top5:
                try:
                    lp = _to_clean_decimal(lv.get("px", 0))
                    ls = _to_clean_decimal(lv.get("sz", 0))
                    ntl = lp * ls
                    if lp > 0 and ntl > best_notional:
                        best_notional = ntl
                        cluster_px = lp
                except Exception:
                    continue
            cand_px = min(bid_dec, cluster_px + tick)
        else:
            cand_px = bid_dec

    clamped_px = min(cand_px, max_post_only_px)
    px_str = round_price(clamped_px, sz_decimals)
    return {
        "regime": regime,
        "px_str": px_str,
        "limit_px": float(px_str),
        "tick_size": float(tick),
        "best_bid": float(bid_dec),
        "best_ask": float(ask_dec),
        "obi_5": obi,
        "b_lead": blead,
        "ssii": ssii_v,
        "recommended_ttl_sec": 900 if regime == "REGIME_A_STEP_AHEAD" else 1800,
    }


class DepthAwareIocPlanner:
    """
    20レベルL2板スイープ計算に基づく「Depth-Aware IOC 決済プランナー」＆端数生成ゼロ保証エンジン (v1.1 Topic 3):
      1. 発注前 `< 10.0 USDC` 端数判定:
         `Q_sell * best_bid < 10.0` の場合、取引所で拒絶される無駄な注文を出さず即座に `QUARANTINE_DUST_ONLY` を返す。
      2. L2板20レベル・スイープ計算 (`P_clear`, `P_vwap`) と端数残留 (`0 < N_rem < 11.2 USDC`) 回避:
         標準1.50%カラー (`best_bid * 0.985`) での約定後残余評価額 `N_rem` が `< 11.2 USDC` の端数になる場合、
         許容カラーを `+0.50%`（合計最大 2.00%）まで拡張して `min(P_limit, P_clear * 0.9990)` で1回で100%スイープする。
      3. 瞬間的板スカスカ (`Transient Book Gap`) 検知:
         非緊急時に `(best_bid - P_clear) / best_bid > 1.20%` かつ Perp乖離 `> -0.30%` の場合は一時的板薄を検知する。
    """

    MIN_EXCHANGE_NOTIONAL_USDC = 10.0
    SAFE_RESIDUAL_NOTIONAL_USDC = 11.2
    POST_EXIT_DUST_THRESHOLD_USDC = 10.5
    BASE_SLIPPAGE_COLLAR = 0.015       # 1.50%
    DUST_AVOIDANCE_EXTRA_COLLAR = 0.005  # +0.50% (最大2.00%)
    TRANSIENT_GAP_SLIPPAGE_PCT = 0.012  # 1.20%

    def plan_exit(
        self,
        actual_balance_total: Union[float, str, Decimal],
        sz_decimals: int,
        best_bid: Union[float, str, Decimal],
        l2_bids: Optional[List[Dict[str, Any]]] = None,
        perp_mid_px: float = 0.0,
        spot_mid_px: float = 0.0,
        is_emergency: bool = True,
    ) -> Dict[str, Any]:
        q_sell_str = floor_size(actual_balance_total, sz_decimals)
        q_sell_dec = _to_clean_decimal(q_sell_str)
        q_sell = float(q_sell_dec)
        bid_dec = _to_clean_decimal(best_bid)
        bid_f = float(bid_dec)
        est_notional = q_sell * bid_f

        if q_sell <= 0.0 or bid_f <= 0.0 or est_notional < self.MIN_EXCHANGE_NOTIONAL_USDC:
            return {
                "action": "QUARANTINE_DUST_ONLY",
                "should_place_order": False,
                "q_sell": q_sell,
                "q_sell_str": q_sell_str,
                "est_notional_usdc": round(est_notional, 4),
                "min_sell_px_str": "0",
                "p_clear": 0.0,
                "p_vwap": 0.0,
                "n_rem_usdc": round(est_notional, 4),
                "collar_widened_for_dust_avoidance": False,
                "transient_gap_detected": False,
                "reason": "BELOW_10_USDC_MIN_NOTIONAL",
            }

        std_collar_px = bid_f * (1.0 - self.BASE_SLIPPAGE_COLLAR)
        max_collar_px = bid_f * (1.0 - (self.BASE_SLIPPAGE_COLLAR + self.DUST_AVOIDANCE_EXTRA_COLLAR))
        limit_px_raw = std_collar_px
        p_clear = bid_f
        p_vwap = bid_f
        n_rem_usdc = 0.0
        collar_widened = False
        transient_gap = False

        if l2_bids and len(l2_bids) > 0:
            rem_to_clear = q_sell
            vwap_ntl = 0.0
            vwap_qty = 0.0
            qty_within_std_collar = 0.0
            last_px = bid_f

            for lv in l2_bids[:20]:
                try:
                    lp = float(lv.get("px", 0.0))
                    ls = float(lv.get("sz", 0.0))
                except (TypeError, ValueError):
                    continue
                if lp <= 0 or ls <= 0:
                    continue
                last_px = lp
                if lp >= std_collar_px - 1e-12:
                    qty_within_std_collar += ls
                take = min(rem_to_clear, ls)
                if take > 0:
                    vwap_ntl += take * lp
                    vwap_qty += take
                    rem_to_clear -= take
                    p_clear = lp
                    if rem_to_clear <= 1e-12:
                        break

            if rem_to_clear > 1e-12:
                p_clear = last_px * 0.995
            p_vwap = (vwap_ntl / vwap_qty) if vwap_qty > 0 else bid_f

            q_rem_std = max(0.0, q_sell - min(q_sell, qty_within_std_collar))
            n_rem_usdc = q_rem_std * bid_f

            clear_slippage = (bid_f - p_clear) / bid_f if bid_f > 0 else 0.0
            s_mid = float(spot_mid_px) if spot_mid_px > 0 else bid_f
            p_mid = float(perp_mid_px) if perp_mid_px > 0 else s_mid
            perp_div = ((p_mid - s_mid) / s_mid) if s_mid > 0 else 0.0

            if (not is_emergency) and clear_slippage > self.TRANSIENT_GAP_SLIPPAGE_PCT and perp_div > -0.0030:
                transient_gap = True

            # 残余評価額 N_rem が 0 < N_rem < 11.2 USDC の端数になるリスクがある場合、カラーを拡張して1回で全量スイープ
            if 0.0 < n_rem_usdc < self.SAFE_RESIDUAL_NOTIONAL_USDC:
                candidate_sweep_px = max(max_collar_px, p_clear * 0.9990)
                if candidate_sweep_px < limit_px_raw:
                    limit_px_raw = candidate_sweep_px
                    collar_widened = True

        min_sell_px_str = round_price(limit_px_raw, sz_decimals)
        return {
            "action": "WAIT_TRANSIENT_GAP_200MS" if transient_gap else "EXECUTE_IOC_SELL",
            "should_place_order": not transient_gap,
            "q_sell": q_sell,
            "q_sell_str": q_sell_str,
            "est_notional_usdc": round(est_notional, 4),
            "min_sell_px_str": min_sell_px_str,
            "min_sell_px": float(min_sell_px_str),
            "p_clear": round(p_clear, 6),
            "p_vwap": round(p_vwap, 6),
            "n_rem_usdc": round(n_rem_usdc, 4),
            "collar_widened_for_dust_avoidance": collar_widened,
            "transient_gap_detected": transient_gap,
            "reason": "OK",
        }


class ActionBudgetController:
    """
    v1.2 論点5: 365日無枯渇の日次アクション・バジェット管理エンジン (ActionBudgetController):
      B_daily(t) = floor(max(0, B_0 + V_cum(t) - A_used(t) - 2500) / 365 + 0.50 * min(V_EMA_7d(t), V_today(t) + 100))
      (※ 当日無約定 V_today == 0 の間はハードキャップ B_zero_vol = 20 枠/日に制限)
      - 保有中SLラチェットのオンチェーン modify 送信は 0回 (100%ローカル監視)
      - 当日消費枠 >= 70% で未約定指値の Re-peg / Modify を禁止
      - 当日消費枠 >= 90% で要求確信度 +8.0pt 引き上げ
      - 当日消費枠 >= 100% で当日 UTC 24:00 まで新規エントリー停止 (決済とキャンセルは常時許可)
      - expiresAfter を使用する場合は必ず現在時刻 + 60,000 ms 以上として 5倍 Stale ペナルティを防止
    """

    B_0: int = 10_000
    B_RESERVE: int = 2_500
    B_ZERO_VOL_CAP: int = 20
    MIN_EXPIRES_AFTER_OFFSET_MS: int = 60_000
    MAX_SCHEDULE_CANCEL_DAILY: int = 8

    def __init__(self) -> None:
        self.v_cum_usdc: float = 0.0
        self.a_used_total: int = 0
        self.v_ema_7d_usdc: float = 100.0
        self.v_today_usdc: float = 0.0
        self.actions_used_today: int = 0
        self.onchain_sl_modify_count: int = 0
        self.schedule_cancel_used_today: int = 0

    def can_use_schedule_cancel(self, max_daily_calls: int = MAX_SCHEDULE_CANCEL_DAILY) -> bool:
        cap = min(int(max_daily_calls), int(self.MAX_SCHEDULE_CANCEL_DAILY))
        b_daily = self.compute_daily_budget()
        return bool(self.schedule_cancel_used_today < cap and self.actions_used_today < b_daily)

    def record_schedule_cancel_use(self) -> None:
        self.schedule_cancel_used_today += 1
        self.actions_used_today += 1
        self.a_used_total += 1

    def compute_daily_budget(
        self,
        v_cum_usdc: Optional[float] = None,
        a_used_total: Optional[int] = None,
        v_ema_7d_usdc: Optional[float] = None,
        v_today_usdc: Optional[float] = None,
    ) -> int:
        v_cum = float(self.v_cum_usdc if v_cum_usdc is None else v_cum_usdc)
        a_used = int(self.a_used_total if a_used_total is None else a_used_total)
        v_ema = max(0.0, float(self.v_ema_7d_usdc if v_ema_7d_usdc is None else v_ema_7d_usdc))
        v_tod = max(0.0, float(self.v_today_usdc if v_today_usdc is None else v_today_usdc))

        surplus_pool = max(0.0, float(self.B_0) + v_cum - float(a_used) - float(self.B_RESERVE))
        raw_budget = int((surplus_pool / 365.0) + 0.50 * min(v_ema, v_tod + 100.0))
        if v_tod <= 0.0:
            return min(self.B_ZERO_VOL_CAP, max(1, raw_budget)) if raw_budget > 0 else 0
        return max(0, raw_budget)

    def evaluate_budget_state(
        self,
        v_cum_usdc: Optional[float] = None,
        a_used_total: Optional[int] = None,
        v_ema_7d_usdc: Optional[float] = None,
        v_today_usdc: Optional[float] = None,
        actions_used_today: Optional[int] = None,
    ) -> Dict[str, Any]:
        b_daily = self.compute_daily_budget(
            v_cum_usdc=v_cum_usdc,
            a_used_total=a_used_total,
            v_ema_7d_usdc=v_ema_7d_usdc,
            v_today_usdc=v_today_usdc,
        )
        used_today = int(self.actions_used_today if actions_used_today is None else actions_used_today)
        usage_ratio = (float(used_today) / float(b_daily)) if b_daily > 0 else 1.0

        repeg_allowed = bool(usage_ratio < 0.70 and b_daily > 0)
        conviction_penalty = 8.0 if usage_ratio >= 0.90 else 0.0
        new_entry_allowed = bool(usage_ratio < 1.00 and b_daily > 0)

        return {
            "b_daily": b_daily,
            "actions_used_today": used_today,
            "usage_ratio": round(usage_ratio, 4),
            "onchain_sl_modify_allowed": False,
            "onchain_sl_modify_count": 0,
            "repeg_modify_allowed": repeg_allowed,
            "conviction_penalty": conviction_penalty,
            "conviction_penalty_norm": round(conviction_penalty / 100.0, 4),
            "new_entry_allowed": new_entry_allowed,
            "exit_and_cancel_allowed": True,
        }

    @classmethod
    def validate_expires_after(
        cls,
        expires_after_ms: Optional[int],
        current_time_ms: Optional[int] = None,
        strict: bool = False,
    ) -> Optional[int]:
        """
        expiresAfter を設定する場合は必ず現在時刻 + 60,000 ms 以上を強制し 5倍 Stale ペナルティを防止する。
        """
        if expires_after_ms is None:
            return None
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        min_allowed = ts + cls.MIN_EXPIRES_AFTER_OFFSET_MS
        if int(expires_after_ms) < min_allowed:
            if strict:
                raise ValueError(
                    f"expiresAfter ({expires_after_ms}) must be >= current_time_ms + 60000 ({min_allowed}) to avoid 5x stale penalty."
                )
            return min_allowed
        return int(expires_after_ms)


def _install_exchange_l1_destination_guard(
    exchange_obj: Any,
    main_address: Optional[str] = None,
) -> None:
    """
    SDK `Exchange` クライアントの `/exchange` アクション送信境界 (`_post_action`) に
    `verify_pinned_hl_action_destination` ガードを装着し、未許可宛先へのL1出金・送金・権限委譲を遮断する。
    """
    if exchange_obj is None:
        return
    pinned = (
        {main_address.strip().lower()}
        if main_address and main_address.strip() and main_address.strip() != ("0x" + "0" * 40)
        else None
    )

    if hasattr(exchange_obj, "_post_action") and not getattr(exchange_obj, "_hl_l1_guard_installed", False):
        orig_post_action = exchange_obj._post_action

        def _guarded_post_action(action: Dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            verify_pinned_hl_action_destination(action, allowed_destinations=pinned)
            return orig_post_action(action, *args, **kwargs)

        exchange_obj._post_action = _guarded_post_action
        setattr(exchange_obj, "_hl_l1_guard_installed", True)


class HyperliquidExchangeWrapper:
    """
    Hyperliquid Spot API 専用ラッパークラス。
    Agent Wallet初期化、Perps完全遮断ガード、動的辞書マッピング、厳密丸め、
    1ステップIOC決済、および10 USDC未満端数の Top-Up & Dump 自己復旧を提供する。
    """

    MIN_ENTRY_NOTIONAL_USDC = Decimal("16.0")
    MAX_INITIAL_SL_PCT = Decimal("0.080")  # 8.0%
    IOC_SELL_SLIPPAGE_FACTOR = Decimal("0.985")
    IOC_BUY_SLIPPAGE_FACTOR = Decimal("1.010")
    RATE_LIMIT_SURPLUS_THRESHOLD = 500
    NON_TRADING_STABLECOINS = frozenset(
        {"USDC", "USDT", "USDT0", "USDE", "USDH", "FEUSD", "DAI", "FDUSD"}
    )

    # DRY_RUN 時のフォールバック用決定論的ダミー秘密鍵（実資金とは無関係）
    _DUMMY_PRIVATE_KEY = "0x" + "11" * 32

    def __init__(
        self,
        main_address: Optional[str] = None,
        agent_private_key: Optional[str] = None,
        base_url: str = MAINNET_API_URL,
        execution_mode: str = "DRY_RUN",
        db: Optional[DatabaseManager] = None,
        coordinator: Optional[ConcurrencyStateCoordinator] = None,
        tax_engine: Optional[HyperliquidTaxEngine] = None,
        nonce_manager: Optional[MonotonicHyperliquidNonceManager] = None,
        http_session: Optional[PersistentHTTPSession] = None,
        info_client: Optional[Any] = None,
        exchange_client: Optional[Any] = None,
    ) -> None:
        self.main_address = (
            main_address or os.getenv("HL_MAIN_ADDRESS") or "0x0000000000000000000000000000000000000000"
        ).strip()
        raw_pk = (
            dpapi_decrypt_str(agent_private_key)
            if agent_private_key
            else get_secret("HL_AGENT_PRIVATE_KEY")
        ).strip()
        self.base_url = base_url or os.getenv("HL_BASE_URL") or MAINNET_API_URL
        self.execution_mode = (execution_mode or os.getenv("EXECUTION_MODE") or "DRY_RUN").strip().upper()

        self.db = db
        self.coordinator = coordinator
        self.tax_engine = tax_engine
        self.nonce_manager = nonce_manager or MonotonicHyperliquidNonceManager()
        self.http_session = http_session or PersistentHTTPSession()

        # Agent Wallet (LocalAccount) の生成（平文秘密鍵は属性や os.environ に保持しない）
        self.agent_account: LocalAccount = self._create_agent_account(raw_pk)
        del raw_pk
        self.agent_address: str = self.agent_account.address

        # SDK Info / Exchange クライアント初期化
        self.info: Any = info_client
        self.exchange: Any = exchange_client
        if self.exchange is not None:
            self._install_exchange_l1_destination_guard(self.exchange)
        if self.info is None and self.exchange is None and self.execution_mode == "LIVE":
            self._init_sdk_clients()

        # 動的マッピング辞書
        self.pair_to_entry: Dict[str, SpotUniverseEntry] = {}
        self.api_coin_to_entry: Dict[str, SpotUniverseEntry] = {}
        self.base_to_entry: Dict[str, SpotUniverseEntry] = {}
        self.perp_coins_set: set[str] = set()
        self.perp_ctxs_by_coin: Dict[str, Dict[str, Any]] = {}
        self.last_universe_refresh_ms: int = 0
        self._pre_order_base_balances: Dict[Tuple[int, str], Decimal] = {}
        self.ioc_planner = DepthAwareIocPlanner()
        self.action_budget = ActionBudgetController()
        self._schedule_cancel_daily_count: int = 0
        self._schedule_cancel_day_str: str = ""
        self._active_deadman_cancel_time_ms: Optional[int] = None
        self._active_scratch_sell_orders: Dict[int, Dict[str, Any]] = {}

    def _create_agent_account(self, raw_private_key: str) -> Any:
        pk = raw_private_key.strip()
        if not pk or pk == "0x" + "0" * 64 or pk == "0" * 64:
            if self.execution_mode == "LIVE":
                raise ValueError("LIVEモードでは有効な HL_AGENT_PRIVATE_KEY の設定が必須です。")
            pk = self._DUMMY_PRIVATE_KEY
        elif not pk.startswith("0x"):
            pk = "0x" + pk
        if EthAccount is not None:
            return EthAccount.from_key(pk)
        return FallbackLocalAccount.from_key(pk)

    def _init_sdk_clients(self) -> None:
        """
        ARCHITECTURE.md Section 1 仕様通り:
        `Exchange(wallet=agent_account, base_url=MAINNET_API_URL, account_address=main_address)`
        で初期化する。また `Info.spot_user_state` と `spot_clearinghouse_state` の互換エイリアスを設定する。
        """
        if HLSDKInfo is None or HLSDKExchange is None:
            raise RuntimeError("hyperliquid-python-sdk がインストールされていません。")
        self.info = HLSDKInfo(base_url=self.base_url, skip_ws=True)
        if not hasattr(self.info, "spot_clearinghouse_state") and hasattr(self.info, "spot_user_state"):
            self.info.spot_clearinghouse_state = self.info.spot_user_state
        self.exchange = HLSDKExchange(
            wallet=self.agent_account,
            base_url=self.base_url,
            account_address=self.main_address,
        )
        self._install_exchange_l1_destination_guard(self.exchange)

    def _install_exchange_l1_destination_guard(self, exchange_obj: Any) -> None:
        _install_exchange_l1_destination_guard(exchange_obj, main_address=self.main_address)

    def _fetch_spot_clearinghouse_state(self) -> Dict[str, Any]:
        """
        `hyperliquid-python-sdk` の `info.spot_user_state(main_address)` と
        モック/REST互換の `info.spot_clearinghouse_state(main_address)` の双方に対応する。
        """
        if self.info is None:
            return {}
        if hasattr(self.info, "spot_clearinghouse_state"):
            return self.info.spot_clearinghouse_state(self.main_address) or {}
        if hasattr(self.info, "spot_user_state"):
            return self.info.spot_user_state(self.main_address) or {}
        if hasattr(self.info, "post"):
            return self.info.post("/info", {"type": "spotClearinghouseState", "user": self.main_address}) or {}
        return {}

    def is_unified_account(self, spot_state: Optional[Dict[str, Any]] = None) -> bool:
        """
        対象ウォレットが Hyperliquid の「Unified Account（統合口座）」モードで稼働しているかを判定する。
        1. `spotClearinghouseState` に `tokenToAvailableAfterMaintenance` が含まれる場合
        2. または `info.query_user_abstraction_state(main_address)` が `"unifiedAccount"` を返す場合
        """
        st = spot_state if spot_state is not None else self._fetch_spot_clearinghouse_state()
        if isinstance(st, dict) and "tokenToAvailableAfterMaintenance" in st:
            return True
        if self.info is not None and hasattr(self.info, "query_user_abstraction_state"):
            try:
                abst = self.info.query_user_abstraction_state(self.main_address)
                if str(abst).strip().strip('"').lower() == "unifiedaccount":
                    return True
            except Exception:
                pass
        return False

    # ==========================================================================
    # 1. Agent Wallet 有効期限監視 (`extra_agents`)
    # ==========================================================================
    def check_agent_wallet_validity(
        self,
        warn_Within_hours: float = 336.0,
        raise_on_invalid: bool = False,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        `info.extra_agents(main_address)` を呼び出し、現在の `agent_account.address` の
        `validUntil` 有効期限を検証する。
        残り14日（336時間）未満で `warning_14d = True` / `warning = True` を返す。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        if self.info is None:
            return {
                "valid": True,
                "agent_address": self.agent_address,
                "valid_until_ms": ts + 30 * 86_400_000,
                "remaining_hours": 720.0,
                "warning": False,
                "warning_14d": False,
                "reason": "DRY_RUN_NO_INFO_CLIENT",
            }

        extra_agents = self.info.extra_agents(self.main_address) or []
        target_addr = self.agent_address.lower()
        matched: Optional[Dict[str, Any]] = None
        for entry in extra_agents:
            addr = str(entry.get("address", "")).lower()
            if addr == target_addr:
                matched = entry
                break

        if matched is None:
            msg = f"Agent Wallet ({self.agent_address}) が main_address ({self.main_address}) の extra_agents に存在しません。"
            if raise_on_invalid:
                raise AgentWalletExpiredError(msg)
            return {
                "valid": False,
                "agent_address": self.agent_address,
                "valid_until_ms": 0,
                "remaining_hours": 0.0,
                "warning": True,
                "warning_14d": True,
                "reason": "AGENT_NOT_FOUND",
            }

        valid_until_ms = int(matched.get("validUntil", 0))
        remaining_ms = valid_until_ms - ts
        remaining_hours = remaining_ms / 3_600_000.0
        is_valid = remaining_ms > 0
        warning_14d = (not is_valid) or (remaining_hours < 336.0)
        is_warning = (not is_valid) or (remaining_hours < float(warn_Within_hours))

        if not is_valid and raise_on_invalid:
            raise AgentWalletExpiredError(
                f"Agent Wallet ({self.agent_address}) の有効期限が切れています (validUntil={valid_until_ms}, now={ts})。"
            )

        return {
            "valid": is_valid,
            "agent_address": self.agent_address,
            "name": matched.get("name", ""),
            "valid_until_ms": valid_until_ms,
            "remaining_hours": round(remaining_hours, 2),
            "warning": is_warning,
            "warning_14d": warning_14d,
            "reason": "OK" if is_valid else "EXPIRED",
        }

    # ==========================================================================
    # 2. Perps ➔ Spot 自動USDC振替 (`usd_class_transfer`)
    # ==========================================================================
    def auto_transfer_perp_to_spot_usdc(
        self,
        min_transfer_usdc: float = 1.0,
        only_when_spot_below_usdc: Optional[float] = 10.0,
    ) -> Dict[str, Any]:
        """
        起動時または資金補充時に Perps口座の `withdrawable` USDC を確認し、
        Perps建玉が存在しない安全な状態で `exchange.usd_class_transfer(amount, to_perp=False)`
        を実行して Spot口座へUSDCを自動振替する。
        （※ Unified Account モード環境では Perp/Spot の USDC プールが統合されているため、
           不要な `usd_class_transfer` 呼び出しや残高の二重計上を100%抑止する）
        """
        if self.info is None:
            return {"transferred": False, "amount_usdc": 0.0, "reason": "NO_INFO_CLIENT"}

        raw_spot_state = self._fetch_spot_clearinghouse_state()
        spot_balances = self.get_spot_balances(raw_spot_state)
        spot_usdc_total = float(spot_balances.get("USDC", {}).get("total", 0.0))

        # Unified Account モードの場合は Perps <-> Spot 間の振替自体が不要・無効のため即スキップ
        if self.is_unified_account(raw_spot_state):
            return {
                "transferred": False,
                "amount_usdc": 0.0,
                "unified_account": True,
                "spot_usdc_total": spot_usdc_total,
                "reason": "UNIFIED_ACCOUNT_NO_TRANSFER_NEEDED",
            }

        if only_when_spot_below_usdc is not None and spot_usdc_total >= float(only_when_spot_below_usdc):
            return {
                "transferred": False,
                "amount_usdc": 0.0,
                "unified_account": False,
                "spot_usdc_total": spot_usdc_total,
                "reason": "SPOT_USDC_ALREADY_SUFFICIENT",
            }

        perp_state = self.info.user_state(self.main_address) or {}
        asset_positions = perp_state.get("assetPositions") or []
        active_perp_positions = [
            p for p in asset_positions
            if abs(float((p.get("position") or {}).get("szi", 0.0))) > 0
        ]
        if active_perp_positions:
            return {
                "transferred": False,
                "amount_usdc": 0.0,
                "reason": "ACTIVE_PERP_POSITIONS_EXIST",
            }

        withdrawable = float(perp_state.get("withdrawable", 0.0))
        # 小数点以下2桁で切り捨てて安全に全額または必要額を振替
        transfer_amt_dec = _to_clean_decimal(withdrawable).quantize(Decimal("0.01"))
        transfer_amt = float(transfer_amt_dec)

        if transfer_amt < float(min_transfer_usdc):
            return {
                "transferred": False,
                "amount_usdc": 0.0,
                "withdrawable": withdrawable,
                "reason": "WITHDRAWABLE_BELOW_MIN_THRESHOLD",
            }

        if self.execution_mode == "DRY_RUN" and self.exchange is None:
            return {
                "transferred": True,
                "amount_usdc": transfer_amt,
                "to_perp": False,
                "mode": "DRY_RUN",
                "response": {"status": "ok", "simulated": True},
            }

        if self.exchange is None:
            raise RuntimeError("Exchange クライアントが初期化されていません。")

        resp = self.exchange.usd_class_transfer(amount=transfer_amt, to_perp=False)
        logger.info("Perps口座からSpot口座へ %.2f USDC を自動振替しました: %s", transfer_amt, resp)
        return {
            "transferred": True,
            "amount_usdc": transfer_amt,
            "to_perp": False,
            "mode": self.execution_mode,
            "response": resp,
        }

    # ==========================================================================
    # 3. Spot-Perp シンボル動的マッピング (`refresh_universe_mapping`)
    # ==========================================================================
    def refresh_universe_mapping(
        self,
        spot_meta_and_ctxs: Optional[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = None,
        perp_meta_and_ctxs: Optional[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = None,
    ) -> Dict[str, SpotUniverseEntry]:
        """
        `info.spot_meta_and_asset_ctxs()` と `info.meta_and_asset_ctxs()` から
        `@index` ⟷ 人間可読ペア名 (`HYPE/USDC`, `UBTC/USDC` 等) ⟷ `szDecimals` ⟷ Perp銘柄 (`BTC`, `HYPE` 等)
        の動的辞書を構築する。
        """
        if spot_meta_and_ctxs is None:
            if self.info is None:
                raise RuntimeError("info クライアントまたは spot_meta_and_ctxs データが必要です。")
            spot_meta_and_ctxs = self.info.spot_meta_and_asset_ctxs()

        if perp_meta_and_ctxs is None and self.info is not None:
            try:
                perp_meta_and_ctxs = self.info.meta_and_asset_ctxs()
            except Exception as exc:
                logger.warning("meta_and_asset_ctxs 取得失敗: %s", exc)
                perp_meta_and_ctxs = ({"universe": []}, [])

        spot_meta, spot_ctxs = spot_meta_and_ctxs[0], spot_meta_and_ctxs[1]
        perp_meta, perp_ctxs = (
            (perp_meta_and_ctxs[0], perp_meta_and_ctxs[1])
            if perp_meta_and_ctxs is not None
            else ({"universe": []}, [])
        )

        # 1. Perp ユニバースとコンテキストのインデックス化
        perp_universe = perp_meta.get("universe") or []
        available_perps: set[str] = set()
        perp_ctx_map: Dict[str, Dict[str, Any]] = {}
        for idx, p_u in enumerate(perp_universe):
            p_name = str(p_u.get("name", "")).strip().upper()
            if not p_name:
                continue
            available_perps.add(p_name)
            ctx = perp_ctxs[idx] if idx < len(perp_ctxs) else {}
            perp_ctx_map[p_name] = dict(ctx)

        # 2. Spot トークン辞書の構築
        tokens_list = spot_meta.get("tokens") or []
        tokens_by_idx: Dict[int, Dict[str, Any]] = {}
        for idx, tok in enumerate(tokens_list):
            t_idx = int(tok.get("index", idx))
            tokens_by_idx[t_idx] = tok

        # 3. Spot ユニバースの構築 (quote_token_idx == 0 (USDC) かつ '#' 予測市場を除外)
        spot_universe = spot_meta.get("universe") or []
        new_pair_map: Dict[str, SpotUniverseEntry] = {}
        new_api_map: Dict[str, SpotUniverseEntry] = {}
        new_base_map: Dict[str, SpotUniverseEntry] = {}

        for u_pos, u_item in enumerate(spot_universe):
            api_coin_name = str(u_item.get("name", "")).strip()
            if not api_coin_name or api_coin_name.startswith("#"):
                continue

            token_indices = u_item.get("tokens") or []
            if len(token_indices) < 2:
                continue
            base_idx = int(token_indices[0])
            quote_idx = int(token_indices[1])

            # 正規USDCクオートペア検証 (quote_token_idx == 0)
            if quote_idx != 0:
                continue

            base_tok = tokens_by_idx.get(base_idx)
            quote_tok = tokens_by_idx.get(quote_idx, {"name": "USDC"})
            if not base_tok:
                continue

            base_asset = str(base_tok.get("name", "")).strip().upper()
            quote_asset = str(quote_tok.get("name", "USDC")).strip().upper()
            if not base_asset or base_asset.startswith("#") or quote_asset != "USDC":
                continue

            u_idx = int(u_item.get("index", u_pos))
            sz_decimals = int(base_tok.get("szDecimals", 0))
            wei_decimals = int(base_tok.get("weiDecimals", sz_decimals))
            # Hyperliquid Mainnet の spotMeta では @index 形式ペア (@107 HYPE, @142 UBTC 等) の
            # raw JSON 上の isCanonical が False になっている（"PURR/USDC" のみ True）。
            # したがって quote_idx == 0 (USDC) かつ非予測市場・非ステーブルコインの正規Spotペアを canonical として扱う。
            is_canonical = bool(
                base_asset not in self.NON_TRADING_STABLECOINS
                and quote_idx == 0
                and not api_coin_name.startswith("#")
            )
            pair_name = f"{base_asset}/{quote_asset}"

            # Spot コンテキスト取得
            s_ctx = spot_ctxs[u_pos] if u_pos < len(spot_ctxs) else {}
            if not isinstance(s_ctx, dict) or str(s_ctx.get("coin", "")) != api_coin_name:
                for c_candidate in spot_ctxs:
                    if str(c_candidate.get("coin", "")) == api_coin_name:
                        s_ctx = c_candidate
                        break

            spot_mid = float(s_ctx.get("midPx") or s_ctx.get("markPx") or 0.0)
            spot_mark = float(s_ctx.get("markPx") or spot_mid or 0.0)
            spot_vlm = float(s_ctx.get("dayNtlVlm") or 0.0)

            # Perp シンボル紐付け (先頭 'U' 除去マッピング)
            perp_coin = map_spot_base_to_perp_symbol(base_asset, available_perps)
            p_ctx = perp_ctx_map.get(perp_coin, {}) if perp_coin else {}

            perp_mark = float(p_ctx.get("markPx") or 0.0)
            perp_oracle = float(p_ctx.get("oraclePx") or 0.0)
            perp_mid = float(p_ctx.get("midPx") or perp_mark or 0.0)
            perp_funding = float(p_ctx.get("funding") or 0.0)
            perp_oi = float(p_ctx.get("openInterest") or 0.0)
            perp_prem = float(p_ctx.get("premium") or 0.0)
            perp_vlm = float(p_ctx.get("dayNtlVlm") or 0.0)

            entry = SpotUniverseEntry(
                pair_name=pair_name,
                api_coin_name=api_coin_name,
                base_asset=base_asset,
                quote_asset=quote_asset,
                base_token_idx=base_idx,
                quote_token_idx=quote_idx,
                universe_idx=u_idx,
                spot_asset_id=10000 + u_idx,
                sz_decimals=sz_decimals,
                wei_decimals=wei_decimals,
                is_canonical=is_canonical,
                perp_coin=perp_coin,
                spot_mid_px=spot_mid,
                spot_mark_px=spot_mark,
                spot_day_ntl_vlm=spot_vlm,
                perp_mark_px=perp_mark,
                perp_oracle_px=perp_oracle,
                perp_mid_px=perp_mid,
                perp_funding_1h=perp_funding,
                perp_open_interest=perp_oi,
                perp_premium=perp_prem,
                perp_day_ntl_vlm=perp_vlm,
                raw_spot_ctx=dict(s_ctx),
                raw_perp_ctx=dict(p_ctx),
            )

            existing = new_pair_map.get(pair_name.upper())
            if existing is None or spot_vlm > existing.spot_day_ntl_vlm:
                new_pair_map[pair_name.upper()] = entry
                new_base_map[base_asset.upper()] = entry
            new_api_map[api_coin_name.upper()] = entry

        self.pair_to_entry = new_pair_map
        self.api_coin_to_entry = new_api_map
        self.base_to_entry = new_base_map
        self.perp_coins_set = available_perps
        self.perp_ctxs_by_coin = perp_ctx_map
        self.last_universe_refresh_ms = now_ms()
        return self.pair_to_entry

    # ==========================================================================
    # 4. Perps発注遮断ガード (`assert_spot_only_coin`)
    # ==========================================================================
    def assert_spot_only_coin(self, coin_or_pair: str) -> SpotUniverseEntry:
        """
        指定された識別子が `spotMeta` に存在する正規USDC建てSpotペアであることを厳密に検証し、
        対応する `SpotUniverseEntry` を返す。
        もし `"BTC"`, `"ETH"`, `"SOL"`, `"HYPE"` 等のPerp単体シンボルや `#` 予測市場、
        未登録シンボルが指定された場合は即座に `PerpsOrderForbiddenError` を送出して発注を100%遮断する。
        """
        raw = str(coin_or_pair or "").strip()
        if not raw:
            raise PerpsOrderForbiddenError("空の銘柄識別子での発注は遮断されました。")

        upper = raw.upper()
        if upper.startswith("#"):
            raise PerpsOrderForbiddenError(
                f"HIP-4予測市場シンボル ({raw}) の取引は禁止されています。"
            )

        # Perp単体名 ("BTC", "ETH", "SOL", "HYPE" 等: '@' も '/USDC' も含まない文字列) を即時遮断
        if not upper.startswith("@") and "/" not in upper:
            raise PerpsOrderForbiddenError(
                f"Perps単体シンボル形式 ('{raw}') での発注は厳禁です。"
                "必ず正規Spotペア名 (例: 'HYPE/USDC', 'UBTC/USDC') または Spot '@index' (例: '@107') を指定してください。"
            )

        if not self.pair_to_entry and self.info is not None:
            self.refresh_universe_mapping()

        entry = self.pair_to_entry.get(upper) or self.api_coin_to_entry.get(upper)
        if entry is None:
            raise PerpsOrderForbiddenError(
                f"指定された銘柄 '{raw}' は spotMeta の正規USDC建てSpotペアに存在しないため遮断されました。"
            )

        if entry.quote_token_idx != 0 or entry.quote_asset != "USDC" or entry.spot_asset_id < 10000:
            raise PerpsOrderForbiddenError(
                f"非USDC建てまたは非Spot資産 ('{raw}', asset_id={entry.spot_asset_id}) の発注は遮断されました。"
            )

        return entry

    def get_spot_entry(self, coin_or_pair_or_base: str) -> Optional[SpotUniverseEntry]:
        """読み取り参照用にペア名 (`HYPE/USDC`)、`@index` (`@107`)、またはBase名 (`UBTC`) からエントリを引く"""
        key = str(coin_or_pair_or_base or "").strip().upper()
        if not key:
            return None
        entry = (
            self.pair_to_entry.get(key)
            or self.api_coin_to_entry.get(key)
            or self.base_to_entry.get(key)
        )
        if entry is None and "/" in key:
            base_part = key.split("/", 1)[0].strip()
            entry = self.base_to_entry.get(base_part)
        return entry

    def normalize_spot_symbol(self, symbol: str) -> Tuple[str, str, str]:
        """
        任意のSpot銘柄表記 (`@107`, `HYPE/USDC`, `HYPE` 等) を双方向正規化し、
        `(pair_name, api_coin_name, base_asset)` の3要素タプル (例: `("HYPE/USDC", "@107", "HYPE")`) を返す。
        辞書に未登録の場合はフォールバック正規化した文字列タプルを返す。
        """
        raw = str(symbol or "").strip().upper()
        if not raw:
            return ("", "", "")
        entry = self.get_spot_entry(raw)
        if entry is not None:
            return (entry.pair_name.upper(), entry.api_coin_name.upper(), entry.base_asset.upper())
        if "/" in raw:
            base_part = raw.split("/", 1)[0].strip()
            return (raw, raw, base_part)
        if raw.startswith("@"):
            return (raw, raw, raw)
        return (f"{raw}/USDC", raw, raw)

    def are_symbols_equivalent(self, sym_a: str, sym_b: str) -> bool:
        """
        2つのシンボル文字列 (例: `"@107"` と `"HYPE/USDC"`、または `"HYPE"` と `"HYPE/USDC"`) が
        同一のSpot銘柄を指しているかを厳密に判定する。
        """
        a = str(sym_a or "").strip().upper()
        b = str(sym_b or "").strip().upper()
        if not a or not b:
            return False
        if a == b:
            return True
        norm_a = self.normalize_spot_symbol(a)
        norm_b = self.normalize_spot_symbol(b)
        return (
            bool(norm_a[0] and norm_a[0] == norm_b[0])
            or bool(norm_a[1] and norm_a[1] == norm_b[1])
            or bool(norm_a[2] and norm_a[2] == norm_b[2])
        )

    def get_open_orders(self, open_orders_override: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        `info.frontend_open_orders(main_address)` または `info.open_orders(main_address)` から
        未約定注文一覧を取得し、`pair_name`, `api_coin_name`, `base_asset` を正規化付与して返す。
        """
        raw_orders: List[Dict[str, Any]] = []
        if open_orders_override is not None:
            raw_orders = list(open_orders_override)
        elif self.info is not None:
            try:
                if hasattr(self.info, "frontend_open_orders"):
                    res = self.info.frontend_open_orders(self.main_address)
                    if isinstance(res, list):
                        raw_orders = res
                if not raw_orders and hasattr(self.info, "open_orders"):
                    res2 = self.info.open_orders(self.main_address)
                    if isinstance(res2, list):
                        raw_orders = res2
            except Exception as exc:
                logger.warning("open_orders 取得失敗: %s", exc)
                raw_orders = []

        enriched: List[Dict[str, Any]] = []
        for oo in raw_orders:
            if not isinstance(oo, dict):
                continue
            raw_coin = str(oo.get("coin", "")).strip()
            pair_name, api_coin, base_asset = self.normalize_spot_symbol(raw_coin)
            enriched.append(
                {
                    **oo,
                    "pair_name": pair_name,
                    "api_coin_name": api_coin,
                    "base_asset": base_asset,
                }
            )
        return enriched

    # ==========================================================================
    # 5. Spot残高照会 ＆ アドレス単位レート制限 (`userRateLimit`) 確認
    # ==========================================================================
    def get_spot_balances(
        self,
        spot_clearinghouse_state: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, Decimal]]:
        """
        `info.spot_clearinghouse_state(main_address)` から各トークンの `total`, `hold`, `free` 残高を
        `Decimal` 辞書として取得する。
        """
        state = spot_clearinghouse_state
        if state is None:
            if self.info is None:
                return {"USDC": {"total": Decimal("0"), "hold": Decimal("0"), "free": Decimal("0")}}
            state = self._fetch_spot_clearinghouse_state()

        balances_list = state.get("balances") or []
        result: Dict[str, Dict[str, Decimal]] = {}
        for b in balances_list:
            coin_name = str(b.get("coin", "")).strip().upper()
            if not coin_name:
                continue
            tot = _to_clean_decimal(b.get("total", "0"))
            hld = _to_clean_decimal(b.get("hold", "0"))
            free = max(Decimal("0"), tot - hld)
            result[coin_name] = {
                "total": tot,
                "hold": hld,
                "free": free,
            }
        if "USDC" not in result:
            result["USDC"] = {"total": Decimal("0"), "hold": Decimal("0"), "free": Decimal("0")}
        return result

    def check_rate_limit_surplus(self) -> Dict[str, Any]:
        """
        `info.user_rate_limit(main_address)` を確認し、
        `nRequestsSurplus = nRequestsCap - nRequestsUsed` が 500 未満かどうかを返す。
        """
        if self.info is None:
            return {
                "nRequestsCap": 10000,
                "nRequestsUsed": 0,
                "nRequestsSurplus": 10000,
                "should_throttle": False,
            }
        rl = self.info.user_rate_limit(self.main_address) or {}
        cap = int(rl.get("nRequestsCap", 10000))
        used = int(rl.get("nRequestsUsed", 0))
        surplus = cap - used
        return {
            "nRequestsCap": cap,
            "nRequestsUsed": used,
            "nRequestsSurplus": surplus,
            "should_throttle": bool(surplus < self.RATE_LIMIT_SURPLUS_THRESHOLD),
        }

    # ==========================================================================
    # 6. Spot 指値買い (`Alo`) ＆ キャンセル ＆ 1ステップ `Ioc` 即時決済
    # ==========================================================================
    @staticmethod
    def _extract_order_status(resp: Dict[str, Any]) -> Tuple[Optional[int], bool, Optional[str]]:
        """
        Hyperliquid `/exchange` 注文レスポンスから `(oid, is_filled, error_msg)` を抽出する。
        """
        if not isinstance(resp, dict):
            return (None, False, f"Unexpected response format: {resp!r}")
        if resp.get("status") != "ok":
            return (None, False, str(resp.get("response") or resp))

        statuses = (
            resp.get("response", {})
            .get("data", {})
            .get("statuses", [])
        )
        if not statuses:
            return (None, False, None)

        st0 = statuses[0]
        if "error" in st0:
            return (None, False, str(st0["error"]))
        if "filled" in st0:
            f_info = st0["filled"]
            return (int(f_info.get("oid", 0)), True, None)
        if "resting" in st0:
            r_info = st0["resting"]
            return (int(r_info.get("oid", 0)), False, None)
        return (None, False, None)

    def place_spot_buy_alo(
        self,
        slot_id: int,
        coin_or_pair: str,
        raw_limit_px: Union[float, str, Decimal],
        raw_sz: Union[float, str, Decimal],
        sl_px: Optional[Union[float, str, Decimal]] = None,
        tp_px: Optional[Union[float, str, Decimal]] = None,
        episode_id: Optional[str] = None,
        cloid_hex: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Spot 専用 Post-Only (`Alo`) 新規指値買い発注。
        - Perps遮断ガード
        - `round_price` / `floor_size` による厳密切り捨て
        - 最小発注額 `16.0 USDC` フロア ＆ 最大初期SL幅 `8.0%` キャップ検証
        - `ConcurrencyStateCoordinator` による `cloid` 先行WALコミット (`ENTRY_PENDING`)
        - `expiresAfter` は絶対に使用しない
        """
        entry = self.assert_spot_only_coin(coin_or_pair)
        px_str = round_price(raw_limit_px, entry.sz_decimals)
        sz_str = floor_size(raw_sz, entry.sz_decimals)

        px_dec = _to_clean_decimal(px_str)
        sz_dec = _to_clean_decimal(sz_str)
        notional_usdc = px_dec * sz_dec

        if px_dec <= 0 or sz_dec <= 0:
            raise OrderValidationError(
                f"丸め後の価格または数量が0以下です (px={px_str}, sz={sz_str})。"
            )

        if notional_usdc < self.MIN_ENTRY_NOTIONAL_USDC:
            raise OrderValidationError(
                f"新規買い発注額 ({notional_usdc:.2f} USDC) が最小発注額フロア ({self.MIN_ENTRY_NOTIONAL_USDC} USDC) 未満です。"
            )

        sl_px_float = 0.0
        if sl_px is not None and _to_clean_decimal(sl_px) > 0:
            sl_str = round_price(sl_px, entry.sz_decimals)
            sl_dec = _to_clean_decimal(sl_str)
            sl_px_float = float(sl_str)
            sl_dist_pct = (px_dec - sl_dec) / px_dec
            if sl_dist_pct <= 0 or sl_dist_pct > self.MAX_INITIAL_SL_PCT:
                raise OrderValidationError(
                    f"初期SL距離 ({float(sl_dist_pct)*100:.2f}%) が許容範囲 (0% < SL <= 8.0%) を逸脱しています。"
                )

        tp_px_float = float(round_price(tp_px, entry.sz_decimals)) if (tp_px is not None and _to_clean_decimal(tp_px) > 0) else 0.0
        cloid = cloid_hex if cloid_hex else generate_cloid()
        nonce = self.nonce_manager.next_nonce()

        # 発注直前の対象ベーストークン実残高を記録し、キャンセル時の Partial Fill (部分約定) 純増分を正確に判定可能にする
        if len(self._pre_order_base_balances) > 64:
            self._pre_order_base_balances.clear()
        try:
            pre_bals = self.get_spot_balances()
            pre_base_tot = pre_bals.get(entry.base_asset.upper(), {}).get("total", Decimal("0"))
            self._pre_order_base_balances[(int(slot_id), entry.base_asset.upper())] = pre_base_tot
        except Exception:
            self._pre_order_base_balances[(int(slot_id), entry.base_asset.upper())] = Decimal("0")

        if self.coordinator is not None:
            self.coordinator.begin_order_intent(
                slot_id=slot_id,
                target_state=SlotState.ENTRY_PENDING,
                coin=entry.pair_name,
                base_asset=entry.base_asset,
                sz_decimals=entry.sz_decimals,
                cloid=cloid,
                entry_px=float(px_str),
                sz=float(sz_str),
                sl_px=sl_px_float,
                tp_px=tp_px_float,
                episode_id=episode_id,
                timestamp_ms=timestamp_ms,
            )

        if self.execution_mode == "DRY_RUN" and self.exchange is None:
            fake_oid = int(nonce % 1_000_000_000)
            if self.coordinator is not None:
                self.coordinator.bind_order_response(
                    slot_id=slot_id,
                    cloid=cloid,
                    oid=fake_oid,
                    filled=False,
                )
            deadman_res = self.schedule_cancel_deadman(
                cancel_time_ms=(int(timestamp_ms) if timestamp_ms is not None else now_ms()) + 4 * 3600 * 1000 + 60_000,
                current_time_ms=timestamp_ms,
            )
            return {
                "status": "ok",
                "mode": "DRY_RUN",
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "px_str": px_str,
                "sz_str": sz_str,
                "notional_usdc": float(notional_usdc),
                "cloid": cloid,
                "oid": fake_oid,
                "filled": False,
                "nonce": nonce,
                "deadman": deadman_res,
            }

        if self.exchange is None:
            raise RuntimeError("Exchange クライアントが未初期化です。")

        # ARCHITECTURE.md Section 4.1 準拠呼び出し + Post-Only (Alo) スプレッド交差拒否時の Re-peg 自動再発注 (最大3回)
        sdk_resp = self.exchange.order(
            name=entry.api_coin_name,
            is_buy=True,
            sz=float(sz_str),
            limit_px=float(px_str),
            order_type={"limit": {"tif": "Alo"}},
            reduce_only=False,
            cloid=make_cloid(cloid),
        )
        oid, is_filled, err_msg = self._extract_order_status(sdk_resp)
        repeg_attempts = 0
        while (
            err_msg is not None
            and repeg_attempts < 3
            and any(k in err_msg.lower() for k in ("post only", "alo", "cross", "would match", "bbo"))
        ):
            repeg_attempts += 1
            time.sleep(0.01 if "PYTEST_CURRENT_TEST" in os.environ else 0.15)
            tick = compute_tick_size(px_dec, entry.sz_decimals)
            new_cand_px = px_dec - tick
            if self.info is not None and hasattr(self.info, "l2_snapshot"):
                try:
                    snap = self.info.l2_snapshot(entry.api_coin_name)
                    levels = (snap or {}).get("levels") or []
                    if len(levels) >= 2 and levels[0] and levels[1]:
                        fresh_bid = _to_clean_decimal(levels[0][0]["px"])
                        fresh_ask = _to_clean_decimal(levels[1][0]["px"])
                        fresh_tick = compute_tick_size(fresh_bid, entry.sz_decimals)
                        new_cand_px = min(fresh_bid, fresh_ask - fresh_tick)
                except Exception:
                    pass
            px_str = round_price(new_cand_px, entry.sz_decimals)
            px_dec = _to_clean_decimal(px_str)
            if px_dec * sz_dec < self.MIN_ENTRY_NOTIONAL_USDC:
                break
            nonce = self.nonce_manager.next_nonce()
            sdk_resp = self.exchange.order(
                name=entry.api_coin_name,
                is_buy=True,
                sz=float(sz_str),
                limit_px=float(px_str),
                order_type={"limit": {"tif": "Alo"}},
                reduce_only=False,
                cloid=make_cloid(cloid),
            )
            oid, is_filled, err_msg = self._extract_order_status(sdk_resp)
            if err_msg is None:
                break

        if self.coordinator is not None:
            self.coordinator.bind_order_response(
                slot_id=slot_id,
                cloid=cloid,
                oid=oid,
                filled=is_filled,
                filled_sz=float(sz_str) if is_filled else None,
                avg_px=float(px_str) if is_filled else None,
                rejected=bool(err_msg is not None),
            )

        if is_filled and err_msg is None and self.tax_engine is not None:
            try:
                syn_tid = 9_000_000_000_000 + int(oid or (nonce % 1_000_000_000))
                self.tax_engine.process_spot_fill(
                    hl_tid=syn_tid,
                    hl_oid=oid,
                    timestamp_ms=int(timestamp_ms) if timestamp_ms is not None else now_ms(),
                    pair_name=entry.pair_name,
                    base_asset=entry.base_asset,
                    is_buy=True,
                    exec_px_usdc=px_str,
                    exec_sz_base=sz_str,
                    raw_fee_amount="0",
                    raw_fee_token=entry.base_asset,
                )
            except Exception as exc:
                logger.warning("即時買い約定時の税務記録警告: %s", exc)

        deadman_res: Optional[Dict[str, Any]] = None
        if err_msg is None and not is_filled:
            deadman_res = self.schedule_cancel_deadman(
                cancel_time_ms=(int(timestamp_ms) if timestamp_ms is not None else now_ms()) + 4 * 3600 * 1000 + 60_000,
                current_time_ms=timestamp_ms,
            )

        return {
            "status": "error" if err_msg else "ok",
            "error": err_msg,
            "mode": self.execution_mode,
            "coin": entry.api_coin_name,
            "pair_name": entry.pair_name,
            "px_str": px_str,
            "sz_str": sz_str,
            "notional_usdc": float(px_dec * sz_dec),
            "cloid": cloid,
            "oid": oid,
            "filled": is_filled,
            "repeg_attempts": repeg_attempts,
            "nonce": nonce,
            "deadman": deadman_res,
            "raw_response": sdk_resp,
        }

    def place_spot_sell_alo(
        self,
        slot_id: int,
        coin_or_pair: str,
        best_ask: Union[float, str, Decimal],
        best_bid: Optional[Union[float, str, Decimal]] = None,
        raw_sz: Optional[Union[float, str, Decimal]] = None,
        ttl_sec: int = 180,
        cloid_hex: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        v1.2 論点2 (第2層): 停滞スクラッチ撤退時の Maker 売り指値 (SELL_ALO, TTL 180秒) 発注ヘルパー。
        最良売り気配 (Best Ask) に Post-Only (`Alo`) で配置し、万が一スプレッド交差する場合は
        `max(best_ask, best_bid + 1 tick)` にクランプする。
        未約定で TTL 満了または L_eff(t) 割れに至った場合は `execute_atomic_ioc_exit` (`DepthAwareIocPlanner`) へフォールバックする。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        entry = self.assert_spot_only_coin(coin_or_pair)
        balances = self.get_spot_balances()
        actual_total = balances.get(entry.base_asset.upper(), {}).get("total", Decimal("0"))
        target_sz = actual_total if actual_total > 0 else _to_clean_decimal(raw_sz or "0")
        sz_str = floor_size(target_sz, entry.sz_decimals)
        sz_dec = _to_clean_decimal(sz_str)

        ask_dec = _to_clean_decimal(best_ask)
        bid_dec = _to_clean_decimal(best_bid) if best_bid is not None else ask_dec
        tick = compute_tick_size(ask_dec if ask_dec > 0 else bid_dec, entry.sz_decimals)
        safe_ask_dec = max(ask_dec, bid_dec + tick) if bid_dec > 0 else ask_dec
        px_str = round_price(safe_ask_dec, entry.sz_decimals)
        px_dec = _to_clean_decimal(px_str)
        notional_usdc = px_dec * sz_dec

        if sz_dec <= 0 or notional_usdc < Decimal("10.0"):
            return {
                "status": "quarantined_dust",
                "order_type": "SELL_ALO",
                "should_fallback_ioc": False,
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "px_str": px_str,
                "sz_str": sz_str,
                "notional_usdc": float(notional_usdc),
                "ttl_sec": int(ttl_sec),
                "expires_at_ms": ts + int(ttl_sec) * 1000,
            }

        cloid = cloid_hex if cloid_hex else generate_cloid()
        nonce = self.nonce_manager.next_nonce()

        if self.execution_mode == "DRY_RUN" and self.exchange is None:
            fake_oid = int(nonce % 1_000_000_000)
            self._active_scratch_sell_orders[int(slot_id)] = {
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "oid": fake_oid,
                "cloid": cloid,
                "created_at_ms": ts,
            }
            deadman_res = self.schedule_cancel_deadman(
                cancel_time_ms=ts + int(ttl_sec) * 1000 + 60_000,
                current_time_ms=ts,
            )
            return {
                "status": "ok",
                "mode": "DRY_RUN",
                "order_type": "SELL_ALO",
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "px_str": px_str,
                "sz_str": sz_str,
                "notional_usdc": float(notional_usdc),
                "cloid": cloid,
                "oid": fake_oid,
                "filled": False,
                "ttl_sec": int(ttl_sec),
                "expires_at_ms": ts + int(ttl_sec) * 1000,
                "fallback_planner": "DepthAwareIocPlanner",
                "nonce": nonce,
                "deadman": deadman_res,
            }

        if self.exchange is None:
            raise RuntimeError("Exchange クライアントが未初期化です。")

        sdk_resp = self.exchange.order(
            name=entry.api_coin_name,
            is_buy=False,
            sz=float(sz_str),
            limit_px=float(px_str),
            order_type={"limit": {"tif": "Alo"}},
            reduce_only=True,
            cloid=make_cloid(cloid),
        )
        oid, is_filled, err_msg = self._extract_order_status(sdk_resp)
        deadman_res_live: Optional[Dict[str, Any]] = None
        if err_msg is None and not is_filled:
            self._active_scratch_sell_orders[int(slot_id)] = {
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "oid": oid,
                "cloid": cloid,
                "created_at_ms": ts,
            }
            deadman_res_live = self.schedule_cancel_deadman(
                cancel_time_ms=ts + int(ttl_sec) * 1000 + 60_000,
                current_time_ms=ts,
            )
        elif is_filled:
            self._active_scratch_sell_orders.pop(int(slot_id), None)
        return {
            "status": "error" if err_msg else "ok",
            "error": err_msg,
            "mode": self.execution_mode,
            "order_type": "SELL_ALO",
            "coin": entry.api_coin_name,
            "pair_name": entry.pair_name,
            "px_str": px_str,
            "sz_str": sz_str,
            "notional_usdc": float(notional_usdc),
            "cloid": cloid,
            "oid": oid,
            "filled": is_filled,
            "ttl_sec": int(ttl_sec),
            "expires_at_ms": ts + int(ttl_sec) * 1000,
            "fallback_planner": "DepthAwareIocPlanner",
            "nonce": nonce,
            "deadman": deadman_res_live,
            "raw_response": sdk_resp,
        }

    def schedule_cancel_deadman(
        self,
        cancel_time_ms: Optional[int] = None,
        max_daily_calls: int = 8,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Hyperliquid ネイティブ `scheduleCancel` (Dead Man's Switch) イベント駆動型安全ラッパー:
        - 1日最大8回 (`max_daily_calls=8`, `ActionBudgetController` 連動) の上限を厳守し、
          新規 `BUY_ALO` / `SELL_ALO` 配置直後（および全指値解消時のクリア `None`）のみ呼び出す。
        - `cancel_time_ms` 指定時は必ず現在UTCミリ秒 + 60,000ms 以上を保証する。
        """
        from src.utils import jst_date_str

        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        day_str = jst_date_str(ts)
        if self._schedule_cancel_day_str != day_str:
            self._schedule_cancel_day_str = day_str
            self._schedule_cancel_daily_count = 0
            self.action_budget.schedule_cancel_used_today = 0

        eff_cap = min(int(max_daily_calls), int(self.action_budget.MAX_SCHEDULE_CANCEL_DAILY))
        if self._schedule_cancel_daily_count >= eff_cap or not self.action_budget.can_use_schedule_cancel(eff_cap):
            return {
                "scheduled": False,
                "cancel_time_ms": cancel_time_ms,
                "daily_calls": self._schedule_cancel_daily_count,
                "reason": "DAILY_SCHEDULE_CANCEL_LIMIT_REACHED",
            }

        target_ms = int(cancel_time_ms) if cancel_time_ms is not None else None
        if target_ms is not None and target_ms < ts + 60_000:
            target_ms = ts + 60_000

        if self.execution_mode == "DRY_RUN" and self.exchange is None:
            self._schedule_cancel_daily_count += 1
            self.action_budget.record_schedule_cancel_use()
            self._active_deadman_cancel_time_ms = target_ms
            return {
                "scheduled": True,
                "mode": "DRY_RUN",
                "cancel_time_ms": target_ms,
                "daily_calls": self._schedule_cancel_daily_count,
            }

        if self.exchange is None or not hasattr(self.exchange, "schedule_cancel"):
            return {
                "scheduled": False,
                "cancel_time_ms": target_ms,
                "daily_calls": self._schedule_cancel_daily_count,
                "reason": "EXCHANGE_CLIENT_NO_SCHEDULE_CANCEL",
            }

        try:
            self.nonce_manager.next_nonce()
            resp = self.exchange.schedule_cancel(target_ms)
            self._schedule_cancel_daily_count += 1
            self.action_budget.record_schedule_cancel_use()
            self._active_deadman_cancel_time_ms = target_ms
            return {
                "scheduled": True,
                "cancel_time_ms": target_ms,
                "daily_calls": self._schedule_cancel_daily_count,
                "response": resp,
            }
        except Exception as exc:
            logger.debug("schedule_cancel 呼び出しスキップ (ローカルTTL管理継続): %s", exc)
            return {
                "scheduled": False,
                "cancel_time_ms": target_ms,
                "daily_calls": self._schedule_cancel_daily_count,
                "reason": f"FALLBACK_LOCAL_TTL:{type(exc).__name__}",
            }

    def clear_deadman_if_no_pending_orders(
        self,
        has_other_pending_orders: bool = False,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        指値が約定して `OPEN_PROTECTED` に移行した際、またはローカルキャンセル完了時に、
        他のスロットに未約定指値が残っていなければ `schedule_cancel_deadman(cancel_time_ms=None)` で予約をクリアする。
        """
        if has_other_pending_orders:
            return {
                "cleared": False,
                "reason": "OTHER_SLOT_STILL_PENDING",
                "active_deadman_cancel_time_ms": self._active_deadman_cancel_time_ms,
            }
        if self._active_deadman_cancel_time_ms is None:
            return {
                "cleared": False,
                "reason": "NO_ACTIVE_DEADMAN_RESERVATION",
                "active_deadman_cancel_time_ms": None,
            }
        res = self.schedule_cancel_deadman(cancel_time_ms=None, current_time_ms=current_time_ms)
        self._active_deadman_cancel_time_ms = None
        return {
            "cleared": bool(res.get("scheduled", False)),
            "schedule_cancel_result": res,
            "active_deadman_cancel_time_ms": self._active_deadman_cancel_time_ms,
        }

    def cancel_spot_order(
        self,
        coin_or_pair: str,
        oid: Optional[int] = None,
        cloid_hex: Optional[str] = None,
        slot_id: Optional[int] = None,
        partial_filled_sz: Optional[Union[float, str, Decimal]] = None,
        reference_px: Optional[Union[float, str, Decimal]] = None,
        trigger_dust_recovery_if_sub10: bool = True,
    ) -> Dict[str, Any]:
        """
        Spot 未約定注文を `oid` または `cloid` でキャンセルする。
        `ENTRY_PENDING` 注文のキャンセル時（4h有効期限切れ、逆選択ガード、親子インターロック等）に
        一部約定（Partial Fill）が発生していた場合は、約定済みトークン評価額を判定し：
          - `>= 10.0 USDC`: `OPEN_PROTECTED`（`INITIAL_RISK`, `sl_px`/`tp_px` 引き継ぎ）へ遷移
          - `0 < 評価額 < 10.0 USDC`: スロットを `IDLE` に戻し、`dust_quarantine` 隔離 ＆ `Top-Up & Dump` 自己復旧を実行
          - `0 USDC`: スロットを `IDLE` に戻す
        """
        entry = self.assert_spot_only_coin(coin_or_pair)
        nonce = self.nonce_manager.next_nonce()
        if slot_id is not None:
            self._active_scratch_sell_orders.pop(int(slot_id), None)

        slot_before: Dict[str, Any] = {}
        if slot_id is not None and self.db is not None:
            slot_before = self.db.get_slot_state(int(slot_id))

        resp: Optional[Dict[str, Any]] = None
        if not (self.execution_mode == "DRY_RUN" and self.exchange is None):
            if self.exchange is None:
                raise RuntimeError("Exchange クライアントが未初期化です。")
            if oid is not None:
                resp = self.exchange.cancel(name=entry.api_coin_name, oid=int(oid))
            elif cloid_hex is not None:
                resp = self.exchange.cancel_by_cloid(
                    name=entry.api_coin_name, cloid=make_cloid(cloid_hex)
                )
            else:
                raise ValueError("キャンセルには oid または cloid_hex のいずれかが必要です。")

        post_cancel_state = "IDLE"
        partial_qty_float = 0.0
        partial_usdc_float = 0.0
        dust_recovery_result: Optional[Dict[str, Any]] = None

        if slot_id is not None and self.coordinator is not None:
            sid = int(slot_id)
            was_entry_pending = str(slot_before.get("state", "")) == SlotState.ENTRY_PENDING.value

            # 部分約定数量の算出 (明示指定 partial_filled_sz または 発注前残高からの増加分 delta_qty)
            delta_qty = Decimal("0")
            if partial_filled_sz is not None:
                delta_qty = max(Decimal("0"), _to_clean_decimal(partial_filled_sz))
            elif was_entry_pending:
                try:
                    post_bals = self.get_spot_balances()
                    post_tot = post_bals.get(entry.base_asset.upper(), {}).get("total", Decimal("0"))
                    pre_key = (sid, entry.base_asset.upper())
                    if pre_key in self._pre_order_base_balances:
                        pre_tot = self._pre_order_base_balances.pop(pre_key)
                        delta_qty = max(Decimal("0"), post_tot - pre_tot)
                except Exception:
                    delta_qty = Decimal("0")

            ref_px_f = float(
                reference_px
                or slot_before.get("entry_px")
                or entry.spot_mid_px
                or 0.0
            )
            floored_delta_str = floor_size(delta_qty, entry.sz_decimals) if delta_qty > 0 else "0"
            floored_delta_dec = _to_clean_decimal(floored_delta_str)
            est_partial_usdc = float(delta_qty) * ref_px_f if ref_px_f > 0 else 0.0
            partial_qty_float = float(floored_delta_dec if floored_delta_dec > 0 else delta_qty)
            partial_usdc_float = round(est_partial_usdc, 4)

            if was_entry_pending and est_partial_usdc >= 10.0 and floored_delta_dec > Decimal("0"):
                # >= 10.0 USDC の部分約定: OPEN_PROTECTED へ引き継ぎ (sl_px / tp_px 維持)
                self.coordinator.bind_order_response(
                    slot_id=sid,
                    cloid=str(slot_before.get("active_cloid") or cloid_hex or ""),
                    oid=int(oid) if oid is not None else slot_before.get("active_oid"),
                    filled=True,
                    filled_sz=float(floored_delta_dec),
                    avg_px=ref_px_f,
                )
                post_cancel_state = SlotState.OPEN_PROTECTED.value
            elif was_entry_pending and Decimal("0") < delta_qty and 0.0 < est_partial_usdc < 10.0:
                # < 10.0 USDC の売却不能端数: スロットを IDLE に戻し、Top-Up & Dump で回収
                self.coordinator.reset_slot_to_idle(sid)
                post_cancel_state = "IDLE_DUST_QUARANTINED"
                if self.db is not None:
                    q_prev = self.db.get_dust_quarantine(entry.base_asset)
                    prev_att = int(q_prev.get("recovery_attempts", 0)) if q_prev else 0
                    self.db.upsert_dust_quarantine(
                        base_asset=entry.base_asset,
                        coin_pair=entry.pair_name,
                        quarantined_qty=float(delta_qty),
                        estimated_usdc_val=est_partial_usdc,
                        recovery_attempts=prev_att,
                        last_attempt_ms=now_ms(),
                        status="QUARANTINED",
                    )
                if trigger_dust_recovery_if_sub10 and ref_px_f > 0:
                    dust_recovery_result = self.recover_dust_top_up_and_dump(
                        coin_or_pair=entry.pair_name,
                        best_bid=ref_px_f,
                        best_ask=ref_px_f * 1.0005,
                        wait_after_top_up_sec=0.05 if self.execution_mode == "DRY_RUN" else 0.6,
                    )
                    if dust_recovery_result.get("recovered"):
                        post_cancel_state = "IDLE_DUST_RECOVERED"
            else:
                self.coordinator.reset_slot_to_idle(sid)
                post_cancel_state = SlotState.IDLE.value

        return {
            "status": "ok",
            "mode": "DRY_RUN" if (self.execution_mode == "DRY_RUN" and self.exchange is None) else self.execution_mode,
            "coin": entry.api_coin_name,
            "pair_name": entry.pair_name,
            "oid": oid,
            "cloid": cloid_hex,
            "nonce": nonce,
            "post_cancel_state": post_cancel_state,
            "partial_fill_qty": partial_qty_float,
            "partial_fill_usdc": partial_usdc_float,
            "dust_recovery_result": dust_recovery_result,
            "raw_response": resp,
        }

    def execute_atomic_ioc_exit(
        self,
        slot_id: int,
        coin_or_pair: str,
        best_bid: Union[float, str, Decimal],
        spot_clearinghouse_state: Optional[Dict[str, Any]] = None,
        fallback_sz: Optional[Union[float, str, Decimal]] = None,
        cloid_hex: Optional[str] = None,
        timestamp_ms: Optional[int] = None,
        l2_bids: Optional[List[Dict[str, Any]]] = None,
        perp_mid_px: float = 0.0,
        spot_mid_px: float = 0.0,
        is_emergency: bool = True,
        quarantine_sub10: bool = True,
    ) -> Dict[str, Any]:
        """
        方式B (hold == 0 維持) に基づく1ステップ IOC 即時決済売り (v1.1 DepthAwareIocPlanner 統合版)。
        - 売却数量は必ず直前の `spot_clearinghouse_state` の `total` 実残高を参照して
          `floor_size(total, sz_decimals)` で切り捨て、買い手数料控除による残高不足エラーを100%防ぐ。
        - 想定元本 `< 10.0 USDC` の場合は API 拒絶ループを防ぐため即座に `dust_quarantine` へ隔離しスロットを `IDLE` へ解放。
        - L2 板情報が与えられた場合は 20段スイープの `P_clear`/`P_vwap` 及び `< 11.2 USDC` 端数防止カラー拡張を適用。
        - 遷移前に `EXITING_ATOMIC` (静止期間 `now + 2500ms`) を先行コミットする。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        entry = self.assert_spot_only_coin(coin_or_pair)
        balances = self.get_spot_balances(spot_clearinghouse_state)
        asset_bal = balances.get(entry.base_asset.upper(), {})
        actual_total = asset_bal.get("total", Decimal("0"))
        actual_hold = asset_bal.get("hold", Decimal("0"))
        pre_cancelled_scratch = False

        # 1) スクラッチ撤退 (SELL_ALO) の未約定指値が残存している場合は hold 拘束を即時解放するため最優先キャンセル
        active_scratch = self._active_scratch_sell_orders.pop(int(slot_id), None)
        if active_scratch is not None:
            pre_cancelled_scratch = True
            if self.exchange is not None:
                try:
                    sc_oid = active_scratch.get("oid")
                    sc_cloid = active_scratch.get("cloid")
                    if sc_oid is not None:
                        self.exchange.cancel(name=entry.api_coin_name, oid=int(sc_oid))
                    elif sc_cloid is not None and hasattr(self.exchange, "cancel_by_cloid"):
                        self.exchange.cancel_by_cloid(name=entry.api_coin_name, cloid=make_cloid(str(sc_cloid)))
                except Exception as exc:
                    logger.warning("IOC決済前のSELL_ALOスクラッチ注文キャンセル試行エラー: %s", exc)

        # 2) 万が一 hold > 0 の拘束がある場合は、実残高 total を優先しつつ既存注文キャンセルを試行
        if actual_hold > 0 and self.exchange is not None and self.info is not None:
            try:
                open_orders = self.info.open_orders(self.main_address) or []
                for oo in open_orders:
                    if self.are_symbols_equivalent(str(oo.get("coin", "")), entry.pair_name):
                        self.exchange.cancel(name=entry.api_coin_name, oid=int(oo["oid"]))
                        pre_cancelled_scratch = True
            except Exception as exc:
                logger.warning("IOC決済前の拘束注文キャンセル試行エラー: %s", exc)

        raw_target_sz = actual_total if actual_total > 0 else _to_clean_decimal(fallback_sz or "0")
        sz_str = floor_size(raw_target_sz, entry.sz_decimals)
        sz_dec = _to_clean_decimal(sz_str)
        if sz_dec <= 0:
            raise OrderValidationError(
                f"{entry.base_asset} の売却可能実残高が0です (actual_total={actual_total}, sz_decimals={entry.sz_decimals})。"
            )

        bid_dec = _to_clean_decimal(best_bid)
        if bid_dec <= 0:
            raise OrderValidationError(f"不正な best_bid 価格です: {best_bid}")

        ioc_plan = self.ioc_planner.plan_exit(
            actual_balance_total=raw_target_sz,
            sz_decimals=entry.sz_decimals,
            best_bid=bid_dec,
            l2_bids=l2_bids,
            perp_mid_px=perp_mid_px,
            spot_mid_px=spot_mid_px if spot_mid_px > 0 else float(bid_dec),
            is_emergency=is_emergency,
        )

        if quarantine_sub10 and ioc_plan.get("action") == "QUARANTINE_DUST_ONLY":
            if self.db is not None:
                try:
                    self.db.upsert_dust_quarantine(
                        base_asset=entry.base_asset,
                        coin_pair=entry.pair_name,
                        quarantined_qty=float(sz_dec),
                        estimated_usdc_val=float(sz_dec * bid_dec),
                        status="QUARANTINED",
                    )
                except Exception as exc:
                    logger.warning("IOC決済前10USDC未満端数隔離記録エラー: %s", exc)
            if self.coordinator is not None:
                try:
                    self.coordinator.reset_slot_to_idle(
                        slot_id=slot_id,
                        timestamp_ms=ts,
                    )
                except Exception as exc:
                    logger.warning("IOC決済前10USDC未満スロットIDLE解放警告: %s", exc)
            return {
                "status": "ok",
                "action": "QUARANTINE_DUST_ONLY",
                "quarantined_dust": True,
                "mode": self.execution_mode,
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "sz_str": sz_str,
                "min_sell_px_str": "0",
                "cloid": cloid_hex or "",
                "oid": None,
                "filled": False,
                "plan": ioc_plan,
            }

        if l2_bids is not None and ioc_plan.get("min_sell_px_str") and ioc_plan["min_sell_px_str"] != "0":
            min_sell_px_str = str(ioc_plan["min_sell_px_str"])
        else:
            min_sell_px_str = round_price(
                bid_dec * self.IOC_SELL_SLIPPAGE_FACTOR,
                entry.sz_decimals,
            )
        cloid = cloid_hex if cloid_hex else generate_cloid()
        nonce = self.nonce_manager.next_nonce()

        if self.coordinator is not None:
            self.coordinator.transition_to_exiting_atomic(
                slot_id=slot_id,
                exit_cloid=cloid,
                quiescence_ms=ConcurrencyStateCoordinator.QUIESCENCE_EXITING_ATOMIC_MS,
                timestamp_ms=ts,
            )
        self._pre_order_base_balances.pop((int(slot_id), entry.base_asset.upper()), None)

        if self.execution_mode == "DRY_RUN" and self.exchange is None:
            fake_oid = int(nonce % 1_000_000_000)
            if self.coordinator is not None:
                self.coordinator.bind_order_response(
                    slot_id=slot_id,
                    cloid=cloid,
                    oid=fake_oid,
                    filled=True,
                    filled_sz=float(sz_str),
                    avg_px=float(bid_dec),
                    is_exit_order=True,
                    timestamp_ms=ts,
                )
            if self.tax_engine is not None:
                try:
                    self.tax_engine.process_spot_fill(
                        hl_tid=9_000_000_000_000 + fake_oid,
                        hl_oid=fake_oid,
                        timestamp_ms=ts,
                        pair_name=entry.pair_name,
                        base_asset=entry.base_asset,
                        is_buy=False,
                        exec_px_usdc=str(bid_dec),
                        exec_sz_base=sz_str,
                        raw_fee_amount=str(sz_dec * bid_dec * Decimal("0.0007")),
                        raw_fee_token="USDC",
                    )
                except Exception as exc:
                    logger.warning("DRY_RUN IOC決済時の税務記録警告: %s", exc)
            return {
                "status": "ok",
                "mode": "DRY_RUN",
                "coin": entry.api_coin_name,
                "pair_name": entry.pair_name,
                "sz_str": sz_str,
                "min_sell_px_str": min_sell_px_str,
                "cloid": cloid,
                "oid": fake_oid,
                "filled": True,
                "nonce": nonce,
                "pre_cancelled_scratch_order": pre_cancelled_scratch,
            }

        if self.exchange is None:
            raise RuntimeError("Exchange クライアントが未初期化です。")

        sdk_resp = self.exchange.order(
            name=entry.api_coin_name,
            is_buy=False,
            sz=float(sz_str),
            limit_px=float(min_sell_px_str),
            order_type={"limit": {"tif": "Ioc"}},
            reduce_only=False,
            cloid=make_cloid(cloid),
        )
        oid, is_filled, err_msg = self._extract_order_status(sdk_resp)

        if self.coordinator is not None:
            self.coordinator.bind_order_response(
                slot_id=slot_id,
                cloid=cloid,
                oid=oid,
                filled=is_filled or (err_msg is None),
                filled_sz=float(sz_str),
                avg_px=float(min_sell_px_str),
                rejected=bool(err_msg is not None),
                is_exit_order=True,
                timestamp_ms=ts,
            )

        if (is_filled or err_msg is None) and self.tax_engine is not None:
            try:
                syn_tid = 9_000_000_000_000 + int(oid or (nonce % 1_000_000_000))
                exec_px_str = str(bid_dec)
                statuses = (sdk_resp.get("response", {}).get("data", {}).get("statuses") or []) if isinstance(sdk_resp, dict) else []
                if statuses and isinstance(statuses[0], dict) and "filled" in statuses[0]:
                    exec_px_str = str(statuses[0]["filled"].get("avgPx") or bid_dec)
                est_fee_usdc = sz_dec * _to_clean_decimal(exec_px_str) * Decimal("0.0007")
                self.tax_engine.process_spot_fill(
                    hl_tid=syn_tid,
                    hl_oid=oid,
                    timestamp_ms=ts,
                    pair_name=entry.pair_name,
                    base_asset=entry.base_asset,
                    is_buy=False,
                    exec_px_usdc=exec_px_str,
                    exec_sz_base=sz_str,
                    raw_fee_amount=str(est_fee_usdc),
                    raw_fee_token="USDC",
                )
            except Exception as exc:
                logger.warning("IOC決済時の税務記録警告: %s", exc)

        residual_sz = max(Decimal("0"), raw_target_sz - sz_dec)
        residual_notional = residual_sz * bid_dec
        quarantined_residual = False
        if Decimal("0") < residual_notional < Decimal("10.5") and self.db is not None:
            try:
                self.db.upsert_dust_quarantine(
                    base_asset=entry.base_asset,
                    coin_pair=entry.pair_name,
                    quarantined_qty=float(residual_sz),
                    estimated_usdc_val=float(residual_notional),
                    status="QUARANTINED",
                )
                quarantined_residual = True
            except Exception as exc:
                logger.warning("IOC決済後の端数残余隔離エラー: %s", exc)

        return {
            "status": "error" if err_msg else "ok",
            "error": err_msg,
            "mode": self.execution_mode,
            "coin": entry.api_coin_name,
            "pair_name": entry.pair_name,
            "sz_str": sz_str,
            "min_sell_px_str": min_sell_px_str,
            "cloid": cloid,
            "oid": oid,
            "filled": is_filled,
            "nonce": nonce,
            "pre_cancelled_scratch_order": pre_cancelled_scratch,
            "quarantined_residual_dust": quarantined_residual,
            "plan": ioc_plan,
            "raw_response": sdk_resp,
        }

    # ==========================================================================
    # 7. 10 USDC未満端数の「Top-Up & Dump (11 USDC買い増し＋全量一括売却)」自己復旧
    # ==========================================================================
    def recover_dust_top_up_and_dump(
        self,
        coin_or_pair: str,
        best_bid: Union[float, str, Decimal],
        best_ask: Union[float, str, Decimal],
        top_up_usdc: Union[float, str, Decimal] = Decimal("11.0"),
        min_free_usdc_required: Union[float, str, Decimal] = Decimal("15.0"),
        wait_after_top_up_sec: float = 0.6,
        max_attempts: int = 3,
    ) -> Dict[str, Any]:
        """
        10.0 USDC 未満の売却不能な端数トークンに対する自己復旧ルーチン:
          1. システム状態を `DUST_RECOVERY_IN_PROGRESS` (静止期間 `now + 5000ms`) へロック
          2. 11.0 USDC 相当の数量を `Ioc` で買い増し (Top-Up)
          3. L1ブロック確定のため 600ms (`wait_after_top_up_sec`) 待機
          4. `spot_clearinghouse_state` を再取得し、合算された `total` 実残高全量を `Ioc` で一括売却 (Dump)
          5. `dust_quarantine` を `'RECOVERED'` へ更新し、システム状態を `'NORMAL'` へ復帰
        """
        entry = self.assert_spot_only_coin(coin_or_pair)
        bid_dec = _to_clean_decimal(best_bid)
        ask_dec = _to_clean_decimal(best_ask)
        target_top_up = _to_clean_decimal(top_up_usdc)
        min_free_usdc = _to_clean_decimal(min_free_usdc_required)

        if bid_dec <= 0 or ask_dec <= 0 or ask_dec < bid_dec:
            return {"recovered": False, "reason": "INVALID_BBO_PRICES"}

        # アクティブスロット保護ガード: OPEN_PROTECTED / ENTRY_PENDING 等の正常スロットで管理中の銘柄は端数復旧対象から100%除外
        if self.db is not None:
            for sid, s_row in self.db.get_all_slots().items():
                s_state = str(s_row.get("state", "IDLE")).strip().upper()
                s_base = str(s_row.get("base_asset") or "").strip().upper()
                s_coin = str(s_row.get("coin") or "").strip().upper()
                if s_state != SlotState.IDLE.value and (
                    s_base == entry.base_asset.upper() or s_coin == entry.pair_name.upper()
                ):
                    return {
                        "recovered": False,
                        "reason": f"ACTIVE_SLOT_PROTECTED(slot={sid},state={s_state})",
                        "slot_id": sid,
                        "slot_state": s_state,
                    }

        # 既存の試行回数確認
        prev_attempts = 0
        if self.db is not None:
            q_row = self.db.get_dust_quarantine(entry.base_asset)
            if q_row is not None:
                prev_attempts = int(q_row.get("recovery_attempts", 0))
                if prev_attempts >= int(max_attempts):
                    return {
                        "recovered": False,
                        "reason": "MAX_RECOVERY_ATTEMPTS_EXCEEDED",
                        "recovery_attempts": prev_attempts,
                    }

        balances_pre = self.get_spot_balances()
        free_usdc = balances_pre.get("USDC", {}).get("free", Decimal("0"))
        initial_dust_qty = balances_pre.get(entry.base_asset.upper(), {}).get("total", Decimal("0"))
        est_dust_val = initial_dust_qty * bid_dec

        if initial_dust_qty <= 0 or est_dust_val >= Decimal("10.0"):
            return {
                "recovered": False,
                "reason": "NOT_ELIGIBLE_DUST_BALANCE",
                "initial_qty": float(initial_dust_qty),
                "estimated_usdc_val": float(est_dust_val),
            }

        if free_usdc < min_free_usdc:
            return {
                "recovered": False,
                "reason": "INSUFFICIENT_FREE_USDC_FOR_TOP_UP",
                "free_usdc": float(free_usdc),
            }

        # Top-Up 数量算出: floor_size 切り捨て後も確実に >= 11.0 USDC となる最小数量を求める
        sz_step = Decimal(10) ** (-max(0, entry.sz_decimals))
        raw_buy_sz = target_top_up / ask_dec
        buy_sz_str = floor_size(raw_buy_sz, entry.sz_decimals)
        buy_sz_dec = _to_clean_decimal(buy_sz_str)
        if buy_sz_dec * ask_dec < target_top_up:
            buy_sz_dec += sz_step
            buy_sz_str = format_decimal_plain(buy_sz_dec)

        buy_limit_px_str = round_price(ask_dec * self.IOC_BUY_SLIPPAGE_FACTOR, entry.sz_decimals)
        sell_limit_px_str = round_price(bid_dec * self.IOC_SELL_SLIPPAGE_FACTOR, entry.sz_decimals)

        if self.coordinator is not None:
            self.coordinator.enter_dust_recovery_mode(
                quiescence_ms=ConcurrencyStateCoordinator.QUIESCENCE_DUST_RECOVERY_MS
            )

        try:
            top_up_cloid = generate_cloid()
            dump_cloid = generate_cloid()

            if self.execution_mode == "DRY_RUN" and self.exchange is None:
                if wait_after_top_up_sec > 0:
                    time.sleep(min(wait_after_top_up_sec, 0.05))
                combined_qty = initial_dust_qty + buy_sz_dec
                dump_sz_str = floor_size(combined_qty, entry.sz_decimals)
                if self.db is not None:
                    self.db.upsert_dust_quarantine(
                        base_asset=entry.base_asset,
                        coin_pair=entry.pair_name,
                        quarantined_qty=0.0,
                        estimated_usdc_val=0.0,
                        recovery_attempts=prev_attempts + 1,
                        last_attempt_ms=now_ms(),
                        status="RECOVERED",
                    )
                return {
                    "recovered": True,
                    "mode": "DRY_RUN",
                    "base_asset": entry.base_asset,
                    "pair_name": entry.pair_name,
                    "initial_dust_qty": float(initial_dust_qty),
                    "top_up_sz_str": buy_sz_str,
                    "top_up_notional_usdc": float(buy_sz_dec * ask_dec),
                    "dump_sz_str": dump_sz_str,
                    "top_up_cloid": top_up_cloid,
                    "dump_cloid": dump_cloid,
                }

            if self.exchange is None:
                raise RuntimeError("Exchange クライアントが未初期化です。")

            # Step 1: 11.0 USDC 相当の IOC 買い増し (Top-Up)
            self.nonce_manager.next_nonce()
            buy_resp = self.exchange.order(
                name=entry.api_coin_name,
                is_buy=True,
                sz=float(buy_sz_str),
                limit_px=float(buy_limit_px_str),
                order_type={"limit": {"tif": "Ioc"}},
                reduce_only=False,
                cloid=make_cloid(top_up_cloid),
            )
            _, buy_filled, buy_err = self._extract_order_status(buy_resp)
            if buy_err is not None or not buy_filled:
                if self.db is not None:
                    self.db.upsert_dust_quarantine(
                        base_asset=entry.base_asset,
                        coin_pair=entry.pair_name,
                        quarantined_qty=float(initial_dust_qty),
                        estimated_usdc_val=float(est_dust_val),
                        recovery_attempts=prev_attempts + 1,
                        last_attempt_ms=now_ms(),
                        status="QUARANTINED",
                    )
                return {
                    "recovered": False,
                    "reason": f"TOP_UP_FAILED:{buy_err or 'NOT_FILLED'}",
                    "raw_buy_response": buy_resp,
                }

            # Step 2: 600ms 待機 (L1 ブロック生成 & Clearinghouse State 反映待ち)
            if wait_after_top_up_sec > 0:
                time.sleep(wait_after_top_up_sec)

            # Step 3: 最新の実残高 total を取得して全量一括 IOC 売却 (Dump)
            balances_post = self.get_spot_balances()
            combined_total = balances_post.get(entry.base_asset.upper(), {}).get(
                "total", initial_dust_qty + buy_sz_dec
            )
            dump_sz_str = floor_size(combined_total, entry.sz_decimals)
            dump_sz_dec = _to_clean_decimal(dump_sz_str)

            self.nonce_manager.next_nonce()
            sell_resp = self.exchange.order(
                name=entry.api_coin_name,
                is_buy=False,
                sz=float(dump_sz_str),
                limit_px=float(sell_limit_px_str),
                order_type={"limit": {"tif": "Ioc"}},
                reduce_only=False,
                cloid=make_cloid(dump_cloid),
            )
            _, sell_filled, sell_err = self._extract_order_status(sell_resp)
            recovered_ok = bool(sell_err is None and sell_filled and dump_sz_dec > 0)

            if self.db is not None:
                self.db.upsert_dust_quarantine(
                    base_asset=entry.base_asset,
                    coin_pair=entry.pair_name,
                    quarantined_qty=0.0 if recovered_ok else float(combined_total),
                    estimated_usdc_val=0.0 if recovered_ok else float(combined_total * bid_dec),
                    recovery_attempts=prev_attempts + 1,
                    last_attempt_ms=now_ms(),
                    status="RECOVERED" if recovered_ok else "QUARANTINED",
                )

            return {
                "recovered": recovered_ok,
                "reason": "OK" if recovered_ok else f"DUMP_FAILED:{sell_err or 'NOT_FILLED'}",
                "mode": self.execution_mode,
                "base_asset": entry.base_asset,
                "pair_name": entry.pair_name,
                "initial_dust_qty": float(initial_dust_qty),
                "top_up_sz_str": buy_sz_str,
                "top_up_notional_usdc": float(buy_sz_dec * ask_dec),
                "dump_sz_str": dump_sz_str,
                "top_up_cloid": top_up_cloid,
                "dump_cloid": dump_cloid,
                "raw_buy_response": buy_resp,
                "raw_sell_response": sell_resp,
            }
        finally:
            if self.coordinator is not None:
                self.coordinator.exit_dust_recovery_mode()
