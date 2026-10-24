"""
HL AI Trader v1 — 3-Tier Concurrent Main Daemon & Campaign Scheduler (src/main.py)

実装機能 (ARCHITECTURE.md Section 2, 3, 5, 6 ＆ Phase 4 仕様準拠):
1. 200ms 高速ガーディアンループ (`run_200ms_guardian_tick`):
   - 方式B (`hold == 0` 維持) による SL/TP 着弾時の1ステップ IOC 即時決済
   - 4段階ダイナミック・トレーリングストップ:
     ①初期SL ➔ ②含み益 +1.20%(大型)/+1.80%(高ボラ) で `Entry + 0.15%` 建値ロック (`FREEROLL_LOCKED`)
     ➔ ③ATRトレーリング ➔ ④過熱時タイトトレーリング
   - Perp清算カスケード緊急脱出 (WebSocket 3ティック=600ms連続で `delta_OI_15m <= -4.5%` & `premium <= -0.20%` & `Spot Mid > Perp Mark` 検知時に即時IOC全決済)
   - 親子スロット連動インターロック (`Slot 1 Bid <= SL_1 * 1.0025` で `Slot 2 ENTRY_PENDING` 即時キャンセル)
   - 事後リスクバジェット再計算 (Slot 1 マイナス決済時に Slot 2 の SL 引き上げまたは即時 IOC 決済)
2. 15秒 高速制御ループ (`run_15s_control_tick`):
   - Webダッシュボード遠隔操作キュー (`PAUSE`, `RESUME`, `CLEAR_PENDING_BUYS`, `EMERGENCY_LIQUIDATE_ALL`) の即時実行
   - Fencing Token + 静止期間ガード付き 3者照合 (Local DB vs Open Orders vs Spot Balances)
   - 4時間未約定買い指値のローカルタイムスタンプ失効キャンセル (`expiresAfter` ペナルティ回避)
   - 10 USDC未満隔離端数の `Top-Up & Dump` 自己復旧
   - 多層価格サニティフィルタ・総資産算出 (`Total_USDC` 基準)・L1〜L5 サーキットブレーカー評価・USDC/JPYレート更新
3. 15分 レーダー＆AI判定ループ (`run_15m_ai_radar_tick`):
   - `spot_meta_and_asset_ctxs` 動的辞書更新 ➔ 7段階マイクロストラクチャフィルタ ➔ 脱バイアスAI判定 ➔ Single-Bullet `Alo` 発注
4. 運用期限スケジューラ (`evaluate_campaign_schedule`):
   - Phase 1 (`2027-07-08 22:00 JST` 新規凍結、`2027-07-09 00:00 JST` 全決済)、24h休止、Phase 2 (`2027-07-10` 〜 `2027-12-10 JST`) 自動制御
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_CEILING, ROUND_DOWN
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.dont_write_bytecode = True
_ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState, SystemMode, TrailingStage
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import ActionBudgetController, HyperliquidExchangeWrapper
from src.radar import (
    LARGE_CAP_PAIRS,
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
from src.utils import (
    SYSTEM_POWER_STATUS,
    UsdcJpyRateFetcher,
    WindowsHighResTimer,
    WindowsSingleInstanceGuard,
    check_ups_power_critical,
    enable_process_extension_point_mitigation,
    get_secret,
    install_egress_domain_whitelist_guard,
    load_safe_dotenv,
    now_jst,
    now_ms,
    prevent_windows_sleep,
    purge_dangerous_environment_variables,
    register_windows_shutdown_handlers,
    round_price,
    verify_code_integrity_seal,
)
from src.ws_manager import HyperliquidWSManager

logger = logging.getLogger("hl_main_daemon")

JST = timezone(timedelta(hours=9))
BASE_DIR = Path(__file__).resolve().parent.parent


def _parse_iso_jst(iso_str: str) -> datetime:
    dt = datetime.fromisoformat(iso_str.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return dt.replace(tzinfo=JST)
    return dt.astimezone(JST)


class HLTraderDaemon:
    """
    HL AI Trader v1 の3並列ループ（200ms Guardian / 15s Control / 15m AI Radar）および
    キャンペーン期限自動決済を統括するメインデーモン。
    """

    ORDER_EXPIRY_MS = 4 * 3_600_000  # 4時間ローカル失効
    CASCADE_REQUIRED_TICKS = 3       # WebSocket 3ティック (600ms) 連続検知
    MAX_DAILY_TRADES = 4             # L1 日次新規トレード上限 (4回/日)
    MAX_FINALIZED_EXIT_KEYS = 1000   # メモリ上限ガード

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        coordinator: Optional[ConcurrencyStateCoordinator] = None,
        tax_engine: Optional[HyperliquidTaxEngine] = None,
        exchange_wrapper: Optional[HyperliquidExchangeWrapper] = None,
        ws_manager: Optional[HyperliquidWSManager] = None,
        radar: Optional[MarketRadarAndFilter] = None,
        ai_brain: Optional[DebiasedAIBrain] = None,
        risk_guard: Optional[RiskAndCircuitBreakerEngine] = None,
        rate_fetcher: Optional[UsdcJpyRateFetcher] = None,
        dashboard_service: Optional[Any] = None,
        phase1_end_jst: str = "2027-07-09T00:00:00+09:00",
        phase2_start_jst: str = "2027-07-10T00:00:00+09:00",
        phase2_end_jst: str = "2027-12-10T00:00:00+09:00",
        pre_deadline_freeze_hours: float = 2.0,
    ) -> None:
        self.db = db or DatabaseManager()
        self.coordinator = coordinator or ConcurrencyStateCoordinator(self.db)
        self.rate_fetcher = rate_fetcher or UsdcJpyRateFetcher(
            db_rate_provider=self.db.get_latest_usdc_jpy_rate
        )
        self.tax_engine = tax_engine or HyperliquidTaxEngine(
            db=self.db, rate_fetcher=self.rate_fetcher
        )
        self.exchange = exchange_wrapper or HyperliquidExchangeWrapper(
            db=self.db,
            coordinator=self.coordinator,
            tax_engine=self.tax_engine,
        )
        self.ws = ws_manager or HyperliquidWSManager(
            main_address=self.exchange.main_address,
            exchange_wrapper=self.exchange,
            tax_engine=self.tax_engine,
        )
        self.radar = radar or MarketRadarAndFilter()
        self.ai_brain = ai_brain or DebiasedAIBrain(db=self.db)
        self.risk_guard = risk_guard or RiskAndCircuitBreakerEngine(
            db=self.db, coordinator=self.coordinator
        )
        self.dashboard_service: Optional[Any] = dashboard_service

        self.phase1_end_dt = _parse_iso_jst(phase1_end_jst)
        self.phase2_start_dt = _parse_iso_jst(phase2_start_jst)
        self.phase2_end_dt = _parse_iso_jst(phase2_end_jst)
        self.pre_deadline_freeze_hours = float(pre_deadline_freeze_hours)

        # 銘柄別のPerp清算カスケード連続ティックカウンタ
        self._cascade_tick_counters: Dict[int, int] = {1: 0, 2: 0}
        self._phase1_liquidated: bool = False
        self._phase2_liquidated: bool = False
        self._finalized_exit_keys: set[str] = set()
        self._last_snapshot_export_bucket: Optional[Tuple[int, int, int, int]] = None
        self._slot_excursions: Dict[int, Dict[str, Any]] = {
            1: {"coin": "", "entry_px": 0.0, "mfe_pct": 0.0, "mae_pct": 0.0},
            2: {"coin": "", "entry_px": 0.0, "mfe_pct": 0.0, "mae_pct": 0.0},
        }

        # WebSocket / REST Backfill 約定イベントをスロット状態遷移へ連動登録
        self.ws.register_fill_callback(self._on_ws_spot_fill)

    def send_discord_notification(self, message: str) -> bool:
        """
        送信直前に `get_secret("DISCORD_WEBHOOK_URL")` でローカル変数へ瞬間復号して通知を送り、
        `os.environ` やインスタンス属性には平文の Webhook URL を保持しない。
        """
        webhook_url = get_secret("DISCORD_WEBHOOK_URL").strip()
        if not webhook_url or not webhook_url.startswith("http"):
            return False
        try:
            resp = self.exchange.http_session.session.post(
                webhook_url,
                json={"content": str(message or "")[:1900]},
                timeout=5.0,
            )
            return 200 <= resp.status_code < 300
        except Exception:
            return False
        finally:
            del webhook_url

    def _update_slot_mfe_mae(
        self,
        slot_id: int,
        slot_state: Dict[str, Any],
        current_px: float,
    ) -> Tuple[float, float]:
        """
        200msガーディアン監視および決済時に保有中スロットのリアルタイム MFE (%) / MAE (%) を更新・保持する。
        """
        sid = int(slot_id)
        entry_px = float(slot_state.get("entry_px") or 0.0)
        coin = str(slot_state.get("coin") or "").strip().upper()
        if entry_px <= 0.0 or current_px <= 0.0:
            exc = self._slot_excursions.get(sid) or {}
            return (float(exc.get("mfe_pct", 0.0)), float(exc.get("mae_pct", 0.0)))

        rec = self._slot_excursions.get(sid)
        if (
            rec is None
            or str(rec.get("coin", "")) != coin
            or abs(float(rec.get("entry_px", 0.0)) - entry_px) > 1e-9
        ):
            rec = {"coin": coin, "entry_px": entry_px, "mfe_pct": 0.0, "mae_pct": 0.0}
            self._slot_excursions[sid] = rec

        delta_pct = ((float(current_px) - entry_px) / entry_px) * 100.0
        if delta_pct > float(rec["mfe_pct"]):
            rec["mfe_pct"] = round(delta_pct, 4)
        if delta_pct < float(rec["mae_pct"]):
            rec["mae_pct"] = round(delta_pct, 4)
        return (float(rec["mfe_pct"]), float(rec["mae_pct"]))

    def _finalize_position_exit(
        self,
        slot_id: int,
        slot_snapshot: Dict[str, Any],
        exit_px: float,
        exit_reason: str,
        timestamp_ms: Optional[int] = None,
        exit_oid: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        ポジション決済（SL着弾、TP到達、Perp清算カスケード緊急脱出、緊急全決済、WS売り約定等）の直後に、
        以下の5つの事後パイプライン処理をべき等に一括実行する:
          1) `HyperliquidTaxEngine` への売却記録（`execute_atomic_ioc_exit` または `ws_manager` で未記録の場合のフォールバック補完）
          2) `DebiasedAIBrain.record_reflection_on_close` による `ai_reflection_memory` への教訓蒸留・保存
          3) `system_state_store.consecutive_losses`（敗北時 `+1`、勝利時 `0` リセット）および `daily_trade_count` の更新
          4) Slot 1 が損失決済 ($D_1 > 0$) だった場合の Slot 2 事後リスクバジェット再計算 (`recalculate_post_slot1_loss_budget`)
          5) `slot_state_store` の確実な `IDLE` リセット
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        sid = int(slot_id)
        raw_coin = str(slot_snapshot.get("coin") or slot_snapshot.get("base_asset") or "").strip()
        pair_name, _, base_asset = self.exchange.normalize_spot_symbol(raw_coin)
        if not pair_name:
            pair_name = raw_coin or "UNKNOWN/USDC"

        entry_px = float(slot_snapshot.get("entry_px") or exit_px or 1.0)
        sl_px = float(slot_snapshot.get("sl_px") or (entry_px * 0.97))
        sz = float(slot_snapshot.get("current_sz") or 0.0)
        order_created_ms = int(slot_snapshot.get("order_created_at_ms") or 0)
        created_ms = order_created_ms if order_created_ms > 0 else int(slot_snapshot.get("updated_at_ms") or ts)
        holding_sec = max(1, int((ts - created_ms) / 1000))

        raw_ep_id = slot_snapshot.get("episode_id")
        ep_id = str(raw_ep_id).strip() if raw_ep_id is not None else ""
        if ep_id.lower() in ("", "0", "none", "null"):
            ep_id = ""

        snap_cloid = str(slot_snapshot.get("active_cloid") or "").strip()
        snap_oid = int(slot_snapshot.get("active_oid") or 0)

        market_regime = "BULL_EXPANSION"
        conn = self.db._get_connection()
        if not ep_id:
            row_ep = None
            if snap_cloid or snap_oid > 0:
                row_ep = conn.execute(
                    """
                    SELECT episode_id, market_regime_4h, initial_sl_px, timestamp_ms
                    FROM ai_episodic_memory
                    WHERE slot_id = ? AND coin = ?
                      AND ((? != '' AND cloid = ?) OR (? > 0 AND oid = ?))
                    ORDER BY timestamp_ms DESC LIMIT 1
                    """,
                    (sid, pair_name, snap_cloid, snap_cloid, snap_oid, snap_oid),
                ).fetchone()
            if row_ep is None and order_created_ms > 0:
                row_ep = conn.execute(
                    """
                    SELECT episode_id, market_regime_4h, initial_sl_px, timestamp_ms
                    FROM ai_episodic_memory
                    WHERE slot_id = ? AND coin = ?
                      AND ABS(timestamp_ms - ?) <= 60000
                    ORDER BY timestamp_ms DESC LIMIT 1
                    """,
                    (sid, pair_name, order_created_ms),
                ).fetchone()
            if row_ep is not None:
                cand_ep = str(row_ep["episode_id"] or "").strip()
                if cand_ep and f"{sid}:{cand_ep}" not in self._finalized_exit_keys:
                    ep_id = cand_ep
                    market_regime = str(row_ep["market_regime_4h"] or market_regime)
                    if float(row_ep["initial_sl_px"] or 0.0) > 0:
                        sl_px = float(row_ep["initial_sl_px"])
        else:
            row_ep = conn.execute(
                "SELECT market_regime_4h, initial_sl_px FROM ai_episodic_memory WHERE episode_id = ?",
                (ep_id,),
            ).fetchone()
            if row_ep:
                market_regime = str(row_ep["market_regime_4h"] or market_regime)
                if float(row_ep["initial_sl_px"] or 0.0) > 0:
                    sl_px = float(row_ep["initial_sl_px"])

        if not ep_id:
            unique_token = (
                (snap_cloid if snap_cloid else None)
                or (f"oid{snap_oid}" if snap_oid > 0 else None)
                or (f"created{order_created_ms}" if order_created_ms > 0 else None)
                or f"ts{ts}_ep{int(slot_snapshot.get('mutation_epoch') or 0)}"
            )
            ep_id = f"ep_slot{sid}_{unique_token}"

        dedup_key = f"{sid}:{ep_id}"
        alt_created_key = f"{sid}:created:{order_created_ms}" if order_created_ms > 0 else ""
        if dedup_key in self._finalized_exit_keys or (alt_created_key and alt_created_key in self._finalized_exit_keys):
            return {"already_finalized": True, "episode_id": ep_id}
        self._finalized_exit_keys.add(dedup_key)
        if alt_created_key:
            self._finalized_exit_keys.add(alt_created_key)
        if len(self._finalized_exit_keys) > self.MAX_FINALIZED_EXIT_KEYS:
            # 古いエントリを半分削除して長期稼働時のメモリ肥大化を防止
            keep_list = list(self._finalized_exit_keys)[-(self.MAX_FINALIZED_EXIT_KEYS // 2) :]
            self._finalized_exit_keys = set(keep_list)
            self._finalized_exit_keys.add(dedup_key)
            if alt_created_key:
                self._finalized_exit_keys.add(alt_created_key)

        # 1) 税務エンジンへの売却記録フォールバック補完 (execute_atomic_ioc_exit / WS で記録済みの場合は process_spot_fill 側でべき等スキップ)
        if self.tax_engine is not None and sz > 0 and float(exit_px) > 0 and base_asset:
            try:
                resolved_exit_oid = int(exit_oid) if (exit_oid is not None and int(exit_oid) > 0) else None
                syn_tid = 9_000_000_000_000 + int(resolved_exit_oid or (ts % 1_000_000_000))
                est_fee = Decimal(str(sz)) * Decimal(str(exit_px)) * Decimal("0.0007")
                self.tax_engine.process_spot_fill(
                    hl_tid=syn_tid,
                    hl_oid=resolved_exit_oid,
                    timestamp_ms=ts,
                    pair_name=pair_name,
                    base_asset=base_asset,
                    is_buy=False,
                    exec_px_usdc=str(exit_px),
                    exec_sz_base=str(sz),
                    raw_fee_amount=str(est_fee),
                    raw_fee_token="USDC",
                )
            except Exception as exc:
                logger.warning("ポジション決済時の税務フォールバック記録警告: %s", exc)

        mfe_pct, mae_pct = self._update_slot_mfe_mae(sid, slot_snapshot, float(exit_px))
        self._slot_excursions[sid] = {"coin": "", "entry_px": 0.0, "mfe_pct": 0.0, "mae_pct": 0.0}

        # 2) AI Reflection Memory 記録 (実測 MFE / MAE を引き渡し)
        reflection_id: Optional[str] = None
        try:
            reflection_id = self.ai_brain.record_reflection_on_close(
                episode_id=ep_id,
                coin=pair_name,
                market_regime_4h=market_regime,
                exit_reason=exit_reason,
                entry_px=entry_px,
                exit_px=float(exit_px),
                initial_sl_px=sl_px if sl_px < entry_px else (entry_px * 0.98),
                holding_duration_sec=holding_sec,
                mfe_pct=mfe_pct,
                mae_pct=mae_pct,
                closed_at_ms=ts,
            )
        except Exception as exc:
            logger.warning("ポジション決済時の AI Reflection 記録警告: %s", exc)

        # 3) consecutive_losses & daily_trade_count のアトミック更新
        is_loss = bool(entry_px > 0 and float(exit_px) < entry_px)
        new_consec_losses = 0
        with self.db.immediate_transaction() as tx:
            sys_row = tx.execute(
                "SELECT consecutive_losses, daily_trade_count FROM system_state_store WHERE id = 1"
            ).fetchone()
            cur_consec = int(sys_row["consecutive_losses"] or 0) if sys_row else 0
            cur_daily = int(sys_row["daily_trade_count"] or 0) if sys_row else 0
            new_consec_losses = (cur_consec + 1) if is_loss else 0
            tx.execute(
                """
                UPDATE system_state_store
                SET consecutive_losses = ?,
                    daily_trade_count = ?,
                    updated_at_ms = ?
                WHERE id = 1
                """,
                (new_consec_losses, cur_daily + 1, ts),
            )

        # 4) Slot 1 損失決済時の Slot 2 事後リスクバジェット再計算
        post_loss_slot2_action: Optional[Dict[str, Any]] = None
        if sid == 1 and is_loss and sz > 0:
            loss_d1 = max(0.0, (entry_px - float(exit_px)) * sz)
            sys_eq = float(self.db.get_system_state().get("current_equity_usdc") or 130.0)
            latest_slot2 = self.db.get_slot_state(2)
            if str(latest_slot2.get("state")) == SlotState.OPEN_PROTECTED.value:
                budget_act = self.risk_guard.recalculate_post_slot1_loss_budget(
                    equity_usdc=sys_eq,
                    slot1_realized_loss_usdc=loss_d1,
                    slot2_state=latest_slot2,
                )
                post_loss_slot2_action = budget_act
                if budget_act["action"] == "EMERGENCY_IOC_FLATTEN_SLOT2":
                    c2 = str(latest_slot2.get("coin") or "")
                    bbo2 = self.ws.get_bbo(c2) or {"best_bid": latest_slot2.get("entry_px", 1.0)}
                    bid2 = float(bbo2.get("best_bid") or latest_slot2.get("entry_px") or 1.0)
                    s2_res = self.exchange.execute_atomic_ioc_exit(
                        slot_id=2,
                        coin_or_pair=c2,
                        best_bid=bid2,
                        fallback_sz=float(latest_slot2.get("current_sz") or 0.0),
                        timestamp_ms=ts,
                    )
                    self._finalize_position_exit(
                        slot_id=2,
                        slot_snapshot=latest_slot2,
                        exit_px=bid2,
                        exit_reason="POST_SLOT1_LOSS_EMERGENCY_FLATTEN",
                        timestamp_ms=ts,
                        exit_oid=s2_res.get("oid"),
                    )
                elif budget_act["action"] == "TIGHTEN_SLOT2_SL":
                    self.coordinator.transition_to_modifying_sl(
                        slot_id=2,
                        new_sl_px=float(budget_act["new_sl_px"]),
                        timestamp_ms=ts,
                    )

        # 5) スロットが IDLE でなければ確実に IDLE へ解放
        cur_slot = self.db.get_slot_state(sid)
        if str(cur_slot.get("state", "IDLE")) != SlotState.IDLE.value:
            self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)

        return {
            "slot_id": sid,
            "episode_id": ep_id,
            "reflection_id": reflection_id,
            "is_loss": is_loss,
            "consecutive_losses": new_consec_losses,
            "post_loss_slot2_action": post_loss_slot2_action,
        }

    def _on_ws_spot_fill(self, fill_event: Dict[str, Any]) -> None:
        """
        `HyperliquidWSManager` から通知された Spot 約定イベントを受け取り、
        - 買い約定 (`is_buy == True`): `ENTRY_PENDING` スロットを `OPEN_PROTECTED` (`INITIAL_RISK`) へ即時遷移（`sl_px`, `tp_px` 完全保持）
        - 売り約定 (`is_buy == False`): `OPEN_PROTECTED` / `EXITING_ATOMIC` スロットを `IDLE` へ即時解放＋事後パイプライン処理
        する。（※ 二重課税イベント計上は `HyperliquidWSManager` 側で `tax_engine.process_spot_fill` 実行済み）
        """
        ts = int(fill_event.get("timestamp_ms") or now_ms())
        is_buy = bool(fill_event.get("is_buy", True))
        raw_coin = str(fill_event.get("coin") or fill_event.get("pair_name") or "").strip()
        pair_name, _, base_asset = self.exchange.normalize_spot_symbol(raw_coin)
        if not pair_name:
            pair_name = str(fill_event.get("pair_name") or raw_coin).strip().upper()
        if not base_asset:
            base_asset = str(fill_event.get("base_asset") or "").strip().upper()
        oid = fill_event.get("oid")
        cloid = str(fill_event.get("cloid") or "").strip().lower()
        px = float(fill_event.get("px") or 0.0)
        sz = float(fill_event.get("sz") or 0.0)
        fee = float(fill_event.get("fee") or 0.0)
        fee_tok = str(fill_event.get("fee_token") or fill_event.get("feeToken") or "").strip().upper()

        slots = self.db.get_all_slots()
        if is_buy:
            net_sz = max(0.0, sz - fee) if (fee_tok == base_asset and base_asset) else sz
            for sid in (1, 2):
                s = slots.get(sid, {})
                if str(s.get("state")) != SlotState.ENTRY_PENDING.value:
                    continue
                s_oid = s.get("active_oid")
                s_cloid = str(s.get("active_cloid") or "").strip().lower()
                s_coin = str(s.get("coin") or "").strip().upper()
                if (
                    (oid is not None and s_oid is not None and int(oid) == int(s_oid))
                    or (cloid and s_cloid and cloid == s_cloid)
                    or (pair_name and self.exchange.are_symbols_equivalent(s_coin, pair_name))
                ):
                    self.coordinator.bind_order_response(
                        slot_id=sid,
                        cloid=str(s.get("active_cloid") or cloid or ""),
                        oid=int(oid) if oid is not None else (int(s_oid) if s_oid is not None else None),
                        filled=True,
                        filled_sz=net_sz,
                        avg_px=px,
                        timestamp_ms=ts,
                    )
                    self.ai_brain.update_episodic_lifecycle_status(
                        status="FILLED",
                        episode_id=s.get("episode_id"),
                        cloid=str(s.get("active_cloid") or cloid or ""),
                        oid=int(oid) if oid is not None else (int(s_oid) if s_oid is not None else None),
                    )
                    break
        else:
            for sid in (1, 2):
                s = slots.get(sid, {})
                if str(s.get("state")) == SlotState.IDLE.value:
                    continue
                s_coin = str(s.get("coin") or "").strip().upper()
                if pair_name and self.exchange.are_symbols_equivalent(s_coin, pair_name):
                    self.coordinator.bind_order_response(
                        slot_id=sid,
                        cloid=str(s.get("active_cloid") or cloid or ""),
                        oid=int(oid) if oid is not None else None,
                        filled=True,
                        filled_sz=sz,
                        avg_px=px,
                        is_exit_order=True,
                        timestamp_ms=ts,
                    )
                    self._finalize_position_exit(
                        slot_id=sid,
                        slot_snapshot=s,
                        exit_px=px,
                        exit_reason="WS_SELL_FILL",
                        timestamp_ms=ts,
                        exit_oid=int(oid) if oid is not None else None,
                    )
                    break

    def scan_and_recover_orphan_dust(
        self,
        spot_balances: Dict[str, Dict[str, Decimal]],
        token_valuations: Dict[str, Dict[str, Any]],
        current_time_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        アクティブスロット (`OPEN_PROTECTED`, `ENTRY_PENDING` 等) の管理外にある
        10.0 USDC 未満の孤立端数 (Orphan Dust) のみを検知し、条件を満たす場合に
        `recover_dust_top_up_and_dump` を実行する。
        正常スロットで保有・注文中の銘柄やステーブルコインは100%除外する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        slots = self.db.get_all_slots()
        active_bases: set[str] = set()
        for sid, s in slots.items():
            if str(s.get("state", "IDLE")).strip().upper() != SlotState.IDLE.value:
                raw_c = str(s.get("coin") or s.get("base_asset") or "").strip()
                _, _, norm_base = self.exchange.normalize_spot_symbol(raw_c)
                b = str(s.get("base_asset") or "").strip().upper()
                c = str(s.get("coin") or "").split("/")[0].strip().upper()
                for cand in (norm_base, b, c):
                    if cand:
                        active_bases.add(cand)

        dust_actions: List[Dict[str, Any]] = []
        free_usdc = spot_balances.get("USDC", {}).get("free", Decimal("0"))

        for asset, bal in spot_balances.items():
            coin = str(asset).strip().upper()
            if not coin or coin in self.exchange.NON_TRADING_STABLECOINS:
                continue
            if coin in active_bases:
                continue

            tot_qty = bal.get("total", Decimal("0"))
            hold_qty = bal.get("hold", Decimal("0"))
            if tot_qty <= 0 or hold_qty > 0:
                continue

            val_info = token_valuations.get(coin) or {}
            p_val = float(val_info.get("p_val") or 0.0)
            if p_val <= 0:
                continue

            est_usdc = float(tot_qty) * p_val
            if est_usdc <= 0.0 or est_usdc >= 10.0:
                continue

            pair_name = f"{coin}/USDC"
            q_existing = self.db.get_dust_quarantine(coin)
            prev_attempts = int(q_existing.get("recovery_attempts", 0)) if q_existing else 0
            self.db.upsert_dust_quarantine(
                base_asset=coin,
                coin_pair=pair_name,
                quarantined_qty=float(tot_qty),
                estimated_usdc_val=est_usdc,
                recovery_attempts=prev_attempts,
                last_attempt_ms=int(q_existing.get("last_attempt_ms", 0)) if q_existing else 0,
                status="QUARANTINED",
            )

            if free_usdc >= Decimal("15.0") and prev_attempts < 3 and self.exchange.get_spot_entry(pair_name) is not None:
                bbo = self.ws.get_bbo(pair_name) or {}
                bid = float(bbo.get("best_bid") or p_val)
                ask = float(bbo.get("best_ask") or (bid * 1.0005))
                rec_res = self.exchange.recover_dust_top_up_and_dump(
                    coin_or_pair=pair_name,
                    best_bid=bid,
                    best_ask=ask,
                    wait_after_top_up_sec=0.05 if self.exchange.execution_mode == "DRY_RUN" else 0.6,
                )
                dust_actions.append({"base_asset": coin, "pair_name": pair_name, "result": rec_res})
            else:
                dust_actions.append(
                    {
                        "base_asset": coin,
                        "pair_name": pair_name,
                        "result": {"recovered": False, "reason": "QUARANTINED_WAITING_CONDITIONS", "est_usdc": est_usdc},
                    }
                )
        return dust_actions

    # ==========================================================================
    # 1. 運用期限スケジューラ (`evaluate_campaign_schedule`)
    # ==========================================================================
    def evaluate_campaign_schedule(
        self,
        now_dt: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Phase 1 終了 (2027-07-09 00:00 JST) / 24時間休止 / Phase 2 (2027-07-10 〜 2027-12-10 JST)
        のスケジュール状態を判定し、期限2時間前の新規エントリー凍結や期限到達時の全決済フラグを返す。
        """
        cur = now_jst(now_dt)
        p1_freeze_start = self.phase1_end_dt - timedelta(hours=self.pre_deadline_freeze_hours)
        p2_freeze_start = self.phase2_end_dt - timedelta(hours=self.pre_deadline_freeze_hours)

        if cur < p1_freeze_start:
            return {
                "phase": "PHASE1_ACTIVE",
                "new_entry_allowed": True,
                "should_flatten_all": False,
            }
        if p1_freeze_start <= cur < self.phase1_end_dt:
            return {
                "phase": "PHASE1_PRE_DEADLINE_FREEZE",
                "new_entry_allowed": False,
                "should_flatten_all": False,
            }
        if self.phase1_end_dt <= cur < self.phase2_start_dt:
            should_liq = not self._phase1_liquidated
            return {
                "phase": "INTER_PHASE_COOLING_WINDOW",
                "new_entry_allowed": False,
                "should_flatten_all": should_liq,
                "liquidation_trigger": "PHASE1_DEADLINE_REACHED" if should_liq else None,
            }
        if self.phase2_start_dt <= cur < p2_freeze_start:
            return {
                "phase": "PHASE2_ACTIVE",
                "new_entry_allowed": True,
                "should_flatten_all": False,
            }
        if p2_freeze_start <= cur < self.phase2_end_dt:
            return {
                "phase": "PHASE2_PRE_DEADLINE_FREEZE",
                "new_entry_allowed": False,
                "should_flatten_all": False,
            }

        should_liq_p2 = not self._phase2_liquidated
        return {
            "phase": "CAMPAIGN_COMPLETED",
            "new_entry_allowed": False,
            "should_flatten_all": should_liq_p2,
            "liquidation_trigger": "PHASE2_DEADLINE_REACHED" if should_liq_p2 else None,
        }

    # ==========================================================================
    # 2. 4段階 & v1.1 6段階ソフト・ラチェット トレーリングストップ計算
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
        beta_score: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Topic 1 & v1.2 論点3: 6段階ソフト・ラチェット（Stage 10/13/17/20/30/40）トレーリングストップ算出。"""
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
            beta_score=beta_score,
        )

    def compute_time_decay_sl(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点2 (第1層): OU過程半減期に基づく連続時間減衰型SLタイトニング。"""
        return compute_time_decay_sl(*args, **kwargs)

    def evaluate_stagnant_scratch_exit(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """v1.2 論点2 (第2層): 4重ゲート停滞スクラッチ撤退判定。"""
        return evaluate_stagnant_scratch_exit(*args, **kwargs)

    @staticmethod
    def evaluate_fast_200ms_adverse_selection(
        perp_price_change_30s_pct: float = 0.0,
        perp_spot_lead_basis_pct: float = 0.0,
        bid_top3_depth_ratio_3s: float = 1.0,
    ) -> Dict[str, Any]:
        """
        Topic 2: ENTRY_PENDING 中の高速200ms逆選択キャンセル判定。
        1) Perp 30秒価格変化率 <= -0.45%
        2) Perp-Spot リードベーシス <= -0.15%
        3) 3秒間のSpot買い板上位3層厚の残存比率 <= 0.35 (-65%以上の板枯渇)
        """
        reasons: List[str] = []
        if float(perp_price_change_30s_pct) <= -0.45:
            reasons.append(f"PERP_30S_DROP({float(perp_price_change_30s_pct):.3f}%<=-0.45%)")
        if float(perp_spot_lead_basis_pct) <= -0.15:
            reasons.append(f"PERP_LEAD_BASIS({float(perp_spot_lead_basis_pct):.3f}%<=-0.15%)")
        if float(bid_top3_depth_ratio_3s) <= 0.35:
            reasons.append(f"BID_TOP3_DEPTH_DEPLETED(ratio={float(bid_top3_depth_ratio_3s):.3f}<=0.35)")
        return {
            "should_cancel": bool(reasons),
            "reasons": reasons,
            "reason": "; ".join(reasons) if reasons else "OK",
        }

    @staticmethod
    def evaluate_dynamic_entry_ttl(
        order_created_at_ms: int,
        current_time_ms: int,
        limit_px: float,
        current_mid_px: float,
        atr_15m: float,
        max_ttl_ms: int = 30 * 60 * 1000,
        drift_ttl_ms: int = 15 * 60 * 1000,
    ) -> Dict[str, Any]:
        """
        Topic 2: 動的注文有効期限 (Dynamic TTL 15〜30分)。
        - 30分経過で無条件失効
        - 15分経過かつ現在価格が指値から +0.6 * ATR_15m 以上上振れ乖離した場合に早期キャンセル
        """
        elapsed_ms = max(0, int(current_time_ms) - int(order_created_at_ms))
        if elapsed_ms >= int(max_ttl_ms):
            return {
                "expired": True,
                "reason": f"DYNAMIC_TTL_30M_EXCEEDED(elapsed={elapsed_ms // 1000}s)",
                "elapsed_ms": elapsed_ms,
            }
        eff_atr = float(atr_15m) if float(atr_15m) > 0 else float(limit_px) * 0.01
        drift = float(current_mid_px) - float(limit_px)
        if elapsed_ms >= int(drift_ttl_ms) and drift >= 0.6 * eff_atr:
            return {
                "expired": True,
                "reason": f"DYNAMIC_TTL_15M_PRICE_DRIFT(drift={drift:.6f}>=0.6*ATR={0.6*eff_atr:.6f})",
                "elapsed_ms": elapsed_ms,
            }
        return {"expired": False, "reason": "ACTIVE", "elapsed_ms": elapsed_ms}

    def compute_4stage_trailing_sl(
        self,
        pair_name: str,
        entry_px: float,
        current_sl_px: float,
        current_stage: int,
        best_bid: float,
        atr_15m: float = 0.0,
    ) -> Tuple[float, int, bool]:
        """
        ARCHITECTURE.md Section 3.2 表に基づく4段階トレーリングストップ:
          - Stage 1: 初期SL
          - Stage 2: 含み益が大型銘柄 (`UBTC/USDC`, `UETH/USDC`) で `+1.20%`、
                     主力高ボラ銘柄 (`HYPE/USDC`, `USOL/USDC`, `PURR/USDC`) で `+1.80%` 到達時、
                     SL を `Entry * 1.0015` (+0.15% 建値ロック・`FREEROLL_LOCKED`) へ引き上げ
          - Stage 3: 含み益が大型 `+2.00%` / 高ボラ `+2.80%` 到達時、ATRトレーリング (`best_bid - 1.2 * atr_15m`)
          - Stage 4: 含み益が大型 `+3.20%` / 高ボラ `+4.50%` 到達時、過熱タイトトレーリング (`best_bid * 0.992`)
        戻り値: `(new_sl_px, new_stage, changed)`
        """
        if entry_px <= 0 or best_bid <= 0:
            return (current_sl_px, current_stage, False)

        is_large = str(pair_name).strip().upper() in LARGE_CAP_PAIRS
        gain_pct = ((best_bid - entry_px) / entry_px) * 100.0

        stage2_trig = 1.20 if is_large else 1.80
        stage3_trig = 2.00 if is_large else 2.80
        stage4_trig = 3.20 if is_large else 4.50

        cand_sl = float(current_sl_px)
        next_stage = int(current_stage)

        if gain_pct >= stage2_trig:
            freeroll_sl = entry_px * 1.0015
            if freeroll_sl > cand_sl:
                cand_sl = freeroll_sl
            next_stage = max(next_stage, 2)

        if gain_pct >= stage3_trig:
            atr_dist = (1.2 * atr_15m) if atr_15m > 0 else (best_bid * 0.012)
            stage3_sl = max(entry_px * 1.005, best_bid - atr_dist)
            if stage3_sl > cand_sl:
                cand_sl = stage3_sl
            next_stage = max(next_stage, 3)

        if gain_pct >= stage4_trig:
            stage4_sl = best_bid * (0.993 if is_large else 0.990)
            if stage4_sl > cand_sl:
                cand_sl = stage4_sl
            next_stage = max(next_stage, 4)

        changed = bool(cand_sl > current_sl_px + 1e-9 or next_stage > current_stage)
        return (cand_sl, next_stage, changed)

    # ==========================================================================
    # 3. 200ms 高速ガーディアンループ (`run_200ms_guardian_tick`)
    # ==========================================================================
    def run_200ms_guardian_tick(
        self,
        perp_metrics_by_slot: Optional[Dict[int, Dict[str, float]]] = None,
        atr_15m_by_slot: Optional[Dict[int, float]] = None,
        current_time_ms: Optional[int] = None,
        use_v1_1_soft_ratchet: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        200ms周期で実行されるローカル高速ガーディアン。
        - 親子スロット連動インターロック (Slot 1 危険水域接近時の Slot 2 待機買い指値即時キャンセル)
        - Perp清算カスケード3ティック連続検知時の即時 IOC 脱出
        - SL 着弾 / TP 到達時の1ステップ IOC 即時決済
        - 4段階 / v1.1 6段階ソフト・ラチェット トレーリングストップの引き上げ更新
        - Slot 1 マイナス決済発生時の Slot 2 事後リスクバジェット再計算
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        self.coordinator.reset_thread_local_lock_state()
        slots = self.db.get_all_slots()
        slot1 = slots.get(1, {})
        slot2 = slots.get(2, {})
        actions_taken: List[Dict[str, Any]] = []

        # Slot 1 の現在 Best Bid 取得
        coin1 = str(slot1.get("coin") or "")
        bbo1 = self.ws.get_bbo(coin1) if coin1 else None
        bid1 = float(bbo1["best_bid"]) if bbo1 and bbo1.get("best_bid") else float(slot1.get("entry_px") or 0.0)

        # 1. 親子スロット連動インターロック検証
        interlock = self.risk_guard.check_parent_child_interlock(
            slot1_state=slot1,
            slot2_state=slot2,
            slot1_best_bid=bid1,
        )
        if interlock.get("should_cancel_slot2"):
            coin2 = str(slot2.get("coin") or "")
            oid2 = slot2.get("active_oid")
            cloid2 = slot2.get("active_cloid")
            ep2 = slot2.get("episode_id")
            if coin2:
                self.exchange.cancel_spot_order(
                    coin_or_pair=coin2,
                    oid=int(oid2) if oid2 is not None else None,
                    cloid_hex=str(cloid2) if cloid2 else None,
                    slot_id=2,
                )
            else:
                self.coordinator.reset_slot_to_idle(2, timestamp_ms=ts)
            self.ai_brain.update_episodic_lifecycle_status(
                status="CANCELLED_ADVERSE",
                episode_id=ep2,
                cloid=str(cloid2) if cloid2 else None,
                oid=int(oid2) if oid2 is not None else None,
            )
            actions_taken.append(
                {"slot_id": 2, "action": "INTERLOCK_CANCEL_SLOT2", "reason": interlock.get("reason")}
            )
            slot2 = self.db.get_slot_state(2)

        # 2. 各OPEN_PROTECTEDスロットの SL / TP / Perp清算カスケード / トレーリング監視
        slots = {1: self.db.get_slot_state(1), 2: slot2}
        for sid in (1, 2):
            s_state = slots[sid]
            if str(s_state.get("state")) != SlotState.OPEN_PROTECTED.value:
                self._cascade_tick_counters[sid] = 0
                continue

            pair = str(s_state.get("coin") or "")
            if not pair:
                continue
            bbo = self.ws.get_bbo(pair)
            if not bbo or float(bbo.get("best_bid", 0.0)) <= 0:
                sp_ent = self.exchange.get_spot_entry(pair)
                if sp_ent is not None and sp_ent.api_coin_name:
                    self.ws.subscribe_coin(sp_ent.api_coin_name)
                mid_fallback = self.ws.get_mid_px(pair) or (float(sp_ent.spot_mid_px) if sp_ent and sp_ent.spot_mid_px > 0 else 0.0)
                if mid_fallback > 0:
                    bbo = {"best_bid": mid_fallback, "best_ask": mid_fallback, "mid_px": mid_fallback}
                else:
                    continue

            best_bid = float(bbo["best_bid"])
            best_ask = float(bbo.get("best_ask") or best_bid)
            mid_px = float(bbo.get("mid_px") or best_bid)
            entry_px = float(s_state.get("entry_px") or 0.0)
            sl_px = float(s_state.get("sl_px") or 0.0)
            tp_px = float(s_state.get("tp_px") or 0.0)
            cur_stage = int(s_state.get("trailing_stage") or 1)
            sz_dec = int(s_state.get("sz_decimals") or 2)

            # 保有中のリアルタイム MFE (%) / MAE (%) を200msごとに更新
            mfe_pct_now, _ = self._update_slot_mfe_mae(sid, s_state, best_bid)
            peak_bid = max(best_bid, entry_px * (1.0 + mfe_pct_now / 100.0))

            # 2a. Perp 清算カスケード 3ティック連続検知チェック
            p_metrics = (perp_metrics_by_slot or {}).get(sid) or {}
            doi_15m = float(p_metrics.get("delta_oi_15m_pct", 0.0))
            prem_pct = float(p_metrics.get("premium_pct", 0.0))
            perp_mark = float(p_metrics.get("perp_mark_px", mid_px))

            if doi_15m <= -4.5 and prem_pct <= -0.20 and mid_px > perp_mark:
                self._cascade_tick_counters[sid] = self._cascade_tick_counters.get(sid, 0) + 1
            else:
                self._cascade_tick_counters[sid] = 0

            exit_reason: Optional[str] = None
            if self._cascade_tick_counters.get(sid, 0) >= self.CASCADE_REQUIRED_TICKS:
                exit_reason = "PERP_CASCADE_CRASH_GUARD"
            elif sl_px > 0 and best_bid <= sl_px:
                exit_reason = "STOP_LOSS_HIT"
            elif tp_px > 0 and best_bid >= tp_px:
                exit_reason = "TAKE_PROFIT_HIT"

            if exit_reason is not None:
                exit_res = self.exchange.execute_atomic_ioc_exit(
                    slot_id=sid,
                    coin_or_pair=pair,
                    best_bid=best_bid,
                    fallback_sz=float(s_state.get("current_sz") or 0.0),
                    timestamp_ms=ts,
                )
                self._cascade_tick_counters[sid] = 0
                fin_res = self._finalize_position_exit(
                    slot_id=sid,
                    slot_snapshot=s_state,
                    exit_px=best_bid,
                    exit_reason=exit_reason,
                    timestamp_ms=ts,
                    exit_oid=exit_res.get("oid"),
                )
                actions_taken.append(
                    {
                        "slot_id": sid,
                        "action": "ATOMIC_IOC_EXIT",
                        "exit_reason": exit_reason,
                        "best_bid": best_bid,
                        "result": exit_res,
                        "finalize": fin_res,
                    }
                )
                p_loss_act = fin_res.get("post_loss_slot2_action")
                if p_loss_act:
                    if p_loss_act.get("action") == "EMERGENCY_IOC_FLATTEN_SLOT2":
                        actions_taken.append(
                            {"slot_id": 2, "action": "POST_LOSS_EMERGENCY_FLATTEN_SLOT2", "details": p_loss_act}
                        )
                    elif p_loss_act.get("action") == "TIGHTEN_SLOT2_SL":
                        actions_taken.append(
                            {"slot_id": 2, "action": "POST_LOSS_TIGHTEN_SLOT2_SL", "details": p_loss_act}
                        )
                continue

            # 2b. トレーリングストップ更新チェック (4段階 + v1.1 6段階ソフト・ラチェット + v1.2 時間減衰SL統合)
            atr_15m = float((atr_15m_by_slot or {}).get(sid, 0.0))
            init_sl_for_slot = sl_px
            ep_id = s_state.get("episode_id")
            if ep_id:
                try:
                    ep_rec = self.ai_brain._fetch_episode(episode_id=str(ep_id))
                    if ep_rec and float(ep_rec.get("initial_sl_px") or 0.0) > 0:
                        init_sl_for_slot = float(ep_rec["initial_sl_px"])
                except Exception:
                    pass

            if use_v1_1_soft_ratchet is True or cur_stage >= 10:
                sp_eff = max(0.0005, (best_ask - best_bid) / mid_px) if mid_px > 0 and best_ask >= best_bid else 0.0010
                atr_pct = (atr_15m / entry_px) if (atr_15m > 0 and entry_px > 0) else 0.0120
                sr = self.compute_soft_ratchet_trailing_sl(
                    entry_px=entry_px,
                    initial_sl_px=init_sl_for_slot,
                    current_sl_px=sl_px,
                    current_stage=cur_stage,
                    best_bid=best_bid,
                    peak_bid=peak_bid,
                    sz_decimals=sz_dec,
                    spread_eff=sp_eff,
                    atr_15m_pct=atr_pct,
                    obi5=float(bbo.get("obi_5") or 0.0),
                )
                new_sl_raw = float(sr["new_sl_px"])
                new_stage = int(sr["new_stage"])
                changed = bool(sr["sl_updated"] or sr["stage_changed"])
            else:
                new_sl_raw, new_stage, changed = self.compute_4stage_trailing_sl(
                    pair_name=pair,
                    entry_px=entry_px,
                    current_sl_px=sl_px,
                    current_stage=cur_stage,
                    best_bid=best_bid,
                    atr_15m=atr_15m,
                )
                # もし初期Stage 1で4段階が未発火 (例: UZEC/USDC +1.79% < +1.80%) でも v1.1 ソフトラチェットが発火する場合は救済適用
                if not changed and cur_stage == 1 and use_v1_1_soft_ratchet is not False:
                    sp_eff = max(0.0005, (best_ask - best_bid) / mid_px) if mid_px > 0 and best_ask >= best_bid else 0.0010
                    atr_pct = (atr_15m / entry_px) if (atr_15m > 0 and entry_px > 0) else 0.0120
                    sr = self.compute_soft_ratchet_trailing_sl(
                        entry_px=entry_px,
                        initial_sl_px=init_sl_for_slot,
                        current_sl_px=sl_px,
                        current_stage=cur_stage,
                        best_bid=best_bid,
                        peak_bid=peak_bid,
                        sz_decimals=sz_dec,
                        spread_eff=sp_eff,
                        atr_15m_pct=atr_pct,
                        obi5=float(bbo.get("obi_5") or 0.0),
                    )
                    if sr["sl_updated"]:
                        new_sl_raw = float(sr["new_sl_px"])
                        new_stage = int(sr["new_stage"])
                        changed = True

            # Stage 2 / Stage 20 未達かつ order_created_at_ms が明示されている場合、時間減衰SLの単調ラチェットを統合評価
            ord_created_ms = int(s_state.get("order_created_at_ms") or 0)
            if (
                use_v1_1_soft_ratchet is True
                and ord_created_ms > 0
                and ts > ord_created_ms
                and not TrailingStage.is_freeroll_locked_stage(new_stage)
                and entry_px > 0
            ):
                hold_min = max(0.0, (ts - ord_created_ms) / 60_000.0)
                if hold_min > 45.0:
                    td_res = self.compute_time_decay_sl(
                        entry_px=entry_px,
                        initial_sl_px=init_sl_for_slot,
                        current_sl_px=max(sl_px, new_sl_raw),
                        holding_minutes=hold_min,
                        mfe_ratchet_sl_px=max(sl_px, new_sl_raw),
                        sz_decimals=sz_dec,
                        stage=new_stage,
                    )
                    if td_res.get("sl_updated") and float(td_res["new_sl_px"]) > max(sl_px, new_sl_raw):
                        new_sl_raw = float(td_res["new_sl_px"])
                        changed = True

            if changed:
                # Stage 2 / Stage 20 以上の建値ロック (entry_px * 1.0015) が ROUND_DOWN で 1.0015 倍を割り込まないよう補正
                rounded_sl = float(round_price(new_sl_raw, sz_dec))
                min_freeroll_px = entry_px * ConcurrencyStateCoordinator.FREEROLL_LOCK_MULTIPLIER
                is_fr_stage = (2 <= new_stage < 10) or (new_stage >= int(TrailingStage.STAGE_20_FREEROLL))
                if is_fr_stage and rounded_sl < min_freeroll_px:
                    rounded_sl = float(round_price(min_freeroll_px, sz_dec, rounding=ROUND_CEILING))
                if rounded_sl > sl_px or new_stage > cur_stage:
                    self.coordinator.transition_to_modifying_sl(
                        slot_id=sid,
                        new_sl_px=max(sl_px, rounded_sl),
                        new_trailing_stage=new_stage,
                        timestamp_ms=ts,
                    )
                    actions_taken.append(
                        {
                            "slot_id": sid,
                            "action": "TRAILING_SL_UPDATED",
                            "old_sl_px": sl_px,
                            "new_sl_px": max(sl_px, rounded_sl),
                            "stage": new_stage,
                        }
                    )

        return {"timestamp_ms": ts, "actions": actions_taken}

    # ==========================================================================
    # 4. 遠隔操作コマンドキュー実行 (`process_remote_commands`)
    # ==========================================================================
    def process_remote_commands(self, current_time_ms: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        `remote_command_queue` に登録されたWebダッシュボードからの操作コマンド
        (`PAUSE`, `RESUME`, `CLEAR_PENDING_BUYS`, `EMERGENCY_LIQUIDATE_ALL`) を即座に処理する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        pending = self.db.fetch_pending_commands()
        executed: List[Dict[str, Any]] = []

        for cmd_row in pending:
            cmd_id = int(cmd_row["cmd_id"])
            cmd = str(cmd_row["command"]).strip().upper()

            if cmd == "PAUSE":
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 1, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
                executed.append({"cmd_id": cmd_id, "command": "PAUSE", "status": "APPLIED"})

            elif cmd == "RESUME":
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 0, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
                executed.append({"cmd_id": cmd_id, "command": "RESUME", "status": "APPLIED"})

            elif cmd in ("CLEAR_PENDING_BUYS", "CANCEL_ENTRIES"):
                slots = self.db.get_all_slots()
                cancelled_slots: List[int] = []
                for sid, s in slots.items():
                    if str(s.get("state")) == SlotState.ENTRY_PENDING.value:
                        coin = str(s.get("coin") or "")
                        if coin:
                            self.exchange.cancel_spot_order(
                                coin_or_pair=coin,
                                oid=s.get("active_oid"),
                                cloid_hex=s.get("active_cloid"),
                                slot_id=sid,
                            )
                        else:
                            self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                        cancelled_slots.append(sid)
                executed.append(
                    {
                        "cmd_id": cmd_id,
                        "command": cmd,
                        "status": "APPLIED",
                        "cancelled_slots": cancelled_slots,
                    }
                )

            elif cmd in ("EMERGENCY_LIQUIDATE_ALL", "FLATTEN_ALL"):
                self._flatten_all_positions_and_orders(reason="OPERATOR_EMERGENCY_LIQUIDATE", timestamp_ms=ts)
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 1, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
                executed.append(
                    {"cmd_id": cmd_id, "command": cmd, "status": "APPLIED"}
                )

            self.db.mark_command_processed(cmd_id)

        return executed

    def _flatten_all_positions_and_orders(
        self,
        reason: str,
        timestamp_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """全スロットの待機注文キャンセルおよび保有ポジションの即時 IOC 100%売却を実行する"""
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        slots = self.db.get_all_slots()
        results: List[Dict[str, Any]] = []

        for sid, s in slots.items():
            st = str(s.get("state", "IDLE"))
            coin = str(s.get("coin") or "")
            if st == SlotState.ENTRY_PENDING.value:
                if coin:
                    res = self.exchange.cancel_spot_order(
                        coin_or_pair=coin,
                        oid=s.get("active_oid"),
                        cloid_hex=s.get("active_cloid"),
                        slot_id=sid,
                    )
                    results.append({"slot_id": sid, "action": "CANCEL_PENDING", "result": res})
                else:
                    self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
            elif st == SlotState.OPEN_PROTECTED.value and coin:
                bbo = self.ws.get_bbo(coin)
                bid = float(bbo["best_bid"]) if (bbo and bbo.get("best_bid")) else float(s.get("entry_px") or 1.0)
                res = self.exchange.execute_atomic_ioc_exit(
                    slot_id=sid,
                    coin_or_pair=coin,
                    best_bid=bid,
                    fallback_sz=float(s.get("current_sz") or 0.0),
                    timestamp_ms=ts,
                )
                fin_res = self._finalize_position_exit(
                    slot_id=sid,
                    slot_snapshot=s,
                    exit_px=bid,
                    exit_reason=reason,
                    timestamp_ms=ts,
                    exit_oid=res.get("oid"),
                )
                results.append(
                    {
                        "slot_id": sid,
                        "action": "IOC_FLATTEN",
                        "reason": reason,
                        "result": res,
                        "finalize": fin_res,
                    }
                )
            else:
                self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
        return results

    def recover_transient_states_if_expired(
        self,
        spot_balances: Optional[Dict[str, Dict[str, Decimal]]] = None,
        open_orders: Optional[List[Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        プロセス強制終了・OS再起動等で `DUST_RECOVERY_IN_PROGRESS` やスロットの過渡状態
        (`MODIFYING_SL`, `EXITING_ATOMIC`, `CANCELLING`) のまま残存した場合、
        静止期間 (`quiescence_until_ms`) 経過後に実口座残高 (`spot_clearinghouse_state`) ＆
        Open Orders と突合して自動的に正常状態 (`OPEN_PROTECTED` または `IDLE`) へ自己修復する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        sys_st = self.db.get_system_state()
        quiescence_until = int(sys_st.get("quiescence_until_ms") or 0)
        if ts < quiescence_until:
            return {"recovered_system_mode": False, "recovered_slots": {}, "reason": "IN_QUIESCENCE"}

        recovered_sys = False
        if str(sys_st.get("system_mode")) == SystemMode.DUST_RECOVERY_IN_PROGRESS.value:
            self.coordinator.exit_dust_recovery_mode(timestamp_ms=ts)
            recovered_sys = True

        slots = self.db.get_all_slots()
        transient_states = {
            SlotState.MODIFYING_SL.value,
            SlotState.EXITING_ATOMIC.value,
            SlotState.CANCELLING.value,
            "CANCELLING",
        }
        has_transient_slot = any(str(s.get("state", "IDLE")) in transient_states for s in slots.values())
        if not has_transient_slot:
            return {"recovered_system_mode": recovered_sys, "recovered_slots": {}}

        bals = spot_balances if spot_balances is not None else self.exchange.get_spot_balances()
        orders = self.exchange.get_open_orders(open_orders_override=open_orders)
        recovered_slots: Dict[int, Dict[str, Any]] = {}

        for sid in (1, 2):
            s = slots.get(sid, {})
            st = str(s.get("state", "IDLE"))
            if st not in transient_states:
                continue

            raw_coin = str(s.get("coin") or s.get("base_asset") or "").strip()
            if not raw_coin:
                self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                recovered_slots[sid] = {"from_state": st, "to_state": SlotState.IDLE.value, "reason": "NO_COIN"}
                continue

            pair_name, api_coin, base_asset = self.exchange.normalize_spot_symbol(raw_coin)
            tot_qty = bals.get(base_asset, {}).get("total", Decimal("0"))
            bbo = self.ws.get_bbo(pair_name) or {}
            sp_ent = self.exchange.get_spot_entry(pair_name)
            ref_px = float(
                bbo.get("best_bid")
                or s.get("entry_px")
                or (sp_ent.spot_mid_px if sp_ent else 0.0)
                or 1.0
            )
            est_usdc = float(tot_qty) * ref_px

            if tot_qty > Decimal("0") and est_usdc >= 10.0:
                entry_px = float(s.get("entry_px") or ref_px)
                cur_sl = float(s.get("sl_px") or (entry_px * 0.97))
                cur_tp = float(s.get("tp_px") or (entry_px * 1.05))
                cur_stage = max(1, int(s.get("trailing_stage") or 1))
                prev_sub = str(s.get("sub_state") or "")
                if prev_sub == SlotSubState.FREEROLL_LOCKED.value or (
                    entry_px > 0 and cur_sl >= entry_px * ConcurrencyStateCoordinator.FREEROLL_LOCK_MULTIPLIER
                ):
                    sub_st = SlotSubState.FREEROLL_LOCKED.value
                    cur_stage = max(cur_stage, 2)
                else:
                    sub_st = SlotSubState.INITIAL_RISK.value

                with self.coordinator.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
                    assert tx is not None
                    slot_row = tx.execute("SELECT mutation_epoch FROM slot_state_store WHERE slot_id = ?", (sid,)).fetchone()
                    new_epoch = (int(slot_row["mutation_epoch"]) + 1) if slot_row else 1
                    tx.execute(
                        """
                        UPDATE slot_state_store
                        SET state = ?, sub_state = ?, coin = ?, base_asset = ?,
                            entry_px = ?, current_sz = ?, sl_px = ?, tp_px = ?,
                            trailing_stage = ?, mutation_epoch = ?, updated_at_ms = ?
                        WHERE slot_id = ?
                        """,
                        (
                            SlotState.OPEN_PROTECTED.value,
                            sub_st,
                            pair_name,
                            base_asset,
                            entry_px,
                            float(tot_qty),
                            cur_sl,
                            cur_tp,
                            cur_stage,
                            new_epoch,
                            ts,
                            sid,
                        ),
                    )
                recovered_slots[sid] = {
                    "from_state": st,
                    "to_state": SlotState.OPEN_PROTECTED.value,
                    "sub_state": sub_st,
                    "spot_total_qty": float(tot_qty),
                    "estimated_usdc": round(est_usdc, 4),
                }
            else:
                # 残存する未約定注文があれば安全にキャンセルした上で IDLE へ戻す
                for oo in orders:
                    oo_coin = str(oo.get("coin") or oo.get("pair_name") or "").strip()
                    if self.exchange.are_symbols_equivalent(raw_coin, oo_coin):
                        try:
                            self.exchange.cancel_spot_order(
                                coin_or_pair=pair_name,
                                oid=oo.get("oid"),
                                cloid_hex=oo.get("cloid"),
                                slot_id=sid,
                                trigger_dust_recovery_if_sub10=False,
                            )
                        except Exception as exc:
                            logger.warning("過渡状態リカバリ時の残存注文キャンセル警告 (slot=%d): %s", sid, exc)
                self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                recovered_slots[sid] = {
                    "from_state": st,
                    "to_state": SlotState.IDLE.value,
                    "spot_total_qty": float(tot_qty),
                    "estimated_usdc": round(est_usdc, 4),
                }

        return {
            "recovered_system_mode": recovered_sys,
            "recovered_slots": recovered_slots,
        }

    def evaluate_adverse_selection_for_pending_entries(
        self,
        perp_signals_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        `ENTRY_PENDING` の買い指値待機中に以下の逆選択（Adverse Selection）条件を検知して先行キャンセルする:
          1. 市場全体の急変（対象ペアまたは BTC/HYPE の Perp `Long-Flush Blocker`:
             `funding_1h_pct >= +0.025%` & `delta_oi_15m_pct <= -2.0%`、または
             急落カスケード兆候 `delta_oi_15m_pct <= -3.0%` & `premium_pct <= -0.15%`、または 15m変化率 `<= -2.5%`）
          2. 現在価格 (`best_bid` / `mid_px`) が初期 `sl_px` 付近 (`<= sl_px * 1.003`) または無効化水準まで下落
        キャンセル実行時は `ai_episodic_memory.lifecycle_status` を `'CANCELLED_ADVERSE'` に更新する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        slots = self.db.get_all_slots()
        cancelled_actions: List[Dict[str, Any]] = []

        for sid in (1, 2):
            s = slots.get(sid, {})
            if str(s.get("state", "IDLE")) != SlotState.ENTRY_PENDING.value:
                continue

            raw_coin = str(s.get("coin") or s.get("base_asset") or "").strip()
            if not raw_coin:
                continue
            pair_name, _, _ = self.exchange.normalize_spot_symbol(raw_coin)
            sl_px = float(s.get("sl_px") or 0.0)
            entry_px = float(s.get("entry_px") or 0.0)

            bbo = self.ws.get_bbo(pair_name) or {}
            sp_entry = self.exchange.get_spot_entry(pair_name)
            cur_bid = float(bbo.get("best_bid") or (sp_entry.spot_mid_px if sp_entry else 0.0) or 0.0)

            adverse_reason: Optional[str] = None

            # 条件1: 現在価格が初期 sl_px の +0.30% 以内まで異常接近または割り込み
            if sl_px > 0.0 and cur_bid > 0.0 and cur_bid <= sl_px * 1.003:
                adverse_reason = f"PRICE_NEAR_OR_BELOW_INITIAL_SL(bid={cur_bid:.4f},sl={sl_px:.4f})"

            # 条件2: 対象銘柄または市場アンカー (UBTC/USDC, HYPE/USDC) の Perp Long-Flush Blocker / 急落検知
            if adverse_reason is None:
                check_pairs = [pair_name, "UBTC/USDC", "HYPE/USDC"]
                for cp in check_pairs:
                    p_sig = dict((perp_signals_by_pair or {}).get(cp) or {})
                    if not p_sig:
                        ent = self.exchange.get_spot_entry(cp)
                        if ent is not None and ent.perp_oracle_px > 0:
                            prem = ((ent.perp_mark_px - ent.perp_oracle_px) / ent.perp_oracle_px) * 100.0
                            p_sig = {
                                "funding_1h_pct": float(ent.perp_funding_1h) * 100.0,
                                "premium_pct": prem,
                                "delta_oi_15m_pct": 0.0,
                            }
                    f_pct = float(p_sig.get("funding_1h_pct", 0.0))
                    doi_15m = float(p_sig.get("delta_oi_15m_pct", 0.0))
                    prem_pct = float(p_sig.get("premium_pct", 0.0))
                    ret_15m = float(p_sig.get("price_change_15m_pct", 0.0))

                    if f_pct >= 0.025 and doi_15m <= -2.0:
                        adverse_reason = f"PERP_LONG_FLUSH_BLOCKER({cp}:funding={f_pct:.4f}%,dOI={doi_15m:.2f}%)"
                        break
                    if doi_15m <= -3.0 and prem_pct <= -0.15:
                        adverse_reason = f"PERP_CASCADE_DUMP({cp}:dOI={doi_15m:.2f}%,prem={prem_pct:.3f}%)"
                        break
                    if ret_15m <= -2.5:
                        adverse_reason = f"MARKET_SUDDEN_DROP_15M({cp}:ret15m={ret_15m:.2f}%)"
                        break

            if adverse_reason is not None:
                oid = s.get("active_oid")
                cloid = s.get("active_cloid")
                ep_id = s.get("episode_id")
                cancel_res = self.exchange.cancel_spot_order(
                    coin_or_pair=pair_name,
                    oid=int(oid) if oid is not None else None,
                    cloid_hex=str(cloid) if cloid else None,
                    slot_id=sid,
                )
                self.ai_brain.update_episodic_lifecycle_status(
                    status="CANCELLED_ADVERSE",
                    episode_id=ep_id,
                    cloid=str(cloid) if cloid else None,
                    oid=int(oid) if oid is not None else None,
                )
                cancelled_actions.append(
                    {
                        "slot_id": sid,
                        "pair_name": pair_name,
                        "action": "ADVERSE_SELECTION_CANCEL",
                        "reason": adverse_reason,
                        "episode_id": ep_id,
                        "cancel_result": cancel_res,
                    }
                )

        return cancelled_actions

    def reconcile_3way_state(
        self,
        spot_balances: Dict[str, Dict[str, Decimal]],
        open_orders: Optional[List[Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        ローカルDB (`slot_state_store`) ⟷ 取引所 Open Orders (`@107` / `HYPE/USDC`) ⟷ Spot実残高 (`HYPE`)
        の3者をシンボル表記揺れ（`@index` ⇄ `PAIR/USDC` ⇄ `BASE`）を正規化して突合する。
        - プロセス再起動等で残存した過渡状態 (`MODIFYING_SL`, `EXITING_ATOMIC`, `CANCELLING`, `DUST_RECOVERY_IN_PROGRESS`)
          は `quiescence_until_ms` 経過後に実残高と突合して自動自己修復 (`OPEN_PROTECTED` または `IDLE`)
        - `ENTRY_PENDING` スロットの注文が Open Orders 上で `@107` 表記であっても `are_symbols_equivalent` で一致確認
        - WS通知の遅延等で `open_orders` から消え、かつ実残高が発注前より `>= 10.0 USDC` 純増している場合は
          自動的に `OPEN_PROTECTED` (`INITIAL_RISK`, `sl_px`/`tp_px` 保持) へ昇格
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        transient_recovery = self.recover_transient_states_if_expired(
            spot_balances=spot_balances,
            open_orders=open_orders,
            current_time_ms=ts,
        )
        orders = self.exchange.get_open_orders(open_orders_override=open_orders)
        slots = self.db.get_all_slots()
        slot_reports: Dict[int, Dict[str, Any]] = {}

        for sid in (1, 2):
            s = slots.get(sid, {})
            st = str(s.get("state", "IDLE"))
            raw_coin = str(s.get("coin") or s.get("base_asset") or "").strip()
            if st == SlotState.IDLE.value or not raw_coin:
                if sid in transient_recovery.get("recovered_slots", {}):
                    rec_info = transient_recovery["recovered_slots"][sid]
                    slot_reports[sid] = {
                        "state": SlotState.IDLE.value,
                        "status": f"RECOVERED_{rec_info['from_state']}_TO_IDLE",
                        "recovery": rec_info,
                    }
                else:
                    slot_reports[sid] = {"state": st, "status": "IDLE_CONSISTENT"}
                continue

            pair_name, api_coin, base_asset = self.exchange.normalize_spot_symbol(raw_coin)
            s_oid = s.get("active_oid")
            s_cloid = str(s.get("active_cloid") or "").strip().lower()

            matched_order: Optional[Dict[str, Any]] = None
            for oo in orders:
                oo_oid = oo.get("oid")
                oo_cloid = str(oo.get("cloid") or "").strip().lower()
                oo_coin = str(oo.get("coin") or oo.get("pair_name") or "").strip()
                if (
                    (s_oid is not None and oo_oid is not None and int(s_oid) == int(oo_oid))
                    or (s_cloid and oo_cloid and s_cloid == oo_cloid)
                    or self.exchange.are_symbols_equivalent(raw_coin, oo_coin)
                ):
                    matched_order = oo
                    break

            bal = spot_balances.get(base_asset, {})
            tot_qty = bal.get("total", Decimal("0"))

            if st == SlotState.ENTRY_PENDING.value:
                if matched_order is not None:
                    slot_reports[sid] = {
                        "state": st,
                        "status": "MATCHED_OPEN_ORDER",
                        "pair_name": pair_name,
                        "api_coin_name": api_coin,
                        "base_asset": base_asset,
                        "matched_oid": matched_order.get("oid"),
                    }
                else:
                    # Open Orders に存在しない場合、まず REST backfill で約定イベントがあれば優先取り込み
                    if (
                        open_orders is None
                        and self.exchange.info is not None
                        and hasattr(self.exchange.info, "user_fills_by_time")
                    ):
                        try:
                            self.ws.info = self.ws.info or self.exchange.info
                            self.ws.backfill_missed_fills(
                                start_time_ms=max(0, int(s.get("order_created_at_ms") or (ts - 3_600_000)) - 60_000)
                            )
                        except Exception as exc:
                            logger.debug(f"[3way Reconcile] backfill_missed_fills スキップ: {exc}")

                    s_refreshed = self.db.get_slot_state(sid)
                    if str(s_refreshed.get("state")) == SlotState.OPEN_PROTECTED.value:
                        slot_reports[sid] = {
                            "state": SlotState.OPEN_PROTECTED.value,
                            "status": "PROMOTED_FILLED_TO_OPEN_PROTECTED",
                            "pair_name": pair_name,
                            "filled_sz": float(s_refreshed.get("current_sz") or tot_qty),
                        }
                        continue

                    # 発注前残高からの純増分 (または open_orders / live info 照会時の実残高) を確認
                    pre_key = (sid, base_asset)
                    if pre_key in self.exchange._pre_order_base_balances:
                        delta_qty = max(Decimal("0"), tot_qty - self.exchange._pre_order_base_balances[pre_key])
                    elif open_orders is not None or (
                        self.exchange.info is not None
                        and (hasattr(self.exchange.info, "open_orders") or hasattr(self.exchange.info, "frontend_open_orders"))
                    ):
                        delta_qty = tot_qty
                    else:
                        delta_qty = Decimal("0")

                    ref_px = float(s.get("entry_px") or 0.0)
                    est_usdc = float(delta_qty) * ref_px
                    if delta_qty > Decimal("0") and est_usdc >= 10.0:
                        self.exchange._pre_order_base_balances.pop(pre_key, None)
                        self.coordinator.bind_order_response(
                            slot_id=sid,
                            cloid=str(s.get("active_cloid") or ""),
                            oid=int(s_oid) if s_oid is not None else None,
                            filled=True,
                            filled_sz=float(delta_qty),
                            avg_px=ref_px,
                            timestamp_ms=ts,
                        )
                        self.ai_brain.update_episodic_lifecycle_status(
                            status="FILLED",
                            episode_id=s.get("episode_id"),
                            cloid=str(s.get("active_cloid") or ""),
                            oid=int(s_oid) if s_oid is not None else None,
                        )
                        slot_reports[sid] = {
                            "state": SlotState.OPEN_PROTECTED.value,
                            "status": "PROMOTED_FILLED_TO_OPEN_PROTECTED",
                            "pair_name": pair_name,
                            "filled_sz": float(delta_qty),
                        }
                    else:
                        slot_reports[sid] = {
                            "state": st,
                            "status": "PENDING_RESTING",
                            "pair_name": pair_name,
                        }
            elif st in (SlotState.OPEN_PROTECTED.value, SlotState.MODIFYING_SL.value):
                rec_info = transient_recovery.get("recovered_slots", {}).get(sid)
                slot_reports[sid] = {
                    "state": st,
                    "status": (
                        f"RECOVERED_{rec_info['from_state']}_TO_OPEN_PROTECTED"
                        if rec_info
                        else ("MATCHED_SPOT_BALANCE" if tot_qty > Decimal("0") else "BALANCE_EMPTY")
                    ),
                    "pair_name": pair_name,
                    "api_coin_name": api_coin,
                    "base_asset": base_asset,
                    "spot_total_qty": float(tot_qty),
                }

        return {
            "timestamp_ms": ts,
            "open_orders_count": len(orders),
            "transient_recovery": transient_recovery,
            "slots": slot_reports,
        }

    # ==========================================================================
    # 5. 15秒 高速制御ループ (`run_15s_control_tick`) ＆ 電源/OSシャットダウン保護
    # ==========================================================================
    def execute_graceful_power_or_os_shutdown(
        self,
        reason: str = "OS_SHUTDOWN",
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Win32 電源クリティカル (`ACLineStatus == 0 & BatteryLifePercent <= 40`) または
        OS再起動/シャットダウン (`CTRL_SHUTDOWN_EVENT`, `WM_QUERYENDSESSION` 等) 検知時に、
        1. 全未約定注文 (`ENTRY_PENDING`) の緊急キャンセル
        2. SQLite `PRAGMA wal_checkpoint(TRUNCATE);` によるDB完全フラッシュ
        3. 安全停止ログの記録
        をアトミックに実行するグレースフル・シャットダウン機構。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        cancelled_pending_slots: List[int] = []
        try:
            slots = self.db.get_all_slots()
            for sid, s in slots.items():
                if str(s.get("state")) == SlotState.ENTRY_PENDING.value:
                    coin = str(s.get("coin") or "")
                    oid = s.get("active_oid")
                    cloid = s.get("active_cloid")
                    if coin:
                        try:
                            self.exchange.cancel_spot_order(
                                coin_or_pair=coin,
                                oid=oid,
                                cloid_hex=cloid,
                                slot_id=sid,
                            )
                        except Exception as exc:
                            logger.warning(f"[Graceful Shutdown] Slot {sid} 注文キャンセル警告: {exc}")
                            self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                    else:
                        self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                    cancelled_pending_slots.append(int(sid))
            try:
                self.exchange.clear_deadman_if_no_pending_orders(
                    has_other_pending_orders=False, current_time_ms=ts
                )
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"[Graceful Shutdown] 未約定注文キャンセル処理例外: {exc}")

        wal_ckpt: Dict[str, Any] = {}
        try:
            wal_ckpt = self.db.run_wal_checkpoint("TRUNCATE")
        except Exception as exc:
            logger.error(f"[Graceful Shutdown] WAL TRUNCATE チェックポイント例外: {exc}")
            wal_ckpt = {"status": "error", "error": str(exc)}

        logger.warning(
            "[Graceful Shutdown] 安全停止処理完了: reason=%s | cancelled_pending_slots=%s | wal_checkpoint=%s",
            reason,
            cancelled_pending_slots,
            wal_ckpt,
        )
        return {
            "shutdown_executed": True,
            "reason": str(reason),
            "timestamp_ms": ts,
            "cancelled_pending_slots": cancelled_pending_slots,
            "wal_checkpoint": wal_ckpt,
        }

    def run_15s_control_tick(
        self,
        current_time_ms: Optional[int] = None,
        now_dt: Optional[datetime] = None,
        perp_signals_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        simulated_power_status: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        15秒周期で実行される制御・電源監視・3者照合・注文失効・逆選択キャンセル・過渡状態自己修復・端数自己復旧・サーキットブレーカー評価ループ。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        self.coordinator.reset_thread_local_lock_state()

        # 0. Win32 電源状態 (UPS / バッテリー残量 <= 40%) 監視
        power_check = check_ups_power_critical(simulated_status=simulated_power_status)
        power_shutdown_report: Optional[Dict[str, Any]] = None
        if power_check.get("power_critical"):
            power_shutdown_report = self.execute_graceful_power_or_os_shutdown(
                reason="UPS_BATTERY_CRITICAL_LE_40PCT",
                timestamp_ms=ts,
            )

        # 1. リモートコマンドの即時処理
        cmds_executed = self.process_remote_commands(current_time_ms=ts)

        # 2. キャンペーン期限スケジューラ確認
        sched = self.evaluate_campaign_schedule(now_dt=now_dt)
        if sched.get("should_flatten_all"):
            self._flatten_all_positions_and_orders(
                reason=str(sched.get("liquidation_trigger", "CAMPAIGN_DEADLINE")),
                timestamp_ms=ts,
            )
            if sched["phase"] == "INTER_PHASE_COOLING_WINDOW":
                self._phase1_liquidated = True
            elif sched["phase"] == "CAMPAIGN_COMPLETED":
                self._phase2_liquidated = True

        # 3. 4時間未約定買い指値のローカルタイムスタンプ失効処理
        expired_slots: List[int] = []
        slots = self.db.get_all_slots()
        for sid, s in slots.items():
            if str(s.get("state")) == SlotState.ENTRY_PENDING.value:
                created_ms = int(s.get("order_created_at_ms") or 0)
                if created_ms > 0 and (ts - created_ms) >= self.ORDER_EXPIRY_MS:
                    coin = str(s.get("coin") or "")
                    oid = s.get("active_oid")
                    cloid = s.get("active_cloid")
                    ep_id = s.get("episode_id")
                    if coin:
                        self.exchange.cancel_spot_order(
                            coin_or_pair=coin,
                            oid=oid,
                            cloid_hex=cloid,
                            slot_id=sid,
                        )
                    else:
                        self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                    self.ai_brain.update_episodic_lifecycle_status(
                        status="EXPIRED_4H",
                        episode_id=ep_id,
                        cloid=str(cloid) if cloid else None,
                        oid=int(oid) if oid is not None else None,
                    )
                    expired_slots.append(sid)

        # 3b. 待機買い指値 (`ENTRY_PENDING`) の逆選択（Adverse Selection）先行キャンセル判定
        adverse_cancelled = self.evaluate_adverse_selection_for_pending_entries(
            perp_signals_by_pair=perp_signals_by_pair,
            current_time_ms=ts,
        )

        # 3b-2. 指値の約定完了またはローカルキャンセル後、他スロットに未約定指値が無ければ Dead Man's Switch 予約をクリア
        has_any_pending = any(
            str(sl.get("state")) == SlotState.ENTRY_PENDING.value
            for sl in self.db.get_all_slots().values()
        )
        deadman_clear_res = self.exchange.clear_deadman_if_no_pending_orders(
            has_other_pending_orders=has_any_pending,
            current_time_ms=ts,
        )

        # 3c. プロセス再起動等で残存した過渡状態 (`MODIFYING_SL`, `EXITING_ATOMIC`, `CANCELLING`, `DUST_RECOVERY_IN_PROGRESS`)
        #     が `quiescence_until_ms` 経過後に永久ブロックしないよう Fencing 取得前に自己修復する
        transient_recovery_pre = self.recover_transient_states_if_expired(current_time_ms=ts)

        # 4. Fencing Token スナップショット取得 -> /info 残高取得 -> 検証
        pre_snap = self.coordinator.capture_fencing_snapshot(current_time_ms=ts)
        spot_balances = self.exchange.get_spot_balances()
        fencing_valid, fencing_reason = self.coordinator.validate_fencing_snapshot(
            pre_snap, current_time_ms=ts
        )

        # 5. 多層価格サニティフィルタ ＆ 総資産算出
        token_valuations: Dict[str, Dict[str, Any]] = {}
        for asset, bal in spot_balances.items():
            coin_up = str(asset).strip().upper()
            if coin_up in self.exchange.NON_TRADING_STABLECOINS or bal.get("total", Decimal("0")) <= 0:
                continue
            pair = f"{coin_up}/USDC"
            bbo = self.ws.get_bbo(pair) or {}
            sp_entry = self.exchange.get_spot_entry(pair)
            bid = float(bbo.get("best_bid") or (sp_entry.spot_mid_px if sp_entry else 1.0))
            ask = float(bbo.get("best_ask") or bid)
            mark = float(sp_entry.spot_mark_px if sp_entry and sp_entry.spot_mark_px > 0 else bid)
            oracle = float(sp_entry.perp_oracle_px if sp_entry else 0.0)
            val_res = self.risk_guard.evaluate_token_price_sanity(
                pair_name=pair,
                best_bid=bid,
                best_ask=ask,
                mark_px=mark,
                perp_oracle_px=oracle,
            )
            token_valuations[coin_up] = val_res

        # 5b. 3者照合 (Local DB vs Open Orders vs Spot Balances) ＆ アクティブスロット外の孤立端数 (< 10.0 USDC) 自己復旧
        reconciliation_report: Dict[str, Any] = {}
        dust_actions: List[Dict[str, Any]] = []
        if fencing_valid:
            reconciliation_report = self.reconcile_3way_state(
                spot_balances=spot_balances,
                current_time_ms=ts,
            )
            dust_actions = self.scan_and_recover_orphan_dust(
                spot_balances=spot_balances,
                token_valuations=token_valuations,
                current_time_ms=ts,
            )

        eq_summary = self.risk_guard.compute_total_equity_usdc(
            spot_balances=spot_balances,
            token_valuations=token_valuations,
        )
        cb_result = self.risk_guard.evaluate_circuit_breakers(
            equity_usdc=eq_summary["equity_usdc"],
            price_tainted_flag=eq_summary["price_tainted_flag"],
            in_quiescence=(not fencing_valid),
            current_time_ms=ts,
        )

        # L3 新規発動時は待機買い指値を全クリア
        if cb_result.get("l3_triggered_now"):
            for sid, s in self.db.get_all_slots().items():
                if str(s.get("state")) == SlotState.ENTRY_PENDING.value and s.get("coin"):
                    self.exchange.cancel_spot_order(
                        coin_or_pair=str(s["coin"]),
                        oid=s.get("active_oid"),
                        cloid_hex=s.get("active_cloid"),
                        slot_id=sid,
                    )

        # L5 ハード・キルスイッチ発動時は全注文取消＋全保有トークン IOC 100%即時売却
        if cb_result.get("l5_triggered_now"):
            self._flatten_all_positions_and_orders(reason="L5_HARD_KILL_SWITCH", timestamp_ms=ts)

        # 6. USDC/JPY 為替レート更新 ＆ 初期USDC在庫の取得単価ブートストラップ (架空為替差益防止ガード)
        rate_val, rate_src = self.rate_fetcher.get_rate()
        self.db.update_latest_usdc_jpy_rate(rate_val)
        usdc_total_dec = spot_balances.get("USDC", {}).get("total", Decimal("0"))
        usdc_bootstrap_res: Optional[Dict[str, Any]] = None
        if usdc_total_dec > Decimal("0") and self.tax_engine is not None:
            usdc_bootstrap_res = self.tax_engine.bootstrap_initial_usdc_inventory(
                actual_usdc_total=usdc_total_dec,
                usdc_jpy_rate=rate_val,
                timestamp_ms=ts,
            )

        # 7. 反事実（Shadow Evaluation）追跡中レコードの1h/4h/24h価格更新＆24h自動完了判定
        shadow_prices: Dict[str, float] = {}
        for coin_up, val_info in token_valuations.items():
            px_val = float(val_info.get("valuation_px") or 0.0)
            if px_val > 0.0:
                shadow_prices[coin_up] = px_val
                shadow_prices[f"{coin_up}/USDC"] = px_val
        for bbo_key, bbo_val in dict(self.ws._bbo_cache).items():
            mid_v = float(bbo_val.get("mid_px") or bbo_val.get("best_bid") or 0.0)
            if mid_v > 0.0:
                shadow_prices[str(bbo_key).upper()] = mid_v
        for pair_key, sp_ent in dict(self.exchange.pair_to_entry).items():
            px_v = float(sp_ent.spot_mid_px or sp_ent.spot_mark_px or 0.0)
            if px_v > 0.0 and pair_key.upper() not in shadow_prices:
                shadow_prices[pair_key.upper()] = px_v
                shadow_prices[sp_ent.base_asset.upper()] = px_v
        shadow_eval_summary = self.ai_brain.process_pending_shadow_evaluations(
            current_prices=shadow_prices,
            current_time_ms=ts,
        )

        # 8. ダッシュボード資産推移記録 ＆ 暗号化スナップショット (08, 23, 38, 53分) 自動出力
        if self.dashboard_service is not None:
            try:
                sys_now = self.db.get_system_state()
                hwm_val = float(sys_now.get("hwm_equity_usdc") or eq_summary["equity_usdc"])
                self.dashboard_service.record_equity_point(
                    equity_usdc=float(eq_summary["equity_usdc"]),
                    usdc_jpy_rate=float(rate_val),
                    hwm_usdc=hwm_val,
                    timestamp_ms=ts,
                )
                cur_jst = now_jst(now_dt)
                min_bucket = (cur_jst.year, cur_jst.month, cur_jst.day, cur_jst.hour * 60 + cur_jst.minute)
                if cur_jst.minute in (8, 23, 38, 53) and self._last_snapshot_export_bucket != min_bucket:
                    self.dashboard_service.export_public_snapshot()
                    self._last_snapshot_export_bucket = min_bucket
                    if self.execution_mode == "LIVE":
                        from src.web_server import sync_and_push_docs_to_github

                        sync_and_push_docs_to_github()
            except Exception as exc:
                logger.debug(f"[15s Control] ダッシュボード同期スキップ: {exc}")

        logger.info(
            "[15s Control] equity=%.2f USDC (rate=%.2f JPY/%s) | mode=%s | fencing=%s",
            float(eq_summary["equity_usdc"]),
            float(rate_val),
            str(rate_src),
            str(cb_result.get("system_mode", "NORMAL")),
            "OK" if fencing_valid else str(fencing_reason),
        )

        return {
            "timestamp_ms": ts,
            "power_status": power_check,
            "power_shutdown_report": power_shutdown_report,
            "deadman_clear": deadman_clear_res,
            "commands_executed": cmds_executed,
            "campaign_schedule": sched,
            "expired_slots": expired_slots,
            "adverse_selection_cancelled": adverse_cancelled,
            "transient_recovery": transient_recovery_pre,
            "reconciliation": reconciliation_report,
            "orphan_dust_actions": dust_actions,
            "fencing_valid": fencing_valid,
            "fencing_reason": fencing_reason,
            "equity_summary": eq_summary,
            "circuit_breakers": cb_result,
            "usdc_jpy_rate": rate_val,
            "usdc_jpy_source": rate_src,
            "usdc_inventory_bootstrap": usdc_bootstrap_res,
            "shadow_evaluations": shadow_eval_summary,
        }

    # ==========================================================================
    # 6. 15分 レーダー＆AI判定ループ (`run_15m_ai_radar_tick`)
    # ==========================================================================
    def run_15m_ai_radar_tick(
        self,
        candidate_pairs: Optional[List[str]] = None,
        l2_books_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        candles_by_pair: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
        perp_signals_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
        now_dt: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        15分周期で実行されるユニバース更新 ➔ 7段階フィルタ ➔ 4H/1H/15m 指標算出 ➔
        脱バイアスAI判定 ➔ Single-Bullet サイジング ➔ Slot 1 / Slot 2 の `Alo` 発注ループ。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        self.coordinator.reset_thread_local_lock_state()
        sys_st = self.db.get_system_state()

        if int(sys_st.get("operator_paused", 0)) == 1:
            return {"status": "SKIPPED", "reason": "OPERATOR_PAUSED"}
        if str(sys_st.get("system_mode")) != SystemMode.NORMAL.value:
            return {"status": "SKIPPED", "reason": f"SYSTEM_MODE_{sys_st.get('system_mode')}"}

        sched = self.evaluate_campaign_schedule(now_dt=now_dt)
        if not sched.get("new_entry_allowed", True):
            return {"status": "SKIPPED", "reason": f"CAMPAIGN_PHASE_{sched.get('phase')}"}

        # L1 日次最大エントリー回数制限 (4回/日)
        if int(sys_st.get("daily_trade_count", 0)) >= self.MAX_DAILY_TRADES:
            return {"status": "SKIPPED", "reason": "L1_DAILY_TRADE_LIMIT_REACHED"}

        if ts < int(sys_st.get("l3_active_until_ms", 0)) or ts < int(sys_st.get("l4_active_until_ms", 0)):
            return {"status": "SKIPPED", "reason": "L3_OR_L4_CIRCUIT_BREAKER_ACTIVE"}

        l2_active = bool(ts < int(sys_st.get("l2_active_until_ms", 0)) or int(sys_st.get("consecutive_losses", 0)) >= 2)
        min_conviction = 85 if l2_active else 75

        # 空きスロットの特定 (Slot 1 が IDLE なら Slot 1、Slot 1 が保有中で Slot 2 が IDLE なら 3重ゲート判定)
        slots = self.db.get_all_slots()
        slot1 = slots.get(1, {})
        slot2 = slots.get(2, {})
        target_slot_id: Optional[int] = None

        if str(slot1.get("state")) == SlotState.IDLE.value:
            target_slot_id = 1
        elif str(slot2.get("state")) == SlotState.IDLE.value:
            c1 = str(slot1.get("coin") or "")
            bbo1 = self.ws.get_bbo(c1) or {}
            bid1 = float(bbo1.get("best_bid") or slot1.get("entry_px") or 0.0)
            btc_p = (perp_signals_by_pair or {}).get("UBTC/USDC") or {}
            hype_p = (perp_signals_by_pair or {}).get("HYPE/USDC") or {}
            gate_res = self.risk_guard.evaluate_slot2_triple_gate(
                slot1_state=slot1,
                slot1_best_bid=bid1,
                slot1_atr_1m=0.0,
                btc_perp_premium_pct=float(btc_p.get("premium_pct", 0.0)),
                btc_perp_delta_oi_15m_pct=float(btc_p.get("delta_oi_15m_pct", 0.0)),
                hype_perp_premium_pct=float(hype_p.get("premium_pct", 0.0)),
                hype_perp_delta_oi_15m_pct=float(hype_p.get("delta_oi_15m_pct", 0.0)),
                l2_active=l2_active,
            )
            if gate_res["allowed"]:
                target_slot_id = 2
            else:
                return {"status": "SKIPPED", "reason": f"SLOT2_GATE_BLOCKED:{gate_res['failed_gate']}"}
        else:
            return {"status": "SKIPPED", "reason": "ALL_SLOTS_OCCUPIED"}

        if self.exchange.info is not None and (
            not self.exchange.pair_to_entry
            or (candidate_pairs is None and hasattr(self.exchange.info, "spot_meta_and_asset_ctxs"))
        ):
            try:
                self.exchange.refresh_universe_mapping()
            except Exception as exc:
                logger.warning(f"[15m Radar] refresh_universe_mapping 警告: {exc}")

        if candidate_pairs is not None:
            pairs_to_scan = list(candidate_pairs)
        else:
            all_known = list(self.exchange.pair_to_entry.keys())
            if len(all_known) > 20:
                filtered_pairs = [
                    p
                    for p in all_known
                    if p in self.radar.tier1_pairs
                    or float(self.exchange.pair_to_entry[p].spot_day_ntl_vlm) >= 500_000.0
                ]
                filtered_pairs.sort(
                    key=lambda p: (
                        0 if p in self.radar.tier1_pairs else 1,
                        -float(self.exchange.pair_to_entry[p].spot_day_ntl_vlm),
                    )
                )
                pairs_to_scan = filtered_pairs
            else:
                pairs_to_scan = all_known
        evaluations: List[Dict[str, Any]] = []
        placed_order: Optional[Dict[str, Any]] = None

        balances = self.exchange.get_spot_balances()
        free_usdc = float(balances.get("USDC", {}).get("free", Decimal("0")))
        equity_usdc = float(sys_st.get("current_equity_usdc") or free_usdc or 130.0)

        for pair in pairs_to_scan:
            sp_entry = self.exchange.get_spot_entry(pair)
            if sp_entry is None:
                continue
            book = (l2_books_by_pair or {}).get(pair) or self.ws.get_bbo(pair) or {}
            min_vlm_req = (
                self.radar.tier1_min_vlm_usdc
                if self.radar.get_pair_tier(sp_entry.pair_name) == 1
                else self.radar.tier2_min_vlm_usdc
            )
            if (
                not book.get("levels")
                and float(sp_entry.spot_day_ntl_vlm) >= min_vlm_req
                and self.exchange.info is not None
                and hasattr(self.exchange.info, "l2_snapshot")
            ):
                try:
                    snap_l2 = self.exchange.info.l2_snapshot(sp_entry.api_coin_name)
                    if isinstance(snap_l2, dict) and snap_l2.get("levels"):
                        book = snap_l2
                        self.ws.handle_l2_book_msg({"data": snap_l2})
                except Exception as exc:
                    logger.debug(f"[15m Radar] l2_snapshot 取得スキップ ({pair}): {exc}")
            p_sig = (perp_signals_by_pair or {}).get(pair)

            gate7 = self.radar.evaluate_7_stage_filter(
                entry=sp_entry,
                l2_book=book,
                perp_signals=p_sig,
            )
            if not gate7.passed:
                self.ai_brain.register_shadow_skip(
                    coin=sp_entry.pair_name,
                    market_regime_4h="NEUTRAL_RANGE",
                    skip_stage=str(gate7.failed_stage or "MICROSTRUCTURE_FILTER"),
                    skip_reason_code=str(gate7.fail_reason or "FILTER_REJECTED"),
                    spot_mid_at_eval=gate7.mid_px or sp_entry.spot_mid_px or 1.0,
                    hypothetical_sl_px=(gate7.mid_px or sp_entry.spot_mid_px or 1.0) * 0.97,
                    hypothetical_tp_px=(gate7.mid_px or sp_entry.spot_mid_px or 1.0) * 1.05,
                    evaluated_at_ms=ts,
                )
                evaluations.append({"pair": pair, "passed_filter": False, "failed_stage": gate7.failed_stage})
                continue

            c_bundle = dict((candles_by_pair or {}).get(pair) or {})
            if not c_bundle and self.exchange.info is not None and hasattr(self.exchange.info, "candles_snapshot"):
                for interval_str, lookback_ms in (
                    ("4h", 60 * 4 * 3600 * 1000),
                    ("1h", 60 * 3600 * 1000),
                    ("15m", 60 * 15 * 60 * 1000),
                ):
                    try:
                        c_rows = self.exchange.info.candles_snapshot(
                            sp_entry.api_coin_name,
                            interval_str,
                            max(0, ts - lookback_ms),
                            ts,
                        )
                        if isinstance(c_rows, list):
                            c_bundle[interval_str] = c_rows
                    except Exception as exc:
                        logger.debug(f"[15m Radar] candles_snapshot 取得スキップ ({pair} {interval_str}): {exc}")

            mtf = self.radar.compute_mtf_indicators(
                pair_name=sp_entry.pair_name,
                candles_4h=c_bundle.get("4h") or [],
                candles_1h=c_bundle.get("1h") or [],
                candles_15m=c_bundle.get("15m") or [],
            )
            decision = self.ai_brain.evaluate_candidate(
                pair_name=sp_entry.pair_name,
                sz_decimals=sp_entry.sz_decimals,
                best_bid=gate7.best_bid,
                mtf_indicators=mtf,
                perp_signals=gate7.details,
                bbo_spread_bps=gate7.bbo_spread_bps,
                min_conviction_score=min_conviction,
                current_time_ms=ts,
            )

            if decision.action != "BUY_ALO":
                self.ai_brain.register_shadow_skip(
                    coin=sp_entry.pair_name,
                    market_regime_4h=decision.market_regime_assessment,
                    skip_stage="AI_DECISION_VETO" if decision.vetoed else "AI_SKIP",
                    skip_reason_code=decision.veto_reason or "AI_CHOSE_SKIP",
                    spot_mid_at_eval=gate7.mid_px,
                    hypothetical_sl_px=decision.sl_px or (gate7.best_bid * 0.97),
                    hypothetical_tp_px=decision.tp_px or (gate7.best_bid * 1.05),
                    ai_conviction_score=decision.conviction_score,
                    evaluated_at_ms=ts,
                )
                evaluations.append({"pair": pair, "passed_filter": True, "decision": decision.to_dict()})
                continue

            sizing = self.risk_guard.calculate_single_bullet_sizing(
                slot_id=target_slot_id,
                equity_usdc=equity_usdc,
                free_usdc=free_usdc,
                entry_px=decision.limit_px,
                sl_px=decision.sl_px,
                sz_decimals=sp_entry.sz_decimals,
                l2_derisk_active=l2_active,
            )
            if not sizing["eligible"]:
                evaluations.append({"pair": pair, "passed_filter": True, "sizing": sizing})
                continue

            ep_id = f"ep_{uuid.uuid4().hex[:16]}"
            order_res = self.exchange.place_spot_buy_alo(
                slot_id=target_slot_id,
                coin_or_pair=sp_entry.pair_name,
                raw_limit_px=sizing["px_str"],
                raw_sz=sizing["sz_str"],
                sl_px=decision.sl_px,
                tp_px=decision.tp_px,
                episode_id=ep_id,
                timestamp_ms=ts,
            )
            if order_res.get("status") == "ok":
                self.ai_brain.record_episodic_entry(
                    slot_id=target_slot_id,
                    coin=sp_entry.pair_name,
                    cloid=order_res["cloid"],
                    oid=order_res.get("oid"),
                    market_regime_4h=decision.market_regime_assessment,
                    trend_alignment_1h=str(mtf.get("trend_alignment_1h", "BULLISH")),
                    bbo_spread_bps=gate7.bbo_spread_bps,
                    perp_funding_rate_hr=float(gate7.details.get("funding_1h_pct", 0.0)),
                    perp_oi_delta_15m_pct=float(gate7.details.get("delta_oi_15m_pct", 0.0)),
                    perp_premium_pct=float(gate7.details.get("premium_pct", 0.0)),
                    decision=decision,
                    order_sz=float(sizing["sz_str"]),
                    notional_usdc=float(sizing["notional_usdc"]),
                    episode_id=ep_id,
                    timestamp_ms=ts,
                )
                placed_order = order_res
                break

        res_status = "ORDER_PLACED" if placed_order else "EVALUATED_NO_ORDER"
        logger.info(
            "[15m Radar] status=%s | target_slot=%s | scanned=%d pairs | passed_filter=%d",
            res_status,
            str(target_slot_id),
            len(evaluations),
            sum(1 for ev in evaluations if ev.get("passed_filter")),
        )
        try:
            self.db.run_wal_checkpoint("PASSIVE")
        except Exception as exc:
            logger.debug(f"[15m Radar] WAL PASSIVE checkpoint スキップ: {exc}")

        if self.dashboard_service is not None:
            try:
                self.dashboard_service.export_public_snapshot()
            except Exception as exc:
                logger.debug(f"[15m Radar] スナップショット出力スキップ: {exc}")

        return {
            "status": res_status,
            "target_slot_id": target_slot_id,
            "placed_order": placed_order,
            "evaluations": evaluations,
        }

    # ==========================================================================
    # 7. 非同期マルチタスク・オーケストレータ (`asyncio.to_thread` 非ブロッキング駆動)
    # ==========================================================================
    async def run_200ms_guardian_step_async(
        self,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        200ms ガーディアンステップ。
        SL/TP/Trailing発動時の同期REST IOC発注が含まれる場合でも `asyncio.to_thread` で
        イベントループの詰まりを防止する。
        """
        return await asyncio.to_thread(self.run_200ms_guardian_tick, current_time_ms)

    async def run_15s_control_step_async(
        self,
        current_time_ms: Optional[int] = None,
        now_dt: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        15秒制御ループをワーカースレッド (`asyncio.to_thread`) で非ブロッキング実行し、
        200ms ガーディアンループのSL監視が一切停止しないことを保証する。
        """
        return await asyncio.to_thread(self.run_15s_control_tick, current_time_ms, now_dt)

    async def run_15m_ai_radar_step_async(
        self,
        candidate_pairs: Optional[List[str]] = None,
        l2_books_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        candles_by_pair: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
        perp_signals_by_pair: Optional[Dict[str, Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
        now_dt: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        15分 AI レーダーループ（REST Info・Gemini API推論等）をワーカースレッド
        (`asyncio.to_thread`) で非ブロッキング実行する。
        """
        return await asyncio.to_thread(
            self.run_15m_ai_radar_tick,
            candidate_pairs,
            l2_books_by_pair,
            candles_by_pair,
            perp_signals_by_pair,
            current_time_ms,
            now_dt,
        )

    async def run_daemon_async(
        self,
        stop_event: Optional[asyncio.Event] = None,
        guardian_interval_sec: float = 0.2,
        control_interval_sec: float = 15.0,
        radar_interval_sec: float = 900.0,
    ) -> None:
        """
        200ms ガーディアン・15秒制御・15分AIレーダーを並列駆動する常駐非同期ランナー。
        Topic 6: Windows 1ms 高分解能タイマー (`timeBeginPeriod(1)` / `timeEndPeriod(1)`) を適用。
        """
        own_stop = stop_event or asyncio.Event()

        async def _guardian_loop() -> None:
            while not own_stop.is_set():
                try:
                    await self.run_200ms_guardian_step_async()
                except Exception as exc:
                    logger.error(f"[Daemon 200ms Guardian] 例外発生: {exc}")
                try:
                    await asyncio.wait_for(own_stop.wait(), timeout=guardian_interval_sec)
                except asyncio.TimeoutError:
                    pass

        async def _control_loop() -> None:
            while not own_stop.is_set():
                try:
                    await self.run_15s_control_step_async()
                except Exception as exc:
                    logger.error(f"[Daemon 15s Control] 例外発生: {exc}")
                try:
                    await asyncio.wait_for(own_stop.wait(), timeout=control_interval_sec)
                except asyncio.TimeoutError:
                    pass

        async def _radar_loop() -> None:
            while not own_stop.is_set():
                try:
                    await self.run_15m_ai_radar_step_async()
                except Exception as exc:
                    logger.error(f"[Daemon 15m Radar] 例外発生: {exc}")
                try:
                    await asyncio.wait_for(own_stop.wait(), timeout=radar_interval_sec)
                except asyncio.TimeoutError:
                    pass

        with WindowsHighResTimer(1):
            await asyncio.gather(_guardian_loop(), _control_loop(), _radar_loop())


def run_production_daemon(
    host: str = "127.0.0.1",
    port: int = 8081,
    pause_on_init: bool = False,
) -> int:
    """
    HL AI Trader v1 本番常駐ランナー:
    - Windows Named Mutex (`Global\\HL_AI_TRADER_V1_MAIN_MUTEX`) による多重起動防止
    - 機密マスク付きローテーションログ (`logs/hl_trader_v1.log`)
    - WebSocket (`userFills` + Tier 1 Spot `l2Book`) バックグラウンド常駐
    - Port 8081 セキュアWebダッシュボード (Forensic Ledger パスワードロック統合)
    - 200ms ガーディアン / 15s 制御 / 15m AI レーダー 3並列非同期ループ
    """
    import threading
    from logging.handlers import RotatingFileHandler
    from src.exchange_wrapper import HLSDKInfo, MAINNET_API_URL
    from src.utils import SecretScrubbingLogFilter, harden_windows_file_acl
    from src.web_server import (
        DashboardStateService,
        create_dashboard_http_server,
        sync_live_readonly_account_state,
    )

    purge_dangerous_environment_variables()
    enable_process_extension_point_mitigation()
    install_egress_domain_whitelist_guard()
    verify_code_integrity_seal(raise_on_failure=True)
    load_safe_dotenv(BASE_DIR / ".env")
    harden_windows_file_acl(BASE_DIR / ".env")
    harden_windows_file_acl(BASE_DIR / ".hl_gitconfig")
    harden_windows_file_acl(BASE_DIR / ".git" / "config")

    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "hl_trader_v1.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    scrub_filter = SecretScrubbingLogFilter()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
        fh = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        fh.addFilter(scrub_filter)
        root_logger.addHandler(fh)

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        sh.addFilter(scrub_filter)
        root_logger.addHandler(sh)

    for lg_name in ("hl_main_daemon", "src.exchange_wrapper", "src.ws_manager", "src.ai_brain", "src.risk_guard", "src.web_server"):
        logging.getLogger(lg_name).addFilter(scrub_filter)

    lock_file = BASE_DIR / "data" / "hl_v1_daemon.lock"
    guard = WindowsSingleInstanceGuard(
        mutex_name=r"Global\HL_AI_TRADER_V1_MAIN_MUTEX",
        lock_file_path=lock_file,
    )
    if not guard.acquire():
        logger.warning("既に別の HL AI Trader v1 インスタンスが稼働中のため起動を中止します。")
        return 0

    try:
        prevent_windows_sleep()
        exec_mode = (os.getenv("EXECUTION_MODE") or "LIVE").strip().upper()
        enable_live_llm = os.getenv("HL_ENABLE_LIVE_GEMINI", "true").strip().lower() in ("1", "true", "yes")

        db_mgr = DatabaseManager()
        harden_windows_file_acl(db_mgr.db_path)
        coord_mgr = ConcurrencyStateCoordinator(db=db_mgr)
        rate_fetcher = UsdcJpyRateFetcher(db_rate_provider=db_mgr.get_latest_usdc_jpy_rate)
        tax_mgr = HyperliquidTaxEngine(db=db_mgr, rate_fetcher=rate_fetcher)

        info_cli = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True) if HLSDKInfo is not None else None
        ex_wrap = HyperliquidExchangeWrapper(
            execution_mode=exec_mode,
            db=db_mgr,
            coordinator=coord_mgr,
            tax_engine=tax_mgr,
            info_client=info_cli if exec_mode != "LIVE" else None,
        )
        ai_brain = DebiasedAIBrain(
            db=db_mgr,
            use_live_llm=enable_live_llm,
        )
        daemon_inst = HLTraderDaemon(
            db=db_mgr,
            coordinator=coord_mgr,
            tax_engine=tax_mgr,
            exchange_wrapper=ex_wrap,
            ai_brain=ai_brain,
            rate_fetcher=rate_fetcher,
            phase1_end_jst=os.getenv("PHASE1_END_JST", "2027-07-09T00:00:00+09:00"),
            phase2_start_jst=os.getenv("PHASE2_START_JST", "2027-07-10T00:00:00+09:00"),
            phase2_end_jst=os.getenv("PHASE2_END_JST", "2027-12-10T00:00:00+09:00"),
            pre_deadline_freeze_hours=float(os.getenv("PRE_DEADLINE_FREEZE_HOURS", "2.0")),
        )
        svc = DashboardStateService(
            db=db_mgr,
            tax_engine=tax_mgr,
            coordinator=coord_mgr,
            daemon=daemon_inst,
        )
        daemon_inst.dashboard_service = svc

        # Win32 コンソール/OSシャットダウン・ログオフハンドラ登録
        register_windows_shutdown_handlers(
            lambda ev_name: daemon_inst.execute_graceful_power_or_os_shutdown(reason=ev_name)
        )

        # Port 8081 セキュア Web ダッシュボードサーバーを即座にバックグラウンドスレッドで起動
        http_srv = create_dashboard_http_server(service=svc, host=host, port=port)
        http_thread = threading.Thread(
            target=http_srv.serve_forever,
            name="hl_web_dashboard_8081",
            daemon=True,
        )
        http_thread.start()
        logger.info(
            "Port %d セキュアWebサーバー稼働開始 (http://%s:%d, Forensic Ledger パスワードロック有効)",
            port,
            host,
            port,
        )

        status_init = sync_live_readonly_account_state(svc, pause_on_init=pause_on_init)
        logger.info(
            "HL AI Trader v1 本番初期化完了: PID=%d | mode=%s | badge=%s | equity=%.2f USDC | agent=%s",
            os.getpid(),
            exec_mode,
            status_init.get("status_badge"),
            float(status_init.get("equity", {}).get("current_usdc", 0.0)),
            ex_wrap.agent_address,
        )

        # Agent Wallet 有効期限チェック
        try:
            ag_check = ex_wrap.check_agent_wallet_validity()
            logger.info("Agent Wallet 検証結果: %s", ag_check)
        except Exception as exc:
            logger.warning("Agent Wallet 検証警告: %s", exc)

        # WebSocket バックグラウンド購読開始 (`userFills` + Tier 1 Spot `l2Book`)
        try:
            daemon_inst.ws.start(subscribe_pairs=sorted(daemon_inst.radar.tier1_pairs))
            logger.info("Hyperliquid WebSocket 常駐購読を開始しました: %s", sorted(daemon_inst.radar.tier1_pairs))
        except Exception as exc:
            logger.warning("WebSocket 起動警告 (REST フォールバック継続): %s", exc)

        guardian_sec = max(0.05, float(os.getenv("GUARDIAN_LOOP_MS", "200")) / 1000.0)
        control_sec = max(5.0, float(os.getenv("CONTROL_LOOP_SEC", "15")))
        radar_sec = max(60.0, float(os.getenv("AI_RADAR_LOOP_SEC", "900")))

        asyncio.run(
            daemon_inst.run_daemon_async(
                guardian_interval_sec=guardian_sec,
                control_interval_sec=control_sec,
                radar_interval_sec=radar_sec,
            )
        )
        return 0
    finally:
        guard.release()


if __name__ == "__main__":
    import argparse

    load_safe_dotenv(BASE_DIR / ".env")
    parser = argparse.ArgumentParser(description="HL AI Trader v1 — Autonomous Production Daemon")
    parser.add_argument("--host", default=os.getenv("WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("WEB_PORT", "8081")))
    parser.add_argument("--paused", action="store_true", default=False, help="Start in PAUSED (operator_paused=1) mode")
    parser.add_argument("--live", action="store_true", default=True, help="Start in LIVE RUNNING (operator_paused=0) mode")
    cli_args = parser.parse_args()

    sys.exit(
        run_production_daemon(
            host=cli_args.host,
            port=cli_args.port,
            pause_on_init=bool(cli_args.paused),
        )
    )



