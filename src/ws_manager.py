"""
HL AI Trader v1 — WebSocket Manager with 60s Ping/Pong & Gapless Fill Backfill (src/ws_manager.py)

実装機能 (ARCHITECTURE.md Section 2, Phase 2 要件準拠):
1. 60秒アイドル切断を防ぐ定期 Ping/Pong ハートビート:
   - デフォルト25秒間隔で `{"method": "ping"}` を送信し、サーバーからの `{"channel": "pong"}` を監視
   - タイムアウト検知時はソケットを閉じて指数バックオフ付き自動再接続を実行
2. リアルタイム購読・インメモリ高速キャッシュ:
   - `l2Book`, `allMids`, `activeAssetCtx`, `orderUpdates`, `userFills` を購読
   - 200msガーディアンが0msで参照できるスレッドセーフなBBO (`best_bid`, `best_ask`, `mid_px`) ＆ Perpコンテキストキャッシュ
3. 切断中の約定を `info.user_fills_by_time` で補完するギャップレス・バックフィル (`backfill_missed_fills`):
   - 再接続時（および定期チェック時）に `last_fill_timestamp_ms - 60_000` から現在までの約定を REST `user_fills_by_time` で取得
   - メモリ内 `_processed_tids` と SQLite `tax_lots.hl_tid` UNIQUE制約の2段構えで重複を100%排除しつつ、切断中の約定を漏れなく `HyperliquidTaxEngine` およびスロット状態へ反映
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from src.db import HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.utils import now_ms

try:
    import websocket  # websocket-client
except ImportError:
    websocket = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

MAINNET_WS_URL = "wss://api.hyperliquid.xyz/ws"


class HyperliquidWSManager:
    """
    Hyperliquid WebSocket 接続・定期Ping/Pong・自動再接続・切断時 `user_fills_by_time` 補完マネージャー。
    """

    DEFAULT_PING_INTERVAL_SEC = 25.0
    DEFAULT_STALE_TIMEOUT_SEC = 55.0
    DEFAULT_BACKFILL_OVERLAP_MS = 60_000
    MAX_PROCESSED_TIDS = 5000
    MAX_SENT_SUBSCRIPTIONS = 200

    def __init__(
        self,
        main_address: str,
        ws_url: str = MAINNET_WS_URL,
        exchange_wrapper: Optional[HyperliquidExchangeWrapper] = None,
        tax_engine: Optional[HyperliquidTaxEngine] = None,
        info_client: Optional[Any] = None,
        ping_interval_sec: float = DEFAULT_PING_INTERVAL_SEC,
        stale_timeout_sec: float = DEFAULT_STALE_TIMEOUT_SEC,
        reconnect_base_delay_sec: float = 1.0,
        reconnect_max_delay_sec: float = 30.0,
    ) -> None:
        self.main_address = str(main_address).strip()
        self.ws_url = ws_url
        self.exchange_wrapper = exchange_wrapper
        self.tax_engine = tax_engine or (exchange_wrapper.tax_engine if exchange_wrapper else None)
        self.info = info_client or (exchange_wrapper.info if exchange_wrapper else None)

        self.ping_interval_sec = float(ping_interval_sec)
        self.stale_timeout_sec = float(stale_timeout_sec)
        self.reconnect_base_delay_sec = float(reconnect_base_delay_sec)
        self.reconnect_max_delay_sec = float(reconnect_max_delay_sec)

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._ws_app: Optional[Any] = None
        self._ws_thread: Optional[threading.Thread] = None
        self._ping_thread: Optional[threading.Thread] = None

        # 接続状態・ハートビート統計
        self.is_connected: bool = False
        self.reconnect_count: int = 0
        self.ping_sent_count: int = 0
        self.pong_received_count: int = 0
        self.last_message_received_ms: int = 0
        self.last_ping_sent_ms: int = 0
        self.last_pong_received_ms: int = 0

        # 購読管理
        self._subscribed_coins: Set[str] = set()
        self._sent_subscriptions: List[Dict[str, Any]] = []

        # インメモリ高速マーケットデータキャッシュ (200msガーディアン用)
        self._bbo_cache: Dict[str, Dict[str, Any]] = {}
        self._all_mids_cache: Dict[str, float] = {}
        self._asset_ctx_cache: Dict[str, Dict[str, Any]] = {}
        self._bid_top3_history: Dict[str, List[Tuple[int, float]]] = {}
        self._trades_history: Dict[str, List[Dict[str, Any]]] = {}
        self.rest_failover_count: int = 0

        # 約定補完 (Backfill) 用状態管理
        self.last_fill_timestamp_ms: int = now_ms() - 3_600_000
        self._processed_tids: Set[int] = set()

        # イベントコールバック
        self._fill_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        self._order_update_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    # ==========================================================================
    # コールバック登録 ＆ キャッシュ参照 API
    # ==========================================================================
    def register_fill_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            self._fill_callbacks.append(callback)

    def register_order_update_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            self._order_update_callbacks.append(callback)

    def subscribe_coin(self, coin: str) -> None:
        """監視対象コイン（`@107`, `PURR/USDC`, `BTC` 等）を購読リストへ追加し、接続中なら即時送信する"""
        c = str(coin).strip()
        if not c:
            return
        with self._lock:
            self._subscribed_coins.add(c)
            if self.is_connected:
                self._send_subscription({"type": "l2Book", "coin": c})
                self._send_subscription({"type": "activeAssetCtx", "coin": c})

    def get_bbo(self, coin_or_pair: str) -> Optional[Dict[str, Any]]:
        """指定銘柄の最新BBO (`best_bid`, `best_ask`, `mid_px`, `spread_bps`, `updated_at_ms`) を返す"""
        key = str(coin_or_pair).strip().upper()
        with self._lock:
            if key in self._bbo_cache:
                return dict(self._bbo_cache[key])
            if self.exchange_wrapper is not None:
                entry = self.exchange_wrapper.get_spot_entry(key)
                if entry is not None:
                    for k_cand in (
                        entry.api_coin_name.upper(),
                        entry.pair_name.upper(),
                        entry.base_asset.upper(),
                    ):
                        if k_cand in self._bbo_cache:
                            return dict(self._bbo_cache[k_cand])
        return None

    def get_mid_px(self, coin_or_pair: str) -> Optional[float]:
        bbo = self.get_bbo(coin_or_pair)
        if bbo and bbo.get("mid_px", 0.0) > 0:
            return float(bbo["mid_px"])
        key = str(coin_or_pair).strip().upper()
        with self._lock:
            if key in self._all_mids_cache:
                return float(self._all_mids_cache[key])
        return None

    def get_active_asset_ctx(self, coin: str) -> Optional[Dict[str, Any]]:
        key = str(coin).strip().upper()
        with self._lock:
            ctx = self._asset_ctx_cache.get(key)
            return dict(ctx) if ctx else None

    def is_ws_stalled(
        self,
        threshold_ms: int = 2500,
        current_time_ms: Optional[int] = None,
        coin_or_pair: Optional[str] = None,
    ) -> bool:
        """
        2.5秒サイレントストール検知器 (v1.1 Topic 6):
        WebSocket 最終メッセージ受信時刻（または指定銘柄の `l2Book` 最終更新時刻）から
        `threshold_ms` (デフォルト 2500ms) 以上経過している場合に True を返す。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        with self._lock:
            if coin_or_pair:
                bbo = self.get_bbo(coin_or_pair)
                if bbo is not None:
                    upd_ms = int(bbo.get("updated_at_ms") or 0)
                    if upd_ms > 0 and (ts - upd_ms) > int(threshold_ms):
                        return True
            if self.last_message_received_ms > 0 and (ts - self.last_message_received_ms) > int(threshold_ms):
                return True
            return False

    def get_bbo_with_rest_failover(
        self,
        coin_or_pair: str,
        info_client: Optional[Any] = None,
        threshold_ms: int = 2500,
        current_time_ms: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        WebSocket キャッシュから BBO を取得し、もし 2.5秒以上サイレントストールしている場合や
        キャッシュ未登録の場合には軽量 REST `l2_snapshot` ポーリングへ自動フェイルオーバーして
        200msガーディアンの盲目化を0msで防ぐ。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        bbo = self.get_bbo(coin_or_pair)
        stalled = self.is_ws_stalled(
            threshold_ms=threshold_ms,
            current_time_ms=ts,
            coin_or_pair=coin_or_pair,
        )
        if bbo is not None and not stalled and float(bbo.get("best_bid", 0.0)) > 0:
            return bbo

        cli = info_client or self.info or (self.exchange_wrapper.info if self.exchange_wrapper else None)
        if cli is not None and hasattr(cli, "l2_snapshot"):
            api_coin = str(coin_or_pair).strip()
            if self.exchange_wrapper is not None:
                sp_ent = self.exchange_wrapper.get_spot_entry(api_coin)
                if sp_ent is not None and sp_ent.api_coin_name:
                    api_coin = sp_ent.api_coin_name
            try:
                snap = cli.l2_snapshot(api_coin)
                if isinstance(snap, dict) and snap.get("levels"):
                    if "coin" not in snap:
                        snap = {**snap, "coin": api_coin, "time": ts}
                    else:
                        snap = {**snap, "time": ts}
                    self.handle_l2_book_msg({"channel": "l2Book", "data": snap}, current_time_ms=ts)
                    with self._lock:
                        self.rest_failover_count += 1
                    fresh = self.get_bbo(coin_or_pair)
                    if fresh is not None:
                        fresh["rest_failover_used"] = True
                        return fresh
            except Exception as exc:
                logger.debug("REST l2_snapshot フェイルオーバー取得失敗 (%s): %s", coin_or_pair, exc)

        return bbo

    def get_bid_top3_depth_ratio_3s(
        self,
        coin_or_pair: str,
        current_time_ms: Optional[int] = None,
        lookback_ms: int = 3000,
    ) -> float:
        """
        指定銘柄の現在の上位3ティック Bid 板厚合計 `sum_{i=1..3} v_{bid,i}(t)` と
        3秒前 (`t - 3000ms`) の基準板厚との比率 `V(t) / V(t - 3s)` を返す。
        履歴が不十分な場合は 1.0 を返す。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        key = str(coin_or_pair).strip().upper()
        if self.exchange_wrapper is not None:
            sp_ent = self.exchange_wrapper.get_spot_entry(key)
            if sp_ent is not None:
                key = sp_ent.pair_name.upper()
        with self._lock:
            hist = list(self._bid_top3_history.get(key) or [])
        if len(hist) < 2:
            return 1.0
        cur_ts, cur_depth = hist[-1]
        ref_depth = hist[0][1]
        for h_ts, h_d in reversed(hist[:-1]):
            if (cur_ts - h_ts) >= int(lookback_ms * 0.7):
                ref_depth = h_d
                break
        if ref_depth <= 1e-9:
            return 1.0
        return float(cur_depth / ref_depth)

    def handle_trades_msg(
        self,
        msg: Dict[str, Any],
        current_time_ms: Optional[int] = None,
    ) -> Optional[str]:
        """
        `trades` チャネルメッセージ（または約定リスト）を受信し、銘柄別の1時間約定フロー履歴を更新する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        data = msg.get("data") if isinstance(msg, dict) and "data" in msg else msg
        trades_list = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        cutoff_1h = ts - 3_600_000

        with self._lock:
            for tr in trades_list:
                if not isinstance(tr, dict):
                    continue
                coin = str(tr.get("coin", "")).strip()
                if not coin:
                    continue
                try:
                    px = float(tr.get("px", 0.0))
                    sz = float(tr.get("sz", 0.0))
                    t_ms = int(tr.get("time", ts))
                except (TypeError, ValueError):
                    continue
                if px <= 0 or sz <= 0:
                    continue
                side_raw = str(tr.get("side", "B")).strip().upper()
                side = "B" if side_raw in ("B", "BUY", "BID") else "A"
                entry = {
                    "coin": coin,
                    "side": side,
                    "px": px,
                    "sz": sz,
                    "notional": px * sz,
                    "time": t_ms,
                }
                keys = {coin.upper()}
                if self.exchange_wrapper is not None:
                    sp = self.exchange_wrapper.get_spot_entry(coin)
                    if sp is not None:
                        keys.update({sp.pair_name.upper(), sp.api_coin_name.upper(), sp.base_asset.upper()})
                for k in keys:
                    hist = self._trades_history.setdefault(k, [])
                    hist.append(entry)
                    if len(hist) > 2000:
                        self._trades_history[k] = [x for x in hist if int(x["time"]) >= cutoff_1h][-2000:]
        return "trades"

    def compute_cvd_and_whale_metrics(
        self,
        coin_or_pair: str,
        trades_override: Optional[List[Dict[str, Any]]] = None,
        current_time_ms: Optional[int] = None,
        eps_vol_usdc: float = 100.0,
        whale_min_usdc: float = 500.0,
    ) -> Dict[str, float]:
        """
        v1.2 論点1: 時間窓 τ in {5m, 15m, 1h} における無次元化正規化CVD:
          CVD_hat_{m,tau}(t) = delta_{m,tau}(t) / (V_{m,tau}(t) + 100.0) in [-1, 1]
        および 90パーセンタイル（下限 500 USDC）大口約定による1時間クジラ約定偏り:
          W_{whale,1h}(t) in [-1, 1]
        を算出する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        if trades_override is not None:
            raw_trades = list(trades_override)
        else:
            key = str(coin_or_pair).strip().upper()
            with self._lock:
                raw_trades = list(self._trades_history.get(key) or [])

        parsed_1h: List[Tuple[int, str, float]] = []
        cutoff_1h = ts - 3_600_000
        cutoff_15m = ts - 900_000
        cutoff_5m = ts - 300_000

        for tr in raw_trades:
            if not isinstance(tr, dict):
                continue
            try:
                t_ms = int(tr.get("time", ts))
                if t_ms < cutoff_1h:
                    continue
                ntl = float(tr.get("notional") or (float(tr.get("px", 0.0)) * float(tr.get("sz", 0.0))))
                if ntl <= 0:
                    continue
                side_raw = str(tr.get("side", "B")).strip().upper()
                side = "B" if side_raw in ("B", "BUY", "BID") else "A"
                parsed_1h.append((t_ms, side, ntl))
            except (TypeError, ValueError):
                continue

        def _calc_window_cvd(cutoff: int) -> float:
            b_vol = sum(ntl for t_ms, s, ntl in parsed_1h if t_ms >= cutoff and s == "B")
            a_vol = sum(ntl for t_ms, s, ntl in parsed_1h if t_ms >= cutoff and s == "A")
            delta = b_vol - a_vol
            tot = b_vol + a_vol
            return float(max(-1.0, min(1.0, delta / (tot + float(eps_vol_usdc)))))

        cvd_5m = _calc_window_cvd(cutoff_5m)
        cvd_15m = _calc_window_cvd(cutoff_15m)
        cvd_1h = _calc_window_cvd(cutoff_1h)

        # 1h Whale trade imbalance (90th percentile with floor 500 USDC)
        whale_1h = 0.0
        if parsed_1h:
            sorted_ntls = sorted(ntl for _, _, ntl in parsed_1h)
            if len(sorted_ntls) >= 10:
                idx90 = min(len(sorted_ntls) - 1, int(len(sorted_ntls) * 0.90))
                p90 = sorted_ntls[idx90]
                whale_thresh = max(float(whale_min_usdc), p90)
            else:
                whale_thresh = float(whale_min_usdc)
            w_buy = sum(ntl for _, s, ntl in parsed_1h if ntl >= whale_thresh and s == "B")
            w_sell = sum(ntl for _, s, ntl in parsed_1h if ntl >= whale_thresh and s == "A")
            w_tot = w_buy + w_sell
            if w_tot > 0:
                whale_1h = float(max(-1.0, min(1.0, (w_buy - w_sell) / (w_tot + float(eps_vol_usdc)))))

        return {
            "cvd_5m": round(cvd_5m, 6),
            "cvd_15m": round(cvd_15m, 6),
            "cvd_1h": round(cvd_1h, 6),
            "whale_1h": round(whale_1h, 6),
        }

    # ==========================================================================
    # WebSocket 送受信・定期 Ping/Pong (60秒タイムアウト防止)
    # ==========================================================================
    def _send_json(self, payload: Dict[str, Any], ws_override: Optional[Any] = None) -> bool:
        target_ws = ws_override if ws_override is not None else self._ws_app
        if target_ws is None:
            return False
        try:
            raw_msg = json.dumps(payload)
            target_ws.send(raw_msg)
            return True
        except Exception as exc:
            logger.debug("WebSocket 送信エラー: %s", exc)
            return False

    def _send_subscription(self, subscription: Dict[str, Any], ws_override: Optional[Any] = None) -> bool:
        msg = {"method": "subscribe", "subscription": subscription}
        ok = self._send_json(msg, ws_override=ws_override)
        if ok:
            with self._lock:
                self._sent_subscriptions.append(subscription)
                if len(self._sent_subscriptions) > self.MAX_SENT_SUBSCRIPTIONS:
                    self._sent_subscriptions = self._sent_subscriptions[-self.MAX_SENT_SUBSCRIPTIONS :]
        return ok

    def send_ping(self, ws_override: Optional[Any] = None) -> bool:
        """
        Hyperliquid WebSocket 仕様に従い `{"method": "ping"}` を送信し、60秒アイドル切断を防ぐ。
        """
        ok = self._send_json({"method": "ping"}, ws_override=ws_override)
        if ok:
            with self._lock:
                self.ping_sent_count += 1
                self.last_ping_sent_ms = now_ms()
        return ok

    def _ping_worker_loop(self) -> None:
        """バックグラウンドで定期 Ping を送信し、無応答タイムアウト時は再接続を促すループ"""
        while not self._stop_event.wait(timeout=self.ping_interval_sec):
            if not self.is_connected:
                continue
            self.send_ping()
            ts = now_ms()
            last_act = max(self.last_message_received_ms, self.last_pong_received_ms)
            if last_act > 0 and (ts - last_act) > int(self.stale_timeout_sec * 1000):
                logger.warning(
                    "WebSocket 無通信時間が %.1f 秒を超過したため再接続をトリガーします。",
                    (ts - last_act) / 1000.0,
                )
                try:
                    if self._ws_app is not None:
                        self._ws_app.close()
                except Exception:
                    pass

    def _on_ws_open(self, ws: Any) -> None:
        ts = now_ms()
        with self._lock:
            was_reconnect = self.reconnect_count > 0 or self.last_message_received_ms > 0
            self.is_connected = True
            self.last_message_received_ms = ts
            self.last_pong_received_ms = ts
            self._sent_subscriptions.clear()
            coins_to_sub = sorted(self._subscribed_coins)

        # 基本チャネルの購読
        self._send_subscription({"type": "allMids"}, ws_override=ws)
        if self.main_address and self.main_address != "0x" + "0" * 40:
            self._send_subscription(
                {"type": "userFills", "user": self.main_address}, ws_override=ws
            )
            self._send_subscription(
                {"type": "orderUpdates", "user": self.main_address}, ws_override=ws
            )
        for coin in coins_to_sub:
            self._send_subscription({"type": "l2Book", "coin": coin}, ws_override=ws)
            self._send_subscription({"type": "activeAssetCtx", "coin": coin}, ws_override=ws)

        # 切断中の約定を REST user_fills_by_time でギャップレス補完
        if was_reconnect or self.info is not None:
            try:
                self.backfill_missed_fills()
            except Exception as exc:
                logger.warning("WebSocket オープン時の約定補完 (backfill) エラー: %s", exc)

    def _on_ws_message(self, ws: Any, raw_message: str) -> None:
        self.handle_raw_message(raw_message)

    def _on_ws_error(self, ws: Any, error: Any) -> None:
        logger.debug("WebSocket エラー検知: %s", error)

    def _on_ws_close(self, ws: Any, close_status_code: Any, close_msg: Any) -> None:
        with self._lock:
            self.is_connected = False

    # ==========================================================================
    # メッセージ解析・ディスパッチ (`handle_raw_message`)
    # ==========================================================================
    def handle_raw_message(self, raw_message: str | Dict[str, Any]) -> Optional[str]:
        """
        受信した WebSocket JSON メッセージを解析してキャッシュまたはコールバックへ反映する。
        処理したチャネル名を返す。
        """
        ts = now_ms()
        with self._lock:
            self.last_message_received_ms = ts

        if isinstance(raw_message, dict):
            msg = raw_message
        else:
            try:
                msg = json.loads(raw_message)
            except Exception as exc:
                logger.debug("WebSocket 非JSONメッセージ無視: %s", exc)
                return None

        channel = str(msg.get("channel", ""))
        data = msg.get("data")

        if channel == "pong":
            with self._lock:
                self.pong_received_count += 1
                self.last_pong_received_ms = ts
            return "pong"

        if channel == "allMids" and isinstance(data, dict):
            mids = data.get("mids") or {}
            with self._lock:
                for k, v in mids.items():
                    try:
                        self._all_mids_cache[str(k).upper()] = float(v)
                    except (TypeError, ValueError):
                        pass
            return "allMids"

        if channel == "l2Book" and isinstance(data, dict):
            return self.handle_l2_book_msg(msg, current_time_ms=ts)

        if channel == "trades":
            return self.handle_trades_msg(msg, current_time_ms=ts)

        if channel == "activeAssetCtx" and isinstance(data, dict):
            coin = str(data.get("coin", "")).strip().upper()
            ctx = data.get("ctx") or {}
            if coin and isinstance(ctx, dict):
                with self._lock:
                    self._asset_ctx_cache[coin] = {
                        **ctx,
                        "coin": coin,
                        "updated_at_ms": ts,
                    }
            return "activeAssetCtx"

        if channel == "userFills":
            fills_list: List[Dict[str, Any]] = []
            if isinstance(data, dict):
                fills_list = data.get("fills") or []
            elif isinstance(data, list):
                fills_list = data
            for fill in fills_list:
                if isinstance(fill, dict):
                    self._process_single_fill(fill, source="WS_STREAM")
            return "userFills"

        if channel == "orderUpdates":
            updates_list = data if isinstance(data, list) else []
            with self._lock:
                cbs = list(self._order_update_callbacks)
            for upd in updates_list:
                if isinstance(upd, dict):
                    for cb in cbs:
                        try:
                            cb(upd)
                        except Exception as exc:
                            logger.warning("orderUpdate コールバック例外: %s", exc)
            return "orderUpdates"

        return channel or None

    def handle_l2_book_msg(
        self,
        msg: Dict[str, Any],
        current_time_ms: Optional[int] = None,
    ) -> Optional[str]:
        """
        `l2Book` メッセージまたは REST `l2_snapshot` レスポンスを解析し、
        BBOキャッシュ・上位5ティックOBI (`obi_5`)・上位3ティックBid板厚3秒履歴を更新する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        data = msg.get("data") if isinstance(msg, dict) and "data" in msg else msg
        if not isinstance(data, dict):
            return None
        coin = str(data.get("coin", "")).strip()
        levels = data.get("levels") or []
        if coin and len(levels) >= 2 and levels[0] and levels[1]:
            try:
                bids = levels[0]
                asks = levels[1]
                best_bid = float(bids[0]["px"])
                best_ask = float(asks[0]["px"])
                mid_px = (best_bid + best_ask) / 2.0 if (best_bid > 0 and best_ask > 0) else 0.0
                spread_bps = (
                    ((best_ask - best_bid) / mid_px) * 10_000.0 if mid_px > 0 else 0.0
                )
                bid_v5 = sum(float(b.get("px", 0.0)) * float(b.get("sz", 0.0)) for b in bids[:5])
                ask_v5 = sum(float(a.get("px", 0.0)) * float(a.get("sz", 0.0)) for a in asks[:5])
                obi_5 = ((bid_v5 - ask_v5) / (bid_v5 + ask_v5)) if (bid_v5 + ask_v5) > 0 else 0.0
                bid_top3_usdc = sum(float(b.get("px", 0.0)) * float(b.get("sz", 0.0)) for b in bids[:3])
                upd_ms = int(data.get("time", ts))
                bbo_entry = {
                    "coin": coin,
                    "best_bid": best_bid,
                    "best_ask": best_ask,
                    "mid_px": mid_px,
                    "spread_bps": spread_bps,
                    "obi_5": round(obi_5, 4),
                    "bid_top3_usdc": round(bid_top3_usdc, 2),
                    "levels": levels,
                    "updated_at_ms": upd_ms,
                }
                with self._lock:
                    self._bbo_cache[coin.upper()] = bbo_entry
                    hist_key = coin.upper()
                    if self.exchange_wrapper is not None:
                        sp_entry = self.exchange_wrapper.get_spot_entry(coin)
                        if sp_entry is not None:
                            self._bbo_cache[sp_entry.pair_name.upper()] = bbo_entry
                            self._bbo_cache[sp_entry.api_coin_name.upper()] = bbo_entry
                            self._bbo_cache[sp_entry.base_asset.upper()] = bbo_entry
                            hist_key = sp_entry.pair_name.upper()
                    hist = self._bid_top3_history.setdefault(hist_key, [])
                    hist.append((upd_ms, bid_top3_usdc))
                    cutoff = upd_ms - 10_000
                    if len(hist) > 30:
                        self._bid_top3_history[hist_key] = [x for x in hist if x[0] >= cutoff][-30:]
            except Exception as exc:
                logger.debug("l2Book 解析エラー: %s", exc)
        return "l2Book"

    # ==========================================================================
    # 約定処理 ＆ 切断時 `user_fills_by_time` バックフィル補完
    # ==========================================================================
    def _resolve_spot_fill_metadata(self, raw_coin: str) -> Optional[Tuple[str, str]]:
        """
        約定データの `coin` フィールドから Spot の `(pair_name, base_asset)` を解決する。
        Perp約定（例: `BTC`, `ETH`, `SOL` で Spot ユニバースに一致しないもの）の場合は `None` を返す。
        """
        c = str(raw_coin or "").strip()
        if not c or c.startswith("#"):
            return None

        if self.exchange_wrapper is not None:
            # `@107` または `HYPE/USDC` として Spot 辞書に存在するか確認
            upper = c.upper()
            entry = (
                self.exchange_wrapper.pair_to_entry.get(upper)
                or self.exchange_wrapper.api_coin_to_entry.get(upper)
            )
            if entry is not None:
                return (entry.pair_name, entry.base_asset)

        if "/" in c:
            parts = c.upper().split("/", 1)
            if parts[1] == "USDC":
                return (f"{parts[0]}/USDC", parts[0])

        if c.startswith("@"):
            # 万一マッピング未登録の @index の場合でも Spot 約定としてペア名を保持
            return (c, c)

        return None

    def _process_single_fill(self, fill: Dict[str, Any], source: str = "WS_STREAM") -> bool:
        """
        単一の約定イベントをべき等に処理し、Spot約定であれば `HyperliquidTaxEngine` および
        登録済みコールバックへ通知する。新規処理された場合は True、重複/非Spotの場合は False を返す。
        """
        tid = int(fill.get("tid", 0))
        if tid <= 0:
            return False

        with self._lock:
            if tid in self._processed_tids:
                return False

        raw_coin = str(fill.get("coin", "")).strip()
        spot_meta = self._resolve_spot_fill_metadata(raw_coin)
        if spot_meta is None:
            # Perps約定などは対象外としてスキップ
            return False

        pair_name, base_asset = spot_meta
        fill_ts = int(fill.get("time", now_ms()))
        side_raw = str(fill.get("side", "")).strip().upper()
        dir_raw = str(fill.get("dir", "")).strip().lower()
        is_buy = (side_raw in ("B", "BUY")) or ("buy" in dir_raw)

        px_str = str(fill.get("px", "0"))
        sz_str = str(fill.get("sz", "0"))
        fee_str = str(fill.get("fee", "0"))
        fee_token = str(fill.get("feeToken") or (base_asset if is_buy else "USDC")).strip().upper()
        oid = int(fill["oid"]) if fill.get("oid") is not None else None

        with self._lock:
            if tid in self._processed_tids:
                return False
            self._processed_tids.add(tid)
            if len(self._processed_tids) > self.MAX_PROCESSED_TIDS:
                keep_count = self.MAX_PROCESSED_TIDS // 2
                sorted_tids = sorted(self._processed_tids)
                self._processed_tids = set(sorted_tids[-keep_count:])
            if fill_ts > self.last_fill_timestamp_ms:
                self.last_fill_timestamp_ms = fill_ts
            cbs = list(self._fill_callbacks)

        if self.tax_engine is not None:
            try:
                self.tax_engine.process_spot_fill(
                    hl_tid=tid,
                    hl_oid=oid,
                    timestamp_ms=fill_ts,
                    pair_name=pair_name,
                    base_asset=base_asset,
                    is_buy=is_buy,
                    exec_px_usdc=px_str,
                    exec_sz_base=sz_str,
                    raw_fee_amount=fee_str,
                    raw_fee_token=fee_token,
                )
            except Exception as exc:
                logger.error("約定の税務エンジン記録中に例外が発生しました (tid=%d): %s", tid, exc)

        enriched_fill = {
            **fill,
            "pair_name": pair_name,
            "base_asset": base_asset,
            "is_buy": is_buy,
            "fee_token": fee_token,
            "timestamp_ms": fill_ts,
            "source": source,
        }
        for cb in cbs:
            try:
                cb(enriched_fill)
            except Exception as exc:
                logger.warning("fill コールバック例外 (tid=%d): %s", tid, exc)

        return True

    def backfill_missed_fills(
        self,
        start_time_ms: Optional[int] = None,
        overlap_window_ms: int = DEFAULT_BACKFILL_OVERLAP_MS,
    ) -> Dict[str, Any]:
        """
        WebSocket 切断中に発生した約定を `info.user_fills_by_time` で取得し、
        未処理の Spot 約定を時系列順に漏れなく補完する。
        """
        if self.info is None:
            return {"fetched_count": 0, "new_processed_count": 0, "reason": "NO_INFO_CLIENT"}

        with self._lock:
            base_ts = int(start_time_ms) if start_time_ms is not None else max(
                0, self.last_fill_timestamp_ms - int(overlap_window_ms)
            )

        try:
            # SDKのバージョンにより aggregate_by_time 引数の有無が異なるため両対応
            try:
                raw_fills = self.info.user_fills_by_time(
                    self.main_address,
                    base_ts,
                    aggregate_by_time=False,
                )
            except TypeError:
                raw_fills = self.info.user_fills_by_time(self.main_address, base_ts)
        except Exception as exc:
            logger.warning("user_fills_by_time 呼び出し失敗: %s", exc)
            return {"fetched_count": 0, "new_processed_count": 0, "error": str(exc)}

        fills_list = raw_fills if isinstance(raw_fills, list) else []
        # 時系列昇順（古い順）にソートして移動平均原価の計算順序を保証
        sorted_fills = sorted(
            [f for f in fills_list if isinstance(f, dict)],
            key=lambda x: (int(x.get("time", 0)), int(x.get("tid", 0))),
        )

        new_count = 0
        processed_tids: List[int] = []
        for f in sorted_fills:
            if self._process_single_fill(f, source="REST_BACKFILL"):
                new_count += 1
                processed_tids.append(int(f.get("tid", 0)))

        return {
            "fetched_count": len(sorted_fills),
            "new_processed_count": new_count,
            "processed_tids": processed_tids,
            "start_time_ms": base_ts,
        }

    # ==========================================================================
    # ライフサイクル制御 (start / stop / 自動再接続ループ)
    # ==========================================================================
    def _connection_supervisor_loop(self) -> None:
        """切断時に指数バックオフで自動再接続を繰り返すワーカー"""
        attempt = 0
        while not self._stop_event.is_set():
            if websocket is None:
                logger.warning("websocket-client パッケージが未導入のためWSループを待機します。")
                break

            try:
                ws_app = websocket.WebSocketApp(
                    self.ws_url,
                    on_open=self._on_ws_open,
                    on_message=self._on_ws_message,
                    on_error=self._on_ws_error,
                    on_close=self._on_ws_close,
                )
                with self._lock:
                    self._ws_app = ws_app
                ws_app.run_forever()
            except Exception as exc:
                logger.warning("WebSocket run_forever 例外: %s", exc)
            finally:
                with self._lock:
                    self.is_connected = False
                    self._ws_app = None

            if self._stop_event.is_set():
                break

            attempt += 1
            with self._lock:
                self.reconnect_count += 1
            delay = min(
                self.reconnect_max_delay_sec,
                self.reconnect_base_delay_sec * (2 ** min(attempt - 1, 5)),
            )
            logger.info("WebSocket 切断検知: %.1f 秒後に再接続を試行します (reconnect=%d)", delay, self.reconnect_count)
            if self._stop_event.wait(timeout=delay):
                break

    def start(self, subscribe_pairs: Optional[List[str]] = None) -> None:
        """WebSocket 監視スレッドおよび定期 Ping スレッドを起動する"""
        if subscribe_pairs:
            for p in subscribe_pairs:
                coin_str = str(p).strip()
                if not coin_str:
                    continue
                if self.exchange_wrapper is not None:
                    sp_ent = self.exchange_wrapper.get_spot_entry(coin_str)
                    if sp_ent is not None and sp_ent.api_coin_name:
                        coin_str = sp_ent.api_coin_name
                self.subscribe_coin(coin_str)

        if self.info is not None and hasattr(self.info, "user_fills_by_time"):
            try:
                self.backfill_missed_fills(start_time_ms=now_ms() - 3_600_000)
            except Exception as exc:
                logger.debug("起動時 backfill_missed_fills スキップ: %s", exc)

        self._stop_event.clear()
        if self._ws_thread is None or not self._ws_thread.is_alive():
            self._ws_thread = threading.Thread(
                target=self._connection_supervisor_loop,
                name="HL-WS-Supervisor",
                daemon=True,
            )
            self._ws_thread.start()

        if self._ping_thread is None or not self._ping_thread.is_alive():
            self._ping_thread = threading.Thread(
                target=self._ping_worker_loop,
                name="HL-WS-PingWorker",
                daemon=True,
            )
            self._ping_thread.start()

    def stop(self) -> None:
        """WebSocket 接続およびバックグラウンドスレッドを安全に停止する"""
        self._stop_event.set()
        with self._lock:
            ws = self._ws_app
            self.is_connected = False
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
