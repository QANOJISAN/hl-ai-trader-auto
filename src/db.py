"""
HL AI Trader v1 — SQLite WAL Database & Dual-Leg Tax Engine (src/db.py)

実装機能:
1. DatabaseManager:
   - `e:/hl-ai-trader-auto/data/hl_v1_state_wal.db` の管理
   - `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=15000; PRAGMA wal_autocheckpoint=1000;`
   - ARCHITECTURE.md 第8章で定義された全10テーブル＋インデックスのDDL完全初期化
   - `BEGIN IMMEDIATE` による排他トランザクション制御
2. HyperliquidTaxEngine:
   - 日本の暗号資産税制に準拠した暗号資産間交換の二重課税イベント（譲渡レグ Disposed Leg ＋ 取得レグ Acquired Leg の同時計上）
   - `raw_fee_token` の3分岐（Base Asset控除 / Quote USDC控除 / 第3トークン控除）の厳密処理
   - `hl_tid` UNIQUE制約による完全べき等記録（WebSocket と `user_fills_by_time` の重複排除）
   - 移動平均法 (`MOVING_AVERAGE`) のリアルタイム簿価更新と、総平均法 (`TOTAL_AVERAGE`) の年次一括再計算レポート出力
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
import threading
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from src.utils import (
    UsdcJpyRateFetcher,
    _to_clean_decimal,
    jst_date_str,
    jst_tax_year,
    now_ms,
)

logger = logging.getLogger(__name__)

# 全10テーブル＋インデックスの完全DDL定義 (ARCHITECTURE.md Section 8 & v1.1 準拠)
DDL_STATEMENTS = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA journal_size_limit = 33554432;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS system_state_store (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    system_mode TEXT NOT NULL DEFAULT 'NORMAL',
    initial_equity_usdc REAL NOT NULL,
    hwm_equity_usdc REAL NOT NULL,
    sod_equity_usdc REAL NOT NULL,
    sow_equity_usdc REAL NOT NULL,
    current_equity_usdc REAL NOT NULL,
    latest_usdc_jpy_rate REAL NOT NULL DEFAULT 155.0,
    l2_active_until_ms INTEGER NOT NULL DEFAULT 0,
    l3_active_until_ms INTEGER NOT NULL DEFAULT 0,
    l4_active_until_ms INTEGER NOT NULL DEFAULT 0,
    l5_strike_count INTEGER NOT NULL DEFAULT 0,
    desync_strike_count INTEGER NOT NULL DEFAULT 0,
    consecutive_losses INTEGER NOT NULL DEFAULT 0,
    daily_trade_count INTEGER NOT NULL DEFAULT 0,
    operator_paused INTEGER NOT NULL DEFAULT 0,
    mutation_epoch INTEGER NOT NULL DEFAULT 0,
    quiescence_until_ms INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS slot_state_store (
    slot_id INTEGER PRIMARY KEY CHECK (slot_id IN (1, 2)),
    state TEXT NOT NULL DEFAULT 'IDLE',
    sub_state TEXT NOT NULL DEFAULT 'NONE',
    coin TEXT,
    base_asset TEXT,
    sz_decimals INTEGER,
    active_cloid TEXT,
    active_oid INTEGER,
    entry_px REAL DEFAULT 0.0,
    current_sz REAL DEFAULT 0.0,
    sl_px REAL DEFAULT 0.0,
    tp_px REAL DEFAULT 0.0,
    trailing_stage INTEGER DEFAULT 1,
    order_created_at_ms INTEGER DEFAULT 0,
    episode_id TEXT,
    mutation_epoch INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dust_quarantine (
    base_asset TEXT PRIMARY KEY,
    coin_pair TEXT NOT NULL,
    quarantined_qty REAL NOT NULL,
    estimated_usdc_val REAL NOT NULL,
    recovery_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_ms INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'QUARANTINED'
);

CREATE TABLE IF NOT EXISTS ai_episodic_memory (
    episode_id TEXT PRIMARY KEY,
    timestamp_ms INTEGER NOT NULL,
    slot_id INTEGER NOT NULL CHECK (slot_id IN (1, 2)),
    coin TEXT NOT NULL,
    cloid TEXT NOT NULL UNIQUE,
    oid INTEGER,
    market_regime_4h TEXT NOT NULL,
    trend_alignment_1h TEXT NOT NULL,
    bbo_spread_bps REAL NOT NULL,
    perp_funding_rate_hr REAL NOT NULL,
    perp_oi_delta_15m_pct REAL NOT NULL,
    perp_premium_pct REAL NOT NULL,
    conviction_score INTEGER NOT NULL CHECK (conviction_score BETWEEN 0 AND 100),
    entry_limit_px REAL NOT NULL,
    initial_sl_px REAL NOT NULL,
    target_tp_px REAL NOT NULL,
    expected_rr_ratio REAL NOT NULL,
    order_sz REAL NOT NULL,
    notional_usdc REAL NOT NULL,
    reasoning_summary TEXT NOT NULL,
    self_critique TEXT NOT NULL,
    invalidation_condition TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL DEFAULT 'PENDING'
);
CREATE INDEX IF NOT EXISTS idx_episodic_coin_ts ON ai_episodic_memory(coin, timestamp_ms DESC);

CREATE TABLE IF NOT EXISTS ai_reflection_memory (
    reflection_id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL UNIQUE,
    closed_at_ms INTEGER NOT NULL,
    coin TEXT NOT NULL,
    market_regime_4h TEXT NOT NULL,
    exit_reason TEXT NOT NULL,
    holding_duration_sec INTEGER NOT NULL,
    entry_px REAL NOT NULL,
    exit_px REAL NOT NULL,
    realized_r_multiple REAL NOT NULL,
    mfe_pct REAL NOT NULL,
    mae_pct REAL NOT NULL,
    execution_slippage_bps REAL NOT NULL,
    thesis_validity_score REAL NOT NULL CHECK (thesis_validity_score BETWEEN 0.0 AND 1.0),
    failure_taxonomy TEXT NOT NULL,
    distilled_rule TEXT NOT NULL,
    importance_weight REAL NOT NULL DEFAULT 1.0,
    FOREIGN KEY (episode_id) REFERENCES ai_episodic_memory(episode_id)
);
CREATE INDEX IF NOT EXISTS idx_reflection_regime_ts ON ai_reflection_memory(market_regime_4h, closed_at_ms DESC);

CREATE TABLE IF NOT EXISTS shadow_evaluations (
    shadow_id TEXT PRIMARY KEY,
    evaluated_at_ms INTEGER NOT NULL,
    coin TEXT NOT NULL,
    market_regime_4h TEXT NOT NULL,
    skip_stage TEXT NOT NULL,
    ai_conviction_score INTEGER,
    skip_reason_code TEXT NOT NULL,
    spot_mid_at_eval REAL NOT NULL,
    hypothetical_sl_px REAL NOT NULL,
    hypothetical_tp_px REAL NOT NULL,
    first_hit_type TEXT DEFAULT 'NONE',
    first_hit_ts_ms INTEGER DEFAULT 0,
    px_after_1h REAL,
    px_after_4h REAL,
    px_after_24h REAL,
    max_high_24h REAL,
    min_low_24h REAL,
    shadow_outcome TEXT DEFAULT 'TRACKING',
    missed_r_multiple REAL,
    calibration_signal TEXT
);
CREATE INDEX IF NOT EXISTS idx_shadow_regime_eval ON shadow_evaluations(market_regime_4h, evaluated_at_ms DESC);

CREATE TABLE IF NOT EXISTS remote_command_queue (
    cmd_id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    processed INTEGER NOT NULL DEFAULT 0,
    processed_at_ms INTEGER
);

CREATE TABLE IF NOT EXISTS tax_inventory_state (
    asset TEXT PRIMARY KEY,
    quantity REAL NOT NULL DEFAULT 0.0,
    book_cost_jpy REAL NOT NULL DEFAULT 0.0,
    moving_avg_unit_jpy REAL NOT NULL DEFAULT 0.0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tax_annual_opening (
    tax_year INTEGER NOT NULL,
    asset TEXT NOT NULL,
    opening_qty REAL NOT NULL DEFAULT 0.0,
    opening_cost_jpy REAL NOT NULL DEFAULT 0.0,
    PRIMARY KEY (tax_year, asset)
);

CREATE TABLE IF NOT EXISTS tax_lots (
    lot_id INTEGER PRIMARY KEY AUTOINCREMENT,
    hl_tid INTEGER UNIQUE NOT NULL,
    hl_oid INTEGER,
    timestamp_ms INTEGER NOT NULL,
    jst_date TEXT NOT NULL,
    tax_year INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    pair_name TEXT NOT NULL,
    base_asset TEXT NOT NULL,
    quote_asset TEXT NOT NULL DEFAULT 'USDC',
    exec_px_usdc REAL NOT NULL,
    exec_sz_base REAL NOT NULL,
    raw_fee_amount REAL NOT NULL,
    raw_fee_token TEXT NOT NULL,
    usdc_jpy_rate REAL NOT NULL,
    rate_source TEXT NOT NULL,
    disposed_asset TEXT NOT NULL,
    disposed_qty REAL NOT NULL DEFAULT 0.0,
    disposed_unit_cost_jpy REAL NOT NULL DEFAULT 0.0,
    disposed_cogs_jpy REAL NOT NULL DEFAULT 0.0,
    gross_proceeds_jpy REAL NOT NULL DEFAULT 0.0,
    selling_expense_jpy REAL NOT NULL DEFAULT 0.0,
    realized_pnl_jpy REAL NOT NULL DEFAULT 0.0,
    acquired_asset TEXT NOT NULL,
    acquired_net_qty REAL NOT NULL DEFAULT 0.0,
    acquisition_cost_jpy REAL NOT NULL DEFAULT 0.0,
    new_moving_avg_unit_jpy REAL NOT NULL DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_tax_lots_year ON tax_lots(tax_year, timestamp_ms);
"""

EXPECTED_TEN_TABLES = (
    "system_state_store",
    "slot_state_store",
    "dust_quarantine",
    "ai_episodic_memory",
    "ai_reflection_memory",
    "shadow_evaluations",
    "remote_command_queue",
    "tax_inventory_state",
    "tax_annual_opening",
    "tax_lots",
)


class DatabaseManager:
    """
    SQLite WAL モードで全10テーブルを管理するスレッドセーフなデータベース基盤クラス。
    """

    def __init__(
        self,
        db_path: Union[str, Path] = "e:/hl-ai-trader-auto/data/hl_v1_state_wal.db",
        initial_equity_usdc: float = 130.0,
        initial_usdc_jpy_rate: float = 155.0,
        auto_init: bool = True,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        self._local = threading.local()
        self._all_connections: List[sqlite3.Connection] = []
        if auto_init:
            self.initialize_schema(
                initial_equity_usdc=initial_equity_usdc,
                initial_usdc_jpy_rate=initial_usdc_jpy_rate,
            )

    @staticmethod
    def _configure_connection(conn: sqlite3.Connection) -> None:
        """高可用性 SQLite WAL PRAGMA (temp_store=MEMORY, mmap_size=256MB, busy_timeout=5000 等) を適用する"""
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA mmap_size = 268435456;")
        conn.execute("PRAGMA wal_autocheckpoint = 1000;")
        conn.execute("PRAGMA journal_size_limit = 33554432;")
        conn.execute("PRAGMA foreign_keys = ON;")

    def _get_connection(self) -> sqlite3.Connection:
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=15.0,
                isolation_level=None,  # 手動で BEGIN IMMEDIATE / COMMIT を制御
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            self._configure_connection(conn)
            self._local.conn = conn
            with self._write_lock:
                self._all_connections.append(conn)
        return conn

    @contextlib.contextmanager
    def immediate_transaction(self) -> Iterator[sqlite3.Connection]:
        """
        プロセス内書き込みロック (`RLock`) と SQLite `BEGIN IMMEDIATE` を結合した
        排他トランザクションコンテキストマネージャ。ネスト呼び出し時は外側のトランザクションに合流する。
        `BaseException` (`asyncio.CancelledError` 等) 発生時も確実に `tx_depth` とトランザクションを復元する。
        """
        with self._write_lock:
            conn = self._get_connection()
            depth = max(0, int(getattr(self._local, "tx_depth", 0)))
            if depth == 0:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK;")
                    except sqlite3.Error:
                        pass
                conn.execute("BEGIN IMMEDIATE;")
            self._local.tx_depth = depth + 1
            try:
                yield conn
            except BaseException:
                self._local.tx_depth = max(0, getattr(self._local, "tx_depth", 1) - 1)
                if self._local.tx_depth == 0 and conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK;")
                    except sqlite3.Error:
                        pass
                raise
            else:
                self._local.tx_depth = max(0, getattr(self._local, "tx_depth", 1) - 1)
                if self._local.tx_depth == 0 and conn.in_transaction:
                    conn.execute("COMMIT;")

    def initialize_schema(
        self,
        initial_equity_usdc: float = 130.0,
        initial_usdc_jpy_rate: float = 155.0,
    ) -> None:
        """全10テーブルおよびシステム初期行・スロット1/2初期行をべき等に作成し、v1.1スキーママイグレーションを適用する"""
        with self._write_lock:
            conn = self._get_connection()
            conn.executescript(DDL_STATEMENTS)
            existing_cols = {
                str(r["name"]).lower()
                for r in conn.execute("PRAGMA table_info(shadow_evaluations)").fetchall()
            }
            for col_name, col_ddl in (
                ("hypothetical_sl_px", "REAL DEFAULT 0.0"),
                ("hypothetical_tp_px", "REAL DEFAULT 0.0"),
                ("first_hit_type", "TEXT DEFAULT 'NONE'"),
                ("first_hit_ts_ms", "INTEGER DEFAULT 0"),
            ):
                if col_name not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE shadow_evaluations ADD COLUMN {col_name} {col_ddl};")
                    except sqlite3.OperationalError:
                        pass

            ts = now_ms()
            eq = float(initial_equity_usdc)
            rate = float(initial_usdc_jpy_rate)
            with self.immediate_transaction() as tx:
                tx.execute(
                    """
                    INSERT OR IGNORE INTO system_state_store (
                        id, system_mode, initial_equity_usdc, hwm_equity_usdc,
                        sod_equity_usdc, sow_equity_usdc, current_equity_usdc,
                        latest_usdc_jpy_rate, updated_at_ms
                    ) VALUES (1, 'NORMAL', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (eq, eq, eq, eq, eq, rate, ts),
                )
                for slot_id in (1, 2):
                    tx.execute(
                        """
                        INSERT OR IGNORE INTO slot_state_store (
                            slot_id, state, sub_state, trailing_stage, mutation_epoch, updated_at_ms
                        ) VALUES (?, 'IDLE', 'NONE', 1, 0, ?)
                        """,
                        (slot_id, ts),
                    )

    def run_wal_checkpoint(self, mode: str = "PASSIVE") -> Dict[str, Any]:
        """
        WALファイルの無制限肥大化を防ぐ定期チェックポイント実行メソッド。
        - `PASSIVE`: 15分周期で読み書きをブロックせずにチェックポイントを実行
        - `TRUNCATE`: 1日1回（両スロット IDLE 時）に `.db-wal` を 0 バイトへ切り詰める
        """
        norm_mode = str(mode or "PASSIVE").strip().upper()
        if norm_mode not in ("PASSIVE", "FULL", "RESTART", "TRUNCATE"):
            norm_mode = "PASSIVE"
        with self._write_lock:
            conn = self._get_connection()
            row = conn.execute(f"PRAGMA wal_checkpoint({norm_mode});").fetchone()
            busy = int(row[0]) if row and len(row) > 0 else 0
            log_frames = int(row[1]) if row and len(row) > 1 else 0
            ckpt_frames = int(row[2]) if row and len(row) > 2 else 0
            return {
                "status": "ok",
                "mode": norm_mode,
                "busy": busy,
                "log_frames": log_frames,
                "checkpointed_frames": ckpt_frames,
            }

    def list_tables(self) -> List[str]:
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [str(r["name"]) for r in rows]

    def get_system_state(self) -> Dict[str, Any]:
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
        return dict(row) if row else {}

    def get_latest_usdc_jpy_rate(self) -> Optional[float]:
        st = self.get_system_state()
        val = st.get("latest_usdc_jpy_rate")
        return float(val) if val is not None else None

    def update_latest_usdc_jpy_rate(self, rate: float) -> None:
        with self.immediate_transaction() as tx:
            tx.execute(
                "UPDATE system_state_store SET latest_usdc_jpy_rate = ?, updated_at_ms = ? WHERE id = 1",
                (float(rate), now_ms()),
            )

    def get_slot_state(self, slot_id: int) -> Dict[str, Any]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM slot_state_store WHERE slot_id = ?", (int(slot_id),)
        ).fetchone()
        return dict(row) if row else {}

    def get_all_slots(self) -> Dict[int, Dict[str, Any]]:
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM slot_state_store ORDER BY slot_id ASC").fetchall()
        return {int(r["slot_id"]): dict(r) for r in rows}

    def upsert_dust_quarantine(
        self,
        base_asset: str,
        coin_pair: str,
        quarantined_qty: float,
        estimated_usdc_val: float,
        recovery_attempts: int = 0,
        last_attempt_ms: int = 0,
        status: str = "QUARANTINED",
    ) -> None:
        with self.immediate_transaction() as tx:
            tx.execute(
                """
                INSERT INTO dust_quarantine (
                    base_asset, coin_pair, quarantined_qty, estimated_usdc_val,
                    recovery_attempts, last_attempt_ms, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(base_asset) DO UPDATE SET
                    coin_pair = excluded.coin_pair,
                    quarantined_qty = excluded.quarantined_qty,
                    estimated_usdc_val = excluded.estimated_usdc_val,
                    recovery_attempts = excluded.recovery_attempts,
                    last_attempt_ms = excluded.last_attempt_ms,
                    status = excluded.status
                """,
                (
                    base_asset,
                    coin_pair,
                    float(quarantined_qty),
                    float(estimated_usdc_val),
                    int(recovery_attempts),
                    int(last_attempt_ms),
                    status,
                ),
            )

    def get_dust_quarantine(self, base_asset: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM dust_quarantine WHERE base_asset = ?", (base_asset,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_quarantined_dust(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM dust_quarantine WHERE status = 'QUARANTINED' ORDER BY base_asset ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def enqueue_remote_command(self, command: str) -> int:
        ts = now_ms()
        with self.immediate_transaction() as tx:
            cur = tx.execute(
                "INSERT INTO remote_command_queue (command, created_at_ms, processed) VALUES (?, ?, 0)",
                (command, ts),
            )
            return int(cur.lastrowid or 0)

    def fetch_pending_commands(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM remote_command_queue WHERE processed = 0 ORDER BY cmd_id ASC"
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_command_processed(self, cmd_id: int) -> None:
        with self.immediate_transaction() as tx:
            tx.execute(
                "UPDATE remote_command_queue SET processed = 1, processed_at_ms = ? WHERE cmd_id = ?",
                (now_ms(), int(cmd_id)),
            )

    def close(self) -> None:
        with self._write_lock:
            conns = list(self._all_connections)
            self._all_connections.clear()
        for c in conns:
            try:
                c.close()
            except Exception:
                pass
        conn: Optional[sqlite3.Connection] = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def __enter__(self) -> "DatabaseManager":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class HyperliquidTaxEngine:
    """
    Hyperliquid Spot 暗号資産間交換（Base Token <-> USDC）の二重課税イベントを管理する税務エンジン。

    日本の所得税法（国税庁「暗号資産に関する税務上の取扱いについて」）に準拠し、
    1回のSpot約定につき以下2つのレグを同時に `tax_lots` の1行および `tax_inventory_state` へ計上する:
      - 譲渡レグ (Disposed Leg): 手放した暗号資産の譲渡原価 (COGS)・譲渡収入・譲渡経費・実現損益 (JPY)
      - 取得レグ (Acquired Leg): 受け取った暗号資産の純増数量・円換算取得価額・新しい移動平均単価 (JPY)
    さらに `raw_fee_token` が Base Asset / Quote Asset (USDC) / 第3トークン のいずれであっても
    正確に数量控除と取得価額・譲渡経費算入を分岐処理し、移動平均法と総平均法の双方に対応する。
    """

    def __init__(
        self,
        db: DatabaseManager,
        rate_fetcher: Optional[UsdcJpyRateFetcher] = None,
    ) -> None:
        self.db = db
        self.rate_fetcher = rate_fetcher or UsdcJpyRateFetcher(
            db_rate_provider=self.db.get_latest_usdc_jpy_rate
        )

    def seed_opening_or_deposit(
        self,
        asset: str,
        qty: Union[float, str, Decimal],
        unit_jpy: Union[float, str, Decimal],
        tax_year: Optional[int] = None,
        timestamp_ms: Optional[int] = None,
        record_as_annual_opening: bool = True,
    ) -> Dict[str, Any]:
        """
        指定資産の期首残高または新規入金残高を `tax_inventory_state`（および `tax_annual_opening`）に登録する。
        """
        ts = timestamp_ms if timestamp_ms is not None else now_ms()
        yr = tax_year if tax_year is not None else jst_tax_year(ts)
        add_qty = _to_clean_decimal(qty)
        unit = _to_clean_decimal(unit_jpy)
        add_cost = add_qty * unit

        with self.db.immediate_transaction() as tx:
            row = tx.execute(
                "SELECT * FROM tax_inventory_state WHERE asset = ?", (asset,)
            ).fetchone()
            if row is None:
                new_qty = add_qty
                new_cost = add_cost
            else:
                new_qty = _to_clean_decimal(row["quantity"]) + add_qty
                new_cost = _to_clean_decimal(row["book_cost_jpy"]) + add_cost

            new_unit = (new_cost / new_qty) if new_qty > 0 else Decimal("0")
            tx.execute(
                """
                INSERT INTO tax_inventory_state (asset, quantity, book_cost_jpy, moving_avg_unit_jpy, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset) DO UPDATE SET
                    quantity = excluded.quantity,
                    book_cost_jpy = excluded.book_cost_jpy,
                    moving_avg_unit_jpy = excluded.moving_avg_unit_jpy,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (asset, float(new_qty), float(new_cost), float(new_unit), ts),
            )

            if record_as_annual_opening:
                op_row = tx.execute(
                    "SELECT * FROM tax_annual_opening WHERE tax_year = ? AND asset = ?",
                    (yr, asset),
                ).fetchone()
                if op_row is None:
                    tx.execute(
                        """
                        INSERT INTO tax_annual_opening (tax_year, asset, opening_qty, opening_cost_jpy)
                        VALUES (?, ?, ?, ?)
                        """,
                        (yr, asset, float(add_qty), float(add_cost)),
                    )
                else:
                    op_qty = _to_clean_decimal(op_row["opening_qty"]) + add_qty
                    op_cost = _to_clean_decimal(op_row["opening_cost_jpy"]) + add_cost
                    tx.execute(
                        """
                        UPDATE tax_annual_opening
                        SET opening_qty = ?, opening_cost_jpy = ?
                        WHERE tax_year = ? AND asset = ?
                        """,
                        (float(op_qty), float(op_cost), yr, asset),
                    )

        return self.get_inventory_state(asset)

    def bootstrap_initial_usdc_inventory(
        self,
        actual_usdc_total: Union[float, str, Decimal],
        usdc_jpy_rate: Optional[Union[float, str, Decimal]] = None,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        初回起動時または口座入金増加時に、口座に存在する USDC 残高 (`actual_usdc_total`, 例: `143.73 USDC`) の
        初期移動平均取得単価 (`moving_avg_unit_jpy`) を `tax_inventory_state` および `tax_annual_opening` に
        自動ブートストラップ（シード）する。
        また、万一 `quantity > 0` かつ `moving_avg_unit_jpy <= 0` の不整合レコードが存在した場合も
        即座に現在レートで簿価を修復し、初回 `SPOT_BUY` 時の `disposed_cogs_jpy = 0`（架空為替差益）を100%防止する。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        yr = jst_tax_year(ts)
        actual_qty = _to_clean_decimal(actual_usdc_total)
        if actual_qty <= Decimal("0"):
            return {**self.get_inventory_state("USDC"), "bootstrapped": False, "reason": "ZERO_ACTUAL_BALANCE"}

        if usdc_jpy_rate is not None and _to_clean_decimal(usdc_jpy_rate) > Decimal("0"):
            rate_dec = _to_clean_decimal(usdc_jpy_rate)
        else:
            rate_f, _ = self.rate_fetcher.get_rate()
            rate_dec = _to_clean_decimal(rate_f)

        bootstrapped = False
        reason = "ALREADY_SEEDED"

        with self.db.immediate_transaction() as tx:
            row = tx.execute(
                "SELECT * FROM tax_inventory_state WHERE asset = 'USDC'"
            ).fetchone()

            if row is None:
                cur_qty = Decimal("0")
                cur_cost = Decimal("0")
                cur_unit = Decimal("0")
            else:
                cur_qty = _to_clean_decimal(row["quantity"])
                cur_cost = _to_clean_decimal(row["book_cost_jpy"])
                cur_unit = _to_clean_decimal(row["moving_avg_unit_jpy"])

            # ケース1: quantity > 0 だが moving_avg_unit_jpy <= 0 のゼロ単価汚染がある場合 -> 簿価修復
            if cur_qty > Decimal("0") and cur_unit <= Decimal("0"):
                cur_unit = rate_dec
                cur_cost = cur_qty * cur_unit
                tx.execute(
                    """
                    UPDATE tax_inventory_state
                    SET book_cost_jpy = ?, moving_avg_unit_jpy = ?, updated_at_ms = ?
                    WHERE asset = 'USDC'
                    """,
                    (float(cur_cost), float(cur_unit), ts),
                )
                tx.execute(
                    """
                    INSERT INTO tax_annual_opening (tax_year, asset, opening_qty, opening_cost_jpy)
                    VALUES (?, 'USDC', ?, ?)
                    ON CONFLICT(tax_year, asset) DO UPDATE SET
                        opening_qty = MAX(opening_qty, excluded.opening_qty),
                        opening_cost_jpy = CASE WHEN opening_cost_jpy <= 0 THEN excluded.opening_cost_jpy ELSE opening_cost_jpy END
                    """,
                    (yr, float(cur_qty), float(cur_cost)),
                )
                bootstrapped = True
                reason = "REPAIRED_ZERO_UNIT_COST"

            # ケース2: 未シード (cur_qty == 0) または実残高に対して在庫が不足している場合 -> 差額をシード
            if cur_qty < actual_qty - Decimal("1e-6"):
                diff_qty = actual_qty - cur_qty
                was_empty = cur_qty <= Decimal("0")
                self.seed_opening_or_deposit(
                    asset="USDC",
                    qty=diff_qty,
                    unit_jpy=rate_dec,
                    tax_year=yr,
                    timestamp_ms=ts,
                    record_as_annual_opening=True,
                )
                bootstrapped = True
                reason = "INITIAL_SEED" if was_empty else "TOP_UP_DEPOSIT_SEED"

        return {
            **self.get_inventory_state("USDC"),
            "bootstrapped": bootstrapped,
            "reason": reason,
        }

    def get_inventory_state(self, asset: str) -> Dict[str, Any]:
        conn = self.db._get_connection()
        row = conn.execute(
            "SELECT * FROM tax_inventory_state WHERE asset = ?", (asset,)
        ).fetchone()
        if row is None:
            return {
                "asset": asset,
                "quantity": 0.0,
                "book_cost_jpy": 0.0,
                "moving_avg_unit_jpy": 0.0,
                "updated_at_ms": 0,
            }
        return dict(row)

    def _ensure_inventory_row_in_tx(
        self,
        tx: sqlite3.Connection,
        asset: str,
        required_qty: Decimal,
        fallback_unit_jpy: Decimal,
        tax_year: int,
        ts: int,
    ) -> Tuple[Decimal, Decimal, Decimal]:
        """
        トランザクション内で対象資産の在庫を取得する。
        未登録または期首在庫登録前に譲渡が発生した場合、あるいは `moving_avg_unit_jpy <= 0` の場合は
        `fallback_unit_jpy` で自動補完してゼロ除算や `disposed_cogs_jpy = 0`（架空利益計上）を100%防止する。
        """
        row = tx.execute(
            "SELECT * FROM tax_inventory_state WHERE asset = ?", (asset,)
        ).fetchone()
        if row is None:
            cur_qty = Decimal("0")
            cur_cost = Decimal("0")
            cur_unit = Decimal("0")
        else:
            cur_qty = _to_clean_decimal(row["quantity"])
            cur_cost = _to_clean_decimal(row["book_cost_jpy"])
            cur_unit = _to_clean_decimal(row["moving_avg_unit_jpy"])

        # 万一 quantity > 0 なのに moving_avg_unit_jpy <= 0 の場合は fallback_unit_jpy で即時修復
        if cur_qty > Decimal("0") and cur_unit <= Decimal("0") and fallback_unit_jpy > Decimal("0"):
            cur_unit = fallback_unit_jpy
            cur_cost = cur_qty * cur_unit
            tx.execute(
                """
                UPDATE tax_inventory_state
                SET book_cost_jpy = ?, moving_avg_unit_jpy = ?, updated_at_ms = ?
                WHERE asset = ?
                """,
                (float(cur_cost), float(cur_unit), ts, asset),
            )
            tx.execute(
                """
                INSERT INTO tax_annual_opening (tax_year, asset, opening_qty, opening_cost_jpy)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(tax_year, asset) DO UPDATE SET
                    opening_qty = MAX(opening_qty, excluded.opening_qty),
                    opening_cost_jpy = CASE WHEN opening_cost_jpy <= 0 THEN excluded.opening_cost_jpy ELSE opening_cost_jpy END
                """,
                (tax_year, asset, float(cur_qty), float(cur_cost)),
            )

        if cur_qty < required_qty:
            shortfall = required_qty - cur_qty
            unit_to_use = cur_unit if cur_unit > 0 else fallback_unit_jpy
            added_cost = shortfall * unit_to_use
            cur_qty += shortfall
            cur_cost += added_cost
            cur_unit = (cur_cost / cur_qty) if cur_qty > 0 else unit_to_use
            tx.execute(
                """
                INSERT INTO tax_inventory_state (asset, quantity, book_cost_jpy, moving_avg_unit_jpy, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset) DO UPDATE SET
                    quantity = excluded.quantity,
                    book_cost_jpy = excluded.book_cost_jpy,
                    moving_avg_unit_jpy = excluded.moving_avg_unit_jpy,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (asset, float(cur_qty), float(cur_cost), float(cur_unit), ts),
            )
            # 期首テーブルにも不足補完分を反映して総平均法の分母整合性を保つ
            op_row = tx.execute(
                "SELECT * FROM tax_annual_opening WHERE tax_year = ? AND asset = ?",
                (tax_year, asset),
            ).fetchone()
            if op_row is None:
                tx.execute(
                    "INSERT INTO tax_annual_opening (tax_year, asset, opening_qty, opening_cost_jpy) VALUES (?, ?, ?, ?)",
                    (tax_year, asset, float(shortfall), float(added_cost)),
                )
            else:
                new_op_qty = _to_clean_decimal(op_row["opening_qty"]) + shortfall
                new_op_cost = _to_clean_decimal(op_row["opening_cost_jpy"]) + added_cost
                tx.execute(
                    "UPDATE tax_annual_opening SET opening_qty = ?, opening_cost_jpy = ? WHERE tax_year = ? AND asset = ?",
                    (float(new_op_qty), float(new_op_cost), tax_year, asset),
                )

        return (cur_qty, cur_cost, cur_unit)

    def process_spot_fill(
        self,
        hl_tid: int,
        pair_name: str,
        base_asset: str,
        is_buy: bool,
        exec_px_usdc: Union[float, str, Decimal],
        exec_sz_base: Union[float, str, Decimal],
        raw_fee_amount: Union[float, str, Decimal],
        raw_fee_token: str,
        timestamp_ms: Optional[int] = None,
        hl_oid: Optional[int] = None,
        usdc_jpy_rate: Optional[float] = None,
        usdc_jpy_rate_override: Optional[float] = None,
        rate_source: Optional[str] = None,
        quote_asset: str = "USDC",
    ) -> Dict[str, Any]:
        """
        Hyperliquid Spot の約定1件を処理し、譲渡レグと取得レグを同時に計算して
        `tax_lots` および `tax_inventory_state` にアトミック記録する。
        既に同一 `hl_tid` が存在する場合はべき等に既存レコードを返す。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        tid = int(hl_tid)
        oid = int(hl_oid) if hl_oid is not None else None
        if usdc_jpy_rate is None and usdc_jpy_rate_override is not None:
            usdc_jpy_rate = usdc_jpy_rate_override

        # 1. 事前べき等チェック
        conn = self.db._get_connection()
        existing = conn.execute(
            "SELECT * FROM tax_lots WHERE hl_tid = ?", (tid,)
        ).fetchone()
        if existing is not None:
            res = dict(existing)
            res["duplicate"] = True
            res["inserted"] = False
            return res

        # 2. USDC/JPY レート解決
        if usdc_jpy_rate is not None and rate_source is not None:
            rate_f = float(usdc_jpy_rate)
            src_s = str(rate_source)
        elif usdc_jpy_rate is not None:
            rate_f = float(usdc_jpy_rate)
            src_s = "EXPLICIT_ARGUMENT"
        else:
            rate_f, src_s = self.rate_fetcher.get_rate()

        px = _to_clean_decimal(exec_px_usdc)
        sz = _to_clean_decimal(exec_sz_base)
        fee = max(Decimal("0"), _to_clean_decimal(raw_fee_amount))
        rate = _to_clean_decimal(rate_f)
        fee_token = str(raw_fee_token).strip().upper()
        base = str(base_asset).strip().upper()
        quote = str(quote_asset).strip().upper()

        date_str = jst_date_str(ts)
        tax_yr = jst_tax_year(ts)
        notional_usdc = sz * px
        market_val_jpy = notional_usdc * rate

        with self.db.immediate_transaction() as tx:
            # トランザクション内でもう一度べき等チェック (hl_tid または REST先行計上された同一 hl_oid + event_type)
            dup_in_tx = tx.execute(
                "SELECT * FROM tax_lots WHERE hl_tid = ?", (tid,)
            ).fetchone()
            if dup_in_tx is not None:
                res = dict(dup_in_tx)
                res["duplicate"] = True
                return res

            expected_evt = "SPOT_BUY" if is_buy else "SPOT_SELL"
            dup_by_oid = None
            if oid is not None and oid > 0:
                dup_by_oid = tx.execute(
                    """
                    SELECT * FROM tax_lots
                    WHERE hl_oid = ? AND event_type = ?
                      AND (hl_tid >= 9000000000000 OR ? >= 9000000000000)
                    LIMIT 1
                    """,
                    (oid, expected_evt, tid),
                ).fetchone()

            if dup_by_oid is None:
                # REST先行合成約定 (hl_tid >= 9_000_000_000_000) と WS/Backfill 実約定 (hl_tid < 9_000_000_000_000) 等で
                # 同一 (base_asset, event_type, exec_sz_base) が60秒以内に到着した場合の重複排除。
                # ただし双方に正の hl_oid が存在し、かつ hl_oid が異なる場合 (Top-Up & Dump や60秒以内の別注文) は絶対にスキップしない。
                oid_val = int(oid) if (oid is not None and int(oid) > 0) else 0
                dup_by_oid = tx.execute(
                    """
                    SELECT * FROM tax_lots
                    WHERE base_asset = ? AND event_type = ?
                      AND ABS(exec_sz_base - ?) <= 1e-9
                      AND ABS(timestamp_ms - ?) <= 60000
                      AND (hl_tid >= 9000000000000 OR ? >= 9000000000000)
                      AND (hl_oid IS NULL OR hl_oid <= 0 OR ? <= 0 OR hl_oid = ?)
                    ORDER BY timestamp_ms DESC LIMIT 1
                    """,
                    (base, expected_evt, float(sz), ts, tid, oid_val, oid_val),
                ).fetchone()

            if dup_by_oid is not None:
                # 合成約定 (hl_tid >= 9e12) に対して実WS約定 (tid < 9e12) が到着した場合、
                # 数量が一致する単一約定のときのみ hl_tid を実TIDへ昇格する。
                # 1つの合成約定に対して複数の分割約定 (Partial Fills: sz < exec_sz_base) が到着した場合は、
                # 後続の分割約定も同一合成ロットに吸収できるよう hl_tid >= 9e12 を維持して二重計上を防ぐ。
                if int(dup_by_oid["hl_tid"]) >= 9_000_000_000_000 and tid < 9_000_000_000_000:
                    if abs(float(dup_by_oid["exec_sz_base"]) - float(sz)) <= 1e-9:
                        tx.execute(
                            "UPDATE tax_lots SET hl_tid = ?, hl_oid = COALESCE(?, hl_oid) WHERE lot_id = ?",
                            (tid, oid, int(dup_by_oid["lot_id"])),
                        )
                res = dict(dup_by_oid)
                res["hl_tid"] = tid if tid < 9_000_000_000_000 else int(dup_by_oid["hl_tid"])
                res["duplicate"] = True
                return res

            if is_buy:
                # ==================================================================
                # SPOT_BUY: USDC を譲渡し、Base Asset を取得する二重イベント
                # ==================================================================
                event_type = "SPOT_BUY"
                disposed_asset = quote
                acquired_asset = base

                if fee_token == base:
                    # 1. 手数料が受取ベーストークンから控除される場合 (標準的なSpot買い)
                    disposed_qty = notional_usdc
                    usdc_qty, usdc_cost, usdc_unit = self._ensure_inventory_row_in_tx(
                        tx, quote, disposed_qty, rate, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = usdc_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = market_val_jpy
                    selling_expense_jpy = Decimal("0")
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy - selling_expense_jpy

                    # 受取トークンの純増数量は (sz - fee)、取得総額は支払った対価の時価 (market_val_jpy)
                    # これにより1単位あたりの移動平均単価に買い手数料が自動的に算入される
                    acquired_net_qty = max(Decimal("0"), sz - fee)
                    acquisition_cost_jpy = market_val_jpy

                elif fee_token == quote:
                    # 2. 手数料がクオート通貨 (USDC) で追加徴収される場合
                    disposed_qty = notional_usdc + fee
                    usdc_qty, usdc_cost, usdc_unit = self._ensure_inventory_row_in_tx(
                        tx, quote, disposed_qty, rate, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = usdc_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = disposed_qty * rate
                    selling_expense_jpy = Decimal("0")
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy

                    # 取得数量は sz 全量、取得価額には購入付随費用 (fee * rate) を算入
                    acquired_net_qty = sz
                    acquisition_cost_jpy = market_val_jpy + (fee * rate)

                else:
                    # 3. 手数料が第3のトークンで支払われた場合
                    disposed_qty = notional_usdc
                    usdc_qty, usdc_cost, usdc_unit = self._ensure_inventory_row_in_tx(
                        tx, quote, disposed_qty, rate, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = usdc_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = market_val_jpy

                    # 第3トークンの在庫から fee を減算して付随費用を算出
                    if fee > 0:
                        t3_qty, t3_cost, t3_unit = self._ensure_inventory_row_in_tx(
                            tx, fee_token, fee, rate, tax_yr, ts
                        )
                        fee_jpy = fee * t3_unit
                        rem_t3_qty = max(Decimal("0"), t3_qty - fee)
                        rem_t3_cost = rem_t3_qty * t3_unit
                        rem_t3_unit = t3_unit if rem_t3_qty > 0 else Decimal("0")
                        tx.execute(
                            """
                            UPDATE tax_inventory_state
                            SET quantity = ?, book_cost_jpy = ?, moving_avg_unit_jpy = ?, updated_at_ms = ?
                            WHERE asset = ?
                            """,
                            (float(rem_t3_qty), float(rem_t3_cost), float(rem_t3_unit), ts, fee_token),
                        )
                    else:
                        fee_jpy = Decimal("0")

                    selling_expense_jpy = Decimal("0")
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy
                    acquired_net_qty = sz
                    acquisition_cost_jpy = market_val_jpy + fee_jpy

            else:
                # ==================================================================
                # SPOT_SELL: Base Asset を譲渡し、USDC を取得する二重イベント
                # ==================================================================
                event_type = "SPOT_SELL"
                disposed_asset = base
                acquired_asset = quote
                fallback_base_unit = px * rate

                if fee_token == quote:
                    # 1. 売却代金 USDC から手数料が控除される場合 (標準的なSpot売り)
                    disposed_qty = sz
                    base_qty, base_cost, base_unit = self._ensure_inventory_row_in_tx(
                        tx, base, disposed_qty, fallback_base_unit, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = base_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = market_val_jpy
                    selling_expense_jpy = fee * rate
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy - selling_expense_jpy

                    # 取得する純USDCは (notional_usdc - fee)、取得価額はその円換算時価
                    acquired_net_qty = max(Decimal("0"), notional_usdc - fee)
                    acquisition_cost_jpy = acquired_net_qty * rate

                elif fee_token == base:
                    # 2. 手数料がベーストークンで控除された場合
                    disposed_qty = sz
                    base_qty, base_cost, base_unit = self._ensure_inventory_row_in_tx(
                        tx, base, disposed_qty, fallback_base_unit, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = base_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = market_val_jpy
                    selling_expense_jpy = fee * px * rate
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy - selling_expense_jpy

                    acquired_net_qty = max(Decimal("0"), (sz - fee) * px)
                    acquisition_cost_jpy = acquired_net_qty * rate

                else:
                    # 3. 手数料が第3のトークンで支払われた場合
                    disposed_qty = sz
                    base_qty, base_cost, base_unit = self._ensure_inventory_row_in_tx(
                        tx, base, disposed_qty, fallback_base_unit, tax_yr, ts
                    )
                    disposed_unit_cost_jpy = base_unit
                    disposed_cogs_jpy = disposed_qty * disposed_unit_cost_jpy
                    gross_proceeds_jpy = market_val_jpy

                    if fee > 0:
                        t3_qty, t3_cost, t3_unit = self._ensure_inventory_row_in_tx(
                            tx, fee_token, fee, rate, tax_yr, ts
                        )
                        fee_jpy = fee * t3_unit
                        rem_t3_qty = max(Decimal("0"), t3_qty - fee)
                        rem_t3_cost = rem_t3_qty * t3_unit
                        rem_t3_unit = t3_unit if rem_t3_qty > 0 else Decimal("0")
                        tx.execute(
                            """
                            UPDATE tax_inventory_state
                            SET quantity = ?, book_cost_jpy = ?, moving_avg_unit_jpy = ?, updated_at_ms = ?
                            WHERE asset = ?
                            """,
                            (float(rem_t3_qty), float(rem_t3_cost), float(rem_t3_unit), ts, fee_token),
                        )
                    else:
                        fee_jpy = Decimal("0")

                    selling_expense_jpy = fee_jpy
                    realized_pnl_jpy = gross_proceeds_jpy - disposed_cogs_jpy - selling_expense_jpy
                    acquired_net_qty = notional_usdc
                    acquisition_cost_jpy = market_val_jpy

            # 3. 譲渡資産 (disposed_asset) の在庫減算 (移動平均単価は譲渡では変化しない)
            disp_row = tx.execute(
                "SELECT * FROM tax_inventory_state WHERE asset = ?", (disposed_asset,)
            ).fetchone()
            old_disp_qty = _to_clean_decimal(disp_row["quantity"]) if disp_row else Decimal("0")
            old_disp_unit = (
                _to_clean_decimal(disp_row["moving_avg_unit_jpy"])
                if disp_row
                else disposed_unit_cost_jpy
            )
            new_disp_qty = max(Decimal("0"), old_disp_qty - disposed_qty)
            new_disp_cost = new_disp_qty * old_disp_unit
            new_disp_unit = old_disp_unit if new_disp_qty > Decimal("1e-12") else Decimal("0")
            if new_disp_qty <= Decimal("1e-12"):
                new_disp_qty = Decimal("0")
                new_disp_cost = Decimal("0")

            tx.execute(
                """
                INSERT INTO tax_inventory_state (asset, quantity, book_cost_jpy, moving_avg_unit_jpy, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset) DO UPDATE SET
                    quantity = excluded.quantity,
                    book_cost_jpy = excluded.book_cost_jpy,
                    moving_avg_unit_jpy = excluded.moving_avg_unit_jpy,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (
                    disposed_asset,
                    float(new_disp_qty),
                    float(new_disp_cost),
                    float(new_disp_unit),
                    ts,
                ),
            )

            # 4. 取得資産 (acquired_asset) の在庫加算と新しい移動平均単価算出
            acq_row = tx.execute(
                "SELECT * FROM tax_inventory_state WHERE asset = ?", (acquired_asset,)
            ).fetchone()
            old_acq_qty = _to_clean_decimal(acq_row["quantity"]) if acq_row else Decimal("0")
            old_acq_cost = _to_clean_decimal(acq_row["book_cost_jpy"]) if acq_row else Decimal("0")

            new_acq_qty = old_acq_qty + acquired_net_qty
            new_acq_cost = old_acq_cost + acquisition_cost_jpy
            new_moving_avg_unit_jpy = (
                (new_acq_cost / new_acq_qty) if new_acq_qty > Decimal("0") else Decimal("0")
            )

            tx.execute(
                """
                INSERT INTO tax_inventory_state (asset, quantity, book_cost_jpy, moving_avg_unit_jpy, updated_at_ms)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(asset) DO UPDATE SET
                    quantity = excluded.quantity,
                    book_cost_jpy = excluded.book_cost_jpy,
                    moving_avg_unit_jpy = excluded.moving_avg_unit_jpy,
                    updated_at_ms = excluded.updated_at_ms
                """,
                (
                    acquired_asset,
                    float(new_acq_qty),
                    float(new_acq_cost),
                    float(new_moving_avg_unit_jpy),
                    ts,
                ),
            )

            # 5. tax_lots テーブルへの記録
            cur = tx.execute(
                """
                INSERT INTO tax_lots (
                    hl_tid, hl_oid, timestamp_ms, jst_date, tax_year,
                    event_type, pair_name, base_asset, quote_asset,
                    exec_px_usdc, exec_sz_base, raw_fee_amount, raw_fee_token,
                    usdc_jpy_rate, rate_source,
                    disposed_asset, disposed_qty, disposed_unit_cost_jpy, disposed_cogs_jpy,
                    gross_proceeds_jpy, selling_expense_jpy, realized_pnl_jpy,
                    acquired_asset, acquired_net_qty, acquisition_cost_jpy, new_moving_avg_unit_jpy
                ) VALUES (
                    ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?
                )
                """,
                (
                    tid,
                    oid,
                    ts,
                    date_str,
                    tax_yr,
                    event_type,
                    pair_name,
                    base,
                    quote,
                    float(px),
                    float(sz),
                    float(fee),
                    fee_token,
                    float(rate),
                    src_s,
                    disposed_asset,
                    float(disposed_qty),
                    float(disposed_unit_cost_jpy),
                    float(disposed_cogs_jpy),
                    float(gross_proceeds_jpy),
                    float(selling_expense_jpy),
                    float(realized_pnl_jpy),
                    acquired_asset,
                    float(acquired_net_qty),
                    float(acquisition_cost_jpy),
                    float(new_moving_avg_unit_jpy),
                ),
            )
            lot_id = int(cur.lastrowid or 0)
            tx.execute(
                "UPDATE system_state_store SET latest_usdc_jpy_rate = ?, updated_at_ms = ? WHERE id = 1",
                (float(rate), ts),
            )

            inserted = tx.execute(
                "SELECT * FROM tax_lots WHERE lot_id = ?", (lot_id,)
            ).fetchone()
            result = dict(inserted) if inserted else {}
            result["duplicate"] = False
            result["inserted"] = True
            return result

    # 互換エイリアス (record_spot_fill <-> process_spot_fill)
    record_spot_fill = process_spot_fill

    def calculate_annual_summary(
        self,
        tax_year: int,
        method: str = "MOVING_AVERAGE",
    ) -> Dict[str, Any]:
        """
        指定課税年度 (`tax_year`) の確定申告用損益サマリーを算出する。
        - `method="MOVING_AVERAGE"`: 移動平均法（約定ごとのリアルタイム移動平均原価を合算）
        - `method="TOTAL_AVERAGE"`: 総平均法（期首在庫＋年間取得総額÷年間総取得数量で年間平均単価を算出し再計算）
        """
        norm_method = method.strip().upper()
        if norm_method not in ("MOVING_AVERAGE", "TOTAL_AVERAGE"):
            raise ValueError(f"未対応の税務計算方式です: {method}")

        conn = self.db._get_connection()
        lots = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM tax_lots WHERE tax_year = ? ORDER BY timestamp_ms ASC, lot_id ASC",
                (int(tax_year),),
            ).fetchall()
        ]
        openings = {
            str(r["asset"]): (
                _to_clean_decimal(r["opening_qty"]),
                _to_clean_decimal(r["opening_cost_jpy"]),
            )
            for r in conn.execute(
                "SELECT * FROM tax_annual_opening WHERE tax_year = ?",
                (int(tax_year),),
            ).fetchall()
        }

        if norm_method == "MOVING_AVERAGE":
            by_asset: Dict[str, Dict[str, Decimal]] = {}
            total_proceeds = Decimal("0")
            total_cogs = Decimal("0")
            total_expense = Decimal("0")
            total_pnl = Decimal("0")

            for lot in lots:
                d_asset = str(lot["disposed_asset"])
                bucket = by_asset.setdefault(
                    d_asset,
                    {
                        "disposed_qty": Decimal("0"),
                        "gross_proceeds_jpy": Decimal("0"),
                        "disposed_cogs_jpy": Decimal("0"),
                        "selling_expense_jpy": Decimal("0"),
                        "realized_pnl_jpy": Decimal("0"),
                    },
                )
                d_qty = _to_clean_decimal(lot["disposed_qty"])
                proc = _to_clean_decimal(lot["gross_proceeds_jpy"])
                cogs = _to_clean_decimal(lot["disposed_cogs_jpy"])
                exp = _to_clean_decimal(lot["selling_expense_jpy"])
                pnl = _to_clean_decimal(lot["realized_pnl_jpy"])

                bucket["disposed_qty"] += d_qty
                bucket["gross_proceeds_jpy"] += proc
                bucket["disposed_cogs_jpy"] += cogs
                bucket["selling_expense_jpy"] += exp
                bucket["realized_pnl_jpy"] += pnl

                total_proceeds += proc
                total_cogs += cogs
                total_expense += exp
                total_pnl += pnl

            return {
                "tax_year": int(tax_year),
                "method": "MOVING_AVERAGE",
                "lot_count": len(lots),
                "total_gross_proceeds_jpy": float(total_proceeds),
                "total_cogs_jpy": float(total_cogs),
                "total_selling_expense_jpy": float(total_expense),
                "total_realized_pnl_jpy": float(total_pnl),
                "total_realized_pnl_jpy_int": int(
                    total_pnl.to_integral_value(rounding=ROUND_HALF_UP)
                ),
                "by_disposed_asset": {
                    k: {m: float(v) for m, v in vals.items()}
                    for k, vals in by_asset.items()
                },
            }

        # ======================================================================
        # TOTAL_AVERAGE (総平均法):
        # 年間総平均単価 = (期首取得価額 + 年間取得価額合計) / (期首数量 + 年間取得数量合計)
        # ======================================================================
        acq_totals: Dict[str, Tuple[Decimal, Decimal]] = {}
        all_assets = set(openings.keys())
        for lot in lots:
            all_assets.add(str(lot["acquired_asset"]))
            all_assets.add(str(lot["disposed_asset"]))
            a_asset = str(lot["acquired_asset"])
            prev_q, prev_c = acq_totals.get(a_asset, (Decimal("0"), Decimal("0")))
            acq_totals[a_asset] = (
                prev_q + _to_clean_decimal(lot["acquired_net_qty"]),
                prev_c + _to_clean_decimal(lot["acquisition_cost_jpy"]),
            )

        annual_unit_costs: Dict[str, Decimal] = {}
        for asset in all_assets:
            op_q, op_c = openings.get(asset, (Decimal("0"), Decimal("0")))
            ac_q, ac_c = acq_totals.get(asset, (Decimal("0"), Decimal("0")))
            denom_q = op_q + ac_q
            numer_c = op_c + ac_c
            annual_unit_costs[asset] = (numer_c / denom_q) if denom_q > 0 else Decimal("0")

        by_asset_total_avg: Dict[str, Dict[str, Decimal]] = {}
        total_proceeds = Decimal("0")
        total_cogs = Decimal("0")
        total_expense = Decimal("0")
        total_pnl = Decimal("0")

        for lot in lots:
            d_asset = str(lot["disposed_asset"])
            unit_cost = annual_unit_costs.get(d_asset, Decimal("0"))
            d_qty = _to_clean_decimal(lot["disposed_qty"])
            proc = _to_clean_decimal(lot["gross_proceeds_jpy"])
            exp = _to_clean_decimal(lot["selling_expense_jpy"])
            cogs = d_qty * unit_cost
            pnl = proc - cogs - exp

            bucket = by_asset_total_avg.setdefault(
                d_asset,
                {
                    "annual_avg_unit_cost_jpy": unit_cost,
                    "disposed_qty": Decimal("0"),
                    "gross_proceeds_jpy": Decimal("0"),
                    "disposed_cogs_jpy": Decimal("0"),
                    "selling_expense_jpy": Decimal("0"),
                    "realized_pnl_jpy": Decimal("0"),
                },
            )
            bucket["disposed_qty"] += d_qty
            bucket["gross_proceeds_jpy"] += proc
            bucket["disposed_cogs_jpy"] += cogs
            bucket["selling_expense_jpy"] += exp
            bucket["realized_pnl_jpy"] += pnl

            total_proceeds += proc
            total_cogs += cogs
            total_expense += exp
            total_pnl += pnl

        return {
            "tax_year": int(tax_year),
            "method": "TOTAL_AVERAGE",
            "lot_count": len(lots),
            "total_gross_proceeds_jpy": float(total_proceeds),
            "total_cogs_jpy": float(total_cogs),
            "total_selling_expense_jpy": float(total_expense),
            "total_realized_pnl_jpy": float(total_pnl),
            "total_realized_pnl_jpy_int": int(
                total_pnl.to_integral_value(rounding=ROUND_HALF_UP)
            ),
            "annual_unit_costs_jpy": {k: float(v) for k, v in annual_unit_costs.items()},
            "by_disposed_asset": {
                k: {m: float(v) for m, v in vals.items()}
                for k, vals in by_asset_total_avg.items()
            },
        }
