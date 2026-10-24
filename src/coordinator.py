"""
HL AI Trader v1 — Concurrency & State Machine Coordinator (src/coordinator.py)

実装機能 (ARCHITECTURE.md Section 2 完全準拠):
1. スロット状態 (`SlotState`) / サブ状態 (`SlotSubState`) / システム状態 (`SystemMode`) 管理:
   - SlotState: `IDLE`, `ENTRY_PENDING`, `OPEN_PROTECTED`, `MODIFYING_SL`, `EXITING_ATOMIC`
   - SlotSubState: `NONE`, `INITIAL_RISK`, `FREEROLL_LOCKED` (sl_px >= entry_px * 1.0015)
   - SystemMode: `NORMAL`, `DUST_RECOVERY_IN_PROGRESS`, `HALTED`
2. 単一方向ロック階層 (`GlobalSystemLock` ➔ `SlotLock(1)` ➔ `SlotLock(2)` ➔ `SQLite BEGIN IMMEDIATE`):
   - スレッドローカルで保持ロック階層を追跡し、逆順ロック要求時に `LockHierarchyViolationError` を即時送出
3. Write-Ahead Intent Logging (`cloid` 先行WALコミット):
   - `/exchange` 注文送信前に16バイト `cloid` (`0x` + 32桁hex) と遷移先状態・`mutation_epoch + 1` をSQLiteへ先行コミット
   - レスポンス受信後に `cloid` と `oid` を即座に紐付け
4. Fencing Token (`mutation_epoch`) ＆ 静止期間 (`quiescence_until_ms`) による汚染データ破棄ガード:
   - `MODIFYING_SL` (+500ms), `EXITING_ATOMIC` (+2500ms), `DUST_RECOVERY_IN_PROGRESS` (+5000ms)
   - 15秒ループの `/info` 呼び出し前後で `mutation_epoch` 変化または静止期間重なりを検知したらスナップショットを破棄 (No-Op)
5. 3回連続不整合ルール (`desync_strike_count`):
   - 静止期間外かつFencing通過時の3者照合不一致が3周期連続に達した場合のみ `HALTED` へ遷移
"""

from __future__ import annotations

import contextlib
import enum
import logging
import sqlite3
import threading
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from src.db import DatabaseManager
from src.utils import generate_cloid, now_ms

logger = logging.getLogger(__name__)


class SlotState(str, enum.Enum):
    IDLE = "IDLE"
    ENTRY_PENDING = "ENTRY_PENDING"
    OPEN_PROTECTED = "OPEN_PROTECTED"
    MODIFYING_SL = "MODIFYING_SL"
    EXITING_ATOMIC = "EXITING_ATOMIC"
    CANCELLING = "CANCELLING"


class SlotSubState(str, enum.Enum):
    NONE = "NONE"
    INITIAL_RISK = "INITIAL_RISK"
    FREEROLL_LOCKED = "FREEROLL_LOCKED"


class TrailingStage(enum.IntEnum):
    """
    Soft-Ratchet 6段階トレーリングストップステージ定義 (v1.1 Deep Research Topic 1):
      - STAGE_10_INITIAL (10): Initial Risk (-1.00R)
      - STAGE_13_FIRST_CUSHION (13): First Cushion (0.38 <= MFE_R < 0.72 -> -0.60R to -0.20R 線形補間)
      - STAGE_17_TIGHT_CUSHION (17): Tight Cushion (0.72 <= MFE_R & MFE_% < theta_2 -> -0.20R to +c_lock 線形補間)
      - STAGE_20_FREEROLL (20): Freeroll Lock (MFE_% >= theta_2 -> Entry*(1+c_lock+0.25*(MFE_%-theta_2)), FREEROLL_LOCKED)
      - STAGE_30_ATR_TRAILING (30): Adaptive Chandelier (MFE_% >= theta_3)
      - STAGE_40_HYPER_TIGHT (40): Climax Tight (MFE_% >= theta_4 or RSI_5m >= 78)
    """

    STAGE_10_INITIAL = 10
    STAGE_13_FIRST_CUSHION = 13
    STAGE_17_TIGHT_CUSHION = 17
    STAGE_20_FREEROLL = 20
    STAGE_30_ATR_TRAILING = 30
    STAGE_40_HYPER_TIGHT = 40

    @classmethod
    def is_freeroll_locked_stage(cls, stage: int) -> bool:
        st = int(stage or 1)
        return st in (2, 3, 4) or st >= int(cls.STAGE_20_FREEROLL)


class SystemMode(str, enum.Enum):
    NORMAL = "NORMAL"
    DUST_RECOVERY_IN_PROGRESS = "DUST_RECOVERY_IN_PROGRESS"
    HALTED = "HALTED"


class LockLevel(enum.IntEnum):
    GLOBAL_SYSTEM = 10
    SLOT_1 = 20
    SLOT_2 = 30
    SQLITE_IMMEDIATE = 40


class LockHierarchyViolationError(RuntimeError):
    """
    単一方向ロック階層 (`GlobalSystemLock` -> `SlotLock(1)` -> `SlotLock(2)` -> `SQLite BEGIN IMMEDIATE`)
    に違反して下位ロック保持中に上位ロックを要求した場合に送出される例外。
    """


class SystemHaltedError(RuntimeError):
    """システムが終端状態 `HALTED` にあるため新規発注・状態遷移が遮断された場合に送出される例外"""


class StaleFencingTokenError(RuntimeError):
    """Fencing Token (`mutation_epoch`) 不一致により古い操作が拒否された場合に送出される例外"""


class ConcurrencyStateCoordinator:
    """
    200ms高速ガーディアン・15秒制御ループ・15分AIループの3並列実行における
    状態遷移・排他ロック・Write-Ahead Intent・Fencing Token検証を統括するコーディネータ。
    """

    QUIESCENCE_MODIFYING_SL_MS = 500
    QUIESCENCE_EXITING_ATOMIC_MS = 2500
    QUIESCENCE_DUST_RECOVERY_MS = 5000
    FREEROLL_LOCK_MULTIPLIER = 1.0015
    DESYNC_HALT_STRIKES = 3

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db
        self._global_lock = threading.RLock()
        self._slot_locks: Dict[int, threading.RLock] = {
            1: threading.RLock(),
            2: threading.RLock(),
        }
        self._local = threading.local()

    def _held_levels(self) -> List[int]:
        levels: Optional[List[int]] = getattr(self._local, "held_levels", None)
        if levels is None:
            levels = []
            self._local.held_levels = levels
        return levels

    def _check_and_push_level(self, level: LockLevel) -> None:
        levels = self._held_levels()
        if levels:
            max_held = max(levels)
            # 同一レベルの再入(RLock)は許可するが、既に保持している最大レベルより小さい（上位の）ロック取得は厳禁
            if int(level) < max_held:
                raise LockHierarchyViolationError(
                    f"ロック階層違反: 現在保持中のロックレベル {max_held} から上位ロック {level.name}({int(level)}) は取得できません。"
                    "必ず GlobalSystemLock(10) -> SlotLock(1)(20) -> SlotLock(2)(30) -> SQLite(40) の順で取得してください。"
                )
        levels.append(int(level))

    def _pop_level(self, level: LockLevel) -> None:
        levels = self._held_levels()
        if levels and levels[-1] == int(level):
            levels.pop()
        elif int(level) in levels:
            levels.remove(int(level))

    def reset_thread_local_lock_state(self) -> None:
        """
        `asyncio.to_thread` のワーカースレッド再利用時に、万が一前回の呼び出しから
        未解放のロック階層スタックや不正なトランザクション深度が残っていた場合にクリーンアップする。
        """
        levels = getattr(self._local, "held_levels", None)
        if levels:
            levels.clear()

    @contextlib.contextmanager
    def global_system_lock(self) -> Iterator[None]:
        """Level 1: GlobalSystemLock を取得するコンテキストマネージャ"""
        self._check_and_push_level(LockLevel.GLOBAL_SYSTEM)
        acquired = False
        try:
            self._global_lock.acquire()
            acquired = True
            yield
        finally:
            try:
                if acquired:
                    self._global_lock.release()
            finally:
                self._pop_level(LockLevel.GLOBAL_SYSTEM)

    @contextlib.contextmanager
    def slot_lock(self, slot_id: int) -> Iterator[None]:
        """Level 2 (Slot 1) または Level 3 (Slot 2) のロックを取得するコンテキストマネージャ"""
        sid = int(slot_id)
        if sid not in (1, 2):
            raise ValueError(f"不正な slot_id です (1 または 2 のみ有効): {slot_id}")
        level = LockLevel.SLOT_1 if sid == 1 else LockLevel.SLOT_2
        self._check_and_push_level(level)
        lock = self._slot_locks[sid]
        acquired = False
        try:
            lock.acquire()
            acquired = True
            yield
        finally:
            try:
                if acquired:
                    lock.release()
            finally:
                self._pop_level(level)

    @contextlib.contextmanager
    def db_immediate_lock(self) -> Iterator[sqlite3.Connection]:
        """Level 4: SQLite BEGIN IMMEDIATE トランザクションロックを取得するコンテキストマネージャ"""
        self._check_and_push_level(LockLevel.SQLITE_IMMEDIATE)
        try:
            with self.db.immediate_transaction() as tx:
                yield tx
        finally:
            self._pop_level(LockLevel.SQLITE_IMMEDIATE)

    @contextlib.contextmanager
    def acquire_hierarchy(
        self,
        use_global: bool = False,
        slot_ids: Sequence[int] = (),
        use_db_tx: bool = False,
    ) -> Iterator[Optional[sqlite3.Connection]]:
        """
        指定されたロック群を必ず `GlobalSystemLock` -> `SlotLock(1)` -> `SlotLock(2)` -> `SQLite BEGIN IMMEDIATE`
        の正規順序に整列して一括取得・解放するヘルパー。
        """
        sorted_slots = sorted({int(s) for s in slot_ids})
        for s in sorted_slots:
            if s not in (1, 2):
                raise ValueError(f"不正な slot_id です: {s}")

        with contextlib.ExitStack() as stack:
            if use_global:
                stack.enter_context(self.global_system_lock())
            for sid in sorted_slots:
                stack.enter_context(self.slot_lock(sid))
            tx: Optional[sqlite3.Connection] = None
            if use_db_tx:
                tx = stack.enter_context(self.db_immediate_lock())
            yield tx

    # ==========================================================================
    # Write-Ahead Intent Logging (`cloid` 先行WALコミット & `mutation_epoch` 更新)
    # ==========================================================================
    def begin_order_intent(
        self,
        slot_id: int,
        target_state: SlotState | str,
        coin: str,
        base_asset: str,
        sz_decimals: int,
        cloid: Optional[str] = None,
        entry_px: float = 0.0,
        sz: float = 0.0,
        sl_px: float = 0.0,
        tp_px: float = 0.0,
        episode_id: Optional[str] = None,
        quiescence_ms: int = 0,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        `/exchange` API へ署名付き注文を送信する前に呼び出す Write-Ahead Intent メソッド。
        16バイト `cloid` と遷移先状態、およびインクリメントした `mutation_epoch` を
        SQLite WAL へ `BEGIN IMMEDIATE` で先行コミットする。
        """
        sid = int(slot_id)
        state_val = target_state.value if isinstance(target_state, SlotState) else str(target_state)
        intent_cloid = cloid if cloid else generate_cloid()
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()

        with self.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            if sys_row and str(sys_row["system_mode"]) == SystemMode.HALTED.value:
                if state_val == SlotState.ENTRY_PENDING.value:
                    raise SystemHaltedError("システムが HALTED 終端状態のため新規発注は遮断されました。")

            new_sys_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            cur_quiescence = int(sys_row["quiescence_until_ms"]) if sys_row else 0
            new_quiescence = max(cur_quiescence, ts + int(quiescence_ms)) if quiescence_ms > 0 else cur_quiescence

            tx.execute(
                """
                UPDATE system_state_store
                SET mutation_epoch = ?, quiescence_until_ms = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (new_sys_epoch, new_quiescence, ts),
            )

            slot_row = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            new_slot_epoch = int(slot_row["mutation_epoch"]) + 1 if slot_row else 1

            sub_state_val = (
                str(slot_row["sub_state"])
                if (slot_row and state_val != SlotState.ENTRY_PENDING.value)
                else SlotSubState.NONE.value
            )

            tx.execute(
                """
                UPDATE slot_state_store
                SET state = ?,
                    sub_state = ?,
                    coin = ?,
                    base_asset = ?,
                    sz_decimals = ?,
                    active_cloid = ?,
                    active_oid = NULL,
                    entry_px = CASE WHEN ? > 0 THEN ? ELSE entry_px END,
                    current_sz = CASE WHEN ? > 0 THEN ? ELSE current_sz END,
                    sl_px = CASE WHEN ? > 0 THEN ? ELSE sl_px END,
                    tp_px = CASE WHEN ? > 0 THEN ? ELSE tp_px END,
                    order_created_at_ms = ?,
                    episode_id = COALESCE(?, episode_id),
                    mutation_epoch = ?,
                    updated_at_ms = ?
                WHERE slot_id = ?
                """,
                (
                    state_val,
                    sub_state_val,
                    coin,
                    base_asset,
                    int(sz_decimals),
                    intent_cloid,
                    float(entry_px),
                    float(entry_px),
                    float(sz),
                    float(sz),
                    float(sl_px),
                    float(sl_px),
                    float(tp_px),
                    float(tp_px),
                    ts,
                    episode_id,
                    new_slot_epoch,
                    ts,
                    sid,
                ),
            )

        return {
            "slot_id": sid,
            "cloid": intent_cloid,
            "state": state_val,
            "system_mutation_epoch": new_sys_epoch,
            "slot_mutation_epoch": new_slot_epoch,
            "quiescence_until_ms": new_quiescence,
            "timestamp_ms": ts,
        }

    def bind_order_response(
        self,
        slot_id: int,
        cloid: str,
        oid: Optional[int] = None,
        filled: bool = False,
        filled_sz: Optional[float] = None,
        avg_px: Optional[float] = None,
        rejected: bool = False,
        is_exit_order: bool = False,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        `/exchange` 注文レスポンス（`resting.oid` または `filled.oid` またはエラー）を受信した直後に
        `cloid` と `oid` を紐付け、スロット状態を確定更新する。
        """
        sid = int(slot_id)
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()

        with self.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_sys_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1

            slot_row = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            if not slot_row:
                raise ValueError(f"slot_id={sid} が存在しません")

            new_slot_epoch = int(slot_row["mutation_epoch"]) + 1

            if rejected:
                if is_exit_order:
                    # 決済注文が拒否された場合は保護監視状態へ戻して再試行可能にする
                    tx.execute(
                        """
                        UPDATE slot_state_store
                        SET state = ?, mutation_epoch = ?, updated_at_ms = ?
                        WHERE slot_id = ?
                        """,
                        (SlotState.OPEN_PROTECTED.value, new_slot_epoch, ts, sid),
                    )
                else:
                    # 新規エントリー指値 (Alo Post-Only 等) が拒否された場合は IDLE へクリーンアップ
                    tx.execute(
                        """
                        UPDATE slot_state_store
                        SET state = 'IDLE', sub_state = 'NONE', coin = NULL, base_asset = NULL,
                            active_cloid = NULL, active_oid = NULL, entry_px = 0.0, current_sz = 0.0,
                            sl_px = 0.0, tp_px = 0.0, trailing_stage = 1, order_created_at_ms = 0,
                            episode_id = NULL, mutation_epoch = ?, updated_at_ms = ?
                        WHERE slot_id = ?
                        """,
                        (new_slot_epoch, ts, sid),
                    )
            elif filled:
                if is_exit_order or str(slot_row["state"]) == SlotState.EXITING_ATOMIC.value:
                    # 決済売りが100%約定完了 -> IDLE へリセット
                    tx.execute(
                        """
                        UPDATE slot_state_store
                        SET state = 'IDLE', sub_state = 'NONE', coin = NULL, base_asset = NULL,
                            active_cloid = NULL, active_oid = NULL, entry_px = 0.0, current_sz = 0.0,
                            sl_px = 0.0, tp_px = 0.0, trailing_stage = 1, order_created_at_ms = 0,
                            episode_id = NULL, mutation_epoch = ?, updated_at_ms = ?
                        WHERE slot_id = ?
                        """,
                        (new_slot_epoch, ts, sid),
                    )
                else:
                    # 新規買いが100%約定完了 -> OPEN_PROTECTED (INITIAL_RISK, hold == 0) へ遷移
                    eff_px = float(avg_px) if (avg_px is not None and avg_px > 0) else float(slot_row["entry_px"])
                    eff_sz = float(filled_sz) if (filled_sz is not None and filled_sz > 0) else float(slot_row["current_sz"])
                    cur_sl = float(slot_row["sl_px"])
                    sub_st = (
                        SlotSubState.FREEROLL_LOCKED.value
                        if (eff_px > 0 and cur_sl >= eff_px * self.FREEROLL_LOCK_MULTIPLIER)
                        else SlotSubState.INITIAL_RISK.value
                    )
                    tx.execute(
                        """
                        UPDATE slot_state_store
                        SET state = ?, sub_state = ?, active_cloid = ?, active_oid = ?,
                            entry_px = ?, current_sz = ?, trailing_stage = 1,
                            mutation_epoch = ?, updated_at_ms = ?
                        WHERE slot_id = ?
                        """,
                        (
                            SlotState.OPEN_PROTECTED.value,
                            sub_st,
                            cloid,
                            int(oid) if oid is not None else None,
                            eff_px,
                            eff_sz,
                            new_slot_epoch,
                            ts,
                            sid,
                        ),
                    )
            else:
                # resting 待機中: active_oid を紐付け
                tx.execute(
                    """
                    UPDATE slot_state_store
                    SET active_cloid = ?, active_oid = ?, mutation_epoch = ?, updated_at_ms = ?
                    WHERE slot_id = ?
                    """,
                    (
                        cloid,
                        int(oid) if oid is not None else None,
                        new_slot_epoch,
                        ts,
                        sid,
                    ),
                )

            tx.execute(
                "UPDATE system_state_store SET mutation_epoch = ?, updated_at_ms = ? WHERE id = 1",
                (new_sys_epoch, ts),
            )
            updated = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            return dict(updated) if updated else {}

    # ==========================================================================
    # 状態遷移 ＆ 静止期間 (`quiescence_until_ms`) ガード
    # ==========================================================================
    def transition_to_modifying_sl(
        self,
        slot_id: int,
        new_sl_px: float,
        new_trailing_stage: Optional[int] = None,
        quiescence_ms: int = QUIESCENCE_MODIFYING_SL_MS,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        200msガーディアンが4段階トレーリングストップの閾値到達により `sl_px` を引き上げる。
        一時的に `MODIFYING_SL` を経由して静止期間 (`now + 500ms`) を設定し、
        `sl_px >= entry_px * 1.0015` 到達時はサブ状態を `FREEROLL_LOCKED` へ昇格させて
        `OPEN_PROTECTED` に確定する。
        """
        sid = int(slot_id)
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        quiescence_until = ts + int(quiescence_ms)

        with self.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_sys_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            eff_quiescence = max(int(sys_row["quiescence_until_ms"]) if sys_row else 0, quiescence_until)

            slot_row = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            if not slot_row:
                raise ValueError(f"slot_id={sid} が存在しません")

            entry_px = float(slot_row["entry_px"] or 0.0)
            cur_sl = float(slot_row["sl_px"] or 0.0)
            cur_stage = int(slot_row["trailing_stage"] or 1)
            cur_sub_state = str(slot_row["sub_state"] or SlotSubState.INITIAL_RISK.value)

            # SLおよびトレーリングステージは単調引き上げ（ラチェット）のみ許可
            eff_sl = max(cur_sl, float(new_sl_px)) if cur_sl > 0 else float(new_sl_px)
            stage = max(cur_stage, int(new_trailing_stage)) if new_trailing_stage is not None else cur_stage

            if (
                cur_sub_state == SlotSubState.FREEROLL_LOCKED.value
                or (entry_px > 0 and eff_sl >= entry_px * self.FREEROLL_LOCK_MULTIPLIER)
                or TrailingStage.is_freeroll_locked_stage(stage)
            ):
                sub_state = SlotSubState.FREEROLL_LOCKED.value
                if stage < 10:
                    stage = max(stage, 2)
                else:
                    stage = max(stage, int(TrailingStage.STAGE_20_FREEROLL))
            else:
                sub_state = cur_sub_state
                if sub_state == SlotSubState.NONE.value:
                    sub_state = SlotSubState.INITIAL_RISK.value

            new_slot_epoch = int(slot_row["mutation_epoch"]) + 1

            tx.execute(
                """
                UPDATE system_state_store
                SET mutation_epoch = ?, quiescence_until_ms = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (new_sys_epoch, eff_quiescence, ts),
            )
            tx.execute(
                """
                UPDATE slot_state_store
                SET state = ?, sub_state = ?, sl_px = ?, trailing_stage = ?,
                    mutation_epoch = ?, updated_at_ms = ?
                WHERE slot_id = ?
                """,
                (
                    SlotState.OPEN_PROTECTED.value,
                    sub_state,
                    eff_sl,
                    stage,
                    new_slot_epoch,
                    ts,
                    sid,
                ),
            )
            updated = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            res = dict(updated) if updated else {}
            res["quiescence_until_ms"] = eff_quiescence
            res["system_mutation_epoch"] = new_sys_epoch
            return res

    def transition_to_exiting_atomic(
        self,
        slot_id: int,
        exit_cloid: Optional[str] = None,
        quiescence_ms: int = QUIESCENCE_EXITING_ATOMIC_MS,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        SL着弾、TP到達、Perp清算カスケード緊急脱出、またはタイムストップにより
        スロットを `EXITING_ATOMIC` 状態へ遷移させ、静止期間 `now + 2500ms` を設定する。
        """
        sid = int(slot_id)
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        cloid = exit_cloid if exit_cloid else generate_cloid()
        quiescence_until = ts + int(quiescence_ms)

        with self.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_sys_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            eff_quiescence = max(int(sys_row["quiescence_until_ms"]) if sys_row else 0, quiescence_until)

            slot_row = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            new_slot_epoch = (int(slot_row["mutation_epoch"]) + 1) if slot_row else 1

            tx.execute(
                """
                UPDATE system_state_store
                SET mutation_epoch = ?, quiescence_until_ms = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (new_sys_epoch, eff_quiescence, ts),
            )
            tx.execute(
                """
                UPDATE slot_state_store
                SET state = ?, active_cloid = ?, mutation_epoch = ?, updated_at_ms = ?
                WHERE slot_id = ?
                """,
                (SlotState.EXITING_ATOMIC.value, cloid, new_slot_epoch, ts, sid),
            )
            updated = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            res = dict(updated) if updated else {}
            res["quiescence_until_ms"] = eff_quiescence
            res["system_mutation_epoch"] = new_sys_epoch
            return res

    def reset_slot_to_idle(
        self,
        slot_id: int,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """キャンセル完了または決済完了後にスロットを `IDLE` (hold=0, total=0) へ戻す"""
        sid = int(slot_id)
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        with self.acquire_hierarchy(use_global=False, slot_ids=(sid,), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_sys_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            slot_row = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            new_slot_epoch = (int(slot_row["mutation_epoch"]) + 1) if slot_row else 1

            tx.execute(
                "UPDATE system_state_store SET mutation_epoch = ?, updated_at_ms = ? WHERE id = 1",
                (new_sys_epoch, ts),
            )
            tx.execute(
                """
                UPDATE slot_state_store
                SET state = 'IDLE', sub_state = 'NONE', coin = NULL, base_asset = NULL,
                    sz_decimals = NULL, active_cloid = NULL, active_oid = NULL,
                    entry_px = 0.0, current_sz = 0.0, sl_px = 0.0, tp_px = 0.0,
                    trailing_stage = 1, order_created_at_ms = 0, episode_id = NULL,
                    mutation_epoch = ?, updated_at_ms = ?
                WHERE slot_id = ?
                """,
                (new_slot_epoch, ts, sid),
            )
            updated = tx.execute(
                "SELECT * FROM slot_state_store WHERE slot_id = ?", (sid,)
            ).fetchone()
            return dict(updated) if updated else {}

    def enter_dust_recovery_mode(
        self,
        quiescence_ms: int = QUIESCENCE_DUST_RECOVERY_MS,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        15秒ループが10.0 USDC未満の隔離端数に対して「Top-Up & Dump」を実行する前に
        システム状態を `DUST_RECOVERY_IN_PROGRESS` に設定し、静止期間 (`now + 5000ms`) をセットする。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        quiescence_until = ts + int(quiescence_ms)
        with self.acquire_hierarchy(use_global=True, slot_ids=(1, 2), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            if sys_row and str(sys_row["system_mode"]) == SystemMode.HALTED.value:
                raise SystemHaltedError("HALTED 状態では Dust Recovery を開始できません。")
            new_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            eff_quiescence = max(int(sys_row["quiescence_until_ms"]) if sys_row else 0, quiescence_until)
            tx.execute(
                """
                UPDATE system_state_store
                SET system_mode = ?, mutation_epoch = ?, quiescence_until_ms = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (SystemMode.DUST_RECOVERY_IN_PROGRESS.value, new_epoch, eff_quiescence, ts),
            )
            return dict(tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone())

    def exit_dust_recovery_mode(
        self,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Top-Up & Dump 完了後にシステム状態を `NORMAL` へ戻す（HALTEDでない場合のみ）"""
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        with self.acquire_hierarchy(use_global=True, slot_ids=(1, 2), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            cur_mode = str(sys_row["system_mode"]) if sys_row else SystemMode.NORMAL.value
            next_mode = (
                SystemMode.HALTED.value
                if cur_mode == SystemMode.HALTED.value
                else SystemMode.NORMAL.value
            )
            tx.execute(
                """
                UPDATE system_state_store
                SET system_mode = ?, mutation_epoch = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (next_mode, new_epoch, ts),
            )
            return dict(tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone())

    def trigger_system_halt(
        self,
        reason: str,
        timestamp_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        システム全体状態を終端状態 `HALTED` に遷移させる。
        """
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        logger.critical("SYSTEM HALTED 遷移発動: reason=%s", reason)
        with self.acquire_hierarchy(use_global=True, slot_ids=(1, 2), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            new_epoch = int(sys_row["mutation_epoch"]) + 1 if sys_row else 1
            tx.execute(
                """
                UPDATE system_state_store
                SET system_mode = ?, mutation_epoch = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (SystemMode.HALTED.value, new_epoch, ts),
            )
            return dict(tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone())

    # ==========================================================================
    # Fencing Token (`mutation_epoch`) ＆ 静止期間 (`quiescence_until_ms`) 検証
    # ==========================================================================
    def capture_fencing_snapshot(self, current_time_ms: Optional[int] = None) -> Dict[str, Any]:
        """
        15秒ループが `/info` API を呼び出す直前に呼び出し、
        現在の `mutation_epoch` と `quiescence_until_ms`、および各スロットの epoch を記録する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        sys_st = self.db.get_system_state()
        slots = self.db.get_all_slots()
        return {
            "captured_at_ms": ts,
            "system_mode": str(sys_st.get("system_mode", SystemMode.NORMAL.value)),
            "system_mutation_epoch": int(sys_st.get("mutation_epoch", 0)),
            "quiescence_until_ms": int(sys_st.get("quiescence_until_ms", 0)),
            "slot_epochs": {sid: int(s.get("mutation_epoch", 0)) for sid, s in slots.items()},
            "slot_states": {sid: str(s.get("state", SlotState.IDLE.value)) for sid, s in slots.items()},
        }

    def validate_fencing_snapshot(
        self,
        pre_snapshot: Dict[str, Any],
        current_time_ms: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        15秒ループが `/info` API を呼び出した直後に呼び出す検証メソッド。
        以下のいずれかに該当する場合は `(False, reason)` を返し、取得した `/info` スナップショットを
        汚染データとして破棄（No-Op）し、3者照合およびL5判定をスキップさせる:
          1. 呼び出し前または呼び出し後のシステム状態が `DUST_RECOVERY_IN_PROGRESS` または `HALTED`
          2. 呼び出し時刻または現在時刻が静止期間 (`quiescence_until_ms`) 内にある
          3. スロットが遷移中状態 (`MODIFYING_SL` または `EXITING_ATOMIC`) にある
          4. `/info` 通信中に200msガーディアンや15分AIループが割り込み、`mutation_epoch` が変化した
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        post_sys = self.db.get_system_state()
        post_slots = self.db.get_all_slots()

        pre_mode = str(pre_snapshot.get("system_mode", SystemMode.NORMAL.value))
        post_mode = str(post_sys.get("system_mode", SystemMode.NORMAL.value))

        if pre_mode == SystemMode.DUST_RECOVERY_IN_PROGRESS.value or post_mode == SystemMode.DUST_RECOVERY_IN_PROGRESS.value:
            return (False, "DUST_RECOVERY_IN_PROGRESS_ACTIVE")

        if post_mode == SystemMode.HALTED.value:
            return (False, "SYSTEM_ALREADY_HALTED")

        pre_quiescence = int(pre_snapshot.get("quiescence_until_ms", 0))
        post_quiescence = int(post_sys.get("quiescence_until_ms", 0))
        captured_at = int(pre_snapshot.get("captured_at_ms", ts))
        eff_quiescence = max(pre_quiescence, post_quiescence)

        if captured_at < eff_quiescence or ts < eff_quiescence:
            return (False, f"IN_QUIESCENCE_WINDOW_UNTIL_{eff_quiescence}")

        pre_epoch = int(pre_snapshot.get("system_mutation_epoch", -1))
        post_epoch = int(post_sys.get("mutation_epoch", -2))
        if pre_epoch != post_epoch:
            return (False, f"MUTATION_EPOCH_CHANGED_{pre_epoch}_TO_{post_epoch}")

        pre_slot_epochs: Dict[int, int] = pre_snapshot.get("slot_epochs") or {}
        for sid, s_row in post_slots.items():
            st = str(s_row.get("state", SlotState.IDLE.value))
            if st in (SlotState.MODIFYING_SL.value, SlotState.EXITING_ATOMIC.value, SlotState.CANCELLING.value):
                return (False, f"SLOT_{sid}_IN_TRANSITION_STATE_{st}")
            if int(s_row.get("mutation_epoch", -1)) != int(pre_slot_epochs.get(sid, -2)):
                return (False, f"SLOT_{sid}_EPOCH_CHANGED")

        return (True, "VALID_CLEAN_SNAPSHOT")

    # ==========================================================================
    # 3回連続不整合ルール (`desync_strike_count`)
    # ==========================================================================
    def record_reconciliation_result(
        self,
        is_synced: bool,
        pre_snapshot: Optional[Dict[str, Any]] = None,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        3者照合の結果を記録する。
        - もし `pre_snapshot` が渡され、Fencing検証または静止期間チェックが不合格の場合は
          汚染データとしてストライクカウントを更新せず `skipped=True` を返す。
        - 静止期間外に `is_synced=True` なら `desync_strike_count = 0` にリセット。
        - 静止期間外に `is_synced=False` なら `desync_strike_count += 1` し、
          3回連続 (`>= 3`) に達した場合のみ `system_mode = 'HALTED'` へ遷移する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        if pre_snapshot is not None:
            valid, reason = self.validate_fencing_snapshot(pre_snapshot, current_time_ms=ts)
            if not valid:
                sys_st = self.db.get_system_state()
                return {
                    "skipped": True,
                    "skip_reason": reason,
                    "desync_strike_count": int(sys_st.get("desync_strike_count", 0)),
                    "system_mode": str(sys_st.get("system_mode", SystemMode.NORMAL.value)),
                    "halted_triggered": False,
                }

        with self.acquire_hierarchy(use_global=True, slot_ids=(), use_db_tx=True) as tx:
            assert tx is not None
            sys_row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
            cur_strikes = int(sys_row["desync_strike_count"]) if sys_row else 0
            cur_mode = str(sys_row["system_mode"]) if sys_row else SystemMode.NORMAL.value
            cur_quiescence = int(sys_row["quiescence_until_ms"]) if sys_row else 0

            if ts < cur_quiescence or cur_mode == SystemMode.DUST_RECOVERY_IN_PROGRESS.value:
                return {
                    "skipped": True,
                    "skip_reason": "QUIESCENCE_ACTIVE",
                    "desync_strike_count": cur_strikes,
                    "system_mode": cur_mode,
                    "halted_triggered": False,
                }

            if is_synced:
                new_strikes = 0
                next_mode = cur_mode
                halted_triggered = False
            else:
                new_strikes = cur_strikes + 1
                if new_strikes >= self.DESYNC_HALT_STRIKES:
                    next_mode = SystemMode.HALTED.value
                    halted_triggered = True
                    logger.critical(
                        "3者照合が %d 周期連続で不整合となったため HALTED へ遷移します。",
                        new_strikes,
                    )
                else:
                    next_mode = cur_mode
                    halted_triggered = False

            tx.execute(
                """
                UPDATE system_state_store
                SET desync_strike_count = ?, system_mode = ?, updated_at_ms = ?
                WHERE id = 1
                """,
                (new_strikes, next_mode, ts),
            )
            return {
                "skipped": False,
                "skip_reason": "NONE",
                "desync_strike_count": new_strikes,
                "system_mode": next_mode,
                "halted_triggered": halted_triggered,
            }
