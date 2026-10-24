"""
HL AI Trader v1 — Phase 1 & Phase 2 Comprehensive Unit Test Suite (tests/test_phase1_phase2.py)

検証対象:
- Phase 1:
  1. `WindowsSingleInstanceGuard` (Named Mutex 二重起動阻止・解放再取得・PID識別)
  2. `MonotonicHyperliquidNonceManager` (単調増加・時刻逆行耐性・マルチスレッド並列安全性・ドリフト上限)
  3. `round_price` & `floor_size` (有効数字5桁 ＆ 小数点以下 `8 - szDecimals` 桁の厳密 `ROUND_DOWN`)
  4. `UsdcJpyRateFetcher` (Tier 1 ➔ Tier 2 ➔ Tier 3 為替レート3段フェイルオーバー)
  5. `DatabaseManager` & `HyperliquidTaxEngine` (SQLite WAL 全10テーブルDDL、暗号資産間交換の譲渡＋取得二重課税イベント、`feeToken` 3分岐、`hl_tid` べき等性、移動平均法・総平均法)
  6. `ConcurrencyStateCoordinator` (単一方向ロック階層、`cloid` 先行WALコミット、`mutation_epoch` フェンシングトークン、`quiescence_until_ms` 静止期間、3回連続不整合HALT)
- Phase 2:
  7. `HyperliquidExchangeWrapper` (Agent Wallet初期化、`extra_agents` 期限チェック、Perps➔Spot自動振替、Spot-Perp動的マッピング、Perps発注遮断ガード、16 USDC最小発注フロア、1ステップIOC決済、10 USDC未満端数の Top-Up & Dump 自己復旧)
  8. `HyperliquidWSManager` (60秒タイムアウト防止 Ping/Pong、BBOキャッシュ、`user_fills_by_time` 切断中約定補完と重複排除)
"""

from __future__ import annotations

import concurrent.futures
import json
import threading
import time
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from src.coordinator import (
    ConcurrencyStateCoordinator,
    LockHierarchyViolationError,
    SlotState,
    SlotSubState,
    SystemHaltedError,
    SystemMode,
)
from src.db import DatabaseManager, EXPECTED_TEN_TABLES, HyperliquidTaxEngine
from src.exchange_wrapper import (
    AgentWalletExpiredError,
    HyperliquidExchangeWrapper,
    OrderValidationError,
    PerpsOrderForbiddenError,
    map_spot_base_to_perp_symbol,
)
from src.utils import (
    MonotonicHyperliquidNonceManager,
    NonceDriftError,
    SingleInstanceAlreadyRunningError,
    UsdcJpyRateFetcher,
    WindowsSingleInstanceGuard,
    floor_size,
    round_price,
)
from src.ws_manager import HyperliquidWSManager


# ==============================================================================
# 1. WindowsSingleInstanceGuard & NonceManager & Decimal Rounding Tests
# ==============================================================================
def test_windows_single_instance_guard(tmp_path: Path) -> None:
    mutex_name = r"Local\HL_AI_TRADER_V1_TEST_MUTEX_" + str(int(time.time() * 1000))
    lock_file = tmp_path / "test_daemon.lock"

    guard1 = WindowsSingleInstanceGuard(mutex_name=mutex_name, lock_file_path=lock_file)
    guard2 = WindowsSingleInstanceGuard(mutex_name=mutex_name, lock_file_path=lock_file)

    assert guard1.acquire() is True
    assert lock_file.exists()

    # 2つ目のインスタンスは取得失敗・例外送出となること
    assert guard2.acquire(raise_on_failure=False) is False
    with pytest.raises(SingleInstanceAlreadyRunningError):
        guard2.acquire(raise_on_failure=True)

    # 解放後は2つ目が取得できること
    guard1.release()
    assert guard2.acquire(raise_on_failure=True) is True
    guard2.release()


def test_monotonic_nonce_manager_clock_regression_and_threads() -> None:
    mgr = MonotonicHyperliquidNonceManager(initial_nonce=1_700_000_000_000)

    # 通常の前進
    n1 = mgr.next_nonce(current_time_ms=1_700_000_001_000)
    assert n1 == 1_700_000_001_000

    # NTP補正等でシステム時計が5秒逆行した場合でも last_nonce + 1 で単調増加すること
    n2 = mgr.next_nonce(current_time_ms=1_700_000_000_500)
    n3 = mgr.next_nonce(current_time_ms=1_700_000_000_500)
    assert n2 == 1_700_000_001_001
    assert n3 == 1_700_000_001_002

    # マルチスレッド並列呼び出し (12スレッド × 100回 = 1,200回) で重複ゼロ・完全単調増加
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(
            pool.map(lambda _: mgr.next_nonce(current_time_ms=1_700_000_002_000), range(1200))
        )
    assert len(results) == 1200
    assert len(set(results)) == 1200
    assert min(results) >= 1_700_000_002_000

    # Hyperliquid L1 の +1日上限を超える異常な時刻逆行（ドリフト）時は NonceDriftError
    with pytest.raises(NonceDriftError):
        mgr.next_nonce(current_time_ms=1_700_000_002_000 - 90_000_000)


def test_round_price_and_floor_size_hyperliquid_spot_rules() -> None:
    # 1. HYPE/USDC (szDecimals = 2 -> max decimals = 8 - 2 = 6, 有効数字5桁)
    assert round_price("25.43289", sz_decimals=2) == "25.432"
    assert round_price(25.4000, sz_decimals=2) == "25.4"

    # 2. UBTC/USDC (szDecimals = 5 -> max decimals = 8 - 5 = 3, 有効数字5桁)
    assert round_price("98765.432", sz_decimals=5) == "98765"
    assert round_price("105439.9", sz_decimals=5) == "105430"

    # 3. UETH/USDC (szDecimals = 4 -> max decimals = 8 - 4 = 4, 有効数字5桁)
    assert round_price("3124.5678", sz_decimals=4) == "3124.5"

    # 4. 小数価格トークン (szDecimals = 2 -> max decimals = 6 が有効数字5桁より優先されるケース)
    assert round_price("0.000123456", sz_decimals=2) == "0.000123"

    # 5. szDecimals = 0 (max decimals = 8)
    assert round_price("0.00001234567", sz_decimals=0) == "0.00001234"
    assert round_price("0.1234567", sz_decimals=0) == "0.12345"

    # 6. floor_size (ROUND_DOWN 切り捨て検証)
    assert floor_size("3.9984", sz_decimals=2) == "3.99"
    assert floor_size("0.123459", sz_decimals=5) == "0.12345"
    assert floor_size("150.99", sz_decimals=0) == "150"
    assert floor_size("-1.5", sz_decimals=2) == "0"


def test_usdc_jpy_rate_fetcher_three_tier_failover() -> None:
    # Case 1: Tier 1 成功
    f1 = UsdcJpyRateFetcher(
        default_rate=155.0,
        tier1_fetcher=lambda: (153.45, "TIER1_MOCK"),
        tier2_fetcher=lambda: (154.00, "TIER2_MOCK"),
    )
    rate, src = f1.get_rate(force_refresh=True)
    assert rate == pytest.approx(153.45)
    assert src == "TIER1_MOCK"

    # Case 2: Tier 1 失敗 -> Tier 2 成功
    f2 = UsdcJpyRateFetcher(
        default_rate=155.0,
        tier1_fetcher=lambda: None,
        tier2_fetcher=lambda: (154.20, "TIER2_OPEN_ER"),
    )
    rate2, src2 = f2.get_rate(force_refresh=True)
    assert rate2 == pytest.approx(154.20)
    assert src2 == "TIER2_OPEN_ER"

    # Case 3: Tier 1 & Tier 2 失敗 -> Tier 3 (SQLite キャッシュ) 成功
    f3 = UsdcJpyRateFetcher(
        default_rate=155.0,
        db_rate_provider=lambda: 156.80,
        tier1_fetcher=lambda: (99999.0, "INVALID_OUTLIER"),  # 異常値は棄却されること
        tier2_fetcher=lambda: None,
    )
    rate3, src3 = f3.get_rate(force_refresh=True)
    assert rate3 == pytest.approx(156.80)
    assert src3 == "TIER3_SQLITE_CACHE"

    # Case 4: 全失敗 -> デフォルト値 155.0
    f4 = UsdcJpyRateFetcher(
        default_rate=155.0,
        db_rate_provider=lambda: None,
        tier1_fetcher=lambda: None,
        tier2_fetcher=lambda: None,
    )
    rate4, src4 = f4.get_rate(force_refresh=True)
    assert rate4 == pytest.approx(155.0)
    assert src4 == "TIER3_DEFAULT_STATIC"


# ==============================================================================
# 2. DatabaseManager (10 Tables DDL) & HyperliquidTaxEngine Tests
# ==============================================================================
def test_database_ten_tables_and_tax_engine_dual_leg(tmp_path: Path) -> None:
    db_file = tmp_path / "hl_v1_state_wal.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=130.0, initial_usdc_jpy_rate=150.0)

    # 全10テーブルが存在すること
    tables = set(db.list_tables())
    assert set(EXPECTED_TEN_TABLES).issubset(tables)
    assert len(EXPECTED_TEN_TABLES) == 10

    tax = HyperliquidTaxEngine(db=db)

    # 2026年 期首残高: 200 USDC @ 150.0 JPY (= 30,000 JPY)
    ts_2026 = 1_775_000_000_000  # 2026年内
    tax.seed_opening_or_deposit(
        asset="USDC",
        qty="200.0",
        unit_jpy="150.0",
        tax_year=2026,
        timestamp_ms=ts_2026,
    )

    # Trade 1: HYPE/USDC を 4.0 HYPE @ 25.0 USDC (= 100.0 USDC) で Spot 買い
    # 手数料: 0.004 HYPE (raw_fee_token = "HYPE"), 約定時為替: 1 USDC = 155.0 JPY
    lot1 = tax.process_spot_fill(
        hl_tid=10001,
        hl_oid=501,
        timestamp_ms=ts_2026 + 1000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.0",
        exec_sz_base="4.0",
        raw_fee_amount="0.004",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
        rate_source="TEST_RATE",
    )
    assert lot1["duplicate"] is False
    assert lot1["event_type"] == "SPOT_BUY"
    assert lot1["disposed_asset"] == "USDC"
    assert lot1["disposed_qty"] == pytest.approx(100.0)
    assert lot1["disposed_cogs_jpy"] == pytest.approx(15000.0)   # 100 * 150
    assert lot1["gross_proceeds_jpy"] == pytest.approx(15500.0)  # 100 * 155
    assert lot1["realized_pnl_jpy"] == pytest.approx(500.0)      # USDCの為替差益 +500円
    assert lot1["acquired_asset"] == "HYPE"
    assert lot1["acquired_net_qty"] == pytest.approx(3.996)      # 4.0 - 0.004
    assert lot1["acquisition_cost_jpy"] == pytest.approx(15500.0)

    # 同一 hl_tid=10001 の再投入時はべき等にスキップされること
    lot1_dup = tax.process_spot_fill(
        hl_tid=10001,
        hl_oid=501,
        timestamp_ms=ts_2026 + 1000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.0",
        exec_sz_base="4.0",
        raw_fee_amount="0.004",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert lot1_dup["duplicate"] is True

    # Trade 2: HYPE/USDC を 3.996 HYPE 全量 @ 30.0 USDC (= 119.88 USDC) で Spot 売り
    # 手数料: 0.083916 USDC (raw_fee_token = "USDC"), 約定時為替: 1 USDC = 155.0 JPY
    lot2 = tax.process_spot_fill(
        hl_tid=10002,
        hl_oid=502,
        timestamp_ms=ts_2026 + 60_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc="30.0",
        exec_sz_base="3.996",
        raw_fee_amount="0.08",
        raw_fee_token="USDC",
        usdc_jpy_rate=155.0,
        rate_source="TEST_RATE",
    )
    assert lot2["event_type"] == "SPOT_SELL"
    assert lot2["disposed_asset"] == "HYPE"
    assert lot2["disposed_qty"] == pytest.approx(3.996)
    assert lot2["disposed_cogs_jpy"] == pytest.approx(15500.0)
    expected_proceeds = 3.996 * 30.0 * 155.0  # 18,581.4 JPY
    expected_expense = 0.08 * 155.0           # 12.4 JPY
    assert lot2["gross_proceeds_jpy"] == pytest.approx(expected_proceeds)
    assert lot2["selling_expense_jpy"] == pytest.approx(expected_expense)
    assert lot2["realized_pnl_jpy"] == pytest.approx(expected_proceeds - 15500.0 - expected_expense)
    assert lot2["acquired_asset"] == "USDC"
    assert lot2["acquired_net_qty"] == pytest.approx(3.996 * 30.0 - 0.08)

    # Trade 3: feeToken == "USDC" での Spot 買い分岐検証
    lot3 = tax.process_spot_fill(
        hl_tid=10003,
        hl_oid=503,
        timestamp_ms=ts_2026 + 120_000,
        pair_name="UBTC/USDC",
        base_asset="UBTC",
        is_buy=True,
        exec_px_usdc="100000.0",
        exec_sz_base="0.0005",
        raw_fee_amount="0.02",
        raw_fee_token="USDC",
        usdc_jpy_rate=155.0,
        rate_source="TEST_RATE",
    )
    assert lot3["disposed_asset"] == "USDC"
    assert lot3["disposed_qty"] == pytest.approx(50.02)  # 50.0 + 0.02 USDC
    assert lot3["acquired_asset"] == "UBTC"
    assert lot3["acquired_net_qty"] == pytest.approx(0.0005)
    assert lot3["acquisition_cost_jpy"] == pytest.approx(50.02 * 155.0)

    # 移動平均法と総平均法の年次サマリー算出検証
    summary_ma = tax.calculate_annual_summary(tax_year=2026, method="MOVING_AVERAGE")
    summary_ta = tax.calculate_annual_summary(tax_year=2026, method="TOTAL_AVERAGE")
    assert summary_ma["lot_count"] == 3
    assert summary_ta["lot_count"] == 3
    assert "HYPE" in summary_ma["by_disposed_asset"]
    assert "USDC" in summary_ta["by_disposed_asset"]
    # HYPEは1回買って1回全量売ったため、移動平均法と総平均法でHYPEの実現損益は完全一致する
    assert summary_ma["by_disposed_asset"]["HYPE"]["realized_pnl_jpy"] == pytest.approx(
        summary_ta["by_disposed_asset"]["HYPE"]["realized_pnl_jpy"]
    )
    db.close()


# ==============================================================================
# 3. ConcurrencyStateCoordinator (Lock Hierarchy, Fencing, Quiescence, 3-Strikes)
# ==============================================================================
def test_coordinator_lock_hierarchy_and_state_machine(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "coord_test.db")
    coord = ConcurrencyStateCoordinator(db=db)

    # 1. 正規ロック順序 (Global -> Slot 1 -> Slot 2 -> DB) は成功すること
    with coord.global_system_lock():
        with coord.slot_lock(1):
            with coord.slot_lock(2):
                with coord.db_immediate_lock() as tx:
                    assert tx is not None

    # 2. 逆順ロック要求 (Slot 2 -> Slot 1) は LockHierarchyViolationError を送出すること
    with coord.slot_lock(2):
        with pytest.raises(LockHierarchyViolationError):
            with coord.slot_lock(1):
                pass

    # 3. 逆順ロック要求 (Slot 1 -> Global) も LockHierarchyViolationError を送出すること
    with coord.slot_lock(1):
        with pytest.raises(LockHierarchyViolationError):
            with coord.global_system_lock():
                pass

    # 4. Write-Ahead Intent & Fencing Token 検証
    pre_snap = coord.capture_fencing_snapshot(current_time_ms=100_000)
    assert coord.validate_fencing_snapshot(pre_snap, current_time_ms=100_100)[0] is True

    # /info 通信中に別ループが注文意図をコミットして mutation_epoch が進んだ場合
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.0,
        sz=3.6,
        sl_px=24.0,
        tp_px=27.5,
        timestamp_ms=100_200,
    )
    valid, reason = coord.validate_fencing_snapshot(pre_snap, current_time_ms=100_300)
    assert valid is False
    assert "MUTATION_EPOCH_CHANGED" in reason

    # 注文約定の紐付け -> OPEN_PROTECTED (INITIAL_RISK)
    slot1 = coord.bind_order_response(
        slot_id=1,
        cloid=intent["cloid"],
        oid=777,
        filled=True,
        filled_sz=3.6,
        avg_px=25.0,
        timestamp_ms=100_500,
    )
    assert slot1["state"] == SlotState.OPEN_PROTECTED.value
    assert slot1["sub_state"] == SlotSubState.INITIAL_RISK.value

    # トレーリングSL引き上げ (25.0 * 1.0015 = 25.0375 以上 -> FREEROLL_LOCKED 昇格 & 静止期間 +500ms)
    mod_res = coord.transition_to_modifying_sl(
        slot_id=1,
        new_sl_px=25.05,
        new_trailing_stage=2,
        timestamp_ms=200_000,
    )
    assert mod_res["sub_state"] == SlotSubState.FREEROLL_LOCKED.value
    assert mod_res["quiescence_until_ms"] == 200_500

    # 静止期間内 (200_300ms < 200_500ms) のスナップショットは破棄されること
    snap_during_q = coord.capture_fencing_snapshot(current_time_ms=200_200)
    valid_q, reason_q = coord.validate_fencing_snapshot(snap_during_q, current_time_ms=200_300)
    assert valid_q is False
    assert "IN_QUIESCENCE_WINDOW" in reason_q

    # 5. 3回連続不整合ルール (静止期間外: 210_000ms 以降)
    r1 = coord.record_reconciliation_result(is_synced=False, current_time_ms=210_000)
    assert r1["desync_strike_count"] == 1
    assert r1["system_mode"] == SystemMode.NORMAL.value

    r2 = coord.record_reconciliation_result(is_synced=False, current_time_ms=225_000)
    assert r2["desync_strike_count"] == 2
    assert r2["system_mode"] == SystemMode.NORMAL.value

    # 途中で1回整合すればストライクカウントが 0 にリセットされること
    r_ok = coord.record_reconciliation_result(is_synced=True, current_time_ms=240_000)
    assert r_ok["desync_strike_count"] == 0

    # 3回連続不整合で HALTED へ遷移すること
    coord.record_reconciliation_result(is_synced=False, current_time_ms=255_000)
    coord.record_reconciliation_result(is_synced=False, current_time_ms=270_000)
    r3 = coord.record_reconciliation_result(is_synced=False, current_time_ms=285_000)
    assert r3["desync_strike_count"] == 3
    assert r3["system_mode"] == SystemMode.HALTED.value
    assert r3["halted_triggered"] is True

    # HALTED 後は新規 ENTRY_PENDING が SystemHaltedError で永久遮断されること
    with pytest.raises(SystemHaltedError):
        coord.begin_order_intent(
            slot_id=2,
            target_state=SlotState.ENTRY_PENDING,
            coin="HYPE/USDC",
            base_asset="HYPE",
            sz_decimals=2,
            entry_px=25.0,
            sz=1.0,
        )
    db.close()


# ==============================================================================
# 4. HyperliquidExchangeWrapper Tests (Perp Block, Mapping, IOC, Top-Up & Dump)
# ==============================================================================
class MockHLInfo:
    def __init__(self, agent_address: str) -> None:
        self.agent_address = agent_address
        self.spot_balances: List[Dict[str, Any]] = [
            {"coin": "USDC", "total": "130.0", "hold": "0.0"},
            {"coin": "HYPE", "total": "3.9984", "hold": "0.0"},
        ]
        self.withdrawable_perp_usdc = "45.50"
        self.valid_until_ms = int(time.time() * 1000) + 10 * 86_400_000
        self.fills_by_time: List[Dict[str, Any]] = []

    def extra_agents(self, address: str) -> List[Dict[str, Any]]:
        return [
            {
                "address": self.agent_address,
                "name": "HL_AI_TRADER_V1_AGENT",
                "validUntil": self.valid_until_ms,
            }
        ]

    def user_state(self, address: str) -> Dict[str, Any]:
        return {
            "withdrawable": self.withdrawable_perp_usdc,
            "assetPositions": [],
        }

    def spot_clearinghouse_state(self, address: str) -> Dict[str, Any]:
        return {"balances": list(self.spot_balances)}

    def user_rate_limit(self, address: str) -> Dict[str, Any]:
        return {"nRequestsCap": 10000, "nRequestsUsed": 120}

    def open_orders(self, address: str) -> List[Dict[str, Any]]:
        return []

    def spot_meta_and_asset_ctxs(self) -> Any:
        spot_meta = {
            "tokens": [
                {"name": "USDC", "szDecimals": 8, "weiDecimals": 8, "index": 0, "isCanonical": True},
                {"name": "PURR", "szDecimals": 0, "weiDecimals": 5, "index": 1, "isCanonical": True},
                {"name": "HYPE", "szDecimals": 2, "weiDecimals": 8, "index": 150, "isCanonical": True},
                {"name": "UBTC", "szDecimals": 5, "weiDecimals": 10, "index": 197, "isCanonical": True},
                {"name": "UETH", "szDecimals": 4, "weiDecimals": 9, "index": 221, "isCanonical": True},
                {"name": "USOL", "szDecimals": 2, "weiDecimals": 8, "index": 254, "isCanonical": True},
            ],
            "universe": [
                {"name": "PURR/USDC", "tokens": [1, 0], "index": 0, "isCanonical": True},
                {"name": "@107", "tokens": [150, 0], "index": 107, "isCanonical": True},
                {"name": "@142", "tokens": [197, 0], "index": 142, "isCanonical": True},
                {"name": "@151", "tokens": [221, 0], "index": 151, "isCanonical": True},
                {"name": "@156", "tokens": [254, 0], "index": 156, "isCanonical": True},
            ],
        }
        spot_ctxs = [
            {"coin": "PURR/USDC", "midPx": "0.25", "markPx": "0.25", "dayNtlVlm": "3500000.0"},
            {"coin": "@107", "midPx": "25.00", "markPx": "25.00", "dayNtlVlm": "85000000.0"},
            {"coin": "@142", "midPx": "95000.0", "markPx": "95000.0", "dayNtlVlm": "42000000.0"},
            {"coin": "@151", "midPx": "3100.0", "markPx": "3100.0", "dayNtlVlm": "18000000.0"},
            {"coin": "@156", "midPx": "180.0", "markPx": "180.0", "dayNtlVlm": "12000000.0"},
        ]
        return [spot_meta, spot_ctxs]

    def meta_and_asset_ctxs(self) -> Any:
        perp_meta = {
            "universe": [
                {"name": "BTC", "szDecimals": 5},
                {"name": "ETH", "szDecimals": 4},
                {"name": "SOL", "szDecimals": 2},
                {"name": "HYPE", "szDecimals": 2},
                {"name": "PURR", "szDecimals": 0},
            ]
        }
        perp_ctxs = [
            {"markPx": "95010.0", "oraclePx": "95000.0", "funding": "0.0000125", "openInterest": "12000.0", "premium": "0.0001"},
            {"markPx": "3101.0", "oraclePx": "3100.0", "funding": "0.0000100", "openInterest": "80000.0", "premium": "0.0001"},
            {"markPx": "180.1", "oraclePx": "180.0", "funding": "-0.0000200", "openInterest": "500000.0", "premium": "-0.0006"},
            {"markPx": "25.01", "oraclePx": "25.00", "funding": "0.0000125", "openInterest": "9500000.0", "premium": "0.0004"},
            {"markPx": "0.25", "oraclePx": "0.25", "funding": "0.0000100", "openInterest": "15000000.0", "premium": "0.0"},
        ]
        return [perp_meta, perp_ctxs]

    def user_fills_by_time(self, address: str, start_time: int, aggregate_by_time: bool = False) -> List[Dict[str, Any]]:
        return [f for f in self.fills_by_time if int(f.get("time", 0)) >= start_time]


class MockHLExchange:
    def __init__(self, info: MockHLInfo) -> None:
        self.info = info
        self.orders_placed: List[Dict[str, Any]] = []
        self.transfers: List[Dict[str, Any]] = []
        self._next_oid = 9000

    def usd_class_transfer(self, amount: float, to_perp: bool = False) -> Dict[str, Any]:
        self.transfers.append({"amount": amount, "to_perp": to_perp})
        return {"status": "ok", "response": {"type": "default"}}

    def order(
        self,
        name: str,
        is_buy: bool,
        sz: float,
        limit_px: float,
        order_type: Dict[str, Any],
        reduce_only: bool = False,
        cloid: Any = None,
    ) -> Dict[str, Any]:
        self._next_oid += 1
        oid = self._next_oid
        rec = {
            "name": name,
            "is_buy": is_buy,
            "sz": sz,
            "limit_px": limit_px,
            "order_type": order_type,
            "reduce_only": reduce_only,
            "cloid": str(cloid) if cloid is not None else None,
            "oid": oid,
        }
        self.orders_placed.append(rec)

        tif = (order_type.get("limit") or {}).get("tif", "Gtc")
        if tif == "Ioc":
            # Top-Up 買い約定時に MockInfo 側の HYPE 残高を加算して Dump テストと連動させる
            if is_buy and name == "@107":
                for b in self.info.spot_balances:
                    if b["coin"] == "HYPE":
                        b["total"] = str(Decimal(b["total"]) + Decimal(str(sz)))
            elif not is_buy and name == "@107":
                for b in self.info.spot_balances:
                    if b["coin"] == "HYPE":
                        b["total"] = str(max(Decimal("0"), Decimal(b["total"]) - Decimal(str(sz))))
            return {
                "status": "ok",
                "response": {"type": "order", "data": {"statuses": [{"filled": {"totalSz": str(sz), "avgPx": str(limit_px), "oid": oid}}]}},
            }

        return {
            "status": "ok",
            "response": {"type": "order", "data": {"statuses": [{"resting": {"oid": oid}}]}},
        }

    def cancel(self, name: str, oid: int) -> Dict[str, Any]:
        return {"status": "ok", "response": {"data": {"statuses": ["success"]}}}


def test_exchange_wrapper_mapping_perp_guard_ioc_and_dust_recovery(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "wrapper_test.db")
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)

    dummy_pk = "0x" + "22" * 32
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key=dummy_pk,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=MockHLInfo("0x0"),  # 後で agent_address を差し替え
        exchange_client=None,
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    mock_ex = MockHLExchange(mock_info)
    wrapper.info = mock_info
    wrapper.exchange = mock_ex

    # 1. extra_agents 有効期限チェック (正常 & 期限切れエラー)
    validity = wrapper.check_agent_wallet_validity(raise_on_invalid=True)
    assert validity["valid"] is True

    mock_info.valid_until_ms = int(time.time() * 1000) - 10_000
    with pytest.raises(AgentWalletExpiredError):
        wrapper.check_agent_wallet_validity(raise_on_invalid=True)
    mock_info.valid_until_ms = int(time.time() * 1000) + 10 * 86_400_000

    # 2. Perps ➔ Spot 自動USDC振替 (usd_class_transfer)
    tr_res = wrapper.auto_transfer_perp_to_spot_usdc(only_when_spot_below_usdc=200.0)
    assert tr_res["transferred"] is True
    assert tr_res["amount_usdc"] == pytest.approx(45.50)
    assert mock_ex.transfers[0] == {"amount": 45.50, "to_perp": False}

    # 3. Spot-Perp シンボル動的マッピング (先頭 'U' 除去 & @index 逆引き)
    universe = wrapper.refresh_universe_mapping()
    assert "UBTC/USDC" in universe
    assert universe["UBTC/USDC"].api_coin_name == "@142"
    assert universe["UBTC/USDC"].perp_coin == "BTC"
    assert universe["UETH/USDC"].perp_coin == "ETH"
    assert universe["USOL/USDC"].perp_coin == "SOL"
    assert universe["HYPE/USDC"].api_coin_name == "@107"
    assert universe["HYPE/USDC"].perp_coin == "HYPE"

    # 4. Perps発注遮断ガード検証 ("BTC", "ETH", "HYPE", "#PRED" 等は100%即時遮断)
    for forbidden_sym in ("BTC", "ETH", "SOL", "HYPE", "PURR", "#HIP4_EVENT", "DOGE/USDC"):
        with pytest.raises(PerpsOrderForbiddenError):
            wrapper.place_spot_buy_alo(
                slot_id=1,
                coin_or_pair=forbidden_sym,
                raw_limit_px="25.0",
                raw_sz="1.0",
            )
    assert len(mock_ex.orders_placed) == 0

    # 5. 最小発注額 16.0 USDC フロア ＆ 最大初期SL 8.0% ガード検証
    with pytest.raises(OrderValidationError):
        wrapper.place_spot_buy_alo(
            slot_id=1,
            coin_or_pair="HYPE/USDC",
            raw_limit_px="25.0",
            raw_sz="0.50",  # 12.5 USDC < 16.0 USDC
        )
    with pytest.raises(OrderValidationError):
        wrapper.place_spot_buy_alo(
            slot_id=1,
            coin_or_pair="HYPE/USDC",
            raw_limit_px="25.0",
            raw_sz="1.0",
            sl_px="22.0",  # -12.0% > 8.0%
        )

    # 6. 正常な Spot Post-Only (Alo) 新規買い指値発注 (@107 へ変換されて送信されること)
    buy_res = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.1239",
        raw_sz="1.559",
        sl_px="24.20",
        tp_px="27.50",
    )
    assert buy_res["status"] == "ok"
    assert buy_res["coin"] == "@107"
    assert buy_res["px_str"] == "25.123"
    assert buy_res["sz_str"] == "1.55"
    assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

    # 7. 1ステップ IOC 即時決済売り (total=3.9984 -> szDecimals=2 で "3.99" に切り捨て)
    ioc_res = wrapper.execute_atomic_ioc_exit(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        best_bid="25.00",
    )
    assert ioc_res["status"] == "ok"
    assert ioc_res["sz_str"] == "3.99"
    assert ioc_res["min_sell_px_str"] == "24.625"  # 25.00 * 0.985 = 24.625
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # 8. 10 USDC未満端数の「Top-Up & Dump」自己復旧ルーチン検証
    # HYPE 実残高を 0.25 HYPE (@ 25.0 USDC = 6.25 USDC < 10.0 USDC) に設定
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "100.0", "hold": "0.0"},
        {"coin": "HYPE", "total": "0.25", "hold": "0.0"},
    ]
    db.upsert_dust_quarantine(
        base_asset="HYPE",
        coin_pair="HYPE/USDC",
        quarantined_qty=0.25,
        estimated_usdc_val=6.25,
        status="QUARANTINED",
    )
    dust_res = wrapper.recover_dust_top_up_and_dump(
        coin_or_pair="HYPE/USDC",
        best_bid="25.00",
        best_ask="25.01",
        wait_after_top_up_sec=0.01,
    )
    assert dust_res["recovered"] is True
    assert float(dust_res["top_up_notional_usdc"]) >= 11.0
    # Top-Up 0.44 HYPE (0.44 * 25.01 = 11.0044 USDC) + 端数 0.25 HYPE = 0.69 HYPE 全量一括売却
    assert dust_res["top_up_sz_str"] == "0.44"
    assert dust_res["dump_sz_str"] == "0.69"
    q_after = db.get_dust_quarantine("HYPE")
    assert q_after is not None and q_after["status"] == "RECOVERED"
    assert db.get_system_state()["system_mode"] == SystemMode.NORMAL.value
    db.close()


# ==============================================================================
# 5. HyperliquidWSManager Tests (Ping/Pong, BBO Cache, user_fills_by_time Backfill)
# ==============================================================================
def test_ws_manager_ping_pong_bbo_and_gapless_backfill(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "ws_test.db")
    tax = HyperliquidTaxEngine(db=db)
    tax.seed_opening_or_deposit("USDC", "200.0", "150.0", tax_year=2026, timestamp_ms=1_775_000_000_000)

    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "33" * 32,
        execution_mode="DRY_RUN",
        db=db,
        tax_engine=tax,
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    wrapper.info = mock_info
    wrapper.refresh_universe_mapping()

    ws_mgr = HyperliquidWSManager(
        main_address=wrapper.main_address,
        exchange_wrapper=wrapper,
        tax_engine=tax,
        info_client=mock_info,
    )

    sent_payloads: List[Dict[str, Any]] = []

    class DummySocket:
        def send(self, data: str) -> None:
            sent_payloads.append(json.loads(data))

    dummy_sock = DummySocket()

    # 1. 定期 Ping 送信と Pong 受信の検証
    assert ws_mgr.send_ping(ws_override=dummy_sock) is True
    assert sent_payloads[-1] == {"method": "ping"}
    assert ws_mgr.ping_sent_count == 1

    ch = ws_mgr.handle_raw_message({"channel": "pong"})
    assert ch == "pong"
    assert ws_mgr.pong_received_count == 1

    # 2. l2Book メッセージから @107 と HYPE/USDC の両方で BBO が0ms取得できること
    ws_mgr.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": 1_775_000_005_000,
                "levels": [
                    [{"px": "25.00", "sz": "100.0", "n": 3}],
                    [{"px": "25.02", "sz": "120.0", "n": 4}],
                ],
            },
        }
    )
    bbo = ws_mgr.get_bbo("HYPE/USDC")
    assert bbo is not None
    assert bbo["best_bid"] == pytest.approx(25.00)
    assert bbo["best_ask"] == pytest.approx(25.02)
    assert bbo["mid_px"] == pytest.approx(25.01)

    # 3. WS リアルタイム約定 (tid=2001) の処理
    received_fills: List[Dict[str, Any]] = []
    ws_mgr.register_fill_callback(lambda f: received_fills.append(f))

    ws_mgr.handle_raw_message(
        {
            "channel": "userFills",
            "data": {
                "isSnapshot": False,
                "user": wrapper.main_address,
                "fills": [
                    {
                        "coin": "@107",
                        "px": "25.0",
                        "sz": "2.0",
                        "side": "B",
                        "time": 1_775_000_010_000,
                        "fee": "0.002",
                        "feeToken": "HYPE",
                        "tid": 2001,
                        "oid": 801,
                    }
                ],
            },
        }
    )
    assert len(received_fills) == 1
    assert received_fills[0]["tid"] == 2001

    # 4. 切断中の約定を user_fills_by_time でギャップレス補完 (tid=2001 は重複スキップ、tid=2002 は新規補完、Perpの tid=2003 は自動除外)
    mock_info.fills_by_time = [
        {
            "coin": "@107",
            "px": "25.0",
            "sz": "2.0",
            "side": "B",
            "time": 1_775_000_010_000,
            "fee": "0.002",
            "feeToken": "HYPE",
            "tid": 2001,
            "oid": 801,
        },
        {
            "coin": "@107",
            "px": "26.0",
            "sz": "1.99",
            "side": "A",
            "time": 1_775_000_025_000,
            "fee": "0.036",
            "feeToken": "USDC",
            "tid": 2002,
            "oid": 802,
        },
        {
            "coin": "BTC",  # Perp約定 (Spot専用のため除外されること)
            "px": "95000.0",
            "sz": "0.01",
            "side": "B",
            "time": 1_775_000_030_000,
            "fee": "0.3",
            "feeToken": "USDC",
            "tid": 2003,
            "oid": 803,
        },
    ]

    bf_res = ws_mgr.backfill_missed_fills(start_time_ms=1_775_000_000_000)
    assert bf_res["fetched_count"] == 3
    assert bf_res["new_processed_count"] == 1
    assert bf_res["processed_tids"] == [2002]
    assert len(received_fills) == 2
    assert received_fills[1]["tid"] == 2002
    assert received_fills[1]["source"] == "REST_BACKFILL"

    # 税務台帳にも tid=2001 (SPOT_BUY) と tid=2002 (SPOT_SELL) の計2件が正確に計上されていること
    summary = tax.calculate_annual_summary(tax_year=2026, method="MOVING_AVERAGE")
    assert summary["lot_count"] == 2
    db.close()


def test_additional_edge_cases_tax_third_token_and_rate_limit_and_dust_fencing(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "edge_test.db")
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)

    ts = 1_775_500_000_000
    tax.seed_opening_or_deposit("USDC", "500.0", "150.0", tax_year=2026, timestamp_ms=ts)
    tax.seed_opening_or_deposit("PURR", "100.0", "40.0", tax_year=2026, timestamp_ms=ts)

    # 第3トークン (PURR) で買い手数料を支払った場合の分岐検証
    lot_t3_buy = tax.process_spot_fill(
        hl_tid=3001,
        timestamp_ms=ts + 1000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.0",
        exec_sz_base="4.0",
        raw_fee_amount="2.0",
        raw_fee_token="PURR",
        usdc_jpy_rate=155.0,
    )
    # 2.0 PURR @ 40 JPY = 80 JPY が HYPE の取得原価 (100 * 155 = 15,500 JPY) に加算され 15,580 JPY になること
    assert lot_t3_buy["acquisition_cost_jpy"] == pytest.approx(15580.0)
    assert tax.get_inventory_state("PURR")["quantity"] == pytest.approx(98.0)

    # Spot売りで feeToken == base_asset ("HYPE") の分岐検証
    lot_base_sell = tax.process_spot_fill(
        hl_tid=3002,
        timestamp_ms=ts + 2000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc="30.0",
        exec_sz_base="2.0",
        raw_fee_amount="0.01",
        raw_fee_token="HYPE",
        usdc_jpy_rate=155.0,
    )
    assert lot_base_sell["selling_expense_jpy"] == pytest.approx(0.01 * 30.0 * 155.0)
    assert lot_base_sell["acquired_net_qty"] == pytest.approx((2.0 - 0.01) * 30.0)

    # Dust Recovery モード中の Fencing 破棄検証
    coord.enter_dust_recovery_mode(quiescence_ms=5000, timestamp_ms=500_000)
    snap = coord.capture_fencing_snapshot(current_time_ms=500_100)
    ok, reason = coord.validate_fencing_snapshot(snap, current_time_ms=500_200)
    assert ok is False
    assert reason == "DUST_RECOVERY_IN_PROGRESS_ACTIVE"
    rec = coord.record_reconciliation_result(is_synced=False, pre_snapshot=snap, current_time_ms=500_200)
    assert rec["skipped"] is True
    coord.exit_dust_recovery_mode(timestamp_ms=506_000)

    # レート制限残枠チェック (surplus < 500 で should_throttle=True)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    wrapper.info = mock_info
    wrapper.refresh_universe_mapping()

    rl_ok = wrapper.check_rate_limit_surplus()
    assert rl_ok["should_throttle"] is False

    mock_info.user_rate_limit = lambda addr: {"nRequestsCap": 10000, "nRequestsUsed": 9650}  # type: ignore[method-assign]
    rl_low = wrapper.check_rate_limit_surplus()
    assert rl_low["nRequestsSurplus"] == 350
    assert rl_low["should_throttle"] is True

    # キャンセル時の Perp 遮断と正常キャンセル
    with pytest.raises(PerpsOrderForbiddenError):
        wrapper.cancel_spot_order("BTC", oid=123)

    cancel_res = wrapper.cancel_spot_order("HYPE/USDC", oid=123, slot_id=1)
    assert cancel_res["status"] == "ok"
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    db.close()

