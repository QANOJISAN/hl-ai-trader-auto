"""
HL AI Trader v1.2 Alpha-Max — Silent Subprocess, High-Availability WAL & Win32 Power Guard Tests
(`tests/test_silent_ha_and_power_guard.py`)

検証項目:
1. 全 `.py` ファイル (`src/`, `watchdog.py`, `scripts/`) 内の `subprocess` 呼び出しに
   `CREATE_NO_WINDOW` (`0x08000000`) & `SW_HIDE` (`hidden_subprocess_kwargs`) が適用されており、
   生の `powershell` サブプロセス起動が 0件 であることの静的AST・コード検査テスト。
2. SQLite接続時の `temp_store=2 (MEMORY)`, `mmap_size=268435456`, `wal_autocheckpoint=1000`,
   `busy_timeout=5000`, `journal_size_limit=33554432` の実測検証テスト。
3. `SYSTEM_POWER_STATUS`（`ctypes.c_ubyte` 定義）による `ACLineStatus==0 & BatteryLifePercent<=40` 検知と、
   検知時の未約定注文（`ENTRY_PENDING`）緊急キャンセル＋`wal_checkpoint(TRUNCATE)` 動作テスト。
4. イベント駆動 `scheduleCancel` (Dead Man's Switch) の最小未来時刻 (`>= now + 60,000ms`) 保証、
   指値解消時のクリア、および日次バジェット保護（`8回/日` 上限）テスト。
"""

from __future__ import annotations

import ast
import ctypes
from pathlib import Path

import pytest

from src.coordinator import ConcurrencyStateCoordinator, SlotState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import ActionBudgetController, HyperliquidExchangeWrapper, SpotUniverseEntry
from src.main import HLTraderDaemon
from src.utils import (
    CREATE_NO_WINDOW_FLAG,
    SW_HIDE_FLAG,
    SYSTEM_POWER_STATUS,
    check_ups_power_critical,
    hidden_subprocess_kwargs,
    register_windows_shutdown_handlers,
    verify_target_process_identity,
)

BASE_DIR = Path(__file__).resolve().parent.parent


def test_static_zero_powershell_and_mandatory_create_no_window_in_all_subprocesses() -> None:
    """
    1. `src/`, `watchdog.py`, `scripts/` 内の全 `.py` ファイルを AST 解析し:
       - `powershell` / `powershell.exe` を起動するコードが 0件 であること
       - すべての `subprocess.run` / `Popen` / `check_output` 呼び出しに `hidden_subprocess_kwargs`
         または `creationflags` が必ず渡されていること
       - `hidden_subprocess_kwargs()` が `creationflags=0x08000000` と `wShowWindow=0` を返すこと
       - `launch_hidden.vbs` と `launch_pwa_sync_hidden.vbs` が `shell.Run cmd, 0, False` を使用していること
    """
    kw = hidden_subprocess_kwargs()
    assert kw["creationflags"] == CREATE_NO_WINDOW_FLAG == 0x08000000
    assert kw["startupinfo"].wShowWindow == SW_HIDE_FLAG == 0

    target_py_files = (
        list((BASE_DIR / "src").glob("*.py"))
        + list((BASE_DIR / "scripts").glob("*.py"))
        + [BASE_DIR / "watchdog.py"]
    )
    assert len(target_py_files) >= 10

    for py_path in target_py_files:
        src_text = py_path.read_text(encoding="utf-8")
        tree = ast.parse(src_text, filename=str(py_path))

        for node in ast.walk(tree):
            # 文字列リテラルとして "powershell" / "powershell.exe" をコマンド実行していないか検査
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val_low = node.value.strip().lower()
                assert val_low not in ("powershell", "powershell.exe", "pwsh", "pwsh.exe"), (
                    f"{py_path.name}:{getattr(node, 'lineno', 0)} に外部 PowerShell 呼び出しが残存しています"
                )

            # subprocess.run / Popen / check_output 呼び出しのキーワード引数検査
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("run", "Popen", "check_output"):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in (
                        "subprocess",
                        "_subprocess",
                        "_sp",
                    ):
                        has_creationflags = any(
                            k.arg in ("creationflags", "startupinfo") for k in node.keywords if k.arg is not None
                        )
                        has_kwargs_unpack = any(k.arg is None for k in node.keywords)
                        assert has_creationflags or has_kwargs_unpack, (
                            f"{py_path.name}:{node.lineno} の {node.func.value.id}.{node.func.attr} に "
                            "CREATE_NO_WINDOW / hidden_subprocess_kwargs が適用されていません"
                        )

    # VBS ステルスランチャー検査
    for vbs_name in ("launch_hidden.vbs", "launch_pwa_sync_hidden.vbs"):
        vbs_path = BASE_DIR / vbs_name
        assert vbs_path.exists(), f"{vbs_name} が存在しません"
        vbs_txt = vbs_path.read_text(encoding="utf-8")
        assert "shell.Run cmd, 0, False" in vbs_txt

    # インプロセス PID 検証が powershell なしで自プロセスを正しく判定できること
    import os

    assert verify_target_process_identity(
        pid=os.getpid(),
        expected_keyword="hl-ai-trader-auto",
        forbidden_keyword="gmo-ai-trader-auto",
    ) is True


def test_sqlite_high_availability_wal_pragmas_live_verification(tmp_path: Path) -> None:
    """
    2. SQLite接続初期化時に以下の高可用性PRAGMAがすべて正確に適用されていることを実測検証:
       - `journal_mode = wal`
       - `synchronous = 1 (NORMAL)`
       - `busy_timeout = 5000`
       - `temp_store = 2 (MEMORY)`
       - `mmap_size = 268435456` (256MB)
       - `wal_autocheckpoint = 1000`
       - `journal_size_limit = 33554432` (32MB)
    """
    db_file = tmp_path / "ha_pragma.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    try:
        conn = db._get_connection()
        j_mode = str(conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower()
        sync_val = int(conn.execute("PRAGMA synchronous;").fetchone()[0])
        busy_ms = int(conn.execute("PRAGMA busy_timeout;").fetchone()[0])
        temp_st = int(conn.execute("PRAGMA temp_store;").fetchone()[0])
        mmap_sz = int(conn.execute("PRAGMA mmap_size;").fetchone()[0])
        autockpt = int(conn.execute("PRAGMA wal_autocheckpoint;").fetchone()[0])
        jsize_lim = int(conn.execute("PRAGMA journal_size_limit;").fetchone()[0])

        assert j_mode == "wal"
        assert sync_val == 1  # NORMAL
        assert busy_ms == 5000
        assert temp_st == 2  # MEMORY
        assert mmap_sz == 268435456
        assert autockpt == 1000
        assert jsize_lim == 33554432
    finally:
        db.close()


def test_win32_system_power_status_c_ubyte_and_graceful_shutdown_on_ups_critical(
    tmp_path: Path,
) -> None:
    """
    3. `SYSTEM_POWER_STATUS` 構造体の先頭4フィールドが符号なし `ctypes.c_ubyte` で定義されており、
       `ACLineStatus == 0` かつ `BatteryLifePercent <= 40` (`255` を除く) のときに
       `power_critical = True` を検知し、15秒制御ループにて:
         ① 未約定注文 (`ENTRY_PENDING`) の即時緊急キャンセル (`IDLE` 復帰)
         ② SQLite `PRAGMA wal_checkpoint(TRUNCATE);` の実行
       がアトミックに完了することを検証する。
    """
    field_dict = dict(SYSTEM_POWER_STATUS._fields_)
    for fname in ("ACLineStatus", "BatteryFlag", "BatteryLifePercent", "SystemStatusFlag"):
        assert field_dict[fname] is ctypes.c_ubyte

    # 255 (Unknown) が負数 (-1) に化けず 255 として扱われること
    st_unknown = check_ups_power_critical(
        simulated_status={"ACLineStatus": 0, "BatteryLifePercent": 255}
    )
    assert st_unknown["battery_life_percent"] == 255
    assert st_unknown["power_critical"] is False

    # ACオンライン時は 30% でもクリティカルではない
    st_ac_online = check_ups_power_critical(
        simulated_status={"ACLineStatus": 1, "BatteryLifePercent": 30}
    )
    assert st_ac_online["power_critical"] is False

    # AC喪失 (0) かつ バッテリー 45% (>40%) はまだクリティカルではない
    st_batt_45 = check_ups_power_critical(
        simulated_status={"ACLineStatus": 0, "BatteryLifePercent": 45}
    )
    assert st_batt_45["power_critical"] is False

    # AC喪失 (0) かつ バッテリー 38% (<=40%) は電源クリティカル
    st_crit = check_ups_power_critical(
        simulated_status={"ACLineStatus": 0, "BatteryLifePercent": 38}
    )
    assert st_crit["power_critical"] is True

    # デーモン制御ループでの未約定注文緊急キャンセル＆WAL TRUNCATE検証
    db_file = tmp_path / "power_guard.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    ex = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
        tax_engine=tax,
    )
    ex.pair_to_entry["HYPE/USDC"] = SpotUniverseEntry(
        pair_name="HYPE/USDC",
        api_coin_name="@107",
        base_asset="HYPE",
        quote_asset="USDC",
        base_token_idx=1,
        quote_token_idx=0,
        universe_idx=0,
        spot_asset_id=10000,
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        perp_coin="HYPE",
        spot_mid_px=25.0,
        spot_mark_px=25.0,
        spot_day_ntl_vlm=5_000_000.0,
    )
    ex.api_coin_to_entry["@107"] = ex.pair_to_entry["HYPE/USDC"]
    ex.base_to_entry["HYPE"] = ex.pair_to_entry["HYPE/USDC"]

    daemon = HLTraderDaemon(
        db=db,
        coordinator=coord,
        tax_engine=tax,
        exchange_wrapper=ex,
    )

    try:
        # Slot 1 に未約定買い指値 (ENTRY_PENDING) を配置
        order_res = ex.place_spot_buy_alo(
            slot_id=1,
            coin_or_pair="HYPE/USDC",
            raw_limit_px=25.0,
            raw_sz=1.0,
            sl_px=24.2,
            tp_px=27.0,
            timestamp_ms=1761300000000,
        )
        assert order_res["status"] == "ok"
        assert db.get_slot_state(1)["state"] == SlotState.ENTRY_PENDING.value

        # 電源クリティカル (ACLineStatus=0, BatteryLifePercent=35) で15秒制御ループを実行
        tick_res = daemon.run_15s_control_tick(
            current_time_ms=1761300015000,
            simulated_power_status={"ACLineStatus": 0, "BatteryLifePercent": 35},
        )
        assert tick_res["power_status"]["power_critical"] is True
        shutdown_rep = tick_res["power_shutdown_report"]
        assert shutdown_rep is not None
        assert shutdown_rep["shutdown_executed"] is True
        assert 1 in shutdown_rep["cancelled_pending_slots"]
        assert shutdown_rep["wal_checkpoint"]["mode"] == "TRUNCATE"
        assert shutdown_rep["wal_checkpoint"]["status"] == "ok"
        assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

        # シャットダウンハンドラ登録テスト
        recorded_events = []
        assert register_windows_shutdown_handlers(lambda ev: recorded_events.append(ev)) is True
    finally:
        db.close()


def test_event_driven_schedule_cancel_deadman_and_daily_budget_cap(tmp_path: Path) -> None:
    """
    4. イベント駆動型 `scheduleCancel` (Dead Man's Switch) の検証:
       - `BUY_ALO` / `SELL_ALO` 発注直後に `cancel_time_ms >= now_ms() + 60,000` で自動予約されること
       - 未約定スロットが無くなった際に `clear_deadman_if_no_pending_orders` で予約解除 (`None`) できること
       - 1日の呼び出し上限 (`8回/日`, `ActionBudgetController.MAX_SCHEDULE_CANCEL_DAILY == 8`) に到達した後は
         `DAILY_SCHEDULE_CANCEL_LIMIT_REACHED` で安全にスキップされ、レートリミット枠を枯渇させないこと
    """
    db_file = tmp_path / "deadman.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    coord = ConcurrencyStateCoordinator(db=db)
    ex = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db,
        coordinator=coord,
    )
    ex.pair_to_entry["HYPE/USDC"] = SpotUniverseEntry(
        pair_name="HYPE/USDC",
        api_coin_name="@107",
        base_asset="HYPE",
        quote_asset="USDC",
        base_token_idx=1,
        quote_token_idx=0,
        universe_idx=0,
        spot_asset_id=10000,
        sz_decimals=2,
        wei_decimals=8,
        is_canonical=True,
        perp_coin="HYPE",
        spot_mid_px=25.0,
        spot_mark_px=25.0,
        spot_day_ntl_vlm=5_000_000.0,
    )

    try:
        base_ts = 1761300000000
        assert ActionBudgetController.MAX_SCHEDULE_CANCEL_DAILY == 8

        # 1回目: BUY_ALO 発注により自動的に Dead Man's Switch が予約される
        buy_res = ex.place_spot_buy_alo(
            slot_id=1,
            coin_or_pair="HYPE/USDC",
            raw_limit_px=25.0,
            raw_sz=1.0,
            sl_px=24.2,
            tp_px=27.0,
            timestamp_ms=base_ts,
        )
        assert buy_res["deadman"]["scheduled"] is True
        assert buy_res["deadman"]["cancel_time_ms"] >= base_ts + 60_000
        assert buy_res["deadman"]["daily_calls"] == 1

        # 2回目: 全未約定指値が解消された際のクリア (cancel_time_ms=None)
        clear_res = ex.clear_deadman_if_no_pending_orders(
            has_other_pending_orders=False,
            current_time_ms=base_ts + 5_000,
        )
        assert clear_res["cleared"] is True
        assert clear_res["active_deadman_cancel_time_ms"] is None
        assert ex._schedule_cancel_daily_count == 2

        # 3〜8回目まで呼び出し (最小オフセット 60,000ms クランプも同時検証)
        for expected_call_num in range(3, 9):
            res = ex.schedule_cancel_deadman(
                cancel_time_ms=base_ts + 10_000,  # 60,000ms 未満 -> 自動で base_ts + 60,000 に引き上げ
                current_time_ms=base_ts,
            )
            assert res["scheduled"] is True
            assert res["cancel_time_ms"] == base_ts + 60_000
            assert res["daily_calls"] == expected_call_num

        # 9回目: 日次上限 (8回/日) 到達によりブロックされること
        res_9th = ex.schedule_cancel_deadman(
            cancel_time_ms=base_ts + 120_000,
            current_time_ms=base_ts,
        )
        assert res_9th["scheduled"] is False
        assert res_9th["reason"] == "DAILY_SCHEDULE_CANCEL_LIMIT_REACHED"
        assert res_9th["daily_calls"] == 8
    finally:
        db.close()
