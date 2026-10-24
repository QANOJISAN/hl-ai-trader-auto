"""
HL AI Trader v1 — Phase 6 Comprehensive Audit Round 2 Deep Edge-Case & State Transition Test Suite
(tests/test_phase6_audit_round2.py)

重点検証項目 (Audit Round 2 全5領域):
1. 初期USDC在庫 (`143.73 USDC`) の取得単価ブートストラップ監査 (`bootstrap_initial_usdc_inventory` ＆ `_ensure_inventory_row_in_tx` ゼロ簿価修復ガードによる架空為替差益の100%防止)
2. シンボル表記揺れ監査 (`@107` ⇄ `HYPE/USDC` ⇄ `HYPE` の全6経路双方向正規化・3者照合 `reconcile_3way_state`)
3. `ENTRY_PENDING` キャンセル時の Partial Fill (一部約定) 引き継ぎ (`>= 10.0 USDC` ➔ `OPEN_PROTECTED` 昇格・`< 10.0 USDC` ➔ `IDLE` ＆ `Top-Up & Dump` 端数回収)
4. ポジション決済時 (SL / TP / Perp清算カスケード / 緊急全決済 / WS売り約定) の事後パイプライン5処理一括連動 (`tax_lots` べき等記録 + `ai_reflection_memory` 蒸留 + `consecutive_losses` 更新 + Slot 2 事後リスクバジェット再計算 + `IDLE` 解放)
5. Web UI / フロントエンドJS (`web/static/app.js`, `docs/index.html`) プロパティ整合性と `public_snapshot.json` 機密情報完全スクラブ監査
"""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict

import pytest

from src.ai_brain import DebiasedAIBrain
from src.coordinator import ConcurrencyStateCoordinator, SlotState, SlotSubState
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HyperliquidExchangeWrapper
from src.main import HLTraderDaemon
from src.web_server import DashboardStateService, decrypt_snapshot_container, scrub_sensitive_data
from tests.test_phase1_phase2 import MockHLExchange, MockHLInfo


# ==============================================================================
# 1. Initial USDC Inventory (143.73 USDC) Cost-Basis Bootstrap Audit
# ==============================================================================
def test_audit_r2_1_initial_usdc_inventory_bootstrap_prevents_phantom_fx_gain(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r2_tax_bootstrap.db", initial_equity_usdc=143.73)
    tax = HyperliquidTaxEngine(db=db)

    # Case A: 明示的な bootstrap_initial_usdc_inventory 呼び出しで 143.73 USDC が初期レート (158.0 JPY) でシードされること
    boot_res = tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total="143.73",
        usdc_jpy_rate="158.0",
        timestamp_ms=1_775_000_000_000,
    )
    assert boot_res["bootstrapped"] is True
    assert boot_res["reason"] == "INITIAL_SEED"
    assert boot_res["quantity"] == pytest.approx(143.73)
    assert boot_res["moving_avg_unit_jpy"] == pytest.approx(158.0)

    # 2回目の同一残高呼び出しは ALREADY_SEEDED でべき等にスキップされること
    boot_res2 = tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total="143.73",
        usdc_jpy_rate="159.0",
        timestamp_ms=1_775_000_015_000,
    )
    assert boot_res2["bootstrapped"] is False
    assert boot_res2["reason"] == "ALREADY_SEEDED"
    assert boot_res2["moving_avg_unit_jpy"] == pytest.approx(158.0)

    # 最初の SPOT_BUY (2.0 HYPE @ 25.00 USDC = 50.00 USDC, 同レート 158.0 JPY) を実行した際、
    # 手放した 50.00 USDC の譲渡原価 (disposed_cogs_jpy) が 50 * 158 = 7,900 JPY となり、
    # 架空の為替差益 (realized_pnl_jpy) が 0円 になること!
    buy_res = tax.process_spot_fill(
        hl_tid=800001,
        hl_oid=9001,
        timestamp_ms=1_775_000_020_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="2.00",
        raw_fee_amount="0.0007",
        raw_fee_token="HYPE",
        usdc_jpy_rate_override=158.0,
    )
    assert buy_res["inserted"] is True
    assert buy_res["disposed_cogs_jpy"] == pytest.approx(50.0 * 158.0)
    assert buy_res["realized_pnl_jpy"] == pytest.approx(0.0, abs=1e-4)

    # Case B: 万一 bootstrap 呼び出し前に未シードDBで直接 process_spot_fill が呼ばれた場合でも、
    # _ensure_inventory_row_in_tx のフォールバックにより disposed_cogs_jpy が 0円 にならないこと
    db_unseeded = DatabaseManager(db_path=tmp_path / "r2_unseeded.db", initial_equity_usdc=143.73)
    tax_unseeded = HyperliquidTaxEngine(db=db_unseeded)
    buy_unseeded = tax_unseeded.process_spot_fill(
        hl_tid=800002,
        hl_oid=9002,
        timestamp_ms=1_775_000_030_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="2.00",
        raw_fee_amount="0.0007",
        raw_fee_token="HYPE",
        usdc_jpy_rate_override=156.0,
    )
    assert buy_unseeded["disposed_unit_cost_jpy"] == pytest.approx(156.0)
    assert buy_unseeded["disposed_cogs_jpy"] == pytest.approx(50.0 * 156.0)
    assert buy_unseeded["realized_pnl_jpy"] == pytest.approx(0.0, abs=1e-4)

    db.close()
    db_unseeded.close()


# ==============================================================================
# 2. Symbol Representation Normalization (@107 <-> HYPE/USDC <-> HYPE) & 3-Way Reconciliation
# ==============================================================================
def test_audit_r2_2_symbol_normalization_across_all_6_paths(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r2_symbols.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=MockHLInfo("0x0"),
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    mock_ex = MockHLExchange(mock_info)
    wrapper.info = mock_info
    wrapper.exchange = mock_ex
    wrapper.refresh_universe_mapping()

    daemon = HLTraderDaemon(db=db, coordinator=coord, tax_engine=tax, exchange_wrapper=wrapper)

    # 1) normalize_spot_symbol & are_symbols_equivalent の双方向検証
    assert wrapper.normalize_spot_symbol("@107") == ("HYPE/USDC", "@107", "HYPE")
    assert wrapper.normalize_spot_symbol("HYPE/USDC") == ("HYPE/USDC", "@107", "HYPE")
    assert wrapper.normalize_spot_symbol("HYPE") == ("HYPE/USDC", "@107", "HYPE")
    assert wrapper.are_symbols_equivalent("@107", "HYPE/USDC") is True
    assert wrapper.are_symbols_equivalent("HYPE", "@107") is True
    assert wrapper.are_symbols_equivalent("UBTC/USDC", "@142") is True
    assert wrapper.are_symbols_equivalent("UBTC", "@142") is True
    assert wrapper.are_symbols_equivalent("@107", "@142") is False

    # 2) WS l2Book に "@107" で届いた板データが "HYPE/USDC", "@107", "HYPE" のいずれでも参照できること
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": 1_775_100_000_000,
                "levels": [[{"px": "25.10", "sz": "50.0", "n": 2}], [{"px": "25.12", "sz": "50.0", "n": 2}]],
            },
        }
    )
    for query_sym in ("@107", "HYPE/USDC", "HYPE"):
        bbo = daemon.ws.get_bbo(query_sym)
        assert bbo is not None
        assert bbo["best_bid"] == pytest.approx(25.10)

    # 3) 15秒ループの3者照合 (reconcile_3way_state):
    # slot_state_store.coin が "HYPE/USDC" で、open_orders の coin が "@107" の場合に MATCHED_OPEN_ORDER となること
    order_res = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="1.00",
        sl_px="24.20",
        tp_px="27.50",
        timestamp_ms=1_775_100_005_000,
    )
    spot_bals = wrapper.get_spot_balances()
    rec_matched = daemon.reconcile_3way_state(
        spot_balances=spot_bals,
        open_orders=[{"coin": "@107", "oid": order_res["oid"], "sz": "1.00", "limitPx": "25.00"}],
        current_time_ms=1_775_100_010_000,
    )
    assert rec_matched["slots"][1]["status"] == "MATCHED_OPEN_ORDER"
    assert rec_matched["slots"][1]["matched_oid"] == order_res["oid"]

    # 4) WS通知遅延中に注文が約定して open_orders から消え、Spot 残高が +1.00 HYPE (25 USDC >= 10 USDC) 純増していた場合、
    #    reconcile_3way_state が ENTRY_PENDING -> OPEN_PROTECTED へ自動昇格し、sl_px/tp_px を保持すること
    spot_bals["HYPE"]["total"] += Decimal("1.00")
    spot_bals["HYPE"]["free"] += Decimal("1.00")
    rec_promoted = daemon.reconcile_3way_state(
        spot_balances=spot_bals,
        open_orders=[],
        current_time_ms=1_775_100_015_000,
    )
    assert rec_promoted["slots"][1]["status"] == "PROMOTED_FILLED_TO_OPEN_PROTECTED"
    s1_state = db.get_slot_state(1)
    assert s1_state["state"] == SlotState.OPEN_PROTECTED.value
    assert float(s1_state["sl_px"]) == pytest.approx(24.20)
    assert float(s1_state["tp_px"]) == pytest.approx(27.50)
    db.close()


# ==============================================================================
# 3. Partial Fill Handling on ENTRY_PENDING Cancellation (>= 10 USDC vs < 10 USDC Dust)
# ==============================================================================
def test_audit_r2_3_partial_fill_handling_on_entry_pending_cancellation(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r2_partial.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=MockHLInfo("0x0"),
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    mock_ex = MockHLExchange(mock_info)
    wrapper.info = mock_info
    wrapper.exchange = mock_ex
    wrapper.refresh_universe_mapping()

    # Sub-case A: >= 10.0 USDC の部分約定 (0.60 HYPE @ 25.00 = 15.00 USDC) 発生後のキャンセル (4h失効等)
    # -> IDLE に戻さず OPEN_PROTECTED (INITIAL_RISK, sl_px=24.10, tp_px=27.20 引き継ぎ) へ遷移すること!
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "143.73", "hold": "25.0"},
        {"coin": "HYPE", "total": "0.0", "hold": "0.0"},
    ]
    ord_a = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="1.00",
        sl_px="24.10",
        tp_px="27.20",
        timestamp_ms=1_775_200_000_000,
    )
    # キャンセル前に 0.60 HYPE (15.00 USDC >= 10.0 USDC) が部分約定したとシミュレート
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "128.73", "hold": "10.0"},
        {"coin": "HYPE", "total": "0.60", "hold": "0.0"},
    ]
    cancel_a = wrapper.cancel_spot_order(
        coin_or_pair="HYPE/USDC",
        oid=ord_a["oid"],
        slot_id=1,
    )
    assert cancel_a["post_cancel_state"] == SlotState.OPEN_PROTECTED.value
    assert cancel_a["partial_fill_qty"] == pytest.approx(0.60)
    assert cancel_a["partial_fill_usdc"] == pytest.approx(15.00)

    s1_after_a = db.get_slot_state(1)
    assert s1_after_a["state"] == SlotState.OPEN_PROTECTED.value
    assert s1_after_a["sub_state"] == SlotSubState.INITIAL_RISK.value
    assert float(s1_after_a["current_sz"]) == pytest.approx(0.60)
    assert float(s1_after_a["sl_px"]) == pytest.approx(24.10)
    assert float(s1_after_a["tp_px"]) == pytest.approx(27.20)

    # Slot 1 を一旦 IDLE へリセットして Sub-case B を検証
    coord.reset_slot_to_idle(1)

    # Sub-case B: 0 < 評価額 < 10.0 USDC の端数部分約定 (0.20 HYPE @ 25.00 = 5.00 USDC) 発生後のキャンセル
    # -> スロットを IDLE に戻し、dust_quarantine 登録 ＆ Top-Up & Dump 自己復旧が即実行されること!
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "143.73", "hold": "25.0"},
        {"coin": "HYPE", "total": "0.0", "hold": "0.0"},
    ]
    ord_b = wrapper.place_spot_buy_alo(
        slot_id=1,
        coin_or_pair="HYPE/USDC",
        raw_limit_px="25.00",
        raw_sz="1.00",
        sl_px="24.10",
        tp_px="27.20",
        timestamp_ms=1_775_200_100_000,
    )
    # キャンセル前に 0.20 HYPE (5.00 USDC < 10.0 USDC) が部分約定したとシミュレート
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "138.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "0.20", "hold": "0.0"},
    ]
    cancel_b = wrapper.cancel_spot_order(
        coin_or_pair="HYPE/USDC",
        oid=ord_b["oid"],
        slot_id=1,
    )
    assert cancel_b["post_cancel_state"] == "IDLE_DUST_RECOVERED"
    assert cancel_b["dust_recovery_result"] is not None
    assert cancel_b["dust_recovery_result"]["recovered"] is True
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value
    assert db.get_dust_quarantine("HYPE")["status"] == "RECOVERED"
    db.close()


# ==============================================================================
# 4. Complete Post-Exit Pipeline (5 Side Effects: Tax + Reflection + Losses + Budget + IDLE)
# ==============================================================================
def test_audit_r2_4_complete_post_exit_pipeline_all_5_side_effects(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r2_post_exit.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    tax.bootstrap_initial_usdc_inventory("143.73", "158.0", timestamp_ms=1_775_300_000_000)

    wrapper = HyperliquidExchangeWrapper(
        main_address="0x1234567890123456789012345678901234567890",
        agent_private_key="0x" + "44" * 32,
        execution_mode="LIVE",
        db=db,
        coordinator=coord,
        tax_engine=tax,
        info_client=MockHLInfo("0x0"),
    )
    mock_info = MockHLInfo(wrapper.agent_address)
    mock_ex = MockHLExchange(mock_info)
    wrapper.info = mock_info
    wrapper.exchange = mock_ex
    wrapper.refresh_universe_mapping()

    daemon = HLTraderDaemon(db=db, coordinator=coord, tax_engine=tax, exchange_wrapper=wrapper)

    # 事前に HYPE の買いロットを計上しておく
    tax.process_spot_fill(
        hl_tid=810001,
        hl_oid=9101,
        timestamp_ms=1_775_300_001_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc="25.00",
        exec_sz_base="2.00",
        raw_fee_amount="0.0",
        raw_fee_token="HYPE",
        usdc_jpy_rate_override=158.0,
    )
    mock_info.spot_balances = [
        {"coin": "USDC", "total": "93.73", "hold": "0.0"},
        {"coin": "HYPE", "total": "2.00", "hold": "0.0"},
        {"coin": "USOL", "total": "0.20", "hold": "0.0"},
    ]

    # Slot 1 (HYPE/USDC @ 25.00, SL=24.40, sz=2.00) と Slot 2 (USOL/USDC @ 180.00, SL=170.00, sz=0.20) を OPEN_PROTECTED にセット
    i1 = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        entry_px=25.00,
        sz=2.00,
        sl_px=24.40,
        tp_px=27.50,
        episode_id="ep_slot1_loss_test",
        timestamp_ms=1_775_300_002_000,
    )
    coord.bind_order_response(slot_id=1, cloid=i1["cloid"], oid=9101, filled=True, filled_sz=2.00, avg_px=25.00)

    i2 = coord.begin_order_intent(
        slot_id=2,
        target_state=SlotState.ENTRY_PENDING,
        coin="USOL/USDC",
        base_asset="USOL",
        sz_decimals=2,
        entry_px=180.00,
        sz=0.20,
        sl_px=170.00,
        tp_px=195.00,
        episode_id="ep_slot2_active_test",
        timestamp_ms=1_775_300_003_000,
    )
    coord.bind_order_response(slot_id=2, cloid=i2["cloid"], oid=9102, filled=True, filled_sz=0.20, avg_px=180.00)

    # 1. Slot 1 が SL 着弾 (Best Bid = 24.30 <= SL 24.40, 損失 D_1 = (25.00 - 24.30) * 2.0 = 1.40 USDC)
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@107",
                "time": 1_775_300_050_000,
                "levels": [[{"px": "24.30", "sz": "100.0", "n": 2}], [{"px": "24.32", "sz": "100.0", "n": 2}]],
            },
        }
    )
    g_out = daemon.run_200ms_guardian_tick(current_time_ms=1_775_300_050_100)

    # 検証 (1): tax_lots に SPOT_SELL が計上されていること (買い1件 + 売り1件 = 2件)
    conn = db._get_connection()
    sell_lots = conn.execute("SELECT * FROM tax_lots WHERE event_type = 'SPOT_SELL'").fetchall()
    assert len(sell_lots) == 1
    sell_oid = sell_lots[0]["hl_oid"]

    # もし直後に同一 hl_oid の WS userFills 売り通知が到着しても重複計上されないこと!
    daemon.ws.handle_raw_message(
        {
            "channel": "userFills",
            "data": {
                "fills": [
                    {
                        "coin": "@107",
                        "px": "24.30",
                        "sz": "2.00",
                        "side": "A",
                        "time": 1_775_300_050_200,
                        "fee": "0.034",
                        "feeToken": "USDC",
                        "tid": 810099,
                        "oid": sell_oid,
                    }
                ]
            },
        }
    )
    sell_lots_after_ws = conn.execute("SELECT * FROM tax_lots WHERE event_type = 'SPOT_SELL'").fetchall()
    assert len(sell_lots_after_ws) == 1

    # 検証 (2): ai_reflection_memory に教訓が蒸留・保存されていること
    ref_rows = conn.execute(
        "SELECT * FROM ai_reflection_memory WHERE episode_id = 'ep_slot1_loss_test'"
    ).fetchall()
    assert len(ref_rows) == 1
    assert "LOSS_STOP_LOSS_HIT" in str(ref_rows[0]["failure_taxonomy"])

    # 検証 (3): system_state_store.consecutive_losses が +1 (1連敗) に更新されていること
    sys_st = db.get_system_state()
    assert int(sys_st["consecutive_losses"]) == 1
    assert int(sys_st["daily_trade_count"]) >= 1

    # 検証 (4): Slot 2 の SL が事後リスクバジェット再計算により 170.00 から引き上げられていること
    assert any(a["action"] == "POST_LOSS_TIGHTEN_SLOT2_SL" for a in g_out["actions"])
    s2_after = db.get_slot_state(2)
    assert float(s2_after["sl_px"]) > 170.00

    # 検証 (5): Slot 1 が IDLE にリセットされていること
    assert db.get_slot_state(1)["state"] == SlotState.IDLE.value

    # さらに Slot 2 が TP 到達 (Best Bid = 196.00 >= TP 195.00) で利確された場合、consecutive_losses が 0 にリセットされること!
    daemon.ws.handle_raw_message(
        {
            "channel": "l2Book",
            "data": {
                "coin": "@156",
                "time": 1_775_300_100_000,
                "levels": [[{"px": "196.00", "sz": "50.0", "n": 2}], [{"px": "196.10", "sz": "50.0", "n": 2}]],
            },
        }
    )
    daemon.run_200ms_guardian_tick(current_time_ms=1_775_300_100_100)
    assert db.get_slot_state(2)["state"] == SlotState.IDLE.value
    assert int(db.get_system_state()["consecutive_losses"]) == 0
    db.close()


# ==============================================================================
# 5. Web UI / Frontend JS Alignment & Public Snapshot Secret Scrubbing Audit
# ==============================================================================
def test_audit_r2_5_web_ui_js_alignment_and_public_snapshot_secret_scrubbing(tmp_path: Path) -> None:
    db = DatabaseManager(db_path=tmp_path / "r2_web_sec.db", initial_equity_usdc=143.73)
    coord = ConcurrencyStateCoordinator(db=db)
    tax = HyperliquidTaxEngine(db=db)
    service = DashboardStateService(db=db, tax_engine=tax, coordinator=coord)

    # Slot 1 に cloid (0x...) 付きポジションをセット
    intent = coord.begin_order_intent(
        slot_id=1,
        target_state=SlotState.ENTRY_PENDING,
        coin="HYPE/USDC",
        base_asset="HYPE",
        sz_decimals=2,
        cloid="0xabcdef1234567890abcdef1234567890",
        entry_px=41.50,
        sz=1.50,
        sl_px=40.10,
        tp_px=44.80,
    )
    coord.bind_order_response(
        slot_id=1,
        cloid=intent["cloid"],
        oid=77701,
        filled=True,
        filled_sz=1.50,
        avg_px=41.50,
    )

    # 1. export_public_snapshot の出力に cloid / oid / 0xアドレス / 秘密鍵が一切含まれないこと
    snap_path = service.export_public_snapshot(output_path=tmp_path / "public_snapshot.json")
    snap_raw = snap_path.read_text(encoding="utf-8")
    snap_json = json.loads(snap_raw)

    assert "0xabcdef1234567890abcdef1234567890" not in snap_raw
    assert "active_cloid" not in snap_raw
    assert "active_oid" not in snap_raw
    assert "private_key" not in snap_raw.lower()

    # 2. scrub_sensitive_data 関数に意図的に秘密鍵・ウォレットアドレス・Gemini APIキー・Discord Webhookを混入させて完全除去を検証
    dirty_payload: Dict[str, Any] = {
        "system_name": "HL AI Trader v1",
        "agent_private_key": "0x" + "99" * 32,
        "main_address": "0xa226258389cf6ff2e3ddb92fc072f8b85fc48777",
        "nested": {
            "discord_webhook_url": "https://discord.com/api/webhooks/123456789/secretTokenXYZ",
            "note": "Wallet 0xa226258389cf6ff2e3ddb92fc072f8b85fc48777 with key AIzaSyB1234567890abcdefghijklmnop and hook https://discord.com/api/webhooks/999/abc",
        },
    }
    cleaned = scrub_sensitive_data(dirty_payload)
    cleaned_str = json.dumps(cleaned)
    assert "agent_private_key" not in cleaned_str
    assert "main_address" not in cleaned_str
    assert "discord_webhook_url" not in cleaned_str
    assert "0xa226258389cf6ff2e3ddb92fc072f8b85fc48777" not in cleaned_str
    assert "AIzaSyB1234567890abcdefghijklmnop" not in cleaned_str
    assert "https://discord.com/api/webhooks" not in cleaned_str

    # 3. 暗号化コンテナを復号し、フロントエンドファイル (docs/index.html, web/static/app.js) と JSON プロパティ名の整合確認
    assert snap_json["encrypted"] is True
    assert snap_json["cipher"] == "AES-256-GCM"
    assert snap_json["kdf"] == "PBKDF2-SHA256"
    assert snap_json["iterations"] == 150000
    decrypted_snap = decrypt_snapshot_container(snap_json)
    assert "0xabcdef1234567890abcdef1234567890" not in json.dumps(decrypted_snap)
    assert "active_cloid" not in json.dumps(decrypted_snap)
    assert "active_oid" not in json.dumps(decrypted_snap)
    assert decrypted_snap["status_badge"] in ("RUNNING", "PAUSED", "HALTED")
    assert "current_usdc" in decrypted_snap["equity"]
    assert "current_jpy" in decrypted_snap["equity"]
    assert "hwm_usdc" in decrypted_snap["equity"]
    assert "l5_floor_usdc" in decrypted_snap["equity"]
    assert "moving_average_pnl_jpy_int" in decrypted_snap["tax_summary"]
    assert "total_average_pnl_jpy_int" in decrypted_snap["tax_summary"]
    assert len(decrypted_snap["default_chart"]["horizontal_lines"]) == 3
    db.close()
