"""
HL AI Trader v1.2 Alpha-Max — Post-Mortem Quant & Tax Forensic Audit Tool Unit Tests
(`tests/test_postmortem_audit_tool.py`)

検証項目:
1. Case A: ダマシ遮断成功 (False-Signal Blocking -> `HEALTHY`, OR_gate > 1, P(theta_live > theta_shadow) > 0.99, 90% HDI > 0)
2. Case B: Timid Miss 検知 (Over-Filtering -> `ALERT: TIMID_MISS`, Regret_R > 0.5, P(theta_live > theta_shadow) < 0.05)
3. 診断2: MFE捕捉効率 `CR_MFE` (`MFE_R=0` の NULL 除外)、利益吐き出し `GB_R`、MAE消化率 `UR_MAE`、`+0.5R` 逆転負け率
4. 診断3 & 診断4: Maker比率 `rho_maker`、ActionBudget残量、日本円税務台帳5大不変条件、
   在庫ゼロ通貨における移動平均法と総平均法の損益一致 (誤差 <= ±1円)、CSVエクスポート、および `PRAGMA query_only = ON` 厳格検証
"""

from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

import pytest

from scripts.run_quant_postmortem_audit import (
    format_postmortem_audit_report,
    open_readonly_sqlite,
    run_diagnostic_1_bayesian_gate_audit,
    run_diagnostic_2_mfe_capture_audit,
    run_diagnostic_3_fee_and_maker_audit,
    run_diagnostic_4_tax_forensic_audit,
    run_full_postmortem_audit,
)
from src.ai_brain import DebiasedAIBrain
from src.db import DatabaseManager, HyperliquidTaxEngine


def test_case_a_false_signal_blocking_healthy_and_readonly_guard(tmp_path: Path) -> None:
    """
    Case A: 実戦トレードが高勝率 (W_live=16, L_live=4) で、見送り群の大多数が SL_FIRST (W_shadow=20, L_shadow=80) の場合、
    - Haldane-Anscombe OR_gate > 10.0
    - 片側 Fisher's Exact p < 0.0001
    - ベイズ事後優越確率 P(theta_live > theta_shadow | D) > 0.999
    - 90% HDI の下限 > +0.35
    - 診断ステータスが `HEALTHY` となること
    - また `open_readonly_sqlite` が `PRAGMA query_only = 1` を強制し、書き込み操作を拒否すること
    """
    db_file = tmp_path / "case_a.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    brain = DebiasedAIBrain(db=db, use_live_llm=False)

    # 実戦決済済みトレード: 16勝 4敗
    for i in range(16):
        brain.record_reflection_on_close(
            episode_id=f"ep_win_{i}",
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="STAGE_4_TRAIL",
            entry_px=20.0,
            exit_px=21.2,
            initial_sl_px=19.6,
            holding_duration_sec=1800,
            mfe_pct=3.5,
            mae_pct=0.4,
        )
    for i in range(4):
        brain.record_reflection_on_close(
            episode_id=f"ep_loss_{i}",
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="INITIAL_SL",
            entry_px=20.0,
            exit_px=19.6,
            initial_sl_px=19.6,
            holding_duration_sec=600,
            mfe_pct=0.3,
            mae_pct=2.0,
        )

    # 見送り追跡完了トレード: 20件 TP_FIRST, 80件 SL_FIRST (ダマシ遮断成功)
    for i in range(20):
        sh_id = brain.register_shadow_skip(
            coin="PURR/USDC",
            market_regime_4h="RANGE_CHOP",
            skip_stage="AI_GATE",
            skip_reason_code="SAI_BULL_TRAP_PENALTY",
            spot_mid_at_eval=10.0,
            hypothetical_sl_px=9.8,
            hypothetical_tp_px=10.3,
            ai_conviction_score=71,
        )
        brain.complete_shadow_evaluation(
            shadow_id=sh_id,
            px_after_1h=10.1,
            px_after_4h=10.2,
            px_after_24h=10.35,
            max_high_24h=10.4,
            min_low_24h=9.9,
            first_hit_type="TP_FIRST",
            first_hit_ts_ms=1700003600000,
        )

    for i in range(80):
        sh_id = brain.register_shadow_skip(
            coin="PURR/USDC",
            market_regime_4h="RANGE_CHOP",
            skip_stage="AI_GATE",
            skip_reason_code="FALSIFICATION_GATE_REJECTED",
            spot_mid_at_eval=10.0,
            hypothetical_sl_px=9.8,
            hypothetical_tp_px=10.3,
            ai_conviction_score=65,
        )
        brain.complete_shadow_evaluation(
            shadow_id=sh_id,
            px_after_1h=9.9,
            px_after_4h=9.75,
            px_after_24h=9.6,
            max_high_24h=10.05,
            min_low_24h=9.5,
            first_hit_type="SL_FIRST",
            first_hit_ts_ms=1700001800000,
        )

    conn = open_readonly_sqlite(db_file)
    try:
        # 読み取り専用ロックの検証
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM ai_reflection_memory;")

        d1 = run_diagnostic_1_bayesian_gate_audit(conn, mc_samples=50_000)
        assert d1["w_live"] == 16
        assert d1["l_live"] == 4
        assert d1["w_shadow"] == 20
        assert d1["l_shadow"] == 80
        assert d1["or_gate_haldane"] > 10.0
        assert d1["fisher_exact_p_one_sided"] < 0.0001
        assert d1["posterior_prob_live_gt_shadow"] > 0.999
        assert d1["hdi_90"][0] > 0.35
        assert d1["status"] == "HEALTHY"
    finally:
        conn.close()
        db.close()


def test_case_b_timid_miss_detection_and_boundary_regret(tmp_path: Path) -> None:
    """
    Case B: 実戦トレードが低迷 (W_live=2, L_live=6) する一方、
    `SSII_BOUNDARY` や `WEEKEND_THIN` で見送った候補が相次いで TP_FIRST (W_shadow=18, L_shadow=4) に到達した場合、
    - P(theta_live > theta_shadow | D) < 0.05
    - 境界バケットの期待R後悔 `Regret_R` > 1.0R
    - 診断ステータスが `ALERT: TIMID_MISS` となること
    """
    db_file = tmp_path / "case_b.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    brain = DebiasedAIBrain(db=db, use_live_llm=False)

    for i in range(2):
        brain.record_reflection_on_close(
            episode_id=f"ep_b_win_{i}",
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="STAGE_3_TRAIL",
            entry_px=20.0,
            exit_px=20.6,
            initial_sl_px=19.6,
            holding_duration_sec=1200,
            mfe_pct=2.0,
            mae_pct=0.5,
        )
    for i in range(6):
        brain.record_reflection_on_close(
            episode_id=f"ep_b_loss_{i}",
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="INITIAL_SL",
            entry_px=20.0,
            exit_px=19.6,
            initial_sl_px=19.6,
            holding_duration_sec=900,
            mfe_pct=0.2,
            mae_pct=2.0,
        )

    for i in range(18):
        sh_id = brain.register_shadow_skip(
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            skip_stage="RADAR_GATE",
            skip_reason_code="SSII_BELOW_THRESHOLD",
            spot_mid_at_eval=20.0,
            hypothetical_sl_px=19.6,
            hypothetical_tp_px=20.8,
            ai_conviction_score=76,
        )
        brain.complete_shadow_evaluation(
            shadow_id=sh_id,
            px_after_1h=20.4,
            px_after_4h=20.9,
            px_after_24h=21.0,
            max_high_24h=21.2,
            min_low_24h=19.9,
            first_hit_type="TP_FIRST",
            first_hit_ts_ms=1700003600000,
        )

    for i in range(4):
        sh_id = brain.register_shadow_skip(
            coin="HYPE/USDC",
            market_regime_4h="BULL_EXPANSION",
            skip_stage="RADAR_GATE",
            skip_reason_code="SSII_BELOW_THRESHOLD",
            spot_mid_at_eval=20.0,
            hypothetical_sl_px=19.6,
            hypothetical_tp_px=20.8,
            ai_conviction_score=74,
        )
        brain.complete_shadow_evaluation(
            shadow_id=sh_id,
            px_after_1h=19.8,
            px_after_4h=19.5,
            px_after_24h=19.4,
            max_high_24h=20.1,
            min_low_24h=19.3,
            first_hit_type="SL_FIRST",
            first_hit_ts_ms=1700001800000,
        )

    conn = open_readonly_sqlite(db_file)
    try:
        d1 = run_diagnostic_1_bayesian_gate_audit(conn, mc_samples=50_000)
        assert d1["status"] == "ALERT: TIMID_MISS"
        assert d1["posterior_prob_live_gt_shadow"] < 0.05
        assert d1["hdi_90"][1] < 0.0
        assert d1["boundary_buckets"]["SSII_BOUNDARY"]["regret_r"] > 1.0
        assert d1["worst_regret_bucket"] == "SSII_BOUNDARY"
    finally:
        conn.close()
        db.close()


def test_diagnostic_2_mfe_capture_efficiency_null_exclusion_and_giveback(tmp_path: Path) -> None:
    """
    診断2:
    - MFE_R = 0 の勝ちトレードがゼロ除算を起こさず NULL (`None`) として除外されること
    - MFE捕捉効率 `CR_MFE = R_realized / MFE_R`、利益吐き出し `GB_R = MFE_R - R_realized`、
      負けトレードの MAE消化率 `UR_MAE = |R_realized| / MAE_R` が正確に算出されること
    - 含み益 `+0.5R` 以上からの逆転負けが多発した場合に `PROFIT_GIVEBACK` と診断されること
    """
    db_file = tmp_path / "diag2.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=150.0)
    brain = DebiasedAIBrain(db=db, use_live_llm=False)

    # Trade 1: 勝ち (+1.0R), 1R=2.0% (entry=100, sl=98), MFE=4.0% (+2.0R) -> CR_MFE = 0.50, GB_R = 1.0R
    brain.record_reflection_on_close(
        episode_id="ep_mfe_1",
        coin="HYPE/USDC",
        market_regime_4h="BULL_EXPANSION",
        exit_reason="STAGE_3_TRAIL",
        entry_px=100.0,
        exit_px=102.0,
        initial_sl_px=98.0,
        holding_duration_sec=1800,
        mfe_pct=4.0,
        mae_pct=0.5,
    )

    # Trade 2: 勝ち (+0.5R), ただし MFE=0.0% (MFE_R=0 -> NULL除外検証)
    brain.record_reflection_on_close(
        episode_id="ep_mfe_zero",
        coin="HYPE/USDC",
        market_regime_4h="BULL_EXPANSION",
        exit_reason="SCRATCH_GAIN",
        entry_px=100.0,
        exit_px=101.0,
        initial_sl_px=98.0,
        holding_duration_sec=600,
        mfe_pct=0.0,
        mae_pct=0.0,
    )

    # Trade 3 & 4: 含み益 +0.8R (MFE=1.6%) に到達した後、-1.0R (exit=98.0, MAE=2.0%) の逆転負け
    for idx in (3, 4):
        brain.record_reflection_on_close(
            episode_id=f"ep_rev_{idx}",
            coin="PURR/USDC",
            market_regime_4h="BULL_EXPANSION",
            exit_reason="TIME_DECAY_SL",
            entry_px=100.0,
            exit_px=98.0,
            initial_sl_px=98.0,
            holding_duration_sec=2400,
            mfe_pct=1.6,
            mae_pct=2.0,
        )

    conn = open_readonly_sqlite(db_file)
    try:
        d2 = run_diagnostic_2_mfe_capture_audit(conn)
        assert d2["total_closed_trades"] == 4
        assert d2["win_trades"] == 2
        assert d2["loss_trades"] == 2
        # MFE_R=0 の勝ちトレードは除外されるため cr_mfe_valid_count == 1
        assert d2["cr_mfe_valid_count"] == 1
        assert d2["mean_cr_mfe"] == pytest.approx(0.50, abs=1e-4)
        assert d2["mean_giveback_r"] == pytest.approx(1.00, abs=1e-4)
        assert d2["mean_ur_mae"] == pytest.approx(1.00, abs=1e-4)
        # MFE >= 0.5R に到達した3件のうち2件が逆転負け -> 2/3 = 66.67%
        assert d2["mfe_ge_05r_count"] == 3
        assert d2["reversal_from_05r_count"] == 2
        assert d2["reversal_from_05r_rate"] == pytest.approx(2.0 / 3.0, abs=1e-3)
        assert d2["status"] == "PROFIT_GIVEBACK"
    finally:
        conn.close()
        db.close()


def test_diagnostic_3_and_4_tax_invariants_ma_vs_ta_match_and_csv_export(tmp_path: Path) -> None:
    """
    診断3 & 診断4:
    - 期首 USDC シード後、HYPE/USDC を異なる価格・為替レートで2回購入し、全量を売却して期末在庫ゼロにした場合:
      ① 数量保存則 PASS
      ② Token/USDC二重仕訳ペアリング PASS
      ③ TTM為替レート欠損ゼロ PASS
      ④ マイナス在庫ゼロ PASS
      ⑤ 在庫ゼロ通貨 (HYPE) における移動平均法と総平均法の実現損益が完全一致 (誤差 <= ±1円) すること
    - `PASS: EXPORT_READY` が出力され、`--export-csv` により月次監査CSVが生成されること
    """
    db_file = tmp_path / "tax_audit.db"
    db = DatabaseManager(db_path=db_file, initial_equity_usdc=200.0, initial_usdc_jpy_rate=150.0)
    tax = HyperliquidTaxEngine(db=db)

    base_ts = 1761264000000  # 2025-10-24 UTC
    tax.bootstrap_initial_usdc_inventory(
        actual_usdc_total=200.0,
        usdc_jpy_rate=150.0,
        timestamp_ms=base_ts,
    )

    # 1. HYPE 1.0枚 @ 20 USDC (1 USDC = 150 JPY, Maker fee = 0.0 USDC)
    tax.process_spot_fill(
        hl_tid=9001,
        hl_oid=101,
        timestamp_ms=base_ts + 60_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc=20.0,
        exec_sz_base=1.0,
        raw_fee_amount=0.0,
        raw_fee_token="USDC",
        usdc_jpy_rate=150.0,
        rate_source="TEST_TTM",
    )
    # 2. HYPE 1.0枚 @ 30 USDC (1 USDC = 152 JPY, Maker fee = 0.0 USDC)
    tax.process_spot_fill(
        hl_tid=9002,
        hl_oid=102,
        timestamp_ms=base_ts + 120_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=True,
        exec_px_usdc=30.0,
        exec_sz_base=1.0,
        raw_fee_amount=0.0,
        raw_fee_token="USDC",
        usdc_jpy_rate=152.0,
        rate_source="TEST_TTM",
    )
    # 3. HYPE 1.0枚 一部売却 @ 32 USDC (1 USDC = 154 JPY, Taker fee 7bps = 0.0224 USDC)
    tax.process_spot_fill(
        hl_tid=9003,
        hl_oid=103,
        timestamp_ms=base_ts + 180_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc=32.0,
        exec_sz_base=1.0,
        raw_fee_amount=0.0224,
        raw_fee_token="USDC",
        usdc_jpy_rate=154.0,
        rate_source="TEST_TTM",
    )
    # 4. HYPE 残り 1.0枚 全量売却 @ 36 USDC (1 USDC = 155 JPY, Taker fee 7bps = 0.0252 USDC) -> HYPE 在庫ゼロへ
    tax.process_spot_fill(
        hl_tid=9004,
        hl_oid=104,
        timestamp_ms=base_ts + 240_000,
        pair_name="HYPE/USDC",
        base_asset="HYPE",
        is_buy=False,
        exec_px_usdc=36.0,
        exec_sz_base=1.0,
        raw_fee_amount=0.0252,
        raw_fee_token="USDC",
        usdc_jpy_rate=155.0,
        rate_source="TEST_TTM",
    )

    export_dir = tmp_path / "exports"
    report = run_full_postmortem_audit(
        db_path=db_file,
        mc_samples=10_000,
        export_csv=True,
        export_month="202510",
        export_dir=export_dir,
    )

    d3 = report["diagnostic_3_fee_and_maker"]
    assert d3["total_fills"] == 4
    assert d3["maker_fills"] == 2
    assert d3["taker_fills"] == 2
    assert d3["rho_maker"] == pytest.approx(0.50)
    assert d3["action_budget"]["daily_budget"] >= 20

    d4 = report["diagnostic_4_tax_forensic"]
    assert d4["status"] == "PASS: EXPORT_READY"
    assert all(d4["invariants"].values())

    # HYPE は期末在庫ゼロのため、移動平均法と総平均法の実現損益が完全一致（誤差 <= 1円）
    hype_rec = d4["zero_inventory_reconciliation"]["HYPE"]
    assert hype_rec["abs_diff_jpy"] <= 1.0
    assert hype_rec["moving_average_pnl_jpy"] > 2900.0

    # エクスポートされた CSV ファイルの検証
    csv_path = Path(d4["exported_csv_path"])
    assert csv_path.exists()
    with csv_path.open("r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 4
    assert rows[0]["pair_name"] == "HYPE/USDC"

    formatted_text = format_postmortem_audit_report(report)
    assert "PASS: EXPORT_READY" in formatted_text
    db.close()
