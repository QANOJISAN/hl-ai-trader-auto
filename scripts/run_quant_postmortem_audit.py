"""
HL AI Trader v1.2 Alpha-Max — Post-Mortem Quant Audit & Tax Forensic CLI Tool
(`scripts/run_quant_postmortem_audit.py`)

第3弾ディープリサーチ白書（Post-Mortem Quant Audit & Walk-Forward Calibration Protocol）準拠:
- 本番データベース (`data/hl_v1_state_wal.db`) に対して完全読み取り専用 (`mode=ro` & `PRAGMA query_only = ON`) で接続し、
  稼働中の `HLTraderDaemon` (Port 8081) や本番コード (`src/`) に一切干渉・変更を加えずに4大診断を一括実行する。

4大診断エンジン:
1. 【診断1：エントリー枯渇（Over-Filtering）vs ダマシ遮断のベイズ＆正確確率診断】
   - Haldane-Anscombe 補正付きゲート・オッズ比 `OR_gate`
   - 片側 Fisher's Exact Test 正確確率 `p_value`
   - Beta(1+W, 1+L) 事後分布モンテカルロ・サンプリング (100,000試行) による
     事後優越確率 `P(theta_live > theta_shadow | D)`、事後平均勝率差 `E[Delta_theta]`、90%最高密度区間 (`90% HDI`)
   - 境界バケット (`WEEKEND_THIN`, `SSII` 境界, `SAI` 境界, 反証ゲート単一遮断等) ごとの期待R後悔 `Regret_{R,k}`
   - `HEALTHY` / `ALERT: TIMID_MISS` / `SAMPLE_ACCUMULATION_REQUIRED` 判定
2. 【診断2：6段階ソフトラチェット ＆ 時間減衰SLのMFE捕捉効率監査】
   - 勝ちトレードの MFE捕捉効率 `CR_MFE = R_realized / MFE_R` (`MFE_R = 0` は NULL 除外)
   - 利益吐き出し量 `GB_R = MFE_R - R_realized`
   - 負けトレードの MAE消化率 `UR_MAE = |R_realized| / MAE_R`
   - 含み益 `+0.5R` 以上からの逆転負け割合
   - `PREMATURE_EXIT` / `PROFIT_GIVEBACK` / `STOP_SWEEP_CLUSTER` / `OPTIMAL` 診断
3. 【診断3：手数料ドラッグ ＆ Maker `Alo` 約定率（`rho_maker`）監査】
   - 全約定イベントにおける Maker 約定比率 `rho_maker`、実効手数料率 (bps / %)、未約定期限切れ件数、
     および `ActionBudgetController` の日次バジェット残量
4. 【診断4：日本円税務台帳（移動平均法 vs 総平均法）＆ Forensic Ledger 月次エクスポート監査】
   - ①数量保存則、②Token/USDC二重仕訳ペアリング、③TTM為替レート欠損ゼロ、
     ④マイナス在庫（Short Lot）ゼロ、⑤在庫ゼロ通貨における移動平均法と総平均法の損益一致（誤差 <= ±1円）
   - 銘柄別の移動平均法実現損益（JPY）と総平均法試算損益（JPY）および `PASS: EXPORT_READY` 判定
   - `--export-csv` 指定時の `data/exports/forensic_ledger_export_YYYYMM.csv` 出力
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sqlite3
import sys
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONUTF8"] = "1"
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.exchange_wrapper import ActionBudgetController
from src.utils import _to_clean_decimal, jst_tax_year, now_ms

JST = timezone(timedelta(hours=9))
DEFAULT_DB_PATH = BASE_DIR / "data" / "hl_v1_state_wal.db"
DEFAULT_EXPORT_DIR = BASE_DIR / "data" / "exports"


def open_readonly_sqlite(db_path: Union[str, Path]) -> sqlite3.Connection:
    """
    指定されたSQLiteデータベースを厳格な読み取り専用モード (`mode=ro` + `PRAGMA query_only = ON`) で開く。
    稼働中の本番デーモン (`HLTraderDaemon`) のWAL書き込みを一切ブロック・変更しない。
    """
    resolved = Path(db_path).resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"監査対象のSQLite DBファイルが存在しません: {resolved}")

    uri = f"{resolved.as_uri()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
        (str(table_name),),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    if not _table_exists(conn, table_name):
        return set()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(r["name"]).lower() for r in rows}


def compute_exact_fisher_one_sided_p(
    w_live: int,
    l_live: int,
    w_shadow: int,
    l_shadow: int,
) -> Tuple[float, float]:
    """
    2x2分割表に対する正確確率検定 (Fisher's Exact Test) の片側 p値 を算出する。
    - `p_superior`: H1: theta_live > theta_shadow (実戦勝率が見送り勝率を上回る片側 p値)
    - `p_inferior`: H1: theta_live < theta_shadow (見送り勝率が実戦勝率を上回る＝Timid Miss 側の片側 p値)
    """
    n_live = max(0, int(w_live) + int(l_live))
    n_shadow = max(0, int(w_shadow) + int(l_shadow))
    n_total = n_live + n_shadow
    w_total = max(0, int(w_live) + int(w_shadow))

    if n_total == 0 or n_live == 0 or n_shadow == 0:
        return (1.0, 1.0)

    denom = math.comb(n_total, w_total)
    if denom == 0:
        return (1.0, 1.0)

    min_x = max(0, w_total - n_shadow)
    max_x = min(n_live, w_total)

    p_sup = 0.0
    for x in range(max(min_x, int(w_live)), max_x + 1):
        p_sup += (math.comb(n_live, x) * math.comb(n_shadow, w_total - x)) / denom

    p_inf = 0.0
    for x in range(min_x, min(int(w_live), max_x) + 1):
        p_inf += (math.comb(n_live, x) * math.comb(n_shadow, w_total - x)) / denom

    return (min(1.0, max(0.0, float(p_sup))), min(1.0, max(0.0, float(p_inf))))


def compute_beta_posterior_mc(
    w_live: int,
    l_live: int,
    w_shadow: int,
    l_shadow: int,
    num_samples: int = 100_000,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    一様事前分布 Beta(1, 1) に基づく事後分布:
      theta_live   ~ Beta(1 + W_live, 1 + L_live)
      theta_shadow ~ Beta(1 + W_shadow, 1 + L_shadow)
    からモンテカルロ・サンプリング (`num_samples = 100,000` 試行) を実行し、
    - ベイズ事後優越確率 P(theta_live > theta_shadow | D)
    - 事後平均勝率差 E[Delta_theta] = E[theta_live - theta_shadow]
    - 90%最高密度区間 (90% HDI: Highest Density Interval)
    を算出する。
    """
    a_live = 1.0 + max(0, int(w_live))
    b_live = 1.0 + max(0, int(l_live))
    a_sh = 1.0 + max(0, int(w_shadow))
    b_sh = 1.0 + max(0, int(l_shadow))

    rng = random.Random(int(seed))
    m = max(1_000, int(num_samples))
    bv = rng.betavariate

    deltas: List[float] = [0.0] * m
    sup_count = 0
    for i in range(m):
        tl = bv(a_live, b_live)
        ts = bv(a_sh, b_sh)
        d = tl - ts
        deltas[i] = d
        if tl > ts:
            sup_count += 1

    prob_sup = sup_count / float(m)
    analytical_mean_live = a_live / (a_live + b_live)
    analytical_mean_shadow = a_sh / (a_sh + b_sh)
    analytical_delta = analytical_mean_live - analytical_mean_shadow
    mc_mean_delta = sum(deltas) / float(m)

    # 90% 最高密度区間 (Shortest interval containing 90% of posterior mass)
    deltas.sort()
    window = int(math.floor(0.90 * m))
    best_width = float("inf")
    best_low = deltas[0]
    best_high = deltas[-1]
    limit = m - window
    for i in range(limit):
        low_v = deltas[i]
        high_v = deltas[i + window]
        w = high_v - low_v
        if w < best_width:
            best_width = w
            best_low = low_v
            best_high = high_v

    return {
        "alpha_live": a_live,
        "beta_live": b_live,
        "alpha_shadow": a_sh,
        "beta_shadow": b_sh,
        "posterior_mean_theta_live": round(analytical_mean_live, 6),
        "posterior_mean_theta_shadow": round(analytical_mean_shadow, 6),
        "posterior_mean_delta_theta": round(analytical_delta, 6),
        "mc_mean_delta_theta": round(mc_mean_delta, 6),
        "posterior_prob_live_gt_shadow": round(prob_sup, 6),
        "hdi_90_low": round(best_low, 6),
        "hdi_90_high": round(best_high, 6),
        "mc_samples": m,
    }


def _classify_boundary_bucket(skip_stage: str, skip_reason_code: str, regime_4h: str) -> str:
    """
    `shadow_evaluations` の見送り理由コード・ステージを第3弾白書の境界バケットに正規化分類する。
    """
    code = str(skip_reason_code or "").strip().upper()
    stage = str(skip_stage or "").strip().upper()
    reg = str(regime_4h or "").strip().upper()

    if "WEEKEND" in code or "WEEKEND" in stage or "WEEKEND" in reg or "WICK" in code:
        return "WEEKEND_THIN"
    if "SSII" in code or "SQUEEZE" in code:
        return "SSII_BOUNDARY"
    if "SAI" in code or "ABSORPTION" in code or "BULL_TRAP" in code:
        return "SAI_BOUNDARY"
    if "FALSIFICATION" in code or "RUBRIC" in code or "GATE_REJECTED" in code:
        return "FALSIFICATION_GATE"
    if "CONVICTION" in code or "THETA" in code or "SCORE" in code:
        return "CONVICTION_BOUNDARY"
    return code if code else (stage if stage else "OTHER_GATE")


# ==============================================================================
# 診断1：エントリー枯渇（Over-Filtering）vs ダマシ遮断のベイズ＆正確確率診断
# ==============================================================================
def run_diagnostic_1_bayesian_gate_audit(
    conn: sqlite3.Connection,
    mc_samples: int = 100_000,
    target_live_n: int = 20,
    target_shadow_n: int = 100,
) -> Dict[str, Any]:
    """
    `ai_episodic_memory` / `ai_reflection_memory`（実戦決済済みトレード）と
    `shadow_evaluations`（見送り追跡完了分）を集計し、
    Haldane-Anscombe オッズ比、Fisher正確確率、Beta事後モンテカルロ優越確率・90% HDI、
    および境界バケット別期待R後悔 `Regret_{R,k}` を算出する。
    """
    w_live = 0
    l_live = 0
    seen_episodes: set[str] = set()

    if _table_exists(conn, "ai_reflection_memory"):
        ref_rows = conn.execute(
            "SELECT episode_id, realized_r_multiple FROM ai_reflection_memory"
        ).fetchall()
        for r in ref_rows:
            ep_id = str(r["episode_id"] or "")
            if ep_id:
                seen_episodes.add(ep_id)
            r_val = float(r["realized_r_multiple"] or 0.0)
            if r_val > 0.0:
                w_live += 1
            else:
                l_live += 1

    if _table_exists(conn, "ai_episodic_memory"):
        ep_cols = _table_columns(conn, "ai_episodic_memory")
        if "realized_r_multiple" in ep_cols:
            ep_rows = conn.execute(
                "SELECT episode_id, lifecycle_status, realized_r_multiple FROM ai_episodic_memory"
            ).fetchall()
            for r in ep_rows:
                ep_id = str(r["episode_id"] or "")
                if ep_id in seen_episodes:
                    continue
                st = str(r["lifecycle_status"] or "").strip().upper()
                if st in ("CLOSED", "COMPLETED", "SETTLED", "WIN", "LOSS"):
                    r_val = float(r["realized_r_multiple"] or 0.0)
                    if r_val > 0.0 or st == "WIN":
                        w_live += 1
                    else:
                        l_live += 1
        else:
            ep_rows = conn.execute(
                "SELECT episode_id, lifecycle_status FROM ai_episodic_memory"
            ).fetchall()
            for r in ep_rows:
                ep_id = str(r["episode_id"] or "")
                if ep_id in seen_episodes:
                    continue
                st = str(r["lifecycle_status"] or "").strip().upper()
                if st in ("WIN", "CLOSED_WIN"):
                    w_live += 1
                elif st in ("LOSS", "CLOSED_LOSS"):
                    l_live += 1

    n_live = w_live + l_live

    w_shadow = 0
    l_shadow = 0
    tracking_shadow = 0
    bucket_rows: Dict[str, List[float]] = {
        "WEEKEND_THIN": [],
        "SSII_BOUNDARY": [],
        "SAI_BOUNDARY": [],
        "FALSIFICATION_GATE": [],
    }
    bucket_counts: Dict[str, Dict[str, int]] = {}

    if _table_exists(conn, "shadow_evaluations"):
        sh_rows = conn.execute("SELECT * FROM shadow_evaluations").fetchall()
        for r in sh_rows:
            rd = dict(r)
            first_hit = str(rd.get("first_hit_type") or "NONE").strip().upper()
            outcome = str(rd.get("shadow_outcome") or "TRACKING").strip().upper()
            missed_r_raw = rd.get("missed_r_multiple")

            is_completed = (
                first_hit in ("TP_FIRST", "SL_FIRST")
                or outcome not in ("TRACKING", "NONE", "")
                or missed_r_raw is not None
            )
            if not is_completed:
                tracking_shadow += 1
                continue

            entry_px = float(rd.get("spot_mid_at_eval") or 0.0)
            sl_px = float(rd.get("hypothetical_sl_px") or 0.0)
            tp_px = float(rd.get("hypothetical_tp_px") or 0.0)
            risk = max(1e-8, entry_px - sl_px) if (entry_px > sl_px > 0.0) else 0.0

            if first_hit == "TP_FIRST" or outcome in ("TP_FIRST", "TIMID_MISS", "MISSED_WIN", "WIN"):
                is_shadow_win = True
                if missed_r_raw is not None:
                    r_sh = float(missed_r_raw)
                elif risk > 0 and tp_px > entry_px:
                    r_sh = (tp_px - entry_px) / risk
                else:
                    r_sh = 1.5
            elif first_hit == "SL_FIRST" or outcome in ("SL_FIRST", "CORRECT_AVOIDANCE", "GOOD_SKIP", "LOSS"):
                is_shadow_win = False
                if missed_r_raw is not None:
                    r_sh = float(missed_r_raw)
                else:
                    r_sh = -1.0
            else:
                r_sh = float(missed_r_raw) if missed_r_raw is not None else 0.0
                is_shadow_win = r_sh > 0.0

            if is_shadow_win:
                w_shadow += 1
            else:
                l_shadow += 1

            b_key = _classify_boundary_bucket(
                skip_stage=str(rd.get("skip_stage") or ""),
                skip_reason_code=str(rd.get("skip_reason_code") or ""),
                regime_4h=str(rd.get("market_regime_4h") or ""),
            )
            bucket_rows.setdefault(b_key, []).append(r_sh)
            b_stat = bucket_counts.setdefault(b_key, {"tp_first": 0, "sl_first": 0})
            if is_shadow_win:
                b_stat["tp_first"] += 1
            else:
                b_stat["sl_first"] += 1

    n_shadow = w_shadow + l_shadow

    # Haldane-Anscombe 補正付きオッズ比 OR_gate
    or_gate = ((w_live + 0.5) * (l_shadow + 0.5)) / ((l_live + 0.5) * (w_shadow + 0.5))
    p_fisher_sup, p_fisher_inf = compute_exact_fisher_one_sided_p(
        w_live=w_live,
        l_live=l_live,
        w_shadow=w_shadow,
        l_shadow=l_shadow,
    )
    bayes = compute_beta_posterior_mc(
        w_live=w_live,
        l_live=l_live,
        w_shadow=w_shadow,
        l_shadow=l_shadow,
        num_samples=mc_samples,
    )

    boundary_buckets: Dict[str, Dict[str, Any]] = {}
    max_regret_r = 0.0
    worst_bucket_name = "NONE"
    for b_key, r_list in bucket_rows.items():
        cnt = len(r_list)
        b_st = bucket_counts.get(b_key, {"tp_first": 0, "sl_first": 0})
        if cnt > 0:
            mean_r = sum(r_list) / float(cnt)
            regret_r = max(0.0, mean_r)
            if regret_r > max_regret_r:
                max_regret_r = regret_r
                worst_bucket_name = b_key
        else:
            mean_r = 0.0
            regret_r = 0.0
        boundary_buckets[b_key] = {
            "sample_count": cnt,
            "tp_first_count": b_st["tp_first"],
            "sl_first_count": b_st["sl_first"],
            "mean_shadow_r": round(mean_r, 4),
            "regret_r": round(regret_r, 4),
        }

    live_progress_pct = min(100.0, round((n_live / float(max(1, target_live_n))) * 100.0, 1))
    shadow_progress_pct = min(100.0, round((n_shadow / float(max(1, target_shadow_n))) * 100.0, 1))

    prob_sup = float(bayes["posterior_prob_live_gt_shadow"])
    shadow_wr = (w_shadow / float(n_shadow)) if n_shadow > 0 else 0.0

    # 判定ロジック:
    # 1. 見送り群の勝率が異常に高く機会損失 (Timid Miss) が顕著な場合 -> ALERT: TIMID_MISS
    if n_shadow >= 5 and (
        prob_sup < 0.25
        or (or_gate < 0.65 and max_regret_r >= 0.25)
        or (shadow_wr >= 0.60 and max_regret_r >= 0.30 and prob_sup < 0.45)
    ):
        status = "ALERT: TIMID_MISS"
    # 2. 実戦と見送りの双方に有意なサンプルがあり、ゲートが明確にダマシを遮断している場合 -> HEALTHY
    elif n_live >= 5 and n_shadow >= 5 and or_gate >= 1.25 and prob_sup >= 0.70:
        status = "HEALTHY"
    # 3. 目標サンプル数 (N_live >= 20, N_shadow >= 100) 未到達の場合 -> SAMPLE_ACCUMULATION_REQUIRED
    elif n_live < target_live_n or n_shadow < target_shadow_n:
        status = "SAMPLE_ACCUMULATION_REQUIRED"
    else:
        status = "HEALTHY"

    return {
        "status": status,
        "w_live": w_live,
        "l_live": l_live,
        "n_live": n_live,
        "w_shadow": w_shadow,
        "l_shadow": l_shadow,
        "n_shadow": n_shadow,
        "tracking_shadow_count": tracking_shadow,
        "target_live_n": target_live_n,
        "target_shadow_n": target_shadow_n,
        "live_progress_pct": live_progress_pct,
        "shadow_progress_pct": shadow_progress_pct,
        "or_gate_haldane": round(or_gate, 4),
        "fisher_exact_p_one_sided": round(p_fisher_sup, 6),
        "fisher_exact_p_timid_miss": round(p_fisher_inf, 6),
        "posterior_prob_live_gt_shadow": bayes["posterior_prob_live_gt_shadow"],
        "posterior_mean_theta_live": bayes["posterior_mean_theta_live"],
        "posterior_mean_theta_shadow": bayes["posterior_mean_theta_shadow"],
        "posterior_mean_delta_theta": bayes["posterior_mean_delta_theta"],
        "hdi_90": [bayes["hdi_90_low"], bayes["hdi_90_high"]],
        "boundary_buckets": boundary_buckets,
        "max_regret_r": round(max_regret_r, 4),
        "worst_regret_bucket": worst_bucket_name,
    }


# ==============================================================================
# 診断2：6段階ソフトラチェット ＆ 時間減衰SLのMFE捕捉効率監査
# ==============================================================================
def run_diagnostic_2_mfe_capture_audit(conn: sqlite3.Connection) -> Dict[str, Any]:
    """
    決済済みトレードの `R_realized`, `MFE_R`, `MAE_R` から、
    - 勝ちトレードの MFE捕捉効率 `CR_MFE = R_realized / MFE_R` (`MFE_R = 0` は NULL 除外)
    - 利益吐き出し量 `GB_R = MFE_R - R_realized`
    - 負けトレードの MAE消化率 `UR_MAE = |R_realized| / MAE_R`
    - 含み益 `+0.5R` 以上からの逆転負け割合
    を集計し、`PREMATURE_EXIT` / `PROFIT_GIVEBACK` / `STOP_SWEEP_CLUSTER` / `OPTIMAL` を診断する。
    """
    if not _table_exists(conn, "ai_reflection_memory"):
        return {
            "status": "OPTIMAL",
            "total_closed_trades": 0,
            "win_trades": 0,
            "loss_trades": 0,
            "cr_mfe_valid_count": 0,
            "mean_cr_mfe": None,
            "mean_giveback_r": 0.0,
            "mean_ur_mae": None,
            "reversal_from_05r_count": 0,
            "reversal_from_05r_rate": 0.0,
            "trades_detail": [],
        }

    ref_cols = _table_columns(conn, "ai_reflection_memory")
    has_ep_table = _table_exists(conn, "ai_episodic_memory")

    if has_ep_table:
        query = """
            SELECT
                r.*,
                e.initial_sl_px AS ep_initial_sl_px,
                e.entry_limit_px AS ep_entry_limit_px,
                e.target_tp_px AS ep_target_tp_px
            FROM ai_reflection_memory r
            LEFT JOIN ai_episodic_memory e ON r.episode_id = e.episode_id
            ORDER BY r.closed_at_ms ASC
        """
    else:
        query = "SELECT * FROM ai_reflection_memory ORDER BY closed_at_ms ASC"

    rows = conn.execute(query).fetchall()

    cr_mfe_list: List[float] = []
    giveback_r_list: List[float] = []
    ur_mae_list: List[float] = []
    win_r_list: List[float] = []
    trades_detail: List[Dict[str, Any]] = []

    win_count = 0
    loss_count = 0
    mfe_ge_05r_count = 0
    reversal_from_05r_count = 0

    for row in rows:
        rd = dict(row)
        r_realized = float(rd.get("realized_r_multiple") or 0.0)
        entry_px = float(rd.get("entry_px") or rd.get("ep_entry_limit_px") or 0.0)
        exit_px = float(rd.get("exit_px") or 0.0)
        init_sl_px = float(rd.get("ep_initial_sl_px") or 0.0)

        # MFE_R / MAE_R の解決:
        # 1) 直接 mfe_r / mae_r カラムが存在すればそれを使用
        # 2) entry_px と initial_sl_px から 1R% を算出し mfe_pct / mae_pct を R 単位へ変換
        # 3) initial_sl_px が無い場合は exit_px, entry_px, realized_r_multiple から 1R% を逆算
        if "mfe_r" in ref_cols and rd.get("mfe_r") is not None:
            mfe_r = max(0.0, float(rd["mfe_r"]))
        else:
            raw_mfe_pct = max(0.0, float(rd.get("mfe_pct") or 0.0))
            one_r_pct = 0.0
            if entry_px > init_sl_px > 0.0:
                one_r_pct = ((entry_px - init_sl_px) / entry_px) * 100.0
            elif entry_px > 0.0 and abs(r_realized) > 1e-6 and abs(exit_px - entry_px) > 1e-9:
                risk_px = abs(exit_px - entry_px) / abs(r_realized)
                one_r_pct = (risk_px / entry_px) * 100.0

            if one_r_pct > 1e-6:
                mfe_r = raw_mfe_pct / one_r_pct
            else:
                # 既に R 倍率スケールまたは 1R=1% 基準で格納されている場合
                mfe_r = raw_mfe_pct

        if "mae_r" in ref_cols and rd.get("mae_r") is not None:
            mae_r = max(0.0, abs(float(rd["mae_r"])))
        else:
            raw_mae_pct = abs(float(rd.get("mae_pct") or 0.0))
            one_r_pct = 0.0
            if entry_px > init_sl_px > 0.0:
                one_r_pct = ((entry_px - init_sl_px) / entry_px) * 100.0
            elif entry_px > 0.0 and abs(r_realized) > 1e-6 and abs(exit_px - entry_px) > 1e-9:
                risk_px = abs(exit_px - entry_px) / abs(r_realized)
                one_r_pct = (risk_px / entry_px) * 100.0

            if one_r_pct > 1e-6:
                mae_r = raw_mae_pct / one_r_pct
            else:
                mae_r = raw_mae_pct

        if mfe_r >= 0.5:
            mfe_ge_05r_count += 1
            if r_realized < 0.0:
                reversal_from_05r_count += 1

        cr_mfe_val: Optional[float] = None
        gb_r_val: Optional[float] = None
        ur_mae_val: Optional[float] = None

        if r_realized > 0.0:
            win_count += 1
            win_r_list.append(r_realized)
            if mfe_r > 0.0:
                cr_mfe_val = r_realized / mfe_r
                cr_mfe_list.append(cr_mfe_val)
                gb_r_val = max(0.0, mfe_r - r_realized)
                giveback_r_list.append(gb_r_val)
            else:
                # MFE_R == 0 はゼロ除算防止のため NULL 除外
                cr_mfe_val = None
        else:
            loss_count += 1
            if mae_r > 0.0:
                ur_mae_val = abs(r_realized) / mae_r
                ur_mae_list.append(ur_mae_val)

        trades_detail.append(
            {
                "episode_id": str(rd.get("episode_id") or ""),
                "coin": str(rd.get("coin") or ""),
                "exit_reason": str(rd.get("exit_reason") or ""),
                "r_realized": round(r_realized, 4),
                "mfe_r": round(mfe_r, 4),
                "mae_r": round(mae_r, 4),
                "cr_mfe": round(cr_mfe_val, 4) if cr_mfe_val is not None else None,
                "gb_r": round(gb_r_val, 4) if gb_r_val is not None else None,
                "ur_mae": round(ur_mae_val, 4) if ur_mae_val is not None else None,
            }
        )

    total_trades = win_count + loss_count
    mean_cr_mfe = (sum(cr_mfe_list) / float(len(cr_mfe_list))) if cr_mfe_list else None
    mean_gb_r = (sum(giveback_r_list) / float(len(giveback_r_list))) if giveback_r_list else 0.0
    mean_ur_mae = (sum(ur_mae_list) / float(len(ur_mae_list))) if ur_mae_list else None
    mean_win_r = (sum(win_r_list) / float(len(win_r_list))) if win_r_list else 0.0

    # 含み益 +0.5R 以上からの逆転負け割合 (母数: MFE >= 0.5R に到達したトレード数、0件時は全トレード比)
    rev_denom = mfe_ge_05r_count if mfe_ge_05r_count > 0 else max(1, total_trades)
    reversal_rate = reversal_from_05r_count / float(rev_denom)
    loss_rate = (loss_count / float(total_trades)) if total_trades > 0 else 0.0

    if total_trades == 0:
        status = "OPTIMAL"
    elif reversal_rate >= 0.30 or (mean_gb_r >= 0.80 and (mean_cr_mfe is not None and mean_cr_mfe < 0.50)):
        status = "PROFIT_GIVEBACK"
    elif mean_cr_mfe is not None and mean_cr_mfe >= 0.85 and mean_win_r < 0.65:
        status = "PREMATURE_EXIT"
    elif loss_count >= 3 and loss_rate >= 0.60 and (mean_ur_mae is not None and mean_ur_mae >= 0.90):
        status = "STOP_SWEEP_CLUSTER"
    else:
        status = "OPTIMAL"

    return {
        "status": status,
        "total_closed_trades": total_trades,
        "win_trades": win_count,
        "loss_trades": loss_count,
        "cr_mfe_valid_count": len(cr_mfe_list),
        "mean_cr_mfe": round(mean_cr_mfe, 4) if mean_cr_mfe is not None else None,
        "mean_giveback_r": round(mean_gb_r, 4),
        "mean_ur_mae": round(mean_ur_mae, 4) if mean_ur_mae is not None else None,
        "mfe_ge_05r_count": mfe_ge_05r_count,
        "reversal_from_05r_count": reversal_from_05r_count,
        "reversal_from_05r_rate": round(reversal_rate, 4),
        "trades_detail": trades_detail,
    }


# ==============================================================================
# 診断3：手数料ドラッグ ＆ Maker `Alo` 約定率（`rho_maker`）監査
# ==============================================================================
def run_diagnostic_3_fee_and_maker_audit(
    conn: sqlite3.Connection,
    reference_ts_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """
    全約定イベントにおける Maker 約定比率 `rho_maker`、実効手数料率、未約定期限切れ件数、
    および現在の `ActionBudgetController` の日次バジェット残量を算出する。
    """
    ref_ts = int(reference_ts_ms) if reference_ts_ms is not None else now_ms()
    cutoff_14d_ms = ref_ts - 14 * 86_400_000
    today_jst_str = datetime.fromtimestamp(ref_ts / 1000.0, tz=JST).strftime("%Y-%m-%d")

    total_fills = 0
    maker_fills = 0
    taker_fills = 0
    total_notional_usdc = 0.0
    total_fee_usdc = 0.0
    volume_14d_usdc = 0.0
    fills_today = 0

    if _table_exists(conn, "tax_lots"):
        lots = conn.execute("SELECT * FROM tax_lots ORDER BY timestamp_ms ASC").fetchall()
        for r in lots:
            rd = dict(r)
            total_fills += 1
            px = float(rd.get("exec_px_usdc") or 0.0)
            sz = float(rd.get("exec_sz_base") or 0.0)
            notional = px * sz
            fee_amt = float(rd.get("raw_fee_amount") or 0.0)
            fee_tok = str(rd.get("raw_fee_token") or "USDC").strip().upper()
            base_tok = str(rd.get("base_asset") or "").strip().upper()
            ev_type = str(rd.get("event_type") or "").strip().upper()
            ts = int(rd.get("timestamp_ms") or 0)
            jst_d = str(rd.get("jst_date") or "")

            if fee_tok == base_tok and px > 0.0:
                fee_usdc = fee_amt * px
            else:
                fee_usdc = fee_amt

            total_notional_usdc += notional
            total_fee_usdc += fee_usdc
            if ts >= cutoff_14d_ms:
                volume_14d_usdc += notional
            if jst_d == today_jst_str:
                fills_today += 1

            fee_bps = ((fee_usdc / notional) * 10_000.0) if notional > 0.0 else 0.0
            # Hyperliquid Spot Tier 0: Maker (Alo) fee <= 4.5 bps (0.040%), Taker (Ioc) >= 5.5 bps (0.070%)
            if fee_bps <= 4.5:
                maker_fills += 1
            else:
                taker_fills += 1

    expired_unfilled_count = 0
    cancelled_adverse_count = 0
    episodes_today = 0
    if _table_exists(conn, "ai_episodic_memory"):
        ep_rows = conn.execute(
            "SELECT timestamp_ms, lifecycle_status FROM ai_episodic_memory"
        ).fetchall()
        for r in ep_rows:
            st = str(r["lifecycle_status"] or "").strip().upper()
            ts = int(r["timestamp_ms"] or 0)
            ep_date = datetime.fromtimestamp(ts / 1000.0, tz=JST).strftime("%Y-%m-%d") if ts > 0 else ""
            if ep_date == today_jst_str:
                episodes_today += 1
            if st in ("EXPIRED_4H", "EXPIRED", "CANCELLED_TTL", "CANCELLED_UNFILLED"):
                expired_unfilled_count += 1
            elif st == "CANCELLED_ADVERSE":
                cancelled_adverse_count += 1

    daily_trade_count_db = 0
    if _table_exists(conn, "system_state_store"):
        st_row = conn.execute("SELECT daily_trade_count FROM system_state_store WHERE id = 1").fetchone()
        if st_row and st_row["daily_trade_count"] is not None:
            daily_trade_count_db = int(st_row["daily_trade_count"])

    rho_maker = (maker_fills / float(total_fills)) if total_fills > 0 else 1.0
    effective_fee_rate = (total_fee_usdc / total_notional_usdc) if total_notional_usdc > 0.0 else 0.0
    effective_fee_bps = effective_fee_rate * 10_000.0

    estimated_actions_today = max(daily_trade_count_db, fills_today + episodes_today)
    v_today_usdc = 0.0
    if _table_exists(conn, "tax_lots"):
        v_tod_row = conn.execute(
            "SELECT SUM(exec_px_usdc * exec_sz_base) AS v_tod FROM tax_lots WHERE jst_date = ?",
            (today_jst_str,),
        ).fetchone()
        if v_tod_row and v_tod_row["v_tod"] is not None:
            v_today_usdc = float(v_tod_row["v_tod"])

    budget_ctrl = ActionBudgetController()
    raw_b_state = budget_ctrl.evaluate_budget_state(
        v_cum_usdc=total_notional_usdc,
        a_used_total=max(total_fills * 2, estimated_actions_today),
        v_ema_7d_usdc=max(100.0, volume_14d_usdc / 14.0),
        v_today_usdc=v_today_usdc,
        actions_used_today=estimated_actions_today,
    )
    b_daily = int(raw_b_state["b_daily"])
    used_today = int(raw_b_state["actions_used_today"])
    budget_state = {
        **raw_b_state,
        "daily_budget": b_daily,
        "remaining_budget": max(0, b_daily - used_today),
        "utilization": float(raw_b_state["usage_ratio"]),
    }

    return {
        "total_fills": total_fills,
        "maker_fills": maker_fills,
        "taker_fills": taker_fills,
        "rho_maker": round(rho_maker, 4),
        "total_notional_usdc": round(total_notional_usdc, 4),
        "total_fee_usdc": round(total_fee_usdc, 6),
        "effective_fee_rate_pct": round(effective_fee_rate * 100.0, 5),
        "effective_fee_bps": round(effective_fee_bps, 3),
        "expired_unfilled_count": expired_unfilled_count,
        "cancelled_adverse_count": cancelled_adverse_count,
        "volume_14d_usdc": round(volume_14d_usdc, 4),
        "action_budget": budget_state,
    }


# ==============================================================================
# 診断4：日本円税務台帳（移動平均法 vs 総平均法）＆ Forensic Ledger 月次エクスポート監査
# ==============================================================================
def run_diagnostic_4_tax_forensic_audit(
    conn: sqlite3.Connection,
    tax_year: Optional[int] = None,
    export_csv: bool = False,
    export_month: Optional[str] = None,
    export_dir: Union[str, Path] = DEFAULT_EXPORT_DIR,
) -> Dict[str, Any]:
    """
    `tax_inventory_state`, `tax_annual_opening`, `tax_lots`（および存在時は `tax_ledger_events`）を検査し、
    ①数量保存則
    ②Token/USDC二重仕訳ペアリング
    ③TTM為替レート欠損ゼロ
    ④マイナス在庫（Short Lot）ゼロ
    ⑤在庫ゼロ通貨における移動平均法と総平均法の損益一致（誤差 <= ±1円）
    の5項目を検証して銘柄別実現損益（移動平均法 vs 総平均法）と `PASS: EXPORT_READY` ステータスを返す。
    """
    if tax_year is not None:
        target_year = int(tax_year)
    elif _table_exists(conn, "tax_lots"):
        yr_row = conn.execute("SELECT MAX(tax_year) AS max_yr FROM tax_lots").fetchone()
        target_year = int(yr_row["max_yr"]) if (yr_row and yr_row["max_yr"] is not None) else jst_tax_year(now_ms())
    else:
        target_year = jst_tax_year(now_ms())

    inv_rows = (
        [dict(r) for r in conn.execute("SELECT * FROM tax_inventory_state ORDER BY asset ASC").fetchall()]
        if _table_exists(conn, "tax_inventory_state")
        else []
    )
    opening_rows = (
        [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM tax_annual_opening WHERE tax_year = ? ORDER BY asset ASC",
                (target_year,),
            ).fetchall()
        ]
        if _table_exists(conn, "tax_annual_opening")
        else []
    )
    lot_rows = (
        [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM tax_lots WHERE tax_year = ? ORDER BY timestamp_ms ASC, lot_id ASC",
                (target_year,),
            ).fetchall()
        ]
        if _table_exists(conn, "tax_lots")
        else []
    )
    ledger_event_rows = (
        [dict(r) for r in conn.execute("SELECT * FROM tax_ledger_events").fetchall()]
        if _table_exists(conn, "tax_ledger_events")
        else []
    )

    inventory_map: Dict[str, Dict[str, Decimal]] = {}
    for r in inv_rows:
        a = str(r["asset"])
        inventory_map[a] = {
            "quantity": _to_clean_decimal(r["quantity"]),
            "book_cost_jpy": _to_clean_decimal(r["book_cost_jpy"]),
            "moving_avg_unit_jpy": _to_clean_decimal(r["moving_avg_unit_jpy"]),
        }

    openings_map: Dict[str, Tuple[Decimal, Decimal]] = {}
    for r in opening_rows:
        a = str(r["asset"])
        openings_map[a] = (
            _to_clean_decimal(r["opening_qty"]),
            _to_clean_decimal(r["opening_cost_jpy"]),
        )

    # ------------------------------------------------------------------
    # 検査②: Token/USDC二重仕訳ペアリング & 検査③: TTM為替レート欠損ゼロ
    # ------------------------------------------------------------------
    check_2_dual_leg_ok = True
    check_3_ttm_rate_ok = True
    dual_leg_violations: List[int] = []
    ttm_rate_violations: List[int] = []

    for lot in lot_rows:
        lid = int(lot.get("lot_id") or 0)
        d_asset = str(lot.get("disposed_asset") or "").strip()
        a_asset = str(lot.get("acquired_asset") or "").strip()
        d_qty = _to_clean_decimal(lot.get("disposed_qty") or 0)
        a_qty = _to_clean_decimal(lot.get("acquired_net_qty") or 0)
        rate = _to_clean_decimal(lot.get("usdc_jpy_rate") or 0)
        rate_src = str(lot.get("rate_source") or "").strip()

        if not d_asset or not a_asset or d_asset == a_asset or d_qty <= Decimal("0") or a_qty < Decimal("0"):
            check_2_dual_leg_ok = False
            dual_leg_violations.append(lid)

        if rate <= Decimal("0") or not rate_src:
            check_3_ttm_rate_ok = False
            ttm_rate_violations.append(lid)

    if _table_exists(conn, "system_state_store"):
        st_r = conn.execute("SELECT latest_usdc_jpy_rate FROM system_state_store WHERE id = 1").fetchone()
        if st_r is not None and float(st_r["latest_usdc_jpy_rate"] or 0.0) <= 0.0:
            check_3_ttm_rate_ok = False

    # ------------------------------------------------------------------
    # 検査①: 数量保存則 & 検査④: マイナス在庫（Short Lot）ゼロ
    # ------------------------------------------------------------------
    check_1_qty_conservation_ok = True
    check_4_no_negative_inv_ok = True
    qty_conservation_diffs: Dict[str, float] = {}
    negative_inventory_assets: List[str] = []

    for asset, vals in inventory_map.items():
        if vals["quantity"] < Decimal("-1e-9") or vals["book_cost_jpy"] < Decimal("-1e-4"):
            check_4_no_negative_inv_ok = False
            negative_inventory_assets.append(asset)

    # 全資産のネット増減を集計
    all_assets = set(inventory_map.keys()) | set(openings_map.keys())
    net_delta_by_asset: Dict[str, Decimal] = {a: Decimal("0") for a in all_assets}

    for lot in lot_rows:
        d_asset = str(lot["disposed_asset"])
        a_asset = str(lot["acquired_asset"])
        f_token = str(lot["raw_fee_token"])
        base_asset = str(lot["base_asset"])
        quote_asset = str(lot["quote_asset"])

        d_qty = _to_clean_decimal(lot["disposed_qty"])
        a_qty = _to_clean_decimal(lot["acquired_net_qty"])
        f_qty = _to_clean_decimal(lot["raw_fee_amount"])

        all_assets.update((d_asset, a_asset, f_token))
        net_delta_by_asset[d_asset] = net_delta_by_asset.get(d_asset, Decimal("0")) - d_qty
        net_delta_by_asset[a_asset] = net_delta_by_asset.get(a_asset, Decimal("0")) + a_qty
        if f_token not in (base_asset, quote_asset) and f_qty > Decimal("0"):
            net_delta_by_asset[f_token] = net_delta_by_asset.get(f_token, Decimal("0")) - f_qty

    # 時系列順のランニング在庫検証と期末残高一致検証
    running_qty: Dict[str, Decimal] = {}
    for a in all_assets:
        if a in openings_map:
            running_qty[a] = openings_map[a][0]
        else:
            # tax_annual_opening に未記録の直接シードがあった場合は期末残高から逆算した初期値を採用
            inv_q = inventory_map.get(a, {}).get("quantity", Decimal("0"))
            inferred_open = inv_q - net_delta_by_asset.get(a, Decimal("0"))
            running_qty[a] = inferred_open if inferred_open >= Decimal("-1e-6") else Decimal("0")

    for lot in lot_rows:
        d_asset = str(lot["disposed_asset"])
        a_asset = str(lot["acquired_asset"])
        f_token = str(lot["raw_fee_token"])
        base_asset = str(lot["base_asset"])
        quote_asset = str(lot["quote_asset"])

        d_qty = _to_clean_decimal(lot["disposed_qty"])
        a_qty = _to_clean_decimal(lot["acquired_net_qty"])
        f_qty = _to_clean_decimal(lot["raw_fee_amount"])

        running_qty[d_asset] = running_qty.get(d_asset, Decimal("0")) - d_qty
        if running_qty[d_asset] < Decimal("-1e-6"):
            check_4_no_negative_inv_ok = False
            if d_asset not in negative_inventory_assets:
                negative_inventory_assets.append(d_asset)
        if Decimal("-1e-6") <= running_qty[d_asset] <= Decimal("1e-12"):
            running_qty[d_asset] = Decimal("0")

        running_qty[a_asset] = running_qty.get(a_asset, Decimal("0")) + a_qty

        if f_token not in (base_asset, quote_asset) and f_qty > Decimal("0"):
            running_qty[f_token] = running_qty.get(f_token, Decimal("0")) - f_qty
            if running_qty[f_token] < Decimal("-1e-6"):
                check_4_no_negative_inv_ok = False
                if f_token not in negative_inventory_assets:
                    negative_inventory_assets.append(f_token)

    for a in sorted(all_assets):
        expected_end_q = running_qty.get(a, Decimal("0"))
        actual_end_q = inventory_map.get(a, {}).get("quantity", Decimal("0"))
        diff_q = abs(actual_end_q - expected_end_q)
        qty_conservation_diffs[a] = float(diff_q)
        if diff_q > Decimal("1e-5"):
            check_1_qty_conservation_ok = False

    # ------------------------------------------------------------------
    # 移動平均法 (`MOVING_AVERAGE`) vs 総平均法 (`TOTAL_AVERAGE`) 損益集計
    # ------------------------------------------------------------------
    ma_by_asset: Dict[str, Dict[str, Decimal]] = {}
    ma_total_pnl = Decimal("0")
    for lot in lot_rows:
        d_asset = str(lot["disposed_asset"])
        bucket = ma_by_asset.setdefault(
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
        ma_total_pnl += pnl

    # 総平均法単価計算
    acq_totals: Dict[str, Tuple[Decimal, Decimal]] = {}
    for lot in lot_rows:
        a_asset = str(lot["acquired_asset"])
        pq, pc = acq_totals.get(a_asset, (Decimal("0"), Decimal("0")))
        acq_totals[a_asset] = (
            pq + _to_clean_decimal(lot["acquired_net_qty"]),
            pc + _to_clean_decimal(lot["acquisition_cost_jpy"]),
        )

    annual_unit_costs: Dict[str, Decimal] = {}
    for a in all_assets:
        if a in openings_map:
            op_q, op_c = openings_map[a]
        else:
            op_q, op_c = (Decimal("0"), Decimal("0"))
        ac_q, ac_c = acq_totals.get(a, (Decimal("0"), Decimal("0")))
        denom_q = op_q + ac_q
        numer_c = op_c + ac_c
        if denom_q > Decimal("0"):
            annual_unit_costs[a] = numer_c / denom_q
        elif a in inventory_map and inventory_map[a]["moving_avg_unit_jpy"] > Decimal("0"):
            annual_unit_costs[a] = inventory_map[a]["moving_avg_unit_jpy"]
        else:
            annual_unit_costs[a] = Decimal("0")

    ta_by_asset: Dict[str, Dict[str, Decimal]] = {}
    ta_total_pnl = Decimal("0")
    for lot in lot_rows:
        d_asset = str(lot["disposed_asset"])
        unit_cost = annual_unit_costs.get(d_asset, Decimal("0"))
        d_qty = _to_clean_decimal(lot["disposed_qty"])
        proc = _to_clean_decimal(lot["gross_proceeds_jpy"])
        exp = _to_clean_decimal(lot["selling_expense_jpy"])
        cogs = d_qty * unit_cost
        pnl = proc - cogs - exp

        bucket = ta_by_asset.setdefault(
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
        ta_total_pnl += pnl

    # ------------------------------------------------------------------
    # 検査⑤: 在庫ゼロ通貨における移動平均法と総平均法の損益一致 (誤差 <= ±1円)
    # ------------------------------------------------------------------
    check_5_zero_inv_pnl_match_ok = True
    zero_inv_reconciliation: Dict[str, Dict[str, float]] = {}
    asset_pnl_comparison: Dict[str, Dict[str, Any]] = {}

    for a in sorted(set(ma_by_asset.keys()) | set(ta_by_asset.keys()) | set(inventory_map.keys())):
        ma_pnl = ma_by_asset.get(a, {}).get("realized_pnl_jpy", Decimal("0"))
        ta_pnl = ta_by_asset.get(a, {}).get("realized_pnl_jpy", Decimal("0"))
        rem_q = inventory_map.get(a, {}).get("quantity", Decimal("0"))
        diff_jpy = abs(ma_pnl - ta_pnl)

        is_zero_inv = rem_q <= Decimal("1e-8")
        asset_pnl_comparison[a] = {
            "ending_quantity": float(rem_q),
            "is_zero_ending_inventory": is_zero_inv,
            "moving_average_pnl_jpy": float(round(ma_pnl, 2)),
            "total_average_pnl_jpy": float(round(ta_pnl, 2)),
            "abs_diff_jpy": float(round(diff_jpy, 4)),
        }
        if is_zero_inv and a in ma_by_asset:
            zero_inv_reconciliation[a] = {
                "moving_average_pnl_jpy": float(round(ma_pnl, 2)),
                "total_average_pnl_jpy": float(round(ta_pnl, 2)),
                "abs_diff_jpy": float(round(diff_jpy, 4)),
            }
            if diff_jpy > Decimal("1.0"):
                check_5_zero_inv_pnl_match_ok = False

    all_five_passed = (
        check_1_qty_conservation_ok
        and check_2_dual_leg_ok
        and check_3_ttm_rate_ok
        and check_4_no_negative_inv_ok
        and check_5_zero_inv_pnl_match_ok
    )
    status = "PASS: EXPORT_READY" if all_five_passed else "FAIL: INVARIANT_VIOLATION"

    exported_csv_path: Optional[str] = None
    if export_csv:
        month_tag = (export_month or datetime.now(tz=JST).strftime("%Y%m")).strip()
        if len(month_tag) == 6 and month_tag.isdigit():
            yyyy_mm_prefix = f"{month_tag[:4]}-{month_tag[4:6]}"
        else:
            yyyy_mm_prefix = month_tag
        out_dir = Path(export_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        csv_file = out_dir / f"forensic_ledger_export_{month_tag}.csv"

        filtered_lots = [
            lot
            for lot in lot_rows
            if not yyyy_mm_prefix
            or str(lot.get("jst_date") or "").startswith(yyyy_mm_prefix)
            or not any(str(x.get("jst_date") or "").startswith(yyyy_mm_prefix) for x in lot_rows)
        ]

        fieldnames = [
            "lot_id",
            "hl_tid",
            "hl_oid",
            "timestamp_ms",
            "jst_date",
            "tax_year",
            "event_type",
            "pair_name",
            "base_asset",
            "quote_asset",
            "exec_px_usdc",
            "exec_sz_base",
            "raw_fee_amount",
            "raw_fee_token",
            "usdc_jpy_rate",
            "rate_source",
            "disposed_asset",
            "disposed_qty",
            "disposed_unit_cost_jpy",
            "disposed_cogs_jpy",
            "gross_proceeds_jpy",
            "selling_expense_jpy",
            "realized_pnl_jpy",
            "acquired_asset",
            "acquired_net_qty",
            "acquisition_cost_jpy",
            "new_moving_avg_unit_jpy",
        ]
        with csv_file.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for lot in filtered_lots:
                writer.writerow(lot)
        exported_csv_path = str(csv_file)

    return {
        "status": status,
        "tax_year": target_year,
        "lot_count": len(lot_rows),
        "ledger_events_count": len(ledger_event_rows),
        "invariants": {
            "check_1_quantity_conservation": check_1_qty_conservation_ok,
            "check_2_dual_leg_pairing": check_2_dual_leg_ok,
            "check_3_zero_missing_ttm_rate": check_3_ttm_rate_ok,
            "check_4_zero_negative_inventory": check_4_no_negative_inv_ok,
            "check_5_zero_inventory_ma_vs_ta_match": check_5_zero_inv_pnl_match_ok,
        },
        "qty_conservation_diffs": qty_conservation_diffs,
        "negative_inventory_assets": negative_inventory_assets,
        "dual_leg_violations": dual_leg_violations,
        "ttm_rate_violations": ttm_rate_violations,
        "moving_average_total_pnl_jpy": float(round(ma_total_pnl, 2)),
        "moving_average_total_pnl_jpy_int": int(
            ma_total_pnl.to_integral_value(rounding=ROUND_HALF_UP)
        ),
        "total_average_total_pnl_jpy": float(round(ta_total_pnl, 2)),
        "total_average_total_pnl_jpy_int": int(
            ta_total_pnl.to_integral_value(rounding=ROUND_HALF_UP)
        ),
        "asset_pnl_comparison": asset_pnl_comparison,
        "zero_inventory_reconciliation": zero_inv_reconciliation,
        "exported_csv_path": exported_csv_path,
    }


def run_full_postmortem_audit(
    db_path: Union[str, Path] = DEFAULT_DB_PATH,
    mc_samples: int = 100_000,
    export_csv: bool = False,
    export_month: Optional[str] = None,
    export_dir: Union[str, Path] = DEFAULT_EXPORT_DIR,
) -> Dict[str, Any]:
    """
    SQLite `hl_v1_state_wal.db` に読み取り専用 (`PRAGMA query_only = ON`) で接続し、
    診断1〜診断4を一括実行して構造化監査レポート辞書を返す。
    """
    conn = open_readonly_sqlite(db_path)
    try:
        q_only = conn.execute("PRAGMA query_only;").fetchone()[0]
        diag1 = run_diagnostic_1_bayesian_gate_audit(conn, mc_samples=mc_samples)
        diag2 = run_diagnostic_2_mfe_capture_audit(conn)
        diag3 = run_diagnostic_3_fee_and_maker_audit(conn)
        diag4 = run_diagnostic_4_tax_forensic_audit(
            conn,
            export_csv=export_csv,
            export_month=export_month,
            export_dir=export_dir,
        )
        return {
            "audit_timestamp_jst": datetime.now(tz=JST).isoformat(),
            "db_path": str(Path(db_path).resolve()),
            "pragma_query_only": int(q_only),
            "diagnostic_1_gate_bayesian": diag1,
            "diagnostic_2_mfe_capture": diag2,
            "diagnostic_3_fee_and_maker": diag3,
            "diagnostic_4_tax_forensic": diag4,
        }
    finally:
        conn.close()


def format_postmortem_audit_report(report: Dict[str, Any]) -> str:
    """4大診断レポートを人間およびクオンツ監査向けに視認性高く整形出力する"""
    d1 = report["diagnostic_1_gate_bayesian"]
    d2 = report["diagnostic_2_mfe_capture"]
    d3 = report["diagnostic_3_fee_and_maker"]
    d4 = report["diagnostic_4_tax_forensic"]

    lines: List[str] = [
        "================================================================================",
        " HL AI Trader v1.2 Alpha-Max — Post-Mortem Quant & Tax Forensic Audit Report",
        "================================================================================",
        f" Audit Timestamp (JST) : {report['audit_timestamp_jst']}",
        f" Target SQLite WAL DB  : {report['db_path']}",
        f" Read-Only Lock Mode   : PRAGMA query_only = {report['pragma_query_only']} (Code Freeze Enforced)",
        "--------------------------------------------------------------------------------",
        " [診断1] エントリー枯渇 (Over-Filtering) vs ダマシ遮断 ベイズ＆正確確率診断",
        f"   - Status                       : {d1['status']}",
        f"   - Live Closed Trades (W / L)   : W_live={d1['w_live']}, L_live={d1['l_live']} (N_live={d1['n_live']} / Target={d1['target_live_n']} -> {d1['live_progress_pct']:.1f}%)",
        f"   - Shadow Completed (TP / SL)   : W_shadow={d1['w_shadow']}, L_shadow={d1['l_shadow']} (N_shadow={d1['n_shadow']} / Target={d1['target_shadow_n']} -> {d1['shadow_progress_pct']:.1f}%, Tracking={d1['tracking_shadow_count']})",
        f"   - Haldane-Anscombe OR_gate     : {d1['or_gate_haldane']:.4f}",
        f"   - Fisher's Exact p (1-sided)   : {d1['fisher_exact_p_one_sided']:.6f} (Timid-Miss tail p={d1['fisher_exact_p_timid_miss']:.6f})",
        f"   - P(theta_live > theta_shadow) : {d1['posterior_prob_live_gt_shadow']*100:.2f}%",
        f"   - Posterior E[Delta_theta]     : {d1['posterior_mean_delta_theta']:+.4f} (90% HDI: [{d1['hdi_90'][0]:+.4f}, {d1['hdi_90'][1]:+.4f}])",
        f"   - Max Boundary Regret_R        : {d1['max_regret_r']:.4f}R (Worst Bucket: {d1['worst_regret_bucket']})",
    ]
    for b_name, b_info in d1["boundary_buckets"].items():
        lines.append(
            f"     * Bucket [{b_name:<18}] : N={b_info['sample_count']:<3} "
            f"(TP={b_info['tp_first_count']}, SL={b_info['sl_first_count']}) | "
            f"Mean_R={b_info['mean_shadow_r']:+.3f}R | Regret_R={b_info['regret_r']:.3f}R"
        )

    cr_str = f"{d2['mean_cr_mfe']*100:.2f}%" if d2["mean_cr_mfe"] is not None else "NULL (No Winning MFE>0)"
    ur_str = f"{d2['mean_ur_mae']*100:.2f}%" if d2["mean_ur_mae"] is not None else "NULL (No Losing MAE>0)"
    lines.extend(
        [
            "--------------------------------------------------------------------------------",
            " [診断2] 6段階ソフトラチェット ＆ 時間減衰SL MFE捕捉効率監査",
            f"   - Status                       : {d2['status']}",
            f"   - Closed Trades (Win / Loss)   : Total={d2['total_closed_trades']} (Win={d2['win_trades']}, Loss={d2['loss_trades']})",
            f"   - MFE Capture Efficiency CR_MFE: {cr_str} (Valid Wins={d2['cr_mfe_valid_count']})",
            f"   - Mean Profit Giveback GB_R    : {d2['mean_giveback_r']:.4f}R",
            f"   - Losing MAE Utilization UR_MAE: {ur_str}",
            f"   - +0.5R Reversal Loss Rate     : {d2['reversal_from_05r_rate']*100:.2f}% ({d2['reversal_from_05r_count']} / {d2['mfe_ge_05r_count']})",
            "--------------------------------------------------------------------------------",
            " [診断3] 手数料ドラッグ ＆ Maker `Alo` 約定率 (rho_maker) 監査",
            f"   - Maker Fill Ratio (rho_maker) : {d3['rho_maker']*100:.2f}% (Maker={d3['maker_fills']}, Taker={d3['taker_fills']}, Total={d3['total_fills']})",
            f"   - Effective Fee Rate           : {d3['effective_fee_bps']:.3f} bps ({d3['effective_fee_rate_pct']:.5f}%, Total Fee={d3['total_fee_usdc']:.6f} USDC)",
            f"   - Unfilled TTL Expired Orders  : {d3['expired_unfilled_count']} (Adverse Cancelled={d3['cancelled_adverse_count']})",
            f"   - ActionBudgetController (14d) : Vol_14d={d3['volume_14d_usdc']:.2f} USDC | Daily Budget={d3['action_budget']['daily_budget']} | Used={d3['action_budget']['actions_used_today']} | Remaining={d3['action_budget']['remaining_budget']} ({d3['action_budget']['utilization']*100:.1f}%)",
            "--------------------------------------------------------------------------------",
            " [診断4] 日本円税務台帳 (移動平均法 vs 総平均法) ＆ Forensic Ledger 監査",
            f"   - Status                       : {d4['status']} (Tax Year={d4['tax_year']}, Lots={d4['lot_count']})",
            f"   - ① 数量保存則                 : {'PASS' if d4['invariants']['check_1_quantity_conservation'] else 'FAIL'}",
            f"   - ② Token/USDC二重仕訳ペアリング: {'PASS' if d4['invariants']['check_2_dual_leg_pairing'] else 'FAIL'}",
            f"   - ③ TTM為替レート欠損ゼロ       : {'PASS' if d4['invariants']['check_3_zero_missing_ttm_rate'] else 'FAIL'}",
            f"   - ④ マイナス在庫 (Short Lot)ゼロ: {'PASS' if d4['invariants']['check_4_zero_negative_inventory'] else 'FAIL'}",
            f"   - ⑤ 在庫ゼロ通貨 移動/総平均一致: {'PASS' if d4['invariants']['check_5_zero_inventory_ma_vs_ta_match'] else 'FAIL'}",
            f"   - 移動平均法 実現損益合計 (JPY) : {d4['moving_average_total_pnl_jpy']:+,.2f} 円 (申告整数: {d4['moving_average_total_pnl_jpy_int']:+,d} 円)",
            f"   - 総平均法   試算損益合計 (JPY) : {d4['total_average_total_pnl_jpy']:+,.2f} 円 (試算整数: {d4['total_average_total_pnl_jpy_int']:+,d} 円)",
        ]
    )
    for asset, comp in d4["asset_pnl_comparison"].items():
        lines.append(
            f"     * Asset [{asset:<8}] : EndingQty={comp['ending_quantity']:.6f} | "
            f"MA_PnL={comp['moving_average_pnl_jpy']:+,.2f} JPY | "
            f"TA_PnL={comp['total_average_pnl_jpy']:+,.2f} JPY | "
            f"Diff={comp['abs_diff_jpy']:.4f} JPY"
        )
    if d4.get("exported_csv_path"):
        lines.append(f"   - Forensic Ledger CSV Exported : {d4['exported_csv_path']}")
    lines.append("================================================================================")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="HL AI Trader v1.2 Alpha-Max — Read-Only Post-Mortem Quant & Tax Forensic Audit Tool"
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_DB_PATH),
        help="Path to SQLite WAL database (default: data/hl_v1_state_wal.db)",
    )
    parser.add_argument(
        "--mc-samples",
        type=int,
        default=100_000,
        help="Monte Carlo sample count for Beta posterior inference (default: 100,000)",
    )
    parser.add_argument(
        "--export-csv",
        action="store_true",
        default=False,
        help="Export monthly audited tax lots to data/exports/forensic_ledger_export_YYYYMM.csv",
    )
    parser.add_argument(
        "--month",
        default=None,
        help="Target YYYYMM for CSV export (default: current JST YYYYMM)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Also output structured JSON report",
    )
    args = parser.parse_args(argv)

    report = run_full_postmortem_audit(
        db_path=args.db_path,
        mc_samples=args.mc_samples,
        export_csv=bool(args.export_csv),
        export_month=args.month,
    )
    print(format_postmortem_audit_report(report))
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
