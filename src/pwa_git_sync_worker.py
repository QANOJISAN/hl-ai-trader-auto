"""
HL AI Trader v1 — Zero-Knowledge Encrypted PWA Snapshot & GitHub Pages Auto-Push Worker
(src/pwa_git_sync_worker.py)

稼働中のメインデーモン (PID 2904) や保有ポジション監視を一切中断・再起動することなく、
毎時 08, 23, 38, 53分（GMO版の 02, 17, 32, 47分と完全非干渉）に:
1. SQLite WAL 台帳 + Hyperliquid Mainnet `/info` から最新ステータス・含み損益・4時間足ローソク足を取得
2. `AES-256-GCM` + `PBKDF2-SHA256` (150,000回) で完全暗号化した `docs/public_snapshot.json` を出力
3. 隔離 `.hl_gitconfig` 環境下で `docs/` のみを `origin main` (GitHub Pages) へ自動コミット＆Pushする。
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

sys.dont_write_bytecode = True
_ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from src.coordinator import ConcurrencyStateCoordinator
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.exchange_wrapper import HLSDKInfo, HyperliquidExchangeWrapper, MAINNET_API_URL
from src.main import HLTraderDaemon
from src.utils import (
    SecretScrubbingLogFilter,
    WindowsSingleInstanceGuard,
    enable_process_extension_point_mitigation,
    harden_windows_file_acl,
    install_egress_domain_whitelist_guard,
    load_safe_dotenv,
    now_jst,
    purge_dangerous_environment_variables,
    scrub_secret_text,
)
from src.web_server import (
    BASE_DIR,
    GIT_PUSH_OFFSET_MINUTES,
    ISOLATED_GITCONFIG_PATH,
    DashboardStateService,
    sync_and_push_docs_to_github,
)

logger = logging.getLogger("hl_pwa_git_sync")


def export_and_push_once() -> Dict[str, Any]:
    """
    最新の暗号化スナップショット (`docs/public_snapshot.json`) を生成し、
    `docs/` のみを GitHub Pages (`origin main`) へ自動Pushする。
    """
    purge_dangerous_environment_variables()
    enable_process_extension_point_mitigation()
    install_egress_domain_whitelist_guard()
    load_safe_dotenv(BASE_DIR / ".env")
    harden_windows_file_acl(BASE_DIR / ".env")
    harden_windows_file_acl(ISOLATED_GITCONFIG_PATH)
    harden_windows_file_acl(BASE_DIR / ".git" / "config")
    db = DatabaseManager()
    harden_windows_file_acl(db.db_path)
    try:
        coord = ConcurrencyStateCoordinator(db=db)
        tax = HyperliquidTaxEngine(db=db)
        info = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True) if HLSDKInfo is not None else None
        ex = HyperliquidExchangeWrapper(
            execution_mode="DRY_RUN",
            db=db,
            coordinator=coord,
            tax_engine=tax,
            info_client=info,
        )
        if ex.info is not None:
            try:
                ex.refresh_universe_mapping()
            except Exception as exc:
                logger.debug("refresh_universe_mapping warning: %s", scrub_secret_text(exc))
        daemon = HLTraderDaemon(
            db=db,
            coordinator=coord,
            tax_engine=tax,
            exchange_wrapper=ex,
        )
        svc = DashboardStateService(
            db=db,
            tax_engine=tax,
            coordinator=coord,
            daemon=daemon,
        )
        snap_path = svc.export_public_snapshot()
        push_res = sync_and_push_docs_to_github(repo_dir=BASE_DIR)
        logger.info(
            "PWA暗号化スナップショット同期完了: path=%s | pushed=%s",
            snap_path.name,
            push_res.get("pushed"),
        )
        return {
            "ok": bool(push_res.get("ok", True)),
            "snapshot_path": str(snap_path),
            "push_result": push_res,
        }
    finally:
        db.close()


def _init_logger() -> None:
    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_dir / "hl_pwa_git_sync.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    handler.addFilter(SecretScrubbingLogFilter())
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)


def run_sync_loop(poll_interval_sec: float = 20.0) -> None:
    """
    毎時 08, 23, 38, 53分 に `export_and_push_once()` を実行する常駐ワーカー。
    起動直後にも1回即時同期を実行する。
    WindowsSingleInstanceGuard により多重起動を100%防止する。
    """
    _init_logger()
    sync_guard = WindowsSingleInstanceGuard(
        mutex_name=r"Global\HL_AI_TRADER_V1_PWA_SYNC_MUTEX",
        lock_file_path=BASE_DIR / "data" / "hl_v1_pwa_sync.lock",
    )
    if not sync_guard.acquire():
        logger.info("PWA Git Sync Worker は既に別プロセスで稼働中のため正常終了します。")
        return

    try:
        logger.info(
            "PWA GitHub Pages 自動Pushワーカー起動: 対象分=%s",
            GIT_PUSH_OFFSET_MINUTES,
        )
        last_bucket: Optional[Tuple[int, int, int, int]] = None

        try:
            export_and_push_once()
        except Exception as exc:
            logger.warning("初回PWA同期警告: %s", scrub_secret_text(exc))

        while True:
            try:
                cur_jst = now_jst()
                bucket = (cur_jst.year, cur_jst.month, cur_jst.day, cur_jst.hour * 60 + cur_jst.minute)
                if cur_jst.minute in GIT_PUSH_OFFSET_MINUTES and bucket != last_bucket:
                    res = export_and_push_once()
                    if res.get("ok"):
                        last_bucket = bucket
            except Exception as exc:
                logger.warning("PWA定時同期ループ警告: %s", scrub_secret_text(exc))
            time.sleep(max(5.0, float(poll_interval_sec)))
    finally:
        sync_guard.release()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HL AI Trader v1 — PWA Encrypted Snapshot Git Sync Worker")
    parser.add_argument("--once", action="store_true", help="Export and push once then exit")
    args = parser.parse_args()
    if args.once:
        _init_logger()
        result = export_and_push_once()
        print(result, flush=True)
    else:
        run_sync_loop()
