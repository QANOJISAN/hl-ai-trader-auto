"""
HL AI Trader v1 — Non-Interfering Safe Process Watchdog (watchdog.py)

絶対遵守仕様 (ARCHITECTURE.md Section 1):
- `PYTHONDONTWRITEBYTECODE=1` (`sys.dont_write_bytecode = True`) を強制
- `taskkill /IM python.exe` のような全体終了コマンドは絶対に使用しない
- 対象PIDが `e:/hl-ai-trader-auto` のプロセスであり、`e:/gmo-ai-trader-auto` でないことを
  `verify_target_process_identity` で厳密に確認した上でのみプロセス制御を行う
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PYTHONUTF8"] = "1"

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("GIT_CONFIG_GLOBAL", str(BASE_DIR / ".hl_gitconfig"))

from src.utils import hidden_subprocess_kwargs, verify_target_process_identity

logger = logging.getLogger("hl_watchdog")

LOCK_FILE = BASE_DIR / "data" / "hl_v1_daemon.lock"


def resolve_venv_python(base_dir: Path = BASE_DIR) -> str:
    """
    `e:/hl-ai-trader-auto/.venv/Scripts/python.exe` を最優先で解決し、
    存在しない場合のみ現在の `sys.executable` にフォールバックする。
    """
    venv_py = base_dir / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def build_isolated_process_env(base_dir: Path = BASE_DIR) -> Dict[str, str]:
    """
    子プロセス起動用の隔離環境変数を構築する。
    - `PYTHONDONTWRITEBYTECODE=1`
    - `PYTHONUTF8=1`
    - `GIT_CONFIG_GLOBAL=<base_dir>/.hl_gitconfig`
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUTF8"] = "1"
    env["GIT_CONFIG_GLOBAL"] = str(base_dir / ".hl_gitconfig")
    return env


def read_recorded_daemon_pid(lock_file: Path = LOCK_FILE) -> Optional[int]:
    """`hl_v1_daemon.lock` から記録されたデーモンPIDを読み取る"""
    if not lock_file.exists():
        return None
    try:
        data = json.loads(lock_file.read_text(encoding="utf-8"))
        pid = int(data.get("pid", 0))
        return pid if pid > 0 else None
    except Exception:
        return None


def is_hl_daemon_alive(lock_file: Path = LOCK_FILE) -> bool:
    """記録されたPIDが生存しており、かつ確実に `hl-ai-trader-auto` のプロセスであるか検証する"""
    pid = read_recorded_daemon_pid(lock_file)
    if pid is None:
        return False
    return verify_target_process_identity(
        pid=pid,
        expected_keyword="hl-ai-trader-auto",
        forbidden_keyword="gmo-ai-trader-auto",
    )


def is_port_listening(host: str = "127.0.0.1", port: int = 8081, timeout_sec: float = 1.5) -> bool:
    """Port 8081 (HL専用Webダッシュボード) がリッスン中か非破壊で確認する（Port 8080 には一切触れない）"""
    if int(port) == 8080:
        raise ValueError("Port 8080 は GMO AI Trader 専用のため HL Watchdog からの操作・監視対象外です。")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_sec):
            return True
    except OSError:
        return False


def terminate_only_verified_hl_pid(pid: int) -> bool:
    """
    指定されたPIDが `hl-ai-trader-auto` であり `gmo-ai-trader-auto` でないことを
    厳密に検証した場合に限り、その単一PIDのみを安全に終了する。
    `taskkill /IM python.exe` は一切使用しない。
    """
    if not verify_target_process_identity(
        pid=pid,
        expected_keyword="hl-ai-trader-auto",
        forbidden_keyword="gmo-ai-trader-auto",
    ):
        logger.warning("PID %d は hl-ai-trader-auto と一致しないため終了操作を拒否しました。", pid)
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except Exception as exc:
        logger.error("PID %d の終了失敗: %s", pid, exc)
        return False


def spawn_hl_daemon(
    base_dir: Path = BASE_DIR,
    host: str = "127.0.0.1",
    port: int = 8081,
    paused: bool = False,
) -> int:
    """
    `src/main.py` を完全非表示（CREATE_NO_WINDOW）・独立プロセスとして起動する。
    """
    py_exe = resolve_venv_python(base_dir)
    main_script = str(base_dir / "src" / "main.py")
    cmd: List[str] = [py_exe, "-B", main_script, "--host", str(host), "--port", str(port)]
    if paused:
        cmd.append("--paused")
    else:
        cmd.append("--live")

    hidden_kw = hidden_subprocess_kwargs()
    if os.name == "nt":
        CREATE_NO_WINDOW = 0x08000000
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        hidden_kw["creationflags"] = int(hidden_kw.get("creationflags", CREATE_NO_WINDOW)) | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(
        cmd,
        cwd=str(base_dir),
        env=build_isolated_process_env(base_dir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **hidden_kw,
    )
    logger.info("HLTraderDaemon を起動しました: PID=%d cmd=%s", proc.pid, " ".join(cmd))
    return int(proc.pid)


def ensure_daemon_running(
    base_dir: Path = BASE_DIR,
    lock_file: Path = LOCK_FILE,
    host: str = "127.0.0.1",
    port: int = 8081,
    paused: bool = False,
    startup_wait_sec: float = 8.0,
) -> Dict[str, Any]:
    """
    `HLTraderDaemon` の生存および Port 8081 の応答を確認し、停止していれば自動再起動する。
    """
    import time

    alive = is_hl_daemon_alive(lock_file)
    listening = is_port_listening(host=host, port=port)
    rec_pid = read_recorded_daemon_pid(lock_file)

    if alive and listening:
        return {
            "status": "HEALTHY",
            "action": "NONE",
            "pid": rec_pid,
            "port_listening": True,
        }

    if alive and not listening:
        # 起動直後の過渡状態の可能性があるため少し待機して再確認
        time.sleep(3.0)
        if is_port_listening(host=host, port=port):
            return {
                "status": "HEALTHY",
                "action": "NONE",
                "pid": rec_pid,
                "port_listening": True,
            }
        if rec_pid is not None:
            logger.warning("PID %d は生存していますが Port %d が無応答のため再起動します。", rec_pid, port)
            terminate_only_verified_hl_pid(rec_pid)
            time.sleep(1.5)

    new_pid = spawn_hl_daemon(base_dir=base_dir, host=host, port=port, paused=paused)
    deadline = time.time() + max(1.0, float(startup_wait_sec))
    while time.time() < deadline:
        if is_hl_daemon_alive(lock_file) and is_port_listening(host=host, port=port):
            break
        time.sleep(0.5)

    return {
        "status": "STARTED",
        "action": "SPAWNED_DAEMON",
        "pid": read_recorded_daemon_pid(lock_file) or new_pid,
        "port_listening": is_port_listening(host=host, port=port),
    }


if __name__ == "__main__":
    import argparse
    import time
    from logging.handlers import RotatingFileHandler
    from src.utils import SecretScrubbingLogFilter, WindowsSingleInstanceGuard

    parser = argparse.ArgumentParser(description="HL AI Trader v1 — Safe Process Watchdog")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--paused", action="store_true", default=False)
    parser.add_argument("--once", action="store_true", default=False, help="Run a single health check and exit")
    parser.add_argument("--interval", type=float, default=30.0, help="Watchdog loop interval in seconds")
    args = parser.parse_args()

    log_dir = BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    wd_log = log_dir / "watchdog.log"
    fh = RotatingFileHandler(wd_log, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    fh.addFilter(SecretScrubbingLogFilter())
    logger.setLevel(logging.INFO)
    logger.addHandler(fh)

    # まず1回即時ヘルスチェック＆必要に応じたデーモン起動を実施
    first_res = ensure_daemon_running(
        base_dir=BASE_DIR,
        lock_file=LOCK_FILE,
        host=args.host,
        port=args.port,
        paused=args.paused,
    )
    logger.info("Watchdog 初回チェック完了: %s", first_res)

    if args.once:
        sys.exit(0)

    wd_guard = WindowsSingleInstanceGuard(
        mutex_name=r"Global\HL_AI_TRADER_V1_WATCHDOG_MUTEX",
        lock_file_path=BASE_DIR / "data" / "hl_v1_watchdog.lock",
    )
    if not wd_guard.acquire():
        logger.info("常駐 Watchdog は既に別プロセスで稼働中のため正常終了します。")
        sys.exit(0)

    try:
        logger.info("Watchdog 常駐監視ループを開始します (PID=%d, interval=%.1fs)", os.getpid(), args.interval)
        while True:
            time.sleep(max(5.0, float(args.interval)))
            try:
                res = ensure_daemon_running(
                    base_dir=BASE_DIR,
                    lock_file=LOCK_FILE,
                    host=args.host,
                    port=args.port,
                    paused=args.paused,
                )
                if res.get("action") != "NONE":
                    logger.info("Watchdog 自動復旧実行: %s", res)
            except Exception as exc:
                logger.error("Watchdog 監視ループ例外: %s", exc)
    finally:
        wd_guard.release()

