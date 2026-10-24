"""
HL AI Trader v1 — Core Utilities (src/utils.py)

実装機能:
1. WindowsSingleInstanceGuard:
   - Windows Kernel Named Mutex (`Global\\HL_AI_TRADER_V1_MAIN_MUTEX`) による二重起動完全防止
   - PID・コマンドラインパス検証（Watchdog制御時も `taskkill /IM python.exe` は絶対に使用せず対象PIDのみを識別）
2. MonotonicHyperliquidNonceManager:
   - 時刻ドリフト（NTP逆行）耐性・マルチスレッド安全性を備えた単調増加ミリ秒Nonce生成器
3. Decimal 厳密丸め関数:
   - `round_price`: 有効数字最大5桁 かつ 小数点以下最大 `(8 - szDecimals)` 桁で `ROUND_DOWN` 切り捨て
   - `floor_size`: `szDecimals` 桁で `ROUND_DOWN` 切り捨て
4. PersistentHTTPSession:
   - `requests.Session` Keep-Aliveコネクションプール再利用による `TIME_WAIT` ポート枯渇防止
5. UsdcJpyRateFetcher:
   - USDC/JPY 為替レートの3段フェイルオーバー取得器（Tier 1: 暗号資産API ➔ Tier 2: 為替API ➔ Tier 3: DBキャッシュ/初期値）
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

JST = timezone(timedelta(hours=9))
_CA_BUNDLE_LOCK = threading.Lock()
_COMBINED_CA_BUNDLE_PATH: Optional[str] = None


def ensure_windows_ca_bundle(
    output_path: Optional[Union[str, Path]] = None,
) -> Optional[str]:
    """
    Windows 環境において Python の `certifi` バンドルと OS 標準証明書ストア (`ROOT`, `CA`) を結合した
    CA 証明書バンドルファイルを生成し、`certifi` / `requests` のデフォルト CA パスおよび `SSL_CERT_FILE` に設定する。
    (※ `REQUESTS_CA_BUNDLE` 環境変数はプロセス環境変数汚染防止ポリシーに従い設定しない)
    これにより SSL 検証を一切無効化することなく、`SSLCertVerificationError` を根絶する。
    """
    global _COMBINED_CA_BUNDLE_PATH
    with _CA_BUNDLE_LOCK:
        if _COMBINED_CA_BUNDLE_PATH and Path(_COMBINED_CA_BUNDLE_PATH).exists() and output_path is None:
            os.environ.setdefault("SSL_CERT_FILE", _COMBINED_CA_BUNDLE_PATH)
            return _COMBINED_CA_BUNDLE_PATH

        try:
            import certifi

            base_pem = Path(certifi.where()).read_text(encoding="utf-8")
        except Exception:
            base_pem = ""

        pem_blocks: List[str] = [base_pem] if base_pem else []
        if os.name == "nt" and hasattr(ssl, "enum_certificates"):
            seen_der: Set[bytes] = set()
            for store_name in ("ROOT", "CA"):
                try:
                    for cert_bytes, encoding, _trust in ssl.enum_certificates(store_name):
                        if encoding == "x509_asn" and cert_bytes not in seen_der:
                            seen_der.add(cert_bytes)
                            pem_blocks.append(ssl.DER_cert_to_PEM_cert(cert_bytes))
                except Exception as exc:
                    logger.debug("Windows 証明書ストア (%s) 読み取りスキップ: %s", store_name, exc)

        if not pem_blocks:
            return None

        target = (
            Path(output_path)
            if output_path is not None
            else (Path(__file__).resolve().parent.parent / "data" / "hl_combined_cacert.pem")
        )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists() or target.stat().st_size < len(base_pem):
                target.write_text("\n".join(pem_blocks), encoding="utf-8")
            resolved = str(target)
            _COMBINED_CA_BUNDLE_PATH = resolved
            os.environ["SSL_CERT_FILE"] = resolved
            os.environ.pop("REQUESTS_CA_BUNDLE", None)
            try:
                import certifi as _certifi_mod

                _certifi_mod.where = lambda: resolved  # type: ignore[assignment]
                requests.utils.DEFAULT_CA_BUNDLE_PATH = resolved  # type: ignore[attr-defined]
                requests.adapters.DEFAULT_CA_BUNDLE_PATH = resolved  # type: ignore[attr-defined]
            except Exception:
                pass
            return resolved
        except Exception as exc:
            logger.debug("結合CAバンドル書き出しスキップ: %s", exc)
            return None


# モジュールロード時にCAバンドル環境変数を初期化
ensure_windows_ca_bundle()

# Windows API 定数
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_AWAYMODE_REQUIRED = 0x00000040
ES_KEEP_AWAKE_FLAGS = ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED

# 同一プロセス内でのNamed Mutex重複取得追跡セット
_PROCESS_ACTIVE_MUTEXES: Set[str] = set()
_PROCESS_MUTEX_LOCK = threading.Lock()


class SingleInstanceAlreadyRunningError(RuntimeError):
    """既に同一Mutexを持つ HL AI Trader v1 インスタンスが稼働中の場合に送出される例外"""


class NonceDriftError(RuntimeError):
    """Hyperliquid L1 の許容Nonceウィンドウ (-2日 〜 +1日) を逸脱した場合に送出される例外"""


def now_ms() -> int:
    """現在時刻のUNIXタイムスタンプ（ミリ秒）を返す"""
    return int(time.time() * 1000)


def now_jst(dt: Optional[datetime] = None) -> datetime:
    """現在時刻（または指定日時）をJSTタイムゾーン付きdatetimeで返す"""
    if dt is None:
        return datetime.now(JST)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=JST)
    return dt.astimezone(JST)


def jst_date_str(timestamp_ms: Optional[int] = None) -> str:
    """ミリ秒タイムスタンプからJSTの日付文字列 (YYYY-MM-DD) を返す"""
    ts = timestamp_ms if timestamp_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    return dt.strftime("%Y-%m-%d")


def jst_tax_year(timestamp_ms: Optional[int] = None) -> int:
    """ミリ秒タイムスタンプから日本の課税年度（暦年: 1月1日〜12月31日 JST）を返す"""
    ts = timestamp_ms if timestamp_ms is not None else now_ms()
    dt = datetime.fromtimestamp(ts / 1000.0, tz=JST)
    return int(dt.year)


def generate_cloid() -> str:
    """Hyperliquid 注文用の16バイト Client Order ID (`0x` + 32桁hex文字列) を生成する"""
    return "0x" + uuid.uuid4().hex


def prevent_windows_sleep() -> bool:
    """
    Windows API `SetThreadExecutionState` を呼び出し、常駐稼働中のOSスリープ移行を抑止する。
    """
    try:
        if os.name == "nt" and hasattr(ctypes, "windll"):
            res = ctypes.windll.kernel32.SetThreadExecutionState(ES_KEEP_AWAKE_FLAGS)
            return bool(res != 0)
    except Exception as exc:
        logger.debug("SetThreadExecutionState 呼び出しスキップ: %s", exc)
    return False


def _is_windows_pid_alive(pid: int) -> bool:
    if pid <= 0 or os.name != "nt" or not hasattr(ctypes, "windll"):
        return False
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    kernel32 = ctypes.windll.kernel32
    h_proc = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not h_proc:
        return False
    try:
        exit_code = ctypes.c_ulong(0)
        if kernel32.GetExitCodeProcess(h_proc, ctypes.byref(exit_code)):
            return int(exit_code.value) == STILL_ACTIVE
        return False
    finally:
        kernel32.CloseHandle(h_proc)


def _read_windows_process_peb_strings(pid: int) -> str:
    """
    外部プロセス (powershell.exe / wmic.exe) を一切起動せず、Win32 API (`QueryFullProcessImageNameW`
    および `NtQueryInformationProcess` + `ReadProcessMemory`) のみを用いてインプロセスで
    対象PIDの実行パス・コマンドライン引数・カレントディレクトリを取得する。
    """
    if pid <= 0 or os.name != "nt" or not hasattr(ctypes, "windll"):
        return ""
    if int(pid) == os.getpid():
        return f"{sys.executable} {' '.join(sys.argv)} {os.getcwd()}"

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    kernel32 = ctypes.windll.kernel32
    parts: List[str] = []

    # 1. QueryFullProcessImageNameW によるイメージパス取得
    h_info = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if h_info:
        try:
            buf_len = ctypes.c_ulong(4096)
            buf = ctypes.create_unicode_buffer(4096)
            if kernel32.QueryFullProcessImageNameW(h_info, 0, buf, ctypes.byref(buf_len)):
                if buf.value:
                    parts.append(buf.value)
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(h_info)

    # 2. 64bit PEB RTL_USER_PROCESS_PARAMETERS から CommandLine と CurrentDirectory を直接読み取る
    h_vm = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if h_vm:
        try:
            class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p),
                ]

            class _UNICODE_STRING(ctypes.Structure):
                _fields_ = [
                    ("Length", ctypes.c_ushort),
                    ("MaximumLength", ctypes.c_ushort),
                    ("Reserved", ctypes.c_ulong),
                    ("Buffer", ctypes.c_void_p),
                ]

            pbi = _PROCESS_BASIC_INFORMATION()
            ret_len = ctypes.c_ulong(0)
            ntdll = ctypes.windll.ntdll
            status = ntdll.NtQueryInformationProcess(
                h_vm, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            if status == 0 and pbi.PebBaseAddress:
                proc_params_ptr = ctypes.c_void_p(0)
                bytes_read = ctypes.c_size_t(0)
                # 64bit PEB offset 0x20 = ProcessParameters
                if kernel32.ReadProcessMemory(
                    h_vm,
                    ctypes.c_void_p(int(pbi.PebBaseAddress) + 0x20),
                    ctypes.byref(proc_params_ptr),
                    ctypes.sizeof(proc_params_ptr),
                    ctypes.byref(bytes_read),
                ) and proc_params_ptr.value:
                    # offset 0x38 = CurrentDirectory.DosPath, offset 0x70 = CommandLine
                    for offset in (0x38, 0x70):
                        ustr = _UNICODE_STRING()
                        if kernel32.ReadProcessMemory(
                            h_vm,
                            ctypes.c_void_p(int(proc_params_ptr.value) + offset),
                            ctypes.byref(ustr),
                            ctypes.sizeof(ustr),
                            ctypes.byref(bytes_read),
                        ) and ustr.Length > 0 and ustr.Buffer:
                            char_count = min(4096, int(ustr.Length) // 2)
                            str_buf = ctypes.create_unicode_buffer(char_count + 1)
                            if kernel32.ReadProcessMemory(
                                h_vm,
                                ctypes.c_void_p(int(ustr.Buffer)),
                                str_buf,
                                char_count * 2,
                                ctypes.byref(bytes_read),
                            ):
                                val = str_buf.value
                                if val:
                                    parts.append(val)
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(h_vm)

    # 3. ロックファイル (hl_v1_daemon.lock / hl_v1_watchdog.lock / hl_v1_pwa_sync.lock) の照合補完
    base_data_dir = Path(__file__).resolve().parent.parent / "data"
    for lock_name in ("hl_v1_daemon.lock", "hl_v1_watchdog.lock", "hl_v1_pwa_sync.lock"):
        lp = base_data_dir / lock_name
        if lp.exists():
            try:
                lock_obj = json.loads(lp.read_text(encoding="utf-8"))
                if int(lock_obj.get("pid", -1)) == int(pid):
                    argv_str = " ".join(str(x) for x in (lock_obj.get("argv") or []))
                    cwd_str = str(lock_obj.get("cwd") or "")
                    exe_str = str(lock_obj.get("executable") or "")
                    parts.extend([exe_str, argv_str, cwd_str])
            except Exception:
                pass

    return " ".join(p for p in parts if p)


def verify_target_process_identity(
    pid: int,
    expected_keyword: str = "hl-ai-trader-auto",
    forbidden_keyword: str = "gmo-ai-trader-auto",
) -> bool:
    """
    指定されたPIDが本当に `hl-ai-trader-auto` のプロセスであり、
    `gmo-ai-trader-auto` 等の他プロセスでないことをコマンドライン引数・作業ディレクトリから厳密に検証する。
    (※ 外部 powershell.exe の起動は行わず、100% インプロセス Win32 API で高速・無窓検証する)
    """
    if pid <= 0:
        return False
    exp_norm = expected_keyword.lower().replace("\\", "/")
    forb_norm = forbidden_keyword.lower().replace("\\", "/")
    try:
        import psutil

        if not psutil.pid_exists(pid):
            return False
        proc = psutil.Process(pid)
        cmdline = " ".join(proc.cmdline()).lower().replace("\\", "/")
        cwd = ""
        try:
            cwd = proc.cwd().lower().replace("\\", "/")
        except Exception:
            pass
        combined = f"{cmdline} {cwd}"
        if forb_norm in combined:
            return False
        if exp_norm in combined:
            return True
        return False
    except ImportError:
        if os.name != "nt" or not _is_windows_pid_alive(pid):
            return False
        try:
            combined = _read_windows_process_peb_strings(int(pid)).strip().lower().replace("\\", "/")
            if not combined:
                return False
            if forb_norm in combined:
                return False
            return exp_norm in combined
        except Exception as exc:
            logger.warning("Windows インプロセスPID検証中に例外が発生しました (pid=%s): %s", pid, exc)
            return False
    except Exception as exc:
        logger.warning("PID検証中に例外が発生しました (pid=%s): %s", pid, exc)
        return False


class WindowsSingleInstanceGuard:
    """
    Windows Kernel Named Mutex (`Global\\HL_AI_TRADER_V1_MAIN_MUTEX`) と
    PID・コマンドライン記録ファイルを併用した単一インスタンス保護ガード。
    """

    DEFAULT_MUTEX_NAME = r"Global\HL_AI_TRADER_V1_MAIN_MUTEX"

    def __init__(
        self,
        mutex_name: str = DEFAULT_MUTEX_NAME,
        lock_file_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.mutex_name = mutex_name
        self.effective_mutex_name = mutex_name
        self.lock_file_path = (
            Path(lock_file_path)
            if lock_file_path is not None
            else Path("e:/hl-ai-trader-auto/data/hl_v1_daemon.lock")
        )
        self._mutex_handle: Optional[int] = None
        self.acquired: bool = False

    def acquire(self, raise_on_failure: bool = False) -> bool:
        """
        Named Mutex を取得する。既に他のインスタンス（または同一プロセス内の別ガード）が
        保持している場合は False を返す（raise_on_failure=True の場合は例外を送出）。
        """
        if self.acquired:
            return True

        with _PROCESS_MUTEX_LOCK:
            if self.mutex_name in _PROCESS_ACTIVE_MUTEXES:
                if raise_on_failure:
                    raise SingleInstanceAlreadyRunningError(
                        f"同一プロセス内で既に Named Mutex '{self.mutex_name}' が保持されています。"
                    )
                return False

            if os.name == "nt" and hasattr(ctypes, "windll"):
                kernel32 = ctypes.windll.kernel32
                kernel32.SetLastError(0)
                handle = kernel32.CreateMutexW(None, True, self.mutex_name)
                last_err = kernel32.GetLastError()

                # セッション権限により Global\ 名前空間が拒否された場合は Local\ へ安全にフォールバック
                if not handle and last_err == ERROR_ACCESS_DENIED and self.mutex_name.startswith("Global\\"):
                    fallback_name = "Local\\" + self.mutex_name[len("Global\\") :]
                    kernel32.SetLastError(0)
                    handle = kernel32.CreateMutexW(None, True, fallback_name)
                    last_err = kernel32.GetLastError()
                    self.effective_mutex_name = fallback_name

                if not handle:
                    if raise_on_failure:
                        raise SingleInstanceAlreadyRunningError(
                            f"CreateMutexW 失敗 (mutex={self.effective_mutex_name}, err={last_err})"
                        )
                    return False

                if last_err == ERROR_ALREADY_EXISTS:
                    # 既に存在する場合、放棄されたMutex(WAIT_ABANDONED)でないか0ms待機で確認
                    wait_res = kernel32.WaitForSingleObject(handle, 0)
                    if wait_res not in (WAIT_OBJECT_0, WAIT_ABANDONED):
                        kernel32.CloseHandle(handle)
                        if raise_on_failure:
                            raise SingleInstanceAlreadyRunningError(
                                f"既に別プロセスが Named Mutex '{self.effective_mutex_name}' を保持しています。"
                            )
                        return False
                    # 同一スレッドによる再入で WAIT_OBJECT_0 が返った場合も ERROR_ALREADY_EXISTS なら拒否
                    kernel32.ReleaseMutex(handle)
                    kernel32.CloseHandle(handle)
                    if raise_on_failure:
                        raise SingleInstanceAlreadyRunningError(
                            f"既に Named Mutex '{self.effective_mutex_name}' が存在します。"
                        )
                    return False

                self._mutex_handle = int(handle)

            _PROCESS_ACTIVE_MUTEXES.add(self.mutex_name)
            self.acquired = True
            self._write_pid_metadata()
            return True

    def _write_pid_metadata(self) -> None:
        """現在のPIDとコマンドラインパスをロックメタデータファイルへ記録する"""
        try:
            self.lock_file_path.parent.mkdir(parents=True, exist_ok=True)
            metadata = {
                "pid": os.getpid(),
                "mutex_name": self.effective_mutex_name,
                "executable": sys.executable,
                "argv": sys.argv,
                "cwd": os.getcwd(),
                "acquired_at_ms": now_ms(),
            }
            self.lock_file_path.write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.debug("PIDメタデータの書き込みをスキップしました: %s", exc)

    def release(self) -> None:
        """保持している Named Mutex を解放し、ハンドルを閉じる"""
        with _PROCESS_MUTEX_LOCK:
            if not self.acquired:
                return
            if os.name == "nt" and self._mutex_handle is not None and hasattr(ctypes, "windll"):
                try:
                    kernel32 = ctypes.windll.kernel32
                    kernel32.ReleaseMutex(self._mutex_handle)
                    kernel32.CloseHandle(self._mutex_handle)
                except Exception as exc:
                    logger.debug("Named Mutex 解放時エラー: %s", exc)
                finally:
                    self._mutex_handle = None
            _PROCESS_ACTIVE_MUTEXES.discard(self.mutex_name)
            self.acquired = False
            try:
                if self.lock_file_path.exists():
                    self.lock_file_path.unlink()
            except Exception:
                pass

    def __enter__(self) -> "WindowsSingleInstanceGuard":
        self.acquire(raise_on_failure=True)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


class WindowsHighResTimer:
    """
    Windows のマルチメディアタイマー分解能をデフォルトの 15.625ms から 1ms へ引き上げ、
    `asyncio.sleep(0.200)` の200msガーディアン周期ジッター（203〜218ms膨張）を排除するコンテキストマネージャ。
    """

    def __init__(self, period_ms: int = 1) -> None:
        self.period_ms = max(1, int(period_ms))
        self.active: bool = False

    def start(self) -> bool:
        if self.active:
            return True
        try:
            if os.name == "nt" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "winmm"):
                res = ctypes.windll.winmm.timeBeginPeriod(self.period_ms)
                if res == 0:
                    self.active = True
                    return True
        except Exception as exc:
            logger.debug("timeBeginPeriod(%d) 呼び出しスキップ: %s", self.period_ms, exc)
        return False

    def stop(self) -> None:
        if not self.active:
            return
        try:
            if os.name == "nt" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "winmm"):
                ctypes.windll.winmm.timeEndPeriod(self.period_ms)
        except Exception as exc:
            logger.debug("timeEndPeriod(%d) 呼び出しスキップ: %s", self.period_ms, exc)
        finally:
            self.active = False

    def __enter__(self) -> "WindowsHighResTimer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()


class MonotonicHyperliquidNonceManager:
    """
    Hyperliquid `/exchange` 署名用の単調増加ミリ秒Nonce生成器 (`MonotonicNonceGenerator`)。
    - 200ms高速ガーディアンと15秒ループ・15分AIループが同時に署名を行っても、
      またNTP時刻同期でOS時計が数ミリ秒〜数秒逆行しても、常に `last_nonce + 1` 以上の
      厳密な単調増加整数 `n_t = max(int(time.time()*1000) + server_time_offset_ms, n_{t-1} + 1)` をスレッドセーフに返す。
    - Hyperliquid L1 の Nonce 許容窓 (T_block - 2日, T_block + 1日) に対するドリフト検証も行う。
    """

    MAX_FORWARD_DRIFT_MS = 80_000_000   # +22.2時間 (L1上限 +24h に対する安全マージン)
    WARN_FORWARD_DRIFT_MS = 300_000     # +5分以上の先行ドリフトで警告
    MAX_BACKWARD_DRIFT_MS = 160_000_000 # -44.4時間 (L1下限 -48h に対する安全マージン)

    def __init__(
        self,
        initial_nonce: Optional[int] = None,
        server_time_offset_ms: int = 0,
    ) -> None:
        self._lock = threading.Lock()
        self._last_nonce: int = int(initial_nonce) if initial_nonce is not None else 0
        self.server_time_offset_ms: int = int(server_time_offset_ms)
        self._drift_warnings: int = 0

    @property
    def last_nonce(self) -> int:
        with self._lock:
            return self._last_nonce

    def update_server_offset(self, server_time_ms: int, local_time_ms: Optional[int] = None) -> int:
        """サーバー時刻とのオフセット `delta_t_srv = server_time_ms - local_time_ms` を更新する"""
        loc = int(local_time_ms) if local_time_ms is not None else now_ms()
        with self._lock:
            self.server_time_offset_ms = int(server_time_ms) - loc
            return self.server_time_offset_ms

    def next_nonce(self, current_time_ms: Optional[int] = None) -> int:
        """
        スレッドセーフに次の単調増加ミリ秒Nonceを発行する。
        """
        with self._lock:
            wall_ms = (
                int(current_time_ms)
                if current_time_ms is not None
                else (now_ms() + self.server_time_offset_ms)
            )
            candidate = max(wall_ms, self._last_nonce + 1)
            forward_drift = candidate - wall_ms
            if forward_drift > self.MAX_FORWARD_DRIFT_MS:
                raise NonceDriftError(
                    f"Nonceがシステム時刻より {forward_drift}ms 先行し、Hyperliquid L1上限(+1日)に接近しています。"
                )
            if forward_drift > self.WARN_FORWARD_DRIFT_MS:
                self._drift_warnings += 1
                logger.warning(
                    "システム時計の逆行または高頻度発火により Nonce が実時刻より %dms 先行しています (candidate=%d, wall=%d)",
                    forward_drift,
                    candidate,
                    wall_ms,
                )
            self._last_nonce = candidate
            return candidate

    def generate(self, current_time_ms: Optional[int] = None) -> int:
        """`next_nonce` のエイリアス"""
        return self.next_nonce(current_time_ms=current_time_ms)


MonotonicNonceGenerator = MonotonicHyperliquidNonceManager


def _to_clean_decimal(val: Union[float, int, str, Decimal]) -> Decimal:
    """浮動小数点の2進表現誤差を排除して Decimal に変換する"""
    if isinstance(val, Decimal):
        return val
    if isinstance(val, int):
        return Decimal(val)
    if isinstance(val, float):
        # float の場合は有効桁15桁の文字列経由で丸め誤差を除去
        return Decimal(f"{val:.15g}")
    raw = str(val).strip()
    if not raw:
        raise ValueError("空文字列はDecimalへ変換できません")
    try:
        return Decimal(raw)
    except InvalidOperation as exc:
        raise ValueError(f"不正な数値表現です: {val!r}") from exc


def format_decimal_plain(d: Decimal) -> str:
    """
    指数表記を一切使わず、小数点以下の不要な末尾ゼロのみを除去した文字列を返す。
    例:
      Decimal('12340.00') -> '12340'
      Decimal('25.43200') -> '25.432'
      Decimal('0.00012300') -> '0.000123'
      Decimal('0.0') -> '0'
    """
    if d == 0:
        return "0"
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s if s and s != "-0" else "0"


def round_price(
    px: Union[float, int, str, Decimal],
    sz_decimals: int,
    rounding: str = ROUND_DOWN,
) -> str:
    """
    Hyperliquid Spot の価格ティック規則に従い、
    1. 有効数字最大 5 桁 (5 significant figures)
    2. 小数点以下最大 `(8 - sz_decimals)` 桁
    の双方を同時に満たすよう `Decimal` (`ROUND_DOWN`) で厳密に切り捨てた文字列を返す。
    """
    d = _to_clean_decimal(px)
    if d <= 0:
        return "0"

    max_dec = max(0, 8 - int(sz_decimals))
    # 最上位桁の指数 mag (例: 25.432 -> mag=1, 0.00123 -> mag=-3, 105439.9 -> mag=5)
    mag = d.adjusted()
    # 有効数字5桁の最小桁指数 = mag - 4, 小数点以下制約の最小桁指数 = -max_dec
    target_exp = max(mag - 4, -max_dec)
    quantum = Decimal(f"1e{target_exp}")
    rounded = d.quantize(quantum, rounding=rounding)
    return format_decimal_plain(rounded)


def floor_size(
    sz: Union[float, int, str, Decimal],
    sz_decimals: int,
) -> str:
    """
    Hyperliquid Spot の数量規則に従い、対象トークンの `sz_decimals` 桁で
    `Decimal` (`ROUND_DOWN`) 切り捨てを行った文字列を返す。
    """
    d = _to_clean_decimal(sz)
    if d <= 0:
        return "0"

    max_dec = max(0, int(sz_decimals))
    quantum = Decimal(f"1e-{max_dec}")
    floored = d.quantize(quantum, rounding=ROUND_DOWN)
    return format_decimal_plain(floored)


def create_keep_alive_session(
    pool_connections: int = 16,
    pool_maxsize: int = 32,
    max_retries: int = 2,
    timeout_sec: float = 10.0,
) -> requests.Session:
    """
    Windows での高頻度ポーリング時に TIME_WAIT エフェメラルポート枯渇を防ぐための
    永続的 HTTP Keep-Alive セッションを生成する。
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        backoff_factor=0.2,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update(
        {
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=60, max=1000",
            "User-Agent": "HL-AI-Trader-v1/1.0 (Keep-Alive)",
        }
    )
    # デフォルトタイムアウトおよび結合CA証明書バンドルを設定
    ca_bundle = ensure_windows_ca_bundle()
    if ca_bundle:
        session.verify = ca_bundle
    session.request_timeout = timeout_sec  # type: ignore[attr-defined]
    return session


class PersistentHTTPSession:
    """
    スレッドセーフな永続的 HTTP Keep-Alive セッションラッパー。
    """

    def __init__(
        self,
        pool_connections: int = 16,
        pool_maxsize: int = 32,
        timeout_sec: float = 10.0,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.session: requests.Session = create_keep_alive_session(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            timeout_sec=timeout_sec,
        )

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout_sec)
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout_sec)
        return self.session.post(url, **kwargs)

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass


class UsdcJpyRateFetcher:
    """
    税務台帳（円換算損益）およびWeb UI表示用の USDC/JPY レート3段フェイルオーバー取得器。

    フェイルオーバー順序:
      - Tier 1 (Primary): CoinGecko API (`usd-coin` ➔ `jpy`) または GMO Public Ticker
      - Tier 2 (Secondary): Open Exchange Rates (`open.er-api.com`) または Frankfurter (`api.frankfurter.app`)
      - Tier 3 (Tertiary / Fallback): SQLite `system_state_store.latest_usdc_jpy_rate` キャッシュ または デフォルト値 (155.0)
    """

    MIN_SANITY_RATE = 80.0
    MAX_SANITY_RATE = 300.0

    def __init__(
        self,
        default_rate: float = 155.0,
        cache_ttl_sec: float = 300.0,
        http_session: Optional[PersistentHTTPSession] = None,
        db_rate_provider: Optional[Callable[[], Optional[float]]] = None,
        tier1_fetcher: Optional[Callable[[], Optional[Tuple[float, str]]]] = None,
        tier2_fetcher: Optional[Callable[[], Optional[Tuple[float, str]]]] = None,
    ) -> None:
        self.default_rate = float(default_rate)
        self.cache_ttl_sec = float(cache_ttl_sec)
        self.http = http_session or PersistentHTTPSession(timeout_sec=5.0)
        self.db_rate_provider = db_rate_provider
        self._custom_tier1 = tier1_fetcher
        self._custom_tier2 = tier2_fetcher

        self._lock = threading.Lock()
        self._cached_rate: Optional[float] = None
        self._cached_source: str = "UNINITIALIZED"
        self._cached_at_sec: float = 0.0

    @classmethod
    def _is_sane_rate(cls, rate: Optional[float]) -> bool:
        if rate is None:
            return False
        try:
            r = float(rate)
            return cls.MIN_SANITY_RATE <= r <= cls.MAX_SANITY_RATE
        except (TypeError, ValueError):
            return False

    def _fetch_tier1(self) -> Optional[Tuple[float, str]]:
        """Tier 1: 暗号資産 USDC/JPY ダイレクトレート取得"""
        if self._custom_tier1 is not None:
            return self._custom_tier1()
        if "PYTEST_CURRENT_TEST" in os.environ:
            return None

        # 1a. CoinGecko usd-coin -> jpy
        try:
            resp = self.http.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={"ids": "usd-coin", "vs_currencies": "jpy"},
                timeout=4.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                rate = float(data.get("usd-coin", {}).get("jpy", 0.0))
                if self._is_sane_rate(rate):
                    return (rate, "TIER1_COINGECKO_USDC_JPY")
        except Exception as exc:
            logger.debug("Tier 1a (CoinGecko) 取得失敗: %s", exc)

        # 1b. Bitbank / GMO Public API フォールバック
        try:
            resp = self.http.get(
                "https://api.coin.z.com/public/v1/ticker",
                params={"symbol": "USDC_JPY"},
                timeout=4.0,
            )
            if resp.status_code == 200:
                body = resp.json()
                rows = body.get("data") or []
                if rows and "last" in rows[0]:
                    rate = float(rows[0]["last"])
                    if self._is_sane_rate(rate):
                        return (rate, "TIER1_GMO_PUBLIC_USDC_JPY")
        except Exception as exc:
            logger.debug("Tier 1b (GMO Public) 取得失敗: %s", exc)

        return None

    def _fetch_tier2(self) -> Optional[Tuple[float, str]]:
        """Tier 2: グローバル外国為替 USD/JPY API 取得"""
        if self._custom_tier2 is not None:
            return self._custom_tier2()
        if "PYTEST_CURRENT_TEST" in os.environ:
            return None

        # 2a. Open ER API
        try:
            resp = self.http.get("https://open.er-api.com/v6/latest/USD", timeout=4.0)
            if resp.status_code == 200:
                data = resp.json()
                rate = float(data.get("rates", {}).get("JPY", 0.0))
                if self._is_sane_rate(rate):
                    return (rate, "TIER2_OPEN_ER_USD_JPY")
        except Exception as exc:
            logger.debug("Tier 2a (open.er-api) 取得失敗: %s", exc)

        # 2b. Frankfurter API (ECB基準)
        try:
            resp = self.http.get(
                "https://api.frankfurter.app/latest",
                params={"from": "USD", "to": "JPY"},
                timeout=4.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                rate = float(data.get("rates", {}).get("JPY", 0.0))
                if self._is_sane_rate(rate):
                    return (rate, "TIER2_FRANKFURTER_USD_JPY")
        except Exception as exc:
            logger.debug("Tier 2b (Frankfurter) 取得失敗: %s", exc)

        return None

    def _fetch_tier3(self) -> Tuple[float, str]:
        """Tier 3: SQLite キャッシュ値 または メモリ直近値 または 設定デフォルト値"""
        if self.db_rate_provider is not None:
            try:
                db_rate = self.db_rate_provider()
                if self._is_sane_rate(db_rate):
                    return (float(db_rate), "TIER3_SQLITE_CACHE")  # type: ignore[arg-type]
            except Exception as exc:
                logger.debug("Tier 3 (DBキャッシュ) 取得失敗: %s", exc)

        if self._is_sane_rate(self._cached_rate):
            return (float(self._cached_rate), "TIER3_MEMORY_CACHE")  # type: ignore[arg-type]

        return (self.default_rate, "TIER3_DEFAULT_STATIC")

    def get_rate(self, force_refresh: bool = False) -> Tuple[float, str]:
        """
        USDC/JPY レートと取得元ソース名 `(rate, source)` を返す。
        TTL内の場合はメモリキャッシュを即座に返す。
        """
        now_sec = time.monotonic()
        with self._lock:
            if (
                not force_refresh
                and self._cached_rate is not None
                and (now_sec - self._cached_at_sec) < self.cache_ttl_sec
            ):
                return (self._cached_rate, self._cached_source)

        # Tier 1 試行
        try:
            t1 = self._fetch_tier1()
            if t1 is not None and self._is_sane_rate(t1[0]):
                with self._lock:
                    self._cached_rate = float(t1[0])
                    self._cached_source = str(t1[1])
                    self._cached_at_sec = time.monotonic()
                return (float(t1[0]), str(t1[1]))
        except Exception as exc:
            logger.debug("Tier 1 例外: %s", exc)

        # Tier 2 試行
        try:
            t2 = self._fetch_tier2()
            if t2 is not None and self._is_sane_rate(t2[0]):
                with self._lock:
                    self._cached_rate = float(t2[0])
                    self._cached_source = str(t2[1])
                    self._cached_at_sec = time.monotonic()
                return (float(t2[0]), str(t2[1]))
        except Exception as exc:
            logger.debug("Tier 2 例外: %s", exc)

        # Tier 3 フォールバック
        t3_rate, t3_source = self._fetch_tier3()
        with self._lock:
            self._cached_rate = float(t3_rate)
            self._cached_source = str(t3_source)
            self._cached_at_sec = time.monotonic()
        return (float(t3_rate), str(t3_source))


# ==============================================================================
# 6. 64bit Windows DPAPI (`Crypt32.dll`) 暗号化エンジン・Layer 7〜10 インプロセス装甲化
# ==============================================================================
import base64 as _base64
import hashlib as _hashlib
import hmac as _hmac
import ipaddress as _ipaddress
import re as _re
import shutil as _shutil
import socket as _socket
import subprocess as _subprocess
from ctypes import wintypes as _wintypes

try:
    import winreg as _winreg
except ImportError:
    _winreg = None  # type: ignore[assignment]

CRYPTPROTECT_UI_FORBIDDEN = 0x01
CRYPTPROTECTMEMORY_BLOCK_SIZE = 16
CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00
PROCESS_EXTENSION_POINT_DISABLE_POLICY = 6

DPAPI_CUSTOM_ENTROPY_SALT = b"HL_AI_TRADER_V1_2_ALPHA_MAX_DPAPI_ENTROPY_V1"
DPAPI_APP_ENTROPY = DPAPI_CUSTOM_ENTROPY_SALT
DPAPI_CUSTOM_ENTROPY_ITERATIONS = 100_000
_CACHED_DPAPI_ENTROPY: Optional[bytes] = None
_DPAPI_ENTROPY_LOCK = threading.RLock()
DEFAULT_CODE_INTEGRITY_SEAL_PATH = Path(__file__).resolve().parent.parent / "data" / "code_integrity.seal"
_CODE_SEAL_TLS = threading.local()


class DATA_BLOB(ctypes.Structure):
    """64bit Windows Crypt32 DATA_BLOB 構造体"""

    _fields_ = [
        ("cbData", _wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


if os.name == "nt":
    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        _wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        _wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptProtectData.restype = _wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.POINTER(_wintypes.LPWSTR),
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        _wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    _crypt32.CryptUnprotectData.restype = _wintypes.BOOL

    if hasattr(_crypt32, "CryptProtectMemory"):
        _crypt32.CryptProtectMemory.argtypes = [
            ctypes.c_void_p,
            _wintypes.DWORD,
            _wintypes.DWORD,
        ]
        _crypt32.CryptProtectMemory.restype = _wintypes.BOOL

    if hasattr(_crypt32, "CryptUnprotectMemory"):
        _crypt32.CryptUnprotectMemory.argtypes = [
            ctypes.c_void_p,
            _wintypes.DWORD,
            _wintypes.DWORD,
        ]
        _crypt32.CryptUnprotectMemory.restype = _wintypes.BOOL

    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p

    _kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualLock.restype = _wintypes.BOOL

    _kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    _kernel32.VirtualUnlock.restype = _wintypes.BOOL

    if hasattr(_kernel32, "IsDebuggerPresent"):
        _kernel32.IsDebuggerPresent.argtypes = []
        _kernel32.IsDebuggerPresent.restype = _wintypes.BOOL

    if hasattr(_kernel32, "SetProcessMitigationPolicy"):
        _kernel32.SetProcessMitigationPolicy.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        _kernel32.SetProcessMitigationPolicy.restype = _wintypes.BOOL

_LOG_PRIVATE_KEY_RE = _re.compile(r"0x[0-9a-fA-F]{64}")
_LOG_GEMINI_KEY_RE = _re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
_LOG_GITHUB_PAT_RE = _re.compile(r"(?:ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,})")
_LOG_WEBHOOK_RE = _re.compile(
    r"https?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)/[^\s\"']+",
    _re.IGNORECASE,
)
_ENV_SECRET_KEYS = (
    "HL_AGENT_PRIVATE_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "DISCORD_WEBHOOK_URL",
    "APP_LOCK_PASSWORD",
    "GITHUB_PUSH_TOKEN",
)
_REQUIRED_DOTENV_DPAPI_KEYS = (
    "HL_AGENT_PRIVATE_KEY",
    "GEMINI_API_KEY",
    "DISCORD_WEBHOOK_URL",
    "APP_LOCK_PASSWORD",
    "GITHUB_PUSH_TOKEN",
)
_CACHED_DOTENV_SECRETS: Optional[List[str]] = None
_RUNTIME_REGISTERED_SECRETS: Set[str] = set()
_DOTENV_SECRETS_LOCK = threading.RLock()


# ==============================================================================
# Layer 8: Win32 VirtualLock + CryptProtectMemory セキュアバッファ ＆ 拡張ポイント緩和策
# ==============================================================================
class SecureByteBuffer:
    """
    Layer 8: Win32 `VirtualLock` / `VirtualUnlock` により `pagefile.sys` へのスワップアウトを禁止し、
    `CryptProtectMemory` によるインプロセス暗号化保護および `__exit__` 時の確実な `ctypes.memset(0)` ゼロ消去を行う
    セキュアメモリバッファ・コンテキストマネージャ。
    """

    def __init__(self, initial: Union[bytes, bytearray, memoryview, int]) -> None:
        if isinstance(initial, int):
            raw_b = b""
            req_size = max(1, int(initial))
        else:
            raw_b = bytes(initial)
            req_size = max(1, len(raw_b))

        self.size: int = len(raw_b) if not isinstance(initial, int) else int(initial)
        # CryptProtectMemory (16バイト境界) に対応するアライメント長
        self.allocated_size: int = max(
            CRYPTPROTECTMEMORY_BLOCK_SIZE,
            ((req_size + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) // CRYPTPROTECTMEMORY_BLOCK_SIZE)
            * CRYPTPROTECTMEMORY_BLOCK_SIZE,
        )
        self._buf = (ctypes.c_char * self.allocated_size)()
        self.ptr: int = ctypes.addressof(self._buf)
        self.locked: bool = False
        self.encrypted_in_memory: bool = False
        self.is_zeroed: bool = False

        if os.name == "nt":
            try:
                self.locked = bool(_kernel32.VirtualLock(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.allocated_size)))
            except Exception:
                self.locked = False

        if raw_b:
            ctypes.memmove(ctypes.c_void_p(self.ptr), raw_b, len(raw_b))

    @property
    def buffer(self) -> ctypes.Array[ctypes.c_char]:
        return self._buf

    def write_from_pointer(self, src_ptr: Any, length: int) -> None:
        n = min(max(0, int(length)), self.allocated_size)
        if n > 0 and src_ptr:
            ctypes.memmove(ctypes.c_void_p(self.ptr), src_ptr, n)
            self.size = n
            self.is_zeroed = False

    def raw_bytes(self) -> bytes:
        if self.size <= 0:
            return b""
        return ctypes.string_at(ctypes.c_void_p(self.ptr), self.size)

    def snapshot_allocated_bytes(self) -> bytes:
        return ctypes.string_at(ctypes.c_void_p(self.ptr), self.allocated_size)

    def protect(self) -> bool:
        ok = protect_in_process_memory(self)
        if ok:
            self.encrypted_in_memory = True
        return ok

    def unprotect(self) -> bool:
        ok = unprotect_in_process_memory(self)
        if ok:
            self.encrypted_in_memory = False
        return ok

    def zero_fill(self) -> None:
        if self.ptr and self.allocated_size > 0:
            ctypes.memset(ctypes.c_void_p(self.ptr), 0, self.allocated_size)
            self.is_zeroed = True
            self.encrypted_in_memory = False

    def close(self) -> None:
        self.zero_fill()
        if os.name == "nt" and self.locked and self.ptr:
            try:
                _kernel32.VirtualUnlock(ctypes.c_void_p(self.ptr), ctypes.c_size_t(self.allocated_size))
            except Exception:
                pass
            self.locked = False

    def __enter__(self) -> "SecureByteBuffer":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def protect_in_process_memory(buf: Union[SecureByteBuffer, ctypes.Array[Any], bytearray]) -> bool:
    """
    Windows `crypt32.CryptProtectMemory` (`CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00`) を呼び出し、
    16バイト境界のメモリバッファをカーネルセッション鍵でインプレース暗号化する。
    """
    if os.name != "nt" or not hasattr(_crypt32, "CryptProtectMemory"):
        return False
    if isinstance(buf, SecureByteBuffer):
        ptr = ctypes.c_void_p(buf.ptr)
        cb = buf.allocated_size
        return bool(_crypt32.CryptProtectMemory(ptr, _wintypes.DWORD(cb), _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS)))
    if isinstance(buf, bytearray):
        if len(buf) == 0 or len(buf) % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0:
            raise ValueError(f"CryptProtectMemory buffer size must be a multiple of {CRYPTPROTECTMEMORY_BLOCK_SIZE}")
        c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return bool(
            _crypt32.CryptProtectMemory(
                ctypes.cast(c_arr, ctypes.c_void_p),
                _wintypes.DWORD(len(buf)),
                _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS),
            )
        )
    cb_len = ctypes.sizeof(buf)
    if cb_len == 0 or cb_len % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0:
        raise ValueError(f"CryptProtectMemory buffer size must be a multiple of {CRYPTPROTECTMEMORY_BLOCK_SIZE}")
    return bool(
        _crypt32.CryptProtectMemory(
            ctypes.cast(buf, ctypes.c_void_p),
            _wintypes.DWORD(cb_len),
            _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS),
        )
    )


def unprotect_in_process_memory(buf: Union[SecureByteBuffer, ctypes.Array[Any], bytearray]) -> bool:
    """
    Windows `crypt32.CryptUnprotectMemory` (`CRYPTPROTECTMEMORY_SAME_PROCESS = 0x00`) を呼び出し、
    インプレース暗号化された16バイト境界バッファを復号する。
    """
    if os.name != "nt" or not hasattr(_crypt32, "CryptUnprotectMemory"):
        return False
    if isinstance(buf, SecureByteBuffer):
        ptr = ctypes.c_void_p(buf.ptr)
        cb = buf.allocated_size
        return bool(
            _crypt32.CryptUnprotectMemory(ptr, _wintypes.DWORD(cb), _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS))
        )
    if isinstance(buf, bytearray):
        if len(buf) == 0 or len(buf) % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0:
            raise ValueError(f"CryptUnprotectMemory buffer size must be a multiple of {CRYPTPROTECTMEMORY_BLOCK_SIZE}")
        c_arr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return bool(
            _crypt32.CryptUnprotectMemory(
                ctypes.cast(c_arr, ctypes.c_void_p),
                _wintypes.DWORD(len(buf)),
                _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS),
            )
        )
    cb_len = ctypes.sizeof(buf)
    if cb_len == 0 or cb_len % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0:
        raise ValueError(f"CryptUnprotectMemory buffer size must be a multiple of {CRYPTPROTECTMEMORY_BLOCK_SIZE}")
    return bool(
        _crypt32.CryptUnprotectMemory(
            ctypes.cast(buf, ctypes.c_void_p),
            _wintypes.DWORD(cb_len),
            _wintypes.DWORD(CRYPTPROTECTMEMORY_SAME_PROCESS),
        )
    )


def enable_process_extension_point_mitigation() -> bool:
    """
    Layer 8: Win32 `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy = 6)` を有効化し、
    AppInit_DLLs やグローバルWin32フック経由の拡張ポイントDLLインジェクションを遮断する。
    """
    if os.name != "nt" or not hasattr(_kernel32, "SetProcessMitigationPolicy"):
        return False
    try:
        policy_flags = _wintypes.DWORD(0x01)  # DisableExtensionPoints = 1
        res = _kernel32.SetProcessMitigationPolicy(
            ctypes.c_int(PROCESS_EXTENSION_POINT_DISABLE_POLICY),
            ctypes.byref(policy_flags),
            ctypes.c_size_t(ctypes.sizeof(policy_flags)),
        )
        return bool(res != 0)
    except Exception:
        return False


# ==============================================================================
# Layer 7: DPAPI カスタム Entropy (MachineGuid + アプリ固有ソルト) ＆ 呼び出し元検証
# ==============================================================================
def get_machine_guid() -> str:
    """
    Windows レジストリ `HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid` からマシン固有GUIDを取得する。
    """
    if os.name == "nt" and _winreg is not None:
        try:
            access = _winreg.KEY_READ | getattr(_winreg, "KEY_WOW64_64KEY", 0x0100)
            with _winreg.OpenKey(
                _winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                access,
            ) as key:
                val, _ = _winreg.QueryValueEx(key, "MachineGuid")
                if val and str(val).strip():
                    return str(val).strip()
        except Exception:
            pass
    return f"FALLBACK-GUID-{uuid.getnode()}"


def get_dpapi_custom_entropy() -> bytes:
    """
    Layer 7: `MachineGuid` とアプリケーション固有ソルト `DPAPI_CUSTOM_ENTROPY_SALT` を結合し、
    `PBKDF2-HMAC-SHA256` (100,000回反復) で導出した 32バイトのカスタム Entropy 鍵を返す。
    これにより、万一同一ユーザー権限の汎用 Infostealer が `CryptUnprotectData(..., pOptionalEntropy=NULL)`
    を実行しても復号は100%失敗する。
    """
    global _CACHED_DPAPI_ENTROPY
    with _DPAPI_ENTROPY_LOCK:
        if _CACHED_DPAPI_ENTROPY is not None:
            return _CACHED_DPAPI_ENTROPY
        guid_str = get_machine_guid()
        derived = _hashlib.pbkdf2_hmac(
            "sha256",
            guid_str.encode("utf-8"),
            DPAPI_CUSTOM_ENTROPY_SALT,
            DPAPI_CUSTOM_ENTROPY_ITERATIONS,
            dklen=32,
        )
        _CACHED_DPAPI_ENTROPY = derived
        return derived


def _check_is_debugger_present() -> bool:
    """Win32 `kernel32.IsDebuggerPresent()` によるデバッガアタッチ検出"""
    if os.name == "nt" and hasattr(_kernel32, "IsDebuggerPresent"):
        try:
            return bool(_kernel32.IsDebuggerPresent() != 0)
        except Exception:
            return False
    return False


_PROJECT_ROOT_NORM = str(Path(__file__).resolve().parent.parent).lower()
_TRUSTED_RUNTIME_PREFIXES: Tuple[str, ...] = tuple(
    dict.fromkeys(
        str(Path(p).resolve()).lower()
        for p in (
            Path(__file__).resolve().parent.parent,
            Path(sys.prefix),
            Path(sys.base_prefix),
            Path(os.__file__).resolve().parent,
        )
        if p
    )
)


def _verify_trusted_dpapi_caller() -> None:
    """
    Layer 7: DPAPI 復号・暗号化呼び出し時のインプロセス検証ガード:
    1) `IsDebuggerPresent()` が非ゼロの場合は `PermissionError` で即座に拒否。
    2) `sys.gettrace()` が有効（かつ `pytest` 実行時でない）場合は `PermissionError` で拒否。
    3) `sys._getframe()` でコールスタックを走査し、プロジェクトルート (`E:\\hl-ai-trader-auto`) または
       Python標準ライブラリ / `.venv` 以外の不審な外部パスからの呼び出しフレームが存在する場合は
       `PermissionError` で復号を遮断する。
    """
    if _check_is_debugger_present():
        raise PermissionError("DPAPI access denied: Debugger detected (IsDebuggerPresent != 0)")

    is_pytest_active = ("pytest" in sys.modules) or ("PYTEST_CURRENT_TEST" in os.environ)
    if sys.gettrace() is not None and not is_pytest_active:
        raise PermissionError("DPAPI access denied: Active trace/debugger hook detected (sys.gettrace)")

    depth = 1
    has_trusted_project_or_cli_frame = False
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            break
        depth += 1

        raw_file = frame.f_code.co_filename or ""
        if not raw_file or raw_file.startswith("<frozen"):
            continue
        if raw_file in ("<string>", "<stdin>"):
            has_trusted_project_or_cli_frame = True
            continue
        if raw_file.startswith("<") and raw_file.endswith(">"):
            continue

        try:
            norm_path = str(Path(raw_file).resolve()).lower()
        except Exception:
            norm_path = raw_file.replace("/", "\\").lower()

        if norm_path.startswith(_PROJECT_ROOT_NORM):
            has_trusted_project_or_cli_frame = True
            continue

        if any(norm_path.startswith(prefix) for prefix in _TRUSTED_RUNTIME_PREFIXES):
            continue

        raise PermissionError(f"DPAPI access denied: Untrusted caller frame path '{raw_file}'")

    if not has_trusted_project_or_cli_frame:
        raise PermissionError("DPAPI access denied: No trusted project frame found in call stack")


def register_secret_for_scrubbing(secret_val: Optional[str]) -> None:
    """復号された機密文字列をスクラバーのマスク対象としてメモリ登録する"""
    if not secret_val:
        return
    s = str(secret_val).strip()
    if len(s) >= 4:
        with _DOTENV_SECRETS_LOCK:
            if len(_RUNTIME_REGISTERED_SECRETS) < 512:
                _RUNTIME_REGISTERED_SECRETS.add(s)


def dpapi_encrypt_str(
    plaintext: str,
    use_custom_entropy: bool = True,
    force_reencrypt: bool = False,
) -> str:
    """
    UTF-8バイト列を 64bit Windows DPAPI (`CryptProtectData`, `CRYPTPROTECT_UI_FORBIDDEN = 0x01`) +
    Layer 7 カスタム Entropy (`pOptionalEntropy`) で暗号化し、
    `"DPAPI:" + base64.b64encode(cipher_bytes).decode("ascii")` を返す。
    すでに `"DPAPI:"` で始まっている場合は `force_reencrypt=True` でない限り二重暗号化せずそのまま返す。
    """
    _verify_trusted_dpapi_caller()
    if plaintext is None:
        return ""
    s = str(plaintext).strip()
    if not s:
        return ""
    if s.startswith("DPAPI:"):
        if not force_reencrypt:
            return s
        s = dpapi_decrypt_str(s, allow_legacy_fallback=True)
        if not s:
            return ""
    register_secret_for_scrubbing(s)
    if os.name != "nt":
        raise RuntimeError("DPAPI encryption is only available on Windows.")

    raw_bytes = s.encode("utf-8")
    with SecureByteBuffer(raw_bytes) as sec_in:
        in_blob = DATA_BLOB(len(raw_bytes), ctypes.cast(ctypes.c_void_p(sec_in.ptr), ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()

        entropy_buf = None
        entropy_blob = DATA_BLOB()
        p_entropy = None
        if use_custom_entropy:
            ent_bytes = get_dpapi_custom_entropy()
            entropy_buf = ctypes.create_string_buffer(ent_bytes, len(ent_bytes))
            entropy_blob = DATA_BLOB(len(ent_bytes), ctypes.cast(entropy_buf, ctypes.POINTER(ctypes.c_char)))
            p_entropy = ctypes.byref(entropy_blob)

        try:
            ok = _crypt32.CryptProtectData(
                ctypes.byref(in_blob),
                "HL_AI_TRADER_V1_2_DPAPI_ENTROPY" if use_custom_entropy else "HL_AI_TRADER_V1_DPAPI",
                p_entropy,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
            if not ok:
                err_code = ctypes.GetLastError()
                raise OSError(f"CryptProtectData failed (winerror={err_code})")

            cipher_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            enc_str = "DPAPI:" + _base64.b64encode(cipher_bytes).decode("ascii")
            register_secret_for_scrubbing(enc_str)
            return enc_str
        finally:
            if entropy_buf is not None:
                ctypes.memset(ctypes.addressof(entropy_buf), 0, ctypes.sizeof(entropy_buf))
            if out_blob.pbData:
                if out_blob.cbData > 0:
                    ctypes.memset(out_blob.pbData, 0, int(out_blob.cbData))
                _kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
                out_blob.pbData = None


def can_decrypt_without_custom_entropy(dpapi_val: str) -> bool:
    """
    指定された `DPAPI:` 暗号文が `pOptionalEntropy = None` (Entropyなし) で復号できてしまうかどうかを検査する。
    Layer 7 カスタム Entropy 移行済みの場合は必ず `False` (復号拒否) を返す。
    """
    if not dpapi_val or not str(dpapi_val).strip().startswith("DPAPI:") or os.name != "nt":
        return False
    b64_part = str(dpapi_val).strip()[6:].strip()
    if not b64_part:
        return False
    try:
        cipher_bytes = _base64.b64decode(b64_part)
    except Exception:
        return False

    in_buf = ctypes.create_string_buffer(cipher_bytes, len(cipher_bytes))
    in_blob = DATA_BLOB(len(cipher_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()
    try:
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        return bool(ok and out_blob.pbData and out_blob.cbData > 0)
    finally:
        if out_blob.pbData:
            if out_blob.cbData > 0:
                ctypes.memset(out_blob.pbData, 0, int(out_blob.cbData))
            _kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
            out_blob.pbData = None


def dpapi_decrypt_str(
    val: str,
    allow_legacy_fallback: bool = True,
    require_custom_entropy: bool = False,
    _skip_seal_check: bool = False,
) -> str:
    """
    `"DPAPI:"` プレフィックスを持つ文字列を受け取り、まず Layer 7 カスタム Entropy (`pOptionalEntropy`) 付きで
    `CryptUnprotectData` を試行し、失敗した場合のみ（`allow_legacy_fallback=True` かつ `require_custom_entropy=False` の時）
    旧形式 (`pOptionalEntropy=None`) でフォールバック復号する。
    さらに `data/code_integrity.seal` が存在する場合はランタイムで SHA-256 + HMAC コード改ざんシールを検証し、
    1バイトでも改ざんがあれば `PermissionError` で秘密鍵の復号自体をハードロックする。
    復号されたネイティブバッファは `SecureByteBuffer` (`VirtualLock`) にコピー直後、即座に `ctypes.memset(0)` 消去＆ `LocalFree` する。
    """
    _verify_trusted_dpapi_caller()
    if val is None:
        return ""
    s = str(val).strip().strip("'\"")
    if not s:
        return ""
    if not s.startswith("DPAPI:"):
        register_secret_for_scrubbing(s)
        return s
    register_secret_for_scrubbing(s)
    if os.name != "nt":
        raise RuntimeError("DPAPI decryption is only available on Windows.")

    if (
        not _skip_seal_check
        and not getattr(_CODE_SEAL_TLS, "in_seal_check", False)
        and DEFAULT_CODE_INTEGRITY_SEAL_PATH.exists()
    ):
        verify_code_integrity_seal(DEFAULT_CODE_INTEGRITY_SEAL_PATH, raise_on_failure=True)

    b64_part = s[6:].strip()
    if not b64_part:
        return ""
    cipher_bytes = _base64.b64decode(b64_part)
    in_buf = ctypes.create_string_buffer(cipher_bytes, len(cipher_bytes))
    in_blob = DATA_BLOB(len(cipher_bytes), ctypes.cast(in_buf, ctypes.POINTER(ctypes.c_char)))
    out_blob = DATA_BLOB()

    ent_bytes = get_dpapi_custom_entropy()
    entropy_buf = ctypes.create_string_buffer(ent_bytes, len(ent_bytes))
    entropy_blob = DATA_BLOB(len(ent_bytes), ctypes.cast(entropy_buf, ctypes.POINTER(ctypes.c_char)))

    try:
        # 1. Layer 7 カスタム Entropy あり (v2) で復号試行
        ok = _crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            ctypes.byref(entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(out_blob),
        )
        # 2. 旧形式 (v1: Entropy なし) フォールバック
        if not ok and allow_legacy_fallback and not require_custom_entropy:
            ok = _crypt32.CryptUnprotectData(
                ctypes.byref(in_blob),
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(out_blob),
            )
        if not ok:
            err_code = ctypes.GetLastError()
            raise OSError(f"CryptUnprotectData failed (winerror={err_code})")

        cb_len = int(out_blob.cbData)
        with SecureByteBuffer(max(1, cb_len)) as sec_out:
            sec_out.write_from_pointer(out_blob.pbData, cb_len)
            # ネイティブバッファを即座にゼロ埋めしてから LocalFree
            if out_blob.pbData and cb_len > 0:
                ctypes.memset(out_blob.pbData, 0, cb_len)
            if out_blob.pbData:
                _kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
                out_blob.pbData = None

            plain_str = sec_out.raw_bytes().decode("utf-8")
            register_secret_for_scrubbing(plain_str)
            return plain_str
    finally:
        ctypes.memset(ctypes.addressof(entropy_buf), 0, ctypes.sizeof(entropy_buf))
        if out_blob.pbData:
            if out_blob.cbData > 0:
                ctypes.memset(out_blob.pbData, 0, int(out_blob.cbData))
            _kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
            out_blob.pbData = None


def migrate_dotenv_to_custom_entropy(
    dotenv_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    Layer 7: `.env` 内の機密5項目 (`HL_AGENT_PRIVATE_KEY`, `GEMINI_API_KEY`, `DISCORD_WEBHOOK_URL`,
    `APP_LOCK_PASSWORD`, `GITHUB_PUSH_TOKEN`) を旧形式 (Entropyなし) から新形式 (MachineGuid + Salt カスタムEntropy) へ
    インプロセスで再暗号化してアトミック更新する。
    - 移行前に `.env.dpapi_v1.bak` を作成し、同一の排他ACL (`harden_windows_file_acl`) を適用する。
    - 移行後に全項目の復号値一致、および `can_decrypt_without_custom_entropy(new_val) == False` を検証する。
    """
    global _CACHED_DOTENV_SECRETS
    target = Path(dotenv_path) if dotenv_path is not None else (Path(__file__).resolve().parent.parent / ".env")
    if not target.exists():
        raise FileNotFoundError(f".env file not found: {target}")

    bak_path = target.parent / ".env.dpapi_v1.bak"
    _shutil.copyfile(target, bak_path)
    harden_windows_file_acl(bak_path, force=True)

    original_text = target.read_text(encoding="utf-8", errors="ignore")
    lines = original_text.splitlines()
    new_lines: List[str] = []
    migrated_keys: List[str] = []
    already_custom_keys: List[str] = []

    for line in lines:
        s_line = line.strip()
        if not s_line or s_line.startswith("#") or "=" not in s_line:
            new_lines.append(line)
            continue

        k_part, v_part = line.split("=", 1)
        k_clean = k_part.strip()
        v_clean = v_part.strip().strip("'\"")

        if k_clean in _ENV_SECRET_KEYS and v_clean:
            plain_val = dpapi_decrypt_str(v_clean, allow_legacy_fallback=True)
            if not plain_val:
                new_lines.append(line)
                continue

            was_legacy = can_decrypt_without_custom_entropy(v_clean) if v_clean.startswith("DPAPI:") else True
            new_enc = dpapi_encrypt_str(plain_val, use_custom_entropy=True, force_reencrypt=True)

            # 検証1: カスタムEntropy必須モードで100%復号一致すること
            verified_plain = dpapi_decrypt_str(new_enc, allow_legacy_fallback=False, require_custom_entropy=True)
            if verified_plain != plain_val:
                raise RuntimeError(f"Custom entropy round-trip verification failed for {k_clean}")
            # 検証2: pOptionalEntropy=None では復号不能 (False) であること
            if can_decrypt_without_custom_entropy(new_enc):
                raise RuntimeError(f"Custom entropy enforcement check failed for {k_clean}")

            del plain_val
            del verified_plain
            new_lines.append(f"{k_clean}={new_enc}")
            if was_legacy:
                migrated_keys.append(k_clean)
            else:
                already_custom_keys.append(k_clean)
        else:
            new_lines.append(line)

    tmp_path = target.parent / ".env.custom_entropy.tmp"
    updated_content = "\n".join(new_lines) + ("\n" if original_text.endswith("\n") else "")
    tmp_path.write_text(updated_content, encoding="utf-8")
    harden_windows_file_acl(tmp_path, force=True)
    os.replace(tmp_path, target)
    harden_windows_file_acl(target, force=True)

    with _DOTENV_SECRETS_LOCK:
        _CACHED_DOTENV_SECRETS = None

    return {
        "ok": True,
        "migrated_keys": migrated_keys,
        "already_custom_keys": already_custom_keys,
        "backup_path": str(bak_path),
        "target_path": str(target),
    }


# ==============================================================================
# Layer 9: プロセス環境変数サニタイズ ＆ インプロセス Egress ドメイン・ホワイトリスト
# ==============================================================================
DANGEROUS_ENV_VARS_TO_PURGE: Tuple[str, ...] = (
    "SSLKEYLOGFILE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONPATH",
)

ALLOWED_EGRESS_DOMAINS: Tuple[str, ...] = (
    "api.hyperliquid.xyz",
    "hyperliquid.xyz",
    "generativelanguage.googleapis.com",
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "discord.com",
    "discordapp.com",
    "github.com",
    "api.github.com",
    "githubusercontent.com",
    "api.coingecko.com",
    "coingecko.com",
    "api.coin.z.com",
    "coin.z.com",
    "open.er-api.com",
    "er-api.com",
    "api.frankfurter.app",
    "frankfurter.app",
)

_EGRESS_GUARD_LOCK = threading.RLock()
_ORIGINAL_SOCKET_GETADDRINFO = _socket.getaddrinfo
_EGRESS_GUARD_INSTALLED: bool = False
try:
    _LOCAL_MACHINE_HOSTNAMES: Tuple[str, ...] = tuple(
        h.strip().lower()
        for h in (_socket.gethostname(), _socket.getfqdn())
        if h and h.strip()
    )
except Exception:
    _LOCAL_MACHINE_HOSTNAMES = ()


def purge_dangerous_environment_variables() -> List[str]:
    """
    Layer 9: プロセス起動時に TLS 鍵ダンプ・プロキシ横取り・CA偽装・スタートアップ注入に使われる
    危険な環境変数 (`SSLKEYLOGFILE`, `HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`, `PYTHONPATH` 等) を
    大小文字区別なしで `os.environ` から完全パージする。
    """
    target_upper = {k.upper() for k in DANGEROUS_ENV_VARS_TO_PURGE}
    purged: List[str] = []
    for env_k in list(os.environ.keys()):
        if env_k.upper() in target_upper:
            os.environ.pop(env_k, None)
            purged.append(env_k)
    return purged


def is_allowed_egress_host(host: Any) -> bool:
    """
    Layer 9: 指定されたホスト名またはIPがホワイトリストまたはローカルループバックに含まれるか判定する。
    """
    if host is None:
        return True
    if isinstance(host, bytes):
        try:
            host_str = host.decode("utf-8", errors="ignore")
        except Exception:
            return False
    else:
        host_str = str(host)

    h = host_str.strip().strip("[]").rstrip(".").lower()
    if not h:
        return True
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    if h in _LOCAL_MACHINE_HOSTNAMES:
        return True

    # IPリテラル指定時はローカルループバック・未指定ソケットのみ許可
    try:
        ip_obj = _ipaddress.ip_address(h.split("%")[0])
        return bool(ip_obj.is_loopback or ip_obj.is_unspecified)
    except ValueError:
        pass

    for dom in ALLOWED_EGRESS_DOMAINS:
        if h == dom or h.endswith("." + dom):
            return True
    return False


def install_egress_domain_whitelist_guard() -> bool:
    """
    Layer 9: `socket.getaddrinfo` をスレッドセーフかつ冪等にラップし、
    ホワイトリスト外の未知の外部ドメイン (例: `evil-exfil.example.com`) への名前解決を
    `PermissionError(f"Blocked unauthorized egress domain: {host}")` で即座に遮断する。
    """
    global _EGRESS_GUARD_INSTALLED
    with _EGRESS_GUARD_LOCK:
        if _EGRESS_GUARD_INSTALLED or getattr(_socket.getaddrinfo, "_hl_egress_guarded", False):
            _EGRESS_GUARD_INSTALLED = True
            return True

        orig_fn = _ORIGINAL_SOCKET_GETADDRINFO

        def _guarded_getaddrinfo(
            host: Any,
            port: Any,
            family: int = 0,
            type: int = 0,
            proto: int = 0,
            flags: int = 0,
        ) -> Any:
            if not is_allowed_egress_host(host):
                raise PermissionError(f"Blocked unauthorized egress domain: {host}")
            return orig_fn(host, port, family, type, proto, flags)

        setattr(_guarded_getaddrinfo, "_hl_egress_guarded", True)
        _socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
        _EGRESS_GUARD_INSTALLED = True
        return True


# ==============================================================================
# Layer 10: AI 三層記憶の不可視Unicode・プロンプトインジェクション無害化 ＆ HMAC 整合性検証
# ==============================================================================
_INVISIBLE_UNICODE_STRIP_RE = _re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    r"\u061c\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff"
    r"\U000e0000-\U000e007f]+"
)
_PROMPT_INJECTION_PATTERNS_RE = _re.compile(
    r"(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above)"
    r"|system\s+override"
    r"|developer\s+mode"
    r"|send\s+usdc\s+to(?:\s+0x[0-9a-fA-F]+)?"
    r"|approve_agent"
    r"|usd_class_transfer"
    r"|withdraw_from_bridge"
    r"|<\s*/?\s*system\s*>"
    r"|\[\s*/?\s*inst\s*\]"
    r"|<<\s*sys\s*>>"
    r")",
    _re.IGNORECASE,
)


def contains_invisible_or_injection_attack(text: Any) -> bool:
    """
    テキスト内に不可視Unicodeタグ文字 (`\\U000E0000`〜`\\U000E007F`)、双方向制御文字 (`\\u202A`〜`\\u202E`, `\\u2066`〜`\\u2069`)、
    ゼロ幅文字、またはプロンプトインジェクション定型句が含まれているかを検出する。
    """
    if text is None:
        return False
    s = str(text)
    if not s:
        return False
    if _INVISIBLE_UNICODE_STRIP_RE.search(s):
        return True
    if _PROMPT_INJECTION_PATTERNS_RE.search(s):
        return True
    return False


def sanitize_untrusted_text(text: Any, max_len: Optional[int] = None) -> str:
    """
    Layer 10: LLMプロンプトやSQLite三層記憶に入出力されるテキストから、
    1) Unicode Tags (`\\U000E0000`〜`\\U000E007F`)
    2) Bidi Control Characters (`\\u202A`〜`\\u202E`, `\\u2066`〜`\\u2069`, `\\u200E`, `\\u200F`, `\\u061C`)
    3) Zero-Width Characters (`\\u200B`〜`\\u200D`, `\\uFEFF`, `\\u2060`)
    4) ASCII / C1 Control Characters (`\\x00`〜`\\x1F`, `\\x7F`〜`\\x9F`)
    を完全ストリップし、さらに代表的なプロンプトインジェクション定型句を
    `[REDACTED_INJECTION_ATTEMPT]` に無害化する。
    """
    if text is None:
        return ""
    s = str(text)
    if not s:
        return ""
    # 改行・タブを空白に正規化した上で不可視制御文字・Unicodeタグを完全除去
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _INVISIBLE_UNICODE_STRIP_RE.sub("", s)
    s = _PROMPT_INJECTION_PATTERNS_RE.sub("[REDACTED_INJECTION_ATTEMPT]", s)
    s = _re.sub(r"\s{2,}", " ", s).strip()
    if max_len is not None and max_len > 0:
        return s[: int(max_len)]
    return s


def compute_memory_record_hmac(record_dict: Dict[str, Any]) -> str:
    """
    Layer 10: 三層記憶レコード辞書 (`ai_reflection_memory` / `ai_episodic_memory`) の内容を正規化し、
    MachineGuid 由来の 32バイト鍵で HMAC-SHA256 署名 (64桁hex) を算出する。
    """
    if not isinstance(record_dict, dict):
        raise TypeError("record_dict must be a dict")
    canonical_map: Dict[str, Any] = {}
    for k in sorted(record_dict.keys()):
        if k in ("record_hmac", "hmac_sig"):
            continue
        v = record_dict[k]
        if isinstance(v, float):
            canonical_map[str(k)] = f"{v:.8f}"
        elif v is None:
            canonical_map[str(k)] = None
        else:
            canonical_map[str(k)] = str(v)
    payload_bytes = json.dumps(canonical_map, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    key_bytes = get_dpapi_custom_entropy()
    return _hmac.new(key_bytes, payload_bytes, _hashlib.sha256).hexdigest()


def verify_memory_record_hmac(record_dict: Dict[str, Any], sig: Optional[str] = None) -> bool:
    """
    Layer 10: 三層記憶レコードの HMAC-SHA256 署名を定数時間比較 (`hmac.compare_digest`) で検証する。
    レコードが改ざんされている場合や署名が不正な場合は `False` を返す。
    """
    if not isinstance(record_dict, dict):
        return False
    candidate_sig = sig if sig is not None else str(record_dict.get("record_hmac") or record_dict.get("hmac_sig") or "")
    candidate_sig = candidate_sig.strip()
    if not candidate_sig:
        return False
    try:
        expected_sig = compute_memory_record_hmac(record_dict)
        return _hmac.compare_digest(expected_sig.encode("ascii"), candidate_sig.encode("ascii"))
    except Exception:
        return False


def is_memory_record_poisoned(record_dict: Dict[str, Any], require_hmac: bool = False) -> bool:
    """
    Layer 10: SQLite から読み出した三層記憶レコードについて、
    1) `record_hmac` / `hmac_sig` が付与されている場合（または `require_hmac=True` の場合）に HMAC 検証が失敗したか、
    2) 任意の文字列フィールドに不可視Unicodeタグ・Bidi文字またはプロンプトインジェクション定型句が含まれているか
    を判定し、汚染・改ざんレコードであれば `True` を返す。
    """
    if not isinstance(record_dict, dict):
        return True
    has_sig = bool(record_dict.get("record_hmac") or record_dict.get("hmac_sig"))
    if has_sig or require_hmac:
        if not verify_memory_record_hmac(record_dict):
            return True
    for k, v in record_dict.items():
        if k in ("record_hmac", "hmac_sig"):
            continue
        if isinstance(v, str) and contains_invisible_or_injection_attack(v):
            return True
    return False


# ==============================================================================
# Audit Round 15 (Tier-0 Addons):
# 1) SHA-256 + HMAC + DPAPI コード完全性改ざん検知シール (`seal_code_integrity_manifest` / `verify_code_integrity_seal`)
# 2) Hyperliquid L1 出金・送金アクションの宛先ピン留め遮断 (`verify_pinned_hl_action_destination`)
# ==============================================================================
def _collect_code_integrity_target_files(
    project_root: Optional[Union[str, Path]] = None,
) -> List[Tuple[str, Path]]:
    root = Path(project_root).resolve() if project_root is not None else Path(__file__).resolve().parent.parent
    src_dir = root / "src"
    targets: List[Path] = []
    if src_dir.exists():
        targets.extend(sorted(src_dir.glob("**/*.py")))
    watchdog_path = root / "watchdog.py"
    if watchdog_path.exists():
        targets.append(watchdog_path)

    pairs: List[Tuple[str, Path]] = []
    for p in targets:
        rel = str(p.relative_to(root)).replace("\\", "/")
        pairs.append((rel, p))
    pairs.sort(key=lambda x: x[0])
    return pairs


def _compute_code_integrity_hmac(files_map: Dict[str, str]) -> str:
    hmac_key = _hashlib.sha256(b"HL_CODE_SEAL_HMAC_V1::" + get_dpapi_custom_entropy()).digest()
    canonical = json.dumps(files_map, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _hmac.new(hmac_key, canonical, _hashlib.sha256).hexdigest()


def seal_code_integrity_manifest(
    seal_path: Optional[Union[str, Path]] = None,
    project_root: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """
    `src/*.py` および `watchdog.py` の SHA-256 ハッシュを計算し、
    `get_dpapi_custom_entropy()` 由来鍵で HMAC-SHA256 署名を付与したマニフェストを生成した上で、
    全体をカスタムEntropy付き `dpapi_encrypt_str()` で暗号化して `data/code_integrity.seal` に保存・排他ACLロックする。
    """
    target_seal = Path(seal_path) if seal_path is not None else DEFAULT_CODE_INTEGRITY_SEAL_PATH
    root = Path(project_root).resolve() if project_root is not None else Path(__file__).resolve().parent.parent

    files_map: Dict[str, str] = {}
    for rel, p in _collect_code_integrity_target_files(root):
        files_map[rel] = _hashlib.sha256(p.read_bytes()).hexdigest()

    hmac_sig = _compute_code_integrity_hmac(files_map)
    manifest: Dict[str, Any] = {
        "version": "1.0",
        "algorithm": "HMAC-SHA256+DPAPI",
        "project_root": str(root),
        "file_count": len(files_map),
        "files": files_map,
        "hmac_sha256": hmac_sig,
    }
    raw_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    encrypted_seal = dpapi_encrypt_str(raw_json, use_custom_entropy=True)

    target_seal.parent.mkdir(parents=True, exist_ok=True)
    tmp_seal = target_seal.with_suffix(".seal.tmp")
    tmp_seal.write_text(encrypted_seal, encoding="utf-8")
    harden_windows_file_acl(tmp_seal, force=True)
    os.replace(tmp_seal, target_seal)
    harden_windows_file_acl(target_seal, force=True)
    return manifest


def verify_code_integrity_seal(
    seal_path: Optional[Union[str, Path]] = None,
    raise_on_failure: bool = True,
    project_root: Optional[Union[str, Path]] = None,
) -> bool:
    """
    `data/code_integrity.seal` を復号・HMAC検証し、現在の `src/*.py` ＆ `watchdog.py` の
    SHA-256 ハッシュと照合する。1バイトでも不一致またはHMAC不正があれば
    `PermissionError("Code integrity seal verification failed")` を送出して遮断する。
    """
    target_seal = Path(seal_path) if seal_path is not None else DEFAULT_CODE_INTEGRITY_SEAL_PATH
    if not target_seal.exists():
        if seal_path is not None:
            if raise_on_failure:
                raise PermissionError("Code integrity seal verification failed: seal file does not exist")
            return False
        return True

    prev_flag = getattr(_CODE_SEAL_TLS, "in_seal_check", False)
    _CODE_SEAL_TLS.in_seal_check = True
    try:
        try:
            enc_text = target_seal.read_text(encoding="utf-8").strip()
            if not enc_text.startswith("DPAPI:"):
                raise ValueError("Seal payload is not DPAPI encrypted")
            dec_json = dpapi_decrypt_str(
                enc_text,
                allow_legacy_fallback=False,
                require_custom_entropy=True,
                _skip_seal_check=True,
            )
            manifest = json.loads(dec_json)
        except Exception as exc:
            if raise_on_failure:
                raise PermissionError(f"Code integrity seal verification failed: {exc}") from exc
            return False

        if not isinstance(manifest, dict):
            if raise_on_failure:
                raise PermissionError("Code integrity seal verification failed: invalid manifest format")
            return False

        files_map = manifest.get("files")
        saved_hmac = str(manifest.get("hmac_sha256") or "").strip()
        if not isinstance(files_map, dict) or not files_map or not saved_hmac:
            if raise_on_failure:
                raise PermissionError("Code integrity seal verification failed: empty files or missing HMAC")
            return False

        expected_hmac = _compute_code_integrity_hmac(files_map)
        if not _hmac.compare_digest(expected_hmac.encode("ascii"), saved_hmac.encode("ascii")):
            if raise_on_failure:
                raise PermissionError("Code integrity seal verification failed: HMAC signature mismatch")
            return False

        eff_root = (
            Path(project_root).resolve()
            if project_root is not None
            else Path(manifest.get("project_root") or Path(__file__).resolve().parent.parent).resolve()
        )
        current_files: Dict[str, str] = {}
        for rel, p in _collect_code_integrity_target_files(eff_root):
            current_files[rel] = _hashlib.sha256(p.read_bytes()).hexdigest()

        if current_files != files_map:
            if raise_on_failure:
                raise PermissionError("Code integrity seal verification failed: source file SHA-256 mismatch detected")
            return False

        return True
    finally:
        _CODE_SEAL_TLS.in_seal_check = prev_flag


_SAFE_HL_TRADING_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "order",
        "cancel",
        "cancelbycloid",
        "batchmodify",
        "modify",
        "schedulecancel",
        "updateleverage",
        "updateisolatedmargin",
        "setreferrer",
        "noop",
    }
)
_FORBIDDEN_HL_DELEGATION_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "approveagent",
        "approvebuilderfee",
    }
)
_TRANSFER_HL_ACTION_TYPES: frozenset[str] = frozenset(
    {
        "usdsend",
        "spotsend",
        "withdraw3",
        "sendasset",
        "usdclasstransfer",
        "vaulttransfer",
        "subaccounttransfer",
    }
)
_ACTION_DESTINATION_KEYS: Tuple[str, ...] = (
    "destination",
    "to",
    "recipient",
    "vaultAddress",
    "subAccountUser",
    "agentAddress",
)


def _get_default_pinned_master_addresses() -> Set[str]:
    """
    `os.environ` または `.env` から自己登録マスターアドレス (`HL_MAIN_ADDRESS` 等) を取得し、
    小文字正規化したセットを返す（ゼロアドレス `0x000...000` は除外）。
    """
    found: Set[str] = set()
    zero_addr = "0x" + "0" * 40
    env_addr = (os.environ.get("HL_MAIN_ADDRESS") or "").strip().lower()
    if env_addr.startswith("0x") and len(env_addr) == 42 and env_addr != zero_addr:
        found.add(env_addr)

    dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    if dotenv_path.exists():
        try:
            for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                s_line = line.strip()
                if not s_line or s_line.startswith("#") or "=" not in s_line:
                    continue
                k_part, v_part = s_line.split("=", 1)
                k_clean = k_part.strip()
                v_clean = v_part.strip().strip("'\"").lower()
                if k_clean == "HL_MAIN_ADDRESS" and v_clean.startswith("0x") and len(v_clean) == 42 and v_clean != zero_addr:
                    found.add(v_clean)
        except Exception:
            pass
    return found


def verify_pinned_hl_action_destination(
    action: Dict[str, Any],
    allowed_destinations: Optional[Set[str]] = None,
) -> bool:
    """
    Hyperliquid L1 アクション送信境界における出金・送金・権限委譲のハードブロック検証:
    1) 通常の取引アクション (`order`, `cancel`, `cancelByCloid`, `batchModify`, `modify`, `scheduleCancel`, `updateLeverage` 等) は無条件で `True`。
    2) 権限委譲アクション (`approveAgent`, `approveBuilderFee`) は常時 `PermissionError` でハードブロック。
    3) 資金移動アクション (`usdSend`, `spotSend`, `withdraw3`, `sendAsset`, `vaultTransfer`, `subAccountTransfer` 等) で
       宛先アドレスが自己登録マスターアドレス (`allowed_destinations` または `HL_MAIN_ADDRESS`) と完全一致しない場合は
       即座に `PermissionError` でハードブロックする。
    """
    if not isinstance(action, dict):
        raise PermissionError("Blocked invalid Hyperliquid L1 action: payload must be a dict")

    act_type = str(action.get("type") or "").strip()
    act_type_low = act_type.lower()
    if not act_type_low:
        raise PermissionError("Blocked Hyperliquid L1 action with empty type")

    # 1. 権限委譲系は常時ハードブロック
    if act_type_low in _FORBIDDEN_HL_DELEGATION_ACTION_TYPES:
        raise PermissionError(f"Blocked forbidden L1 privilege delegation action: {act_type}")

    # 2. 通常の取引系アクションは100%無条件通過
    if act_type_low in _SAFE_HL_TRADING_ACTION_TYPES:
        return True

    # 3. 許可宛先セットの解決
    if allowed_destinations is not None:
        allowed_set = {
            str(addr).strip().lower()
            for addr in allowed_destinations
            if addr is not None and str(addr).strip() and str(addr).strip().lower() != ("0x" + "0" * 40)
        }
    else:
        allowed_set = _get_default_pinned_master_addresses()

    dest_values = [
        str(action[dk]).strip()
        for dk in _ACTION_DESTINATION_KEYS
        if dk in action and action[dk] is not None and str(action[dk]).strip()
    ]

    # 同一アカウント内の Perp <-> Spot 振替 (usdClassTransfer) で外部宛先指定がない場合は許可
    if act_type_low == "usdclasstransfer" and not dest_values:
        return True

    if act_type_low in _TRANSFER_HL_ACTION_TYPES or dest_values:
        if not dest_values:
            raise PermissionError(f"Blocked L1 transfer action '{act_type}': missing destination address")
        if not allowed_set:
            raise PermissionError(f"Blocked L1 transfer action '{act_type}': no pinned master destination configured")
        for d_val in dest_values:
            if d_val.lower() not in allowed_set:
                raise PermissionError(
                    f"Blocked unauthorized L1 transfer/withdrawal '{act_type}' to unpinned destination: {d_val}"
                )
        return True

    raise PermissionError(f"Blocked unrecognized Hyperliquid L1 action type: {act_type}")


def get_secret(key_name: str, dotenv_path: Optional[Union[str, Path]] = None) -> str:
    """
    `os.environ` に平文を展開することなく、`.env` ファイル（または暗号化済み環境変数）から
    対象キーを読み取り、呼び出し元のローカルスコープにのみ瞬間復号して返すヘルパー関数。
    """
    k = str(key_name or "").strip()
    if not k:
        return ""

    # 1. 環境変数に明示設定がある場合（単体テストの monkeypatch または DPAPI:... 暗号文）
    env_val = (os.environ.get(k) or "").strip().strip("'\"")
    if env_val:
        return dpapi_decrypt_str(env_val)

    # 2. .env ファイルから直接対象キーを読み取り、メモリ上でのみ瞬間復号（os.environ は汚さない）
    target = Path(dotenv_path) if dotenv_path is not None else (Path(__file__).resolve().parent.parent / ".env")
    if target.exists():
        try:
            for line in target.read_text(encoding="utf-8", errors="ignore").splitlines():
                s_line = line.strip()
                if not s_line or s_line.startswith("#") or "=" not in s_line:
                    continue
                k_part, v_part = s_line.split("=", 1)
                if k_part.strip() == k:
                    v_clean = v_part.strip().strip("'\"")
                    if v_clean:
                        return dpapi_decrypt_str(v_clean)
        except Exception:
            pass
    return ""


def load_safe_dotenv(dotenv_path: Optional[Union[str, Path]] = None) -> None:
    """
    `.env` を読み込む際、機密キー (`HL_AGENT_PRIVATE_KEY`, `GEMINI_API_KEY`, `DISCORD_WEBHOOK_URL`,
    `APP_LOCK_PASSWORD`, `GITHUB_PUSH_TOKEN`) の平文を `os.environ` に一切展開しない安全なローダー。
    仮に既存の平文または危険な環境変数が `os.environ` に残っていた場合は消去し、非機密の設定項目のみを `os.environ` に反映する。
    """
    global _CACHED_DOTENV_SECRETS
    purge_dangerous_environment_variables()
    target = Path(dotenv_path) if dotenv_path is not None else (Path(__file__).resolve().parent.parent / ".env")

    for sk in _ENV_SECRET_KEYS:
        if sk in os.environ:
            os.environ.pop(sk, None)

    if not target.exists():
        return

    dangerous_upper = {k.upper() for k in DANGEROUS_ENV_VARS_TO_PURGE}
    try:
        for line in target.read_text(encoding="utf-8", errors="ignore").splitlines():
            s_line = line.strip()
            if not s_line or s_line.startswith("#") or "=" not in s_line:
                continue
            k_part, v_part = s_line.split("=", 1)
            k_clean = k_part.strip()
            v_clean = v_part.strip().strip("'\"")
            if not k_clean:
                continue
            if k_clean.upper() in dangerous_upper:
                continue
            if k_clean in _ENV_SECRET_KEYS:
                if v_clean:
                    register_secret_for_scrubbing(v_clean)
                    try:
                        dec = dpapi_decrypt_str(v_clean)
                        if dec:
                            register_secret_for_scrubbing(dec)
                    except Exception:
                        pass
                continue
            os.environ[k_clean] = v_clean
        with _DOTENV_SECRETS_LOCK:
            _CACHED_DOTENV_SECRETS = None
    except Exception as exc:
        logger.debug("load_safe_dotenv warning: %s", exc)


def _collect_known_secrets() -> List[str]:
    global _CACHED_DOTENV_SECRETS
    secrets_list: List[str] = []
    for k in _ENV_SECRET_KEYS:
        val = (os.environ.get(k) or "").strip()
        if len(val) >= 4 and val not in secrets_list:
            secrets_list.append(val)
            if val.startswith("DPAPI:"):
                try:
                    dec_v = dpapi_decrypt_str(val)
                    if len(dec_v) >= 4 and dec_v not in secrets_list:
                        secrets_list.append(dec_v)
                except Exception:
                    pass

    with _DOTENV_SECRETS_LOCK:
        for r_sec in _RUNTIME_REGISTERED_SECRETS:
            if r_sec not in secrets_list:
                secrets_list.append(r_sec)
        if _CACHED_DOTENV_SECRETS is None:
            loaded: List[str] = []
            try:
                dotenv_path = Path(__file__).resolve().parent.parent / ".env"
                if dotenv_path.exists():
                    for line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        s_line = line.strip()
                        if not s_line or s_line.startswith("#") or "=" not in s_line:
                            continue
                        k_part, v_part = s_line.split("=", 1)
                        k_clean = k_part.strip()
                        v_clean = v_part.strip().strip("'\"")
                        if k_clean in _ENV_SECRET_KEYS and len(v_clean) >= 4:
                            loaded.append(v_clean)
                            if v_clean.startswith("DPAPI:"):
                                try:
                                    dec_line = dpapi_decrypt_str(v_clean)
                                    if len(dec_line) >= 4 and dec_line not in loaded:
                                        loaded.append(dec_line)
                                except Exception:
                                    pass
            except Exception:
                pass
            _CACHED_DOTENV_SECRETS = loaded
        for s_val in _CACHED_DOTENV_SECRETS:
            if s_val not in secrets_list:
                secrets_list.append(s_val)
    return secrets_list


def scrub_secret_text(text: Any) -> str:
    """
    ログ文字列や例外トレースから `HL_AGENT_PRIVATE_KEY`、`GEMINI_API_KEY`、
    `DISCORD_WEBHOOK_URL`、`APP_LOCK_PASSWORD`、`GITHUB_PUSH_TOKEN` 等の機密文字列を完全除去する。
    """
    s = str(text or "")
    if not s:
        return s
    for sec in _collect_known_secrets():
        if sec and sec in s:
            s = s.replace(sec, "[REDACTED_SECRET]")
    s = _LOG_PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", s)
    s = _LOG_GEMINI_KEY_RE.sub("[REDACTED_API_KEY]", s)
    s = _LOG_GITHUB_PAT_RE.sub("[REDACTED_GITHUB_TOKEN]", s)
    s = _LOG_WEBHOOK_RE.sub("[REDACTED_WEBHOOK]", s)
    return s


class SecretScrubbingLogFilter(logging.Filter):
    """すべてのログ出力レコードから機密情報を自動スクラブするフィルタ"""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = scrub_secret_text(record.msg)
            if record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(
                        scrub_secret_text(a) if isinstance(a, str) else a for a in record.args
                    )
                elif isinstance(record.args, dict):
                    record.args = {
                        k: (scrub_secret_text(v) if isinstance(v, str) else v)
                        for k, v in record.args.items()
                    }
            if record.exc_text:
                record.exc_text = scrub_secret_text(record.exc_text)
        except Exception:
            pass
        return True


def install_global_secret_log_filter() -> None:
    """ルートロガーおよび主要ロガーに `SecretScrubbingLogFilter` を装着する"""
    root_logger = logging.getLogger()
    if not any(isinstance(f, SecretScrubbingLogFilter) for f in root_logger.filters):
        root_logger.addFilter(SecretScrubbingLogFilter())
    for handler in root_logger.handlers:
        if not any(isinstance(f, SecretScrubbingLogFilter) for f in handler.filters):
            handler.addFilter(SecretScrubbingLogFilter())


install_global_secret_log_filter()


CREATE_NO_WINDOW_FLAG = 0x08000000
SW_HIDE_FLAG = 0
_ACL_HARDENED_CACHE: set[str] = set()


def hidden_subprocess_kwargs() -> Dict[str, Any]:
    """
    Windows 環境で子プロセス (git / icacls / python 等) のコンソールウィンドウポップアップを
    100% 抑止するための共通 `subprocess` キーワード引数辞書を返す。
    - `creationflags = 0x08000000` (`CREATE_NO_WINDOW`)
    - `startupinfo`: `STARTF_USESHOWWINDOW` & `wShowWindow = 0` (`SW_HIDE`)
    """
    if os.name != "nt":
        return {}
    si = _subprocess.STARTUPINFO()
    si.dwFlags |= getattr(_subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
    si.wShowWindow = SW_HIDE_FLAG
    return {
        "creationflags": CREATE_NO_WINDOW_FLAG,
        "startupinfo": si,
    }


def harden_windows_file_acl(file_path: Union[str, Path], force: bool = False) -> bool:
    """
    Windows の `icacls` を用いて `.env` や SQLite DB ファイルのアクセス制御リスト (ACL) を検証・保護し、
    現在のユーザー・Administrators・SYSTEM 以外の第三者アクセスを遮断する。
    (※ 同一プロセス内ではキャッシュにより初回1回のみ実行し、かつ CREATE_NO_WINDOW + SW_HIDE を強制する)
    """
    target = Path(file_path)
    if not target.exists() or os.name != "nt":
        return False
    try:
        resolved_key = str(target.resolve()).lower()
        if not force and resolved_key in _ACL_HARDENED_CACHE:
            return True
        username = os.environ.get("USERNAME") or ""
        if not username:
            return False
        res = _subprocess.run(
            [
                "icacls",
                str(target),
                "/inheritance:r",
                "/grant:r",
                f"{username}:(F)",
                "SYSTEM:(F)",
                "Administrators:(F)",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            **hidden_subprocess_kwargs(),
        )
        if res.returncode == 0:
            _ACL_HARDENED_CACHE.add(resolved_key)
            return True
        return False
    except Exception:
        return False


# ==============================================================================
# 7. Win32 電源状態 (UPS / バッテリー低下) ＆ OSシャットダウン・シグナル監視
# ==============================================================================
CTRL_C_EVENT = 0
CTRL_BREAK_EVENT = 1
CTRL_CLOSE_EVENT = 2
CTRL_LOGOFF_EVENT = 5
CTRL_SHUTDOWN_EVENT = 6
WM_QUERYENDSESSION = 0x0011
WM_ENDSESSION = 0x0016

UPS_BATTERY_CRITICAL_PCT = 40


class SYSTEM_POWER_STATUS(ctypes.Structure):
    """
    Win32 `GetSystemPowerStatus` 用構造体。
    `ACLineStatus`, `BatteryFlag`, `BatteryLifePercent`, `SystemStatusFlag` は
    255 (0xFF = Unknown) を正しく表現するため必ず符号なし `ctypes.c_ubyte` で定義する。
    """

    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", _wintypes.DWORD),
        ("BatteryFullLifeTime", _wintypes.DWORD),
    ]


def check_ups_power_critical(
    critical_pct_threshold: int = UPS_BATTERY_CRITICAL_PCT,
    simulated_status: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """
    Win32 `Kernel32.GetSystemPowerStatus` を呼び出して現在の電源・UPS・バッテリー状態を検査する。
    - `ACLineStatus == 0` (AC電源喪失・UPS/バッテリー稼働) かつ
      `BatteryLifePercent <= 40` (`255`＝不明を除く) の場合に `power_critical = True` を返す。
    """
    status = SYSTEM_POWER_STATUS()
    if simulated_status is not None:
        status.ACLineStatus = int(simulated_status.get("ACLineStatus", 1)) & 0xFF
        status.BatteryFlag = int(simulated_status.get("BatteryFlag", 0)) & 0xFF
        status.BatteryLifePercent = int(simulated_status.get("BatteryLifePercent", 100)) & 0xFF
        status.SystemStatusFlag = int(simulated_status.get("SystemStatusFlag", 0)) & 0xFF
        status.BatteryLifeTime = int(simulated_status.get("BatteryLifeTime", 0xFFFFFFFF)) & 0xFFFFFFFF
        status.BatteryFullLifeTime = int(simulated_status.get("BatteryFullLifeTime", 0xFFFFFFFF)) & 0xFFFFFFFF
        api_ok = True
    elif os.name == "nt" and hasattr(ctypes, "windll"):
        try:
            res = ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status))
            api_ok = bool(res != 0)
        except Exception:
            api_ok = False
    else:
        status.ACLineStatus = 1
        status.BatteryFlag = 128
        status.BatteryLifePercent = 255
        status.SystemStatusFlag = 0
        status.BatteryLifeTime = 0xFFFFFFFF
        status.BatteryFullLifeTime = 0xFFFFFFFF
        api_ok = False

    ac_line = int(status.ACLineStatus)
    batt_flag = int(status.BatteryFlag)
    batt_pct = int(status.BatteryLifePercent)
    sys_flag = int(status.SystemStatusFlag)

    is_on_battery = ac_line == 0
    is_pct_known = 0 <= batt_pct <= 100 and batt_pct != 255
    power_critical = bool(
        api_ok and is_on_battery and is_pct_known and batt_pct <= int(critical_pct_threshold)
    )

    return {
        "ok": api_ok,
        "ac_line_status": ac_line,
        "battery_flag": batt_flag,
        "battery_life_percent": batt_pct,
        "system_status_flag": sys_flag,
        "battery_life_time": int(status.BatteryLifeTime),
        "battery_full_life_time": int(status.BatteryFullLifeTime),
        "is_on_battery": is_on_battery,
        "power_critical": power_critical,
    }


_REGISTERED_CONSOLE_CTRL_HANDLERS: List[Any] = []


def register_windows_shutdown_handlers(
    on_shutdown_callback: Callable[[str], Any],
) -> bool:
    """
    Windows の `Kernel32.SetConsoleCtrlHandler` (`CTRL_C_EVENT`, `CTRL_BREAK_EVENT`,
    `CTRL_CLOSE_EVENT`, `CTRL_LOGOFF_EVENT`, `CTRL_SHUTDOWN_EVENT`) および
    Python 標準 `signal` (`SIGINT`, `SIGTERM`, `SIGBREAK`)、`WM_QUERYENDSESSION` / `WM_ENDSESSION`
    ディスパッチャを登録する。
    """
    import signal as _signal

    event_names = {
        CTRL_C_EVENT: "CTRL_C_EVENT",
        CTRL_BREAK_EVENT: "CTRL_BREAK_EVENT",
        CTRL_CLOSE_EVENT: "CTRL_CLOSE_EVENT",
        CTRL_LOGOFF_EVENT: "CTRL_LOGOFF_EVENT",
        CTRL_SHUTDOWN_EVENT: "CTRL_SHUTDOWN_EVENT",
        WM_QUERYENDSESSION: "WM_QUERYENDSESSION",
        WM_ENDSESSION: "WM_ENDSESSION",
    }

    def _safe_invoke(ev_label: str) -> None:
        try:
            on_shutdown_callback(ev_label)
        except Exception as exc:
            logger.error("Shutdown handler callback error (%s): %s", ev_label, exc)

    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig_num = getattr(_signal, sig_name, None)
        if sig_num is not None:
            try:
                _signal.signal(sig_num, lambda signum, frame, sn=sig_name: _safe_invoke(sn))
            except Exception:
                pass

    if os.name == "nt" and hasattr(ctypes, "WINFUNCTYPE") and hasattr(ctypes, "windll"):
        try:
            HandlerRoutine = ctypes.WINFUNCTYPE(_wintypes.BOOL, _wintypes.DWORD)

            def _ctrl_handler(ctrl_type: int) -> bool:
                ev_str = event_names.get(int(ctrl_type), f"CTRL_EVENT_{ctrl_type}")
                _safe_invoke(ev_str)
                return True

            c_handler = HandlerRoutine(_ctrl_handler)
            _REGISTERED_CONSOLE_CTRL_HANDLERS.append(c_handler)
            res = ctypes.windll.kernel32.SetConsoleCtrlHandler(c_handler, True)
            return bool(res != 0)
        except Exception as exc:
            logger.debug("SetConsoleCtrlHandler 登録スキップ: %s", exc)
            return False
    return True


