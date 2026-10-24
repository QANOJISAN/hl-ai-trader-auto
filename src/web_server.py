"""
HL AI Trader v1 — Port 8081 Zero-Knowledge Encrypted Web Server, 6-Layer Security & PWA Sync (src/web_server.py)

実装機能 (ARCHITECTURE.md Section 1, Phase 5 & Phase 6 Security Hardening 完全準拠):
1. 起動時パスワード認証ロック画面（Forensic Ledger 完全準拠デザイン）＆ PCローカルAPI認証強制:
   - `.env` の `APP_LOCK_PASSWORD` をマスターパスワードとして使用
   - `POST /api/auth/unlock`: 定数時間比較 (`hmac.compare_digest`) によるパスワード検証＆HMAC-SHA256署名トークン発行
   - 5回連続認証失敗時のブルートフォース・ロックアウト（60秒間 ➔ 指数バックオフ, `HTTP 429 Too Many Requests`）
   - 未認証リクエストに対する `/api/status` (`/api/state`), `/api/chart` (`/api/candles`), `/api/command` (`/api/control`) の
     完全遮断 (`HTTP 401 Unauthorized`)
2. 外出先スマホPWA用スナップショットの完全暗号化 (`AES-256-GCM` + `PBKDF2-SHA256` 150,000回):
   - `export_public_snapshot` にて平文データの出力を100%禁止
   - 16バイト乱数 `salt` + 12バイト乱数 `iv` (Nonce) + `PBKDF2-SHA256` (150,000回) で導出した256bit鍵により
     機密スクラブ済みJSONを `AES-256-GCM` 暗号化し、暗号化コンテナのみを `docs/public_snapshot.json` に出力
3. DNS Rebinding / CSRF / クリックジャッキング / クローラー完全防御:
   - `Host` ヘッダ厳格検証 (`127.0.0.1` / `localhost` 以外は `HTTP 403 Forbidden`)
   - 全レスポンスへのセキュリティヘッダ付与 (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
     `Referrer-Policy: no-referrer`, `Robots-Tag: noindex, nofollow`, `Content-Security-Policy`)
   - CORSワイルドカード禁止・同一オリジン強制
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time
import zlib
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.dont_write_bytecode = True
_ROOT_DIR = str(Path(__file__).resolve().parent.parent)
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from src.coordinator import ConcurrencyStateCoordinator, SlotState, SystemMode
from src.db import DatabaseManager, HyperliquidTaxEngine
from src.main import HLTraderDaemon
from src.utils import (
    enable_process_extension_point_mitigation,
    get_secret,
    harden_windows_file_acl,
    hidden_subprocess_kwargs,
    install_egress_domain_whitelist_guard,
    jst_tax_year,
    load_safe_dotenv,
    now_jst,
    now_ms,
    purge_dangerous_environment_variables,
    scrub_secret_text,
)

logger = logging.getLogger("hl_web_server")

BASE_DIR = Path(__file__).resolve().parent.parent
DOCS_DIR = BASE_DIR / "docs"
WEB_STATIC_DIR = BASE_DIR / "web" / "static"
ISOLATED_GITCONFIG_PATH = BASE_DIR / ".hl_gitconfig"

GIT_PUSH_OFFSET_MINUTES = (8, 23, 38, 53)
SUPPORTED_INTERVALS = ("15m", "1h", "4h", "1D")
SUPPORTED_PAIRS = (
    "HYPE/USDC",
    "UBTC/USDC",
    "UETH/USDC",
    "USOL/USDC",
    "PURR/USDC",
    "UZEC/USDC",
    "XMR1/USDC",
)

VALID_REMOTE_COMMANDS = frozenset(
    {
        "PAUSE",
        "RESUME",
        "CLEAR_PENDING_BUYS",
        "EMERGENCY_LIQUIDATE_ALL",
    }
)

PBKDF2_ITERATIONS = 150_000
DEFAULT_FALLBACK_LOCK_PASSWORD = "HL-2026-Secure!"


def get_app_lock_password() -> str:
    """
    `os.environ` に平文を展開することなく、`get_secret("APP_LOCK_PASSWORD")` で瞬間復号して返す。
    """
    pw = get_secret("APP_LOCK_PASSWORD").strip()
    if pw:
        return pw
    return DEFAULT_FALLBACK_LOCK_PASSWORD


def encrypt_snapshot_payload(
    payload: Dict[str, Any],
    password: Optional[str] = None,
    iterations: int = PBKDF2_ITERATIONS,
    updated_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """
    機密スクラブ済みのダッシュボードJSONペイロードを、
    ランダム16バイト `salt` + ランダム12バイト `iv` + `PBKDF2-SHA256` (150,000回) + `AES-256-GCM` で完全暗号化する。
    ブラウザの Web Crypto API (`window.crypto.subtle.decrypt`) と100%バイナリ互換（`ciphertext || 16-byte tag`）。
    """
    pw = (password if password is not None else get_app_lock_password()).strip()
    if not pw:
        raise ValueError("APP_LOCK_PASSWORD が空です")

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    iters = int(iterations)
    key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters, dklen=32)

    cleaned_payload = scrub_sensitive_data(payload)
    plaintext_bytes = json.dumps(cleaned_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext_with_tag = AESGCM(key).encrypt(iv, plaintext_bytes, None)

    ts = int(updated_at_ms) if updated_at_ms is not None else int(payload.get("generated_at_ms") or now_ms())
    return {
        "encrypted": True,
        "cipher": "AES-256-GCM",
        "kdf": "PBKDF2-SHA256",
        "iterations": iters,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext_with_tag).decode("ascii"),
        "updated_at_ms": ts,
    }


def decrypt_snapshot_container(
    container: Dict[str, Any],
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    `encrypt_snapshot_payload` が生成した暗号化コンテナを検証・復号して元の辞書を返す。
    パスワード不一致や改ざんがある場合は例外 (`ValueError`) を送出する。
    """
    if not isinstance(container, dict) or container.get("encrypted") is not True:
        raise ValueError("暗号化コンテナ形式ではありません")
    if container.get("cipher") != "AES-256-GCM" or container.get("kdf") != "PBKDF2-SHA256":
        raise ValueError("未対応の暗号スイートまたはKDFです")

    pw = (password if password is not None else get_app_lock_password()).strip()
    try:
        salt = base64.b64decode(str(container["salt_b64"]))
        iv = base64.b64decode(str(container["iv_b64"]))
        ciphertext_with_tag = base64.b64decode(str(container["ciphertext_b64"]))
        iters = int(container.get("iterations", PBKDF2_ITERATIONS))
        if len(salt) != 16 or len(iv) != 12 or iters < 10_000:
            raise ValueError("暗号パラメータ長が不正です")
        key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters, dklen=32)
        plaintext_bytes = AESGCM(key).decrypt(iv, ciphertext_with_tag, None)
        return json.loads(plaintext_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("AES-256-GCM 復号または認証タグ検証に失敗しました") from exc


class WebAuthSecurityManager:
    """
    ローカルWebサーバー (`http://127.0.0.1:8081`) 用の認証・セッショントークン・
    ブルートフォースロックアウト管理クラス。
    - 5回連続でパスワード認証に失敗した場合、60秒間（以降は 120秒, 240秒... の指数バックオフ）ロックアウトし
      `HTTP 429 Too Many Requests` を返す。
    - パスワード比較およびトークン署名検証はすべて `hmac.compare_digest` による定数時間比較を行う。
    """

    MAX_FAILED_ATTEMPTS = 5
    BASE_LOCKOUT_SEC = 60.0
    TOKEN_TTL_MS = 30 * 86_400_000  # 30日 (端末記憶用; 「🔒 今すぐロック」でいつでも即時失効可能)

    def __init__(self, password: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._custom_password = password
        self._failed_attempts: int = 0
        self._locked_until_ms: int = 0
        self._session_salt = secrets.token_hex(16)
        self._revoked_tokens: Set[str] = set()

    def _get_master_password(self) -> str:
        if self._custom_password is not None:
            return self._custom_password
        return get_app_lock_password()

    def _get_signing_key(self) -> bytes:
        pw = self._get_master_password()
        return hashlib.sha256(f"HL-AI-TRADER-V1-AUTH::{self._session_salt}::{pw}".encode("utf-8")).digest()

    def is_locked_out(self, current_time_ms: Optional[int] = None) -> Tuple[bool, float]:
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        with self._lock:
            if ts < self._locked_until_ms:
                rem_sec = max(0.1, (self._locked_until_ms - ts) / 1000.0)
                return (True, round(rem_sec, 2))
            return (False, 0.0)

    def issue_session_token(self, current_time_ms: Optional[int] = None) -> str:
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        nonce = secrets.token_hex(12)
        payload_part = f"{ts}.{nonce}"
        sig = hmac.new(self._get_signing_key(), payload_part.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{payload_part}.{sig}"

    def attempt_unlock(
        self,
        candidate_password: str,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        """
        パスワードを定数時間比較 (`hmac.compare_digest`) で検証する。
        戻り値: `(HTTPステータスコード, レスポンス辞書)`
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        locked, retry_sec = self.is_locked_out(current_time_ms=ts)
        if locked:
            return (
                429,
                {
                    "ok": False,
                    "authenticated": False,
                    "locked_out": True,
                    "retry_after_sec": retry_sec,
                    "failed_attempts": self._failed_attempts,
                    "error": f"Too Many Requests: Locked out for {retry_sec:.1f}s due to repeated failed attempts.",
                },
            )

        expected_pw = self._get_master_password()
        cand_bytes = str(candidate_password or "").encode("utf-8")
        exp_bytes = expected_pw.encode("utf-8")
        is_valid = hmac.compare_digest(cand_bytes, exp_bytes)

        with self._lock:
            if is_valid:
                self._failed_attempts = 0
                self._locked_until_ms = 0
                token = self.issue_session_token(current_time_ms=ts)
                return (
                    200,
                    {
                        "ok": True,
                        "authenticated": True,
                        "locked_out": False,
                        "token": token,
                        "cipher": "AES-256-GCM",
                        "kdf": "PBKDF2-SHA256",
                        "iterations": PBKDF2_ITERATIONS,
                    },
                )

            self._failed_attempts += 1
            if self._failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                exponent = self._failed_attempts - self.MAX_FAILED_ATTEMPTS
                lockout_sec = self.BASE_LOCKOUT_SEC * (2 ** min(exponent, 8))
                self._locked_until_ms = ts + int(lockout_sec * 1000)
                return (
                    429,
                    {
                        "ok": False,
                        "authenticated": False,
                        "locked_out": True,
                        "retry_after_sec": round(lockout_sec, 2),
                        "failed_attempts": self._failed_attempts,
                        "error": f"Too Many Requests: Locked out for {lockout_sec:.0f}s after {self._failed_attempts} failed attempts.",
                    },
                )

            rem = max(0, self.MAX_FAILED_ATTEMPTS - self._failed_attempts)
            return (
                401,
                {
                    "ok": False,
                    "authenticated": False,
                    "locked_out": False,
                    "failed_attempts": self._failed_attempts,
                    "remaining_attempts": rem,
                    "error": "Unauthorized: Invalid master password.",
                },
            )

    def revoke_token(self, token: str) -> None:
        raw = str(token or "").strip()
        if raw.lower().startswith("bearer "):
            raw = raw[7:].strip()
        if raw:
            with self._lock:
                if len(self._revoked_tokens) >= 2000:
                    self._revoked_tokens.clear()
                self._revoked_tokens.add(raw)

    def verify_request_token(
        self,
        token: Optional[str],
        current_time_ms: Optional[int] = None,
    ) -> bool:
        """
        リクエストヘッダ `X-HL-Auth` (または `Authorization: Bearer ...`) のトークンを
        定数時間比較 (`hmac.compare_digest`) で検証する。
        """
        raw = str(token or "").strip()
        if not raw:
            return False
        if raw.lower().startswith("bearer "):
            raw = raw[7:].strip()
        if not raw:
            return False

        with self._lock:
            if raw in self._revoked_tokens:
                return False

        # 1. 署名付きセッショントークン (ts.nonce.sig) の検証
        parts = raw.split(".")
        if len(parts) == 3:
            ts_str, nonce_str, sig_hex = parts
            if ts_str.isdigit() and nonce_str and sig_hex:
                ts_now = int(current_time_ms) if current_time_ms is not None else now_ms()
                issued_ms = int(ts_str)
                if -60_000 <= (ts_now - issued_ms) <= self.TOKEN_TTL_MS:
                    payload_part = f"{ts_str}.{nonce_str}"
                    expected_sig = hmac.new(
                        self._get_signing_key(), payload_part.encode("ascii"), hashlib.sha256
                    ).hexdigest()
                    if hmac.compare_digest(sig_hex.encode("ascii"), expected_sig.encode("ascii")):
                        return True

        # 2. 直接パスワードまたはHMACダイジェストが渡された場合の定数時間比較
        master_pw = self._get_master_password()
        if hmac.compare_digest(raw.encode("utf-8"), master_pw.encode("utf-8")):
            return True
        expected_hmac = hmac.new(master_pw.encode("utf-8"), b"HL-AI-TRADER-AUTH", hashlib.sha256).hexdigest()
        if hmac.compare_digest(raw.encode("utf-8"), expected_hmac.encode("utf-8")):
            return True

        return False


def should_run_git_push_at_minute(minute: int) -> bool:
    """
    GMO版 (毎時 02, 17, 32, 47分) との競合を回避するため、
    毎時 08, 23, 38, 53分 のみ True を返す。
    """
    return int(minute) in GIT_PUSH_OFFSET_MINUTES


def build_isolated_git_env(base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    `GIT_CONFIG_GLOBAL` を `e:/hl-ai-trader-auto/.hl_gitconfig` に隔離した環境変数辞書を返す。
    """
    env = dict(base_env if base_env is not None else os.environ)
    env["GIT_CONFIG_GLOBAL"] = str(ISOLATED_GITCONFIG_PATH)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


_SENSITIVE_KEY_SUBSTRINGS = (
    "private_key",
    "secret",
    "api_key",
    "apikey",
    "webhook",
    "password",
    "mnemonic",
    "seed_phrase",
    "main_address",
    "agent_address",
    "wallet_address",
    "active_cloid",
    "cloid",
    "active_oid",
)
_HEX_SECRET_OR_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{16,64}")
_GEMINI_KEY_RE = re.compile(r"AIza[0-9A-Za-z_\-]{20,}")
_WEBHOOK_URL_RE = re.compile(
    r"https?://(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)/[^\s\"']+",
    re.IGNORECASE,
)


def scrub_sensitive_data(obj: Any) -> Any:
    """
    公開用スナップショット (`docs/public_snapshot.json`) から秘密鍵・ウォレットアドレス・
    cloid/oid・APIキー・Webhook URL・パスワード等の機密情報を再帰的に完全除去する。
    """
    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in obj.items():
            k_low = str(k).lower()
            if any(sub in k_low for sub in _SENSITIVE_KEY_SUBSTRINGS):
                continue
            cleaned[k] = scrub_sensitive_data(v)
        return cleaned
    if isinstance(obj, list):
        return [scrub_sensitive_data(item) for item in obj]
    if isinstance(obj, tuple):
        return [scrub_sensitive_data(item) for item in obj]
    if isinstance(obj, str):
        s = _HEX_SECRET_OR_ADDR_RE.sub("[REDACTED_HEX]", obj)
        s = _GEMINI_KEY_RE.sub("[REDACTED_API_KEY]", s)
        s = _WEBHOOK_URL_RE.sub("[REDACTED_WEBHOOK]", s)
        return scrub_secret_text(s)
    return obj


# ==============================================================================
# 純Python 高解像度 PWA アイコン PNG 生成器 ("HL" ロゴ)
# ==============================================================================
_GLYPH_H = [
    "11011",
    "11011",
    "11011",
    "11111",
    "11011",
    "11011",
    "11011",
]
_GLYPH_L = [
    "11000",
    "11000",
    "11000",
    "11000",
    "11000",
    "11000",
    "11111",
]


def generate_hl_icon_png(size: int, out_path: Path) -> Path:
    """角丸グラデーション＋『HL』ロゴ入りのPWA用PNGアイコンを純Pythonで生成する"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows: List[bytes] = []
    radius = size * 0.22
    center = size / 2.0

    for y in range(size):
        row = bytearray([0])
        ny = y / float(size)
        for x in range(size):
            nx = x / float(size)
            dx = max(abs(x - center) - (size / 2.0 - radius), 0.0)
            dy = max(abs(y - center) - (size / 2.0 - radius), 0.0)
            dist = math.hypot(dx, dy)
            if dist > radius + 0.8:
                row.extend((0, 0, 0, 0))
                continue
            alpha = 255
            if dist > radius - 0.8:
                alpha = int(max(0.0, min(1.0, (radius + 0.8 - dist) / 1.6)) * 255)

            t = nx * 0.55 + ny * 0.45
            if t < 0.5:
                u = t * 2.0
                r = int(15 * (1 - u) + 2 * u)
                g = int(23 * (1 - u) + 132 * u)
                b = int(42 * (1 - u) + 199 * u)
            else:
                u = (t - 0.5) * 2.0
                r = int(2 * (1 - u) + 13 * u)
                g = int(132 * (1 - u) + 148 * u)
                b = int(199 * (1 - u) + 136 * u)

            in_glyph = False
            if 0.27 <= ny <= 0.73:
                gy = min(6, max(0, int((ny - 0.27) / 0.46 * 7.0)))
                if 0.21 <= nx <= 0.47:
                    gx = min(4, max(0, int((nx - 0.21) / 0.26 * 5.0)))
                    if _GLYPH_H[gy][gx] == "1":
                        in_glyph = True
                elif 0.53 <= nx <= 0.79:
                    gx = min(4, max(0, int((nx - 0.53) / 0.26 * 5.0)))
                    if _GLYPH_L[gy][gx] == "1":
                        in_glyph = True

            if 0.21 <= nx <= 0.79 and 0.78 <= ny <= 0.825:
                r, g, b = 94, 234, 212
            if in_glyph:
                r, g, b = 255, 255, 255

            row.extend((r, g, b, alpha))
        rows.append(bytes(row))

    raw_data = b"".join(rows)

    def _chunk(c_type: bytes, c_data: bytes) -> bytes:
        crc = zlib.crc32(c_type + c_data) & 0xFFFFFFFF
        return struct.pack(">I", len(c_data)) + c_type + c_data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_data, level=9)
    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    out_path.write_bytes(png)
    return out_path


def ensure_pwa_static_assets() -> None:
    """`docs/` 配下のPWAアイコン・マニフェスト・スクリプト・`.nojekyll`・`robots.txt` を最新状態に同期する"""
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    static_sub = DOCS_DIR / "static"
    static_sub.mkdir(parents=True, exist_ok=True)

    for fname, sz in (("icon-192.png", 192), ("icon-512.png", 512), ("apple-touch-icon.png", 180)):
        fpath = DOCS_DIR / fname
        if not fpath.exists():
            try:
                generate_hl_icon_png(sz, fpath)
            except Exception as exc:
                logger.debug("PWA アイコン生成スキップ (%s): %s", fname, exc)

    nojekyll_path = DOCS_DIR / ".nojekyll"
    if not nojekyll_path.exists():
        try:
            nojekyll_path.write_text("", encoding="utf-8")
        except Exception:
            pass

    robots_path = DOCS_DIR / "robots.txt"
    if not robots_path.exists():
        try:
            robots_path.write_text("User-agent: *\nDisallow: /\n", encoding="utf-8")
        except Exception:
            pass

    src_app_js = WEB_STATIC_DIR / "app.js"
    if src_app_js.exists():
        for dst_app_js in (DOCS_DIR / "app.js", static_sub / "app.js"):
            try:
                shutil.copyfile(src_app_js, dst_app_js)
            except Exception:
                pass


class DashboardStateService:
    """
    SQLite WAL 台帳および `HLTraderDaemon` と連携し、
    Web API レスポンス構築・0秒コマンド適用・チャートデータ生成・AES-256-GCM暗号化スナップショット出力を行うサービス。
    """

    def __init__(
        self,
        db: DatabaseManager,
        tax_engine: Optional[HyperliquidTaxEngine] = None,
        coordinator: Optional[ConcurrencyStateCoordinator] = None,
        daemon: Optional[HLTraderDaemon] = None,
        equity_history_provider: Optional[Any] = None,
        candle_provider: Optional[Any] = None,
        auth_manager: Optional[WebAuthSecurityManager] = None,
    ) -> None:
        self.db = db
        self.tax_engine = tax_engine or HyperliquidTaxEngine(db=self.db)
        self.coordinator = coordinator or ConcurrencyStateCoordinator(db=self.db)
        self.daemon = daemon
        self._equity_history_provider = equity_history_provider
        self._candle_provider = candle_provider
        self.auth_manager = auth_manager or WebAuthSecurityManager()
        self._equity_history: List[Dict[str, Any]] = []
        self._candle_cache: Dict[Tuple[str, str], Tuple[int, List[Dict[str, Any]]]] = {}

    def fetch_live_or_cached_candles(
        self,
        pair_name: str,
        interval: str,
        current_time_ms: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        デーモンまたは `exchange_wrapper.info` が接続されている場合、
        Hyperliquid Mainnet `/info` (`candles_snapshot`) から実ローソク足データを取得して数値正規化する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        key = (pair_name.upper(), interval)
        cached = self._candle_cache.get(key)
        if cached is not None and (ts - cached[0]) < 15_000 and cached[1]:
            return cached[1]

        if self._candle_provider is not None:
            try:
                res = self._candle_provider(pair_name, interval)
                if res:
                    if len(self._candle_cache) >= 64:
                        self._candle_cache.clear()
                    self._candle_cache[key] = (ts, res)
                    return res
            except Exception as exc:
                logger.warning("カスタム candle_provider 取得失敗 (%s, %s): %s", pair_name, interval, exc)

        if self.daemon is not None and self.daemon.exchange is not None and self.daemon.exchange.info is not None:
            ex = self.daemon.exchange
            info = ex.info
            if hasattr(info, "candles_snapshot"):
                try:
                    if not ex.pair_to_entry:
                        ex.refresh_universe_mapping()
                    sp_entry = ex.get_spot_entry(pair_name)
                    api_coin = sp_entry.api_coin_name if sp_entry is not None else pair_name
                    hl_iv = "1d" if interval == "1D" else interval
                    step_ms = {
                        "15m": 15 * 60_000,
                        "1h": 60 * 60_000,
                        "4h": 4 * 60 * 60_000,
                        "1d": 24 * 60 * 60_000,
                    }.get(hl_iv, 15 * 60_000)
                    start_ms = ts - 60 * step_ms
                    raw_bars = info.candles_snapshot(api_coin, hl_iv, start_ms, ts) or []
                    norm_bars: List[Dict[str, Any]] = []
                    for b in raw_bars[-60:]:
                        norm_bars.append(
                            {
                                "t": int(b.get("t", ts)),
                                "o": float(b.get("o", 0.0)),
                                "h": float(b.get("h", 0.0)),
                                "l": float(b.get("l", 0.0)),
                                "c": float(b.get("c", 0.0)),
                                "v": float(b.get("v", 0.0)),
                            }
                        )
                    if norm_bars:
                        if len(self._candle_cache) >= 64:
                            self._candle_cache.clear()
                        self._candle_cache[key] = (ts, norm_bars)
                        return norm_bars
                except Exception as exc:
                    logger.warning("Hyperliquid candles_snapshot 取得失敗 (%s, %s): %s", pair_name, interval, exc)
        return []

    def record_equity_point(
        self,
        equity_usdc: float,
        usdc_jpy_rate: float,
        hwm_usdc: float,
        timestamp_ms: Optional[int] = None,
    ) -> None:
        ts = int(timestamp_ms) if timestamp_ms is not None else now_ms()
        l5_floor = 0.85 * hwm_usdc
        self._equity_history.append(
            {
                "timestamp_ms": ts,
                "equity_usdc": round(float(equity_usdc), 4),
                "equity_jpy": round(float(equity_usdc) * float(usdc_jpy_rate), 1),
                "hwm_usdc": round(float(hwm_usdc), 4),
                "l5_floor_usdc": round(float(l5_floor), 4),
            }
        )
        if len(self._equity_history) > 500:
            self._equity_history = self._equity_history[-500:]

    def get_status_payload(self, current_time_ms: Optional[int] = None) -> Dict[str, Any]:
        """
        `/api/status` 用の統合ステータスペイロードを生成する。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        sys_st = self.db.get_system_state()
        slots = self.db.get_all_slots()

        sys_mode = str(sys_st.get("system_mode", SystemMode.NORMAL.value))
        op_paused = int(sys_st.get("operator_paused", 0)) == 1

        if sys_mode == SystemMode.HALTED.value:
            status_badge = "HALTED"
        elif op_paused:
            status_badge = "PAUSED"
        else:
            status_badge = "RUNNING"

        init_eq = float(sys_st.get("initial_equity_usdc", 130.0))
        hwm_eq = max(init_eq, float(sys_st.get("hwm_equity_usdc", init_eq)))
        cur_eq = float(sys_st.get("current_equity_usdc", init_eq))
        sod_eq = float(sys_st.get("sod_equity_usdc", init_eq))
        sow_eq = float(sys_st.get("sow_equity_usdc", init_eq))
        rate_jpy = float(sys_st.get("latest_usdc_jpy_rate", 155.0))
        l5_floor_usdc = round(0.85 * hwm_eq, 4)

        if not self._equity_history:
            self.record_equity_point(cur_eq, rate_jpy, hwm_eq, timestamp_ms=ts)

        conn = self.db._get_connection()
        recent_episodes = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM ai_episodic_memory ORDER BY timestamp_ms DESC LIMIT 5"
            ).fetchall()
        ]
        recent_reflections = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM ai_reflection_memory ORDER BY closed_at_ms DESC LIMIT 5"
            ).fetchall()
        ]
        dust_list = self.db.get_all_quarantined_dust()

        tax_yr = jst_tax_year(ts)
        tax_ma = self.tax_engine.calculate_annual_summary(tax_year=tax_yr, method="MOVING_AVERAGE")
        tax_ta = self.tax_engine.calculate_annual_summary(tax_year=tax_yr, method="TOTAL_AVERAGE")

        enriched_slots: Dict[str, Dict[str, Any]] = {}
        for sid in (1, 2):
            raw_s = dict(slots.get(sid, {}) or {})
            st_val = str(raw_s.get("state", "IDLE"))
            coin_val = str(raw_s.get("coin") or "").strip().upper()
            epx = float(raw_s.get("entry_px") or 0.0)
            sz_val = float(raw_s.get("current_sz") or raw_s.get("filled_sz") or raw_s.get("sz") or 0.0)
            cur_px = float(raw_s.get("current_px") or 0.0)

            if st_val in (SlotState.OPEN_PROTECTED.value, SlotState.MODIFYING_SL.value, SlotState.ENTRY_PENDING.value) and coin_val:
                if cur_px <= 0.0 and self.daemon is not None and self.daemon.exchange is not None:
                    try:
                        sp_e = self.daemon.exchange.get_spot_entry(coin_val)
                        if sp_e is not None:
                            cur_px = float(sp_e.spot_mid_px or sp_e.spot_mark_px or 0.0)
                    except Exception:
                        pass
                if cur_px <= 0.0:
                    cached_15m = self._candle_cache.get((coin_val, "15m"))
                    if cached_15m and cached_15m[1]:
                        cur_px = float(cached_15m[1][-1].get("c") or 0.0)
                if cur_px <= 0.0 and epx > 0.0:
                    cur_px = epx
                if cur_px > 0.0:
                    raw_s["current_px"] = round(cur_px, 6)
                if epx > 0.0 and sz_val > 0.0 and cur_px > 0.0:
                    raw_s["unrealized_pnl_usdc"] = round((cur_px - epx) * sz_val, 4)
                    raw_s["unrealized_pnl_pct"] = round(((cur_px - epx) / epx) * 100.0, 2)
            enriched_slots[str(sid)] = raw_s

        return {
            "timestamp_ms": ts,
            "version": "v1.2-alpha-max",
            "port": 8081,
            "status_badge": status_badge,
            "system_mode": sys_mode,
            "operator_paused": op_paused,
            "equity": {
                "initial_usdc": round(init_eq, 4),
                "current_usdc": round(cur_eq, 4),
                "current_jpy": round(cur_eq * rate_jpy, 1),
                "hwm_usdc": round(hwm_eq, 4),
                "hwm_jpy": round(hwm_eq * rate_jpy, 1),
                "l5_floor_usdc": l5_floor_usdc,
                "l5_floor_jpy": round(l5_floor_usdc * rate_jpy, 1),
                "sod_usdc": round(sod_eq, 4),
                "sow_usdc": round(sow_eq, 4),
                "total_return_pct": round(((cur_eq - init_eq) / init_eq) * 100.0, 2) if init_eq > 0 else 0.0,
                "daily_dd_pct": round(((cur_eq - sod_eq) / sod_eq) * 100.0, 2) if sod_eq > 0 else 0.0,
                "usdc_jpy_rate": round(rate_jpy, 3),
            },
            "equity_history": list(self._equity_history),
            "slots": enriched_slots,
            "circuit_breakers": {
                "l2_active": bool(ts < int(sys_st.get("l2_active_until_ms", 0))),
                "l2_active_until_ms": int(sys_st.get("l2_active_until_ms", 0)),
                "l3_active": bool(ts < int(sys_st.get("l3_active_until_ms", 0))),
                "l3_active_until_ms": int(sys_st.get("l3_active_until_ms", 0)),
                "l4_active": bool(ts < int(sys_st.get("l4_active_until_ms", 0))),
                "l4_active_until_ms": int(sys_st.get("l4_active_until_ms", 0)),
                "l5_strike_count": int(sys_st.get("l5_strike_count", 0)),
                "desync_strike_count": int(sys_st.get("desync_strike_count", 0)),
                "consecutive_losses": int(sys_st.get("consecutive_losses", 0)),
            },
            "ai_memory": {
                "recent_episodes": recent_episodes,
                "recent_reflections": recent_reflections,
            },
            "dust_quarantine": dust_list,
            "tax_summary": {
                "tax_year": tax_yr,
                "moving_average_pnl_jpy": tax_ma["total_realized_pnl_jpy"],
                "moving_average_pnl_jpy_int": tax_ma["total_realized_pnl_jpy_int"],
                "total_average_pnl_jpy": tax_ta["total_realized_pnl_jpy"],
                "total_average_pnl_jpy_int": tax_ta["total_realized_pnl_jpy_int"],
                "lot_count": tax_ma["lot_count"],
            },
            "git_sync": {
                "push_minutes": list(GIT_PUSH_OFFSET_MINUTES),
                "isolated_gitconfig": str(ISOLATED_GITCONFIG_PATH),
            },
        }

    def get_chart_payload(
        self,
        pair_name: str = "HYPE/USDC",
        interval: str = "15m",
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        `/api/chart` 用に指定銘柄・時間足のローソク足配列と、
        保有中/待機中スロットの Entry価格・SL価格・TP目標の水平ライン (`horizontal_lines`) を返す。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        pair = str(pair_name or "HYPE/USDC").strip().upper()
        if "/" not in pair:
            pair = f"{pair}/USDC"
        iv = str(interval or "15m").strip()
        if iv not in SUPPORTED_INTERVALS:
            iv = "15m"

        slots = self.db.get_all_slots()
        horizontal_lines: List[Dict[str, Any]] = []
        ref_base_px = 25.0 if "HYPE" in pair else (95000.0 if "BTC" in pair else (3100.0 if "ETH" in pair else 180.0))

        for sid in (1, 2):
            s = slots.get(sid, {})
            st = str(s.get("state", "IDLE"))
            s_coin = str(s.get("coin") or "").strip().upper()
            coin_matches = (s_coin == pair) or (f"{s_coin}/USDC" == pair)
            if not coin_matches and self.daemon is not None and self.daemon.exchange is not None:
                coin_matches = self.daemon.exchange.are_symbols_equivalent(s_coin, pair)
            if st in (SlotState.ENTRY_PENDING.value, SlotState.OPEN_PROTECTED.value, SlotState.MODIFYING_SL.value) and coin_matches:
                epx = float(s.get("entry_px") or 0.0)
                spx = float(s.get("sl_px") or 0.0)
                tpx = float(s.get("tp_px") or 0.0)
                if epx > 0:
                    ref_base_px = epx
                    horizontal_lines.append(
                        {
                            "slot_id": sid,
                            "type": "ENTRY",
                            "label": f"Slot {sid} Entry ({st})",
                            "price": epx,
                            "color": "#3b82f6",
                            "style": "solid",
                        }
                    )
                if spx > 0:
                    horizontal_lines.append(
                        {
                            "slot_id": sid,
                            "type": "SL",
                            "label": f"Slot {sid} SL (Stage {s.get('trailing_stage', 1)})",
                            "price": spx,
                            "color": "#ef4444",
                            "style": "dashed",
                        }
                    )
                if tpx > 0:
                    horizontal_lines.append(
                        {
                            "slot_id": sid,
                            "type": "TP",
                            "label": f"Slot {sid} TP Target",
                            "price": tpx,
                            "color": "#10b981",
                            "style": "dashed",
                        }
                    )

        candles: List[Dict[str, Any]] = self.fetch_live_or_cached_candles(
            pair_name=pair, interval=iv, current_time_ms=ts
        )
        if not candles:
            step_ms = {
                "15m": 15 * 60_000,
                "1h": 60 * 60_000,
                "4h": 4 * 60 * 60_000,
                "1D": 24 * 60 * 60_000,
            }.get(iv, 15 * 60_000)
            num_bars = 48
            base = ref_base_px
            for i in range(num_bars):
                bar_ts = ts - (num_bars - 1 - i) * step_ms
                wave = math.sin(i * 0.25) * 0.008 * base
                o_px = round(base + wave, 6)
                c_px = round(base + math.sin((i + 1) * 0.25) * 0.008 * base, 6)
                h_px = round(max(o_px, c_px) * 1.004, 6)
                l_px = round(min(o_px, c_px) * 0.996, 6)
                candles.append(
                    {
                        "t": bar_ts,
                        "o": o_px,
                        "h": h_px,
                        "l": l_px,
                        "c": c_px,
                        "v": round(1500.0 + (i % 7) * 250.0, 2),
                    }
                )

        return {
            "pair_name": pair,
            "coin": pair,
            "interval": iv,
            "candles": candles,
            "horizontal_lines": horizontal_lines,
            "supported_pairs": list(SUPPORTED_PAIRS),
            "supported_intervals": list(SUPPORTED_INTERVALS),
        }

    def execute_control_command(
        self,
        command: str,
        confirmed: bool = False,
        current_time_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Web UI の操作ボタン (`PAUSE`, `RESUME`, `CLEAR_PENDING_BUYS`, `EMERGENCY_LIQUIDATE_ALL`) を
        `remote_command_queue` に登録し、さらに0秒でDB状態およびデーモンへ即時反映する。
        `EMERGENCY_LIQUIDATE_ALL` は誤操作防止の2段階確認 (`confirmed=True`) が必須。
        """
        ts = int(current_time_ms) if current_time_ms is not None else now_ms()
        cmd = str(command or "").strip().upper()
        if cmd not in VALID_REMOTE_COMMANDS:
            raise ValueError(f"未対応のコマンドです: {command}")

        if cmd == "EMERGENCY_LIQUIDATE_ALL" and not confirmed:
            return {
                "ok": False,
                "requires_confirmation": True,
                "command": cmd,
                "message": "緊急全決済を実行するには2段階確認モーダルでの承認 (confirmed=true) が必要です。",
            }

        cmd_id = self.db.enqueue_remote_command(cmd)

        if self.daemon is not None:
            self.daemon.process_remote_commands(current_time_ms=ts)
        else:
            if cmd == "PAUSE":
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 1, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
            elif cmd == "RESUME":
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 0, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
            elif cmd == "CLEAR_PENDING_BUYS":
                for sid, s in self.db.get_all_slots().items():
                    if str(s.get("state")) == SlotState.ENTRY_PENDING.value:
                        self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
            elif cmd == "EMERGENCY_LIQUIDATE_ALL":
                for sid in (1, 2):
                    self.coordinator.reset_slot_to_idle(sid, timestamp_ms=ts)
                with self.db.immediate_transaction() as tx:
                    tx.execute(
                        "UPDATE system_state_store SET operator_paused = 1, updated_at_ms = ? WHERE id = 1",
                        (ts,),
                    )
            self.db.mark_command_processed(cmd_id)

        updated_status = self.get_status_payload(current_time_ms=ts)
        return {
            "ok": True,
            "cmd_id": cmd_id,
            "command": cmd,
            "status_badge": updated_status["status_badge"],
            "operator_paused": updated_status["operator_paused"],
            "updated_status": updated_status,
        }

    def build_scrubbed_snapshot_dict(self, current_time_ms: Optional[int] = None) -> Dict[str, Any]:
        """暗号化前の機密スクラブ済みスナップショット辞書を構築する（内部用）"""
        status = self.get_status_payload(current_time_ms=current_time_ms)
        slots_dict = status.get("slots", {})
        s1 = slots_dict.get("1", {}) or {}
        s2 = slots_dict.get("2", {}) or {}

        default_pair = "HYPE/USDC"
        active_pairs: List[str] = []
        for s_item in (s1, s2):
            c_str = str(s_item.get("coin") or "").strip().upper()
            st_str = str(s_item.get("state") or "IDLE").strip().upper()
            if c_str and st_str != "IDLE":
                norm_c = c_str if "/" in c_str else f"{c_str}/USDC"
                if norm_c not in active_pairs:
                    active_pairs.append(norm_c)
        if active_pairs:
            default_pair = active_pairs[0]

        chart_default = self.get_chart_payload(default_pair, "15m", current_time_ms=current_time_ms)

        api_coin_map: Dict[str, str] = {
            "HYPE/USDC": "@107",
            "UBTC/USDC": "@142",
            "UETH/USDC": "@151",
            "USOL/USDC": "@156",
            "PURR/USDC": "PURR/USDC",
            "UZEC/USDC": "@272",
            "XMR1/USDC": "@260",
        }
        if self.daemon is not None and self.daemon.exchange is not None:
            for p_name, sp_ent in self.daemon.exchange.pair_to_entry.items():
                if "/" in p_name and sp_ent.api_coin_name:
                    api_coin_map[p_name.upper()] = sp_ent.api_coin_name

        charts_by_pair: Dict[str, Any] = {}
        priority_pairs = list(dict.fromkeys(active_pairs + ["UZEC/USDC", "HYPE/USDC"]))
        for p_name in priority_pairs:
            candles_by_iv: Dict[str, List[Dict[str, Any]]] = {}
            h_lines: List[Dict[str, Any]] = []
            intervals_to_embed = ("15m", "1h", "4h", "1D") if p_name in active_pairs else ("15m",)
            for iv in intervals_to_embed:
                cp = self.get_chart_payload(p_name, iv, current_time_ms=current_time_ms)
                candles_by_iv[iv] = cp.get("candles", [])
                if not h_lines and cp.get("horizontal_lines"):
                    h_lines = cp.get("horizontal_lines", [])
            charts_by_pair[p_name] = {
                "pair_name": p_name,
                "api_coin_name": api_coin_map.get(p_name, p_name),
                "horizontal_lines": h_lines,
                "candles_by_interval": candles_by_iv,
            }

        raw_public_data = {
            "system_name": "HL AI Trader v1 (Hyperliquid Spot)",
            "generated_at_ms": status["timestamp_ms"],
            "status_badge": status["status_badge"],
            "system_mode": status["system_mode"],
            "operator_paused": status["operator_paused"],
            "equity": status["equity"],
            "equity_history": status["equity_history"][-100:],
            "slots": status["slots"],
            "circuit_breakers": status["circuit_breakers"],
            "ai_memory": status["ai_memory"],
            "tax_summary": status["tax_summary"],
            "default_chart": chart_default,
            "api_coin_map": api_coin_map,
            "charts_by_pair": charts_by_pair,
        }
        return scrub_sensitive_data(raw_public_data)

    def export_public_snapshot(
        self,
        output_path: Optional[Path] = None,
        password: Optional[str] = None,
    ) -> Path:
        """
        GitHub Pages 外出先スマホPWA同期用に、平文の取引データ・銘柄名・残高を1文字も含まない
        完全暗号化コンテナ (`AES-256-GCM` + `PBKDF2-SHA256` 150,000回) を `docs/public_snapshot.json` に出力する。
        """
        ensure_pwa_static_assets()
        target = Path(output_path) if output_path is not None else (DOCS_DIR / "public_snapshot.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        scrubbed_data = self.build_scrubbed_snapshot_dict()
        encrypted_container = encrypt_snapshot_payload(
            payload=scrubbed_data,
            password=password if password is not None else self.auth_manager._get_master_password(),
            iterations=PBKDF2_ITERATIONS,
            updated_at_ms=int(scrubbed_data.get("generated_at_ms") or now_ms()),
        )
        target.write_text(json.dumps(encrypted_container, ensure_ascii=False, indent=2), encoding="utf-8")
        return target


def sync_and_push_docs_to_github(repo_dir: Path = BASE_DIR) -> Dict[str, Any]:
    """
    `docs/` 配下の自己完結PWAおよび暗号化スナップショット (`docs/public_snapshot.json`) のみを
    隔離Git環境 (`.hl_gitconfig`) で安全にコミット＆ `origin main` へ自動Pushする。
    `.env`, `data/*.db`, `logs/` 等の機密ファイルがステージングされることは100%防止する。
    """
    env = build_isolated_git_env()
    try:
        subprocess.run(
            ["git", "add", "docs/"],
            cwd=str(repo_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        st_proc = subprocess.run(
            ["git", "status", "--porcelain", "docs/"],
            cwd=str(repo_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        staged_lines = [ln.strip() for ln in (st_proc.stdout or "").splitlines() if ln.strip()]
        if not staged_lines:
            return {"ok": True, "pushed": False, "reason": "NO_CHANGES_IN_DOCS"}

        ts_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        commit_proc = subprocess.run(
            ["git", "commit", "-m", f"chore(pwa): update encrypted snapshot ({ts_str})", "--", "docs/"],
            cwd=str(repo_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=25,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        gh_token = get_secret("GITHUB_PUSH_TOKEN", dotenv_path=repo_dir / ".env").strip()
        if gh_token:
            auth_b64 = base64.b64encode(f"x-access-token:{gh_token}".encode("utf-8")).decode("ascii")
            push_cmd = [
                "git",
                "-c",
                f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth_b64}",
                "push",
                "origin",
                "main",
            ]
        else:
            auth_b64 = ""
            push_cmd = ["git", "push", "origin", "main"]
        try:
            push_proc = subprocess.run(
                push_cmd,
                cwd=str(repo_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                **hidden_subprocess_kwargs(),
            )
        finally:
            del gh_token
            del auth_b64
            del push_cmd
        if push_proc.returncode != 0:
            err_msg = scrub_secret_text(push_proc.stderr or push_proc.stdout or "git push failed")
            logger.warning("GitHub Pages 自動Push警告: %s", err_msg)
            return {"ok": False, "pushed": False, "error": err_msg}
        return {"ok": True, "pushed": True, "commit_rc": commit_proc.returncode}
    except Exception as exc:
        err_msg = scrub_secret_text(exc)
        logger.warning("GitHub Pages 自動Push例外: %s", err_msg)
        return {"ok": False, "pushed": False, "error": err_msg}


# ==============================================================================
# HTML / PWA テンプレート (Forensic Ledger 完全準拠 認証ロック画面 + ダッシュボード)
# ==============================================================================
def _load_dashboard_html() -> str:
    idx_path = DOCS_DIR / "index.html"
    if idx_path.exists():
        return idx_path.read_text(encoding="utf-8")
    return ""


DASHBOARD_HTML = _load_dashboard_html()

MANIFEST_JSON = {
    "name": "HL AI Trader v1 — 暗号化AI自動売買コンソール",
    "short_name": "HLTraderV1",
    "description": "ゼロ知識クライアント復号型 Hyperliquid AI自動売買ダッシュボード (AES-256-GCM / PBKDF2-SHA256 150,000回)",
    "start_url": "./",
    "scope": "./",
    "display": "standalone",
    "orientation": "any",
    "background_color": "#0b1220",
    "theme_color": "#0d9488",
    "icons": [
        {"src": "./icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any maskable"},
        {"src": "./icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
        {"src": "./icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
    ],
}

SW_JS = """const CACHE_NAME = 'hl-ai-trader-v1-shell-v3';
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {});
"""

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#0f172a"/>
  <path d="M24 92 L50 52 L70 72 L104 30" stroke="#5eead4" stroke-width="10" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="64" y="114" text-anchor="middle" fill="#ffffff" font-family="sans-serif" font-weight="800" font-size="22">HL AI</text>
</svg>"""

ROBOTS_TXT = "User-agent: *\nDisallow: /\n"

SECURITY_HEADERS: Dict[str, str] = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Robots-Tag": "noindex, nofollow",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self' 'unsafe-inline' data: blob: https:; "
        "frame-ancestors 'none'"
    ),
}

ALLOWED_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]", "::1"})


def _get_header_ci(headers: Any, key: str) -> str:
    if headers is None:
        return ""
    if hasattr(headers, "get"):
        val = headers.get(key)
        if val is not None:
            return str(val)
    if isinstance(headers, dict):
        key_low = key.lower()
        for k, v in headers.items():
            if str(k).lower() == key_low and v is not None:
                return str(v)
    return ""


def validate_local_request_security(
    headers: Any,
    method: str = "GET",
    bound_port: int = 8081,
) -> bool:
    """
    ローカルWebサーバー (`127.0.0.1:8081`) の DNS Rebinding / CSRF / Cross-Site 防御検証:
    1) `Sec-Fetch-Site` が `cross-site` の場合は即座に `False` (`HTTP 403 Forbidden`)。
    2) `Origin` ヘッダが存在しローカルオリジン (`127.0.0.1`, `localhost`, `[::1]`) でない場合は `False`。
    3) `Host` ヘッダが `127.0.0.1:8081`, `localhost:8081`, `127.0.0.1`, `localhost`, `[::1]:8081`, `[::1]`
       (またはテスト用バインドポート `bound_port`) 以外の場合は `False`。
    """
    sec_fetch_site = _get_header_ci(headers, "Sec-Fetch-Site").strip().lower()
    if sec_fetch_site == "cross-site":
        return False

    origin = _get_header_ci(headers, "Origin").strip().lower()
    if origin:
        if origin == "null":
            return False
        try:
            parsed_orig = urlparse(origin)
            hostname = (parsed_orig.hostname or "").lower()
            if hostname not in ("127.0.0.1", "localhost", "::1"):
                return False
            if parsed_orig.port is not None and int(parsed_orig.port) not in (8081, int(bound_port)):
                return False
        except Exception:
            return False

    raw_host = _get_header_ci(headers, "Host").strip().lower()
    if not raw_host:
        return False

    if raw_host.startswith("["):
        if "]:" in raw_host:
            h_part, p_part = raw_host.rsplit(":", 1)
        else:
            h_part, p_part = raw_host, ""
    elif ":" in raw_host:
        h_part, p_part = raw_host.rsplit(":", 1)
    else:
        h_part, p_part = raw_host, ""

    if h_part not in ALLOWED_LOCAL_HOSTS:
        return False

    if p_part:
        if not p_part.isdigit():
            return False
        req_port = int(p_part)
        if req_port not in (8081, int(bound_port)):
            return False

    return True


def create_dashboard_http_server(
    service: DashboardStateService,
    host: str = "127.0.0.1",
    port: int = 8081,
) -> ThreadingHTTPServer:
    """
    `DashboardStateService` をバインドし、6層セキュリティ（Host検証、CSRF防御、
    セキュリティヘッダ強制、パスワード認証強制、ブルートフォースロックアウト）を備えた
    `ThreadingHTTPServer` (デフォルト Port 8081) を生成する。
    """
    ensure_pwa_static_assets()

    class DashboardRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _apply_security_headers(self, extra_headers: Optional[Dict[str, str]] = None) -> None:
            for hk, hv in SECURITY_HEADERS.items():
                self.send_header(hk, hv)
            if extra_headers:
                for ek, ev in extra_headers.items():
                    self.send_header(ek, ev)

        def _send_json(
            self,
            payload: Dict[str, Any],
            status_code: int = 200,
            extra_headers: Optional[Dict[str, str]] = None,
        ) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self._apply_security_headers(extra_headers)
            self.end_headers()
            self.wfile.write(raw)

        def _send_bytes(
            self,
            raw: bytes,
            content_type: str,
            status_code: int = 200,
        ) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(raw)

        def _send_text(self, text: str, content_type: str, status_code: int = 200) -> None:
            self._send_bytes(text.encode("utf-8"), content_type, status_code=status_code)

        def _verify_host_header(self) -> bool:
            """
            DNS Rebinding / Cross-Site 攻撃防御:
            `validate_local_request_security` により `Host`, `Origin`, `Sec-Fetch-Site` を検証する。
            """
            bound_port = int(self.server.server_address[1])  # type: ignore[attr-defined]
            return validate_local_request_security(self.headers, method=self.command or "GET", bound_port=bound_port)

        def _verify_same_origin_on_post(self) -> bool:
            """
            CSRF / Cross-Site 防御: `Origin` および `Sec-Fetch-Site` を検証する。
            """
            bound_port = int(self.server.server_address[1])  # type: ignore[attr-defined]
            return validate_local_request_security(self.headers, method="POST", bound_port=bound_port)

        def _is_authenticated(self) -> bool:
            token = self.headers.get("X-HL-Auth") or self.headers.get("Authorization") or ""
            return service.auth_manager.verify_request_token(token)

        def do_GET(self) -> None:
            if not self._verify_host_header():
                self._send_json(
                    {"ok": False, "error": "Forbidden: Invalid Host header (DNS Rebinding defense)"},
                    status_code=403,
                )
                return

            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            # 1. 公開静的シェル & PWAアセット (平文の取引データは0文字)
            if path in ("/", "/index.html"):
                html_text = _load_dashboard_html() or DASHBOARD_HTML
                self._send_text(html_text, "text/html; charset=utf-8")
                return
            if path == "/manifest.json":
                self._send_json(MANIFEST_JSON)
                return
            if path == "/sw.js":
                sw_path = DOCS_DIR / "sw.js"
                sw_body = sw_path.read_text(encoding="utf-8") if sw_path.exists() else SW_JS
                self._send_text(sw_body, "application/javascript; charset=utf-8")
                return
            if path == "/robots.txt":
                self._send_text(ROBOTS_TXT, "text/plain; charset=utf-8")
                return
            if path == "/icon.svg":
                svg_path = DOCS_DIR / "icon.svg"
                svg_body = svg_path.read_text(encoding="utf-8") if svg_path.exists() else ICON_SVG
                self._send_text(svg_body, "image/svg+xml; charset=utf-8")
                return
            if path in ("/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"):
                img_path = DOCS_DIR / path.lstrip("/")
                if not img_path.exists():
                    sz = 192 if "192" in path else (512 if "512" in path else 180)
                    generate_hl_icon_png(sz, img_path)
                self._send_bytes(img_path.read_bytes(), "image/png")
                return
            if path in ("/static/app.js", "/app.js"):
                app_js_path = WEB_STATIC_DIR / "app.js"
                js_body = (
                    app_js_path.read_text(encoding="utf-8")
                    if app_js_path.exists()
                    else "window.HL_TRADER_V1_PORT = 8081;"
                )
                self._send_text(js_body, "application/javascript; charset=utf-8")
                return
            if path == "/public_snapshot.json":
                snap_path = service.export_public_snapshot()
                self._send_text(snap_path.read_text(encoding="utf-8"), "application/json; charset=utf-8")
                return
            if path == "/api/auth/status":
                locked, retry_sec = service.auth_manager.is_locked_out()
                self._send_json(
                    {
                        "ok": True,
                        "authenticated": self._is_authenticated(),
                        "locked_out": locked,
                        "retry_after_sec": retry_sec,
                    }
                )
                return

            # 2. 認証保護対象APIエンドポイント (未認証は HTTP 401 Unauthorized で完全遮断)
            if path in ("/api/status", "/api/state", "/api/chart", "/api/candles"):
                if not self._is_authenticated():
                    self._send_json(
                        {
                            "ok": False,
                            "error": "Unauthorized: Master password unlock required.",
                            "locked": True,
                        },
                        status_code=401,
                    )
                    return

                if path in ("/api/status", "/api/state"):
                    self._send_json(service.get_status_payload())
                    return
                if path in ("/api/chart", "/api/candles"):
                    pair = (qs.get("pair") or qs.get("coin") or ["HYPE/USDC"])[0]
                    interval = (qs.get("interval") or ["15m"])[0]
                    self._send_json(service.get_chart_payload(pair_name=pair, interval=interval))
                    return

            self._send_json({"error": "Not Found", "path": path}, status_code=404)

        def do_POST(self) -> None:
            try:
                length = max(0, int(self.headers.get("Content-Length", "0")))
            except ValueError:
                length = 0
            raw_body = (
                self.rfile.read(min(length, 65536)).decode("utf-8", errors="replace")
                if length > 0
                else "{}"
            )

            if not self._verify_host_header():
                self._send_json(
                    {"ok": False, "error": "Forbidden: Invalid Host header (DNS Rebinding defense)"},
                    status_code=403,
                )
                return
            if not self._verify_same_origin_on_post():
                self._send_json(
                    {"ok": False, "error": "Forbidden: Cross-origin POST blocked (CSRF defense)"},
                    status_code=403,
                )
                return

            parsed = urlparse(self.path)
            path = parsed.path

            # 1. パスワードロック解除エンドポイント (POST /api/auth/unlock)
            if path == "/api/auth/unlock":
                try:
                    body = json.loads(raw_body) if raw_body.strip() else {}
                except Exception:
                    self._send_json({"ok": False, "error": "Invalid JSON body"}, status_code=400)
                    return
                candidate_pw = str(body.get("password", ""))
                code, res_dict = service.auth_manager.attempt_unlock(candidate_pw)
                extra_hdr = (
                    {"Retry-After": str(int(math.ceil(res_dict.get("retry_after_sec", 60))))}
                    if code == 429
                    else None
                )
                self._send_json(res_dict, status_code=code, extra_headers=extra_hdr)
                return

            # 2. 即時ロックエンドポイント (POST /api/auth/lock)
            if path == "/api/auth/lock":
                tok = self.headers.get("X-HL-Auth") or self.headers.get("Authorization") or ""
                service.auth_manager.revoke_token(tok)
                self._send_json({"ok": True, "locked": True})
                return

            # 3. 制御コマンドエンドポイント (POST /api/command, /api/control) — 認証必須
            if path in ("/api/command", "/api/control"):
                if not self._is_authenticated():
                    self._send_json(
                        {
                            "ok": False,
                            "error": "Unauthorized: Master password unlock required.",
                            "locked": True,
                        },
                        status_code=401,
                    )
                    return

                try:
                    body = json.loads(raw_body)
                    command = str(body.get("command", ""))
                    confirmed = bool(body.get("confirmed") or body.get("confirm") or False)
                    result = service.execute_control_command(command=command, confirmed=confirmed)
                    code = 200 if result.get("ok") else 400
                    self._send_json(result, status_code=code)
                except ValueError as exc:
                    self._send_json({"ok": False, "error": scrub_secret_text(exc)}, status_code=400)
                except Exception as exc:
                    self._send_json({"ok": False, "error": scrub_secret_text(exc)}, status_code=500)
                return

            self._send_json({"error": "Not Found"}, status_code=404)

    return ThreadingHTTPServer((host, int(port)), DashboardRequestHandler)


def sync_live_readonly_account_state(
    service: DashboardStateService,
    pause_on_init: bool = True,
) -> Dict[str, Any]:
    """
    Hyperliquid Mainnet `/info` を読み取り専用で照会し、メインウォレットの最新USDC残高・
    USDC/JPY為替レート・ユニバース辞書を `system_state_store` および `DashboardStateService` に同期する。
    監査・待機モード中は `operator_paused = 1` (`PAUSED`) を設定し、一切の自動発注を行わない。
    """
    from src.exchange_wrapper import HLSDKInfo, HyperliquidExchangeWrapper, MAINNET_API_URL

    dotenv_file = BASE_DIR / ".env"
    load_safe_dotenv(dotenv_file)
    harden_windows_file_acl(dotenv_file)
    harden_windows_file_acl(service.db.db_path)
    harden_windows_file_acl(ISOLATED_GITCONFIG_PATH)
    harden_windows_file_acl(BASE_DIR / ".git" / "config")
    ts = now_ms()

    if service.daemon is not None and service.daemon.exchange is not None:
        wrapper = service.daemon.exchange
    else:
        info_client = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True) if HLSDKInfo is not None else None
        wrapper = HyperliquidExchangeWrapper(
            execution_mode="DRY_RUN",
            db=service.db,
            coordinator=service.coordinator,
            tax_engine=service.tax_engine,
            info_client=info_client,
        )

    if wrapper.info is None and HLSDKInfo is not None:
        wrapper.info = HLSDKInfo(base_url=wrapper.base_url, skip_ws=True)

    if wrapper.info is not None:
        try:
            wrapper.refresh_universe_mapping()
        except Exception as exc:
            logger.warning("起動時 refresh_universe_mapping 警告: %s", exc)

    balances = wrapper.get_spot_balances()
    usdc_total = float(balances.get("USDC", {}).get("total", 0.0))
    non_usdc_val = 0.0
    for asset_name, bal_info in balances.items():
        coin_up = str(asset_name).strip().upper()
        if coin_up in wrapper.NON_TRADING_STABLECOINS:
            continue
        qty_f = float(bal_info.get("total", 0.0))
        if qty_f <= 0.0:
            continue
        sp_ent = wrapper.get_spot_entry(f"{coin_up}/USDC") or wrapper.get_spot_entry(coin_up)
        px_f = float((sp_ent.spot_mid_px or sp_ent.spot_mark_px) if sp_ent else 0.0)
        if px_f > 0.0:
            non_usdc_val += qty_f * px_f

    portfolio_total_usdc = usdc_total + non_usdc_val

    rate_jpy = 155.0
    if service.daemon is not None and service.daemon.rate_fetcher is not None:
        rate_jpy, _ = service.daemon.rate_fetcher.get_rate()
    else:
        from src.utils import UsdcJpyRateFetcher

        rf = UsdcJpyRateFetcher(db_rate_provider=service.db.get_latest_usdc_jpy_rate)
        rate_jpy, _ = rf.get_rate()

    eq_val = 143.73
    with service.db.immediate_transaction() as tx:
        row = tx.execute("SELECT * FROM system_state_store WHERE id = 1").fetchone()
        ep_cnt_row = tx.execute("SELECT COUNT(*) AS cnt FROM ai_episodic_memory").fetchone()
        ep_cnt = int(ep_cnt_row["cnt"]) if ep_cnt_row else 0
        if row:
            eq_val = portfolio_total_usdc if portfolio_total_usdc > 0 else float(row["current_equity_usdc"] or 143.73)
            prev_init = float(row["initial_equity_usdc"] or 0.0)
            prev_sod = float(row["sod_equity_usdc"] or 0.0)
            prev_sow = float(row["sow_equity_usdc"] or 0.0)
            if ep_cnt == 0 and non_usdc_val == 0.0 and portfolio_total_usdc > 0:
                init_eq = eq_val
                hwm_eq = eq_val
                sod_eq = eq_val
                sow_eq = eq_val
            else:
                baseline_eq = 143.730553 if (prev_init < 100.0 and eq_val >= 100.0) else (prev_init if prev_init > 0 else eq_val)
                init_eq = baseline_eq
                hwm_eq = max(init_eq, eq_val, float(row["hwm_equity_usdc"] or 0.0))
                sod_eq = baseline_eq if (prev_sod < 100.0 and eq_val >= 100.0) else (prev_sod if prev_sod > 0 else eq_val)
                sow_eq = baseline_eq if (prev_sow < 100.0 and eq_val >= 100.0) else (prev_sow if prev_sow > 0 else eq_val)
            paused_int = 1 if pause_on_init else 0
            tx.execute(
                """
                UPDATE system_state_store
                SET operator_paused = ?,
                    initial_equity_usdc = ?,
                    hwm_equity_usdc = ?,
                    sod_equity_usdc = ?,
                    sow_equity_usdc = ?,
                    current_equity_usdc = ?,
                    latest_usdc_jpy_rate = ?,
                    updated_at_ms = ?
                WHERE id = 1
                """,
                (paused_int, init_eq, hwm_eq, sod_eq, sow_eq, eq_val, rate_jpy, ts),
            )
            service._equity_history.clear()
            service.record_equity_point(eq_val, rate_jpy, hwm_eq, timestamp_ms=ts)

    if service.tax_engine is not None and usdc_total > 0 and non_usdc_val == 0.0:
        try:
            service.tax_engine.bootstrap_initial_usdc_inventory(
                actual_usdc_total=usdc_total,
                usdc_jpy_rate=rate_jpy,
                timestamp_ms=ts,
            )
        except Exception as exc:
            logger.warning("起動時 USDC 税務在庫ブートストラップ警告: %s", exc)

    # 暗号化済み docs/public_snapshot.json も最新状態に更新
    try:
        service.export_public_snapshot()
    except Exception as exc:
        logger.warning("起動時 暗号化スナップショット出力警告: %s", exc)

    return service.get_status_payload(current_time_ms=ts)


if __name__ == "__main__":
    import argparse
    from src.exchange_wrapper import HLSDKInfo, HyperliquidExchangeWrapper, MAINNET_API_URL

    purge_dangerous_environment_variables()
    enable_process_extension_point_mitigation()
    install_egress_domain_whitelist_guard()
    load_safe_dotenv(BASE_DIR / ".env")
    parser = argparse.ArgumentParser(description="HL AI Trader v1 — Port 8081 Web Dashboard Server")
    parser.add_argument("--host", default=os.getenv("WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("WEB_PORT", "8081")))
    parser.add_argument("--paused", action="store_true", default=True, help="Start in PAUSED (operator_paused=1) mode")
    args = parser.parse_args()

    db_mgr = DatabaseManager()
    coord_mgr = ConcurrencyStateCoordinator(db=db_mgr)
    tax_mgr = HyperliquidTaxEngine(db=db_mgr)
    info_cli = HLSDKInfo(base_url=MAINNET_API_URL, skip_ws=True) if HLSDKInfo is not None else None
    ex_wrap = HyperliquidExchangeWrapper(
        execution_mode="DRY_RUN",
        db=db_mgr,
        coordinator=coord_mgr,
        tax_engine=tax_mgr,
        info_client=info_cli,
    )
    daemon_inst = HLTraderDaemon(
        db=db_mgr,
        coordinator=coord_mgr,
        tax_engine=tax_mgr,
        exchange_wrapper=ex_wrap,
    )
    svc = DashboardStateService(
        db=db_mgr,
        tax_engine=tax_mgr,
        coordinator=coord_mgr,
        daemon=daemon_inst,
    )
    sync_live_readonly_account_state(svc, pause_on_init=args.paused)
    srv = create_dashboard_http_server(service=svc, host=args.host, port=args.port)
    print(
        f"HL AI Trader v1 Web Dashboard running on http://{args.host}:{args.port} (PAUSED={args.paused}, AUTH_LOCK=ENABLED)",
        flush=True,
    )
    srv.serve_forever()
