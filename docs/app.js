// ============================================================================
// HL AI Trader v1 — Zero-Knowledge AES-256-GCM PWA & Port 8081 Console Controller
// (web/static/app.js / docs/app.js / docs/static/app.js)
// - Web Crypto API: importKey -> deriveKey (PBKDF2-SHA256, 150,000 iter) -> decrypt (AES-GCM)
// - Port 8081 Local Server Auth: POST ./api/auth/unlock -> X-HL-Auth HMAC token
// - GitHub Pages Subpath & Local Port 8081 Dual Compatibility (Relative Paths ./...)
// - Remember Device (<0.5s instant auto-unlock) & "🔒 今すぐロック" instant wipe
// ============================================================================
'use strict';

window.HL_TRADER_V1_PORT = 8081;

const HL_STORAGE_TOKEN_KEY = 'HL_TRADER_AUTH_TOKEN_V1';
const HL_STORAGE_REMEMBER_KEY = 'HL_TRADER_REMEMBER_DEVICE_V1';
const HL_STORAGE_DERIVED_CACHE_KEY = 'HL_TRADER_DERIVED_KEY_CACHE_V1';
const HL_STORAGE_DEVICE_VAULT_KEY = 'HL_TRADER_DEVICE_VAULT_V1';
const HL_STORAGE_DEVICE_WRAP_KEY = 'HL_TRADER_DEVICE_WRAP_KEY_V1';
const PBKDF2_ITERATIONS = 150000;

const DEFAULT_SPOT_API_COINS = {
  'UZEC/USDC': '@272',
  'HYPE/USDC': '@107',
  'UBTC/USDC': '@142',
  'UETH/USDC': '@151',
  'USOL/USDC': '@156',
  'PURR/USDC': 'PURR/USDC',
  'XMR1/USDC': '@260'
};

let __hlAuthToken = '';
let __hlDecryptedState = null;
let __hlConnectionMode = 'DETECTING'; // 'LOCAL_API' | 'ENCRYPTED_PWA'
let __hlLastUpdatedMs = 0;
let __hlPollTimer = null;
let __hlElapsedTimer = null;
let __hlCachedPasscodeInMemory = '';
let __hlInitialPairSelected = false;
let __hlLiveMidPrices = {};

function isLikelyLocalhost() {
  if (typeof window === 'undefined' || !window.location) return false;
  const h = (window.location.hostname || '').toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]';
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function bytesToB64(buf) {
  const u8 = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < u8.length; i++) {
    bin += String.fromCharCode(u8[i]);
  }
  return btoa(bin);
}

function togglePwVisibility() {
  const inp = document.getElementById('hl-pw-input');
  const eye = document.getElementById('hl-pw-eye');
  if (!inp || !eye) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    eye.textContent = '🙈';
  } else {
    inp.type = 'password';
    eye.textContent = '👁️';
  }
}

function setLockMessage(msg, isError) {
  const el = document.getElementById('hl-lock-msg');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'lock-msg ' + (isError ? 'err' : 'ok');
}

function shakeLockCard() {
  const card = document.getElementById('hl-lock-card');
  if (!card) return;
  card.classList.remove('shake');
  void card.offsetWidth;
  card.classList.add('shake');
}

// ============================================================================
// Web Crypto API: PBKDF2-SHA256 (150,000回) + AES-256-GCM 復号エンジン
// ============================================================================
async function deriveAesGcmKeyFromPassword(password, saltBytes, iterations) {
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey', 'deriveBits']
  );
  const aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: iterations || PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  return aesKey;
}

async function decryptSnapshotContainerWithKey(container, aesKey) {
  const ivBytes = b64ToBytes(container.iv_b64);
  const ctBytes = b64ToBytes(container.ciphertext_b64);
  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    aesKey,
    ctBytes
  );
  const jsonText = new TextDecoder('utf-8').decode(decryptedBuf);
  return JSON.parse(jsonText);
}

async function decryptSnapshotContainerWithPassword(container, password, rememberDevice) {
  if (!container || !container.encrypted || !container.salt_b64 || !container.iv_b64 || !container.ciphertext_b64) {
    throw new Error('暗号化スナップショットの形式が不正です');
  }
  const saltB64 = container.salt_b64;
  const iterations = Number(container.iterations || PBKDF2_ITERATIONS);

  // 1. Web Crypto API: importKey (extractable: false) -> deriveKey (PBKDF2 150,000回, extractable: false) -> decrypt (AES-GCM)
  const saltBytes = b64ToBytes(saltB64);
  const aesKey = await deriveAesGcmKeyFromPassword(password, saltBytes, iterations);
  const decryptedData = await decryptSnapshotContainerWithKey(container, aesKey);

  // 2. 端末記憶ON時は非抽出ラップ鍵 (extractable: false) でパスコードをローカル保護（exportKey は一切不使用）
  if (rememberDevice) {
    try {
      localStorage.removeItem(HL_STORAGE_DERIVED_CACHE_KEY);
      await saveDeviceWrappedPasscode(password);
    } catch (_) {}
  }
  return decryptedData;
}

// 端末ローカル専用のランダムAES-GCM鍵でパスコードをラップ保存（15分ごとの新Salt更新時も0.2秒で自動復号）
async function saveDeviceWrappedPasscode(password) {
  try {
    const rawWrapKey = window.crypto.getRandomValues(new Uint8Array(32));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await window.crypto.subtle.importKey(
      'raw',
      rawWrapKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt']
    );
    const ctBuf = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      wrapKey,
      new TextEncoder().encode(password)
    );
    localStorage.setItem(HL_STORAGE_DEVICE_WRAP_KEY, bytesToB64(rawWrapKey));
    localStorage.setItem(
      HL_STORAGE_DEVICE_VAULT_KEY,
      JSON.stringify({ iv_b64: bytesToB64(iv), ct_b64: bytesToB64(ctBuf) })
    );
  } catch (_) {}
}

async function loadDeviceWrappedPasscode() {
  try {
    const wrapKeyB64 = localStorage.getItem(HL_STORAGE_DEVICE_WRAP_KEY);
    const vaultRaw = localStorage.getItem(HL_STORAGE_DEVICE_VAULT_KEY);
    if (!wrapKeyB64 || !vaultRaw) return '';
    const vault = JSON.parse(vaultRaw);
    const wrapKey = await window.crypto.subtle.importKey(
      'raw',
      b64ToBytes(wrapKeyB64),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const ptBuf = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(vault.iv_b64) },
      wrapKey,
      b64ToBytes(vault.ct_b64)
    );
    return new TextDecoder('utf-8').decode(ptBuf);
  } catch (_) {
    return '';
  }
}

// ============================================================================
// ロック解除 & 即時ロック制御
// ============================================================================
function showUnlockedDashboard(mode) {
  __hlConnectionMode = mode;
  const lockScreen = document.getElementById('hl-lock-screen');
  const appMount = document.getElementById('hl-app-mount');
  if (lockScreen) lockScreen.style.display = 'none';
  if (appMount) appMount.style.display = 'block';

  const modeBadge = document.getElementById('connectionModeBadge');
  const localControls = document.getElementById('localControlButtons');
  if (modeBadge) {
    if (mode === 'LOCAL_API') {
      modeBadge.textContent = '🖥️ PCローカルLIVE制御 (Port 8081)';
      modeBadge.className = 'mode-badge mode-local';
      if (localControls) localControls.style.display = 'flex';
    } else {
      modeBadge.textContent = '📱 外出先スマホPWA (AES-256-GCM復号)';
      modeBadge.className = 'mode-badge mode-pwa';
      if (localControls) localControls.style.display = 'none';
    }
  }

  startBackgroundTimers();
}

function lockNow() {
  if (__hlConnectionMode === 'LOCAL_API' && __hlAuthToken) {
    fetch('./api/auth/lock', {
      method: 'POST',
      headers: getAuthHeaders()
    }).catch(() => {});
  }
  __hlAuthToken = '';
  __hlDecryptedState = null;
  __hlCachedPasscodeInMemory = '';
  try {
    localStorage.removeItem(HL_STORAGE_TOKEN_KEY);
    localStorage.removeItem(HL_STORAGE_REMEMBER_KEY);
    localStorage.removeItem(HL_STORAGE_DERIVED_CACHE_KEY);
    localStorage.removeItem(HL_STORAGE_DEVICE_VAULT_KEY);
    localStorage.removeItem(HL_STORAGE_DEVICE_WRAP_KEY);
    sessionStorage.clear();
  } catch (_) {}

  if (__hlPollTimer) {
    clearInterval(__hlPollTimer);
    __hlPollTimer = null;
  }

  const sensitiveIds = ['eqUsdc', 'eqJpy', 'hwmAndL5', 'slot1Box', 'slot2Box', 'taxBox'];
  sensitiveIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '-- (🔒 ロック中)';
  });
  ['equityCanvas', 'candleCanvas'].forEach(cid => {
    const c = document.getElementById(cid);
    if (c && c.getContext) {
      const ctx = c.getContext('2d');
      ctx.clearRect(0, 0, c.width, c.height);
    }
  });

  const appMount = document.getElementById('hl-app-mount');
  const lockScreen = document.getElementById('hl-lock-screen');
  const pwInput = document.getElementById('hl-pw-input');
  if (appMount) appMount.style.display = 'none';
  if (lockScreen) lockScreen.style.display = 'flex';
  if (pwInput) {
    pwInput.value = '';
    pwInput.focus();
  }
  setLockMessage('🔒 セッションをロックし、端末内の復号鍵を消去しました。', false);
}

async function handleUnlockSubmit(event) {
  if (event) event.preventDefault();
  const pwInput = document.getElementById('hl-pw-input');
  const remChk = document.getElementById('hl-remember-chk');
  const btn = document.getElementById('hl-unlock-btn');
  const password = pwInput ? pwInput.value : '';
  const rememberDevice = remChk ? Boolean(remChk.checked) : true;

  if (!password) {
    setLockMessage('パスワードを入力してください。', true);
    shakeLockCard();
    return;
  }

  if (btn) btn.disabled = true;
  setLockMessage('🔐 PBKDF2-SHA256 (150,000回) 鍵導出 ＆ 認証確認中...', false);

  try {
    let localServerReachable = false;
    if (isLikelyLocalhost()) {
      try {
        const authRes = await fetch('./api/auth/unlock', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        if (authRes.status === 200 || authRes.status === 401 || authRes.status === 429) {
          localServerReachable = true;
          const authData = await authRes.json();
          if (authRes.status === 429) {
            setLockMessage(
              `🚫 ロックアウト中: 連続失敗のため ${Math.ceil(authData.retry_after_sec || 60)}秒間 再試行できません。`,
              true
            );
            shakeLockCard();
            return;
          }
          if (authRes.status === 401 || !authData.ok) {
            const rem = typeof authData.remaining_attempts === 'number' ? ` (残り試行回数: ${authData.remaining_attempts}回)` : '';
            setLockMessage(`❌ パスワードが正しくありません${rem}`, true);
            shakeLockCard();
            return;
          }
          __hlAuthToken = authData.token || '';
          __hlCachedPasscodeInMemory = password;
          if (rememberDevice) {
            localStorage.setItem(HL_STORAGE_REMEMBER_KEY, '1');
            localStorage.setItem(HL_STORAGE_TOKEN_KEY, __hlAuthToken);
            await saveDeviceWrappedPasscode(password);
          } else {
            localStorage.removeItem(HL_STORAGE_REMEMBER_KEY);
            localStorage.removeItem(HL_STORAGE_TOKEN_KEY);
          }
          setLockMessage('', false);
          showUnlockedDashboard('LOCAL_API');
          await fetchStatus();
          await loadChart();
          return;
        }
      } catch (_) {
        localServerReachable = false;
      }
    }

    if (!localServerReachable) {
      const snapRes = await fetch('./public_snapshot.json?t=' + Date.now(), { cache: 'no-store' });
      if (!snapRes.ok) {
        throw new Error('暗号化スナップショット (public_snapshot.json) を取得できませんでした。');
      }
      const container = await snapRes.json();
      const decrypted = await decryptSnapshotContainerWithPassword(container, password, rememberDevice);
      __hlDecryptedState = decrypted;
      __hlCachedPasscodeInMemory = password;
      if (rememberDevice) {
        localStorage.setItem(HL_STORAGE_REMEMBER_KEY, '1');
      }
      setLockMessage('', false);
      showUnlockedDashboard('ENCRYPTED_PWA');
      renderDashboardStatus(decrypted);
      await loadChart();
      return;
    }
  } catch (err) {
    setLockMessage('❌ パスワードが異なるか、復号に失敗しました。', true);
    shakeLockCard();
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function attemptAutoUnlockOnBoot() {
  try {
    const remembered = localStorage.getItem(HL_STORAGE_REMEMBER_KEY) === '1';
    if (!remembered) return;

    if (isLikelyLocalhost()) {
      const savedToken = localStorage.getItem(HL_STORAGE_TOKEN_KEY) || '';
      if (savedToken) {
        try {
          const res = await fetch('./api/status', {
            headers: { 'X-HL-Auth': savedToken },
            cache: 'no-store'
          });
          if (res.ok) {
            __hlAuthToken = savedToken;
            const data = await res.json();
            showUnlockedDashboard('LOCAL_API');
            renderDashboardStatus(data);
            await loadChart();
            return;
          }
        } catch (_) {}
      }
    }

    const wrappedPassword = await loadDeviceWrappedPasscode();
    if (!wrappedPassword) return;

    if (isLikelyLocalhost()) {
      try {
        const authRes = await fetch('./api/auth/unlock', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: wrappedPassword })
        });
        if (authRes.ok) {
          const authData = await authRes.json();
          if (authData && authData.ok && authData.token) {
            __hlAuthToken = authData.token;
            __hlCachedPasscodeInMemory = wrappedPassword;
            localStorage.setItem(HL_STORAGE_TOKEN_KEY, __hlAuthToken);
            showUnlockedDashboard('LOCAL_API');
            await fetchStatus();
            await loadChart();
            return;
          }
        }
      } catch (_) {}
    }

    try {
      const snapRes = await fetch('./public_snapshot.json?t=' + Date.now(), { cache: 'no-store' });
      if (snapRes.ok) {
        const container = await snapRes.json();
        const decrypted = await decryptSnapshotContainerWithPassword(container, wrappedPassword, true);
        __hlDecryptedState = decrypted;
        __hlCachedPasscodeInMemory = wrappedPassword;
        showUnlockedDashboard('ENCRYPTED_PWA');
        renderDashboardStatus(decrypted);
        await loadChart();
      }
    } catch (_) {}
  } catch (_) {}
}

// ============================================================================
// ステータス・チャート取得 & 手動リフレッシュ
// ============================================================================
function getAuthHeaders(extra) {
  const h = Object.assign({}, extra || {});
  if (__hlAuthToken) {
    h['X-HL-Auth'] = __hlAuthToken;
  }
  return h;
}

async function fetchStatus() {
  try {
    if (__hlConnectionMode === 'LOCAL_API' && __hlAuthToken) {
      const res = await fetch('./api/status', {
        headers: getAuthHeaders(),
        cache: 'no-store'
      });
      if (res.status === 401) {
        lockNow();
        return;
      }
      if (res.ok) {
        const data = await res.json();
        renderDashboardStatus(data);
        return;
      }
    }

    if (__hlConnectionMode === 'ENCRYPTED_PWA') {
      const pw = __hlCachedPasscodeInMemory || (await loadDeviceWrappedPasscode());
      if (!pw) return;
      const snapRes = await fetch('./public_snapshot.json?t=' + Date.now(), { cache: 'no-store' });
      if (snapRes.ok) {
        const container = await snapRes.json();
        const decrypted = await decryptSnapshotContainerWithPassword(container, pw, true);
        __hlDecryptedState = decrypted;
        renderDashboardStatus(decrypted);
      }
    }
  } catch (err) {
    console.error('fetchStatus error:', err);
  }
}

async function manualRefreshDashboard() {
  const btn = document.getElementById('btnManualRefresh');
  if (btn) btn.textContent = '⏳ 取得中...';
  try {
    await fetchStatus();
    await loadChart();
  } finally {
    if (btn) btn.textContent = '🔄 更新 (最新データ取得)';
  }
}

function updateElapsedTimestampDisplay() {
  const el = document.getElementById('lastUpdatedLabel');
  if (!el) return;
  if (!__hlLastUpdatedMs) {
    el.textContent = '最終更新: --';
    return;
  }
  const diffSec = Math.max(0, Math.floor((Date.now() - __hlLastUpdatedMs) / 1000));
  const dt = new Date(__hlLastUpdatedMs);
  const hh = String(dt.getHours()).padStart(2, '0');
  const mm = String(dt.getMinutes()).padStart(2, '0');
  const ss = String(dt.getSeconds()).padStart(2, '0');
  if (diffSec < 60) {
    el.textContent = `最終更新: ${diffSec}秒前 (${hh}:${mm}:${ss})`;
  } else {
    const mins = Math.floor(diffSec / 60);
    el.textContent = `最終更新: ${mins}分${diffSec % 60}秒前 (${hh}:${mm}:${ss})`;
  }
}

function startBackgroundTimers() {
  if (__hlPollTimer) clearInterval(__hlPollTimer);
  if (__hlElapsedTimer) clearInterval(__hlElapsedTimer);
  const pollInterval = __hlConnectionMode === 'LOCAL_API' ? 5000 : 30000;
  __hlPollTimer = setInterval(fetchStatus, pollInterval);
  __hlElapsedTimer = setInterval(updateElapsedTimestampDisplay, 1000);
}

function formatSlotCardHtml(s, rateJpy) {
  if (!s || !s.state || s.state === 'IDLE') {
    return '<div style="color:#9ca3af;"><strong>IDLE</strong> (待機中 / ポジションなし)</div>';
  }
  const state = escapeHtml(s.state || 'IDLE');
  const subState = escapeHtml(s.sub_state || 'NONE');
  const pair = escapeHtml(s.coin || '-');
  const sz = Number(s.current_sz || 0);
  const entryPx = Number(s.entry_px || 0);
  const slPx = Number(s.sl_px || 0);
  const tpPx = Number(s.tp_px || 0);
  const stage = Number(s.trailing_stage || 1);
  const livePx = Number(
    __hlLiveMidPrices[s.coin] || s.current_px || s.mark_px || entryPx || 0
  );

  let pnlHtml = '';
  if (entryPx > 0 && sz > 0 && livePx > 0) {
    const pnlUsdc = (livePx - entryPx) * sz;
    const pnlPct = ((livePx - entryPx) / entryPx) * 100.0;
    const pnlJpy = Math.round(pnlUsdc * (rateJpy || 156.8));
    const color = pnlUsdc >= 0 ? '#10b981' : '#ef4444';
    const sign = pnlUsdc >= 0 ? '+' : '';
    pnlHtml =
      `<div style="margin-top:6px; font-weight:700; color:${color};">` +
      `現在値: ${livePx} | 含み損益: ${sign}${pnlUsdc.toFixed(2)} USDC (${sign}${pnlPct.toFixed(2)}% / ≈ ${sign}¥${pnlJpy.toLocaleString()})` +
      `</div>`;
  }

  return (
    `<div style="line-height:1.5;">` +
    `<div><strong style="color:#38bdf8;">${state}</strong> <span style="font-size:0.82rem; color:#94a3b8;">(${subState} / 4段階トレーリング: Stage ${stage}/4)</span></div>` +
    `<div>銘柄: <strong>${pair}</strong> | 数量: ${sz}</div>` +
    `<div>Entry: <strong style="color:#60a5fa;">${entryPx}</strong> | SL: <strong style="color:#f87171;">${slPx}</strong> | TP: <strong style="color:#34d399;">${tpPx}</strong></div>` +
    pnlHtml +
    `</div>`
  );
}

function ensurePairOptionAndSelectActive(slots) {
  const pairEl = document.getElementById('pairSelect');
  if (!pairEl || !slots) return;

  ['1', '2'].forEach(sid => {
    const s = slots[sid] || {};
    const c = (s.coin || '').trim().toUpperCase();
    if (c && s.state && s.state !== 'IDLE') {
      const exists = Array.from(pairEl.options).some(opt => opt.value.toUpperCase() === c);
      if (!exists) {
        const opt = document.createElement('option');
        opt.value = c;
        opt.textContent = c;
        pairEl.insertBefore(opt, pairEl.firstChild);
      }
      if (!__hlInitialPairSelected) {
        pairEl.value = c;
        __hlInitialPairSelected = true;
      }
    }
  });
}

function renderDashboardStatus(data) {
  if (!data) return;
  __hlLastUpdatedMs = Number(data.timestamp_ms || data.generated_at_ms || Date.now());
  updateElapsedTimestampDisplay();

  const badge = document.getElementById('statusBadge');
  if (badge && data.status_badge) {
    badge.textContent = data.status_badge;
    badge.className = 'badge badge-' + data.status_badge;
  }
  const eq = data.equity || {};
  const rate = typeof eq.usdc_jpy_rate === 'number' ? eq.usdc_jpy_rate : 155.0;
  const eqUsdcEl = document.getElementById('eqUsdc');
  if (eqUsdcEl && typeof eq.current_usdc === 'number') {
    const retPct = typeof eq.total_return_pct === 'number' ? eq.total_return_pct : 0.0;
    eqUsdcEl.textContent =
      eq.current_usdc.toFixed(2) + ' USDC (' + (retPct >= 0 ? '+' : '') + retPct.toFixed(2) + '%)';
  }
  const eqJpyEl = document.getElementById('eqJpy');
  if (eqJpyEl && typeof eq.current_jpy === 'number') {
    eqJpyEl.textContent =
      '≈ ¥' + Math.round(eq.current_jpy).toLocaleString() + ' (USDC/JPY: ' + rate.toFixed(2) + ')';
  }
  const hwmEl = document.getElementById('hwmAndL5');
  if (hwmEl && typeof eq.hwm_usdc === 'number' && typeof eq.l5_floor_usdc === 'number') {
    hwmEl.textContent =
      'HWM: ' + eq.hwm_usdc.toFixed(2) + ' USDC | L5防衛ライン(85%): ' + eq.l5_floor_usdc.toFixed(2) + ' USDC';
  }

  const slots = data.slots || {};
  ensurePairOptionAndSelectActive(slots);

  const s1Box = document.getElementById('slot1Box');
  if (s1Box) {
    s1Box.innerHTML = formatSlotCardHtml(slots['1'] || {}, rate);
  }
  const s2Box = document.getElementById('slot2Box');
  if (s2Box) {
    s2Box.innerHTML = formatSlotCardHtml(slots['2'] || {}, rate);
  }

  const tx = data.tax_summary || {};
  const taxBox = document.getElementById('taxBox');
  if (taxBox) {
    taxBox.innerHTML = `年度: ${escapeHtml(String(tx.tax_year || '-'))}年 (${Number(tx.lot_count || 0)}約定)<br>移動平均法損益: ¥${Number(tx.moving_average_pnl_jpy_int || 0).toLocaleString()}<br>総平均法損益: ¥${Number(tx.total_average_pnl_jpy_int || 0).toLocaleString()}`;
  }

  drawEquityChart(data.equity_history || [], eq.hwm_usdc || 0, eq.l5_floor_usdc || 0);
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildHorizontalLinesForPair(pair, stateObj) {
  const lines = [];
  if (!stateObj || !stateObj.slots) return lines;
  const targetPair = String(pair || '').trim().toUpperCase();

  ['1', '2'].forEach(sid => {
    const s = stateObj.slots[sid] || {};
    const st = String(s.state || 'IDLE');
    const sCoin = String(s.coin || '').trim().toUpperCase();
    if (
      (st === 'OPEN_PROTECTED' || st === 'ENTRY_PENDING' || st === 'MODIFYING_SL') &&
      (sCoin === targetPair || `${sCoin}/USDC` === targetPair)
    ) {
      const epx = Number(s.entry_px || 0);
      const spx = Number(s.sl_px || 0);
      const tpx = Number(s.tp_px || 0);
      const stg = Number(s.trailing_stage || 1);
      if (epx > 0) {
        lines.push({
          slot_id: Number(sid),
          type: 'ENTRY',
          label: `Slot ${sid} Entry (${st})`,
          price: epx,
          color: '#3b82f6',
          style: 'solid'
        });
      }
      if (spx > 0) {
        lines.push({
          slot_id: Number(sid),
          type: 'SL',
          label: `Slot ${sid} SL (Stage ${stg})`,
          price: spx,
          color: '#ef4444',
          style: 'dashed'
        });
      }
      if (tpx > 0) {
        lines.push({
          slot_id: Number(sid),
          type: 'TP',
          label: `Slot ${sid} TP Target`,
          price: tpx,
          color: '#10b981',
          style: 'dashed'
        });
      }
    }
  });
  return lines;
}

async function fetchPublicHyperliquidCandles(pair, iv, stateObj) {
  const normPair = String(pair || 'HYPE/USDC').trim().toUpperCase();
  const mapFromSnap = (stateObj && stateObj.api_coin_map) || {};
  const apiCoin = mapFromSnap[normPair] || DEFAULT_SPOT_API_COINS[normPair] || normPair;
  const hlIv = iv === '1D' ? '1d' : iv;
  const stepMs = {
    '15m': 15 * 60000,
    '1h': 60 * 60000,
    '4h': 4 * 60 * 60000,
    '1d': 24 * 60 * 60000
  }[hlIv] || (15 * 60000);
  const endMs = Date.now();
  const startMs = endMs - 60 * stepMs;

  const resp = await fetch('https://api.hyperliquid.xyz/info', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'candleSnapshot',
      req: {
        coin: apiCoin,
        interval: hlIv,
        startTime: startMs,
        endTime: endMs
      }
    })
  });
  if (!resp.ok) return [];
  const raw = await resp.json();
  if (!Array.isArray(raw) || !raw.length) return [];
  return raw.slice(-60).map(b => ({
    t: Number(b.t || endMs),
    o: Number(b.o || 0),
    h: Number(b.h || 0),
    l: Number(b.l || 0),
    c: Number(b.c || 0),
    v: Number(b.v || 0)
  }));
}

async function loadChart() {
  try {
    const pairEl = document.getElementById('pairSelect');
    const ivEl = document.getElementById('intervalSelect');
    const pair = pairEl ? pairEl.value : 'UZEC/USDC';
    const iv = ivEl ? ivEl.value : '15m';

    if (__hlConnectionMode === 'LOCAL_API' && __hlAuthToken) {
      const res = await fetch(
        `./api/chart?pair=${encodeURIComponent(pair)}&interval=${encodeURIComponent(iv)}`,
        { headers: getAuthHeaders(), cache: 'no-store' }
      );
      if (res.ok) {
        const data = await res.json();
        const bars = data.candles || [];
        if (bars.length) {
          __hlLiveMidPrices[pair] = Number(bars[bars.length - 1].c || 0);
        }
        drawCandleChart(bars, data.horizontal_lines || []);
        return;
      }
    }

    if (__hlDecryptedState) {
      const byPairMap = __hlDecryptedState.charts_by_pair || {};
      const pairBundle = byPairMap[pair] || {};
      const byInterval = pairBundle.candles_by_interval || {};
      let candles = byInterval[iv] || (iv === '15m' ? pairBundle.candles : null) || [];
      let hLines = pairBundle.horizontal_lines || buildHorizontalLinesForPair(pair, __hlDecryptedState);
      if (!hLines || !hLines.length) {
        hLines = buildHorizontalLinesForPair(pair, __hlDecryptedState);
      }

      if (candles && candles.length) {
        __hlLiveMidPrices[pair] = Number(candles[candles.length - 1].c || 0);
        drawCandleChart(candles, hLines);
        renderDashboardStatus(__hlDecryptedState);
      }

      // Hyperliquid 公開 /info (candleSnapshot) CORS フォールバックで最新足をリアルタイム取得
      try {
        const liveBars = await fetchPublicHyperliquidCandles(pair, iv, __hlDecryptedState);
        if (liveBars && liveBars.length) {
          __hlLiveMidPrices[pair] = Number(liveBars[liveBars.length - 1].c || 0);
          drawCandleChart(liveBars, hLines);
          renderDashboardStatus(__hlDecryptedState);
          return;
        }
      } catch (_) {}

      if (!candles || !candles.length) {
        const defChart = __hlDecryptedState.default_chart || {};
        drawCandleChart(defChart.candles || [], hLines);
      }
    }
  } catch (err) {
    console.error('loadChart error:', err);
  }
}

async function sendCommand(command, confirmed = false) {
  if (__hlConnectionMode !== 'LOCAL_API' || !__hlAuthToken) return;
  const res = await fetch('./api/command', {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ command, confirmed })
  });
  if (res.status === 401) {
    lockNow();
    return;
  }
  await res.json();
  await fetchStatus();
  await loadChart();
}

function openConfirmModal() {
  const m = document.getElementById('confirmModal');
  if (m) m.style.display = 'flex';
}
function closeConfirmModal() {
  const m = document.getElementById('confirmModal');
  if (m) m.style.display = 'none';
}
async function confirmEmergencyLiquidate() {
  closeConfirmModal();
  await sendCommand('EMERGENCY_LIQUIDATE_ALL', true);
}

function drawEquityChart(points, hwm, l5Floor) {
  const c = document.getElementById('equityCanvas');
  if (!c) return;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  if (!points.length) return;
  const vals = points.map(p => p.equity_usdc).concat([hwm, l5Floor]);
  const minV = Math.min(...vals) * 0.98;
  const maxV = Math.max(...vals) * 1.02;
  const toY = v => c.height - 20 - ((v - minV) / Math.max(1e-6, maxV - minV)) * (c.height - 40);

  ctx.strokeStyle = '#10b981';
  ctx.setLineDash([4, 4]);
  ctx.beginPath();
  ctx.moveTo(20, toY(hwm));
  ctx.lineTo(c.width - 20, toY(hwm));
  ctx.stroke();
  ctx.fillStyle = '#10b981';
  ctx.font = '11px sans-serif';
  ctx.fillText(`HWM: ${Number(hwm).toFixed(2)} USDC`, 24, Math.max(12, toY(hwm) - 5));

  ctx.strokeStyle = '#ef4444';
  ctx.beginPath();
  ctx.moveTo(20, toY(l5Floor));
  ctx.lineTo(c.width - 20, toY(l5Floor));
  ctx.stroke();
  ctx.fillStyle = '#ef4444';
  ctx.fillText(`L5 Floor (85%): ${Number(l5Floor).toFixed(2)} USDC`, 24, Math.min(c.height - 6, toY(l5Floor) + 13));
  ctx.setLineDash([]);

  ctx.strokeStyle = '#3b82f6';
  ctx.lineWidth = 2;
  ctx.beginPath();
  points.forEach((p, idx) => {
    const x = 20 + (idx / Math.max(1, points.length - 1)) * (c.width - 40);
    const y = toY(p.equity_usdc);
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function drawCandleChart(candles, hLines) {
  const c = document.getElementById('candleCanvas');
  if (!c) return;
  const ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  if (!candles.length) return;
  let allPx = [];
  candles.forEach(b => {
    allPx.push(b.h, b.l);
  });
  hLines.forEach(l => {
    allPx.push(l.price);
  });
  const minP = Math.min(...allPx) * 0.998;
  const maxP = Math.max(...allPx) * 1.002;
  const toY = p => c.height - 20 - ((p - minP) / Math.max(1e-6, maxP - minP)) * (c.height - 40);

  const stepX = (c.width - 40) / candles.length;
  candles.forEach((b, i) => {
    const x = 20 + i * stepX + stepX * 0.5;
    const isUp = b.c >= b.o;
    ctx.strokeStyle = isUp ? '#10b981' : '#ef4444';
    ctx.fillStyle = ctx.strokeStyle;
    ctx.beginPath();
    ctx.moveTo(x, toY(b.h));
    ctx.lineTo(x, toY(b.l));
    ctx.stroke();
    const yTop = toY(Math.max(b.o, b.c));
    const yBot = toY(Math.min(b.o, b.c));
    ctx.fillRect(x - stepX * 0.3, yTop, stepX * 0.6, Math.max(2, yBot - yTop));
  });

  ctx.font = 'bold 11px sans-serif';
  hLines.forEach(l => {
    const y = toY(l.price);
    ctx.strokeStyle = l.color || '#3b82f6';
    ctx.lineWidth = 1.5;
    ctx.setLineDash(l.style === 'dashed' ? [5, 4] : []);
    ctx.beginPath();
    ctx.moveTo(20, y);
    ctx.lineTo(c.width - 20, y);
    ctx.stroke();
    ctx.fillStyle = l.color || '#3b82f6';
    ctx.fillText(`${l.label}: ${l.price}`, 26, Math.max(14, y - 4));
  });
  ctx.setLineDash([]);
  ctx.lineWidth = 1;
}

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./sw.js').catch(() => {});
    }
    attemptAutoUnlockOnBoot();
  });
}
