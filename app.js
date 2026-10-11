/* カギメモ — 端末内で暗号化するパスワードメモ（PWA）
 *
 * 暗号の構成
 *  - データ鍵(DEK): AES-GCM 256bit。メモ一覧(JSON)はこの鍵で暗号化して IndexedDB に保存
 *  - DEK は次の2通りで「包んで」保存（どちらか一方で解除できる）
 *      1) パスキー(Face ID)の PRF 出力 → HKDF-SHA256 → 鍵暗号鍵
 *      2) 復旧用パスフレーズ → PBKDF2-SHA256(600,000回) → 鍵暗号鍵
 *  - 解除後の DEK はエクスポート不可の CryptoKey としてメモリにだけ置き、ロックで破棄
 *  - サーバー通信なし。外部スクリプトなし（CSPで禁止）
 */
'use strict';
(() => {
  const APP_VERSION = '1.1.0';
  const PBKDF2_ITER = 600000;
  const MIN_PASS = 10;
  const te = new TextEncoder();
  const td = new TextDecoder();
  const AAD_VAULT = te.encode('kagimemo:vault:v1');
  const AAD_PRF = te.encode('kagimemo:wrap:prf:v1');
  const AAD_PASS = te.encode('kagimemo:wrap:pass:v1');
  const DEFAULTS = { idleSec: 300, hideSec: 60, clipSec: 60, lastBackup: null };

  const $ = (s, r = document) => r.querySelector(s);
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  const b64 = (buf) => {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s);
  };
  const ub64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const ymd = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const fmtDate = (t) => { const d = new Date(t); return `${ymd(d)} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };

  class AppError extends Error {}

  /* ---------- IndexedDB ---------- */
  let dbp;
  function openDB() {
    if (!dbp) {
      dbp = new Promise((res, rej) => {
        const r = indexedDB.open('kagimemo', 1);
        r.onupgradeneeded = () => r.result.createObjectStore('kv');
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
    }
    return dbp;
  }
  async function tx(mode, fn) {
    const db = await openDB();
    return new Promise((res, rej) => {
      const t = db.transaction('kv', mode);
      const req = fn(t.objectStore('kv'));
      t.oncomplete = () => res(req ? req.result : undefined);
      t.onerror = () => rej(t.error);
      t.onabort = () => rej(t.error);
    });
  }
  const dbGet = (k) => tx('readonly', (s) => s.get(k));
  const dbPut = (k, v) => tx('readwrite', (s) => s.put(v, k));
  const dbPutMany = (obj) => tx('readwrite', (s) => { for (const [k, v] of Object.entries(obj)) s.put(v, k); });
  const dbClear = () => tx('readwrite', (s) => s.clear());

  /* ---------- 暗号 ---------- */
  async function prfKEK(prfOut) {
    const base = await crypto.subtle.importKey('raw', prfOut, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('kagimemo kek v1') },
      base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
  }
  async function passKEK(pass, salt, iter) {
    const base = await crypto.subtle.importKey('raw', te.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter },
      base, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
  }
  async function wrap(dek, kek, aad) {
    const iv = rnd(12);
    const ct = await crypto.subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv, additionalData: aad });
    return { iv: b64(iv), ct: b64(ct) };
  }
  function unwrap(w, kek, aad, extractable) {
    return crypto.subtle.unwrapKey('raw', ub64(w.ct), kek, { name: 'AES-GCM', iv: ub64(w.iv), additionalData: aad },
      { name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
  }
  async function toNonExtractable(key) {
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const k = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    raw.fill(0);
    return k;
  }
  async function encVault(entries, key) {
    const iv = rnd(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD_VAULT }, key, te.encode(JSON.stringify({ entries })));
    return { iv: b64(iv), ct: b64(ct) };
  }
  async function decVault(v, key) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(v.iv), additionalData: AAD_VAULT }, key, ub64(v.ct));
    const obj = JSON.parse(td.decode(pt));
    return Array.isArray(obj.entries) ? obj.entries : [];
  }

  /* ---------- パスキー(WebAuthn PRF) ---------- */
  async function registerPasskey(salt) {
    if (!window.PublicKeyCredential) throw new AppError('この環境はパスキーに対応していません。');
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'カギメモ' },
        user: { id: rnd(16), name: `カギメモ (${ymd(new Date())})`, displayName: 'カギメモ' },
        challenge: rnd(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        timeout: 120000,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
    const prf = cred.getClientExtensionResults().prf || {};
    if (prf.enabled === false) throw new AppError('PRF');
    const first = prf.results && prf.results.first;
    return { credId: b64(cred.rawId), prfOut: first ? new Uint8Array(first) : null };
  }
  async function prfEval(credIdB64, saltB64) {
    const a = await navigator.credentials.get({
      publicKey: {
        challenge: rnd(32),
        allowCredentials: [{ type: 'public-key', id: ub64(credIdB64) }],
        userVerification: 'required',
        timeout: 120000,
        extensions: { prf: { eval: { first: ub64(saltB64) } } },
      },
    });
    const r = a.getClientExtensionResults().prf;
    if (!r || !r.results || !r.results.first) throw new AppError('PRF');
    return new Uint8Array(r.results.first);
  }
  function webauthnMessage(e) {
    if (e instanceof AppError && e.message === 'PRF') {
      return 'このパスキーは暗号化に必要な機能(PRF)に対応していません。iOS 18以降で、パスキーの保存先に「iCloudキーチェーン（パスワード）」を選んでください。';
    }
    if (e instanceof AppError) return e.message;
    switch (e && e.name) {
      case 'NotAllowedError': return 'キャンセルされたか、時間切れになりました。';
      case 'InvalidStateError': return 'このパスキーはすでに登録されています。';
      case 'SecurityError': return 'このアドレスではパスキーを使えません（HTTPSの正式なドメインで開いてください）。';
      case 'NotSupportedError': return 'この端末はパスキーに対応していません。';
      default: return '失敗しました：' + ((e && e.message) || e);
    }
  }

  /* ---------- 状態 ---------- */
  const state = {
    meta: null, vault: null, dek: null, entries: [], settings: { ...DEFAULTS },
    setup: {}, query: '', current: null, idleTimer: 0, hiddenAt: 0,
    clip: { timer: 0, until: 0, pending: false },
  };

  /* ---------- 画面 ---------- */
  function show(name) {
    document.querySelectorAll('.screen').forEach((s) => { s.hidden = s.id !== 'screen-' + name; });
    window.scrollTo(0, 0);
  }
  let toastTimer = 0;
  function toast(msg, ms = 2200) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), ms);
  }
  function closeDialogs() { document.querySelectorAll('dialog[open]').forEach((d) => d.close()); }
  function setErr(id, msg) { $(id).textContent = msg || ''; }

  /* ---------- 起動 ---------- */
  async function init() {
    if (!window.isSecureContext || !window.crypto || !crypto.subtle) {
      document.body.textContent = 'HTTPS で開いてください。';
      return;
    }
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    bindUI();
    $('#app-version').textContent = 'カギメモ v' + APP_VERSION;
    const isIOS = /iPhone|iPad|iPod/.test(navigator.userAgent);
    const standalone = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
    $('#install-hint').hidden = !(isIOS && !standalone);

    state.settings = { ...DEFAULTS, ...((await dbGet('settings')) || {}) };
    state.meta = await dbGet('meta');
    state.vault = await dbGet('vault');
    if (state.meta && state.vault) showLock(); else show('welcome');
  }

  /* ---------- セットアップ ---------- */
  function passHint(p) {
    if (!p) return '';
    const len = [...p].length;
    if (len < MIN_PASS) return `あと${MIN_PASS - len}文字以上必要です`;
    if (len < 14) return '使えます。14文字以上にするとより安全です';
    return 'じゅうぶんな長さです';
  }
  async function finishSetup(pk) {
    const pass = state.setup.pass;
    if (!pass) { show('setup-pass'); return; }
    const dek = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const salt = rnd(16);
    const meta = {
      v: 1, created: Date.now(),
      pass: { salt: b64(salt), iter: PBKDF2_ITER, wrap: await wrap(dek, await passKEK(pass, salt, PBKDF2_ITER), AAD_PASS) },
    };
    if (pk) {
      meta.prf = { credId: pk.credId, salt: b64(pk.salt), wrap: await wrap(dek, await prfKEK(pk.prfOut), AAD_PRF) };
      pk.prfOut.fill(0);
    }
    const key = await toNonExtractable(dek);
    const vault = await encVault([], key);
    await dbPutMany({ meta, vault });
    state.meta = meta; state.vault = vault; state.dek = key; state.entries = [];
    state.setup = {};
    $('#sp-1').value = ''; $('#sp-2').value = '';
    enterMain();
    toast('準備ができました');
  }

  /* ---------- 解除・ロック ---------- */
  function showLock() {
    $('#btn-unlock-face').hidden = !state.meta.prf;
    setErr('#lock-err');
    show('lock');
  }
  async function unlockWithFace() {
    setErr('#lock-err');
    try {
      const m = state.meta;
      const out = await prfEval(m.prf.credId, m.prf.salt);
      const kek = await prfKEK(out);
      out.fill(0);
      let dek;
      try { dek = await unwrap(m.prf.wrap, kek, AAD_PRF, false); } catch { throw new AppError('Face IDの鍵が一致しません。パスフレーズで解除してから、設定でFace IDを登録し直してください。'); }
      await openVault(dek);
    } catch (e) {
      setErr('#lock-err', webauthnMessage(e));
    }
  }
  async function dekFromPass(pass, extractable) {
    const m = state.meta;
    const kek = await passKEK(pass, ub64(m.pass.salt), m.pass.iter);
    try { return await unwrap(m.pass.wrap, kek, AAD_PASS, extractable); } catch { throw new AppError('パスフレーズが違います。'); }
  }
  async function openVault(dek) {
    const entries = await decVault(state.vault, dek);
    state.dek = dek;
    state.entries = entries;
    enterMain();
  }
  function lock() {
    state.dek = null;
    state.entries = [];
    state.current = null;
    closeDialogs();
    $('#list').replaceChildren();
    $('#search').value = ''; state.query = '';
    clearEditForm();
    clearDetail();
    clearTimeout(state.idleTimer);
    if (state.meta) showLock(); else show('welcome');
  }
  function resetIdle() {
    if (!state.dek) return;
    clearTimeout(state.idleTimer);
    state.idleTimer = setTimeout(lock, state.settings.idleSec * 1000);
  }

  /* ---------- メイン一覧 ---------- */
  function enterMain() {
    render();
    show('main');
    resetIdle();
  }
  function matches(e, q) {
    if (!q) return true;
    return [e.title, e.username, e.url, e.note].some((v) => (v || '').toLowerCase().includes(q));
  }
  function hostOf(url) { try { return new URL(url).hostname; } catch { return ''; } }
  function render() {
    const q = state.query.trim().toLowerCase();
    const items = state.entries.filter((e) => matches(e, q))
      .sort((a, b) => (a.title || '').localeCompare(b.title || '', 'ja'));
    const list = $('#list');
    list.replaceChildren();
    for (const e of items) {
      const li = document.createElement('li');
      li.className = 'item';
      const main = document.createElement('button');
      main.className = 'row-main';
      main.type = 'button';
      main.addEventListener('click', () => openDetail(e.id));
      const av = document.createElement('span');
      av.className = 'avatar';
      av.textContent = [...(e.title || '?').trim()][0] || '?';
      const txt = document.createElement('span');
      txt.className = 'row-text';
      const t = document.createElement('div');
      t.className = 'row-title';
      t.textContent = e.title || '(名前なし)';
      const s = document.createElement('div');
      s.className = 'row-sub';
      s.textContent = e.username || hostOf(e.url) || ' ';
      txt.append(t, s);
      main.append(av, txt);
      const cu = copyButton('ID', () => e.username, 'IDをコピー');
      const cp = copyButton('PW', () => e.password, 'パスワードをコピー');
      li.append(main, cu, cp);
      list.append(li);
    }
    $('#empty').hidden = state.entries.length !== 0;
    if (state.entries.length && !items.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = '見つかりませんでした';
      list.append(li);
    }
    renderBanner();
  }
  function copyButton(label, getter, aria) {
    const b = document.createElement('button');
    b.className = 'copy';
    b.type = 'button';
    b.textContent = label;
    b.setAttribute('aria-label', aria);
    b.dataset.copyBtn = '1';
    if (!getter()) b.disabled = true;
    b.addEventListener('click', () => copyText(getter(), label === 'ID' ? 'ID' : 'パスワード', b));
    return b;
  }
  function renderBanner() {
    const el = $('#banner');
    el.replaceChildren();
    let msg = '';
    if (!state.meta.prf) msg = 'Face IDが未設定です。';
    else if (state.entries.length && (!state.settings.lastBackup || Date.now() - state.settings.lastBackup > 30 * 86400e3)) {
      msg = state.settings.lastBackup ? '最後のバックアップから30日以上たっています。' : 'まだバックアップがありません。端末をなくすと復元できません。';
    }
    el.hidden = !msg;
    if (!msg) return;
    el.append(msg);
    const b = document.createElement('button');
    b.className = 'link small';
    b.textContent = '設定を開く';
    b.addEventListener('click', openSettings);
    el.append(b);
  }

  /* ---------- コピー ---------- */
  async function copyText(text, label, btn) {
    if (!text) return;
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = legacyCopy(text); }
    if (!ok) { toast('コピーできませんでした'); return; }
    if (btn) { btn.classList.add('done'); setTimeout(() => btn.classList.remove('done'), 900); }
    const sec = state.settings.clipSec;
    clearTimeout(state.clip.timer);
    state.clip.pending = sec > 0;
    state.clip.until = Date.now() + sec * 1000;
    if (sec > 0) {
      state.clip.timer = setTimeout(() => tryClearClipboard(), sec * 1000);
      toast(`${label}をコピーしました（${sec}秒後に消去）`);
    } else {
      toast(`${label}をコピーしました`);
    }
  }
  function legacyCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.className = 'secret';
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    return ok;
  }
  async function tryClearClipboard() {
    if (!state.clip.pending || Date.now() < state.clip.until) return;
    try { await navigator.clipboard.writeText(''); state.clip.pending = false; } catch { /* iOSはタップ時に再試行 */ }
  }

  /* ---------- 詳細 ---------- */
  function findEntry(id) { return state.entries.find((e) => e.id === id); }
  function clearDetail() {
    ['#d-title', '#d-user', '#d-pass', '#d-note', '#d-updated'].forEach((s) => { $(s).textContent = ''; });
    $('#d-url').textContent = ''; $('#d-url').removeAttribute('href');
  }
  function openDetail(id) {
    const e = findEntry(id);
    if (!e) return;
    state.current = id;
    $('#d-title').textContent = e.title || '(名前なし)';
    $('#d-user').textContent = e.username || '';
    $('#d-user-row').hidden = !e.username;
    setPassMasked(true);
    $('#d-pass-row').hidden = !e.password;
    const safeUrl = /^https?:\/\//i.test(e.url || '') ? e.url : '';
    $('#d-url').textContent = e.url || '';
    if (safeUrl) $('#d-url').href = safeUrl; else $('#d-url').removeAttribute('href');
    $('#d-url-row').hidden = !e.url;
    $('#d-note').textContent = e.note || '';
    $('#d-note-row').hidden = !e.note;
    $('#d-updated').textContent = '更新：' + fmtDate(e.updated || e.created);
    $('#dlg-detail').showModal();
  }
  function setPassMasked(masked) {
    const e = findEntry(state.current);
    $('#d-pass').textContent = masked ? '•'.repeat(Math.min(12, (e && e.password || '').length || 8)) : (e && e.password) || '';
    $('#btn-d-reveal').textContent = masked ? '表示' : '隠す';
    $('#btn-d-reveal').dataset.masked = masked ? '1' : '';
  }

  /* ---------- 編集 ---------- */
  function clearEditForm() {
    ['#e-title', '#e-user', '#e-pass', '#e-url', '#e-note'].forEach((s) => { $(s).value = ''; });
    $('#e-pass').classList.remove('reveal');
    $('#btn-e-reveal').textContent = '表示';
  }
  function openEdit(id, copyFromId) {
    clearEditForm();
    const e = id ? findEntry(id) : null;
    const src = e || (copyFromId ? findEntry(copyFromId) : null);
    state.current = e ? e.id : null;
    $('#e-heading').textContent = e ? '編集' : (src ? '複製して追加' : '追加');
    if (src) {
      $('#e-title').value = e ? (src.title || '') : `${src.title || ''}（コピー）`;
      $('#e-user').value = src.username || '';
      $('#e-pass').value = src.password || '';
      $('#e-url').value = src.url || '';
      $('#e-note').value = src.note || '';
    }
    $('#dlg-edit').showModal();
    if (!e) setTimeout(() => { const t = $('#e-title'); t.focus(); if (src) t.select(); }, 50);
  }
  async function saveEdit() {
    const data = {
      title: $('#e-title').value.trim(),
      username: $('#e-user').value.trim(),
      password: $('#e-pass').value,
      url: $('#e-url').value.trim(),
      note: $('#e-note').value,
    };
    if (!data.title) { toast('名前を入力してください'); return; }
    const now = Date.now();
    if (state.current) {
      const e = findEntry(state.current);
      Object.assign(e, data, { updated: now });
    } else {
      state.entries.push({ id: b64(rnd(12)), ...data, created: now, updated: now });
    }
    await persist();
    $('#dlg-edit').close();
    clearEditForm();
    render();
    toast('保存しました');
  }
  async function persist() {
    const v = await encVault(state.entries, state.dek);
    await dbPut('vault', v);
    state.vault = v;
  }
  async function deleteCurrent() {
    const e = findEntry(state.current);
    if (!e) return;
    if (!confirm(`「${e.title}」を削除しますか？`)) return;
    state.entries = state.entries.filter((x) => x.id !== e.id);
    await persist();
    $('#dlg-detail').close();
    render();
    toast('削除しました');
  }

  /* ---------- パスワード生成 ---------- */
  function randInt(n) {
    const lim = Math.floor(0x100000000 / n) * n;
    const a = new Uint32Array(1);
    do crypto.getRandomValues(a); while (a[0] >= lim);
    return a[0] % n;
  }
  function genPassword(len, sym) {
    const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789'];
    if (sym) sets.push('!#$%&*+-=?@_');
    const all = sets.join('');
    for (;;) {
      let s = '';
      for (let i = 0; i < len; i++) s += all[randInt(all.length)];
      if (sets.every((set) => [...s].some((c) => set.includes(c)))) return s;
    }
  }

  /* ---------- ダイアログ補助 ---------- */
  function askPass(title, msg, okLabel = 'OK') {
    return new Promise((resolve) => {
      const d = $('#dlg-pass');
      $('#p-title').textContent = title;
      $('#p-msg').textContent = msg || '';
      $('#p-ok').textContent = okLabel;
      $('#p-input').value = '';
      setErr('#p-err');
      const form = $('#form-pass');
      const onSubmit = (ev) => {
        ev.preventDefault();
        const v = $('#p-input').value;
        cleanup();
        d.close();
        resolve(v);
      };
      const onClose = () => { cleanup(); resolve(null); };
      function cleanup() {
        form.removeEventListener('submit', onSubmit);
        d.removeEventListener('close', onClose);
        $('#p-input').value = '';
      }
      form.addEventListener('submit', onSubmit);
      d.addEventListener('close', onClose);
      d.showModal();
      setTimeout(() => $('#p-input').focus(), 50);
    });
  }
  // Face IDの呼び出しにはタップ直後である必要があるため、確認ボタンを1回挟む
  function askTap(title, msg, okLabel) {
    return new Promise((resolve) => {
      const d = $('#dlg-action');
      $('#a-title').textContent = title;
      $('#a-msg').textContent = msg || '';
      $('#a-ok').textContent = okLabel;
      const ok = () => { done(true); };
      const cancel = () => { done(false); };
      const onClose = () => { done(false); };
      let fired = false;
      function done(v) {
        if (fired) return;
        fired = true;
        $('#a-ok').removeEventListener('click', ok);
        $('#a-cancel').removeEventListener('click', cancel);
        d.removeEventListener('close', onClose);
        if (d.open) d.close();
        resolve(v);
      }
      $('#a-ok').addEventListener('click', ok);
      $('#a-cancel').addEventListener('click', cancel);
      d.addEventListener('close', onClose);
      d.showModal();
    });
  }

  /* ---------- 設定 ---------- */
  function openSettings() {
    $('#set-idle').value = String(state.settings.idleSec);
    $('#set-hide').value = String(state.settings.hideSec);
    $('#set-clip').value = String(state.settings.clipSec);
    $('#face-status').textContent = state.meta.prf ? '登録済み' : '未設定';
    $('#btn-reregister').textContent = state.meta.prf ? 'Face ID（パスキー）を登録し直す' : 'Face ID（パスキー）を登録する';
    $('#backup-status').textContent = state.settings.lastBackup ? '最後の書き出し：' + fmtDate(state.settings.lastBackup) : 'まだ書き出していません';
    show('settings');
  }
  async function saveSettings() { await dbPut('settings', state.settings); }

  async function reRegisterPasskey() {
    const pass = await askPass('Face IDを登録', '確認のため、復旧用パスフレーズを入力してください。');
    if (pass === null) return;
    let dekX;
    try { dekX = await dekFromPass(pass, true); } catch (e) { toast(e.message, 3000); return; }
    const go = await askTap('Face IDを登録', '次の画面でパスキーを保存してください。', '登録する');
    if (!go) return;
    try {
      const salt = rnd(32);
      let { credId, prfOut } = await registerPasskey(salt);
      if (!prfOut) {
        const go2 = await askTap('もう一度Face ID', '有効化のため、もう一度Face IDで確認します。', '確認する');
        if (!go2) return;
        prfOut = await prfEval(credId, b64(salt));
      }
      const meta = { ...state.meta, prf: { credId, salt: b64(salt), wrap: await wrap(dekX, await prfKEK(prfOut), AAD_PRF) } };
      prfOut.fill(0);
      await dbPut('meta', meta);
      state.meta = meta;
      openSettings();
      toast('Face IDを登録しました');
    } catch (e) {
      alert(webauthnMessage(e));
    }
  }
  async function changePass(ev) {
    ev.preventDefault();
    setErr('#np-err');
    const cur = $('#np-cur').value, p1 = $('#np-1').value, p2 = $('#np-2').value;
    if ([...p1].length < MIN_PASS) { setErr('#np-err', `新しいパスフレーズは${MIN_PASS}文字以上にしてください。`); return; }
    if (p1 !== p2) { setErr('#np-err', '確認用が一致しません。'); return; }
    try {
      const dekX = await dekFromPass(cur, true);
      const salt = rnd(16);
      const meta = { ...state.meta, pass: { salt: b64(salt), iter: PBKDF2_ITER, wrap: await wrap(dekX, await passKEK(p1, salt, PBKDF2_ITER), AAD_PASS) } };
      await dbPut('meta', meta);
      state.meta = meta;
      ['#np-cur', '#np-1', '#np-2'].forEach((s) => { $(s).value = ''; });
      $('#dlg-newpass').close();
      toast('変更しました。新しいバックアップを書き出してください', 3500);
    } catch (e) {
      setErr('#np-err', e.message);
    }
  }

  /* ---------- バックアップ ---------- */
  async function exportBackup() {
    // 共有シートはタップ直後に呼ぶ必要があるため、メモリ上のデータから同期的にファイルを作る
    const data = { format: 'kagimemo-backup', version: 1, exported: new Date().toISOString(), origin: location.origin, meta: state.meta, vault: state.vault };
    const name = `kagimemo-backup-${ymd(new Date())}.json`;
    const file = new File([JSON.stringify(data)], name, { type: 'application/json' });
    let done = false;
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      try { await navigator.share({ files: [file], title: name }); done = true; } catch (e) { if (e.name === 'AbortError') return; }
    }
    if (!done) {
      const url = URL.createObjectURL(file);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    }
    state.settings.lastBackup = Date.now();
    await saveSettings();
    if (!$('#screen-settings').hidden) openSettings();
    toast('書き出しました');
  }
  function validBackup(d) {
    const w = (x) => x && typeof x.iv === 'string' && typeof x.ct === 'string';
    return d && d.format === 'kagimemo-backup' && d.meta && d.meta.pass && w(d.meta.pass.wrap)
      && typeof d.meta.pass.salt === 'string' && Number.isInteger(d.meta.pass.iter) && d.meta.pass.iter >= 100000 && w(d.vault)
      && (!d.meta.prf || (typeof d.meta.prf.credId === 'string' && typeof d.meta.prf.salt === 'string' && w(d.meta.prf.wrap)));
  }
  async function restoreFromFile(file) {
    let d;
    try { d = JSON.parse(await file.text()); } catch { alert('ファイルを読み込めませんでした。'); return; }
    if (!validBackup(d)) { alert('カギメモのバックアップファイルではありません。'); return; }
    if (state.meta && !confirm('この端末の今のデータを、バックアップの内容で置き換えます。よろしいですか？')) return;
    const meta = { v: 1, created: d.meta.created || Date.now(), pass: d.meta.pass };
    if (d.meta.prf && d.origin === location.origin) meta.prf = d.meta.prf;
    // 先にパスフレーズで開けることを確認してから保存する
    const prev = state.meta;
    state.meta = meta;
    const pass = await askPass('復元', 'バックアップ作成時のパスフレーズを入力してください。', '復元する');
    if (pass === null) { state.meta = prev; return; }
    try {
      const dek = await dekFromPass(pass, false);
      await decVault(d.vault, dek);
      await dbPutMany({ meta, vault: d.vault });
      state.vault = d.vault;
      lock();
      state.meta = meta;
      state.vault = d.vault;
      await openVault(dek);
      toast(meta.prf ? '復元しました' : '復元しました。設定からFace IDを登録してください', 3500);
    } catch (e) {
      state.meta = prev;
      alert(e instanceof AppError ? e.message : '復元できませんでした。');
    }
  }
  async function wipeAll() {
    const ans = prompt('この端末のカギメモのデータをすべて削除します。元に戻せません。\n続けるには「削除」と入力してください。');
    if (ans !== '削除') return;
    await dbClear();
    state.meta = null; state.vault = null; state.settings = { ...DEFAULTS };
    lock();
    show('welcome');
    toast('削除しました（iPhoneの「パスワード」アプリに残るパスキーは手動で削除できます）', 4500);
  }

  /* ---------- イベント ---------- */
  function bindUI() {
    document.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => show(b.dataset.go)));
    document.querySelectorAll('dialog [data-close]').forEach((b) => b.addEventListener('click', () => b.closest('dialog').close()));

    $('#btn-start').addEventListener('click', () => show('setup-pass'));
    $('#btn-restore-welcome').addEventListener('click', () => $('#file-restore').click());
    $('#btn-restore').addEventListener('click', () => $('#file-restore').click());
    $('#file-restore').addEventListener('change', async (ev) => {
      const f = ev.target.files && ev.target.files[0];
      ev.target.value = '';
      if (f) await restoreFromFile(f);
    });

    const sp1 = $('#sp-1');
    sp1.addEventListener('input', () => { $('#sp-meter').textContent = passHint(sp1.value); });
    $('#sp-show').addEventListener('change', (ev) => {
      ['#sp-1', '#sp-2'].forEach((s) => $(s).classList.toggle('reveal', ev.target.checked));
    });
    $('#form-setup-pass').addEventListener('submit', (ev) => {
      ev.preventDefault();
      setErr('#sp-err');
      const p1 = $('#sp-1').value, p2 = $('#sp-2').value;
      if ([...p1].length < MIN_PASS) { setErr('#sp-err', `${MIN_PASS}文字以上にしてください。`); return; }
      if (p1 !== p2) { setErr('#sp-err', '確認用が一致しません。'); return; }
      state.setup = { pass: p1 };
      $('#btn-sp-activate').hidden = true;
      $('#btn-sp-register').hidden = false;
      setErr('#pk-err');
      show('setup-passkey');
    });
    $('#btn-sp-register').addEventListener('click', async () => {
      setErr('#pk-err');
      try {
        const salt = rnd(32);
        const { credId, prfOut } = await registerPasskey(salt);
        if (prfOut) {
          await finishSetup({ credId, salt, prfOut });
        } else {
          state.setup.pending = { credId, salt };
          $('#btn-sp-register').hidden = true;
          $('#btn-sp-activate').hidden = false;
        }
      } catch (e) { setErr('#pk-err', webauthnMessage(e)); }
    });
    $('#btn-sp-activate').addEventListener('click', async () => {
      setErr('#pk-err');
      const p = state.setup.pending;
      if (!p) return;
      try {
        const prfOut = await prfEval(p.credId, b64(p.salt));
        await finishSetup({ credId: p.credId, salt: p.salt, prfOut });
      } catch (e) { setErr('#pk-err', webauthnMessage(e)); }
    });
    $('#btn-sp-skip').addEventListener('click', async () => {
      if (!confirm('パスフレーズだけで使います（あとで設定からFace IDを登録できます）。')) return;
      await finishSetup(null);
    });

    $('#btn-unlock-face').addEventListener('click', unlockWithFace);
    $('#btn-unlock-pass').addEventListener('click', async () => {
      const pass = await askPass('パスフレーズで解除', '', '解除');
      if (pass === null) return;
      try { await openVault(await dekFromPass(pass, false)); } catch (e) { setErr('#lock-err', e instanceof AppError ? e.message : '解除できませんでした。'); }
    });

    $('#btn-lock').addEventListener('click', lock);
    $('#btn-add').addEventListener('click', () => openEdit(null));
    $('#search').addEventListener('input', (ev) => { state.query = ev.target.value; render(); });
    $('#btn-settings').addEventListener('click', openSettings);
    $('#btn-settings-back').addEventListener('click', () => { render(); show('main'); });

    $('#btn-d-edit').addEventListener('click', () => { const id = state.current; $('#dlg-detail').close(); openEdit(id); });
    $('#btn-d-reveal').addEventListener('click', () => setPassMasked(!$('#btn-d-reveal').dataset.masked));
    $('#btn-d-dup').addEventListener('click', () => { const id = state.current; $('#dlg-detail').close(); openEdit(null, id); });
    $('#btn-d-delete').addEventListener('click', deleteCurrent);
    $('#dlg-detail').addEventListener('close', () => { setPassMasked(true); });
    document.querySelectorAll('#dlg-detail [data-copy]').forEach((b) => {
      b.dataset.copyBtn = '1';
      b.addEventListener('click', () => {
        const e = findEntry(state.current);
        if (!e) return;
        const k = b.dataset.copy;
        copyText(e[k], { username: 'ID', password: 'パスワード', url: 'URL' }[k], b);
      });
    });

    $('#form-edit').addEventListener('submit', (ev) => { ev.preventDefault(); saveEdit().catch((e) => alert('保存できませんでした：' + e.message)); });
    $('#dlg-edit').addEventListener('close', () => { $('#e-pass').classList.remove('reveal'); });
    $('#btn-e-reveal').addEventListener('click', () => {
      const r = $('#e-pass').classList.toggle('reveal');
      $('#btn-e-reveal').textContent = r ? '隠す' : '表示';
    });
    $('#btn-gen').addEventListener('click', () => {
      if ($('#e-pass').value && !confirm('今のパスワードを置き換えますか？')) return;
      $('#e-pass').value = genPassword(Number($('#gen-len').value), $('#gen-sym').checked);
      $('#e-pass').classList.add('reveal');
      $('#btn-e-reveal').textContent = '隠す';
    });

    $('#set-idle').addEventListener('change', (ev) => { state.settings.idleSec = Number(ev.target.value); saveSettings(); resetIdle(); });
    $('#set-hide').addEventListener('change', (ev) => { state.settings.hideSec = Number(ev.target.value); saveSettings(); });
    $('#set-clip').addEventListener('change', (ev) => { state.settings.clipSec = Number(ev.target.value); saveSettings(); });
    $('#btn-reregister').addEventListener('click', reRegisterPasskey);
    $('#btn-change-pass').addEventListener('click', () => { setErr('#np-err'); $('#dlg-newpass').showModal(); });
    $('#form-newpass').addEventListener('submit', changePass);
    $('#dlg-newpass').addEventListener('close', () => ['#np-cur', '#np-1', '#np-2'].forEach((s) => { $(s).value = ''; }));
    $('#btn-export').addEventListener('click', exportBackup);
    $('#btn-wipe').addEventListener('click', wipeAll);

    // 操作があれば自動ロックのタイマーを延長
    ['pointerdown', 'keydown', 'input', 'scroll'].forEach((t) => document.addEventListener(t, resetIdle, { passive: true, capture: true }));
    // iOSはタップ時でないとクリップボードを書き換えられないので、期限切れならタップのついでに消去
    document.addEventListener('click', (ev) => {
      if (ev.target.closest && ev.target.closest('[data-copy-btn]')) return;
      tryClearClipboard();
    }, true);

    // 他のアプリへ切り替えたとき：中身を隠す＋一定時間でロック
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        document.body.classList.add('veiled');
        state.hiddenAt = Date.now();
        if (state.dek && state.settings.hideSec === 0) lock();
      } else {
        if (state.dek && state.hiddenAt && Date.now() - state.hiddenAt >= state.settings.hideSec * 1000) lock();
        else resetIdle();
        state.hiddenAt = 0;
        document.body.classList.remove('veiled');
        tryClearClipboard();
      }
    });
    window.addEventListener('pagehide', () => document.body.classList.add('veiled'));
    window.addEventListener('pageshow', () => { if (!document.hidden) document.body.classList.remove('veiled'); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
