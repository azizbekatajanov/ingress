import {
  GetProfiles, GetSelectedProfileID, SelectProfile, AddProfile, UpdateProfile, RemoveProfile,
  GetPassword, SetPassword, GetTheme, SetTheme,
  Connect, Disconnect, CancelConnect, SubmitOtp, SubmitPrompt, GetSnapshot,
  GetComponents, InstallComponent, RemoveComponent, SetComponentOverride, BrowseFile,
  PickProfileLogo, RemoveProfileLogo, GetProfileLogos,
  WindowMinimise, WindowToggleFullscreen, HideWindow, ConfirmQuit,
  GetAppInfo, GetI18n, SetLanguage,
  GetUpdateStatus, CheckForUpdates, SetUpdateCheck, DismissUpdate, InstallUpdate,
} from '../wailsjs/go/main/App';
import { EventsOn, BrowserOpenURL, ClipboardSetText } from '../wailsjs/runtime/runtime';

// ---- i18n: the catalog comes from Go (i18n/<lang>.json), see i18n.go ----
const i18n = { language: 'en', setting: '', languages: ['en'], strings: {} };
function t(key, ...args) {
  const s = i18n.strings[key] ?? key;
  if (!args.length) return s;
  return s.replace(/\{(\d+)\}/g, (m, i) => (i < args.length ? String(args[i]) : m));
}
// Static text in index.html carries data-i18n / -placeholder / -title.
function applyI18n() {
  document.documentElement.lang = i18n.language;
  document.querySelectorAll('[data-i18n]').forEach(n => { n.textContent = t(n.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(n => { n.placeholder = t(n.dataset.i18nPlaceholder); });
  document.querySelectorAll('[data-i18n-title]').forEach(n => { n.title = t(n.dataset.i18nTitle); });
  const sel = $('#langSelect');
  sel.innerHTML = '';
  // "System (Русский)" first, then each language in its own name.
  const sys = document.createElement('option');
  sys.value = ''; sys.textContent = t('ui.language.system', t('lang.' + (i18n.setting ? i18n.systemLanguage : i18n.language)));
  sel.appendChild(sys);
  for (const l of i18n.languages) {
    const o = document.createElement('option');
    o.value = l; o.textContent = t('lang.' + l);
    sel.appendChild(o);
  }
  sel.value = i18n.setting || '';
}
function setI18n(bundle) { Object.assign(i18n, bundle); applyI18n(); }

const TYPE_LABELS = { fortinet: 'Fortinet', globalprotect: 'GlobalProtect', cisco: 'Cisco', sstp: 'SSTP' };
const PROFILE_COLORS = ['#ff6961', '#5ac8fa', '#ffd60a', '#bf5af2', '#30d158', '#ff9f0a'];

const state = {
  profiles: [],
  selectedProfileId: null,
  activeTab: 'general',
  showSettings: false,
  // showLog: the log of the last (failed) attempt, viewable while
  // disconnected — otherwise the log tab only exists while connected.
  showLog: false,
  theme: 'light',
  showPassword: false,
  otpCode: '',
  snapshots: {}, // profileId -> ConnectionSnapshot from the Go backend
  passwords: {}, // profileId -> cached password (fetched from keychain on demand)
  logos: {}, // profileId -> data: URL of the uploaded logo
  components: [], // ComponentStatus[] from components.go
  componentProgress: {}, // name -> {phase, done, total} while installing/removing
  componentErrors: {}, // name -> last install/remove/override error message
  appInfo: null,
  update: null, // UpdateStatus from updater.go
};

function selected() { return state.profiles.find(p => p.id === state.selectedProfileId); }
function snapshotOf(id) { return state.snapshots[id] || { profileId: id, status: 'disconnected', logLines: [] }; }
// Prefers the currently selected profile when it's the one awaiting OTP —
// with multiple profiles connecting independently, the previous version
// always returned the first "otp" profile in array order regardless of which
// one the user actually triggered, so a second profile's OTP prompt could
// silently never surface if an earlier profile happened to reach "otp" (or
// stay there) first. Falls back to any pending OTP profile so one isn't
// missed entirely while looking at an unrelated profile.
function otpProfile() {
  const sp = selected();
  if (sp && snapshotOf(sp.id).status === 'otp') return sp;
  return state.profiles.find(p => snapshotOf(p.id).status === 'otp');
}
// Statuses where a connect attempt is in progress (any of them blocks the
// settings form and shows the "connecting" indicator).
const PENDING_STATUSES = ['connecting', 'otp', 'choose'];
function chooseProfile() {
  const sp = selected();
  if (sp && snapshotOf(sp.id).status === 'choose') return sp;
  return state.profiles.find(p => snapshotOf(p.id).status === 'choose');
}
async function submitChoice(id, value) {
  try { await SubmitPrompt(id, value); } catch (e) { alert(t('js.err.choice', errText(e))); }
}
const GENERIC_2FA_LABEL = /^(second\s+)?(password|passcode|pass\s*code|answer|response|otp|token|code|verification\s+code|пароль|код)$/i;
function otpMinLength(snap) { return snap && snap.promptLabel ? 1 : 4; }
function connectedProfiles() { return state.profiles.filter(p => snapshotOf(p.id).status === 'connected'); }

function formatDuration(sec) {
  const pad = n => (n < 10 ? '0' + n : '' + n);
  return `${pad(Math.floor(sec/3600))}:${pad(Math.floor((sec%3600)/60))}:${pad(sec%60)}`;
}
function formatBytes(n) {
  if (n < 1024) return t('js.bytes.b', n);
  if (n < 1024*1024) return t('js.bytes.kb', (n/1024).toFixed(1));
  return t('js.bytes.mb', (n/1024/1024).toFixed(2));
}

// Profile settings live in nested objects per VPN type (profile.fortinet /
// profile.globalprotect); form controls name them by dotted path in
// data-bind / data-switch / data-browse.
function getSetting(p, path) { return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), p); }
function setSetting(p, path, value) {
  const keys = path.split('.');
  let o = p;
  keys.slice(0, -1).forEach(k => { if (o[k] == null) o[k] = {}; o = o[k]; });
  o[keys[keys.length - 1]] = value;
}
function hostLine(p) {
  const where = p.host ? `${p.host}:${p.port}` : t('js.not_configured');
  return `${TYPE_LABELS[p.type] || ''} · ${where}`;
}

// ---- backend-driven actions ----
async function startConnect(id) {
  state.showLog = false;
  try { await Connect(id); } catch (e) { alert(t('js.err.connect', errText(e))); }
}
async function cancelConnect(id) { try { await CancelConnect(id); } catch (e) { /* ignore */ } }
async function disconnect(id) { try { await Disconnect(id); } catch (e) { /* ignore */ } }
async function submitOtp(id) {
  if (!state.otpCode || state.otpCode.length < otpMinLength(snapshotOf(id))) return;
  try { await SubmitOtp(id, state.otpCode); state.otpCode = ''; } catch (e) { alert(t('js.err.code', errText(e))); }
}

function addProfile() { $('#typeOverlay').hidden = false; }
async function createProfile(type) {
  $('#typeOverlay').hidden = true;
  let p;
  try { p = await AddProfile(type); } catch (e) { alert(t('js.err.create', errText(e))); return; }
  state.profiles.push(p);
  state.selectedProfileId = p.id;
  // Straight into settings: a fresh profile has nothing to show yet.
  state.activeTab = 'general'; state.showSettings = true;
  render();
}
let pendingDeleteId = null;
function askRemoveProfile(id) {
  const p = state.profiles.find(x => x.id === id);
  if (!p || state.profiles.length <= 1) return;
  pendingDeleteId = id;
  $('#deleteTitle').textContent = t('js.del.title', p.name || t('js.untitled'));
  const st = snapshotOf(id).status;
  $('#deleteSub').textContent = st === 'disconnected'
    ? t('ui.del.sub')
    : t('js.del.sub_connected');
  $('#deleteOverlay').hidden = false;
}
function closeDeleteDialog() { pendingDeleteId = null; $('#deleteOverlay').hidden = true; }
async function removeProfile(id) {
  if (state.profiles.length <= 1) return;
  try { await RemoveProfile(id); } catch (e) { alert(t('js.err.delete', errText(e))); return; }
  state.profiles = state.profiles.filter(x => x.id !== id);
  delete state.snapshots[id]; delete state.passwords[id]; delete state.logos[id];
  if (state.selectedProfileId === id) state.selectedProfileId = state.profiles[0].id;
  render();
}

// Debounce per profile: one shared timer dropped profile A's pending save
// if the user edited profile B within the 250ms window.
const saveTimers = {};
function scheduleSave(profile) {
  clearTimeout(saveTimers[profile.id]);
  saveTimers[profile.id] = setTimeout(() => { UpdateProfile(profile).catch(() => {}); }, 250);
}
const passwordSaveTimers = {};
function schedulePasswordSave(id, password) {
  clearTimeout(passwordSaveTimers[id]);
  passwordSaveTimers[id] = setTimeout(() => { SetPassword(id, password).catch(() => {}); }, 250);
}

// ---- DOM refs ----
const $ = sel => document.querySelector(sel);
const profileListEl = $('#profileList');
const profileSelectEl = $('#profileSelect');

function el(tag, cls, text) { const e = document.createElement('div'); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

// Shows the profile's uploaded logo if there is one, otherwise the colored
// first-letter badge.
function paintAvatar(node, p, color) {
  const logo = p.logo && state.logos[p.id];
  node.classList.toggle('has-logo', !!logo);
  if (logo) {
    node.textContent = '';
    node.style.background = `center / cover no-repeat url(${logo})`;
  } else {
    node.textContent = (p.name||'?').trim().charAt(0).toUpperCase() || '?';
    node.style.background = color;
  }
}

function render() {
  document.body.className = state.theme === 'dark' ? 'theme-dark' : 'theme-light';
  const sp = selected();
  const selIdx = state.profiles.indexOf(sp);
  const snap = sp ? snapshotOf(sp.id) : null;

  // A connect attempt takes over the content area (#viewConnecting/#otpOverlay
  // sit on top of it, see style.css), but nothing previously stopped Settings
  // from staying open underneath — reachable either by clicking the gear
  // mid-attempt (now hidden during connecting/otp too, below) or because the
  // attempt itself was started from the tray while Settings was already open
  // for this profile. Both left the "Подключение…" card rendered directly
  // over the settings form, looking broken. Confirmed live via a screenshot.
  if (snap && PENDING_STATUSES.includes(snap.status)) {
    state.showSettings = false;
  }

  // sidebar list
  profileListEl.innerHTML = '';
  state.profiles.forEach((p, i) => {
    const pStatus = snapshotOf(p.id).status;
    const row = el('div', 'profile-row' + (p.id === state.selectedProfileId ? ' selected' : ''));
    row.onclick = () => { state.selectedProfileId = p.id; state.showSettings = false; state.showLog = false; SelectProfile(p.id).catch(() => {}); render(); };
    const avatar = el('div', 'avatar');
    paintAvatar(avatar, p, PROFILE_COLORS[i % PROFILE_COLORS.length]);
    const info = el('div', 'profile-info');
    info.appendChild(el('div', 'profile-name', p.name));
    info.appendChild(el('div', 'profile-host', hostLine(p)));
    row.appendChild(avatar); row.appendChild(info);
    if (pStatus === 'connected') row.appendChild(el('div', 'status-dot connected'));
    if (PENDING_STATUSES.includes(pStatus)) row.appendChild(el('div', 'status-dot connecting'));
    if (state.profiles.length > 1) {
      const del = el('div', 'delete-btn', '×');
      del.onclick = (e) => { e.stopPropagation(); askRemoveProfile(p.id); };
      row.appendChild(del);
    }
    profileListEl.appendChild(row);
  });

  // header select
  profileSelectEl.innerHTML = '';
  state.profiles.forEach(p => {
    const opt = document.createElement('option');
    opt.value = p.id; opt.textContent = p.name;
    if (p.id === state.selectedProfileId) opt.selected = true;
    profileSelectEl.appendChild(opt);
  });
  $('#hostLine').textContent = sp ? hostLine(sp) : '';

  // status pill + connect button
  const pill = $('#statusPill'); const btn = $('#connectBtn');
  pill.className = 'pill'; btn.className = 'btn primary';
  if (!sp) { pill.textContent = '—'; }
  else if (snap.status === 'connected') { pill.classList.add('connected'); pill.textContent = t('ui.st.connected'); btn.className = 'btn danger'; btn.textContent = t('ui.disconnect'); btn.onclick = () => disconnect(sp.id); }
  else if (snap.status === 'connecting') { pill.classList.add('pending'); pill.textContent = t('js.st.connecting'); btn.className = 'btn neutral'; btn.textContent = t('js.st.connecting'); btn.onclick = () => cancelConnect(sp.id); }
  else if (snap.status === 'choose') { pill.classList.add('pending'); pill.textContent = t('js.st.choose'); btn.className = 'btn neutral'; btn.textContent = t('js.st.choose'); btn.onclick = () => cancelConnect(sp.id); }
  else if (snap.status === 'otp') { pill.classList.add('pending'); pill.textContent = t('js.st.otp'); btn.className = 'btn neutral'; btn.textContent = t('js.st.otp'); btn.onclick = () => cancelConnect(sp.id); }
  else { pill.textContent = t('tray.not_connected'); btn.textContent = t('js.connect'); btn.onclick = () => startConnect(sp.id); }

  $('#gearBtn').style.display = sp && snap.status !== 'disconnected' ? 'none' : 'flex';

  // tabs
  const isConnected = sp && snap.status === 'connected';
  const tabsRow = $('#tabsRow'); const backBtn = $('#backToOverview');
  const allTabs = tabsRow.querySelectorAll('.tab[data-tab]');
  let tabsDef = [];
  if (isConnected) tabsDef = ['status', 'log'];
  else if (state.showSettings) tabsDef = ['general', 'certificate', 'advanced'];
  // The log of a failed attempt, or of one still in progress (otherwise the
  // spinner hides everything the client prints).
  const showPastLog = sp && (snap.status === 'disconnected' || snap.status === 'connecting') && state.showLog && !state.showSettings;
  tabsRow.hidden = tabsDef.length === 0 && !showPastLog;
  backBtn.hidden = !((state.showSettings || showPastLog) && !isConnected);
  if (!tabsDef.includes(state.activeTab)) state.activeTab = tabsDef[0];
  allTabs.forEach(t => {
    const show = tabsDef.includes(t.dataset.tab);
    t.style.display = show ? '' : 'none';
    t.classList.toggle('active', t.dataset.tab === state.activeTab);
  });

  // content views
  const showOverview = sp && snap.status === 'disconnected' && !state.showSettings && !showPastLog;
  const showConnecting = sp && snap.status === 'connecting' && !showPastLog;
  $('#viewOverview').hidden = !showOverview;
  $('#viewConnecting').hidden = !showConnecting;
  $('#viewGeneral').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'general');
  $('#viewCertificate').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'certificate');
  $('#viewAdvanced').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'advanced');
  $('#viewStatus').hidden = !(isConnected && state.activeTab === 'status');
  $('#viewLog').hidden = !((isConnected && state.activeTab === 'log') || showPastLog);

  if (showOverview) {
    paintAvatar($('#overviewAvatar'), sp, PROFILE_COLORS[selIdx % PROFILE_COLORS.length]);
    $('#overviewName').textContent = sp.name;
    $('#overviewHost').textContent = hostLine(sp);
    renderUpdateBanner();
    renderInstallBanner(sp);
    renderErrorBanner(snap);
  }
  if (showConnecting) $('#connectingTitle').textContent = t('js.connecting_to', `${sp.host}:${sp.port}`);

  if (sp && !isConnected) fillForm(sp);
  if (isConnected && state.activeTab === 'status') fillStatus(sp, snap);
  if ((isConnected && state.activeTab === 'log') || showPastLog) {
    $('#logTitle').textContent = ({ fortinet: t('js.log.fortinet'), sstp: t('js.log.sstp') })[sp.type] || t('js.log.openconnect');
    fillLog(snap);
  }

  // OTP modal
  const otp = otpProfile();
  $('#otpOverlay').hidden = !otp;
  if (otp) {
    const otpSnap = snapshotOf(otp.id);
    // A server-defined field (Cisco second factor) comes with its label and
    // message; a plain 2FA code (Fortinet, GlobalProtect) doesn't.
    // Servers often name the second-factor field just "Password" (Cisco
    // ASA does) — showing that reads like "your password again". Generic
    // labels get a plain explanation instead; a specific one is shown as is.
    const textPrompt = !!otpSnap.promptLabel;
    const genericLabel = textPrompt && GENERIC_2FA_LABEL.test(otpSnap.promptLabel.trim());
    $('#otpTitle').textContent = textPrompt ? (otpSnap.promptMessage || t('js.otp.second_factor')) : t('js.otp.title');
    $('#otpLabel').hidden = !textPrompt;
    $('#otpLabel').textContent = !textPrompt ? ''
      : genericLabel ? t('js.otp.generic_hint')
      : t('js.otp.server_asks', otpSnap.promptLabel);
    $('#otpTarget').textContent = `${otp.username || '—'}@${otp.host || '—'}`;
    const input = $('#otpCode');
    input.maxLength = textPrompt ? 128 : 8;
    input.placeholder = !textPrompt ? '000000' : genericLabel ? t('js.otp.code') : otpSnap.promptLabel;
    input.inputMode = textPrompt ? 'text' : 'numeric';
    input.value = state.otpCode;
    const windowSec = textPrompt ? 120 : 60;
    $('#otpProgressFill').style.width = Math.max(0, Math.min(100, (otpSnap.otpSecondsLeft/windowSec)*100)) + '%';
    $('#otpTimer').textContent = t('js.otp.timer', otpSnap.otpSecondsLeft);
    $('#otpSubmitBtn').style.opacity = (!state.otpCode || state.otpCode.length < otpMinLength(otpSnap)) ? 0.5 : 1;
  }

  // choice modal (e.g. GlobalProtect gateway)
  const ch = otp ? null : chooseProfile();
  $('#chooseOverlay').hidden = !ch;
  if (ch) {
    const chSnap = snapshotOf(ch.id);
    $('#chooseTitle').textContent = chSnap.promptLabel === 'GATEWAY:' ? t('js.choose.gateway') : (/group/i.test(chSnap.promptLabel || '') ? t('js.choose.group') : (chSnap.promptLabel || t('js.choose.option')).replace(/:$/, ''));
    $('#chooseTarget').textContent = ch.host ? `${ch.name} · ${ch.host}` : ch.name;
    const box = $('#chooseOptions');
    const key = ch.id + '|' + (chSnap.promptOptions || []).join('|');
    if (box.dataset.key !== key) { // don't rebuild on every 1s tick
      box.dataset.key = key;
      box.innerHTML = '';
      (chSnap.promptOptions || []).forEach(opt => {
        const o = el('div', 'choose-option', opt);
        o.onclick = () => submitChoice(ch.id, opt);
        box.appendChild(o);
      });
    }
  }

  // theme switch
  $('#themeToggle').classList.toggle('on', state.theme === 'dark');

  if (!$('#componentsOverlay').hidden) renderComponents();
}

// ---- in-app updates (updater.go) ----
function renderUpdateBanner() {
  const host = $('#updateBanner');
  host.innerHTML = '';
  const u = state.update;
  if (!u) return;
  if (u.phase) {
    const pct = u.total > 0 ? ` ${Math.round(u.done / u.total * 100)}%` : '';
    host.appendChild(el('div', 'banner', u.phase === 'downloading' ? t('js.upd.downloading', pct) : t('js.upd.installing')));
    return;
  }
  if (!u.available || u.dismissed) return;
  const b = el('div', 'banner', t('js.upd.available', u.version));
  if (u.error) b.appendChild(el('div', 'banner-detail', t('js.upd.failed', u.error)));
  else if (!u.canInstall && u.blocker) b.appendChild(el('div', 'banner-detail', u.blocker));
  const actions = el('div', 'banner-actions');
  if (u.canInstall) actions.appendChild(actionBtn('primary', t('js.upd.update'), startUpdate));
  else actions.appendChild(actionBtn('primary', t('js.upd.download'), () => BrowserOpenURL(u.notesUrl)));
  if (u.canInstall && u.notesUrl) actions.appendChild(actionBtn('neutral', t('js.upd.whats_new'), () => BrowserOpenURL(u.notesUrl)));
  actions.appendChild(actionBtn('neutral', t('ui.upd.later'), () => DismissUpdate()));
  b.appendChild(actions);
  host.appendChild(b);
}

function startUpdate() {
  const n = state.profiles.filter(p => snapshotOf(p.id).status !== 'disconnected').length;
  if (n === 0) { runUpdate(false); return; }
  $('#updateConfirmTitle').textContent = t('js.upd.confirm_title', state.update.version);
  $('#updateConfirmSub').textContent = t('js.upd.confirm_sub', n);
  $('#updateOverlay').hidden = false;
}
async function runUpdate(disconnectFirst) {
  $('#updateOverlay').hidden = true;
  try { await InstallUpdate(disconnectFirst); } catch (e) { /* shown in the banner via update:status */ }
}

function renderAboutUpdate() {
  const u = state.update;
  if (!u) return;
  let line;
  if (u.checking) line = t('js.upd.checking');
  else if (u.available) line = t('js.upd.available', u.version);
  else if (u.error) line = t('js.upd.check_failed', u.error);
  else if (u.lastCheck) line = t('js.upd.latest', new Date(u.lastCheck).toLocaleString(i18n.language));
  else line = '';
  $('#aboutUpdateLine').textContent = line;
  $('#autoUpdateCheck').checked = !!u.autoCheck;
  $('#checkUpdatesBtn').style.opacity = u.checking ? 0.5 : 1;
}

function renderErrorBanner(snap) {
  const host = $('#errorBanner');
  host.innerHTML = '';
  if (!snap.lastError) return;
  const b = el('div', 'banner error', t('js.err.connect', snap.lastError));
  if ((snap.logLines || []).length) {
    const actions = el('div', 'banner-actions');
    actions.appendChild(actionBtn('neutral', t('ui.tab.log'), () => { state.showLog = true; render(); }));
    actions.appendChild(actionBtn('neutral', t('js.copy_log'), () => copyLog(snap)));
    b.appendChild(actions);
  }
  host.appendChild(b);
}

function logText(snap) {
  return (snap.logLines || []).map(l => `[${l.ts}] ${l.text}`).join('\n');
}
async function copyLog(snap) {
  try { await ClipboardSetText(logText(snap)); } catch (e) { alert(t('js.err.copy', errText(e))); }
}

// ---- components (openfortivpn / openconnect binaries) ----
const SOURCE_LABELS = { managed: 'js.src.managed', override: 'js.src.override', system: 'js.src.system' };

function componentByName(name) { return state.components.find(c => c.name === name); }
function componentForProfile(p) { return { globalprotect: 'openconnect', cisco: 'openconnect', sstp: 'sstpc' }[p.type] || 'openfortivpn'; }

// Wails rejects bound-method promises with an Error whose message is the Go
// error text; String(e) would prefix it with "Error: ".
function errText(e) { return (e && e.message) ? e.message : String(e); }

async function refreshComponents() {
  try { state.components = await GetComponents(); } catch (e) { /* keep the previous list */ }
  render();
}

async function runComponentAction(name, action) {
  state.componentErrors[name] = '';
  state.componentProgress[name] = { phase: action === 'remove' ? 'install' : 'download', done: 0, total: -1 };
  render();
  try {
    if (action === 'remove') await RemoveComponent(name);
    else await InstallComponent(name);
  } catch (e) {
    state.componentErrors[name] = errText(e);
  } finally {
    delete state.componentProgress[name];
    await refreshComponents();
  }
}

async function setComponentOverride(name, path) {
  state.componentErrors[name] = '';
  try { await SetComponentOverride(name, path); } catch (e) { state.componentErrors[name] = errText(e); }
  await refreshComponents();
}

function progressText(c, pr) {
  if (pr.phase === 'download') {
    return pr.total > 0
      ? t('js.comp.downloading', c.title, `${Math.round(pr.done / pr.total * 100)}%`)
      : t('js.comp.downloading', c.title, formatBytes(pr.done));
  }
  return t('js.comp.admin');
}
function progressBar(pr) {
  const bar = el('div', 'progress');
  const fill = el('div', 'progress-fill');
  if (pr.phase === 'download' && pr.total > 0) fill.style.width = Math.round(pr.done / pr.total * 100) + '%';
  else fill.classList.add('indeterminate');
  bar.appendChild(fill);
  return bar;
}
function actionBtn(cls, text, onclick) {
  const b = el('div', 'btn ' + cls, text);
  b.onclick = onclick;
  return b;
}

// Banner on the profile overview: what's needed to connect this profile.
function renderInstallBanner(p) {
  const host = $('#installBanner');
  host.innerHTML = '';
  const c = componentByName(componentForProfile(p));
  if (!c) return;
  const pr = state.componentProgress[c.name];
  const err = state.componentErrors[c.name];

  if (pr) {
    const b = el('div', 'banner', progressText(c, pr));
    b.appendChild(progressBar(pr));
    host.appendChild(b);
    return;
  }

  let b = null;
  const actions = el('div', 'banner-actions');
  if (!c.activeSource) {
    if (c.broken) {
      b = el('div', 'banner error', t('js.comp.broken_banner', c.title, c.broken));
      if (c.available) actions.appendChild(actionBtn('primary', t('js.comp.reinstall'), () => runComponentAction(c.name, 'install')));
    } else if (c.available) {
      b = el('div', 'banner', t('js.comp.need_banner', c.vpn, c.title, c.latestVersion));
      actions.appendChild(actionBtn('primary', t('js.comp.install_x', c.title), () => runComponentAction(c.name, 'install')));
    } else {
      b = el('div', 'banner error', t('js.comp.no_build_banner', c.vpn, c.title));
    }
    if (!c.available || c.broken) actions.appendChild(actionBtn('neutral', t('ui.components'), showComponents));
  } else if (c.activeSource === 'system') {
    // 1.0.x users (or anyone with a brew/apt install): never block them,
    // offer the switch to the pinned build.
    const intro = t('js.comp.system_found', c.title, c.systemVersion || '', c.systemPath);
    const tail = c.available
      ? ' ' + t('js.comp.system_tail', c.latestVersion)
      : ' ' + t('js.comp.system_only');
    b = el('div', c.warning ? 'banner error' : 'banner', intro + tail + (c.warning ? ' ' + c.warning : ''));
    if (c.available) actions.appendChild(actionBtn('primary', t('js.comp.install_builtin'), () => runComponentAction(c.name, 'install')));
    actions.appendChild(actionBtn('neutral', t('js.comp.use_system'), () => setComponentOverride(c.name, c.systemPath)));
  } else if (c.warning) {
    b = el('div', 'banner error', c.warning);
    if (c.available) actions.appendChild(actionBtn('primary', t('js.comp.install_builtin'), async () => {
      await setComponentOverride(c.name, '');
      await runComponentAction(c.name, 'install');
    }));
  }

  if (b) {
    if (actions.childElementCount) b.appendChild(actions);
    host.appendChild(b);
  }
  if (err) host.appendChild(el('div', 'banner error', err));
}

// ---- Компоненты screen ----
function showComponents() {
  $('#componentsOverlay').hidden = false;
  refreshComponents();
}

function componentState(c) {
  if (state.componentProgress[c.name]) return [t('js.comp.st.installing'), 'warn'];
  if (c.broken) return [t('js.comp.st.broken'), 'bad'];
  if (!c.activeSource) return [t('js.comp.st.missing'), 'bad'];
  if (c.warning) return [t('js.comp.st.bad_version'), 'bad'];
  if (c.activeSource === 'managed') return [c.updateAvailable ? t('js.comp.st.update') : t('js.comp.st.installed'), c.updateAvailable ? 'warn' : 'ok'];
  return [c.activeSource === 'override' ? t('js.comp.st.override') : t('js.comp.st.system'), 'warn'];
}

function renderComponents() {
  const list = $('#componentsList');
  // Don't rebuild while the user is typing a path: it would drop focus.
  if (list.contains(document.activeElement) && document.activeElement.tagName === 'INPUT') return;
  list.innerHTML = '';
  state.components.forEach(c => {
    const row = el('div', 'component-row');
    const head = el('div', 'component-head');
    const name = el('div', 'component-name', c.title);
    name.appendChild(Object.assign(document.createElement('span'), { className: 'component-vpn', textContent: c.vpn }));
    const [label, cls] = componentState(c);
    head.appendChild(name);
    head.appendChild(el('div', 'component-state ' + cls, label));
    row.appendChild(head);

    if (c.activePath) {
      const ver = c.activeSource === 'managed' ? c.installedVersion : (c.activeSource === 'override' ? c.overrideVersion : c.systemVersion);
      row.appendChild(el('div', 'component-line', t('js.comp.in_use', `${c.activePath}${ver ? ' · ' + ver : ''}`, t(SOURCE_LABELS[c.activeSource]))));
    }
    if (c.installed) row.appendChild(el('div', 'component-line', (c.updateAvailable ? t('js.comp.installed_update', c.installedVersion, c.latestVersion) : t('js.comp.installed_v', c.installedVersion))));
    else if (c.available) row.appendChild(el('div', 'component-line', t('js.comp.available', c.latestVersion)));
    else row.appendChild(el('div', 'component-line', t('js.comp.no_build')));
    if (c.override && (c.installed || c.available)) row.appendChild(el('div', 'component-line', t('js.comp.override_note')));
    if (c.broken) row.appendChild(el('div', 'component-line error', t('js.comp.integrity_failed', c.broken)));
    if (c.warning) row.appendChild(el('div', 'component-line warning', c.warning));

    const pr = state.componentProgress[c.name];
    if (pr) {
      row.appendChild(el('div', 'component-line', progressText(c, pr)));
      row.appendChild(progressBar(pr));
    } else {
      const actions = el('div', 'component-actions');
      if (c.available) {
        const text = !c.installed ? t('js.comp.install') : (c.updateAvailable ? t('js.comp.update') : t('js.comp.reinstall'));
        actions.appendChild(actionBtn(c.installed && !c.updateAvailable && !c.broken ? 'neutral' : 'primary', text, () => runComponentAction(c.name, 'install')));
      }
      if (c.installed) actions.appendChild(actionBtn('neutral', t('ui.delete'), () => runComponentAction(c.name, 'remove')));
      if (actions.childElementCount) row.appendChild(actions);
    }

    row.appendChild(el('div', 'component-label', t('js.comp.override_label')));
    const ov = el('div', 'component-override');
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = c.systemPath || t('js.comp.path_ph', c.name);
    input.value = c.override || '';
    const commit = () => { if (input.value.trim() !== (c.override || '')) setComponentOverride(c.name, input.value.trim()); };
    input.addEventListener('keydown', e => { if (e.key === 'Enter') input.blur(); });
    input.addEventListener('blur', commit);
    ov.appendChild(input);
    ov.appendChild(actionBtn('neutral', t('ui.browse'), async () => {
      const path = await BrowseFile(t('js.comp.pick_exec', c.name)).catch(() => '');
      if (path) setComponentOverride(c.name, path);
    }));
    if (c.override) ov.appendChild(actionBtn('neutral', t('js.comp.reset'), () => setComponentOverride(c.name, '')));
    row.appendChild(ov);
    if (c.overrideError) row.appendChild(el('div', 'component-line error', t('js.comp.override_broken', c.overrideError)));

    const err = state.componentErrors[c.name];
    if (err) row.appendChild(el('div', 'component-line error', err));
    list.appendChild(row);
  });
}

function fillForm(p) {
  paintAvatar($('#logoPreview'), p, PROFILE_COLORS[state.profiles.indexOf(p) % PROFILE_COLORS.length]);
  $('#logoRemoveBtn').style.display = p.logo ? '' : 'none';
  $('#f-name').value = p.name;
  $('#f-host').value = p.host;
  $('#f-port').value = p.port;
  $('#f-username').value = p.username;
  const pw = state.passwords[p.id];
  if (pw === undefined) {
    GetPassword(p.id).then(v => { state.passwords[p.id] = v || ''; if (selected() && selected().id === p.id) render(); });
  } else {
    $('#f-password').value = pw;
  }
  $('#f-password').type = state.showPassword ? 'text' : 'password';
  $('#togglePassword').textContent = state.showPassword ? t('js.hide') : t('ui.show');

  const gp = p.type === 'globalprotect';
  $('#f-host-label').textContent = gp ? t('js.f.portal') : t('js.f.host');
  // SAML logs in through the IdP's page, there's no password to store.
  $('#f-password-field').hidden = gp && getSetting(p, 'globalprotect.auth') === 'saml';
  document.querySelectorAll('[data-for]').forEach(n => {
    let show = n.dataset.for === p.type;
    if (show && n.dataset.connectTo) show = getSetting(p, 'globalprotect.connectTo') === n.dataset.connectTo;
    // data-when="path=value": shown only while that setting has that value.
    if (show && n.dataset.when) { const [path, val] = n.dataset.when.split('='); show = getSetting(p, path) === val; }
    n.hidden = !show;
  });
  document.querySelectorAll('[data-bind]').forEach(n => {
    if (document.activeElement === n) return; // don't fight the cursor while typing
    const v = getSetting(p, n.dataset.bind);
    // data-lines: an array setting edited one item per line.
    n.value = v == null ? '' : ('lines' in n.dataset && Array.isArray(v) ? v.join('\n') : v);
  });
  document.querySelectorAll('[data-switch]').forEach(n => n.classList.toggle('on', !!getSetting(p, n.dataset.switch)));
}
function fillStatus(p, snap) {
  $('#statusDuration').textContent = formatDuration(snap.connectSeconds || 0);
  $('#statusIp').textContent = snap.assignedIp || '—';
  $('#statusGateway').textContent = `${p.host}:${p.port}`;
  $('#statusTx').textContent = formatBytes(snap.txBytes || 0);
  $('#statusRx').textContent = formatBytes(snap.rxBytes || 0);
}
function fillLog(snap) {
  const panel = $('#logPanel');
  panel.innerHTML = '';
  const lines = snap.logLines || [];
  if (lines.length === 0) { panel.appendChild(el('div', 'empty', t('js.log.empty'))); return; }
  lines.forEach(line => {
    const row = document.createElement('div');
    const ts = document.createElement('span');
    ts.className = 'ts'; ts.textContent = `[${line.ts}]`;
    row.appendChild(ts);
    row.appendChild(document.createTextNode(' ' + line.text)); // VPN output is untrusted: never innerHTML
    panel.appendChild(row);
  });
  panel.scrollTop = panel.scrollHeight;
}

// ---- event wiring ----
profileSelectEl.addEventListener('change', e => {
  state.selectedProfileId = e.target.value; state.showSettings = false; state.showLog = false;
  SelectProfile(e.target.value).catch(() => {});
  render();
});
$('#addProfile').onclick = addProfile;
$('#themeToggle').onclick = () => { state.theme = state.theme === 'light' ? 'dark' : 'light'; SetTheme(state.theme).catch(() => {}); render(); };
$('#gearBtn').onclick = () => { state.showSettings = !state.showSettings; render(); };
$('#backToOverview').onclick = () => { state.showSettings = false; state.showLog = false; render(); };
$('#showConnectLogBtn').onclick = () => { state.showLog = true; render(); };
$('#copyLogBtn').onclick = () => { const sp = selected(); if (sp) copyLog(snapshotOf(sp.id)); };
$('#cancelConnectBtn').onclick = () => { const sp = selected(); if (sp) cancelConnect(sp.id); };
$('#togglePassword').onclick = () => { state.showPassword = !state.showPassword; render(); };
$('#openSettingsLink').onclick = () => { state.showSettings = true; render(); };
$('#disconnectBtn').onclick = () => { const sp = selected(); if (sp) disconnect(sp.id); };
$('#clearLogBtn').onclick = () => { const sp = selected(); if (sp) { const s = snapshotOf(sp.id); s.logLines = []; render(); } };
$('#otpCancelBtn').onclick = () => { const p = otpProfile(); if (p) cancelConnect(p.id); };
$('#otpSubmitBtn').onclick = () => { const p = otpProfile(); if (p) submitOtp(p.id); };
$('#chooseCancelBtn').onclick = () => { const p = chooseProfile(); if (p) cancelConnect(p.id); };
$('#otpCode').addEventListener('input', e => {
  const p = otpProfile();
  const textPrompt = p && !!snapshotOf(p.id).promptLabel;
  // Codes are case-insensitive and short; a server-defined answer (Duo's
  // "push", a passphrase) is passed as typed.
  state.otpCode = textPrompt ? e.target.value.slice(0, 128) : e.target.value.toUpperCase().slice(0, 8);
  render();
});

// window controls (frameless window — traffic lights are custom-drawn, see style.css)
$('#dotClose').onclick = () => HideWindow();
$('#dotMinimise').onclick = () => WindowMinimise();
$('#dotMaximise').onclick = () => WindowToggleFullscreen();

document.querySelectorAll('.tab[data-tab]').forEach(t => t.onclick = () => { state.activeTab = t.dataset.tab; render(); });
document.querySelectorAll('[data-browse]').forEach(b => b.onclick = async () => {
  const sp = selected(); if (!sp) return;
  const path = await BrowseFile(t('js.pick_file')).catch(() => '');
  if (!path) return;
  setSetting(sp, b.dataset.browse, path);
  scheduleSave(sp);
  render();
});

['name','host','port','username'].forEach(key => {
  const input = document.getElementById('f-' + key);
  if (input) input.addEventListener('input', e => {
    const sp = selected(); if (!sp) return;
    sp[key] = key === 'port' ? e.target.value.replace(/\D/g, '') : e.target.value;
    scheduleSave(sp);
    if (key === 'name' || key === 'host' || key === 'port') render(); // keep sidebar/select in sync
  });
});
$('#f-password').addEventListener('input', e => {
  const sp = selected(); if (!sp) return;
  state.passwords[sp.id] = e.target.value;
  schedulePasswordSave(sp.id, e.target.value);
});
document.querySelectorAll('[data-bind]').forEach(n => {
  n.addEventListener(n.tagName === 'SELECT' ? 'change' : 'input', e => {
    const sp = selected(); if (!sp) return;
    const value = 'lines' in n.dataset ? e.target.value.split('\n').map(s => s.trim()).filter(Boolean) : e.target.value;
    setSetting(sp, n.dataset.bind, value);
    scheduleSave(sp);
    if (n.tagName === 'SELECT') render(); // auth/connectTo change which fields show
  });
});
document.querySelectorAll('[data-switch]').forEach(sw => {
  sw.onclick = () => {
    const sp = selected(); if (!sp) return;
    setSetting(sp, sw.dataset.switch, !getSetting(sp, sw.dataset.switch));
    scheduleSave(sp);
    render();
  };
});

// ---- new profile type picker ----
document.querySelectorAll('.type-option').forEach(o => o.onclick = () => createProfile(o.dataset.type));
$('#typeCancelBtn').onclick = () => { $('#typeOverlay').hidden = true; };

// ---- profile logo ----
function replaceProfile(updated) {
  const i = state.profiles.findIndex(x => x.id === updated.id);
  if (i >= 0) state.profiles[i] = { ...state.profiles[i], logo: updated.logo };
}
$('#logoPickBtn').onclick = async () => {
  const sp = selected(); if (!sp) return;
  try {
    const updated = await PickProfileLogo(sp.id);
    if (updated.logo) { state.logos = await GetProfileLogos(); replaceProfile(updated); }
  } catch (e) { alert(t('js.err.logo', errText(e))); }
  render();
};
$('#logoRemoveBtn').onclick = async () => {
  const sp = selected(); if (!sp) return;
  try { replaceProfile(await RemoveProfileLogo(sp.id)); delete state.logos[sp.id]; } catch (e) { /* ignore */ }
  render();
};

// ---- delete confirmation ----
$('#deleteCancelBtn').onclick = closeDeleteDialog;
$('#deleteConfirmBtn').onclick = async () => {
  const id = pendingDeleteId; closeDeleteDialog();
  if (id) await removeProfile(id);
};

// ---- about ----
function showAbout() {
  renderAboutUpdate();
  if (state.appInfo) {
    $('#aboutVersion').textContent = t('js.about.version', state.appInfo.version);
    $('#aboutAuthor').textContent = t('js.about.author', state.appInfo.author);
    $('#aboutGithub').textContent = state.appInfo.githubUrl;
  }
  $('#aboutOverlay').hidden = false;
}
$('#aboutTrigger').onclick = showAbout;
$('#checkUpdatesBtn').onclick = async () => { state.update = await CheckForUpdates(); renderAboutUpdate(); render(); };
$('#autoUpdateCheck').onchange = (e) => SetUpdateCheck(e.target.checked).catch(err => alert(errText(err)));
$('#updateLaterBtn').onclick = () => { $('#updateOverlay').hidden = true; };
$('#updateConfirmBtn').onclick = () => runUpdate(true);
EventsOn('update:status', (s) => { state.update = s; renderAboutUpdate(); render(); });
$('#langSelect').onchange = async (e) => {
  try {
    setI18n(await SetLanguage(e.target.value));
    showAbout(); // its dynamic lines are built with t()
    render();
  } catch (err) { alert(errText(err)); }
};
$('#aboutCloseBtn').onclick = () => { $('#aboutOverlay').hidden = true; };
$('#aboutGithub').onclick = () => {
  if (state.appInfo && state.appInfo.githubUrl) BrowserOpenURL(state.appInfo.githubUrl);
};

// ---- components ----
$('#componentsTrigger').onclick = showComponents;
$('#componentsCloseBtn').onclick = () => { $('#componentsOverlay').hidden = true; };
$('#componentsSources').onclick = () => BrowserOpenURL('https://github.com/azizbekatajanov/ingress-deps');

// ---- quit confirmation ----
$('#quitCancelBtn').onclick = () => { $('#quitOverlay').hidden = true; };
$('#quitConfirmBtn').onclick = () => {
  ConfirmQuit($('#quitRemember').checked);
};

// ---- backend push events ----
EventsOn('vpn:update', (snap) => {
  state.snapshots[snap.profileId] = snap;
  render();
});
EventsOn('quit:confirm', () => {
  $('#quitRemember').checked = false;
  $('#quitOverlay').hidden = false;
});
EventsOn('about:show', showAbout);
EventsOn('component:progress', (p) => {
  if (!state.componentProgress[p.name]) return; // not started from this window
  state.componentProgress[p.name] = p;
  render();
});
EventsOn('components:changed', refreshComponents);
// The backend changed a profile on its own (e.g. auto-filled the gateway
// certificate after an untrusted-cert error). Take its copy, or this
// window's next debounced save would write the stale one back.
EventsOn('profile:updated', (updated) => {
  const i = state.profiles.findIndex(p => p.id === updated.id);
  if (i < 0) return;
  clearTimeout(saveTimers[updated.id]);
  state.profiles[i] = updated;
  render();
});
// Connect failed before a tunnel even started (e.g. the component isn't
// installed) while triggered from the tray — show it instead of dropping it.
EventsOn('connect:error', ({ profileId, message }) => {
  if (state.profiles.some(p => p.id === profileId)) {
    state.selectedProfileId = profileId;
    state.showSettings = false;
  }
  render();
  setTimeout(() => alert(t('js.err.connect', message)), 0);
});
// Fired by Manager.finish (vpn_manager.go) right when a connection attempt
// fails — jumps to the profile that failed so its overview + error banner
// is what's actually on screen once the window comes forward, rather than
// whatever profile happened to be selected before (often not the one you
// just tried to connect from the tray).
EventsOn('profile:failed', (profileId) => {
  if (!state.profiles.some(p => p.id === profileId)) return;
  state.selectedProfileId = profileId;
  state.showSettings = false;
  render();
});

// ---- startup ----
async function init() {
  const [profiles, selectedId, theme, components, appInfo, logos, bundle, update] = await Promise.all([
    GetProfiles(), GetSelectedProfileID(), GetTheme(), GetComponents(), GetAppInfo(), GetProfileLogos(), GetI18n(), GetUpdateStatus(),
  ]);
  state.update = update;
  setI18n(bundle);
  state.logos = logos || {};
  state.profiles = profiles;
  state.selectedProfileId = selectedId || (profiles[0] && profiles[0].id);
  state.theme = theme;
  state.components = components || [];
  state.appInfo = appInfo;
  await Promise.all(profiles.map(p => GetSnapshot(p.id).then(s => { state.snapshots[p.id] = s; })));
  render();
}
init();
