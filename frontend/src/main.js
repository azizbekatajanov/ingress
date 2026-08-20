import {
  GetProfiles, GetSelectedProfileID, SelectProfile, AddProfile, UpdateProfile, RemoveProfile,
  GetPassword, SetPassword, GetTheme, SetTheme,
  Connect, Disconnect, CancelConnect, SubmitOtp, GetSnapshot,
  CheckOpenfortivpn, InstallOpenfortivpn, BrowseFile,
  WindowMinimise, WindowToggleMaximise, HideWindow, ConfirmQuit,
  GetAppInfo,
} from '../wailsjs/go/main/App';
import { EventsOn, BrowserOpenURL } from '../wailsjs/runtime/runtime';

const PROFILE_COLORS = ['#ff6961', '#5ac8fa', '#ffd60a', '#bf5af2', '#30d158', '#ff9f0a'];

const state = {
  profiles: [],
  selectedProfileId: null,
  activeTab: 'general',
  showSettings: false,
  theme: 'light',
  showPassword: false,
  otpCode: '',
  snapshots: {}, // profileId -> ConnectionSnapshot from the Go backend
  passwords: {}, // profileId -> cached password (fetched from keychain on demand)
  binaryStatus: null,
  appInfo: null,
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
function connectedProfiles() { return state.profiles.filter(p => snapshotOf(p.id).status === 'connected'); }

function formatDuration(sec) {
  const pad = n => (n < 10 ? '0' + n : '' + n);
  return `${pad(Math.floor(sec/3600))}:${pad(Math.floor((sec%3600)/60))}:${pad(sec%60)}`;
}
function formatBytes(n) {
  if (n < 1024) return n + ' Б';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' КБ';
  return (n/1024/1024).toFixed(2) + ' МБ';
}

// ---- backend-driven actions ----
async function startConnect(id) {
  try { await Connect(id); } catch (e) { alert('Не удалось подключиться: ' + e); }
}
async function cancelConnect(id) { try { await CancelConnect(id); } catch (e) { /* ignore */ } }
async function disconnect(id) { try { await Disconnect(id); } catch (e) { /* ignore */ } }
async function submitOtp(id) {
  if (!state.otpCode || state.otpCode.length < 4) return;
  try { await SubmitOtp(id, state.otpCode); state.otpCode = ''; } catch (e) { alert('Ошибка проверки кода: ' + e); }
}

async function addProfile() {
  const p = await AddProfile();
  state.profiles.push(p);
  state.selectedProfileId = p.id;
  state.activeTab = 'general'; state.showSettings = false;
  render();
}
async function removeProfile(id) {
  if (state.profiles.length <= 1) return;
  await RemoveProfile(id);
  state.profiles = state.profiles.filter(x => x.id !== id);
  delete state.snapshots[id]; delete state.passwords[id];
  if (state.selectedProfileId === id) state.selectedProfileId = state.profiles[0].id;
  render();
}

let saveTimer = null;
function scheduleSave(profile) {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => { UpdateProfile(profile).catch(() => {}); }, 250);
}
let passwordSaveTimer = null;
function schedulePasswordSave(id, password) {
  clearTimeout(passwordSaveTimer);
  passwordSaveTimer = setTimeout(() => { SetPassword(id, password).catch(() => {}); }, 250);
}

// ---- DOM refs ----
const $ = sel => document.querySelector(sel);
const profileListEl = $('#profileList');
const profileSelectEl = $('#profileSelect');

function el(tag, cls, text) { const e = document.createElement('div'); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

function render() {
  document.body.className = state.theme === 'dark' ? 'theme-dark' : 'theme-light';
  const sp = selected();
  const selIdx = state.profiles.indexOf(sp);
  const snap = sp ? snapshotOf(sp.id) : null;

  // sidebar list
  profileListEl.innerHTML = '';
  state.profiles.forEach((p, i) => {
    const pStatus = snapshotOf(p.id).status;
    const row = el('div', 'profile-row' + (p.id === state.selectedProfileId ? ' selected' : ''));
    row.onclick = () => { state.selectedProfileId = p.id; state.showSettings = false; SelectProfile(p.id).catch(() => {}); render(); };
    const avatar = el('div', 'avatar', (p.name||'?').trim().charAt(0).toUpperCase() || '?');
    avatar.style.background = PROFILE_COLORS[i % PROFILE_COLORS.length];
    const info = el('div', 'profile-info');
    info.appendChild(el('div', 'profile-name', p.name));
    info.appendChild(el('div', 'profile-host', p.host ? `${p.host}:${p.port}` : 'не настроен'));
    row.appendChild(avatar); row.appendChild(info);
    if (pStatus === 'connected') row.appendChild(el('div', 'status-dot connected'));
    if (pStatus === 'connecting' || pStatus === 'otp') row.appendChild(el('div', 'status-dot connecting'));
    if (state.profiles.length > 1) {
      const del = el('div', 'delete-btn', '×');
      del.onclick = (e) => { e.stopPropagation(); removeProfile(p.id); };
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
  $('#hostLine').textContent = sp ? (sp.host ? `${sp.host}:${sp.port}` : 'не настроен') : '';

  // status pill + connect button
  const pill = $('#statusPill'); const btn = $('#connectBtn');
  pill.className = 'pill'; btn.className = 'btn primary';
  if (!sp) { pill.textContent = '—'; }
  else if (snap.status === 'connected') { pill.classList.add('connected'); pill.textContent = 'Подключено'; btn.className = 'btn danger'; btn.textContent = 'Отключить'; btn.onclick = () => disconnect(sp.id); }
  else if (snap.status === 'connecting') { pill.classList.add('pending'); pill.textContent = 'Подключение…'; btn.className = 'btn neutral'; btn.textContent = 'Подключение…'; btn.onclick = () => cancelConnect(sp.id); }
  else if (snap.status === 'otp') { pill.classList.add('pending'); pill.textContent = 'Ожидание кода'; btn.className = 'btn neutral'; btn.textContent = 'Ожидание кода'; btn.onclick = () => cancelConnect(sp.id); }
  else { pill.textContent = 'Не подключено'; btn.textContent = 'Подключить'; btn.onclick = () => startConnect(sp.id); }

  $('#gearBtn').style.display = sp && snap.status === 'connected' ? 'none' : 'flex';

  // tabs
  const isConnected = sp && snap.status === 'connected';
  const tabsRow = $('#tabsRow'); const backBtn = $('#backToOverview');
  const allTabs = tabsRow.querySelectorAll('.tab[data-tab]');
  let tabsDef = [];
  if (isConnected) tabsDef = ['status', 'log'];
  else if (state.showSettings) tabsDef = ['general', 'certificate', 'advanced'];
  tabsRow.hidden = tabsDef.length === 0;
  backBtn.hidden = !(state.showSettings && !isConnected);
  if (!tabsDef.includes(state.activeTab)) state.activeTab = tabsDef[0];
  allTabs.forEach(t => {
    const show = tabsDef.includes(t.dataset.tab);
    t.style.display = show ? '' : 'none';
    t.classList.toggle('active', t.dataset.tab === state.activeTab);
  });

  // content views
  const showOverview = sp && snap.status === 'disconnected' && !state.showSettings;
  const showConnecting = sp && snap.status === 'connecting';
  $('#viewOverview').hidden = !showOverview;
  $('#viewConnecting').hidden = !showConnecting;
  $('#viewGeneral').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'general');
  $('#viewCertificate').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'certificate');
  $('#viewAdvanced').hidden = !(sp && !isConnected && state.showSettings && state.activeTab === 'advanced');
  $('#viewStatus').hidden = !(isConnected && state.activeTab === 'status');
  $('#viewLog').hidden = !(isConnected && state.activeTab === 'log');

  if (showOverview) {
    const avatar = $('#overviewAvatar'); avatar.textContent = (sp.name||'?').charAt(0).toUpperCase();
    avatar.style.background = PROFILE_COLORS[selIdx % PROFILE_COLORS.length];
    $('#overviewName').textContent = sp.name;
    $('#overviewHost').textContent = sp.host ? `${sp.host}:${sp.port}` : 'не настроен';
    renderInstallBanner();
    renderErrorBanner(snap);
  }
  if (showConnecting) $('#connectingTitle').textContent = `Подключение к ${sp.host}:${sp.port}…`;

  if (sp && !isConnected) fillForm(sp);
  if (isConnected && state.activeTab === 'status') fillStatus(sp, snap);
  if (isConnected && state.activeTab === 'log') fillLog(snap);

  // OTP modal
  const otp = otpProfile();
  $('#otpOverlay').hidden = !otp;
  if (otp) {
    const otpSnap = snapshotOf(otp.id);
    $('#otpTarget').textContent = `${otp.username || '—'}@${otp.host || '—'}`;
    $('#otpCode').value = state.otpCode;
    $('#otpProgressFill').style.width = Math.max(0, Math.min(100, (otpSnap.otpSecondsLeft/60)*100)) + '%';
    $('#otpTimer').textContent = `Код действителен ещё ${otpSnap.otpSecondsLeft} с`;
    $('#otpSubmitBtn').style.opacity = (!state.otpCode || state.otpCode.length < 4) ? 0.5 : 1;
  }

  // theme switch
  $('#themeToggle').classList.toggle('on', state.theme === 'dark');
}

function renderErrorBanner(snap) {
  const host = $('#errorBanner');
  host.innerHTML = '';
  if (!snap.lastError) return;
  host.appendChild(el('div', 'banner error', snap.lastError));
}

function renderInstallBanner() {
  const host = $('#installBanner');
  host.innerHTML = '';
  if (!state.binaryStatus) return;
  if (!state.binaryStatus.installed) {
    const b = el('div', 'banner');
    b.textContent = 'openfortivpn не найден. ';
    const btn = document.createElement('span');
    btn.className = 'btn primary'; btn.textContent = 'Установить через Homebrew';
    btn.style.marginLeft = '8px';
    btn.onclick = async () => { btn.textContent = 'Установка…'; await InstallOpenfortivpn().catch(() => {}); state.binaryStatus = await CheckOpenfortivpn(); render(); };
    b.appendChild(btn);
    host.appendChild(b);
  } else if (state.binaryStatus.warning) {
    const b = el('div', 'banner error', state.binaryStatus.warning);
    host.appendChild(b);
  }
}

function fillForm(p) {
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
  $('#togglePassword').textContent = state.showPassword ? 'Скрыть' : 'Показать';
  $('#f-realm').value = p.realm;
  $('#f-caFile').value = p.caFile;
  $('#f-userCert').value = p.userCert;
  $('#f-userKey').value = p.userKey;
  $('#f-trustedCert').value = p.trustedCert;
  $('#f-insecureSsl').classList.toggle('on', p.insecureSsl);
  $('#f-setDns').classList.toggle('on', p.setDns);
  $('#f-pppdUsePeerdns').classList.toggle('on', p.pppdUsePeerdns);
  $('#f-setRoutes').classList.toggle('on', p.setRoutes);
  $('#f-halfInternetRoutes').classList.toggle('on', p.halfInternetRoutes);
  $('#f-pppdLog').value = p.pppdLog;
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
  if (lines.length === 0) { panel.appendChild(el('div', 'empty', 'Журнал пуст — выполните подключение.')); return; }
  lines.forEach(line => {
    const row = document.createElement('div');
    row.innerHTML = `<span class="ts">[${line.ts}]</span> ${line.text}`;
    panel.appendChild(row);
  });
  panel.scrollTop = panel.scrollHeight;
}

// ---- event wiring ----
profileSelectEl.addEventListener('change', e => {
  state.selectedProfileId = e.target.value; state.showSettings = false;
  SelectProfile(e.target.value).catch(() => {});
  render();
});
$('#addProfile').onclick = addProfile;
$('#themeToggle').onclick = () => { state.theme = state.theme === 'light' ? 'dark' : 'light'; SetTheme(state.theme).catch(() => {}); render(); };
$('#gearBtn').onclick = () => { state.showSettings = !state.showSettings; render(); };
$('#backToOverview').onclick = () => { state.showSettings = false; render(); };
$('#cancelConnectBtn').onclick = () => { const sp = selected(); if (sp) cancelConnect(sp.id); };
$('#togglePassword').onclick = () => { state.showPassword = !state.showPassword; render(); };
$('#openSettingsLink').onclick = () => { state.showSettings = true; render(); };
$('#disconnectBtn').onclick = () => { const sp = selected(); if (sp) disconnect(sp.id); };
$('#clearLogBtn').onclick = () => { const sp = selected(); if (sp) { const s = snapshotOf(sp.id); s.logLines = []; render(); } };
$('#otpCancelBtn').onclick = () => { const p = otpProfile(); if (p) cancelConnect(p.id); };
$('#otpSubmitBtn').onclick = () => { const p = otpProfile(); if (p) submitOtp(p.id); };
$('#otpCode').addEventListener('input', e => { state.otpCode = e.target.value.toUpperCase().slice(0, 8); render(); });

// window controls (frameless window — traffic lights are custom-drawn, see style.css)
$('#dotClose').onclick = () => HideWindow();
$('#dotMinimise').onclick = () => WindowMinimise();
$('#dotMaximise').onclick = () => WindowToggleMaximise();

document.querySelectorAll('.tab[data-tab]').forEach(t => t.onclick = () => { state.activeTab = t.dataset.tab; render(); });
document.querySelectorAll('[data-browse]').forEach(b => b.onclick = async () => {
  const sp = selected(); if (!sp) return;
  const path = await BrowseFile('Выберите файл').catch(() => '');
  if (!path) return;
  sp[b.dataset.browse] = path;
  scheduleSave(sp);
  render();
});

['name','host','port','username','realm','caFile','userCert','userKey','trustedCert','pppdLog'].forEach(key => {
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
['insecureSsl','setDns','pppdUsePeerdns','setRoutes','halfInternetRoutes'].forEach(key => {
  const sw = document.getElementById('f-' + key);
  if (sw) sw.onclick = () => { const sp = selected(); if (!sp) return; sp[key] = !sp[key]; scheduleSave(sp); render(); };
});

// ---- about ----
function showAbout() {
  if (state.appInfo) {
    $('#aboutVersion').textContent = `Версия ${state.appInfo.version}`;
    $('#aboutAuthor').textContent = `Автор: ${state.appInfo.author}`;
    $('#aboutGithub').textContent = state.appInfo.githubUrl;
  }
  $('#aboutOverlay').hidden = false;
}
$('#aboutTrigger').onclick = showAbout;
$('#aboutCloseBtn').onclick = () => { $('#aboutOverlay').hidden = true; };
$('#aboutGithub').onclick = () => {
  if (state.appInfo && state.appInfo.githubUrl) BrowserOpenURL(state.appInfo.githubUrl);
};

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

// ---- startup ----
async function init() {
  const [profiles, selectedId, theme, binaryStatus, appInfo] = await Promise.all([
    GetProfiles(), GetSelectedProfileID(), GetTheme(), CheckOpenfortivpn(), GetAppInfo(),
  ]);
  state.profiles = profiles;
  state.selectedProfileId = selectedId || (profiles[0] && profiles[0].id);
  state.theme = theme;
  state.binaryStatus = binaryStatus;
  state.appInfo = appInfo;
  await Promise.all(profiles.map(p => GetSnapshot(p.id).then(s => { state.snapshots[p.id] = s; })));
  render();
}
init();
