const state = { status: null, features: [], incidents: [], integrity: null, selected: 'risk_score', range: 1, view: 'overview', connected: false };
const $ = (id) => document.getElementById(id);
const fmtTime = (value) => value ? new Date(value).toLocaleString() : '—';
const fmtValue = (value, unit = '') => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return '—';
  if (unit === 'score' || unit === 'ratio') return value.toFixed(3);
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: value >= 100 ? 0 : 2, notation: value >= 1e7 ? 'compact' : 'standard' }).format(value);
};
const text = (el, value) => { el.textContent = value == null ? '—' : String(value); };
function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value != null) node.textContent = value;
  return node;
}
async function api(path) {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) throw new Error(`API ${response.status}`);
  return response.json();
}
function setView(view) {
  state.view = view;
  const titles = { overview: 'System overview', features: 'Feature history', incidents: 'Incidents', evidence: 'Evidence', health: 'Service health' };
  text($('page-title'), titles[view]);
  for (const node of document.querySelectorAll('.view')) node.classList.toggle('active', node.id === `${view}-view`);
  for (const node of document.querySelectorAll('.nav-item')) {
    const active = node.dataset.view === view;
    node.classList.toggle('active', active);
    if (active) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
  }
  if (view === 'features') loadChart();
  if (view === 'evidence') loadAudit();
  window.history.replaceState(null, '', `#${view}`);
}
function row(parent, values, tags = []) {
  const tr = element('tr');
  values.forEach((value, index) => {
    const td = element('td');
    if (tags.includes(index)) td.append(element('span', `tag ${value === 'Available' ? 'ok' : ''}`, value));
    else text(td, value);
    tr.append(td);
  });
  parent.append(tr);
}
function renderFeatures() {
  const select = $('feature-select');
  const previous = select.value || state.selected;
  select.replaceChildren();
  for (const feature of state.features) {
    const option = element('option', '', feature.label);
    option.value = feature.id;
    select.append(option);
  }
  state.selected = state.features.some(f => f.id === previous) ? previous : (state.features[0]?.id || 'risk_score');
  select.value = state.selected;
  const readings = $('readings-body');
  const all = $('all-features-body');
  readings.replaceChildren(); all.replaceChildren();
  const values = state.status?.values || {};
  const top = ['cycles_per_s', 'instructions_per_s', 'cache_misses_per_s', 'cache_miss_ratio', 'cache_miss_cv'];
  for (const feature of state.features) {
    const available = typeof values[feature.id] === 'number';
    const value = fmtValue(values[feature.id], feature.unit);
    row(all, [feature.label, value, feature.unit, available ? 'Available' : 'Unavailable'], [3]);
    if (top.includes(feature.id)) row(readings, [feature.label, value, available ? 'Live' : 'Unavailable'], [2]);
  }
  for (const tr of all.querySelectorAll('tr')) tr.tabIndex = 0;
  [...all.querySelectorAll('tr')].forEach((tr, i) => {
    tr.addEventListener('click', () => { $('feature-select').value = state.features[i].id; state.selected = state.features[i].id; loadChart(); });
    tr.addEventListener('keydown', e => { if (e.key === 'Enter') tr.click(); });
  });
}
function renderIncidents() {
  const active = state.incidents.filter(incident => incident.status === 'active').length;
  text($('incidents-stat'), active);
  const targets = [$('recent-incidents-body'), $('incident-list')];
  targets.forEach((target, index) => {
    target.replaceChildren();
    const items = index === 0 ? state.incidents.slice(0, 4) : state.incidents;
    if (!items.length) {
      const empty = element('div', 'empty-state');
      empty.append(element('span', 'empty-icon', '△'), element('strong', '', 'No incidents recorded'),
                   element('p', '', 'Suspicious activity will appear here when detected.'));
      target.append(empty);
    }
    for (const incident of items) {
      const wrapper = element('div', 'incident-row');
      const when = element('div', '', fmtTime(incident.opened_at));
      const desc = element('div');
      desc.append(element('strong', '', `Suspected Rowhammer activity · peak ${fmtValue(incident.peak_score, 'score')}`),
                  element('small', '', `Incident ${incident.id.slice(0, 8)} · ${incident.suspicious_windows} suspicious windows`));
      const candidates = incident.process_candidates || [];
      desc.append(element('small', 'process-candidate', candidates.length ?
        `Top CPU near alert (unverified): ${candidates.map(item => `${item.name} (PID ${item.pid})`).join(', ')}` :
        'Process unknown · system-wide counters'));
      wrapper.append(when, desc, element('span', `tag ${incident.status === 'active' ? 'bad' : ''}`, incident.status));
      target.append(wrapper);
    }
  });
}
function detail(parent, name, value) {
  const wrapper = element('div');
  wrapper.append(element('dt', '', name), element('dd', '', value));
  parent.append(wrapper);
}
function renderIntegrity() {
  const result = state.integrity;
  const anchor = state.status?.external_anchor;
  const label = !result ? 'UNKNOWN' : !result.ok ? 'FAILED' : anchor?.state === 'ACKNOWLEDGED' ? 'ANCHORED' : 'LOCAL ONLY';
  text($('integrity-stat'), label);
  $('integrity-stat').className = result?.ok ? anchor?.state === 'ACKNOWLEDGED' ? 'good' : 'warn' : result ? 'bad' : '';
  text($('integrity-detail'), result?.ok ? `Signed through #${result.locally_signed_through}` : result?.error || 'Verification pending');
  const dl = $('evidence-summary'); dl.replaceChildren();
  detail(dl, 'Local verification', result?.ok ? 'Passed' : result ? 'Failed' : 'Pending');
  detail(dl, 'Signed through', result ? `#${result.locally_signed_through}` : '—');
  detail(dl, 'Off-host checkpoint', anchor?.state === 'ACKNOWLEDGED' ? `Acknowledged through #${anchor.sequence}` : anchor?.state === 'STALE' ? `Stale at #${anchor.sequence}` : 'Not configured');
  detail(dl, 'Last checkpoint', fmtTime(state.status?.local_checkpoint?.timestamp));
  const banner = $('evidence-banner');
  banner.className = `notice ${result && !result.ok ? 'bad' : ''}`;
  text(banner, result && !result.ok ? `Integrity check failed: ${result.error}` :
    anchor?.state === 'ACKNOWLEDGED' ? 'The checkpoint receiver acknowledged the latest local checkpoint. Independent verification still requires trusted keys and receiver access.' :
    anchor?.state === 'STALE' ? `Off-host checkpoint delivery is behind: ${anchor.error || 'retry pending'}. Recent evidence is only local.` :
    'Local hash chain and signature verification is available. Off-host anchoring is not configured, so rollback or deletion of local evidence cannot be ruled out.');
}
function renderHealth() {
  const status = state.status;
  const dl = $('health-list'); dl.replaceChildren();
  detail(dl, 'Host', status?.host || '—');
  detail(dl, 'PMU state', status?.pmu_state || 'OFFLINE');
  detail(dl, 'Collector detail', status?.reason || 'Daemon unreachable');
  detail(dl, 'Last sample', fmtTime(status?.last_sample));
  detail(dl, 'Running ratio', fmtValue(status?.quality?.running_ratio, 'ratio'));
  detail(dl, 'Dropped windows', status?.dropped_windows ?? '—');
  detail(dl, 'Detector', status?.detector || '—');
  detail(dl, 'Audit sequence', status?.audit_sequence ?? '—');
  detail(dl, 'Local checkpoint', `#${status?.local_checkpoint?.sequence ?? 0}`);
  detail(dl, 'External anchor', status?.external_anchor?.state || 'Not configured');
  detail(dl, 'Session ID', status?.session_id || '—');
  detail(dl, 'Boot ID', status?.boot_id || '—');
}
function renderStatus() {
  const status = state.status;
  const pmu = state.connected ? status?.pmu_state || 'STARTING' : 'OFFLINE';
  const badge = $('state-badge');
  const suspicious = Boolean(status?.active_incident);
  const degraded = Boolean(status?.model_error) || pmu === 'DEGRADED';
  text(badge, !state.connected ? 'OFFLINE' : suspicious ? 'SUSPICIOUS' : degraded ? 'DEGRADED' : pmu);
  badge.className = `state-badge ${!state.connected ? 'degraded' : suspicious ? 'suspicious' : degraded ? 'degraded' : pmu === 'MONITORING' ? 'monitoring' : 'starting'}`;
  text($('state-reason'), state.connected ? status?.reason || 'Monitoring' : 'Connection to daemon unavailable');
  text($('host'), status?.host || '—');
  text($('pmu-stat'), pmu);
  $('pmu-stat').className = pmu === 'MONITORING' ? 'good' : 'warn';
  text($('pmu-detail'), pmu === 'MONITORING' ? 'Live counters' : 'Measurements unavailable');
  text($('score-stat'), fmtValue(status?.risk_score, 'score'));
  text($('score-detail'), status?.risk_score == null ? 'Data unavailable' : status?.model_sha256 ? 'Trained model' : 'Experimental PMU rule');
  text($('risk-caption'), status?.risk_score == null ? 'Risk score unavailable until a valid PMU window is collected' :
    status?.model_sha256 ? 'Trained model · real PMU measurements' : 'Experimental rule · real PMU measurements');
  text($('footer-mode'), status?.model_error ? 'Detection unavailable · Model failed validation' :
    status?.model_sha256 ? 'Experimental ML model · Tested on one host and one tool' :
    'Experimental PMU rule · One host tested; false alerts remain possible');
  renderFeatures(); renderIncidents(); renderIntegrity(); renderHealth();
}
function chart(target, points, label, unit) {
  const width = Math.max(340, Math.round(target.clientWidth || 820)), height = target.clientHeight || 310, left = 49, right = 17, top = 12, bottom = 29;
  const drawable = height - top - bottom;
  const clean = points.filter(point => typeof point.value === 'number' && Number.isFinite(point.value));
  let max = unit === 'score' ? 1 : Math.max(1, ...clean.map(point => point.value)) * 1.1;
  let min = 0;
  if (unit === 'ratio') max = Math.max(1, max);
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  svg.classList.add('chart-svg');
  const add = (tag, attrs, content) => {
    const node = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    if (content != null) node.textContent = content;
    svg.append(node);
  };
  for (let i = 0; i <= 5; i++) {
    const y = top + drawable * i / 5;
    add('line', { x1: left, y1: y, x2: width - right, y2: y, class: 'chart-grid' });
    add('text', { x: left - 9, y: y + 4, 'text-anchor': 'end', class: 'chart-label' }, fmtValue(max - (max - min) * i / 5, unit));
  }
  add('line', { x1: left, y1: height - bottom, x2: width - right, y2: height - bottom, class: 'chart-axis' });
  if (points.length) {
    const first = new Date(points[0].timestamp).getTime();
    const last = new Date(points[points.length - 1].timestamp).getTime();
    const span = Math.max(last - first, 1);
    let path = '';
    let segmentOpen = false;
    for (const point of points) {
      if (typeof point.value !== 'number' || !Number.isFinite(point.value)) { segmentOpen = false; continue; }
      const x = left + ((new Date(point.timestamp).getTime() - first) / span) * (width - left - right);
      const y = top + (1 - (point.value - min) / (max - min)) * drawable;
      path += `${segmentOpen ? ' L' : ' M'}${x.toFixed(2)} ${y.toFixed(2)}`;
      segmentOpen = true;
    }
    if (clean.length > 1) add('path', { d: path, class: 'chart-line' });
    if (clean.length === 1) add('circle', { cx: left + (width - left - right) / 2, cy: top + (1 - (clean[0].value - min) / (max - min)) * drawable, r: 4, class: 'chart-dot' });
    const ticks = width < 460 ? 2 : 4;
    for (let i = 0; i <= ticks; i++) {
      const timestamp = new Date(first + span * i / ticks);
      add('text', { x: left + (width - left - right) * i / ticks, y: height - 7, 'text-anchor': i === 0 ? 'start' : i === ticks ? 'end' : 'middle', class: 'chart-label' }, timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    }
  }
  if (!clean.length) {
    add('text', { x: (width + left) / 2, y: height / 2 - 7, class: 'chart-empty' }, 'Data unavailable');
    add('text', { x: (width + left) / 2, y: height / 2 + 16, class: 'chart-empty-sub' }, 'No valid PMU measurements in this time range');
  }
  target.replaceChildren(svg);
  target.setAttribute('aria-label', `${label} over time. ${clean.length ? `${clean.length} measured points` : 'No measurements available'}`);
}
async function loadChart() {
  const feature = state.view === 'features' ? state.selected : 'risk_score';
  const target = state.view === 'features' ? $('feature-chart') : $('risk-chart');
  const def = state.features.find(f => f.id === feature);
  if (state.view === 'features') {
    text($('feature-chart-title'), def?.label || 'Feature');
    text($('feature-unit'), def?.unit || '');
  }
  try {
    const points = await api(`/api/v1/timeseries?feature=${encodeURIComponent(feature)}&hours=${state.view === 'features' ? state.range : 1}&limit=600`);
    chart(target, points, def?.label || 'Risk score', def?.unit || 'score');
  } catch { chart(target, [], def?.label || 'Risk score', def?.unit || 'score'); }
}
async function loadAudit() {
  try {
    const entries = await api('/api/v1/audit?limit=50');
    const list = $('audit-list'); list.replaceChildren();
    for (const record of entries) {
      const item = element('div', 'audit-row');
      item.append(element('strong', '', `#${record.seq}`), element('time', '', fmtTime(record.timestamp_utc)), element('span', '', record.event));
      list.append(item);
    }
    if (!entries.length) list.append(element('div', 'empty-state', 'No audit records yet.'));
  } catch { text($('audit-list'), 'Audit records unavailable'); }
}
async function clearHistory() {
  const buttons = [...document.querySelectorAll('[data-clear-history]')];
  buttons.forEach(button => { button.disabled = true; });
  let message;
  try {
    const response = await fetch('/api/v1/history/clear', { method: 'POST', headers: { 'X-RowGuard-Action': 'clear-visible-history' } });
    if (!response.ok) throw new Error(`API ${response.status}`);
    const result = await response.json();
    message = result.active_incident_retained ? 'History cleared; the active incident remains. Signed audit evidence is retained.' :
      'Visible history cleared. Signed audit evidence is retained.';
    await refresh(true);
    if (state.view === 'evidence') await loadAudit();
  } catch (error) {
    message = `Could not clear visible history: ${error.message}`;
  } finally {
    buttons.forEach(button => { button.disabled = false; });
    document.querySelectorAll('[data-clear-result]').forEach(node => text(node, message));
  }
}
async function refresh(full = false) {
  try {
    const [status, incidents] = await Promise.all([api('/api/v1/status'), api('/api/v1/incidents')]);
    Object.assign(state, { status, incidents, connected: true });
    if (full || !state.features.length) {
      const [features, integrity] = await Promise.all([api('/api/v1/features'), api('/api/v1/integrity')]);
      Object.assign(state, { features, integrity });
    }
    renderStatus();
    if (state.view === 'overview' || state.view === 'features') loadChart();
    if (full && state.view === 'evidence') loadAudit();
  } catch {
    state.connected = false;
    renderStatus();
  }
}
let pending = false;
function scheduleRefresh() {
  if (pending) return;
  pending = true;
  window.setTimeout(() => { pending = false; refresh(); }, 650);
}
function connect() {
  const stream = new EventSource('/api/v1/events');
  let errors = 0;
  for (const name of ['reset', 'status', 'sample', 'incident', 'history']) stream.addEventListener(name, scheduleRefresh);
  stream.onopen = () => { errors = 0; };
  // Quick Tunnels do not carry SSE. Polling below keeps the same-origin dashboard live.
  stream.onerror = () => { if (++errors >= 3) stream.close(); };
}
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => setView(button.dataset.view)));
document.querySelectorAll('[data-open]').forEach(button => button.addEventListener('click', () => setView(button.dataset.open)));
document.querySelectorAll('[data-clear-history]').forEach(button => button.addEventListener('click', clearHistory));
$('feature-select').addEventListener('change', event => { state.selected = event.target.value; loadChart(); });
$('range-select').addEventListener('change', event => { state.range = Number(event.target.value); loadChart(); });
const initial = location.hash.slice(1);
setView(['overview', 'features', 'incidents', 'evidence', 'health'].includes(initial) ? initial : 'overview');
refresh(true);
window.setTimeout(connect, 1200);
window.setInterval(() => refresh(), 2000);
window.setInterval(() => refresh(true), 15000);
window.addEventListener('resize', scheduleRefresh);
