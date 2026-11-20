const API = '/api/targets';

let targets = [];
let activeId = null;

// ---- running state + live output panel ----
const runningKeys = new Set();
const ACTIVITY_MAX = 200;
// tools that light up a pipeline stage other than their own card
const STAGE_OF = { httpxfilter: 'httpxlive', cvenvd: 'cvemerge', cvecircl: 'cvemerge' };

function logActivity(text, cls = 'a-info') {
  const list = document.getElementById('activity-list');
  if (!list) return;
  const empty = list.querySelector('.act-empty');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = 'act-row ' + cls;
  const time = document.createElement('i');
  time.textContent = new Date().toTimeString().slice(0, 8);
  row.append(time, document.createTextNode(text)); // text nodes only - no HTML injection
  list.appendChild(row);
  while (list.children.length > ACTIVITY_MAX) list.removeChild(list.firstChild);
  list.scrollTop = list.scrollHeight;
}

function logResult(key, data) {
  const n = data.count ?? data.total ?? (Array.isArray(data.findings) ? data.findings.length : undefined);
  logActivity(`${key} done` + (n !== undefined ? ` - ${n} result(s)` : ''), 'a-ok');
  if (Array.isArray(data.cves)) {
    // worst CVEs first (the backend sorts them), coloured like the result lists
    data.cves.filter(l => /^CVE-/i.test(l)).slice(0, 3)
      .forEach(l => logActivity(l.split('\t').slice(0, 3).join('  '), severityClass(l) || 'a-info'));
  }
  if (Array.isArray(data.findings) && data.findings.length) {
    logActivity(`${key}: ${data.findings.length} finding(s)`, 'sev-danger');
  }
}

function markRunning() {
  const busy = runningKeys.size > 0;
  document.body.classList.toggle('is-running', busy);
  const engine = document.getElementById('engine-state');
  if (engine) engine.textContent = busy ? 'running: ' + [...runningKeys].join(', ') : 'engine online';
  const stages = new Set([...runningKeys].map(k => STAGE_OF[k] || k));
  document.querySelectorAll('.pl-node').forEach(n => n.classList.toggle('run', stages.has(n.dataset.key)));
}

function setTopbar(text) {
  const el = document.getElementById('topbar-cmd');
  if (el) el.textContent = text;
}

// UI collapse/expand state - kept in memory so it survives re-renders
// (e.g. after running a tool) instead of resetting every time.
let uiState = {
  sections: { recon: false, vuln: false, auth: false, aiKey: false },
  tools: {
    subdomains: false, httpxlive: false, httpxfilter: false,
    portscan: false, endpoints: false,
    dns: false, whois: false, techinfo: false, wayback: false, uro: false,
    urlpatterns: false, xssprobe: false, openredirect: false, sqliprobe: false, lfiprobe: false,
    cvenvd: false, cvecircl: false, cvemerge: false, allparams: false,
    tlschecks: false, webmisconfig: false, nsevuln: false, subtakeover: false,
    katana: false, jsextract: false, jsurls: false, jssecrets: false, jsparams: false,
    wafdetect: false, waffilter: false
  }
};

function resetUiState() {
  uiState = {
    sections: { recon: false, vuln: false, auth: false, aiKey: false },
    tools: {
      subdomains: false, httpxlive: false, httpxfilter: false,
      portscan: false, endpoints: false,
      dns: false, whois: false, techinfo: false, wayback: false, uro: false,
      urlpatterns: false, xssprobe: false, openredirect: false, sqliprobe: false, lfiprobe: false,
    cvenvd: false, cvecircl: false, cvemerge: false, allparams: false,
    tlschecks: false, webmisconfig: false, nsevuln: false, subtakeover: false,
      katana: false, jsextract: false, jsurls: false, jssecrets: false, jsparams: false,
      wafdetect: false, waffilter: false
    }
  };
}

// Dependency-safe order for "Run All" (Recon):
//   1) passive intel      : subdomains, dns, whois, wayback
//   2) live hosts         : httpx probe -> status split
//   3) fingerprint        : wafw00f -> waf filter, tech fingerprint, port scan
//   4) crawl + JS         : katana -> JS extractor -> jsluice urls
//   5) URL cleanup        : uro (incl. optional urldedupe pass) -> Parameter Collector
//   6) merge + endpoints  : JS Parameter Collector (must run AFTER Parameter
//                           Collector, which rewrites all_params.txt), endpoints
const RUN_ALL_ORDER = [
  { key: 'subdomains', endpoint: 'subdomains' },
  { key: 'dns', endpoint: 'dns' },
  { key: 'whois', endpoint: 'whois' },
  { key: 'wayback', endpoint: 'wayback' },
  { key: 'httpxlive', endpoint: 'httpx_live' },
  { key: 'httpxfilter', endpoint: 'httpx_filter' },
  { key: 'wafdetect', endpoint: 'waf' },
  { key: 'waffilter', endpoint: 'waf_filter' },
  { key: 'techinfo', endpoint: 'techinfo' },
  { key: 'portscan', endpoint: 'portscan' },
  { key: 'katana', endpoint: 'katana' },
  { key: 'jsextract', endpoint: 'js_extractor' },
  { key: 'jsurls', endpoint: 'jsluice_urls' },
  { key: 'uro', endpoint: 'uro' },
  { key: 'allparams', endpoint: 'all_params' },
  { key: 'jsparams', endpoint: 'js_params' },
  { key: 'endpoints', endpoint: 'endpoints' },
];

// Tools that belong to the Vulnerability Scan section (everything else is Recon).
const VULN_TOOL_KEYS = ['cvenvd', 'cvecircl', 'cvemerge', 'urlpatterns', 'jssecrets', 'xssprobe', 'openredirect', 'sqliprobe', 'lfiprobe', 'tlschecks', 'webmisconfig', 'nsevuln', 'subtakeover'];

// Run order for the Vulnerability Scan section's "Run All".
//   CVE lookups (passive, need versions from Recon) -> merge -> URL Pattern Filter ->
//   JS Secrets (needs JS Extractor from Recon) -> XSS Prober (active, last)
const VULN_RUN_ALL_ORDER = [
  { key: 'cvenvd', endpoint: 'cve_nvd' },
  { key: 'cvecircl', endpoint: 'cve_circl' },
  { key: 'cvemerge', endpoint: 'cve_merge' },
  { key: 'urlpatterns', endpoint: 'urlpatterns' },
  { key: 'jssecrets', endpoint: 'jsluice_secrets' },
  { key: 'xssprobe', endpoint: 'xssprobe' },
  { key: 'openredirect', endpoint: 'openredirect' },
  { key: 'sqliprobe', endpoint: 'sqliprobe' },
  { key: 'lfiprobe', endpoint: 'lfiprobe' },
  { key: 'tlschecks', endpoint: 'tlschecks' },
  { key: 'webmisconfig', endpoint: 'webmisconfig' },
  { key: 'nsevuln', endpoint: 'nsevuln' },
  { key: 'subtakeover', endpoint: 'subtakeover' },
];

async function fetchTargets() {
  const res = await fetch(API);
  targets = await res.json();
}

function renderSidebar() {
  const list = document.getElementById('target-list');
  if (targets.length === 0) {
    list.innerHTML = '<div id="empty-targets">No targets yet.<br>Click + Add Target to start.</div>';
    return;
  }
  list.innerHTML = '';
  targets.forEach(t => {
    const el = document.createElement('div');
    el.className = 'target-item' + (t.id === activeId ? ' active' : '');
    const badge = t.xss_findings > 0 ? `<span class="t-badge" title="${t.xss_findings} unescaped XSS finding(s)"></span>` : '';
    el.innerHTML = `${badge}<span class="t-name">${escapeHtml(t.name)}</span><span class="t-remove" data-id="${t.id}">✕</span>`;
    el.addEventListener('click', (e) => {
      if (e.target.classList.contains('t-remove')) return;
      activeId = t.id;
      resetUiState();
      renderSidebar();
      renderMain();
    });
    el.querySelector('.t-remove').addEventListener('click', async (e) => {
      e.stopPropagation();
      if (confirm(`Delete target "${t.name}"? Its folder on disk will be removed too.`)) {
        await fetch(`${API}/${t.id}`, { method: 'DELETE' });
        if (activeId === t.id) activeId = null;
        await fetchTargets();
        renderSidebar();
        renderMain();
      }
    });
    list.appendChild(el);
  });
}

// ---- generic helpers shared by every recon tool card ----

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, ch => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function renderMarkdownLite(md) {
  // Just enough Markdown to render the AI report: ## headings, **bold**, - lists.
  // No library (keeps the frontend dependency-free) - escape first, then unescape
  // only the few tags this function itself introduces.
  const lines = escapeHtml(md).split('\n');
  let html = '';
  let inList = false;
  const closeList = () => { if (inList) { html += '</ul>'; inList = false; } };
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) { closeList(); continue; }
    const inline = line.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
    if (line.startsWith('## ')) { closeList(); html += `<h4>${inline.slice(3)}</h4>`; }
    else if (line.startsWith('# ')) { closeList(); html += `<h3>${inline.slice(2)}</h3>`; }
    else if (line.startsWith('- ')) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += `<li>${inline.slice(2)}</li>`;
    } else { closeList(); html += `<p>${inline}</p>`; }
  }
  closeList();
  return html;
}

function toggleBlock(id, open) {
  const el = document.getElementById(id);
  if (el) el.style.display = open ? '' : 'none';
}
function toggleChevron(headId, open) {
  const head = document.getElementById(headId);
  if (!head) return;
  const chevron = head.querySelector('.chevron');
  if (chevron) chevron.classList.toggle('open', open);
}

// Category tiers for URL Pattern Filter lines, e.g. "https://...\t(xss, redirect)"
const CRITICAL_TAGS = ['rce', 'sqli'];
const HIGH_TAGS = ['xss', 'ssrf', 'lfi'];
const MEDIUM_TAGS = ['idor', 'debug_logic'];
const LOW_TAGS = ['redirect', 'interesting_ext'];

// Classifies a result line so dangerous/noteworthy findings stand out from
// routine output instead of every line looking the same shade of gray.
function severityClass(line) {
  const cve = line.match(/^CVE-\d{4}-\d+\s+(CRITICAL|HIGH|MEDIUM|LOW)\b/i);
  if (cve) return 'sev-' + cve[1].toLowerCase();
  if (/UNESCAPED|SUCCEEDED/.test(line)) return 'sev-danger';
  if (/escaped \(likely safe\)|refused\/failed/.test(line)) return 'sev-safe';

  // URL Pattern Filter lines end with a tag list like "(xss, redirect)" -
  // color by the worst category present on that line.
  const tagMatch = line.match(/\(([a-z_, ]+)\)\s*$/i);
  if (tagMatch) {
    const tags = tagMatch[1].split(',').map(s => s.trim().toLowerCase());
    if (tags.some(t => CRITICAL_TAGS.includes(t))) return 'sev-critical';
    if (tags.some(t => HIGH_TAGS.includes(t))) return 'sev-high';
    if (tags.some(t => MEDIUM_TAGS.includes(t))) return 'sev-medium';
    if (tags.some(t => LOW_TAGS.includes(t))) return 'sev-low';
  }
  return '';
}

// Turns an ISO timestamp (or null) into a short "Xm ago" style string for
// display next to a tool's status.
function formatRelativeTime(iso) {
  if (!iso) return null;
  const diffSec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diffSec < 5) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.floor(diffHr / 24)}d ago`;
}

// Only show the per-card filter box once there's enough output to
// actually need filtering.
const SEARCH_THRESHOLD = 8;

function toolCardHTML({ key, title, description, note, statusText, items, disabledReason, updatedAt }) {
  const open = uiState.tools[key];
  const disabledAttr = disabledReason ? 'disabled' : '';
  const titleAttr = disabledReason ? ` title="${disabledReason}"` : '';
  const displayedStatus = disabledReason
    ? `<span class="tool-status locked">${disabledReason}</span>`
    : statusText;
  const relTime = formatRelativeTime(updatedAt);
  const fullNote = relTime ? `${note} · Last run: ${relTime}` : note;
  const showSearch = items.length > SEARCH_THRESHOLD;
  return `
    <div class="tool-card">
      <div class="tool-card-head" id="tool-head-${key}">
        <span class="chevron ${open ? 'open' : ''}">&#9656;</span>
        <div class="tool-info">
          <h3>${title}</h3>
          <p>${description}</p>
        </div>
      </div>
      <div class="tool-body" id="tool-body-${key}" style="${open ? '' : 'display:none;'}">
        <div class="tool-run-row">
          <button class="run-btn" id="run-${key}" ${disabledAttr}${titleAttr}>Run</button>
          <div class="tool-status" id="status-${key}">${displayedStatus}</div>
        </div>
        <div id="results-wrap-${key}" style="${items.length > 0 ? '' : 'display:none;'}">
          ${showSearch ? `<input type="text" class="result-search" id="search-${key}" placeholder="Filter ${items.length} results...">` : ''}
          <div class="result-list" id="results-${key}">${items.map(s => `<div class="${severityClass(s)}">${s}</div>`).join('')}</div>
          <div class="tool-actions">
            <button class="ghost-btn" id="copy-${key}">Copy all</button>
          </div>
        </div>
        <p class="tool-note">${fullNote}</p>
      </div>
    </div>`;
}

function toolGroupHTML(title, cardsHtml) {
  return `<div class="tool-group"><h4 class="tool-group-title">${title}</h4>${cardsHtml}</div>`;
}

function wireToolCard(key, items, runFn) {
  document.getElementById(`tool-head-${key}`).addEventListener('click', () => {
    uiState.tools[key] = !uiState.tools[key];
    toggleBlock(`tool-body-${key}`, uiState.tools[key]);
    toggleChevron(`tool-head-${key}`, uiState.tools[key]);
  });
  document.getElementById(`run-${key}`).addEventListener('click', (e) => {
    e.stopPropagation();
    runFn();
  });
  const cpBtn = document.getElementById(`copy-${key}`);
  if (cpBtn) cpBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(items.join('\n'));
    const original = cpBtn.textContent;
    cpBtn.textContent = 'Copied!';
    setTimeout(() => { cpBtn.textContent = original; }, 1200);
  });
  const searchEl = document.getElementById(`search-${key}`);
  if (searchEl) {
    searchEl.addEventListener('click', (e) => e.stopPropagation());
    searchEl.addEventListener('input', () => {
      const q = searchEl.value.toLowerCase();
      document.querySelectorAll(`#results-${key} > div`).forEach(div => {
        div.style.display = div.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
}

function statusFor(ran, count, foundLabel, notRunLabel) {
  if (!ran) return notRunLabel || 'Not run yet.';
  if (count > 0) return `Last result: ${count} ${foundLabel}`;
  return `Last run found 0 ${foundLabel}.`;
}

async function runTool({ key, endpoint, method, resultKey, t, onDone }) {
  const statusEl = document.getElementById(`status-${key}`);
  const btn = document.getElementById(`run-${key}`);
  btn.disabled = true;
  statusEl.className = 'tool-status running';
  statusEl.textContent = 'Running... this can take a little while.';
  runningKeys.add(key);
  markRunning();
  logActivity(`${key} started`, 'a-info');

  try {
    const res = await fetch(`${API}/${t.id}/${endpoint}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Unknown error');
    logResult(key, data);

    uiState.sections[VULN_TOOL_KEYS.includes(key) ? 'vuln' : 'recon'] = true;
    uiState.tools[key] = true;
    renderMain();
  } catch (err) {
    statusEl.className = 'tool-status err';
    statusEl.textContent = 'Error: ' + err.message;
    btn.disabled = false;
    logActivity(`${key} failed: ${err.message}`, 'a-err');
  } finally {
    runningKeys.delete(key);
    markRunning();
  }
}

async function runAll(t, order = RUN_ALL_ORDER, btnId = 'run-all-btn', statusId = 'run-all-status', sectionKey = 'recon') {
  const btn = document.getElementById(btnId);
  const statusEl = document.getElementById(statusId);
  if (!btn || !statusEl) return;
  btn.disabled = true;
  const failures = [];

  for (let i = 0; i < order.length; i++) {
    const step = order[i];
    statusEl.textContent = `Running ${step.key}... (${i + 1}/${order.length})`;
    runningKeys.add(step.key);
    markRunning();
    logActivity(`${step.key} started (${i + 1}/${order.length})`, 'a-info');
    try {
      const res = await fetch(`${API}/${t.id}/${step.endpoint}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        failures.push(`${step.key}: ${data.error || 'error'}`);
        logActivity(`${step.key} failed: ${data.error || 'error'}`, 'a-err');
      } else {
        logResult(step.key, data);
        uiState.tools[step.key] = true; // auto-expand the card so the result is visible without a manual re-run
      }
    } catch (err) {
      failures.push(`${step.key}: ${err.message}`);
      logActivity(`${step.key} failed: ${err.message}`, 'a-err');
    } finally {
      runningKeys.delete(step.key);
      markRunning();
    }
  }

  statusEl.textContent = failures.length
    ? `Done, with ${failures.length} issue(s) - ${failures.join(' | ')}`
    : 'All tools finished.';
  btn.disabled = false;
  uiState.sections[sectionKey] = true;
  renderMain();
}

function reportSection(title, items) {
  const body = items.length
    ? items.map(i => `- ${i}`).join('\n')
    : '_Not run, or no results yet._';
  return `## ${title}\n\n${body}\n\n`;
}

function buildReportMarkdown(t, data) {
  let md = `# Recon Report - ${t.name}\n\n`;
  md += `**Target:** ${t.domain}\n**Generated:** ${new Date().toISOString()}\n\n---\n\n`;
  md += reportSection('Subdomain Enumeration (all-in-one)', data.subs);
  md += reportSection('Live Host Probe (httpx)', data.liveHosts);
  md += reportSection('Live Host Status Split', data.httpxSplit);
  md += reportSection('WAF Detection (wafw00f)', data.wafRows);
  md += reportSection('WAF Split - WAF-protected', data.wafWith);
  md += reportSection('WAF Split - No WAF', data.wafWithout);
  md += reportSection('Web Crawl (katana)', data.katanaUrls);
  md += reportSection('JS Files Extracted', data.jsFiles);
  md += reportSection('JS URLs (jsluice)', data.jsUrlsFound);
  md += reportSection('JS Secrets (jsluice)', data.jsSecretFindings);
  md += reportSection('JS Parameter Worklist (all_params)', data.jsParamUrls);
  md += reportSection('Port Scan (nmap)', data.ports);
  md += reportSection('DNS Records', data.dnsRecords);
  md += reportSection('WHOIS / RDAP Lookup', data.whoisLines);
  md += reportSection('Directory / Endpoint Discovery', data.endpoints);
  md += reportSection('Wayback Machine URLs', data.waybackUrls);
  md += reportSection('URL Cleaner (uro)', data.uroUrls);
  md += reportSection('URL Pattern Filter', data.urlPatterns);
  md += reportSection('Parameter Collector (all_params)', data.paramUrls);
  md += reportSection('Tech Fingerprint + TLS', data.techLines);
  md += reportSection('XSS Reflection Prober (dalfox-inspired)', data.xssFindings);
  md += reportSection('Open Redirect Prober', data.openRedirFindings);
  md += reportSection('SQL Injection Error-Based Prober', data.sqliFindings);
  md += reportSection('LFI / Path Traversal Prober', data.lfiFindings);
  md += reportSection('TLS / SSL Deep Checks', data.tlsFindings);
  md += reportSection('Web Misconfiguration Checker', data.webMiscFindings);
  md += reportSection('Nmap Vuln Scripts', data.nseVulnFindings);
  md += reportSection('Subdomain Takeover Checker', data.subTakeoverFindings);
  md += reportSection('CVEs - merged (NVD + CIRCL)', data.cveMergedLines);
  md += reportSection('CVE Lookup (NVD)', data.cveNvdLines);
  md += reportSection('CVE Lookup (CIRCL)', data.cveCirclLines);
  return md;
}

function downloadReport(t, data) {
  const md = buildReportMarkdown(t, data);
  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${t.id}-recon-report.md`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}



// ---------- Monitoring page (landing option, beside Framework) ----------
const MON = '/api/monitoring';
function monEsc(s){ return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
window.monTogglePw = function(btn){
  const span = btn.parentElement.querySelector('.pw-val');
  if (!span) return;
  const hidden = span.classList.toggle('pw-blur');
  span.classList.toggle('pw-show', !hidden);
  btn.textContent = hidden ? 'Show' : 'Hide';
};
function monRenderEmpty(msg){
  document.getElementById('mon-results').innerHTML = `<tr><td colspan="5" style="color:var(--text-faint);padding:14px">${monEsc(msg)}</td></tr>`;
  document.getElementById('mon-count').textContent = '';
}
function monRenderRows(results){
  const body = document.getElementById('mon-results');
  document.getElementById('mon-count').textContent = results.length + ' result(s)';
  if (!results.length) { monRenderEmpty('No matches. Try another email, username, domain or URL.'); return; }
  body.innerHTML = results.slice(0, 200).map(e => {
    const pw = e.password || '';
    const pwCell = pw ? `<span class="pw-val pw-blur">${monEsc(pw)}</span><button class="pw-eye" onclick="monTogglePw(this)" title="Show / hide password">Show</button>` : '—';
    return `<tr><td>${monEsc((e.date||'').slice(0,10))}</td><td>${monEsc(e.url||e.domain||'—')}</td><td>${e.email ? monEsc(e.email) : monEsc(e.username||'—')}</td><td>${pwCell}</td><td>${monEsc(e.source||'—')}</td></tr>`;
  }).join('');
}
async function monRefresh(){
  try { const d = await (await fetch(`${MON}/status`)).json(); document.getElementById('mon-total').textContent = d.logs || 0; } catch (e) { /* server not up yet */ }
}
async function monSearch(){
  const q = document.getElementById('mon-q').value.trim();
  if (!q) { monRenderEmpty('Search for something to see results — nothing is listed until you search.'); return; }
  const field = document.getElementById('mon-field').value;
  const d = await (await fetch(`${MON}/search?q=${encodeURIComponent(q)}&field=${encodeURIComponent(field)}`)).json();
  monRenderRows(d.results || []);
}
async function monIngestFiles(files){
  let total = 0;
  for (const f of files) {
    const text = await f.text();
    const res = await fetch(`${MON}/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, source: f.name }) });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'import failed');
    total += d.added || 0;
  }
  return total;
}
async function monAfterImport(added){
  document.getElementById('mon-ingest-status').textContent = 'Indexed ' + added + ' new entries.';
  await monRefresh();
  monSearch();
}
document.getElementById('mon-search-btn').addEventListener('click', monSearch);
document.getElementById('mon-q').addEventListener('keydown', (e) => { if (e.key === 'Enter') monSearch(); });
document.getElementById('mon-clear-btn').addEventListener('click', () => {
  document.getElementById('mon-q').value = '';
  monRenderEmpty('Search for something to see results — nothing is listed until you search.');
});
document.getElementById('mon-link-btn').addEventListener('click', async () => {
  const url = document.getElementById('mon-link-url').value.trim();
  if (!url) return alert('Paste a log link first.');
  try {
    const res = await fetch(`${MON}/ingest-url`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'fetch failed');
    document.getElementById('mon-link-status').textContent = 'Indexed ' + d.added + ' new entries from that link.';
    await monRefresh();
    alert('Indexed ' + d.added + ' new entries from that link. Now search for something.');
  } catch (err) { alert('Link failed: ' + err.message); }
});
document.getElementById('mon-paste-btn').addEventListener('click', async () => {
  const text = document.getElementById('mon-paste').value;
  if (!text.trim()) return alert('Paste some log lines first.');
  try {
    const res = await fetch(`${MON}/ingest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, source: 'pasted lines' }) });
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || 'import failed');
    document.getElementById('mon-paste').value = '';
    await monAfterImport(d.added || 0);
    alert('Indexed ' + (d.added || 0) + ' new entries.');
  } catch (err) { alert('Import failed: ' + err.message); }
});
// Drop zone: highlight + import, and stop the browser opening dropped files.
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());
const monDrop = document.getElementById('mon-drop');
monDrop.addEventListener('click', (e) => { if (e.target.id !== 'mon-file') document.getElementById('mon-file').click(); });
monDrop.addEventListener('dragenter', (e) => { e.preventDefault(); monDrop.classList.add('drag'); });
monDrop.addEventListener('dragover', (e) => { e.preventDefault(); monDrop.classList.add('drag'); });
monDrop.addEventListener('dragleave', () => monDrop.classList.remove('drag'));
monDrop.addEventListener('drop', async (e) => {
  e.preventDefault(); e.stopPropagation(); monDrop.classList.remove('drag');
  try { const added = await monIngestFiles(e.dataTransfer.files); await monAfterImport(added); alert('Indexed ' + added + ' new entries.'); }
  catch (err) { alert('Import failed: ' + err.message); }
});
document.getElementById('mon-choose-btn').addEventListener('click', (e) => { e.stopPropagation(); document.getElementById('mon-file').click(); });
document.getElementById('mon-file').addEventListener('change', async (e) => {
  try { const added = await monIngestFiles(e.target.files); await monAfterImport(added); alert('Indexed ' + added + ' new entries.'); }
  catch (err) { alert('Import failed: ' + err.message); }
  e.target.value = '';
});

// ---- main render ----

async function renderMain() {
  const container = document.getElementById('main-inner');
  const t = targets.find(x => x.id === activeId);
  if (!t) {
    setTopbar('select a target');
    container.innerHTML = `
      <div id="empty-state">
        <div class="glyph">&gt;_</div>
        <p>Select a target on the left, or add a new one to start recon.</p>
      </div>`;
    return;
  }

  setTopbar('scan ' + t.domain);

  const [subRes, portRes, endpRes, dnsRes, whoisRes, techRes, waybackRes, uroRes, urlPatRes, xssRes, paramsRes, httpxLiveRes, httpxFilterRes, katanaRes, jsRes, jsUrlsRes, jsSecretsRes, jsParamsRes, wafRes, wafFilterRes, cveNvdRes, cveCirclRes, cveMergeRes, authRes, openRedirRes, sqliRes, lfiRes, tlsRes, webMiscRes, nseVulnRes, subTakeoverRes, openaiKeyRes, aiReportRes] = await Promise.all([
    fetch(`${API}/${t.id}/subdomains`).then(r => r.json()),
    fetch(`${API}/${t.id}/portscan`).then(r => r.json()),
    fetch(`${API}/${t.id}/endpoints`).then(r => r.json()),
    fetch(`${API}/${t.id}/dns`).then(r => r.json()),
    fetch(`${API}/${t.id}/whois`).then(r => r.json()),
    fetch(`${API}/${t.id}/techinfo`).then(r => r.json()),
    fetch(`${API}/${t.id}/wayback`).then(r => r.json()),
    fetch(`${API}/${t.id}/uro`).then(r => r.json()),
    fetch(`${API}/${t.id}/urlpatterns`).then(r => r.json()),
    fetch(`${API}/${t.id}/xssprobe`).then(r => r.json()),
    fetch(`${API}/${t.id}/openredirect`).then(r => r.json()),
    fetch(`${API}/${t.id}/sqliprobe`).then(r => r.json()),
    fetch(`${API}/${t.id}/lfiprobe`).then(r => r.json()),
    fetch(`${API}/${t.id}/tlschecks`).then(r => r.json()),
    fetch(`${API}/${t.id}/webmisconfig`).then(r => r.json()),
    fetch(`${API}/${t.id}/nsevuln`).then(r => r.json()),
    fetch(`${API}/${t.id}/subtakeover`).then(r => r.json()),
    fetch(`${API}/${t.id}/all_params`).then(r => r.json()),
    fetch(`${API}/${t.id}/httpx_live`).then(r => r.json()),
    fetch(`${API}/${t.id}/httpx_filter`).then(r => r.json()),
    fetch(`${API}/${t.id}/katana`).then(r => r.json()),
    fetch(`${API}/${t.id}/js_extractor`).then(r => r.json()),
    fetch(`${API}/${t.id}/jsluice_urls`).then(r => r.json()),
    fetch(`${API}/${t.id}/jsluice_secrets`).then(r => r.json()),
    fetch(`${API}/${t.id}/js_params`).then(r => r.json()),
    fetch(`${API}/${t.id}/waf`).then(r => r.json()),
    fetch(`${API}/${t.id}/waf_filter`).then(r => r.json()),
    fetch(`${API}/${t.id}/cve_nvd`).then(r => r.json()),
    fetch(`${API}/${t.id}/cve_circl`).then(r => r.json()),
    fetch(`${API}/${t.id}/cve_merge`).then(r => r.json()),
    fetch(`${API}/${t.id}/auth`).then(r => r.json()),
    fetch('/api/openai-key').then(r => r.json()),
    fetch(`${API}/${t.id}/ai_report`).then(r => r.json()),
  ]);

  const subs = subRes.subdomains || [];
  const ports = portRes.ports || [];
  const endpoints = endpRes.endpoints || [];
  const dnsRecords = dnsRes.records || [];
  const whoisLines = whoisRes.whois || [];
  const techLines = techRes.techinfo || [];
  const waybackUrls = waybackRes.urls || [];
  const uroUrls = uroRes.urls || [];
  const urlPatterns = urlPatRes.matches || [];
  const xssFindings = xssRes.findings || [];
  const openRedirFindings = openRedirRes.findings || [];
  const sqliFindings = sqliRes.findings || [];
  const lfiFindings = lfiRes.findings || [];
  const tlsFindings = tlsRes.findings || [];
  const webMiscFindings = webMiscRes.findings || [];
  const nseVulnFindings = nseVulnRes.findings || [];
  const subTakeoverFindings = subTakeoverRes.findings || [];
  const paramUrls = paramsRes.urls || [];
  const liveHosts = httpxLiveRes.hosts || [];
  const httpxSplit = httpxFilterRes.summary || [];
  const katanaUrls = katanaRes.urls || [];
  const jsFiles = jsRes.js_files || [];
  const jsUrlsFound = jsUrlsRes.urls || [];
  const jsSecretFindings = jsSecretsRes.findings || [];
  const jsParamUrls = jsParamsRes.urls || [];
  const cveNvdLines = cveNvdRes.cves || [];
  const cveCirclLines = cveCirclRes.cves || [];
  const cveMergedLines = cveMergeRes.cves || [];
  const wafRows = wafRes.rows || [];
  const wafStatusText = wafRes.ran
    ? `${wafRes.detected || 0} host(s) behind WAF${(wafRes.wafs_found || []).length ? ': ' + wafRes.wafs_found.join(', ') : ''} · ${wafRes.not_detected || 0} without WAF`
    : null;
  const wafSplitText = wafFilterRes.ran
    ? `${wafFilterRes.with_waf_count || 0} with WAF · ${wafFilterRes.no_waf_count || 0} no WAF`
    : null;

  const reconOpen = uiState.sections.recon;
  const vulnOpen = uiState.sections.vuln;

  const stats = [
    { label: 'Subdomains', value: subs.length },
    { label: 'Live hosts', value: liveHosts.length },
    { label: 'WAF-protected', value: wafRes.detected || 0 },
    { label: 'Crawled URLs', value: katanaUrls.length },
    { label: 'JS files', value: jsFiles.length },
    { label: 'JS URLs', value: jsUrlsFound.length },
    { label: 'JS secrets', value: (jsSecretsRes.counts ? (jsSecretsRes.counts.total || 0) : 0), danger: true },
    { label: 'JS param URLs', value: jsParamUrls.length },
    { label: 'Open ports', value: ports.length },
    { label: 'Endpoints', value: endpoints.length },
    { label: 'DNS records', value: dnsRecords.length },
    { label: 'WHOIS fields', value: whoisLines.length },
    { label: 'Tech fields', value: techLines.length },
    { label: 'Wayback URLs', value: waybackUrls.length },
    { label: 'Clean URLs (uro)', value: uroUrls.length },
    { label: 'Pattern matches', value: urlPatterns.length },
    { label: 'Param URLs', value: paramUrls.length },
    { label: 'XSS findings', value: xssFindings.length, danger: true },
    { label: 'Open redirect findings', value: openRedirFindings.filter(l => l.startsWith('VULNERABLE')).length, danger: true },
    { label: 'SQLi findings', value: sqliFindings.length, danger: true },
    { label: 'LFI findings', value: lfiFindings.length, danger: true },
    { label: 'TLS issues', value: tlsFindings.filter(l => l.includes('INSECURE') || l.includes('ISSUE')).length, danger: true },
    { label: 'Missing headers', value: webMiscRes.missing_headers || 0 },
    { label: 'Dir listings exposed', value: webMiscRes.exposed_directories || 0, danger: true },
    { label: 'Nmap vuln hits', value: nseVulnFindings.length, danger: true },
    { label: 'Subdomain takeovers', value: subTakeoverRes.count || 0, danger: true },
    { label: 'CVEs (merged)', value: cveMergeRes.count || 0, danger: true },
  ];
  const statsBarHTML = `
    <div class="stats-bar">
      ${stats.map(s => `
        <div class="stat-chip${s.danger && s.value > 0 ? ' stat-danger' : ''}">
          <span class="stat-value">${s.value}</span>
          <span class="stat-label">${s.label}</span>
        </div>`).join('')}
    </div>`;

  const discoveryGroup = toolGroupHTML('Discovery', [
    toolCardHTML({
      key: 'subdomains',
      title: 'Subdomain Enumeration (all-in-one)',
      description: 'Merges crt.sh, CertSpotter, HackerTarget and (if installed) subfinder, de-duplicated - each result is tagged with which source(s) found it. Fully passive, no traffic sent to the target.',
      note: `Saved to targets/${t.id}/subdomains.txt`,
      statusText: statusFor(subRes.ran, subs.length, 'subdomains'),
      updatedAt: subRes.updated_at,
      items: subs
    }),
    toolCardHTML({
      key: 'httpxlive',
      title: 'Live Host Probe (httpx)',
      description: 'Industry-standard httpx CLI - probes every subdomain and keeps all live responses: 200, 301/302 redirects AND 401/403 (restricted) and 404 (interesting), annotated with titles and detected tech. Active - sends HTTP requests to the target\u2019s hosts.',
      note: `Saved to targets/${t.id}/live_hosts.txt · requires httpx installed on this machine`,
      statusText: statusFor(httpxLiveRes.ran, liveHosts.length, 'live hosts'),
      updatedAt: httpxLiveRes.updated_at,
      items: liveHosts,
      disabledReason: !subRes.ran ? 'Run "Subdomain Enumeration" first' : null
    }),
    toolCardHTML({
      key: 'httpxfilter',
      title: 'Live Host Filter (403/404 Split)',
      description: 'Splits the httpx results into live_200.txt, live_301/302.txt, live_401.txt, live_403.txt and live_404.txt so each class of live host can be triaged separately. Passive, zero traffic - run the Live Host Probe first.',
      note: `Saved to targets/${t.id}/live_<code>.txt`,
      statusText: statusFor(httpxFilterRes.ran, liveHosts.length, 'hosts split'),
      updatedAt: httpxFilterRes.updated_at,
      items: httpxSplit,
      disabledReason: !httpxLiveRes.ran ? 'Run "Live Host Probe (httpx)" first' : null
    }),
    toolCardHTML({
      key: 'portscan',
      title: 'Port Scan (nmap)',
      description: 'Fast scan of the top 100 TCP ports via nmap. Active - sends real traffic to the target.',
      note: `Saved to targets/${t.id}/ports.txt · requires nmap installed on this machine`,
      statusText: statusFor(portRes.ran, ports.length, 'open ports'),
      updatedAt: portRes.updated_at,
      items: ports
    }),
    toolCardHTML({
      key: 'dns',
      title: 'DNS Records',
      description: 'Looks up A/AAAA/MX/NS/TXT/CNAME/SOA records and tries a zone transfer (AXFR). Mostly passive - the AXFR attempt talks directly to the target\u2019s nameservers.',
      note: `Saved to targets/${t.id}/dns_records.txt`,
      statusText: statusFor(dnsRes.ran, dnsRecords.length, 'records found'),
      updatedAt: dnsRes.updated_at,
      items: dnsRecords
    }),
    toolCardHTML({
      key: 'whois',
      title: 'WHOIS / RDAP Lookup',
      description: 'Registrar, registration/expiry dates, and nameservers via the public RDAP bootstrap service. Fully passive - no traffic sent to the target.',
      note: `Saved to targets/${t.id}/whois.txt`,
      statusText: statusFor(whoisRes.ran, whoisLines.length, 'fields found'),
      updatedAt: whoisRes.updated_at,
      items: whoisLines
    }),
  ].join(''));

  const contentGroup = toolGroupHTML('Content & URL Analysis', [
    toolCardHTML({
      key: 'wafdetect',
      title: 'WAF Detection (wafw00f)',
      description: 'Industry-standard wafw00f CLI - sends crafted requests to each live host and fingerprints the WAF in front of it (Cloudflare, Akamai, AWS WAF, Imperva, generic...). Know your walls before active testing. Active - probes the target\u2019s hosts.',
      note: `Saved to targets/${t.id}/waf_summary.txt (raw JSON: waf_results.json) · requires wafw00f (pip install wafw00f)`,
      statusText: wafStatusText || statusFor(wafRes.ran, wafRows.length, 'hosts checked'),
      updatedAt: wafRes.updated_at,
      items: wafRows,
      disabledReason: !httpxLiveRes.ran ? 'Run "Live Host Probe (httpx)" first' : null
    }),
    toolCardHTML({
      key: 'waffilter',
      title: 'WAF Filter (Split by WAF Presence)',
      description: 'Splits the WAF results into hosts_with_waf.txt (handle with care) and hosts_no_waf.txt (safe-ish for active testing - no firewall shielding them). Passive, zero traffic - run WAF Detection first.',
      note: `Saved to targets/${t.id}/hosts_with_waf.txt + hosts_no_waf.txt`,
      statusText: wafSplitText || statusFor(wafFilterRes.ran, wafRows.length, 'hosts split'),
      updatedAt: wafFilterRes.updated_at,
      items: wafFilterRes.ran ? (wafFilterRes.with_waf_count ? wafFilterRes.with_waf : wafFilterRes.no_waf) : [],
      disabledReason: !wafRes.ran ? 'Run "WAF Detection (wafw00f)" first' : null
    }),
    toolCardHTML({
      key: 'katana',
      title: 'Web Crawler (katana)',
      description: 'Industry-standard katana CLI - crawls every live 200 host at depth 3 and extracts all discovered URLs, forms and JS-embedded endpoints (-jc). Active - sends crawl requests to the target.',
      note: `Saved to targets/${t.id}/katana_urls.txt · requires katana installed on this machine`,
      statusText: statusFor(katanaRes.ran, katanaUrls.length, 'URLs discovered'),
      updatedAt: katanaRes.updated_at,
      items: katanaUrls,
      disabledReason: !httpxLiveRes.ran ? 'Run "Live Host Probe (httpx)" first' : null
    }),
    toolCardHTML({
      key: 'jsextract',
      title: 'JS File Extractor',
      description: 'Pulls the pure .js file URLs (including .js?query=) out of the katana results - JS files can hide API routes, parameter names and dead-code panels. Passive, zero traffic - run the Katana Crawler first.',
      note: `Saved to targets/${t.id}/js_files.txt`,
      statusText: statusFor(jsRes.ran, jsFiles.length, 'JS files found'),
      updatedAt: jsRes.updated_at,
      items: jsFiles,
      disabledReason: !katanaRes.ran ? 'Run "Web Crawler (katana)" first' : null
    }),
    toolCardHTML({
      key: 'jsurls',
      title: 'jsluice URLs (JS Endpoints & Parameters)',
      description: 'Industry-standard jsluice (Bishop Fox) - parses JS with tree-sitter and pulls URLs actually used in code: fetch() calls, redirects, API paths, query parameters. -I ignores bare string literals to cut noise. Fetches each JS file - active-ish.',
      note: `Saved to targets/${t.id}/jsluice_urls.txt (raw JSON: jsluice_urls.json) · requires jsluice on PATH`,
      statusText: statusFor(jsUrlsRes.ran, jsUrlsFound.length, 'URLs extracted'),
      updatedAt: jsUrlsRes.updated_at,
      items: jsUrlsFound,
      disabledReason: !jsRes.ran ? 'Run "JS File Extractor" first' : null
    }),
    toolCardHTML({
      key: 'jsparams',
      title: 'JS Parameter Collector (all_params)',
      description: 'Aggregates every parameterized URL from jsluice results, katana output and the previously collected list into one deduplicated worklist (all_params.txt) for the active-testing phase. Passive, zero traffic.',
      note: `Saved to targets/${t.id}/all_params.txt`,
      statusText: statusFor(jsParamsRes.ran, jsParamUrls.length, 'parameterized URLs'),
      updatedAt: jsParamsRes.updated_at,
      items: jsParamUrls,
      disabledReason: !jsUrlsRes.ran && !katanaRes.ran ? 'Run "jsluice URLs" or "Web Crawler (katana)" first' : null
    }),
    toolCardHTML({
      key: 'endpoints',
      title: 'Directory / Endpoint Discovery',
      description: 'Checks a built-in path list PLUS real historical paths pulled from the Wayback Machine results (run that tool first for better coverage). Active - sends requests to the target.',
      note: `Saved to targets/${t.id}/endpoints.txt`,
      statusText: statusFor(endpRes.ran, endpoints.length, 'endpoints found'),
      updatedAt: endpRes.updated_at,
      items: endpoints
    }),
    toolCardHTML({
      key: 'wayback',
      title: 'Wayback Machine URLs',
      description: 'Pulls historical URLs for this domain from archive.org - often surfaces old endpoints no longer linked anywhere. Fully passive.',
      note: `Saved to targets/${t.id}/wayback.txt`,
      statusText: statusFor(waybackRes.ran, waybackUrls.length, 'URLs found'),
      updatedAt: waybackRes.updated_at,
      items: waybackUrls
    }),
    toolCardHTML({
      key: 'uro',
      title: 'URL Cleaner (uro)',
      description: 'Drops boring static-asset URLs and collapses near-duplicate URLs (same pattern, different ID/param value) from the Wayback list, then runs the industry-standard urldedupe CLI as an optional second pass if it is installed. Passive, zero traffic - run Wayback Machine first.',
      note: `Saved to targets/${t.id}/uro_urls.txt · optional second pass if urldedupe is installed`,
      statusText: statusFor(uroRes.ran, uroUrls.length, 'URLs kept'),
      updatedAt: uroRes.updated_at,
      items: uroUrls,
      disabledReason: !waybackRes.ran ? 'Run "Wayback Machine URLs" first' : null
    }),
    toolCardHTML({
      key: 'allparams',
      title: 'Parameter Collector',
      description: 'Consolidates every parameterized URL (?id=1, ?page=2, ...) found across Subdomain Enumeration results and the cleaned URL lists into one worklist (all_params.txt) for the active-testing phase. Passive, zero traffic.',
      note: `Saved to targets/${t.id}/all_params.txt`,
      statusText: statusFor(paramsRes.ran, paramUrls.length, 'parameterized URLs'),
      updatedAt: paramsRes.updated_at,
      items: paramUrls,
      disabledReason: !subRes.ran && !waybackRes.ran ? 'Run "Subdomain Enumeration" or "Wayback Machine URLs" first' : null
    }),
  ].join(''));

  const fingerprintGroup = toolGroupHTML('Fingerprinting', [
    toolCardHTML({
      key: 'techinfo',
      title: 'Tech Fingerprint + TLS',
      description: 'Reads server headers, a generator meta tag if present, and the TLS certificate (issuer, expiry, SANs). Active - one lightweight request + TLS handshake.',
      note: `Saved to targets/${t.id}/techinfo.txt`,
      statusText: statusFor(techRes.ran, techLines.length, 'fields found'),
      updatedAt: techRes.updated_at,
      items: techLines
    }),
  ].join(''));

  const needVersions = !techRes.ran && !httpxLiveRes.ran
    ? 'Run "Tech Fingerprint" or "Live Host Probe" first' : null;

  const vulnCveGroup = toolGroupHTML('CVE Lookup', [
    toolCardHTML({
      key: 'cvenvd',
      title: 'CVE Lookup (NVD)',
      description: 'Takes the product + version pairs found by Tech Fingerprint / Live Host Probe (e.g. nginx 1.18.0) and asks NIST NVD which CVEs affect that exact version. Passive - nothing is sent to the target. Slow on purpose (NVD limits free use to ~5 requests / 30s). Needs a visible version number: CDN-hidden servers give nothing.',
      note: `Saved to targets/${t.id}/cve_nvd.txt (records: cve_nvd.json)`,
      statusText: statusFor(cveNvdRes.ran, cveNvdRes.count || 0, 'CVE(s) found'),
      updatedAt: cveNvdRes.updated_at,
      items: cveNvdLines,
      disabledReason: needVersions
    }),
    toolCardHTML({
      key: 'cvecircl',
      title: 'CVE Lookup (CIRCL)',
      description: 'Second, independent source: CIRCL Vulnerability-Lookup. Downloads the CVEs of each detected product and keeps only those whose affected-version ranges include the version found on the target. Passive. Run it next to NVD, then use CVE Merge.',
      note: `Saved to targets/${t.id}/cve_circl.txt (records: cve_circl.json)`,
      statusText: statusFor(cveCirclRes.ran, cveCirclRes.count || 0, 'CVE(s) found'),
      updatedAt: cveCirclRes.updated_at,
      items: cveCirclLines,
      disabledReason: needVersions
    }),
    toolCardHTML({
      key: 'cvemerge',
      title: 'CVE Merge (dedupe)',
      description: 'Combines the NVD and CIRCL results into one list: the same CVE found by both sources becomes a single line (sources and affected products are combined, the highest CVSS score is kept), sorted by severity. No network calls.',
      note: `Saved to targets/${t.id}/cve_merged.txt (records: cve_merged.json)`,
      statusText: statusFor(cveMergeRes.ran, cveMergeRes.count || 0, 'unique CVE(s)'),
      updatedAt: cveMergeRes.updated_at,
      items: cveMergedLines,
      disabledReason: (!cveNvdRes.ran && !cveCirclRes.ran) ? 'Run a CVE lookup (NVD or CIRCL) first' : null
    }),
  ].join(''));

  const vulnTriageGroup = toolGroupHTML('Triage & Secrets', [
    toolCardHTML({
      key: 'urlpatterns',
      title: 'URL Pattern Filter',
      description: 'Sorts URLs into categories (xss, sqli, ssrf, lfi, rce, idor, redirect, debug_logic, interesting_ext) by param name / extension. Uses the uro-cleaned list if available. Passive, zero traffic - run Wayback Machine first.',
      note: `Saved to targets/${t.id}/url_patterns.txt`,
      statusText: statusFor(urlPatRes.ran, urlPatterns.length, 'matches found'),
      updatedAt: urlPatRes.updated_at,
      items: urlPatterns,
      disabledReason: !waybackRes.ran ? 'Run "Wayback Machine URLs" first' : null
    }),
    toolCardHTML({
      key: 'jssecrets',
      title: 'jsluice Secrets (Keys, Tokens, Credentials)',
      description: 'jsluice secrets mode - built-in extractors flag leaked AWS/GCP keys, GitHub tokens, Firebase configs and more inside the JS files. HIGH-priority surface: confirm manually before reporting.',
      note: `Saved to targets/${t.id}/jsluice_secrets_summary.txt (raw JSON: jsluice_secrets.json)`,
      statusText: statusFor(jsSecretsRes.ran, (jsSecretsRes.counts ? (jsSecretsRes.counts.total || 0) : 0), 'secret finding(s)'),
      updatedAt: jsSecretsRes.updated_at,
      items: jsSecretFindings,
      disabledReason: !jsRes.ran ? 'Run "JS File Extractor" first' : null
    }),
  ].join(''));

  const vulnActiveGroup = toolGroupHTML('Active Testing', [
    toolCardHTML({
      key: 'xssprobe',
      title: 'XSS Reflection Prober (dalfox-inspired)',
      description: 'Injects a marker into each param of the "xss"-tagged URLs and checks if it reflects unescaped - a signal, not proof, of reflected XSS. Active - run URL Pattern Filter first.',
      note: `Saved to targets/${t.id}/xss_probe.txt`,
      statusText: statusFor(xssRes.ran, xssFindings.length, 'findings'),
      updatedAt: xssRes.updated_at,
      items: xssFindings,
      disabledReason: !urlPatRes.ran ? 'Run "URL Pattern Filter" first' : null
    }),
    toolCardHTML({
      key: 'openredirect',
      title: 'Open Redirect Prober',
      description: 'Replaces each param of the "redirect"-tagged URLs with an external marker domain and checks (without following) whether the Location header sends browsers straight there - a signal of an unvalidated redirect destination. Active - run URL Pattern Filter first.',
      note: `Saved to targets/${t.id}/open_redirect_probe.txt`,
      statusText: statusFor(openRedirRes.ran, openRedirFindings.length, 'findings'),
      updatedAt: openRedirRes.updated_at,
      items: openRedirFindings,
      disabledReason: !urlPatRes.ran ? 'Run "URL Pattern Filter" first' : null
    }),
    toolCardHTML({
      key: 'sqliprobe',
      title: 'SQL Injection Error-Based Prober',
      description: 'Appends syntax-breaking payloads to each param of the "sqli"-tagged URLs and checks the response for known MySQL/PostgreSQL/MSSQL/Oracle/SQLite error signatures - a signal, not proof, of SQL injection. Active - run URL Pattern Filter first.',
      note: `Saved to targets/${t.id}/sqli_probe.txt`,
      statusText: statusFor(sqliRes.ran, sqliFindings.length, 'findings'),
      updatedAt: sqliRes.updated_at,
      items: sqliFindings,
      disabledReason: !urlPatRes.ran ? 'Run "URL Pattern Filter" first' : null
    }),
    toolCardHTML({
      key: 'lfiprobe',
      title: 'LFI / Path Traversal Prober',
      description: 'Tries path-traversal payloads (/etc/passwd, win.ini) on each param of the "lfi"-tagged URLs and checks the response for that file\'s own content - a strong signal of local file inclusion. Active - run URL Pattern Filter first.',
      note: `Saved to targets/${t.id}/lfi_probe.txt`,
      statusText: statusFor(lfiRes.ran, lfiFindings.length, 'findings'),
      updatedAt: lfiRes.updated_at,
      items: lfiFindings,
      disabledReason: !urlPatRes.ran ? 'Run "URL Pattern Filter" first' : null
    }),
  ].join(''));

  const vulnInfraGroup = toolGroupHTML('Infrastructure & Config', [
    toolCardHTML({
      key: 'tlschecks',
      title: 'TLS / SSL Deep Checks',
      description: 'Forces a handshake on each TLS/SSL protocol version to find which deprecated ones (SSLv3, TLS1.0, TLS1.1) the server still accepts, and separately checks for a self-signed cert, hostname mismatch, expired cert or broken chain. Active - a few TLS handshakes, no HTTP request.',
      note: `Saved to targets/${t.id}/tls_checks.txt`,
      statusText: statusFor(tlsRes.ran, tlsFindings.length, 'checks'),
      updatedAt: tlsRes.updated_at,
      items: tlsFindings
    }),
    toolCardHTML({
      key: 'webmisconfig',
      title: 'Web Misconfiguration Checker',
      description: 'Checks for missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) and probes a handful of common directories for an exposed directory listing. Active - a handful of HTTP requests.',
      note: `Saved to targets/${t.id}/web_misconfig.txt`,
      statusText: statusFor(webMiscRes.ran, webMiscFindings.length, 'checks'),
      updatedAt: webMiscRes.updated_at,
      items: webMiscFindings
    }),
    toolCardHTML({
      key: 'nsevuln',
      title: 'Nmap Vuln Scripts (nmap --script vuln)',
      description: 'Re-scans just the open ports Port Scan found with nmap\'s "vuln" NSE script category - checks for known CVEs and misconfigurations specific to whatever service is listening. Active, more intensive than the plain port scan - requires nmap and run Port Scan first.',
      note: `Saved to targets/${t.id}/nse_vuln.txt · requires nmap installed on this machine`,
      statusText: statusFor(nseVulnRes.ran, nseVulnFindings.length, 'findings'),
      updatedAt: nseVulnRes.updated_at,
      items: nseVulnFindings,
      disabledReason: !ports.length ? 'Run "Port Scan" first' : null
    }),
    toolCardHTML({
      key: 'subtakeover',
      title: 'Subdomain Takeover Checker',
      description: 'Resolves each subdomain\'s CNAME and, if it points at a known cloud service (S3, GitHub Pages, Heroku, Netlify...), checks the service\'s own "not claimed" fingerprint text - flags subdomains an attacker could potentially take over. Mostly passive DNS + one request per match - run Subdomain Enumeration first.',
      note: `Saved to targets/${t.id}/subdomain_takeover.txt`,
      statusText: statusFor(subTakeoverRes.ran, subTakeoverFindings.length, 'checked'),
      updatedAt: subTakeoverRes.updated_at,
      items: subTakeoverFindings,
      disabledReason: !subRes.ran ? 'Run "Subdomain Enumeration" first' : null
    }),
  ].join(''));

  const pipelineStages = [
    { key: 'subdomains', label: 'SUBDOMAINS', value: subs.length, ran: !!subRes.ran },
    { key: 'httpxlive', label: 'LIVE HOSTS', value: liveHosts.length, ran: !!httpxLiveRes.ran },
    { key: 'katana', label: 'CRAWL', value: katanaUrls.length, ran: !!katanaRes.ran },
    { key: 'cvemerge', label: 'CVE', value: cveMergeRes.count || 0, ran: !!cveMergeRes.ran, danger: true },
    { key: 'xssprobe', label: 'XSS', value: xssFindings.length, ran: !!xssRes.ran, danger: true },
  ].map(st => ({ ...st, done: st.ran || st.value > 0 }));
  const pipelineHTML = `
    <div class="pipeline">
      ${pipelineStages.map((st, i) => `${i ? `<div class="pl-line ${pipelineStages[i - 1].done ? 'go' : ''}"></div>` : ''}
        <div class="pl-node ${st.done ? 'done' : ''} ${st.danger && st.value > 0 ? 'bad' : ''}" data-key="${st.key}">
          <b>${st.label}</b><span>${st.done ? st.value : 'pending'}</span><i></i>
        </div>`).join('')}
    </div>
  `;

  const hasAuth = !!authRes.has_auth;
  const authOpen = uiState.sections.auth;
  const authPanelHTML = `
    <div class="auth-panel">
      <div class="auth-row">
        <span class="auth-label">Login session</span>
        <span class="auth-status ${hasAuth ? 'on' : ''}">${hasAuth
          ? 'Active - sent only to ' + escapeHtml(t.domain) + ' and its subdomains'
          : 'None - scanning as an anonymous visitor'}</span>
        <button id="auth-toggle-btn" class="ghost-btn">${hasAuth ? 'Change' : 'Add'}</button>
        ${hasAuth ? '<button id="auth-clear-btn" class="ghost-btn">Remove</button>' : ''}
      </div>
      ${hasAuth ? `<div class="auth-masked">${(authRes.headers || []).map(h => escapeHtml(h)).join('<br>')}</div>` : ''}
      <div class="auth-form" id="auth-form" style="${authOpen ? '' : 'display:none;'}">
        <textarea id="auth-input" rows="3" spellcheck="false" autocomplete="off"
          placeholder="Cookie: sessionid=abc123; csrftoken=xyz&#10;Authorization: Bearer eyJ..."></textarea>
        <div class="auth-hint">One header per line (or paste just the cookie string). Use a TEST account you are
          allowed to use, never a real user's session. Saved only on this machine (git-ignored) and sent only
          to this target's domain by Live Host Probe, Katana, Tech Fingerprint, Endpoint Discovery and the XSS Prober.
          Saving replaces the current value.</div>
        <div class="auth-actions">
          <button id="auth-save-btn" class="ghost-btn">Save</button>
          <span id="auth-msg" class="auth-msg"></span>
        </div>
      </div>
    </div>
  `;

  const hasOpenaiKey = !!openaiKeyRes.has_key;
  const aiKeyOpen = uiState.sections.aiKey;
  const aiReport = aiReportRes.report || '';
  const aiPanelHTML = `
    <div class="auth-panel">
      <div class="auth-row">
        <span class="auth-label">AI Analysis (OpenAI)</span>
        <span class="auth-status ${hasOpenaiKey ? 'on' : ''}">${hasOpenaiKey
          ? 'Key saved: ' + escapeHtml(openaiKeyRes.masked || '')
          : 'No API key saved yet'}</span>
        <button id="ai-key-toggle-btn" class="ghost-btn">${hasOpenaiKey ? 'Change key' : 'Add key'}</button>
        ${hasOpenaiKey ? '<button id="ai-key-clear-btn" class="ghost-btn">Remove</button>' : ''}
      </div>
      <div class="auth-form" id="ai-key-form" style="${aiKeyOpen ? '' : 'display:none;'}">
        <textarea id="ai-key-input" rows="1" spellcheck="false" autocomplete="off"
          placeholder="sk-..."></textarea>
        <div class="auth-hint">Your own OpenAI API key, used only to run the AI Analysis below. Saved locally on
          this machine (git-ignored) - never committed, never sent anywhere except api.openai.com. Each person
          running this framework adds their own key once.</div>
        <div class="auth-actions">
          <button id="ai-key-save-btn" class="ghost-btn">Save</button>
          <span id="ai-key-msg" class="auth-msg"></span>
        </div>
      </div>
      <div class="auth-row" style="margin-top:${hasOpenaiKey ? '10px' : '0'}">
        ${hasOpenaiKey ? `<button id="ai-report-btn" class="ghost-btn">${aiReport ? 'Re-run AI Analysis' : 'Run AI Analysis'}</button>
        <span id="ai-report-status" class="auth-msg"></span>` : ''}
      </div>
      ${aiReport ? `<div class="ai-report">${renderMarkdownLite(aiReport)}</div>` : ''}
    </div>
  `;

  container.innerHTML = `
    <div class="target-header">
      <div class="target-header-top">
        <div>
          <div class="t-label">TARGET</div>
          <h2>${t.name}</h2>
          <div class="t-url">${t.domain}</div>
        </div>
        <button id="export-report-btn" class="ghost-btn export-report-btn">Export Report</button>
      </div>
    </div>

    ${authPanelHTML}
    ${aiPanelHTML}

    ${pipelineHTML}

    ${statsBarHTML}

    <div class="section">
      <div class="section-header" id="section-recon">
        <span class="chevron ${reconOpen ? 'open' : ''}">&#9656;</span>
        <span class="section-title">Recon</span>
        <span class="section-sub">information gathering</span>
        <button id="run-all-btn" class="ghost-btn run-all-btn">Run All</button>
      </div>
      <div id="run-all-status" class="run-all-status"></div>
      <div class="section-body" id="section-recon-body" style="${reconOpen ? '' : 'display:none;'}">
        ${discoveryGroup}
        ${contentGroup}
        ${fingerprintGroup}
      </div>
    </div>

    <div class="section">
      <div class="section-header" id="section-vuln">
        <span class="chevron ${vulnOpen ? 'open' : ''}">&#9656;</span>
        <span class="section-title">Vulnerability Scan</span>
        <span class="section-sub">finding weaknesses</span>
        <button id="run-all-vuln-btn" class="ghost-btn run-all-btn">Run All</button>
      </div>
      <div id="run-all-vuln-status" class="run-all-status"></div>
      <div class="section-body" id="section-vuln-body" style="${vulnOpen ? '' : 'display:none;'}">
        ${vulnCveGroup}
        ${vulnTriageGroup}
        ${vulnActiveGroup}
        ${vulnInfraGroup}
      </div>
    </div>
  `;

  markRunning();

  document.getElementById('section-recon').addEventListener('click', (e) => {
    if (e.target.id === 'run-all-btn') return;
    uiState.sections.recon = !uiState.sections.recon;
    toggleBlock('section-recon-body', uiState.sections.recon);
    toggleChevron('section-recon', uiState.sections.recon);
  });

  document.getElementById('run-all-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    runAll(t);
  });

  document.getElementById('section-vuln').addEventListener('click', (e) => {
    if (e.target.id === 'run-all-vuln-btn') return;
    uiState.sections.vuln = !uiState.sections.vuln;
    toggleBlock('section-vuln-body', uiState.sections.vuln);
    toggleChevron('section-vuln', uiState.sections.vuln);
  });

  document.getElementById('run-all-vuln-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    runAll(t, VULN_RUN_ALL_ORDER, 'run-all-vuln-btn', 'run-all-vuln-status', 'vuln');
  });

  document.getElementById('auth-toggle-btn').addEventListener('click', () => {
    uiState.sections.auth = !uiState.sections.auth;
    document.getElementById('auth-form').style.display = uiState.sections.auth ? '' : 'none';
  });

  document.getElementById('auth-save-btn').addEventListener('click', async () => {
    const msg = document.getElementById('auth-msg');
    const text = document.getElementById('auth-input').value;
    if (!text.trim()) { msg.textContent = 'Paste a cookie or header first.'; return; }
    try {
      const res = await fetch(`${API}/${t.id}/auth`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headers: text }),
      });
      const data = await res.json();
      if (!res.ok) { msg.textContent = data.error || 'Could not save.'; return; }
      uiState.sections.auth = false;
      renderMain();
    } catch (err) {
      msg.textContent = 'Could not reach the backend.';
    }
  });

  const authClear = document.getElementById('auth-clear-btn');
  if (authClear) {
    authClear.addEventListener('click', async () => {
      await fetch(`${API}/${t.id}/auth`, { method: 'DELETE' });
      renderMain();
    });
  }

  document.getElementById('ai-key-toggle-btn').addEventListener('click', () => {
    uiState.sections.aiKey = !uiState.sections.aiKey;
    document.getElementById('ai-key-form').style.display = uiState.sections.aiKey ? '' : 'none';
  });

  document.getElementById('ai-key-save-btn').addEventListener('click', async () => {
    const msg = document.getElementById('ai-key-msg');
    const key = document.getElementById('ai-key-input').value;
    if (!key.trim()) { msg.textContent = 'Paste your OpenAI API key first.'; return; }
    try {
      const res = await fetch('/api/openai-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      });
      const data = await res.json();
      if (!res.ok) { msg.textContent = data.error || 'Could not save.'; return; }
      uiState.sections.aiKey = false;
      renderMain();
    } catch (err) {
      msg.textContent = 'Could not reach the backend.';
    }
  });

  const aiKeyClear = document.getElementById('ai-key-clear-btn');
  if (aiKeyClear) {
    aiKeyClear.addEventListener('click', async () => {
      await fetch('/api/openai-key', { method: 'DELETE' });
      renderMain();
    });
  }

  const aiReportBtn = document.getElementById('ai-report-btn');
  if (aiReportBtn) {
    aiReportBtn.addEventListener('click', async () => {
      const status = document.getElementById('ai-report-status');
      aiReportBtn.disabled = true;
      status.textContent = 'Analyzing... (this can take up to a minute)';
      try {
        const res = await fetch(`${API}/${t.id}/ai_report`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) { status.textContent = data.error || 'Analysis failed.'; aiReportBtn.disabled = false; return; }
        renderMain();
      } catch (err) {
        status.textContent = 'Could not reach the backend.';
        aiReportBtn.disabled = false;
      }
    });
  }

  document.getElementById('export-report-btn').addEventListener('click', () => {
    downloadReport(t, {
      subs, liveHosts, httpxSplit, wafRows,
      wafWith: wafFilterRes.with_waf || [], wafWithout: wafFilterRes.no_waf || [],
      katanaUrls, jsFiles,
      jsUrlsFound, jsSecretFindings, jsParamUrls,
      ports, dnsRecords, whoisLines, endpoints,
      waybackUrls, uroUrls, urlPatterns, paramUrls,
      techLines, xssFindings, openRedirFindings, sqliFindings, lfiFindings,
      tlsFindings, webMiscFindings, nseVulnFindings, subTakeoverFindings,
      cveNvdLines, cveCirclLines, cveMergedLines
    });
  });

  wireToolCard('subdomains', subs, () => runTool({ key: 'subdomains', endpoint: 'subdomains', t }));
  wireToolCard('httpxlive', liveHosts, () => runTool({ key: 'httpxlive', endpoint: 'httpx_live', t }));
  wireToolCard('httpxfilter', httpxSplit, () => runTool({ key: 'httpxfilter', endpoint: 'httpx_filter', t }));
  wireToolCard('wafdetect', wafRows, () => runTool({ key: 'wafdetect', endpoint: 'waf', t }));
  wireToolCard('waffilter', wafFilterRes.ran ? (wafFilterRes.with_waf_count ? wafFilterRes.with_waf : wafFilterRes.no_waf) : [], () => runTool({ key: 'waffilter', endpoint: 'waf_filter', t }));
  wireToolCard('katana', katanaUrls, () => runTool({ key: 'katana', endpoint: 'katana', t }));
  wireToolCard('jsextract', jsFiles, () => runTool({ key: 'jsextract', endpoint: 'js_extractor', t }));
  wireToolCard('jsurls', jsUrlsFound, () => runTool({ key: 'jsurls', endpoint: 'jsluice_urls', t }));
  wireToolCard('jssecrets', jsSecretFindings, () => runTool({ key: 'jssecrets', endpoint: 'jsluice_secrets', t }));
  wireToolCard('jsparams', jsParamUrls, () => runTool({ key: 'jsparams', endpoint: 'js_params', t }));
  wireToolCard('portscan', ports, () => runTool({ key: 'portscan', endpoint: 'portscan', t }));
  wireToolCard('endpoints', endpoints, () => runTool({ key: 'endpoints', endpoint: 'endpoints', t }));
  wireToolCard('dns', dnsRecords, () => runTool({ key: 'dns', endpoint: 'dns', t }));
  wireToolCard('whois', whoisLines, () => runTool({ key: 'whois', endpoint: 'whois', t }));
  wireToolCard('techinfo', techLines, () => runTool({ key: 'techinfo', endpoint: 'techinfo', t }));
  wireToolCard('wayback', waybackUrls, () => runTool({ key: 'wayback', endpoint: 'wayback', t }));
  wireToolCard('uro', uroUrls, () => runTool({ key: 'uro', endpoint: 'uro', t }));
  wireToolCard('urlpatterns', urlPatterns, () => runTool({ key: 'urlpatterns', endpoint: 'urlpatterns', t }));
  wireToolCard('allparams', paramUrls, () => runTool({ key: 'allparams', endpoint: 'all_params', t }));
  wireToolCard('xssprobe', xssFindings, () => runTool({ key: 'xssprobe', endpoint: 'xssprobe', t }));
  wireToolCard('openredirect', openRedirFindings, () => runTool({ key: 'openredirect', endpoint: 'openredirect', t }));
  wireToolCard('sqliprobe', sqliFindings, () => runTool({ key: 'sqliprobe', endpoint: 'sqliprobe', t }));
  wireToolCard('lfiprobe', lfiFindings, () => runTool({ key: 'lfiprobe', endpoint: 'lfiprobe', t }));
  wireToolCard('tlschecks', tlsFindings, () => runTool({ key: 'tlschecks', endpoint: 'tlschecks', t }));
  wireToolCard('webmisconfig', webMiscFindings, () => runTool({ key: 'webmisconfig', endpoint: 'webmisconfig', t }));
  wireToolCard('nsevuln', nseVulnFindings, () => runTool({ key: 'nsevuln', endpoint: 'nsevuln', t }));
  wireToolCard('subtakeover', subTakeoverFindings, () => runTool({ key: 'subtakeover', endpoint: 'subtakeover', t }));
  wireToolCard('cvenvd', cveNvdLines, () => runTool({ key: 'cvenvd', endpoint: 'cve_nvd', t }));
  wireToolCard('cvecircl', cveCirclLines, () => runTool({ key: 'cvecircl', endpoint: 'cve_circl', t }));
  wireToolCard('cvemerge', cveMergedLines, () => runTool({ key: 'cvemerge', endpoint: 'cve_merge', t }));

}

// Modal
const overlay = document.getElementById('modal-overlay');
const nameInput = document.getElementById('input-name');
const urlInput = document.getElementById('input-url');
const errorEl = document.getElementById('modal-error');

document.getElementById('add-target-btn').addEventListener('click', () => {
  nameInput.value = '';
  urlInput.value = '';
  errorEl.style.display = 'none';
  overlay.classList.add('show');
  nameInput.focus();
});
document.getElementById('modal-cancel').addEventListener('click', () => overlay.classList.remove('show'));
overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.classList.remove('show'); });

document.getElementById('modal-save').addEventListener('click', async () => {
  const name = nameInput.value.trim();
  const domain = urlInput.value.trim();
  if (!name || !domain) {
    errorEl.textContent = 'Please enter a valid name and domain.';
    errorEl.style.display = 'block';
    return;
  }
  const res = await fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, domain })
  });
  const data = await res.json();
  if (!res.ok) {
    errorEl.textContent = data.error || 'Something went wrong';
    errorEl.style.display = 'block';
    return;
  }
  await fetchTargets();
  activeId = data.id;
  resetUiState();
  overlay.classList.remove('show');
  renderSidebar();
  renderMain();
});

// Landing page navigation
let frameworkInitialized = false;

async function showFramework() {
  document.getElementById('landing-page').style.display = 'none';
  document.getElementById('monitoring-page').style.display = 'none';
  document.getElementById('app-shell').style.display = 'flex';
  if (!frameworkInitialized) {
    frameworkInitialized = true;
    await fetchTargets();
    renderSidebar();
    renderMain();
  }
}

async function showMonitoring() {
  document.getElementById('landing-page').style.display = 'none';
  document.getElementById('app-shell').style.display = 'none';
  document.getElementById('monitoring-page').style.display = 'block';
  document.getElementById('monitoring-page').scrollTop = 0;
  await monRefresh();
  monRenderEmpty('Search for something to see results — nothing is listed until you search.');
}

function showLanding() {
  document.getElementById('app-shell').style.display = 'none';
  document.getElementById('monitoring-page').style.display = 'none';
  document.getElementById('landing-page').style.display = 'flex';
}

document.getElementById('landing-framework-btn').addEventListener('click', showFramework);
document.getElementById('landing-monitoring-btn').addEventListener('click', showMonitoring);
document.getElementById('back-to-landing-from-app').addEventListener('click', showLanding);
document.getElementById('back-to-landing-from-monitoring').addEventListener('click', showLanding);


// ---------- Theme toggle - persisted in localStorage (per-browser, this is a local
// tool running on your own machine, not a hosted Claude artifact).
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = theme === 'light' ? '\u263D Dark' : '\u2600 Light';
}

(function initTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  applyTheme(saved);
})();

document.getElementById('theme-toggle-btn').addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem('theme', next);
  applyTheme(next);
});

document.getElementById('act-clear-btn').addEventListener('click', () => {
  document.getElementById('activity-list').innerHTML =
    '<div class="act-empty">Nothing running yet. Run a tool to see its output here.</div>';
});
