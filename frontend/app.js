const API = '/api/targets';

let targets = [];
let activeId = null;

// UI collapse/expand state - kept in memory so it survives re-renders
// (e.g. after running a tool) instead of resetting every time.
let uiState = {
  sections: { recon: false },
  tools: {
    subdomains: false, portscan: false, endpoints: false,
    dns: false, whois: false, techinfo: false, wayback: false, uro: false,
    urlpatterns: false, xssprobe: false
  }
};

function resetUiState() {
  uiState = {
    sections: { recon: false },
    tools: {
      subdomains: false, portscan: false, endpoints: false,
      dns: false, whois: false, techinfo: false, wayback: false, uro: false,
      urlpatterns: false, xssprobe: false
    }
  };
}

// Dependency-safe order for "Run All" - independent tools first, then the
// Wayback -> uro -> URL Pattern Filter -> XSS Prober chain, in order.
const RUN_ALL_ORDER = [
  { key: 'subdomains', endpoint: 'subdomains' },
  { key: 'portscan', endpoint: 'portscan' },
  { key: 'dns', endpoint: 'dns' },
  { key: 'whois', endpoint: 'whois' },
  { key: 'techinfo', endpoint: 'techinfo' },
  { key: 'wayback', endpoint: 'wayback' },
  { key: 'uro', endpoint: 'uro' },
  { key: 'endpoints', endpoint: 'endpoints' },
  { key: 'urlpatterns', endpoint: 'urlpatterns' },
  { key: 'xssprobe', endpoint: 'xssprobe' },
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
    el.innerHTML = `${badge}<span class="t-name">${t.name}</span><span class="t-remove" data-id="${t.id}">✕</span>`;
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
  statusEl.className = 'tool-status';
  statusEl.textContent = 'Running... this can take a little while.';

  try {
    const res = await fetch(`${API}/${t.id}/${endpoint}`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Unknown error');

    uiState.sections.recon = true;
    uiState.tools[key] = true;
    renderMain();
  } catch (err) {
    statusEl.className = 'tool-status err';
    statusEl.textContent = 'Error: ' + err.message;
    btn.disabled = false;
  }
}

async function runAll(t) {
  const btn = document.getElementById('run-all-btn');
  const statusEl = document.getElementById('run-all-status');
  if (!btn || !statusEl) return;
  btn.disabled = true;
  const failures = [];

  for (let i = 0; i < RUN_ALL_ORDER.length; i++) {
    const step = RUN_ALL_ORDER[i];
    statusEl.textContent = `Running ${step.key}... (${i + 1}/${RUN_ALL_ORDER.length})`;
    try {
      const res = await fetch(`${API}/${t.id}/${step.endpoint}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) failures.push(`${step.key}: ${data.error || 'error'}`);
    } catch (err) {
      failures.push(`${step.key}: ${err.message}`);
    }
  }

  statusEl.textContent = failures.length
    ? `Done, with ${failures.length} issue(s) - ${failures.join(' | ')}`
    : 'All tools finished.';
  btn.disabled = false;
  uiState.sections.recon = true;
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
  md += reportSection('Port Scan (nmap)', data.ports);
  md += reportSection('DNS Records', data.dnsRecords);
  md += reportSection('WHOIS / RDAP Lookup', data.whoisLines);
  md += reportSection('Directory / Endpoint Discovery', data.endpoints);
  md += reportSection('Wayback Machine URLs', data.waybackUrls);
  md += reportSection('URL Cleaner (uro)', data.uroUrls);
  md += reportSection('URL Pattern Filter (gf-patterns)', data.urlPatterns);
  md += reportSection('Tech Fingerprint + TLS', data.techLines);
  md += reportSection('XSS Reflection Prober (dalfox-inspired)', data.xssFindings);
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

// ---- main render ----

async function renderMain() {
  const container = document.getElementById('main-inner');
  const t = targets.find(x => x.id === activeId);
  if (!t) {
    container.innerHTML = `
      <div id="empty-state">
        <div class="glyph">&gt;_</div>
        <p>Select a target on the left, or add a new one to start recon.</p>
      </div>`;
    return;
  }

  const [subRes, portRes, endpRes, dnsRes, whoisRes, techRes, waybackRes, uroRes, urlPatRes, xssRes] = await Promise.all([
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

  const reconOpen = uiState.sections.recon;

  const stats = [
    { label: 'Subdomains', value: subs.length },
    { label: 'Open ports', value: ports.length },
    { label: 'Endpoints', value: endpoints.length },
    { label: 'DNS records', value: dnsRecords.length },
    { label: 'WHOIS fields', value: whoisLines.length },
    { label: 'Tech fields', value: techLines.length },
    { label: 'Wayback URLs', value: waybackUrls.length },
    { label: 'Clean URLs (uro)', value: uroUrls.length },
    { label: 'Pattern matches', value: urlPatterns.length },
    { label: 'XSS findings', value: xssFindings.length, danger: true },
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
      description: 'Merges crt.sh, CertSpotter and HackerTarget, de-duplicated - each result is tagged with which source(s) found it. Fully passive, no traffic sent to the target.',
      note: `Saved to targets/${t.id}/subdomains.txt`,
      statusText: statusFor(subRes.ran, subs.length, 'subdomains'),
      updatedAt: subRes.updated_at,
      items: subs
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
      description: 'Drops boring static-asset URLs and collapses near-duplicate URLs (same pattern, different ID/param value) from the Wayback list. Passive, zero traffic - run Wayback Machine first.',
      note: `Saved to targets/${t.id}/uro_urls.txt`,
      statusText: statusFor(uroRes.ran, uroUrls.length, 'URLs kept'),
      updatedAt: uroRes.updated_at,
      items: uroUrls,
      disabledReason: !waybackRes.ran ? 'Run "Wayback Machine URLs" first' : null
    }),
    toolCardHTML({
      key: 'urlpatterns',
      title: 'URL Pattern Filter (gf-patterns)',
      description: 'Sorts URLs into categories (xss, sqli, ssrf, lfi, rce, idor, redirect, debug_logic, interesting_ext) by param name / extension. Uses the uro-cleaned list if available. Passive, zero traffic - run Wayback Machine first.',
      note: `Saved to targets/${t.id}/url_patterns.txt`,
      statusText: statusFor(urlPatRes.ran, urlPatterns.length, 'matches found'),
      updatedAt: urlPatRes.updated_at,
      items: urlPatterns,
      disabledReason: !waybackRes.ran ? 'Run "Wayback Machine URLs" first' : null
    }),
  ].join(''));

  const activeGroup = toolGroupHTML('Active Testing', [
    toolCardHTML({
      key: 'techinfo',
      title: 'Tech Fingerprint + TLS',
      description: 'Reads server headers, a generator meta tag if present, and the TLS certificate (issuer, expiry, SANs). Active - one lightweight request + TLS handshake.',
      note: `Saved to targets/${t.id}/techinfo.txt`,
      statusText: statusFor(techRes.ran, techLines.length, 'fields found'),
      updatedAt: techRes.updated_at,
      items: techLines
    }),
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
  ].join(''));

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
        ${activeGroup}
      </div>
    </div>
  `;

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

  document.getElementById('export-report-btn').addEventListener('click', () => {
    downloadReport(t, {
      subs, ports, dnsRecords, whoisLines, endpoints,
      waybackUrls, uroUrls, urlPatterns, techLines, xssFindings
    });
  });

  wireToolCard('subdomains', subs, () => runTool({ key: 'subdomains', endpoint: 'subdomains', t }));
  wireToolCard('portscan', ports, () => runTool({ key: 'portscan', endpoint: 'portscan', t }));
  wireToolCard('endpoints', endpoints, () => runTool({ key: 'endpoints', endpoint: 'endpoints', t }));
  wireToolCard('dns', dnsRecords, () => runTool({ key: 'dns', endpoint: 'dns', t }));
  wireToolCard('whois', whoisLines, () => runTool({ key: 'whois', endpoint: 'whois', t }));
  wireToolCard('techinfo', techLines, () => runTool({ key: 'techinfo', endpoint: 'techinfo', t }));
  wireToolCard('wayback', waybackUrls, () => runTool({ key: 'wayback', endpoint: 'wayback', t }));
  wireToolCard('uro', uroUrls, () => runTool({ key: 'uro', endpoint: 'uro', t }));
  wireToolCard('urlpatterns', urlPatterns, () => runTool({ key: 'urlpatterns', endpoint: 'urlpatterns', t }));
  wireToolCard('xssprobe', xssFindings, () => runTool({ key: 'xssprobe', endpoint: 'xssprobe', t }));
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

function showMonitoring() {
  document.getElementById('landing-page').style.display = 'none';
  document.getElementById('app-shell').style.display = 'none';
  document.getElementById('monitoring-page').style.display = 'flex';
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

// Theme toggle - persisted in localStorage (per-browser, this is a local
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
