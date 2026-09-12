const API = '/api/targets';

let targets = [];
let activeId = null;

// UI collapse/expand state - kept in memory so it survives re-renders
// (e.g. after running a tool) instead of resetting every time.
let uiState = {
  sections: { recon: false },
  tools: { subdomains: false, portscan: false, endpoints: false }
};

function resetUiState() {
  uiState = {
    sections: { recon: false },
    tools: { subdomains: false, portscan: false, endpoints: false }
  };
}

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
    el.innerHTML = `<span class="t-name">${t.name}</span><span class="t-remove" data-id="${t.id}">✕</span>`;
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

function toolCardHTML({ key, title, description, note, statusText, items }) {
  const open = uiState.tools[key];
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
          <button class="run-btn" id="run-${key}">Run</button>
          <div class="tool-status" id="status-${key}">${statusText}</div>
        </div>
        <div id="results-wrap-${key}" style="${items.length > 0 ? '' : 'display:none;'}">
          <div class="result-list" id="results-${key}">${items.map(s => `<div>${s}</div>`).join('')}</div>
          <div class="tool-actions">
            <button class="ghost-btn" id="copy-${key}">Copy all</button>
          </div>
        </div>
        <p class="tool-note">${note}</p>
      </div>
    </div>`;
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

  const [subRes, portRes, endpRes] = await Promise.all([
    fetch(`${API}/${t.id}/subdomains`).then(r => r.json()),
    fetch(`${API}/${t.id}/portscan`).then(r => r.json()),
    fetch(`${API}/${t.id}/endpoints`).then(r => r.json()),
  ]);

  const subs = subRes.subdomains || [];
  const ports = portRes.ports || [];
  const endpoints = endpRes.endpoints || [];

  const reconOpen = uiState.sections.recon;

  container.innerHTML = `
    <div class="target-header">
      <div class="t-label">TARGET</div>
      <h2>${t.name}</h2>
      <div class="t-url">${t.domain}</div>
    </div>

    <div class="section">
      <div class="section-header" id="section-recon">
        <span class="chevron ${reconOpen ? 'open' : ''}">&#9656;</span>
        <span class="section-title">Recon</span>
        <span class="section-sub">information gathering</span>
      </div>
      <div class="section-body" id="section-recon-body" style="${reconOpen ? '' : 'display:none;'}">

        ${toolCardHTML({
          key: 'subdomains',
          title: 'Subdomain Enumeration',
          description: 'Pulls subdomains from public SSL certificate logs (crt.sh) - fully passive, no traffic sent to the target.',
          note: `Saved to targets/${t.id}/subdomains.txt`,
          statusText: statusFor(subRes.ran, subs.length, 'subdomains'),
          items: subs
        })}

        ${toolCardHTML({
          key: 'portscan',
          title: 'Port Scan (nmap)',
          description: 'Fast scan of the top 100 TCP ports via nmap. Active - sends real traffic to the target.',
          note: `Saved to targets/${t.id}/ports.txt · requires nmap installed on this machine`,
          statusText: statusFor(portRes.ran, ports.length, 'open ports'),
          items: ports
        })}

        ${toolCardHTML({
          key: 'endpoints',
          title: 'Directory / Endpoint Discovery',
          description: 'Checks a built-in list of commonly-exposed paths (admin panels, .git, config files, etc). Active - sends requests to the target.',
          note: `Saved to targets/${t.id}/endpoints.txt`,
          statusText: statusFor(endpRes.ran, endpoints.length, 'endpoints found'),
          items: endpoints
        })}

      </div>
    </div>
  `;

  document.getElementById('section-recon').addEventListener('click', () => {
    uiState.sections.recon = !uiState.sections.recon;
    toggleBlock('section-recon-body', uiState.sections.recon);
    toggleChevron('section-recon', uiState.sections.recon);
  });

  wireToolCard('subdomains', subs, () => runTool({ key: 'subdomains', endpoint: 'subdomains', t }));
  wireToolCard('portscan', ports, () => runTool({ key: 'portscan', endpoint: 'portscan', t }));
  wireToolCard('endpoints', endpoints, () => runTool({ key: 'endpoints', endpoint: 'endpoints', t }));
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

// Init
(async function init() {
  await fetchTargets();
  renderSidebar();
  renderMain();
})();
