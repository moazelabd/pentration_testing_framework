const API = '/api/targets';

let targets = [];
let activeId = null;

// UI collapse/expand state - kept in memory so it survives re-renders
// (e.g. after running a tool) instead of resetting every time.
let uiState = {
  sections: { recon: false },
  tools: { subdomains: false }
};

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
      // reset accordion state when switching targets
      uiState = { sections: { recon: false }, tools: { subdomains: false } };
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

  const subRes = await fetch(`${API}/${t.id}/subdomains`);
  const subData = await subRes.json();
  const subs = subData.subdomains || [];
  const ran = subData.ran || false;

  let statusText;
  if (!ran) {
    statusText = 'Not run yet.';
  } else if (subs.length > 0) {
    statusText = `Last result: ${subs.length} subdomains`;
  } else {
    statusText = 'Last run found 0 subdomains.';
  }

  const reconOpen = uiState.sections.recon;
  const subOpen = uiState.tools.subdomains;

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
        <span class="section-sub">passive information gathering</span>
      </div>
      <div class="section-body" id="section-recon-body" style="${reconOpen ? '' : 'display:none;'}">

        <div class="tool-card">
          <div class="tool-card-head" id="tool-head-subdomains">
            <span class="chevron ${subOpen ? 'open' : ''}">&#9656;</span>
            <div class="tool-info">
              <h3>Subdomain Enumeration</h3>
              <p>Pulls subdomains from public SSL certificate logs (crt.sh) - a fully passive OSINT source.</p>
            </div>
          </div>
          <div class="tool-body" id="tool-body-subdomains" style="${subOpen ? '' : 'display:none;'}">
            <div class="tool-run-row">
              <button class="run-btn" id="run-subdomains">Run</button>
              <div class="tool-status" id="sub-status">${statusText}</div>
            </div>
            <div id="sub-results-wrap" style="${subs.length > 0 ? '' : 'display:none;'}">
              <div class="result-list" id="sub-results">${subs.map(s => `<div>${s}</div>`).join('')}</div>
              <div class="tool-actions">
                <button class="ghost-btn" id="copy-sub">Copy all</button>
              </div>
            </div>
            <p class="tool-note">Results are saved to targets/${t.id}/subdomains.txt.</p>
          </div>
        </div>

        <div class="tool-card coming-soon">
          <div class="tool-card-head">
            <span class="chevron muted">&#9656;</span>
            <div class="tool-info"><h3>Port Scan</h3><p>Coming later.</p></div>
          </div>
        </div>

        <div class="tool-card coming-soon">
          <div class="tool-card-head">
            <span class="chevron muted">&#9656;</span>
            <div class="tool-info"><h3>Directory / Endpoint Discovery</h3><p>Coming later.</p></div>
          </div>
        </div>

      </div>
    </div>
  `;

  document.getElementById('section-recon').addEventListener('click', () => {
    uiState.sections.recon = !uiState.sections.recon;
    toggleBlock('section-recon-body', uiState.sections.recon);
    toggleChevron('section-recon', uiState.sections.recon);
  });

  document.getElementById('tool-head-subdomains').addEventListener('click', () => {
    uiState.tools.subdomains = !uiState.tools.subdomains;
    toggleBlock('tool-body-subdomains', uiState.tools.subdomains);
    toggleChevron('tool-head-subdomains', uiState.tools.subdomains);
  });

  document.getElementById('run-subdomains').addEventListener('click', (e) => {
    e.stopPropagation();
    runSubdomainEnum(t);
  });
  const cpBtn = document.getElementById('copy-sub');
  if (cpBtn) cpBtn.addEventListener('click', (e) => { e.stopPropagation(); copySub(subs); });
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

async function runSubdomainEnum(t) {
  const statusEl = document.getElementById('sub-status');
  const btn = document.getElementById('run-subdomains');
  btn.disabled = true;
  statusEl.className = 'tool-status';
  statusEl.textContent = 'Querying crt.sh... this can take up to a minute if crt.sh is under load.';

  try {
    const res = await fetch(`${API}/${t.id}/subdomains`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Unknown error');

    // keep the panel open so the result is visible right after the run
    uiState.sections.recon = true;
    uiState.tools.subdomains = true;
    renderMain();
  } catch (err) {
    statusEl.className = 'tool-status err';
    statusEl.textContent = 'Error: ' + err.message;
    btn.disabled = false;
  }
}

function copySub(subs) {
  navigator.clipboard.writeText(subs.join('\n'));
  const btn = document.getElementById('copy-sub');
  const original = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = original; }, 1200);
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
  uiState = { sections: { recon: false }, tools: { subdomains: false } };
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
