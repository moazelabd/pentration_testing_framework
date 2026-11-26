# Penetration Testing Framework

An internal tool covering the full **recon + vulnerability scanning** phases of
authorized penetration tests / in-scope bug bounty work. Each target gets a
folder on disk with one text file per tool's results.

⚠️ **Only use this on targets you have explicit, documented authorization to test.**

## Structure

```
capstone_prj/
├── backend/
│   ├── app.py              # Flask server - routes only
│   ├── storage.py           # target folders / meta.json helpers
│   ├── requirements.txt
│   ├── modules/
│   │   ├── auth_ctx.py       # optional login session, scoped to the target's own domain
│   │   ├── recon/           # one file per recon tool
│   │   └── vuln_scan/       # CVE lookup (NVD + CIRCL + merge), triage/secrets, active probers (XSS/open redirect/SQLi/LFI), TLS/web-misconfig/nmap-vuln/subdomain-takeover checks
│   └── targets/              # one folder per target, created automatically
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

`TOOLS_USED.txt` lists every external tool/API each module calls.

## Running it (fresh machine, zero prior setup)

These steps assume nothing is installed yet. Follow them top to bottom, in
order, and the app will run with every tool working - no extra debugging.

### 1. System packages (Linux / Kali / Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap golang-go git
```

- `python3-venv` / `python3-pip` - needed to create the virtualenv below.
- `nmap` - used directly by the Port Scan and Nmap Vuln Scripts tools.
- `golang-go` - needed only to install the 5 Go-based tools in step 3. If
  `apt`'s Go is older than 1.21, install a newer one from
  [go.dev/dl](https://go.dev/dl/) instead - any method works, `go install`
  just needs to exist.
- macOS: `brew install python nmap go git`. Windows: install
  [Python](https://www.python.org/downloads/), [Nmap](https://nmap.org/download.html)
  and [Go](https://go.dev/dl/) from their installers, then use `py` instead
  of `python3`/`python` below.

### 2. Python environment

```bash
cd capstone_prj/backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

On Kali/Debian you may see `error: externally-managed-environment` if you
skip the venv - always activate `venv` first, don't `pip install` system-wide.

### 3. External CLI tools (required for the industry-standard modules)

See the **External CLI tools** section right below - do that now, then come
back here.

### 4. Run it

```bash
python app.py        # still inside backend/, with venv activated
```

Open `http://localhost:5000`. On Windows, if `python`/`pip` aren't
recognized, use `py` instead.

You'll land on a start screen with two options: **Framework** (the recon
tool) and **Monitoring** (placeholder, not built yet).

## Tool order

Most tools run independently. The dependent ones build chains, in order -
the UI disables a tool's Run button until its prerequisite has run:

```
Subfinder (+ Subdomain Enumeration) -> Live Host Probe (httpx) -> Live Host Filter -> Web Crawler (katana) -> JS File Extractor -> jsluice (urls/secrets) -> JS Parameter Collector
                       \-> WAF Detection (wafw00f) -> WAF Filter
Wayback Machine URLs -> URL Cleaner (uro)   -> URL Pattern Filter -> XSS Reflection Prober
                     -> URL Dedupe (urldedupe) -> Parameter Collector
                     \-> Directory / Endpoint Discovery
```

**Run All** (top of the Recon section) runs every tool in this safe order
automatically, skipping past any tool that fails.

The **Vulnerability Scan** section has its own **Run All** (CVE NVD -> CVE CIRCL -> CVE Merge -> URL Pattern Filter ->
JS Secrets -> XSS Prober -> Open Redirect Prober -> SQLi Prober -> LFI Prober -> TLS Checks -> Web Misconfiguration
Checker -> Nmap Vuln Scripts -> Subdomain Takeover Checker). It relies on Recon results, so run Recon first.

The target page has two collapsible sections.

**Recon** - **Discovery** (Subdomains, Subfinder, Live Host Probe, Live Host Filter, Port Scan, DNS, WHOIS),
**Content & URL Analysis** (WAF Detection/Filter, Katana, JS Extractor, jsluice URLs, JS Parameter Collector,
Endpoints, Wayback, uro, urldedupe, Parameter Collector) and **Fingerprinting** (Tech Fingerprint + TLS).

**Vulnerability Scan** - **CVE Lookup** (NVD, CIRCL, Merge), **Triage & Secrets** (URL Pattern Filter, JS Secrets via
jsluice), **Active Testing** (XSS Reflection Prober, Open Redirect Prober, SQL Injection Error-Based Prober,
LFI / Path Traversal Prober) and **Infrastructure & Config** (TLS / SSL Deep Checks, Web Misconfiguration Checker,
Nmap Vuln Scripts, Subdomain Takeover Checker).

## Scanning behind a login (optional)

By default every tool sees the site like an anonymous visitor. On the target page, the **Login session**
panel lets you add a cookie and/or `Authorization` header of a **test account** so the crawl and probes can
reach pages that need a login.

1. Log in to the site in your browser with a test account you are allowed to use (never a real user's).
2. Press `F12` -> **Network** -> click any request to the site -> copy the `Cookie:` line (or the
   `Authorization: Bearer ...` line) from **Request Headers**.
3. Paste it in the panel (one header per line) and press **Save**.

It is stored only on your machine in `backend/targets/<id>/auth.txt` (a `.gitignore` next to it keeps it out of
git) and is sent **only to the target's own domain and subdomains** - never to crt.sh, Wayback, NVD or any other
site, and it is dropped if a redirect leaves the domain. Used by: Live Host Probe, Katana, Tech Fingerprint,
Endpoint Discovery and the XSS Reflection Prober. Session cookies expire - paste a fresh one if results stop.

## External CLI tools (recommended - several Recon tools need these)

Every tool below is optional in the sense that a missing one just shows an
error on its own card and the rest of the pipeline keeps working - but for
the full framework to work out of the box, install all of them now.

**Most are Go tools; wafw00f is a pip package; nmap is a system package**
(already installed in step 1 above if you followed it):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
go install -v github.com/ameenmaali/urldedupe@latest
pip install wafw00f        # inside the same activated venv as step 2
```

### ⚠️ The #1 reason these "don't work" after installing: PATH

`go install` puts every binary in `$HOME/go/bin` (or `$GOBIN` if you've set
that), **not** in a folder your shell already searches. If you skip this
step, `subfinder`/`katana`/etc. will say `command not found` even though
the install above printed no error.

Add Go's bin folder to your PATH, then make it permanent:

```bash
export PATH=$PATH:$HOME/go/bin

# make it permanent (pick the line matching your shell):
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc     # bash (default on most Linux/Kali)
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc       # zsh (default on macOS)

# then reload the current terminal:
source ~/.bashrc   # or source ~/.zshrc
```

### Verify every tool is actually reachable

Run this after the PATH step above - every line must print a path, not
"not found":

```bash
which subfinder httpx katana jsluice urldedupe wafw00f nmap
```

If one is still missing: re-run its `go install`/`pip install` command,
open a **new terminal** (PATH changes only apply to new shells), then
re-run the `which` check.

> `httpx` name clash: this project's `requirements.txt` deliberately never
> installs the Python `httpx` pip package - only ProjectDiscovery's Go
> `httpx` binary. If `which httpx` ever points at a Python package instead
> of `$HOME/go/bin/httpx`, something installed the wrong one; uninstall the
> pip package (`pip uninstall httpx`) and make sure `$HOME/go/bin` comes
> first on your PATH.

## Tools

| Tool | Type | What it does |
|---|---|---|
| Subdomain Enumeration (all-in-one) | passive | Merges crt.sh, CertSpotter, HackerTarget - deduplicated, tagged by source |
| Subdomain Enumeration (subfinder) | passive | Industry-standard `subfinder` CLI - needs subfinder on your PATH |
| Live Host Probe (httpx) | active | Industry-standard `httpx` CLI - probes every subdomain, keeps 200/301/302/401/403/404 with titles + tech. Needs httpx on your PATH |
| Live Host Filter (403/404 Split) | passive | Splits live_hosts.txt into live_<code>.txt files for per-status triage |
| Web Crawler (katana) | active | Industry-standard `katana` CLI - depth-3 crawl of live 200 hosts, extracts URLs/forms/JS endpoints (-jc). Needs katana on your PATH |
| JS File Extractor | passive | Keeps the .js URLs (incl. .js?query) from katana output into js_files.txt |
| JS URLs (jsluice) | active-ish | `jsluice urls -I` (Bishop Fox, tree-sitter) - real fetch/redirect/API URLs + params from JS, not regex |
| JS Secrets (jsluice) | active-ish | `jsluice secrets` - AWS/GCP/GitHub/Firebase tokens and keys leaked in JS, per-finding severity summary |
| JS Parameter Collector | passive | Merges jsluice + katana + existing params into all_params.txt (input for active testing) |
| WAF Detection (wafw00f) | active | Industry-standard `wafw00f` CLI (pip package) - fingerprints Cloudflare/Akamai/AWS WAF etc. per live host |
| WAF Filter (WAF presence split) | passive | Splits hosts into hosts_with_waf.txt (careful) / hosts_no_waf.txt (safe for active testing) |
| Port Scan (nmap) | active | Top 100 TCP ports. **Requires nmap installed separately** - [nmap.org](https://nmap.org/download.html) / `brew install nmap` / `apt install nmap` |
| Directory / Endpoint Discovery | active | Built-in path list + real paths from Wayback results |
| DNS Records | mostly passive | A/AAAA/MX/NS/TXT/CNAME/SOA + zone-transfer (AXFR) attempt |
| WHOIS / RDAP Lookup | passive | Registrar, dates, nameservers via `rdap.org` |
| Tech Fingerprint + TLS | active | Server headers + TLS certificate details |
| Wayback Machine URLs | passive | Historical URLs from archive.org |
| URL Cleaner (uro) | passive | Drops static assets, collapses near-duplicate URLs |
| URL Pattern Filter | passive | Tags URLs: xss, sqli, ssrf, lfi, rce, idor, redirect, debug_logic, interesting_ext || URL Dedupe (urldedupe) | passive | Industry-standard `urldedupe` CLI - collapses near-duplicate URLs from wayback.txt |
| Parameter Collector | passive | Merges subfinder + cleaned URLs, keeps only `?parameterized` URLs into all_params.txt (worklist for the active-testing phase) |
| XSS Reflection Prober (dalfox-inspired) | active | Injects a marker per param, flags unescaped reflections (signal, not proof) |
| CVE Lookup (NVD) | passive | Looks up the product + version pairs found by Tech Fingerprint / Live Host Probe (e.g. nginx 1.18.0) in NIST NVD. Nothing is sent to the target. ~6.5s per request without a key - set `NVD_API_KEY` to speed up |
| CVE Lookup (CIRCL) | passive | Same input, second independent source (CIRCL Vulnerability-Lookup): fetches the product's CVEs and keeps those whose affected-version ranges include the detected version |
| CVE Merge | passive | Combines NVD + CIRCL results: one line per CVE (duplicates removed, sources combined, highest CVSS kept), sorted by severity |
| Open Redirect Prober | active | Injects `https://evil-redirect-poc.example/` (and encoded variants) into URLs tagged `redirect`, flags any `Location` header that follows it (no actual redirect used) |
| SQL Injection Error-Based Prober | active | Injects `'`, `"`, `' OR '1'='1` etc. into URLs tagged `sqli`, flags responses matching known MySQL/MSSQL/PostgreSQL/Oracle/SQLite error signatures |
| LFI / Path Traversal Prober | active | Injects path-traversal payloads (several encodings/bypasses) into URLs tagged `lfi`, flags `/etc/passwd` or `win.ini` content in the response |
| TLS / SSL Deep Checks | active | Forces a handshake on each deprecated protocol (SSLv3/TLSv1/TLSv1.1) to flag if it's still accepted, plus classifies certificate verification failures (self-signed, hostname mismatch, expired, incomplete chain) |
| Web Misconfiguration Checker | active | Checks for 5 missing security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) and probes common paths for exposed directory listings |
| Nmap Vuln Scripts | active | Re-scans the open ports found by Port Scan with nmap's `--script vuln` category (CVE/misconfiguration checks specific to the listening service) |
| Subdomain Takeover Checker | passive + 1 request | Resolves each subdomain's CNAME, and if it points at a known third-party service (S3, GitHub Pages, Heroku, Azure, Netlify, etc.) checks the response against that service's own "unclaimed resource" fingerprint |

Results save to `backend/targets/<target-id>/*.txt`, one file per tool.

## What's next

The **Monitoring** button is still just a placeholder for now. Recon and Vulnerability Scan are both
fully built out.

## Adding a new tool

1. A module in `backend/modules/recon/` with `get_cached(target_path)` and
   `run(domain, target_path)`, matching the existing modules' pattern.
2. Two routes in `app.py` (GET + POST) - copy an existing pair.
3. A card in `app.js` - call `toolCardHTML({...})` / `wireToolCard(...)`
   with a new `key`, and add that key to `uiState.tools` in both places.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/targets` | List targets |
| POST | `/api/targets` | Add a target `{name, domain}` |
| DELETE | `/api/targets/<id>` | Delete a target |
| GET/POST | `/api/targets/<id>/subdomains` | Subdomain Enumeration (all-in-one) |
| GET/POST | `/api/targets/<id>/subfinder` | Subdomain Enumeration (subfinder) |
| GET/POST | `/api/targets/<id>/httpx_live` | Live Host Probe (httpx) |
| GET/POST | `/api/targets/<id>/httpx_filter` | Live Host Filter (status split) |
| GET/POST | `/api/targets/<id>/katana` | Web Crawler (katana) |
| GET/POST | `/api/targets/<id>/js_extractor` | JS File Extractor |
| GET/POST | `/api/targets/<id>/jsluice_urls` | JS URLs + parameters (jsluice) |
| GET/POST | `/api/targets/<id>/jsluice_secrets` | JS secrets (jsluice) |
| GET/POST | `/api/targets/<id>/cve_nvd` | CVE Lookup (NVD) |
| GET/POST | `/api/targets/<id>/cve_circl` | CVE Lookup (CIRCL) |
| GET/POST | `/api/targets/<id>/cve_merge` | CVE Merge (dedupe) |
| GET/PUT/DELETE | `/api/targets/<id>/auth` | Optional login cookie / Authorization header (the secret is never returned, only a masked summary) |
| GET/POST | `/api/targets/<id>/js_params` | JS Parameter Collector |
| GET/POST | `/api/targets/<id>/portscan` | Port Scan |
| GET/POST | `/api/targets/<id>/endpoints` | Endpoint Discovery |
| GET/POST | `/api/targets/<id>/dns` | DNS Records |
| GET/POST | `/api/targets/<id>/whois` | WHOIS / RDAP |
| GET/POST | `/api/targets/<id>/techinfo` | Tech Fingerprint + TLS |
| GET/POST | `/api/targets/<id>/wayback` | Wayback Machine URLs |
| GET/POST | `/api/targets/<id>/uro` | URL Cleaner |
| GET/POST | `/api/targets/<id>/urldedupe` | URL Dedupe (urldedupe) |
| GET/POST | `/api/targets/<id>/waf` | WAF Detection (wafw00f) |
| GET/POST | `/api/targets/<id>/waf_filter` | WAF Filter (presence split) |
| GET/POST | `/api/targets/<id>/all_params` | Parameter Collector |
| GET/POST | `/api/targets/<id>/urlpatterns` | URL Pattern Filter |
| GET/POST | `/api/targets/<id>/xssprobe` | XSS Reflection Prober |
| GET/POST | `/api/targets/<id>/openredirect` | Open Redirect Prober |
| GET/POST | `/api/targets/<id>/sqliprobe` | SQL Injection Error-Based Prober |
| GET/POST | `/api/targets/<id>/lfiprobe` | LFI / Path Traversal Prober |
| GET/POST | `/api/targets/<id>/tlschecks` | TLS / SSL Deep Checks |
| GET/POST | `/api/targets/<id>/webmisconfig` | Web Misconfiguration Checker |
| GET/POST | `/api/targets/<id>/nsevuln` | Nmap Vuln Scripts |
| GET/POST | `/api/targets/<id>/subtakeover` | Subdomain Takeover Checker |
| GET | `/api/targets/<id>/report.pdf` | Export - builds a clean PDF report from whatever results already exist for the target |

GET returns the last saved result (`{"ran": false}` if never run). POST
runs the tool fresh and overwrites the saved result.
