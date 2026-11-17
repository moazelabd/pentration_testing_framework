# Recon Framework

An internal tool for the **recon** phase of authorized penetration tests /
in-scope bug bounty work. Each target gets a folder on disk with one text
file per tool's results.

⚠️ **Only use this on targets you have explicit, documented authorization to test.**

## Structure

```
capstone_prj/
├── backend/
│   ├── app.py              # Flask server - routes only
│   ├── storage.py           # target folders / meta.json helpers
│   ├── requirements.txt
│   ├── modules/
│   │   ├── recon/           # one file per recon tool
│   │   └── vuln_scan/       # URL pattern filter, JS secrets, XSS prober (+ planned modules)
│   └── targets/              # one folder per target, created automatically
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

`TOOLS_USED.txt` lists every external tool/API each module calls.

## Running it

```bash
cd capstone_prj/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`. On Windows, if `python`/`pip` aren't
recognized, use `py` instead.

You'll land on a start screen with two options: **Framework** (the recon
tool) and **Monitoring** (placeholder, not built yet).

## Tool order

Most tools run independently. The dependent ones build chains, in order -
the UI disables a tool's Run button until its prerequisite has run:

```
Subfinder (+ Subdomain Enumeration) -> Live Host Probe (httpx) -> Live Host Filter -> Web Crawler (katana) -> JS File Extractor (katana + Wayback) -> jsluice (urls/secrets) -> JS Parameter Collector
                       \-> WAF Detection (wafw00f) -> WAF Filter
Wayback Machine URLs -> URL Cleaner (uro)   -> URL Pattern Filter -> XSS Reflection Prober
                     -> URL Dedupe (urldedupe) -> Parameter Collector
                     \-> Directory / Endpoint Discovery
```

**Run All** (top of the Recon section) runs every tool in this safe order
automatically, skipping past any tool that fails.

The **Vulnerability Scan** section has its own **Run All** (URL Pattern Filter -> JS Secrets -> XSS Prober).
It relies on Recon results, so run Recon first.

The target page has two collapsible sections.

**Recon** - **Discovery** (Subdomains, Subfinder, Live Host Probe, Live Host Filter, Port Scan, DNS, WHOIS),
**Content & URL Analysis** (WAF Detection/Filter, Katana, JS Extractor, jsluice URLs, JS Parameter Collector,
Endpoints, Wayback, uro, urldedupe, Parameter Collector) and **Fingerprinting** (Tech Fingerprint + TLS).

**Vulnerability Scan** - **Triage & Secrets** (URL Pattern Filter, JS Secrets via jsluice) and
**Active Testing** (XSS Reflection Prober).

## External CLI tools (optional but recommended)

The new industry-standard modules need these binaries on your PATH.
Most are Go tools; **wafw00f is a pip package**:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
pip install wafw00f
```

**urldedupe is a C++ project, not Go** - build it from source:

```bash
git clone https://github.com/ameenmaali/urldedupe
cd urldedupe
g++ -std=c++17 -O2 -o ~/go/bin/urldedupe main.cpp utils.cpp flags.cpp Url.cpp
```

If `go install` fails with `sum.golang.org: connection refused`
(blocked network), retry with the checksum DB disabled:

```bash
GOSUMDB=off go install <the module>@latest
```

nmap stays a separate package install (`apt install nmap`). If a CLI tool
is missing, its card shows an error message with the install command -
the rest of the pipeline keeps working.

## Tools

| Tool | Type | What it does |
|---|---|---|
| Subdomain Enumeration (all-in-one) | passive | Merges crt.sh, CertSpotter, HackerTarget - deduplicated, tagged by source |
| Subdomain Enumeration (subfinder) | passive | Industry-standard `subfinder` CLI - needs subfinder on your PATH |
| Live Host Probe (httpx) | active | Industry-standard `httpx` CLI - probes every subdomain, keeps 200/301/302/401/403/404 with titles + tech. Needs httpx on your PATH |
| Live Host Filter (403/404 Split) | passive | Splits live_hosts.txt into live_<code>.txt files for per-status triage |
| Web Crawler (katana) | active | Industry-standard `katana` CLI - depth-3 crawl of live 200 hosts, extracts URLs/forms/JS endpoints (-jc). Needs katana on your PATH |
| JS File Extractor | passive | Merges the .js URLs (incl. .js?query) from the katana crawl AND the Wayback Machine results into one deduplicated js_files.txt |
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

Results save to `backend/targets/<target-id>/*.txt`, one file per tool.

## What's next (not built yet)

`backend/modules/vuln_scan/` already holds `url_pattern_filter.py`, `jsluice_secrets.py` and
`xss_prober.py`. Still planned: `nse_vuln_scripts.py`, `tls_checks.py`, `web_misconfig.py`,
`cve_lookup.py`. The **Monitoring** button is also just a placeholder for now.

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

GET returns the last saved result (`{"ran": false}` if never run). POST
runs the tool fresh and overwrites the saved result.
