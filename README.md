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
│   │   └── vuln_scan/       # next phase - scaffolded, not implemented yet
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

Most tools run independently. These four build on each other, in order -
the UI disables a tool's Run button until its prerequisite has run:

```
Wayback Machine URLs -> URL Cleaner (uro) -> URL Pattern Filter -> XSS Reflection Prober
                     \-> Directory / Endpoint Discovery
```

**Run All** (top of the Recon section) runs every tool in this safe order
automatically, skipping past any tool that fails.

Tools are grouped into **Discovery** (Subdomains, Port Scan, DNS, WHOIS),
**Content & URL Analysis** (Endpoints, Wayback, uro, URL Pattern Filter),
and **Active Testing** (Tech Fingerprint, XSS Prober).

## Tools

| Tool | Type | What it does |
|---|---|---|
| Subdomain Enumeration (all-in-one) | passive | Merges crt.sh, CertSpotter, HackerTarget - deduplicated, tagged by source |
| Port Scan (nmap) | active | Top 100 TCP ports. **Requires nmap installed separately** - [nmap.org](https://nmap.org/download.html) / `brew install nmap` / `apt install nmap` |
| Directory / Endpoint Discovery | active | Built-in path list + real paths from Wayback results |
| DNS Records | mostly passive | A/AAAA/MX/NS/TXT/CNAME/SOA + zone-transfer (AXFR) attempt |
| WHOIS / RDAP Lookup | passive | Registrar, dates, nameservers via `rdap.org` |
| Tech Fingerprint + TLS | active | Server headers + TLS certificate details |
| Wayback Machine URLs | passive | Historical URLs from archive.org |
| URL Cleaner (uro) | passive | Drops static assets, collapses near-duplicate URLs |
| URL Pattern Filter (gf-patterns) | passive | Tags URLs: xss, sqli, ssrf, lfi, rce, idor, redirect, debug_logic, interesting_ext |
| XSS Reflection Prober (dalfox-inspired) | active | Injects a marker per param, flags unescaped reflections (signal, not proof) |

Results save to `backend/targets/<target-id>/*.txt`, one file per tool.

## What's next (not built yet)

`backend/modules/vuln_scan/` is scaffolded for: `nse_vuln_scripts.py`,
`tls_checks.py`, `web_misconfig.py`, `cve_lookup.py`. The **Monitoring**
button is also just a placeholder for now.

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
| GET/POST | `/api/targets/<id>/subdomains` | Subdomain Enumeration |
| GET/POST | `/api/targets/<id>/portscan` | Port Scan |
| GET/POST | `/api/targets/<id>/endpoints` | Endpoint Discovery |
| GET/POST | `/api/targets/<id>/dns` | DNS Records |
| GET/POST | `/api/targets/<id>/whois` | WHOIS / RDAP |
| GET/POST | `/api/targets/<id>/techinfo` | Tech Fingerprint + TLS |
| GET/POST | `/api/targets/<id>/wayback` | Wayback Machine URLs |
| GET/POST | `/api/targets/<id>/uro` | URL Cleaner |
| GET/POST | `/api/targets/<id>/urlpatterns` | URL Pattern Filter |
| GET/POST | `/api/targets/<id>/xssprobe` | XSS Reflection Prober |

GET returns the last saved result (`{"ran": false}` if never run). POST
runs the tool fresh and overwrites the saved result.
