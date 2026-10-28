# Recon Framework

An internal tool for organizing the **recon** phase of authorized penetration
tests / in-scope bug bounty work. Each target gets a real folder on disk
containing text files with each tool's results.

⚠️ **Only use this on targets you have explicit, documented authorization to test.**

## Structure

```
capstone_prj/
├── backend/
│   ├── app.py                    # Flask server - routes only
│   ├── storage.py                 # target folders / meta.json helpers
│   ├── requirements.txt
│   ├── modules/
│   │   ├── recon/                 # one file per recon tool (see below)
│   │   └── vuln_scan/             # next phase - scaffolded, not implemented yet
│   └── targets/                   # a folder per target, created automatically
│       └── <target-id>/
│           ├── meta.json
│           └── *.txt              # one result file per tool that's been run
└── frontend/
    ├── index.html                 # landing page + app shell + monitoring placeholder
    ├── style.css
    └── app.js
```

See `TOOLS_USED.txt` for a quick reference of every external tool/API each
module uses.

## Running it

```bash
cd capstone_prj/backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open your browser at:

```
http://localhost:5000
```

On Windows, if `python`/`pip` aren't recognized, try `py` and
`py -m pip install -r requirements.txt` instead.

You'll land on a start screen with two options:
- **Framework** - the recon tool (everything below).
- **Monitoring** - placeholder for a later phase, not built yet.

## Available tools

Recon tools live under `backend/modules/recon/`, one file per tool. Several
of them build on each other's output - **run them in this order** for best
results (the UI disables a tool's Run button with a tooltip until its
prerequisite has been run):

```
<<<<<<< HEAD
Wayback Machine URLs  ->  URL Pattern Filter  ->  XSS Reflection Prober
                      \-> Directory / Endpoint Discovery (merges in wayback paths)
=======
Wayback Machine URLs -> URL Cleaner (uro) -> URL Pattern Filter -> XSS Reflection Prober
                     \-> Directory / Endpoint Discovery (merges in wayback paths)
>>>>>>> 2aa2b0a (Add URL filtering and UI improvements; fix Nmap crash)
```

Everything else (Subdomains, Port Scan, DNS, WHOIS, Tech Fingerprint) can be
run independently, in any order.

<<<<<<< HEAD
=======
The **Run All** button (top-right of the Recon section) runs every tool in
this dependency-safe order automatically, one at a time, and keeps going
even if an individual tool fails (nmap missing, target unreachable, etc.) -
check the status line under the button for anything it had to skip.

Tools are grouped in the UI into three sections: **Discovery** (Subdomains,
Port Scan, DNS, WHOIS), **Content & URL Analysis** (Endpoint Discovery,
Wayback, URL Cleaner, URL Pattern Filter), and **Active Testing** (Tech
Fingerprint, XSS Prober). A stats bar at the top of each target shows a
quick count from every tool's last run.

>>>>>>> 2aa2b0a (Add URL filtering and UI improvements; fix Nmap crash)
- **Subdomain Enumeration (all-in-one)** *(passive)* - `subdomains_all_in_one.py`
  Merges 3 free, no-API-key sources and de-duplicates: **crt.sh**,
  **CertSpotter** (certificate transparency, different coverage than crt.sh),
  and **HackerTarget** (passive DNS, not cert-based). Each result is tagged
  with which source(s) found it. No traffic is ever sent to the target.

- **Port Scan** *(active - requires nmap)* - `portscan.py`
  Fast scan of the top 100 TCP ports via nmap (`-T4 -F -Pn`). Sends real
  traffic to the target.

  **nmap must be installed separately** - it's a system tool, not a Python
  package:
  - Windows: [nmap.org/download](https://nmap.org/download.html)
  - macOS: `brew install nmap`
  - Linux: `sudo apt install nmap`

  Verify it's on your PATH with `nmap --version` before running the scan.

- **Directory / Endpoint Discovery** *(active)* - `endpoints.py`
  Checks a built-in list of commonly-exposed paths (`.git/HEAD`, `.env`,
  `/admin`, etc.) **plus** real historical paths pulled from this target's
  own `wayback.txt`, if Wayback has already been run. Sends real requests
  to the target.

- **DNS Records** *(mostly passive)* - `dns_records.py`
  A/AAAA/MX/NS/TXT/CNAME/SOA lookups, plus a zone-transfer (AXFR) attempt
  against each nameserver - the AXFR attempt is the one active part (it
  talks directly to the target's own nameservers). A server that allows it
  is a real misconfiguration finding.

- **WHOIS / RDAP Lookup** *(passive)* - `whois_lookup.py`
  Registrar, registration/expiry dates, nameservers, via the public RDAP
  bootstrap service (`rdap.org`). No traffic sent to the target.

- **Tech Fingerprint + TLS Info** *(active)* - `tech_fingerprint.py`
  One lightweight request + one TLS handshake: server headers, a generator
  meta tag if present, and TLS certificate details (issuer, expiry, SANs).

- **Wayback Machine URLs** *(passive)* - `wayback_urls.py`
  Historical URLs for the domain from archive.org's CDX API - often
  surfaces old endpoints no longer linked anywhere. Feeds into both
  Endpoint Discovery and URL Pattern Filter below.

<<<<<<< HEAD
- **URL Pattern Filter (gf-patterns-inspired)** *(passive, zero network calls)* - `url_pattern_filter.py`
  Sorts the URLs from `wayback.txt` into categories (`xss`, `redirect`,
  `ssrf`, `sqli`, `lfi`, `rce`, `idor`, `debug_logic`, `interesting_ext`)
  based on query-param names and file extensions - inspired by
  [Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns), implemented
  directly in Python. **Requires Wayback Machine URLs to have been run
  first.**
=======
- **URL Cleaner (uro-inspired)** *(passive, zero network calls)* - `uro_filter.py`
  Drops boring static-asset URLs (images, fonts, css, js, media) and
  collapses near-duplicate URLs - same path pattern and same query-param
  names, just a different ID or value - from `wayback.txt`. Inspired by
  [uro](https://github.com/s0md3v/uro). **Requires Wayback Machine URLs to
  have been run first.**

- **URL Pattern Filter (gf-patterns-inspired)** *(passive, zero network calls)* - `url_pattern_filter.py`
  Sorts URLs into categories (`xss`, `redirect`, `ssrf`, `sqli`, `lfi`,
  `rce`, `idor`, `debug_logic`, `interesting_ext`) based on query-param
  names and file extensions - inspired by
  [Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns), implemented
  directly in Python. Prefers URL Cleaner's output if available, falls
  back to raw `wayback.txt` otherwise. **Requires Wayback Machine URLs to
  have been run first.**
>>>>>>> 2aa2b0a (Add URL filtering and UI improvements; fix Nmap crash)

- **XSS Reflection Prober (dalfox-inspired)** *(active)* - `xss_prober.py`
  Takes the URLs tagged `xss` by URL Pattern Filter and injects a marker
  with HTML-significant characters (`'"><`) into each query param, then
  checks whether it reflects back **unescaped**. This is a signal, not
  proof, of reflected XSS - no `<script>` payload is injected or executed;
  verify manually before treating it as a confirmed finding. **Requires
  URL Pattern Filter to have been run first.**

Results are saved automatically under `backend/targets/<target-id>/` as one
`.txt` file per tool (`subdomains.txt`, `ports.txt`, `endpoints.txt`,
`dns_records.txt`, `whois.txt`, `techinfo.txt`, `wayback.txt`,
<<<<<<< HEAD
`url_patterns.txt`, `xss_probe.txt`).
=======
`uro_urls.txt`, `url_patterns.txt`, `xss_probe.txt`).
>>>>>>> 2aa2b0a (Add URL filtering and UI improvements; fix Nmap crash)

## What's next (not built yet)

`backend/modules/vuln_scan/` is scaffolded for the next phase:
- `nse_vuln_scripts.py` - `nmap --script vuln` against open ports
- `tls_checks.py` - weak/expired certs, outdated ciphers
- `web_misconfig.py` - missing security headers, directory listing, etc.
- `cve_lookup.py` - match fingerprinted versions to known CVEs

The frontend's **Monitoring** button also currently opens an empty
placeholder page - not implemented yet.

## Adding a new tool later

Every new recon tool needs:
1. **A module in `backend/modules/recon/`** with `get_cached(target_path)`
   and `run(domain, target_path)` functions, following the pattern used by
   the existing modules. `run()` returns either a success dict, or
   `{"error": str, "status": int}` on failure.
2. **Two routes in `app.py`** (GET for cached results, POST to run it) -
   copy an existing pair like `get_dns_records` / `run_dns_records_route`.
3. **A card in the frontend** - call `toolCardHTML({...})` and
   `wireToolCard(...)` in `app.js` with a new `key`, following the pattern
   used by the other tools. Add the key to `uiState.tools` in both places
   it's defined at the top of the file.

## API Reference

| Method   | Endpoint                         | Purpose                            |
|----------|-----------------------------------|-------------------------------------|
| GET      | `/api/targets`                    | List all targets                   |
| POST     | `/api/targets`                    | Add a new target `{name, domain}`  |
| DELETE   | `/api/targets/<id>`               | Delete a target and its whole folder |
| GET/POST | `/api/targets/<id>/subdomains`    | Subdomain Enumeration (all-in-one) |
| GET/POST | `/api/targets/<id>/portscan`      | Port Scan (nmap)                   |
| GET/POST | `/api/targets/<id>/endpoints`     | Directory / Endpoint Discovery     |
| GET/POST | `/api/targets/<id>/dns`           | DNS Records                        |
| GET/POST | `/api/targets/<id>/whois`         | WHOIS / RDAP Lookup                |
| GET/POST | `/api/targets/<id>/techinfo`      | Tech Fingerprint + TLS Info        |
| GET/POST | `/api/targets/<id>/wayback`       | Wayback Machine URLs               |
<<<<<<< HEAD
=======
| GET/POST | `/api/targets/<id>/uro`           | URL Cleaner (uro)                  |
>>>>>>> 2aa2b0a (Add URL filtering and UI improvements; fix Nmap crash)
| GET/POST | `/api/targets/<id>/urlpatterns`   | URL Pattern Filter                 |
| GET/POST | `/api/targets/<id>/xssprobe`      | XSS Reflection Prober              |

GET returns the last saved result (or `{"ran": false}` if the tool hasn't
been run yet for that target). POST runs the tool fresh and overwrites the
saved result.
