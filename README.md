# Recon Framework

An internal tool for organizing the **recon** phase of authorized penetration
tests / in-scope bug bounty work. Each target gets a real folder on disk
containing text files with each tool's results.

⚠️ **Only use this on targets you have explicit, documented authorization to test.**

## Structure

```
recon-framework/
├── backend/
│   ├── app.py            # Flask server + all API endpoints
│   ├── requirements.txt
│   └── targets/          # a folder per target is created automatically
│       └── <target-id>/
│           ├── meta.json
│           └── subdomains.txt
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## Running it

```bash
cd recon-framework/backend
pip install -r requirements.txt
python app.py
```

Then open your browser at:

```
http://localhost:5000
```

On Windows, if `python`/`pip` aren't recognized, try `py` and
`py -m pip install -r requirements.txt` instead.

## Available tools

- **Subdomain Enumeration** *(passive)*: pulls subdomains from **crt.sh**
  (public SSL certificate transparency logs). No traffic is ever sent to
  the target itself.

  Note: crt.sh is a public, sometimes-overloaded server. If a run seems to
  hang for a while and then fails, it usually means crt.sh was slow to
  respond (the backend times out after 60s) - just try again in a bit.

- **Port Scan** *(active - requires nmap)*: a fast scan of the top 100 TCP
  ports via nmap. This sends real traffic to the target, so only run it
  against in-scope, authorized targets.

  **nmap must be installed separately** - it's a system tool, not a Python
  package:
  - Windows: download the installer from [nmap.org/download](https://nmap.org/download.html)
  - macOS: `brew install nmap`
  - Linux: `sudo apt install nmap` (or your distro's equivalent)

  Verify it's on your PATH with `nmap --version` before running the scan.

- **Directory / Endpoint Discovery** *(active)*: checks a small built-in
  list of commonly-exposed paths (`.git/HEAD`, `.env`, `/admin`,
  `/wp-admin`, etc.) over HTTP/HTTPS. This is a quick-check list, not a
  full wordlist brute-force like gobuster/ffuf - it sends real requests to
  the target, so authorized targets only.

Results are saved automatically under `backend/targets/<target-id>/`:
`subdomains.txt`, `ports.txt`, `endpoints.txt`.

## Adding a new tool later

Every new recon tool needs:
1. **An endpoint in `app.py`** - like `run_subdomain_enum` - that takes the
   target, fetches the result, and writes it to a txt file inside the
   target's folder.
2. **A card in the frontend** - call `toolCardHTML({...})` and
   `wireToolCard(...)` in `app.js` with a new `key`, following the pattern
   used for `subdomains` / `portscan` / `endpoints`.

## API Reference

| Method | Endpoint                          | Purpose                              |
|--------|------------------------------------|----------------------------------------|
| GET    | `/api/targets`                     | List all targets                       |
| POST   | `/api/targets`                     | Add a new target `{name, domain}`      |
| DELETE | `/api/targets/<id>`                | Delete a target and its whole folder   |
| GET    | `/api/targets/<id>/subdomains`     | Get the last saved subdomain results   |
| POST   | `/api/targets/<id>/subdomains`     | Run subdomain enumeration              |
| GET    | `/api/targets/<id>/portscan`       | Get the last saved port scan results   |
| POST   | `/api/targets/<id>/portscan`       | Run an nmap port scan                  |
| GET    | `/api/targets/<id>/endpoints`      | Get the last saved endpoint results    |
| POST   | `/api/targets/<id>/endpoints`      | Run endpoint/directory discovery       |
