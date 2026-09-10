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

- **Subdomain Enumeration**: pulls subdomains from **crt.sh** (public SSL
  certificate transparency logs). This is a fully passive OSINT source -
  no traffic is ever sent to the target itself.

  Note: crt.sh is a public, sometimes-overloaded server. If a run seems to
  hang for a while and then fails, it usually means crt.sh was slow to
  respond (the backend times out after 60s) - just try again in a bit.
  If it fails immediately with a connection error, check that no
  firewall/antivirus on your machine is blocking outbound requests from
  Python.

Results are saved automatically to `backend/targets/<target-id>/subdomains.txt`.

## Adding a new tool later

Every new recon tool needs:
1. **An endpoint in `app.py`** - like `run_subdomain_enum` - that takes the
   target, fetches the result, and writes it to a txt file inside the
   target's folder.
2. **A card in the frontend** - like the Subdomain Enumeration card in
   `app.js`.

## API Reference

| Method | Endpoint                          | Purpose                              |
|--------|------------------------------------|----------------------------------------|
| GET    | `/api/targets`                     | List all targets                       |
| POST   | `/api/targets`                     | Add a new target `{name, domain}`      |
| DELETE | `/api/targets/<id>`                | Delete a target and its whole folder   |
| GET    | `/api/targets/<id>/subdomains`     | Get the last saved subdomain results   |
| POST   | `/api/targets/<id>/subdomains`     | Run a fresh enumeration and save it    |
