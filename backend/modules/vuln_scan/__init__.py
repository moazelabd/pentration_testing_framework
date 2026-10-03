"""
Vulnerability scanning modules - next capstone phase, not implemented yet.

Each module here should follow the same shape as modules/recon/*.py:
  - get_cached(target_path) -> {"<key>": [...], "ran": bool}
  - run(domain, target_path) -> {"<key>": [...], "count": n}
                                 or {"error": str, "status": int} on failure

Planned modules:
  - tls_checks.py        weak/expired TLS certs, outdated ciphers
  - web_misconfig.py      missing security headers, directory listing, etc.
  - nse_vuln_scripts.py   nmap --script vuln against discovered open ports
  - cve_lookup.py         match fingerprinted service/versions to known CVEs
"""
