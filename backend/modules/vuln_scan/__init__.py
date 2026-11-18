"""
Vulnerability scanning modules.

Implemented: url_pattern_filter.py, jsluice_secrets.py, xss_prober.py, cve_nvd.py,
cve_circl.py, cve_merge.py (shared helpers: cve_common.py).
Still planned (not implemented yet): the modules listed at the bottom.

Each module here should follow the same shape as modules/recon/*.py:
  - get_cached(target_path) -> {"<key>": [...], "ran": bool}
  - run(domain, target_path) -> {"<key>": [...], "count": n}
                                 or {"error": str, "status": int} on failure

Planned modules:
  - tls_checks.py        weak/expired TLS certs, outdated ciphers
  - web_misconfig.py      missing security headers, directory listing, etc.
  - nse_vuln_scripts.py   nmap --script vuln against discovered open ports
"""
