"""
Endpoint / Directory Discovery - ACTIVE.

Checks a small built-in list of commonly-exposed paths against the target
over HTTP(S). This DOES send requests directly to the target - authorized
targets only.
"""
import os

import requests

USER_AGENT = "recon-framework/1.0"

# Quick-check list, not a full brute-force wordlist - it's meant to flag
# commonly-exposed paths, not replace a dedicated tool like gobuster/ffuf
# with a large wordlist.
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    ".git/HEAD", ".git/config", ".env", ".env.local",
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "api", "api/v1", "graphql", "swagger", "swagger-ui",
    "backup", "backups", "config", "config.php", "config.json",
    "uploads", "dashboard", "console", "server-status",
    "test", "staging", "phpinfo.php", "readme.md", "changelog.md",
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "endpoints.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"endpoints": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    working_base = None
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        try:
            session.get(base, timeout=8, allow_redirects=True)
            working_base = base
            break
        except requests.exceptions.RequestException:
            continue

    if not working_base:
        return {
            "error": f"Could not reach '{domain}' over HTTPS or HTTP. "
                     f"Check the domain is correct and currently online.",
            "status": 502,
        }

    found = []
    for path in COMMON_PATHS:
        url = f"{working_base}/{path}"
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 401, 403):
                found.append(f"{r.status_code}  {url}")
        except requests.exceptions.RequestException:
            continue

    with open(os.path.join(target_path, "endpoints.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(found))

    return {"endpoints": found, "count": len(found), "base": working_base}
