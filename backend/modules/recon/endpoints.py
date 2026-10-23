"""
Endpoint / Directory Discovery - ACTIVE.

Checks a merged, de-duplicated set of candidate paths against the target
over HTTP(S):

  - a small built-in list of commonly-exposed paths (admin panels, .git,
    config files, ...)
  - real historical paths pulled from this target's own wayback.txt
    (written by wayback_urls.py), if that tool has already been run -
    these are paths that genuinely existed on the target at some point,
    which a generic wordlist could never guess.

This DOES send requests directly to the target - authorized targets only.
"""
import os
import re

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

# Cap on how many extra wayback-derived paths we probe, so a target with
# thousands of archived URLs doesn't turn one click into a 20-minute scan.
MAX_WAYBACK_PATHS = 100


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "endpoints.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"endpoints": lines, "ran": ran}


def _paths_from_wayback(target_path: str, limit: int = MAX_WAYBACK_PATHS) -> list:
    wb_path = os.path.join(target_path, "wayback.txt")
    if not os.path.isfile(wb_path):
        return []

    paths = []
    seen = set()
    with open(wb_path, "r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            match = re.match(r"^https?://[^/]+(/.*)?$", url)
            if not match:
                continue
            path = (match.group(1) or "/").lstrip("/")
            if path and path not in seen:
                seen.add(path)
                paths.append(path)
            if len(paths) >= limit:
                break
    return paths


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

    # Merge the static wordlist with real paths seen in the Wayback
    # Machine data (if that tool has been run for this target), tagging
    # each candidate with where it came from and de-duplicating.
    candidates = {}
    for path in COMMON_PATHS:
        candidates.setdefault(path, set()).add("wordlist")
    wayback_paths = _paths_from_wayback(target_path)
    for path in wayback_paths:
        candidates.setdefault(path, set()).add("wayback")

    found = []
    for path, sources in candidates.items():
        url = f"{working_base}/{path}"
        try:
            r = session.get(url, timeout=6, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 401, 403):
                found.append(f"{r.status_code}  {url}  ({', '.join(sorted(sources))})")
        except requests.exceptions.RequestException:
            continue

    with open(os.path.join(target_path, "endpoints.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(found))

    return {
        "endpoints": found,
        "count": len(found),
        "base": working_base,
        "candidates_checked": len(candidates),
        "from_wayback": len(wayback_paths),
    }
