"""
Web Misconfiguration Checker - ACTIVE (a handful of HTTP requests to the target).

Two checks in one module:

  1. Missing security headers - Content-Security-Policy, Strict-
     Transport-Security, X-Content-Type-Options, X-Frame-Options,
     Referrer-Policy. None of these alone is usually critical, but their
     absence is a common, low-effort finding worth flagging.
  2. Directory listing - requests a handful of common directories and
     checks for the tell-tale "Index of /" (Apache/nginx autoindex) text,
     which exposes the raw file list of that folder to anyone.

Sends real requests to the target - authorized targets only.
"""
import os

import requests

from modules import auth_ctx

USER_AGENT = "recon-framework/1.0"

SECURITY_HEADERS = [
    ("Content-Security-Policy", "Mitigates XSS/data-injection by restricting what the page can load/run"),
    ("Strict-Transport-Security", "Forces browsers to only use HTTPS for this site"),
    ("X-Content-Type-Options", "Stops browsers from MIME-sniffing a response away from its declared type"),
    ("X-Frame-Options", "Prevents the page from being framed (clickjacking)"),
    ("Referrer-Policy", "Controls how much of the URL leaks to other sites via the Referer header"),
]

DIR_CANDIDATES = ["/uploads/", "/images/", "/backup/", "/files/", "/static/", "/assets/", "/.git/"]
LISTING_SIGNATURES = ["Index of /", "<title>Directory listing for", "Parent Directory</a>"]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "web_misconfig.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _check_headers(session, domain: str):
    resp = None
    for scheme in ("https", "http"):
        try:
            resp = session.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            break
        except requests.exceptions.RequestException:
            continue
    if resp is None:
        return ["Error\tCould not reach the target over HTTPS or HTTP"], 0

    findings = []
    missing = 0
    for header, why in SECURITY_HEADERS:
        if header in resp.headers:
            findings.append(f"Header-OK\t{header}: {resp.headers[header]}")
        else:
            findings.append(f"Header-MISSING\t{header}\t{why}")
            missing += 1
    return findings, missing


def _check_directory_listing(session, domain: str):
    findings = []
    exposed = 0
    for path in DIR_CANDIDATES:
        for scheme in ("https", "http"):
            try:
                resp = session.get(f"{scheme}://{domain}{path}", timeout=8, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue
            if resp.status_code == 200 and any(sig in resp.text for sig in LISTING_SIGNATURES):
                findings.append(f"DirListing-EXPOSED\t{scheme}://{domain}{path}")
                exposed += 1
            break  # one successful scheme attempt per path is enough
    return findings, exposed


def run(domain: str, target_path: str) -> dict:
    # Adds the target's login cookie / Authorization header (if set) - own domain only.
    session = auth_ctx.make_session(domain, target_path, USER_AGENT)

    header_findings, missing_count = _check_headers(session, domain)
    dir_findings, exposed_count = _check_directory_listing(session, domain)

    findings = header_findings + dir_findings

    with open(os.path.join(target_path, "web_misconfig.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {
        "findings": findings,
        "count": len(findings),
        "missing_headers": missing_count,
        "exposed_directories": exposed_count,
    }
