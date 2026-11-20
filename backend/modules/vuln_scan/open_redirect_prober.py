"""
Open Redirect Prober - ACTIVE.

Takes the URLs tagged "redirect" by url_pattern_filter.py (url_patterns.txt)
and, for each query parameter, replaces its value with an external marker
domain, then checks (without following the redirect) whether the server
sends the browser straight there - the same core idea as tools like
Oralyzer.

Detection: request with allow_redirects=False and inspect the Location
header on a 3xx response for the marker domain, which means the app is
building the redirect destination directly from user-controlled input
without validating it against an allowlist.

This is a SIGNAL, not proof of real-world impact (some "open redirects"
only matter when chained with something else) - verify manually before
reporting it. Sends real, crafted requests to the target - authorized
targets only. Run "URL Pattern Filter" first.
"""
import os
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

from modules import auth_ctx

USER_AGENT = "recon-framework/1.0"
MARKER_DOMAIN = "evil-redirect-poc.example"
PROBE_VALUES = [f"https://{MARKER_DOMAIN}/", f"//{MARKER_DOMAIN}/", f"https:{MARKER_DOMAIN}"]
MAX_REQUESTS = 150


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "open_redirect_probe.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _candidate_urls(target_path: str):
    """Returns None if url_pattern_filter hasn't been run yet, else a list."""
    patterns_path = os.path.join(target_path, "url_patterns.txt")
    if not os.path.isfile(patterns_path):
        return None
    urls = []
    with open(patterns_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            url, tags = line.split("\t", 1)
            if "redirect" in tags:
                urls.append(url)
    return urls


def _build_probe_url(url: str, param: str, params: dict, value: str) -> str:
    parts = urlsplit(url)
    new_params = {k: (v[0] if v else "") for k, v in params.items()}
    new_params[param] = value
    new_query = urlencode(new_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def run(domain: str, target_path: str) -> dict:
    candidates = _candidate_urls(target_path)
    if candidates is None:
        return {
            "error": "No url_patterns.txt found - run 'URL Pattern Filter' first "
                     "(which itself needs Wayback Machine URLs run before it).",
            "status": 400,
        }
    if not candidates:
        return {"findings": [], "count": 0, "tested": 0}

    # Adds the target's login cookie / Authorization header (if set) - own domain only.
    session = auth_ctx.make_session(domain, target_path, USER_AGENT)

    findings = []
    tested = 0

    for url in candidates:
        if tested >= MAX_REQUESTS:
            break
        parts = urlsplit(url)
        params = parse_qs(parts.query)
        for param in list(params.keys()):
            if tested >= MAX_REQUESTS:
                break

            matched_value = None
            for value in PROBE_VALUES:
                if tested >= MAX_REQUESTS:
                    break
                probe_url = _build_probe_url(url, param, params, value)
                tested += 1
                try:
                    resp = session.get(probe_url, timeout=8, allow_redirects=False)
                except requests.exceptions.RequestException:
                    continue
                location = resp.headers.get("Location", "")
                if MARKER_DOMAIN in location:
                    matched_value = probe_url
                    break

            if matched_value:
                findings.append(f"VULNERABLE (open redirect)\tparam={param}\t{matched_value}")

    with open(os.path.join(target_path, "open_redirect_probe.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {"findings": findings, "count": len(findings), "tested": tested}
