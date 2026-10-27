"""
XSS Reflection Prober (dalfox-inspired) - ACTIVE.

Takes the URLs tagged "xss" by url_pattern_filter.py (url_patterns.txt)
and, for each query parameter, replaces its value with a distinctive
marker containing HTML-significant characters, then checks whether that
marker comes back UNESCAPED in the response body - the same core
detection technique dalfox and kxss use for reflected-XSS discovery.

An unescaped reflection is a strong SIGNAL of a reflected-XSS candidate,
not proof of exploitability, and this never injects or executes an
actual <script> payload - verify and go further manually, within your
authorized scope, before reporting it as a confirmed finding.

This sends real, crafted requests to the target - authorized targets
only. Run "URL Pattern Filter" first (which itself needs Wayback Machine
URLs run before it).
"""
import os
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

USER_AGENT = "recon-framework/1.0"
MARKER = "zXzPoC1"
PROBE_SUFFIX = "'\"><"
PROBE_STRING = MARKER + PROBE_SUFFIX
MAX_REQUESTS = 150  # bounds worst-case runtime on a target with many candidate URLs/params


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "xss_probe.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _xss_candidate_urls(target_path: str):
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
            if "xss" in tags:
                urls.append(url)
    return urls


def _build_probe_url(url: str, param: str, params: dict) -> str:
    parts = urlsplit(url)
    new_params = {k: (v[0] if v else "") for k, v in params.items()}
    new_params[param] = PROBE_STRING
    new_query = urlencode(new_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def run(domain: str, target_path: str) -> dict:
    candidates = _xss_candidate_urls(target_path)
    if candidates is None:
        return {
            "error": "No url_patterns.txt found - run 'URL Pattern Filter' first "
                     "(which itself needs Wayback Machine URLs run before it).",
            "status": 400,
        }
    if not candidates:
        return {"findings": [], "count": 0, "tested": 0}

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

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
            probe_url = _build_probe_url(url, param, params)
            tested += 1
            try:
                resp = session.get(probe_url, timeout=8, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue

            if PROBE_STRING in resp.text:
                findings.append(f"UNESCAPED (investigate)\tparam={param}\t{probe_url}")
            elif MARKER in resp.text:
                findings.append(f"escaped (likely safe)\tparam={param}\t{probe_url}")

    with open(os.path.join(target_path, "xss_probe.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {"findings": findings, "count": len(findings), "tested": tested}
