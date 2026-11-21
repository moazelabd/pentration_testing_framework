"""
SQL Injection Error-Based Prober - ACTIVE.

Takes the URLs tagged "sqli" by url_pattern_filter.py (url_patterns.txt)
and, for each query parameter, appends a syntax-breaking payload (a
quote, a boolean trick), then checks the response body for a well-known
database error signature (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) -
the same baseline check error-based SQLi tools start from.

A matched signature is a SIGNAL of a possible SQL injection, not proof -
the app may just echo a generic error page, or the input may reach a
query that isn't actually exploitable. Verify manually, within your
authorized scope, before reporting it as a confirmed finding.

This sends real, crafted requests to the target - authorized targets
only. Run "URL Pattern Filter" first.
"""
import os
import re
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import requests

from modules import auth_ctx

USER_AGENT = "recon-framework/1.0"
# Error-based payloads: checked against ERROR_SIGNATURES below.
ERROR_PROBES = ["'", "\""]
# Boolean-blind pair: these never raise a DB error, so they were previously
# wasted requests - a TRUE condition and a FALSE condition are compared
# against each other below instead.
TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"
# A FALSE response at least this much shorter than the TRUE response (with
# the TRUE response itself not looking like a hard error) is the classic
# boolean-blind signal: the query silently returns fewer/no rows.
BOOLEAN_DIFF_THRESHOLD = 0.15
MAX_REQUESTS = 150

ERROR_SIGNATURES = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft sql server", "MSSQL"),
    (r"pg_query\(\)|postgresql.*error|org\.postgresql", "PostgreSQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"sqlite3\.operationalerror|sqlite_error|near \".*\":\s*syntax error", "SQLite"),
    (r"syntax error at or near", "PostgreSQL/SQL"),
]
_COMPILED = [(re.compile(pat, re.I), label) for pat, label in ERROR_SIGNATURES]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "sqli_probe.txt")
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
            if "sqli" in tags:
                urls.append(url)
    return urls


def _build_probe_url(url: str, param: str, params: dict, payload: str) -> str:
    parts = urlsplit(url)
    new_params = {k: (v[0] if v else "") for k, v in params.items()}
    new_params[param] = new_params.get(param, "") + payload
    new_query = urlencode(new_params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def _match_signature(text: str):
    for pattern, label in _COMPILED:
        if pattern.search(text):
            return label
    return None


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

            matched_db = None
            matched_url = None
            for probe in ERROR_PROBES:
                if tested >= MAX_REQUESTS:
                    break
                probe_url = _build_probe_url(url, param, params, probe)
                tested += 1
                try:
                    resp = session.get(probe_url, timeout=8, allow_redirects=True)
                except requests.exceptions.RequestException:
                    continue
                db = _match_signature(resp.text)
                if db:
                    matched_db = db
                    matched_url = probe_url
                    break

            if matched_db:
                findings.append(f"POSSIBLE SQLi ({matched_db})\tparam={param}\t{matched_url}")
                continue

            # No error signature - try the boolean-blind pair instead of
            # discarding these two requests (they never raise a DB error,
            # so the error-signature check alone could never catch them).
            if tested + 2 > MAX_REQUESTS:
                continue
            true_url = _build_probe_url(url, param, params, TRUE_PAYLOAD)
            false_url = _build_probe_url(url, param, params, FALSE_PAYLOAD)
            tested += 2
            try:
                true_resp = session.get(true_url, timeout=8, allow_redirects=True)
                false_resp = session.get(false_url, timeout=8, allow_redirects=True)
            except requests.exceptions.RequestException:
                continue
            if _match_signature(true_resp.text) or _match_signature(false_resp.text):
                continue  # already covered by the error-based path above
            true_len, false_len = len(true_resp.text), len(false_resp.text)
            if true_len == 0:
                continue
            relative_diff = abs(true_len - false_len) / true_len
            if true_resp.status_code == false_resp.status_code and relative_diff >= BOOLEAN_DIFF_THRESHOLD:
                findings.append(f"POSSIBLE SQLi (boolean-blind)\tparam={param}\t{true_url}")

    with open(os.path.join(target_path, "sqli_probe.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {"findings": findings, "count": len(findings), "tested": tested}
