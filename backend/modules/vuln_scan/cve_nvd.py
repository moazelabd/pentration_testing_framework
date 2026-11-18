"""
CVE Lookup (NVD) - PASSIVE toward the target. Queries NIST's public NVD API.

Reads the product + version pairs found by Tech Fingerprint (techinfo.txt) and Live Host
Probe (live_hosts.txt), asks NVD which CVEs apply to each exact version, and saves them
to cve_nvd.json / cve_nvd.txt. Nothing is sent to the target itself.

NVD allows ~5 requests per 30 seconds without an API key, so the tool waits ~6.5s
between requests. Set the NVD_API_KEY environment variable (free key from nvd.nist.gov)
to go ~8x faster.
"""
import os
import time
import urllib.parse

import requests

from . import cve_common as common

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BASENAME = "cve_nvd"
PAGE_SIZE = 200
MAX_PAGES = 3        # per product query -> at most 600 CVEs per product version
MAX_QUERIES = 14     # keeps one run from taking many minutes
USER_AGENT = "recon-framework/1.0"


def get_cached(target_path: str) -> dict:
    return common.read_cached(target_path, BASENAME)


def _delay() -> float:
    return 0.8 if os.environ.get("NVD_API_KEY") else 6.5


def _get(session, cpe, start):
    headers = {"User-Agent": USER_AGENT}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    base = (f"{NVD_URL}?cpeName={urllib.parse.quote(cpe, safe=':*')}"
            f"&resultsPerPage={PAGE_SIZE}&startIndex={start}")
    # isVulnerable = only CVEs where this product itself is the vulnerable one
    resp = session.get(base + "&isVulnerable", headers=headers, timeout=60)
    if resp.status_code == 400:
        resp = session.get(base, headers=headers, timeout=60)
    return resp


def _parse(cve: dict, affects: str):
    cve_id = cve.get("id")
    if not cve_id:
        return None
    desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, severity = common.best_nvd_metric(cve.get("metrics"))
    return common.new_record(cve_id, severity, score, desc, cve.get("published"), [affects], "nvd")


def run(domain: str, target_path: str) -> dict:
    techs, skipped = common.collect_technologies(target_path)
    if not techs:
        return {
            "error": "No versioned technologies found to look up. Run Tech Fingerprint or "
                     "Live Host Probe first. Targets behind a CDN (e.g. Cloudflare) usually "
                     "hide their server version, so there may be nothing to match.",
            "status": 400,
        }

    session = requests.Session()
    found = {}
    notes, analyzed = [], []
    queries = attempted_ok = 0
    stop = False

    for tech in techs:
        if stop:
            break
        spec = common.PRODUCTS[tech["key"]]
        for vendor, product in spec["cpe"]:
            if stop:
                break
            if queries >= MAX_QUERIES:
                notes.append(f"stopped after {MAX_QUERIES} NVD queries - run again for the rest")
                stop = True
                break
            label = f"{vendor}/{product} {tech['version']}"
            cpe = f"cpe:2.3:a:{vendor}:{product}:{tech['version']}:*:*:*:*:*:*:*"
            start, hits = 0, 0
            for _ in range(MAX_PAGES):
                if queries:
                    time.sleep(_delay())
                queries += 1
                try:
                    resp = _get(session, cpe, start)
                except requests.exceptions.RequestException as e:
                    notes.append(f"{label}: could not reach NVD ({type(e).__name__})")
                    break
                if resp.status_code in (403, 429):
                    notes.append(f"NVD rate-limited the request (HTTP {resp.status_code}) - "
                                 "stopped; wait a minute or set NVD_API_KEY")
                    stop = True
                    break
                if resp.status_code == 404:
                    attempted_ok += 1
                    break  # this exact CPE isn't in NVD's dictionary - normal for rare versions
                if not resp.ok:
                    notes.append(f"{label}: NVD returned HTTP {resp.status_code}")
                    break
                try:
                    data = resp.json()
                except ValueError:
                    notes.append(f"{label}: NVD returned a non-JSON response")
                    break
                attempted_ok += 1
                for item in data.get("vulnerabilities", []):
                    rec = _parse(item.get("cve", {}), f"{vendor}/{product} {tech['version']}")
                    if rec:
                        hits += 1
                        found.setdefault(rec["id"], []).append(rec)
                start += PAGE_SIZE
                if start >= int(data.get("totalResults", 0)):
                    break
            analyzed.append(f"{label} ({tech['source']}): {hits} CVE(s)")

    if not attempted_ok:
        return {"error": "NVD could not be reached or rate-limited every request. "
                         + "; ".join(notes[:3]), "status": 502}

    merged = common.merge_records(found.values())
    records = list(merged.values())
    out_notes = [f"analyzed: {a}" for a in analyzed] + notes
    if skipped:
        out_notes.append("no CPE mapping (skipped): " + ", ".join(skipped[:15]))
    lines = common.write_results(target_path, BASENAME, records, out_notes)
    return {"cves": lines, "count": len(records)}
