"""
CVE Lookup (CIRCL) - PASSIVE toward the target. Queries CIRCL's public Vulnerability-Lookup.

Second, independent source next to cve_nvd.py. CIRCL searches by vendor/product (not by
version), so this tool downloads the CVEs of each product and keeps only those whose
affected-version ranges include the version found on the target.
Results go to cve_circl.json / cve_circl.txt; run "CVE Merge" to combine with NVD.
"""
import time

import requests

from . import cve_common as common

SEARCH_URL = "https://vulnerability.circl.lu/api/vulnerability/search/{vendor}/{product}"
BASENAME = "cve_circl"
PER_PAGE = 100
MAX_PAGES = 10
DELAY = 0.5
USER_AGENT = "recon-framework/1.0"


def get_cached(target_path: str) -> dict:
    return common.read_cached(target_path, BASENAME)


# ------------------------------------------------------------------ response handling

def _unwrap(payload):
    """The list of records can arrive as {"data": [...]}, a bare list, and each item as a
    dict or a (source, dict) pair - accept all of them."""
    items = payload
    if isinstance(payload, dict):
        items = payload.get("data")
        if items is None:
            items = payload.get("results", [])
    out = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(it)
        elif isinstance(it, (list, tuple)) and len(it) >= 2 and isinstance(it[1], dict):
            out.append(it[1])
    return out


def _fetch_product(session, vendor, product, notes):
    records, page = [], 1
    while page <= MAX_PAGES:
        try:
            resp = session.get(SEARCH_URL.format(vendor=vendor, product=product),
                               params={"page": page, "per_page": PER_PAGE},
                               headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                               timeout=60)
        except requests.exceptions.RequestException as e:
            notes.append(f"{vendor}/{product}: could not reach CIRCL ({type(e).__name__})")
            return records, False
        if resp.status_code == 404:
            return records, True  # CIRCL knows nothing about this vendor/product
        if not resp.ok:
            notes.append(f"{vendor}/{product}: CIRCL returned HTTP {resp.status_code}")
            return records, False
        try:
            payload = resp.json()
        except ValueError:
            notes.append(f"{vendor}/{product}: CIRCL returned a non-JSON response")
            return records, False
        batch = _unwrap(payload)
        records.extend(batch)
        total = None
        if isinstance(payload, dict) and isinstance(payload.get("metadata"), dict):
            total = payload["metadata"].get("count")
        if len(batch) < PER_PAGE or (isinstance(total, int) and page * PER_PAGE >= total):
            return records, True
        page += 1
        time.sleep(DELAY)
    notes.append(f"{vendor}/{product}: only the first {MAX_PAGES * PER_PAGE} CVEs were checked")
    return records, True


def _cve_id(rec):
    body = rec.get("cve") if isinstance(rec.get("cve"), dict) else rec
    cid = (rec.get("cveMetadata") or {}).get("cveId") or body.get("id") or ""
    cid = str(cid).upper()
    return cid if cid.startswith("CVE-") else None


# ------------------------------------------------------------------ version matching

def _cve5_affected(rec):
    containers = rec.get("containers") or {}
    items = list((containers.get("cna") or {}).get("affected") or [])
    for adp in containers.get("adp") or []:
        items.extend(adp.get("affected") or [])
    return items


def _cve5_matches(rec, spec, version) -> bool:
    for aff in _cve5_affected(rec):
        pnorm = common.norm(aff.get("product"))
        vnorm = common.norm(aff.get("vendor"))
        if pnorm not in spec["product_alias"]:
            continue
        if vnorm and not any(a in vnorm for a in spec["vendor_alias"]):
            continue
        for v in aff.get("versions") or []:
            if str(v.get("status", "affected")).lower() != "affected":
                continue
            low = str(v.get("version", "") or "")
            less, less_eq = v.get("lessThan"), v.get("lessThanOrEqual")
            if less or less_eq:
                if common.in_range(version, low, True, less or less_eq, bool(less_eq)):
                    return True
            elif low.endswith(("*", ".x")):
                if common.vtuple(version)[:len(common.vtuple(low))] == common.vtuple(low):
                    return True
            elif low and common.vtuple(low) and common.vcmp(version, low) == 0:
                return True
    return False


def _nvd_format_matches(rec, spec, version) -> bool:
    body = rec.get("cve") if isinstance(rec.get("cve"), dict) else rec
    for conf in body.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable", True):
                    continue
                parts = str(m.get("criteria", "")).split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue
                if (parts[3], parts[4]) not in spec["cpe"]:
                    continue
                cver = parts[5]
                s_in, s_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
                e_in, e_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
                if s_in or s_ex or e_in or e_ex:
                    if common.in_range(version, s_in or s_ex, bool(s_in), e_in or e_ex, bool(e_in)):
                        return True
                elif cver in ("*", "-"):
                    return True
                elif common.vcmp(version, cver) == 0:
                    return True
    return False


def _matches(rec, spec, version) -> bool:
    return _cve5_matches(rec, spec, version) or _nvd_format_matches(rec, spec, version)


# ------------------------------------------------------------------ record fields

def _cve5_metric(rec):
    containers = rec.get("containers") or {}
    blocks = list((containers.get("cna") or {}).get("metrics") or [])
    for adp in containers.get("adp") or []:
        blocks.extend(adp.get("metrics") or [])
    best = (None, None)
    for block in blocks:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            d = block.get(key)
            if isinstance(d, dict) and d.get("baseScore") is not None:
                if best[0] is None or d["baseScore"] > best[0]:
                    sev = d.get("baseSeverity")
                    best = (d["baseScore"], str(sev).upper() if sev else common.severity_from_score(d["baseScore"]))
    return best


def _to_record(rec, cve_id, affects):
    body = rec.get("cve") if isinstance(rec.get("cve"), dict) else rec
    score, severity = _cve5_metric(rec)
    if score is None:
        score, severity = common.best_nvd_metric(body.get("metrics"))
    cna = (rec.get("containers") or {}).get("cna") or {}
    descs = cna.get("descriptions") or body.get("descriptions") or []
    summary = next((d.get("value", "") for d in descs
                    if str(d.get("lang", "en")).lower().startswith("en")), "")
    published = (rec.get("cveMetadata") or {}).get("datePublished") or body.get("published") or ""
    return common.new_record(cve_id, severity, score, summary, published, [affects], "circl")


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
    cache, notes, analyzed = {}, [], []
    found = {}
    reached = 0

    for tech in techs:
        spec = common.PRODUCTS[tech["key"]]
        hits = 0
        for vendor, product in spec["cpe"]:
            if (vendor, product) not in cache:
                cache[(vendor, product)] = _fetch_product(session, vendor, product, notes)
            records, ok = cache[(vendor, product)]
            if ok:
                reached += 1
            affects = f"{vendor}/{product} {tech['version']}"
            for rec in records:
                cid = _cve_id(rec)
                if cid and _matches(rec, spec, tech["version"]):
                    hits += 1
                    found.setdefault(cid, []).append(_to_record(rec, cid, affects))
        fetched = sum(len(cache[p][0]) for p in spec["cpe"] if p in cache)
        analyzed.append(f"{tech['key']} {tech['version']} ({tech['source']}): "
                        f"{fetched} CIRCL record(s) checked, {hits} matched the version")

    if not reached:
        return {"error": "CIRCL could not be reached. " + "; ".join(notes[:3]), "status": 502}

    merged = common.merge_records(found.values())
    records = list(merged.values())
    out_notes = [f"analyzed: {a}" for a in analyzed] + notes
    if skipped:
        out_notes.append("no CPE mapping (skipped): " + ", ".join(skipped[:15]))
    lines = common.write_results(target_path, BASENAME, records, out_notes)
    return {"cves": lines, "count": len(records)}
