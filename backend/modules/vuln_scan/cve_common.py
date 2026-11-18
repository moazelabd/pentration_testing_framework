"""
Shared helpers for the CVE tools (cve_nvd, cve_circl, cve_merge) - no network here.

What this module does:
  - collect_technologies(): reads techinfo.txt (Tech Fingerprint) and live_hosts.txt
    (httpx -tech-detect) and extracts "product + version" pairs, e.g. nginx 1.18.0.
  - A small product table that maps those names to CPE vendor/product pairs.
  - Version comparison, record formatting, merge/dedupe, and read/write of results.

A CVE "record" is a plain dict:
  {"id": "CVE-2021-41773", "severity": "CRITICAL", "score": 9.8, "summary": "...",
   "published": "2021-10-05T...", "affects": ["apache/http_server 2.4.49"],
   "sources": ["nvd"]}
"""
import json
import os
import re

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# canonical key -> spec.
#   cpe:           candidate (cpe_vendor, cpe_product) pairs to query (nginx has two
#                  because NVD has both the old and the new vendor name)
#   vendor_alias:  normalized words a CVE record may use for the vendor
#   product_alias: normalized words a CVE record may use for the product
PRODUCTS = {
    "nginx": {"cpe": [("f5", "nginx"), ("nginx", "nginx")],
              "vendor_alias": ["f5", "nginx"], "product_alias": ["nginx"]},
    "apache_httpd": {"cpe": [("apache", "http_server")],
                     "vendor_alias": ["apache"],
                     "product_alias": ["httpserver", "apachehttpserver", "apachehttpd", "httpd"]},
    "tomcat": {"cpe": [("apache", "tomcat")], "vendor_alias": ["apache"],
               "product_alias": ["tomcat", "apachetomcat"]},
    "iis": {"cpe": [("microsoft", "internet_information_services")],
            "vendor_alias": ["microsoft"],
            "product_alias": ["internetinformationservices", "iis"]},
    "php": {"cpe": [("php", "php")], "vendor_alias": ["php"], "product_alias": ["php"]},
    "openssl": {"cpe": [("openssl", "openssl")], "vendor_alias": ["openssl"],
                "product_alias": ["openssl"]},
    "wordpress": {"cpe": [("wordpress", "wordpress")], "vendor_alias": ["wordpress"],
                  "product_alias": ["wordpress"]},
    "drupal": {"cpe": [("drupal", "drupal")], "vendor_alias": ["drupal"],
               "product_alias": ["drupal"]},
    "jquery": {"cpe": [("jquery", "jquery")], "vendor_alias": ["jquery"],
               "product_alias": ["jquery"]},
    "bootstrap": {"cpe": [("getbootstrap", "bootstrap"), ("bootstrap", "bootstrap")],
                  "vendor_alias": ["getbootstrap", "bootstrap", "twitter"],
                  "product_alias": ["bootstrap"]},
    "angularjs": {"cpe": [("angularjs", "angular.js")], "vendor_alias": ["angularjs", "google"],
                  "product_alias": ["angularjs", "angular"]},
    "lighttpd": {"cpe": [("lighttpd", "lighttpd")], "vendor_alias": ["lighttpd"],
                 "product_alias": ["lighttpd"]},
    "litespeed": {"cpe": [("litespeedtech", "litespeed_web_server")],
                  "vendor_alias": ["litespeedtech", "litespeed"],
                  "product_alias": ["litespeedwebserver", "litespeed"]},
    "jetty": {"cpe": [("eclipse", "jetty")], "vendor_alias": ["eclipse"],
              "product_alias": ["jetty"]},
    "haproxy": {"cpe": [("haproxy", "haproxy")], "vendor_alias": ["haproxy"],
                "product_alias": ["haproxy"]},
    "squid": {"cpe": [("squid-cache", "squid")], "vendor_alias": ["squidcache", "squid"],
              "product_alias": ["squid"]},
    "nodejs": {"cpe": [("nodejs", "node.js")], "vendor_alias": ["nodejs"],
               "product_alias": ["nodejs"]},
}

# name seen in a banner / httpx tech list (lowercase) -> canonical key
ALIASES = {
    "nginx": "nginx",
    "apache": "apache_httpd", "apache httpd": "apache_httpd", "apache http server": "apache_httpd",
    "httpd": "apache_httpd",
    "tomcat": "tomcat", "apache tomcat": "tomcat",
    "microsoft-iis": "iis", "microsoft iis": "iis", "iis": "iis",
    "php": "php", "openssl": "openssl", "wordpress": "wordpress", "drupal": "drupal",
    "jquery": "jquery", "bootstrap": "bootstrap", "angularjs": "angularjs", "angular.js": "angularjs",
    "lighttpd": "lighttpd", "litespeed": "litespeed", "jetty": "jetty", "haproxy": "haproxy",
    "squid": "squid", "node.js": "nodejs", "nodejs": "nodejs",
}

_BANNER_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.+\-]*)/(\d+(?:\.\d+){1,3})")
_HTTPX_TECH_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.+ \-]*?):(\d+(?:\.\d+){1,3})")
_GENERATOR_RE = re.compile(r"([A-Za-z][A-Za-z .+_\-]*?)\s+v?(\d+(?:\.\d+){1,3})")


def norm(text) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


# ------------------------------------------------------------------ technologies

def _read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\r\n") for line in f]


def collect_technologies(target_path: str):
    """Returns (technologies, skipped).

    technologies: [{"name", "version", "key", "source"}] - only products we can map to a CPE.
    skipped:      ["name version", ...] - versioned products we have no CPE mapping for.
    """
    found = []  # (raw_name, version, source)

    for line in _read_lines(os.path.join(target_path, "techinfo.txt")):
        kind, _, value = line.partition("\t")
        if kind == "Header":
            header, _, hval = value.partition(":")
            hval = hval.strip()
            if header.strip().lower() == "x-aspnet-version":
                continue  # bare version with no product name we can map reliably
            for name, ver in _BANNER_RE.findall(hval):
                found.append((name, ver, "techinfo"))
        elif kind == "Meta-generator":
            for name, ver in _GENERATOR_RE.findall(value):
                found.append((name.strip(), ver, "techinfo"))

    for line in _read_lines(os.path.join(target_path, "live_hosts.txt")):
        # "https://sub.example.com [200] [Title] [Nginx:1.18.0,PHP:7.4.3]" - skip the URL itself
        _, _, rest = line.partition(" ")
        for name, ver in _HTTPX_TECH_RE.findall(rest):
            found.append((name.strip(), ver, "httpx"))

    techs, skipped, seen = [], [], set()
    for name, ver, source in found:
        key = ALIASES.get(name.strip().lower())
        label = f"{name.strip()} {ver}"
        if key is None:
            if label not in skipped:
                skipped.append(label)
            continue
        if (key, ver) in seen:
            continue
        seen.add((key, ver))
        techs.append({"name": name.strip(), "version": ver, "key": key, "source": source})
    return techs, skipped


# ------------------------------------------------------------------ versions

def vtuple(version) -> tuple:
    parts = []
    for seg in re.split(r"[.\-_]", str(version or "").strip()):
        m = re.match(r"\d+", seg)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def vcmp(a, b) -> int:
    ta, tb = vtuple(a), vtuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def in_range(version, start=None, start_incl=True, end=None, end_incl=False) -> bool:
    if start not in (None, "", "0", "-", "*"):
        c = vcmp(version, start)
        if c < 0 or (c == 0 and not start_incl):
            return False
    if end not in (None, "", "*", "-"):
        c = vcmp(version, end)
        if c > 0 or (c == 0 and not end_incl):
            return False
    return True


# ------------------------------------------------------------------ severity / metrics

def severity_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return None


def best_nvd_metric(metrics):
    """NVD-style metrics dict -> (score, severity). Prefers the newest CVSS version."""
    metrics = metrics or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr and isinstance(arr[0], dict):
            data = arr[0].get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity")
            sev = str(sev).upper() if sev else severity_from_score(score)
            return score, sev
    return None, None


# ------------------------------------------------------------------ records / merge

def new_record(cve_id, severity, score, summary, published, affects, source):
    return {
        "id": cve_id.upper(),
        "severity": severity,
        "score": score,
        "summary": " ".join(str(summary or "").split()),
        "published": published or "",
        "affects": list(affects),
        "sources": [source],
    }


def merge_records(record_lists):
    """Merge several lists of records into {cve_id: record}, removing duplicates.

    Same CVE id -> one record: sources and affected products are unioned, the highest
    score wins, and the first non-empty summary is kept (list order = priority).
    """
    merged = {}
    for records in record_lists:
        for rec in records:
            cur = merged.get(rec["id"])
            if cur is None:
                merged[rec["id"]] = {**rec, "affects": list(rec["affects"]), "sources": list(rec["sources"])}
                continue
            cur["sources"] = sorted(set(cur["sources"]) | set(rec["sources"]))
            cur["affects"] = sorted(set(cur["affects"]) | set(rec["affects"]))
            if rec.get("score") is not None and (cur.get("score") is None or rec["score"] > cur["score"]):
                cur["score"] = rec["score"]
                cur["severity"] = rec.get("severity") or severity_from_score(rec["score"])
            elif not cur.get("severity") and rec.get("severity"):
                cur["severity"] = rec["severity"]
            if not cur.get("summary") and rec.get("summary"):
                cur["summary"] = rec["summary"]
            if rec.get("published") and (not cur.get("published") or rec["published"] < cur["published"]):
                cur["published"] = rec["published"]
    return merged


def sort_records(records):
    return sorted(records, key=lambda r: (-(r.get("score") if r.get("score") is not None else -1),
                                          -SEVERITY_RANK.get(r.get("severity") or "", 0), r["id"]))


def format_line(rec) -> str:
    sev = rec.get("severity") or "N/A"
    score = f"{rec['score']:.1f}" if isinstance(rec.get("score"), (int, float)) else "-"
    summary = rec.get("summary", "")
    if len(summary) > 220:
        summary = summary[:217] + "..."
    return (f"{rec['id']}\t{sev} {score}\t{', '.join(rec['affects'])}\t"
            f"({', '.join(sorted(rec['sources']))})\t{summary}")


# ------------------------------------------------------------------ files

def write_results(target_path, basename, records, notes):
    """Writes <basename>.json (records, for the merge step) and <basename>.txt (display)."""
    records = sort_records(records)
    with open(os.path.join(target_path, basename + ".json"), "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    lines = [format_line(r) for r in records]
    if notes:
        lines.append("")
        lines.extend(f"# {n}" for n in notes)
    with open(os.path.join(target_path, basename + ".txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return lines


def read_json(target_path, basename):
    path = os.path.join(target_path, basename + ".json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else None
    except (OSError, ValueError):
        return None


def read_cached(target_path, basename):
    path = os.path.join(target_path, basename + ".txt")
    ran = os.path.isfile(path)
    lines = []
    if ran:
        with open(path, "r", encoding="utf-8") as f:
            lines = [ln.rstrip("\r\n") for ln in f if ln.strip()]
    count = sum(1 for ln in lines if ln.upper().startswith("CVE-"))
    return {"cves": lines, "count": count, "ran": ran}
