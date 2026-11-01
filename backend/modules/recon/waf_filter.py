"""
WAF Filter (split by WAF presence) - PASSIVE, zero network calls.

Reads waf_summary.txt (from waf_detect.py) and splits the hosts into:

  - hosts_with_waf.txt - WAF-protected; handle with care during active
    testing (probe lightly, prioritize less)
  - hosts_no_waf.txt   - unfiltered - prio prime marks for the XSS
    Prober and future vuln_scan modules

This never contacts the target - it only re-reads data wafw00f already
collected, so run the WAF Detection module first.
"""
import os

WITH_WAF = "hosts_with_waf.txt"
NO_WAF = "hosts_no_waf.txt"


def get_cached(target_path: str) -> dict:
    with_path = os.path.join(target_path, WITH_WAF)
    no_path = os.path.join(target_path, NO_WAF)
    ran = os.path.isfile(with_path) or os.path.isfile(no_path)

    hosts_with, hosts_without = [], []
    if os.path.isfile(with_path):
        with open(with_path, "r", encoding="utf-8") as f:
            hosts_with = [line.strip() for line in f if line.strip()]
    if os.path.isfile(no_path):
        with open(no_path, "r", encoding="utf-8") as f:
            hosts_without = [line.strip() for line in f if line.strip()]

    return {
        "with_waf": hosts_with,
        "no_waf": hosts_without,
        "with_waf_count": len(hosts_with),
        "no_waf_count": len(hosts_without),
        "ran": ran,
    }


def _parse_summary(target_path: str):
    summary_path = os.path.join(target_path, "waf_summary.txt")
    if not os.path.isfile(summary_path):
        return None
    entries = []
    with open(summary_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                continue  # tolerate malformed rows rather than crash
            url, waf, detected = parts
            entries.append((url, waf, detected.lower() == "yes"))
    return entries


def run(domain: str, target_path: str) -> dict:
    entries = _parse_summary(target_path)
    if entries is None:
        return {
            "error": "No waf_summary.txt found for this target - run the WAF "
                     "Detection (wafw00f) module first; this module only "
                     "splits its output.",
            "status": 400,
        }
    if not entries:
        return {"error": "waf_summary.txt has no result rows - wafw00f found "
                         "nothing to split.", "status": 400}

    hosts_with = [url for url, _, detected in entries if detected]
    hosts_without = [url for url, _, detected in entries if not detected]

    for filename, hosts in [(WITH_WAF, hosts_with), (NO_WAF, hosts_without)]:
        result_path = os.path.join(target_path, filename)
        if os.path.isfile(result_path):
            os.remove(result_path)  # clear stale lists before rewriting
        if hosts:
            with open(result_path, "w", encoding="utf-8") as f:
                f.write("\n".join(hosts))

    return {
        "with_waf": hosts_with,
        "no_waf": hosts_without,
        "with_waf_count": len(hosts_with),
        "no_waf_count": len(hosts_without),
        "split": len(entries),
        "note": "hosts_no_waf.txt is the safe list for active testing; treat "
                "hosts_with_waf.txt entries carefully (they may block probes).",
    }
