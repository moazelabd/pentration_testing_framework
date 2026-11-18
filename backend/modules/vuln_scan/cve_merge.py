"""
CVE Merge - combines the results of the CVE lookup tools into one deduplicated list.

Reads cve_nvd.json and cve_circl.json (whichever exist), merges records that share a CVE
id into one (sources and affected products are combined, the highest CVSS score wins) and
writes cve_merged.json / cve_merged.txt. No network calls.
"""
from . import cve_common as common

BASENAME = "cve_merged"
# order = priority for which source's summary is kept when several have one
SOURCES = [("nvd", "cve_nvd"), ("circl", "cve_circl")]


def get_cached(target_path: str) -> dict:
    return common.read_cached(target_path, BASENAME)


def run(domain: str, target_path: str) -> dict:
    loaded = {}
    for name, base in SOURCES:
        recs = common.read_json(target_path, base)
        if recs is not None:
            loaded[name] = recs

    if not loaded:
        return {"error": "No CVE results to merge yet. Run CVE Lookup (NVD) and/or "
                         "CVE Lookup (CIRCL) first.", "status": 400}

    total_in = sum(len(r) for r in loaded.values())
    merged = common.merge_records(loaded.values())
    removed = total_in - len(merged)
    per_source = ", ".join(f"{n}: {len(r)}" for n, r in loaded.items())

    notes = [f"merged {total_in} record(s) ({per_source}) into {len(merged)} unique CVE(s); "
             f"{removed} duplicate(s) removed"]
    missing = [n for n, _ in SOURCES if n not in loaded]
    if missing:
        notes.append("not run yet: " + ", ".join(missing))

    lines = common.write_results(target_path, BASENAME, list(merged.values()), notes)
    return {"cves": lines, "count": len(merged), "duplicates_removed": removed}
