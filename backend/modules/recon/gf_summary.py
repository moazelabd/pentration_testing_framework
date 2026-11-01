"""
GF Summary Report - PASSIVE, zero network calls.

Walks the target folder's gf_*.txt category files (written by the GF
Parameter Filtering module and by the older gf_extractor.py) and
produces a one-glance report gf_summary.txt:

    # gf summary - example.com
    xss: 12
    sqli: 8
    ...

plus a compact "worst categories" note (rce/sqli/xss dominate the
attack-surface view). Exposed via its own API route so the frontend
can render the counts as badges without re-reading every file.

Run the GF Parameter Filtering first - with no gf_*.txt files there is
nothing to summarize.
"""
import os

SUMMARY_FILE = "gf_summary.txt"
CRITICAL = ["rce", "sqli", "xss"]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, SUMMARY_FILE)
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    # skip header lines when re-deriving counts from the cached report
    counts = {}
    for line in lines:
        if line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().strip("-").strip()
        value = value.strip()
        if name and value.isdigit():
            counts[name] = counts.get(name, 0) + int(value)
    return {"summary": lines, "counts": counts, "ran": ran}


def _category_files(target_path: str) -> dict:
    """pattern name -> line count, for every gf_*.txt present."""
    counts = {}
    for name in sorted(os.listdir(target_path)):
        if not (name.startswith("gf_") and name.endswith(".txt")):
            continue
        path = os.path.join(target_path, name)
        with open(path, "r", encoding="utf-8") as f:
            hits = [line for line in f if line.strip()]
        counts[name[len("gf_"):-len(".txt")]] = len(hits)
    return counts


def run(domain: str, target_path: str) -> dict:
    counts = _category_files(target_path)
    if not counts:
        return {
            "error": "No gf_*.txt files found for this target - run the GF "
                     "Parameter Filtering (or the older gf module) first.",
            "status": 400,
        }

    total = sum(counts.values())
    lines = [f"# gf summary - {domain}"]
    lines.extend(f"{pattern}: {count}" for pattern, count in sorted(counts.items()))
    hot = [p for p in CRITICAL if counts.get(p, 0) > 0]
    if hot:
        lines.append(f"# priority review: {', '.join(sorted(hot))}")

    with open(os.path.join(target_path, SUMMARY_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {
        "summary": lines,
        "counts": counts,
        "total": total,
        "priority": sorted(hot),
        "note": "rce/sqli/xss categories are the usual first thing to "
                "manually triage.",
    }
