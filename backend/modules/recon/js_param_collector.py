"""
JS Parameter Collector - PASSIVE, zero network calls (pure file merge).

Aggregates every parameterized URL discovered during the JS-analysis
phase into the shared all_params.txt worklist for the next phase
(gf filtering, XSS prober, vuln_scan):

  - jsluice_urls.txt  - URLs/params extracted from JS source
                        (fetch calls, redirects, API paths)
  - katana_urls.txt   - crawler output (has its own forms/JS endpoints)
  - all_params.txt    - keeps whatever param_collector.py (the earlier
                        subfinder+urldedupe merge) already wrote, so the
                        two collectors compose instead of clobbering

Filter: only lines containing '?' (actual `?id=1`-style URLs) survive;
everything is deduplicated and written back to all_params.txt.

Run jsluice urls (and ideally katana) first - otherwise there is
nothing new to add (it still refuses to run blind: it wants all_params
to exist or at least one source file).
"""
import os

OUTPUT_FILE = "all_params.txt"


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, OUTPUT_FILE)
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def _read_lines(path: str) -> list:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def run(domain: str, target_path: str) -> dict:
    jsluice_path = os.path.join(target_path, "jsluice_urls.txt")
    katana_path = os.path.join(target_path, "katana_urls.txt")
    existing_path = os.path.join(target_path, OUTPUT_FILE)

    jsluice_urls = _read_lines(jsluice_path)
    katana_urls = _read_lines(katana_path)
    existing = _read_lines(existing_path)

    if not jsluice_urls and not katana_urls and not existing:
        return {
            "error": "Nothing to aggregate yet - run the Katana Crawler (+ jsluice "
                     "urls) first. This module merges their parameterized URLs "
                     "into all_params.txt.",
            "status": 400,
        }

    sources = {
        "jsluice": len(jsluice_urls),
        "katana": len(katana_urls),
        "collected_existing": len(existing),  # kept so the two collectors compose
    }

    # Order-preserving dedupe, then keep only true parameterized URLs.
    combined = list(dict.fromkeys(existing + jsluice_urls + katana_urls))
    param_urls = sorted({line for line in combined if "?" in line})

    with open(os.path.join(target_path, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(param_urls))

    return {
        "urls": param_urls,
        "count": len(param_urls),
        "combined": len(combined),
        "sources": sources,
        "note": "Ready for the active-testing phase (gf / XSS Prober / vuln_scan).",
    }
