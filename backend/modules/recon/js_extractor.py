"""
JavaScript File Extractor - PASSIVE, zero network calls.

Merges the JavaScript file URLs discovered by two sources into one
deduplicated js_files.txt worklist for the jsluice phase:

  - katana_urls.txt  - crawler output, incl. the -jc JS-crawl endpoints
  - urldedupe.txt    - deduplicated Wayback Machine URLs (preferred)
  - wayback.txt      - raw Wayback Machine URLs (fallback)

A line qualifies if it ends in .js (including .min.js) or carries .js
followed by a query string (.js?ver=...). Everything else is dropped.

This never contacts the target - it only re-reads data other tools
already collected. Katana output alone is enough to run; the Wayback
sources are merged in automatically when available, so historical .js
files no longer linked anywhere still make it into the analysis.
"""
import os
import re

OUTPUT_FILE = "js_files.txt"

_JS_MENTION = re.compile(r"\.js(?:\?[^ ]*)?$", re.IGNORECASE)

# (file, human-readable source label) - first hit wins for the note,
# but every file present is merged.
_SOURCES = [
    ("katana_urls.txt", "Web Crawler (katana)"),
    ("urldedupe.txt", "URL Dedupe (urldedupe)"),
    ("wayback.txt", "Wayback Machine URLs"),
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, OUTPUT_FILE)
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"js_files": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    available = []
    for fname, label in _SOURCES:
        path = os.path.join(target_path, fname)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            if lines:
                available.append((fname, label, lines))

    if not available:
        return {
            "error": "No katana_urls.txt or wayback.txt found for this target - "
                     "run the Web Crawler (katana) and/or Wayback Machine URLs "
                     "first; this module only filters their output.",
            "status": 400,
        }

    merged = set()
    per_source = []
    for fname, label, lines in available:
        found = {line for line in lines if _JS_MENTION.search(line)}
        merged |= found
        per_source.append(f"{label}: {len(found)}")

    js_files = sorted(merged)

    with open(os.path.join(target_path, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(js_files))

    return {
        "js_files": js_files,
        "count": len(js_files),
        "sources": per_source,
        "note": "Ready for the JS analysis pass - endpoints inside these files "
                "feed the active-testing phase (see all_params.txt).",
    }
