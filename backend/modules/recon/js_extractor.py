"""
JavaScript File Extractor - PASSIVE, zero network calls.

Reads katana_urls.txt (from katana_crawl.py, including the -jc JS-crawl
endpoints) and keeps only JavaScript file URLs - the attack surface the
crawling phase was run for: js files can hide API routes, parameter
names and dead code pointing at removed panels.

A line qualifies if it ends in .js (including .min.js) or carries .js
followed by a query string (.js?ver=...). Everything else is dropped.

This never contacts the target - it only re-reads data katana already
collected, so run the Katana Crawler first.
"""
import os
import re

OUTPUT_FILE = "js_files.txt"

_JS_MENTION = re.compile(r"\.js(?:\?[^ ]*)?$", re.IGNORECASE)


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, OUTPUT_FILE)
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"js_files": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    katana_path = os.path.join(target_path, "katana_urls.txt")
    if not os.path.isfile(katana_path):
        return {
            "error": "No katana_urls.txt found for this target - run the Katana "
                     "Crawler first; this module only filters its output.",
            "status": 400,
        }

    with open(katana_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        return {"error": "katana_urls.txt is empty - katana found nothing last "
                         "time it ran.", "status": 400}

    js_files = sorted({line for line in lines if _JS_MENTION.search(line)})

    with open(os.path.join(target_path, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(js_files))

    return {
        "js_files": js_files,
        "count": len(js_files),
        "scanned": len(lines),
        "note": "Ready for the JS analysis pass - endpoints inside these files "
                "feed the active-testing phase (see all_params.txt).",
    }
