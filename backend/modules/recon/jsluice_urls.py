"""
JavaScript URL Extraction via jsluice - ACTIVE-ISH (jsluice itself makes
HTTP requests to fetch each JS file listed as a URL - only run against
in-scope, authorized targets).

Runs the `jsluice` CLI (github.com/BishopFox/jsluice, Bishop Fox) in
`urls` mode over the JS files collected by js_extractor.py. Unlike
regex-based extraction, jsluice parses JavaScript with tree-sitter and
finds URLs where they're actually USED: fetch() calls, document.location
assignments, window.open(), XHR and jquery patterns - plus query
parameters and string-concatenation endpoints (inserted as EXPR).

The -I/--ignore-strings flag skips bare string literals to cut noise
and keep real URL assignments and fetch calls.

jsluice output is JSON lines per match; we keep the raw lines in
jsluice_urls.json and write just the `url` field into the clean
jsluice_urls.txt (one URL per line) that downstream modules read.

Requires jsluice on your PATH:
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest
Run the JS File Extractor first - this module analyzes its output.
"""
import json
import os
import subprocess

JSLUICE_TIMEOUT = 600  # many JS files fetched over HTTP take a while


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "jsluice_urls.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    js_path = os.path.join(target_path, "js_files.txt")
    if not os.path.isfile(js_path):
        return {
            "error": "No js_files.txt found for this target - run the Katana "
                     "Crawler first, then the JS File Extractor; this module "
                     "analyzes the JS files katana discovered.",
            "status": 400,
        }

    with open(js_path, "r", encoding="utf-8") as f:
        js_urls = [line.strip() for line in f if line.strip()]
    if not js_urls:
        return {"error": "js_files.txt is empty - katana found no JS files for "
                         "this target.", "status": 400}

    urls_json_path = os.path.join(target_path, "jsluice_urls.json")
    urls_txt_path = os.path.join(target_path, "jsluice_urls.txt")
    for path in (urls_json_path, urls_txt_path):
        if os.path.isfile(path):
            os.remove(path)  # a failed run must not look like fresh output

    try:
        # jsluice reads its file/URL list from stdin, one per line - the
        # exact usage from its docs (`find . -name '*.js' | jsluice urls`).
        proc = subprocess.run(
            ["jsluice", "urls", "-I"],
            input="\n".join(js_urls),
            capture_output=True,
            text=True,
            timeout=JSLUICE_TIMEOUT,
            check=False,  # per-file fetch failures log to stderr, not exit codes
        )
    except FileNotFoundError:
        return {
            "error": "jsluice isn't installed or isn't on your PATH. Install it "
                     "with `go install github.com/BishopFox/jsluice/cmd/jsluice@latest`, "
                     "then try again.",
            "status": 502,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"jsluice timed out after {JSLUICE_TIMEOUT}s and was stopped - "
                     "many JS hosts may be unreachable/slow.",
            "status": 504,
        }

    # Raw output is JSON lines, one object per match. Keep it verbatim for
    # later deep-diving, while parsing leniently below.
    raw_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    with open(urls_json_path, "w", encoding="utf-8") as f:
        f.write("\n".join(raw_lines))

    urls = []
    malformed = 0
    for line in raw_lines:
        try:
            record = json.loads(line)
            url = (record.get("url") or "").strip()
            if url:
                urls.append(url)
        except ValueError:
            malformed += 1  # a single bad line must not kill the whole run

    urls = sorted(set(urls))
    with open(urls_txt_path, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    response = {
        "urls": urls,
        "count": len(urls),
        "scanned_js": len(js_urls),
        "with_params": sum(1 for u in urls if "?" in u),
    }
    if malformed:
        response["note"] = (f"{malformed} malformed jsluice output line(s) skipped - "
                            "raw output kept in jsluice_urls.json")
    return response
