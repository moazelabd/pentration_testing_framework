"""
Secret Extraction from JavaScript via jsluice - ACTIVE-ISH (jsluice itself
makes HTTP requests to fetch each JS file listed as a URL - only run
against in-scope, authorized targets).

Runs the `jsluice` CLI (github.com/BishopFox/jsluice, Bishop Fox) in
`secrets` mode over the JS files from js_files.txt. Built-in extractor
matchers flag leaked AWS keys, GCP keys, GitHub tokens, Firebase configs
and more; custom extra patterns can be added with jsluice's
-p/--patterns flag (out of scope here by default).

Output handling:
  - jsluice_secrets.json          -> raw JSON lines, kept for deep-diving
  - jsluice_secrets_summary.txt   -> human-readable lines, one per finding:
      "[AWSAccessKeyID] [high] found in https://host/app.js"
    (the pattern is stable enough to re-derive counts in get_cached)

Requires jsluice on your PATH:
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest
Run the JS File Extractor first - this module analyzes its output.
"""
import json
import os
import re
import subprocess

JSLUICE_TIMEOUT = 600
SUMMARY_FILE = "jsluice_secrets_summary.txt"

_SUMMARY_LINE = re.compile(r"^\[([^]]+)\] \[([^]]+)\] found in (.+)$")


def get_cached(target_path: str) -> dict:
    """Rebuild the findings summary + counts from the summary file so no
    extra bookkeeping is needed between runs."""
    result_path = os.path.join(target_path, SUMMARY_FILE)
    ran = os.path.isfile(result_path)
    findings = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            findings = [line.strip() for line in f if line.strip()]

    counts = {}
    for line in findings:
        m = _SUMMARY_LINE.match(line)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return {"findings": findings, "counts": counts, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    js_path = os.path.join(target_path, "js_files.txt")
    if not os.path.isfile(js_path):
        return {
            "error": "No js_files.txt found for this target - run the JS File "
                     "Extractor first (it merges katana and Wayback Machine "
                     "results), then scan them here for leaked secrets.",
            "status": 400,
        }

    with open(js_path, "r", encoding="utf-8") as f:
        js_urls = [line.strip() for line in f if line.strip()]
    if not js_urls:
        return {"error": "js_files.txt is empty - no JS files were found in "
                         "the katana / Wayback results last run.", "status": 400}

    raw_json_path = os.path.join(target_path, "jsluice_secrets.json")
    summary_path = os.path.join(target_path, SUMMARY_FILE)
    for path in (raw_json_path, summary_path):
        if os.path.isfile(path):
            os.remove(path)  # a failed run must not look like fresh output

    try:
        proc = subprocess.run(
            ["jsluice", "secrets"],
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
            "error": f"jsluice timed out after {JSLUICE_TIMEOUT}s and was stopped",
            "status": 504,
        }

    # jsluice prints one JSON object per secret match with keys:
    #   kind, severity, filename, data {...}, context {...}
    raw_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    with open(raw_json_path, "w", encoding="utf-8") as f:
        f.write("\n".join(raw_lines))

    findings = []
    counts = {}
    severity_counts = {}
    malformed = 0
    for line in raw_lines:
        try:
            record = json.loads(line)
        except ValueError:
            malformed += 1  # a single bad line must not kill the whole run
            continue

        kind = (record.get("kind") or "<unknown>").strip()
        severity = (record.get("severity") or "").strip().lower()
        filename = (record.get("filename") or "<unknown file>").strip()

        findings.append(f"[{kind}] [{severity}] found in {filename}" if severity
                        else f"[{kind}] found in {filename}")
        counts[kind] = counts.get(kind, 0) + 1
        if severity:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    findings.sort()
    counts["total"] = sum(counts.values())
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    response = {
        "findings": findings,
        "counts": counts,
        "total": counts["total"],
        "scanned_js": len(js_urls),
        "severity_counts": severity_counts,
    }
    if malformed:
        response["note"] = (f"{malformed} malformed jsluice output line(s) skipped - "
                            "raw output kept in jsluice_secrets.json")
    return response
