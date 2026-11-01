"""
URL Deduplication via urldedupe - PASSIVE, zero network calls.

Pipes the raw URL list from wayback.txt through the industry-standard
`urldedupe` CLI (github.com/ameenmaali/urldedupe), which collapses
near-duplicate URLs (differing only by parameter values) far faster than
the Python-built `uro_filter.py` implementation that sits alongside it.

That older module is NOT removed - both can be run; urldedupe works on
wayback.txt directly, uro_filter.py's output (uro_urls.txt) is picked up
by URL Pattern Filter the same way as before.

Requires urldedupe to be installed and on your PATH:
    go install -v github.com/ameenmaali/urldedupe@latest
Run Wayback Machine URL Discovery first - this module cleans up its
output.
"""
import os
import subprocess

URLDEDUPE_TIMEOUT = 120  # seconds


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "urldedupe.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    wb_path = os.path.join(target_path, "wayback.txt")
    result_path = os.path.join(target_path, "urldedupe.txt")

    if not os.path.isfile(wb_path):
        return {
            "error": "No wayback.txt found for this target - run the Wayback Machine "
                     "tool first, this module deduplicates its output.",
            "status": 400,
        }

    # Delete a stale result before running so a failed attempt doesn't
    # look like fresh output in get_cached().
    if os.path.isfile(result_path):
        os.remove(result_path)

    with open(wb_path, "r", encoding="utf-8") as f:
        input_urls = [line.strip() for line in f if line.strip()]

    try:
        # -s sorts the output; urldedupe reads URLs from stdin by default
        # so we pipe the wayback list in and capture stdout.
        proc = subprocess.run(
            ["urldedupe", "-s"],
            input="\n".join(input_urls),
            capture_output=True,
            text=True,
            timeout=URLDEDUPE_TIMEOUT,
            check=False,  # nonzero exit with empty output just means 0 matches
        )
    except FileNotFoundError:
        return {
            "error": "urldedupe isn't installed or isn't on your PATH. Install it "
                     "with `go install -v github.com/ameenmaali/urldedupe@latest`, "
                     "then try again.",
            "status": 502,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"urldedupe timed out after {URLDEDUPE_TIMEOUT}s and was stopped",
            "status": 504,
        }

    urls = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})

    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    return {
        "urls": urls,
        "count": len(urls),
        "scanned": len(input_urls),
        "dropped_duplicate": len(input_urls) - len(urls),
    }
