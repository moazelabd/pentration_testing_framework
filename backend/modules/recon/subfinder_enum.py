"""
Subdomain Enumeration via subfinder - PASSIVE.

Runs the industry-standard `subfinder` CLI (github.com/projectdiscovery/
subfinder) against the domain. subfinder is fully passive - it queries
public data sources like certificate transparency logs, DNS aggregators
and other passive sources, so no traffic is sent to the target itself.

This runs ALONGSIDE the older Python-built `subdomains_all_in_one.py`
(that module is not touched - use whichever, or both, and merge results
yourself if you want maximum coverage).

Requires subfinder to be installed and on your PATH:
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
(see https://github.com/projectdiscovery/subfinder for other options).
"""
import os
import subprocess

USER_AGENT_NOTE = "subfinder handles its own HTTP user agent internally"
SUBFINDER_TIMEOUT = 300  # seconds - passive enumeration can be slow


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "subfinder.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"subdomains": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    result_path = os.path.join(target_path, "subfinder.txt")

    # Remove any stale result file first - if subfinder fails mid-run we
    # don't want get_cached() to report a half-written previous run as
    # if it were fresh output.
    if os.path.isfile(result_path):
        os.remove(result_path)

    try:
        # -silent suppresses the banner so the output file contains only
        # subdomains, one per line.
        subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-o", result_path],
            timeout=SUBFINDER_TIMEOUT,
            check=False,  # subfinder may exit non-zero on partial results
        )
    except FileNotFoundError:
        return {
            "error": "subfinder isn't installed or isn't on your PATH. Install it "
                     "with `go install -v github.com/projectdiscovery/subfinder/v2/"
                     "cmd/subfinder@latest`, then try again.",
            "status": 502,
        }
    except subprocess.TimeoutExpired:
        # The file may still hold partial results if subfinder wrote
        # anything before timing out - keep it, but flag the run.
        partial = get_cached(target_path)
        return {
            "error": "subfinder timed out after "
                     f"{SUBFINDER_TIMEOUT}s and was stopped",
            "status": 504,
            **({"subdomains": partial["subdomains"], "count": len(partial["subdomains"])}
               if partial["ran"] else {}),
        }

    subdomains = []
    if os.path.isfile(result_path):
        with open(result_path, "r", encoding="utf-8") as f:
            subdomains = sorted({line.strip() for line in f if line.strip()})
        # -o writes the raw stream; rewrite deduplicated/sorted for a
        # cleaner file that matches the other modules' output style.
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("\n".join(subdomains))

    if not subdomains:
        return {
            "subdomains": [],
            "count": 0,
            "note": "subfinder ran but found no subdomains (or exited early - "
                    "check that the domain is correct and resolvable).",
        }

    return {"subdomains": subdomains, "count": len(subdomains)}
