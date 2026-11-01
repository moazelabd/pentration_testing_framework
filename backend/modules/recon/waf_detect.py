"""
WAF Detection via wafw00f - ACTIVE (sends crafted requests to the target -
only run against in-scope, authorized targets).

Feeds the live hosts (live_200.txt preferred, live_hosts.txt fallback)
through the industry-standard `wafw00f` CLI (EnableSecurity, pip package)
to detect Web Application Firewalls - Cloudflare, Akamai, AWS WAF,
Imperva, generic - so the active-testing phase knows which hosts to
treat with care and which are unfiltered.

Output design:
  - waf_results.json  - wafw00f's own JSON dump. The scan runs ONCE:
    running it a second time just to also capture text output would
    double the traffic; the text files below are derived from the JSON.
  - waf_results.txt   - one line per host: "url | waf"  (Yes stripped)
  - waf_summary.txt   - "URL | WAF | Yes/No" table; what waf_filter.py
    splits and what the frontend displays.
Return: {"detected": n, "not_detected": n, "wafs_found": [...]}.

Requires wafw00f (Python package - unlike the Go tools):
    pip install wafw00f
Run the Live Host Probe (httpx) first.
"""
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager

WAFW00F_TIMEOUT = 900  # each host gets several probing requests


@contextmanager
def _temp_url_list(urls):
    """wafw00f's -i reads a plain URL-per-line file; write ours to a temp
    file instead of dropping intermediate clutter into the target dir."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                     encoding="utf-8") as tf:
        tf.write("\n".join(urls))
        # flush BEFORE handing the path to the CLI: NamedTemporaryFile
        # stays open inside this context manager, and without flush()
        # the tool would read an (apparently) empty file.
        tf.flush()
        try:
            yield tf.name
        finally:
            try:
                os.remove(tf.name)
            except OSError:
                pass


def _read_input_urls(target_path: str):
    """Prefer live_200.txt; fall back to the full live_hosts.txt. Both
    carry httpx annotations (' [200] [Title]') - keep bare URLs only."""
    for filename, label in [("live_200.txt", "live_200.txt"),
                            ("live_hosts.txt", "live_hosts.txt")]:
        path = os.path.join(target_path, filename)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    url = line.split(" [")[0].strip()
                    if url and "://" in url:
                        urls.append(url)
            return path, label, list(dict.fromkeys(urls))
    return None, None, []


def get_cached(target_path: str) -> dict:
    """Rebuild the summary + counts from the cached waf_summary.txt."""
    summary_path = os.path.join(target_path, "waf_summary.txt")
    ran = os.path.isfile(summary_path)
    rows = []
    if ran:
        with open(summary_path, "r", encoding="utf-8") as f:
            raw = [line.strip() for line in f
                   if line.strip() and not line.startswith("#")]
        # only well-formed "url | waf | Yes/No" rows count
        rows = [r for r in raw if r.count("|") == 2 and all(p.strip() for p in r.split("|"))]

    detected = sum(1 for r in rows if r.lower().endswith("| yes"))
    wafs = sorted({r.split("|")[1].strip() for r in rows
                   if r.lower().endswith("| yes")})
    return {
        "rows": rows,
        "detected": detected,
        "not_detected": max(len(rows) - detected, 0),
        "wafs_found": wafs,
        "ran": ran,
    }


def run(domain: str, target_path: str) -> dict:
    input_path, source_label, urls = _read_input_urls(target_path)
    if input_path is None:
        return {
            "error": "No live_200.txt (or live_hosts.txt) found for this target - "
                     "run the Live Host Probe (httpx) first.",
            "status": 400,
        }
    if not urls:
        return {"error": f"{source_label} holds no usable URLs to probe - "
                         "check the live hosts list.", "status": 400}

    results_json = os.path.join(target_path, "waf_results.json")
    results_txt = os.path.join(target_path, "waf_results.txt")
    summary_path = os.path.join(target_path, "waf_summary.txt")

    with _temp_url_list(urls) as tmp_path:
        for path in (results_json, results_txt, summary_path):
            if os.path.isfile(path):
                os.remove(path)  # a failed run must not look like fresh output

        try:
            # -o file-extension picks the csv/json/text format; -f json
            # forces it. One run only - text outputs derive from the JSON.
            proc = subprocess.run(
                ["wafw00f", "-i", tmp_path, "-o", results_json, "-f", "json"],
                timeout=WAFW00F_TIMEOUT,
                capture_output=True,
                text=True,
                check=False,  # unreachable hosts log errors, not exit codes
            )
        except FileNotFoundError:
            return {
                "error": "wafw00f isn't installed or isn't on your PATH. Install it "
                         "with `pip install wafw00f`, then try again.",
                "status": 502,
            }
        except subprocess.TimeoutExpired:
            return {
                "error": f"wafw00f timed out after {WAFW00F_TIMEOUT}s and was "
                         "stopped - many slow hosts to probe.",
                "status": 504,
            }

        # wafw00f writes a JSON array of records like:
        #   {"url": ..., "detected": bool, "firewall": str, "manufacturer": str}
        records = []
        malformed = False
        if os.path.isfile(results_json):
            try:
                with open(results_json, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                records = loaded if isinstance(loaded, list) else [loaded]
            except ValueError:
                malformed = True

        if not records:
            return {
                "error": "wafw00f produced no usable results (all targets "
                         "unreachable, or its JSON output was malformed). Check "
                         "the hosts are alive - run the Live Host Probe first.",
                "status": 502,
            }

        rows = []
        wafs_found = set()
        detected = 0
        seen = set()
        for record in records:
            url = (record.get("url") or "").strip()
            if not url or url in seen:
                continue  # duplicates are possible with redirect-following
            seen.add(url)
            if record.get("detected"):
                firewall = (record.get("firewall") or "Unknown").strip()
                detected += 1
                if firewall.lower() != "none":
                    wafs_found.add(firewall)
                rows.append(f"{url} | {firewall} | Yes")
            else:
                rows.append(f"{url} | None | No")

        # "url | waf" view without the Yes/No column
        with open(results_txt, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(row.rsplit(" | ", 1)[0] + "\n")

        lines = [f"# waf summary - {domain}"]
        lines.extend(rows)
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    unreachable = len(urls) - len(seen)
    response = {
        "rows": lines,
        "row_values": rows,
        "detected": detected,
        "not_detected": len(rows) - detected,
        "wafs_found": sorted(wafs_found),
        "scanned": len(urls),
        "unreachable": max(unreachable, 0),
        "source": source_label,
        "note": "WAF-protected hosts need care during active testing; split "
                "them out with the WAF Filter module next.",
    }
    if unreachable > 0:
        response["warning"] = (f"{unreachable} input host(s) got no result - "
                               "likely unreachable or timed out during probing")
    return response
