"""
Parameter Collector - PASSIVE, zero network calls.

Consolidates every parameterized URL found across the pipeline so the
active-testing phase has one place to pull its worklist from:

  1. subdomains.txt  - subdomains from Subdomain Enumeration (all-in-one)
  2. uro_urls.txt     - cleaned URLs from the URL Cleaner module (falls
                       back to wayback.txt when uro hasn't been run yet)

Combined, filtered to lines containing '?' (i.e. URLs that actually
carry query parameters - `?id=1`, `?page=2`, ...), deduplicated, and
saved to all_params.txt.

Ready for the next phase: feed all_params.txt into the XSS Prober or
future vuln_scan modules instead of re-merging the per-tool outputs
every time. Run Subdomain Enumeration and Wayback (+ URL Cleaner) first.
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
    subdomains_path = os.path.join(target_path, "subdomains.txt")

    # Parameterized URLs: uro's cleaned output first, falling back to
    # raw wayback.txt if uro hasn't been run yet.
    url_source = None
    source_label = None
    for filename, label in [
        ("uro_urls.txt", "uro_urls.txt"),
        ("wayback.txt", "wayback.txt"),
    ]:
        path = os.path.join(target_path, filename)
        if os.path.isfile(path):
            url_source = path
            source_label = label
            break

    missing = []
    if not os.path.isfile(subdomains_path):
        missing.append("Subdomain Enumeration")
    if url_source is None:
        missing.append("Wayback Machine (or URL Cleaner)")
    if missing:
        return {
            "error": "Input results missing for this target - run "
                     f"{', '.join(missing)} first. Checked for subdomains.txt and "
                     "a cleaned URL file (uro_urls.txt / wayback.txt).",
            "status": 400,
        }

    subdomains = _read_lines(subdomains_path)
    urls = _read_lines(url_source)

    combined = list(dict.fromkeys(subdomains + urls))  # order-preserving dedupe

    # Keep only URLs that actually carry parameters; subdomains without a
    # query string drop out here naturally.
    param_urls = sorted({line for line in combined if "?" in line})

    with open(os.path.join(target_path, OUTPUT_FILE), "w", encoding="utf-8") as f:
        f.write("\n".join(param_urls))

    return {
        "urls": param_urls,
        "count": len(param_urls),
        "combined": len(combined),
        "url_source": source_label,
        "note": "Ready for the active-testing phase (XSS Prober / vuln_scan).",
    }
