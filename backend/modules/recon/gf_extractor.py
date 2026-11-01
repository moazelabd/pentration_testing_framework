"""
URL Pattern Extraction via gf - PASSIVE, zero network calls.

Feeds the cleaned URL list through the industry-standard `gf` CLI
(tomnomnom/gf) with the community Gf-Patterns set, writing one result
file per pattern: gf_xss.txt, gf_sqli.txt, gf_ssrf.txt, etc.

This runs ALONGSIDE the Python-built `url_pattern_filter.py` (gf inspired
that module, which is NOT removed - both can be run). Pattern names match
the categories that filter already uses, so downstream modules like the
XSS Prober can consume either output.

Input preference per the pipeline: urldedupe.txt first (the fast
industry-standard cleaner), falling back to wayback.txt so the module
still works on its own.

Requires gf (github.com/tomnomnom/gf) and the Gf-Patterns set
(github.com/1ndianl33t/Gf-Patterns) installed:
    go install -v github.com/tomnomnom/gf@latest
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/gf/patterns
Run Wayback Machine URL Discovery first (and ideally urldedupe).
"""
import os
import subprocess

GF_TIMEOUT = 120  # seconds per pattern

# Same categories as url_pattern_filter.py so the outputs line up.
PATTERNS = ["xss", "sqli", "ssrf", "lfi", "rce", "redirect", "idor", "debug_logic"]


def get_cached(target_path: str) -> dict:
    """Rebuild the combined UI list by reading every gf_<pattern>.txt
    file found on disk, merging URLs that hit several patterns."""
    ran = False
    matched = {}  # url -> set of pattern names
    for pattern in PATTERNS:
        result_path = os.path.join(target_path, f"gf_{pattern}.txt")
        if not os.path.isfile(result_path):
            continue
        ran = True
        with open(result_path, "r", encoding="utf-8") as f:
            for line in f:
                url = line.strip()
                if url:
                    matched.setdefault(url, set()).add(pattern)

    lines = [f"{url}\t({', '.join(sorted(patterns))})"
             for url, patterns in matched.items()]
    return {"matches": lines, "ran": ran}


def _pattern_hit(target_path: str, pattern: str) -> dict:
    """Copy of get_cached's per-file check, used to report per-pattern
    counts in run()'s response."""
    result_path = os.path.join(target_path, f"gf_{pattern}.txt")
    if not os.path.isfile(result_path):
        return 0
    with open(result_path, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def run(domain: str, target_path: str) -> dict:
    # Prefer the urldedupe-cleaned list; fall back to raw wayback.txt so
    # this module still works on its own.
    urldedupe_path = os.path.join(target_path, "urldedupe.txt")
    wb_path = os.path.join(target_path, "wayback.txt")
    source_path = urldedupe_path if os.path.isfile(urldedupe_path) else wb_path

    if not os.path.isfile(source_path):
        return {
            "error": "No urldedupe.txt (or wayback.txt) found for this target - run "
                     "the Wayback Machine tool first, then urldedupe.",
            "status": 400,
        }

    with open(source_path, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    per_pattern = {}   # pattern -> count
    missing_tools = []
    stale = {f"gf_{p}.txt" for p in PATTERNS}

    for pattern in PATTERNS:
        try:
            # gf is a grep wrapper: matches go to stdout, and it exits 1
            # when there are no matches (grep's "nothing found"), which
            # is a normal outcome - hence check=False.
            proc = subprocess.run(
                ["gf", pattern],
                input="\n".join(urls),
                capture_output=True,
                text=True,
                timeout=GF_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            missing_tools.append(pattern)
            continue
        except subprocess.TimeoutExpired:
            missing_tools.append(f"{pattern} (timeout)")
            continue

        hits = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})
        result_path = os.path.join(target_path, f"gf_{pattern}.txt")
        if os.path.isfile(result_path):
            stale.discard(os.path.basename(result_path))
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("\n".join(hits))
        per_pattern[pattern] = len(hits)

    if missing_tools and not per_pattern:
        return {
            "error": "gf isn't installed or isn't on your PATH. Install it with "
                     "`go install -v github.com/tomnomnom/gf@latest` and add the "
                     "Gf-Patterns repo to your ~/.gf/patterns directory, then try "
                     f"again. Details: {', '.join(missing_tools)}",
            "status": 502,
        }

    for name in stale:
        path = os.path.join(target_path, name)
        if os.path.isfile(path):
            os.remove(path)  # stale result from a pattern that no longer ran

    total = sum(per_pattern.values())
    response = {
        "matches": get_cached(target_path)["matches"],
        "count": total,
        "scanned": len(urls),
        "per_pattern": per_pattern,
        "input_source": "urldedupe.txt" if source_path == urldedupe_path else "wayback.txt",
    }
    if missing_tools:
        # gf exists but some patterns errored or timed out - surface it
        # without losing the patterns that did match.
        response["note"] = f"Some patterns failed: {', '.join(missing_tools)}"
    return response
