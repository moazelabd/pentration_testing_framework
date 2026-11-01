"""
GF Parameter Filtering - PASSIVE, zero network calls (gf is a local
pattern matcher; no requests are made).

Feeds the aggregated parameterized worklist all_params.txt (built by
js_param_collector.py - and by param_collector.py before it) through
the industry-standard `gf` CLI (github.com/tomnomnom/gf) with the
community Gf-Patterns set (github.com/1ndianl33t/Gf-Patterns), sorting
each URL into vulnerability categories by its parameter names /
extensions: xss, sqli, ssrf, lfi, rce, idor, redirect, debug_logic,
interesting_ext.

This is the gf run for the JS-analysis pipeline - it differs from the
older gf_extractor.py (kept untouched) only in INPUT: that module runs
on the wayback/urldedupe URL lists, this one consumes the combined
all_params.txt worklist. Both write the same gf_<pattern>.txt category
files, so downstream consumers (XSS Prober reads "xss") stay unchanged.

Output: one gf_<pattern>.txt per pattern (the gf-19/13-style naming
downstream modules already expect), plus per-pattern counts.

Requires gf + the Gf-Patterns set:
    go install -v github.com/tomnomnom/gf@latest
    # patterns go DIRECTLY into ~/.gf (gf looks there, one level):
    git clone https://github.com/1ndianl33t/Gf-Patterns
    cp Gf-Patterns/*.json ~/.gf/
Run the JS Parameter Collector (or Parameter Collector) first.
"""
import os
import subprocess

GF_TIMEOUT = 120  # seconds per pattern

# The categories the active-testing phase consumes (XSS Prober reads xss).
PATTERNS = ["xss", "sqli", "ssrf", "lfi", "rce", "idor", "redirect",
            "debug_logic", "interesting_ext"]

# Gf-Patterns ships some community patterns under different filenames
# (e.g. interestingEXT.json) - try the canonical name first, then aliases.
_ALIASES = {"interesting_ext": ["interesting_ext", "interestingEXT"]}


def _pattern_candidates(pattern: str) -> list:
    return _ALIASES.get(pattern, [pattern])


def _patterns_installed() -> tuple:
    """Check gf's default pattern dir has at least one .json file.
    gf looks in ~/.gf (optionally with patterns dropped directly into
    it, as Gf-Patterns instructs). Helpful error info is returned."""
    home = os.path.expanduser("~")
    pattern_dir = os.environ.get("GF_PATTERN_DIR") or os.path.join(home, ".gf")
    if os.path.isdir(pattern_dir):
        found = [f for f in os.listdir(pattern_dir) if f.endswith(".json")]
        if found:
            return True, f"{len(found)} pattern(s) in {pattern_dir}"
        # some installs nest them one level deep
        for name in sorted(os.listdir(pattern_dir)):
            sub = os.path.join(pattern_dir, name)
            if os.path.isdir(sub):
                deep = [f for f in os.listdir(sub) if f.endswith(".json")]
                if deep:
                    return True, f"{len(deep)} pattern(s) in {sub}"
    return False, f"no .json patterns found in {pattern_dir}"


def get_cached(target_path: str) -> dict:
    """Rebuild the combined UI list by reading every gf_<pattern>.txt
    file on disk, merging URLs that hit several categories."""
    ran = False
    matched = {}  # url -> set of categories
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
    counts = {p: sum(1 for _, cs in matched.items() if p in cs) for p in PATTERNS}
    return {"matches": lines, "counts": counts, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    input_path = os.path.join(target_path, "all_params.txt")
    if not os.path.isfile(input_path):
        return {
            "error": "No all_params.txt found for this target - run the JS "
                     "Parameter Collector (or Parameter Collector) first; "
                     "this module tags its parameterized URLs.",
            "status": 400,
        }

    with open(input_path, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]
    if not urls:
        return {"error": "all_params.txt is empty - collect parameterized "
                         "URLs first.", "status": 400}

    ready, detail = _patterns_installed()
    if not ready:
        return {
            "error": "gf is present but no Gf-Patterns are installed. Install the "
                     "pattern set: `git clone https://github.com/1ndianl33t/Gf-Patterns` "
                     "then `cp Gf-Patterns/*.json ~/.gf/`. Details: " + detail,
            "status": 502,
        }

    # Clear stale per-pattern files so a failed pattern doesn't leave
    # old hits looking fresh.
    for pattern in PATTERNS:
        result_path = os.path.join(target_path, f"gf_{pattern}.txt")
        if os.path.isfile(result_path):
            os.remove(result_path)

    counts = {}
    not_found_patterns = []
    per_pattern = {}
    for pattern in PATTERNS:
        hits = None
        tried_candidates = []
        for candidate in _pattern_candidates(pattern):
            try:
                # gf reads URLs on stdin; exit 1 with empty output is
                # grep-style "no matches", not an error.
                proc = subprocess.run(
                    ["gf", candidate],
                    input="\n".join(urls),
                    capture_output=True,
                    text=True,
                    timeout=GF_TIMEOUT,
                    check=False,
                )
            except FileNotFoundError:
                return {
                    "error": "gf isn't installed or isn't on your PATH. Install it "
                             "with `go install -v github.com/tomnomnom/gf@latest`, "
                             "then add the Gf-Patterns set to ~/.gf.",
                    "status": 502,
                }
            except subprocess.TimeoutExpired:
                return {
                    "error": f"gf timed out after {GF_TIMEOUT}s on pattern "
                             f"'{candidate}' and was stopped",
                    "status": 504,
                }

            # unknown pattern names print to stderr ("no such pattern")
            err = (proc.stderr or "").strip().lower()
            if "no pattern" in err or "no such" in err:
                continue  # pattern name not present - try alias / flag as missing
            hits = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})
            break

        if hits is None:
            not_found_patterns.append(pattern)
            counts[pattern] = 0
            continue  # leave the file absent so get_cached reports 0 for it

        result_path = os.path.join(target_path, f"gf_{pattern}.txt")
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("\n".join(hits))
        counts[pattern] = len(hits)
        per_pattern[pattern] = hits

    # Reuse get_cached's merging so the response and cache agree.
    matched = {}
    for pattern, hits in per_pattern.items():
        for url in hits:
            matched.setdefault(url, set()).add(pattern)
    matches = [f"{url}\t({', '.join(sorted(patterns))})"
               for url, patterns in matched.items()]

    response = {
        "matches": matches,
        "counts": counts,
        "total": sum(counts.values()),
        "scanned": len(urls),
        "note": "Tagged the all_params.txt worklist. Feed the xss-tagged "
                "URLs to the XSS Prober next.",
    }
    if not_found_patterns and sum(counts.values()) > 0:
        response["warning"] = (f"pattern(s) not found in ~/.gf: "
                               f"{', '.join(not_found_patterns)} - install Gf-Patterns "
                               "fully (`cp Gf-Patterns/*.json ~/.gf/`) to cover all "
                               "categories")
    return response
