"""
URL Cleaner (uro-inspired) - PASSIVE, zero network calls.

Takes the raw URL list from wayback.txt and cuts the noise before it
reaches URL Pattern Filter / XSS Prober - the same idea as s0md3v's `uro`
tool (github.com/s0md3v/uro), implemented directly in Python here:

  - drops boring static-asset extensions (images, fonts, css, js, media...)
  - collapses near-duplicate URLs that only differ by a numeric ID or by
    query-PARAM VALUES (keeps one representative per path-pattern +
    query-param-NAME combination, since testing 500 URLs that are really
    the same page with a different ?id=N is wasted effort)

This never contacts the target - it only re-reads data wayback_urls.py
already collected, so run Wayback Machine URL Discovery first.
"""
import os
import re
from urllib.parse import parse_qs, urlsplit

BORING_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "mp3", "avi", "mov", "wav", "ogg",
    "pdf", "zip", "rar", "gz", "tar",
}

_DIGIT_RUN = re.compile(r"\d+")


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "uro_urls.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def _is_boring(path: str) -> bool:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    return ext in BORING_EXTENSIONS


def _pattern_key(url: str) -> str:
    """Path with digit runs collapsed to 'N', plus the SET of query param
    NAMES (not values) - two URLs that only differ by an ID or a param
    value collapse to the same key."""
    parts = urlsplit(url)
    normalized_path = _DIGIT_RUN.sub("N", parts.path)
    param_names = tuple(sorted(parse_qs(parts.query).keys()))
    return f"{normalized_path}?{param_names}"


def run(domain: str, target_path: str) -> dict:
    wb_path = os.path.join(target_path, "wayback.txt")
    if not os.path.isfile(wb_path):
        return {
            "error": "No wayback.txt found for this target - run the Wayback Machine "
                     "tool first, this module cleans up its output.",
            "status": 400,
        }

    with open(wb_path, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    seen_patterns = set()
    kept = []
    dropped_boring = 0
    dropped_dupe = 0

    for url in urls:
        parts = urlsplit(url)
        if _is_boring(parts.path):
            dropped_boring += 1
            continue

        key = _pattern_key(url)
        if key in seen_patterns:
            dropped_dupe += 1
            continue
        seen_patterns.add(key)
        kept.append(url)

    with open(os.path.join(target_path, "uro_urls.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(kept))

    return {
        "urls": kept,
        "count": len(kept),
        "scanned": len(urls),
        "dropped_boring": dropped_boring,
        "dropped_duplicate_pattern": dropped_dupe,
    }
