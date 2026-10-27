"""
URL Pattern Filter (Gf-Patterns-inspired) - PASSIVE, zero network calls.

Takes the URLs already collected by wayback_urls.py (wayback.txt) and sorts
them into categories based on common vulnerability-indicator parameter
names and file extensions - the same idea as tomnomnom's `gf` tool and the
community Gf-Patterns set (github.com/1ndianl33t/Gf-Patterns), implemented
directly in Python here instead of shelling out to `gf`. The category
param-name lists below are inspired by those patterns, not a byte-for-byte
copy of that repo's regexes.

This never contacts the target - it only re-reads data another module
already collected, so run Wayback Machine URL Discovery first.
"""
import os
from urllib.parse import parse_qs, urlsplit

PATTERNS = {
    "xss": ["q", "s", "search", "query", "keyword", "k", "u", "url", "redirect",
            "next", "data", "input", "text", "val", "name", "message", "comment", "page"],
    "redirect": ["redirect", "redir", "url", "next", "return", "returnto",
                 "continue", "dest", "destination", "out", "view", "to"],
    "ssrf": ["url", "uri", "path", "dest", "redirect", "continue", "return",
             "src", "source", "feed", "host", "port", "callback", "domain"],
    "sqli": ["id", "pid", "category", "cat", "item", "page", "report",
             "select", "order", "sort", "filter"],
    "lfi": ["file", "path", "page", "folder", "dir", "template", "doc",
            "document", "root", "inc", "include", "load"],
    "rce": ["cmd", "exec", "command", "execute", "run", "ping", "jump", "code"],
    "idor": ["id", "uid", "user_id", "account", "order_id", "invoice", "number", "ref"],
    "debug_logic": ["debug", "test", "phpinfo", "trace", "config", "env"],
}

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".json", ".env", ".config",
    ".bak", ".sql", ".zip", ".log", ".xml", ".yml", ".yaml",
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "url_patterns.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"matches": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    wb_path = os.path.join(target_path, "wayback.txt")
    if not os.path.isfile(wb_path):
        return {
            "error": "No wayback.txt found for this target - run the Wayback Machine "
                     "tool first, this module filters its output.",
            "status": 400,
        }

    with open(wb_path, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    matched = {}  # url -> set of categories
    for url in urls:
        parts = urlsplit(url)
        params = {k.lower() for k in parse_qs(parts.query).keys()}
        path_lower = parts.path.lower()

        cats = set()
        for cat, names in PATTERNS.items():
            if params & set(names):
                cats.add(cat)
        if any(path_lower.endswith(ext) for ext in INTERESTING_EXTENSIONS):
            cats.add("interesting_ext")

        if cats:
            matched[url] = cats

    if not matched:
        return {"matches": [], "count": 0, "scanned": len(urls)}

    lines = [f"{url}\t({', '.join(sorted(cats))})" for url, cats in matched.items()]

    with open(os.path.join(target_path, "url_patterns.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"matches": lines, "count": len(matched), "scanned": len(urls)}
