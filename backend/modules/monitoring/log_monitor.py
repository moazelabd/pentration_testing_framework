"""
Monitoring - global log store (used by the Monitoring page).

Logs are indexed once (by link, by file, or by pasted lines) and live in
backend/monitoring_data/logs.jsonl. The Monitoring page searches that
store. Password values ARE stored in plain text so the eye icon on the
page can reveal them - they are blurred on screen by default. Do not
share backend/monitoring_data/ with anyone.
"""
import json
import os
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.normpath(os.path.join(BASE, "..", "..", "monitoring_data"))
os.makedirs(DATA, exist_ok=True)

MAX_LINK_MB = 50
ALLOWED_LINK_EXT = {".txt", ".log", ".csv", ".json"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _domain_of(url):
    import re
    u = re.sub(r"^https?://", "", (url or "").strip()).split("/")[0].split(":")[0]
    return u.replace("www.", "")


def parse_line(line, source="import"):
    """Parse one log line into an entry. Password value is kept (see module docstring)."""
    import re
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("{"):
        try:
            j = json.loads(line)
            url = j.get("url") or j.get("service") or j.get("domain") or ""
            email = j.get("email") or ""
            username = j.get("username") or j.get("user") or (email.split("@")[0] if email else "")
            pw = j.get("password") or ""
            return {"date": j.get("date") or _now()[:10], "seen_at": _now(), "source": source,
                    "url": url, "domain": _domain_of(url or j.get("domain") or ""),
                    "email": email, "username": username, "ip": j.get("ip") or "",
                    "type": j.get("type") or "log", "has_password": bool(pw),
                    "pw_len": len(str(pw)) if pw else 0, "password": str(pw) if pw else ""}
        except Exception:
            pass
    url, user, pw = "", "", ""
    if "|" in line:
        _p = [x.strip() for x in line.split("|")]
        url, user, pw = _p[0], (_p[1] if len(_p) > 1 else ""), (_p[2] if len(_p) > 2 else "")
    else:
        m = re.match(r"^(https?://[^:\s/]+(?::\d+)?(?:/[^:\s]*)?):([^:]+)(?::(.*))?$", line)
        if m:
            url, user, pw = m.group(1), m.group(2).strip(), (m.group(3) or "").strip()
        else:
            _p = [x.strip() for x in line.split(":")]
            if len(_p) >= 2:
                if "@" in _p[0]:
                    url, user, pw = "", _p[0], _p[1]
                else:
                    url, user, pw = _p[0], _p[1], (_p[2] if len(_p) > 2 else "")
            else:
                return None
    email = user if "@" in user else ""
    username = email.split("@")[0] if email else user
    if not url and not email and not username:
        return None
    return {"date": _now()[:10], "seen_at": _now(), "source": source, "url": url,
            "domain": _domain_of(url), "email": email, "username": username, "ip": "",
            "type": "stealer log" if url else "combo", "has_password": bool(pw),
            "pw_len": len(pw), "password": pw}


def _load(path, default):
    if not os.path.isfile(path):
        return default
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def _save(path, data):
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def entries():
    p = os.path.join(DATA, "logs.jsonl")
    if not os.path.isfile(p):
        return []
    out = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def status():
    es = entries()
    return {"logs": len(es), "hits": len(es),
            "sources": len(_load(os.path.join(DATA, "sources.json"), [])),
            "alerts": len(_load(os.path.join(DATA, "alerts.json"), [])),
            "watchlist": len(_load(os.path.join(DATA, "watchlist.json"), []))}


def search(q, field="all", source=""):
    """Empty query returns nothing - the page only shows what you search."""
    q = (q or "").strip().lower()
    if not q:
        return []
    out = []
    for e in entries():
        if source and e.get("source") != source:
            continue
        hay = {"all": (e.get("email") or "") + " " + (e.get("username") or "") + " " + (e.get("url") or "") + " " + (e.get("domain") or "") + " " + (e.get("ip") or ""),
               "email": e.get("email") or "",
               "username": e.get("username") or "",
               "domain": e.get("domain") or "",
               "url": e.get("url") or ""}.get(field, "")
        if q in hay.lower():
            out.append(e)
    return out


def append_text(text, source="import"):
    os.makedirs(DATA, exist_ok=True)
    existing = {(e.get("url"), e.get("email"), e.get("username")) for e in entries()}
    added, skipped = 0, 0
    with open(os.path.join(DATA, "logs.jsonl"), "a", encoding="utf-8") as f:
        for raw in text.splitlines():
            e = parse_line(raw, source)
            if not e:
                continue
            key = (e["url"], e["email"], e["username"])
            if key in existing:
                skipped += 1
                continue
            existing.add(key)
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
            added += 1
    if source and source.startswith("http"):
        p = os.path.join(DATA, "sources.json")
        srcs = _load(p, [])
        if not any(s.get("url") == source for s in srcs):
            srcs.append({"name": source, "handle": "", "url": source, "kind": "Log link", "active": True, "logs": added})
            _save(p, srcs)
    return {"added": added, "skipped": skipped, "count": len(existing)}


def fetch_url(url):
    import requests
    if not url.startswith(("http://", "https://")):
        return {"error": "Give a http:// or https:// link to a log file."}
    path = url.split("?", 1)[0].lower()
    ext = os.path.splitext(path)[1]
    if ext not in ALLOWED_LINK_EXT:
        return {"error": f"Link must end in .txt, .log, .csv or .json (got '{ext or 'none'}')."}
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "Monitor/1.0"}, stream=True)
        r.raise_for_status()
        size = int(r.headers.get("Content-Length") or 0)
        if size > MAX_LINK_MB * 1024 * 1024:
            return {"error": f"File is larger than {MAX_LINK_MB} MB."}
        chunks, total = [], 0
        for chunk in r.iter_content(chunk_size=65536, decode_unicode=True):
            if chunk:
                total += len(chunk)
                if total > MAX_LINK_MB * 1024 * 1024:
                    return {"error": f"File is larger than {MAX_LINK_MB} MB."}
                chunks.append(chunk)
        return {"text": "".join(chunks)}
    except Exception as e:
        return {"error": f"Could not download that link: {e}"}
