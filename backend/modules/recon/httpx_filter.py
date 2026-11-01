"""
Live Host Status-Code Splitter - PASSIVE, zero network calls.

Takes live_hosts.txt written by httpx_live.py and splits it into one file
per status code - live_200.txt, live_403.txt, live_401.txt, live_404.txt,
live_301.txt, live_302.txt - so each class of "live but restricted" host
can be triaged on its own (403/401 hostnames shortlist direct-access
targets, 404s hint at removed pages, 301/302s flag redirect chains that
are worth following).

The code set mirrors httpx_live.py's -mc list, so nothing httpx reported
ever gets dropped here. This never contacts the target - it only re-reads
data httpx already collected, so run the Live Host Probe first.
"""
import os
import re

# Must mirror STATUS_CODES in httpx_live.py (its -mc argument).
STATUS_CODES = [200, 301, 302, 401, 403, 404]

_LINE_CODE = re.compile(r"\[(\d{3})\]")


def get_cached(target_path: str) -> dict:
    """Rebuild the summary by reading every live_<code>.txt file that
    exists on disk - no extra bookkeeping needed between runs."""
    codes = {}
    ran = False
    for code in STATUS_CODES:
        result_path = os.path.join(target_path, f"live_{code}.txt")
        if not os.path.isfile(result_path):
            continue
        ran = True
        with open(result_path, "r", encoding="utf-8") as f:
            hosts = [line.strip() for line in f if line.strip()]
        codes[code] = {"file": f"live_{code}.txt", "count": len(hosts), "urls": hosts}

    summary = [f"[{code}] {data['count']} host(s) -> {data['file']}"
               for code, data in sorted(codes.items())]
    return {"groups": codes, "summary": summary, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    live_path = os.path.join(target_path, "live_hosts.txt")
    if not os.path.isfile(live_path):
        return {
            "error": "No live_hosts.txt found for this target - run the Live Host "
                     "Probe (httpx) first; this module only splits its output.",
            "status": 400,
        }

    with open(live_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        return {"error": "live_hosts.txt is empty - httpx found no live hosts "
                         "last time it ran.", "status": 400}

    grouped = {code: [] for code in STATUS_CODES}
    for line in lines:
        m = _LINE_CODE.search(line)
        if m:
            code = int(m.group(1))
            if code in grouped:
                grouped[code].append(line)
            # other codes would only appear if httpx_live.py's -mc list
            # was widened - intentionally preserved via live_hosts.txt,
            # not split into files here.

    codes = {}
    for code, hits in grouped.items():
        result_path = os.path.join(target_path, f"live_{code}.txt")
        if os.path.isfile(result_path):
            os.remove(result_path)  # clear stale files before rewriting
        if hits:
            with open(result_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(hits)))
        codes[code] = {"file": f"live_{code}.txt", "count": len(hits), "urls": sorted(hits)}

    summary = [f"[{code}] {len(hits)} host(s) -> live_{code}.txt"
               for code, hits in sorted(codes.items()) if hits]

    interesting = codes[403]["count"] + codes[401]["count"]
    return {
        "groups": codes,
        "summary": summary,
        "count": sum(len(hits) for hits in grouped.values()),
        "scanned": len(lines),
        "restricted_hosts": interesting,
        "note": f"{interesting} host(s) answered 401/403 - access-restricted, "
                "usually worth a manual look.",
    }
