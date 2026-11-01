"""
Live Host Discovery via httpx - ACTIVE (sends HTTP requests to the target's
subdomains - only run against in-scope, authorized targets).

Takes the subdomains collected by the enumeration modules (subfinder.txt
preferred, falling back to the all-in-one subdomains.txt) and probes each
one with the industry-standard `httpx` CLI (github.com/projectdiscovery/
httpx) to find which hosts actually respond.

Deliberately keeps non-200 answers: -mc 200,301,302,401,403,404 means
forbidden (403), unauthorized (401) and even 404 paths are reported -
these are often the most interesting attack surfaces - while 40x noise
like 400 or dead 5xx hosts is dropped. httpx_live_filter.py splits the
result into one file per status code afterwards.

Requires httpx to be installed and on your PATH:
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
"""
import os
import re
import subprocess

# Kept as separate strings at module scope so httpx_filter.py can mirror
# the same set when splitting the output into per-code files.
STATUS_CODES = "200,301,302,401,403,404"
HTTPX_TIMEOUT = 600  # probing many subdomains takes a while


def _read_input_hosts(target_path: str):
    """Read candidate subdomains for probing. Prefers subfinder.txt
    (module 11: plain one-per-line hosts), falls back to subdomains.txt
    (module 1: hosts tagged with sources - strip the tags, httpx must
    only ever see bare hostnames)."""
    for filename, label in [("subfinder.txt", "subfinder.txt"),
                            ("subdomains.txt", "subdomains.txt")]:
        path = os.path.join(target_path, filename)
        if os.path.isfile(path):
            return path, label, _clean_hosts(path)
    return None, None, []


def _clean_hosts(path: str):
    hosts = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # skip empty lines and the "# note:" comment lines module 1 adds
            if not line or line.startswith("#"):
                continue
            # subdomains.txt tags lines like "host\t(crt.sh)" - keep the host token
            host = line.split()[0].strip()
            if host:
                hosts.append(host)
    return list(dict.fromkeys(hosts))  # order-preserving dedupe


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "live_hosts.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"hosts": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    input_path, source_label, hosts = _read_input_hosts(target_path)
    if input_path is None:
        return {
            "error": "No subfinder.txt (or subdomains.txt) found for this target - "
                     "run Subfinder or Subdomain Enumeration first; this module "
                     "probes their results for live hosts.",
            "status": 400,
        }
    if not hosts:
        return {
            "error": f"{source_label} exists but holds no usable hostnames for "
                     f"'{domain}' - run a subdomain enumeration tool first.",
            "status": 400,
        }

    result_path = os.path.join(target_path, "live_hosts.txt")
    if os.path.isfile(result_path):
        os.remove(result_path)  # a failed probe must not look like fresh output

    try:
        # -silent: no banner/progress -  -status-code -title: annotate each
        # result  -tech-detect: server/tech hints  -mc: keep all "live"
        # statuses including 401/403/404 (attack surfaces, filter later).
        proc = subprocess.run(
            ["httpx", "-silent", "-status-code", "-title", "-tech-detect",
             "-mc", STATUS_CODES],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=HTTPX_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        return {
            "error": "httpx isn't installed or isn't on your PATH. Install it with "
                     "`go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`, "
                     "then try again.",
            "status": 502,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": f"httpx timed out after {HTTPX_TIMEOUT}s and was stopped - "
                     "the target had a lot of hosts; try again or raise the timeout.",
            "status": 504,
        }

    # httpx result lines look like:
    #   https://sub.example.com [200] [Page title] [nginx]
    lines = sorted({line.strip() for line in proc.stdout.splitlines() if line.strip()})

    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    alive = [line for line in lines if _status_of(line) is not None]

    return {
        "hosts": lines,
        "count": len(alive),
        "probed": len(hosts),
        "source": source_label,
        "status_codes": STATUS_CODES,
        "note": "Includes 401/403/404 responses on purpose - live but "
                "restricted hosts are interesting. Use the Split filter module "
                "next to break them into per-status files.",
    }


def _status_of(line: str):
    """httpx annotates each result as:
        https://sub.example.com [200] [Page title] [nginx]
    The FIRST bracketed 3-digit token is always the status code (the
    title/tech brackets come after it)."""
    m = re.search(r"\[(\d{3})\]", line)
    return int(m.group(1)) if m else None
