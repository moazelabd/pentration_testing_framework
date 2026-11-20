"""
Live Host Discovery via httpx - ACTIVE (sends HTTP requests to the target's
subdomains - only run against in-scope, authorized targets).

Takes the subdomains collected by Subdomain Enumeration (subdomains.txt)
and probes each one with the industry-standard `httpx` CLI (github.com/projectdiscovery/
httpx) to find which hosts actually respond.

Deliberately keeps non-200 answers: -mc 200,301,302,401,403,404 means
forbidden (403), unauthorized (401) and even 404 paths are reported -
these are often the most interesting attack surfaces - while 40x noise
like 400 or dead 5xx hosts is dropped. httpx_live_filter.py splits the
result into one file per status code afterwards.

Requires ProjectDiscovery's httpx (a Go program, NOT the Python 'httpx' package):
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    or download a release: https://github.com/projectdiscovery/httpx/releases

The module looks for the right program itself: it tests every command called
`httpx` on your PATH (plus Go's default bin folder) and uses the one that is really
ProjectDiscovery's. A Python httpx CLI installed on the same machine is skipped, so
it can no longer shadow the real tool.
"""
import os
import re
import subprocess

from modules import auth_ctx

# Kept as separate strings at module scope so httpx_filter.py can mirror
# the same set when splitting the output into per-code files.
STATUS_CODES = "200,301,302,401,403,404"
HTTPX_TIMEOUT = 600  # probing many subdomains takes a while

_REAL_HTTPX = None  # path of the verified ProjectDiscovery binary (cached once found)


def _httpx_candidates():
    """Every file named httpx on PATH (in PATH order), then Go's default bin folders."""
    names = ["httpx.exe", "httpx"] if os.name == "nt" else ["httpx"]
    dirs = os.environ.get("PATH", "").split(os.pathsep)
    gopath = os.environ.get("GOPATH") or os.path.join(os.path.expanduser("~"), "go")
    dirs += [os.environ.get("GOBIN", ""), os.path.join(gopath, "bin")]
    seen, found = set(), []
    for d in dirs:
        d = d.strip().strip('"')
        if not d:
            continue
        for name in names:
            path = os.path.join(d, name)
            key = os.path.normcase(os.path.abspath(path))
            if key in seen:
                continue
            seen.add(key)
            if os.path.isfile(path):
                found.append(path)
    return found


def _is_projectdiscovery(path: str) -> bool:
    """ProjectDiscovery's httpx prints its banner / version line on -version; the
    Python httpx CLI prints a 'pip install httpx[cli]' message or an error instead."""
    try:
        proc = subprocess.run([path, "-version"], capture_output=True, text=True,
                              timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    out = ((proc.stdout or "") + (proc.stderr or "")).lower()
    return "projectdiscovery" in out or "current version" in out


def _find_real_httpx():
    """Returns (path or None, rejected) - rejected = other 'httpx' programs we skipped."""
    global _REAL_HTTPX
    if _REAL_HTTPX and os.path.isfile(_REAL_HTTPX):
        return _REAL_HTTPX, []
    rejected = []
    for path in _httpx_candidates():
        if _is_projectdiscovery(path):
            _REAL_HTTPX = path
            return path, rejected
        rejected.append(path)
    return None, rejected


def _read_input_hosts(target_path: str):
    """Read candidate subdomains for probing from subdomains.txt (hosts
    tagged with sources - strip the tags, httpx must only ever see bare
    hostnames)."""
    path = os.path.join(target_path, "subdomains.txt")
    if os.path.isfile(path):
        return path, "subdomains.txt", _clean_hosts(path)
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
            "error": "No subdomains.txt found for this target - run Subdomain "
                     "Enumeration first; this module probes its results for live hosts.",
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

    httpx_bin, rejected = _find_real_httpx()
    if httpx_bin is None:
        if rejected:
            return {
                "error": "The 'httpx' command on this machine is not ProjectDiscovery's httpx "
                         "(it looks like the Python httpx library's command: "
                         + ", ".join(rejected) + "). Install ProjectDiscovery's httpx - download "
                         "a release from github.com/projectdiscovery/httpx/releases (put httpx.exe "
                         "in a folder on your PATH) or run `go install -v "
                         "github.com/projectdiscovery/httpx/cmd/httpx@latest` - then try again. "
                         "You do not need to uninstall the Python one.",
                "status": 502,
            }
        return {
            "error": "ProjectDiscovery's httpx isn't installed or isn't on your PATH. Download a "
                     "release from github.com/projectdiscovery/httpx/releases (put httpx.exe in a "
                     "folder on your PATH) or run `go install -v "
                     "github.com/projectdiscovery/httpx/cmd/httpx@latest`, then try again.",
            "status": 502,
        }

    try:
        # -silent: no banner/progress -  -status-code -title: annotate each
        # result  -tech-detect: server/tech hints  -mc: keep all "live"
        # statuses including 401/403/404 (attack surfaces, filter later).
        proc = subprocess.run(
            [httpx_bin, "-silent", "-status-code", "-title", "-tech-detect",
             "-mc", STATUS_CODES, *auth_ctx.cli_args(auth_ctx.load(target_path))],
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
