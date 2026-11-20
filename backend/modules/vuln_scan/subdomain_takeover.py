"""
Subdomain Takeover Checker - mostly PASSIVE DNS lookups, plus one
lightweight HTTP request per matching candidate (no exploitation attempted).

For every subdomain in subdomains.txt, resolves its CNAME record and
checks if it points at a known third-party service (S3, GitHub Pages,
Heroku, Azure, Netlify, etc.). If so, it makes one HTTP request to the
subdomain and checks the response body against that service's own
"not claimed" fingerprint text - the same core signal tools like subzy /
can-i-take-over-xyz rely on.

A positive match means the CNAME points somewhere that currently has
nothing bound to this hostname - anyone could potentially register that
resource and serve their own content under YOUR subdomain. This never
attempts to actually claim or register anything.

Run Subdomain Enumeration first.
"""
import os

import dns.resolver
import requests

USER_AGENT = "recon-framework/1.0"
DNS_TIMEOUT = 5
HTTP_TIMEOUT = 8
MAX_CHECKED = 100

# (CNAME suffix to match, human label, fingerprint text on the service's
# own "unclaimed resource" page)
SERVICES = [
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("azurewebsites.net", "Azure App Service", "Error 404 - Web app not found"),
    ("cloudapp.net", "Azure Cloud Service", "Error 404 - Web app not found"),
    ("netlify.app", "Netlify", "Not Found - Request ID"),
    ("netlify.com", "Netlify", "Not Found - Request ID"),
    ("surge.sh", "Surge.sh", "project not found"),
    ("fastly.net", "Fastly", "Fastly error: unknown domain"),
    ("pantheonsite.io", "Pantheon", "The gates are closed"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("statuspage.io", "Statuspage", "You are being redirected"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "subdomain_takeover.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _read_hosts(target_path: str):
    """Returns None if Subdomain Enumeration hasn't been run yet."""
    sub_path = os.path.join(target_path, "subdomains.txt")
    if not os.path.isfile(sub_path):
        return None
    hosts = []
    with open(sub_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = line.split()[0].strip()  # strip the "(source1, source2)" tag
            if host:
                hosts.append(host)
    return list(dict.fromkeys(hosts))  # order-preserving dedupe


def _resolve_cname(host: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answer = resolver.resolve(host, "CNAME")
        return str(answer[0].target).rstrip(".").lower()
    except Exception:
        return None


def _matched_service(cname: str):
    for suffix, label, fingerprint in SERVICES:
        if cname == suffix or cname.endswith("." + suffix):
            return label, fingerprint
    return None, None


def run(domain: str, target_path: str) -> dict:
    hosts = _read_hosts(target_path)
    if hosts is None:
        return {
            "error": "No subdomains.txt found for this target - run Subdomain "
                     "Enumeration first; this module checks its results for dangling CNAMEs.",
            "status": 400,
        }
    if not hosts:
        return {"findings": [], "count": 0, "checked": 0}

    findings = []
    checked = 0

    for host in hosts[:MAX_CHECKED]:
        cname = _resolve_cname(host)
        if not cname:
            continue
        label, fingerprint = _matched_service(cname)
        if not label:
            continue

        checked += 1
        vulnerable = False
        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{host}", timeout=HTTP_TIMEOUT,
                                    headers={"User-Agent": USER_AGENT})
                if fingerprint.lower() in resp.text.lower():
                    vulnerable = True
                    break
            except requests.exceptions.RequestException:
                continue

        if vulnerable:
            findings.append(f"VULNERABLE (dangling CNAME -> {label})\t{host}\t-> {cname}")
        else:
            findings.append(f"CNAME to {label} (looks claimed/active)\t{host}\t-> {cname}")

    with open(os.path.join(target_path, "subdomain_takeover.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    vulnerable_count = len([line for line in findings if line.startswith("VULNERABLE")])
    return {"findings": findings, "count": vulnerable_count, "checked": checked, "scanned": len(hosts)}
