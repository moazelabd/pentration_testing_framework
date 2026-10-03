"""
Tech Fingerprinting + TLS Info - ACTIVE.

One lightweight HTTP(S) request plus one TLS handshake to the target -
the same footprint as the endpoint-discovery module. Reads what the
target's own server reveals about itself: response headers, a generator
meta tag if present, and its TLS certificate.
"""
import os
import re
import socket
import ssl
from datetime import datetime, timezone

import requests

USER_AGENT = "recon-framework/1.0"
INTERESTING_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-Generator",
    "Via", "X-Cache", "CF-RAY", "X-Varnish",
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "techinfo.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"techinfo": lines, "ran": ran}


def _http_fingerprint(domain: str) -> list:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    resp = None
    for scheme in ("https", "http"):
        try:
            resp = session.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True)
            break
        except requests.exceptions.RequestException:
            continue
    if resp is None:
        return ["Error\tCould not reach the target over HTTPS or HTTP"]

    lines = []
    for header in INTERESTING_HEADERS:
        if header in resp.headers:
            lines.append(f"Header\t{header}: {resp.headers[header]}")

    cookie_names = [c.split("=")[0].strip() for c in resp.headers.get("Set-Cookie", "").split(",") if "=" in c]
    if cookie_names:
        lines.append(f"Cookies\t{', '.join(cookie_names)}")

    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', resp.text, re.I)
    if match:
        lines.append(f"Meta-generator\t{match.group(1)}")

    if not lines:
        lines.append("Header\t(server disclosed no identifying headers)")

    return lines


def _tls_info(domain: str) -> list:
    lines = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()

        lines.append(f"TLS-version\t{version}")

        not_after = cert.get("notAfter")
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            lines.append(f"Cert-expires\t{not_after} ({days_left} days left)")

        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        if sans:
            lines.append(f"Cert-SANs\t{', '.join(sans)}")

        issuer = dict(x[0] for x in cert.get("issuer", []))
        if issuer:
            lines.append(f"Cert-issuer\t{issuer.get('organizationName', issuer.get('commonName', 'unknown'))}")
    except Exception as e:
        lines.append(f"TLS\tcould not fetch certificate ({type(e).__name__}: {e})")
    return lines


def run(domain: str, target_path: str) -> dict:
    lines = _http_fingerprint(domain) + _tls_info(domain)

    with open(os.path.join(target_path, "techinfo.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"techinfo": lines, "count": len(lines)}
