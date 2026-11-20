"""
TLS / SSL Deep Checks - ACTIVE (a handful of TLS handshakes to the target).

Goes further than Tech Fingerprint's basic certificate dump: actively
tries to negotiate each TLS/SSL protocol version separately to see which
old, insecure ones the server still accepts (SSLv3/TLS1.0/TLS1.1 are all
deprecated and flagged by most compliance scanners), and separately
attempts a fully-verified handshake to read the specific failure reason
if one occurs - self-signed certificate, hostname mismatch, expired
certificate, or an incomplete chain.

Each protocol probe is its own lightweight TLS handshake with no HTTP
request or payload involved - still "active" in the sense that it opens
a real TCP + TLS connection to the target.
"""
import os
import socket
import ssl

TARGET_PORT = 443
CONNECT_TIMEOUT = 8

# (attribute name on the ssl module, human label, is this protocol insecure)
_PROTOCOLS = [
    ("PROTOCOL_SSLv3", "SSLv3", True),
    ("PROTOCOL_TLSv1", "TLSv1.0", True),
    ("PROTOCOL_TLSv1_1", "TLSv1.1", True),
    ("PROTOCOL_TLSv1_2", "TLSv1.2", False),
]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "tls_checks.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _probe_protocol(domain: str, attr: str):
    """True if the server accepted a handshake forced to this protocol,
    False if it refused, None if this build of Python/OpenSSL doesn't
    even support offering that protocol (very common for SSLv3/TLS1.0/1.1
    on modern systems - that absence is itself a good sign)."""
    proto = getattr(ssl, attr, None)
    if proto is None:
        return None
    try:
        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, TARGET_PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError):
        return False


def _verified_handshake_issue(domain: str):
    """Attempts a hostname-and-chain-verified handshake. Returns a finding
    string describing the problem, or None if it verified cleanly."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, TARGET_PORT), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return None
    except ssl.SSLCertVerificationError as e:
        reason = (getattr(e, "verify_message", "") or str(e)).lower()
        if "self signed" in reason or "self-signed" in reason:
            return "Self-signed certificate - browsers will show a warning page to every visitor"
        if "hostname mismatch" in reason or "doesn't match" in reason:
            return f"Certificate hostname mismatch - the cert isn't valid for '{domain}'"
        if "certificate has expired" in reason or "expired" in reason:
            return "Certificate has expired"
        if "unable to get local issuer" in reason:
            return "Incomplete certificate chain (missing intermediate certificate)"
        return f"Certificate verification failed: {e}"
    except (ssl.SSLError, OSError) as e:
        return f"Could not complete a verified TLS handshake: {e}"


def run(domain: str, target_path: str) -> dict:
    findings = []
    insecure_found = []
    any_connection_worked = False

    for attr, label, insecure in _PROTOCOLS:
        result = _probe_protocol(domain, attr)
        if result is None:
            continue
        any_connection_worked = True
        if result:
            tag = "INSECURE - still accepted" if insecure else "accepted"
            findings.append(f"{label}\t{tag}")
            if insecure:
                insecure_found.append(label)
        else:
            findings.append(f"{label}\trejected")

    cert_issue = _verified_handshake_issue(domain)
    if cert_issue is None:
        findings.append("Certificate\tverified cleanly (valid chain + hostname match)")
        any_connection_worked = True
    else:
        findings.append(f"Certificate\tISSUE: {cert_issue}")
        if "Could not complete" not in cert_issue:
            any_connection_worked = True

    if not any_connection_worked:
        return {
            "error": f"Could not open any TLS connection to '{domain}:{TARGET_PORT}' - "
                     "check the domain is correct and serves HTTPS.",
            "status": 502,
        }

    with open(os.path.join(target_path, "tls_checks.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    return {
        "findings": findings,
        "count": len(findings),
        "insecure_protocols": insecure_found,
        "cert_issue": cert_issue,
    }
