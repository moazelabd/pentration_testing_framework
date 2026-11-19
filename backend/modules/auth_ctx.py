"""
Authenticated scanning support (optional, per target).

A target can carry extra HTTP headers - normally a session Cookie and/or an
Authorization header of a TEST account - so tools that talk to the target can reach
pages behind the login. Use a test account you are authorized to use, never a real
user's session.

Where it is stored: targets/<id>/auth.txt, one "Name: value" per line. A nested
.gitignore is written next to it so the secret is never committed by accident.

Where it is sent (and where it is NOT):
  - ONLY to the target's own domain and its subdomains. Third-party lookups (crt.sh,
    Wayback, RDAP, NVD...) never get it, and a redirect to another domain strips it.
  - Used by: Live Host Probe (httpx), Web Crawler (katana), Tech Fingerprint,
    Endpoint Discovery and the XSS Reflection Prober.
"""
import os
import re
from urllib.parse import urlsplit

import requests

AUTH_FILE = "auth.txt"
MAX_HEADERS = 10
MAX_VALUE_LEN = 8192
_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_FORBIDDEN = {"host", "content-length", "transfer-encoding", "connection", "upgrade"}


def parse_headers(text: str):
    """'Name: value' lines -> (headers dict, error or None).

    A line that is just a cookie string ("sessionid=abc; csrftoken=xyz") is accepted and
    treated as the Cookie header. Several Cookie lines are joined with '; '.
    """
    headers = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not _NAME_RE.match(name) or " " in name:
            # not "Name: value" -> maybe a bare cookie string
            if "=" in line and "\r" not in line and "\n" not in line:
                name, value = "Cookie", line
            else:
                return None, f"Could not read this line (use 'Name: value'): {line[:40]}"
        if name.lower() in _FORBIDDEN:
            return None, f"The header '{name}' is not allowed here."
        if not value:
            return None, f"The header '{name}' has no value."
        if len(value) > MAX_VALUE_LEN or any(ord(c) < 32 or ord(c) == 127 for c in value):
            return None, f"The value of '{name}' is too long or has control characters."
        key = next((k for k in headers if k.lower() == name.lower()), None)
        if key and key.lower() == "cookie":
            headers[key] = headers[key] + "; " + value
        else:
            headers[key or name] = value
        if len(headers) > MAX_HEADERS:
            return None, f"At most {MAX_HEADERS} headers are allowed."
    return headers, None


def load(target_path: str) -> dict:
    path = os.path.join(target_path, AUTH_FILE)
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        headers, _ = parse_headers(f.read())
    return headers or {}


def save(target_path: str, text: str):
    """Validates and stores the headers. Empty text clears them. Returns an error or None."""
    path = os.path.join(target_path, AUTH_FILE)
    if not (text or "").strip():
        if os.path.isfile(path):
            os.remove(path)
        return None
    headers, error = parse_headers(text)
    if error:
        return error
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(f"{k}: {v}" for k, v in headers.items()))
    gi = os.path.join(target_path, ".gitignore")
    if not os.path.isfile(gi):
        with open(gi, "w", encoding="utf-8") as f:
            f.write(AUTH_FILE + "\n")
    return None


def masked(headers: dict) -> list:
    """Safe-to-display summary - the secret itself is never sent back to the browser."""
    out = []
    for name, value in headers.items():
        out.append(f"{name}: {value[:6]}... ({len(value)} chars)" if len(value) > 10
                   else f"{name}: ({len(value)} chars)")
    return out


def cli_args(headers: dict) -> list:
    """['-H', 'Name: value', ...] for httpx / katana (given as a list, never via a shell)."""
    args = []
    for name, value in headers.items():
        args += ["-H", f"{name}: {value}"]
    return args


class AuthSession(requests.Session):
    """requests.Session that adds the auth headers only for the target's own domain."""

    def __init__(self, domain: str, headers: dict):
        super().__init__()
        self._scope = (domain or "").lower().strip(".")
        self._auth = dict(headers or {})

    def _in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return bool(self._scope) and (host == self._scope or host.endswith("." + self._scope))

    def _apply(self, headers):
        for name, value in self._auth.items():
            if name.lower() == "cookie":
                # keep cookies the server set during this session next to the login cookie
                existing = headers.get("Cookie")
                if existing:
                    value = value + "; " + existing
            headers[name] = value

    def prepare_request(self, request):
        prepared = super().prepare_request(request)
        if self._auth and self._in_scope(prepared.url):
            self._apply(prepared.headers)
        return prepared

    def rebuild_auth(self, prepared_request, response):
        super().rebuild_auth(prepared_request, response)
        # Called on every redirect hop. requests itself drops the Cookie header here, so put
        # it back for the target's own domain - and make sure nothing leaks to other domains.
        if self._in_scope(prepared_request.url):
            self._apply(prepared_request.headers)
        else:
            for name in self._auth:
                prepared_request.headers.pop(name, None)


def make_session(domain: str, target_path: str, user_agent: str) -> requests.Session:
    session = AuthSession(domain, load(target_path))
    session.headers.update({"User-Agent": user_agent})
    return session
