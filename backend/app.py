"""
Recon Framework - Backend
--------------------------
Passive recon (OSINT) helper for AUTHORIZED penetration testing / bug bounty
scope only. Every recon module in here queries public, third-party data
sources (like crt.sh's certificate transparency log) rather than sending
traffic to the target itself.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://localhost:5000 in your browser.
"""

import json
import os
import re
import shutil

import nmap
import requests
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

os.makedirs(TARGETS_DIR, exist_ok=True)

# Small built-in wordlist for the endpoint/directory discovery module.
# This is a quick-check list, not a full brute-force wordlist - it's meant
# to flag commonly-exposed paths, not replace a dedicated tool like
# gobuster/ffuf with a large wordlist.
COMMON_PATHS = [
    "robots.txt", "sitemap.xml", ".well-known/security.txt",
    ".git/HEAD", ".git/config", ".env", ".env.local",
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "api", "api/v1", "graphql", "swagger", "swagger-ui",
    "backup", "backups", "config", "config.php", "config.json",
    "uploads", "dashboard", "console", "server-status",
    "test", "staging", "phpinfo.php", "readme.md", "changelog.md",
]

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")


# ---------- helpers ----------

def slugify(name: str) -> str:
    """Turn a target name into a filesystem-safe folder name."""
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip().lower())
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "target"


def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def safe_target_path(target_id: str):
    """Prevent path traversal - only allow slug-safe ids that exist."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", target_id or ""):
        return None
    path = os.path.join(TARGETS_DIR, target_id)
    return path


def read_meta(target_path: str) -> dict:
    with open(os.path.join(target_path, "meta.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def write_meta(target_path: str, meta: dict) -> None:
    with open(os.path.join(target_path, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def count_lines(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return len([line for line in f if line.strip()])


# ---------- static frontend ----------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------- target CRUD ----------

@app.route("/api/targets", methods=["GET"])
def list_targets():
    targets = []
    for folder in sorted(os.listdir(TARGETS_DIR)):
        target_path = os.path.join(TARGETS_DIR, folder)
        meta_path = os.path.join(target_path, "meta.json")
        if not os.path.isfile(meta_path):
            continue
        meta = read_meta(target_path)
        meta["id"] = folder
        meta["subdomain_count"] = count_lines(os.path.join(target_path, "subdomains.txt"))
        targets.append(meta)
    return jsonify(targets)


@app.route("/api/targets", methods=["POST"])
def create_target():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    domain = clean_domain(data.get("domain") or "")

    if not name or not domain:
        return jsonify({"error": "Name and domain are required"}), 400

    folder_id = slugify(name)
    target_path = os.path.join(TARGETS_DIR, folder_id)

    if os.path.exists(target_path):
        return jsonify({"error": "A target with this name already exists"}), 409

    os.makedirs(target_path)
    meta = {"name": name, "domain": domain}
    write_meta(target_path, meta)

    meta["id"] = folder_id
    meta["subdomain_count"] = 0
    return jsonify(meta), 201


@app.route("/api/targets/<target_id>", methods=["DELETE"])
def delete_target(target_id):
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404
    shutil.rmtree(target_path)
    return jsonify({"ok": True})


# ---------- recon modules ----------

@app.route("/api/targets/<target_id>/subdomains", methods=["GET"])
def get_subdomains(target_id):
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404
    sub_path = os.path.join(target_path, "subdomains.txt")
    subs = []
    ran = os.path.isfile(sub_path)
    if ran:
        with open(sub_path, "r", encoding="utf-8") as f:
            subs = [line.strip() for line in f if line.strip()]
    return jsonify({"subdomains": subs, "ran": ran})


@app.route("/api/targets/<target_id>/subdomains", methods=["POST"])
def run_subdomain_enum(target_id):
    """
    Passive subdomain enumeration via crt.sh (certificate transparency logs).
    This never contacts the target directly - it only queries crt.sh's
    public database of issued SSL certificates.
    """
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404

    meta = read_meta(target_path)
    domain = meta["domain"]

    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=60,
            headers={"User-Agent": "recon-framework/1.0"},
        )
        if resp.status_code == 404:
            # crt.sh returns 404 (instead of an empty 200) when it has no
            # certificates at all for this domain - that's a valid "0 results",
            # not a failure.
            data = []
        else:
            resp.raise_for_status()
            data = resp.json()
    except requests.exceptions.Timeout:
        return jsonify({
            "error": "crt.sh took too long to respond (over 60s). It's a public server that "
                     "gets overloaded sometimes - wait a bit and try again."
        }), 504
    except requests.exceptions.ConnectionError as e:
        return jsonify({
            "error": f"Could not reach crt.sh - check your internet connection, or a firewall/"
                     f"antivirus on this machine may be blocking outbound requests from Python. ({e})"
        }), 502
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Request to crt.sh failed: {e}"}), 502
    except ValueError:
        return jsonify({"error": "crt.sh returned an unexpected response - try again in a bit"}), 502

    found = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            clean = line.strip().lower().lstrip("*.")
            if clean.endswith(domain):
                found.add(clean)

    subs = sorted(found)
    sub_path = os.path.join(target_path, "subdomains.txt")
    with open(sub_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs))

    return jsonify({"subdomains": subs, "count": len(subs)})


@app.route("/api/targets/<target_id>/portscan", methods=["GET"])
def get_portscan(target_id):
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404
    result_path = os.path.join(target_path, "ports.txt")
    lines = []
    ran = os.path.isfile(result_path)
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return jsonify({"ports": lines, "ran": ran})


@app.route("/api/targets/<target_id>/portscan", methods=["POST"])
def run_portscan(target_id):
    """
    Active port scan via nmap (fast scan of the top 100 ports, TCP connect
    scan - no elevated privileges required). This DOES send traffic to the
    target, so only run it against in-scope, authorized targets.
    """
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404

    meta = read_meta(target_path)
    domain = meta["domain"]

    scanner = nmap.PortScanner()
    try:
        # -Pn skips nmap's host-discovery ping. Without it, a target that
        # blocks ICMP (very common) gets reported as "down" even though its
        # TCP ports are reachable - that looked like a random first-run
        # failure but was actually every scan against a no-ping host.
        scanner.scan(domain, arguments="-T4 -F -Pn")
    except nmap.PortScannerError as e:
        return jsonify({
            "error": "nmap isn't installed, isn't on your system PATH, or the scan command "
                     "itself failed. Install it from nmap.org (Windows) or via your package "
                     f"manager (apt/brew), then try again. Details: {e}"
        }), 502
    except Exception as e:
        # Surface the real exception type too - "first click fails" bugs are
        # often a transient network/permission error (e.g. a firewall or
        # antivirus prompt blocking the app's first outbound connection)
        # rather than a missing-nmap problem, and the type narrows it down.
        return jsonify({"error": f"nmap scan failed ({type(e).__name__}): {e}"}), 502

    lines = []
    scanned_hosts = scanner.all_hosts()
    # nmap/python-nmap keys results by the resolved IP address, not the
    # hostname you passed in - so a scan of "www.arc.io" shows up under
    # e.g. "198.202.211.1". Checking "domain in scanned_hosts" was the real
    # bug behind "could not resolve or reach" even on a successful scan.
    if scanned_hosts:
        host_info = scanner[scanned_hosts[0]]
        for proto in host_info.all_protocols():
            port_dict = host_info[proto]
            for port in sorted(port_dict.keys()):
                info = port_dict[port]
                state = info.get("state", "")
                service = info.get("name", "")
                lines.append(f"{port}/{proto}  {state}  {service}".strip())
    else:
        # nmap ran but couldn't resolve/reach the host at all
        return jsonify({
            "error": f"nmap could not resolve or reach '{domain}'. "
                     f"Double-check the domain is correct and reachable."
        }), 502

    result_path = os.path.join(target_path, "ports.txt")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return jsonify({"ports": lines, "count": len(lines)})


@app.route("/api/targets/<target_id>/endpoints", methods=["GET"])
def get_endpoints(target_id):
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404
    result_path = os.path.join(target_path, "endpoints.txt")
    lines = []
    ran = os.path.isfile(result_path)
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return jsonify({"endpoints": lines, "ran": ran})


@app.route("/api/targets/<target_id>/endpoints", methods=["POST"])
def run_endpoint_discovery(target_id):
    """
    Active endpoint/directory discovery: checks a small built-in list of
    commonly-exposed paths against the target over HTTP(S). This DOES send
    requests directly to the target - authorized targets only.
    """
    target_path = safe_target_path(target_id)
    if not target_path or not os.path.isdir(target_path):
        return jsonify({"error": "not found"}), 404

    meta = read_meta(target_path)
    domain = meta["domain"]

    session = requests.Session()
    session.headers.update({"User-Agent": "recon-framework/1.0"})

    working_base = None
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        try:
            session.get(base, timeout=8, allow_redirects=True)
            working_base = base
            break
        except requests.exceptions.RequestException:
            continue

    if not working_base:
        return jsonify({
            "error": f"Could not reach '{domain}' over HTTPS or HTTP. "
                     f"Check the domain is correct and currently online."
        }), 502

    found = []
    for path in COMMON_PATHS:
        url = f"{working_base}/{path}"
        try:
            r = session.get(url, timeout=8, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 401, 403):
                found.append(f"{r.status_code}  {url}")
        except requests.exceptions.RequestException:
            continue

    result_path = os.path.join(target_path, "endpoints.txt")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write("\n".join(found))

    return jsonify({"endpoints": found, "count": len(found), "base": working_base})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
