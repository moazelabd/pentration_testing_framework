"""
Recon Framework - Backend
--------------------------
Flask routes only. Target storage lives in storage.py; each recon tool
lives in its own file under modules/recon/ (and modules/vuln_scan/ for the
next phase). Every module documents whether it's passive (only queries
third-party sources) or active (sends traffic to the target itself).

Run:
    pip install -r requirements.txt
    python app.py
Then open http://localhost:5000 in your browser.
"""

from flask import Flask, jsonify, request, send_from_directory

import storage
from modules.recon import dns_records, endpoints, portscan, subdomains_all_in_one as subdomains, tech_fingerprint, wayback_urls, whois_lookup

app = Flask(__name__, static_folder=storage.FRONTEND_DIR, static_url_path="")


def module_result(result: dict):
    """Turn a module's return dict into a Flask (json, status) response."""
    if "error" in result:
        return jsonify({"error": result["error"]}), result.get("status", 502)
    return jsonify(result)


def resolve_target(target_id: str):
    """Returns the target's folder path, or None if invalid/not found."""
    target_path = storage.safe_target_path(target_id)
    if not storage.target_exists(target_path):
        return None
    return target_path


# ---------- static frontend ----------

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------- target CRUD ----------

@app.route("/api/targets", methods=["GET"])
def list_targets():
    return jsonify(storage.list_targets())


@app.route("/api/targets", methods=["POST"])
def create_target():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    domain = storage.clean_domain(data.get("domain") or "")

    if not name or not domain:
        return jsonify({"error": "Name and domain are required"}), 400

    meta = storage.create_target(name, domain)
    if meta is None:
        return jsonify({"error": "A target with this name already exists"}), 409
    return jsonify(meta), 201


@app.route("/api/targets/<target_id>", methods=["DELETE"])
def delete_target_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    storage.delete_target(target_path)
    return jsonify({"ok": True})


# ---------- recon: subdomains ----------

@app.route("/api/targets/<target_id>/subdomains", methods=["GET"])
def get_subdomains(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(subdomains.get_cached(target_path))


@app.route("/api/targets/<target_id>/subdomains", methods=["POST"])
def run_subdomain_enum(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(subdomains.run(domain, target_path))


# ---------- recon: port scan ----------

@app.route("/api/targets/<target_id>/portscan", methods=["GET"])
def get_portscan(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(portscan.get_cached(target_path))


@app.route("/api/targets/<target_id>/portscan", methods=["POST"])
def run_portscan_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(portscan.run(domain, target_path))


# ---------- recon: endpoint discovery ----------

@app.route("/api/targets/<target_id>/endpoints", methods=["GET"])
def get_endpoints(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(endpoints.get_cached(target_path))


@app.route("/api/targets/<target_id>/endpoints", methods=["POST"])
def run_endpoint_discovery_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(endpoints.run(domain, target_path))


# ---------- recon: DNS records ----------

@app.route("/api/targets/<target_id>/dns", methods=["GET"])
def get_dns_records(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(dns_records.get_cached(target_path))


@app.route("/api/targets/<target_id>/dns", methods=["POST"])
def run_dns_records_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(dns_records.run(domain, target_path))


# ---------- recon: WHOIS / RDAP ----------

@app.route("/api/targets/<target_id>/whois", methods=["GET"])
def get_whois(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(whois_lookup.get_cached(target_path))


@app.route("/api/targets/<target_id>/whois", methods=["POST"])
def run_whois_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(whois_lookup.run(domain, target_path))


# ---------- recon: tech fingerprint + TLS ----------

@app.route("/api/targets/<target_id>/techinfo", methods=["GET"])
def get_techinfo(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(tech_fingerprint.get_cached(target_path))


@app.route("/api/targets/<target_id>/techinfo", methods=["POST"])
def run_techinfo_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(tech_fingerprint.run(domain, target_path))


# ---------- recon: Wayback Machine URLs ----------

@app.route("/api/targets/<target_id>/wayback", methods=["GET"])
def get_wayback(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(wayback_urls.get_cached(target_path))


@app.route("/api/targets/<target_id>/wayback", methods=["POST"])
def run_wayback_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(wayback_urls.run(domain, target_path))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
