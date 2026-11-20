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

import os

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

import storage
from modules.monitoring import log_monitor
from modules.recon import (
    dns_records, endpoints,
    httpx_filter, httpx_live,
    js_param_collector, js_extractor, jsluice_urls,
    katana_crawl, param_collector, portscan,
    subdomains_all_in_one as subdomains,
    tech_fingerprint,
    uro_filter, waf_detect, waf_filter, wayback_urls, whois_lookup,
)
from modules import auth_ctx
from modules.vuln_scan import (
    cve_circl, cve_merge, cve_nvd, jsluice_secrets, lfi_prober, nse_vuln_scripts,
    open_redirect_prober, sqli_prober, subdomain_takeover, tls_checks,
    url_pattern_filter, web_misconfig, xss_prober,
)

app = Flask(__name__, static_folder=storage.FRONTEND_DIR, static_url_path="")


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    # Let Flask's own HTTP errors (404, 405, ...) pass through unchanged -
    # only unexpected bugs should be wrapped here.
    if isinstance(e, HTTPException):
        return e
    # Safety net: any bug in a module that isn't caught locally would
    # otherwise crash the request and make Flask return an HTML error
    # page, which breaks the frontend's res.json() with a confusing
    # "unexpected character" error instead of a readable message.
    return jsonify({"error": f"Unexpected server error ({type(e).__name__}): {e}"}), 500


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


# ---------- target authentication (optional cookie / Authorization header) ----------

def _auth_summary(target_path):
    headers = auth_ctx.load(target_path)
    # the secret itself is never sent back to the browser - only a masked summary
    return {"has_auth": bool(headers), "headers": auth_ctx.masked(headers)}


@app.route("/api/targets/<target_id>/auth", methods=["GET"])
def get_target_auth(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    return jsonify(_auth_summary(target_path))


@app.route("/api/targets/<target_id>/auth", methods=["PUT"])
def set_target_auth(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    error = auth_ctx.save(target_path, str(data.get("headers") or ""))
    if error:
        return jsonify({"error": error}), 400
    return jsonify(_auth_summary(target_path))


@app.route("/api/targets/<target_id>/auth", methods=["DELETE"])
def clear_target_auth(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    auth_ctx.save(target_path, "")
    return jsonify(_auth_summary(target_path))


# ---------- recon: subdomains ----------

@app.route("/api/targets/<target_id>/subdomains", methods=["GET"])
def get_subdomains(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = subdomains.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "subdomains.txt")
    return jsonify(result)


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
    result = portscan.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "ports.txt")
    return jsonify(result)


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
    result = endpoints.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "endpoints.txt")
    return jsonify(result)


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
    result = dns_records.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "dns_records.txt")
    return jsonify(result)


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
    result = whois_lookup.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "whois.txt")
    return jsonify(result)


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
    result = tech_fingerprint.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "techinfo.txt")
    return jsonify(result)


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
    result = wayback_urls.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "wayback.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/wayback", methods=["POST"])
def run_wayback_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(wayback_urls.run(domain, target_path))


# ---------- recon: URL cleaner (uro-inspired) ----------

@app.route("/api/targets/<target_id>/uro", methods=["GET"])
def get_uro(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = uro_filter.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "uro_urls.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/uro", methods=["POST"])
def run_uro_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(uro_filter.run(domain, target_path))


# ---------- vuln scan: URL pattern filter (gf-patterns-inspired) ----------

@app.route("/api/targets/<target_id>/urlpatterns", methods=["GET"])
def get_urlpatterns(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = url_pattern_filter.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "url_patterns.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/urlpatterns", methods=["POST"])
def run_urlpatterns_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(url_pattern_filter.run(domain, target_path))


# ---------- vuln scan: XSS reflection prober (dalfox-inspired) ----------

@app.route("/api/targets/<target_id>/xssprobe", methods=["GET"])
def get_xssprobe(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = xss_prober.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "xss_probe.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/xssprobe", methods=["POST"])
def run_xssprobe_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(xss_prober.run(domain, target_path))


# ---------- vuln scan: open redirect prober ----------

@app.route("/api/targets/<target_id>/openredirect", methods=["GET"])
def get_openredirect(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = open_redirect_prober.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "open_redirect_probe.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/openredirect", methods=["POST"])
def run_openredirect_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(open_redirect_prober.run(domain, target_path))


# ---------- vuln scan: SQL injection error-based prober ----------

@app.route("/api/targets/<target_id>/sqliprobe", methods=["GET"])
def get_sqliprobe(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = sqli_prober.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "sqli_probe.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/sqliprobe", methods=["POST"])
def run_sqliprobe_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(sqli_prober.run(domain, target_path))


# ---------- vuln scan: LFI / path traversal prober ----------

@app.route("/api/targets/<target_id>/lfiprobe", methods=["GET"])
def get_lfiprobe(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = lfi_prober.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "lfi_probe.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/lfiprobe", methods=["POST"])
def run_lfiprobe_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(lfi_prober.run(domain, target_path))


# ---------- vuln scan: TLS / SSL deep checks ----------

@app.route("/api/targets/<target_id>/tlschecks", methods=["GET"])
def get_tlschecks(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = tls_checks.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "tls_checks.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/tlschecks", methods=["POST"])
def run_tlschecks_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(tls_checks.run(domain, target_path))


# ---------- vuln scan: web misconfiguration (headers + dir listing) ----------

@app.route("/api/targets/<target_id>/webmisconfig", methods=["GET"])
def get_webmisconfig(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = web_misconfig.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "web_misconfig.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/webmisconfig", methods=["POST"])
def run_webmisconfig_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(web_misconfig.run(domain, target_path))


# ---------- vuln scan: nmap vuln NSE scripts ----------

@app.route("/api/targets/<target_id>/nsevuln", methods=["GET"])
def get_nsevuln(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = nse_vuln_scripts.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "nse_vuln.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/nsevuln", methods=["POST"])
def run_nsevuln_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(nse_vuln_scripts.run(domain, target_path))


# ---------- vuln scan: subdomain takeover checker ----------

@app.route("/api/targets/<target_id>/subtakeover", methods=["GET"])
def get_subtakeover(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = subdomain_takeover.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "subdomain_takeover.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/subtakeover", methods=["POST"])
def run_subtakeover_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(subdomain_takeover.run(domain, target_path))


# ---------- vuln scan: CVE lookup via NVD ----------

@app.route("/api/targets/<target_id>/cve_nvd", methods=["GET"])
def get_cve_nvd(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = cve_nvd.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "cve_nvd.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/cve_nvd", methods=["POST"])
def run_cve_nvd_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(cve_nvd.run(domain, target_path))


# ---------- vuln scan: CVE lookup via CIRCL ----------

@app.route("/api/targets/<target_id>/cve_circl", methods=["GET"])
def get_cve_circl(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = cve_circl.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "cve_circl.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/cve_circl", methods=["POST"])
def run_cve_circl_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(cve_circl.run(domain, target_path))


# ---------- vuln scan: CVE merge (dedupe NVD + CIRCL) ----------

@app.route("/api/targets/<target_id>/cve_merge", methods=["GET"])
def get_cve_merge(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = cve_merge.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "cve_merged.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/cve_merge", methods=["POST"])
def run_cve_merge_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(cve_merge.run(domain, target_path))


# ---------- recon: parameter collection (feeds active testing) ----------

@app.route("/api/targets/<target_id>/all_params", methods=["GET"])
def get_all_params(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = param_collector.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "all_params.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/all_params", methods=["POST"])
def run_all_params_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(param_collector.run(domain, target_path))


# ---------- recon: live host probe (industry-standard httpx) ----------

@app.route("/api/targets/<target_id>/httpx_live", methods=["GET"])
def get_httpx_live(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = httpx_live.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "live_hosts.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/httpx_live", methods=["POST"])
def run_httpx_live_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(httpx_live.run(domain, target_path))


# ---------- recon: live host status-code splitter ----------

@app.route("/api/targets/<target_id>/httpx_filter", methods=["GET"])
def get_httpx_filter(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = httpx_filter.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "live_200.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/httpx_filter", methods=["POST"])
def run_httpx_filter_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(httpx_filter.run(domain, target_path))


# ---------- recon: katana live-host web crawler ----------

@app.route("/api/targets/<target_id>/katana", methods=["GET"])
def get_katana(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = katana_crawl.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "katana_urls.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/katana", methods=["POST"])
def run_katana_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(katana_crawl.run(domain, target_path))


# ---------- recon: JS file extraction from katana output ----------

@app.route("/api/targets/<target_id>/js_extractor", methods=["GET"])
def get_js_extractor(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = js_extractor.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "js_files.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/js_extractor", methods=["POST"])
def run_js_extractor_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(js_extractor.run(domain, target_path))


# ---------- recon: jsluice JS analysis (urls mode) ----------

@app.route("/api/targets/<target_id>/jsluice_urls", methods=["GET"])
def get_jsluice_urls(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = jsluice_urls.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "jsluice_urls.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/jsluice_urls", methods=["POST"])
def run_jsluice_urls_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(jsluice_urls.run(domain, target_path))


# ---------- recon: jsluice JS analysis (secrets mode) ----------

@app.route("/api/targets/<target_id>/jsluice_secrets", methods=["GET"])
def get_jsluice_secrets(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = jsluice_secrets.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "jsluice_secrets_summary.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/jsluice_secrets", methods=["POST"])
def run_jsluice_secrets_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(jsluice_secrets.run(domain, target_path))


# ---------- recon: JS parameter aggregation for the next phase ----------

@app.route("/api/targets/<target_id>/js_params", methods=["GET"])
def get_js_params(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = js_param_collector.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "all_params.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/js_params", methods=["POST"])
def run_js_params_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(js_param_collector.run(domain, target_path))


# ---------- recon: WAF detection (industry-standard wafw00f) ----------

@app.route("/api/targets/<target_id>/waf", methods=["GET"])
def get_waf(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = waf_detect.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "waf_summary.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/waf", methods=["POST"])
def run_waf_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(waf_detect.run(domain, target_path))


# ---------- recon: WAF presence splitter ----------

@app.route("/api/targets/<target_id>/waf_filter", methods=["GET"])
def get_waf_filter(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    result = waf_filter.get_cached(target_path)
    result["updated_at"] = storage.updated_at(target_path, "hosts_with_waf.txt")
    return jsonify(result)


@app.route("/api/targets/<target_id>/waf_filter", methods=["POST"])
def run_waf_filter_route(target_id):
    target_path = resolve_target(target_id)
    if not target_path:
        return jsonify({"error": "not found"}), 404
    domain = storage.read_meta(target_path)["domain"]
    return module_result(waf_filter.run(domain, target_path))




# ---------- monitoring (built-in, was "Coming soon") ----------
# The Monitoring page on the landing screen. Logs are indexed globally
# (by link or by file/paste) into backend/monitoring_data/logs.jsonl,
# and the page searches that store. No watchlist/sources/alerts cards
# in the UI any more, but their API routes stay so old data still loads.

@app.route("/api/monitoring/status", methods=["GET"])
def monitoring_status():
    return jsonify(log_monitor.status())


@app.route("/api/monitoring/search", methods=["GET"])
def monitoring_search():
    q = request.args.get("q", "")
    field = request.args.get("field", "all")
    source = request.args.get("source", "")
    results = log_monitor.search(q, field, source)
    return jsonify({"results": results, "count": len(results)})


@app.route("/api/monitoring/ingest", methods=["POST"])
def monitoring_ingest():
    data = request.get_json(force=True, silent=True) or {}
    text = data.get("text") or ""
    if not text.strip():
        return jsonify({"error": "No log text provided"}), 400
    return jsonify(log_monitor.append_text(text, data.get("source") or "import"))


@app.route("/api/monitoring/ingest-url", methods=["POST"])
def monitoring_ingest_url():
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    res = log_monitor.fetch_url(url)
    if "error" in res:
        return jsonify({"error": res["error"]}), 502
    result = log_monitor.append_text(res["text"], url)
    result["url"] = url
    return jsonify(result)


@app.route("/api/monitoring/watchlist", methods=["GET", "POST"])
def monitoring_watchlist():
    path = os.path.join(log_monitor.DATA, "watchlist.json")
    items = log_monitor._load(path, [])
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        value = (data.get("value") or "").strip()
        if value and value not in items:
            items.append(value)
            log_monitor._save(path, items)
        return jsonify({"items": items})
    return jsonify({"items": items})


@app.route("/api/monitoring/watchlist/<int:i>", methods=["DELETE"])
def monitoring_watchlist_delete(i):
    path = os.path.join(log_monitor.DATA, "watchlist.json")
    items = log_monitor._load(path, [])
    if 0 <= i < len(items):
        items.pop(i)
        log_monitor._save(path, items)
    return jsonify({"items": items})


@app.route("/api/monitoring/sources", methods=["GET", "POST"])
def monitoring_sources():
    path = os.path.join(log_monitor.DATA, "sources.json")
    items = log_monitor._load(path, [])
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        if data.get("name"):
            items.append(data)
            log_monitor._save(path, items)
        return jsonify({"items": items})
    return jsonify({"items": items})


@app.route("/api/monitoring/sources/<int:i>", methods=["DELETE"])
def monitoring_sources_delete(i):
    path = os.path.join(log_monitor.DATA, "sources.json")
    items = log_monitor._load(path, [])
    if 0 <= i < len(items):
        items.pop(i)
        log_monitor._save(path, items)
    return jsonify({"items": items})


@app.route("/api/monitoring/alerts", methods=["GET"])
def monitoring_alerts():
    return jsonify({"items": log_monitor._load(os.path.join(log_monitor.DATA, "alerts.json"), [])})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
