"""
Subdomain Enumeration - "all-in-one" - PASSIVE.

Replaces the old crt.sh-only version. Queries 3 independent, free,
no-API-key passive sources in parallel-ish fashion and MERGES the results,
removing duplicates:

  - crt.sh          certificate transparency logs
  - CertSpotter      certificate transparency logs (different vantage point/
                      coverage than crt.sh - catches certs crt.sh misses)
  - HackerTarget      passive DNS / hostsearch (not cert-based at all, so it
                      can surface subdomains that never got a cert)

No single source finds everything - that's exactly why the old single-
source version was weak. Each result line is tagged with which source(s)
found it. If one or two sources fail or hit their free-tier rate limit,
the others still contribute - this only fails if ALL of them come back
empty.
"""
import os

import requests

USER_AGENT = "recon-framework/1.0"


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "subdomains.txt")
    ran = os.path.isfile(result_path)
    subs = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            subs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return {"subdomains": subs, "ran": ran}


def _from_crtsh(domain: str):
    found = set()
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=60,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 404:
            return found, None  # genuinely zero certs - not a failure
        resp.raise_for_status()
        for entry in resp.json():
            for line in entry.get("name_value", "").split("\n"):
                clean = line.strip().lower().lstrip("*.")
                if clean.endswith(domain):
                    found.add(clean)
        return found, None
    except requests.exceptions.Timeout:
        return found, "crt.sh timed out"
    except requests.exceptions.RequestException as e:
        return found, f"crt.sh failed: {e}"
    except ValueError:
        return found, "crt.sh returned an unexpected (non-JSON) response"


def _from_certspotter(domain: str):
    found = set()
    try:
        resp = requests.get(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 429:
            return found, "certspotter rate-limited (free tier) - skipped this run"
        resp.raise_for_status()
        for entry in resp.json():
            for name in entry.get("dns_names", []):
                clean = name.strip().lower().lstrip("*.")
                if clean.endswith(domain):
                    found.add(clean)
        return found, None
    except requests.exceptions.Timeout:
        return found, "certspotter timed out"
    except requests.exceptions.RequestException as e:
        return found, f"certspotter failed: {e}"
    except ValueError:
        return found, "certspotter returned an unexpected (non-JSON) response"


def _from_hackertarget(domain: str):
    found = set()
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=30,
            headers={"User-Agent": USER_AGENT},
        )
        resp.raise_for_status()
        text = resp.text.strip()
        if not text or "error" in text.lower() or "api count exceeded" in text.lower():
            return found, "hackertarget returned no usable results (free daily quota may be used up)"
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host.endswith(domain):
                found.add(host)
        return found, None
    except requests.exceptions.Timeout:
        return found, "hackertarget timed out"
    except requests.exceptions.RequestException as e:
        return found, f"hackertarget failed: {e}"


def run(domain: str, target_path: str) -> dict:
    sources = {
        "crt.sh": _from_crtsh(domain),
        "certspotter": _from_certspotter(domain),
        "hackertarget": _from_hackertarget(domain),
    }

    merged = {}  # hostname -> set of source names that found it
    warnings = []
    for source_name, (found, warning) in sources.items():
        for host in found:
            merged.setdefault(host, set()).add(source_name)
        if warning:
            warnings.append(f"{source_name}: {warning}")

    if not merged:
        detail = " | ".join(warnings) if warnings else "double-check the domain is correct."
        return {"error": f"No subdomains found - every source came back empty. {detail}", "status": 502}

    lines = [f"{host}\t({', '.join(sorted(srcs))})" for host, srcs in sorted(merged.items())]
    if warnings:
        lines.append("")
        lines.extend(f"# note: {w}" for w in warnings)

    with open(os.path.join(target_path, "subdomains.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"subdomains": lines, "count": len(merged), "sources_used": list(sources.keys())}
