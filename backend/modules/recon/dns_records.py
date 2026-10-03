"""
DNS Records Enumeration - mostly PASSIVE.

Looks up standard DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) through a
resolver - that traffic goes to a DNS resolver, not to the target's own
infrastructure, so it's passive in the same sense as the crt.sh lookup.

The one exception is the zone transfer (AXFR) attempt: that query goes
directly to the target's own authoritative nameservers, so it IS a small
amount of active traffic to target-controlled infrastructure - though a
server that still allows it is a genuinely valuable, common finding.
"""
import os

import dns.query
import dns.resolver
import dns.zone

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "dns_records.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"records": lines, "ran": ran}


def _lookup_records(domain: str) -> list:
    lines = []
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=10)
            for rdata in answers:
                lines.append(f"{rtype}\t{rdata.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            lines.append(f"{rtype}\terror: {type(e).__name__}: {e}")
    return lines


def _try_zone_transfer(domain: str) -> list:
    """Ask each authoritative nameserver for a full zone transfer. A modern,
    correctly-configured nameserver will refuse this - that's the expected,
    secure outcome. If one allows it, the whole DNS zone just leaked."""
    lines = []
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=10)
    except Exception:
        return lines

    for ns in ns_answers:
        ns_host = str(ns.target).rstrip(".")
        try:
            ns_ip = str(dns.resolver.resolve(ns_host, "A", lifetime=10)[0])
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, lifetime=10))
            names = sorted(str(n) for n in zone.nodes.keys())
            lines.append(
                f"AXFR\tSUCCEEDED on {ns_host} ({ns_ip}) - {len(names)} records "
                f"leaked! This nameserver is misconfigured."
            )
            for name in names[:50]:
                lines.append(f"AXFR\t  {name}.{domain}")
        except Exception:
            lines.append(f"AXFR\trefused/failed on {ns_host} (expected - this is normal, secure behavior)")
    return lines


def run(domain: str, target_path: str) -> dict:
    lines = _lookup_records(domain)
    lines += _try_zone_transfer(domain)

    if not lines:
        return {
            "error": f"No DNS records found for '{domain}'. Double-check the domain is correct.",
            "status": 502,
        }

    with open(os.path.join(target_path, "dns_records.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"records": lines, "count": len(lines)}
