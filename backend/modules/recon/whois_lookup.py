"""
WHOIS / RDAP Lookup - PASSIVE.

Queries RDAP (the modern, structured, JSON replacement for legacy WHOIS)
via the public rdap.org bootstrap service, which redirects to whichever
registry actually holds the domain's data. Fully passive - this never
touches the target itself, only public registry servers.
"""
import os

import requests

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"
USER_AGENT = "recon-framework/1.0"


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "whois.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"whois": lines, "ran": ran}


def _entity_name(entity: dict) -> str:
    vcard = entity.get("vcardArray")
    if vcard and len(vcard) > 1:
        for item in vcard[1]:
            if item[0] == "fn" and len(item) > 3:
                return item[3]
    return entity.get("handle", "unknown")


def run(domain: str, target_path: str) -> dict:
    try:
        resp = requests.get(
            RDAP_BOOTSTRAP.format(domain=domain),
            timeout=20,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
        )
        if resp.status_code == 404:
            return {
                "error": f"No RDAP record found for '{domain}' - the domain may not exist, "
                         f"or its TLD doesn't support RDAP yet.",
                "status": 502,
            }
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return {"error": "RDAP lookup timed out - try again in a bit.", "status": 504}
    except requests.exceptions.RequestException as e:
        return {"error": f"RDAP request failed: {e}", "status": 502}
    except ValueError:
        return {"error": "RDAP server returned an unexpected (non-JSON) response.", "status": 502}

    lines = [f"Domain\t{data.get('ldhName', domain)}"]

    status = data.get("status", [])
    if status:
        lines.append(f"Status\t{', '.join(status)}")

    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action and date:
            lines.append(f"{action.capitalize()}\t{date}")

    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if roles:
            lines.append(f"{'/'.join(roles).capitalize()}\t{_entity_name(entity)}")

    for ns in data.get("nameservers", []):
        name = ns.get("ldhName")
        if name:
            lines.append(f"Nameserver\t{name}")

    with open(os.path.join(target_path, "whois.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"whois": lines, "count": len(lines)}
