"""
Subdomain Enumeration - PASSIVE.

Pulls subdomains from public SSL certificate logs via crt.sh. This never
contacts the target directly - it only queries crt.sh's public database
of issued certificates.

Every function here returns a plain dict - no Flask objects - so it can
be reused or unit-tested outside a request context. run() returns either
{"error": str, "status": int} on failure, or the success payload on success.
"""
import os

import requests

CRTSH_URL = "https://crt.sh/"
USER_AGENT = "recon-framework/1.0"


def get_cached(target_path: str) -> dict:
    sub_path = os.path.join(target_path, "subdomains.txt")
    ran = os.path.isfile(sub_path)
    subs = []
    if ran:
        with open(sub_path, "r", encoding="utf-8") as f:
            subs = [line.strip() for line in f if line.strip()]
    return {"subdomains": subs, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=60,
            headers={"User-Agent": USER_AGENT},
        )
        if resp.status_code == 404:
            # crt.sh returns 404 (instead of an empty 200) when it has no
            # certificates at all for this domain - that's a valid "0
            # results", not a failure.
            data = []
        else:
            resp.raise_for_status()
            data = resp.json()
    except requests.exceptions.Timeout:
        return {
            "error": "crt.sh took too long to respond (over 60s). It's a public server "
                     "that gets overloaded sometimes - wait a bit and try again.",
            "status": 504,
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "error": f"Could not reach crt.sh - check your internet connection, or a "
                     f"firewall/antivirus on this machine may be blocking outbound "
                     f"requests from Python. ({e})",
            "status": 502,
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Request to crt.sh failed: {e}", "status": 502}
    except ValueError:
        return {"error": "crt.sh returned an unexpected response - try again in a bit", "status": 502}

    found = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            clean = line.strip().lower().lstrip("*.")
            if clean.endswith(domain):
                found.add(clean)

    subs = sorted(found)
    with open(os.path.join(target_path, "subdomains.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs))

    return {"subdomains": subs, "count": len(subs)}
