"""
Wayback Machine URL Discovery - PASSIVE.

Pulls historical URLs for the domain from the Internet Archive's CDX API.
Fully passive - the request goes to archive.org, never the target. Often
surfaces old endpoints (dev panels, old API versions, removed pages) that
are no longer linked anywhere but may still be live.
"""
import os

import requests

CDX_URL = "http://web.archive.org/cdx/search/cdx"
USER_AGENT = "recon-framework/1.0"
MAX_RESULTS = 500


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "wayback.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"urls": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": str(MAX_RESULTS),
    }
    try:
        resp = requests.get(CDX_URL, params=params, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return {"error": "archive.org took too long to respond - try again in a bit.", "status": 504}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request to the Wayback Machine failed: {e}", "status": 502}
    except ValueError:
        return {"error": "archive.org returned an unexpected response - try again in a bit", "status": 502}

    # The first row is the column header (["original"]) - skip it.
    urls = sorted({row[0] for row in data[1:]}) if len(data) > 1 else []

    with open(os.path.join(target_path, "wayback.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    return {"urls": urls, "count": len(urls)}
