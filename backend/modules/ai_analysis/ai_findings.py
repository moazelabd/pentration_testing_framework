"""
AI Findings Analyst - reads every result file already collected for a
target (Recon + Vulnerability Scan) and asks an LLM (OpenAI) to triage
them into one report: severity ranking, a false-positive call on each
signal from the active probers, a plain-English explanation of every
CVE, and a suggested fix.

This sends no traffic to the target itself - only the text already saved
on disk gets sent to OpenAI's API. Nothing here is a substitute for a
human reviewing the actual findings before they go in a client report.

API key: NOT stored per-target. Each person running this framework pastes
their own OpenAI key once (Settings panel in the UI); it's saved locally
in <project-root>/backend/openai.key, which .gitignore already excludes
(matches the repo's existing "*.key" rule) - it never gets committed and
is never sent anywhere except OpenAI's own API.
"""
import json
import os

import requests

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "openai.key")
KEY_FILE = os.path.normpath(KEY_FILE)

API_URL = "https://api.openai.com/v1/chat/completions"
MODEL = "gpt-4o-mini"
REQUEST_TIMEOUT = 90

# Result files worth sending - everything else in a target folder is
# plumbing (meta.json) or secrets that must never leave the machine (auth.txt).
INCLUDE_FILES = [
    "subdomains.txt", "live_hosts.txt", "dns_records.txt", "whois.txt",
    "techinfo.txt", "ports.txt", "waf.txt", "endpoints.txt", "wayback.txt",
    "js_files.txt", "jsluice_urls.txt", "jsluice_secrets.txt",
    "url_patterns.txt", "xss_probe.txt", "open_redirect_probe.txt",
    "sqli_probe.txt", "lfi_probe.txt", "tls_checks.txt", "web_misconfig.txt",
    "nse_vuln.txt", "subdomain_takeover.txt",
    "cve_nvd.txt", "cve_circl.txt", "cve_merge.txt",
]
MAX_CHARS_PER_FILE = 6000
MAX_TOTAL_CHARS = 60000

SYSTEM_PROMPT = """You are a senior penetration tester triaging raw tool output for a \
client report. You will be given the saved results of several recon and \
vulnerability-scanning tools run against one authorized target. Some of \
these tools (XSS/SQLi/LFI/Open Redirect probers) only report a SIGNAL, not \
proof - judge each one on its merits and say plainly when something looks \
like a false positive.

Reply in Markdown with exactly these sections, in this order:

## Summary
2-4 sentences: overall risk posture of this target.

## Findings by severity
For each real finding (skip pure noise), one entry:
- **[Critical|High|Medium|Low|Info] <short title>** - which tool reported it, \
your assessment of whether it's a true positive or likely false positive \
and why, and a one-line suggested fix.

## CVEs explained
For each CVE in the CVE Lookup results, 1-2 plain-English sentences on what \
it actually lets an attacker do - skip this section if there are none.

Do not invent findings that are not supported by the provided text."""


def _key_path_exists() -> bool:
    return os.path.isfile(KEY_FILE)


def has_key() -> bool:
    return _key_path_exists() and bool(_read_key())


def _read_key() -> str:
    if not _key_path_exists():
        return ""
    with open(KEY_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def save_key(raw_key: str):
    """Returns an error string, or None on success. Empty string clears the key."""
    key = (raw_key or "").strip()
    if not key:
        if _key_path_exists():
            os.remove(KEY_FILE)
        return None
    if not key.startswith("sk-") or len(key) < 20 or "\n" in key or "\r" in key:
        return "That doesn't look like a valid OpenAI API key (should start with 'sk-')."
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return None


def key_status() -> dict:
    key = _read_key()
    if not key:
        return {"has_key": False}
    return {"has_key": True, "masked": f"{key[:7]}...{key[-4:]}"}


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "ai_report.txt")
    ran = os.path.isfile(result_path)
    report = ""
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            report = f.read()
    return {"report": report, "ran": ran}


def _collect_context(target_path: str) -> str:
    chunks = []
    total = 0
    for name in INCLUDE_FILES:
        path = os.path.join(target_path, name)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
        if not content:
            continue
        content = content[:MAX_CHARS_PER_FILE]
        chunk = f"### {name}\n{content}"
        if total + len(chunk) > MAX_TOTAL_CHARS:
            break
        chunks.append(chunk)
        total += len(chunk)
    return "\n\n".join(chunks)


def run(domain: str, target_path: str) -> dict:
    api_key = _read_key()
    if not api_key:
        return {
            "error": "No OpenAI API key saved yet - add yours in the AI Analysis panel first.",
            "status": 400,
        }

    context = _collect_context(target_path)
    if not context:
        return {
            "error": "No Recon / Vulnerability Scan results found yet for this target - "
                     "run those tools first so there's something to analyze.",
            "status": 400,
        }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Target: {domain}\n\nSaved tool results:\n\n{context}"},
        ],
        "temperature": 0.2,
    }

    try:
        resp = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        return {"error": f"Could not reach OpenAI's API: {e}", "status": 502}

    if resp.status_code == 401:
        return {"error": "OpenAI rejected the saved API key (401) - check it's correct and active.",
                "status": 401}
    if resp.status_code == 429:
        return {"error": "OpenAI rate-limited this key (429) - wait a bit and try again, "
                          "or check your usage/billing on platform.openai.com.", "status": 429}
    if resp.status_code != 200:
        return {"error": f"OpenAI API error ({resp.status_code}): {resp.text[:300]}",
                "status": 502}

    try:
        report = resp.json()["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, ValueError) as e:
        return {"error": f"Unexpected response shape from OpenAI: {e}", "status": 502}

    with open(os.path.join(target_path, "ai_report.txt"), "w", encoding="utf-8") as f:
        f.write(report)

    return {"report": report}
