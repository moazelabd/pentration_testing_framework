"""
Nmap Vulnerability Scripts (nmap --script vuln) - ACTIVE.

Reads the open ports found by Port Scan (ports.txt) and re-scans just
those ports with nmap's "vuln" NSE script category - a broad set of
scripts that check for known CVEs and common misconfigurations specific
to whatever service is listening (e.g. slowloris, heartbleed, SMB
vulnerabilities), rather than the generic top-100-ports sweep Port Scan
itself does.

This sends real, more intensive traffic to the target than a plain port
scan - only run it against in-scope, authorized targets, and only after
Port Scan has found open ports for it to focus on.
"""
import os

import nmap


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "nse_vuln.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"findings": lines, "ran": ran}


def _open_ports(target_path: str):
    """Returns None if Port Scan hasn't been run yet, else a list of
    port-number strings that were reported open."""
    ports_path = os.path.join(target_path, "ports.txt")
    if not os.path.isfile(ports_path):
        return None
    ports = []
    with open(ports_path, "r", encoding="utf-8") as f:
        for line in f:
            tokens = line.split()
            if len(tokens) < 2 or "/" not in tokens[0]:
                continue
            port, state = tokens[0].split("/")[0], tokens[1]
            if port.isdigit() and state == "open":
                ports.append(port)
    return ports


def run(domain: str, target_path: str) -> dict:
    ports = _open_ports(target_path)
    if ports is None:
        return {
            "error": "No ports.txt found for this target - run Port Scan first; "
                     "this module targets whichever ports it found open.",
            "status": 400,
        }
    if not ports:
        return {"findings": [], "count": 0, "note": "Port Scan found no open ports to target."}

    try:
        # Same PortScannerError-inside-try precaution as portscan.py - a
        # missing nmap binary must not crash the whole Flask request.
        scanner = nmap.PortScanner()
        scanner.scan(domain, ports=",".join(ports), arguments="-Pn --script vuln")
    except nmap.PortScannerError as e:
        return {
            "error": "nmap isn't installed, isn't on your system PATH, or the scan "
                     f"command itself failed. Details: {e}",
            "status": 502,
        }
    except Exception as e:
        return {"error": f"nmap vuln scan failed ({type(e).__name__}): {e}", "status": 502}

    scanned_hosts = scanner.all_hosts()
    if not scanned_hosts:
        return {
            "error": f"nmap could not resolve or reach '{domain}' for the vuln scan.",
            "status": 502,
        }

    findings = []
    host_info = scanner[scanned_hosts[0]]
    for proto in host_info.all_protocols():
        port_dict = host_info[proto]
        for port in sorted(port_dict.keys()):
            script_results = port_dict[port].get("script", {})
            for script_name, output in script_results.items():
                clean_output = " | ".join(line.strip() for line in output.splitlines() if line.strip())
                findings.append(f"{port}/{proto}\t{script_name}\t{clean_output}")

    with open(os.path.join(target_path, "nse_vuln.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(findings))

    if not findings:
        return {
            "findings": [], "count": 0, "ports_scanned": len(ports),
            "note": "No vuln-category NSE scripts reported anything on these ports.",
        }

    return {"findings": findings, "count": len(findings), "ports_scanned": len(ports)}
