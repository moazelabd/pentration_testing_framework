"""
Port Scan (nmap) - ACTIVE.

Fast scan of the top 100 TCP ports via nmap, using a TCP connect scan
(no elevated privileges required). This DOES send real traffic to the
target - only run it against in-scope, authorized targets.
"""
import os

import nmap


def get_cached(target_path: str) -> dict:
    result_path = os.path.join(target_path, "ports.txt")
    ran = os.path.isfile(result_path)
    lines = []
    if ran:
        with open(result_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
    return {"ports": lines, "ran": ran}


def run(domain: str, target_path: str) -> dict:
    try:
        # PortScanner() itself probes for the nmap binary and raises
        # PortScannerError if it's missing - this has to be inside the try
        # block too, or a missing nmap crashes the whole Flask request with
        # an unhandled exception (Flask then returns an HTML error page,
        # which breaks the frontend's res.json() with a JSON-parse error).
        scanner = nmap.PortScanner()
        # -Pn skips nmap's host-discovery ping. Without it, a target that
        # blocks ICMP (very common) gets reported as "down" even though
        # its TCP ports are reachable.
        scanner.scan(domain, arguments="-T4 -F -Pn")
    except nmap.PortScannerError as e:
        return {
            "error": "nmap isn't installed, isn't on your system PATH, or the scan "
                     "command itself failed. Install it from nmap.org (Windows) or via "
                     f"your package manager (apt/brew), then try again. Details: {e}",
            "status": 502,
        }
    except Exception as e:
        # Surface the real exception type too - this narrows down transient
        # network/permission errors (firewall or antivirus blocking the
        # app's first outbound connection) vs. a genuinely missing nmap.
        return {"error": f"nmap scan failed ({type(e).__name__}): {e}", "status": 502}

    scanned_hosts = scanner.all_hosts()
    # nmap/python-nmap keys results by the resolved IP address, not the
    # hostname you passed in - so a scan of "www.example.com" shows up
    # under its IP. Checking "domain in scanned_hosts" was the real bug
    # behind "could not resolve or reach" even on a successful scan.
    if not scanned_hosts:
        return {
            "error": f"nmap could not resolve or reach '{domain}'. "
                     f"Double-check the domain is correct and reachable.",
            "status": 502,
        }

    lines = []
    host_info = scanner[scanned_hosts[0]]
    for proto in host_info.all_protocols():
        port_dict = host_info[proto]
        for port in sorted(port_dict.keys()):
            info = port_dict[port]
            state = info.get("state", "")
            service = info.get("name", "")
            lines.append(f"{port}/{proto}  {state}  {service}".strip())

    with open(os.path.join(target_path, "ports.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return {"ports": lines, "count": len(lines)}
