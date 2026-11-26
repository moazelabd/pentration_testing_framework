import nmap

from modules.recon import portscan


class FakeScanner:
    """Stands in for nmap.PortScanner() so no real nmap binary is needed."""

    def __init__(self, scan_result=None):
        self.scan_calls = []
        self._hosts = {"93.184.216.34": {"tcp": {80: {"state": "open", "name": "http"}}}}

    def scan(self, domain, arguments, timeout=None):
        self.scan_calls.append({"domain": domain, "arguments": arguments, "timeout": timeout})

    def all_hosts(self):
        return list(self._hosts.keys())

    def __getitem__(self, host):
        info = self._hosts[host]
        return _HostInfo(info)


class _HostInfo:
    def __init__(self, protocols):
        self._protocols = protocols

    def all_protocols(self):
        return list(self._protocols.keys())

    def __getitem__(self, proto):
        return self._protocols[proto]


def test_scan_passes_a_timeout_so_it_cannot_hang_forever(target_path, monkeypatch):
    """Regression test: a missing `timeout=` on scanner.scan() lets a slow or
    filtered target hang the request (and the worker serving it) indefinitely."""
    fake = FakeScanner()
    monkeypatch.setattr(portscan.nmap, "PortScanner", lambda: fake)

    result = portscan.run("example.test", target_path)

    assert fake.scan_calls, "scanner.scan() was never called"
    assert fake.scan_calls[0]["timeout"] is not None
    assert fake.scan_calls[0]["timeout"] > 0
    assert result["count"] == 1
    assert "80/tcp" in result["ports"][0]


def test_missing_nmap_binary_returns_actionable_error(target_path, monkeypatch):
    def explode():
        raise nmap.PortScannerError("nmap program was not found in path")

    monkeypatch.setattr(portscan.nmap, "PortScanner", explode)

    result = portscan.run("example.test", target_path)

    assert result["status"] == 502
    assert "nmap" in result["error"].lower()


def test_unreachable_target_returns_actionable_error(target_path, monkeypatch):
    class EmptyScanner(FakeScanner):
        def all_hosts(self):
            return []

    monkeypatch.setattr(portscan.nmap, "PortScanner", EmptyScanner)

    result = portscan.run("doesnotresolve.example.test", target_path)

    assert result["status"] == 502
    assert "could not resolve or reach" in result["error"]
