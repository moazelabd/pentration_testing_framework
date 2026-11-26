import os

from modules.vuln_scan import sqli_prober


class FakeResp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class FakeSession:
    """Stands in for auth_ctx.make_session()'s requests.Session. Returns a
    canned response based on which payload is in the URL, so no real HTTP
    request is ever made."""

    def __init__(self, responses):
        self.responses = responses  # list of (match_fn, FakeResp)
        self.calls = []

    def get(self, url, timeout=8, allow_redirects=True):
        self.calls.append(url)
        for match, resp in self.responses:
            if match(url):
                return resp
        return FakeResp("")  # default: empty 200, no error, no SQLi


def _patch_session(monkeypatch, fake_session):
    monkeypatch.setattr(sqli_prober.auth_ctx, "make_session", lambda *a, **k: fake_session)


def _write_url_patterns(target_path, url):
    with open(os.path.join(target_path, "url_patterns.txt"), "w", encoding="utf-8") as f:
        f.write(f"{url}\tsqli\n")


def test_error_based_detection_short_circuits_boolean_pass(target_path, monkeypatch):
    url = "http://example.test/item?id=1"
    _write_url_patterns(target_path, url)

    fake = FakeSession([
        # the raw "'" probe gets URL-encoded to %27 by urlencode()
        (lambda u: "%27" in u, FakeResp("You have an error in your SQL syntax near '")),
    ])
    _patch_session(monkeypatch, fake)

    result = sqli_prober.run("example.test", target_path)

    assert result["count"] == 1
    assert "MySQL" in result["findings"][0]
    # Only the 1 error probe should have fired for this param - the
    # boolean-blind pair is skipped once an error signature already matched.
    assert result["tested"] == 1


def test_boolean_blind_detected_when_lengths_differ(target_path, monkeypatch):
    url = "http://example.test/item?id=1"
    _write_url_patterns(target_path, url)

    # TRUE_PAYLOAD/FALSE_PAYLOAD survive URL-encoding with their " OR "/" AND "
    # intact (quotes get escaped, letters don't), so that's a safe, simple way
    # to tell the two apart in the fake transport below.
    def responder(url, timeout=8, allow_redirects=True):
        if "OR" in url.upper():
            return FakeResp("x" * 1000, 200)       # TRUE payload: big page
        if "AND" in url.upper():
            return FakeResp("x" * 50, 200)          # FALSE payload: much smaller page
        return FakeResp("", 200)                    # the two ERROR_PROBES ("'" and '"') - no error text

    fake = FakeSession([])
    fake.get = responder
    monkeypatch.setattr(sqli_prober.auth_ctx, "make_session", lambda *a, **k: fake)

    result = sqli_prober.run("example.test", target_path)

    assert result["count"] == 1
    assert "boolean-blind" in result["findings"][0]
    # 2 error-based probes + 2 boolean-blind requests for the one param
    assert result["tested"] == 4


def test_no_candidates_returns_zero_without_requests(target_path, monkeypatch):
    _write_url_patterns(target_path, "http://example.test/page?x=1")
    # Overwrite with a file that has no "sqli" tagged URL at all
    with open(os.path.join(target_path, "url_patterns.txt"), "w", encoding="utf-8") as f:
        f.write("http://example.test/page?x=1\txss\n")

    calls = []

    class ExplodingSession:
        def get(self, *a, **k):
            calls.append(1)
            raise AssertionError("should never make a request with 0 sqli candidates")

    monkeypatch.setattr(sqli_prober.auth_ctx, "make_session", lambda *a, **k: ExplodingSession())

    result = sqli_prober.run("example.test", target_path)
    assert result == {"findings": [], "count": 0, "tested": 0}
    assert calls == []


def test_missing_url_pattern_file_gives_actionable_error(target_path):
    result = sqli_prober.run("example.test", target_path)
    assert result["status"] == 400
    assert "URL Pattern Filter" in result["error"]
