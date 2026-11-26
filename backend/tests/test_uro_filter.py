import os
import subprocess

from modules.recon import uro_filter


def _write_wayback(target_path, urls):
    with open(os.path.join(target_path, "wayback.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(urls))


def test_missing_wayback_file_gives_actionable_error(target_path):
    result = uro_filter.run("example.test", target_path)
    assert result["status"] == 400
    assert "Wayback Machine" in result["error"]


def test_drops_boring_static_assets_and_collapses_duplicates(target_path):
    _write_wayback(target_path, [
        "http://example.test/logo.png",
        "http://example.test/product?id=1",
        "http://example.test/product?id=2",  # same pattern as above -> dropped
        "http://example.test/about",
    ])

    result = uro_filter.run("example.test", target_path)

    assert result["dropped_boring"] == 1
    assert result["dropped_duplicate_pattern"] == 1
    assert result["count"] == 2


def test_urldedupe_not_installed_falls_back_gracefully(target_path, monkeypatch):
    """Regression guard: if the optional `urldedupe` CLI isn't on PATH, the
    tool must still return the Python-only result (with a note) instead of
    crashing the whole request."""
    _write_wayback(target_path, ["http://example.test/about"])

    def fake_run(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(uro_filter.subprocess, "run", fake_run)

    result = uro_filter.run("example.test", target_path)

    assert result["count"] == 1
    assert "urldedupe" in result["note"].lower()
    assert "install" in result["note"].lower()


def test_urldedupe_timeout_falls_back_gracefully(target_path, monkeypatch):
    _write_wayback(target_path, ["http://example.test/about"])

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="urldedupe", timeout=120)

    monkeypatch.setattr(uro_filter.subprocess, "run", fake_run)

    result = uro_filter.run("example.test", target_path)

    assert result["count"] == 1
    assert "timed out" in result["note"]
