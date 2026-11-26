import json
import os

import storage


def _make_target(base, folder, meta_content):
    path = os.path.join(base, folder)
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "meta.json"), "w", encoding="utf-8") as f:
        f.write(meta_content)
    return path


def test_list_targets_skips_corrupted_meta_json(tmp_path, monkeypatch):
    """A corrupted/partially-written meta.json for ONE target must not take
    down the whole /api/targets listing for every other target."""
    monkeypatch.setattr(storage, "TARGETS_DIR", str(tmp_path))

    _make_target(tmp_path, "good-one", json.dumps({"name": "Good One", "domain": "a.test"}))
    _make_target(tmp_path, "broken-one", "{not valid json at all")

    targets = storage.list_targets()

    ids = [t["id"] for t in targets]
    assert "good-one" in ids
    assert "broken-one" not in ids
    assert len(targets) == 1


def test_list_targets_counts_subdomains_and_xss(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "TARGETS_DIR", str(tmp_path))
    path = _make_target(tmp_path, "t1", json.dumps({"name": "T1", "domain": "t1.test"}))
    with open(os.path.join(path, "subdomains.txt"), "w") as f:
        f.write("a.t1.test\nb.t1.test\n\n")  # blank line must not be counted
    with open(os.path.join(path, "xss_probe.txt"), "w") as f:
        f.write("UNESCAPED reflection\tparam=q\thttp://t1.test?q=x\nclean line\n")

    [meta] = storage.list_targets()
    assert meta["subdomain_count"] == 2
    assert meta["xss_findings"] == 1


def test_safe_target_path_blocks_path_traversal():
    assert storage.safe_target_path("../../etc") is None
    assert storage.safe_target_path("some/slash") is None
    assert storage.safe_target_path("valid-id_123") is not None


def test_clean_domain_strips_scheme_path_port():
    assert storage.clean_domain("https://Example.COM:8443/some/path") == "example.com"
    assert storage.clean_domain("example.com") == "example.com"
