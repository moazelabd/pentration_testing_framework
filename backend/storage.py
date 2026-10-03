"""
Target storage.
----------------
Each target is a folder under targets/<slug>/ holding a meta.json
({"name", "domain"}) plus whatever result files each recon/vuln_scan
module writes (subdomains.txt, ports.txt, endpoints.txt, ...).

This module only knows about the filesystem layout - it has no Flask
or module-specific logic, so it can be reused by any module.
"""
import json
import os
import re
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGETS_DIR = os.path.join(BASE_DIR, "targets")
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")

os.makedirs(TARGETS_DIR, exist_ok=True)


def slugify(name: str) -> str:
    """Turn a target name into a filesystem-safe folder name."""
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", name.strip().lower())
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "target"


def clean_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def safe_target_path(target_id: str):
    """Prevent path traversal - only allow slug-safe ids."""
    if not re.match(r"^[a-zA-Z0-9_-]+$", target_id or ""):
        return None
    return os.path.join(TARGETS_DIR, target_id)


def target_exists(target_path: str) -> bool:
    return bool(target_path) and os.path.isdir(target_path)


def read_meta(target_path: str) -> dict:
    with open(os.path.join(target_path, "meta.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def write_meta(target_path: str, meta: dict) -> None:
    with open(os.path.join(target_path, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def count_lines(path: str) -> int:
    if not os.path.isfile(path):
        return 0
    with open(path, "r", encoding="utf-8") as f:
        return len([line for line in f if line.strip()])


def list_targets() -> list:
    targets = []
    for folder in sorted(os.listdir(TARGETS_DIR)):
        target_path = os.path.join(TARGETS_DIR, folder)
        meta_path = os.path.join(target_path, "meta.json")
        if not os.path.isfile(meta_path):
            continue
        meta = read_meta(target_path)
        meta["id"] = folder
        meta["subdomain_count"] = count_lines(os.path.join(target_path, "subdomains.txt"))
        targets.append(meta)
    return targets


def create_target(name: str, domain: str):
    """Returns the new target's meta dict, or None if the name is taken."""
    folder_id = slugify(name)
    target_path = os.path.join(TARGETS_DIR, folder_id)
    if os.path.exists(target_path):
        return None
    os.makedirs(target_path)
    meta = {"name": name, "domain": domain}
    write_meta(target_path, meta)
    meta["id"] = folder_id
    meta["subdomain_count"] = 0
    return meta


def delete_target(target_path: str) -> None:
    shutil.rmtree(target_path)
