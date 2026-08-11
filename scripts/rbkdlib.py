#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Common utilities for RBKD-templates capability repository (Ticket 06)."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP_DIR = ROOT / "capabilities"


def sha256_digest(text):
    if isinstance(text, str):
        text = text.encode("utf-8")
    return "sha256:" + hashlib.sha256(text).hexdigest()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def write_canonical(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = canonical_json(obj)
    path.write_text(text, encoding="utf-8")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    sidecar.write_text(sha256_digest(text) + "\n", encoding="utf-8")
    return path


def iter_templates():
    for path in sorted(ROOT.rglob("*.yaml")):
        rel = path.relative_to(ROOT).as_posix()
        if any(part.startswith(".") for part in path.relative_to(ROOT).parts):
            continue
        if rel.startswith("tests/") or rel.startswith("releases/") or rel.startswith("capabilities/"):
            continue
        yield rel, path


def load_provenance():
    path = CAP_DIR / "rights" / "provenance.json"
    if not path.is_file():
        return {"assets": []}
    return json.loads(path.read_text(encoding="utf-8"))
