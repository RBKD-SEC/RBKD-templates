#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RBKD-templates release gate validator (Ticket 06).

Checks:
  - catalog-v1.json validates against vendored schema and sidecar matches
  - every YAML template has a top-level id
  - no duplicate template ids
  - templates are valid YAML
  - secret scan (no private keys, tokens)
  - if nuclei CLI is available, run nuclei -validate -t .

Usage:
  uv run python scripts/validate_templates.py
"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rbkdlib as rl  # noqa: E402


def check_catalog(errors):
    catalog_path = rl.CAP_DIR / "catalog-v1.json"
    schema_path = rl.CAP_DIR / "schema" / "catalog-v1.schema.json"
    if not catalog_path.is_file():
        errors.append("capabilities/catalog-v1.json missing")
        return
    if not schema_path.is_file():
        errors.append("capabilities/schema/catalog-v1.schema.json missing")
        return
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(catalog):
        path = ".".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"catalog schema: {path}: {err.message}")
    sidecar = catalog_path.with_suffix(".json.sha256")
    if not sidecar.is_file():
        errors.append("catalog sidecar missing")
        return
    expected = rl.sha256_digest(catalog_path.read_text(encoding="utf-8"))
    actual = sidecar.read_text(encoding="utf-8").strip()
    if actual != expected:
        errors.append("catalog sidecar mismatch")


def check_templates(errors):
    seen = {}
    for rel, path in rl.iter_templates():
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: invalid YAML ({exc})")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{rel}: template root is not a mapping")
            continue
        tid = doc.get("id")
        if not tid:
            errors.append(f"{rel}: missing top-level id")
            continue
        if tid in seen:
            errors.append(f"{rel}: duplicate id '{tid}' (first at {seen[tid]})")
        else:
            seen[tid] = rel
        # workflows do not carry info.severity
        if "workflows" not in doc:
            info = doc.get("info") or {}
            if not info.get("severity"):
                errors.append(f"{rel}: missing info.severity")


def check_secrets(errors):
    pat = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b")
    for rel, path in rl.iter_templates():
        text = path.read_text(encoding="utf-8", errors="replace")
        if pat.search(text):
            errors.append(f"{rel}: potential secret detected")


def check_nuclei_validate(errors):
    if not shutil.which("nuclei"):
        print("  nuclei CLI not available; skipping nuclei -validate")
        return
    # Validate only template directories, excluding .venv, capabilities, releases, scripts, tests
    dirs = ["http", "network", "javascript", "workflows"]
    cmd = ["nuclei", "-validate"] + ["-t", *dirs]
    result = subprocess.run(
        cmd, cwd=rl.ROOT, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        errors.append(f"nuclei -validate failed:\n{result.stderr}")


def main():
    errors = []
    print("Validating RBKD-templates gates...")
    check_catalog(errors)
    check_templates(errors)
    check_secrets(errors)
    check_nuclei_validate(errors)
    if errors:
        print(f"\n✗ {len(errors)} gate failure(s):")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("\n✓ All RBKD-templates gates passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
