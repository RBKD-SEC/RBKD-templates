#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RBKD-templates capability catalog generator (Ticket 06).

Generates capabilities/catalog-v1.json from Nuclei YAML templates,
including only assets marked accepted in capabilities/rights/provenance.json.

Usage:
  uv run python scripts/generate_catalog.py --write
"""
import argparse
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rbkdlib as rl  # noqa: E402


def classify_safety(doc):
    tags = doc.get("tags", "")
    if isinstance(tags, str):
        tags = tags.lower()
    else:
        tags = ""
    info = doc.get("info", {}) or {}
    classification = info.get("classification", {}) or {}
    cve = classification.get("cve-id")
    # high-impact protocols / actions default to manual-gated
    if any(t in tags for t in ["code", "headless", "fuzz", "bruteforce", "dos"]):
        return "gated"
    if cve:
        return "optional"
    return "safe"


def build_catalog():
    provenance = rl.load_provenance()
    accepted = {a["destination"]: a for a in provenance.get("assets", []) if a.get("decision") == "accepted"}
    capabilities = []
    for rel, path in rl.iter_templates():
        prov = accepted.get(rel)
        if not prov:
            continue
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        info = doc.get("info", {}) or {}
        capabilities.append({
            "id": doc.get("id", rel),
            "kind": "nuclei-template",
            "path": rel,
            "contract": {
                "target_types": ["host-port", "url"],
                "inputs": ["host", "port", "url"],
                "positive_evidence": info.get("description", "nuclei template match"),
                "negative_or_failure": "no match does not prove absence",
                "interface_version": "nuclei-template-v1",
            },
            "safety": classify_safety(doc),
            "lifecycle": "active",
            "replacement": None,
            "provenance_id": prov["provenance_id"],
            "content_digest": prov["content_digest"],
            "components": [],
            "requires": [],
            "extensions": {
                "rbkd": {
                    "severity": info.get("severity"),
                    "tags": info.get("tags"),
                    "reference": info.get("reference"),
                }
            },
        })
    return {
        "schema_version": 1,
        "repository": "RBKD-templates",
        "capabilities": capabilities,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    catalog = build_catalog()
    catalog_path = rl.CAP_DIR / "catalog-v1.json"
    if args.write:
        rl.write_canonical(catalog_path, catalog)
        print(f"✓ wrote {catalog_path} ({len(catalog['capabilities'])} capabilities)")
        return 0
    expected = rl.canonical_json(catalog)
    actual = catalog_path.read_text(encoding="utf-8") if catalog_path.is_file() else ""
    if expected != actual:
        print("✗ catalog drift")
        return 1
    print("✓ catalog up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
