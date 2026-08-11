#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RBKD-templates gate tests (Ticket 06)."""
import json
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rbkdlib as rl  # noqa: E402
import generate_catalog  # noqa: E402
import validate_templates  # noqa: E402

PASS = 0
FAIL = 0


def case(name, fn):
    global PASS, FAIL
    try:
        fn()
        PASS += 1
        print(f"  ✓ {name}")
    except Exception as exc:
        FAIL += 1
        print(f"  ✗ {name}: {exc}")


def t_held_excluded():
    provenance = {"assets": [{"destination": "x.yaml", "decision": "held",
                              "provenance_id": "p", "content_digest": "sha256:" + "0" * 64}]}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        rl.ROOT = tmp
        rl.CAP_DIR = tmp / "capabilities"
        (tmp / "x.yaml").write_text("id: x\ninfo:\n  name: x\n  severity: info\n", encoding="utf-8")
        (rl.CAP_DIR / "schema").mkdir(parents=True)
        (rl.CAP_DIR / "rights").mkdir(parents=True)
        json.dump({"$schema": "..."}, (rl.CAP_DIR / "schema" / "catalog-v1.schema.json").open("w"))
        (rl.CAP_DIR / "rights" / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        generate_catalog.main(["--write"])
        catalog = json.loads((rl.CAP_DIR / "catalog-v1.json").read_text(encoding="utf-8"))
        assert catalog["capabilities"] == []


def t_duplicate_id_detected():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "a.yaml").write_text(
            "id: dup\ninfo:\n  name: a\n  severity: info\n", encoding="utf-8")
        (tmp / "b.yaml").write_text(
            "id: dup\ninfo:\n  name: b\n  severity: info\n", encoding="utf-8")
        original_root = rl.ROOT
        rl.ROOT = tmp
        try:
            errors = []
            validate_templates.check_templates(errors)
            assert any("duplicate id" in e for e in errors), \
                f"check_templates 未检测到重复 ID: {errors}"
        finally:
            rl.ROOT = original_root


def main():
    cases = [
        ("held template excluded from catalog", t_held_excluded),
        ("duplicate id detection logic", t_duplicate_id_detected),
    ]
    print("RBKD-templates gate tests")
    for name, fn in cases:
        case(name, fn)
    print()
    print(f"结果：{PASS} 通过，{FAIL} 失败，共 {PASS + FAIL} 项")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
