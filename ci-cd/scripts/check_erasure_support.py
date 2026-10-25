#!/usr/bin/env python3
"""
check_erasure_support.py
Validates that every model containing PII fields has a corresponding
erasure method, satisfying DPDPA Section 8(7) erasure obligations.

Usage: python check_erasure_support.py \
         --models-dir src/models/ \
         --pii-fields-config config/pii-fields.yaml
"""
import argparse
import ast
import sys
from pathlib import Path

import yaml


def load_pii_fields(config_path: str) -> set:
    """Load the set of field names classified as PII."""
    with open(config_path) as f:
        config = yaml.safe_load(f)
    return set(config.get("pii_field_names", []))


def check_model_file(file_path: Path, pii_fields: set) -> list:
    """Parse a Python model file and check for erasure support."""
    violations = []
    source = file_path.read_text()
    tree = ast.parse(source, filename=str(file_path))

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Find fields that match PII field names
        model_pii_fields = []
        has_erasure_method = False

        for item in node.body:
            # Check for PII field assignments
            # `email = models.CharField()` (Django) and annotated fields such as
            # `email: str` (dataclasses, Pydantic) or `email: Mapped[str] = ...` (SQLAlchemy 2.0)
            targets = item.targets if isinstance(item, ast.Assign) else (
                [item.target] if isinstance(item, ast.AnnAssign) else []
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    if target.id in pii_fields:
                        model_pii_fields.append(target.id)

            # Check for erasure/anonymise method
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if item.name in ("erase", "anonymise", "anonymize",
                                 "delete_personal_data", "gdpr_erase",
                                 "dpdpa_erase"):
                    has_erasure_method = True

        if model_pii_fields and not has_erasure_method:
            violations.append({
                "file": str(file_path),
                "model": node.name,
                "pii_fields": model_pii_fields,
                "violation": (
                    f"Model '{node.name}' contains PII fields "
                    f"{model_pii_fields} but has no erasure method. "
                    f"DPDPA Section 8(7) requires erasure capability."
                ),
            })

    return violations


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", required=True)
    parser.add_argument("--pii-fields-config", required=True)
    args = parser.parse_args()

    pii_fields = load_pii_fields(args.pii_fields_config)
    models_dir = Path(args.models_dir)
    all_violations = []

    for py_file in models_dir.rglob("*.py"):
        violations = check_model_file(py_file, pii_fields)
        all_violations.extend(violations)

    if all_violations:
        print(f"DPDPA GATE 3 FAILED: {len(all_violations)} model(s) "
              f"lack erasure support")
        for v in all_violations:
            print(f"  - {v['violation']}")
        sys.exit(1)
    else:
        print("DPDPA Gate 3 PASSED: All PII models have erasure methods")
        sys.exit(0)


if __name__ == "__main__":
    main()
