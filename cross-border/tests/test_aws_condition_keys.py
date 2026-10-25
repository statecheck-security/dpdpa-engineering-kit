"""Every IAM condition key in the kit's AWS policies must exist.

An unknown key never matches, so a Deny with StringNotEquals/StringNotLike on
it applies to every request, and an Allow on it never applies. AWS accepts the
policy anyway, so this has to be caught here.

Service keys are checked against AWS's machine-readable Service Reference
(https://servicereference.us-east-1.amazonaws.com/). Needs network access.
"""
import json
import re
import urllib.request
from functools import cache
from pathlib import Path

import pytest

pytestmark = pytest.mark.network

ROOT = Path(__file__).resolve().parents[2]

# Global condition keys used in the kit (documented in the IAM User Guide,
# "AWS global condition context keys"). Add to this list deliberately.
GLOBAL_KEYS = {"aws:PrincipalArn", "aws:RequestedRegion", "aws:SecureTransport"}

KEY_RE = re.compile(r'"((?:[a-z0-9-]+):[A-Za-z0-9_:${}/.-]+)"\s*[=:]')


def _policy_files():
    return sorted(
        p for p in ROOT.rglob("*")
        if p.suffix in {".json", ".tf"} and ".terraform" not in p.parts and ".venv" not in p.parts
        and (p.suffix == ".tf" or '"Statement"' in p.read_text(encoding="utf-8"))
    )


def _condition_keys(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        doc = json.loads(text)
        keys = set()
        for stmt in doc.get("Statement", []):
            for operator_block in stmt.get("Condition", {}).values():
                keys.update(operator_block)
        return keys
    # Terraform: keys inside `Condition = { Operator = { "svc:Key" = ... } }` blocks
    keys = set()
    for block in re.findall(r"Condition\s*=\s*\{(.*?)\n\s{8}\}", text, flags=re.S):
        keys.update(KEY_RE.findall(block))
    return keys


@cache
def _service_keys(service: str) -> frozenset[str]:
    url = f"https://servicereference.us-east-1.amazonaws.com/v1/{service}/{service}.json"
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - fixed https URL
        data = json.load(resp)
    return frozenset(k["Name"] for k in data.get("ConditionKeys", []))


def _key_exists(key: str) -> bool:
    service, _, name = key.partition(":")
    if service == "aws":
        return key in GLOBAL_KEYS
    known = _service_keys(service)
    if key in known:
        return True
    # Templated keys such as kms:EncryptionContext:${EncryptionContextKey}
    return any(k.endswith("}") and key.startswith(k.split("${")[0]) for k in known)


def test_policies_are_found():
    files = [p.relative_to(ROOT).as_posix() for p in _policy_files()]
    assert "cross-border/aws/scp-india-residency.json" in files
    assert "encryption/terraform/aws/kms.tf" in files


@pytest.mark.parametrize("path", _policy_files(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_condition_keys_exist(path):
    unknown = sorted(k for k in _condition_keys(path) if not _key_exists(k))
    assert not unknown, f"unknown IAM condition keys: {unknown}"


def test_the_published_article_keys_are_rejected():
    """The two keys from the original cross-border article do not exist."""
    assert not _key_exists("s3:ReplicationDestinationBucket")
    assert not _key_exists("rds:CopyDestinationRegion")
