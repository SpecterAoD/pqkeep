#!/usr/bin/env python3
"""Strict HMAC event binding for an independently trusted authorization stage.

Only the trusted preflight may hold the signing key. The AI runner must never
receive that key or be able to modify the signed record. This module does not
establish workflow isolation or key custody.
"""
import hashlib
import hmac
import json
import re

REPOSITORY = "SpecterAoD/pqkeep"
WORKFLOW = ".github/workflows/opencode.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
FIELDS = {
    "repository", "workflow", "run_id", "issue_number", "comment_id",
    "base_sha", "event", "actor_id",
}
ACTOR_ID = 77644070


def canonical(record: dict) -> bytes:
    """Encode only an exact, bounded, immutable event identity."""
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise ValueError("invalid event binding fields")
    for key in ("run_id", "issue_number", "comment_id"):
        if type(record[key]) is not int or record[key] <= 0:
            raise ValueError("invalid event identity")
    if (record["repository"] != REPOSITORY
            or record["workflow"] != WORKFLOW
            or record["event"] != "issue_comment"
            or type(record["actor_id"]) is not int
            or record["actor_id"] != ACTOR_ID
            or not isinstance(record["base_sha"], str)
            or not SHA.fullmatch(record["base_sha"])):
        raise ValueError("untrusted event identity")
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sign(record: dict, key: bytes) -> dict:
    """Sign in trusted preflight only; never call from agent-controlled code."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("invalid signing key")
    digest = hmac.new(key, canonical(record), hashlib.sha256).hexdigest()
    return {"binding": record, "mac_sha256": digest}


def verify(envelope: dict, key: bytes, expected: dict) -> bool:
    """Constant-time verify and compare every independently expected field."""
    if not isinstance(key, bytes) or len(key) < 32:
        return False
    if not isinstance(envelope, dict) or set(envelope) != {
        "binding", "mac_sha256"
    }:
        return False
    signature = envelope["mac_sha256"]
    if not isinstance(signature, str) or not re.fullmatch(
        r"[0-9a-f]{64}\Z", signature
    ):
        return False
    try:
        data = canonical(envelope["binding"])
        expected_data = canonical(expected)
    except (ValueError, TypeError):
        return False
    return (
        hmac.compare_digest(data, expected_data)
        and hmac.compare_digest(
            hmac.new(key, data, hashlib.sha256).hexdigest(), signature
        )
    )
