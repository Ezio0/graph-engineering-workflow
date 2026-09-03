"""Isolated byte-pipe oracle for one WP-08 rejection execution envelope."""

from __future__ import annotations

import hashlib
import json


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def protocol_main(payload: object) -> dict[str, object]:
    fields = {
        "schema_version", "test_id", "result", "expected_result",
        "error_type", "expected_error_type", "error_message",
        "expected_error_message", "before_state", "after_state",
        "before_candidate", "after_candidate", "oracle_id", "oracle_digest",
        "plan_digest",
    }
    if (
        type(payload) is not dict
        or set(payload) != fields
        or payload.get("schema_version") != "1.0.0"
        or payload.get("result") != payload.get("expected_result")
        or payload.get("error_type") != payload.get("expected_error_type")
        or payload.get("error_message") != payload.get("expected_error_message")
        or payload.get("before_state") != payload.get("after_state")
        or payload.get("before_candidate") != payload.get("after_candidate")
    ):
        raise RuntimeError("Profile coverage rejection envelope is not exact")
    body = {
        "schema_version": "1.0.0",
        "test_id": payload["test_id"],
        "result": payload["result"],
        "zero_state_change": True,
        "unchanged_input": True,
        "oracle_id": payload["oracle_id"],
        "oracle_digest": payload["oracle_digest"],
        "plan_digest": payload["plan_digest"],
    }
    return {
        **body,
        "oracle_result_digest": hashlib.sha256(_canonical(body)).hexdigest(),
    }


if "_GEW_PROFILE_COVERAGE_PAYLOAD" in globals():
    print(json.dumps(
        protocol_main(_GEW_PROFILE_COVERAGE_PAYLOAD),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ))
