"""Generate the frozen 250-case WP-01 cross-implementation corpus."""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def canonical(value: object) -> bytes:
    if value is None:
        return b"null"
    if type(value) is bool:
        return b"true" if value else b"false"
    if type(value) is int:
        return str(value).encode()
    if type(value) is str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if type(value) is list:
        return b"[" + b",".join(canonical(item) for item in value) + b"]"
    if type(value) is dict:
        ordered = sorted(value, key=lambda item: item.encode("utf-16-be"))
        return b"{" + b",".join(canonical(key) + b":" + canonical(value[key]) for key in ordered) + b"}"
    raise TypeError(type(value).__name__)


def semantic_preimage(
    body: object,
    *,
    contract_type: str,
    projection_id: str,
    schema_id: str,
    canonicalizer: str = "urn:gew:canonicalizer:jcs-input:1.0.0",
    digest_domain: str = "urn:gew:digest:semantic:1.0.0",
) -> bytes:
    envelope = {
        "algorithm": "sha-256",
        "body": body,
        "canonicalizer": canonicalizer,
        "contract_type": contract_type,
        "digest_domain": digest_domain,
        "projection_id": projection_id,
        "schema_id": schema_id,
    }
    return canonical(envelope)


def semantic_digest_for(body: object, **arguments: str) -> str:
    return "sha256-jcs-v1:" + hashlib.sha256(semantic_preimage(body, **arguments)).hexdigest()


def contract_digest(body: object, contract_type: str, schema_id: str) -> str:
    return semantic_digest_for(
        body,
        contract_type=contract_type,
        projection_id="urn:gew:digest-projection:identity:1.0.0",
        schema_id=schema_id,
    )


def make_case(index: int, domain: str, request: dict[str, object], expected: dict[str, object]) -> dict[str, object]:
    case: dict[str, object] = {
        "case_id": f"GEW-CON-{index:03d}",
        "domain": domain,
        "obligation": f"{domain}/{index:03d}",
        "request": request,
        "expected": expected,
    }
    case["vector_digest"] = "sha256-raw-v1:" + hashlib.sha256(canonical(case)).hexdigest()
    return case


def measure(value: object) -> tuple[int, int, int, int, int]:
    nodes, members, items = 1, 0, 0
    scalars = len(value) if type(value) is str else 0
    if type(value) is dict:
        members = len(value)
        scalars += sum(len(key) for key in value)
        for child in value.values():
            child_measure = measure(child)
            nodes += child_measure[0]; members += child_measure[1]; items += child_measure[2]; scalars += child_measure[3]
    elif type(value) is list:
        items = len(value)
        for child in value:
            child_measure = measure(child)
            nodes += child_measure[0]; members += child_measure[1]; items += child_measure[2]; scalars += child_measure[3]
    return nodes, members, items, scalars, len(canonical(value))


def charge_result(events: list[tuple[str, int, list[int]]], budget: int, output: object) -> dict[str, object]:
    balance = budget
    trace: list[dict[str, object]] = []
    for ordinal, (event_id, count, operation_path) in enumerate(events):
        attempt: dict[str, object] = {
            "amount": str(count), "coefficient": "1", "count": str(count), "event_id": event_id,
            "event_ordinal": str(ordinal), "multiplier": "1", "operation_path": operation_path,
            "pre_balance": str(balance),
        }
        if count > balance:
            attempt["status"] = "rejected"; trace.append(attempt)
            return {"status": "error", "code": "E_BUDGET", "balance": balance, "trace": trace}
        balance -= count; attempt["post_balance"] = str(balance); attempt["status"] = "charged"; trace.append(attempt)
    return {"status": "ok", "balance": balance, "trace": trace, "output": output}


def raw_digest_bytes(value: bytes) -> str:
    return "sha256-raw-v1:" + hashlib.sha256(value).hexdigest()


def schema_document(name: str, properties: dict[str, object], required: list[str], **extra: object) -> dict[str, object]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"urn:gew:schema:{name}:1.0.0",
        "type": "object",
        "properties": {"schema_version": {"const": "1.0.0"}, **properties},
        "required": ["schema_version", *required],
        "unevaluatedProperties": False,
        **extra,
    }


def registry_manifest(registry_id: str, bodies: dict[str, str]) -> dict[str, object]:
    resources = [
        {"schema_id": schema_id, "body_digest": raw_digest_bytes(bodies[schema_id].encode())}
        for schema_id in sorted(bodies)
    ]
    unsigned: dict[str, object] = {"schema_version": "1.0.0", "registry_id": registry_id, "resources": resources}
    unsigned["registry_digest"] = semantic_digest_for(
        unsigned,
        contract_type="urn:gew:contract:schema-registry",
        projection_id="urn:gew:digest-projection:schema-registry:1.0.0",
        schema_id="urn:gew:schema:schema-registry:1.0.0",
    )
    return unsigned


def main() -> None:
    cases: list[dict[str, object]] = []
    valid_raw = ["null", "true", "false", "0", "-1", '"é"', "[]", "{}", '[1,"x"]', '{"a":1,"b":2}']
    invalid_raw = ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', "-0", "1.0", "1e0", "9007199254740992", "\ufeff{}", '"\\ud800"', "{", "???"]
    for offset, raw in enumerate(valid_raw + invalid_raw, 1):
        expected = {"status": "ok", "canonical": raw if offset <= 5 else json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"))} if offset <= 10 else {
            "status": "error",
            "code": ("DUPLICATE" if offset <= 12 else "NUMBER" if offset <= 16 else "BOM" if offset == 17 else "SURROGATE" if offset == 18 else "SYNTAX"),
        }
        cases.append(make_case(offset, "strict-json", {"operation": "strict_json", "raw": raw}, expected))

    schema_vectors = [
        ({"type": "integer"}, 1, []),
        ({"type": "integer"}, True, ["schema/type"]),
        ({"enum": [1, 2]}, 3, ["schema/enum"]),
        ({"const": "x"}, "y", ["schema/const"]),
        ({"type": "integer", "minimum": 2}, 1, ["schema/minimum"]),
        ({"type": "integer", "maximum": 2}, 3, ["schema/maximum"]),
        ({"type": "integer", "exclusiveMinimum": 2}, 2, ["schema/exclusiveMinimum"]),
        ({"type": "integer", "exclusiveMaximum": 2}, 2, ["schema/exclusiveMaximum"]),
        ({"type": "string", "minLength": 2}, "a", ["schema/minLength"]),
        ({"type": "string", "maxLength": 1}, "ab", ["schema/maxLength"]),
        ({"type": "string", "format": "gew-id"}, "Bad", ["schema/format/gew-id"]),
        ({"type": "object", "required": ["x"]}, {}, ["schema/required"]),
        ({"type": "object", "properties": {"x": {"type": "integer"}}}, {"x": True}, ["schema/type"]),
        ({"type": "object", "properties": {}, "additionalProperties": False}, {"x": 1}, ["schema/false-schema"]),
        ({"type": "object", "properties": {}, "unevaluatedProperties": False}, {"x": 1}, ["schema/unevaluatedProperties"]),
        ({"type": "object", "minProperties": 2}, {"x": 1}, ["schema/minProperties"]),
        ({"type": "object", "maxProperties": 1}, {"x": 1, "y": 2}, ["schema/maxProperties"]),
        ({"type": "object", "dependentRequired": {"x": ["y"]}}, {"x": 1}, ["schema/dependentRequired"]),
        ({"type": "object", "dependentSchemas": {"x": {"required": ["y"]}}}, {"x": 1}, ["schema/required"]),
        ({"type": "array", "minItems": 2}, [1], ["schema/minItems"]),
    ]
    for index, (schema, instance, failures) in enumerate(schema_vectors, 21):
        cases.append(make_case(index, "schema-profile", {"operation": "schema", "schema": schema, "instance": instance}, {"failures": failures}))
    profile_valid = schema_document("profile-valid", {"value": {"type": "integer"}}, ["value"])
    profile_metadata = schema_document("profile-metadata", {"value": {"type": "string", "title": "Value", "description": "A value"}}, ["value"])
    profile_vectors: list[tuple[dict[str, object], bool]] = [(profile_valid, True), (profile_metadata, True)]
    profile_mutations: list[tuple[str, object]] = [
        ("pattern", "x"), ("type", "number"), ("$id", "urn:gew:schema:nested:1.0.0"),
        ("format", "email"), ("array-unbounded", None), ("root-open", None),
        ("missing-version", None), ("$dynamicRef", "#node"),
    ]
    for ordinal, (mutation, value) in enumerate(profile_mutations, 43):
        changed = json.loads(json.dumps(schema_document(f"profile-invalid-{ordinal}", {"value": {"type": "integer"}}, ["value"])))
        if mutation == "array-unbounded":
            changed["properties"]["value"] = {"type": "array", "items": {"type": "integer"}}
        elif mutation == "root-open":
            del changed["unevaluatedProperties"]
        elif mutation == "missing-version":
            del changed["properties"]["schema_version"]
        else:
            changed["properties"]["value"][mutation] = value
        profile_vectors.append((changed, False))
    for index, (schema, valid) in enumerate(profile_vectors, 41):
        cases.append(make_case(index, "schema-profile", {"operation": "schema_profile", "schema": schema}, {"valid": valid}))

    registry_vectors: list[tuple[dict[str, str], dict[str, object], dict[str, object]]] = []
    base = schema_document("registry-base", {"value": {"type": "integer"}}, ["value"])
    base_raw = canonical(base).decode()
    base_bodies = {base["$id"]: base_raw}
    registry_vectors.append((base_bodies, registry_manifest("urn:gew:schema-registry:corpus-51:1.0.0", base_bodies), {"status": "ok", "resource_ids": [base["$id"]]}))
    wrapper = schema_document("registry-wrapper", {"payload": {"$ref": base["$id"]}}, ["payload"])
    two_bodies = {base["$id"]: base_raw, wrapper["$id"]: canonical(wrapper).decode()}
    registry_vectors.append((two_bodies, registry_manifest("urn:gew:schema-registry:corpus-52:1.0.0", two_bodies), {"status": "ok", "resource_ids": sorted(two_bodies)}))
    local = schema_document("registry-local", {"payload": {"$ref": "#/$defs/value"}}, ["payload"], **{"$defs": {"value": {"type": "integer"}}})
    local_bodies = {local["$id"]: canonical(local).decode()}
    registry_vectors.append((local_bodies, registry_manifest("urn:gew:schema-registry:corpus-53:1.0.0", local_bodies), {"status": "ok", "resource_ids": [local["$id"]]}))
    for corpus_index, definition_key, reference in ((54, "a~b", "#/$defs/a~0b"), (55, "a/b", "#/$defs/a~1b")):
        escaped = schema_document(f"registry-escaped-{corpus_index}", {"payload": {"$ref": reference}}, ["payload"], **{"$defs": {definition_key: {"type": "integer"}}})
        escaped_bodies = {escaped["$id"]: canonical(escaped).decode()}
        registry_vectors.append((escaped_bodies, registry_manifest(f"urn:gew:schema-registry:corpus-{corpus_index}:1.0.0", escaped_bodies), {"status": "ok", "resource_ids": [escaped["$id"]]}))
    array_pointer = schema_document("registry-array-pointer", {"payload": {"$ref": "#/$defs/choices/anyOf/0"}}, ["payload"], **{"$defs": {"choices": {"anyOf": [{"type": "integer"}]}}})
    array_bodies = {array_pointer["$id"]: canonical(array_pointer).decode()}
    registry_vectors.append((array_bodies, registry_manifest("urn:gew:schema-registry:corpus-56:1.0.0", array_bodies), {"status": "ok", "resource_ids": [array_pointer["$id"]]}))
    bad_references = [
        (57, "other.json", "REF"), (58, "https://example.test/schema", "REF"),
        (59, "file:///tmp/schema", "REF"), (60, "#anchor", "REF"),
        (61, "urn:gew:schema:not-registered:1.0.0", "REF"), (62, "#/missing", "REF"),
        (63, "#/$defs/a~2b", "REF"),
    ]
    for corpus_index, reference, code in bad_references:
        invalid = schema_document(f"registry-bad-ref-{corpus_index}", {"payload": {"$ref": reference}}, ["payload"])
        invalid_bodies = {invalid["$id"]: canonical(invalid).decode()}
        registry_vectors.append((invalid_bodies, registry_manifest(f"urn:gew:schema-registry:corpus-{corpus_index}:1.0.0", invalid_bodies), {"status": "error", "code": code}))
    self_cycle = schema_document("registry-self-cycle", {"payload": {"$ref": "#"}}, ["payload"])
    self_cycle_bodies = {self_cycle["$id"]: canonical(self_cycle).decode()}
    registry_vectors.append((self_cycle_bodies, registry_manifest("urn:gew:schema-registry:corpus-64:1.0.0", self_cycle_bodies), {"status": "error", "code": "CYCLE"}))
    cycle_a = schema_document("registry-cycle-a", {"payload": {"$ref": "urn:gew:schema:registry-cycle-b:1.0.0"}}, ["payload"])
    cycle_b = schema_document("registry-cycle-b", {"payload": {"$ref": cycle_a["$id"]}}, ["payload"])
    cycle_bodies = {cycle_a["$id"]: canonical(cycle_a).decode(), cycle_b["$id"]: canonical(cycle_b).decode()}
    registry_vectors.append((cycle_bodies, registry_manifest("urn:gew:schema-registry:corpus-65:1.0.0", cycle_bodies), {"status": "error", "code": "CYCLE"}))
    swapped = registry_manifest("urn:gew:schema-registry:corpus-66:1.0.0", base_bodies); swapped["registry_digest"] = "sha256-jcs-v1:" + "0" * 64
    registry_vectors.append((base_bodies, swapped, {"status": "error", "code": "MANIFEST"}))
    tamper_manifest = registry_manifest("urn:gew:schema-registry:corpus-67:1.0.0", base_bodies)
    registry_vectors.append(({base["$id"]: base_raw + " "}, tamper_manifest, {"status": "error", "code": "DIGEST"}))
    undeclared = dict(base_bodies); extra = schema_document("registry-extra", {}, []); undeclared[extra["$id"]] = canonical(extra).decode()
    registry_vectors.append((undeclared, registry_manifest("urn:gew:schema-registry:corpus-68:1.0.0", base_bodies), {"status": "error", "code": "BODY"}))
    duplicate_manifest = registry_manifest("urn:gew:schema-registry:corpus-69:1.0.0", base_bodies)
    duplicate_manifest["resources"].append(dict(duplicate_manifest["resources"][0]))  # type: ignore[union-attr]
    unsigned_duplicate = dict(duplicate_manifest); del unsigned_duplicate["registry_digest"]
    duplicate_manifest["registry_digest"] = semantic_digest_for(unsigned_duplicate, contract_type="urn:gew:contract:schema-registry", projection_id="urn:gew:digest-projection:schema-registry:1.0.0", schema_id="urn:gew:schema:schema-registry:1.0.0")
    registry_vectors.append((base_bodies, duplicate_manifest, {"status": "error", "code": "BODY"}))
    registry_vectors.append((two_bodies, registry_manifest("urn:gew:schema-registry:corpus-70:1.0.0", two_bodies), {"status": "error", "code": "LIMIT"}))
    for index, (bodies, manifest, expected) in enumerate(registry_vectors, 51):
        request: dict[str, object] = {"operation": "registry_contract", "manifest": manifest, "bodies": bodies}
        if index == 70:
            request["limit_override"] = {"registry_resources": 1}
        cases.append(make_case(index, "closed-registry", request, expected))

    canonical_values = [
        {"b": 1, "a": "x"}, [True, None, -2], "é", "é", {"a": [1, 2]}, {"z": "\n"}, 0, -9, [], {"nested": {"x": 1}},
    ]
    for index, value in enumerate(canonical_values, 71):
        cases.append(make_case(index, "jcs-format", {"operation": "canonical", "value": value}, {"canonical": canonical(value).decode()}))
    format_vectors = [
        ("gew-bigint", "0", True), ("gew-bigint", "-12", True), ("gew-bigint", "-0", False), ("gew-bigint", "01", False),
        ("gew-decimal", "1.25", True), ("gew-decimal", "1.20", False), ("gew-decimal", "-0", False),
        ("gew-duration", "PT0S", True), ("gew-duration", "PT1.25S", True), ("gew-duration", "PT01S", False),
        ("gew-id", "graph/node-1", True), ("gew-id", "Graph", False), ("gew-id", "a--b", False),
        ("gew-opaque-ref", "YQ", True), ("gew-opaque-ref", "YR", False), ("gew-opaque-ref", "YQ==", False),
        ("gew-timestamp", "2024-02-29T23:59:59Z", True), ("gew-timestamp", "2023-02-29T00:00:00Z", False),
        ("gew-timestamp", "2024-01-01T00:00:60Z", False), ("gew-duration", "PT1.20S", False),
    ]
    for index, (format_id, value, valid) in enumerate(format_vectors, 81):
        cases.append(make_case(index, "jcs-format", {"operation": "format", "format_id": format_id, "value": value}, {"valid": valid}))

    identity_bodies = [
        {"schema_version": "1.0.0", "value": 1},
        {"value": 1, "schema_version": "1.0.0"},
        {"schema_version": "1.0.0", "value": {"nested": True}},
        {"schema_version": "1.0.0", "value": [1, "x", None]},
        {"schema_version": "1.0.0", "value": "é"},
        {"schema_version": "1.0.0", "value": "é"},
        {"schema_version": "1.0.0", "value": False},
        {"schema_version": "1.0.0", "value": None},
        {"schema_version": "1.0.0", "value": {}},
        {"schema_version": "1.0.0", "value": []},
    ]
    for index, body in enumerate(identity_bodies, 101):
        arguments = {
            "contract_type": f"urn:gew:contract:digest-vector-{index}",
            "projection_id": f"urn:gew:digest-projection:vector-{index}:1.0.0",
            "schema_id": f"urn:gew:schema:digest-vector-{index}:1.0.0",
        }
        request = {
            "operation": "digest_contract",
            "action": "identity",
            "body": body,
            **arguments,
        }
        preimage = semantic_preimage(body, **arguments)
        cases.append(make_case(index, "digest-projection", request, {
            "status": "ok", "projected_body": body, "preimage": preimage.decode(),
            "digest": "sha256-jcs-v1:" + hashlib.sha256(preimage).hexdigest(),
        }))

    projection = {
        "projection_id": "urn:gew:digest-projection:corpus-self:1.0.0",
        "source_schema_id": "urn:gew:schema:corpus-self-source:1.0.0",
        "digest_input_schema_id": "urn:gew:schema:corpus-self-input:1.0.0",
        "derived_field": "digest",
        "contract_type": "urn:gew:contract:corpus-self",
        "schema_id": "urn:gew:schema:corpus-self-input:1.0.0",
    }
    self_candidates = [
        {"schema_version": "1.0.0", "value": value}
        for value in (0, 1, -1, True, False, None, "é", "é", [1, 2], {"a": 1})
    ]
    completed: list[dict[str, object]] = []
    for index, candidate in enumerate(self_candidates, 111):
        digest = semantic_digest_for(
            candidate,
            contract_type=projection["contract_type"],
            projection_id=projection["projection_id"],
            schema_id=projection["schema_id"],
        )
        complete = {**candidate, "digest": digest}
        completed.append(complete)
        preimage = semantic_preimage(
            candidate,
            contract_type=projection["contract_type"],
            projection_id=projection["projection_id"],
            schema_id=projection["schema_id"],
        )
        cases.append(make_case(index, "digest-projection", {
            "operation": "digest_contract", "action": "create-self", "candidate": candidate, "projection": projection,
        }, {
            "status": "ok", "complete": complete, "projected_body": candidate,
            "preimage": preimage.decode(), "digest": digest,
        }))

    verification_records = [
        completed[0], completed[4], completed[7], completed[8], completed[9],
        {**completed[1], "value": 2},
        {key: value for key, value in completed[2].items() if key != "digest"},
        {**completed[3], "digest": None},
        {**completed[5], "digest": "pending"},
        {**completed[6], "digest": "sha256-jcs-v1:" + "0" * 64},
    ]
    verification_errors = [None] * 5 + ["MISMATCH", "SOURCE", "DIGEST_FIELD", "DIGEST_FIELD", "MISMATCH"]
    for index, (record, error_code) in enumerate(zip(verification_records, verification_errors, strict=True), 121):
        request = {"operation": "digest_contract", "action": "verify-self", "record": record, "projection": projection}
        expected = {"status": "error", "code": error_code} if error_code is not None else {
            "status": "ok", "complete": record,
            "projected_body": {key: value for key, value in record.items() if key != "digest"},
            "digest": record["digest"],
        }
        cases.append(make_case(index, "digest-projection", request, expected))

    lit = lambda value: {"op": "literal", "value": value}
    path = lambda *tokens: {"op": "path", "root": "input", "tokens": list(tokens)}
    exists = lambda *tokens: {"op": "exists", "root": "input", "tokens": list(tokens)}
    declaration_root = {"root": "input", "tokens": [], "value_type": "object"}
    def declared(tokens: list[str | int], value_type: str) -> list[dict[str, object]]:
        return [declaration_root, {"root": "input", "tokens": tokens, "value_type": value_type}]

    expressions: list[tuple[dict[str, object], object, dict[str, object], list[dict[str, object]]]] = [
        (lit(True), True, {}, []), (lit(False), False, {}, []),
        ({"op": "eq", "left": lit(1), "right": lit(1)}, True, {}, []),
        ({"op": "eq", "left": lit("a"), "right": lit("b")}, False, {}, []),
        ({"op": "ne", "left": lit(1), "right": lit(2)}, True, {}, []),
        ({"op": "ne", "left": path("obj"), "right": path("other")}, False, {"input": {"obj": {"a": 1}, "other": {"a": 1}}}, [declaration_root, {"root": "input", "tokens": ["obj"], "value_type": "object"}, {"root": "input", "tokens": ["other"], "value_type": "object"}]),
        ({"op": "lt", "left": lit(1), "right": lit(2)}, True, {}, []),
        ({"op": "lt", "left": lit("z"), "right": lit("a")}, False, {}, []),
        ({"op": "lte", "left": lit(2), "right": lit(2)}, True, {}, []),
        ({"op": "lte", "left": lit(3), "right": lit(2)}, False, {}, []),
        ({"op": "gt", "left": lit(3), "right": lit(2)}, True, {}, []),
        ({"op": "gt", "left": lit(2), "right": lit(3)}, False, {}, []),
        ({"op": "gte", "left": lit("b"), "right": lit("a")}, True, {}, []),
        ({"op": "gte", "left": lit(1), "right": lit(2)}, False, {}, []),
        ({"op": "not", "arg": lit(False)}, True, {}, []), ({"op": "not", "arg": lit(True)}, False, {}, []),
        ({"op": "all", "args": [lit(True), lit(True)]}, True, {}, []),
        ({"op": "all", "args": [lit(True), lit(False)]}, False, {}, []),
        ({"op": "any", "args": [lit(False), lit(False)]}, False, {}, []),
        ({"op": "any", "args": [lit(False), lit(True)]}, True, {}, []),
        ({"op": "contains", "container": path("items"), "value": lit(2)}, True, {"input": {"items": [1, 2]}}, declared(["items"], "array")),
        ({"op": "contains", "container": path("items"), "value": lit(3)}, False, {"input": {"items": [1, 2]}}, declared(["items"], "array")),
        ({"op": "in", "value": lit("x"), "container": path("items")}, True, {"input": {"items": ["x", "y"]}}, declared(["items"], "array")),
        ({"op": "in", "value": lit("z"), "container": path("items")}, False, {"input": {"items": ["x", "y"]}}, declared(["items"], "array")),
        ({"op": "eq", "left": {"op": "length", "value": lit("😀a")}, "right": lit(2)}, True, {}, []),
        ({"op": "eq", "left": {"op": "length", "value": path("items")}, "right": lit(2)}, True, {"input": {"items": [1, 2]}}, declared(["items"], "array")),
        (exists("name"), True, {"input": {"name": "GEW"}}, declared(["name"], "string")),
        (exists("name"), False, {"input": {}}, declared(["name"], "string")),
        ({"op": "eq", "left": path("count"), "right": lit(2)}, True, {"input": {"count": 2}}, declared(["count"], "integer")),
        ({"op": "eq", "left": path("missing"), "right": lit("x")}, "E_PATH_MISSING", {"input": {}}, declared(["missing"], "string")),
        ({"op": "eq", "left": path("items", 0), "right": lit("x")}, "E_PATH_TYPE", {"input": {"items": {}}}, [declaration_root, {"root": "input", "tokens": ["items", 0], "value_type": "string"}]),
        ({"op": "is_type", "value": lit(None), "expected": "null"}, True, {}, []),
        ({"op": "is_type", "value": lit(True), "expected": "integer"}, False, {}, []),
        ({"op": "is_type", "value": lit("x"), "expected": "string"}, True, {}, []),
        ({"op": "predicate", "predicate_id": "urn:gew:predicate:string-starts-with", "version": "1.0.0", "args": [lit("graph"), lit("gra")]}, True, {}, []),
        ({"op": "predicate", "predicate_id": "urn:gew:predicate:string-starts-with", "version": "1.0.0", "args": [lit("graph"), lit("agent")]}, False, {}, []),
        ({"op": "all", "args": []}, "E_SCHEMA", {}, []),
        ({"op": "unknown"}, "E_OPERATOR", {}, []),
        ({"op": "eq", "left": lit(1), "right": lit(True)}, "E_TYPE", {}, []),
        ({"op": "all", "args": [lit(False), path("missing")]}, "E_PATH_MISSING", {"input": {}}, declared(["missing"], "boolean")),
    ]
    for index, (expression, outcome, roots, declarations) in enumerate(expressions, 131):
        expected = {"status": "error", "code": outcome} if isinstance(outcome, str) and outcome.startswith("E_") else {"status": "ok", "value": outcome}
        cases.append(make_case(index, "geel", {
            "operation": "geel_summary", "expression": expression, "roots": roots, "declarations": declarations,
        }, expected))

    boundary_scenarios = [
        "parse-null", "parse-string", "parse-array", "parse-object", "parse-nested",
        "schema-integer", "schema-properties", "schema-items", "schema-all-of", "schema-any-of",
        "schema-one-of", "schema-not", "schema-if-then", "schema-format-id", "schema-format-opaque",
        "schema-unique", "schema-contains", "schema-unevaluated-properties", "schema-unevaluated-items",
        "schema-ref", "registry-single", "registry-ref", "geel-literal", "geel-path", "geel-equality",
        "geel-membership", "geel-predicate", "geel-eager-error", "canonical-integer", "canonical-string",
        "canonical-object", "canonical-array", "compare-integer", "compare-string", "compare-object",
        "compare-array", "digest-integer", "digest-object", "result-nested", "migration-success",
    ]
    from tests.conformance.test_wp01_cross_implementation import CrossImplementationTests

    CrossImplementationTests.setUpClass()
    production = CrossImplementationTests(methodName="test_complete_gew_con_001_through_250_matches_frozen_and_independent_results")
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("Node.js is required to freeze independent boundary evidence")
    for index, scenario in enumerate(boundary_scenarios, 171):
        request = {"operation": "production_boundary", "scenario": scenario}
        expected = production.production_boundary(scenario)
        reference = subprocess.run(
            [node, "tests/support/wp01_reference.mjs"],
            input=json.dumps(request, ensure_ascii=False) + "\n",
            check=True,
            capture_output=True,
            text=True,
        )
        independent = json.loads(reference.stdout)
        if independent.pop("status", None) != "ok" or independent != expected:
            raise AssertionError(f"independent boundary disagreement: {scenario}")
        cases.append(make_case(index, "budget-cost", request, expected))

    alias_values: list[object] = [
        {"value": 1}, {"nested": {"value": 2}}, {"items": [1, 2]}, {"flag": True}, {"null": None},
        [1], [True, 1], [{"value": 3}], [[]], ["é", "é"],
    ]
    for index, shared in enumerate(alias_values, 211):
        original = {"left": shared, "right": shared}
        if isinstance(shared, dict):
            mutated_shared = {**shared, "mutation": index}
        else:
            mutated_shared = [*shared, index]
        mutated = {"left": mutated_shared, "right": mutated_shared}
        cases.append(make_case(index, "immutable-model", {
            "operation": "immutable_alias", "shared": shared, "mutation": index,
        }, {
            "frozen_canonical": canonical(original).decode(),
            "mutated_source_canonical": canonical(mutated).decode(),
            "mutation_rejected": True,
        }))
    immutable_values = [None, True, False, 0, 1, -1, "é", "é", [1, True, None], {"b": 1, "a": 2}]
    for index, value in enumerate(immutable_values, 221):
        cases.append(make_case(index, "immutable-model", {"operation": "immutable", "value": value}, {
            "canonical": canonical(value).decode(), "round_trip_canonical": canonical(value).decode(),
            "json_type": "null" if value is None else "boolean" if type(value) is bool else "integer" if type(value) is int else "string" if type(value) is str else "array" if isinstance(value, list) else "object",
        }))

    compatibility_vectors = [
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a"]}], "urn:gew:reader:a", "urn:gew:writer:a", True),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a"]}], "urn:gew:reader:a", "urn:gew:writer:b", False),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a", "urn:gew:writer:b"]}], "urn:gew:reader:a", "urn:gew:writer:b", True),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": []}], "urn:gew:reader:a", "urn:gew:writer:a", False),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a"]}], "urn:gew:reader:unknown", "urn:gew:writer:a", False),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a"]}, {"reader_id": "urn:gew:reader:b", "accepted_writer_ids": ["urn:gew:writer:b"]}], "urn:gew:reader:b", "urn:gew:writer:b", True),
        ([{"reader_id": "urn:gew:reader:a", "accepted_writer_ids": ["urn:gew:writer:a"]}, {"reader_id": "urn:gew:reader:b", "accepted_writer_ids": ["urn:gew:writer:b"]}], "urn:gew:reader:b", "urn:gew:writer:a", False),
        ([{"reader_id": "urn:gew:reader:new", "accepted_writer_ids": ["urn:gew:writer:old"]}], "urn:gew:reader:new", "urn:gew:writer:old", True),
        ([{"reader_id": "urn:gew:reader:old", "accepted_writer_ids": ["urn:gew:writer:old"]}], "urn:gew:reader:old", "urn:gew:writer:new", False),
        ([{"reader_id": "urn:gew:reader:strict", "accepted_writer_ids": ["urn:gew:writer:1-0-0"]}], "urn:gew:reader:strict", "urn:gew:writer:1-0-0", True),
    ]
    for index, (rows, reader, writer, compatible) in enumerate(compatibility_vectors, 231):
        cases.append(make_case(index, "version-migration", {
            "operation": "compatibility", "rows": rows, "reader_id": reader, "writer_id": writer,
        }, {"compatible": compatible}))
    migration_manifest = json.loads(pathlib.Path("config/contracts/migration-registry-v1.json").read_text())
    migration_schema_manifest = json.loads(pathlib.Path("config/contracts/migration-schema-registry-v1.json").read_text())
    for index in range(241, 251):
        if index == 250:
            request = {
                "operation": "migration_path",
                "source": "urn:gew:contract:a",
                "target": "urn:gew:contract:c",
                "edges": [
                    {"source": "urn:gew:contract:a", "target": "urn:gew:contract:c"},
                    {"source": "urn:gew:contract:a", "target": "urn:gew:contract:b"},
                    {"source": "urn:gew:contract:b", "target": "urn:gew:contract:c"},
                ],
            }
            cases.append(make_case(index, "version-migration", request, {"path_count": 2}))
            continue
        value: dict[str, object] = {"schema_version": "1.0.0", "index": index}
        manifest = json.loads(json.dumps(migration_manifest))
        expected_source_digest = contract_digest(value, "urn:gew:contract-stack:1.0.0", "urn:gew:schema:contract-stack:1.0.0")
        source_contract_id = "urn:gew:contract-stack:1.0.0"
        target_contract_id = "urn:gew:contract-stack:1.0.1"
        error_code: str | None = None
        if index == 242:
            value["schema_version"] = "0.9.0"
            expected_source_digest = contract_digest(value, "urn:gew:contract-stack:1.0.0", "urn:gew:schema:contract-stack:1.0.0")
            error_code = "SOURCE"
        elif index == 244:
            expected_source_digest = "sha256-jcs-v1:" + "0" * 64
            error_code = "DIGEST"
        elif index == 245:
            manifest["registry_digest"] = "sha256-jcs-v1:" + "0" * 64
            error_code = "REGISTRY"
        elif index == 246:
            manifest["transforms"][0]["implementation_digest"] = "sha256-raw-v1:" + "0" * 64
            error_code = "REGISTRY"
        elif index == 247:
            target_contract_id = "urn:gew:contract-stack:2.0.0"
            error_code = "PATH"
        elif index in {248, 249}:
            error_code = "REGISTRY"
        request = {
            "operation": "migration",
            "value": value,
            "manifest": manifest,
            "expected_source_digest": expected_source_digest,
            "expected_schema_registry_id": migration_schema_manifest["registry_id"],
            "expected_schema_registry_digest": migration_schema_manifest["registry_digest"],
            "source_contract_id": source_contract_id,
            "target_contract_id": target_contract_id,
            "actor_id": "codex:corpus",
            "transaction_id": f"corpus-{index}",
        }
        if index == 248:
            request["expected_schema_registry_id"] = "urn:gew:schema-registry:migration:9.9.9"
        elif index == 249:
            request["expected_schema_registry_digest"] = "sha256-jcs-v1:" + "0" * 64
        if error_code is not None:
            expected = {"status": "error", "code": error_code}
        else:
            output = {**value, "schema_version": "1.0.1"}
            source_digest = contract_digest(value, source_contract_id, "urn:gew:schema:contract-stack:1.0.0")
            target_digest = contract_digest(output, target_contract_id, "urn:gew:schema:contract-stack:1.0.1")
            transform = manifest["transforms"][0]
            provenance = {
                "actor_id": "codex:corpus",
                "registry_digest": manifest["registry_digest"],
                "registry_id": manifest["registry_id"],
                "result": "migrated",
                "schema_version": "1.0.0",
                "source_contract_id": source_contract_id,
                "source_digest": source_digest,
                "steps": [{
                    "implementation_digest": transform["implementation_digest"],
                    "index": 0,
                    "output_digest": target_digest,
                    "transform_id": transform["transform_id"],
                    "version": transform["version"],
                }],
                "target_contract_id": target_contract_id,
                "target_digest": target_digest,
                "transaction_id": f"corpus-{index}",
            }
            expected = {
                "status": "ok",
                "output": output,
                "output_canonical": canonical(output).decode(),
                "provenance": provenance,
                "provenance_canonical": canonical(provenance).decode(),
            }
        cases.append(make_case(index, "version-migration", request, expected))

    if [case["case_id"] for case in cases] != [f"GEW-CON-{index:03d}" for index in range(1, 251)]:
        raise AssertionError("corpus ID set is not exact")
    payload: dict[str, object] = {
        "schema_version": "1.0.0",
        "corpus_id": "urn:gew:corpus:cross-implementation:1.0.0",
        "canonical": [
            {"case_id": "object-order", "value": {"b": 1, "a": "x"}},
            {"case_id": "utf16-order", "value": {"": 2, "𐀀": 1}},
            {"case_id": "no-normalization", "value": {"composed": "é", "decomposed": "é"}},
            {"case_id": "nested", "value": {"array": [True, None, -2], "object": {"z": "\n"}}},
        ],
        "geel": [
            {"case_id": "all", "expression": {"op": "all", "args": [{"op": "literal", "value": True}, {"op": "path", "root": "input", "tokens": ["enabled"]}]}, "roots": {"input": {"enabled": True}}},
            {"case_id": "membership", "expression": {"op": "contains", "container": {"op": "path", "root": "input", "tokens": ["tags"]}, "value": {"op": "literal", "value": "graph"}}, "roots": {"input": {"tags": ["agent", "graph"]}}},
            {"case_id": "unicode-length", "expression": {"op": "eq", "left": {"op": "length", "value": {"op": "literal", "value": "😀a"}}, "right": {"op": "literal", "value": 2}}, "roots": {}},
        ],
        "schema": [
            {"case_id": "valid", "schema": {"type": "object", "properties": {"schema_version": {"const": "1.0.0"}, "count": {"type": "integer", "minimum": 1}}, "required": ["schema_version", "count"], "unevaluatedProperties": False}, "instance": {"schema_version": "1.0.0", "count": 2}},
            {"case_id": "wrong-type", "schema": {"type": "object", "properties": {"schema_version": {"const": "1.0.0"}, "count": {"type": "integer"}}, "required": ["schema_version", "count"], "unevaluatedProperties": False}, "instance": {"schema_version": "1.0.0", "count": True}},
            {"case_id": "unknown-member", "schema": {"type": "object", "properties": {"schema_version": {"const": "1.0.0"}}, "required": ["schema_version"], "unevaluatedProperties": False}, "instance": {"schema_version": "1.0.0", "rogue": 1}},
        ],
        "cases": cases,
    }
    unsigned = canonical(payload)
    payload["corpus_digest"] = "sha256-raw-v1:" + hashlib.sha256(unsigned).hexdigest()
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(sys.argv) == 3 and sys.argv[1] == "--output":
        output = pathlib.Path(sys.argv[2])
        output.write_text(rendered + "\n", encoding="utf-8")
    elif len(sys.argv) == 1:
        print(rendered)
    else:
        raise SystemExit("usage: generate_wp01_corpus.py [--output PATH]")


if __name__ == "__main__":
    main()
