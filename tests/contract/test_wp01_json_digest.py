from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.core.contracts.digest import (  # noqa: E402
    DigestProjection,
    create_self_digest,
    raw_digest,
    semantic_digest,
    semantic_preimage,
    verify_self_digest,
)
from graph_engineering.core.contracts.formats import validate_format  # noqa: E402
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw  # noqa: E402
from graph_engineering.core.contracts.strict_json import parse_json  # noqa: E402


class StrictJsonAndDigestTests(unittest.TestCase):
    def test_strict_json_and_jcs_vectors(self) -> None:
        self.assertEqual(parse_json(b'{"b":1,"a":"x"}'), {"b": 1, "a": "x"})
        self.assertEqual(canonical_bytes({"b": 1, "a": "x"}), b'{"a":"x","b":1}')
        self.assertEqual(canonical_bytes({"\U00010000": 1, "\ue000": 2}), '{"\U00010000":1,"\ue000":2}'.encode())
        self.assertNotEqual(canonical_bytes("e\u0301"), canonical_bytes("\u00e9"))
        for raw in (
            b'{"a":1,"\\u0061":2}',
            b'{"n":-0}',
            b'{"n":1.0}',
            b'{"n":1e0}',
            b'{"n":9007199254740992}',
            b'\xef\xbb\xbf{}',
            b'"\\ud800"',
        ):
            with self.subTest(raw=raw), self.assertRaises((UnicodeDecodeError, ValueError)):
                parse_json(raw)
        with self.assertRaises(TypeError):
            canonical_bytes({"n": True, 1: "bad"})

    def test_formats_are_canonical_and_closed(self) -> None:
        cases = {
            "gew-bigint": (("0", "-12"), ("-0", "+1", "01")),
            "gew-decimal": (("0", "-1.25"), ("-0", "1.20", "1e2")),
            "gew-timestamp": (("2024-02-29T23:59:59.123Z",), ("2023-02-29T00:00:00Z", "2024-01-01T00:00:60Z")),
            "gew-duration": (("PT0S", "PT1.25S"), ("PT01S", "PT1.20S", "-PT1S")),
            "gew-id": (("graph/node-1",), ("Graph", "a--b")),
            "gew-opaque-ref": (("YQ",), ("YR", "YS", "YT", "YQ==", "A")),
        }
        for format_id, (valid, invalid) in cases.items():
            for value in valid:
                self.assertTrue(validate_format(format_id, value), (format_id, value))
            for value in invalid:
                self.assertFalse(validate_format(format_id, value), (format_id, value))
        with self.assertRaises(ValueError):
            validate_format("email", "a@example.test")

    def test_recursive_freeze_breaks_aliases_and_round_trips(self) -> None:
        source = {"items": [{"value": 1}]}
        frozen = freeze(source)
        self.assertIsInstance(frozen, FrozenMap)
        source["items"][0]["value"] = 2
        self.assertEqual(thaw(frozen), {"items": [{"value": 1}]})
        mutable = thaw(frozen)
        mutable["items"][0]["value"] = 3
        self.assertEqual(thaw(frozen), {"items": [{"value": 1}]})
        with self.assertRaises(TypeError):
            freeze({"flag": 1.5})

    def test_semantic_digest_is_framed_and_self_projection_is_exact(self) -> None:
        body = {"schema_version": "1.0.0", "value": 1}
        arguments = {
            "contract_type": "urn:gew:contract:test",
            "projection_id": "urn:gew:digest-projection:identity:1.0.0",
            "schema_id": "urn:gew:schema:test:1.0.0",
        }
        digest = semantic_digest(body, **arguments)
        self.assertTrue(digest.startswith("sha256-jcs-v1:"))
        self.assertIn(b'"algorithm":"sha-256"', semantic_preimage(body, **arguments))
        self.assertNotEqual(digest, semantic_digest(body, **{**arguments, "contract_type": "urn:gew:contract:other"}))
        self.assertTrue(raw_digest(b"body").startswith("sha256-raw-v1:"))

        projection = DigestProjection(
            projection_id="urn:gew:digest-projection:test:1.0.0",
            source_schema_id="urn:gew:schema:test-source:1.0.0",
            digest_input_schema_id="urn:gew:schema:test-input:1.0.0",
            derived_field="digest",
            contract_type="urn:gew:contract:test",
            schema_id="urn:gew:schema:test-input:1.0.0",
        )

        def validate_input(value: object) -> None:
            if not isinstance(value, dict) or set(value) != {"schema_version", "value"}:
                raise ValueError("invalid input")

        def validate_source(value: object) -> None:
            if not isinstance(value, dict) or set(value) != {"schema_version", "value", "digest"}:
                raise ValueError("invalid source")

        complete = create_self_digest(body, projection, validate_input=validate_input, validate_source=validate_source)
        body["value"] = {"nested": 2}
        self.assertEqual(complete["value"], 1)
        self.assertEqual(verify_self_digest(complete, projection, validate_input=validate_input, validate_source=validate_source), complete)
        tampered = dict(complete)
        tampered["value"] = 2
        with self.assertRaises(ValueError):
            verify_self_digest(tampered, projection, validate_input=validate_input, validate_source=validate_source)
        for placeholder in (None, "", "pending"):
            candidate = dict(body)
            candidate["digest"] = placeholder
            with self.assertRaises(ValueError):
                create_self_digest(candidate, projection, validate_input=validate_input, validate_source=validate_source)

    def test_digest_domain_and_record_mutation_are_rejected(self) -> None:
        body = {"schema_version": "1.0.0", "value": 1}
        common = {
            "projection_id": "urn:gew:digest-projection:identity:1.0.0",
            "schema_id": "urn:gew:schema:test:1.0.0",
        }
        original = semantic_digest(body, contract_type="urn:gew:contract:test", **common)
        self.assertNotEqual(original, semantic_digest(body, contract_type="urn:gew:contract:other", **common))
        self.assertNotEqual(original, semantic_digest({**body, "value": 2}, contract_type="urn:gew:contract:test", **common))
        self.assertNotEqual(original.replace("sha256-jcs-v1:", "sha256-raw-v1:"), raw_digest(canonical_bytes(body)))

    def test_mutable_and_non_json_model_inputs_are_rejected(self) -> None:
        for value in ({"bad": {1, 2}}, {1: "bad"}, {"bad": 1.5}):
            with self.subTest(value=value), self.assertRaises(TypeError):
                freeze(value)


if __name__ == "__main__":
    unittest.main()
