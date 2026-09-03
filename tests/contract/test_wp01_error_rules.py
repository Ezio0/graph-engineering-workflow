from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry  # noqa: E402
from graph_engineering.core.contracts.errors import ErrorDetail  # noqa: E402


class ErrorRuleRegistryTests(unittest.TestCase):
    def test_registry_is_digest_locked_closed_and_rejects_unknown_rule(self) -> None:
        value = json.loads((ROOT / "config" / "contracts" / "error-rule-registry-v1.json").read_text())
        registry = ErrorRuleRegistry.from_dict(value)
        detail = ErrorDetail(code="E_TYPE", phase="static", rule_id="type/root-result", source_id="urn:gew:test")
        registry.require(detail)
        unknown = ErrorDetail(code="E_TYPE", phase="static", rule_id="type/not-registered", source_id="urn:gew:test")
        with self.assertRaisesRegex(ValueError, "unregistered"):
            registry.require(unknown)
        illegal = ErrorDetail(code="E_BUDGET", phase="runtime", rule_id="schema/type", source_id="urn:gew:test")
        with self.assertRaisesRegex(ValueError, "triple"):
            registry.require(illegal)
        tampered = json.loads(json.dumps(value))
        tampered["rules"].pop()
        with self.assertRaisesRegex(ValueError, "digest"):
            ErrorRuleRegistry.from_dict(tampered)
        duplicate = json.loads(json.dumps(value))
        duplicate["rules"].append(duplicate["rules"][0])
        duplicate["rules"].sort(key=lambda item: (item["rule_id"], item["code"], item["phase"]))
        with self.assertRaises(ValueError):
            ErrorRuleRegistry.from_dict(duplicate)
        with self.assertRaises(TypeError):
            ErrorRuleRegistry(
                "urn:gew:error-rule-registry:forged:1.0.0",
                "sha256-jcs-v1:" + "0" * 64,
                frozenset({("schema/type", "E_BUDGET", "runtime")}),
            )  # type: ignore[call-arg]
        with self.assertRaises((AttributeError, TypeError)):
            registry.rules = frozenset({("schema/type", "E_BUDGET", "runtime")})  # type: ignore[assignment]
        with self.assertRaises(TypeError):
            ErrorRuleRegistry()  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            type("ForgedErrorRuleRegistry", (ErrorRuleRegistry,), {})

if __name__ == "__main__":
    unittest.main()
