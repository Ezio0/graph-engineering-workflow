"""Digest-locked closed registry for machine error rule IDs."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.errors import ERROR_CODES, ERROR_PHASES, ErrorDetail


RULE_ID = re.compile(r"[a-z][a-z0-9-]*(?:/[A-Za-z0-9$._-]+)+\Z")
CONTRACT_TYPE = "urn:gew:contract:error-rule-registry"
SCHEMA_ID = "urn:gew:schema:error-rule-registry:1.0.0"
PROJECTION_ID = "urn:gew:digest-projection:error-rule-registry:1.0.0"


@dataclass(frozen=True, slots=True, init=False)
class ErrorRuleRegistry:
    """Exact stable code/phase/rule triples without display messages."""

    registry_id: str
    registry_digest: str
    rules: frozenset[tuple[str, str, str]]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ErrorRuleRegistry must be loaded from a manifest")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ErrorRuleRegistry is final")

    @classmethod
    def create_manifest(cls, registry_id: str, rules: list[dict[str, object]]) -> dict[str, object]:
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:error-rule-registry:"):
            raise ValueError("invalid ErrorRuleRegistry ID")
        triples: list[tuple[str, str, str]] = []
        for rule in rules:
            if not isinstance(rule, Mapping) or set(rule) != {"code", "phase", "rule_id"}:
                raise ValueError("ErrorRuleRegistry rule shape is not exact")
            triple = (rule["rule_id"], rule["code"], rule["phase"])
            if (
                type(triple[0]) is not str
                or RULE_ID.fullmatch(triple[0]) is None
                or triple[1] not in ERROR_CODES
                or triple[2] not in ERROR_PHASES
            ):
                raise ValueError("ErrorRuleRegistry triple is invalid")
            triples.append(triple)  # type: ignore[arg-type]
        if triples != sorted(triples) or len(triples) != len(set(triples)):
            raise ValueError("ErrorRuleRegistry triples must be sorted and unique")
        manifest: dict[str, object] = {
            "schema_version": "1.0.0",
            "registry_id": registry_id,
            "rules": rules,
        }
        manifest["registry_digest"] = semantic_digest(manifest, contract_type=CONTRACT_TYPE, projection_id=PROJECTION_ID, schema_id=SCHEMA_ID)
        return manifest

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ErrorRuleRegistry:
        if set(value) != {"schema_version", "registry_id", "rules", "registry_digest"} or value.get("schema_version") != "1.0.0":
            raise ValueError("ErrorRuleRegistry properties are not exact")
        registry_id = value.get("registry_id")
        rules = value.get("rules")
        registry_digest = value.get("registry_digest")
        if type(registry_id) is not str or not isinstance(rules, list) or type(registry_digest) is not str:
            raise ValueError("ErrorRuleRegistry fields are invalid")
        expected = ErrorRuleRegistry.create_manifest(registry_id, rules)
        if expected["registry_digest"] != registry_digest:
            raise ValueError("ErrorRuleRegistry digest mismatch")
        result = object.__new__(ErrorRuleRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", registry_digest)
        object.__setattr__(result, "rules", frozenset(
            (rule["rule_id"], rule["code"], rule["phase"]) for rule in rules  # type: ignore[misc]
        ))
        return result

    def require(self, detail: ErrorDetail) -> None:
        triple = (detail.rule_id, detail.code, detail.phase)
        if triple not in self.rules:
            raise ValueError(f"unregistered error rule triple: {triple}")
