"""Closed deterministic records for data-only extension materialization."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw


class ExtensionDataError(ValueError):
    """A data extension record or invariant binding is invalid."""


def _digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _text(value: object, label: str, maximum: int = 4096) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode()) > maximum
    ):
        raise ExtensionDataError(f"{label} is invalid")
    return value


def _digest_value(value: object, label: str) -> str:
    text = _text(value, label, 78)
    if len(text) != 78 or not text.startswith("sha256-jcs-v1:") or any(
        character not in "0123456789abcdef" for character in text[14:]
    ):
        raise ExtensionDataError(f"{label} is invalid")
    return text


def _strings(value: object, label: str, maximum: int = 1024) -> tuple[str, ...]:
    if type(value) is not list or len(value) > maximum:
        raise ExtensionDataError(f"{label} is invalid")
    result = tuple(_text(item, label) for item in value)
    if [canonical_bytes(item) for item in result] != sorted(
        {canonical_bytes(item) for item in result}
    ):
        raise ExtensionDataError(f"{label} is not canonical")
    return result


@dataclass(frozen=True, slots=True)
class ExtensionCoreInvariantSet:
    invariant_set_id: str
    invariant_ids: tuple[str, ...]
    allowed_security_effects: tuple[str, ...]
    invariant_set_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ExtensionCoreInvariantSet:
        fields = {
            "schema_version", "invariant_set_id", "invariant_ids",
            "allowed_security_effects", "invariant_set_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionDataError("extension CoreInvariantSet is not exact")
        body = dict(value)
        claimed = _digest_value(body.pop("invariant_set_digest"), "invariant set digest")
        if (
            body.get("schema_version") != "1.0.0"
            or not hmac.compare_digest(_digest(body, "extension-core-invariant-set"), claimed)
        ):
            raise ExtensionDataError("extension CoreInvariantSet self-digest mismatch")
        effects = _strings(value.get("allowed_security_effects"), "security effects")
        if effects != ("constrain-only",):
            raise ExtensionDataError("extension CoreInvariantSet security floor was weakened")
        invariants = _strings(value.get("invariant_ids"), "core invariant IDs")
        if not invariants:
            raise ExtensionDataError("extension CoreInvariantSet is empty")
        return cls(
            _text(value.get("invariant_set_id"), "invariant set ID"),
            invariants,
            effects,
            claimed,
        )


@dataclass(frozen=True, slots=True, init=False)
class ExtensionDataRecord:
    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension data records require exact decoding")

    @classmethod
    def from_dict(cls, value: object) -> ExtensionDataRecord:
        fields = {
            "schema_version", "data_kind", "identity_id", "data_version",
            "dependencies", "core_invariant_set_digest", "security_effect", "body",
            "record_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionDataError("extension data record is not exact")
        kind = _text(value.get("data_kind"), "data kind")
        if kind not in {"node", "edge", "policy", "template"}:
            raise ExtensionDataError("extension data kind is unsupported")
        body = dict(value)
        claimed = _digest_value(body.pop("record_digest"), "data record digest")
        if body.get("schema_version") != "1.0.0" or not hmac.compare_digest(
            _digest(body, f"extension-data-{kind}"), claimed
        ):
            raise ExtensionDataError("extension data record self-digest mismatch")
        _text(value.get("identity_id"), "data identity")
        _text(value.get("data_version"), "data version", 64)
        _digest_value(value.get("core_invariant_set_digest"), "core invariant set digest")
        _text(value.get("security_effect"), "security effect")
        dependencies = value.get("dependencies")
        if type(dependencies) is not list or len(dependencies) > 1024:
            raise ExtensionDataError("extension data dependencies are invalid")
        dependency_pairs: list[tuple[str, str]] = []
        for dependency in dependencies:
            if not isinstance(dependency, Mapping) or set(dependency) != {"kind", "id"}:
                raise ExtensionDataError("extension data dependency is not exact")
            dependency_pairs.append(
                (_text(dependency.get("kind"), "dependency kind"), _text(dependency.get("id"), "dependency ID"))
            )
        if dependency_pairs != sorted(set(dependency_pairs)):
            raise ExtensionDataError("extension data dependencies are not canonical")
        cls._validate_body(kind, value.get("body"))
        result = object.__new__(cls)
        object.__setattr__(result, "_document", freeze(value))
        return result

    @staticmethod
    def _validate_body(kind: str, value: object) -> None:
        if not isinstance(value, Mapping):
            raise ExtensionDataError("extension data body is invalid")
        fields = {
            "node": {
                "node_semantics", "input_schema_id", "output_schema_id", "invalidation_tags"
            },
            "edge": {
                "source_id", "target_id", "edge_type", "condition_ref", "invalidation_mode"
            },
            "policy": {"policy_effect", "rule_ids"},
            "template": {"template_schema_id", "template_text"},
        }[kind]
        if set(value) != fields:
            raise ExtensionDataError(f"extension {kind} body is not exact")
        if kind == "node":
            if value.get("node_semantics") != "declarative-only":
                raise ExtensionDataError("extension node cannot be executable")
            _text(value.get("input_schema_id"), "node input schema")
            _text(value.get("output_schema_id"), "node output schema")
            _strings(value.get("invalidation_tags"), "node invalidation tags")
        elif kind == "edge":
            _text(value.get("source_id"), "edge source")
            _text(value.get("target_id"), "edge target")
            if (
                value.get("edge_type") != "typed-data"
                or value.get("condition_ref") is not None
                or value.get("invalidation_mode") != "descendants"
            ):
                raise ExtensionDataError("extension edge semantics are not deterministic data")
        elif kind == "policy":
            _text(value.get("policy_effect"), "policy effect")
            _strings(value.get("rule_ids"), "policy rule IDs")
        else:
            _text(value.get("template_schema_id"), "template schema")
            _text(value.get("template_text"), "template text", 1_048_576)

    @property
    def kind(self) -> str:
        return str(self._document["data_kind"])

    @property
    def identity_id(self) -> str:
        return str(self._document["identity_id"])

    @property
    def record_digest(self) -> str:
        return str(self._document["record_digest"])

    @property
    def dependencies(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (str(item["kind"]), str(item["id"]))
            for item in self._document["dependencies"]
        )

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result
