"""Closed, platform-neutral WP-08 category execution contracts.

This module contains only immutable records, policy validation, and the pure
state reducer.  Target I/O, persistence, and action coordination live behind
application ports.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import stat
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.profiles import MaterializationRecord


class CategoryExecutionError(ValueError):
    """A category execution input or authority failed closed."""


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise CategoryExecutionError(f"{label} properties are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or not value.isascii()
    ):
        raise CategoryExecutionError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise CategoryExecutionError(f"{label} is not a semantic digest")
    return result


def _strings(value: object, label: str, *, empty: bool = False) -> tuple[str, ...]:
    if type(value) is not list or (not empty and not value):
        raise CategoryExecutionError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if result != tuple(sorted(set(result))):
        raise CategoryExecutionError(f"{label} must be sorted and unique")
    return result


def _ordered_strings(value: object, label: str, *, empty: bool = False) -> tuple[str, ...]:
    if type(value) is not list or (not empty and not value):
        raise CategoryExecutionError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if len(result) != len(set(result)):
        raise CategoryExecutionError(f"{label} contains duplicates")
    return result


def _frozen(value: object, label: str) -> FrozenMap:
    if not isinstance(value, Mapping):
        raise CategoryExecutionError(f"{label} must be an object")
    result = freeze(value)
    if not isinstance(result, FrozenMap):
        raise AssertionError(f"{label} did not freeze")
    return result


def _self_digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        freeze(body),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _internal_digest(value: object, name: str) -> str:
    """Digest an internal reducer value without claiming a public schema."""

    framed = b"GEW-INTERNAL-DIGEST-V1\x00" + name.encode("ascii") + b"\x00"
    return "sha256-jcs-v1:" + hashlib.sha256(framed + canonical_bytes(value)).hexdigest()


def _strict_json_bytes(body: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in items:
            if key in result:
                raise CategoryExecutionError(f"{label} contains a duplicate key")
            result[key] = item
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CategoryExecutionError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise CategoryExecutionError(f"{label} root is not an object")
    return value


def _stable_installation_bytes(
    root: pathlib.Path, relative: str, *, maximum: int, label: str
) -> bytes:
    if (
        type(relative) is not str
        or not relative
        or pathlib.PurePosixPath(relative).is_absolute()
        or ".." in pathlib.PurePosixPath(relative).parts
        or "\\" in relative
    ):
        raise CategoryExecutionError(f"{label} path is not portable")
    path = root.joinpath(*pathlib.PurePosixPath(relative).parts)
    parent = path.parent.resolve(strict=True)
    if root not in (parent, *parent.parents):
        raise CategoryExecutionError(f"{label} path escapes the installation")
    before_entry = os.stat(path, follow_symlinks=False)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum
            or (before.st_dev, before.st_ino) != (before_entry.st_dev, before_entry.st_ino)
        ):
            raise CategoryExecutionError(f"{label} installation identity is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise CategoryExecutionError(f"{label} was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CategoryExecutionError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        after_entry = os.stat(path, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_uid, stat.S_IMODE(item.st_mode),
            item.st_nlink, item.st_size,
        )
        if identity(before) != identity(after) or identity(after) != identity(after_entry):
            raise CategoryExecutionError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _raw_digest(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(item not in "0123456789abcdef" for item in result):
        raise CategoryExecutionError(f"{label} is not a lowercase SHA-256")
    return result


def _installed_policy_document() -> dict[str, object]:
    from graph_engineering import (
        DistributionIdentityError,
        _category_policy_installation_resources,
    )

    try:
        provenance_bytes, registry_bytes, policy_bytes = (
            _category_policy_installation_resources()
        )
        provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
        bootstrap = provenance["tool"]["gew"]["profile"][
            "category-execution-policy"
        ]
    except (
        DistributionIdentityError,
        KeyError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise CategoryExecutionError(
            "category policy installation bootstrap is unavailable"
        ) from error
    bootstrap = _exact(
        bootstrap,
        frozenset({
            "registry-id", "registry-digest", "registry-raw-sha256",
            "registry-source", "registry-resource", "policy-id", "policy-digest",
            "policy-raw-sha256", "policy-source", "policy-resource",
        }),
        "category policy installation bootstrap",
    )
    if not hmac.compare_digest(
        hashlib.sha256(registry_bytes).hexdigest(),
        _raw_digest(bootstrap["registry-raw-sha256"], "bootstrap registry raw digest"),
    ):
        raise CategoryExecutionError("category policy registry differs from bootstrap")
    registry = _exact(
        _strict_json_bytes(registry_bytes, "category policy registry"),
        frozenset({
            "schema_version", "registry_id", "policy_id", "policy_digest",
            "policy_path", "policy_raw_sha256", "registry_digest",
        }),
        "category policy registry",
    )
    if (
        registry["schema_version"] != "1.0.0"
        or registry["registry_id"] != bootstrap["registry-id"]
        or registry["policy_id"] != bootstrap["policy-id"]
        or registry["policy_digest"] != bootstrap["policy-digest"]
    ):
        raise CategoryExecutionError("category policy registry identity changed")
    registry_body = dict(registry)
    expected_registry_digest = _digest(
        registry_body.pop("registry_digest"), "category policy registry digest"
    )
    actual_registry_digest = "sha256-jcs-v1:" + hashlib.sha256(
        b"GEW-CATEGORY-POLICY-REGISTRY-V1\x00" + canonical_bytes(registry_body)
    ).hexdigest()
    if not hmac.compare_digest(expected_registry_digest, actual_registry_digest):
        raise CategoryExecutionError("category policy registry self digest changed")
    if not hmac.compare_digest(
        expected_registry_digest,
        _digest(bootstrap["registry-digest"], "bootstrap registry digest"),
    ):
        raise CategoryExecutionError("category policy registry bootstrap pin changed")
    if not hmac.compare_digest(
        hashlib.sha256(policy_bytes).hexdigest(),
        _raw_digest(registry["policy_raw_sha256"], "category policy raw digest"),
    ) or not hmac.compare_digest(
        hashlib.sha256(policy_bytes).hexdigest(),
        _raw_digest(bootstrap["policy-raw-sha256"], "bootstrap policy raw digest"),
    ):
        raise CategoryExecutionError("category policy bytes differ from registry")
    policy = _strict_json_bytes(policy_bytes, "category execution policy")
    if (
        policy.get("policy_id") != registry["policy_id"]
        or policy.get("policy_digest") != registry["policy_digest"]
        or policy.get("policy_id") != bootstrap["policy-id"]
        or policy.get("policy_digest") != bootstrap["policy-digest"]
    ):
        raise CategoryExecutionError("category policy identity differs from registry")
    return policy


def _verify_document_digest(
    document: Mapping[str, object], name: str, field: str
) -> str:
    expected = _digest(document.get(field), f"{name} digest")
    body = thaw(freeze(document))
    if not isinstance(body, dict):
        raise AssertionError(f"{name} did not copy")
    del body[field]
    if not hmac.compare_digest(expected, _self_digest(body, name)):
        raise CategoryExecutionError(f"{name} self digest changed")
    return expected


_PIN_FIELDS = frozenset({
    "base_graph_digest",
    "profile_digest",
    "overlay_digest",
    "project_config_digest",
    "support_matrix_digest",
    "materialization_digest",
})
_RUNNER_FIELDS = frozenset({
    "node_ids",
    "edge_ids",
    "artifact_contract_ids",
    "validator_ids",
    "completion_predicate_ids",
    "required_invariant_ids",
    "budget_limits",
})
_CANDIDATE_FIELDS = frozenset({
    "schema_version",
    "request_id",
    "task_id",
    "task_revision",
    "snapshot_digest",
    "invalidation_epoch",
    "profile_id",
    "profile_version",
    "profile_digest",
    "overlay_id",
    "materialization_digest",
    "digest_pins",
    "column_id",
    "scenario_id",
    "execution_kind",
    "authority_refs",
    "required_node_ids",
    "passed_node_ids",
    "required_artifact_contract_ids",
    "current_artifact_contract_ids",
    "required_validator_ids",
    "passed_validator_ids",
    "required_completion_predicate_ids",
    "passed_completion_predicate_ids",
    "runner_outputs",
    "review",
    "target",
    "rollback",
    "unresolved_refs",
})


@dataclass(frozen=True, slots=True, init=False)
class CategoryExecutionPolicy:
    policy_id: str
    policy_digest: str
    profile_id: str
    profile_version: str
    profile_digest: str
    support_matrix_digest: str
    authority_refs: tuple[str, ...]
    column_ids: tuple[str, ...]
    local_execution_kinds: tuple[str, ...]
    real_e2e_execution_kinds: tuple[str, ...]
    category_boundary_case_ids: tuple[str, ...]
    required_node_ids: tuple[str, ...]
    artifact_contract_ids: tuple[str, ...]
    validator_ids: tuple[str, ...]
    completion_predicate_ids: tuple[str, ...]
    rollback_contract: FrozenMap
    rollback_protocol_mappings: FrozenMap
    transition_rules: FrozenMap
    materialization_record: MaterializationRecord
    materialization_graph_ref: FrozenMap
    materialization_output: FrozenMap
    _policy_body: FrozenMap
    _profile_document: FrozenMap
    _support_matrix_document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryExecutionPolicy is issued only from installed config")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        profile_document: object,
        support_matrix_document: object,
        materialization_record: object,
    ) -> CategoryExecutionPolicy:
        installed = _installed_policy_document()
        if freeze(value) != freeze(installed):
            raise CategoryExecutionError("category policy is not the installed policy bytes")
        return cls._from_installed(
            installed,
            profile_document=profile_document,
            support_matrix_document=support_matrix_document,
            materialization_record=materialization_record,
        )

    @classmethod
    def from_installation(
        cls,
        *,
        profile_document: object,
        support_matrix_document: object,
        materialization_record: object,
    ) -> CategoryExecutionPolicy:
        return cls._from_installed(
            _installed_policy_document(),
            profile_document=profile_document,
            support_matrix_document=support_matrix_document,
            materialization_record=materialization_record,
        )

    @classmethod
    def _from_installed(
        cls,
        value: object,
        *,
        profile_document: object,
        support_matrix_document: object,
        materialization_record: object,
    ) -> CategoryExecutionPolicy:
        fields = frozenset({
            "schema_version",
            "policy_id",
            "profile_identities",
            "support_matrix_digest",
            "authority_refs",
            "column_ids",
            "local_execution_kinds",
            "real_e2e_execution_kinds",
            "rollback_protocol_mappings",
            "transition_rules",
            "policy_digest",
        })
        record = _exact(value, fields, "category execution policy")
        if record["schema_version"] != "1.0.0":
            raise CategoryExecutionError("category execution policy version is unsupported")
        policy_digest = _verify_document_digest(record, "category-execution-policy", "policy_digest")
        profile = _exact(
            profile_document,
            frozenset({
                "schema_version", "profile_id", "version",
                "approved_profile_registry_digest", "coverage_policy_digest",
                "profile_semantic_policy_digest", "required_node_ids",
                "optional_node_ids", "required_edge_ids", "optional_edge_ids",
                "route_overrides", "artifact_contract_ids", "validator_ids",
                "completion_predicate_ids", "compatible_risk_paths",
                "rollback_contract", "required_case_ids",
                "category_boundary_case_ids", "real_e2e_requirement_id",
                "required_capabilities", "unsupported_integrations",
                "evidence_policy", "digest",
            }),
            "Profile definition source",
        )
        profile_digest = _verify_document_digest(profile, "profile-definition", "digest")
        matrix = _exact(
            support_matrix_document,
            frozenset({
                "schema_version", "matrix_id", "version",
                "approved_profile_registry_digest", "coverage_policy_digest",
                "profile_ids", "profile_column_ids", "risk_path_ids",
                "profile_case_ids", "scenario_case_ids", "case_bindings", "digest",
            }),
            "support matrix source",
        )
        matrix_digest = _verify_document_digest(matrix, "support-matrix-definition", "digest")
        if not hmac.compare_digest(
            matrix_digest,
            _digest(record["support_matrix_digest"], "policy support matrix digest"),
        ):
            raise CategoryExecutionError("category execution support matrix changed")
        profile_ids = _ordered_strings(matrix["profile_ids"], "support matrix Profile IDs")
        profile_id = _text(profile["profile_id"], "Profile ID")
        profile_version = _text(profile["version"], "Profile version")
        if profile_id not in profile_ids:
            raise CategoryExecutionError("Profile is absent from the support matrix")
        raw_identities = record["profile_identities"]
        if type(raw_identities) is not list:
            raise CategoryExecutionError("category execution Profile identities are invalid")
        identities: list[tuple[str, str, str]] = []
        for raw in raw_identities:
            item = _exact(
                raw,
                frozenset({"profile_id", "profile_version", "profile_digest"}),
                "category execution Profile identity",
            )
            identities.append((
                _text(item["profile_id"], "policy Profile ID"),
                _text(item["profile_version"], "policy Profile version"),
                _digest(item["profile_digest"], "policy Profile digest"),
            ))
        if len(identities) != len(set(identities)) or tuple(item[0] for item in identities) != profile_ids:
            raise CategoryExecutionError("category execution Profile identities are not closed")
        try:
            approved_identity = next(item for item in identities if item[0] == profile_id)
        except StopIteration as error:
            raise CategoryExecutionError("Profile has no category execution identity") from error
        if (
            approved_identity[1] != profile_version
            or not hmac.compare_digest(approved_identity[2], profile_digest)
        ):
            raise CategoryExecutionError("Profile category execution identity changed")
        if type(materialization_record) is not MaterializationRecord:
            raise CategoryExecutionError("materialization authority is missing or forged")
        try:
            materialization_record.require_issued()
        except ValueError as error:
            raise CategoryExecutionError("materialization authority is missing or forged") from error
        graph_ref = materialization_record.graph_ref_body
        output = materialization_record.output_body
        if (
            graph_ref["profile_id"] != profile_id
            or graph_ref["profile_version"] != profile_version
            or graph_ref["profile_digest"] != profile_digest
            or graph_ref["support_matrix_digest"] != matrix_digest
        ):
            raise CategoryExecutionError("materialization authority does not bind the Profile")
        raw_transitions = record["transition_rules"]
        if type(raw_transitions) is not list:
            raise CategoryExecutionError("category transition rules are invalid")
        transitions: dict[str, FrozenMap] = {}
        for raw in raw_transitions:
            item = _exact(
                raw,
                frozenset({
                    "column_id", "from_state", "event_type", "to_state",
                    "evidence_kind", "required_outcome", "required_fact_ids",
                    "owner_route",
                }),
                "category transition rule",
            )
            column = _text(item["column_id"], "category transition column")
            _text(item["required_outcome"], "category required outcome")
            _strings(item["required_fact_ids"], "category required evidence facts")
            if column == "revise":
                _text(item["owner_route"], "category revise owner route")
            elif item["owner_route"] is not None:
                raise CategoryExecutionError(
                    "only the revise column may declare an owner route"
                )
            if column in transitions:
                raise CategoryExecutionError("duplicate category transition column")
            transitions[column] = _frozen(item, "category transition rule")
        columns = _ordered_strings(record["column_ids"], "category execution columns")
        if tuple(transitions) != columns:
            raise CategoryExecutionError("category transition closure changed")
        outcomes = tuple(str(item["required_outcome"]) for item in transitions.values())
        if len(outcomes) != len(set(outcomes)):
            raise CategoryExecutionError("category outcomes must be column-specific")
        raw_mappings = record["rollback_protocol_mappings"]
        if type(raw_mappings) is not list:
            raise CategoryExecutionError("rollback protocol mappings are invalid")
        mappings: dict[str, FrozenMap] = {}
        for raw in raw_mappings:
            item = _exact(
                raw,
                frozenset({
                    "logical_action_kind", "action_protocol_kind", "prepared_status",
                    "authorized_status", "success_status", "unknown_route", "failure_route",
                }),
                "rollback protocol mapping",
            )
            kind = _text(item["logical_action_kind"], "rollback logical action kind")
            if kind in mappings:
                raise CategoryExecutionError("duplicate rollback logical action kind")
            mappings[kind] = _frozen(item, "rollback protocol mapping")
        result = object.__new__(cls)
        body = {key: item for key, item in record.items() if key != "policy_digest"}
        values = (
            ("policy_id", _text(record["policy_id"], "category execution policy ID")),
            ("policy_digest", policy_digest),
            ("profile_id", profile_id),
            ("profile_version", profile_version),
            ("profile_digest", profile_digest),
            ("support_matrix_digest", matrix_digest),
            ("authority_refs", _strings(record["authority_refs"], "category authority refs")),
            ("column_ids", columns),
            ("local_execution_kinds", _strings(record["local_execution_kinds"], "local execution kinds")),
            ("real_e2e_execution_kinds", _strings(record["real_e2e_execution_kinds"], "real E2E execution kinds")),
            ("category_boundary_case_ids", _strings(profile["category_boundary_case_ids"], "category boundary cases")),
            ("required_node_ids", _strings(profile["required_node_ids"], "required Profile nodes")),
            ("artifact_contract_ids", _strings(profile["artifact_contract_ids"], "required Profile artifacts")),
            ("validator_ids", _strings(profile["validator_ids"], "required Profile validators")),
            ("completion_predicate_ids", _strings(profile["completion_predicate_ids"], "required completion predicates")),
            ("rollback_contract", _frozen(profile["rollback_contract"], "Profile rollback contract")),
            ("rollback_protocol_mappings", FrozenMap.from_dict(mappings)),
            ("transition_rules", FrozenMap.from_dict(transitions)),
            ("materialization_record", materialization_record),
            ("materialization_graph_ref", graph_ref),
            ("materialization_output", output),
            ("_policy_body", _frozen(body, "category execution policy body")),
            ("_profile_document", _frozen(profile, "Profile definition source")),
            ("_support_matrix_document", _frozen(matrix, "support matrix source")),
        )
        for name, item in values:
            object.__setattr__(result, name, item)
        result.require_current()
        return result

    def require_current(self) -> None:
        installed = _installed_policy_document()
        body = thaw(self._policy_body)
        if not isinstance(body, dict):
            raise CategoryExecutionError("category execution policy body changed")
        body["policy_digest"] = self.policy_digest
        if freeze(installed) != freeze(body):
            raise CategoryExecutionError("category execution installation pin changed")
        if not hmac.compare_digest(
            self.policy_digest,
            _self_digest(self._policy_body, "category-execution-policy"),
        ):
            raise CategoryExecutionError("category execution policy authority changed")
        if not hmac.compare_digest(
            self.profile_digest,
            _verify_document_digest(self._profile_document, "profile-definition", "digest"),
        ):
            raise CategoryExecutionError("Profile definition authority changed")
        if not hmac.compare_digest(
            self.support_matrix_digest,
            _verify_document_digest(
                self._support_matrix_document, "support-matrix-definition", "digest"
            ),
        ):
            raise CategoryExecutionError("support matrix authority changed")
        try:
            self.materialization_record.require_issued()
        except ValueError as error:
            raise CategoryExecutionError("materialization authority changed") from error

    def require_candidate(self, value: object) -> Mapping[str, object]:
        self.require_current()
        candidate = _exact(value, _CANDIDATE_FIELDS, "category execution candidate")
        if candidate["schema_version"] != "1.0.0":
            raise CategoryExecutionError("category execution candidate version is unsupported")
        for field in ("request_id", "task_id"):
            _text(candidate[field], field)
        if type(candidate["task_revision"]) is not int or candidate["task_revision"] <= 0:
            raise CategoryExecutionError("task revision is invalid")
        _digest(candidate["snapshot_digest"], "task snapshot digest")
        if type(candidate["invalidation_epoch"]) is not int or candidate["invalidation_epoch"] < 0:
            raise CategoryExecutionError("invalidation epoch is invalid")
        if (
            candidate["profile_id"] != self.profile_id
            or candidate["profile_version"] != self.profile_version
            or not hmac.compare_digest(
                _digest(candidate["profile_digest"], "candidate Profile digest"),
                self.profile_digest,
            )
        ):
            raise CategoryExecutionError("candidate Profile identity is stale or foreign")
        pins = _exact(candidate["digest_pins"], _PIN_FIELDS, "category materialization pins")
        for field in _PIN_FIELDS:
            _digest(pins[field], f"category materialization {field}")
        expected_pins = {
            "base_graph_digest": self.materialization_graph_ref["graph_digest"],
            "profile_digest": self.materialization_graph_ref["profile_digest"],
            "overlay_digest": self.materialization_graph_ref["overlay_digest"],
            "project_config_digest": self.materialization_graph_ref["project_config_digest"],
            "support_matrix_digest": self.materialization_graph_ref["support_matrix_digest"],
            "materialization_digest": self.materialization_graph_ref["materialization_digest"],
        }
        if any(
            not hmac.compare_digest(str(pins[field]), str(expected_pins[field]))
            for field in _PIN_FIELDS
        ):
            raise CategoryExecutionError("category materialization pins are stale or foreign")
        if (
            candidate["overlay_id"] != self.materialization_graph_ref["overlay_id"]
            or candidate["materialization_digest"] != pins["materialization_digest"]
        ):
            raise CategoryExecutionError("category materialization identity changed")
        column = _text(candidate["column_id"], "category execution column")
        if column not in self.column_ids:
            raise CategoryExecutionError("category execution column is not approved")
        scenario = _text(candidate["scenario_id"], "category boundary scenario")
        if scenario not in self.category_boundary_case_ids or not scenario.endswith("-P"):
            raise CategoryExecutionError("category boundary scenario is not an approved PASS member")
        execution_kind = _text(candidate["execution_kind"], "category execution kind")
        if column == "real-e2e":
            if execution_kind not in self.real_e2e_execution_kinds:
                raise CategoryExecutionError("local execution cannot satisfy real E2E")
        elif execution_kind not in self.local_execution_kinds:
            raise CategoryExecutionError("category execution kind is not approved")
        if _strings(candidate["authority_refs"], "category authority refs") != self.authority_refs:
            raise CategoryExecutionError("category execution authority is stale or foreign")
        for required_field, passed_field, approved in (
            ("required_node_ids", "passed_node_ids", self.required_node_ids),
            (
                "required_artifact_contract_ids",
                "current_artifact_contract_ids",
                self.artifact_contract_ids,
            ),
            ("required_validator_ids", "passed_validator_ids", self.validator_ids),
            (
                "required_completion_predicate_ids",
                "passed_completion_predicate_ids",
                self.completion_predicate_ids,
            ),
        ):
            required = _strings(candidate[required_field], required_field)
            passed = _strings(candidate[passed_field], passed_field)
            if required != approved or passed != required:
                raise CategoryExecutionError("category completion set is incomplete or stale")
        runner = _exact(candidate["runner_outputs"], _RUNNER_FIELDS, "category runner outputs")
        for field in _RUNNER_FIELDS - {"budget_limits"}:
            if _strings(runner[field], f"runner {field}", empty=True) != tuple(
                self.materialization_output[field]
            ):
                raise CategoryExecutionError("runner output is stale or incomplete")
        raw_budgets = runner["budget_limits"]
        if type(raw_budgets) is not dict or raw_budgets != dict(
            self.materialization_output["budget_limits"]
        ):
            raise CategoryExecutionError("runner budget output is stale or incomplete")
        review = _exact(
            candidate["review"],
            frozenset({
                "author_id", "reviewer_id", "trust", "verdict",
                "body_digest", "previous_body_digest",
            }),
            "category independent review",
        )
        author = _text(review["author_id"], "category author")
        reviewer = _text(review["reviewer_id"], "category reviewer")
        if (
            author.casefold() == reviewer.casefold()
            or review["trust"] != "independently-reviewed"
            or review["verdict"] != "PASS"
            or hmac.compare_digest(
                _digest(review["body_digest"], "review body digest"),
                _digest(review["previous_body_digest"], "previous review body digest"),
            )
        ):
            raise CategoryExecutionError("category independent review is absent or stale")
        _exact(
            candidate["target"],
            frozenset({"target_id", "resource_id", "expected_state"}),
            "category target",
        )
        rollback = _exact(
            candidate["rollback"],
            frozenset({
                "logical_action_kind", "action_protocol_kind", "authority_requirement",
                "compensation_graph_ref", "precondition_ids", "verification_ids",
            }),
            "category rollback",
        )
        logical_kind = _text(rollback["logical_action_kind"], "rollback logical action kind")
        try:
            mapping = self.rollback_protocol_mappings[logical_kind]
        except KeyError as error:
            raise CategoryExecutionError("rollback logical action kind is not approved") from error
        if not isinstance(mapping, FrozenMap) or rollback["action_protocol_kind"] != mapping["action_protocol_kind"]:
            raise CategoryExecutionError("rollback ActionPolicy mapping changed")
        for field in ("authority_requirement", "compensation_graph_ref"):
            if rollback[field] != self.rollback_contract[field]:
                raise CategoryExecutionError("rollback Profile contract changed")
        for candidate_field, profile_field in (
            ("precondition_ids", "precondition_ids"),
            ("verification_ids", "verification_ids"),
        ):
            if _strings(rollback[candidate_field], candidate_field) != tuple(
                self.rollback_contract[profile_field]
            ):
                raise CategoryExecutionError("rollback Profile verification changed")
        if _strings(candidate["unresolved_refs"], "unresolved category refs", empty=True):
            raise CategoryExecutionError("category execution has unresolved refs")
        return candidate


@dataclass(frozen=True, slots=True, init=False)
class CategoryExecutionState:
    schema_version: str
    task_id: str
    profile_id: str
    column_id: str
    lifecycle: str
    revision: int
    snapshot_digest: str
    invalidation_epoch: int
    last_event_digest: str | None
    state_digest: str
    _reducer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryExecutionState is reducer-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "task_id": self.task_id,
            "profile_id": self.profile_id,
            "column_id": self.column_id,
            "lifecycle": self.lifecycle,
            "revision": self.revision,
            "snapshot_digest": self.snapshot_digest,
            "invalidation_epoch": self.invalidation_epoch,
            "last_event_digest": self.last_event_digest,
            "state_digest": self.state_digest,
        }


@dataclass(frozen=True, slots=True, init=False)
class CategoryExecutionEvent:
    schema_version: str
    event_type: str
    task_id: str
    profile_id: str
    column_id: str
    expected_revision: int
    assessment_digest: str
    previous_event_digest: str | None
    event_digest: str
    _reducer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryExecutionEvent is reducer-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "event_type": self.event_type,
            "task_id": self.task_id,
            "profile_id": self.profile_id,
            "column_id": self.column_id,
            "expected_revision": self.expected_revision,
            "assessment_digest": self.assessment_digest,
            "previous_event_digest": self.previous_event_digest,
            "event_digest": self.event_digest,
        }


class CategoryExecutionReducer:
    """Pure transition reducer over config-declared column transitions."""

    def __init__(self, policy: CategoryExecutionPolicy) -> None:
        if type(policy) is not CategoryExecutionPolicy:
            raise CategoryExecutionError("category reducer policy is missing or forged")
        policy.require_current()
        self._policy = policy
        self.__states: dict[int, CategoryExecutionState] = {}
        self.__events: dict[int, CategoryExecutionEvent] = {}

    def initial(self, candidate: object) -> CategoryExecutionState:
        value = self._policy.require_candidate(candidate)
        column = str(value["column_id"])
        rule = self._policy.transition_rules[column]
        if not isinstance(rule, FrozenMap):
            raise CategoryExecutionError("category transition rule authority changed")
        body = {
            "schema_version": "1.0.0",
            "task_id": value["task_id"],
            "profile_id": value["profile_id"],
            "column_id": column,
            "lifecycle": rule["from_state"],
            "revision": 0,
            "snapshot_digest": value["snapshot_digest"],
            "invalidation_epoch": value["invalidation_epoch"],
            "last_event_digest": None,
        }
        state = object.__new__(CategoryExecutionState)
        for name, item in body.items():
            object.__setattr__(state, name, item)
        object.__setattr__(state, "state_digest", _self_digest(body, "category-execution-state"))
        object.__setattr__(state, "_reducer", self)
        self.__states[id(state)] = state
        return state

    def transition(
        self,
        state: CategoryExecutionState,
        *,
        assessment_digest: str,
    ) -> tuple[CategoryExecutionEvent, CategoryExecutionState]:
        if (
            type(state) is not CategoryExecutionState
            or state._reducer is not self
            or self.__states.get(id(state)) is not state
        ):
            raise CategoryExecutionError("category execution state is missing or foreign")
        digest = _digest(assessment_digest, "category assessment digest")
        rule = self._policy.transition_rules[state.column_id]
        if not isinstance(rule, FrozenMap) or state.lifecycle != rule["from_state"]:
            raise CategoryExecutionError("category transition is stale or invalid")
        event_body = {
            "schema_version": "1.0.0",
            "event_type": rule["event_type"],
            "task_id": state.task_id,
            "profile_id": state.profile_id,
            "column_id": state.column_id,
            "expected_revision": state.revision,
            "assessment_digest": digest,
            "previous_event_digest": state.last_event_digest,
        }
        event = object.__new__(CategoryExecutionEvent)
        for name, item in event_body.items():
            object.__setattr__(event, name, item)
        object.__setattr__(event, "event_digest", _internal_digest(event_body, "category-execution-event"))
        object.__setattr__(event, "_reducer", self)
        self.__events[id(event)] = event
        state_body = {
            "schema_version": "1.0.0",
            "task_id": state.task_id,
            "profile_id": state.profile_id,
            "column_id": state.column_id,
            "lifecycle": rule["to_state"],
            "revision": state.revision + 1,
            "snapshot_digest": state.snapshot_digest,
            "invalidation_epoch": state.invalidation_epoch,
            "last_event_digest": event.event_digest,
        }
        successor = object.__new__(CategoryExecutionState)
        for name, item in state_body.items():
            object.__setattr__(successor, name, item)
        object.__setattr__(successor, "state_digest", _self_digest(state_body, "category-execution-state"))
        object.__setattr__(successor, "_reducer", self)
        self.__states[id(successor)] = successor
        return event, successor

    def restore_assessed(
        self,
        assessment: object,
    ) -> tuple[CategoryExecutionEvent, CategoryExecutionState]:
        """Rebuild the reducer proof carried by one verified assessment body."""

        if not isinstance(assessment, Mapping):
            raise CategoryExecutionError("stored category assessment is malformed")
        column = assessment.get("column_id")
        task_id = assessment.get("task_id")
        profile_id = assessment.get("profile_id")
        snapshot_digest = assessment.get("snapshot_digest")
        epoch = assessment.get("invalidation_epoch")
        digest = assessment.get("assessment_digest")
        state_digest = assessment.get("state_digest")
        if (
            type(column) is not str
            or column not in self._policy.column_ids
            or type(task_id) is not str
            or profile_id != self._policy.profile_id
            or type(snapshot_digest) is not str
            or type(epoch) is not int
            or type(digest) is not str
            or type(state_digest) is not str
        ):
            raise CategoryExecutionError("stored category reducer binding is invalid")
        rule = self._policy.transition_rules[column]
        if not isinstance(rule, FrozenMap):
            raise CategoryExecutionError("stored category transition policy changed")
        body = {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "profile_id": profile_id,
            "column_id": column,
            "lifecycle": rule["from_state"],
            "revision": 0,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": epoch,
            "last_event_digest": None,
        }
        initial = object.__new__(CategoryExecutionState)
        for name, item in body.items():
            object.__setattr__(initial, name, item)
        object.__setattr__(initial, "state_digest", _self_digest(body, "category-execution-state"))
        object.__setattr__(initial, "_reducer", self)
        if not hmac.compare_digest(initial.state_digest, state_digest):
            raise CategoryExecutionError("stored category state digest changed")
        self.__states[id(initial)] = initial
        return self.transition(initial, assessment_digest=digest)


@dataclass(frozen=True, slots=True, init=False)
class CategoryTargetObservation:
    schema_version: str
    task_id: str
    profile_id: str
    snapshot_digest: str
    target_id: str
    resource_id: str
    execution_kind: str
    fresh: bool
    observation_revision: int
    file_identity: tuple[int, int]
    state: FrozenMap
    state_bytes_sha256: str
    materialization_digest: str
    observation_digest: str
    _authority: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryTargetObservation is authority-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "task_id": self.task_id,
            "profile_id": self.profile_id,
            "snapshot_digest": self.snapshot_digest,
            "target_id": self.target_id,
            "resource_id": self.resource_id,
            "execution_kind": self.execution_kind,
            "fresh": self.fresh,
            "observation_revision": self.observation_revision,
            "file_identity": list(self.file_identity),
            "state": thaw(self.state),
            "state_bytes_sha256": self.state_bytes_sha256,
            "materialization_digest": self.materialization_digest,
            "observation_digest": self.observation_digest,
        }


@dataclass(frozen=True, slots=True, init=False)
class CategoryRollbackAssessment:
    schema_version: str
    task_id: str
    profile_id: str
    logical_action_kind: str
    action_protocol_kind: str
    authority_requirement: str
    compensation_graph_ref: str
    status: str
    route: str
    observation_digest: str
    assessment_digest: str
    _authority: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryRollbackAssessment is bridge-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "task_id": self.task_id,
            "profile_id": self.profile_id,
            "logical_action_kind": self.logical_action_kind,
            "action_protocol_kind": self.action_protocol_kind,
            "authority_requirement": self.authority_requirement,
            "compensation_graph_ref": self.compensation_graph_ref,
            "status": self.status,
            "route": self.route,
            "observation_digest": self.observation_digest,
            "assessment_digest": self.assessment_digest,
        }


@dataclass(frozen=True, slots=True, init=False)
class CategoryCompletionAssessment:
    schema_version: str
    request_id: str
    request_digest: str
    task_id: str
    task_revision: int
    snapshot_digest: str
    invalidation_epoch: int
    profile_id: str
    profile_version: str
    profile_digest: str
    overlay_id: str
    column_id: str
    scenario_id: str
    category_boundary_case_ids: tuple[str, ...]
    status: str
    materialization_pins: FrozenMap
    runner_outputs: FrozenMap
    artifact_contract_ids: tuple[str, ...]
    authority_refs: tuple[str, ...]
    review_digest: str
    target_observation_digest: str
    rollback_assessment_digest: str
    state_digest: str
    column_evidence_digest: str
    performance_evidence_projection: FrozenMap | None
    migration_rehearsal_projection: FrozenMap | None
    dependency_graph_projection: FrozenMap | None
    scenario_truth_projection: FrozenMap | None
    release_operations_projection: FrozenMap | None
    assessment_digest: str
    object_digest: str
    _authority: object
    _performance_evidence: object
    _migration_rehearsal_evidence: object
    _dependency_graph_evidence: object
    _scenario_truth_evidence: object
    _release_operations_evidence: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CategoryCompletionAssessment is oracle-issued")

    def body(self) -> dict[str, object]:
        result = {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "snapshot_digest": self.snapshot_digest,
            "invalidation_epoch": self.invalidation_epoch,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "profile_digest": self.profile_digest,
            "overlay_id": self.overlay_id,
            "column_id": self.column_id,
            "scenario_id": self.scenario_id,
            "category_boundary_case_ids": list(self.category_boundary_case_ids),
            "status": self.status,
            "materialization_pins": thaw(self.materialization_pins),
            "runner_outputs": thaw(self.runner_outputs),
            "artifact_contract_ids": list(self.artifact_contract_ids),
            "authority_refs": list(self.authority_refs),
            "review_digest": self.review_digest,
            "target_observation_digest": self.target_observation_digest,
            "rollback_assessment_digest": self.rollback_assessment_digest,
            "state_digest": self.state_digest,
            "column_evidence_digest": self.column_evidence_digest,
        }
        if self.performance_evidence_projection is not None:
            result["performance_evidence_projection"] = thaw(
                self.performance_evidence_projection
            )
        if self.migration_rehearsal_projection is not None:
            result["migration_rehearsal_projection"] = thaw(
                self.migration_rehearsal_projection
            )
        if self.dependency_graph_projection is not None:
            result["dependency_graph_projection"] = thaw(
                self.dependency_graph_projection
            )
        if self.scenario_truth_projection is not None:
            result["scenario_truth_projection"] = thaw(
                self.scenario_truth_projection
            )
        if self.release_operations_projection is not None:
            result["release_operations_projection"] = thaw(
                self.release_operations_projection
            )
        return result

    def to_dict(self) -> dict[str, object]:
        result = self.body()
        result["assessment_digest"] = self.assessment_digest
        return result

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())


def category_object_digest(body: bytes) -> str:
    if type(body) is not bytes:
        raise CategoryExecutionError("category assessment object must be exact bytes")
    return "sha256:" + hashlib.sha256(body).hexdigest()


__all__ = (
    "CategoryCompletionAssessment",
    "CategoryExecutionError",
    "CategoryExecutionEvent",
    "CategoryExecutionPolicy",
    "CategoryExecutionReducer",
    "CategoryExecutionState",
    "CategoryRollbackAssessment",
    "CategoryTargetObservation",
    "category_object_digest",
)
