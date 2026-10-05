"""Consumer-local installed ADR-0008 scenario-truth authority."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import pathlib
import stat
import tomllib
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.schema import validate_instance
from graph_engineering.core.scenario_truth import (
    SCENARIO_TRUTH_SCHEMA_IDS,
    ScenarioTruthError,
    ScenarioTruthObservation,
    ScenarioTruthRegistry,
    evaluate_incident_gates,
    evaluate_refactor_gates,
    evaluate_scenario_assertions,
    issue_scenario_truth_observation,
    minimal_change_bytes,
    parse_scenario_truth_registries,
)


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ScenarioTruthError(f"{label} has a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScenarioTruthError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise ScenarioTruthError(f"{label} root is not an object")
    return value


def _raw(value: object, label: str) -> str:
    if (
        type(value) is not str or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ScenarioTruthError(f"{label} is not a raw SHA-256")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise ScenarioTruthError(f"{label} is not a semantic digest")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise ScenarioTruthError(f"{label} is not exact text")
    return value


def _rejection_input_projection(value: object) -> object:
    """Project configured malformed scalars into an exact, auditable value."""

    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) in (list, tuple):
        return [_rejection_input_projection(item) for item in value]
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ScenarioTruthError(
                "scenario rejected request has a non-text object key"
            )
        return {
            key: _rejection_input_projection(item)
            for key, item in value.items()
        }
    if type(value) is float:
        return {
            "rejected_type": "float",
            "exact_value": value.hex(),
        }
    raise ScenarioTruthError(
        "scenario rejected request contains an unprojectable value"
    )


def _semantic(document: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        freeze(document),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _self_digest(document: Mapping[str, object], name: str, field: str) -> str:
    expected = _digest(document.get(field), field)
    body = copy.deepcopy(dict(document))
    del body[field]
    if not hmac.compare_digest(expected, _semantic(body, name)):
        raise ScenarioTruthError(f"{name} self digest changed")
    return expected


_BOOTSTRAP_FIELDS = (
    "schema_version", "bootstrap_id", "policy_registry_id",
    "policy_registry_digest", "policy_registry_raw_sha256", "fixture_registry_id",
    "fixture_registry_digest", "fixture_registry_raw_sha256",
    "profile_schema_registry_digest", "profile_schema_registry_raw_sha256",
    "schema_vectors", "protected_resources", "protected_closure_digest",
    "bootstrap_digest",
)
_SCHEMA_VECTOR_FIELDS = ("schema_id", "raw_sha256")
_PROTECTED_FIELDS = ("path", "raw_sha256")
_BINDING_FIELDS = (
    "task_id", "task_revision", "snapshot_digest", "invalidation_epoch",
    "profile_id", "profile_version", "scenario_id", "graph_ref_pins",
    "branch_id", "ref_id",
)
_PIN_FIELDS = (
    "base_graph_digest", "profile_digest", "overlay_digest",
    "project_config_digest", "support_matrix_digest", "materialization_digest",
)
_REQUEST_FIELDS = (
    "branch_id", "ref_id", "targets", "ordered_phase_ids",
    "rollback_or_compensation",
)
_REQUEST_TARGET_FIELDS = (
    "role_id", "path_id", "expected_before_state_id", "expected_after_state_id",
    "expected_rollback_state_id", "apply",
)


def _validate_bootstrap(
    document: object,
    *,
    policy_bytes: bytes,
    fixture_bytes: bytes,
    schema_registry_bytes: bytes,
    schema_bodies: tuple[bytes, ...],
    protected_bodies: tuple[bytes, ...],
) -> FrozenMap:
    if type(document) is not dict or tuple(document) != _BOOTSTRAP_FIELDS:
        raise ScenarioTruthError("scenario bootstrap fields/order are not exact")
    if document["schema_version"] != "1.0.0":
        raise ScenarioTruthError("scenario bootstrap version changed")
    _text(document["bootstrap_id"], "scenario bootstrap ID")
    vectors = document["schema_vectors"]
    if type(vectors) is not list or len(vectors) != len(SCENARIO_TRUTH_SCHEMA_IDS):
        raise ScenarioTruthError("scenario schema vectors are incomplete")
    vector_ids: list[str] = []
    for row, body in zip(vectors, schema_bodies, strict=True):
        if type(row) is not dict or tuple(row) != _SCHEMA_VECTOR_FIELDS:
            raise ScenarioTruthError("scenario schema vector is not exact")
        vector_ids.append(_text(row["schema_id"], "scenario schema ID"))
        if not hmac.compare_digest(_raw(row["raw_sha256"], "schema raw digest"), hashlib.sha256(body).hexdigest()):
            raise ScenarioTruthError("scenario schema bytes changed")
        schema = _strict_json(body, "scenario schema")
        if schema.get("$id") != row["schema_id"]:
            raise ScenarioTruthError("scenario schema identity changed")
    if tuple(vector_ids) != SCENARIO_TRUTH_SCHEMA_IDS:
        raise ScenarioTruthError("scenario schema set/order changed")
    protected = document["protected_resources"]
    if type(protected) is not list or len(protected) != len(protected_bodies):
        raise ScenarioTruthError("scenario protected closure is incomplete")
    protected_projection: list[dict[str, object]] = []
    paths: list[str] = []
    for row, body in zip(protected, protected_bodies, strict=True):
        if type(row) is not dict or tuple(row) != _PROTECTED_FIELDS:
            raise ScenarioTruthError("scenario protected member is not exact")
        path = _text(row["path"], "scenario protected path")
        paths.append(path)
        raw = _raw(row["raw_sha256"], "protected raw digest")
        if not hmac.compare_digest(raw, hashlib.sha256(body).hexdigest()):
            raise ScenarioTruthError("scenario protected bytes changed")
        protected_projection.append({"path": path, "raw_sha256": raw})
    if tuple(paths) != tuple(sorted(set(paths))):
        raise ScenarioTruthError("scenario protected paths are not canonical")
    if not hmac.compare_digest(
        _digest(document["protected_closure_digest"], "protected closure digest"),
        _semantic({"protected_resources": protected_projection}, "scenario-truth-protected-closure"),
    ):
        raise ScenarioTruthError("scenario protected closure digest changed")
    policy = _strict_json(policy_bytes, "scenario policy")
    fixture = _strict_json(fixture_bytes, "scenario fixture")
    schema_registry = _strict_json(schema_registry_bytes, "Profile schema registry")
    pin_values = (
        ("policy_registry_id", policy.get("registry_id")),
        ("policy_registry_digest", policy.get("registry_digest")),
        ("policy_registry_raw_sha256", hashlib.sha256(policy_bytes).hexdigest()),
        ("fixture_registry_id", fixture.get("registry_id")),
        ("fixture_registry_digest", fixture.get("registry_digest")),
        ("fixture_registry_raw_sha256", hashlib.sha256(fixture_bytes).hexdigest()),
        ("profile_schema_registry_digest", schema_registry.get("registry_digest")),
        ("profile_schema_registry_raw_sha256", hashlib.sha256(schema_registry_bytes).hexdigest()),
    )
    for field, actual in pin_values:
        expected = document[field]
        if type(expected) is not str or not hmac.compare_digest(expected, str(actual)):
            raise ScenarioTruthError(f"scenario bootstrap {field} changed")
    _self_digest(document, "scenario-truth-installation-bootstrap", "bootstrap_digest")
    return freeze(document)


@dataclass(frozen=True, slots=True, eq=False)
class _RegistryAuthority:
    _factory: object
    registry: ScenarioTruthRegistry

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return self.registry.profile_ids

    @property
    def scenario_pairs(self) -> tuple[tuple[str, str], ...]:
        return self.registry.scenario_pairs

    @property
    def testability(self) -> FrozenMap:
        return self.registry.testability


@dataclass(frozen=True, slots=True, eq=False)
class _RestoredScenarioEvidence:
    _factory: object
    projection: FrozenMap
    root_identity: tuple[int, int, int]


@dataclass(frozen=True, slots=True, eq=False, init=False)
class ScenarioTruthRejectionReceipt:
    """Opaque receipt of one actual, registry-observed zero-write rejection."""

    attack_id: str
    root_path: str
    mutation_count: int
    request_unchanged: bool
    target_bytes_unchanged: bool
    projection: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("scenario rejection receipts are registry-issued")


@dataclass(frozen=True, slots=True, eq=False, init=False)
class ScenarioTruthRejectionEvidence:
    """Process-local identity for a complete installed rejection closure."""

    receipts: tuple[ScenarioTruthRejectionReceipt, ...]
    projection: FrozenMap
    evidence_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("scenario rejection evidence is registry-issued")


def _identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_uid


@contextmanager
def _private_target(root: pathlib.Path, path_id: str, *, write: bool = False,
                    root_identity: tuple[int, int, int] | None = None):
    """Walk below the private root using no-follow descriptors, never resolve links."""
    relative = pathlib.PurePosixPath(path_id)
    if (not path_id or relative.is_absolute() or "\\" in path_id
            or any(part in {"", ".", ".."} for part in path_id.split("/"))):
        raise ScenarioTruthError("scenario target path is unsafe")
    descriptors: list[int] = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory = os.open(root, directory_flags)
        descriptors.append(directory)
        metadata = os.fstat(directory)
        if (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077
                or (root_identity is not None and _identity(metadata) != root_identity)):
            raise ScenarioTruthError("scenario private root identity changed")
        for part in relative.parts[:-1]:
            directory = os.open(part, directory_flags, dir_fd=directory)
            descriptors.append(directory)
            if os.fstat(directory).st_uid != os.getuid():
                raise ScenarioTruthError("scenario target directory is foreign")
        descriptor = os.open(relative.name, (os.O_RDWR if write else os.O_RDONLY)
                             | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1):
            raise ScenarioTruthError("scenario target is not a private regular file")
        yield descriptor
    except OSError as error:
        raise ScenarioTruthError("scenario target path is stale or unsafe") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_private_target(root: pathlib.Path, path_id: str, *, root_identity=None) -> bytes:
    with _private_target(root, path_id, root_identity=root_identity) as descriptor:
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            return stream.read()


class ScenarioBaselineReceipt:
    """An identity-only, observer-owned pre-mutation capability."""

    __slots__ = ()

    def __init__(self):
        raise TypeError("scenario baseline is observer-issued")

    def __reduce_ex__(self, protocol):
        raise TypeError("scenario baseline authority is not serializable")


def _control_observations(fixture, root, root_identity):
    rows = []
    for control in fixture["execution_contract"]["controls"]:
        body = _read_private_target(root, control["path_id"], root_identity=root_identity)
        if body != control["expected_value"].encode("ascii"):
            raise ScenarioTruthError("scenario control is stale or unauthorized")
        rows.append({"control_id": control["control_id"], "kind": control["kind"],
                     "path_id": control["path_id"],
                     "value_digest": "sha256:" + hashlib.sha256(body).hexdigest()})
    return rows


def _baseline_projection(binding, fixture, pins, root, root_identity):
    task_id = _text(binding["task_id"], "guarded task ID")
    if (binding["branch_id"] != "branch:" + task_id
            or binding["ref_id"] != "ref:" + task_id
            or _read_private_target(root, ".scenario-truth-root", root_identity=root_identity)
            != task_id.encode("ascii")):
        raise ScenarioTruthError("scenario guarded private root binding changed")
    contract = fixture["execution_contract"]
    targets = fixture["target_roles"]
    if (fixture["rollback_or_compensation"]["required"] is not True
            or any(row["rollback_value"] != row["baseline_value"]
                   or row["rollback_state_id"] != row["baseline_state_id"] for row in targets)):
        raise ScenarioTruthError("scenario rollback readiness is incomplete")
    change = sum(minimal_change_bytes(row["baseline_value"].encode("ascii"),
                                     row["candidate_value"].encode("ascii")) for row in targets)
    if change > contract["minimal_change_budget"]:
        raise ScenarioTruthError("scenario minimal change budget exceeded")
    return {
        "binding": thaw(binding), "installation_pins": thaw(pins),
        "root_path": os.fspath(root), "root_identity": list(root_identity),
        "contract": thaw(contract),
        "baseline_targets": [ScenarioTruthObservationFactory._target_observation(
            row, row["baseline_value"].encode("ascii"), row["baseline_state_id"])
            for row in targets],
        "control_observations": _control_observations(fixture, root, root_identity),
        "pre_mutation_sequence": 0, "change_bytes": change,
    }


def _guarded_proof(binding, fixture, pins, root, root_identity):
    """Recompute deterministic relationships and freshly read gate predicates."""
    baseline = _baseline_projection(binding, fixture, pins, root, root_identity)
    contract = fixture["execution_contract"]
    targets = {row["role_id"]: row for row in fixture["target_roles"]}
    phases = [{"phase_id": "baseline-captured", "sequence": 0, "mutation_count": 0},
              {"phase_id": "candidate-observed", "sequence": 1, "mutation_count": len(targets)}]
    results = []
    for gate in contract["ordered_gates"]:
        if gate["kind"] == "impact":
            for row in targets.values():
                if _read_private_target(root, row["path_id"], root_identity=root_identity) != row["candidate_value"].encode("ascii"):
                    raise ScenarioTruthError("scenario impact gate target is stale")
        elif gate["kind"] == "health":
            for predicate in contract["health_predicates"]:
                row = targets[predicate["target_role"]]
                body = _read_private_target(root, row["path_id"], root_identity=root_identity)
                actual = _strict_json(body, "scenario candidate health")
                for field in predicate["field_path"]:
                    if type(actual) is not dict or field not in actual:
                        raise ScenarioTruthError("scenario health field is missing")
                    actual = actual[field]
                if type(actual) is not type(predicate["expected"]) or actual != predicate["expected"]:
                    raise ScenarioTruthError("scenario health predicate failed")
        elif gate["kind"] == "rollback":
            # Baseline projection above verified installed rollback A readiness.
            _control_observations(fixture, root, root_identity)
        else:
            raise ScenarioTruthError("scenario gate kind is unsupported")
        results.append({"gate_id": gate["gate_id"], "kind": gate["kind"], "passed": True})
        phases.append({"phase_id": gate["gate_id"], "sequence": len(phases),
                       "mutation_count": len(targets)})
    if _control_observations(fixture, root, root_identity) != baseline["control_observations"]:
        raise ScenarioTruthError("scenario controls changed during gate")
    for row in targets.values():
        if _read_private_target(root, row["path_id"], root_identity=root_identity) != row["candidate_value"].encode("ascii"):
            raise ScenarioTruthError("scenario target changed during gate")
    return {"baseline": baseline, "ordered_phases": phases, "gate_results": results}


def _refactor_proof(binding, fixture, pins, root, root_identity):
    """Freshly observe one config-owned refactor target and ordered gates."""

    task_id = _text(binding["task_id"], "refactor task ID")
    if (
        binding["branch_id"] != "branch:" + task_id
        or binding["ref_id"] != "ref:" + task_id
        or _read_private_target(
            root, ".scenario-truth-root", root_identity=root_identity,
        ) != task_id.encode("ascii")
    ):
        raise ScenarioTruthError("scenario refactor private root binding changed")
    targets = fixture["target_roles"]
    if len(targets) != 1:
        raise ScenarioTruthError("scenario refactor target closure changed")
    target = targets[0]
    baseline_bytes = target["baseline_value"].encode("ascii")
    candidate_bytes = _read_private_target(
        root, target["path_id"], root_identity=root_identity,
    )
    if candidate_bytes != target["candidate_value"].encode("ascii"):
        raise ScenarioTruthError("scenario refactor candidate is stale")
    before = _strict_json(baseline_bytes, "scenario refactor baseline")
    after = _strict_json(candidate_bytes, "scenario refactor candidate")
    contract = fixture["refactor_contract"]
    results = evaluate_refactor_gates(contract, before, after)
    if _read_private_target(
        root, target["path_id"], root_identity=root_identity,
    ) != candidate_bytes:
        raise ScenarioTruthError("scenario refactor candidate changed during gate")

    def proof_observation(document: dict[str, object], body: bytes) -> dict[str, object]:
        value = copy.deepcopy(document)
        value["value_digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
        return value

    metric = None
    if contract["nonfunctional_target"] is not None:
        target_metric = contract["nonfunctional_target"]
        observed = next(
            row for row in after["metric_observations"]
            if row["metric_id"] == target_metric["metric_id"]
        )
        metric = {
            "environment_id": target_metric["environment_id"],
            "metric_id": target_metric["metric_id"],
            "comparator": target_metric["comparator"],
            "threshold": target_metric["threshold"],
            "observed_value": observed["value"],
            "passed": True,
        }
    return {
        "binding": thaw(binding),
        "installation_pins": thaw(pins),
        "root_path": os.fspath(root),
        "root_identity": list(root_identity),
        "contract": thaw(contract),
        "before": proof_observation(before, baseline_bytes),
        "after": proof_observation(after, candidate_bytes),
        "gate_results": list(results),
        "metric_comparison": metric,
        "fresh_candidate_digest": "sha256:" + hashlib.sha256(candidate_bytes).hexdigest(),
    }


def _incident_proof(
    binding, fixture, pins, root, root_identity, mutation_count,
):
    """Freshly observe one config-owned incident closure and ordered gates."""

    task_id = _text(binding["task_id"], "incident task ID")
    if (
        binding["branch_id"] != "branch:" + task_id
        or binding["ref_id"] != "ref:" + task_id
        or _read_private_target(
            root, ".scenario-truth-root", root_identity=root_identity,
        ) != task_id.encode("ascii")
    ):
        raise ScenarioTruthError("scenario incident private root binding changed")
    targets = fixture["target_roles"]
    if len(targets) != 1:
        raise ScenarioTruthError("scenario incident target closure changed")
    target = targets[0]
    baseline_bytes = target["baseline_value"].encode("ascii")
    candidate_bytes = _read_private_target(
        root, target["path_id"], root_identity=root_identity,
    )
    if candidate_bytes != target["candidate_value"].encode("ascii"):
        raise ScenarioTruthError("scenario incident candidate is stale")
    before = _strict_json(baseline_bytes, "scenario incident baseline")
    after = _strict_json(candidate_bytes, "scenario incident candidate")
    contract = fixture["incident_contract"]
    results = evaluate_incident_gates(contract, before, after)
    blocked = tuple(contract["gate_ids"]) == ("owner-route",)
    if (blocked and mutation_count != 0) or (not blocked and mutation_count != 1):
        raise ScenarioTruthError("scenario incident mutation accounting changed")
    if _read_private_target(
        root, target["path_id"], root_identity=root_identity,
    ) != candidate_bytes:
        raise ScenarioTruthError("scenario incident candidate changed during gate")
    return {
        "binding": thaw(binding),
        "installation_pins": thaw(pins),
        "root_path": os.fspath(root),
        "root_identity": list(root_identity),
        "contract": thaw(contract),
        "observation": copy.deepcopy(after),
        "gate_results": list(results),
        "action_ids": copy.deepcopy(after["action_ids"]),
        "mutation_count": mutation_count,
        "unknown_claim_retained": after["unknown_claim_retained"],
        "service_restored": after["service_restored"],
        "owner_route": after["owner_route"],
        "inner_outcome": after["inner_outcome"],
        "fresh_candidate_digest": "sha256:" + hashlib.sha256(candidate_bytes).hexdigest(),
    }


class ScenarioTruthObservationFactory:
    """One opaque task/profile/scenario observer over a private local root."""

    __slots__ = (
        "_owner", "_binding", "_policy_row", "_fixture_row", "_root",
        "_mutation_count", "_executed", "_request", "_root_identity",
        "_baseline_receipts",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ScenarioTruthObservationFactory is registry-issued")

    def request(self) -> dict[str, object]:
        return copy.deepcopy(self._request)

    @property
    def mutation_count(self) -> int:
        return self._mutation_count

    def target_bytes(self) -> tuple[tuple[str, bytes], ...]:
        result: list[tuple[str, bytes]] = []
        for target in self._fixture_row["target_roles"]:
            result.append((target["role_id"], self._read_target(target["path_id"])))
        return tuple(result)

    def _read_target(self, path_id: str) -> bytes:
        return _read_private_target(self._root, path_id, root_identity=self._root_identity)

    def capture_baseline(self) -> ScenarioBaselineReceipt:
        self._owner.require_observer(self)
        if ("execution_contract" not in self._fixture_row
                or self._executed or self._mutation_count):
            raise ScenarioTruthError("scenario baseline is absent or late")
        for row in self._fixture_row["target_roles"]:
            if self._read_target(row["path_id"]) != row["baseline_value"].encode("ascii"):
                raise ScenarioTruthError("scenario baseline is not current A")
        projection = freeze(_baseline_projection(self._binding, self._fixture_row,
            self._owner.installation_pins, self._root, self._root_identity))
        receipt = object.__new__(ScenarioBaselineReceipt)
        self._baseline_receipts[id(receipt)] = (receipt, projection)
        return receipt

    def _require_baseline(self, receipt):
        issued = self._baseline_receipts.get(id(receipt))
        if (type(receipt) is not ScenarioBaselineReceipt or issued is None
                or issued[0] is not receipt or self._executed or self._mutation_count):
            raise ScenarioTruthError("scenario baseline is missing, cloned, foreign, or late")
        projection = freeze(_baseline_projection(self._binding, self._fixture_row,
            self._owner.installation_pins, self._root, self._root_identity))
        if projection != issued[1]:
            raise ScenarioTruthError("scenario baseline binding or controls changed")
        return issued[1]

    def reject(self, attack_id: str, request: object, *, baseline_receipt: object = None) -> ScenarioTruthRejectionReceipt:
        self._owner.require_observer(self)
        if self._executed or self._mutation_count:
            raise ScenarioTruthError("scenario rejection observer is one-shot")
        if attack_id not in self._fixture_row.get("rejection_attack_ids", ()):
            raise ScenarioTruthError("scenario rejection attack is not installed")
        root_marker_digest = self._guarded_root_marker_digest()
        before_request = copy.deepcopy(request)
        before_targets = self.target_bytes()
        before_controls = self._control_bytes()
        if ("execution_contract" in self._fixture_row
                and attack_id not in ("missing-baseline", "foreign-baseline")):
            issued_baseline = self._baseline_receipts.get(id(baseline_receipt))
            if issued_baseline is None or issued_baseline[0] is not baseline_receipt:
                raise ScenarioTruthError("scenario rejection prerequisite baseline is missing")
        if not self._matches_rejection(attack_id, request, before_targets, baseline_receipt):
            raise ScenarioTruthError("scenario rejection attack label is false")
        try:
            self.execute(request, baseline_receipt=baseline_receipt)
        except ScenarioTruthError as error:
            error_message = str(error)
        else:
            raise ScenarioTruthError("scenario rejection unexpectedly succeeded")
        if (request != before_request or self.target_bytes() != before_targets
                or self._control_bytes() != before_controls
                or self._guarded_root_marker_digest() != root_marker_digest
                or self._mutation_count != 0 or self._executed):
            raise ScenarioTruthError("scenario rejection changed state or input")
        self._executed = True
        raw_projection = {
            "attack_id": attack_id, "binding": thaw(self._binding),
            "root_path": os.fspath(self._root),
            "root_identity": list(self._root_identity),
            "request": _rejection_input_projection(before_request),
            "error_message": error_message,
            "targets": [{"role_id": role, "sha256": hashlib.sha256(body).hexdigest()}
                        for role, body in before_targets],
            "mutation_count": 0, "request_unchanged": True,
            "target_bytes_unchanged": True,
        }
        if (
            "execution_contract" in self._fixture_row
            or "refactor_contract" in self._fixture_row
            or "incident_contract" in self._fixture_row
        ):
            raw_projection["root_marker_digest"] = root_marker_digest
        if "execution_contract" in self._fixture_row:
            baseline = self._baseline_receipts.get(id(baseline_receipt))
            raw_projection["baseline_argument"] = (thaw(baseline[1]) if baseline else None)
            raw_projection["controls"] = [{"control_id": key, "sha256": hashlib.sha256(body).hexdigest()}
                                           for key, body in before_controls]
        projection = freeze(raw_projection)
        receipt = object.__new__(ScenarioTruthRejectionReceipt)
        for name in ("attack_id", "root_path", "mutation_count", "request_unchanged",
                     "target_bytes_unchanged"):
            object.__setattr__(receipt, name, projection[name])
        object.__setattr__(receipt, "projection", projection)
        self._owner._issued_rejections[id(receipt)] = (
            receipt, self, projection, before_targets,
        )
        return receipt

    def _guarded_root_marker_digest(self):
        if (
            "execution_contract" not in self._fixture_row
            and "refactor_contract" not in self._fixture_row
            and "incident_contract" not in self._fixture_row
        ):
            return None
        task_id = self._binding["task_id"]
        marker = self._read_target(".scenario-truth-root")
        if (marker != task_id.encode("ascii")
                or self._binding["branch_id"] != "branch:" + task_id
                or self._binding["ref_id"] != "ref:" + task_id):
            raise ScenarioTruthError("scenario rejection root marker binding changed")
        return "sha256:" + hashlib.sha256(marker).hexdigest()

    def _control_bytes(self):
        contract = self._fixture_row.get("execution_contract")
        return tuple((row["control_id"], self._read_target(row["path_id"]))
                     for row in contract["controls"]) if contract else ()

    def _matches_rejection(self, attack_id: str, request: object, targets: object, baseline_receipt=None) -> bool:
        """Recognize universal structural failure classes, not caller labels."""
        if type(request) is not dict or type(request.get("targets")) is not list:
            return False
        rows = request["targets"]
        if any(type(row) is not dict for row in rows):
            return False
        expected = self._request["targets"]
        roles = [row.get("role_id") for row in rows]
        if "execution_contract" in self._fixture_row:
            if attack_id == "missing-baseline":
                return request == self._request and baseline_receipt is None
            if attack_id == "foreign-baseline":
                return (request == self._request and type(baseline_receipt) is ScenarioBaselineReceipt
                        and id(baseline_receipt) not in self._baseline_receipts)
            if attack_id == "stale-control":
                return (request == self._request and self._control_bytes() != tuple(
                    (row["control_id"], row["expected_value"].encode("ascii"))
                    for row in self._fixture_row["execution_contract"]["controls"]))
            if attack_id == "wrong-environment":
                return request.get("environment") != self._request["environment"]
            if attack_id == "gate-omission":
                return (type(request.get("ordered_gate_ids")) is list
                        and len(request["ordered_gate_ids"]) < len(self._request["ordered_gate_ids"]))
            if attack_id == "gate-reorder":
                return (type(request.get("ordered_gate_ids")) is list
                        and request["ordered_gate_ids"] != self._request["ordered_gate_ids"]
                        and sorted(request["ordered_gate_ids"]) == sorted(self._request["ordered_gate_ids"]))
        if "refactor_contract" in self._fixture_row:
            actual = request.get("refactor_contract")
            expected_contract = self._request["refactor_contract"]
            if type(actual) is not dict:
                return False
            actual_cases = actual.get("behavior_cases")
            expected_cases = expected_contract["behavior_cases"]
            if attack_id == "behavior-case-omission":
                return type(actual_cases) is list and len(actual_cases) < len(expected_cases)
            if attack_id == "behavior-case-addition":
                return type(actual_cases) is list and len(actual_cases) > len(expected_cases)
            if attack_id == "behavior-case-reorder":
                return (
                    type(actual_cases) is list
                    and actual_cases != expected_cases
                    and sorted(actual_cases, key=lambda item: item.get("case_id", ""))
                    == sorted(expected_cases, key=lambda item: item.get("case_id", ""))
                )
            if attack_id == "behavior-delta":
                return type(actual_cases) is list and actual_cases != expected_cases
            if attack_id == "expected-vector-alias":
                return (
                    type(actual_cases) is list and len(actual_cases) > 1
                    and actual_cases[0] == actual_cases[1]
                )
            if attack_id == "caller-behavior-equivalent":
                return request.get("behavior_equivalent") is True
            if attack_id == "architecture-missing-edge":
                return len(actual.get("required_edges", ())) < len(
                    expected_contract["required_edges"]
                )
            if attack_id == "architecture-forbidden-edge":
                return actual.get("required_edges") == expected_contract["forbidden_edges"]
            if attack_id == "architecture-path-alias":
                edges = actual.get("required_edges", ())
                return bool(edges) and edges[0].get("from_path_id") == edges[0].get("to_path_id")
            if attack_id == "architecture-count-only":
                return request.get("architecture_edge_count") is not None
            if attack_id == "architecture-set-only":
                return request.get("architecture_nodes") is not None
            if attack_id == "behavior-gate-skip":
                return actual.get("gate_ids", [None])[0] != "behavior-equivalence"
            target = actual.get("nonfunctional_target")
            expected_target = expected_contract["nonfunctional_target"]
            if attack_id == "environment-drift":
                return actual.get("environment_id") != expected_contract["environment_id"]
            if attack_id == "hardcoded-threshold":
                return isinstance(target, dict) and target.get("threshold") != expected_target["threshold"]
            if attack_id == "threshold-float":
                return isinstance(target, dict) and type(target.get("threshold")) is float
            if attack_id == "threshold-bool":
                return isinstance(target, dict) and type(target.get("threshold")) is bool
            if attack_id == "metric-miss":
                return isinstance(target, dict) and target.get("metric_id") != expected_target["metric_id"]
            if attack_id == "caller-metric-pass":
                return request.get("metric_passed") is True
        if "incident_contract" in self._fixture_row:
            actual = request.get("incident_contract")
            expected_contract = self._request["incident_contract"]
            if type(actual) is not dict:
                return False
            if attack_id == "signal-missing":
                return actual.get("signal") is None
            if attack_id == "signal-stale":
                signal = actual.get("signal")
                return isinstance(signal, dict) and (
                    signal.get("current_epoch", 0) - signal.get("observed_epoch", 0)
                    > signal.get("max_age_epochs", 0)
                )
            if attack_id == "signal-substitution":
                signal = actual.get("signal")
                expected_signal = expected_contract["signal"]
                return (
                    isinstance(signal, dict)
                    and signal.get("signal_id") != expected_signal["signal_id"]
                )
            if attack_id == "caller-detection-claim":
                return request.get("detection_passed") is True
            if attack_id == "impact-scope-substitution":
                return actual.get("impact_roles") != expected_contract["impact_roles"]
            if attack_id == "severity-substitution":
                return actual.get("severity") != expected_contract["severity"]
            if attack_id == "affected-scope-substitution":
                return (
                    type(actual.get("affected_roles")) is list
                    and len(actual["affected_roles"])
                    < len(expected_contract["affected_roles"])
                )
            if attack_id == "over-containment":
                return (
                    type(actual.get("affected_roles")) is list
                    and len(actual["affected_roles"])
                    > len(expected_contract["affected_roles"])
                )
            if attack_id == "unaffected-mutation":
                return (
                    actual.get("unaffected_observations")
                    != expected_contract["unaffected_observations"]
                )
            if attack_id == "authority-omission":
                return actual.get("authority_id") is None
            if attack_id == "authority-substitution":
                return (
                    actual.get("authority_id") is not None
                    and actual.get("authority_id") != expected_contract["authority_id"]
                )
            if attack_id == "fence-omission":
                return actual.get("fence_id") is None
            if attack_id == "fence-substitution":
                return (
                    actual.get("fence_id") is not None
                    and actual.get("fence_id") != expected_contract["fence_id"]
                )
            if attack_id == "residual-state-substitution":
                return (
                    actual.get("residual_state_id")
                    != expected_contract["residual_state_id"]
                )
            if attack_id == "caller-scope-claim":
                return request.get("scope_contained") is True
            if attack_id == "original-action-replay":
                return actual.get("original_action_id") in actual.get("action_ids", ())
            if attack_id == "service-verification-omission":
                return len(actual.get("service_predicates", ())) < len(
                    expected_contract["service_predicates"]
                )
            if attack_id == "service-verification-stale":
                predicates = actual.get("service_predicates")
                return type(predicates) is list and any(
                    isinstance(predicate, dict)
                    and predicate.get("current_epoch", 0)
                    - predicate.get("observed_epoch", 0)
                    > predicate.get("max_age_epochs", 0)
                    for predicate in predicates
                )
            if attack_id == "follow-up-omission":
                return actual.get("follow_up_id") is None
            if attack_id == "unknown-recovery-input":
                return actual.get("effect_classification") == "unknown"
            if attack_id == "uncontained-recovery-input":
                return actual.get("contained_input") is None
            if attack_id == "service-restored-claim":
                return request.get("service_restored") is True
            if attack_id == "unknown-claim-consumed":
                return actual.get("unknown_claim_id") is None
            if attack_id == "owner-route-empty":
                return actual.get("owner_route") == ""
            if attack_id == "owner-route-substitution":
                return actual.get("owner_route") != expected_contract["owner_route"]
            if attack_id == "forbidden-unknown-action":
                return bool(actual.get("action_ids"))
            if attack_id == "unknown-recovery-attempt":
                return (
                    actual.get("compensation_id") is not None
                    and bool(actual.get("action_ids"))
                )
        if attack_id == "missing-role":
            return len(rows) == len(expected) and any("role_id" not in row for row in rows)
        if attack_id == "extra-role":
            return len(rows) > len(expected) and len(set(roles)) == len(rows)
        if attack_id == "aliased-role":
            return len(rows) == len(expected) and len(set(roles)) < len(rows)
        if attack_id == "one-target-only":
            return len(rows) == 1 and len(expected) > 1
        if attack_id == "cross-branch":
            return request.get("branch_id") != self._request["branch_id"]
        if attack_id == "partial-success":
            return len(rows) == len(expected) and any(row.get("apply") is False for row in rows)
        if attack_id == "stale-target":
            baseline = tuple((row["role_id"], row["baseline_value"].encode("ascii"))
                             for row in self._fixture_row["target_roles"])
            return request == self._request and targets != baseline
        if attack_id == "wrong-rollback":
            return request.get("rollback_or_compensation") != self._request["rollback_or_compensation"]
        return False

    def _validate_request(self, request: object) -> Mapping[str, object]:
        fields = _REQUEST_FIELDS
        if "execution_contract" in self._fixture_row:
            fields = (*fields, "environment", "ordered_gate_ids")
        if "refactor_contract" in self._fixture_row:
            fields = (*fields, "refactor_contract")
        if "incident_contract" in self._fixture_row:
            fields = (*fields, "incident_contract")
        if type(request) is not dict or tuple(request) != fields:
            raise ScenarioTruthError("scenario request fields/order are not exact")
        try:
            frozen_request = freeze(request)
        except TypeError as error:
            raise ScenarioTruthError(
                "scenario request is not exact JSON"
            ) from error
        if frozen_request != freeze(self._request):
            raise ScenarioTruthError("scenario request differs from installed policy")
        targets = request["targets"]
        if type(targets) is not list:
            raise ScenarioTruthError("scenario target request is not exact")
        paths: list[str] = []
        roles: list[str] = []
        for value in targets:
            if type(value) is not dict or tuple(value) != _REQUEST_TARGET_FIELDS:
                raise ScenarioTruthError("scenario target request row is not exact")
            roles.append(_text(value["role_id"], "scenario target request role"))
            paths.append(_text(value["path_id"], "scenario target request path"))
            if type(value["apply"]) is not bool or not value["apply"]:
                raise ScenarioTruthError("scenario target transition is partial")
        if len(roles) != len(set(roles)) or len(paths) != len(set(paths)):
            raise ScenarioTruthError("scenario target request aliases a role or path")
        return request

    def execute(self, request: object, *, baseline_receipt: object = None) -> ScenarioTruthObservation:
        value = self._validate_request(request)
        self._owner.require_observer(self)
        if self._executed or self._mutation_count:
            raise ScenarioTruthError("scenario observer is one-shot")
        guarded = "execution_contract" in self._fixture_row
        refactor = "refactor_contract" in self._fixture_row
        incident = "incident_contract" in self._fixture_row
        incident_contract = self._fixture_row.get("incident_contract")
        incident_blocked = (
            incident and tuple(incident_contract["gate_ids"]) == ("owner-route",)
        )
        if incident and (
            incident_contract["owner_route"] != self._policy_row["owner_route_policy"]
            or (
                incident_blocked
                and incident_contract["expected_outcome"]
                != self._policy_row["blocked_outcome"]
            )
            or (
                not incident_blocked
                and incident_contract["expected_outcome"]
                != self._policy_row["success_outcome"]
            )
        ):
            raise ScenarioTruthError("scenario incident policy binding changed")
        baseline = self._require_baseline(baseline_receipt) if guarded else None
        if not guarded and baseline_receipt is not None:
            raise ScenarioTruthError("unguarded scenario cannot consume a baseline authority")
        before: list[dict[str, object]] = []
        transitions: list[dict[str, object]] = []
        after: list[dict[str, object]] = []
        fixture_targets = self._fixture_row["target_roles"]
        # All validation and all reads precede the first scenario mutation.
        current_bodies: list[bytes] = []
        for target in fixture_targets:
            body = self._read_target(target["path_id"])
            expected = target["baseline_value"].encode("ascii")
            if body != expected:
                raise ScenarioTruthError("scenario target baseline is stale")
            current_bodies.append(body)
            before.append(self._target_observation(target, body, target["baseline_state_id"]))
        for target, old_body in zip(fixture_targets, current_bodies, strict=True):
            new_body = target["candidate_value"].encode("ascii")
            if incident_blocked:
                if new_body != old_body:
                    raise ScenarioTruthError("blocked incident attempts a target mutation")
            else:
                with _private_target(self._root, target["path_id"], write=True,
                                     root_identity=self._root_identity) as descriptor:
                    with os.fdopen(os.dup(descriptor), "r+b") as stream:
                        if stream.read() != old_body:
                            raise ScenarioTruthError("scenario target changed before mutation")
                        stream.seek(0)
                        # Count a started write even if an I/O fault leaves a partial
                        # patch. Such an observer can never issue zero-write R proof.
                        self._mutation_count += 1
                        stream.write(new_body)
                        stream.truncate()
                transitions.append({
                    "phase_id": self._fixture_row["phase_expectations"][0]["phase_id"],
                    "role_id": target["role_id"],
                    "before_digest": "sha256:" + hashlib.sha256(old_body).hexdigest(),
                    "after_digest": "sha256:" + hashlib.sha256(new_body).hexdigest(),
                })
            observed = self._read_target(target["path_id"])
            if observed != new_body:
                raise ScenarioTruthError("scenario target did not reach candidate state")
            after.append(self._target_observation(target, observed, target["candidate_state_id"]))
        fact_values: dict[str, bool] = {}
        target_by_role = {
            str(target["role_id"]): (target, old_body, observed_row)
            for target, old_body, observed_row in zip(
                fixture_targets, current_bodies, after, strict=True,
            )
        }
        for expectation in self._fixture_row["assertion_expectations"]:
            assertion_id = str(expectation["assertion_id"])
            kind = str(expectation["kind"])
            matches = tuple(
                role_id for role_id in target_by_role
                if assertion_id == kind + ":" + role_id
            )
            if len(matches) != 1:
                raise ScenarioTruthError("scenario assertion role binding changed")
            target, old_body, observed_row = target_by_role[matches[0]]
            candidate_body = str(target["candidate_value"]).encode("ascii")
            baseline_body = str(target["baseline_value"]).encode("ascii")
            if kind == "acceptance":
                actual = (
                    observed_row["state_id"] == target["candidate_state_id"]
                    and self._read_target(str(target["path_id"]))
                    == candidate_body
                )
            elif kind == "fresh-target":
                actual = old_body == baseline_body and baseline_body != candidate_body
            elif kind == "regression":
                actual = (
                    old_body != candidate_body
                    and observed_row["state_id"] == target["candidate_state_id"]
                    and self._read_target(str(target["path_id"]))
                    == candidate_body
                )
            elif kind in {"blocked", "claim-retained", "no-action"}:
                if not incident_blocked:
                    raise ScenarioTruthError("blocked assertion lacks an incident block")
                incident_value = _strict_json(
                    self._read_target(str(target["path_id"])),
                    "scenario blocked incident",
                )
                if kind == "blocked":
                    actual = (
                        self._mutation_count == 0 and not transitions
                        and incident_value["inner_outcome"]
                        == incident_contract["expected_outcome"]
                    )
                elif kind == "claim-retained":
                    actual = (
                        incident_value["unknown_claim_id"]
                        == incident_contract["unknown_claim_id"]
                        and incident_value["unknown_claim_retained"] is True
                    )
                else:
                    actual = (
                        not incident_value["action_ids"]
                        and incident_value["service_restored"] is False
                    )
            else:
                raise ScenarioTruthError("scenario assertion kind is unsupported")
            fact_values["fact:" + assertion_id] = actual
        assertion_results = list(evaluate_scenario_assertions(
            self._fixture_row["assertion_expectations"], fact_values,
        ))
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "evidence_kind": "scenario-truth-observation-v1",
            "task_id": self._binding["task_id"],
            "task_revision": self._binding["task_revision"],
            "snapshot_digest": self._binding["snapshot_digest"],
            "invalidation_epoch": self._binding["invalidation_epoch"],
            "profile_id": self._binding["profile_id"],
            "profile_version": self._binding["profile_version"],
            "scenario_id": self._binding["scenario_id"],
            "graph_ref_pins": thaw(self._binding["graph_ref_pins"]),
            "installation_pins": thaw(self._owner.installation_pins),
            "policy_row": thaw(self._policy_row),
            "fixture_row": thaw(self._fixture_row),
            "branch_binding": {
                "branch_id": self._binding["branch_id"],
                "ref_id": self._binding["ref_id"],
                "root_path": os.fspath(self._root),
            },
            "before_targets": before,
            "ordered_transitions": transitions,
            "after_targets": after,
            "assertion_results": assertion_results,
            "rollback_or_compensation": copy.deepcopy(value["rollback_or_compensation"]),
            "owner_route": self._policy_row["owner_route_policy"],
            "scenario_outcome": (
                incident_contract["expected_outcome"]
                if incident else self._policy_row["success_outcome"]
            ),
        }
        if guarded:
            proof = _guarded_proof(self._binding, self._fixture_row,
                self._owner.installation_pins, self._root, self._root_identity)
            if freeze(proof["baseline"]) != baseline:
                raise ScenarioTruthError("scenario baseline changed during execution")
            body["execution_proof"] = proof
        if refactor:
            body["refactor_proof"] = _refactor_proof(
                self._binding, self._fixture_row,
                self._owner.installation_pins, self._root, self._root_identity,
            )
        if incident:
            body["incident_proof"] = _incident_proof(
                self._binding, self._fixture_row, self._owner.installation_pins,
                self._root, self._root_identity, self._mutation_count,
            )
        observation = issue_scenario_truth_observation(body, authority=self)
        self._executed = True
        self._owner.register_observation(self, observation)
        return observation

    def _safe_target_path(self, path_id: str) -> pathlib.Path:
        with _private_target(self._root, path_id, root_identity=self._root_identity):
            return self._root / path_id

    @staticmethod
    def _target_observation(target: Mapping[str, object], body: bytes, state_id: str) -> dict[str, object]:
        return {
            "role_id": target["role_id"],
            "path_id": target["path_id"],
            "state_id": state_id,
            "value_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        }


class ScenarioTruthRegistryFactory:
    """Unique current installation issuer for scenario registries and observers."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("use ScenarioTruthRegistryFactory.from_installation()")

    @classmethod
    def from_installation(cls) -> ScenarioTruthRegistryFactory:
        from graph_engineering import (
            DistributionIdentityError,
            _scenario_truth_installation_resources,
        )

        try:
            resources = _scenario_truth_installation_resources()
            provenance_bytes, policy_bytes, fixture_bytes, bootstrap_bytes, schema_registry_bytes = resources[:5]
            schema_bodies = tuple(resources[5:5 + len(SCENARIO_TRUTH_SCHEMA_IDS)])
            bootstrap_document = _strict_json(bootstrap_bytes, "scenario bootstrap")
            protected_count = len(bootstrap_document.get("protected_resources", ()))
            protected_bodies = tuple(resources[5 + len(SCENARIO_TRUTH_SCHEMA_IDS):])
            if len(protected_bodies) != protected_count:
                raise ScenarioTruthError("scenario installation resource closure is incomplete")
            provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
            pin = provenance["tool"]["gew"]["profile"]["scenario-truth"]
        except (DistributionIdentityError, KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ScenarioTruthError("scenario installation bootstrap is unavailable") from error
        expected_pin_fields = {
            "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
            "bootstrap-resource", "policy-source", "policy-resource", "fixture-source",
            "fixture-resource", "profile-schema-registry-source",
            "profile-schema-registry-resource", "schema-sources", "schema-resources",
            "protected-sources", "protected-resources", "distribution-name",
            "distribution-version",
        }
        if type(pin) is not dict or set(pin) != expected_pin_fields:
            raise ScenarioTruthError("scenario independent installation pin is not exact")
        if not hmac.compare_digest(
            _raw(pin["bootstrap-raw-sha256"], "scenario bootstrap raw digest"),
            hashlib.sha256(bootstrap_bytes).hexdigest(),
        ):
            raise ScenarioTruthError("scenario bootstrap bytes changed")
        bootstrap = _validate_bootstrap(
            bootstrap_document,
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            schema_registry_bytes=schema_registry_bytes,
            schema_bodies=schema_bodies,
            protected_bodies=protected_bodies,
        )
        if pin["bootstrap-id"] != bootstrap["bootstrap_id"] or pin["bootstrap-digest"] != bootstrap["bootstrap_digest"]:
            raise ScenarioTruthError("scenario bootstrap provenance pin changed")
        schema_documents = {
            str(document["$id"]): document
            for document in (
                _strict_json(body, "scenario schema") for body in schema_bodies
            )
        }

        def resolve_schema(current_id: str, reference: str) -> tuple[object, str]:
            target_text, separator, fragment = reference.partition("#")
            target_id = current_id if not target_text else target_text
            if target_id not in schema_documents:
                raise ScenarioTruthError("scenario schema reference is not closed")
            target: object = schema_documents[target_id]
            if separator and fragment:
                if not fragment.startswith("/"):
                    raise ScenarioTruthError("scenario schema pointer is invalid")
                for encoded in fragment[1:].split("/"):
                    token = encoded.replace("~1", "/").replace("~0", "~")
                    if type(target) is not dict or token not in target:
                        raise ScenarioTruthError(
                            "scenario schema pointer is unresolved"
                        )
                    target = target[token]
            return target, target_id

        for name, body, derived in (
            ("scenario-truth-policy-registry", policy_bytes, "registry_digest"),
            ("scenario-truth-fixture-registry", fixture_bytes, "registry_digest"),
            (
                "scenario-truth-installation-bootstrap",
                bootstrap_bytes,
                "bootstrap_digest",
            ),
        ):
            document = _strict_json(body, f"{name} installed document")
            source_id = f"urn:gew:schema:{name}:1.0.0"
            input_id = f"urn:gew:schema:{name}-input:1.0.0"
            if validate_instance(
                schema_documents[source_id], document, source_id=source_id,
                resolver=resolve_schema,
            ):
                raise ScenarioTruthError(
                    "scenario installed document failed its source schema"
                )
            unsigned = copy.deepcopy(document)
            unsigned.pop(derived, None)
            if validate_instance(
                schema_documents[input_id], unsigned, source_id=input_id,
                resolver=resolve_schema,
            ):
                raise ScenarioTruthError(
                    "scenario installed projection failed its input schema"
                )
        registry = parse_scenario_truth_registries(
            _strict_json(policy_bytes, "scenario policy"),
            _strict_json(fixture_bytes, "scenario fixture"),
        )
        result = object.__new__(cls)
        result._registry = registry
        result._schema_documents = schema_documents
        result._resolve_schema = resolve_schema
        result._authority = _RegistryAuthority(result, registry)
        result._issued_observers: dict[int, ScenarioTruthObservationFactory] = {}
        result._issued_observations: dict[int, tuple[ScenarioTruthObservationFactory, ScenarioTruthObservation]] = {}
        result._restored_evidence: dict[int, tuple] = {}
        result._issued_rejections: dict[int, tuple] = {}
        result._rejection_evidence: dict[int, tuple] = {}
        result._closed = False
        result.installation_pins = freeze({
            "bootstrap_id": bootstrap["bootstrap_id"],
            "bootstrap_digest": bootstrap["bootstrap_digest"],
            "policy_registry_digest": bootstrap["policy_registry_digest"],
            "fixture_registry_digest": bootstrap["fixture_registry_digest"],
            "profile_schema_registry_digest": bootstrap["profile_schema_registry_digest"],
            "protected_closure_digest": bootstrap["protected_closure_digest"],
            "distribution_name": pin["distribution-name"],
            "distribution_version": pin["distribution-version"],
        })
        result._installation_projection = tuple(
            hashlib.sha256(body).hexdigest() for body in resources
        )
        return result

    def _require_installation_current(self) -> None:
        from graph_engineering import (
            DistributionIdentityError,
            _scenario_truth_installation_resources,
        )

        try:
            current = _scenario_truth_installation_resources()
        except (DistributionIdentityError, OSError) as error:
            raise ScenarioTruthError(
                "scenario installation closure is unavailable"
            ) from error
        if type(current) is not tuple or any(type(body) is not bytes for body in current):
            raise ScenarioTruthError("scenario installation closure is malformed")
        observed = tuple(hashlib.sha256(body).hexdigest() for body in current)
        if len(observed) != len(self._installation_projection) or any(
            not hmac.compare_digest(actual, expected)
            for actual, expected in zip(
                observed, self._installation_projection, strict=True,
            )
        ):
            raise ScenarioTruthError("scenario installation closure changed")

    def registry(self) -> _RegistryAuthority:
        self.require_current(self._authority)
        return self._authority

    def observation_factory(
        self,
        authority: object,
        *,
        binding: object,
        private_root: str | os.PathLike[str],
    ) -> ScenarioTruthObservationFactory:
        self.require_current(authority)
        if type(binding) is not dict or tuple(binding) != _BINDING_FIELDS:
            raise ScenarioTruthError("scenario binding fields/order are not exact")
        task_id = _text(binding["task_id"], "scenario task ID")
        if type(binding["task_revision"]) is not int or binding["task_revision"] < 1:
            raise ScenarioTruthError("scenario task revision is invalid")
        if type(binding["invalidation_epoch"]) is not int or binding["invalidation_epoch"] < 0:
            raise ScenarioTruthError("scenario invalidation epoch is invalid")
        _digest(binding["snapshot_digest"], "scenario snapshot digest")
        profile_id = _text(binding["profile_id"], "scenario profile ID")
        profile_version = _text(binding["profile_version"], "scenario profile version")
        scenario_id = _text(binding["scenario_id"], "scenario ID")
        pins = binding["graph_ref_pins"]
        if type(pins) is not dict or tuple(pins) != _PIN_FIELDS:
            raise ScenarioTruthError("scenario GraphRef pins are not exact")
        for field in _PIN_FIELDS:
            _digest(pins[field], f"scenario GraphRef {field}")
        branch_id = _text(binding["branch_id"], "scenario branch ID")
        ref_id = _text(binding["ref_id"], "scenario ref ID")
        if branch_id != "branch:" + task_id or ref_id != "ref:" + task_id:
            raise ScenarioTruthError("scenario branch/ref namespace is foreign")
        policy_row = self._registry.policy_row(profile_id, scenario_id)
        if policy_row["profile_version"] != profile_version:
            raise ScenarioTruthError("scenario Profile version changed")
        fixture_row = self._registry.fixture_row(policy_row["fixture_id"])
        raw_root = pathlib.Path(private_root)
        metadata = os.lstat(raw_root)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ScenarioTruthError("scenario root is not private")
        root = raw_root.resolve(strict=True)
        if tuple(root.iterdir()):
            raise ScenarioTruthError("scenario root is not fresh")
        marker = root / ".scenario-truth-root"
        marker.write_text(task_id, encoding="ascii")
        os.chmod(marker, 0o600)
        seeds = [(row["path_id"], row["baseline_value"]) for row in fixture_row["target_roles"]]
        contract = fixture_row.get("execution_contract")
        if contract is not None:
            seeds.extend((row["path_id"], row["expected_value"]) for row in contract["controls"])
        for path_id, seed in seeds:
            relative = pathlib.PurePosixPath(path_id)
            if (relative.is_absolute() or any(part in ("", ".", "..") for part in path_id.split("/"))
                    or "\\" in path_id or path_id == ".scenario-truth-root"
                    or any(other != path_id and other.startswith(path_id + "/") for other, _ in seeds)):
                raise ScenarioTruthError("scenario fixture path is unsafe or aliased")
        for path_id, seed in seeds:
            relative = pathlib.PurePosixPath(path_id)
            path = root / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(seed.encode("ascii"))
            os.chmod(path, 0o600)
        result = object.__new__(ScenarioTruthObservationFactory)
        result._owner = self
        result._binding = freeze(binding)
        result._policy_row = policy_row
        result._fixture_row = fixture_row
        result._root = root
        result._root_identity = _identity(metadata)
        result._mutation_count = 0
        result._executed = False
        result._baseline_receipts = {}
        targets = [
            {
                "role_id": row["role_id"],
                "path_id": row["path_id"],
                "expected_before_state_id": row["baseline_state_id"],
                "expected_after_state_id": row["candidate_state_id"],
                "expected_rollback_state_id": row["rollback_state_id"],
                "apply": True,
            }
            for row in fixture_row["target_roles"]
        ]
        result._request = {
            "branch_id": branch_id,
            "ref_id": ref_id,
            "targets": targets,
            "ordered_phase_ids": list(policy_row["ordered_phase_ids"]),
            "rollback_or_compensation": thaw(fixture_row["rollback_or_compensation"]),
        }
        if contract is not None:
            result._request["environment"] = {
                "environment_id": contract["environment_id"],
                "classification": contract["environment_classification"],
            }
            result._request["ordered_gate_ids"] = [row["gate_id"] for row in contract["ordered_gates"]]
        refactor_contract = fixture_row.get("refactor_contract")
        if refactor_contract is not None:
            result._request["refactor_contract"] = thaw(refactor_contract)
        incident_contract = fixture_row.get("incident_contract")
        if incident_contract is not None:
            result._request["incident_contract"] = thaw(incident_contract)
        self._issued_observers[id(result)] = result
        return result

    def require_observer(self, value: object) -> ScenarioTruthObservationFactory:
        if (
            self._closed or type(value) is not ScenarioTruthObservationFactory
            or self._issued_observers.get(id(value)) is not value
        ):
            raise ScenarioTruthError("scenario observer is missing, cloned, or foreign")
        self._require_installation_current()
        return value

    def register_observation(
        self, observer: ScenarioTruthObservationFactory, observation: ScenarioTruthObservation,
    ) -> None:
        self.require_observer(observer)
        self._validate_observation_schema(observation.to_dict())
        self._issued_observations[id(observation)] = (observer, observation, freeze(observation.to_dict()))

    def _validate_observation_schema(self, value):
        schema_id = "urn:gew:schema:scenario-truth-observation:1.0.0"
        if validate_instance(self._schema_documents[schema_id], value,
                             source_id=schema_id, resolver=self._resolve_schema):
            raise ScenarioTruthError("scenario observation schema is not exact")

    def rejection_attack_ids(self, profile_id: str, scenario_id: str) -> tuple[str, ...]:
        self.require_current(self._authority)
        if (profile_id, scenario_id) not in self._registry.scenario_pairs:
            return ()
        policy = self._registry.policy_row(profile_id, scenario_id)
        fixture = self._registry.fixture_row(policy["fixture_id"])
        return tuple(fixture.get("rejection_attack_ids", ()))

    def _require_rejection_receipt(self, value: object) -> tuple:
        issued = self._issued_rejections.get(id(value))
        if (type(value) is not ScenarioTruthRejectionReceipt or issued is None
                or issued[0] is not value):
            raise ScenarioTruthError("scenario rejection receipt is missing, cloned, or foreign")
        _, observer, projection, targets = issued
        self.require_observer(observer)
        if (("execution_contract" in observer._fixture_row
             or "refactor_contract" in observer._fixture_row
             or "incident_contract" in observer._fixture_row)
                and observer._guarded_root_marker_digest() != projection.get("root_marker_digest")):
            raise ScenarioTruthError("scenario rejection root marker digest changed")
        if (value.projection != projection
                or type(value.mutation_count) is not int
                or value.request_unchanged is not True
                or value.target_bytes_unchanged is not True
                or any(getattr(value, field) != projection[field] for field in (
                    "attack_id", "root_path", "mutation_count", "request_unchanged",
                    "target_bytes_unchanged"))
                or observer._binding != projection["binding"]
                or observer.mutation_count != 0 or not observer._executed
                or observer.target_bytes() != targets):
            raise ScenarioTruthError("scenario rejection receipt is stale or altered")
        if "controls" in projection and freeze([
                {"control_id": key, "sha256": hashlib.sha256(body).hexdigest()}
                for key, body in observer._control_bytes()]) != projection["controls"]:
            raise ScenarioTruthError("scenario rejection controls changed")
        return issued

    def bind_rejections(self, receipts: object, *, test_id: str,
                        oracle_digest: str) -> ScenarioTruthRejectionEvidence:
        self.require_current(self._authority)
        if type(receipts) is not tuple or not receipts:
            raise ScenarioTruthError("scenario rejection closure is absent")
        issued = [self._require_rejection_receipt(receipt) for receipt in receipts]
        binding = issued[0][1]._binding
        expected = self.rejection_attack_ids(binding["profile_id"], binding["scenario_id"])
        if (tuple(receipt.attack_id for receipt in receipts) != expected
                or len({receipt.root_path for receipt in receipts}) != len(receipts)
                or any(item[1]._binding != binding for item in issued)):
            raise ScenarioTruthError("scenario rejection closure is incomplete or foreign")
        projection = freeze({
            "binding": thaw(binding), "test_id": _text(test_id, "scenario rejection test"),
            "oracle_digest": _digest(oracle_digest, "scenario rejection oracle"),
            "installation_pins": thaw(self.installation_pins),
            "receipts": [thaw(receipt.projection) for receipt in receipts],
        })
        # This is an internal process-local projection, not a new persistent schema.
        digest = "sha256:" + hashlib.sha256(json.dumps(
            thaw(projection), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")).hexdigest()
        result = object.__new__(ScenarioTruthRejectionEvidence)
        for name, value in (("receipts", receipts), ("projection", projection),
                            ("evidence_digest", digest)):
            object.__setattr__(result, name, value)
        self._rejection_evidence[id(result)] = (result, receipts, projection, digest)
        return result

    def require_rejections(self, value: object, *, binding: Mapping[str, object],
                           test_id: str, oracle_digest: str) -> str:
        self.require_current(self._authority)
        issued = self._rejection_evidence.get(id(value))
        if (type(value) is not ScenarioTruthRejectionEvidence or issued is None
                or issued[0] is not value or value.receipts != issued[1]
                or value.projection != issued[2] or value.evidence_digest != issued[3]):
            raise ScenarioTruthError("scenario rejection evidence is missing, altered, or foreign")
        projection = issued[2]
        if (projection["binding"] != freeze(dict(binding))
                or projection["test_id"] != test_id or projection["oracle_digest"] != oracle_digest
                or projection["installation_pins"] != self.installation_pins):
            raise ScenarioTruthError("scenario rejection evidence binding is stale or foreign")
        for receipt in value.receipts:
            self._require_rejection_receipt(receipt)
        return issued[3]

    def require_current(self, value: object) -> object:
        if self._closed:
            raise ScenarioTruthError("scenario authority is closed")
        self._require_installation_current()
        if type(value) is _RegistryAuthority:
            if value is not self._authority:
                raise ScenarioTruthError("scenario registry authority is missing, cloned, or foreign")
            return value
        if type(value) is _RestoredScenarioEvidence:
            issued = self._restored_evidence.get(id(value))
            if (
                value._factory is not self
                or issued is None or issued[0] is not value
                or issued[1] != value.projection or issued[2] != value.root_identity
            ):
                raise ScenarioTruthError("scenario restored evidence is cloned or foreign")
            self._validate_restored_targets(thaw(value.projection), value.root_identity)
            return value
        if type(value) is not ScenarioTruthObservation:
            raise ScenarioTruthError("scenario observation is missing, cloned, or foreign")
        issued = self._issued_observations.get(id(value))
        if issued is None or issued[1] is not value or value._authority is not issued[0]:
            raise ScenarioTruthError("scenario observation is missing, cloned, or foreign")
        observer = issued[0]
        if freeze(value.to_dict()) != issued[2]:
            raise ScenarioTruthError("scenario observation issued projection changed")
        if tuple(row["state_id"] for row in value.after_targets) != tuple(
            row["candidate_state_id"] for row in observer._fixture_row["target_roles"]
        ):
            raise ScenarioTruthError("scenario observation target states changed")
        expected = value.body()
        if not hmac.compare_digest(
            value.observation_digest, _semantic(expected, "scenario-truth-observation")
        ):
            raise ScenarioTruthError("scenario observation digest changed")
        for target in observer._fixture_row["target_roles"]:
            if observer._read_target(target["path_id"]) != target["candidate_value"].encode("ascii"):
                raise ScenarioTruthError("scenario target changed after observation")
        if "execution_contract" in observer._fixture_row:
            self._validate_guarded_projection(value.to_dict(), observer._root, observer._root_identity)
        elif "refactor_contract" in observer._fixture_row:
            self._validate_refactor_projection(
                value.to_dict(), observer._root, observer._root_identity,
            )
        elif "incident_contract" in observer._fixture_row:
            self._validate_incident_projection(
                value.to_dict(), observer._root, observer._root_identity,
            )
        return value

    def projection(self, value: object) -> FrozenMap:
        evidence = self.require_current(value)
        if type(evidence) is _RestoredScenarioEvidence:
            return evidence.projection
        return freeze(evidence.to_dict())

    def restore_projection(self, value: object) -> _RestoredScenarioEvidence:
        if self._closed:
            raise ScenarioTruthError("scenario authority is closed")
        self._require_installation_current()
        if type(value) is not dict:
            raise ScenarioTruthError("scenario projection is not an object")
        self._validate_observation_schema(value)
        digest = value.get("observation_digest")
        body = copy.deepcopy(value)
        body.pop("observation_digest", None)
        if type(digest) is not str or not hmac.compare_digest(
            digest, _semantic(body, "scenario-truth-observation")
        ):
            raise ScenarioTruthError("scenario projection digest changed")
        if freeze(body.get("installation_pins")) != self.installation_pins:
            raise ScenarioTruthError("scenario projection installation changed")
        root_identity = self._validate_restored_targets(value)
        projection = freeze(value)
        if not isinstance(projection, FrozenMap):
            raise ScenarioTruthError("scenario projection did not freeze")
        result = _RestoredScenarioEvidence(self, projection, root_identity)
        self._restored_evidence[id(result)] = (result, projection, root_identity)
        return result

    def _validate_restored_targets(self, body: dict[str, object], root_identity=None):
        branch = body.get("branch_binding")
        fixture = body.get("fixture_row")
        task_id = body.get("task_id")
        if (
            type(branch) is not dict or set(branch) != {"branch_id", "ref_id", "root_path"}
            or type(fixture) is not dict or type(fixture.get("target_roles")) is not list
            or type(task_id) is not str
        ):
            raise ScenarioTruthError("scenario projection branch binding changed")
        root = pathlib.Path(_text(branch["root_path"], "scenario projection root"))
        metadata = os.lstat(root)
        if (
            not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or (root_identity is not None and _identity(metadata) != root_identity)
            or _read_private_target(root, ".scenario-truth-root").decode("ascii") != task_id
        ):
            raise ScenarioTruthError("scenario projection root is stale or foreign")
        if (branch["branch_id"] != "branch:" + task_id or branch["ref_id"] != "ref:" + task_id):
            raise ScenarioTruthError("scenario projection branch namespace is foreign")
        installed_policy = self._registry.policy_row(body.get("profile_id"), body.get("scenario_id"))
        installed_fixture = self._registry.fixture_row(installed_policy["fixture_id"])
        if (freeze(fixture) != installed_fixture or freeze(body.get("policy_row")) != installed_policy
                or body.get("profile_version") != installed_policy["profile_version"]):
            raise ScenarioTruthError("scenario projection differs from installed registry")
        if "execution_contract" in installed_fixture:
            self._validate_guarded_projection(body, root, _identity(metadata))
        elif "refactor_contract" in installed_fixture:
            self._validate_refactor_projection(body, root, _identity(metadata))
        elif "incident_contract" in installed_fixture:
            self._validate_incident_projection(body, root, _identity(metadata))
        elif any(key in body for key in (
            "execution_proof", "refactor_proof", "incident_proof",
        )):
            raise ScenarioTruthError("unguarded projection carries a conditional proof")
        after = body.get("after_targets")
        if type(after) is not list or len(after) != len(fixture["target_roles"]):
            raise ScenarioTruthError("scenario projection target set changed")
        for target, observed in zip(fixture["target_roles"], after, strict=True):
            if type(target) is not dict or type(observed) is not dict:
                raise ScenarioTruthError("scenario projection target row changed")
            expected = str(target["candidate_value"]).encode("ascii")
            if (
                _read_private_target(root, str(target["path_id"]),
                                     root_identity=_identity(metadata)) != expected
                or observed.get("value_digest")
                != "sha256:" + hashlib.sha256(expected).hexdigest()
            ):
                raise ScenarioTruthError("scenario projection target is stale")
        return _identity(metadata)

    def _validate_guarded_projection(self, body, root, root_identity):
        policy = self._registry.policy_row(body.get("profile_id"), body.get("scenario_id"))
        fixture = self._registry.fixture_row(policy["fixture_id"])
        if (freeze(body.get("fixture_row")) != fixture or freeze(body.get("policy_row")) != policy
                or freeze(body.get("installation_pins")) != self.installation_pins):
            raise ScenarioTruthError("scenario guarded installation binding changed")
        binding = {field: body.get(field) for field in _BINDING_FIELDS[:-2]}
        branch = body.get("branch_binding", {})
        binding.update({"branch_id": branch.get("branch_id"), "ref_id": branch.get("ref_id")})
        if (type(binding["task_revision"]) is not int or binding["task_revision"] < 1
                or type(binding["invalidation_epoch"]) is not int or binding["invalidation_epoch"] < 0
                or binding["profile_version"] != policy["profile_version"]):
            raise ScenarioTruthError("scenario guarded task revision is invalid")
        _digest(binding["snapshot_digest"], "guarded snapshot")
        pins = binding["graph_ref_pins"]
        if type(pins) is not dict or set(pins) != set(_PIN_FIELDS):
            raise ScenarioTruthError("scenario guarded GraphRef closure changed")
        for digest in pins.values():
            _digest(digest, "guarded GraphRef pin")
        expected = _guarded_proof(freeze(binding), fixture, self.installation_pins, root, root_identity)
        if freeze(body.get("execution_proof")) != freeze(expected):
            raise ScenarioTruthError("scenario guarded execution proof is missing or changed")
        before = expected["baseline"]["baseline_targets"]
        after = [ScenarioTruthObservationFactory._target_observation(
            row, row["candidate_value"].encode("ascii"), row["candidate_state_id"])
            for row in fixture["target_roles"]]
        transitions = [{"phase_id": fixture["phase_expectations"][0]["phase_id"],
            "role_id": row["role_id"], "before_digest": first["value_digest"],
            "after_digest": last["value_digest"]} for row, first, last in zip(
                fixture["target_roles"], before, after, strict=True)]
        if (body.get("before_targets") != before or body.get("after_targets") != after
                or body.get("ordered_transitions") != transitions
                or body.get("rollback_or_compensation") != thaw(fixture["rollback_or_compensation"])
                or body.get("owner_route") != policy["owner_route_policy"]
                or body.get("scenario_outcome") != policy["success_outcome"]
                or body.get("assertion_results") != [
                    {"assertion_id": row["assertion_id"], "passed": True}
                    for row in fixture["assertion_expectations"]]):
            raise ScenarioTruthError("scenario guarded observation relationships changed")

    def _validate_refactor_projection(self, body, root, root_identity):
        policy = self._registry.policy_row(
            body.get("profile_id"), body.get("scenario_id"),
        )
        fixture = self._registry.fixture_row(policy["fixture_id"])
        if (
            freeze(body.get("fixture_row")) != fixture
            or freeze(body.get("policy_row")) != policy
            or freeze(body.get("installation_pins")) != self.installation_pins
        ):
            raise ScenarioTruthError("scenario refactor installation binding changed")
        binding = {field: body.get(field) for field in _BINDING_FIELDS[:-2]}
        branch = body.get("branch_binding", {})
        binding.update({
            "branch_id": branch.get("branch_id"),
            "ref_id": branch.get("ref_id"),
        })
        if (
            type(binding["task_revision"]) is not int
            or binding["task_revision"] < 1
            or type(binding["invalidation_epoch"]) is not int
            or binding["invalidation_epoch"] < 0
            or binding["profile_version"] != policy["profile_version"]
        ):
            raise ScenarioTruthError("scenario refactor task revision is invalid")
        _digest(binding["snapshot_digest"], "refactor snapshot")
        pins = binding["graph_ref_pins"]
        if type(pins) is not dict or set(pins) != set(_PIN_FIELDS):
            raise ScenarioTruthError("scenario refactor GraphRef closure changed")
        for digest in pins.values():
            _digest(digest, "refactor GraphRef pin")
        expected = _refactor_proof(
            freeze(binding), fixture, self.installation_pins,
            root, root_identity,
        )
        if freeze(body.get("refactor_proof")) != freeze(expected):
            raise ScenarioTruthError("scenario refactor proof is missing or changed")
        before = [ScenarioTruthObservationFactory._target_observation(
            row, row["baseline_value"].encode("ascii"), row["baseline_state_id"],
        ) for row in fixture["target_roles"]]
        after = [ScenarioTruthObservationFactory._target_observation(
            row, row["candidate_value"].encode("ascii"), row["candidate_state_id"],
        ) for row in fixture["target_roles"]]
        transitions = [{
            "phase_id": fixture["phase_expectations"][0]["phase_id"],
            "role_id": row["role_id"],
            "before_digest": first["value_digest"],
            "after_digest": last["value_digest"],
        } for row, first, last in zip(
            fixture["target_roles"], before, after, strict=True,
        )]
        if (
            body.get("before_targets") != before
            or body.get("after_targets") != after
            or body.get("ordered_transitions") != transitions
            or body.get("rollback_or_compensation")
            != thaw(fixture["rollback_or_compensation"])
            or body.get("owner_route") != policy["owner_route_policy"]
            or body.get("scenario_outcome") != policy["success_outcome"]
            or body.get("assertion_results") != [
                {"assertion_id": row["assertion_id"], "passed": True}
                for row in fixture["assertion_expectations"]
            ]
        ):
            raise ScenarioTruthError("scenario refactor observation relationships changed")

    def _validate_incident_projection(self, body, root, root_identity):
        policy = self._registry.policy_row(
            body.get("profile_id"), body.get("scenario_id"),
        )
        fixture = self._registry.fixture_row(policy["fixture_id"])
        if (
            freeze(body.get("fixture_row")) != fixture
            or freeze(body.get("policy_row")) != policy
            or freeze(body.get("installation_pins")) != self.installation_pins
        ):
            raise ScenarioTruthError("scenario incident installation binding changed")
        binding = {field: body.get(field) for field in _BINDING_FIELDS[:-2]}
        branch = body.get("branch_binding", {})
        binding.update({
            "branch_id": branch.get("branch_id"),
            "ref_id": branch.get("ref_id"),
        })
        if (
            type(binding["task_revision"]) is not int
            or binding["task_revision"] < 1
            or type(binding["invalidation_epoch"]) is not int
            or binding["invalidation_epoch"] < 0
            or binding["profile_version"] != policy["profile_version"]
        ):
            raise ScenarioTruthError("scenario incident task revision is invalid")
        _digest(binding["snapshot_digest"], "incident snapshot")
        pins = binding["graph_ref_pins"]
        if type(pins) is not dict or set(pins) != set(_PIN_FIELDS):
            raise ScenarioTruthError("scenario incident GraphRef closure changed")
        for digest in pins.values():
            _digest(digest, "incident GraphRef pin")
        contract = fixture["incident_contract"]
        blocked = tuple(contract["gate_ids"]) == ("owner-route",)
        expected_mutations = 0 if blocked else 1
        expected = _incident_proof(
            freeze(binding), fixture, self.installation_pins, root, root_identity,
            expected_mutations,
        )
        if freeze(body.get("incident_proof")) != freeze(expected):
            raise ScenarioTruthError("scenario incident proof is missing or changed")
        before = [ScenarioTruthObservationFactory._target_observation(
            row, row["baseline_value"].encode("ascii"), row["baseline_state_id"],
        ) for row in fixture["target_roles"]]
        after = [ScenarioTruthObservationFactory._target_observation(
            row, row["candidate_value"].encode("ascii"), row["candidate_state_id"],
        ) for row in fixture["target_roles"]]
        transitions = [] if blocked else [{
            "phase_id": fixture["phase_expectations"][0]["phase_id"],
            "role_id": row["role_id"],
            "before_digest": first["value_digest"],
            "after_digest": last["value_digest"],
        } for row, first, last in zip(
            fixture["target_roles"], before, after, strict=True,
        )]
        if (
            body.get("before_targets") != before
            or body.get("after_targets") != after
            or body.get("ordered_transitions") != transitions
            or body.get("rollback_or_compensation")
            != thaw(fixture["rollback_or_compensation"])
            or body.get("owner_route") != policy["owner_route_policy"]
            or body.get("scenario_outcome") != contract["expected_outcome"]
            or body.get("assertion_results") != [
                {"assertion_id": row["assertion_id"], "passed": True}
                for row in fixture["assertion_expectations"]
            ]
        ):
            raise ScenarioTruthError("scenario incident observation relationships changed")

    def close(self) -> None:
        self._closed = True
        self._issued_observers.clear()
        self._issued_observations.clear()
        self._restored_evidence.clear()
        self._issued_rejections.clear()
        self._rejection_evidence.clear()


__all__ = (
    "ScenarioTruthObservationFactory",
    "ScenarioTruthRegistryFactory",
)
