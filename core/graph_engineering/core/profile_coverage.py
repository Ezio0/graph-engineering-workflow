"""Installation-bound WP-08 production coverage records and plan authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.profiles import ProfileContractError, SupportMatrixDefinition


_SEMANTIC = re.compile(r"sha256-jcs-v1:[0-9a-f]{64}\Z")
_OBJECT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RAW = re.compile(r"[0-9a-f]{64}\Z")


class ProfileCoverageError(ValueError):
    """A production Profile coverage authority check failed closed."""


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ProfileCoverageError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if _SEMANTIC.fullmatch(result) is None:
        raise ProfileCoverageError(f"{label} is not a semantic digest")
    return result


def _raw(value: object, label: str) -> str:
    result = _text(value, label)
    if _RAW.fullmatch(result) is None:
        raise ProfileCoverageError(f"{label} is not a lowercase SHA-256")
    return result


def _object_digest(value: object, label: str) -> str:
    result = _text(value, label)
    if _OBJECT.fullmatch(result) is None:
        raise ProfileCoverageError(f"{label} is not an object digest")
    return result


def _exact(
    value: object,
    fields: frozenset[str],
    label: str,
) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ProfileCoverageError(f"{label} properties are not exact")
    return value


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ProfileCoverageError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        result = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileCoverageError(f"{label} is malformed") from error
    if type(result) is not dict:
        raise ProfileCoverageError(f"{label} is not a JSON object")
    return result


def _self_digest(
    value: Mapping[str, object],
    *,
    field: str,
    contract: str,
    schema: str,
) -> str:
    body = dict(value)
    claimed = _digest(body.pop(field, None), f"{contract} digest")
    expected = semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{contract}",
        projection_id=f"urn:gew:digest-projection:{contract}:1.0.0",
        schema_id=f"urn:gew:schema:{schema}:1.0.0",
    )
    if not hmac.compare_digest(claimed, expected):
        raise ProfileCoverageError(f"{contract} digest mismatch")
    return claimed


@dataclass(frozen=True, slots=True, init=False)
class ProfileCoverageExecutionPlan:
    plan_id: str
    plan_digest: str
    support_matrix_digest: str
    runtime_binding: FrozenMap
    oracle_bindings: tuple[FrozenMap, ...]
    oracles: Mapping[tuple[str, str, str, str, str | None], FrozenMap]
    bindings: Mapping[str, FrozenMap]
    _plan_raw_sha256: str
    _oracle_raw_sha256: tuple[str, ...]
    _runner_raw_sha256: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileCoverageExecutionPlan is installation-issued")

    @classmethod
    def from_installation(
        cls,
        *,
        matrix: SupportMatrixDefinition,
    ) -> ProfileCoverageExecutionPlan:
        if type(matrix) is not SupportMatrixDefinition:
            raise ProfileCoverageError("coverage plan matrix authority is invalid")
        from graph_engineering import (
            DistributionIdentityError,
            _profile_coverage_installation_resources,
        )

        try:
            provenance_bytes, plan_bytes, oracle_bodies, runner_bytes = (
                _profile_coverage_installation_resources()
            )
            provenance = tomllib.loads(
                provenance_bytes.decode("utf-8", errors="strict")
            )
            bootstrap = provenance["tool"]["gew"]["profile"][
                "coverage-execution-plan"
            ]
        except (
            DistributionIdentityError,
            KeyError,
            TypeError,
            UnicodeError,
            tomllib.TOMLDecodeError,
        ) as error:
            raise ProfileCoverageError(
                "coverage plan installation bootstrap is unavailable"
            ) from error
        bootstrap = _exact(
            bootstrap,
            frozenset({
                "plan-id", "plan-digest", "plan-raw-sha256", "plan-source",
                "plan-resource", "oracle-vectors",
                "runner-raw-sha256", "runner-source", "runner-resource",
                "protected-sources", "protected-resources",
            }),
            "coverage installation bootstrap",
        )
        if (
            not hmac.compare_digest(
                hashlib.sha256(plan_bytes).hexdigest(),
                _raw(bootstrap["plan-raw-sha256"], "bootstrap plan raw digest"),
            )
            or not hmac.compare_digest(
                hashlib.sha256(runner_bytes).hexdigest(),
                _raw(bootstrap["runner-raw-sha256"], "bootstrap runner raw digest"),
            )
        ):
            raise ProfileCoverageError("coverage installation bytes changed")
        if type(oracle_bodies) is not tuple or not oracle_bodies:
            raise ProfileCoverageError("Profile coverage oracle vector is not exact")
        plan = _exact(
            _strict_json(plan_bytes, "Profile coverage execution plan"),
            frozenset({
                "schema_version", "plan_id", "support_matrix_digest",
                "runtime_binding", "oracle_bindings", "bindings", "plan_digest",
            }),
            "Profile coverage execution plan",
        )
        if plan["schema_version"] != "1.0.0":
            raise ProfileCoverageError("coverage execution plan version is unsupported")
        plan_digest = _self_digest(
            plan,
            field="plan_digest",
            contract="profile-coverage-execution-plan",
            schema="profile-coverage-execution-plan-input",
        )
        for bootstrap_field, observed in (
            ("plan-id", plan["plan_id"]),
            ("plan-digest", plan_digest),
        ):
            if bootstrap[bootstrap_field] != observed:
                raise ProfileCoverageError("coverage bootstrap semantic pin changed")
        matrix_digest = _digest(
            plan["support_matrix_digest"], "coverage plan matrix digest"
        )
        if not hmac.compare_digest(matrix_digest, matrix.digest):
            raise ProfileCoverageError("coverage plan support matrix is stale")
        runtime = _exact(
            plan["runtime_binding"],
            frozenset({"runtime_kind", "runtime_lineage_id", "runtime_digest"}),
            "coverage runtime binding",
        )
        _text(runtime["runtime_kind"], "coverage runtime kind")
        _text(runtime["runtime_lineage_id"], "coverage runtime lineage")
        _digest(runtime["runtime_digest"], "coverage runtime digest")
        raw_oracle_bindings = plan["oracle_bindings"]
        bootstrap_oracles = bootstrap["oracle-vectors"]
        if (
            type(raw_oracle_bindings) is not list
            or type(bootstrap_oracles) is not list
            or len(raw_oracle_bindings) != len(oracle_bodies)
            or len(bootstrap_oracles) != len(oracle_bodies)
        ):
            raise ProfileCoverageError("coverage oracle vector is absent")
        oracle_fields = frozenset({
            "schema_version", "oracle_id", "oracle_kind", "profile_id",
            "selector_kind", "column_id", "scenario_id",
            "category_boundary_case_id", "overlay_id",
            "evidence_kind", "required_outcome", "required_fact_ids",
            "pass_result", "reject_result",
            "reject_error_type", "reject_error_message",
            "reject_state_relation", "reject_input_relation", "oracle_digest",
            "isolated_runner_raw_sha256", "task_ids",
        })
        oracle_binding_fields = frozenset({
            "oracle_id", "profile_id", "selector_kind", "column_id",
            "scenario_id", "category_boundary_case_id", "overlay_id", "oracle_member",
            "oracle_raw_sha256", "oracle_digest", "task_ids",
        })
        bootstrap_oracle_fields = frozenset({
            "oracle-id", "profile-id", "selector-kind", "column-id",
            "scenario-id", "category-boundary-case-id", "overlay-id", "oracle-digest",
            "oracle-raw-sha256", "oracle-source", "oracle-resource",
            "pass-task-id", "reject-task-id",
        })
        oracle_index: dict[tuple[str, str, str, str, str | None], FrozenMap] = {}
        frozen_oracle_bindings: list[FrozenMap] = []
        oracle_raw_digests: list[str] = []
        oracle_order: list[tuple[str, str, str, str, str | None]] = []
        oracle_task_ids: set[str] = set()
        for body, raw_binding, raw_bootstrap in zip(
            oracle_bodies, raw_oracle_bindings, bootstrap_oracles, strict=True,
        ):
            oracle = _exact(
                _strict_json(body, "Profile coverage oracle"),
                oracle_fields,
                "Profile coverage oracle",
            )
            binding = _exact(
                raw_binding, oracle_binding_fields, "coverage oracle binding",
            )
            installed = _exact(
                raw_bootstrap, bootstrap_oracle_fields,
                "coverage bootstrap oracle vector",
            )
            if oracle["schema_version"] != "1.0.0":
                raise ProfileCoverageError(
                    "Profile coverage oracle version is unsupported"
                )
            oracle_digest = _self_digest(
                oracle,
                field="oracle_digest",
                contract="profile-coverage-oracle",
                schema="profile-coverage-oracle-input",
            )
            fact_ids = oracle["required_fact_ids"]
            if (
                type(fact_ids) is not list
                or not fact_ids
                or any(type(item) is not str or not item for item in fact_ids)
                or len(fact_ids) != len(set(fact_ids))
                or tuple(fact_ids) != tuple(sorted(fact_ids))
            ):
                raise ProfileCoverageError("coverage oracle fact closure is not exact")
            _text(oracle["evidence_kind"], "coverage oracle evidence kind")
            _text(oracle["required_outcome"], "coverage oracle outcome")
            task_ids = _exact(
                oracle["task_ids"], frozenset({"P", "R"}),
                "coverage oracle task identities",
            )
            pass_task_id = _text(task_ids["P"], "coverage oracle PASS task ID")
            reject_task_id = _text(task_ids["R"], "coverage oracle rejection task ID")
            if (
                pass_task_id == reject_task_id
                or pass_task_id in oracle_task_ids
                or reject_task_id in oracle_task_ids
            ):
                raise ProfileCoverageError(
                    "coverage oracle task identity is not unique"
                )
            oracle_task_ids.update((pass_task_id, reject_task_id))
            raw_digest = hashlib.sha256(body).hexdigest()
            key = (
                _text(oracle["oracle_id"], "coverage oracle ID"),
                _text(oracle["profile_id"], "coverage oracle Profile ID"),
                _text(oracle["selector_kind"], "coverage oracle selector kind"),
                _text(oracle["column_id"], "coverage oracle column ID"),
                (
                    None
                    if oracle["scenario_id"] is None
                    else _text(oracle["scenario_id"], "coverage oracle scenario ID")
                ),
            )
            binding_key = tuple(binding[field] for field in (
                "oracle_id", "profile_id", "selector_kind", "column_id", "scenario_id",
            ))
            installed_key = (
                installed["oracle-id"],
                installed["profile-id"],
                installed["selector-kind"],
                installed["column-id"],
                installed["scenario-id"] or None,
            )
            if (
                key in oracle_index
                or binding_key != key
                or installed_key != key
                or binding["category_boundary_case_id"]
                != oracle["category_boundary_case_id"]
                or (installed["category-boundary-case-id"] or None)
                != oracle["category_boundary_case_id"]
                or binding["overlay_id"] != oracle["overlay_id"]
                or installed["overlay-id"] != oracle["overlay_id"]
                or binding["oracle_digest"] != oracle_digest
                or installed["oracle-digest"] != oracle_digest
                or binding["oracle_raw_sha256"] != raw_digest
                or installed["oracle-raw-sha256"] != raw_digest
                or binding["task_ids"] != task_ids
                or installed["pass-task-id"] != pass_task_id
                or installed["reject-task-id"] != reject_task_id
                or installed["oracle-source"] != binding["oracle_member"]
                or installed["oracle-resource"]
                != "graph_engineering/" + str(binding["oracle_member"])
                or oracle["isolated_runner_raw_sha256"]
                != hashlib.sha256(runner_bytes).hexdigest()
            ):
                raise ProfileCoverageError("coverage oracle binding is stale")
            frozen_oracle = freeze(oracle)
            frozen_binding = freeze(binding)
            assert isinstance(frozen_oracle, FrozenMap)
            assert isinstance(frozen_binding, FrozenMap)
            oracle_index[key] = frozen_oracle
            frozen_oracle_bindings.append(frozen_binding)
            oracle_raw_digests.append(raw_digest)
            oracle_order.append(key)
        if tuple(oracle_order) != tuple(sorted(oracle_order)):
            raise ProfileCoverageError("coverage oracle vector is not canonical")
        raw_bindings = plan["bindings"]
        if type(raw_bindings) is not list or not raw_bindings:
            raise ProfileCoverageError("coverage execution bindings are absent")
        indexed: dict[str, FrozenMap] = {}
        ordered: list[str] = []
        binding_fields = frozenset({
            "test_id", "profile_id", "selector_kind", "column_id",
            "scenario_id", "category_boundary_case_id", "overlay_id", "disposition",
            "expected_result", "execution_kind", "oracle_id", "oracle_digest", "selector_digest",
            "request_digest", "task_id",
        })
        for raw_binding in raw_bindings:
            binding = _exact(raw_binding, binding_fields, "coverage execution binding")
            test_id = _text(binding["test_id"], "coverage execution test ID")
            expected_task_id = "task:wp08-coverage:" + test_id.lower()
            if test_id in indexed or test_id not in matrix.case_bindings:
                raise ProfileCoverageError("coverage execution binding is not unique/current")
            matrix_binding = matrix.case_bindings[test_id]
            profile_id = _text(binding["profile_id"], "coverage binding Profile ID")
            selector = {
                "schema_version": "1.0.0",
                **{
                    field: binding[field]
                    for field in (
                        "test_id", "profile_id", "selector_kind", "column_id",
                        "scenario_id", "category_boundary_case_id", "overlay_id", "disposition",
                        "expected_result", "execution_kind", "oracle_id",
                        "oracle_digest", "task_id",
                    )
                },
            }
            selector_digest = _digest(
                binding["selector_digest"], "coverage plan selector digest",
            )
            expected_selector_digest = semantic_digest(
                selector,
                contract_type="urn:gew:contract:profile-coverage-plan-selector",
                projection_id=(
                    "urn:gew:digest-projection:profile-coverage-plan-selector:1.0.0"
                ),
                schema_id="urn:gew:schema:profile-coverage-plan-selector:1.0.0",
            )
            request_digest = binding["request_digest"]
            oracle_key = (
                _text(binding["oracle_id"], "coverage binding oracle ID"),
                profile_id,
                _text(binding["selector_kind"], "coverage binding selector kind"),
                _text(binding["column_id"], "coverage binding column ID"),
                (
                    None
                    if binding["scenario_id"] is None
                    else _text(binding["scenario_id"], "coverage binding scenario ID")
                ),
            )
            oracle = oracle_index.get(oracle_key)
            try:
                expected_selector = matrix.expected_plan_selector(test_id)
            except ProfileContractError as error:
                raise ProfileCoverageError(
                    "coverage execution test has no authoritative selector"
                ) from error
            expected_column_id = expected_selector["column_id"]
            expected_result = (
                oracle["pass_result"]
                if oracle is not None and expected_selector["disposition"] == "P"
                else oracle["reject_result"] if oracle is not None else None
            )
            if (
                oracle is None
                or binding["task_id"] != expected_task_id
                or binding["profile_id"] != expected_selector["profile_id"]
                or binding["selector_kind"] != expected_selector["selector_kind"]
                or (
                    expected_column_id is not None
                    and binding["column_id"] != expected_column_id
                )
                or binding["scenario_id"] != expected_selector["scenario_id"]
                or binding["category_boundary_case_id"]
                != expected_selector["category_boundary_case_id"]
                or binding["disposition"] != expected_selector["disposition"]
                or binding["expected_result"] != expected_result
                or binding["execution_kind"]
                != expected_selector["execution_kind"]
                or matrix_binding["fixture_id"]
                != f"profile:{profile_id}:1.0.0"
                or matrix_binding["oracle_id"] != oracle["oracle_id"]
                or oracle["profile_id"] != profile_id
                or binding["selector_kind"] != oracle["selector_kind"]
                or binding["column_id"] != oracle["column_id"]
                or binding["scenario_id"] != oracle["scenario_id"]
                or binding["category_boundary_case_id"]
                != oracle["category_boundary_case_id"]
                or binding["overlay_id"] != oracle["overlay_id"]
                or binding["oracle_digest"] != oracle["oracle_digest"]
                or binding["task_id"]
                != oracle["task_ids"][binding["disposition"]]
                or not hmac.compare_digest(
                    selector_digest, expected_selector_digest,
                )
                or (
                    binding["disposition"] == "P"
                    and request_digest is not None
                )
                or (
                    binding["disposition"] == "R"
                    and _digest(
                        request_digest, "coverage rejection request digest",
                    )
                    != request_digest
                )
            ):
                raise ProfileCoverageError("coverage execution binding is incoherent")
            ordered.append(test_id)
            frozen = freeze(binding)
            assert isinstance(frozen, FrozenMap)
            indexed[test_id] = frozen
        if tuple(ordered) != tuple(sorted(ordered)):
            raise ProfileCoverageError("coverage execution bindings are not canonical")
        result = object.__new__(cls)
        for field, value in (
            ("plan_id", _text(plan["plan_id"], "coverage plan ID")),
            ("plan_digest", plan_digest),
            ("support_matrix_digest", matrix_digest),
            ("runtime_binding", freeze(runtime)),
            ("oracle_bindings", tuple(frozen_oracle_bindings)),
            ("oracles", MappingProxyType(oracle_index)),
            ("bindings", MappingProxyType(indexed)),
            ("_plan_raw_sha256", hashlib.sha256(plan_bytes).hexdigest()),
            ("_oracle_raw_sha256", tuple(oracle_raw_digests)),
            ("_runner_raw_sha256", hashlib.sha256(runner_bytes).hexdigest()),
        ):
            object.__setattr__(result, field, value)
        return result

    def binding(self, test_id: object) -> FrozenMap:
        test = _text(test_id, "coverage execution test ID")
        binding = self.bindings.get(test)
        if binding is None:
            raise ProfileCoverageError("coverage execution test is not installed")
        return binding

    def oracle_for(self, test_id: object) -> FrozenMap:
        binding = self.binding(test_id)
        key = (
            str(binding["oracle_id"]),
            str(binding["profile_id"]),
            str(binding["selector_kind"]),
            str(binding["column_id"]),
            (
                None
                if binding["scenario_id"] is None
                else str(binding["scenario_id"])
            ),
        )
        oracle = self.oracles.get(key)
        if oracle is None:
            raise ProfileCoverageError("coverage oracle selector is not installed")
        return oracle

    def isolated_runner_bytes(self) -> bytes:
        from graph_engineering import (
            DistributionIdentityError,
            _profile_coverage_installation_resources,
        )

        try:
            _provenance, plan, oracles, runner = (
                _profile_coverage_installation_resources()
            )
        except DistributionIdentityError as error:
            raise ProfileCoverageError(
                "coverage installation changed after plan issuance"
            ) from error
        observed = (
            hashlib.sha256(plan).hexdigest(),
            tuple(hashlib.sha256(oracle).hexdigest() for oracle in oracles),
            hashlib.sha256(runner).hexdigest(),
        )
        expected = (
            self._plan_raw_sha256,
            self._oracle_raw_sha256,
            self._runner_raw_sha256,
        )
        if observed != expected:
            raise ProfileCoverageError("coverage plan/oracle/runner is stale")
        return runner


@dataclass(frozen=True, slots=True, init=False, eq=False)
class ProfileCoverageExecutionRecord:
    test_id: str
    result: str
    request_digest: str
    profile_id: str
    profile_version: str
    column_id: str
    selector_kind: str
    scenario_id: str | None
    category_boundary_case_id: str | None
    plan_selector_digest: str
    profile_digest: str
    overlay_id: str
    overlay_version: str
    overlay_digest: str
    task_id: str
    task_revision: int
    snapshot_digest: str
    invalidation_epoch: int
    materialization_pins: FrozenMap
    assessment_digest: str | None
    assessment_object_digest: str | None
    assessment_reference_digest: str | None
    column_evidence_digest: str | None
    typed_evidence_object_digest: str | None
    matrix_digest: str
    plan_digest: str
    oracle_id: str
    oracle_digest: str
    runtime_kind: str
    runtime_lineage_id: str
    runtime_digest: str
    execution_kind: str
    before_state_digest: str
    after_state_digest: str
    rejection_error_type: str | None
    rejection_error_message: str | None
    isolated_oracle_digest: str
    execution_digest: str
    execution_object_digest: str
    _authority: object
    _capability: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileCoverageExecutionRecord is authority-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            **{
                field: thaw(value) if isinstance(value, FrozenMap) else value
                for field, value in (
                    (name, getattr(self, name))
                    for name in self.__dataclass_fields__
                    if not name.startswith("_")
                )
            },
        }

    def to_bytes(self) -> bytes:
        body = self.to_dict()
        body.pop("execution_object_digest")
        return canonical_bytes(body)


@dataclass(frozen=True, slots=True, init=False, eq=False)
class ProfileCoverageObservation:
    test_id: str
    matrix_digest: str
    profile_id: str
    profile_version: str
    column_id: str
    selector_kind: str
    scenario_id: str | None
    category_boundary_case_id: str | None
    plan_digest: str
    plan_selector_digest: str
    profile_digest: str
    overlay_id: str
    overlay_version: str
    overlay_digest: str
    runtime_kind: str
    runtime_lineage_id: str
    runtime_digest: str
    fixture_id: str
    oracle_id: str
    evidence_type: str
    owner_gate: str
    evidence_ref: str
    evidence_digest: str
    execution_kind: str
    observation_digest: str
    execution_digest: str
    _authority: object
    _capability: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileCoverageObservation is authority-issued")


_APPLICATION_AUTHORITY_TYPE: type | None = None


def _register_profile_coverage_authority_type(authority_type: type) -> None:
    global _APPLICATION_AUTHORITY_TYPE
    if (
        type(authority_type) is not type
        or authority_type.__module__
        != "graph_engineering.application.profile_coverage"
        or authority_type.__name__ != "ProfileCoverageAuthority"
        or (
            _APPLICATION_AUTHORITY_TYPE is not None
            and _APPLICATION_AUTHORITY_TYPE is not authority_type
        )
    ):
        raise ProfileCoverageError("Profile coverage authority type is substituted")
    _APPLICATION_AUTHORITY_TYPE = authority_type


@dataclass(frozen=True, slots=True, init=False, eq=False)
class ProfileCoverageAuthorityRegistration:
    _authority: object | None
    _plan: ProfileCoverageExecutionPlan | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Profile coverage registration is factory-issued")

    @classmethod
    def _issue(
        cls,
        authority: object,
        plan: ProfileCoverageExecutionPlan,
    ) -> ProfileCoverageAuthorityRegistration:
        if (
            _APPLICATION_AUTHORITY_TYPE is None
            or type(authority) is not _APPLICATION_AUTHORITY_TYPE
            or type(plan) is not ProfileCoverageExecutionPlan
        ):
            raise ProfileCoverageError("Profile coverage authority is not registered")
        result = object.__new__(cls)
        object.__setattr__(result, "_authority", authority)
        object.__setattr__(result, "_plan", plan)
        return result

    def require_observation(
        self,
        authority: object,
        observation: object,
    ) -> ProfileCoverageObservation:
        if authority is not self._authority:
            raise ProfileCoverageError("Profile coverage consumer authority is foreign")
        require = getattr(self._authority, "_require_observation", None)
        if not callable(require):
            raise ProfileCoverageError("Profile coverage observer authority is unavailable")
        result = require(observation)
        if type(result) is not ProfileCoverageObservation:
            raise ProfileCoverageError("Profile coverage observation is substituted")
        return result

    def _register_factory(
        self,
        authority: object,
        factory: object,
    ) -> object:
        from graph_engineering.core.profiles import CoverageRecordFactory

        if authority is not self._authority or type(factory) is not CoverageRecordFactory:
            raise ProfileCoverageError("Profile coverage lifecycle owner is foreign")
        register = getattr(factory, "_register_authority_capability", None)
        if not callable(register):
            raise ProfileCoverageError("Profile coverage lifecycle authority is unavailable")
        capability = object()
        register(authority, self, capability)
        return capability

    def _revoke(
        self,
        authority: object,
        factory: object,
        capability: object,
    ) -> None:
        from graph_engineering.core.profiles import CoverageRecordFactory

        if authority is not self._authority or type(factory) is not CoverageRecordFactory:
            raise ProfileCoverageError("Profile coverage lifecycle owner is foreign")
        revoke = getattr(authority, "_revoke_from_factory", None)
        if not callable(revoke):
            raise ProfileCoverageError("Profile coverage lifecycle authority is unavailable")
        closed = revoke(self, factory, capability)
        if type(closed) is not bool:
            raise ProfileCoverageError(
                "Profile coverage lifecycle result is invalid"
            )
        # Retain only the already-stripped authority identity so an exact
        # same-capability retry can complete after a lost revoke return. The
        # factory drops this registration after the monotonic abort step.


def profile_coverage_digest(
    value: object,
    *,
    contract: str,
    schema: str,
) -> str:
    return semantic_digest(
        value,
        contract_type=f"urn:gew:contract:{contract}",
        projection_id=f"urn:gew:digest-projection:{contract}:1.0.0",
        schema_id=f"urn:gew:schema:{schema}:1.0.0",
    )


__all__ = [
    "ProfileCoverageError",
    "ProfileCoverageExecutionPlan",
    "ProfileCoverageExecutionRecord",
    "ProfileCoverageObservation",
]
