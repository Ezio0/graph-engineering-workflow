"""Focused Remaining54 consumer-local authority attacks."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from graph_engineering.core.actions import ActionContractError, ActionPolicy
from graph_engineering.core.security._common import unsigned_digest
from graph_engineering.core.security.attestation import (
    SecurityAttestationError,
    SecurityRuntimeManifest,
    validate_installed_runtime_document,
)
from graph_engineering.application.scenario_truth import (
    ScenarioTruthObservationFactory,
    ScenarioTruthRegistryFactory,
)
from graph_engineering.core.scenario_truth import ScenarioTruthError
from tests.support.wp05a_security import security_context, security_schema_registry
from tests.unit.test_wp08_scenario_truth import ScenarioTruthAuthorityTests


ROOT = pathlib.Path(__file__).resolve().parents[2]


def _document(relative: str) -> dict[str, object]:
    value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise AssertionError(f"configuration must be an exact object: {relative}")
    return value


def _runtime(
    document: dict[str, object],
    installed: dict[str, object],
) -> tuple[object, object, SecurityRuntimeManifest]:
    context = security_context()
    schemas = security_schema_registry(context)
    fields = validate_installed_runtime_document(
        document,
        expected_manifest_id=str(installed["manifest_id"]),
        expected_manifest_digest=str(installed["manifest_digest"]),
        schema_registry=schemas,
        context=context,
    )
    runtime = object.__new__(SecurityRuntimeManifest)
    for name, value in fields.items():
        object.__setattr__(runtime, name, value)
    object.__setattr__(runtime, "_issuer", object())
    return context, schemas, runtime


def _resign_action_policy(document: dict[str, object]) -> None:
    document["policy_digest"] = unsigned_digest(
        document,
        digest_field="policy_digest",
        contract_type="urn:gew:contract:action-policy",
        schema_id="urn:gew:schema:action-policy:1.0.0",
    )


def _resign_runtime(document: dict[str, object]) -> None:
    document["manifest_digest"] = SecurityRuntimeManifest.digest_document(document)


class ScenarioTruthSecurityTests(unittest.TestCase):
    def test_f1_dependency_requests_keep_the_frozen_mandatory_selectors(self) -> None:
        from tests.support import wp08_release_coverage as coverage_fixture

        plan = _document("config/profiles/profile-coverage-execution-plan-v1.json")
        rows = [
            binding for binding in plan["bindings"]
            if binding["profile_id"] == "dependency-security"
            and binding["selector_kind"] == "mandatory"
            and binding["disposition"] == "R"
        ]
        self.assertEqual(
            {row["column_id"] for row in rows},
            set(coverage_fixture.approved_mandatory_columns()),
        )
        self.assertEqual(len(rows), len({row["column_id"] for row in rows}))
        for row in rows:
            with self.subTest(test_id=row["test_id"]):
                candidate = (
                    coverage_fixture.real_e2e_candidate(
                        accepted=False,
                        profile_id=row["profile_id"],
                        task_id=row["task_id"],
                    )
                    if row["column_id"] == "real-e2e"
                    else coverage_fixture.mandatory_candidate(
                        row["column_id"],
                        profile_id=row["profile_id"],
                        task_id=row["task_id"],
                    )
                )
                self.assertEqual(
                    coverage_fixture.coverage_request_digest(candidate),
                    row["request_digest"],
                )
                if row["column_id"] == "artifacts":
                    self.assertEqual(
                        candidate["scenario_id"],
                        "GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P",
                    )
                    self.assertEqual(
                        row["request_digest"],
                        "sha256-jcs-v1:"
                        "e9315eb7ced2072939c95533b7f8aeb53e11e1e1c137d5e462c69c5130a9b938",
                    )
                    substituted = copy.deepcopy(candidate)
                    substituted["scenario_id"] = (
                        "GEW-PSC-DEPENDENCY-SECURITY-VULNERABLE-GRAPH-P"
                    )
                    self.assertNotEqual(
                        coverage_fixture.coverage_request_digest(substituted),
                        row["request_digest"],
                    )

    def test_action_provenance_has_two_current_non_interchangeable_runtime_branches(self) -> None:
        default_policy = _document("config/actions/action-policy-v1.json")
        local_policy = _document("config/actions/action-policy-local-actions-v1.json")
        default_runtime = _document("config/security/security-runtime-v1.json")
        local_runtime = _document(
            "config/security/security-runtime-local-actions-v1.json"
        )

        self.assertEqual(
            default_runtime["manifest_digest"],
            SecurityRuntimeManifest.digest_document(default_runtime),
        )
        self.assertEqual(
            local_runtime["manifest_digest"],
            SecurityRuntimeManifest.digest_document(local_runtime),
        )
        self.assertEqual(
            default_policy["policy_digest"],
            unsigned_digest(
                default_policy,
                digest_field="policy_digest",
                contract_type="urn:gew:contract:action-policy",
                schema_id="urn:gew:schema:action-policy:1.0.0",
            ),
        )
        self.assertEqual(
            local_policy["policy_digest"],
            unsigned_digest(
                local_policy,
                digest_field="policy_digest",
                contract_type="urn:gew:contract:action-policy",
                schema_id="urn:gew:schema:action-policy:1.0.0",
            ),
        )
        self.assertEqual(
            default_policy["concrete_action_authority"],
            local_policy["concrete_action_authority"],
        )
        self.assertEqual(
            default_policy["separately_authorized_action_kinds"],
            local_policy["separately_authorized_action_kinds"],
        )
        self.assertEqual(
            default_runtime["policies"]["action"],  # type: ignore[index]
            {
                "policy_id": default_policy["policy_id"],
                "policy_digest": default_policy["policy_digest"],
            },
        )
        self.assertEqual(
            local_runtime["policies"]["action"],  # type: ignore[index]
            {
                "policy_id": local_policy["policy_id"],
                "policy_digest": local_policy["policy_digest"],
            },
        )

        default_context, default_schemas, loaded_default = _runtime(
            default_runtime, default_runtime
        )
        local_context, local_schemas, loaded_local = _runtime(
            local_runtime, local_runtime
        )
        ActionPolicy.from_dict(
            default_policy,
            schema_registry=default_schemas,
            context=default_context,
            runtime=loaded_default,
        )
        ActionPolicy.from_dict(
            local_policy,
            schema_registry=local_schemas,
            context=local_context,
            runtime=loaded_local,
        )
        with self.assertRaises(ActionContractError):
            ActionPolicy.from_dict(
                local_policy,
                schema_registry=default_schemas,
                context=default_context,
                runtime=loaded_default,
            )
        with self.assertRaises(ActionContractError):
            ActionPolicy.from_dict(
                default_policy,
                schema_registry=local_schemas,
                context=local_context,
                runtime=loaded_local,
            )

    def test_runtime_topology_attacks_fail_against_installed_current_pins(self) -> None:
        default_policy = _document("config/actions/action-policy-v1.json")
        local_policy = _document("config/actions/action-policy-local-actions-v1.json")
        default_runtime = _document("config/security/security-runtime-v1.json")
        local_runtime = _document(
            "config/security/security-runtime-local-actions-v1.json"
        )

        runtime_attacks: list[dict[str, object]] = []
        for foreign in (local_policy, {"policy_id": "action-policy-old", "policy_digest": "sha256-jcs-v1:" + "0" * 64}):
            changed = copy.deepcopy(default_runtime)
            changed["policies"]["action"] = {  # type: ignore[index]
                "policy_id": foreign["policy_id"],
                "policy_digest": foreign["policy_digest"],
            }
            _resign_runtime(changed)
            runtime_attacks.append(changed)

        missing = copy.deepcopy(default_runtime)
        missing["policies"].pop("action")  # type: ignore[union-attr]
        _resign_runtime(missing)
        runtime_attacks.append(missing)

        extra = copy.deepcopy(default_runtime)
        extra["policies"]["foreign"] = copy.deepcopy(  # type: ignore[index]
            extra["policies"]["action"]  # type: ignore[index]
        )
        _resign_runtime(extra)
        runtime_attacks.append(extra)

        for field in ("peer_runtime", "runtime_manifest_digest"):
            changed = copy.deepcopy(default_runtime)
            changed[field] = local_runtime["manifest_digest"]
            _resign_runtime(changed)
            runtime_attacks.append(changed)

        coherent_policy = copy.deepcopy(default_policy)
        coherent_policy["unknown_routes"] = [
            *coherent_policy["unknown_routes"],  # type: ignore[list-item]
            "foreign-route",
        ]
        coherent_policy["unknown_routes"].sort()  # type: ignore[union-attr]
        _resign_action_policy(coherent_policy)
        coherent_runtime = copy.deepcopy(default_runtime)
        coherent_runtime["policies"]["action"] = {  # type: ignore[index]
            "policy_id": coherent_policy["policy_id"],
            "policy_digest": coherent_policy["policy_digest"],
        }
        _resign_runtime(coherent_runtime)
        runtime_attacks.append(coherent_runtime)

        for index, changed in enumerate(runtime_attacks):
            with self.subTest(runtime_attack=index), self.assertRaises(
                SecurityAttestationError
            ):
                _runtime(changed, default_runtime)

        cycle = copy.deepcopy(default_policy)
        cycle["runtime_manifest_digest"] = default_runtime["manifest_digest"]
        _resign_action_policy(cycle)
        context, schemas, runtime = _runtime(default_runtime, default_runtime)
        with self.assertRaises(ActionContractError):
            ActionPolicy.from_dict(
                cycle,
                schema_registry=schemas,
                context=context,
                runtime=runtime,
            )

    def test_c_envelope_and_dual_runtime_source_membership_are_exact(self) -> None:
        envelope = _document(
            ".workflow/delivery/GEW-REMAINING54-V1/authority-envelope.json"
        )
        targets = envelope["allowed_targets"]
        self.assertEqual(len(targets), 183)  # type: ignore[arg-type]
        self.assertEqual(len(set(targets)), 183)  # type: ignore[arg-type]
        record = _document(
            ".workflow/delivery/GEW-REMAINING54-V1/human-decision-p1-p2-p3-r0.json"
        )
        bridge = record["p3_restart_bridge_security_amendment"]
        bridge_targets = {
            "application/graph_engineering/application/security.py",
            "storage/graph_engineering/storage/security.py",
        }
        self.assertEqual(set(bridge["approved_target_boundary_additions"]), bridge_targets)
        self.assertEqual(bridge["user_message"], "批准")
        self.assertEqual(bridge["previous_allowed_target_count"], 181)
        self.assertEqual(bridge["current_allowed_target_count"], 183)
        self.assertLessEqual(bridge_targets, set(targets))
        targets = set(targets) - bridge_targets
        restart = record["p3_restart_implementation_amendment"]
        restart_targets = {
            "config/contracts/schemas/release-recovery-binding-1.0.0.json",
            "config/contracts/schemas/release-recovery-binding-input-1.0.0.json",
        }
        self.assertEqual(set(restart["approved_target_boundary_additions"]), restart_targets)
        self.assertEqual(restart["user_message"], "批准")
        self.assertEqual(restart["previous_allowed_target_count"], 179)
        self.assertEqual(restart["current_allowed_target_count"], 181)
        self.assertLessEqual(restart_targets, set(targets))
        targets = set(targets) - restart_targets
        p3_amendment = record["p3_foundation_record_and_contract_amendment"]
        p3_targets = {
            "tests/contract/test_wp07a_action_contracts.py",
            ".workflow/delivery/GEW-REMAINING54-V1/p3-foundation-source-manifest-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p3-foundation-state-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p3-foundation-review-verdict-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p3-foundation-decision-r2.json",
        }
        self.assertEqual(
            set(p3_amendment["approved_target_boundary_addition"]), p3_targets,
        )
        self.assertEqual(p3_amendment["human_approval"], "明确批准这五个路径")
        self.assertEqual(p3_amendment["previous_allowed_target_count"], 174)
        self.assertEqual(p3_amendment["current_allowed_target_count"], 179)
        self.assertLessEqual(p3_targets, set(targets))
        self.assertEqual(len(set(targets) - p3_targets), 174)
        historical_identity = json.dumps(
            sorted(set(targets) - p3_targets),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        # Frozen from the approved exact174 envelope at base 1f77f735f3036c9.
        self.assertEqual(
            hashlib.sha256(historical_identity).hexdigest(),
            "dad52f1888bf262ce9ddd4b6528a2ca634e2ff0a06a8cd51c2a1ddffe870a7e9",
            "historical exact174 target identities changed",
        )
        repair = record["memory_repair_amendment"]
        repair_targets = {
            "core/graph_engineering/core/contracts/resources.py",
            "tests/support/wp05_actions.py",
            ".workflow/delivery/GEW-REMAINING54-V1/p2-scenarios-source-manifest-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p2-scenarios-state-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p2-scenarios-review-verdict-r2.json",
            ".workflow/delivery/GEW-REMAINING54-V1/p2-scenarios-decision-r2.json",
        }
        self.assertEqual(set(repair["approved_target_boundary_addition"]), repair_targets)
        self.assertEqual(repair["human_approval"], "批准先修复")
        self.assertEqual(repair["previous_allowed_target_count"], 168)
        self.assertEqual(repair["current_allowed_target_count"], 174)
        self.assertLessEqual(repair_targets, set(targets))
        historical_targets = set(targets) - repair_targets - p3_targets
        f1_target = "application/graph_engineering/application/dependency_security.py"
        d_target = "tests/security/test_wp07a_action_contract_security.py"
        self.assertIn(f1_target, targets)
        self.assertIn(d_target, targets)
        self.assertEqual(len(historical_targets - {f1_target}), 167)
        self.assertEqual(len(historical_targets - {f1_target, d_target}), 166)
        amendment = _document(
            ".workflow/delivery/GEW-REMAINING54-V1/human-decision-p1-p2-p3-r0.json"
        )["f1_amendment"]
        self.assertEqual(
            amendment["approved_target_boundary_addition"], [f1_target],  # type: ignore[index]
        )
        self.assertEqual(amendment["current_allowed_target_count"], 168)  # type: ignore[index]
        self.assertNotIn("tests/support/wp08_dependency_security.py", targets)
        self.assertNotIn("tests/support/wp08_migration_rehearsal.py", targets)
        self.assertIn("config/security/security-runtime-v1.json", targets)
        self.assertNotIn("scripts/evidence_utils.py", targets)
        self.assertNotIn("scripts/build_backend.py", targets)

        required = {
            "config/actions/action-policy-local-actions-v1.json",
            "config/actions/action-policy-v1.json",
            "config/actions/concrete-action-policy-v1.json",
            "config/contracts/action-adapter-registry-v1.json",
            "config/security/security-runtime-local-actions-v1.json",
            "config/security/security-runtime-v1.json",
        }
        source_targets = set(
            _document("config/verification/wp-00-targets.json")["files"]  # type: ignore[arg-type]
        )
        self.assertLessEqual(required, source_targets)

    def test_equal_cardinality_historical_authority_substitution_is_rejected(self) -> None:
        original_document = _document
        envelope_path = ".workflow/delivery/GEW-REMAINING54-V1/authority-envelope.json"

        def substituted_document(relative: str) -> dict[str, object]:
            document = original_document(relative)
            if relative == envelope_path:
                targets = document["allowed_targets"]
                index = targets.index("docs/adr/0009-offline-release-operations-simulator-authority.md")
                targets[index] = "docs/adr/unauthorized-equal-cardinality-substitution.md"
                self.assertEqual(len(targets), 183)
                self.assertEqual(len(set(targets)), 183)
            return document

        with mock.patch(__name__ + "._document", side_effect=substituted_document):
            with self.assertRaisesRegex(AssertionError, "historical exact174 target identities"):
                self.test_c_envelope_and_dual_runtime_source_membership_are_exact()

    def test_registry_and_observer_authorities_are_factory_local(self) -> None:
        first = ScenarioTruthRegistryFactory.from_installation()
        second = ScenarioTruthRegistryFactory.from_installation()
        root = tempfile.TemporaryDirectory(prefix="gew-scenario-authority-")
        try:
            authority = first.registry()
            with self.assertRaises(ScenarioTruthError):
                second.observation_factory(
                    authority,
                    binding=ScenarioTruthAuthorityTests.binding(),
                    private_root=root.name,
                )
            with self.assertRaises(ScenarioTruthError):
                first.observation_factory(
                    type(authority)(authority._factory, authority.registry),
                    binding=ScenarioTruthAuthorityTests.binding(),
                    private_root=root.name,
                )
            forged = object.__new__(ScenarioTruthObservationFactory)
            with self.assertRaises(ScenarioTruthError):
                first.require_observer(forged)
        finally:
            first.close()
            second.close()
            root.cleanup()

    def test_symlink_substitution_is_rejected_before_scenario_mutation(self) -> None:
        factory = ScenarioTruthRegistryFactory.from_installation()
        root = tempfile.TemporaryDirectory(prefix="gew-scenario-symlink-")
        foreign = tempfile.NamedTemporaryFile(prefix="gew-scenario-foreign-", delete=False)
        foreign.write(b"foreign\n")
        foreign.close()
        try:
            observer = factory.observation_factory(
                factory.registry(),
                binding=ScenarioTruthAuthorityTests.binding(),
                private_root=root.name,
            )
            path = pathlib.Path(root.name) / "targets/component-a.state"
            path.unlink()
            path.symlink_to(foreign.name)
            before = pathlib.Path(foreign.name).read_bytes()
            with self.assertRaises(ScenarioTruthError):
                observer.execute(observer.request())
            self.assertEqual(observer.mutation_count, 0)
            self.assertEqual(pathlib.Path(foreign.name).read_bytes(), before)
        finally:
            factory.close()
            root.cleanup()
            os.unlink(foreign.name)


if __name__ == "__main__":
    unittest.main()
