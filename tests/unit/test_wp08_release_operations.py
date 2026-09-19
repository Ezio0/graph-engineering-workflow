from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import pathlib
import tomllib
import unittest
from unittest import mock

from graph_engineering.adapters.local_release_simulator import ReleaseSimulatorError
from graph_engineering.application.release_operations import (
    ReleaseOperationsRegistryFactory,
    _semantic,
)
from graph_engineering.application.profile_execution import (
    CategoryCompletionOracle,
    CategoryExecutionError,
    CategoryExecutionPolicy,
    CategoryTargetObservationAuthority,
)
from graph_engineering.core.release_operations import (
    RELEASE_OPERATIONS_SCHEMA_IDS,
    ReleaseArtifactManifest,
    ReleaseOperationsError,
    ReleaseOperationsRegistry,
)
from tests.support.wp05_actions import action_stack, authority_document
from tests.support import wp08_category_execution as category_fixture
from tests.support.wp08_release_operations import (
    artifact_bytes,
    release_disclosure_plan,
    release_prepared_document,
    release_restore_prepared_document,
    retarget_security_binding,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "release-operations"


class WP08ReleaseOperationsFoundationTests(unittest.TestCase):
    @staticmethod
    def installation_documents() -> dict[str, object]:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        return {
            "policy_bytes": (ROOT / pin["policy-source"]).read_bytes(),
            "fixture_bytes": (ROOT / pin["fixture-source"]).read_bytes(),
            "bootstrap_bytes": (ROOT / pin["bootstrap-source"]).read_bytes(),
            "profile_schema_registry_bytes": (
                ROOT / pin["profile-schema-registry-source"]
            ).read_bytes(),
            "package_provenance_bytes": (ROOT / "pyproject.toml").read_bytes(),
            "schema_bodies": {
                json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
                for path in pin["schema-sources"]
            },
            "protected_resources": {
                path: (ROOT / path).read_bytes() for path in pin["protected-sources"]
            },
        }

    def registry(self) -> ReleaseOperationsRegistry:
        return ReleaseOperationsRegistry.from_dicts(
            json.loads((CONFIG / "release-operations-policy-registry-v1.json").read_text()),
            json.loads((CONFIG / "release-simulator-fixture-registry-v1.json").read_text()),
        )

    @staticmethod
    def issued_artifacts(
        factory: ReleaseOperationsRegistryFactory,
    ) -> tuple[ReleaseArtifactManifest, bytes, ReleaseArtifactManifest, bytes]:
        baseline = factory.issue_artifact_manifest(
            fixture_id="release-foundation-v1", artifact_id="artifact-a",
        )
        candidate = factory.issue_artifact_manifest(
            fixture_id="release-foundation-v1", artifact_id="artifact-b",
        )
        baseline_bytes = factory.artifact_bytes(baseline)
        candidate_bytes = factory.artifact_bytes(candidate)
        if (baseline_bytes, candidate_bytes) != artifact_bytes():
            raise AssertionError("installed fixture artifact bytes changed")
        return baseline, baseline_bytes, candidate, candidate_bytes

    def session(
        self,
        factory: ReleaseOperationsRegistryFactory,
        fixture,
        *,
        fault_hook=lambda _step: None,
    ):  # type: ignore[no-untyped-def]
        baseline, baseline_bytes, candidate, candidate_bytes = self.issued_artifacts(factory)
        session = factory.issue_simulator(
            action_coordinator=fixture.raw_coordinator,
            task_id="task-wp05",
            fixture_id="release-foundation-v1",
            target_id="target-project",
            resource_id="target:project",
            baseline_manifest=baseline,
            authorized_artifacts=(baseline, candidate),
            fault_hook=fault_hook,
        )
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        return session, baseline, baseline_bytes, candidate, candidate_bytes

    def execute_apply(
        self,
        fixture,
        session,
        baseline,
        candidate,
        candidate_bytes,
    ):  # type: ignore[no-untyped-def]
        document = release_prepared_document(
            fixture,
            target_digest=session.target.target_digest,
            baseline=baseline,
            candidate=candidate,
            candidate_bytes=candidate_bytes,
        )
        prepared = fixture.coordinator.prepare(document)
        fixture.coordinator.authorize(authority_document(
            prepared, context=fixture.context,
        ))
        outcome = fixture.coordinator.execute(
            prepared.action_id,
            owner_id="owner-wp05",
            runtime_kind="codex",
            runtime_lineage_id="lineage-wp05",
            lease=fixture.action_lease,
            target=session.target,
            observer=session.observer,
            disclosure_plan=release_disclosure_plan(fixture, prepared),
        )
        return prepared, outcome

    def test_eight_schema_pairs_are_exact_and_release_only(self) -> None:
        names = (
            "category-completion-assessment",
            "release-artifact-manifest",
            "release-deployment-observation",
            "release-health-observation",
            "release-operations-installation-bootstrap",
            "release-operations-observation",
            "release-operations-policy-registry",
            "release-simulator-fixture-registry",
        )
        expected = tuple(sorted(
            f"urn:gew:schema:{name}{suffix}:{'1.4.0' if name == 'category-completion-assessment' else '1.0.0'}"
            for name in names for suffix in ("", "-input")
        ))
        self.assertEqual(RELEASE_OPERATIONS_SCHEMA_IDS, expected)

    def test_policy_fixture_registry_is_closed_and_self_digest_bound(self) -> None:
        registry = self.registry()
        self.assertEqual(len(registry.operation_ids), 3)
        self.assertEqual(len(registry.fault_points), 5)
        policy = json.loads(
            (CONFIG / "release-operations-policy-registry-v1.json").read_text()
        )
        policy["deployment_policy"]["operation_ids"].append("release.real")
        with self.assertRaises(ReleaseOperationsError):
            ReleaseOperationsRegistry.from_dicts(
                policy,
                json.loads(
                    (CONFIG / "release-simulator-fixture-registry-v1.json").read_text()
                ),
            )

    def test_installed_bootstrap_and_protected_closure_are_current(self) -> None:
        factory = ReleaseOperationsRegistryFactory.from_installation()
        self.assertEqual(len(factory.registry().operation_ids), 3)

    def test_non_installation_factories_cannot_issue_or_enter_oracle(self) -> None:
        documents = self.installation_documents()
        schema_bodies = documents["schema_bodies"]
        self.assertIsInstance(schema_bodies, dict)
        bootstrap_bytes = documents["bootstrap_bytes"]
        self.assertIsInstance(bootstrap_bytes, bytes)

        def assert_zero_issuance(factory: ReleaseOperationsRegistryFactory) -> None:
            self.assertEqual(factory._issued, {})
            self.assertEqual(factory._issued_manifests, {})
            self.assertEqual(factory._issued_sessions, {})
            self.assertEqual(factory._issued_deployments, {})
            self.assertEqual(factory._issued_health, {})

        direct_fixture = json.loads(documents["fixture_bytes"])
        direct_fixture["fixtures"][0]["artifact_vectors"][0][
            "artifact_base64"
        ] = base64.b64encode(b"direct-constructor-artifact\n").decode("ascii")
        direct_fixture.pop("registry_digest")
        direct_fixture["registry_digest"] = _semantic(
            direct_fixture, "release-simulator-fixture-registry",
        )

        direct = ReleaseOperationsRegistryFactory(
            ReleaseOperationsRegistry.from_dicts(
                json.loads(documents["policy_bytes"]), direct_fixture,
            ),
            json.loads(bootstrap_bytes),
            schema_documents={
                schema_id: json.loads(body)
                for schema_id, body in schema_bodies.items()
            },
            currentness_check=lambda: None,
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            direct.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(direct)

        validation_only = ReleaseOperationsRegistryFactory.from_documents(**documents)
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            validation_only.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(validation_only)

        forged_fixture = json.loads(documents["fixture_bytes"])
        forged_fixture["fixtures"][0]["artifact_vectors"][0][
            "artifact_base64"
        ] = base64.b64encode(b"caller-owned-artifact\n").decode("ascii")
        forged_fixture.pop("registry_digest")
        forged_fixture["registry_digest"] = _semantic(
            forged_fixture, "release-simulator-fixture-registry",
        )
        forged_fixture_bytes = (
            json.dumps(forged_fixture, indent=2).encode("utf-8") + b"\n"
        )
        forged_fixture_bootstrap = json.loads(bootstrap_bytes)
        forged_fixture_bootstrap["fixture_registry_digest"] = forged_fixture[
            "registry_digest"
        ]
        forged_fixture_bootstrap["fixture_registry_raw_sha256"] = hashlib.sha256(
            forged_fixture_bytes
        ).hexdigest()
        forged_fixture_bootstrap.pop("bootstrap_digest")
        forged_fixture_bootstrap["bootstrap_digest"] = _semantic(
            forged_fixture_bootstrap, "release-operations-installation-bootstrap",
        )
        fixture_factory = ReleaseOperationsRegistryFactory.from_documents(
            **{
                **documents,
                "fixture_bytes": forged_fixture_bytes,
                "bootstrap_bytes": (
                    json.dumps(forged_fixture_bootstrap, indent=2).encode("utf-8")
                    + b"\n"
                ),
            },
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            fixture_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(fixture_factory)

        forged_schema_bodies = dict(schema_bodies)
        forged_schema_id = "urn:gew:schema:release-artifact-manifest:1.0.0"
        forged_schema_bodies[forged_schema_id] = json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": forged_schema_id,
            "type": "object",
        }).encode("utf-8")
        forged_schema_bootstrap = json.loads(bootstrap_bytes)
        for row in forged_schema_bootstrap["schema_vectors"]:
            if row["schema_id"] == forged_schema_id:
                row["raw_sha256"] = hashlib.sha256(
                    forged_schema_bodies[forged_schema_id]
                ).hexdigest()
        forged_schema_bootstrap.pop("bootstrap_digest")
        forged_schema_bootstrap["bootstrap_digest"] = _semantic(
            forged_schema_bootstrap, "release-operations-installation-bootstrap",
        )
        schema_factory = ReleaseOperationsRegistryFactory.from_documents(
            **{
                **documents,
                "bootstrap_bytes": (
                    json.dumps(forged_schema_bootstrap, indent=2).encode("utf-8")
                    + b"\n"
                ),
                "schema_bodies": forged_schema_bodies,
            },
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            schema_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(schema_factory)

        profile_id = "release-operations"
        materialized = category_fixture.materialized_profile(profile_id)
        policy = CategoryExecutionPolicy.from_installation(
            profile_document=category_fixture.profile_document(profile_id),
            support_matrix_document=category_fixture.load_json(
                category_fixture.SUPPORT_MATRIX_PATH
            ),
            materialization_record=materialized.record,
        )
        with self.assertRaisesRegex(CategoryExecutionError, "authority is invalid"):
            CategoryCompletionOracle(
                policy=policy,
                target_authority=CategoryTargetObservationAuthority(policy),
                release_operations_factory=validation_only,
            )
        assert_zero_issuance(validation_only)

    def test_action_source_and_package_pin_substitutions_fail_closed(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        policy_bytes = (ROOT / pin["policy-source"]).read_bytes()
        fixture_bytes = (ROOT / pin["fixture-source"]).read_bytes()
        bootstrap = json.loads((ROOT / pin["bootstrap-source"]).read_bytes())
        profile_bytes = (ROOT / pin["profile-schema-registry-source"]).read_bytes()
        provenance_bytes = (ROOT / "pyproject.toml").read_bytes()
        schema_bodies = {
            json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
            for path in pin["schema-sources"]
        }
        protected = {
            path: (ROOT / path).read_bytes() for path in pin["protected-sources"]
        }
        mutations = (
            (
                "action authority pin",
                lambda value: value["action_authority_pins"].__setitem__(
                    "adapter_registry_digest", "sha256-jcs-v1:" + "f" * 64,
                ),
            ),
            (
                "source authority pin",
                lambda value: value["source_authority_pins"].__setitem__(
                    "source_file_count",
                    value["source_authority_pins"]["source_file_count"] + 1,
                ),
            ),
            (
                "package authority pin",
                lambda value: value["package_authority_pins"].__setitem__(
                    "distribution_name", "foreign-distribution",
                ),
            ),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                changed = copy.deepcopy(bootstrap)
                mutate(changed)
                changed.pop("bootstrap_digest")
                changed["bootstrap_digest"] = _semantic(
                    changed, "release-operations-installation-bootstrap",
                )
                with self.assertRaisesRegex(ReleaseOperationsError, expected):
                    ReleaseOperationsRegistryFactory.from_documents(
                        policy_bytes=policy_bytes,
                        fixture_bytes=fixture_bytes,
                        bootstrap_bytes=(
                            json.dumps(changed, indent=2).encode("utf-8") + b"\n"
                        ),
                        profile_schema_registry_bytes=profile_bytes,
                        package_provenance_bytes=provenance_bytes,
                        schema_bodies=schema_bodies,
                        protected_resources=protected,
                    )

        import graph_engineering

        installed = graph_engineering._release_operations_installation_resources()
        text = installed[0].decode("utf-8")
        marker = "[tool.gew.profile.release-operations]"
        before, section = text.split(marker, 1)
        section = section.replace(
            'distribution-name = "graph-engineering-workflow"',
            'distribution-name = "foreign-distribution"',
            1,
        )
        substituted = ((before + marker + section).encode("utf-8"), *installed[1:])
        with mock.patch.object(
            graph_engineering,
            "_release_operations_installation_resources",
            return_value=substituted,
        ), self.assertRaisesRegex(ReleaseOperationsError, "independent installation pin"):
            ReleaseOperationsRegistryFactory.from_installation()

    def test_validation_only_factory_still_enforces_currentness(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        policy_bytes = (ROOT / pin["policy-source"]).read_bytes()
        fixture_bytes = (ROOT / pin["fixture-source"]).read_bytes()
        bootstrap_bytes = (ROOT / pin["bootstrap-source"]).read_bytes()
        profile_bytes = (ROOT / pin["profile-schema-registry-source"]).read_bytes()
        package_provenance_bytes = (ROOT / "pyproject.toml").read_bytes()
        schema_bodies = {
            json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
            for path in pin["schema-sources"]
        }
        protected = {path: (ROOT / path).read_bytes() for path in pin["protected-sources"]}
        current = {
            "policy": policy_bytes,
            "fixture": fixture_bytes,
            "bootstrap": bootstrap_bytes,
            "profile-schema-registry": profile_bytes,
            "package-provenance": package_provenance_bytes,
            **{f"schema:{key}": value for key, value in schema_bodies.items()},
            **{f"protected:{key}": value for key, value in protected.items()},
        }
        factory = ReleaseOperationsRegistryFactory.from_documents(
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            bootstrap_bytes=bootstrap_bytes,
            profile_schema_registry_bytes=profile_bytes,
            package_provenance_bytes=package_provenance_bytes,
            schema_bodies=schema_bodies,
            protected_resources=protected,
            current_resource_reader=lambda: current,
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        self.assertEqual(factory._issued_manifests, {})
        current["policy"] += b"\n"
        with self.assertRaisesRegex(ReleaseOperationsError, "currentness"):
            factory.registry()

    def test_manifest_and_mutation_capabilities_are_factory_confined(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                payload = {
                    "operation_id": "local-release-simulator.apply",
                    "expected_generation": 0,
                    "artifact_manifest": candidate.to_dict(),
                    "artifact_bytes_base64": base64.b64encode(candidate_bytes).decode(),
                }
                gate = session.target._durable_execution_gate
                self.assertFalse(hasattr(gate, "_arm"))
                self.assertFalse(hasattr(gate, "_issuer"))
                before = session.tree_digest()
                with self.assertRaisesRegex(ReleaseSimulatorError, "coordinator capability"):
                    session.target.invoke(
                        payload=payload, fencing_token=1, started_was_durable=True,
                    )
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 0)
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "fixture artifact identity",
                ):
                    factory.issue_artifact_manifest(
                        fixture_id="release-foundation-v1",
                        artifact_id="caller-controlled",
                    )
                clone = ReleaseArtifactManifest.from_dict(copy.deepcopy(baseline.to_dict()))
                with self.assertRaisesRegex(ReleaseOperationsError, "artifact authority"):
                    factory.issue_simulator(
                        action_coordinator=fixture.raw_coordinator,
                        task_id="task-wp05",
                        fixture_id="release-foundation-v1",
                        target_id="target-project-foreign",
                        resource_id="target:project",
                        baseline_manifest=clone,
                        authorized_artifacts=(clone,),
                    )

    def test_root_replacement_after_fault_hook_fails_before_write(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            holder: dict[str, object] = {}

            def fault(step: str) -> None:
                if step != "before-stage-write":
                    return
                session = holder["session"]
                root = session._root._root_path  # type: ignore[attr-defined]
                moved = root.with_name(root.name + ".moved")
                os.replace(root, moved)
                os.symlink(moved, root)
                holder["root"] = root
                holder["moved"] = moved

            session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture, fault_hook=fault,
            )
            holder["session"] = session
            try:
                with self.assertRaisesRegex(ReleaseSimulatorError, "root identity"):
                    self.execute_apply(
                        fixture, session, baseline, candidate, candidate_bytes,
                    )
                self.assertEqual(session.target.apply_count, 0)
            finally:
                root = holder.get("root")
                moved = holder.get("moved")
                if root is not None and moved is not None:
                    os.unlink(root)  # type: ignore[arg-type]
                    os.replace(moved, root)  # type: ignore[arg-type]
                session.close()

    def test_all_fault_cuts_preserve_queryable_atomic_states(self) -> None:
        expectations = {
            "before-stage-write": (0, "baseline", None, 0),
            "after-stage-durable": (0, "baseline", "candidate", 0),
            "before-active-switch": (0, "baseline", "candidate", 0),
            "after-active-switch-durable": (1, "candidate", "candidate", 1),
            "before-health-observe": (1, "candidate", "candidate", 1),
        }
        for fault_point, expected in expectations.items():
            with self.subTest(fault_point=fault_point), action_stack() as fixture:
                factory = ReleaseOperationsRegistryFactory.from_installation()

                def fault(step: str, *, selected=fault_point) -> None:
                    if step == selected:
                        raise TimeoutError("configured cut")

                session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                    factory, fixture, fault_hook=fault,
                )
                with session:
                    _prepared, outcome = self.execute_apply(
                        fixture, session, baseline, candidate, candidate_bytes,
                    )
                    self.assertEqual(outcome.route, "manual-reconciliation")
                    state = session.observer.observe()["state"]
                    generation, active, staged, mutations = expected
                    self.assertEqual(state["generation"], generation)
                    self.assertEqual(
                        state["active_artifact_digest"],
                        baseline.manifest_digest if active == "baseline" else candidate.manifest_digest,
                    )
                    self.assertEqual(
                        state["staged_artifact_digest"],
                        None if staged is None else candidate.manifest_digest,
                    )
                    self.assertEqual(session.target.apply_count, mutations)
                    if fault_point in {"after-stage-durable", "before-active-switch"}:
                        reconciled = fixture.coordinator.reconcile_unknown(
                            "action-wp05",
                            lease=fixture.action_lease,
                            observer=session.observer,
                        )
                        self.assertEqual(reconciled.route, "manual-reconciliation")
                        self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_exact_original_receipt_restores_exact_baseline(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                _prepared, outcome = self.execute_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                forged = object.__new__(type(outcome))
                for field in (
                    "action_id", "state", "route", "claim_id", "receipt_digest",
                ):
                    object.__setattr__(forged, field, getattr(outcome, field))
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "coordinator-issued/current",
                ):
                    factory.issue_deployment_observation(
                        action_coordinator=fixture.raw_coordinator,
                        session=session,
                        outcome=forged,
                    )
                factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                restore_document = release_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=outcome.claim_id,
                    original_receipt_digest=str(outcome.receipt_digest),
                )
                prepared = fixture.coordinator.prepare(restore_document)
                fixture.coordinator.authorize(authority_document(
                    prepared, context=fixture.context,
                ))
                restored = fixture.coordinator.execute(
                    prepared.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=fixture.action_lease,
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, prepared),
                )
                self.assertEqual(restored.route, "reconciled-effect-verified")
                state = session.observer.observe()["state"]
                self.assertEqual(state["generation"], 2)
                self.assertEqual(state["active_artifact_digest"], baseline.manifest_digest)

    def test_wrong_restore_receipt_fails_before_restore_mutation(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                _prepared, outcome = self.execute_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                restore_document = release_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=outcome.claim_id,
                    original_receipt_digest="sha256-jcs-v1:" + "f" * 64,
                )
                prepared = fixture.coordinator.prepare(restore_document)
                fixture.coordinator.authorize(authority_document(
                    prepared, context=fixture.context,
                ))
                before = session.tree_digest()
                with self.assertRaisesRegex(ReleaseSimulatorError, "original receipt"):
                    fixture.coordinator.execute(
                        prepared.action_id,
                        owner_id="owner-wp05",
                        runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05",
                        lease=fixture.action_lease,
                        target=session.target,
                        observer=session.observer,
                        disclosure_plan=release_disclosure_plan(fixture, prepared),
                    )
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 1)


if __name__ == "__main__":
    unittest.main()
