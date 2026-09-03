"""WP-08 Slice 3 RED: authoritative category execution and completion."""

from __future__ import annotations

import copy
import inspect
import unittest

from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.profiles import ReleaseCoverageGate
from tests.support import wp08_category_execution as fixture
from tests.unit import test_wp08_profile_contracts as slice1


class WP08CategoryExecutionTests(unittest.TestCase):
    maxDiff = None

    def _load_contract_or_red(
        self,
        repository: fixture.RecordingCategoryRepository,
        candidate: dict[str, object],
    ) -> fixture.Slice3API:
        before_repository = repository.signature()
        before_candidate = copy.deepcopy(candidate)
        try:
            api = fixture.load_slice3_api()
        except fixture.MissingCategoryExecutionContract as error:
            self.assertEqual(repository.signature(), before_repository)
            self.assertEqual(candidate, before_candidate)
            self.fail(str(error))
        self.assertTrue(fixture.CATEGORY_POLICY_PATH.is_file())
        self.assertTrue(set(fixture.REQUIRED_SCHEMA_IDS).issubset(
            fixture.profile_schema_ids()
        ))
        fixture.assert_frozen_policy_and_schema_contract()
        return api

    def _runtime(
        self,
        profile_id: str,
        column: str,
        *,
        fault_hook=lambda _step: None,  # noqa: B008
    ):
        api = fixture.load_slice3_api()
        profile = fixture.profile_document(profile_id)
        materialized = fixture.materialized_profile(profile_id)
        policy = api.CategoryExecutionPolicy.from_installation(
            profile_document=profile,
            support_matrix_document=fixture.load_json(fixture.SUPPORT_MATRIX_PATH),
            materialization_record=materialized.record,
        )
        target = fixture.DisposableLocalTarget(profile_id)
        (
            task_application,
            repository,
            objects,
            runtime,
            probe,
        ) = fixture.production_category_runtime(
            profile_id, column, target=target,
        )
        authority = api.CategoryTargetObservationAuthority(policy)
        oracle = api.CategoryCompletionOracle(
            policy=policy,
            target_authority=authority,
        )
        action_coordinator, action_context = fixture.action_rollback_binding(
            probe, target,
        )
        rollback = api.CategoryRollbackBridge(policy, action_coordinator)
        rollback.prepare_action(**action_context)
        probe.bind_rollback_evidence(rollback)
        resolver = api.CategoryAssessmentResolver(
            repository,
            objects,
            task_application=task_application,
            runtime=runtime,
        )
        application = api.CategoryExecutionApplication(
            repository=repository,
            object_repository=objects,
            policy=policy,
            reducer=api.CategoryExecutionReducer(policy),
            completion_oracle=oracle,
            rollback_bridge=rollback,
            assessment_resolver=resolver,
            fault_hook=fault_hook,
            task_application=task_application,
            runtime=runtime,
            target_observer=target,
        )
        application.bind_current_sources(probe.task_id)
        return api, application, probe, target

    @staticmethod
    def _assert_release_gate_false() -> None:
        api = slice1._profile_api()
        matrix = api.SupportMatrixDefinition.from_dict(
            slice1._support_matrix_document(),
            approved_profiles=slice1._approved_registry(),
            coverage_policy=slice1._coverage_policy(),
        )
        coverage_policy = slice1._coverage_policy()
        observation_registry = api.EvidenceObservationRegistry.from_dict(
            slice1._evidence_registry_document(),
            coverage_policy=coverage_policy,
            oracle_manifest_bytes=slice1._oracle_manifest_bytes(),
        )
        observation_authority = api.EvidenceObservationAuthority(
            observation_registry,
            evidence_root=slice1.ROOT / "tests/fixtures",
        )
        coverage_factory = api.CoverageRecordFactory(
            authority=observation_authority,
            coverage_policy=coverage_policy,
        )
        before: tuple[object, ...] = ()
        decision = ReleaseCoverageGate.evaluate(
            matrix,
            coverage_records=before,
            coverage_factory=coverage_factory,
        )
        if decision.passed or len(decision.missing_test_ids) != 274:
            raise AssertionError("Slice 3 local fixtures must leave 274 coverage cells missing")

    def _assert_profile_positive(self, profile_id: str) -> None:
        bootstrap = fixture.RecordingCategoryRepository()
        bootstrap_candidate = fixture.candidate_document(profile_id, "normal")
        self._load_contract_or_red(bootstrap, bootstrap_candidate)
        for column in fixture.COLUMNS:
            api, application, repository, target = self._runtime(profile_id, column)
            candidate = fixture.candidate_document(profile_id, column)
            before_candidate = copy.deepcopy(candidate)
            try:
                receipt = application.assess_and_commit(
                    candidate,
                    observer=target,
                )
                self.assertIs(type(receipt.assessment), api.CategoryCompletionAssessment)
                self.assertEqual(receipt.assessment.status, "PASS")
                self.assertEqual(receipt.assessment.profile_id, profile_id)
                self.assertEqual(receipt.assessment.column_id, column)
                self.assertEqual(len(repository.signature()["events"]), 1)
                self.assertEqual(len(repository.signature()["snapshots"]), 1)
                self.assertEqual(len(repository.signature()["object_references"]), 1)
                restarted_task, restarted_runtime = repository.restart_authorities()
                restarted = application.restart(
                    restarted_task, restarted_runtime, target,
                )
                current = restarted.current_assessment(
                    candidate["task_id"],
                    expected_profile_id=profile_id,
                )
                self.assertIs(type(current), api.CategoryCompletionAssessment)
                self.assertIsNot(current, receipt.assessment)
                self.assertEqual(
                    current.assessment_digest,
                    receipt.assessment.assessment_digest,
                )
                duplicate = restarted.assess_and_commit(candidate, observer=target)
                self.assertTrue(duplicate.idempotent_replay)
                self.assertEqual(len(repository.signature()["events"]), 1)
                self.assertEqual(candidate, before_candidate)
                if column == "boundary":
                    registered = fixture.profile_document(profile_id)[
                        "category_boundary_case_ids"
                    ]
                    self.assertEqual(
                        receipt.assessment.category_boundary_case_ids,
                        tuple(registered),
                    )
                if column == "recovery":
                    self.assertEqual(target.mutation_count, 0)
                if profile_id == "new-feature" and column == "normal":
                    schemas, context = fixture.category_schema_registry()
                    canonical = fixture.load_json_bytes(
                        receipt.assessment.to_bytes()
                    )
                    self.assertEqual(
                        schemas.validate(
                            "urn:gew:schema:category-completion-assessment:1.0.0",
                            canonical,
                            context,
                        ),
                        [],
                    )
                    for label, mutate in (
                        ("null", lambda value: value.__setitem__("task_id", None)),
                        ("wrong-type", lambda value: value.__setitem__("task_revision", True)),
                        ("missing", lambda value: value.pop("column_id")),
                        ("extra", lambda value: value.__setitem__("forged", True)),
                        (
                            "nested-extra",
                            lambda value: value["materialization_pins"].__setitem__(
                                "forged", fixture.digest("forged")
                            ),
                        ),
                        (
                            "duplicate",
                            lambda value: value["authority_refs"].append(
                                value["authority_refs"][0]
                            ),
                        ),
                    ):
                        changed = copy.deepcopy(canonical)
                        mutate(changed)
                        with self.subTest(finding="WP08-S3-R1-007", schema=label):
                            self.assertTrue(schemas.validate(
                                "urn:gew:schema:category-completion-assessment:1.0.0",
                                changed,
                                context,
                            ))
                    duplicate_json = receipt.assessment.to_bytes().replace(
                        b'"task_id":',
                        b'"task_id":"duplicate","task_id":',
                        1,
                    )
                    with self.subTest(finding="WP08-S3-R1-007", schema="duplicate-json"):
                        with self.assertRaises(api.CategoryExecutionError):
                            application._oracle.restore(duplicate_json)
            finally:
                target.close()
        self._assert_release_gate_false()

    def _assert_profile_rejections(self, profile_id: str) -> None:
        bootstrap = fixture.RecordingCategoryRepository()
        bootstrap_candidate = fixture.candidate_document(profile_id, "normal")
        self._load_contract_or_red(bootstrap, bootstrap_candidate)
        for column in fixture.COLUMNS:
            api, application, repository, target = self._runtime(profile_id, column)
            baseline = fixture.candidate_document(profile_id, column)
            for label, mutate in fixture.reject_mutations(baseline, target):
                candidate = copy.deepcopy(baseline)
                mutate(candidate)
                before_candidate = copy.deepcopy(candidate)
                before_repository = repository.signature()
                with self.subTest(profile=profile_id, column=column, mutation=label):
                    with self.assertRaises(api.CategoryExecutionError):
                        application.assess_and_commit(candidate, observer=target)
                    self.assertEqual(repository.signature(), before_repository)
                    self.assertEqual(candidate, before_candidate)
            target.close()

        api, application, repository, target = self._runtime(
            profile_id, "boundary"
        )
        candidate = fixture.candidate_document(profile_id, "boundary")
        candidate["scenario_id"] = candidate["scenario_id"].replace(profile_id.upper(), "ALIAS")
        before = repository.signature()
        with self.assertRaises(api.CategoryExecutionError):
            application.assess_and_commit(candidate, observer=target)
        self.assertEqual(repository.signature(), before)
        target.close()

        api, application, repository, target = self._runtime(
            profile_id, "real-e2e"
        )
        local_claim = fixture.assert_local_real_e2e_rejected_input(profile_id)
        before = repository.signature()
        with self.assertRaises(api.CategoryExecutionError):
            application.assess_and_commit(local_claim, observer=target)
        self.assertEqual(repository.signature(), before)
        target.close()

        crash_points = (
            "category-assessment.before-commit",
            "category-assessment.after-commit",
        )
        for crash_point in crash_points:
            calls: list[str] = []

            def fault(step: str, *, crash_point=crash_point) -> None:
                calls.append(step)
                if step == crash_point:
                    raise RuntimeError(crash_point)

            api, application, repository, target = self._runtime(
                profile_id, "recovery", fault_hook=fault
            )
            candidate = fixture.candidate_document(profile_id, "recovery")
            before = repository.signature()
            with self.subTest(profile=profile_id, crash=crash_point):
                with self.assertRaisesRegex(RuntimeError, crash_point):
                    application.assess_and_commit(candidate, observer=target)
                restarted_task, restarted_runtime = repository.restart_authorities()
                restarted = application.restart(
                    restarted_task, restarted_runtime, target,
                )
                if crash_point.endswith("before-commit"):
                    self.assertEqual(repository.signature(), before)
                    self.assertIsNone(restarted.current_assessment(
                        candidate["task_id"], expected_profile_id=profile_id,
                    ))
                else:
                    self.assertEqual(len(repository.signature()["events"]), 1)
                    self.assertIsNotNone(restarted.current_assessment(
                        candidate["task_id"], expected_profile_id=profile_id,
                    ))
                    duplicate = restarted.assess_and_commit(
                        candidate, observer=target
                    )
                    self.assertTrue(duplicate.idempotent_replay)
                    self.assertEqual(len(repository.signature()["events"]), 1)
                self.assertEqual(target.mutation_count, 0)
            target.close()
        if profile_id == "new-feature":
            profile = fixture.profile_document(profile_id)
            materialized = fixture.materialized_profile(profile_id)
            with self.subTest(
                finding="WP08-S3-R1-006",
                probe="independent-installed-bootstrap-api",
            ):
                self.assertTrue(hasattr(api.CategoryExecutionPolicy, "from_installation"))
                parameters = inspect.signature(
                    api.CategoryExecutionPolicy.from_installation
                ).parameters
                self.assertNotIn("installation_root", parameters)
                self.assertNotIn("policy_registry_path", parameters)
            with self.subTest(
                finding="WP08-S3-R1-007",
                probe="exact-lowercase-digest-patterns",
            ):
                fixture.assert_digest_schema_patterns()

            api, application, repository, target = self._runtime(
                profile_id, "normal"
            )
            with self.subTest(
                finding="WP08-S3-R1-001",
                probe="duck-repository-is-not-production-authority",
            ):
                self.assertNotIsInstance(
                    application._repository,
                    fixture.RecordingCategoryRepository,
                )
            with self.subTest(
                finding="WP08-S3-R1-002",
                probe="assessment-ref-is-in-task-evidence",
            ):
                receipt = application.assess_and_commit(
                    fixture.candidate_document(profile_id, "normal"),
                    observer=target,
                )
                current = repository.signature()["current"]
                self.assertIsInstance(current, dict)
                self.assertIn(
                    {
                        "evidence_id": receipt.assessment.assessment_digest,
                        "evidence_type": "category-completion-assessment",
                        "source_ref": receipt.assessment.object_digest,
                        "digest": receipt.assessment.assessment_digest,
                        "trust": "factory-attested",
                    },
                    current.get("evidence", []),
                )
            target.close()

            with self.subTest(
                finding="WP08-S3-R1-003",
                probe="factory-issued-target-observation-fence",
            ):
                self.assertTrue(hasattr(api, "TargetObservationFence"))
                commit_parameters = inspect.signature(
                    type(application._repository).commit
                ).parameters
                self.assertIn("fence_token", commit_parameters)

            api, application, repository, target = self._runtime(
                profile_id, "normal"
            )
            candidate = fixture.candidate_document(profile_id, "normal")
            evidence = repository.resolve_category_evidence(
                candidate["task_id"], candidate["column_id"]
            )
            evidence["facts"]["runner-output-digest"] = fixture.digest(
                "forged-runner-output"
            )
            repository.replace_category_evidence(evidence)
            before = repository.signature()
            with self.subTest(
                finding="WP08-S3-R1-005",
                probe="record-digest-must-be-recomputed-from-durable-object",
            ):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(candidate, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            api, application, _repository, target = self._runtime(
                profile_id, "rollback"
            )
            with self.subTest(
                finding="WP08-S3-R1-004",
                probe="duck-coordinator-is-not-action-coordinator",
            ):
                with self.assertRaises(api.CategoryExecutionError):
                    api.CategoryRollbackBridge(
                        application._policy,
                        fixture.RecordingRollbackCoordinator(target),
                    )
            target.close()

            for label, mutate_policy in (
                (
                    "authority",
                    lambda value: value.__setitem__(
                        "authority_refs", ["authority:coherently-resigned"]
                    ),
                ),
                (
                    "execution-kind",
                    lambda value: value.__setitem__(
                        "local_execution_kinds", ["resigned-local"]
                    ),
                ),
                (
                    "transition",
                    lambda value: value["transition_rules"][0].__setitem__(
                        "event_type", "category.resigned.assessed"
                    ),
                ),
                (
                    "rollback-mapping",
                    lambda value: value["rollback_protocol_mappings"][0].__setitem__(
                        "failure_route", "resigned-owner"
                    ),
                ),
            ):
                document = fixture.category_policy_document()
                mutate_policy(document)
                fixture.resign_category_policy(document)
                with self.subTest(finding="WP08-S3-R1-006", coherent_resign=label):
                    with self.assertRaises(api.CategoryExecutionError):
                        api.CategoryExecutionPolicy.from_dict(
                            document,
                            profile_document=profile,
                            support_matrix_document=fixture.load_json(
                                fixture.SUPPORT_MATRIX_PATH
                            ),
                            materialization_record=materialized.record,
                        )

            api, application, repository, target = self._runtime(
                profile_id, "normal"
            )
            request = fixture.candidate_document(profile_id, "normal")
            repository.replace_category_facts(None)
            before = repository.signature()
            with self.subTest(finding="WP08-S3-R1-001", probe="missing-durable-facts"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            api, application, repository, target = self._runtime(
                profile_id, "normal"
            )
            request = fixture.candidate_document(profile_id, "normal")
            receipt = application.assess_and_commit(request, observer=target)
            with self.subTest(
                finding="WP08-S3-R1-002",
                probe="canonical-selector-request-digest",
            ):
                self.assertEqual(
                    receipt.assessment.request_digest,
                    fixture.selector_request_digest(request),
                )
            changed = copy.deepcopy(request)
            changed["target_id"] = "target:forged-same-key"
            before = repository.signature()
            with self.subTest(finding="WP08-S3-R1-002", probe="same-key-different-body"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(changed, observer=target)
                self.assertEqual(repository.signature(), before)

            selector_attacks = (
                (
                    "schema-version",
                    lambda value: value.__setitem__("schema_version", "2.0.0"),
                ),
                ("extra", lambda value: value.__setitem__("forged", True)),
                (
                    "request-id",
                    lambda value: value.__setitem__("request_id", "same-key:forged"),
                ),
                (
                    "task-id",
                    lambda value: value.__setitem__("task_id", "task:foreign"),
                ),
                (
                    "column-id",
                    lambda value: value.__setitem__("column_id", "boundary"),
                ),
                (
                    "scenario-id",
                    lambda value: value.__setitem__("scenario_id", "GEW-PRO-FORGED-P"),
                ),
                (
                    "target-id",
                    lambda value: value.__setitem__("target_id", "target:foreign"),
                ),
            )
            for label, mutate in selector_attacks:
                changed = copy.deepcopy(request)
                mutate(changed)
                before = repository.signature()
                with self.subTest(
                    finding="WP08-S3-R1-002",
                    probe="completed-selector-mutation",
                    selector=label,
                ):
                    with self.assertRaises(api.CategoryExecutionError):
                        application.assess_and_commit(changed, observer=target)
                    self.assertEqual(repository.signature(), before)

            canonical_evidence = repository.resolve_category_evidence(
                request["task_id"], request["column_id"]
            )
            boundary_evidence = repository.resolve_category_evidence(
                request["task_id"], "boundary"
            )

            def evidence_attack(label: str) -> object:
                if label == "delete":
                    return None
                changed_evidence = copy.deepcopy(
                    boundary_evidence if label == "cross-column" else canonical_evidence
                )
                if label == "cross-column":
                    changed_evidence["column_id"] = "normal"
                if label == "replace":
                    changed_evidence["facts"]["runner-output-digest"] = fixture.digest(
                        "coherent-current-replacement"
                    )
                elif label == "stale":
                    changed_evidence["task_revision"] += 1
                fixture.resign_column_evidence(changed_evidence)
                return changed_evidence

            for label in ("delete", "replace", "stale", "cross-column"):
                for operation in ("resolve", "replay"):
                    repository.replace_category_evidence_for(
                        "normal", evidence_attack(label)
                    )
                    before = repository.signature()
                    with self.subTest(
                        finding="WP08-S3-R1-002",
                        probe="current-column-evidence",
                        attack=label,
                        operation=operation,
                    ):
                        with self.assertRaises(api.CategoryExecutionError):
                            if operation == "resolve":
                                application.current_assessment(
                                    request["task_id"],
                                    expected_profile_id=profile_id,
                                )
                            else:
                                application.assess_and_commit(
                                    request, observer=target
                                )
                        self.assertEqual(repository.signature(), before)
                    repository.replace_category_evidence_for(
                        "normal", canonical_evidence
                    )

            replay = application.assess_and_commit(request, observer=target)
            self.assertTrue(replay.idempotent_replay)
            self.assertEqual(len(repository.signature()["events"]), 1)
            repository.replace_task_authority({
                "task_id": request["task_id"],
                "task_revision": 2,
                "snapshot_digest": fixture.digest("snapshot:new-feature:2"),
                "invalidation_epoch": 1,
            })
            with self.subTest(finding="WP08-S3-R1-002", probe="stale-current-assessment"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.current_assessment(
                        request["task_id"], expected_profile_id=profile_id,
                    )
            target.close()

            semantic_mismatch = {
                "normal": ("runner-output-digest", fixture.digest("runner:foreign")),
                "boundary": ("scenario-id", "GEW-PRO-FORGED-P"),
                "revise": ("budget-remaining", 999),
                "authority": ("authority-ref", "authority:foreign"),
                "drift": ("target-digest", fixture.digest("target:foreign")),
                "invalidation": ("invalidation-epoch", 999),
                "recovery": ("recovery-id", "recovery:foreign"),
                "artifacts": (
                    "artifact-record-digests",
                    [fixture.digest("artifact-record:foreign")],
                ),
                "review": ("review-record-digest", fixture.digest("review:foreign")),
                "target": (
                    "expected-state-digest",
                    fixture.digest("target-state:foreign"),
                ),
                "rollback": ("action-id", "rollback:foreign"),
            }
            for column_index, column in enumerate(fixture.COLUMNS):
                api, application, repository, target = self._runtime(
                    profile_id, column
                )
                request = fixture.candidate_document(profile_id, column)
                canonical = repository.resolve_category_evidence(
                    request["task_id"], column
                )
                cross = repository.resolve_category_evidence(
                    request["task_id"],
                    fixture.COLUMNS[(column_index + 1) % len(fixture.COLUMNS)],
                )
                wrong_outcome = copy.deepcopy(canonical)
                wrong_outcome["outcome"] = cross["outcome"]
                cross["column_id"] = column
                fact_ids = tuple(canonical["facts"])
                attacks: list[tuple[str, dict[str, object]]] = []
                none_value = copy.deepcopy(canonical)
                none_value["facts"][fact_ids[0]] = None
                attacks.append(("none", none_value))
                arbitrary = copy.deepcopy(canonical)
                arbitrary["facts"][fact_ids[0]] = fixture.digest(
                    f"arbitrary:{column}"
                )
                attacks.append(("arbitrary-digest", arbitrary))
                attacks.append(("wrong-outcome", wrong_outcome))
                attacks.append(("cross-column", copy.deepcopy(cross)))
                stale = copy.deepcopy(canonical)
                stale["task_revision"] += 1
                attacks.append(("stale", stale))
                mismatch = copy.deepcopy(canonical)
                fact_id, fact_value = semantic_mismatch[column]
                mismatch["facts"][fact_id] = copy.deepcopy(fact_value)
                attacks.append(("semantic-mismatch", mismatch))
                try:
                    for attack, changed_evidence in attacks:
                        fixture.resign_column_evidence(changed_evidence)
                        repository.replace_category_evidence_for(
                            column, changed_evidence
                        )
                        before = repository.signature()
                        with self.subTest(
                            finding="WP08-S3-R1-005",
                            column=column,
                            attack=attack,
                        ):
                            with self.assertRaises(api.CategoryExecutionError):
                                application.assess_and_commit(
                                    request, observer=target
                                )
                            self.assertEqual(repository.signature(), before)
                        repository.replace_category_evidence_for(
                            column, canonical
                        )

                    source_authority = application._facts
                    source_by_column = getattr(
                        source_authority,
                        "_CategoryFactsAuthority__source_by_column",
                    )
                    original_source = source_by_column[column]
                    foreign_source = object.__new__(type(original_source))
                    object.__setattr__(
                        foreign_source, "body", original_source.body
                    )
                    object.__setattr__(
                        foreign_source,
                        "source_digest",
                        original_source.source_digest,
                    )
                    object.__setattr__(
                        foreign_source, "_authority", source_authority
                    )
                    source_by_column[column] = foreign_source
                    repository.replace_category_evidence_for(
                        column, copy.deepcopy(canonical)
                    )
                    before = repository.signature()
                    with self.subTest(
                        finding="WP08-S3-R1-005",
                        column=column,
                        attack="coherent-source-evidence-foreign-issuer",
                    ):
                        with self.assertRaises(api.CategoryExecutionError):
                            application.assess_and_commit(
                                request, observer=target
                            )
                        self.assertEqual(repository.signature(), before)
                    source_by_column[column] = original_source

                    stale_evidence = copy.deepcopy(canonical)
                    stale_evidence["task_revision"] += 1
                    fixture.resign_column_evidence(stale_evidence)
                    stale_body = thaw(original_source.body)
                    stale_body["task_revision"] = stale_evidence["task_revision"]
                    stale_body["evidence_record_digest"] = stale_evidence[
                        "record_digest"
                    ]
                    stale_body["facts"] = copy.deepcopy(stale_evidence["facts"])
                    stale_source = object.__new__(type(original_source))
                    object.__setattr__(stale_source, "body", freeze(stale_body))
                    object.__setattr__(
                        stale_source,
                        "source_digest",
                        fixture.internal_digest(
                            stale_body, "category-source-record"
                        ),
                    )
                    object.__setattr__(
                        stale_source, "_authority", source_authority
                    )
                    source_by_column[column] = stale_source
                    repository.replace_category_evidence_for(
                        column, stale_evidence
                    )
                    before = repository.signature()
                    with self.subTest(
                        finding="WP08-S3-R1-005",
                        column=column,
                        attack="coherent-source-evidence-stale-replacement",
                    ):
                        with self.assertRaises(api.CategoryExecutionError):
                            application.assess_and_commit(
                                request, observer=target
                            )
                        self.assertEqual(repository.signature(), before)
                    source_by_column[column] = original_source
                    repository.replace_category_evidence_for(
                        column, canonical
                    )
                finally:
                    target.close()

            api, application, repository, target = self._runtime(
                profile_id, "revise"
            )
            request = fixture.candidate_document(profile_id, "revise")
            source = repository.resolve_category_source(
                "category-revision-record-v1"
            )
            source["owner_route"] = "owner:coherently-resigned"
            fixture.resign_durable_record(source)
            repository.replace_category_source(
                "category-revision-record-v1", source
            )
            evidence = repository.resolve_category_evidence(
                request["task_id"], "revise"
            )
            evidence["facts"]["owner-route"] = source["owner_route"]
            fixture.resign_column_evidence(evidence)
            repository.replace_category_evidence_for("revise", evidence)
            before = repository.signature()
            with self.subTest(
                finding="WP08-S3-R1-005",
                probe="coherent-source-and-evidence-resign",
                column="revise",
            ):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            api, application, repository, target = self._runtime(
                profile_id, "target"
            )
            request = fixture.candidate_document(profile_id, "target")
            foreign = copy.copy(target)
            before = repository.signature()
            with self.subTest(finding="WP08-S3-R1-003", probe="foreign-observer-capability"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=foreign)
                self.assertEqual(repository.signature(), before)
            target.force_observation_revision = 1
            with self.subTest(finding="WP08-S3-R1-003", probe="non-increasing-fresh-revision"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            holder: dict[str, fixture.DisposableLocalTarget] = {}

            def mutate_after_old_final_observe(step: str) -> None:
                if step == "category-assessment.before-commit":
                    holder["target"].apply_rollback()

            api, application, repository, target = self._runtime(
                profile_id,
                "target",
                fault_hook=mutate_after_old_final_observe,
            )
            holder["target"] = target
            request = fixture.candidate_document(profile_id, "target")
            before = repository.signature()
            with self.subTest(finding="WP08-S3-R1-003", probe="target-mutation-at-final-cut"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            api, application, repository, target = self._runtime(
                profile_id, "artifacts"
            )
            request = fixture.candidate_document(profile_id, "artifacts")
            repository.replace_category_evidence(None)
            before = repository.signature()
            with self.subTest(finding="WP08-S3-R1-005", probe="missing-typed-column-evidence"):
                with self.assertRaises(api.CategoryExecutionError):
                    application.assess_and_commit(request, observer=target)
                self.assertEqual(repository.signature(), before)
            target.close()

            api, application, _repository, target = self._runtime(
                profile_id, "rollback"
            )
            with self.subTest(finding="WP08-S3-R1-004", probe="rollback-without-coordinator"):
                with self.assertRaises(api.CategoryExecutionError):
                    api.CategoryRollbackBridge(application._policy)
            target.close()
        self._assert_release_gate_false()

    def test_gew_wp08_s3_new_feature_execution_p(self) -> None:
        """GEW-WP08-S3-NEW-FEATURE-EXECUTION-P."""
        self._assert_profile_positive("new-feature")

    def test_gew_wp08_s3_new_feature_execution_r(self) -> None:
        """GEW-WP08-S3-NEW-FEATURE-EXECUTION-R."""
        self._assert_profile_rejections("new-feature")

    def test_gew_wp08_s3_bug_fix_execution_p(self) -> None:
        """GEW-WP08-S3-BUG-FIX-EXECUTION-P."""
        self._assert_profile_positive("bug-fix")

    def test_gew_wp08_s3_bug_fix_execution_r(self) -> None:
        """GEW-WP08-S3-BUG-FIX-EXECUTION-R."""
        self._assert_profile_rejections("bug-fix")

    def test_gew_wp08_s3_hotfix_execution_p(self) -> None:
        """GEW-WP08-S3-HOTFIX-EXECUTION-P."""
        self._assert_profile_positive("hotfix")

    def test_gew_wp08_s3_hotfix_execution_r(self) -> None:
        """GEW-WP08-S3-HOTFIX-EXECUTION-R."""
        self._assert_profile_rejections("hotfix")

    def test_gew_wp08_s3_refactor_debt_execution_p(self) -> None:
        """GEW-WP08-S3-REFACTOR-DEBT-EXECUTION-P."""
        self._assert_profile_positive("refactor-debt")

    def test_gew_wp08_s3_refactor_debt_execution_r(self) -> None:
        """GEW-WP08-S3-REFACTOR-DEBT-EXECUTION-R."""
        self._assert_profile_rejections("refactor-debt")

    def test_gew_wp08_s3_migration_execution_p(self) -> None:
        """GEW-WP08-S3-MIGRATION-EXECUTION-P."""
        self._assert_profile_positive("migration")

    def test_gew_wp08_s3_migration_execution_r(self) -> None:
        """GEW-WP08-S3-MIGRATION-EXECUTION-R."""
        self._assert_profile_rejections("migration")

    def test_gew_wp08_s3_dependency_security_execution_p(self) -> None:
        """GEW-WP08-S3-DEPENDENCY-SECURITY-EXECUTION-P."""
        self._assert_profile_positive("dependency-security")

    def test_gew_wp08_s3_dependency_security_execution_r(self) -> None:
        """GEW-WP08-S3-DEPENDENCY-SECURITY-EXECUTION-R."""
        self._assert_profile_rejections("dependency-security")

    def test_gew_wp08_s3_performance_execution_p(self) -> None:
        """GEW-WP08-S3-PERFORMANCE-EXECUTION-P."""
        self._assert_profile_positive("performance")

    def test_gew_wp08_s3_performance_execution_r(self) -> None:
        """GEW-WP08-S3-PERFORMANCE-EXECUTION-R."""
        self._assert_profile_rejections("performance")

    def test_gew_wp08_s3_release_operations_execution_p(self) -> None:
        """GEW-WP08-S3-RELEASE-OPERATIONS-EXECUTION-P."""
        self._assert_profile_positive("release-operations")

    def test_gew_wp08_s3_release_operations_execution_r(self) -> None:
        """GEW-WP08-S3-RELEASE-OPERATIONS-EXECUTION-R."""
        self._assert_profile_rejections("release-operations")

    def test_gew_wp08_s3_incident_response_execution_p(self) -> None:
        """GEW-WP08-S3-INCIDENT-RESPONSE-EXECUTION-P."""
        self._assert_profile_positive("incident-response")

    def test_gew_wp08_s3_incident_response_execution_r(self) -> None:
        """GEW-WP08-S3-INCIDENT-RESPONSE-EXECUTION-R."""
        self._assert_profile_rejections("incident-response")


if __name__ == "__main__":
    unittest.main()
