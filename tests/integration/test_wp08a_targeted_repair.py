"""Targeted final reviewer repairs for WP08A-QR-R1 and WP08A-QR-R3-008."""

from __future__ import annotations

import copy
import contextlib
import dataclasses
import fcntl
import gc
import json
import os
import pathlib
import subprocess
import stat
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
import weakref
import zipfile
import importlib.util
import hashlib
import zlib

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.extensions import (
    ExtensionTrustOperation,
    ExtensionTrustPolicy,
    ExtensionTrustPolicyReducer,
)
from graph_engineering.storage.extension_activation import ExtensionTaskPinAuthority
from tests.support.wp03_repository import ROOT
from tests.support.wp08a_extension_bundle import DIGEST, trust_policy_chain


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    return {
        **body,
        field: semantic_digest(
            body,
            contract_type=f"urn:gew:contract:{name}",
            projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
            schema_id=f"urn:gew:schema:{name}-input:1.0.0",
        ),
    }


class ExtensionTargetedRepairTests(unittest.TestCase):
    @staticmethod
    def _load_build_backend():  # type: ignore[no-untyped-def]
        specification = importlib.util.spec_from_file_location(
            "gew_build_backend_adversarial", ROOT / "scripts/build_backend.py"
        )
        assert specification is not None and specification.loader is not None
        backend = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(backend)
        return backend

    @contextlib.contextmanager
    def _offline_preflight_fixture(self):  # type: ignore[no-untyped-def]
        with tempfile.TemporaryDirectory(prefix="gew-parser-attestation-") as directory:
            root = pathlib.Path(directory).resolve(strict=True)
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/build_wheel.py"), str(root)],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            candidate = next(root.glob("*.whl")).resolve(strict=True)
            wheelhouse = root / "wheelhouse"
            wheelhouse.mkdir()
            cryptography = wheelhouse / "cryptography-50.0.0-py3-none-any.whl"
            packaging = wheelhouse / "packaging-26.3-py3-none-any.whl"
            cffi = wheelhouse / "cffi-2.0.0-py3-none-any.whl"
            self._write_fixture_wheel(
                cryptography,
                "cryptography",
                "50.0.0",
                requires_dist=("cffi>=2.0.0",),
            )
            self._write_fixture_wheel(packaging, "packaging", "26.3")
            self._write_fixture_wheel(cffi, "cffi", "2.0.0")
            yield (
                self._load_build_backend(), candidate, wheelhouse,
                cryptography, packaging, cffi,
            )

    @staticmethod
    def _coverage_authority(  # type: ignore[no-untyped-def]
        candidate_id: str = "candidate.wp08a.adversarial",
    ):
        from graph_engineering.core import extension_coverage as coverage_module

        trace = json.loads(
            (ROOT / "config/release-coverage/trace-matrix-v1.json").read_text()
        )
        oracle = json.loads(
            (ROOT / "config/release-coverage/oracle-manifest-v1.json").read_text()
        )
        context = coverage_module.ExtensionCoverageCandidateContext.verify_current(
            candidate_id,
            ROOT.resolve(strict=True),
        )
        authority = coverage_module.ExtensionCoverageAuthority.issue(
            coverage_module.ExtensionCoverageMatrix.from_dict(trace),
            coverage_module.ExtensionOracleManifest.from_dict(oracle),
            context,
        )
        test_id = next(iter(trace["executions"]))
        return coverage_module, authority, test_id

    def test_wp08a_qr_r1_001_nested_record_and_operation_semantics_are_closed(self) -> None:
        genesis, current = trust_policy_chain("installation.nested-closed")
        malformed_policy = current.to_dict()
        malformed_policy["trust_keys"][0]["status"] = "invented"  # type: ignore[index]
        malformed_policy.pop("policy_digest")
        with self.assertRaises(ValueError):
            ExtensionTrustPolicy.from_dict(
                _complete(malformed_policy, "extension-trust-policy", "policy_digest"),
                previous=genesis,
            )

        source = copy.deepcopy(current.to_dict()["source_rules"][0])
        source["allowed_source_ids"] = [7]
        operation_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "operation_id": "operation.malformed-source",
            "operation_kind": "set-source-rule",
            "expected_policy_digest": current.policy_digest,
            "target_identity": source["source_type"],
            "expected_old": current.to_dict()["source_rules"][0],
            "new_value": source,
        }
        with self.assertRaises(ValueError):
            ExtensionTrustOperation.from_dict(
                _complete(operation_body, "extension-trust-operation", "operation_digest")
            )

    def test_wp08a_qr_r1_002_capability_sets_are_comparable(self) -> None:
        _genesis, current = trust_policy_chain("installation.capability-comparable")
        ceiling = current.to_dict()["capability_ceilings"][0]
        self.assertIn("capability_ids", ceiling)
        self.assertEqual(
            ExtensionTaskPinAuthority._capability_relation(
                ("capability.read",),
                ("capability.read", "capability.write"),
            ),
            "expansion",
        )
        self.assertEqual(
            ExtensionTaskPinAuthority._capability_relation(
                ("capability.read", "capability.write"),
                ("capability.read",),
            ),
            "contraction",
        )

    def test_wp08a_qr_r1_003_security_join_is_monotonic_or_unprovable(self) -> None:
        genesis, current = trust_policy_chain("installation.security-join")
        reducer = ExtensionTrustPolicyReducer.issue(genesis)
        published_body = current.to_dict()
        published_body.update(
            generation=current.generation + 1,
            previous_policy_digest=current.policy_digest,
        )
        published_body["source_rules"][0]["allowed_source_ids"] = []  # type: ignore[index]
        published_body.pop("policy_digest")
        published = ExtensionTrustPolicy.from_dict(
            _complete(published_body, "extension-trust-policy", "policy_digest"),
            previous=current,
        )
        joined = reducer.security_join(current, published)
        self.assertEqual(joined.to_dict()["source_rules"][0]["allowed_source_ids"], [])

        unknown_body = published.to_dict()
        unknown_body.update(
            generation=published.generation + 1,
            previous_policy_digest=published.policy_digest,
            resource_policy_digest="sha256-jcs-v1:" + "f" * 64,
        )
        unknown_body.pop("policy_digest")
        unknown = ExtensionTrustPolicy.from_dict(
            _complete(unknown_body, "extension-trust-policy", "policy_digest"),
            previous=published,
        )
        with self.assertRaisesRegex(ValueError, "unprovable"):
            reducer.security_join(published, unknown)

    def test_wp08a_qr_r1_007_execution_records_are_authenticated_and_digest_bound(self) -> None:
        from graph_engineering.core.extension_coverage import (
            ADR4_GOLDEN_PAYLOAD_BYTES,
            ADR4_GOLDEN_PAYLOAD_ROOT_DIGEST,
            ExtensionCoverageAuthority,
            ExtensionCoverageCandidateContext,
            ExtensionCoverageError,
            ExtensionCoverageMatrix,
            ExtensionOracleManifest,
        )

        trace = json.loads(
            (ROOT / "config/release-coverage/trace-matrix-v1.json").read_text()
        )
        oracle = json.loads(
            (ROOT / "config/release-coverage/oracle-manifest-v1.json").read_text()
        )
        matrix = ExtensionCoverageMatrix.from_dict(trace)
        with self.assertRaises(TypeError):
            ExtensionCoverageAuthority.issue(
                matrix, ExtensionOracleManifest.from_dict(oracle), DIGEST  # type: ignore[arg-type]
            )
        context = ExtensionCoverageCandidateContext.verify_current(
            "candidate.wp08a.targeted",
            ROOT.resolve(strict=True),
        )
        manifest_spec = importlib.util.spec_from_file_location(
            "gew_source_manifest_targeted", ROOT / "scripts/source_manifest.py"
        )
        assert manifest_spec is not None and manifest_spec.loader is not None
        source_manifest = importlib.util.module_from_spec(manifest_spec)
        manifest_spec.loader.exec_module(source_manifest)
        self.assertEqual(
            context.source_manifest_digest,
            source_manifest.create_manifest()["manifest_digest"],
        )
        with self.assertRaises(TypeError):
            ExtensionCoverageCandidateContext.verify_current(  # type: ignore[call-arg]
                "candidate.caller-selected",
                ROOT.resolve(strict=True),
                ("tests",),
                ("pyproject.toml",),
            )
        authority = ExtensionCoverageAuthority.issue(
            matrix, ExtensionOracleManifest.from_dict(oracle), context
        )
        runner_source = (ROOT / "scripts/run_verified_test.py").read_text(encoding="utf-8")
        self.assertNotIn("loadTestsFromName", runner_source)
        self.assertIn("module_source_b64", runner_source)
        stale = dataclasses.replace(context, source_manifest_digest="f" * 64)
        with self.assertRaises(ExtensionCoverageError):
            ExtensionCoverageAuthority.issue(
                matrix, ExtensionOracleManifest.from_dict(oracle), stale
            )
        original_read = pathlib.Path.read_bytes

        def substituted_read(path: pathlib.Path) -> bytes:
            body = original_read(path)
            return body + b"\n# substituted" if path.name == "extension_coverage.py" else body

        with mock.patch.object(pathlib.Path, "read_bytes", substituted_read):
            with self.assertRaisesRegex(ExtensionCoverageError, "stale"):
                ExtensionCoverageAuthority.issue(
                    matrix, ExtensionOracleManifest.from_dict(oracle), context
                )
        from graph_engineering.core import extension_coverage as coverage_module

        first_test_id = next(iter(trace["executions"]))
        qualified = trace["executions"][first_test_id]["qualified_test"]
        forged_binding = context.execution_binding(qualified)
        forged_binding["module_digest"] = "f" * 64
        forged_body = {
            "schema_version": "1.0.0",
            "qualified_test": qualified,
            "tests_run": 1,
            "successful": True,
            "failures": 0,
            "errors": 0,
            "captured_stdout_empty": True,
            "captured_stderr_empty": True,
            **forged_binding,
        }
        forged_result = {
            **forged_body,
            "observed_result_digest": hashlib.sha256(canonical_bytes(forged_body)).hexdigest(),
        }
        with mock.patch.object(
            coverage_module.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                args=(), returncode=0,
                stdout=json.dumps(forged_result, sort_keys=True, separators=(",", ":")),
                stderr="",
            ),
        ):
            with self.assertRaises(ExtensionCoverageError):
                authority.execute(first_test_id, occurred_at="2026-08-21T00:00:00Z")
        exact_binding = context.execution_binding(qualified)
        exact_body = {
            "schema_version": "1.0.0",
            "qualified_test": qualified,
            "tests_run": 1,
            "successful": True,
            "failures": 0,
            "errors": 0,
            "captured_stdout_empty": True,
            "captured_stderr_empty": True,
            **exact_binding,
        }
        exact_result = {
            **exact_body,
            "observed_result_digest": hashlib.sha256(canonical_bytes(exact_body)).hexdigest(),
        }
        substituted_launch = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=canonical_bytes(exact_result),
            stderr=b"",
        )
        with mock.patch.object(
            coverage_module.subprocess, "run", return_value=substituted_launch
        ) as launched:
            with self.assertRaisesRegex(ExtensionCoverageError, "launch"):
                authority.execute(first_test_id, occurred_at="2026-08-21T00:00:00Z")
        self.assertIs(type(launched.call_args.kwargs["input"]), bytes)
        self.assertNotIn("text", launched.call_args.kwargs)
        records = tuple(
            authority.execute(
                test_id,
                occurred_at="2026-08-21T00:00:00Z",
            )
            for test_id in trace["executions"]
        )
        self.assertTrue(all(record._authority is authority for record in records))
        self.assertEqual(authority._issued_record_count(), len(records))
        for record in records:
            document = record.to_dict()
            for field in (
                "module_digest", "callable_source_digest", "callable_code_digest",
                "runner_digest", "observed_result_digest",
            ):
                self.assertRegex(str(document[field]), r"^[0-9a-f]{64}$")
        self.assertEqual(matrix.reduce_results(records), frozenset(trace["test_ids"]))
        with self.assertRaises(ExtensionCoverageError):
            matrix.reduce_results(records[:-1])
        with self.assertRaises(ExtensionCoverageError):
            matrix.reduce_results(tuple(item.to_dict() for item in records))
        foreign_context = ExtensionCoverageCandidateContext.verify_current(
            "candidate.wp08a.foreign",
            ROOT.resolve(strict=True),
        )
        foreign_authority = ExtensionCoverageAuthority.issue(
            matrix,
            ExtensionOracleManifest.from_dict(oracle),
            foreign_context,
        )
        foreign_record = foreign_authority.execute(
            first_test_id,
            occurred_at="2026-08-21T00:00:01Z",
        )
        mixed_records = tuple(
            foreign_record if item.to_dict()["test_id"] == first_test_id else item
            for item in records
        )
        with self.assertRaisesRegex(ExtensionCoverageError, "authority"):
            matrix.reduce_results(mixed_records)
        with self.assertRaisesRegex(
            ExtensionCoverageError,
            "authenticated|authority|issued",
        ):
            authority._require_issued_record(foreign_record)
        self.assertEqual(ADR4_GOLDEN_PAYLOAD_BYTES, b"hello")
        self.assertEqual(
            ADR4_GOLDEN_PAYLOAD_ROOT_DIGEST,
            "sha256-jcs-v1:7f05ee9a843ddd9a9a822f21f7932ace1763756f093cca164285ba35a0191c4a",
        )

    def test_wp08a_qr_r1_007_issuance_transaction_adversarial_hooks(self) -> None:
        coverage_module, authority, test_id = self._coverage_authority()
        target = ROOT / "tests/unit/test_wp08a_adr4_corpus.py"
        original = target.read_bytes()
        control_root = pathlib.Path(
            str(sys._xoptions["gew_installation_control_root"])
        ).resolve(strict=True)
        points = (
            "coverage.child-import",
            "coverage.child-return",
            "coverage.result-interpretation",
            "coverage.pre-auth",
            "coverage.post-insert-pre-return",
        )
        baseline = authority.execute(
            test_id,
            occurred_at="2026-08-21T00:00:00Z",
        )
        self.assertIs(baseline._authority, authority)
        self.assertFalse(hasattr(coverage_module, "_ISSUED_EXECUTION_RECORDS"))
        baseline_count = authority._issued_record_count()
        self.assertEqual(baseline_count, 1)
        for cut in points:
            observed: list[str] = []

            def probe(point: str, expected: str) -> str:
                observed.append(point)
                descriptor = os.open(
                    control_root / "installation-maintenance.lock",
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                acquired = False
                try:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                    except BlockingIOError:
                        pass
                    if acquired:
                        self.fail(f"source mutation exclusion was absent at {point}")
                finally:
                    if acquired:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    os.close(descriptor)
                if point == cut:
                    try:
                        target.write_bytes(original + b"\n# substitute-and-restore probe\n")
                    finally:
                        target.write_bytes(original)
                    return "hook-mismatch"
                return expected

            with self.subTest(cut=cut), self.assertRaisesRegex(
                coverage_module.ExtensionCoverageError,
                "probe|hook|transaction|binding",
            ):
                authority.execute(
                    test_id,
                    occurred_at="2026-08-21T00:00:00Z",
                    _probe_hook=probe,
                )
            self.assertIn(cut, observed)
            authority._require_issued_record(baseline)
            self.assertEqual(authority._issued_record_count(), baseline_count)
            self.assertEqual(target.read_bytes(), original)

        clone = object.__new__(type(baseline))
        object.__setattr__(clone, "_document", baseline._document)
        object.__setattr__(clone, "_authority", authority)
        with self.assertRaisesRegex(
            coverage_module.ExtensionCoverageError,
            "authenticated|authority|issued",
        ):
            authority._require_issued_record(clone)

        for round_index in range(2):
            transient = authority.execute(
                test_id,
                occurred_at=f"2026-08-21T00:00:0{round_index + 1}Z",
            )
            authority._require_issued_record(transient)
            observed_reference = weakref.ref(transient)
            self.assertEqual(authority._issued_record_count(), baseline_count + 1)
            del transient
            gc.collect()
            self.assertIsNone(observed_reference())
            self.assertEqual(authority._issued_record_count(), baseline_count)

        threaded: list[object] = []
        threaded_lock = threading.Lock()

        def issue_from_thread(second: int) -> None:
            record = authority.execute(
                test_id,
                occurred_at=f"2026-08-21T00:01:0{second}Z",
            )
            with threaded_lock:
                threaded.append(record)

        workers = tuple(
            threading.Thread(target=issue_from_thread, args=(index,))
            for index in range(2)
        )
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(len(threaded), 2)
        for record in threaded:
            authority._require_issued_record(record)
        self.assertEqual(authority._issued_record_count(), baseline_count + 2)
        threaded_references = tuple(weakref.ref(record) for record in threaded)
        del record
        threaded.clear()
        gc.collect()
        self.assertTrue(all(reference() is None for reference in threaded_references))
        self.assertEqual(authority._issued_record_count(), baseline_count)

        _module, foreign_authority, foreign_test_id = self._coverage_authority(
            "candidate.wp08a.foreign"
        )
        foreign_record = foreign_authority.execute(
            foreign_test_id,
            occurred_at="2026-08-21T00:02:00Z",
        )
        foreign_authority._require_issued_record(foreign_record)
        with self.assertRaisesRegex(
            coverage_module.ExtensionCoverageError,
            "authenticated|authority|issued",
        ):
            authority._require_issued_record(foreign_record)
        with self.assertRaisesRegex(
            coverage_module.ExtensionCoverageError,
            "authenticated|authority|issued",
        ):
            foreign_authority._require_issued_record(baseline)
        foreign_authority_reference = weakref.ref(foreign_authority)
        del foreign_record, foreign_authority
        gc.collect()
        self.assertIsNone(foreign_authority_reference())

        _module, restarted_authority, restarted_test_id = self._coverage_authority()
        restarted_record = restarted_authority.execute(
            restarted_test_id,
            occurred_at="2026-08-21T00:03:00Z",
        )
        restarted_authority._require_issued_record(restarted_record)
        with self.assertRaisesRegex(
            coverage_module.ExtensionCoverageError,
            "authenticated|authority|issued",
        ):
            restarted_authority._require_issued_record(baseline)
        restarted_authority_reference = weakref.ref(restarted_authority)
        del restarted_record, restarted_authority
        gc.collect()
        self.assertIsNone(restarted_authority_reference())
        self.assertTrue(
            all(
                reference() is not None
                for reference in coverage_module._ISSUED_COVERAGE_AUTHORITIES
            )
        )

    def test_wp08a_qr_r3_008_parser_attestation_rejects_missing_wrong_and_shadow(self) -> None:
        with self._offline_preflight_fixture() as fixture:
            backend, candidate, wheelhouse, _crypto, _packaging, _cffi = fixture
            plan = backend.preflight_offline_candidate(candidate, wheelhouse)
            self.assertEqual(plan.parser_attestation.distribution_name, "packaging")
            self.assertEqual(plan.parser_attestation.distribution_version, "26.3")
            self.assertEqual(
                plan.dependency_wheels,
                (_crypto.resolve(), _packaging.resolve(), _cffi.resolve()),
            )
            with mock.patch.object(
                backend.importlib.metadata, "distributions", return_value=()
            ):
                with self.assertRaisesRegex(ValueError, "parser|packaging|distribution"):
                    backend.preflight_offline_candidate(candidate, wheelhouse)
            actual = backend.importlib.metadata.distribution("packaging")
            wrong = mock.Mock(wraps=actual)
            wrong.metadata = actual.metadata
            wrong.version = "0.0"
            with mock.patch.object(
                backend.importlib.metadata, "distributions", return_value=(wrong,)
            ):
                with self.assertRaisesRegex(ValueError, "version|parser|packaging"):
                    backend.preflight_offline_candidate(candidate, wheelhouse)
            shadow = pathlib.Path(fixture[1]).parent / "shadow-packaging.py"
            shadow.write_bytes(pathlib.Path(backend.packaging.__file__).read_bytes())
            with mock.patch.object(backend.packaging, "__file__", str(shadow)):
                with self.assertRaisesRegex(ValueError, "origin|shadow|parser"):
                    backend.preflight_offline_candidate(candidate, wheelhouse)
            changed = copy.deepcopy(backend._configuration())
            changed["tool"]["gew"]["build"]["package-parser-requirement"][
                "sha256"
            ] = "0" * 64
            with mock.patch.object(backend, "_configuration", return_value=changed):
                with self.assertRaisesRegex(ValueError, "requirement|digest|parser"):
                    backend.preflight_offline_candidate(candidate, wheelhouse)

    def test_wp08a_qr_r3_008_same_path_replacements_reject_before_plan(self) -> None:
        cases = tuple(
            (point, target_kind)
            for point in (
                "preflight.after-open",
                "preflight.after-traversal",
                "preflight.before-plan-return",
            )
            for target_kind in ("candidate", "dependency")
        )
        for point, target_kind in cases:
            with self.subTest(point=point, target=target_kind), self._offline_preflight_fixture() as fixture:
                backend, candidate, wheelhouse, cryptography, _packaging, _cffi = fixture
                target = candidate if target_kind == "candidate" else cryptography
                invoked: list[str] = []

                def probe(current: str) -> None:
                    invoked.append(current)
                    if current != point:
                        return
                    replacement = target.with_name(target.name + ".replacement")
                    replacement.write_bytes(target.read_bytes())
                    replacement.chmod(stat.S_IMODE(target.stat().st_mode))
                    os.replace(replacement, target)

                with self.assertRaisesRegex(ValueError, "changed|replacement|binding"):
                    backend.preflight_offline_candidate(
                        candidate,
                        wheelhouse,
                        _probe_hook=probe,
                    )
                self.assertIn(point, invoked)

    def test_wp08a_final_r3_008_001_closure_return_rechecks_every_held_wheel(self) -> None:
        for api in ("candidate", "dependencies"):
            with self._offline_preflight_fixture() as fixture:
                backend, candidate, wheelhouse, cryptography, packaging, cffi = fixture
                targets = (
                    (candidate, cryptography, packaging, cffi)
                    if api == "candidate"
                    else (cryptography, packaging, cffi)
                )
                for original_target in targets:
                    with self.subTest(api=api, target=original_target.name):
                        target = original_target
                        returned: list[object] = []
                        observed: list[str] = []
                        attestation_calls: list[str] = []
                        closure_attestation_counts: list[int] = []
                        original_attestation = backend._package_parser_attestation

                        def attest():  # type: ignore[no-untyped-def]
                            result = original_attestation()
                            attestation_calls.append(result.attestation_digest)
                            return result

                        def probe(point: str) -> None:
                            observed.append(point)
                            if point != "preflight.closure-return":
                                return
                            closure_attestation_counts.append(len(attestation_calls))
                            replacement = target.with_name(target.name + ".closure-return")
                            replacement.write_bytes(target.read_bytes())
                            replacement.chmod(stat.S_IMODE(target.stat().st_mode))
                            os.replace(replacement, target)

                        with mock.patch.object(
                            backend, "_package_parser_attestation", side_effect=attest
                        ):
                            with self.assertRaisesRegex(
                                ValueError, "binding|replaced|closure|changed"
                            ):
                                if api == "candidate":
                                    returned.append(backend.preflight_offline_candidate(
                                        candidate,
                                        wheelhouse,
                                        _probe_hook=probe,
                                    ))
                                else:
                                    returned.append(backend.preflight_offline_dependencies(
                                        wheelhouse,
                                        _probe_hook=probe,
                                    ))
                        self.assertIn("preflight.closure-return", observed)
                        self.assertEqual(closure_attestation_counts, [3])
                        self.assertEqual(returned, [])

    def test_wp08a_final_r3_008_002_parser_protected_fields_are_exact(self) -> None:
        backend = self._load_build_backend()
        requirement_path = (
            ROOT / "config/supply-chain/extension-package-parser-requirement-v1.json"
        ).resolve(strict=True)
        original_document = json.loads(requirement_path.read_text(encoding="utf-8"))
        mutations: list[tuple[str, dict[str, object]]] = []

        wrong_python = copy.deepcopy(original_document)
        wrong_python["python_requires"] = ">=3.11"
        mutations.append(("python-requires", wrong_python))
        wrong_activation = copy.deepcopy(original_document)
        wrong_activation["activation_status"] = "active"
        mutations.append(("activation-status", wrong_activation))
        wrong_authority = copy.deepcopy(original_document)
        wrong_authority["update_authority"] = "caller"
        mutations.append(("update-authority", wrong_authority))
        for label, pins in (
            ("pin-omitted", original_document["required_release_install_pins"][:-1]),
            (
                "pin-added",
                [*original_document["required_release_install_pins"], "unexpected-pin"],
            ),
            (
                "pin-duplicated",
                [
                    *original_document["required_release_install_pins"],
                    original_document["required_release_install_pins"][0],
                ],
            ),
            (
                "pin-reordered",
                list(reversed(original_document["required_release_install_pins"])),
            ),
        ):
            changed = copy.deepcopy(original_document)
            changed["required_release_install_pins"] = pins
            mutations.append((label, changed))

        original_reader = backend._regular_descriptor_bytes
        for label, document in mutations:
            raw = json.dumps(
                document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            changed_configuration = copy.deepcopy(backend._configuration())
            changed_configuration["tool"]["gew"]["build"][
                "package-parser-requirement"
            ]["sha256"] = hashlib.sha256(raw).hexdigest()

            def descriptor_bytes(path: pathlib.Path) -> bytes:
                if path.resolve(strict=True) == requirement_path:
                    return raw
                return original_reader(path)

            with self.subTest(mutation=label), mock.patch.object(
                backend, "_configuration", return_value=changed_configuration
            ), mock.patch.object(
                backend, "_regular_descriptor_bytes", side_effect=descriptor_bytes
            ), mock.patch.object(
                backend,
                "_prepare_physical_closure",
                side_effect=AssertionError("physical traversal started"),
            ):
                with self.assertRaisesRegex(ValueError, "parser|requirement|protected"):
                    backend.preflight_offline_dependencies(pathlib.Path("unused"))

    def test_wp08a_qr_r3_008_wheel_has_one_exact_requires_dist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-requires-dist-") as directory:
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/build_wheel.py"), directory],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            wheel = next(pathlib.Path(directory).glob("*.whl")).resolve(strict=True)
            with zipfile.ZipFile(wheel) as archive:
                metadata_name = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
                )
                lines = archive.read(metadata_name).decode().splitlines()
            self.assertEqual(
                [line for line in lines if line.startswith("Requires-Dist:")],
                [
                    "Requires-Dist: cryptography==50.0.0",
                    "Requires-Dist: packaging==26.3",
                ],
            )
            spec = importlib.util.spec_from_file_location(
                "gew_build_backend_targeted", ROOT / "scripts/build_backend.py"
            )
            assert spec is not None and spec.loader is not None
            backend = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(backend)
            policy = backend._configuration()["tool"]["gew"]["build"]["offline-wheel-policy"]
            self.assertEqual(
                set(policy),
                {
                    "max-members", "max-member-bytes", "max-total-bytes", "compatible-tags",
                    "max-closure-wheels", "max-closure-bytes", "max-dependency-edges",
                    "max-dependency-depth", "max-requirements",
                },
            )
            wheelhouse = pathlib.Path(directory).resolve(strict=True) / "wheelhouse"
            wheelhouse.mkdir()
            sentinel = pathlib.Path(directory) / "install-target"
            with self.assertRaisesRegex(ValueError, "unavailable or ambiguous"):
                backend.preflight_offline_dependencies(wheelhouse)
            self.assertFalse(sentinel.exists())
            dependency = wheelhouse / "cryptography-50.0.0-py3-none-any.whl"
            dependency.write_bytes(b"offline-fixture")
            with self.assertRaisesRegex(ValueError, "wheel"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            dependency.unlink()
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", requires_dist=("cffi>=2.0.0",)
            )
            packaging_wheel = wheelhouse / "packaging-26.3-py3-none-any.whl"
            self._write_fixture_wheel(packaging_wheel, "packaging", "26.3")
            cffi_wheel = wheelhouse / "cffi-2.0.0-py3-none-any.whl"
            self._write_fixture_wheel(cffi_wheel, "cffi", "2.0.0")
            plan = backend.preflight_offline_candidate(wheel, wheelhouse)
            self.assertEqual(
                plan.dependency_wheels,
                (dependency.resolve(), packaging_wheel.resolve(), cffi_wheel.resolve()),
            )
            with mock.patch.object(
                pathlib.Path,
                "read_bytes",
                side_effect=AssertionError("wheel verification reopened a path snapshot"),
            ):
                backend._validate_wheel(
                    dependency,
                    expected_name="cryptography",
                    expected_version="50.0.0",
                    expected_requirements=None,
                )
            self._write_fixture_wheel(
                dependency,
                "cryptography",
                "50.0.0",
                requires_dist=("cffi>=2.0.0",),
                extra_member="cryptography/extra.py",
            )
            member_limited = copy.deepcopy(backend._configuration())
            member_limited["tool"]["gew"]["build"]["offline-wheel-policy"][
                "max-members"
            ] = 4
            with mock.patch.object(
                backend, "_configuration", return_value=member_limited
            ), mock.patch.object(
                backend.zipfile.ZipFile,
                "infolist",
                side_effect=AssertionError("central directory allocated before count charge"),
            ):
                with self.assertRaisesRegex(ValueError, "member limit"):
                    backend._validate_wheel(
                        dependency,
                        expected_name="cryptography",
                        expected_version="50.0.0",
                        expected_requirements=None,
                    )
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", requires_dist=("cffi>=2.0.0",)
            )
            padding = b"".join(
                hashlib.sha256(index.to_bytes(4, "big")).digest()
                for index in range(131072)
            )
            self._write_fixture_wheel(
                cffi_wheel,
                "cffi",
                "2.0.0",
                extra_member="cffi/padding.bin",
                extra_body=padding,
            )
            base_configuration = backend._configuration()
            wheel_paths = (wheel, dependency, packaging_wheel, cffi_wheel)
            maximum_wheel = max(item.stat().st_size for item in wheel_paths)
            maximum_member = 1
            maximum_uncompressed = 1
            for wheel_path in wheel_paths:
                with zipfile.ZipFile(wheel_path) as archive:
                    maximum_member = max(
                        maximum_member, *(item.file_size for item in archive.infolist())
                    )
                    maximum_uncompressed = max(
                        maximum_uncompressed, sum(item.file_size for item in archive.infolist())
                    )
            per_wheel_bound = max(maximum_wheel, maximum_uncompressed)
            limit_mutations = {
                "wheel-count": {"max-closure-wheels": 2},
                "aggregate-bytes": {
                    "max-member-bytes": maximum_member,
                    "max-total-bytes": per_wheel_bound,
                    "max-closure-bytes": per_wheel_bound,
                },
                "edge-count": {"max-dependency-edges": 1},
                "depth": {"max-dependency-depth": 1},
                "requirement-count": {"max-requirements": 1},
            }
            for limit_name, changes in limit_mutations.items():
                limited = copy.deepcopy(base_configuration)
                limited["tool"]["gew"]["build"]["offline-wheel-policy"].update(changes)
                with self.subTest(limit_name=limit_name), mock.patch.object(
                    backend, "_configuration", return_value=limited
                ):
                    with self.assertRaisesRegex(ValueError, "closure.*limit|depth|requirement"):
                        backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency,
                "cryptography",
                "50.0.0",
                requires_dist=("cffi>=2.0.0",),
                metadata_versions=("2.4", "2.4"),
            )
            with self.assertRaisesRegex(ValueError, "singular|metadata"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency,
                "cryptography",
                "50.0.0",
                requires_dist=("cffi>=2.0.0",),
                root_is_purelib=("true", "true"),
            )
            with self.assertRaisesRegex(ValueError, "singular|metadata"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency,
                "cryptography",
                "50.0.0",
                requires_dist=("cffi>=2.0.0",),
                generators=("fixture-a", "fixture-b"),
            )
            with self.assertRaisesRegex(ValueError, "identity|metadata"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", requires_dist=("cffi>=2.0.0",)
            )
            self._append_hidden_local_member(dependency, "hidden.py", b"pass\n")
            with self.assertRaisesRegex(ValueError, "physical|local"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            for unsafe_member in (
                "cryptography\\escape.py",
                "C:/cryptography/escape.py",
                "/cryptography/escape.py",
                "cryptography/../escape.py",
                "cryptography/nul\x00escape.py",
                "cryptography/CON.py",
                "cryptography/trailing. ",
                "cryptography/question?.py",
                "cryptography/star*.py",
                "cryptography/pipe|.py",
                "cryptography/quote\".py",
                "cryptography/e\u0301.py",
            ):
                self._write_fixture_wheel(
                    dependency,
                    "cryptography",
                    "50.0.0",
                    requires_dist=("cffi>=2.0.0",),
                    extra_member=unsafe_member,
                )
                with self.subTest(unsafe_member=unsafe_member), self.assertRaises(ValueError):
                    backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency,
                "cryptography",
                "50.0.0",
                requires_dist=("not a valid @@@",),
            )
            with self.assertRaisesRegex(ValueError, "Requires-Dist"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", requires_dist=("cffi>=2.0.0",)
            )
            corrupt = bytearray(dependency.read_bytes())
            corrupt[-1] ^= 1
            dependency.write_bytes(corrupt)
            with self.assertRaises(ValueError):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self.assertFalse(sentinel.exists())
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", metadata_name="spoofed",
                requires_dist=("cffi>=2.0.0",),
            )
            with self.assertRaisesRegex(ValueError, "identity"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", wheel_tag="cp312-none-any",
                requires_dist=("cffi>=2.0.0",),
            )
            with self.assertRaisesRegex(ValueError, "tag"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self._write_fixture_wheel(
                dependency, "cryptography", "50.0.0", corrupt_record=True,
                requires_dist=("cffi>=2.0.0",),
            )
            with self.assertRaisesRegex(ValueError, "RECORD"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            dependency.unlink()
            packaging_wheel.unlink()
            cffi_wheel.unlink()
            spoofed_filename = wheelhouse / "cryptography-49.0.0-py3-none-any.whl"
            self._write_fixture_wheel(spoofed_filename, "cryptography", "50.0.0")
            with self.assertRaisesRegex(ValueError, "unavailable"):
                backend.preflight_offline_candidate(wheel, wheelhouse)
            self.assertFalse(sentinel.exists())

    @staticmethod
    def _write_fixture_wheel(
        path: pathlib.Path,
        name: str,
        version: str,
        *,
        metadata_name: str | None = None,
        wheel_tag: str = "py3-none-any",
        corrupt_record: bool = False,
        requires_dist: tuple[str, ...] = (),
        extra_member: str | None = None,
        extra_body: bytes = b"pass\n",
        metadata_versions: tuple[str, ...] = ("2.4",),
        root_is_purelib: tuple[str, ...] = ("true",),
        generators: tuple[str, ...] = (),
    ) -> None:
        dist = name.replace("-", "_")
        info = f"{dist}-{version}.dist-info"
        members = {
            f"{dist}/__init__.py": b"",
            f"{info}/METADATA": (
                "".join(f"Metadata-Version: {item}\n" for item in metadata_versions)
                + f"Name: {metadata_name or name}\nVersion: {version}\n"
                + "".join(f"Requires-Dist: {item}\n" for item in requires_dist)
                + "\n"
            ).encode(),
            f"{info}/WHEEL": (
                "Wheel-Version: 1.0\n"
                + "".join(f"Generator: {item}\n" for item in generators)
                + "".join(f"Root-Is-Purelib: {item}\n" for item in root_is_purelib)
                + f"Tag: {wheel_tag}\n"
            ).encode(),
        }
        if extra_member is not None:
            members[extra_member] = extra_body
        rows = []
        import base64
        for member, body in members.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
            rows.append(f"{member},sha256={digest},{len(body)}")
        rows.append(f"{info}/RECORD,,")
        if corrupt_record:
            rows[0] = rows[0].replace("sha256=", "sha256=corrupt")
        members[f"{info}/RECORD"] = ("\n".join(rows) + "\n").encode()
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member, body in members.items():
                archive.writestr(member, body)

    @staticmethod
    def _append_hidden_local_member(path: pathlib.Path, name: str, body: bytes) -> None:
        raw = bytearray(path.read_bytes())
        eocd = raw.rfind(b"PK\x05\x06")
        central_offset = struct.unpack_from("<L", raw, eocd + 16)[0]
        encoded = name.encode("utf-8")
        local = struct.pack(
            "<4s5H3L2H",
            b"PK\x03\x04", 20, 0, 0, 0, 0, zlib.crc32(body), len(body), len(body),
            len(encoded), 0,
        ) + encoded + body
        raw[central_offset:central_offset] = local
        struct.pack_into("<L", raw, eocd + len(local) + 16, central_offset + len(local))
        path.write_bytes(raw)


if __name__ == "__main__":
    unittest.main()
