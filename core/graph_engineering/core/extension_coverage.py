"""Closed WP-08A trace and independent-oracle manifest contracts."""

from __future__ import annotations

import hashlib
import ast
import base64
import contextlib
import fcntl
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import threading
import weakref
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from types import CodeType

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.security._common import parse_timestamp, require_digest


class ExtensionCoverageError(ValueError):
    """A coverage or oracle manifest is incomplete or substituted."""


ADR4_GOLDEN_PAYLOAD_BYTES = b"hello"
ADR4_GOLDEN_PAYLOAD_ROOT_DIGEST = (
    "sha256-jcs-v1:7f05ee9a843ddd9a9a822f21f7932ace1763756f093cca164285ba35a0191c4a"
)
_RAW_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_OPTION = "gew_installation_control_root"
_CONTROL_LOCK = "installation-maintenance.lock"
_PIPE_BOOTSTRAP = """\
import base64
import hashlib
import json
import sys

envelope = json.loads(sys.stdin.buffer.read())
if type(envelope) is not dict or set(envelope) != {"runner_source_b64", "payload"}:
    raise RuntimeError("verified runner envelope is not exact")
runner = base64.b64decode(envelope["runner_source_b64"], validate=True)
payload = envelope["payload"]
if type(payload) is not dict or hashlib.sha256(runner).hexdigest() != payload.get("runner_digest"):
    raise RuntimeError("verified runner bytes are substituted")
scope = {
    "_GEW_PROTOCOL_PAYLOAD": payload,
    "_GEW_RUNNER_SOURCE": runner,
    "__name__": "__gew_pipe_runner__",
}
exec(compile(runner, "<verified-runner>", "exec", dont_inherit=True), scope)
"""


@contextlib.contextmanager
def _source_mutation_exclusion(
    candidate: ExtensionCoverageCandidateContext,
) -> Iterator[None]:
    """Hold the canonical installation source lock for one issuance transaction."""

    issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(candidate))
    configured = sys._xoptions.get(_CONTROL_OPTION)
    if issued is None or type(configured) is not str or not configured:
        raise ExtensionCoverageError("extension source mutation exclusion is unavailable")
    configured_path = pathlib.Path(configured)
    if not configured_path.is_absolute():
        raise ExtensionCoverageError("extension source mutation exclusion is unavailable")
    try:
        control_root = configured_path.resolve(strict=True)
        source_root = issued[0].resolve(strict=True)
    except OSError as error:
        raise ExtensionCoverageError("extension source mutation exclusion is unavailable") from error
    if control_root != configured_path:
        raise ExtensionCoverageError("extension source mutation exclusion is not canonical")
    control_metadata = os.lstat(control_root)
    source_metadata = os.lstat(source_root)
    if (
        not stat.S_ISDIR(control_metadata.st_mode)
        or stat.S_ISLNK(control_metadata.st_mode)
        or stat.S_IMODE(control_metadata.st_mode) != 0o700
        or control_metadata.st_uid != source_metadata.st_uid
        or not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or stat.S_IMODE(source_metadata.st_mode) & 0o022
    ):
        raise ExtensionCoverageError("extension source mutation exclusion is unsafe")
    control_descriptor = os.open(
        control_root,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor = -1
    try:
        opened_control = os.fstat(control_descriptor)
        lock_entry = os.stat(
            _CONTROL_LOCK,
            dir_fd=control_descriptor,
            follow_symlinks=False,
        )
        descriptor = os.open(
            _CONTROL_LOCK,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=control_descriptor,
        )
        metadata = os.fstat(descriptor)
        if (
            (opened_control.st_dev, opened_control.st_ino)
            != (control_metadata.st_dev, control_metadata.st_ino)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != source_metadata.st_uid
            or metadata.st_nlink != 1
            or (
                lock_entry.st_dev, lock_entry.st_ino, lock_entry.st_uid,
                stat.S_IMODE(lock_entry.st_mode), lock_entry.st_nlink,
            ) != (
                metadata.st_dev, metadata.st_ino, metadata.st_uid,
                stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
            )
        ):
            raise ExtensionCoverageError("extension source mutation exclusion lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        locked_entry = os.stat(
            _CONTROL_LOCK,
            dir_fd=control_descriptor,
            follow_symlinks=False,
        )
        if (locked_entry.st_dev, locked_entry.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ExtensionCoverageError("extension source mutation exclusion lock changed")
        candidate.require_current()
        yield
        candidate.require_current()
        live_control = os.stat(control_root, follow_symlinks=False)
        live_entry = os.stat(
            _CONTROL_LOCK,
            dir_fd=control_descriptor,
            follow_symlinks=False,
        )
        live_lock = os.fstat(descriptor)
        if (
            (live_control.st_dev, live_control.st_ino)
            != (control_metadata.st_dev, control_metadata.st_ino)
            or (live_entry.st_dev, live_entry.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or (live_lock.st_dev, live_lock.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise ExtensionCoverageError("extension source mutation exclusion binding changed")
    except OSError as error:
        raise ExtensionCoverageError("extension source mutation exclusion changed") from error
    finally:
        try:
            if descriptor >= 0:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(control_descriptor)


def _coverage_digest(body: object, name: str) -> str:
    schema_ids = {
        "extension-coverage-matrix": "urn:gew:schema:trace-matrix:1.0.0",
        "extension-oracle-manifest": "urn:gew:schema:oracle-manifest:1.0.0",
    }
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=schema_ids.get(name, f"urn:gew:schema:{name}-input:1.0.0"),
    )


_REQUIREMENT_ROW = {
    "obligation_id": "FR-18", "pass_test_id": "GEW-REQ-FR18-P",
    "reject_test_id": "GEW-REQ-FR18-R", "fixture_id": "trusted-extension",
    "oracle_id": "ORA-EXTENSION-POLICY", "evidence_type": "load/rejection",
    "owner_gate": "WP-08A",
}
_EXIT_ROW = {
    "obligation_id": "WP-08A-EXIT", "pass_test_id": "GEW-WP-08A-EXIT-P",
    "reject_test_id": "GEW-WP-08A-EXIT-R", "fixture_id": "wp08a-exit",
    "oracle_id": "ORA-WP08A-EXIT", "evidence_type": "WorkPackageExitRecord",
    "owner_gate": "WP-08A",
}
_ADR4_RESULTS = {
    "ADR4-PKG-P-001": "accept",
    "ADR4-PKG-R-001": "E_EXTENSION_DIGEST_CYCLE",
    "ADR4-PKG-R-002": "E_EXTENSION_DIGEST_CYCLE",
    "ADR4-PKG-R-003": "E_EXTENSION_ARCHIVE_PROFILE",
    "ADR4-PKG-R-004": "E_EXTENSION_PAYLOAD_ROOT",
    "ADR4-PKG-R-005": "E_EXTENSION_PROJECTION",
    "ADR4-PKG-R-006": "E_EXTENSION_SIGNATURE_INPUT",
    "ADR4-PKG-R-007": "E_EXTENSION_TRUST_ROOT",
    "ADR4-PKG-R-008": "E_EXTENSION_SOURCE_CHANGED",
    "ADR4-PKG-R-009": "E_EXTENSION_PACKAGE_IDENTITY",
    "ADR4-PKG-R-010": "E_EXTENSION_PAYLOAD_ROOT",
}
_TEST_IDS = frozenset({
    *_ADR4_RESULTS,
    "GEW-REQ-FR18-P", "GEW-REQ-FR18-R",
    "GEW-WP-08A-EXIT-P", "GEW-WP-08A-EXIT-R",
    "GEW-WP-08A-TRUST-FAULT-P", "GEW-WP-08A-ACTIVATION-FAULT-P",
    "GEW-WP-08A-ROLLBACK-P",
})
_EXECUTIONS = {
    **{
        vector_id: {
            "qualified_test": (
                "tests.unit.test_wp08a_adr4_corpus.ExtensionAdr4CorpusTests."
                + "test_" + vector_id.lower().replace("-", "_")
            ),
            "expected_result": result,
        }
        for vector_id, result in _ADR4_RESULTS.items()
    },
    "GEW-REQ-FR18-P": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_policy_enforcement."
            "ExtensionPolicyEnforcementTests.test_gew_ext_029_signed_production_policy_content_is_required_and_exact"
        ),
        "expected_result": "PASS",
    },
    "GEW-REQ-FR18-R": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_policy_enforcement."
            "ExtensionPolicyEnforcementTests.test_gew_ext_028_exact_key_rules_and_all_target_revocations_precede_install"
        ),
        "expected_result": "PASS",
    },
    "GEW-WP-08A-EXIT-P": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_policy_enforcement."
            "ExtensionPolicyEnforcementTests.test_gew_ext_031_versioned_fault_schedule_recovers_install_activation_and_rollback"
        ),
        "expected_result": "PASS",
    },
    "GEW-WP-08A-EXIT-R": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_policy_enforcement."
            "ExtensionPolicyEnforcementTests.test_gew_ext_032_trust_plane_has_zero_dns_socket_proxy_and_executable_gates"
        ),
        "expected_result": "PASS",
    },
    "GEW-WP-08A-TRUST-FAULT-P": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_trust_repository."
            "ExtensionTrustRepositoryTests.test_gew_ext_005_fault_cuts_are_atomic_and_restart_recovers_exact_old_or_new"
        ),
        "expected_result": "PASS",
    },
    "GEW-WP-08A-ACTIVATION-FAULT-P": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_active_set."
            "ExtensionActiveSetTests.test_gew_ext_022_fault_cuts_restart_to_exact_old_or_new_generation"
        ),
        "expected_result": "PASS",
    },
    "GEW-WP-08A-ROLLBACK-P": {
        "qualified_test": (
            "tests.integration.test_wp08a_extension_active_set."
            "ExtensionActiveSetTests.test_gew_ext_021_supersede_rollback_remove_and_owner_ingress_are_deterministic"
        ),
        "expected_result": "PASS",
    },
}
_ORACLES = [
    {
        "oracle_id": "ORA-EXTENSION-POLICY",
        "implementation": "tests.integration.test_wp08a_extension_policy_enforcement",
        "independent_state": "bundle/trust/activation",
    },
    {
        "oracle_id": "ORA-WP08A-EXIT",
        "implementation": "tests.integration.test_wp08a_review_closure",
        "independent_state": "exact-set/fault/network",
    },
    {
        "oracle_id": "ORA-ADR4-GOLDEN",
        "implementation": "tests.unit.test_wp08a_adr4_corpus",
        "independent_state": "golden/rejection-vectors",
    },
    *(
        {
            "oracle_id": f"ORA-PROFILE-{profile_id}",
            "implementation": "tests.unit.test_wp08_profile_contracts",
            "independent_state": f"profile/{profile_id.lower()}",
        }
        for profile_id in (
            "NEW-FEATURE", "BUG-FIX", "HOTFIX", "REFACTOR-DEBT", "MIGRATION",
            "DEPENDENCY-SECURITY", "PERFORMANCE", "RELEASE-OPERATIONS",
            "INCIDENT-RESPONSE",
        )
    ),
]
_FAULT_SCHEDULES = {
    "trust": [
        "extension-trust.after-commit-durability",
        "extension-trust.before-restoration-publication",
        "extension-trust.after-restoration-durability",
        "extension-trust.after-restoration-reread",
    ],
    "install": [
        "extension-install.before-content", "extension-install.after-content",
        "extension-install.after-ledger", "extension-install.after-commit",
    ],
    "activation": [
        "extension-activation.after-data-registry",
        "extension-activation.after-manifest",
        "extension-activation.after-pointer-cas",
        "extension-activation.after-commit",
        "extension-activation.after-publish-durability",
        "extension-activation.before-restoration-publication",
        "extension-activation.after-restoration-durability",
        "extension-activation.after-restoration-reread",
    ],
    "rollback": [
        "extension-activation.after-data-registry",
        "extension-activation.after-manifest",
        "extension-activation.after-pointer-cas",
        "extension-activation.after-commit",
    ],
}


@dataclass(frozen=True, slots=True)
class ExtensionCoverageMatrix:
    _document: FrozenMap

    @classmethod
    def from_dict(cls, value: object) -> ExtensionCoverageMatrix:
        fields = {
            "schema_version", "matrix_id", "requirement_rows", "work_package_rows",
            "adr4_vectors", "test_ids", "executions",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionCoverageError("extension trace matrix is not exact")
        if value.get("schema_version") != "1.0.0" or value.get("matrix_id") != "gew.wp08a.trace-matrix":
            raise ExtensionCoverageError("extension trace matrix identity is invalid")
        if value.get("requirement_rows") != [_REQUIREMENT_ROW] or value.get("work_package_rows") != [_EXIT_ROW]:
            raise ExtensionCoverageError("extension trace obligation rows are incomplete")
        vectors = value.get("adr4_vectors")
        if type(vectors) is not list or {
            item.get("vector_id"): item.get("result")
            for item in vectors if isinstance(item, Mapping) and set(item) == {"vector_id", "result"}
        } != _ADR4_RESULTS or len(vectors) != len(_ADR4_RESULTS):
            raise ExtensionCoverageError("ADR-0004 vector set is incomplete or substituted")
        test_ids = value.get("test_ids")
        if type(test_ids) is not list or frozenset(test_ids) != _TEST_IDS or len(test_ids) != len(_TEST_IDS):
            raise ExtensionCoverageError("extension trace test ID set is incomplete or substituted")
        if value.get("executions") != _EXECUTIONS:
            raise ExtensionCoverageError("extension trace executable bindings are incomplete")
        return cls(freeze(value))

    def to_dict(self) -> dict[str, object]:
        document = thaw(self._document)
        assert isinstance(document, dict)
        return document

    def reduce_results(self, results: object) -> frozenset[str]:
        """Reduce only exact records issued by the bound execution authority."""

        if type(results) is not tuple or any(
            type(item) is not ExtensionCoverageExecutionRecord for item in results
        ):
            raise ExtensionCoverageError("extension runnable result set is incomplete")
        indexed: dict[str, ExtensionCoverageExecutionRecord] = {}
        authority: ExtensionCoverageAuthority | None = None
        for record in results:
            record_authority = record._authority
            if type(record_authority) is not ExtensionCoverageAuthority:
                raise ExtensionCoverageError("extension execution authority is substituted")
            record_authority._require_issued_record(record)
            if authority is None:
                authority = record_authority
            elif authority is not record_authority:
                raise ExtensionCoverageError("extension execution authority is substituted")
            document = record.to_dict()
            test_id = str(document["test_id"])
            if test_id in indexed:
                raise ExtensionCoverageError("extension execution record is duplicated")
            indexed[test_id] = record
        if set(indexed) != set(_EXECUTIONS):
            raise ExtensionCoverageError("extension runnable result set is incomplete")
        if authority is None or authority._matrix is not self:
            raise ExtensionCoverageError("extension execution authority is unavailable")
        authority_binding = authority._issued_binding()
        context = authority_binding[2]
        context.require_current()
        for test_id, binding in _EXECUTIONS.items():
            document = indexed[test_id].to_dict()
            executable_binding = authority_binding[3][test_id]
            if (
                document["matrix_digest"] != _coverage_digest(self.to_dict(), "extension-coverage-matrix")
                or document["oracle_digest"] != authority_binding[1]
                or document["candidate_id"] != context.candidate_id
                or document["candidate_context_digest"] != context.context_digest
                or document["source_manifest_digest"] != context.source_manifest_digest
                or document["qualified_test"] != binding["qualified_test"]
                or document["result"] != binding["expected_result"]
                or any(document[field] != value for field, value in executable_binding.items())
            ):
                raise ExtensionCoverageError(
                    f"extension runnable result differs for {test_id}"
                )
        return frozenset(indexed)


@dataclass(frozen=True, slots=True)
class ExtensionOracleManifest:
    _document: FrozenMap

    @classmethod
    def from_dict(cls, value: object) -> ExtensionOracleManifest:
        fields = {
            "schema_version", "manifest_id", "oracles", "fault_schedules",
            "trust_plane_network_counters",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionCoverageError("extension oracle manifest is not exact")
        if value.get("schema_version") != "1.0.0" or value.get("manifest_id") != "gew.wp08a.oracle-manifest":
            raise ExtensionCoverageError("extension oracle manifest identity is invalid")
        oracles = value.get("oracles")
        if oracles != _ORACLES:
            raise ExtensionCoverageError("extension oracle set is incomplete")
        counters = value.get("trust_plane_network_counters")
        if counters != {"dns": 0, "socket": 0, "proxy": 0}:
            raise ExtensionCoverageError("extension trust-plane network oracle is not zero")
        schedules = value.get("fault_schedules")
        if schedules != _FAULT_SCHEDULES:
            raise ExtensionCoverageError("extension fault schedule set is incomplete")
        return cls(freeze(value))

    def to_dict(self) -> dict[str, object]:
        document = thaw(self._document)
        assert isinstance(document, dict)
        return document


_ISSUED_CANDIDATE_CONTEXTS: dict[int, tuple[pathlib.Path, str, str]] = {}


@dataclass(frozen=True, slots=True)
class ExtensionCoverageCandidateContext:
    candidate_id: str
    source_manifest_digest: str
    target_set_digest: str
    root_device: int
    root_inode: int
    root_owner: int
    root_mode: int
    context_digest: str

    @staticmethod
    def _snapshot(
        root: pathlib.Path,
    ) -> tuple[str, str, dict[str, object], frozenset[str]]:
        resolved = root.resolve(strict=True)
        root_stat = resolved.stat()
        if (
            resolved != root.absolute()
            or root.is_symlink()
            or not resolved.is_dir()
            or not stat.S_ISDIR(root_stat.st_mode)
        ):
            raise ExtensionCoverageError("extension Candidate root is not canonical")
        target_path = resolved / "config/verification/wp-00-targets.json"
        try:
            specification = json.loads(target_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExtensionCoverageError("extension Candidate target set is unavailable") from error
        if not isinstance(specification, Mapping) or set(specification) != {
            "schema_version", "owned_roots", "files",
        } or specification.get("schema_version") != "1.0":
            raise ExtensionCoverageError("extension Candidate target set is not exact")
        declared_value = specification.get("files")
        owned_value = specification.get("owned_roots")
        if (
            type(declared_value) is not list
            or not declared_value
            or any(type(item) is not str or not item for item in declared_value)
            or declared_value != sorted(set(declared_value))
            or type(owned_value) is not list
            or not owned_value
            or any(
                type(item) is not str
                or not item
                or pathlib.PurePosixPath(item).is_absolute()
                or any(part in {"", ".", ".."} for part in pathlib.PurePosixPath(item).parts)
                for item in owned_value
            )
            or len(owned_value) != len(set(owned_value))
        ):
            raise ExtensionCoverageError("extension Candidate target set is not canonical")
        declared = tuple(declared_value)
        owned_roots = tuple(owned_value)
        actual: set[str] = {"pyproject.toml", "uv.lock"}
        for root_name in owned_roots:
            owned = resolved / root_name
            if owned.is_symlink() or not owned.is_dir() or owned.resolve() != owned.absolute():
                raise ExtensionCoverageError("extension Candidate owned root is invalid")
            for path in owned.rglob("*"):
                if path.is_symlink():
                    raise ExtensionCoverageError("extension Candidate contains a symlink")
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    actual.add(path.relative_to(resolved).as_posix())
        if actual != set(declared):
            raise ExtensionCoverageError("extension Candidate target set differs from repository")
        files: list[dict[str, object]] = []
        for name in declared:
            relative = pathlib.PurePosixPath(name)
            if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
                raise ExtensionCoverageError("extension Candidate target path is invalid")
            path = resolved / relative
            if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
                raise ExtensionCoverageError("extension Candidate target file is invalid")
            body = path.read_bytes()
            files.append({
                "path": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "size": len(body),
            })
        manifest_body: dict[str, object] = {"schema_version": "1.0", "files": files}
        digest = hashlib.sha256(canonical_bytes(manifest_body)).hexdigest()
        target_set_digest = hashlib.sha256(canonical_bytes(specification)).hexdigest()
        return digest, target_set_digest, {
            "root_device": root_stat.st_dev,
            "root_inode": root_stat.st_ino,
            "root_owner": root_stat.st_uid,
            "root_mode": stat.S_IMODE(root_stat.st_mode),
        }, frozenset(declared)

    @classmethod
    def verify_current(
        cls,
        candidate_id: str,
        source_root: pathlib.Path,
    ) -> ExtensionCoverageCandidateContext:
        if type(candidate_id) is not str or not candidate_id or candidate_id.strip() != candidate_id:
            raise ExtensionCoverageError("extension Candidate ID is invalid")
        if not isinstance(source_root, pathlib.Path):
            raise TypeError("extension Candidate verification inputs are not exact")
        digest, target_set_digest, identity, _declared = cls._snapshot(source_root)
        body = {
            "schema_version": "1.0.0",
            "candidate_id": candidate_id,
            "source_manifest_digest": digest,
            "target_set_digest": target_set_digest,
            **identity,
        }
        context = cls(
            candidate_id,
            digest,
            target_set_digest,
            int(identity["root_device"]),
            int(identity["root_inode"]),
            int(identity["root_owner"]),
            int(identity["root_mode"]),
            _coverage_digest(body, "extension-coverage-candidate-context"),
        )
        _ISSUED_CANDIDATE_CONTEXTS[id(context)] = (
            source_root.resolve(strict=True), target_set_digest, context.context_digest,
        )
        return context

    def require_current(self) -> None:
        issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(self))
        if issued is None or issued[2] != self.context_digest:
            raise ExtensionCoverageError("extension Candidate context is not verified")
        digest, target_set_digest, identity, _declared = self._snapshot(issued[0])
        if (
            digest != self.source_manifest_digest
            or target_set_digest != self.target_set_digest
            or target_set_digest != issued[1]
            or identity != {
                "root_device": self.root_device,
                "root_inode": self.root_inode,
                "root_owner": self.root_owner,
                "root_mode": self.root_mode,
            }
        ):
            raise ExtensionCoverageError("extension Candidate source manifest is stale")

    def require_execution_bindings(self) -> None:
        issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(self))
        if issued is None:
            raise ExtensionCoverageError("extension Candidate context is not verified")
        root = issued[0]
        _digest, _target_digest, _identity, declared = self._snapshot(root)
        module_file = pathlib.Path(__file__).resolve(strict=True)
        if not module_file.is_relative_to(root):
            raise ExtensionCoverageError("coverage reducer is outside the verified Candidate")
        for binding in _EXECUTIONS.values():
            module_name = ".".join(str(binding["qualified_test"]).split(".")[:3])
            relative = pathlib.PurePosixPath(module_name.replace(".", "/") + ".py")
            origin = (root / relative).resolve(strict=True)
            if relative.as_posix() not in declared or not origin.is_relative_to(root):
                raise ExtensionCoverageError(
                    "coverage execution module is outside the verified Candidate"
                )
        if "scripts/run_verified_test.py" not in declared:
            raise ExtensionCoverageError("coverage runner is outside the verified Candidate")

    def execution_binding(self, qualified_test: str) -> dict[str, str]:
        issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(self))
        if issued is None:
            raise ExtensionCoverageError("extension Candidate context is not verified")
        binding, _module_source, _callable_source, _runner_source = self.execution_sources(
            qualified_test
        )
        return binding

    @staticmethod
    def _descriptor_bytes(path: pathlib.Path) -> bytes:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) & 0o022
            ):
                raise ExtensionCoverageError("extension execution source descriptor is unsafe")
            body = bytearray()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                body.extend(chunk)
            after = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(body) != before.st_size
            ):
                raise ExtensionCoverageError("extension execution source changed during read")
            return bytes(body)
        finally:
            os.close(descriptor)

    @staticmethod
    def _code_fingerprint(code: CodeType) -> str:
        def value_projection(value: object) -> object:
            if value is None or type(value) in (bool, int, float, str):
                return value
            if type(value) is bytes:
                return {"bytes": base64.b64encode(value).decode("ascii")}
            if type(value) is tuple:
                return {"tuple": [value_projection(item) for item in value]}
            if type(value) is frozenset:
                projected = [value_projection(item) for item in value]
                return {"frozenset": sorted(projected, key=canonical_bytes)}
            if type(value) is CodeType:
                return code_projection(value)
            return {"constant_type": type(value).__name__, "representation": repr(value)}

        def code_projection(current: CodeType) -> dict[str, object]:
            return {
                "argcount": current.co_argcount,
                "posonlyargcount": current.co_posonlyargcount,
                "kwonlyargcount": current.co_kwonlyargcount,
                "nlocals": current.co_nlocals,
                "stacksize": current.co_stacksize,
                "flags": current.co_flags,
                "code": base64.b64encode(current.co_code).decode("ascii"),
                "consts": [value_projection(value) for value in current.co_consts],
                "names": list(current.co_names),
                "varnames": list(current.co_varnames),
                "freevars": list(current.co_freevars),
                "cellvars": list(current.co_cellvars),
                "name": current.co_name,
                "qualname": current.co_qualname,
                "firstlineno": current.co_firstlineno,
                "linetable": base64.b64encode(current.co_linetable).decode("ascii"),
                "exceptiontable": base64.b64encode(current.co_exceptiontable).decode("ascii"),
            }

        return hashlib.sha256(canonical_bytes(code_projection(code))).hexdigest()

    @classmethod
    def _execution_binding_from_bytes(
        cls,
        module_body: bytes,
        runner_body: bytes,
        qualified_test: str,
    ) -> dict[str, str]:
        parts = qualified_test.split(".")
        if len(parts) < 5:
            raise ExtensionCoverageError("extension test binding is malformed")
        try:
            source = module_body.decode("utf-8")
            tree = ast.parse(source, filename="<verified-test-module>")
            class_node = next(
                node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == parts[-2]
            )
            callable_node = next(
                node for node in class_node.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == parts[-1]
            )
            segment = ast.get_source_segment(source, callable_node)
            module_code = compile(source, "<verified-test-module>", "exec", dont_inherit=True)
            class_code = next(
                value for value in module_code.co_consts
                if type(value) is CodeType and value.co_name == parts[-2]
            )
            runtime_code = next(
                value for value in class_code.co_consts
                if type(value) is CodeType and value.co_name == parts[-1]
            )
        except (UnicodeDecodeError, SyntaxError, StopIteration) as error:
            raise ExtensionCoverageError("extension test binding is unavailable") from error
        if segment is None:
            raise ExtensionCoverageError("extension test source binding is unavailable")
        return {
            "module_digest": hashlib.sha256(module_body).hexdigest(),
            "callable_source_digest": hashlib.sha256(segment.encode("utf-8")).hexdigest(),
            "callable_code_digest": cls._code_fingerprint(runtime_code),
            "runner_digest": hashlib.sha256(runner_body).hexdigest(),
        }

    @staticmethod
    def _callable_source_bytes(module_body: bytes, qualified_test: str) -> bytes:
        parts = qualified_test.split(".")
        try:
            source = module_body.decode("utf-8")
            tree = ast.parse(source, filename="<verified-test-module>")
            class_node = next(
                node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == parts[-2]
            )
            callable_node = next(
                node for node in class_node.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == parts[-1]
            )
            segment = ast.get_source_segment(source, callable_node)
        except (UnicodeDecodeError, SyntaxError, StopIteration, IndexError) as error:
            raise ExtensionCoverageError("extension callable source is unavailable") from error
        if segment is None:
            raise ExtensionCoverageError("extension callable source is unavailable")
        return segment.encode("utf-8")

    def execution_sources(
        self,
        qualified_test: str,
    ) -> tuple[dict[str, str], bytes, bytes, bytes]:
        self.require_current()
        issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(self))
        if issued is None:
            raise ExtensionCoverageError("extension Candidate context is not verified")
        root = issued[0]
        module_name = ".".join(qualified_test.split(".")[:3])
        module_body = self._descriptor_bytes(
            root / (module_name.replace(".", "/") + ".py")
        )
        runner_body = self._descriptor_bytes(root / "scripts/run_verified_test.py")
        binding = self._execution_binding_from_bytes(
            module_body, runner_body, qualified_test
        )
        callable_source = self._callable_source_bytes(module_body, qualified_test)
        self.require_current()
        return binding, module_body, callable_source, runner_body

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "candidate_id": self.candidate_id,
            "source_manifest_digest": self.source_manifest_digest,
            "target_set_digest": self.target_set_digest,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "root_owner": self.root_owner,
            "root_mode": self.root_mode,
            "context_digest": self.context_digest,
        }


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class ExtensionCoverageExecutionRecord:
    _document: FrozenMap
    _authority: ExtensionCoverageAuthority

    @classmethod
    def _from_issued(
        cls,
        value: Mapping[str, object],
        authority: ExtensionCoverageAuthority,
    ) -> ExtensionCoverageExecutionRecord:
        if type(authority) is not ExtensionCoverageAuthority:
            raise ExtensionCoverageError("extension execution authority is substituted")
        authority._require_factory_issued()
        fields = {
            "schema_version", "test_id", "qualified_test", "result",
            "harness_result",
            "matrix_digest", "oracle_digest", "candidate_id",
            "candidate_context_digest", "source_manifest_digest",
            "module_digest", "callable_source_digest", "callable_code_digest",
            "runner_digest", "observed_result_digest",
            "occurred_at", "execution_digest",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise ExtensionCoverageError("extension execution record is not exact")
        body = dict(value)
        claimed = require_digest(body.pop("execution_digest", None), "execution digest")
        if claimed != _coverage_digest(body, "extension-coverage-execution"):
            raise ExtensionCoverageError("extension execution record digest mismatch")
        if (
            type(body.get("test_id")) is not str
            or body["test_id"] not in _EXECUTIONS
            or type(body.get("qualified_test")) is not str
            or not body["qualified_test"]
        ):
            raise ExtensionCoverageError("extension execution identity is invalid")
        if body.get("harness_result") != "PASS":
            raise ExtensionCoverageError("extension execution did not pass its exact harness")
        require_digest(body.get("matrix_digest"), "extension execution matrix digest")
        require_digest(body.get("oracle_digest"), "extension execution oracle digest")
        require_digest(
            body.get("candidate_context_digest"), "extension execution Candidate context digest"
        )
        for field in (
            "module_digest", "callable_source_digest", "callable_code_digest",
            "runner_digest", "observed_result_digest",
        ):
            digest_value = body.get(field)
            if type(digest_value) is not str or _RAW_SHA256.fullmatch(digest_value) is None:
                raise ExtensionCoverageError(f"extension execution {field} is invalid")
        if (
            type(body.get("candidate_id")) is not str
            or not body["candidate_id"]
            or type(body.get("source_manifest_digest")) is not str
            or _RAW_SHA256.fullmatch(body["source_manifest_digest"]) is None
        ):
            raise ExtensionCoverageError("extension execution Candidate binding is invalid")
        parse_timestamp(body.get("occurred_at"), "extension execution time")
        return cls(freeze(value), authority)

    def to_dict(self) -> dict[str, object]:
        document = thaw(self._document)
        assert isinstance(document, dict)
        return document


_ISSUED_COVERAGE_AUTHORITIES: list[weakref.ReferenceType[object]] = []
_COVERAGE_AUTHORITY_REGISTRY_LOCK = threading.RLock()


def _register_coverage_authority(authority: ExtensionCoverageAuthority) -> None:
    def release(reference: weakref.ReferenceType[object]) -> None:
        with _COVERAGE_AUTHORITY_REGISTRY_LOCK:
            _ISSUED_COVERAGE_AUTHORITIES[:] = [
                item
                for item in _ISSUED_COVERAGE_AUTHORITIES
                if item is not reference and item() is not None
            ]

    reference = weakref.ref(authority, release)
    with _COVERAGE_AUTHORITY_REGISTRY_LOCK:
        _ISSUED_COVERAGE_AUTHORITIES[:] = [
            item for item in _ISSUED_COVERAGE_AUTHORITIES if item() is not None
        ]
        _ISSUED_COVERAGE_AUTHORITIES.append(reference)


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class ExtensionCoverageAuthority:
    _matrix: ExtensionCoverageMatrix
    _oracle: ExtensionOracleManifest
    _candidate: ExtensionCoverageCandidateContext
    _matrix_digest: str
    _oracle_digest: str
    _execution_bindings: FrozenMap
    _issued_records: list[weakref.ReferenceType[object]]
    _issued_record_lock: threading.RLock

    @classmethod
    def issue(
        cls,
        matrix: ExtensionCoverageMatrix,
        oracle: ExtensionOracleManifest,
        candidate: ExtensionCoverageCandidateContext,
    ) -> ExtensionCoverageAuthority:
        if type(matrix) is not ExtensionCoverageMatrix or type(oracle) is not ExtensionOracleManifest:
            raise ExtensionCoverageError("extension coverage authority inputs are not exact")
        if type(candidate) is not ExtensionCoverageCandidateContext:
            raise TypeError("extension coverage Candidate context is required")
        candidate.require_current()
        candidate.require_execution_bindings()
        execution_bindings = {
            test_id: candidate.execution_binding(str(binding["qualified_test"]))
            for test_id, binding in _EXECUTIONS.items()
        }
        authority = cls(
            matrix,
            oracle,
            candidate,
            _coverage_digest(matrix.to_dict(), "extension-coverage-matrix"),
            _coverage_digest(oracle.to_dict(), "extension-oracle-manifest"),
            freeze(execution_bindings),
            [],
            threading.RLock(),
        )
        _register_coverage_authority(authority)
        return authority

    def _require_factory_issued(self) -> None:
        with _COVERAGE_AUTHORITY_REGISTRY_LOCK:
            live: list[weakref.ReferenceType[object]] = []
            authenticated = False
            for reference in _ISSUED_COVERAGE_AUTHORITIES:
                observed = reference()
                if observed is not None:
                    live.append(reference)
                    authenticated = authenticated or observed is self
            _ISSUED_COVERAGE_AUTHORITIES[:] = live
        if not authenticated:
            raise ExtensionCoverageError("extension coverage authority is not factory-issued")

    def _issued_binding(
        self,
    ) -> tuple[str, str, ExtensionCoverageCandidateContext, dict[str, dict[str, str]]]:
        self._require_factory_issued()
        execution_bindings = thaw(self._execution_bindings)
        assert isinstance(execution_bindings, dict)
        return (
            self._matrix_digest,
            self._oracle_digest,
            self._candidate,
            execution_bindings,
        )

    def _remove_issued_record_reference(
        self,
        target: weakref.ReferenceType[object],
    ) -> None:
        with self._issued_record_lock:
            self._issued_records[:] = [
                reference
                for reference in self._issued_records
                if reference is not target and reference() is not None
            ]

    def _register_issued_record(
        self,
        record: ExtensionCoverageExecutionRecord,
    ) -> weakref.ReferenceType[object]:
        self._require_factory_issued()
        if type(record) is not ExtensionCoverageExecutionRecord or record._authority is not self:
            raise ExtensionCoverageError("extension execution record authority is substituted")
        authority_reference = weakref.ref(self)

        def release(reference: weakref.ReferenceType[object]) -> None:
            authority = authority_reference()
            if type(authority) is ExtensionCoverageAuthority:
                authority._remove_issued_record_reference(reference)

        reference = weakref.ref(record, release)
        with self._issued_record_lock:
            self._issued_records[:] = [
                item for item in self._issued_records if item() is not None
            ]
            self._issued_records.append(reference)
        return reference

    def _withdraw_issued_record(
        self,
        record: ExtensionCoverageExecutionRecord,
        reference: weakref.ReferenceType[object],
    ) -> None:
        with self._issued_record_lock:
            for index, issued in enumerate(self._issued_records):
                if issued is reference:
                    if issued() is not record:
                        raise ExtensionCoverageError(
                            "extension execution record withdrawal is substituted"
                        )
                    del self._issued_records[index]
                    return
        raise ExtensionCoverageError("extension execution record was not issued")

    def _require_issued_record(self, record: ExtensionCoverageExecutionRecord) -> None:
        self._require_factory_issued()
        if type(record) is not ExtensionCoverageExecutionRecord or record._authority is not self:
            raise ExtensionCoverageError("extension execution record authority is substituted")
        with self._issued_record_lock:
            self._issued_records[:] = [
                reference
                for reference in self._issued_records
                if reference() is not None
            ]
            if not any(reference() is record for reference in self._issued_records):
                raise ExtensionCoverageError(
                    "extension execution record is not authenticated"
                )

    def _issued_record_count(self) -> int:
        self._require_factory_issued()
        with self._issued_record_lock:
            self._issued_records[:] = [
                reference
                for reference in self._issued_records
                if reference() is not None
            ]
            return len(self._issued_records)

    def execute(
        self,
        test_id: str,
        *,
        occurred_at: str,
        _probe_hook: Callable[[str, str], str] | None = None,
    ) -> ExtensionCoverageExecutionRecord:
        """Execute and authenticate one record under source-mutation exclusion."""

        binding = self._issued_binding()
        if _EXECUTIONS.get(test_id) is None:
            raise ExtensionCoverageError("extension execution binding is not authorized")
        if _probe_hook is not None and not callable(_probe_hook):
            raise TypeError("extension execution probe hook must be callable")
        with _source_mutation_exclusion(binding[2]):
            return self._execute_transaction(
                test_id,
                occurred_at=occurred_at,
                probe_hook=_probe_hook,
            )

    @staticmethod
    def _transaction_probe(
        point: str,
        *,
        candidate: ExtensionCoverageCandidateContext,
        qualified_test: str,
        executable_binding: dict[str, str],
        probe_hook: Callable[[str, str], str] | None,
    ) -> None:
        expected = hashlib.sha256(canonical_bytes({
            "schema_version": "1.0.0",
            "point": point,
            "candidate_context_digest": candidate.context_digest,
            "qualified_test": qualified_test,
            "executable_binding": executable_binding,
        })).hexdigest()
        if probe_hook is not None:
            try:
                observed = probe_hook(point, expected)
            except BaseException as error:
                raise ExtensionCoverageError(
                    f"extension issuance probe failed at {point}"
                ) from error
            if observed != expected:
                raise ExtensionCoverageError(
                    f"extension issuance probe mismatch at {point}"
                )
        candidate.require_current()
        rebound, _module, _callable, _runner = candidate.execution_sources(qualified_test)
        if rebound != executable_binding:
            raise ExtensionCoverageError(
                f"extension issuance transaction binding changed at {point}"
            )

    def _execute_transaction(
        self,
        test_id: str,
        *,
        occurred_at: str,
        probe_hook: Callable[[str, str], str] | None,
    ) -> ExtensionCoverageExecutionRecord:
        """Construct and publish one record atomically while the source lock is held."""

        binding = self._issued_binding()
        expected = _EXECUTIONS.get(test_id)
        if expected is None:
            raise ExtensionCoverageError("extension execution binding is not authorized")
        binding[2].require_current()
        parse_timestamp(occurred_at, "extension execution time")
        qualified_test = str(expected["qualified_test"])
        current_binding, module_source, callable_source, runner_source = (
            binding[2].execution_sources(qualified_test)
        )
        if current_binding != binding[3][test_id]:
            raise ExtensionCoverageError("extension executable binding changed")
        issued = _ISSUED_CANDIDATE_CONTEXTS.get(id(binding[2]))
        if issued is None:
            raise ExtensionCoverageError("extension Candidate context is unavailable")
        root = issued[0]
        payload = {
            "schema_version": "1.0.0",
            "source_root": str(root),
            "qualified_test": qualified_test,
            "module_name": ".".join(qualified_test.split(".")[:3]),
            "module_source_b64": base64.b64encode(module_source).decode("ascii"),
            "callable_source_b64": base64.b64encode(callable_source).decode("ascii"),
            **current_binding,
        }
        envelope = {
            "runner_source_b64": base64.b64encode(runner_source).decode("ascii"),
            "payload": payload,
        }
        self._transaction_probe(
            "coverage.child-import",
            candidate=binding[2],
            qualified_test=qualified_test,
            executable_binding=current_binding,
            probe_hook=probe_hook,
        )
        command = [sys.executable, "-I", "-c", _PIPE_BOOTSTRAP]
        completed = subprocess.run(
            command,
            cwd=root,
            input=canonical_bytes(envelope),
            check=False,
            capture_output=True,
        )
        self._transaction_probe(
            "coverage.child-return",
            candidate=binding[2],
            qualified_test=qualified_test,
            executable_binding=current_binding,
            probe_hook=probe_hook,
        )
        # Rebind the canonical manifest and the three executable byte sets as
        # soon as the byte-pipe child returns.  No child output is interpreted
        # and no record can be issued before these postconditions pass.
        binding[2].require_current()
        post_binding, _post_module, _post_callable, _post_runner = (
            binding[2].execution_sources(qualified_test)
        )
        if post_binding != current_binding:
            raise ExtensionCoverageError("extension executable binding changed")
        if completed.args != command:
            raise ExtensionCoverageError("extension isolated harness launch was substituted")
        self._transaction_probe(
            "coverage.result-interpretation",
            candidate=binding[2],
            qualified_test=qualified_test,
            executable_binding=current_binding,
            probe_hook=probe_hook,
        )
        try:
            observed = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExtensionCoverageError("extension isolated harness output is malformed") from error
        expected_observation_body = {
            "schema_version": "1.0.0",
            "qualified_test": qualified_test,
            "tests_run": 1,
            "successful": True,
            "failures": 0,
            "errors": 0,
            "captured_stdout_empty": True,
            "captured_stderr_empty": True,
            **current_binding,
        }
        expected_observation = {
            **expected_observation_body,
            "observed_result_digest": hashlib.sha256(
                canonical_bytes(expected_observation_body)
            ).hexdigest(),
        }
        if completed.returncode != 0 or observed != expected_observation or completed.stderr != b"":
            raise ExtensionCoverageError("extension bound test did not pass")
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "test_id": test_id,
            "qualified_test": qualified_test,
            "result": expected["expected_result"],
            "harness_result": "PASS",
            "matrix_digest": binding[0],
            "oracle_digest": binding[1],
            "candidate_id": binding[2].candidate_id,
            "candidate_context_digest": binding[2].context_digest,
            "source_manifest_digest": binding[2].source_manifest_digest,
            **current_binding,
            "observed_result_digest": observed["observed_result_digest"],
            "occurred_at": occurred_at,
        }
        document = {**body, "execution_digest": _coverage_digest(body, "extension-coverage-execution")}
        self._transaction_probe(
            "coverage.pre-auth",
            candidate=binding[2],
            qualified_test=qualified_test,
            executable_binding=current_binding,
            probe_hook=probe_hook,
        )
        record = ExtensionCoverageExecutionRecord._from_issued(document, self)
        record_reference = self._register_issued_record(record)
        try:
            self._transaction_probe(
                "coverage.post-insert-pre-return",
                candidate=binding[2],
                qualified_test=qualified_test,
                executable_binding=current_binding,
                probe_hook=probe_hook,
            )
            return record
        except BaseException:
            self._withdraw_issued_record(record, record_reference)
            raise
