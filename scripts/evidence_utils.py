"""Deterministic command and evidence primitives for WP-00."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.metadata as importlib_metadata
import importlib.util
import itertools
import json
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tomllib
import _sqlite3


ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
GOVERNING_DOCUMENT_PATHS = (
    "docs/adr/0003-deterministic-contract-stack.md",
    "docs/test-plans/graph-engineering-workflow.md",
)
WP02_GOVERNING_DOCUMENT_PATHS = (
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0003-deterministic-contract-stack.md",
)
WP02_REFERENCE_IMPLEMENTATION = "tests/support/wp01_reference.mjs"
WP03_GOVERNING_DOCUMENT_PATHS = (
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0002-local-event-repository-and-coordination.md",
)
WP04A_GOVERNING_DOCUMENT_PATHS = (
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
)
WP04_GOVERNING_DOCUMENT_PATHS = WP04A_GOVERNING_DOCUMENT_PATHS
WP05A_GOVERNING_DOCUMENT_PATHS = WP04A_GOVERNING_DOCUMENT_PATHS
WP05_GOVERNING_DOCUMENT_PATHS = (
    "docs/positioning/baselines/graph-engineering-workflow-v2.md",
    "docs/positioning/baselines/graph-engineering-workflow-v2.sha256",
    "docs/prd/baselines/graph-engineering-workflow-v2.md",
    "docs/prd/baselines/graph-engineering-workflow-v2.sha256",
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0001-core-implementation-and-local-packaging.md",
    "docs/adr/0002-local-event-repository-and-coordination.md",
    "docs/adr/0003-deterministic-contract-stack.md",
    "docs/adr/0005-recovery-claim-compensation.md",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope.json",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope-wp-05-recovery-claim-amendment-r0.json",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/human-decision-wp-05-recovery-claim-r0.json",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-05-recovery-architecture-review-verdict-r3.json",
)
WP05_FROZEN_COMMAND_EVIDENCE_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-05-command-evidence-r2.json"
)
WP05_FROZEN_EXIT_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-05-exit-r2.json"
)
WP05_FROZEN_VERDICT_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-05-review-verdict-r2.json"
)
WP05_FROZEN_SOURCE_MANIFEST_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-05-source-manifest-r2.json"
)
WP05_FROZEN_SOURCE_MANIFEST_DIGEST = (
    "48536f411e6fb6213f049e7136541e69561fac0bb33df8a11bdab722898a7b8b"
)
WP05_FROZEN_COMMAND_EVIDENCE_DIGEST = (
    "ac096675fd5710c258929d859c673027864f63674db841d8fd1640d38aa05c0b"
)
WP05_FROZEN_EXIT_DIGEST = (
    "3d3f593b10bb3a8648519d9311bd032db5e78768ba7428ce10880f4ffb7fac9d"
)
WP05_FROZEN_VERDICT_DIGEST = (
    "118ad293fd39735c6ab19641687175c4b4a798f3ed2a0e481d84054897c223cc"
)
WP06_FROZEN_SOURCE_MANIFEST_DIGEST = (
    "505e0a62a2c2895f695372444f543e9d4bd71714fa93e3cfc91af0c272bcbb4e"
)
WP06_FROZEN_COMMAND_EVIDENCE_DIGEST = (
    "00affbb777987b06e0c4712babbc0f21ab8ffc94022532b6d95f95b4534b3052"
)
WP06_FROZEN_EXIT_DIGEST = (
    "08a310e77b881c1b029425a1e4615818fd039c7aba04737d6b4bc15172ba7cea"
)
WP06_FROZEN_VERDICT_DIGEST = (
    "07cc593a5561b13bfac0e59dfad615015660815358bee6b38111da896b319554"
)
WP06_FROZEN_BINDING_GROUPS_DIGEST = (
    "6a48eb5d51413664ccca447f81ea919fdcfee4c968e91a0cca525c10f134ebad"
)
WP06_FROZEN_RUNTIME_PINS_DIGEST = (
    "bb8d0ecb705a6c29a22cf71f8fd768a9a1fdfc8b0a7a5f2961a5ef8c1e38e95d"
)
WP07_FROZEN_SOURCE_MANIFEST_DIGEST = (
    "229c7d3727975ae0b49ef7aba18a4eca0682817305cabf3389a07b31dec561f4"
)
WP07_FROZEN_COMMAND_EVIDENCE_DIGEST = (
    "da7ba7624ee6a1867def4d7cf8ddaa824af6304764da3a107ff21c29b54f8d2c"
)
WP07_FROZEN_EXIT_DIGEST = (
    "db805abdd8961c3023aba177cd31f2e26c6dd9b3b5cfe272c9925a9eaa684e7f"
)
WP07_FROZEN_VERDICT_DIGEST = (
    "3b279fb9c6a3f5e6e7549e84fd0e33513a699d52c0351ae75a42311f777865cb"
)
WP07_FROZEN_BINDING_GROUPS_DIGEST = (
    "f89f88b559269c2aef737e01192d1c50ae2a2079b90fa4e5cee504f9bf2f7714"
)
WP07_FROZEN_RUNTIME_PINS_DIGEST = (
    "e8f0f4331819eb4ef34b288d6cbb650d317e5c8538f135c80b5d4ba413aca893"
)
WP06_GOVERNING_DOCUMENT_PATHS = (
    "docs/positioning/baselines/graph-engineering-workflow-v2.md",
    "docs/positioning/baselines/graph-engineering-workflow-v2.sha256",
    "docs/prd/baselines/graph-engineering-workflow-v2.md",
    "docs/prd/baselines/graph-engineering-workflow-v2.sha256",
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0002-local-event-repository-and-coordination.md",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope.json",
)
WP07_GOVERNING_DOCUMENT_PATHS = (
    "docs/positioning/baselines/graph-engineering-workflow-v2.md",
    "docs/positioning/baselines/graph-engineering-workflow-v2.sha256",
    "docs/prd/baselines/graph-engineering-workflow-v2.md",
    "docs/prd/baselines/graph-engineering-workflow-v2.sha256",
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0001-core-implementation-and-local-packaging.md",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope.json",
)
WP07A_GOVERNING_DOCUMENT_PATHS = (
    "docs/positioning/baselines/graph-engineering-workflow-v2.md",
    "docs/positioning/baselines/graph-engineering-workflow-v2.sha256",
    "docs/prd/baselines/graph-engineering-workflow-v2.md",
    "docs/prd/baselines/graph-engineering-workflow-v2.sha256",
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0001-core-implementation-and-local-packaging.md",
    "docs/adr/0002-local-event-repository-and-coordination.md",
    "docs/adr/0003-deterministic-contract-stack.md",
    "docs/adr/0005-recovery-claim-compensation.md",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope.json",
)
WP07A_SCHEMA_PATHS = (
    "config/contracts/schemas/action-adapter-registry-1.0.0.json",
    "config/contracts/schemas/action-invocation-1.0.0.json",
    "config/contracts/schemas/action-receipt-1.0.0.json",
    "config/contracts/schemas/command-execution-request-1.0.0.json",
    "config/contracts/schemas/command-execution-result-1.0.0.json",
    "config/contracts/schemas/command-registry-1.0.0.json",
    "config/contracts/schemas/command-runtime-policy-1.0.0.json",
    "config/contracts/schemas/concrete-action-policy-1.0.0.json",
    "config/contracts/schemas/connector-capability-mismatch-1.0.0.json",
    "config/contracts/schemas/connector-registry-1.0.0.json",
    "config/contracts/schemas/git-adapter-configuration-1.0.0.json",
    "config/contracts/schemas/git-identity-observation-1.0.0.json",
    "config/contracts/schemas/git-ref-mutation-plan-1.0.0.json",
    "config/contracts/schemas/git-target-plan-1.0.0.json",
    "config/contracts/schemas/secret-provider-registry-1.0.0.json",
    "config/contracts/schemas/target-observation-1.0.0.json",
)
WP07A_CONFIG_PATHS = (
    "config/contracts/action-adapter-schema-registry-v1.json",
    "config/contracts/action-adapter-registry-v1.json",
    "config/actions/action-policy-local-actions-v1.json",
    "config/actions/concrete-action-policy-v1.json",
    "config/actions/connector-registry-v1.json",
    "config/security/security-runtime-local-actions-v1.json",
)
WP07A_RUNTIME_SOURCE_PATHS = (
    "core/graph_engineering/core/action_adapters.py",
    "adapters/graph_engineering/adapters/action_adapters.py",
    "adapters/graph_engineering/adapters/command_native.py",
    "adapters/graph_engineering/adapters/connector_unavailable.py",
    "adapters/graph_engineering/adapters/git_native.py",
    "application/graph_engineering/application/actions.py",
    "storage/graph_engineering/storage/concrete_actions.py",
    "adapters/graph_engineering/adapters/__init__.py",
    "scripts/build_backend.py",
    "core/graph_engineering/__init__.py",
    "core/graph_engineering/core/source_checkout.py",
)
WP07A_FROZEN_COMMAND_EVIDENCE_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07a-command-evidence-r6.json"
)
WP07A_FROZEN_EXIT_PATH = (
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07a-exit-r6.json"
)
REQUIRED_REJECT_TESTS = {
    "GEW-WP-00-BUILD-R": "test_wp00_packaging.PackagingContractTests.test_build_backend_rejects_unowned_and_symlinked_package_inputs",
    "GEW-WP-00-MAPPING-R": "test_wp00_packaging.PackagingContractTests.test_build_backend_rejects_mapping_traversal",
    "GEW-WP-00-SECURITY-R": "test_wp00_architecture_mutations.SecurityMutationTests.test_architecture_scanner_rejects_forbidden_dependencies_and_data_values",
    "GEW-WP-00-PLATFORM-R": "test_wp00_architecture_mutations.SecurityMutationTests.test_platform_matrix_rejects_missing_linux_and_duplicate_cells",
    "GEW-WP-00-MANIFEST-R": "test_wp00_manifest_contract.GateManifestContractTests.test_source_manifest_is_exact_and_detects_mutation",
    "GEW-WP-00-SOURCE-SYMLINK-R": "test_wp00_manifest_contract.GateManifestContractTests.test_every_owned_root_rejects_internal_and_external_symlink_nodes",
    "GEW-WP-00-IMPORT-R": "test_wp00_installed_wheel.InstalledWheelTests.test_wheel_runs_inside_decoy_project_without_source_imports",
}
REQUIRED_EXIT_TESTS = {
    "GEW-WP-00-EXIT-P": "test_wp00_evidence_contract.EvidenceContractTests.test_valid_binding_and_independence_pass",
    "GEW-WP-00-EXIT-R": "test_wp00_evidence_contract.EvidenceContractTests.test_source_command_interpreter_and_reviewer_mutations_fail",
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def governing_documents(
    root: pathlib.Path = ROOT,
    paths: tuple[str, ...] = GOVERNING_DOCUMENT_PATHS,
) -> list[dict[str, object]]:
    """Return an ordered manifest for the selected governing documents."""

    records: list[dict[str, object]] = []
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid governing document: {relative}")
        body = path.read_bytes()
        records.append({"path": relative, "sha256": digest(body), "size": len(body)})
    return records


def governing_documents_digest(records: object) -> str:
    """Digest the exact ordered governing-document manifest."""

    return digest(canonical_bytes(records))


def expand_argv(command: dict[str, object]) -> list[str]:
    values = command["argv"]
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("command argv must be a string list")
    return [sys.executable if value == "{python}" else value for value in values]


def command_record(command: dict[str, object]) -> dict[str, object]:
    argv = expand_argv(command)
    result = subprocess.run(argv, cwd=ROOT, check=False, capture_output=True)
    try:
        outcome = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"command {command['id']} did not emit one JSON outcome") from error
    if not isinstance(outcome, dict):
        raise ValueError(f"command {command['id']} outcome is not an object")
    return {
        "test_id": command["id"],
        "argv": argv,
        "exit_code": result.returncode,
        "outcome": outcome,
        "outcome_sha256": digest(canonical_bytes(outcome)),
        "stderr_sha256": digest(result.stderr),
    }


def command_records(commands: list[dict[str, object]]) -> list[dict[str, object]]:
    return [command_record(command) for command in commands]


def passed_test_ids(records: list[dict[str, object]]) -> set[str]:
    """Return passed qualified tests from the single test-runner outcome."""

    test_outcomes = [
        record.get("outcome")
        for record in records
        if isinstance(record.get("outcome"), dict)
        and isinstance(record["outcome"].get("tests"), list)  # type: ignore[union-attr]
    ]
    if len(test_outcomes) != 1:
        return set()
    tests = test_outcomes[0]["tests"]  # type: ignore[index]
    return {
        item["id"]
        for item in tests
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("status") == "PASS"
    }


def passed_test_execution_count(records: list[dict[str, object]]) -> int:
    """Return the exact unfiltered execution count only when every test passed."""

    outcomes = [
        record.get("outcome") for record in records
        if isinstance(record.get("outcome"), dict)
        and isinstance(record["outcome"].get("tests"), list)  # type: ignore[union-attr]
    ]
    if len(outcomes) != 1:
        return 0
    outcome = outcomes[0]
    tests = outcome["tests"]  # type: ignore[index]
    count = outcome.get("test_count")  # type: ignore[union-attr]
    if (
        type(count) is not int or count != len(tests)
        or any(
            not isinstance(item, dict)
            or type(item.get("id")) is not str
            or item.get("status") != "PASS"
            for item in tests
        )
    ):
        return 0
    return count


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None


def valid_actor(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip() and value.isascii()


def reference_runtime(root: pathlib.Path = ROOT) -> dict[str, object]:
    """Attest the exact Node binary and independent oracle source."""

    executable = shutil.which("node")
    if executable is None:
        raise ValueError("Node reference runtime is unavailable")
    resolved = pathlib.Path(executable).resolve()
    implementation = root / WP02_REFERENCE_IMPLEMENTATION
    if implementation.is_symlink() or not implementation.is_file():
        raise ValueError("WP02 reference implementation is unavailable")
    version = subprocess.run(
        [str(resolved), "--version"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    return {
        "kind": "node",
        "executable": str(resolved),
        "executable_sha256": digest(resolved.read_bytes()),
        "version": version,
        "implementation": WP02_REFERENCE_IMPLEMENTATION,
        "implementation_sha256": digest(implementation.read_bytes()),
    }


def repository_runtime(root: pathlib.Path = ROOT) -> dict[str, object]:
    """Attest the exact SQLite extension, policy, and fault schedule inputs."""

    extension_name = getattr(_sqlite3, "__file__", None)
    specification = importlib.util.find_spec("_sqlite3")
    if extension_name is None:
        extension: pathlib.Path | None = None
        extension_record: dict[str, object] = {
            "kind": "built-in",
            "origin": None if specification is None else specification.origin,
            "loader": None if specification is None or specification.loader is None
            else type(specification.loader).__qualname__,
        }
    else:
        extension = pathlib.Path(extension_name).resolve()
        extension_record = {
            "kind": "dynamic-library",
            "path": str(extension),
            "sha256": digest(extension.read_bytes()),
        }
    policy = root / "config" / "contracts" / "repository-policy-v1.json"
    schedule = root / "config" / "contracts" / "persistence-fault-schedule-v1.json"
    if (
        (extension is not None and (extension.is_symlink() or not extension.is_file()))
        or any(path.is_symlink() or not path.is_file() for path in (policy, schedule))
    ):
        raise ValueError("repository runtime input is unavailable")
    connection = sqlite3.connect(":memory:")
    try:
        compile_options = sorted(row[0] for row in connection.execute("PRAGMA compile_options"))
    finally:
        connection.close()
    for responsibility in ("core", "storage"):
        path = str(root / responsibility)
        if path not in sys.path:
            sys.path.insert(0, path)
    from graph_engineering.storage.connection import ConnectionFactory
    from graph_engineering.storage.policy import RepositoryPolicy

    repository_policy = RepositoryPolicy.from_dict(json.loads(policy.read_text()))
    with tempfile.TemporaryDirectory(prefix="gew-evidence-doctor-") as directory:
        factory = ConnectionFactory.initialize(
            pathlib.Path(directory) / "repository",
            repository_policy,
            "wp03-evidence-doctor-v1",
        )
        filesystem_capability = json.loads(json.dumps(
            dataclasses.asdict(factory.filesystem_capability),
            sort_keys=True,
            separators=(",", ":"),
        ))
    return {
        "kind": "sqlite-delete-extra-filesystem-objects",
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_version_info": list(sqlite3.sqlite_version_info),
        "extension": extension_record,
        "compile_options": compile_options,
        "filesystem_capability": filesystem_capability,
        "policy_path": policy.relative_to(root).as_posix(),
        "policy_sha256": digest(policy.read_bytes()),
        "fault_schedule_path": schedule.relative_to(root).as_posix(),
        "fault_schedule_sha256": digest(schedule.read_bytes()),
    }


def artifact_runtime(root: pathlib.Path = ROOT) -> dict[str, object]:
    """Attest the exact closed registries and schemas consumed by WP-04A."""

    paths = (
        "config/contracts/artifact-contracts-v1.json",
        "config/contracts/artifact-schema-registry-v1.json",
        "config/contracts/schemas/artifact-contract-registry-1.0.0.json",
        "config/contracts/schemas/artifact-lifecycle-event-1.0.0.json",
        "config/contracts/schemas/artifact-record-1.0.0.json",
        "config/contracts/schemas/logical-body-manifest-1.0.0.json",
    )
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("artifact runtime input is unavailable")
        try:
            value = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError("artifact runtime input is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("artifact runtime input must be an object")
        documents[relative] = value
        records.append({"path": relative, "sha256": digest(path.read_bytes()), "size": path.stat().st_size})
    contracts = documents[paths[0]]
    schemas = documents[paths[1]]
    if (
        contracts.get("registry_id") != "urn:gew:artifact-contract-registry:builtin:1.0.0"
        or not valid_digest(str(contracts.get("registry_digest", "")).removeprefix("sha256-jcs-v1:"))
        or schemas.get("registry_id") != "urn:gew:schema-registry:artifact-engine:1.0.0"
        or not valid_digest(str(schemas.get("registry_digest", "")).removeprefix("sha256-jcs-v1:"))
    ):
        raise ValueError("artifact runtime registry identity is invalid")
    return {
        "kind": "artifact-contract-engine-v1",
        "artifact_contract_registry_id": contracts["registry_id"],
        "artifact_contract_registry_digest": contracts["registry_digest"],
        "schema_registry_id": schemas["registry_id"],
        "schema_registry_digest": schemas["registry_digest"],
        "inputs": records,
    }


def security_runtime(root: pathlib.Path = ROOT) -> dict[str, object]:
    """Attest the closed WP-05A schemas and policy documents."""

    paths = (
        "config/contracts/security-schema-registry-v1.json",
        "config/contracts/schemas/action-policy-1.0.0.json",
        "config/contracts/schemas/authority-envelope-1.0.0.json",
        "config/contracts/schemas/data-disclosure-plan-1.0.0.json",
        "config/contracts/schemas/disclosure-policy-1.0.0.json",
        "config/contracts/schemas/disclosure-receipt-1.0.0.json",
        "config/contracts/schemas/evidence-policy-registry-1.0.0.json",
        "config/contracts/schemas/evidence-record-1.0.0.json",
        "config/contracts/schemas/input-safety-policy-1.0.0.json",
        "config/contracts/schemas/prepared-action-1.0.0.json",
        "config/contracts/schemas/redaction-policy-1.0.0.json",
        "config/contracts/schemas/retention-policy-registry-1.0.0.json",
        "config/contracts/schemas/security-binding-1.0.0.json",
        "config/contracts/schemas/security-runtime-manifest-1.0.0.json",
        "config/actions/action-policy-v1.json",
        "config/security/disclosure-policy-v1.json",
        "config/security/evidence-policies-v1.json",
        "config/security/input-safety-policy-v1.json",
        "config/security/redaction-policy-v1.json",
        "config/security/retention-policies-v1.json",
        "config/security/security-runtime-v1.json",
    )
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("security runtime input is unavailable")
        try:
            value = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError("security runtime input is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("security runtime input must be an object")
        documents[relative] = value
        records.append({"path": relative, "sha256": digest(path.read_bytes()), "size": path.stat().st_size})
    registry = documents[paths[0]]
    if (
        registry.get("registry_id") != "urn:gew:schema-registry:security-foundation:1.0.0"
        or not valid_digest(str(registry.get("registry_digest", "")).removeprefix("sha256-jcs-v1:"))
    ):
        raise ValueError("security schema registry identity is invalid")
    policy_paths = (
        "config/actions/action-policy-v1.json",
        "config/security/disclosure-policy-v1.json",
        "config/security/evidence-policies-v1.json",
        "config/security/input-safety-policy-v1.json",
        "config/security/redaction-policy-v1.json",
        "config/security/retention-policies-v1.json",
    )
    policy_bindings: list[dict[str, str]] = []
    for relative in policy_paths:
        document = documents[relative]
        identity = document.get("policy_id", document.get("registry_id"))
        binding = document.get("policy_digest", document.get("registry_digest"))
        if type(identity) is not str or not identity or not valid_digest(str(binding).removeprefix("sha256-jcs-v1:")):
            raise ValueError("security policy identity is invalid")
        policy_bindings.append({"path": relative, "identity": identity, "digest": str(binding)})
    installed = documents["config/security/security-runtime-v1.json"]
    if (
        installed.get("manifest_id") != "security-runtime-default"
        or not valid_digest(str(installed.get("manifest_digest", "")).removeprefix("sha256-jcs-v1:"))
        or installed.get("schema_registry") != {
            "registry_id": registry["registry_id"],
            "registry_digest": registry["registry_digest"],
        }
    ):
        raise ValueError("installed security runtime identity is invalid")
    installed_policies = installed.get("policies")
    expected_policies = {
        kind: {"policy_id": item["identity"], "policy_digest": item["digest"]}
        for kind, item in zip(
            ("action", "disclosure", "evidence", "input-safety", "redaction", "retention"),
            policy_bindings,
            strict=True,
        )
    }
    if installed_policies != expected_policies:
        raise ValueError("installed security runtime policy pins are invalid")
    return {
        "kind": "security-privacy-evidence-foundation-v1",
        "schema_registry_id": registry["registry_id"],
        "schema_registry_digest": registry["registry_digest"],
        "policy_bindings": policy_bindings,
        "installed_manifest_id": installed["manifest_id"],
        "installed_manifest_digest": installed["manifest_digest"],
        "inputs": records,
        "real_external_actions_enabled": False,
    }


def action_runtime(root: pathlib.Path = ROOT) -> dict[str, object]:
    """Attest the exact local-only action and recovery runtime inputs for WP-05."""

    try:
        gate = json.loads((root / "config" / "verification" / "wp-05-gate.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("WP-05 gate runtime pins are unavailable") from error
    recovery_pin = gate.get("recovery_schedule") if isinstance(gate, dict) else None
    if (
        not isinstance(recovery_pin, dict)
        or set(recovery_pin) != {"path", "schedule_id", "sha256", "point_count"}
        or recovery_pin.get("path") != "config/contracts/action-recovery-fault-schedule-v2.json"
        or recovery_pin.get("schedule_id") != "wp05-action-recovery-fault-schedule-v2"
        or not valid_digest(recovery_pin.get("sha256"))
        or recovery_pin.get("point_count") != 13
    ):
        raise ValueError("WP-05 recovery schedule pin is not exact")
    paths = (
        str(recovery_pin["path"]),
        "config/verification/wp-05-gate-mutations.json",
    )
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for relative in paths:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("action runtime input is unavailable")
        try:
            value = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError("action runtime input is invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("action runtime input must be an object")
        documents[relative] = value
        records.append({"path": relative, "sha256": digest(path.read_bytes()), "size": path.stat().st_size})
    schedule = documents[paths[0]]
    mutations = documents[paths[1]]
    expected_points = [
        "claim.after-consume",
        "gate.before-start",
        "query.after-observation",
        "receipt-event.after-commit",
        "receipt-event.after-journal-apply-before-commit",
        "receipt-event.before-commit",
        "receipt-object.after-durable",
        "receipt-object.before-durable",
        "reconcile.after-commit",
        "reconcile.before-commit",
        "start.after-commit",
        "start.before-commit",
        "tool.after-effect",
    ]
    expected_precedence = [
        "GEW-AUT-PRECONDITION-CHANGED",
        "GEW-AUT-PRECONDITION-UNVERIFIABLE",
        "GEW-AUT-IDEMPOTENCY-KEY-CHANGED",
        "GEW-AUT-IDEMPOTENCY-CLASS-CHANGED",
        "GEW-AUT-IDEMPOTENCY-DUPLICATE",
        "GEW-AUT-IDEMPOTENCY-UNKNOWN",
        "GEW-AUT-ROLLBACK-MISSING",
        "GEW-AUT-ROLLBACK-CHANGED",
        "GEW-AUT-VERIFY-MISSING",
        "GEW-AUT-VERIFY-CHANGED",
        "GEW-AUT-TARGET-EVIDENCE-STALE",
    ]
    if (
        schedule.get("schema_version") != "1.0.0"
        or schedule.get("schedule_id") != recovery_pin["schedule_id"]
        or schedule.get("points") != expected_points
        or records[0]["sha256"] != recovery_pin["sha256"]
        or len(expected_points) != recovery_pin["point_count"]
        or mutations.get("schema_version") != "1.0.0"
        or mutations.get("mutation_set_id") != "wp-05-execute-gate-exact-v1"
        or mutations.get("frozen_precedence") != expected_precedence
        or mutations.get("combined_mutation_id") != "GEW-AUT-COMBINED-MUTATION"
        or mutations.get("all_unordered_pairs_required") is not True
    ):
        raise ValueError("action recovery runtime contract is not exact")
    security = security_runtime(root)
    repository = repository_runtime(root)
    if security.get("real_external_actions_enabled") is not False:
        raise ValueError("real external actions must remain disabled")
    return {
        "kind": "authority-action-recovery-local-fake-v1",
        "security_runtime": security,
        "repository_runtime": repository,
        "recovery_schedule_id": schedule["schedule_id"],
        "recovery_schedule_sha256": records[0]["sha256"],
        "recovery_points": schedule["points"],
        "execute_gate_mutation_set_id": mutations["mutation_set_id"],
        "execute_gate_precedence": mutations["frozen_precedence"],
        "inputs": records,
        "real_external_actions_enabled": False,
    }


def wp05_exact_gate_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Derive every singleton and unordered-pair execute-gate test binding."""

    relative = _project_relative_path(
        gate.get("gate_mutation_manifest_path"), "WP-05 mutation manifest path",
    )
    try:
        manifest = json.loads((root / relative).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("WP-05 mutation manifest is missing or invalid") from error
    if not isinstance(manifest, dict):
        raise ValueError("WP-05 mutation manifest must be an object")
    codes = manifest.get("frozen_precedence")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("mutation_set_id") != "wp-05-execute-gate-exact-v1"
        or not isinstance(codes, list)
        or len(codes) != 11
        or len(set(codes)) != len(codes)
        or not all(isinstance(code, str) and code.startswith("GEW-AUT-") for code in codes)
        or manifest.get("combined_mutation_id") != "GEW-AUT-COMBINED-MUTATION"
        or manifest.get("all_unordered_pairs_required") is not True
    ):
        raise ValueError("WP-05 mutation manifest is not exact")

    def suffix(code: str) -> str:
        return code.casefold().replace("-", "_")

    bindings = [{
        "test_id": "GEW-AUT-GATE-MANIFEST-P",
        "qualified_test": (
            "test_wp05_exact_gate_mutations.WP05ExactExecuteGateMutations."
            "test_manifest_exactly_matches_frozen_decision_table"
        ),
    }]
    history = {
        "GEW-AUT-IDEMPOTENCY-DUPLICATE": "test_gew_aut_idempotency_duplicate_singleton",
        "GEW-AUT-IDEMPOTENCY-UNKNOWN": "test_gew_aut_idempotency_unknown_singleton",
    }
    for code in codes:
        if code in history:
            qualified = f"test_wp05_exact_gate_mutations.WP05JournalHistorySingletons.{history[code]}"
        else:
            qualified = (
                "test_wp05_exact_gate_mutations.WP05ExactExecuteGateMutations.test_exact_"
                + suffix(code)
            )
        bindings.append({"test_id": code, "qualified_test": qualified})
    for first, second in itertools.combinations(codes, 2):
        bindings.append({
            "test_id": f"GEW-AUT-COMBINED-MUTATION:{first}+{second}",
            "qualified_test": (
                "test_wp05_exact_gate_mutations.WP05CombinedMutationPrecedence.test_combined_"
                f"{suffix(first)}__{suffix(second)}"
            ),
        })
    return bindings


def wp05_action_source_records(
    gate: dict[str, object],
    source_manifest: dict[str, object],
) -> list[dict[str, object]]:
    """Select the exact WP-05 implementation surface from the full source manifest."""

    paths = gate.get("action_source_paths")
    files = source_manifest.get("files")
    if (
        not isinstance(paths, list)
        or paths != sorted(paths)
        or len(paths) != len(set(paths))
        or not paths
        or not all(isinstance(path, str) and path for path in paths)
        or not isinstance(files, list)
    ):
        raise ValueError("WP-05 action source scope is not exact")
    indexed = {
        record.get("path"): record for record in files
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    if len(indexed) != len(files) or any(path not in indexed for path in paths):
        raise ValueError("WP-05 action source is missing from the source manifest")
    selected = [indexed[path] for path in paths]
    if any(
        set(record) != {"path", "sha256", "size"}
        or not valid_digest(record.get("sha256"))
        or type(record.get("size")) is not int
        or record["size"] < 0
        for record in selected
    ):
        raise ValueError("WP-05 action source record is invalid")
    return selected


def wp05_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the exact approved WP-05 document and authority digest set."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP05_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-05 governing document pins are not exact")
    documents = governing_documents(root=root, paths=WP05_GOVERNING_DOCUMENT_PATHS)
    if any(
        document["path"] != pin["path"] or document["sha256"] != pin["sha256"]
        for document, pin in zip(documents, pins, strict=True)
    ):
        raise ValueError("WP-05 governing document digest mismatch")
    return documents


def _wp05_frozen_records(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Return records from one read of the validated accepted WP-05 r2 tuple."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP05_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-05 frozen governing document pin set is not exact")

    paths = [
        root / WP05_FROZEN_SOURCE_MANIFEST_PATH,
        root / WP05_FROZEN_COMMAND_EVIDENCE_PATH,
        root / WP05_FROZEN_EXIT_PATH,
        root / WP05_FROZEN_VERDICT_PATH,
    ]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("WP-05 frozen governing document records are unavailable")
    try:
        source_manifest, command_evidence, exit_record, verdict = [
            json.loads(path.read_text(encoding="utf-8")) for path in paths
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("WP-05 frozen governing document records cannot be parsed") from error
    if not all(
        isinstance(record, dict)
        for record in (source_manifest, command_evidence, exit_record, verdict)
    ):
        raise ValueError("WP-05 frozen governing document record is not an object")

    documents = command_evidence.get("governing_documents")
    source_files = source_manifest.get("files")
    action_runtime = command_evidence.get("action_runtime")
    action_sources = command_evidence.get("action_sources")
    dependencies = command_evidence.get("dependency_verdicts")
    command_digest = digest(canonical_bytes(command_evidence))
    exit_digest = digest(canonical_bytes(exit_record))
    verdict_digest = digest(canonical_bytes(verdict))
    source_preimage = {
        "schema_version": source_manifest.get("schema_version"),
        "files": source_files,
    }
    source_digest = digest(canonical_bytes(source_preimage))
    exit_fields = {
        "schema_version", "artifact", "status", "author_id", "reviewer_id",
        "source_manifest_digest", "command_evidence_digest",
        "governing_documents_digest", "architecture_review_digest",
        "action_runtime_digest", "action_sources_digest",
        "dependency_verdicts_digest", "real_external_actions_enabled", "test_ids",
    }
    verdict_fields = {
        "schema_version", "artifact", "verdict", "scope_changed", "reviewer_id",
        "source_manifest_digest", "command_evidence_digest", "candidate_exit_digest",
        "governing_documents_digest", "architecture_review_digest",
        "action_runtime_digest", "action_sources_digest", "dependency_verdicts_digest",
        "finding_dispositions", "findings",
    }
    architecture_review_digest = next(
        (
            record.get("sha256") for record in documents
            if isinstance(record, dict)
            and record.get("path")
            == ".workflow/delivery/GEW-IMPLEMENTATION-V1/"
            "wp-05-recovery-architecture-review-verdict-r3.json"
        ),
        None,
    ) if isinstance(documents, list) else None
    if (
        set(source_manifest) != {"schema_version", "files", "manifest_digest"}
        or source_manifest.get("schema_version") != "1.0"
        or source_manifest.get("manifest_digest") != WP05_FROZEN_SOURCE_MANIFEST_DIGEST
        or source_digest != WP05_FROZEN_SOURCE_MANIFEST_DIGEST
        or not isinstance(source_files, list)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not record["path"]
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in source_files
        )
        or [record["path"] for record in source_files] != sorted(
            record["path"] for record in source_files
        )
        or len({record["path"] for record in source_files}) != len(source_files)
        or command_evidence.get("schema_version") != "1.0"
        or command_evidence.get("status") != "PASS"
        or command_digest != WP05_FROZEN_COMMAND_EVIDENCE_DIGEST
        or command_evidence.get("source_manifest_digest")
        != WP05_FROZEN_SOURCE_MANIFEST_DIGEST
        or exit_record.get("schema_version") != "1.0"
        or set(exit_record) != exit_fields
        or exit_record.get("artifact") != "wp-05"
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest")
        != command_evidence.get("source_manifest_digest")
        or exit_record.get("command_evidence_digest")
        != command_digest
        or exit_digest != WP05_FROZEN_EXIT_DIGEST
        or not valid_actor(exit_record.get("author_id"))
        or not valid_actor(exit_record.get("reviewer_id"))
        or str(exit_record.get("author_id")).casefold()
        == str(exit_record.get("reviewer_id")).casefold()
        or not isinstance(documents, list)
        or len(documents) != len(pins)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in documents
        )
        or [
            {"path": record["path"], "sha256": record["sha256"]}
            for record in documents
        ] != pins
        or exit_record.get("governing_documents_digest")
        != governing_documents_digest(documents)
        or exit_record.get("architecture_review_digest") != architecture_review_digest
        or exit_record.get("action_runtime_digest") != digest(canonical_bytes(action_runtime))
        or exit_record.get("action_sources_digest") != digest(canonical_bytes(action_sources))
        or exit_record.get("dependency_verdicts_digest") != digest(canonical_bytes(dependencies))
        or exit_record.get("real_external_actions_enabled") is not False
        or exit_record.get("test_ids") != ["GEW-WP-05-EXIT-P", "GEW-WP-05-EXIT-R"]
        or set(verdict) != verdict_fields
        or verdict_digest != WP05_FROZEN_VERDICT_DIGEST
        or verdict.get("schema_version") != "1.0"
        or verdict.get("artifact") != "wp-05"
        or verdict.get("verdict") != "PASS"
        or verdict.get("scope_changed") is not False
        or verdict.get("reviewer_id") != exit_record.get("reviewer_id")
        or verdict.get("source_manifest_digest") != WP05_FROZEN_SOURCE_MANIFEST_DIGEST
        or verdict.get("command_evidence_digest") != command_digest
        or verdict.get("candidate_exit_digest") != exit_digest
        or verdict.get("governing_documents_digest")
        != exit_record.get("governing_documents_digest")
        or verdict.get("architecture_review_digest") != architecture_review_digest
        or verdict.get("action_runtime_digest") != exit_record.get("action_runtime_digest")
        or verdict.get("action_sources_digest") != exit_record.get("action_sources_digest")
        or verdict.get("dependency_verdicts_digest")
        != exit_record.get("dependency_verdicts_digest")
        or not isinstance(verdict.get("finding_dispositions"), list)
        or any(
            not isinstance(item, dict) or item.get("status") != "closed"
            for item in verdict.get("finding_dispositions", [])
        )
        or verdict.get("findings") != []
    ):
        raise ValueError("WP-05 frozen governing document binding is invalid")
    return documents, command_evidence


def wp05_frozen_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the document manifest embedded in the accepted WP-05 r2 tuple."""

    documents, _ = _wp05_frozen_records(gate, root=root)
    return documents


def wp05_frozen_action_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Return the runtime record embedded in the exact accepted WP-05 r2 tuple."""

    _, command_evidence = _wp05_frozen_records(gate, root=root)
    runtime = command_evidence.get("action_runtime")
    schedule = gate.get("recovery_schedule")
    if (
        not isinstance(runtime, dict)
        or not isinstance(schedule, dict)
        or runtime.get("recovery_schedule_id") != schedule.get("schedule_id")
        or runtime.get("recovery_schedule_sha256") != schedule.get("sha256")
        or not isinstance(runtime.get("recovery_points"), list)
        or len(runtime["recovery_points"]) != schedule.get("point_count")
    ):
        raise ValueError("WP-05 frozen runtime binding is invalid")
    return runtime


def _frozen_candidate_command(
    *,
    artifact: str,
    revision: int,
    source_manifest_digest: str,
    command_evidence_digest: str,
    exit_digest: str,
    verdict_digest: str,
    root: pathlib.Path,
) -> dict[str, object]:
    """Read once and validate an exact accepted historical candidate tuple."""

    prefix = f".workflow/delivery/GEW-IMPLEMENTATION-V1/{artifact}"
    relative_paths = (
        f"{prefix}-source-manifest-r{revision}.json",
        f"{prefix}-command-evidence-r{revision}.json",
        f"{prefix}-exit-r{revision}.json",
        f"{prefix}-review-verdict-r{revision}.json",
    )
    paths = [root / relative for relative in relative_paths]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError(f"{artifact} frozen candidate records are unavailable")
    try:
        source, command, exit_record, verdict = [
            json.loads(path.read_text(encoding="utf-8")) for path in paths
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{artifact} frozen candidate records cannot be parsed") from error
    if not all(isinstance(record, dict) for record in (source, command, exit_record, verdict)):
        raise ValueError(f"{artifact} frozen candidate record is not an object")

    source_files = source.get("files")
    source_preimage = {"schema_version": source.get("schema_version"), "files": source_files}
    command_digest = digest(canonical_bytes(command))
    candidate_exit_digest = digest(canonical_bytes(exit_record))
    reviewer_verdict_digest = digest(canonical_bytes(verdict))
    code = artifact.replace("-", "")
    payload_digests = {
        f"{code}_runtime_digest": f"{code}_runtime",
        f"{code}_sources_digest": f"{code}_sources",
        "dependency_verdicts_digest": "dependency_verdicts",
    }
    exit_fields = {
        "schema_version", "artifact", "status", "author_id", "reviewer_id",
        "source_manifest_digest", "command_evidence_digest",
        "governing_documents_digest", "real_external_actions_enabled", "test_ids",
        *payload_digests,
    }
    verdict_fields = {
        "schema_version", "artifact", "verdict", "scope_changed", "change_kinds",
        "reviewer_id", "source_manifest_digest", "command_evidence_digest",
        "candidate_exit_digest", "governing_documents_digest",
        "finding_dispositions", "findings", *payload_digests,
    }
    documents = command.get("governing_documents")
    if (
        set(source) != {"schema_version", "files", "manifest_digest"}
        or source.get("schema_version") != "1.0"
        or source.get("manifest_digest") != source_manifest_digest
        or digest(canonical_bytes(source_preimage)) != source_manifest_digest
        or not isinstance(source_files, list)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not record["path"]
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in source_files
        )
        or [record["path"] for record in source_files]
        != sorted(record["path"] for record in source_files)
        or len({record["path"] for record in source_files}) != len(source_files)
        or command.get("schema_version") != "1.0"
        or command.get("status") != "PASS"
        or command.get("source_manifest_digest") != source_manifest_digest
        or command_digest != command_evidence_digest
        or not isinstance(documents, list)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in documents
        )
        or set(exit_record) != exit_fields
        or candidate_exit_digest != exit_digest
        or exit_record.get("schema_version") != "1.0"
        or exit_record.get("artifact") != artifact
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest") != source_manifest_digest
        or exit_record.get("command_evidence_digest") != command_digest
        or exit_record.get("governing_documents_digest")
        != governing_documents_digest(documents)
        or not valid_actor(exit_record.get("author_id"))
        or not valid_actor(exit_record.get("reviewer_id"))
        or str(exit_record.get("author_id")).casefold()
        == str(exit_record.get("reviewer_id")).casefold()
        or exit_record.get("real_external_actions_enabled") is not False
        or exit_record.get("test_ids")
        != [f"GEW-{artifact.upper()}-EXIT-P", f"GEW-{artifact.upper()}-EXIT-R"]
        or any(
            exit_record.get(field) != digest(canonical_bytes(command.get(payload)))
            for field, payload in payload_digests.items()
        )
        or set(verdict) != verdict_fields
        or reviewer_verdict_digest != verdict_digest
        or verdict.get("schema_version") != "1.0"
        or verdict.get("artifact") != artifact
        or verdict.get("verdict") != "PASS"
        or verdict.get("scope_changed") is not False
        or not isinstance(verdict.get("change_kinds"), list)
        or any(
            not isinstance(kind, str) or not kind
            for kind in verdict.get("change_kinds", [])
        )
        or verdict.get("reviewer_id") != exit_record.get("reviewer_id")
        or verdict.get("source_manifest_digest") != source_manifest_digest
        or verdict.get("command_evidence_digest") != command_digest
        or verdict.get("candidate_exit_digest") != candidate_exit_digest
        or verdict.get("governing_documents_digest")
        != exit_record.get("governing_documents_digest")
        or any(
            verdict.get(field) != exit_record.get(field) for field in payload_digests
        )
        or not isinstance(verdict.get("finding_dispositions"), list)
        or any(
            not isinstance(item, dict) or item.get("status") != "closed"
            for item in verdict.get("finding_dispositions", [])
        )
        or verdict.get("findings") != []
    ):
        raise ValueError(f"{artifact} frozen candidate binding is invalid")
    return command


def _frozen_candidate_documents(
    *,
    gate: dict[str, object],
    command: dict[str, object],
    paths: tuple[str, ...],
    artifact: str,
) -> list[dict[str, object]]:
    pins = gate.get("governing_document_digests")
    documents = command.get("governing_documents")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)] != list(paths)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
        or not isinstance(documents, list)
        or [{"path": item["path"], "sha256": item["sha256"]} for item in documents]
        != pins
    ):
        raise ValueError(f"{artifact} frozen governing document binding is invalid")
    return documents


def _frozen_candidate_payload(
    *,
    gate_value: object,
    gate_digest: str,
    command: dict[str, object],
    field: str,
    artifact: str,
) -> object:
    if digest(canonical_bytes(gate_value)) != gate_digest or field not in command:
        raise ValueError(f"{artifact} frozen {field} binding is invalid")
    return command[field]


def wp06_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the exact approved WP-06 documents and authority envelope."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP06_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-06 governing document pins are not exact")
    documents = governing_documents(root=root, paths=WP06_GOVERNING_DOCUMENT_PATHS)
    if any(
        document["path"] != pin["path"] or document["sha256"] != pin["sha256"]
        for document, pin in zip(documents, pins, strict=True)
    ):
        raise ValueError("WP-06 governing document digest mismatch")
    return documents


def _wp06_frozen_command(root: pathlib.Path) -> dict[str, object]:
    return _frozen_candidate_command(
        artifact="wp-06",
        revision=3,
        source_manifest_digest=WP06_FROZEN_SOURCE_MANIFEST_DIGEST,
        command_evidence_digest=WP06_FROZEN_COMMAND_EVIDENCE_DIGEST,
        exit_digest=WP06_FROZEN_EXIT_DIGEST,
        verdict_digest=WP06_FROZEN_VERDICT_DIGEST,
        root=root,
    )


def wp06_frozen_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Return the governing records from the exact accepted WP-06 r3 tuple."""

    return _frozen_candidate_documents(
        gate=gate,
        command=_wp06_frozen_command(root),
        paths=WP06_GOVERNING_DOCUMENT_PATHS,
        artifact="WP-06",
    )


def wp06_frozen_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Return stable bindings from the exact accepted WP-06 r3 tuple."""

    value = _frozen_candidate_payload(
        gate_value=gate.get("binding_groups"),
        gate_digest=WP06_FROZEN_BINDING_GROUPS_DIGEST,
        command=_wp06_frozen_command(root),
        field="stable_test_bindings",
        artifact="WP-06",
    )
    if (
        not isinstance(value, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"test_id", "qualified_test"}
            or not all(isinstance(item[field], str) and item[field] for field in item)
            for item in value
        )
    ):
        raise ValueError("WP-06 frozen stable test bindings are invalid")
    return value


def wp06_frozen_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Return runtime evidence from the exact accepted WP-06 r3 tuple."""

    value = _frozen_candidate_payload(
        gate_value=gate.get("runtime_pins"),
        gate_digest=WP06_FROZEN_RUNTIME_PINS_DIGEST,
        command=_wp06_frozen_command(root),
        field="wp06_runtime",
        artifact="WP-06",
    )
    if not isinstance(value, dict):
        raise ValueError("WP-06 frozen runtime is invalid")
    return value


def wp06_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Derive the exact stable GEW-MIG/LIF bindings from named test classes."""

    groups = gate.get("binding_groups")
    if not isinstance(groups, list) or len(groups) != 10:
        raise ValueError("WP-06 binding groups are not exact")
    expected_keys = {"prefix", "start", "end", "path", "module", "class"}
    ranges: dict[str, list[int]] = {"GEW-MIG": [], "GEW-LIF": []}
    bindings: list[dict[str, str]] = []
    qualified_seen: set[str] = set()
    ids_seen: set[str] = set()
    surface_declared: dict[tuple[str, str, str, str], set[int]] = {}
    surface_observed: dict[tuple[str, str, str, str], set[int]] = {}
    for group in groups:
        if not isinstance(group, dict) or set(group) != expected_keys:
            raise ValueError("WP-06 binding group is not exact")
        prefix = group["prefix"]
        start = group["start"]
        end = group["end"]
        module = group["module"]
        class_name = group["class"]
        if (
            prefix not in ranges
            or type(start) is not int
            or type(end) is not int
            or start < 1
            or end < start
            or type(module) is not str
            or not module
            or type(class_name) is not str
            or not class_name
        ):
            raise ValueError("WP-06 binding group value is invalid")
        relative = _project_relative_path(group["path"], "WP-06 test path")
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stem != module:
            raise ValueError("WP-06 bound test source is invalid")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError) as error:
            raise ValueError("WP-06 bound test source cannot be parsed") from error
        classes = [
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            raise ValueError("WP-06 bound test class is not unique")
        prefix_slug = prefix.casefold().replace("-", "_")
        methods: dict[int, list[str]] = {}
        for node in classes[0].body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            match = re.fullmatch(rf"test_{re.escape(prefix_slug)}_(\d{{3}})_.+", node.name)
            if match:
                methods.setdefault(int(match.group(1)), []).append(node.name)
        expected_numbers = list(range(start, end + 1))
        if any(number not in methods or len(methods[number]) != 1 for number in expected_numbers):
            raise ValueError("WP-06 stable test method set is not exact")
        surface = (relative.as_posix(), module, class_name, prefix)
        surface_declared.setdefault(surface, set()).update(expected_numbers)
        surface_observed[surface] = set(methods)
        ranges[prefix].extend(expected_numbers)
        for number in expected_numbers:
            test_id = f"{prefix}-{number:03d}"
            qualified = f"{module}.{class_name}.{methods[number][0]}"
            if test_id in ids_seen or qualified in qualified_seen:
                raise ValueError("WP-06 stable test binding is not one-to-one")
            ids_seen.add(test_id)
            qualified_seen.add(qualified)
            bindings.append({"test_id": test_id, "qualified_test": qualified})
    if (
        ranges != {"GEW-MIG": list(range(1, 47)), "GEW-LIF": list(range(1, 23))}
        or surface_declared != surface_observed
    ):
        raise ValueError("WP-06 stable test ranges contain a gap or overlap")
    return bindings


def wp06_reviewer_remedy_test_bindings(
    gate: dict[str, object],
) -> list[dict[str, str]]:
    """Validate and flatten the exact tests closing the WP-06 r1 review findings."""

    expected = [
        {
            "finding_id": "WP06-CODE-R1-001",
            "qualified_tests": [
                "test_wp06_migration_orchestration.WP06MigrationOrchestrationTests."
                "test_post_activation_operations_route_only_current_repository",
            ],
        },
        {
            "finding_id": "WP06-CODE-R1-002",
            "qualified_tests": [
                "test_wp06_migration_authority.WP06MigrationAuthorityTests."
                "test_gew_mig_037_activation_recomputes_exact_candidate",
            ],
        },
        {
            "finding_id": "WP06-CODE-R1-006",
            "qualified_tests": [
                "test_wp06_project_scope_repository.WP06ProjectScopeRepositoryTests."
                "test_gew_lif_015_rebase_invalidates_exact_targets_and_expands_authority",
                "test_wp06_project_scope_repository.WP06ProjectScopeRepositoryTests."
                "test_scope_dependency_mapping_fails_closed",
            ],
        },
        {
            "finding_id": "WP06-CODE-R1-007",
            "qualified_tests": [
                "test_wp06_lifecycle_application.WP06LifecycleApplicationTests."
                "test_gew_lif_020_cancel_uses_durable_retention_schedule",
            ],
        },
        {
            "finding_id": "WP06-CODE-R1-008",
            "qualified_tests": [
                "test_wp06_migration_orchestration.WP06MigrationOrchestrationTests."
                "test_gew_mig_042_versioned_fault_schedule_covers_every_production_cut",
                "test_wp06_migration_orchestration.WP06MigrationOrchestrationTests."
                "test_gew_mig_043_every_durable_cut_sigkill_recovers_active_or_blocked",
            ],
        },
    ]
    if gate.get("reviewer_remedy_bindings") != expected:
        raise ValueError("WP-06 reviewer remedy bindings are not exact")
    return [
        {"finding_id": record["finding_id"], "qualified_test": qualified}
        for record in expected
        for qualified in record["qualified_tests"]
    ]


def wp06_source_records(
    gate: dict[str, object],
    source_manifest: dict[str, object],
) -> list[dict[str, object]]:
    """Select the exact WP-06 implementation and evidence surface."""

    paths = gate.get("source_paths")
    files = source_manifest.get("files")
    if (
        not isinstance(paths, list)
        or paths != sorted(paths)
        or len(paths) != len(set(paths))
        or not paths
        or not all(isinstance(path, str) and path for path in paths)
        or not isinstance(files, list)
    ):
        raise ValueError("WP-06 source scope is not exact")
    indexed = {
        record.get("path"): record for record in files
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    if len(indexed) != len(files) or any(path not in indexed for path in paths):
        raise ValueError("WP-06 source is missing from the source manifest")
    selected = [indexed[path] for path in paths]
    if any(
        set(record) != {"path", "sha256", "size"}
        or not valid_digest(record.get("sha256"))
        or type(record.get("size")) is not int
        or record["size"] < 0
        for record in selected
    ):
        raise ValueError("WP-06 source record is invalid")
    return selected


def wp06_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Attest exact project-lifecycle and migration runtime inputs."""

    pins = gate.get("runtime_pins")
    expected_pin_keys = {
        "migration_fault_schedule", "migration_registry", "migration_schema_registry",
        "migration_storage_policy", "project_scope_schema",
        "project_scope_digest_input_schema",
    }
    if not isinstance(pins, dict) or set(pins) != expected_pin_keys:
        raise ValueError("WP-06 runtime pins are not exact")
    specifications = {
        "migration_fault_schedule": {
            "path", "sha256", "schedule_id", "point_count",
            "process_crash_point_count", "concurrency_scenario_count",
        },
        "migration_registry": {"path", "sha256", "registry_id", "registry_digest"},
        "migration_schema_registry": {"path", "sha256", "registry_id", "registry_digest"},
        "migration_storage_policy": {"path", "sha256", "policy_id"},
        "project_scope_schema": {"path", "sha256", "schema_id"},
        "project_scope_digest_input_schema": {"path", "sha256", "schema_id"},
    }
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for name in sorted(expected_pin_keys):
        pin = pins[name]
        if (
            not isinstance(pin, dict)
            or set(pin) != specifications[name]
            or not valid_digest(pin.get("sha256"))
        ):
            raise ValueError("WP-06 runtime pin is not exact")
        relative = _project_relative_path(pin.get("path"), "WP-06 runtime path")
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("WP-06 runtime input is unavailable")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("WP-06 runtime input is invalid JSON") from error
        if not isinstance(document, dict) or digest(path.read_bytes()) != pin["sha256"]:
            raise ValueError("WP-06 runtime input digest mismatch")
        documents[name] = document
        records.append({"path": relative.as_posix(), "sha256": pin["sha256"], "size": path.stat().st_size})
    schedule_pin = pins["migration_fault_schedule"]
    schedule = documents["migration_fault_schedule"]
    points = schedule.get("points")
    crashes = schedule.get("process_crash_points")
    concurrency = schedule.get("concurrency_scenarios")
    if (
        schedule_pin.get("path") != "config/contracts/migration-fault-schedule-v2.json"
        or schedule.get("schema_version") != "2.0"
        or schedule.get("schedule_id") != schedule_pin.get("schedule_id")
        or not all(isinstance(value, list) for value in (points, crashes, concurrency))
        or not all(isinstance(item, str) and item for values in (points, crashes, concurrency) for item in values)
        or points != sorted(points) or len(points) != len(set(points))
        or crashes != sorted(crashes) or len(crashes) != len(set(crashes))
        or concurrency != sorted(concurrency) or len(concurrency) != len(set(concurrency))
        or len(points) != 51 or schedule_pin.get("point_count") != 51
        or len(crashes) != 31 or schedule_pin.get("process_crash_point_count") != 31
        or len(concurrency) != 4 or schedule_pin.get("concurrency_scenario_count") != 4
        or not set(crashes).issubset(set(points))
    ):
        raise ValueError("WP-06 migration fault schedule is not exact")
    registry_pin = pins["migration_registry"]
    registry = documents["migration_registry"]
    schema_registry_pin = pins["migration_schema_registry"]
    schema_registry = documents["migration_schema_registry"]
    policy_pin = pins["migration_storage_policy"]
    policy = documents["migration_storage_policy"]
    project_pin = pins["project_scope_schema"]
    project = documents["project_scope_schema"]
    digest_project_pin = pins["project_scope_digest_input_schema"]
    digest_project = documents["project_scope_digest_input_schema"]
    if (
        registry.get("registry_id") != registry_pin.get("registry_id")
        or registry.get("registry_digest") != registry_pin.get("registry_digest")
        or schema_registry.get("registry_id") != schema_registry_pin.get("registry_id")
        or schema_registry.get("registry_digest") != schema_registry_pin.get("registry_digest")
        or policy.get("policy_id") != policy_pin.get("policy_id")
        or project.get("$id") != project_pin.get("schema_id")
        or digest_project.get("$id") != digest_project_pin.get("schema_id")
    ):
        raise ValueError("WP-06 runtime identity mismatch")
    repository = repository_runtime(root)
    return {
        "kind": "project-lifecycle-migration-local-v1",
        "repository_runtime": repository,
        "migration_schedule_id": schedule["schedule_id"],
        "migration_schedule_sha256": schedule_pin["sha256"],
        "migration_points": points,
        "process_crash_points": crashes,
        "concurrency_scenarios": concurrency,
        "migration_registry_id": registry["registry_id"],
        "migration_registry_digest": registry["registry_digest"],
        "migration_schema_registry_id": schema_registry["registry_id"],
        "migration_schema_registry_digest": schema_registry["registry_digest"],
        "migration_storage_policy_id": policy["policy_id"],
        "project_scope_schema_id": project["$id"],
        "project_scope_digest_input_schema_id": digest_project["$id"],
        "inputs": records,
        "real_external_actions_enabled": False,
    }


def wp07_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the exact approved WP-07 documents and authority envelope."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP07_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-07 governing document pins are not exact")
    documents = governing_documents(root=root, paths=WP07_GOVERNING_DOCUMENT_PATHS)
    if any(
        document["path"] != pin["path"] or document["sha256"] != pin["sha256"]
        for document, pin in zip(documents, pins, strict=True)
    ):
        raise ValueError("WP-07 governing document digest mismatch")
    return documents


def _wp07_frozen_command(root: pathlib.Path) -> dict[str, object]:
    return _frozen_candidate_command(
        artifact="wp-07",
        revision=3,
        source_manifest_digest=WP07_FROZEN_SOURCE_MANIFEST_DIGEST,
        command_evidence_digest=WP07_FROZEN_COMMAND_EVIDENCE_DIGEST,
        exit_digest=WP07_FROZEN_EXIT_DIGEST,
        verdict_digest=WP07_FROZEN_VERDICT_DIGEST,
        root=root,
    )


def wp07_frozen_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Return the governing records from the exact accepted WP-07 r3 tuple."""

    return _frozen_candidate_documents(
        gate=gate,
        command=_wp07_frozen_command(root),
        paths=WP07_GOVERNING_DOCUMENT_PATHS,
        artifact="WP-07",
    )


def wp07_frozen_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Return stable bindings from the exact accepted WP-07 r3 tuple."""

    value = _frozen_candidate_payload(
        gate_value=gate.get("binding_groups"),
        gate_digest=WP07_FROZEN_BINDING_GROUPS_DIGEST,
        command=_wp07_frozen_command(root),
        field="stable_test_bindings",
        artifact="WP-07",
    )
    if (
        not isinstance(value, list)
        or any(
            not isinstance(item, dict)
            or set(item) != {"test_id", "qualified_test"}
            or not all(isinstance(item[field], str) and item[field] for field in item)
            for item in value
        )
    ):
        raise ValueError("WP-07 frozen stable test bindings are invalid")
    return value


def wp07_frozen_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Return runtime evidence from the exact accepted WP-07 r3 tuple."""

    value = _frozen_candidate_payload(
        gate_value=gate.get("runtime_pins"),
        gate_digest=WP07_FROZEN_RUNTIME_PINS_DIGEST,
        command=_wp07_frozen_command(root),
        field="wp07_runtime",
        artifact="WP-07",
    )
    if not isinstance(value, dict):
        raise ValueError("WP-07 frozen runtime is invalid")
    return value


def wp07_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Derive the exact one-to-one GEW-RT-001..032 test bindings."""

    groups = gate.get("binding_groups")
    if not isinstance(groups, list) or len(groups) != 10:
        raise ValueError("WP-07 binding groups are not exact")
    expected_keys = {"prefix", "start", "end", "path", "module", "class"}
    bindings: list[dict[str, str]] = []
    numbers: list[int] = []
    ids_seen: set[str] = set()
    qualified_seen: set[str] = set()
    surface_declared: dict[tuple[str, str, str], set[int]] = {}
    surface_observed: dict[tuple[str, str, str], set[int]] = {}
    for group in groups:
        if not isinstance(group, dict) or set(group) != expected_keys:
            raise ValueError("WP-07 binding group is not exact")
        if group["prefix"] != "GEW-RT":
            raise ValueError("WP-07 binding prefix is not exact")
        start = group["start"]
        end = group["end"]
        module = group["module"]
        class_name = group["class"]
        if (
            type(start) is not int or type(end) is not int or start < 1 or end < start
            or type(module) is not str or not module
            or type(class_name) is not str or not class_name
        ):
            raise ValueError("WP-07 binding group value is invalid")
        relative = _project_relative_path(group["path"], "WP-07 test path")
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stem != module:
            raise ValueError("WP-07 bound test source is invalid")
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError) as error:
            raise ValueError("WP-07 bound test source cannot be parsed") from error
        classes = [
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            raise ValueError("WP-07 bound test class is not unique")
        methods: dict[int, list[str]] = {}
        for node in classes[0].body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            match = re.fullmatch(r"test_gew_rt_(\d{3})_.+", node.name)
            if match:
                methods.setdefault(int(match.group(1)), []).append(node.name)
        expected_numbers = list(range(start, end + 1))
        if any(number not in methods or len(methods[number]) != 1 for number in expected_numbers):
            raise ValueError("WP-07 stable test method set is not exact")
        surface = (relative.as_posix(), module, class_name)
        surface_declared.setdefault(surface, set()).update(expected_numbers)
        surface_observed[surface] = set(methods)
        numbers.extend(expected_numbers)
        for number in expected_numbers:
            test_id = f"GEW-RT-{number:03d}"
            qualified = f"{module}.{class_name}.{methods[number][0]}"
            if test_id in ids_seen or qualified in qualified_seen:
                raise ValueError("WP-07 stable test binding is not one-to-one")
            ids_seen.add(test_id)
            qualified_seen.add(qualified)
            bindings.append({"test_id": test_id, "qualified_test": qualified})
    if numbers != list(range(1, 46)) or surface_declared != surface_observed:
        raise ValueError("WP-07 stable test range contains a gap or overlap")
    return bindings


def wp07_supplemental_test_bindings(gate: dict[str, object]) -> list[dict[str, str]]:
    """Validate the exact non-numeric hardening supplements."""

    expected = [
        {
            "test_id": "GEW-RT-022A",
            "qualified_test": (
                "test_wp07_runtime_hardening.WP07RuntimeHardeningTests."
                "test_gew_rt_022a_callback_context_is_one_use_and_exception_safe"
            ),
        },
        {
            "test_id": "GEW-RT-025A",
            "qualified_test": (
                "test_wp07_runtime_hardening.WP07RuntimeHardeningTests."
                "test_gew_rt_025a_resigned_adapter_result_binding_is_rejected"
            ),
        },
        {
            "test_id": "GEW-RT-044A",
            "qualified_test": (
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_044a_resigned_independence_field_substitution_is_zero_call"
            ),
        },
    ]
    if gate.get("supplemental_test_bindings") != expected:
        raise ValueError("WP-07 supplemental test bindings are not exact")
    return expected


def wp07_required_skill_test_bindings(gate: dict[str, object]) -> list[dict[str, str]]:
    """Validate explicit quick-validation and isolated-wheel Skill bindings."""

    expected = [
        {
            "test_id": "GEW-WP-07-SKILL-QUICK-P",
            "qualified_test": (
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_026_codex_and_hermes_skills_are_thin_and_structurally_valid"
            ),
        },
        {
            "test_id": "GEW-WP-07-ISOLATED-WHEEL-P",
            "qualified_test": (
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_031_isolated_prerelease_wheel_and_skill_fixture_uses_exact_origin"
            ),
        },
        {
            "test_id": "GEW-WP-07-ISOLATED-FULL-FLOW-P",
            "qualified_test": (
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_043_isolated_wheel_executes_full_owner_turn_surface_for_all_cells"
            ),
        },
    ]
    if gate.get("required_skill_test_bindings") != expected:
        raise ValueError("WP-07 required Skill test bindings are not exact")
    return expected


def wp07_reviewer_remedy_test_bindings(gate: dict[str, object]) -> list[dict[str, str]]:
    """Validate and flatten the exact tests closing all WP-07 r1 findings."""

    expected = [
        {
            "finding_id": "WP07-CODE-R1-001",
            "qualified_tests": [
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_043_isolated_wheel_executes_full_owner_turn_surface_for_all_cells",
                "test_wp07_owner_turns.WP07OwnerTurnTests."
                "test_gew_rt_045_each_owner_turn_is_one_exact_versioned_operation",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-002",
            "qualified_tests": [
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_042_independent_skill_and_running_executable_handshake_fail_closed",
                "test_wp07_skill_cli.WP07SkillCliTests."
                "test_gew_rt_031_isolated_prerelease_wheel_and_skill_fixture_uses_exact_origin",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-003",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_037_operation_capability_is_rechecked_before_adapter_call",
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_038_foreign_task_rejects_before_runtime_call",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-004",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_036_interleaved_channel_sessions_never_cross_delivery",
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_033_arbitrary_duck_adapter_is_not_runtime_authority",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-005",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_040_runtime_query_facade_seals_raw_show_search_and_list",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-006",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_039_independence_attestation_rejects_before_reviewer_call",
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_044_independence_attestation_cannot_cross_reviewer_request",
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_044a_resigned_independence_field_substitution_is_zero_call",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-007",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_041_runtime_resource_policy_rejects_before_port_call",
            ],
        },
        {
            "finding_id": "WP07-CODE-R1-008",
            "qualified_tests": [
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_034_duplicate_owner_alias_configuration_is_rejected",
                "test_wp07_runtime_r2.WP07RuntimeR2Tests."
                "test_gew_rt_035_lineage_binds_exact_platform_identity_source",
            ],
        },
    ]
    if gate.get("reviewer_remedy_bindings") != expected:
        raise ValueError("WP-07 reviewer remedy bindings are not exact")
    return [
        {"finding_id": record["finding_id"], "qualified_test": qualified}
        for record in expected
        for qualified in record["qualified_tests"]
    ]


def wp07_source_records(
    gate: dict[str, object],
    source_manifest: dict[str, object],
) -> list[dict[str, object]]:
    """Select the exact WP-07 runtime, Skill, test, and evidence surface."""

    paths = gate.get("source_paths")
    files = source_manifest.get("files")
    if (
        not isinstance(paths, list)
        or paths != sorted(paths)
        or len(paths) != len(set(paths))
        or not paths
        or not all(isinstance(path, str) and path for path in paths)
        or not isinstance(files, list)
    ):
        raise ValueError("WP-07 source scope is not exact")
    indexed = {
        record.get("path"): record for record in files
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    if len(indexed) != len(files) or any(path not in indexed for path in paths):
        raise ValueError("WP-07 source is missing from the source manifest")
    selected = [indexed[path] for path in paths]
    if any(
        set(record) != {"path", "sha256", "size"}
        or not valid_digest(record.get("sha256"))
        or type(record.get("size")) is not int
        or record["size"] < 0
        for record in selected
    ):
        raise ValueError("WP-07 source record is invalid")
    return selected


def _frozenset_assignment(tree: ast.Module, name: str) -> list[str]:
    matches: list[list[str]] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        value = node.value
        if (
            isinstance(target, ast.Name) and target.id == name
            and isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
            and value.func.id == "frozenset" and len(value.args) == 1
            and isinstance(value.args[0], ast.Set)
        ):
            values = [element.value for element in value.args[0].elts if isinstance(element, ast.Constant)]
            if len(values) == len(value.args[0].elts) and all(isinstance(item, str) for item in values):
                matches.append(sorted(values))
    if len(matches) != 1:
        raise ValueError(f"WP-07 runtime configuration field {name} is not exact")
    return matches[0]


def wp07_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Attest the exact local WP-07 runtime fixture, config fields, and Skills."""

    pins = gate.get("runtime_pins")
    if not isinstance(pins, dict) or set(pins) != {
        "runtime_fixture", "runtime_configuration_contract", "runtime_resource_policy",
        "runtime_local_port_policy", "skill_assets",
    }:
        raise ValueError("WP-07 runtime pins are not exact")
    fixture_pin = pins["runtime_fixture"]
    config_pin = pins["runtime_configuration_contract"]
    policy_pin = pins["runtime_resource_policy"]
    local_port_pin = pins["runtime_local_port_policy"]
    skill_pins = pins["skill_assets"]
    if (
        not isinstance(fixture_pin, dict)
        or set(fixture_pin) != {
            "path", "sha256", "schema_version", "cell_count", "cell_ids",
            "runtime_kinds", "channel_kinds", "capabilities",
        }
        or fixture_pin.get("path") != "tests/fixtures/wp07-runtime-adapters.json"
        or not valid_digest(fixture_pin.get("sha256"))
        or fixture_pin.get("schema_version") != "1.0"
        or fixture_pin.get("cell_count") != 3
        or fixture_pin.get("cell_ids") != ["codex-native", "hermes-telegram", "hermes-discord"]
        or fixture_pin.get("runtime_kinds") != ["codex", "hermes"]
        or fixture_pin.get("channel_kinds") != ["discord", "native", "telegram"]
        or fixture_pin.get("capabilities") != [
            "agent.invoke", "human.request", "presentation.deliver", "reviewer.invoke", "tool.invoke",
        ]
    ):
        raise ValueError("WP-07 runtime fixture pin is not exact")
    if (
        not isinstance(config_pin, dict)
        or set(config_pin) != {
            "path", "sha256", "configuration_fields", "runtime_input_fields",
            "capability_fields",
        }
        or config_pin.get("path") != "adapters/graph_engineering/adapters/runtime_config.py"
        or not valid_digest(config_pin.get("sha256"))
        or any(
            not isinstance(config_pin.get(name), list)
            or config_pin[name] != sorted(config_pin[name])
            or len(config_pin[name]) != len(set(config_pin[name]))
            or not all(isinstance(item, str) and item for item in config_pin[name])
            for name in ("configuration_fields", "runtime_input_fields", "capability_fields")
        )
    ):
        raise ValueError("WP-07 runtime configuration pin is not exact")
    if (
        not isinstance(policy_pin, dict)
        or set(policy_pin) != {
            "path", "sha256", "schema_version", "policy_id", "policy_digest",
            "resource_profile_digest", "cost_schedule_digest", "max_record_bytes",
            "max_executable_bytes", "max_string_chars", "max_segments", "max_items",
            "max_depth",
        }
        or policy_pin.get("path") != "config/contracts/runtime-resource-policy-v1.json"
        or not valid_digest(policy_pin.get("sha256"))
    ):
        raise ValueError("WP-07 runtime resource policy pin is not exact")
    if (
        not isinstance(local_port_pin, dict)
        or set(local_port_pin) != {
            "path", "sha256", "schema_version", "human_status", "decision_ref_prefix",
            "presentation_status", "delivery_ref_prefix", "policy_digest",
        }
        or local_port_pin.get("path") != "config/contracts/runtime-local-port-policy-v1.json"
        or not valid_digest(local_port_pin.get("sha256"))
    ):
        raise ValueError("WP-07 runtime local port policy pin is not exact")
    expected_skill_paths = [
        "skills/graph-engineering-codex/SKILL.md",
        "skills/graph-engineering-codex/agents/openai.yaml",
        "skills/graph-engineering-hermes/SKILL.md",
        "skills/graph-engineering-hermes/agents/openai.yaml",
    ]
    if (
        not isinstance(skill_pins, list)
        or [item.get("path") for item in skill_pins if isinstance(item, dict)] != expected_skill_paths
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in skill_pins
        )
    ):
        raise ValueError("WP-07 Skill asset pins are not exact")

    fixture_path = root / str(fixture_pin["path"])
    config_path = root / str(config_pin["path"])
    policy_path = root / str(policy_pin["path"])
    local_port_path = root / str(local_port_pin["path"])
    if any(
        path.is_symlink() or not path.is_file()
        for path in (fixture_path, config_path, policy_path, local_port_path)
    ):
        raise ValueError("WP-07 runtime input is unavailable")
    if (
        digest(fixture_path.read_bytes()) != fixture_pin["sha256"]
        or digest(config_path.read_bytes()) != config_pin["sha256"]
        or digest(policy_path.read_bytes()) != policy_pin["sha256"]
        or digest(local_port_path.read_bytes()) != local_port_pin["sha256"]
    ):
        raise ValueError("WP-07 runtime input digest mismatch")
    try:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        local_port_policy = json.loads(local_port_path.read_text(encoding="utf-8"))
        config_tree = ast.parse(config_path.read_text(encoding="utf-8"), filename=str(config_path))
    except (OSError, UnicodeError, json.JSONDecodeError, SyntaxError) as error:
        raise ValueError("WP-07 runtime input cannot be parsed") from error
    cells = fixture.get("cells") if isinstance(fixture, dict) else None
    shared = fixture.get("shared") if isinstance(fixture, dict) else None
    if (
        not isinstance(fixture, dict) or set(fixture) != {"schema_version", "shared", "cells"}
        or fixture.get("schema_version") != fixture_pin["schema_version"]
        or not isinstance(shared, dict)
        or not isinstance(cells, list) or len(cells) != fixture_pin["cell_count"]
        or [cell.get("cell_id") for cell in cells if isinstance(cell, dict)] != fixture_pin["cell_ids"]
        or sorted({cell.get("runtime_kind") for cell in cells if isinstance(cell, dict)})
        != fixture_pin["runtime_kinds"]
        or sorted({cell.get("channel_kind") for cell in cells if isinstance(cell, dict)})
        != fixture_pin["channel_kinds"]
        or shared.get("capabilities") != fixture_pin["capabilities"]
        or any(
            not isinstance(cell, dict)
            or set(cell) != {
                "cell_id", "runtime_kind", "adapter_id", "runtime_instance_id", "skill_id",
                "channel_kind", "owner_bindings", "allowed_channels",
            }
            for cell in cells
        )
    ):
        raise ValueError("WP-07 runtime fixture is not exact")
    if not isinstance(policy, dict) or policy != {
        key: value for key, value in policy_pin.items() if key not in {"path", "sha256"}
    }:
        raise ValueError("WP-07 runtime resource policy is not exact")
    if shared.get("runtime_resource_policy_digest") != policy["policy_digest"]:
        raise ValueError("WP-07 runtime fixture resource policy binding is not exact")
    if not isinstance(local_port_policy, dict) or local_port_policy != {
        key: value for key, value in local_port_pin.items() if key not in {"path", "sha256"}
    }:
        raise ValueError("WP-07 runtime local port policy is not exact")
    if shared.get("runtime_local_port_policy_digest") != local_port_policy["policy_digest"]:
        raise ValueError("WP-07 runtime fixture local port policy binding is not exact")
    field_names = {
        "configuration_fields": "CONFIGURATION_FIELDS",
        "runtime_input_fields": "RUNTIME_INPUT_FIELDS",
        "capability_fields": "CAPABILITY_FIELDS",
    }
    for pin_name, assignment in field_names.items():
        if _frozenset_assignment(config_tree, assignment) != config_pin[pin_name]:
            raise ValueError("WP-07 runtime configuration field mismatch")
    skill_records: list[dict[str, object]] = []
    for pin in skill_pins:
        path = root / str(pin["path"])
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != pin["sha256"]:
            raise ValueError("WP-07 Skill asset mismatch")
        skill_records.append({"path": pin["path"], "sha256": pin["sha256"], "size": path.stat().st_size})
    return {
        "kind": "codex-hermes-runtime-adapters-v1",
        "fixture": {
            "path": fixture_pin["path"],
            "sha256": fixture_pin["sha256"],
            "size": fixture_path.stat().st_size,
            "schema_version": fixture["schema_version"],
            "cell_ids": fixture_pin["cell_ids"],
            "runtime_kinds": fixture_pin["runtime_kinds"],
            "channel_kinds": fixture_pin["channel_kinds"],
            "capabilities": fixture_pin["capabilities"],
        },
        "configuration_contract": {
            "path": config_pin["path"],
            "sha256": config_pin["sha256"],
            "size": config_path.stat().st_size,
            "configuration_fields": config_pin["configuration_fields"],
            "runtime_input_fields": config_pin["runtime_input_fields"],
            "capability_fields": config_pin["capability_fields"],
        },
        "runtime_resource_policy": {
            "path": policy_pin["path"],
            "sha256": policy_pin["sha256"],
            "size": policy_path.stat().st_size,
            "policy_id": policy["policy_id"],
            "policy_digest": policy["policy_digest"],
            "resource_profile_digest": policy["resource_profile_digest"],
            "cost_schedule_digest": policy["cost_schedule_digest"],
            "bounds": {
                key: policy[key] for key in (
                    "max_record_bytes", "max_executable_bytes", "max_string_chars",
                    "max_segments", "max_items", "max_depth",
                )
            },
        },
        "runtime_local_port_policy": {
            "path": local_port_pin["path"],
            "sha256": local_port_pin["sha256"],
            "size": local_port_path.stat().st_size,
            "schema_version": local_port_policy["schema_version"],
            "human_status": local_port_policy["human_status"],
            "decision_ref_prefix": local_port_policy["decision_ref_prefix"],
            "presentation_status": local_port_policy["presentation_status"],
            "delivery_ref_prefix": local_port_policy["delivery_ref_prefix"],
            "policy_digest": local_port_policy["policy_digest"],
        },
        "skill_assets": skill_records,
        "required_skill_tests": wp07_required_skill_test_bindings(gate),
        "real_external_actions_enabled": False,
    }


def wp07a_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the approved WP-07A documents, ADRs, and authority envelope."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP07A_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-07A governing document pins are not exact")
    documents = governing_documents(root=root, paths=WP07A_GOVERNING_DOCUMENT_PATHS)
    if any(
        document["path"] != pin["path"] or document["sha256"] != pin["sha256"]
        for document, pin in zip(documents, pins, strict=True)
    ):
        raise ValueError("WP-07A governing document digest mismatch")
    return documents


def _wp07a_qualified_methods(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    module: str,
    class_name: str,
) -> set[str]:
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stem != module:
        raise ValueError("WP-07A bound test source is invalid")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as error:
        raise ValueError("WP-07A bound test source cannot be parsed") from error
    classes = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(classes) != 1:
        raise ValueError("WP-07A bound test class is not unique")
    return {
        node.name for node in classes[0].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def wp07a_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Derive the exact one-to-one GEW-ACT-001..010 stable bindings."""

    groups = gate.get("binding_groups")
    if not isinstance(groups, list) or len(groups) != 7:
        raise ValueError("WP-07A binding groups are not exact")
    bindings: list[dict[str, str]] = []
    numbers: list[int] = []
    ids: set[str] = set()
    qualified: set[str] = set()
    surfaces: dict[tuple[str, str, str], set[str]] = {}
    for group in groups:
        if not isinstance(group, dict) or set(group) != {
            "prefix", "start", "end", "path", "module", "class",
        }:
            raise ValueError("WP-07A binding group is not exact")
        start, end = group["start"], group["end"]
        module, class_name = group["module"], group["class"]
        if (
            group["prefix"] != "GEW-ACT"
            or type(start) is not int or type(end) is not int
            or start < 1 or end < start
            or type(module) is not str or not module
            or type(class_name) is not str or not class_name
        ):
            raise ValueError("WP-07A binding group value is invalid")
        relative = _project_relative_path(group["path"], "WP-07A test path")
        methods = _wp07a_qualified_methods(root, relative, module, class_name)
        surface = (relative.as_posix(), module, class_name)
        surfaces.setdefault(surface, methods)
        for number in range(start, end + 1):
            matches = sorted(
                method for method in methods
                if re.fullmatch(rf"test_gew_act_{number:03d}_.+", method)
            )
            if len(matches) != 1:
                raise ValueError("WP-07A stable test method is not unique")
            test_id = f"GEW-ACT-{number:03d}"
            name = f"{module}.{class_name}.{matches[0]}"
            if test_id in ids or name in qualified:
                raise ValueError("WP-07A stable test binding is not one-to-one")
            ids.add(test_id)
            qualified.add(name)
            numbers.append(number)
            bindings.append({"test_id": test_id, "qualified_test": name})
    if numbers != list(range(1, 11)):
        raise ValueError("WP-07A stable test range contains a gap or overlap")
    return bindings


def wp07a_supplemental_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Validate every WP-07A security and real-adapter supplemental test."""

    bindings = gate.get("supplemental_test_bindings")
    if not isinstance(bindings, list) or len(bindings) != 28:
        raise ValueError("WP-07A supplemental test bindings are not exact")
    expected_ids = [
        "GEW-ACT-001A", "GEW-ACT-001B", "GEW-ACT-001C", "GEW-ACT-001D", "GEW-ACT-001E",
        "GEW-ACT-001F", "GEW-ACT-001G", "GEW-ACT-001H",
        "GEW-ACT-002A", "GEW-ACT-003A", "GEW-ACT-004A",
        "GEW-ACT-004B", "GEW-ACT-005A", "GEW-ACT-006A", "GEW-ACT-006B",
        "GEW-ACT-006C", "GEW-ACT-006D", "GEW-ACT-006E", "GEW-ACT-006F",
        "GEW-ACT-006G", "GEW-ACT-007A", "GEW-ACT-008A", "GEW-ACT-008B",
        "GEW-ACT-008C", "GEW-ACT-009A", "GEW-ACT-010A", "GEW-ACT-010B",
        "GEW-ACT-010C",
    ]
    if [item.get("test_id") for item in bindings if isinstance(item, dict)] != expected_ids:
        raise ValueError("WP-07A supplemental test ID set is not exact")
    seen: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"test_id", "qualified_test"}:
            raise ValueError("WP-07A supplemental binding is invalid")
        qualified = binding["qualified_test"]
        if type(qualified) is not str or qualified in seen:
            raise ValueError("WP-07A supplemental qualified test is invalid")
        parts = qualified.split(".")
        if len(parts) != 3:
            raise ValueError("WP-07A supplemental qualified test is invalid")
        module, class_name, method = parts
        candidates = list(root.glob(f"tests/*/{module}.py"))
        if len(candidates) != 1:
            raise ValueError("WP-07A supplemental test module is not unique")
        relative = pathlib.PurePosixPath(candidates[0].relative_to(root).as_posix())
        if method not in _wp07a_qualified_methods(root, relative, module, class_name):
            raise ValueError("WP-07A supplemental test method is missing")
        seen.add(qualified)
    return bindings  # type: ignore[return-value]


def wp07a_reviewer_remedy_test_bindings(gate: dict[str, object]) -> list[dict[str, str]]:
    """Validate and flatten the exact tests closing all five WP-07A r1 code findings."""

    expected = [
        {"finding_id": "WP07A-CODE-R1-001", "qualified_tests": [
            "test_wp07a_action_coordinator.WP07AConcreteActionCoordinatorTests."
            "test_gew_act_008c_after_receipt_drift_cannot_consume_the_claim",
        ]},
        {"finding_id": "WP07A-CODE-R1-002", "qualified_tests": [
            "test_wp07a_command_runtime.WP07ACommandRuntimeTests."
            "test_gew_act_006e_semantic_escaped_and_derived_secret_outputs_are_blocked",
            "test_wp07a_command_runtime.WP07ACommandRuntimeTests."
            "test_gew_act_006f_secret_material_is_destroyed_on_every_post_resolution_path",
        ]},
        {"finding_id": "WP07A-CODE-R1-003", "qualified_tests": [
            "test_wp07a_action_contract_security.WP07AActionContractSecurityTests."
            "test_gew_act_001b_installation_anchor_rejects_re_signed_registry_and_provenance_substitutions",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001c_clean_installed_wheel_resolves_exact_builtin_provenance",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001d_copied_source_payload_has_no_checkout_authority",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001e_zip_physical_protected_members_are_unique",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001f_source_uses_only_explicit_control_identity",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001g_direct_archive_never_stages_adapter_bytes",
            "test_wp07a_real_action.WP07ARealActionE2ETests."
            "test_gew_act_001h_zip_loader_bytes_must_match_validated_archive",
        ]},
        {"finding_id": "WP07A-CODE-R1-004", "qualified_tests": [
            "test_wp07a_command_runtime.WP07ACommandRuntimeTests."
            "test_gew_act_006g_timeout_and_output_bound_terminate_and_reap_the_full_process_group",
        ]},
        {"finding_id": "WP07A-CODE-R1-005", "qualified_tests": [
            "test_wp07a_action_coordinator.WP07AConcreteActionCoordinatorTests."
            "test_gew_act_008c_after_receipt_drift_cannot_consume_the_claim",
        ]},
    ]
    if gate.get("reviewer_remedy_bindings") != expected:
        raise ValueError("WP-07A reviewer remedy bindings are not exact")
    return [
        {"finding_id": item["finding_id"], "qualified_test": qualified}
        for item in expected for qualified in item["qualified_tests"]
    ]


def wp07a_candidate_identities(gate: dict[str, object]) -> dict[str, str]:
    """Validate the actual author and designated independent reviewer."""

    expected = {
        "author_id": "codex:/root/wp05_evidence_author_r1",
        "reviewer_id": "codex:/root/wp07a_reviewer_r5",
    }
    if (
        gate.get("candidate_author_id") != expected["author_id"]
        or gate.get("designated_reviewer_id") != expected["reviewer_id"]
        or not valid_actor(expected["author_id"]) or not valid_actor(expected["reviewer_id"])
        or expected["author_id"].casefold() == expected["reviewer_id"].casefold()
    ):
        raise ValueError("WP-07A candidate identities are not exact and independent")
    return expected


def wp07a_external_action_boundary(gate: dict[str, object]) -> dict[str, object]:
    """Validate the explicit disposable-local-only external-action boundary."""

    expected = {
        "mode": "disposable-local-only",
        "real_external_actions_enabled": True,
        "network_enabled": False,
        "user_repository_enabled": False,
        "allowed_adapter_ids": [
            "connector-unavailable-v1", "git-native-v1", "project-command-v1",
            "secret-provider-v1", "target-query-v1",
        ],
        "mutation_targets": ["temporary-git-fixture"],
        "command_launcher": "structured-argv-shell-false",
    }
    if gate.get("external_action_boundary") != expected:
        raise ValueError("WP-07A external-action boundary is not exact")
    return expected


def wp07a_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Attest exact schemas, product runtime, policies, and closed registries."""

    pins = gate.get("runtime_pins")
    expected_paths = list(WP07A_CONFIG_PATHS + WP07A_SCHEMA_PATHS + WP07A_RUNTIME_SOURCE_PATHS)
    if not isinstance(pins, list) or [item.get("path") for item in pins if isinstance(item, dict)] != expected_paths:
        raise ValueError("WP-07A runtime pin path set is not exact")
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for pin in pins:
        if (
            not isinstance(pin, dict) or set(pin) != {"path", "sha256"}
            or not valid_digest(pin.get("sha256"))
        ):
            raise ValueError("WP-07A runtime pin is invalid")
        path = root / str(pin["path"])
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != pin["sha256"]:
            raise ValueError("WP-07A runtime input digest mismatch")
        records.append({"path": pin["path"], "sha256": pin["sha256"], "size": path.stat().st_size})
        if str(pin["path"]).endswith(".json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ValueError("WP-07A runtime JSON cannot be parsed") from error
            if not isinstance(value, dict):
                raise ValueError("WP-07A runtime JSON is not an object")
            documents[str(pin["path"])] = value
    schema_manifest = documents[WP07A_CONFIG_PATHS[0]]
    adapter_registry = documents[WP07A_CONFIG_PATHS[1]]
    action_policy = documents[WP07A_CONFIG_PATHS[2]]
    concrete_policy = documents[WP07A_CONFIG_PATHS[3]]
    connector_registry = documents[WP07A_CONFIG_PATHS[4]]
    security_runtime = documents[WP07A_CONFIG_PATHS[5]]
    resources = schema_manifest.get("resources")
    schemas = [documents[path] for path in WP07A_SCHEMA_PATHS]
    if (
        schema_manifest.get("registry_id") != "urn:gew:schema-registry:action-adapters:1.0.0"
        or schema_manifest.get("registry_digest") != "sha256-jcs-v1:26da6daa65594e6b85635f63df033db3e4b1a0a36f1eb7b4bec36403ba294d9a"
        or not isinstance(resources, list) or len(resources) != 16
        or [item.get("schema_id") for item in resources if isinstance(item, dict)]
        != [schema.get("$id") for schema in schemas]
        or [item.get("body_digest") for item in resources if isinstance(item, dict)]
        != [f"sha256-raw-v1:{record['sha256']}" for record in records[6:22]]
    ):
        raise ValueError("WP-07A closed schema registry is not exact")
    entries = adapter_registry.get("entries")
    adapter_ids = [
        "git-native-v1", "project-command-v1", "target-query-v1",
        "secret-provider-v1", "connector-unavailable-v1",
    ]
    if (
        adapter_registry.get("registry_id") != "action-adapter-registry-default"
        or adapter_registry.get("registry_digest") != "sha256-jcs-v1:d9c939144b8f00e7afc2a4caa8a8b444d1f2bda88d57e635d28be5ca528eb4ff"
        or not isinstance(entries, list)
        or [item.get("adapter_id") for item in entries if isinstance(item, dict)] != adapter_ids
        or [item.get("adapter_kind") for item in entries if isinstance(item, dict)]
        != ["git", "project-command", "target-query", "secret-provider", "connector"]
    ):
        raise ValueError("WP-07A action adapter registry is not exact")
    if (
        action_policy.get("real_external_actions_enabled") is not True
        or action_policy.get("policy_id") != "action-policy-local-actions"
        or concrete_policy.get("real_local_actions_enabled") is not True
        or concrete_policy.get("launcher_mode") != "structured-argv-shell-false"
        or concrete_policy.get("registry_digest") != adapter_registry.get("registry_digest")
        or concrete_policy.get("allowed_adapter_ids") != sorted(adapter_ids)
        or connector_registry.get("registry_id") != "connector-registry-default"
        or len(connector_registry.get("entries", [])) != 1
        or connector_registry["entries"][0].get("status") != "unavailable"
        or security_runtime.get("policies", {}).get("action", {}).get("policy_digest")
        != action_policy.get("policy_digest")
    ):
        raise ValueError("WP-07A policy or connector closure is not exact")
    command_source = (root / "adapters/graph_engineering/adapters/command_native.py").read_text()
    if (
        "class CommandRegistry:" not in command_source
        or "class SecretProviderRegistry:" not in command_source
        or "shell=False" not in command_source
    ):
        raise ValueError("WP-07A command/secret registry closure is missing")
    boundary = wp07a_external_action_boundary(gate)
    return {
        "kind": "concrete-local-action-adapters-v1",
        "inputs": records,
        "schema_registry_id": schema_manifest["registry_id"],
        "schema_registry_digest": schema_manifest["registry_digest"],
        "schema_count": len(schemas),
        "adapter_registry_id": adapter_registry["registry_id"],
        "adapter_registry_digest": adapter_registry["registry_digest"],
        "adapter_ids": adapter_ids,
        "operation_ids": sorted(concrete_policy["allowed_operation_ids"]),
        "policy_id": action_policy["policy_id"],
        "concrete_policy_id": concrete_policy["policy_id"],
        "connector_registry_id": connector_registry["registry_id"],
        "connector_status": connector_registry["entries"][0]["status"],
        "command_registry_closed": True,
        "secret_provider_registry_closed": True,
        "external_action_boundary": boundary,
    }


def wp07a_frozen_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Validate and return the runtime embedded in the accepted WP-07A r6 tuple.

    Historical evidence must remain verifiable after later work packages change
    a runtime input. The accepted command record already embeds every exact
    runtime input, while its exit record binds that runtime and the complete
    command record canonically. This helper therefore validates those archived
    records against the immutable gate pins without hashing the live worktree.
    """

    pins = gate.get("runtime_pins")
    expected_paths = list(WP07A_CONFIG_PATHS + WP07A_SCHEMA_PATHS + WP07A_RUNTIME_SOURCE_PATHS)
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)] != expected_paths
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-07A frozen runtime pin set is not exact")

    paths = [
        root / WP07A_FROZEN_COMMAND_EVIDENCE_PATH,
        root / WP07A_FROZEN_EXIT_PATH,
    ]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("WP-07A frozen runtime records are unavailable")
    try:
        command_evidence, exit_record = [
            json.loads(path.read_text(encoding="utf-8")) for path in paths
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("WP-07A frozen runtime records cannot be parsed") from error
    if not isinstance(command_evidence, dict) or not isinstance(exit_record, dict):
        raise ValueError("WP-07A frozen runtime record is not an object")

    runtime = command_evidence.get("wp07a_runtime")
    inputs = runtime.get("inputs") if isinstance(runtime, dict) else None
    if (
        command_evidence.get("schema_version") != "1.0"
        or command_evidence.get("status") != "PASS"
        or exit_record.get("schema_version") != "1.0"
        or exit_record.get("artifact") != "wp-07a"
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest")
        != command_evidence.get("source_manifest_digest")
        or exit_record.get("command_evidence_digest")
        != digest(canonical_bytes(command_evidence))
        or not isinstance(runtime, dict)
        or exit_record.get("wp07a_runtime_digest") != digest(canonical_bytes(runtime))
        or not isinstance(inputs, list)
        or len(inputs) != len(pins)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in inputs
        )
        or [
            {"path": record["path"], "sha256": record["sha256"]}
            for record in inputs
        ] != pins
    ):
        raise ValueError("WP-07A frozen runtime binding is invalid")
    return runtime


def wp07a_frozen_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the document manifest embedded in the accepted WP-07A r6 tuple."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP07A_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-07A frozen governing document pin set is not exact")

    paths = [
        root / WP07A_FROZEN_COMMAND_EVIDENCE_PATH,
        root / WP07A_FROZEN_EXIT_PATH,
    ]
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("WP-07A frozen governing document records are unavailable")
    try:
        command_evidence, exit_record = [
            json.loads(path.read_text(encoding="utf-8")) for path in paths
        ]
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("WP-07A frozen governing document records cannot be parsed") from error
    if not isinstance(command_evidence, dict) or not isinstance(exit_record, dict):
        raise ValueError("WP-07A frozen governing document record is not an object")

    documents = command_evidence.get("governing_documents")
    if (
        command_evidence.get("schema_version") != "1.0"
        or command_evidence.get("status") != "PASS"
        or exit_record.get("schema_version") != "1.0"
        or exit_record.get("artifact") != "wp-07a"
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest")
        != command_evidence.get("source_manifest_digest")
        or exit_record.get("command_evidence_digest")
        != digest(canonical_bytes(command_evidence))
        or not isinstance(documents, list)
        or len(documents) != len(pins)
        or any(
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not valid_digest(record.get("sha256"))
            or type(record.get("size")) is not int
            or record["size"] < 0
            for record in documents
        )
        or [
            {"path": record["path"], "sha256": record["sha256"]}
            for record in documents
        ] != pins
        or exit_record.get("governing_documents_digest")
        != governing_documents_digest(documents)
    ):
        raise ValueError("WP-07A frozen governing document binding is invalid")
    return documents


def wp07a_source_records(
    gate: dict[str, object],
    source_manifest: dict[str, object],
) -> list[dict[str, object]]:
    """Select the exact WP-07A implementation, tests, and evidence surface."""

    return wp07_source_records(gate, source_manifest)


def _project_relative_path(value: object, label: str) -> pathlib.PurePosixPath:
    if type(value) is not str or not value:
        raise ValueError(f"invalid {label}")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"invalid {label}")
    return path


def dependency_verdicts(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate and summarize exact historical prerequisite candidates.

    A prerequisite candidate has its own immutable source identity. Requiring it
    to equal the downstream worktree identity would make updating the revision
    pointer self-invalidating. The downstream candidate is source-bound
    separately; this routine binds every record in the approved upstream tuple.
    """

    dependencies = gate.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("WP02 dependency verdict configuration is missing")
    results: list[dict[str, object]] = []
    identities: set[str] = set()
    for raw in dependencies:
        if not isinstance(raw, dict) or set(raw) != {
            "work_package", "revision", "source_manifest_path",
            "source_manifest_digest", "command_evidence_path", "verdict_path",
            "exit_path",
        }:
            raise ValueError("WP02 dependency verdict configuration is not exact")
        work_package = raw["work_package"]
        revision = raw["revision"]
        if (
            type(work_package) is not str
            or not work_package
            or work_package in identities
            or type(revision) is not int
            or revision < 0
        ):
            raise ValueError("invalid WP02 dependency identity")
        identities.add(work_package)
        source_path = _project_relative_path(
            raw["source_manifest_path"], "dependency source manifest path",
        )
        expected_source_digest = raw["source_manifest_digest"]
        if not valid_digest(expected_source_digest):
            raise ValueError("invalid dependency source manifest digest")
        command_path = _project_relative_path(
            raw["command_evidence_path"], "dependency command evidence path",
        )
        verdict_path = _project_relative_path(raw["verdict_path"], "dependency verdict path")
        exit_path = _project_relative_path(raw["exit_path"], "dependency exit path")
        try:
            source_manifest = json.loads((root / source_path).read_text())
            command_evidence = json.loads((root / command_path).read_text())
            verdict = json.loads((root / verdict_path).read_text())
            exit_record = json.loads((root / exit_path).read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("dependency verdict record is missing or invalid") from error
        if not all(isinstance(value, dict) for value in (
            source_manifest, command_evidence, verdict, exit_record,
        )):
            raise ValueError("dependency verdict record is not an object")
        manifest_payload = dict(source_manifest)
        manifest_digest = manifest_payload.pop("manifest_digest", None)
        command_digest = digest(canonical_bytes(command_evidence))
        exit_digest = digest(canonical_bytes(exit_record))
        reviewer = verdict.get("reviewer_id")
        author = exit_record.get("author_id")
        dispositions = verdict.get("finding_dispositions")
        if (
            manifest_digest != expected_source_digest
            or digest(canonical_bytes(manifest_payload)) != expected_source_digest
            or command_evidence.get("status") != "PASS"
            or command_evidence.get("source_manifest_digest") != expected_source_digest
            or verdict.get("verdict") != "PASS"
            or verdict.get("artifact") != work_package.casefold()
            or verdict.get("source_manifest_digest") != expected_source_digest
            or verdict.get("command_evidence_digest") != command_digest
            or verdict.get("candidate_exit_digest") != exit_digest
            or verdict.get("governing_documents_digest") != exit_record.get("governing_documents_digest")
            or verdict.get("findings") != []
            or not isinstance(dispositions, list)
            or not dispositions
            or any(
                not isinstance(item, dict) or item.get("status") != "closed"
                for item in dispositions
            )
            or exit_record.get("artifact") != work_package.casefold()
            or exit_record.get("source_manifest_digest") != expected_source_digest
            or exit_record.get("command_evidence_digest") != command_digest
            or exit_record.get("reviewer_id") != reviewer
            or not valid_actor(author)
            or not valid_actor(reviewer)
            or str(author).casefold() == str(reviewer).casefold()
        ):
            raise ValueError("dependency verdict is stale, non-PASS, or not independent")
        results.append({
            "work_package": work_package,
            "revision": revision,
            "source_manifest_path": source_path.as_posix(),
            "source_manifest_digest": expected_source_digest,
            "command_evidence_path": command_path.as_posix(),
            "command_evidence_digest": command_digest,
            "verdict_path": verdict_path.as_posix(),
            "verdict_digest": digest(canonical_bytes(verdict)),
            "exit_path": exit_path.as_posix(),
            "exit_digest": exit_digest,
            "reviewer_id": reviewer,
        })
    return results


WP08A_GOVERNING_DOCUMENT_PATHS = (
    "docs/positioning/baselines/graph-engineering-workflow-v2.md",
    "docs/positioning/baselines/graph-engineering-workflow-v2.sha256",
    "docs/prd/baselines/graph-engineering-workflow-v2.md",
    "docs/prd/baselines/graph-engineering-workflow-v2.sha256",
    "docs/specs/graph-engineering-workflow.md",
    "docs/impact/graph-engineering-workflow.md",
    "docs/plans/2026-08-13-graph-engineering-workflow.md",
    "docs/test-plans/graph-engineering-workflow.md",
    "docs/adr/0001-core-implementation-and-local-packaging.md",
    "docs/adr/0002-local-event-repository-and-coordination.md",
    "docs/adr/0003-deterministic-contract-stack.md",
    "docs/adr/0004-extension-source-and-capability-trust.md",
    "docs/adr/0005-recovery-claim-compensation.md",
    ".workflow/delivery/GEW-IMPLEMENTATION-V1/authority-envelope.json",
)
WP08A_RUNTIME_CONFIG_PATHS = (
    "config/contracts/extension-schema-registry-v1.json",
    "config/extensions/extension-activation-policy-v1.json",
    "config/extensions/extension-built-in-identities-v1.json",
    "config/extensions/extension-bundle-policy-v1.json",
    "config/extensions/extension-core-invariants-v1.json",
    "config/extensions/extension-fault-schedule-v1.json",
    "config/extensions/extension-storage-policy-v1.json",
    "config/release-coverage/oracle-manifest-v1.json",
    "config/release-coverage/trace-matrix-v1.json",
    "config/supply-chain/extension-crypto-provider-requirement-v1.json",
    "config/supply-chain/extension-package-parser-requirement-v1.json",
    "config/supply-chain/license-policy-v1.json",
)
WP08A_RUNTIME_SOURCE_PATHS = (
    "adapters/graph_engineering/adapters/extension_crypto.py",
    "application/graph_engineering/application/extensions.py",
    "application/graph_engineering/application/tasks.py",
    "core/graph_engineering/core/extension_activation.py",
    "core/graph_engineering/core/extension_bundle.py",
    "core/graph_engineering/core/extension_coverage.py",
    "core/graph_engineering/core/extension_data.py",
    "core/graph_engineering/core/extensions.py",
    "core/graph_engineering/core/graph/state.py",
    "core/graph_engineering/core/security/extensions.py",
    "scripts/build_backend.py",
    "scripts/run_verified_test.py",
    "storage/graph_engineering/storage/connection.py",
    "storage/graph_engineering/storage/extension_activation.py",
    "storage/graph_engineering/storage/extension_bundle.py",
    "storage/graph_engineering/storage/extension_install.py",
    "storage/graph_engineering/storage/extensions.py",
    "storage/graph_engineering/storage/migration.py",
    "storage/graph_engineering/storage/ports.py",
    "storage/graph_engineering/storage/repository.py",
)


def wp08a_governing_documents(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Validate the frozen product documents, Accepted ADR-0004 r7, and authority."""

    pins = gate.get("governing_document_digests")
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)]
        != list(WP08A_GOVERNING_DOCUMENT_PATHS)
        or any(
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or not valid_digest(item.get("sha256"))
            for item in pins
        )
    ):
        raise ValueError("WP-08A governing document pins are not exact")
    documents = governing_documents(root=root, paths=WP08A_GOVERNING_DOCUMENT_PATHS)
    if any(
        document["path"] != pin["path"] or document["sha256"] != pin["sha256"]
        for document, pin in zip(documents, pins, strict=True)
    ):
        raise ValueError("WP-08A governing document digest mismatch")
    adr = (root / "docs/adr/0004-extension-source-and-capability-trust.md").read_text()
    if (
        "Accepted，revision 7" not in adr
        or "wp08a_adr_reviewer_r4` PASS，zero findings" not in adr
    ):
        raise ValueError("WP-08A Accepted ADR-0004 r7 marker is missing")
    return documents


def _wp08a_qualified_methods(
    root: pathlib.Path,
    relative: pathlib.PurePosixPath,
    module: str,
    class_name: str,
) -> set[str]:
    path = root / relative
    if path.is_symlink() or not path.is_file() or path.stem != module:
        raise ValueError("WP-08A bound test source is invalid")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as error:
        raise ValueError("WP-08A bound test source cannot be parsed") from error
    classes = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    ]
    if len(classes) != 1:
        raise ValueError("WP-08A bound test class is not unique")
    return {
        node.name for node in classes[0].body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def wp08a_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    """Derive exact one-to-one GEW-EXT-001..032 stable bindings."""

    groups = gate.get("binding_groups")
    if not isinstance(groups, list) or len(groups) != 10:
        raise ValueError("WP-08A stable binding groups are not exact")
    bindings: list[dict[str, str]] = []
    numbers: list[int] = []
    qualified: set[str] = set()
    for group in groups:
        if not isinstance(group, dict) or set(group) != {
            "prefix", "start", "end", "path", "module", "class",
        }:
            raise ValueError("WP-08A stable binding group is invalid")
        start, end = group["start"], group["end"]
        module, class_name = group["module"], group["class"]
        if (
            group["prefix"] != "GEW-EXT"
            or type(start) is not int or type(end) is not int
            or start < 1 or end < start
            or type(module) is not str or not module
            or type(class_name) is not str or not class_name
        ):
            raise ValueError("WP-08A stable binding group value is invalid")
        relative = _project_relative_path(group["path"], "WP-08A stable test path")
        methods = _wp08a_qualified_methods(root, relative, module, class_name)
        for number in range(start, end + 1):
            matches = sorted(
                method for method in methods
                if re.fullmatch(rf"test_gew_ext_{number:03d}_.+", method)
            )
            if len(matches) != 1:
                raise ValueError("WP-08A stable test method is not unique")
            name = f"{module}.{class_name}.{matches[0]}"
            if name in qualified:
                raise ValueError("WP-08A stable test binding is not one-to-one")
            qualified.add(name)
            numbers.append(number)
            bindings.append({"test_id": f"GEW-EXT-{number:03d}", "qualified_test": name})
    if numbers != list(range(1, 33)):
        raise ValueError("WP-08A stable test range contains a gap or overlap")
    return bindings


def _validate_wp08a_explicit_bindings(
    bindings: object,
    expected_ids: list[str],
    *,
    root: pathlib.Path,
    label: str,
) -> list[dict[str, str]]:
    if (
        not isinstance(bindings, list)
        or [item.get("test_id") for item in bindings if isinstance(item, dict)] != expected_ids
    ):
        raise ValueError(f"WP-08A {label} binding IDs are not exact")
    seen: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"test_id", "qualified_test"}:
            raise ValueError(f"WP-08A {label} binding is invalid")
        qualified = binding["qualified_test"]
        if type(qualified) is not str or qualified in seen:
            raise ValueError(f"WP-08A {label} qualified test is invalid")
        parts = qualified.split(".")
        if len(parts) != 3:
            raise ValueError(f"WP-08A {label} qualified test is invalid")
        module, class_name, method = parts
        candidates = list(root.glob(f"tests/*/{module}.py"))
        if len(candidates) != 1:
            raise ValueError(f"WP-08A {label} test module is not unique")
        relative = pathlib.PurePosixPath(candidates[0].relative_to(root).as_posix())
        if method not in _wp08a_qualified_methods(root, relative, module, class_name):
            raise ValueError(f"WP-08A {label} test method is missing")
        seen.add(qualified)
    return bindings  # type: ignore[return-value]


def wp08a_supplemental_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    expected = [
        "ADR4-PKG-P-001",
        *(f"ADR4-PKG-R-{number:03d}" for number in range(1, 11)),
        "GEW-EXT-009A",
    ]
    return _validate_wp08a_explicit_bindings(
        gate.get("supplemental_test_bindings"), expected, root=root, label="supplemental",
    )


def wp08a_reviewer_remedy_test_bindings(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, str]]:
    remedies = gate.get("reviewer_remedy_bindings")
    expected_ids = [
        "WP08A-QR-R1-001", "WP08A-QR-R1-002", "WP08A-QR-R1-003",
        "WP08A-QR-R1-004", "WP08A-QR-R1-005", "WP08A-QR-R1-006",
        "WP08A-QR-R1-007", "WP08A-QR-R3-008", "WP08A-CODE-R4-009",
    ]
    if (
        not isinstance(remedies, list)
        or [item.get("finding_id") for item in remedies if isinstance(item, dict)] != expected_ids
    ):
        raise ValueError("WP-08A reviewer remedy finding IDs are not exact")
    flattened: list[dict[str, str]] = []
    qualified: list[str] = []
    for remedy in remedies:
        if (
            not isinstance(remedy, dict)
            or set(remedy) != {"finding_id", "qualified_tests"}
            or not isinstance(remedy["qualified_tests"], list)
            or not remedy["qualified_tests"]
        ):
            raise ValueError("WP-08A reviewer remedy binding is invalid")
        for test in remedy["qualified_tests"]:
            if type(test) is not str:
                raise ValueError("WP-08A reviewer remedy qualified test is invalid")
            qualified.append(test)
            flattened.append({"finding_id": remedy["finding_id"], "qualified_test": test})
    checked = _validate_wp08a_explicit_bindings(
        [
            {"test_id": f"REMEDY-{number:03d}", "qualified_test": item}
            for number, item in enumerate(qualified, start=1)
        ],
        [f"REMEDY-{number:03d}" for number in range(1, 21)],
        root=root,
        label="reviewer remedy",
    )
    del checked
    if len(qualified) != 20:
        raise ValueError("WP-08A reviewer remedy test count is not exact")
    return flattened


def wp08a_candidate_identities(gate: dict[str, object]) -> dict[str, str]:
    expected = {
        "author_id": "codex:/root/wp08a_evidence_author_r1",
        "reviewer_id": "codex:/root/wp08a_candidate_reviewer_r1",
    }
    if (
        gate.get("candidate_author_id") != expected["author_id"]
        or gate.get("designated_reviewer_id") != expected["reviewer_id"]
        or not valid_actor(expected["author_id"])
        or not valid_actor(expected["reviewer_id"])
        or expected["author_id"].casefold() == expected["reviewer_id"].casefold()
    ):
        raise ValueError("WP-08A candidate identities are not exact and independent")
    return expected


def wp08a_external_action_boundary(gate: dict[str, object]) -> dict[str, object]:
    expected = {
        "mode": "offline-local-data-only-candidate",
        "real_external_actions_enabled": False,
        "network_enabled": False,
        "user_repository_enabled": False,
        "trust_plane": "offline-only",
        "data_only_extension_status": "local-data-only-active",
        "non_builtin_executable_status": "blocked-pending-adr0003-revision-and-conformance",
        "formal_release_status": "blocked-pending-wp10-release-install-manifest",
        "dependency_artifact_attestations_available": False,
        "allowed_extension_categories": ["edge", "node", "policy", "template"],
    }
    if gate.get("external_action_boundary") != expected:
        raise ValueError("WP-08A external action boundary is not exact")
    return expected


def wp08a_runtime(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Attest the complete extension registry, configuration, and runtime source pins."""

    pins = gate.get("runtime_pins")
    expected_paths = list(WP08A_RUNTIME_CONFIG_PATHS + WP08A_RUNTIME_SOURCE_PATHS)
    if (
        not isinstance(pins, list)
        or [item.get("path") for item in pins if isinstance(item, dict)] != expected_paths
    ):
        raise ValueError("WP-08A runtime pin path set is not exact")
    records: list[dict[str, object]] = []
    documents: dict[str, dict[str, object]] = {}
    for pin in pins:
        if (
            not isinstance(pin, dict)
            or set(pin) != {"path", "sha256"}
            or not valid_digest(pin.get("sha256"))
        ):
            raise ValueError("WP-08A runtime pin is invalid")
        path = root / str(pin["path"])
        if path.is_symlink() or not path.is_file() or digest(path.read_bytes()) != pin["sha256"]:
            raise ValueError("WP-08A runtime input digest mismatch")
        records.append({"path": pin["path"], "sha256": pin["sha256"], "size": path.stat().st_size})
        if path.suffix == ".json":
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise ValueError("WP-08A runtime JSON cannot be parsed") from error
            if not isinstance(value, dict):
                raise ValueError("WP-08A runtime JSON is not an object")
            documents[str(pin["path"])] = value
    registry = documents[WP08A_RUNTIME_CONFIG_PATHS[0]]
    resources = registry.get("resources")
    schema_paths = sorted((root / "config/contracts/schemas").glob("extension-*.json"))
    contract = gate.get("runtime_contract")
    if (
        not isinstance(contract, dict)
        or registry.get("registry_id") != contract.get("schema_registry_id")
        or registry.get("registry_digest") != contract.get("schema_registry_digest")
        or not isinstance(resources, list)
        or len(resources) != 76
        or len(schema_paths) != 76
    ):
        raise ValueError("WP-08A schema registry identity or cardinality mismatch")
    schema_records: list[dict[str, object]] = []
    resource_by_id = {
        item.get("schema_id"): item for item in resources if isinstance(item, dict)
    }
    if len(resource_by_id) != 76:
        raise ValueError("WP-08A schema registry is not closed")
    for path in schema_paths:
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("WP-08A extension schema cannot be parsed") from error
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        resource = resource_by_id.get(schema_id)
        raw = digest(path.read_bytes())
        if not isinstance(resource, dict) or resource.get("body_digest") != f"sha256-raw-v1:{raw}":
            raise ValueError("WP-08A schema registry body digest mismatch")
        schema_records.append({
            "path": path.relative_to(root).as_posix(), "schema_id": schema_id,
            "sha256": raw, "size": path.stat().st_size,
        })
    activation = documents["config/extensions/extension-activation-policy-v1.json"]
    trace = documents["config/release-coverage/trace-matrix-v1.json"]
    oracle = documents["config/release-coverage/oracle-manifest-v1.json"]
    if (
        set(contract) != {
            "schema_registry_id", "schema_registry_digest", "schema_count",
            "activation_policy_id", "activation_policy_digest", "trace_matrix_id",
            "oracle_manifest_id", "runtime_source_count", "configuration_count",
        }
        or contract["schema_count"] != len(schema_records)
        or contract["runtime_source_count"] != len(WP08A_RUNTIME_SOURCE_PATHS)
        or contract["configuration_count"] != len(WP08A_RUNTIME_CONFIG_PATHS)
        or activation.get("policy_id") != contract["activation_policy_id"]
        or activation.get("policy_digest") != contract["activation_policy_digest"]
        or trace.get("matrix_id") != contract["trace_matrix_id"]
        or oracle.get("manifest_id") != contract["oracle_manifest_id"]
    ):
        raise ValueError("WP-08A runtime contract mismatch")
    boundary = wp08a_external_action_boundary(gate)
    if (
        activation.get("allowed_data_categories") != boundary["allowed_extension_categories"]
        or activation.get("local_activation_status") != boundary["data_only_extension_status"]
        or activation.get("executable_status") != boundary["non_builtin_executable_status"]
        or activation.get("formal_release_status") != boundary["formal_release_status"]
        or oracle.get("trust_plane_network_counters") != {"dns": 0, "socket": 0, "proxy": 0}
    ):
        raise ValueError("WP-08A runtime boundary configuration mismatch")
    return {
        "kind": "offline-extension-trust-and-data-loader-v1",
        "inputs": records,
        "schemas": schema_records,
        "schema_registry_id": registry["registry_id"],
        "schema_registry_digest": registry["registry_digest"],
        "schema_count": len(schema_records),
        "activation_policy_id": activation["policy_id"],
        "activation_policy_digest": activation["policy_digest"],
        "trace_matrix_id": trace["matrix_id"],
        "oracle_manifest_id": oracle["manifest_id"],
        "runtime_source_count": len(WP08A_RUNTIME_SOURCE_PATHS),
        "configuration_count": len(WP08A_RUNTIME_CONFIG_PATHS),
        "external_action_boundary": boundary,
    }


def wp08a_runtime_dependencies(
    gate: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> dict[str, object]:
    """Bind candidate-only dependency declarations while preserving the WP-10 block."""

    boundary = gate.get("dependency_boundary")
    expected_keys = {
        "project_dependency_declarations", "declared_external_imports",
        "candidate_runtime_distributions", "uv_lock_mode", "network_mode", "fallback",
        "formal_release_status", "update_authority", "pyproject_sha256", "uv_lock_sha256",
    }
    if not isinstance(boundary, dict) or set(boundary) != expected_keys:
        raise ValueError("WP-08A dependency boundary is not exact")
    pyproject_path = root / "pyproject.toml"
    lock_path = root / "uv.lock"
    if (
        digest(pyproject_path.read_bytes()) != boundary["pyproject_sha256"]
        or digest(lock_path.read_bytes()) != boundary["uv_lock_sha256"]
    ):
        raise ValueError("WP-08A dependency declaration digest mismatch")
    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    if (
        project.get("project", {}).get("dependencies") != boundary["project_dependency_declarations"]
        or project.get("tool", {}).get("gew", {}).get("architecture", {}).get(
            "declared-external-imports"
        ) != boundary["declared_external_imports"]
    ):
        raise ValueError("WP-08A dependency declaration mismatch")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if (
        boundary["uv_lock_mode"] != "project-only-no-third-party-artifact-pins"
        or not isinstance(packages, list)
        or [item.get("name") for item in packages if isinstance(item, dict)]
        != ["graph-engineering-workflow"]
    ):
        raise ValueError("WP-08A WP-10 lock boundary mismatch")
    distributions = boundary["candidate_runtime_distributions"]
    if not isinstance(distributions, list) or len(distributions) != 2:
        raise ValueError("WP-08A candidate runtime dependency set is not exact")
    records: list[dict[str, object]] = []
    for item in distributions:
        if not isinstance(item, dict) or set(item) != {
            "distribution_name", "distribution_version", "import_prefix", "requirement_path",
        }:
            raise ValueError("WP-08A candidate runtime dependency is invalid")
        requirement_path = _project_relative_path(
            item["requirement_path"], "WP-08A dependency requirement path",
        )
        requirement = json.loads((root / requirement_path).read_text(encoding="utf-8"))
        if (
            requirement.get("distribution_name") != item["distribution_name"]
            or requirement.get("distribution_version") != item["distribution_version"]
            or requirement.get("import_prefix") != item["import_prefix"]
            or requirement.get("network_mode") != boundary["network_mode"]
            or requirement.get("fallback") != boundary["fallback"]
            or requirement.get("activation_status") != boundary["formal_release_status"]
            or requirement.get("update_authority") != boundary["update_authority"]
        ):
            raise ValueError("WP-08A dependency requirement boundary mismatch")
        try:
            distribution = importlib_metadata.distribution(str(item["distribution_name"]))
            version = distribution.version
            spec = importlib.util.find_spec(str(item["import_prefix"]))
        except importlib_metadata.PackageNotFoundError as error:
            raise ValueError("WP-08A candidate runtime dependency is unavailable") from error
        if version != item["distribution_version"] or spec is None or spec.origin is None:
            raise ValueError("WP-08A candidate runtime dependency identity mismatch")
        origin = pathlib.Path(spec.origin).resolve(strict=True)
        records.append({
            "distribution_name": item["distribution_name"],
            "distribution_version": version,
            "import_prefix": item["import_prefix"],
            "module_origin": str(origin),
            "module_origin_sha256": digest(origin.read_bytes()),
            "requirement_path": requirement_path.as_posix(),
            "requirement_sha256": digest((root / requirement_path).read_bytes()),
        })
    if (
        boundary["network_mode"] != "offline-only"
        or boundary["fallback"] != "disabled"
        or boundary["formal_release_status"] != "blocked-pending-wp10-release-install-manifest"
        or boundary["update_authority"]
        != "wp10-owner-authorized-supply-chain-install-manifest"
    ):
        raise ValueError("WP-08A dependency authority boundary mismatch")
    return {
        "declarations": boundary["project_dependency_declarations"],
        "declared_external_imports": boundary["declared_external_imports"],
        "candidate_runtime_distributions": records,
        "uv_lock_mode": boundary["uv_lock_mode"],
        "network_mode": boundary["network_mode"],
        "fallback": boundary["fallback"],
        "formal_release_status": boundary["formal_release_status"],
        "update_authority": boundary["update_authority"],
        "pyproject_sha256": boundary["pyproject_sha256"],
        "uv_lock_sha256": boundary["uv_lock_sha256"],
    }


def wp08a_source_records(
    gate: dict[str, object],
    source_manifest: dict[str, object],
    *,
    root: pathlib.Path = ROOT,
) -> list[dict[str, object]]:
    """Bind every and only new or changed file since the WP-07A r6 PASS tuple."""

    paths = gate.get("source_paths")
    files = source_manifest.get("files")
    predecessor_path = gate.get("predecessor_source_manifest_path")
    if (
        not isinstance(paths, list) or paths != sorted(paths) or len(paths) != len(set(paths))
        or not paths or not isinstance(files, list)
        or predecessor_path
        != ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07a-source-manifest-r6.json"
    ):
        raise ValueError("WP-08A source scope is not exact")
    predecessor = json.loads((root / str(predecessor_path)).read_text(encoding="utf-8"))
    old_files = predecessor.get("files")
    if not isinstance(old_files, list):
        raise ValueError("WP-08A predecessor source manifest is invalid")
    indexed = {
        record.get("path"): record for record in files
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    old = {
        record.get("path"): record for record in old_files
        if isinstance(record, dict) and isinstance(record.get("path"), str)
    }
    if len(indexed) != len(files) or len(old) != len(old_files):
        raise ValueError("WP-08A source manifest path set is ambiguous")
    expected = sorted(
        path for path, record in indexed.items()
        if path not in old or record.get("sha256") != old[path].get("sha256")
    )
    new_count = sum(path not in old for path in expected)
    changed_count = len(expected) - new_count
    if (
        paths != expected
        or gate.get("newly_targeted_file_count") != new_count
        or gate.get("changed_targeted_file_count") != changed_count
        or gate.get("source_path_count") != len(expected)
    ):
        raise ValueError("WP-08A changed/new source targeting mismatch")
    selected = [indexed[path] for path in paths]
    if any(
        set(record) != {"path", "sha256", "size"}
        or not valid_digest(record.get("sha256"))
        or type(record.get("size")) is not int
        or record["size"] < 0
        for record in selected
    ):
        raise ValueError("WP-08A source record is invalid")
    return selected
