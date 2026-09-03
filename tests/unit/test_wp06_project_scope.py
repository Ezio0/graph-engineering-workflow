from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.project import (  # noqa: E402
    ProjectScope,
    ProjectScopeError,
    classify_scope_change,
)


def contracts() -> tuple[ClosedSchemaRegistry, ResourceProfile, CostSchedule]:
    root = ROOT / "config" / "contracts"
    names = ("project-scope-1.0.0.json", "project-scope-digest-input-1.0.0.json")
    bodies = {
        json.loads((root / "schemas" / name).read_text())["$id"]: (root / "schemas" / name).read_bytes()
        for name in names
    }
    profile = ResourceProfile.from_dict(json.loads((root / "resource-profile-v1.json").read_text()))
    schedule = CostSchedule.from_dict(json.loads((root / "cost-schedule-v1.json").read_text()))
    policy = SchemaProfilePolicy.from_dict(json.loads((root / "schema-profile-v1.json").read_text()))
    manifest = ClosedSchemaRegistry.create_manifest("urn:gew:schema-registry:project-scope:1.0.0", bodies)
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy), profile, schedule


SCHEMAS, PROFILE, SCHEDULE = contracts()


def digest(label: str) -> str:
    import hashlib

    return "sha256-jcs-v1:" + hashlib.sha256(label.encode()).hexdigest()


def scope_document() -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "scope_id": "scope-main",
        "version": 1,
        "mode": "create-or-attach",
        "repositories": [
            {
                "binding_id": "repo-existing", "mode": "attach_existing", "vcs": "git",
                "locator_ref": "locator-existing", "canonical_identity": "git-common-a-worktree-a",
                "planned_target_id": None, "realized_git_identity": "git-common-a-worktree-a",
                "allowed_path_boundary": "boundary-existing", "default_branch_ref": "branch-main",
                "command_refs": ["command-build", "command-test"],
            },
            {
                "binding_id": "repo-new", "mode": "create_new", "vcs": "git",
                "locator_ref": "locator-new", "canonical_identity": None,
                "planned_target_id": "planned-parent-name", "realized_git_identity": None,
                "allowed_path_boundary": "boundary-new", "default_branch_ref": "branch-main",
                "command_refs": ["command-test"],
            },
        ],
        "services": [
            {
                "binding_id": "service-api", "repository_id": "repo-existing",
                "component_refs": ["component-api"], "capability_refs": ["capability-build"],
                "dependency_refs": [], "target_state_contract_ref": "state-api-healthy",
            }
        ],
        "environments": [
            {
                "binding_id": "environment-local", "kind": "local",
                "adapter_locator_ref": "adapter-local", "canonical_identity": "environment-local-identity",
                "service_ids": ["service-api"], "sensitivity": "internal",
                "operation_classes": ["read", "test"], "target_state_validator_ref": "validator-local",
            }
        ],
        "target_bindings": [
            {
                "target_id": "target-api", "acceptance_id": "acceptance-api",
                "repository_ids": ["repo-existing"], "service_ids": ["service-api"],
                "environment_ids": ["environment-local"], "resource_ids": ["resource-api"],
                "required_final_state": "healthy", "verification_contract_ref": "verify-api",
            },
            {
                "target_id": "target-new", "acceptance_id": "acceptance-new",
                "repository_ids": ["repo-new"], "service_ids": [], "environment_ids": [],
                "resource_ids": ["resource-new"], "required_final_state": "initialized",
                "verification_contract_ref": "verify-new",
            },
        ],
        "discovery_digest": digest("discovery"),
        "metadata_revision": 1,
        "scope_digest": digest("placeholder"),
    }
    value["scope_digest"] = ProjectScope.digest_document(value)
    return value


def load(value: dict[str, object]) -> ProjectScope:
    return ProjectScope.from_dict(value, schema_registry=SCHEMAS, context=WorkContext(PROFILE, SCHEDULE))


class WP06ProjectScopeTests(unittest.TestCase):
    def test_gew_lif_001_canonical_multi_target_scope_loads(self) -> None:
        scope = load(scope_document())
        self.assertEqual(tuple(scope.repositories), ("repo-existing", "repo-new"))
        self.assertEqual(tuple(scope.target_bindings), ("target-api", "target-new"))

    def test_gew_lif_002_non_git_duplicates_and_unknown_refs_fail_closed(self) -> None:
        mutations = []
        non_git = scope_document()
        non_git["repositories"][0]["vcs"] = "svn"  # type: ignore[index]
        mutations.append(non_git)
        duplicate = scope_document()
        duplicate["repositories"][1]["realized_git_identity"] = "git-common-a-worktree-a"  # type: ignore[index]
        mutations.append(duplicate)
        unknown = scope_document()
        unknown["target_bindings"][0]["service_ids"] = ["service-unknown"]  # type: ignore[index]
        mutations.append(unknown)
        for value in mutations:
            value["scope_digest"] = ProjectScope.digest_document(value)
            with self.subTest(value=value):
                with self.assertRaises(ProjectScopeError):
                    load(value)

    def test_gew_lif_003_equivalent_locator_realization_is_metadata_only(self) -> None:
        current_document = scope_document()
        candidate_document = copy.deepcopy(current_document)
        candidate_document["metadata_revision"] = 2
        candidate_document["repositories"][0]["locator_ref"] = "locator-equivalent"  # type: ignore[index]
        candidate_document["repositories"][1]["realized_git_identity"] = "git-common-new-worktree-new"  # type: ignore[index]
        candidate_document["environments"][0]["adapter_locator_ref"] = "adapter-equivalent"  # type: ignore[index]
        self.assertEqual(ProjectScope.digest_document(candidate_document), current_document["scope_digest"])
        candidate_document["scope_digest"] = current_document["scope_digest"]
        change = classify_scope_change(load(current_document), load(candidate_document))
        self.assertEqual(change.change_class, "metadata-only")
        self.assertFalse(change.requires_reapproval)

    def test_gew_lif_004_semantic_change_requires_reapproval_and_minimal_invalidation(self) -> None:
        current_document = scope_document()
        candidate_document = copy.deepcopy(current_document)
        candidate_document["version"] = 2
        candidate_document["target_bindings"][0]["required_final_state"] = "ready"  # type: ignore[index]
        candidate_document["scope_digest"] = ProjectScope.digest_document(candidate_document)
        change = classify_scope_change(load(current_document), load(candidate_document))
        self.assertEqual(change.change_class, "semantic")
        self.assertEqual(change.invalidated_target_ids, ("target-api",))
        self.assertTrue(change.requires_reapproval)

    def test_gew_lif_005_added_binding_requires_authority_expansion(self) -> None:
        current_document = scope_document()
        candidate_document = copy.deepcopy(current_document)
        candidate_document["version"] = 2
        candidate_document["target_bindings"].append({  # type: ignore[union-attr]
            "target_id": "target-third", "acceptance_id": "acceptance-third",
            "repository_ids": ["repo-existing"], "service_ids": [], "environment_ids": [],
            "resource_ids": ["resource-third"], "required_final_state": "present",
            "verification_contract_ref": "verify-third",
        })
        candidate_document["scope_digest"] = ProjectScope.digest_document(candidate_document)
        change = classify_scope_change(load(current_document), load(candidate_document))
        self.assertEqual(change.change_class, "authority-expansion")
        self.assertTrue(change.requires_authority_expansion)

    def test_gew_lif_006_realized_git_identity_mismatch_fails_closed(self) -> None:
        value = scope_document()
        value["repositories"][1]["realized_git_identity"] = "git-common-new-worktree-new"  # type: ignore[index]
        value["metadata_revision"] = 2
        value["scope_digest"] = ProjectScope.digest_document(value)
        scope = load(value)
        scope.require_realization("repo-new", "git-common-new-worktree-new")
        with self.assertRaises(ProjectScopeError):
            scope.require_realization("repo-new", "git-common-other-worktree-other")

    def test_gew_lif_007_loaded_scope_is_recursively_immutable(self) -> None:
        value = scope_document()
        scope = load(value)
        value["target_bindings"][0]["required_final_state"] = "mutated"  # type: ignore[index]
        self.assertEqual(scope.target_bindings["target-api"].required_final_state, "healthy")
        with self.assertRaises(TypeError):
            scope.services["service-api"]["repository_id"] = "other"  # type: ignore[index]

    def test_gew_lif_008_source_projection_and_digest_mutations_fail(self) -> None:
        for mutation in ("extra", "digest", "order"):
            value = scope_document()
            if mutation == "extra":
                value["unknown"] = True
            elif mutation == "digest":
                value["scope_digest"] = digest("wrong")
            else:
                value["repositories"].reverse()  # type: ignore[union-attr]
                value["scope_digest"] = ProjectScope.digest_document(value)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ProjectScopeError):
                    load(value)


if __name__ == "__main__":
    unittest.main()
