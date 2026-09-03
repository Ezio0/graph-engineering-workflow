from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from graph_engineering.adapters.action_adapters import ActionAdapterFactory
from graph_engineering.adapters.git_native import (
    GitAdapterConfiguration,
    GitAdapterRejection,
    GitIdentityObservation,
    GitRefMutationPlan,
    GitTargetPlan,
)
from graph_engineering.core.action_adapters import (
    ActionAdapterRegistry,
    ActionInvocation,
    ActionReceipt,
    ConcreteActionPolicy,
)
from tests.contract.test_wp07a_action_contracts import digest, invocation_document
from tests.support.wp07a_actions import installed_action_adapter_attestation


ROOT = pathlib.Path(__file__).resolve().parents[2]


def adapter_factory(configuration_document: dict[str, object] | None = None) -> ActionAdapterFactory:
    registry = ActionAdapterRegistry.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
    ))
    policy = ConcreteActionPolicy.from_dict(
        json.loads((ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()),
        registry=registry,
    )
    pins = {} if configuration_document is None else {
        "git-adapter-configuration": configuration_document["configuration_digest"],
    }
    return ActionAdapterFactory(
        policy,
        registry,
        installation_attestation=installed_action_adapter_attestation(),
        configuration_digests=pins,
    )  # type: ignore[arg-type]


def configuration(executable: pathlib.Path) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "configuration_id": "git-native-test",
        "adapter_id": "git-native-v1",
        "executable": os.fspath(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "max_output_bytes": 65536,
        "timeout_seconds": 10,
    }
    body["configuration_digest"] = GitAdapterConfiguration.digest_document(body)
    return body


def target_plan(root: pathlib.Path, relative_path: str = "project") -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "plan_id": "git-plan-wp07a",
        "target_id": "target-project",
        "target_digest": digest("target"),
        "allowed_root": os.fspath(root),
        "relative_path": relative_path,
    }
    body["plan_digest"] = GitTargetPlan.digest_document(body)
    return body


def raw_git(executable: pathlib.Path, repository: pathlib.Path, *args: str) -> str:
    completed = subprocess.run(
        (os.fspath(executable), "-C", os.fspath(repository), *args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=True,
        timeout=10,
    )
    return completed.stdout.decode("utf-8").strip()


def mutation_plan(
    target: GitTargetPlan,
    invocation: ActionInvocation,
    *,
    ref_name: str,
    expected_old_oid: str,
    new_oid: str,
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "plan_id": "git-mutation-plan-wp07a",
        "target_plan_id": target.plan_id,
        "target_plan_digest": target.plan_digest,
        "task_id": invocation.task_id,
        "action_id": invocation.action_id,
        "prepared_action_digest": invocation.prepared_action_digest,
        "authority_digest": invocation.authority_digest,
        "invocation_id": invocation.invocation_id,
        "invocation_digest": invocation.invocation_digest,
        "target_id": invocation.target_id,
        "target_digest": invocation.target_digest,
        "resources": list(invocation.resources),
        "lease_id": invocation.lease_id,
        "fencing_tokens": [dict(item) for item in invocation.fencing_tokens],
        "idempotency_key": invocation.idempotency_key,
        "ref_name": ref_name,
        "expected_old_oid": expected_old_oid,
        "new_oid": new_oid,
    }
    body["plan_digest"] = GitRefMutationPlan.digest_document(body)
    return body


def git_invocation(payload: dict[str, object]) -> tuple[dict[str, object], ActionInvocation]:
    body = invocation_document()
    body["payload_digest"] = ActionInvocation.payload_digest_for(payload)
    body["invocation_digest"] = ActionInvocation.digest_document(body)
    return body, ActionInvocation.from_dict(body)


def mutation_payload(
    target: GitTargetPlan,
    *,
    ref_name: str,
    expected_old_oid: str,
    new_oid: str,
) -> dict[str, object]:
    return {
        "target_plan_id": target.plan_id,
        "target_plan_digest": target.plan_digest,
        "ref_name": ref_name,
        "expected_old_oid": expected_old_oid,
        "new_oid": new_oid,
    }


class WP07AGitReadOnlyTests(unittest.TestCase):
    def test_gew_act_005_read_only_git_identity_matches_independent_raw_git_oracle(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-git-") as directory:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=True,
                timeout=10,
            )
            config = configuration(executable)
            adapter = adapter_factory(config).issue_git_native(config)
            plan = GitTargetPlan.from_dict(target_plan(root))
            observation = adapter.observe(target_plan(root), expected=plan)
            self.assertIsInstance(observation, GitIdentityObservation)
            observation.require_plan(plan)
            self.assertEqual(
                pathlib.Path(observation.worktree_path),
                pathlib.Path(raw_git(executable, repository, "rev-parse", "--show-toplevel")),
            )
            common = raw_git(executable, repository, "rev-parse", "--git-common-dir")
            common_path = pathlib.Path(common)
            if not common_path.is_absolute():
                common_path = (repository / common_path).resolve()
            self.assertEqual(pathlib.Path(observation.common_dir_path), common_path)
            self.assertEqual(observation.head_ref, raw_git(
                executable, repository, "symbolic-ref", "--quiet", "HEAD",
            ))
            self.assertIsNone(observation.head_oid)
            self.assertTrue(observation.fresh)
            self.assertEqual(adapter.query_count, 1)

    def test_gew_act_005a_path_plan_and_observation_substitution_fail_closed(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-git-") as directory:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=True,
                timeout=10,
            )
            config = configuration(executable)
            adapter = adapter_factory(config).issue_git_native(config)
            expected = GitTargetPlan.from_dict(target_plan(root))
            for relative in ("../project", "/tmp/project", "project/../project"):
                with self.subTest(relative=relative), self.assertRaises(GitAdapterRejection):
                    adapter.observe(target_plan(root, relative), expected=expected)
            link = root / "linked"
            link.symlink_to(repository, target_is_directory=True)
            with self.assertRaises(GitAdapterRejection):
                adapter.observe(target_plan(root, "linked"), expected=expected)
            changed = copy.deepcopy(target_plan(root))
            changed["target_id"] = "target-other"
            changed["plan_digest"] = GitTargetPlan.digest_document(changed)
            with self.assertRaises(GitAdapterRejection):
                adapter.observe(changed, expected=expected)
            self.assertEqual(adapter.query_count, 0)

    def test_gew_act_007_native_update_ref_uses_exact_expected_old_and_full_authority_binding(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-git-") as directory:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            for message in ("first", "second"):
                subprocess.run(
                    (
                        os.fspath(executable), "-C", os.fspath(repository),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "--quiet", "--allow-empty", "-m", message,
                    ),
                    shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                if message == "first":
                    first_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            second_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            subprocess.run(
                (os.fspath(executable), "-C", os.fspath(repository), "reset", "--quiet", "--hard", first_oid),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            config = configuration(executable)
            adapter = adapter_factory(config).issue_git_native(config)
            target = GitTargetPlan.from_dict(target_plan(root))
            before = adapter.observe(target_plan(root), expected=target)
            invocation_document_value, invocation = git_invocation(mutation_payload(
                target,
                ref_name=before.head_ref,
                expected_old_oid=first_oid,
                new_oid=second_oid,
            ))
            plan_document = mutation_plan(
                target,
                invocation,
                ref_name=before.head_ref,
                expected_old_oid=first_oid,
                new_oid=second_oid,
            )
            receipt, after = adapter.update_ref(
                invocation_document_value,
                expected=invocation,
                target_plan_document=target_plan(root),
                expected_target=target,
                mutation_plan_document=plan_document,
                before=before,
            )
            self.assertIsInstance(receipt, ActionReceipt)
            receipt.require_invocation(invocation)
            self.assertEqual(receipt.result, "succeeded")
            self.assertIsInstance(after, GitIdentityObservation)
            self.assertEqual(after.head_oid, second_oid)
            self.assertEqual(raw_git(executable, repository, "rev-parse", before.head_ref), second_oid)
            self.assertEqual(adapter.mutation_count, 1)

            with self.assertRaises(GitAdapterRejection):
                adapter.update_ref(
                    invocation_document_value,
                    expected=invocation,
                    target_plan_document=target_plan(root),
                    expected_target=target,
                    mutation_plan_document=plan_document,
                    before=after,
                )
            self.assertEqual(raw_git(executable, repository, "rev-parse", before.head_ref), second_oid)
            self.assertEqual(adapter.mutation_count, 1)

    def test_gew_act_007a_forged_target_invocation_and_fences_reject_before_native_mutation(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-git-") as directory:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            config = configuration(executable)
            adapter = adapter_factory(config).issue_git_native(config)
            target = GitTargetPlan.from_dict(target_plan(root))
            before = adapter.observe(target_plan(root), expected=target)
            invocation_value, invocation = git_invocation(mutation_payload(
                target,
                ref_name=before.head_ref,
                expected_old_oid="0" * 40,
                new_oid="1" * 40,
            ))
            plan = mutation_plan(
                target,
                invocation,
                ref_name=before.head_ref,
                expected_old_oid="0" * 40,
                new_oid="1" * 40,
            )
            changed_invocation = copy.deepcopy(invocation_value)
            changed_invocation["fencing_tokens"] = list(reversed(changed_invocation["fencing_tokens"]))
            changed_invocation["invocation_digest"] = ActionInvocation.digest_document(changed_invocation)
            changed_target = target_plan(root)
            changed_target["target_id"] = "target-foreign"
            changed_target["plan_digest"] = GitTargetPlan.digest_document(changed_target)
            for invocation_candidate, target_candidate in (
                (changed_invocation, target_plan(root)),
                (invocation_value, changed_target),
            ):
                with self.assertRaises(GitAdapterRejection):
                    adapter.update_ref(
                        invocation_candidate,
                        expected=invocation,
                        target_plan_document=target_candidate,
                        expected_target=target,
                        mutation_plan_document=plan,
                        before=before,
                    )
            self.assertEqual(adapter.mutation_count, 0)


if __name__ == "__main__":
    unittest.main()
