from __future__ import annotations

import copy
import pathlib
import tempfile
import unittest

from graph_engineering.core.security.identity import (
    BindingMismatchError,
    SecurityBinding,
)
from graph_engineering.core.security.inputs import (
    CommandEnvelope,
    InputSafetyError,
    InputSafetyPolicy,
    PathResolver,
    PromptEnvelope,
)
from tests.support.wp05a_security import (
    binding_document,
    digest_value,
    input_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
    task_security_context,
)


class IdentityBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)

    def load(self, value: dict[str, object]) -> SecurityBinding:
        return task_security_context(
            self.context,
            self.schemas,
            self.runtime,
            binding=value,
        ).binding

    def test_binding_is_factory_only_digest_bound_and_current(self) -> None:
        value = binding_document()
        binding = self.load(value)
        self.assertEqual(binding.task_id, "task-wp05a")
        self.assertEqual(binding.runtime_kind, "codex")
        self.assertEqual(binding.target_digest("target-project"), value["targets"][0]["target_digest"])
        binding.require_current(self.load(copy.deepcopy(value)))
        with self.assertRaises(TypeError):
            SecurityBinding()
        with self.assertRaises(BindingMismatchError):
            SecurityBinding.from_dict(
                value,
                schema_registry=self.schemas,
                context=self.context,
                allowed_runtime_kinds=("codex", "hermes"),
            )

    def test_every_identity_scope_and_digest_mutation_fails_closed(self) -> None:
        source = binding_document()
        mutations: list[tuple[str, dict[str, object]]] = []
        for field, replacement in (
            ("task_id", "task-other"),
            ("owner_id", "owner-other"),
            ("runtime_kind", "other-runtime"),
            ("runtime_lineage_id", "lineage-other"),
            ("scope_digest", digest_value("other-scope")),
            ("snapshot_digest", digest_value("other-snapshot")),
        ):
            changed = copy.deepcopy(source)
            changed[field] = replacement
            mutations.append((field, changed))
        changed = copy.deepcopy(source)
        changed["baselines"]["intent"] = digest_value("other-baseline")
        mutations.append(("baseline", changed))
        changed = copy.deepcopy(source)
        changed["targets"][0]["canonical_identity"] = "project-other"
        mutations.append(("target-identity", changed))
        changed = copy.deepcopy(source)
        changed["targets"][0]["target_digest"] = digest_value("other-target")
        mutations.append(("target-digest", changed))
        expected = self.load(source)
        for name, value in mutations:
            value["binding_digest"] = SecurityBinding.digest_document(value)
            with self.subTest(name=name), self.assertRaises(BindingMismatchError):
                expected.require_current(self.load(value))

    def test_noncanonical_identity_duplicate_target_and_forged_digest_reject(self) -> None:
        cases: list[dict[str, object]] = []
        source = binding_document()
        changed = copy.deepcopy(source)
        changed["owner_id"] = " Owner-WP05A "
        cases.append(changed)
        changed = copy.deepcopy(source)
        changed["targets"].append(copy.deepcopy(changed["targets"][0]))
        cases.append(changed)
        changed = copy.deepcopy(source)
        changed["binding_digest"] = digest_value("forged")
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises((BindingMismatchError, ValueError)):
                self.load(value)


class InputSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)
        self.policy = InputSafetyPolicy.from_dict(
            input_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )

    def test_path_resolver_rejects_escape_absolute_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp05a-root-") as root_name:
            root = pathlib.Path(root_name)
            (root / "safe").mkdir()
            (root / "safe" / "file.txt").write_text("safe")
            with PathResolver.resolve(root, "safe/file.txt", policy=self.policy) as resolved:
                self.assertEqual(resolved.relative_path, "safe/file.txt")
                (root / "safe" / "file.txt").replace(root / "safe" / "old.txt")
                (root / "safe" / "file.txt").write_text("attacker replacement")
                self.assertEqual(resolved.read_bytes(), b"safe")
            for candidate in ("../escape", "/absolute", "safe/../../escape", "safe\x00name"):
                with self.subTest(candidate=candidate), self.assertRaises(InputSafetyError):
                    PathResolver.resolve(root, candidate, policy=self.policy)
            external = pathlib.Path(root_name).parent / "wp05a-external"
            external.mkdir(exist_ok=True)
            (root / "link").symlink_to(external, target_is_directory=True)
            with self.assertRaises(InputSafetyError):
                PathResolver.resolve(root, "link/file.txt", policy=self.policy, must_exist=False)

    def test_command_is_structured_argv_and_shell_fails_closed(self) -> None:
        command = CommandEnvelope.from_dict(
            {
                "schema_version": "1.0.0",
                "executable_ref": "tool-git",
                "argv": ["status", "--short"],
                "shell": False,
                "stdin_digest": None,
            },
            policy=self.policy,
        )
        self.assertEqual(command.argv, ("status", "--short"))
        for argv, shell in ((["status", "a\x00b"], False), (["status"], True), ("status", False)):
            with self.subTest(argv=argv, shell=shell), self.assertRaises(InputSafetyError):
                CommandEnvelope.from_dict(
                    {
                        "schema_version": "1.0.0",
                        "executable_ref": "tool-git",
                        "argv": argv,
                        "shell": shell,
                        "stdin_digest": None,
                    },
                    policy=self.policy,
                )

    def test_prompt_is_untrusted_data_and_cannot_supply_control_fields(self) -> None:
        prompt = PromptEnvelope.from_dict({
            "schema_version": "1.0.0",
            "content_ref": "object-prompt",
            "content_digest": digest_value("prompt"),
            "trust": "untrusted",
            "instructions_allowed": False,
        })
        self.assertFalse(prompt.instructions_allowed)
        changed = {
            "schema_version": "1.0.0",
            "content_ref": "object-prompt",
            "content_digest": digest_value("prompt"),
            "trust": "untrusted",
            "instructions_allowed": True,
        }
        with self.assertRaises(InputSafetyError):
            PromptEnvelope.from_dict(changed)


if __name__ == "__main__":
    unittest.main()
