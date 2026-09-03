from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock

from graph_engineering.adapters.action_adapters import ActionAdapterFactory, ActionAdapterRejection
from graph_engineering.adapters.command_native import (
    CommandExecutionRequest,
    CommandExecutionResult,
    CommandRegistry,
    CommandRuntimePolicy,
    SecretProviderPorts,
    SecretProviderRegistry,
    StructuredCommandRejection,
)
from graph_engineering.core.action_adapters import ActionAdapterRegistry, ActionInvocation, ConcreteActionPolicy
from graph_engineering.core.security.privacy import SecretMaterial
from tests.contract.test_wp07a_action_contracts import digest, invocation_document
from tests.support.wp07a_actions import installed_action_adapter_attestation


ROOT = pathlib.Path(__file__).resolve().parents[2]
CHILD = ROOT / "tests" / "support" / "wp07a_command_child.py"
SECRET_VALUE = b"fixture-secret-alpha+/="


def adapter_factory(pins: dict[str, str] | None = None) -> ActionAdapterFactory:
    registry = ActionAdapterRegistry.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
    ))
    policy = ConcreteActionPolicy.from_dict(
        json.loads((ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()),
        registry=registry,
    )
    return ActionAdapterFactory(
        policy,
        registry,
        installation_attestation=installed_action_adapter_attestation(),
        configuration_digests=pins,
    )


def self_digest(kind: type[object], body: dict[str, object], field: str) -> dict[str, object]:
    body[field] = kind.digest_document(body)  # type: ignore[attr-defined]
    return body


def provider_registry() -> dict[str, object]:
    return self_digest(SecretProviderRegistry, {
        "schema_version": "1.0.0",
        "registry_id": "secret-provider-registry-test",
        "entries": [{
            "provider_id": "provider-fixture",
            "adapter_id": "secret-provider-v1",
            "implementation_ref": "port:fixture-secret-provider",
            "allowed_references": [{
                "schema_version": "1.0.0",
                "provider_id": "provider-fixture",
                "key_ref": "project-token",
                "version_ref": "version-one",
            }],
        }],
    }, "registry_digest")


def command_registry(root: pathlib.Path, *, cwd_relative: str = "work") -> dict[str, object]:
    executable = pathlib.Path(sys.executable).resolve()
    return self_digest(CommandRegistry, {
        "schema_version": "1.0.0",
        "registry_id": "command-registry-test",
        "entries": [{
            "command_id": "fixture-command",
            "adapter_id": "project-command-v1",
            "executable": os.fspath(executable),
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "allowed_root": os.fspath(root),
            "cwd_relative": cwd_relative,
            "argv_prefix": [os.fspath(CHILD)],
            "parameter_order": ["mode"],
            "parameter_values": {"mode": [
                "clean", "descendant-output", "descendant-timeout", "leak-base64", "leak-hex",
                "leak-json-escaped", "leak-raw", "leak-sha256", "leak-stderr", "leak-url",
                "malformed", "oversized", "sleep",
            ]},
            "static_environment": {"LANG": "C", "LC_ALL": "C"},
            "secret_environment": {"WP07A_TOKEN": {
                "schema_version": "1.0.0", "provider_id": "provider-fixture",
                "key_ref": "project-token", "version_ref": "version-one",
            }},
            "side_effect_class": "local-mutation",
            "idempotency_class": "idempotent",
        }],
    }, "registry_digest")


def runtime_policy() -> dict[str, object]:
    return self_digest(CommandRuntimePolicy, {
        "schema_version": "1.0.0",
        "policy_id": "command-runtime-policy-test",
        "launcher_mode": "structured-argv-shell-false",
        "max_parameters": 4,
        "max_parameter_bytes": 128,
        "max_output_bytes": 4096,
        "read_chunk_bytes": 256,
        "timeout_ms": 250,
        "poll_interval_ms": 10,
        "termination_grace_ms": 50,
        "termination_force_wait_ms": 250,
        "output_field_allowlist": ["secret_present", "summary"],
        "secret_encodings": ["base64", "hex", "json", "raw", "sha256", "url"],
    }, "policy_digest")


def request(mode: str) -> dict[str, object]:
    return self_digest(CommandExecutionRequest, {
        "schema_version": "1.0.0",
        "request_id": "command-request-wp07a",
        "command_id": "fixture-command",
        "parameters": {"mode": mode},
        "secret_references": [{
            "schema_version": "1.0.0", "provider_id": "provider-fixture",
            "key_ref": "project-token", "version_ref": "version-one",
        }],
    }, "request_digest")


def invocation_for(request_document: dict[str, object]) -> tuple[dict[str, object], ActionInvocation]:
    document = invocation_document()
    document.update({
        "adapter_id": "project-command-v1",
        "operation_id": "project.run",
        "idempotency_class": "idempotent",
        "payload_digest": ActionInvocation.payload_digest_for(request_document),
    })
    document["invocation_digest"] = ActionInvocation.digest_document(document)
    return document, ActionInvocation.from_dict(document)


class WP07ACommandRuntimeTests(unittest.TestCase):
    def _stack(
        self,
        root: pathlib.Path,
        calls: list[object],
        *,
        secret_value: bytes = SECRET_VALUE,
    ):
        provider_document = provider_registry()
        command_document = command_registry(root)
        runtime_document = runtime_policy()
        factory = adapter_factory({
            "secret-provider-registry": provider_document["registry_digest"],  # type: ignore[dict-item]
            "command-registry": command_document["registry_digest"],  # type: ignore[dict-item]
            "command-runtime-policy": runtime_document["policy_digest"],  # type: ignore[dict-item]
        })

        def resolve(reference: object) -> bytes:
            calls.append(reference)
            return secret_value

        provider = factory.issue_secret_provider(
            provider_document, SecretProviderPorts(resolve=resolve),
        )
        launcher = factory.issue_project_command(
            command_document, runtime_document, provider=provider,
        )
        return provider, launcher

    def test_gew_act_006_structured_launcher_resolves_secret_ephemerally_and_returns_redacted_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            calls: list[object] = []
            provider, launcher = self._stack(root, calls)
            request_document = request("clean")
            invocation, expected = invocation_for(request_document)
            result = launcher.execute(invocation, expected=expected, request_document=request_document)
            self.assertIsInstance(result, CommandExecutionResult)
            self.assertEqual(result.outcome, "succeeded")
            self.assertFalse(result.reconciliation_required)
            self.assertEqual(result.output, {"secret_present": True, "summary": "ok"})
            self.assertEqual(len(calls), 1)
            serialized = json.dumps(result.as_dict(), sort_keys=True)
            self.assertNotIn(SECRET_VALUE.decode(), serialized)
            self.assertNotIn(hashlib.sha256(SECRET_VALUE).hexdigest(), serialized)
            self.assertNotIn("_value", repr(provider))

    def test_gew_act_006a_reference_parameter_and_cwd_substitution_reject_before_resolution_or_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            calls: list[object] = []
            _, launcher = self._stack(root, calls)
            valid = request("clean")
            invocation, expected = invocation_for(valid)
            bad_requests = []
            for mutation in ("missing-ref", "extra-ref", "argv-injection", "env-injection"):
                changed = copy.deepcopy(valid)
                if mutation == "missing-ref":
                    changed["secret_references"] = []
                elif mutation == "extra-ref":
                    changed["secret_references"].append({  # type: ignore[union-attr]
                        "schema_version": "1.0.0", "provider_id": "provider-fixture",
                        "key_ref": "other-token", "version_ref": "version-one",
                    })
                elif mutation == "argv-injection":
                    changed["parameters"] = {"mode": "clean\u0000--foreign"}
                else:
                    changed["parameters"] = {"mode": "clean", "ENV": "secret"}
                changed["request_digest"] = CommandExecutionRequest.digest_document(changed)
                bad_requests.append(changed)
            for changed in bad_requests:
                changed_invocation, changed_expected = invocation_for(changed)
                with self.subTest(changed=changed), self.assertRaises(StructuredCommandRejection):
                    launcher.execute(
                        changed_invocation, expected=changed_expected, request_document=changed,
                    )
            escaped_provider_document = provider_registry()
            escaped_command_document = command_registry(root, cwd_relative="../work")
            escaped_runtime_document = runtime_policy()
            escaped = adapter_factory({
                "secret-provider-registry": escaped_provider_document["registry_digest"],  # type: ignore[dict-item]
                "command-registry": escaped_command_document["registry_digest"],  # type: ignore[dict-item]
                "command-runtime-policy": escaped_runtime_document["policy_digest"],  # type: ignore[dict-item]
            })
            provider = escaped.issue_secret_provider(
                escaped_provider_document, SecretProviderPorts(resolve=lambda reference: SECRET_VALUE),
            )
            with self.assertRaises(StructuredCommandRejection):
                escaped.issue_project_command(
                    escaped_command_document, escaped_runtime_document, provider=provider,
                )
            self.assertEqual(calls, [])
            self.assertEqual(launcher.launch_count, 0)

    def test_gew_act_006b_raw_and_encoded_secret_leaks_are_blocked_without_echo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            _, launcher = self._stack(root, [])
            for mode in ("leak-raw", "leak-base64", "leak-hex", "leak-url", "leak-stderr"):
                request_document = request(mode)
                invocation, expected = invocation_for(request_document)
                with self.subTest(mode=mode):
                    result = launcher.execute(
                        invocation, expected=expected, request_document=request_document,
                    )
                    self.assertEqual(result.outcome, "unknown")
                    self.assertEqual(result.failure_class, "secret-leakage")
                    self.assertTrue(result.reconciliation_required)
                    serialized = json.dumps(result.as_dict(), sort_keys=True)
                    self.assertNotIn(SECRET_VALUE.decode(), serialized)
                    self.assertNotIn(hashlib.sha256(SECRET_VALUE).hexdigest(), serialized)

    def test_gew_act_006c_timeout_cancel_oversize_and_malformed_have_bounded_safe_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            _, launcher = self._stack(root, [])
            expected_failures = {
                "sleep": "timeout", "oversized": "output-bound", "malformed": "malformed-output",
            }
            for mode, failure in expected_failures.items():
                request_document = request(mode)
                invocation, expected = invocation_for(request_document)
                result = launcher.execute(invocation, expected=expected, request_document=request_document)
                self.assertEqual(result.outcome, "unknown")
                self.assertEqual(result.failure_class, failure)
                self.assertTrue(result.reconciliation_required)
            request_document = request("clean")
            invocation, expected = invocation_for(request_document)
            cancelled = launcher.execute(
                invocation, expected=expected, request_document=request_document,
                cancelled=lambda: True,
            )
            self.assertEqual(cancelled.outcome, "cancelled")
            self.assertEqual(cancelled.failure_class, "cancelled-before-launch")
            self.assertFalse(cancelled.reconciliation_required)

    def test_gew_act_006g_timeout_and_output_bound_terminate_and_reap_the_full_process_group(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-process-group-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            calls: list[object] = []
            provider, launcher = self._stack(root, calls)
            for mode, expected in (
                ("descendant-timeout", "timeout"),
                ("descendant-output", "output-bound"),
            ):
                with self.subTest(mode=mode):
                    document = request(mode)
                    invocation_document, expected_invocation = invocation_for(document)
                    result = launcher.execute(
                        invocation_document,
                        expected=expected_invocation,
                        request_document=document,
                    )
                    self.assertEqual(result.failure_class, expected)
                    time.sleep(0.9)
                    self.assertFalse((root / "work" / "descendant-survived").exists())
            self.assertEqual(len(calls), 2)

    def test_gew_act_006d_re_signed_unpinned_provider_or_command_registry_is_zero_call(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            provider_document = provider_registry()
            command_document = command_registry(root)
            runtime_document = runtime_policy()
            factory = adapter_factory({
                "secret-provider-registry": provider_document["registry_digest"],  # type: ignore[dict-item]
                "command-registry": command_document["registry_digest"],  # type: ignore[dict-item]
                "command-runtime-policy": runtime_document["policy_digest"],  # type: ignore[dict-item]
            })
            calls: list[object] = []
            changed_provider = copy.deepcopy(provider_document)
            changed_provider["entries"][0]["allowed_references"][0]["key_ref"] = "foreign-token"  # type: ignore[index]
            changed_provider["registry_digest"] = SecretProviderRegistry.digest_document(changed_provider)
            with self.assertRaises(ActionAdapterRejection):
                factory.issue_secret_provider(
                    changed_provider,
                    SecretProviderPorts(resolve=lambda reference: calls.append(reference) or SECRET_VALUE),
                )
            provider = factory.issue_secret_provider(
                provider_document,
                SecretProviderPorts(resolve=lambda reference: calls.append(reference) or SECRET_VALUE),
            )
            changed_command = copy.deepcopy(command_document)
            changed_command["entries"][0]["cwd_relative"] = "foreign"  # type: ignore[index]
            changed_command["registry_digest"] = CommandRegistry.digest_document(changed_command)
            with self.assertRaises(ActionAdapterRejection):
                factory.issue_project_command(
                    changed_command,
                    runtime_document,
                    provider=provider,
                )
            self.assertEqual(calls, [])

    def test_gew_act_006e_semantic_escaped_and_derived_secret_outputs_are_blocked(self) -> None:
        special_values = (
            b'quote"value',
            b"slash\\value",
            b"line\nvalue",
            b"control\x01value",
            "unicode-雪".encode(),
        )
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-semantic-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            for secret_value in special_values:
                with self.subTest(secret_value=secret_value):
                    _, launcher = self._stack(root, [], secret_value=secret_value)
                    request_document = request("leak-raw")
                    invocation, expected = invocation_for(request_document)
                    result = launcher.execute(
                        invocation, expected=expected, request_document=request_document,
                    )
                    self.assertEqual((result.outcome, result.failure_class), (
                        "unknown", "secret-leakage",
                    ))
                    serialized = json.dumps(result.as_dict(), sort_keys=True, ensure_ascii=True)
                    self.assertNotIn(secret_value.decode(), serialized)
                    self.assertNotIn(hashlib.sha256(secret_value).hexdigest(), serialized)

            escaped_secret = b'json"slash\\line\ncontrol\x02'
            _, launcher = self._stack(root, [], secret_value=escaped_secret)
            for mode in (
                "leak-json-escaped", "leak-sha256", "leak-base64", "leak-hex", "leak-url",
            ):
                with self.subTest(mode=mode):
                    request_document = request(mode)
                    invocation, expected = invocation_for(request_document)
                    result = launcher.execute(
                        invocation, expected=expected, request_document=request_document,
                    )
                    self.assertEqual((result.outcome, result.failure_class), (
                        "unknown", "secret-leakage",
                    ))

    def test_gew_act_006f_secret_material_is_destroyed_on_every_post_resolution_path(self) -> None:
        original_destroy = SecretMaterial.destroy
        destroyed: list[SecretMaterial] = []

        def track_destroy(material: SecretMaterial) -> None:
            original_destroy(material)
            destroyed.append(material)

        with tempfile.TemporaryDirectory(prefix="gew-wp07a-command-destroy-") as directory:
            root = pathlib.Path(directory)
            (root / "work").mkdir()
            _, launcher = self._stack(root, [])
            with mock.patch.object(SecretMaterial, "destroy", track_destroy):
                for mode in ("clean", "leak-raw", "malformed", "sleep"):
                    request_document = request(mode)
                    invocation, expected = invocation_for(request_document)
                    launcher.execute(
                        invocation, expected=expected, request_document=request_document,
                    )
            self.assertEqual(len(destroyed), 4)
            for material in destroyed:
                self.assertEqual(material.reveal(), b"\x00" * len(SECRET_VALUE))


if __name__ == "__main__":
    unittest.main()
