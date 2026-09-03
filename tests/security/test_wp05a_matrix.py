from __future__ import annotations

import copy
import pathlib
import tempfile
import unittest

from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import ResourceProfile
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.security.disclosure import (
    DataDisclosurePlan,
    DisclosurePolicy,
)
from graph_engineering.core.security.evidence import (
    EvidencePolicyRegistry,
    EvidenceRecord,
    EvidenceValidator,
)
from graph_engineering.core.security.extensions import ExtensionDescriptor, ExtensionGate
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.inputs import (
    CommandEnvelope,
    InputSafetyPolicy,
    PathBinding,
    PathResolver,
    PromptEnvelope,
)
from graph_engineering.core.security.privacy import (
    LeakageIncident,
    RedactionPolicy,
    Redactor,
    SecretMaterial,
    SecretReference,
)
from graph_engineering.core.security.retention import (
    RetentionDecision,
    RetentionEngine,
    RetentionPolicyRegistry,
)
from tests.support.wp05a_security import (
    ROOT,
    SECURITY_SCHEMA_NAMES,
    binding_document,
    digest_value,
    disclosure_plan_document,
    disclosure_policy_document,
    evidence_document,
    evidence_policy_document,
    input_policy_document,
    load_json,
    redaction_policy_document,
    retention_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
    task_security_context,
)


class WP05ASecurityPrivacyMatrixTests(unittest.TestCase):
    def _contracts(self) -> tuple[object, object]:
        context = security_context()
        return context, security_schema_registry(context)

    def _binding(self, value: dict[str, object]) -> SecurityBinding:
        context, schemas = self._contracts()
        runtime = security_runtime(context, schemas)
        return task_security_context(context, schemas, runtime, binding=value).binding

    def run_security_case(self, number: int) -> None:
        family, variant = divmod(number - 1, 10)
        if family == 0:
            value = binding_document()
            fields = ("task_id", "owner_id", "runtime_kind", "runtime_lineage_id", "scope_id")
            invalid = ("", " Upper", "UPPER", "ü", "a..b", "a/", "-a", "a b", "a" * 256, 1)
            value[fields[variant % len(fields)]] = invalid[variant]
            value["binding_digest"] = SecurityBinding.digest_document(value)
            with self.assertRaises(ValueError):
                self._binding(value)
            return
        if family == 1:
            original = self._binding(binding_document())
            value = binding_document()
            if variant == 0:
                value["task_id"] = "task-other"
            elif variant == 1:
                value["owner_id"] = "owner-other"
            elif variant == 2:
                value["runtime_kind"] = "hermes"
            elif variant == 3:
                value["runtime_lineage_id"] = "lineage-other"
            elif variant == 4:
                value["scope_id"] = "scope-other"
            elif variant == 5:
                value["scope_digest"] = digest_value("scope-other")
            elif variant == 6:
                value["snapshot_digest"] = digest_value("snapshot-other")
            elif variant == 7:
                value["baselines"]["intent"] = digest_value("intent-other")
            elif variant == 8:
                value["targets"][0]["target_digest"] = digest_value("target-other")
            else:
                value["targets"][0]["canonical_identity"] = "project-other"
            value["binding_digest"] = SecurityBinding.digest_document(value)
            with self.assertRaises(ValueError):
                original.require_current(self._binding(value))
            return
        if family == 2:
            value = binding_document()
            target = value["targets"][0]
            if variant == 0:
                value["targets"].append(copy.deepcopy(target))
            elif variant == 1:
                value["targets"].append({**copy.deepcopy(target), "target_id": "target-alpha"})
            elif variant == 2:
                target["target_id"] = "INVALID"
            elif variant == 3:
                target["target_kind"] = ""
            elif variant == 4:
                target["canonical_identity"] = " ../escape"
            elif variant == 5:
                target["target_digest"] = "bad"
            elif variant == 6:
                target["rogue"] = True
            elif variant == 7:
                del target["canonical_identity"]
            elif variant == 8:
                value["targets"] = []
            else:
                value["targets"] = "target-project"
            value["binding_digest"] = SecurityBinding.digest_document(value)
            with self.assertRaises(ValueError):
                self._binding(value)
            return
        if family == 3:
            value = binding_document()
            field = sorted(set(value) - {"binding_digest"})[variant]
            del value[field]
            with self.assertRaises(ValueError):
                self._binding(value)
            return
        if family == 4:
            candidates = (
                "../escape", "/absolute", "./safe", "safe/../escape", "", "safe\x00name",
                "missing", "safe/missing/child", ".", "..",
            )
            context, schemas = self._contracts()
            runtime = security_runtime(context, schemas)
            policy = InputSafetyPolicy.from_dict(input_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            with tempfile.TemporaryDirectory(prefix="gew-sec-path-") as name:
                root = pathlib.Path(name)
                (root / "safe").mkdir()
                (root / "safe" / "file").write_text("safe")
                with self.assertRaises(ValueError):
                    PathResolver.resolve(root, candidates[variant], policy=policy)
            return
        if family == 5:
            context, schemas = self._contracts()
            runtime = security_runtime(context, schemas)
            policy = InputSafetyPolicy.from_dict(input_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            with tempfile.TemporaryDirectory(prefix="gew-sec-link-") as name:
                root = pathlib.Path(name)
                external = root / f"actual-{variant}"
                external.mkdir()
                link = root / f"link-{variant}"
                link.symlink_to(external, target_is_directory=True)
                with self.assertRaises(ValueError):
                    PathResolver.resolve(root, f"link-{variant}/body", policy=policy, must_exist=False)
            return
        if family == 6:
            context, schemas = self._contracts()
            runtime = security_runtime(context, schemas)
            policy = InputSafetyPolicy.from_dict(input_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            value: dict[str, object] = {"schema_version": "1.0.0", "executable_ref": "tool-git", "argv": ["status"], "shell": False, "stdin_digest": None}
            if variant == 0:
                value["argv"] = []
            elif variant == 1:
                value["argv"] = "status"
            elif variant == 2:
                value["argv"] = [""]
            elif variant == 3:
                value["argv"] = [None]
            elif variant == 4:
                value["argv"] = ["bad\x00arg"]
            elif variant == 5:
                value["argv"] = ["x" * (policy.max_argument_chars + 1)]
            elif variant == 6:
                value["argv"] = ["x"] * (policy.max_arguments + 1)
            elif variant == 7:
                value["shell"] = True
            elif variant == 8:
                value["executable_ref"] = "../tool"
            else:
                value["stdin_digest"] = "bad"
            with self.assertRaises(ValueError):
                CommandEnvelope.from_dict(value, policy=policy)
            return
        if family == 7:
            value: dict[str, object] = {"schema_version": "1.0.0", "content_ref": "object-prompt", "content_digest": digest_value("prompt"), "trust": "untrusted", "instructions_allowed": False}
            if variant == 0:
                value["instructions_allowed"] = True
            elif variant == 1:
                value["trust"] = "validated"
            elif variant == 2:
                value["content_ref"] = "../prompt"
            elif variant == 3:
                value["content_digest"] = "bad"
            elif variant == 4:
                value["schema_version"] = "2.0.0"
            elif variant == 5:
                value["authority_digest"] = digest_value("authority")
            elif variant == 6:
                del value["content_ref"]
            elif variant == 7:
                value["instructions_allowed"] = 0
            elif variant == 8:
                value["trust"] = None
            else:
                value["content_ref"] = ""
            with self.assertRaises(ValueError):
                PromptEnvelope.from_dict(value)
            return
        if family == 8:
            approved_digest = digest_value("builtin-extension")
            value: dict[str, object] = {"schema_version": "1.0.0", "extension_id": "builtin-validator", "extension_version": "1.0.0", "extension_kind": "validator", "source_kind": "built-in", "executable": False, "capabilities": [], "side_effects": [], "package_digest": approved_digest}
            if variant == 0:
                value.update(source_kind="third-party", executable=True)
            elif variant == 1:
                value["implementation"] = lambda: True
            elif variant == 2:
                value["package_digest"] = digest_value("wrong")
            elif variant == 3:
                value["capabilities"] = ["filesystem-write"]
            elif variant == 4:
                value["side_effects"] = ["external-communication"]
            elif variant == 5:
                value["source_kind"] = "marketplace"
            elif variant == 6:
                value["capabilities"] = ["z", "a"]
            elif variant == 7:
                value["extension_id"] = "UNKNOWN"
            elif variant == 8:
                value["extension_version"] = ""
            else:
                value["executable"] = "false"
            with self.assertRaises(ValueError):
                ExtensionGate.validate(value, approved_builtins={"builtin-validator": approved_digest})
            return
        if family == 9:
            manifest = load_json(ROOT / "config" / "contracts" / "security-schema-registry-v1.json")
            bodies: dict[str, bytes] = {}
            for name in SECURITY_SCHEMA_NAMES:
                path = ROOT / "config" / "contracts" / "schemas" / name
                bodies[str(load_json(path)["$id"])] = path.read_bytes()
            if variant < len(SECURITY_SCHEMA_NAMES):
                schema_id = sorted(bodies)[variant]
                bodies[schema_id] += b" "
            with self.assertRaises(ValueError):
                ClosedSchemaRegistry.build(
                    manifest,
                    bodies,
                    ResourceProfile.from_dict(load_json(ROOT / "config" / "contracts" / "resource-profile-v1.json")),
                    SchemaProfilePolicy.from_dict(load_json(ROOT / "config" / "contracts" / "schema-profile-v1.json")),
                    security_context(),
                )
            return
        if family == 10:
            loaders = (
                (InputSafetyPolicy, input_policy_document),
                (RedactionPolicy, redaction_policy_document),
                (DisclosurePolicy, disclosure_policy_document),
                (EvidencePolicyRegistry, evidence_policy_document),
                (RetentionPolicyRegistry, retention_policy_document),
            )
            loader, factory = loaders[variant % 5]
            value = factory()
            if variant < 5:
                digest_field = "registry_digest" if "registry_digest" in value else "policy_digest"
                value[digest_field] = "sha256-jcs-v1:" + str(variant) * 64
            else:
                if "policies" in value:
                    value["policies"] = list(reversed(value["policies"]))
                elif "rules" in value:
                    value["rules"] = list(reversed(value["rules"]))
                else:
                    value["max_arguments" if "max_arguments" in value else "max_fields"] += 1
            context, schemas = self._contracts()
            runtime = security_runtime(context, schemas)
            with self.assertRaises(ValueError):
                loader.from_dict(value, schema_registry=schemas, context=context, runtime=runtime)
            return
        constructors = (
            SecurityBinding, InputSafetyPolicy, RedactionPolicy, DisclosurePolicy,
            EvidencePolicyRegistry, RetentionPolicyRegistry, PathBinding,
            CommandEnvelope, PromptEnvelope, ExtensionDescriptor,
        )
        with self.assertRaises(TypeError):
            constructors[variant]()

    def _redaction(self) -> tuple[object, object, RedactionPolicy]:
        context, schemas = self._contracts()
        runtime = security_runtime(context, schemas)
        policy = RedactionPolicy.from_dict(redaction_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
        return context, schemas, policy

    def run_privacy_case(self, number: int) -> None:
        family, variant = divmod(number - 1, 10)
        if family == 0:
            if variant == 0:
                with self.assertRaises(TypeError):
                    SecretReference()
                return
            value: dict[str, object] = {"schema_version": "1.0.0", "provider_id": "provider-local", "key_ref": "secret-token", "version_ref": "current"}
            actions = (
                ("provider_id", ""), ("provider_id", "UPPER"), ("key_ref", "../key"),
                ("version_ref", ""), ("schema_version", "2.0.0"), ("key_ref", 1),
                ("value", "secret"), ("provider_id", None), ("version_ref", " current"),
            )
            key, replacement = actions[variant - 1]
            value[key] = replacement
            with self.assertRaises(ValueError):
                SecretReference.from_dict(value)
            return
        if family == 1:
            context, _schemas, policy = self._redaction()
            reference = SecretReference.from_dict({"schema_version": "1.0.0", "provider_id": "provider-local", "key_ref": "secret-token", "version_ref": "current"})
            secret_text = f"fixture-secret-{variant}"
            secret = SecretMaterial.from_provider(secret_text.encode(), reference=reference)
            payload: dict[str, object]
            pointer: str
            if variant == 9:
                payload, pointer = {secret_text: "safe"}, f"/{secret_text}"
            else:
                variants: tuple[object, ...] = (
                    secret_text, f"prefix-{secret_text}", f"{secret_text}-suffix", [secret_text],
                    {"nested": secret_text}, f" {secret_text} ", f"x{secret_text}y",
                    f"{secret_text}{secret_text}", f"line\n{secret_text}",
                )
                payload, pointer = {"value": variants[variant]}, "/value"
            with self.assertRaises(ValueError):
                Redactor.redact(payload, field_allowlist=(pointer,), transforms={}, secret_materials=(secret,), policy=policy, context=context)
            return
        if family == 2:
            context, _schemas, policy = self._redaction()
            pointers = ("value", "/", "", "/missing", "/a/~2bad", "/a/", "/a//b", "/a", "/a/c", "/a/~")
            payload = {"value": "ok", "a": {"b": "ok"}}
            allowlist = (pointers[variant],)
            if variant == 7:
                allowlist = ("/a", "/a/b")
            with self.assertRaises(ValueError):
                Redactor.redact(payload, field_allowlist=allowlist, transforms={}, secret_materials=(), policy=policy, context=context)
            return
        if family == 3:
            context, _schemas, policy = self._redaction()
            payload = {"a": "ok", "b": "ok"}
            allowlist: tuple[str, ...] = ("/a",)
            transforms: object = {"/a": "mask"}
            if variant == 0:
                transforms = {"/a": "unknown"}
            elif variant == 1:
                transforms = {"/b": "mask"}
            elif variant == 2:
                transforms = {1: "mask"}
            elif variant == 3:
                transforms = {"/a": 1}
            elif variant == 4:
                transforms = []
            elif variant == 5:
                allowlist = ("/a", "/a")
            elif variant == 6:
                allowlist = ("/b", "/a")
            elif variant == 7:
                allowlist = ()
            elif variant == 8:
                allowlist = ["/a"]  # type: ignore[assignment]
            else:
                transforms = {"/a": "drop", "/b": "mask"}
            with self.assertRaises(ValueError):
                Redactor.redact(payload, field_allowlist=allowlist, transforms=transforms, secret_materials=(), policy=policy, context=context)  # type: ignore[arg-type]
            return
        context, schemas, redaction_policy = self._redaction()
        redacted = Redactor.redact(
            {"source": "private", "summary": "passed"},
            field_allowlist=("/source", "/summary"),
            transforms={"/source": "mask"},
            secret_materials=(),
            policy=redaction_policy,
            context=context,
        )
        if family in {4, 5}:
            runtime = security_runtime(context, schemas)
            task_context = task_security_context(context, schemas, runtime)
            policy = DisclosurePolicy.from_dict(disclosure_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            base = disclosure_plan_document(redacted.payload_digest, external=True)
            value = copy.deepcopy(base)
            if family == 4:
                mutations = (
                    ("destination", "kind", "unknown"), ("destination", "trust_boundary", "unknown"),
                    ("destination", "identity_ref", "INVALID"), (None, "purpose", "unknown"),
                    (None, "authority_digest", None), (None, "receipt_required", False),
                    (None, "retention_class", "../bad"), (None, "schema_version", "2.0.0"),
                    (None, "disclosure_id", ""), (None, "plan_digest", "bad"),
                )
            else:
                mutations = (
                    (None, "maximum_sensitivity", "secret"), ("data_refs", "sensitivity", "secret"),
                    ("data_refs", "digest", "bad"), (None, "payload_digest", digest_value("wrong")),
                    (None, "prepared_action_digest", digest_value("wrong-action")),
                    (None, "snapshot_digest", digest_value("wrong-snapshot")),
                    (None, "field_allowlist", ["/summary"]), (None, "redaction_transforms", []),
                    (None, "data_refs", []), (None, "plan_digest", "bad"),
                )
            parent, key, replacement = mutations[variant]
            if parent == "destination":
                value["destination"][key] = replacement
            elif parent == "data_refs":
                value["data_refs"][0][key] = replacement
            else:
                value[key] = replacement
            if key != "plan_digest":
                value["plan_digest"] = DataDisclosurePlan.digest_document(value)
            with self.assertRaises(ValueError):
                DataDisclosurePlan.from_dict(
                    value,
                    policy=policy,
                    runtime=runtime,
                    task_context=task_context,
                    redacted_payload=redacted,
                    schema_registry=schemas,
                    context=context,
                )
            return
        if family == 6:
            runtime = security_runtime(context, schemas)
            task_context = task_security_context(context, schemas, runtime)
            policy = EvidencePolicyRegistry.from_dict(evidence_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            base = evidence_document()
            value = copy.deepcopy(base)
            mutations = (
                ("task_id", "task-other"), ("evidence_type", "incident"), ("source_ref", "command-other"),
                ("collection_action_digest", digest_value("other-action")), ("baseline_digest", digest_value("other-baseline")),
                ("snapshot_digest", digest_value("other-snapshot")), ("target_refs", [{"target_id": "target-project", "target_digest": digest_value("other-target")}]),
                ("content_digest", digest_value("other-content")), ("fresh_until", "2026-08-14T02:00:00Z"),
                ("producer_id", "author-wp05a"),
            )
            key, replacement = mutations[variant]
            value[key] = replacement
            value["record_digest"] = EvidenceRecord.digest_document(value)
            with self.assertRaises(ValueError):
                EvidenceValidator.load(
                    value,
                    runtime=runtime, task_context=task_context,
                    policy_registry=policy, schema_registry=schemas, context=context,
                )
            return
        runtime = security_runtime(context, schemas)
        registry = RetentionPolicyRegistry.from_dict(retention_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
        if variant < 5:
            overrides: dict[str, object] = {"category": "evidence-body", "created_at": "2026-08-01T00:00:00Z"}
            trigger = "archive"
            if variant == 0:
                overrides["sensitivity"] = "secret"
            elif variant == 1:
                overrides["category"] = "unknown"
            elif variant == 2:
                overrides["created_at"] = "2026-09-01T00:00:00Z"
            elif variant == 3:
                trigger = "INVALID"
            else:
                overrides["extracted"] = 1
            with self.assertRaises(ValueError):
                RetentionEngine.evaluate(
                    runtime=runtime,
                    task_context=task_security_context(context, schemas, runtime, retention_overrides=overrides),
                    registry=registry,
                    subject_ref="object-tool-output",
                    trigger=trigger,
                )
            return
        if variant < 8:
            flag = ("legal_hold", "rollback_dependency", "unresolved_action")[variant - 5]
            decision = RetentionEngine.evaluate(
                runtime=runtime,
                task_context=task_security_context(
                    context, schemas, runtime,
                    current_time="2026-08-14T00:00:00Z",
                    retention_overrides={"category": "evidence-body", "created_at": "2026-08-01T00:00:00Z", flag: True},
                ),
                registry=registry, subject_ref="object-tool-output", trigger="archive",
            )
            self.assertEqual(decision.action, "blocked")
            return
        if variant == 8:
            record_value = evidence_document()
            policy = EvidencePolicyRegistry.from_dict(evidence_policy_document(), schema_registry=schemas, context=context, runtime=runtime)
            evidence_context = task_security_context(context, schemas, runtime)
            record = EvidenceValidator.load(
                record_value, runtime=runtime, task_context=evidence_context,
                policy_registry=policy, schema_registry=schemas, context=context,
            )
            incident = LeakageIncident.create(
                incident_id="incident-wrong", source_ref="object-evidence", suspect_digest=digest_value("wrong"),
                detector_ids=("known-secret",), occurred_at="2026-08-14T00:31:00Z",
            )
            with self.assertRaises(ValueError):
                EvidenceRecord.quarantine(record, incident, context=context)
            return
        with self.assertRaises(TypeError):
            RetentionDecision()


def _matrix_test(kind: str, number: int):
    def test(self: WP05ASecurityPrivacyMatrixTests) -> None:
        if kind == "sec":
            self.run_security_case(number)
        else:
            self.run_privacy_case(number)

    test.__name__ = f"test_gew_{kind}_{number:03d}"
    return test


for _number in range(1, 121):
    setattr(WP05ASecurityPrivacyMatrixTests, f"test_gew_sec_{_number:03d}", _matrix_test("sec", _number))
for _number in range(1, 81):
    setattr(WP05ASecurityPrivacyMatrixTests, f"test_gew_pri_{_number:03d}", _matrix_test("pri", _number))


if __name__ == "__main__":
    unittest.main()
