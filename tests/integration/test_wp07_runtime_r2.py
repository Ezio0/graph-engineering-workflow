from __future__ import annotations

import pathlib
import sys
import threading
import unittest
import hashlib
import json
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.adapters.runtime_config import (  # noqa: E402
    ConfiguredRuntimeHandshake,
    RuntimeAdapterRejection,
)
from graph_engineering.adapters.runtime_locator import (  # noqa: E402
    ExecutableLocator,
    ExecutableLocatorError,
)
from graph_engineering.adapters.runtime_adapters import (  # noqa: E402
    RuntimeAdapterFactory,
    RuntimeInvocationPorts,
)
from graph_engineering.application.runtime import (  # noqa: E402
    RuntimeMutationGateway,
    RuntimeQueryGateway,
    RuntimeSession,
    RuntimeSessionError,
)
from graph_engineering.application.tasks import ApplicationError, TaskApplication  # noqa: E402
from graph_engineering.core.graph.state import TaskCommand  # noqa: E402
from graph_engineering.core.runtime import DeliveryPresentation  # noqa: E402
from graph_engineering.core.runtime import (  # noqa: E402
    AgentRequest,
    ReviewerIndependenceAttestation,
    ReviewerRequest,
    ToolRequest,
)
from tests.integration.test_wp07_runtime_parity import (  # noqa: E402
    DIGEST,
    FIXTURE,
    adapter_document,
    compatibility,
    executable,
    raw_input,
    resign_configuration,
    signed,
)
from tests.support.wp07_runtime_adapter import ConfiguredRuntimeAdapter  # noqa: E402
from tests.support.runtime_adapter_authority import reviewer_attestation  # noqa: E402
from tests.support.runtime_resources import runtime_resource_guard  # noqa: E402
from tests.support.runtime_distribution import running_distribution  # noqa: E402
from tests.integration.test_wp04_application import SCHEMAS, WORK  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


def production_adapter(cell):
    fixture = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
    ports = RuntimeInvocationPorts(
        lambda task_id, owner, lineage: {
            "task_id": task_id, "owner_id": owner.owner_id,
            "runtime_kind": lineage.runtime_kind,
            "runtime_lineage_id": lineage.lineage_id,
        },
        lambda request, owner, lineage, capabilities: reviewer_attestation(
            request, owner, lineage, capabilities,
            reviewer_id=f"reviewer:{cell['adapter_id']}",
            source_ref=f"reviewer-source:{cell['cell_id']}",
        ),
        lambda request, _owner, _lineage: fixture.invoke_agent(request),
        lambda request, independence, _owner, _lineage: fixture.invoke_reviewer(
            request, {"author_id": independence["author_id"]}
        ),
        lambda request, _owner, _lineage: fixture.invoke_tool(request),
        lambda request, _owner, _lineage: fixture.request_human(request),
        lambda presentation, _owner, lineage: presentation.receipt(tuple(
            f"delivery:{lineage.channel_kind}:{lineage.channel_ref}:{presentation.presentation_id}:{index}"
            for index, _segment in enumerate(presentation.segments, start=1)
        )),
    )
    factory = RuntimeAdapterFactory(runtime_resource_guard())
    return (
        factory.codex(adapter_document(cell), executable(), ports)
        if cell["runtime_kind"] == "codex"
        else factory.hermes(adapter_document(cell), executable(), ports)
    )


class WP07RuntimeR2Tests(unittest.TestCase):
    def test_gew_rt_033_arbitrary_duck_adapter_is_not_runtime_authority(self) -> None:
        cell = FIXTURE["cells"][0]
        arbitrary = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
        with self.assertRaisesRegex(RuntimeSessionError, "attested|factory"):
            RuntimeSession.establish(arbitrary, raw_input(cell), compatibility(cell))

    def test_gew_rt_034_duplicate_owner_alias_configuration_is_rejected(self) -> None:
        for cell in FIXTURE["cells"][1:]:
            document = adapter_document(cell)
            document["owner_bindings"] = {
                next(iter(cell["owner_bindings"])): "owner-fixture",
                "second-platform-user": "owner-fixture",
            }
            resign_configuration(document)
            with self.subTest(cell=cell["cell_id"]), self.assertRaisesRegex(
                RuntimeAdapterRejection, "one-to-one|alias|owner",
            ):
                ConfiguredRuntimeHandshake.from_dict(
                    document, executable(), runtime_resource_guard()
                )

    def test_gew_rt_035_lineage_binds_exact_platform_identity_source(self) -> None:
        for cell in FIXTURE["cells"]:
            handshake = ConfiguredRuntimeHandshake.from_dict(
                adapter_document(cell), executable(), runtime_resource_guard()
            )
            owner = handshake.resolve_owner(raw_input(cell))
            lineage = handshake.resolve_lineage(raw_input(cell))
            with self.subTest(cell=cell["cell_id"]):
                self.assertEqual(lineage.owner_id, owner.owner_id)
                self.assertEqual(lineage.identity_source_ref, owner.identity_source_ref)

    def test_gew_rt_036_interleaved_channel_sessions_never_cross_delivery(self) -> None:
        telegram, discord = FIXTURE["cells"][1:]
        receipts = []
        barrier = threading.Barrier(2)

        def deliver(cell):
            active = RuntimeSession.establish(
                production_adapter(cell), raw_input(cell), compatibility(cell)
            )
            body = {
                "schema_version": "1.0", "presentation_id": f"present:{cell['cell_id']}",
                "task_id": f"task:{cell['cell_id']}", "kind": "result",
                "segments": ["first", "second"], "content_digest": DIGEST,
            }
            presentation = DeliveryPresentation.from_dict(
                signed("delivery-presentation", "presentation_digest", body)
            )
            barrier.wait()
            receipts.append(active.present(presentation))

        threads = [
            threading.Thread(target=deliver, args=(cell,))
            for cell in (telegram, discord)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(receipts), 2)
        by_task = {receipt.task_id: receipt for receipt in receipts}
        self.assertTrue(all("telegram" in ref for ref in by_task["task:hermes-telegram"].delivery_refs))
        self.assertTrue(all("discord" in ref for ref in by_task["task:hermes-discord"].delivery_refs))

    def test_gew_rt_037_operation_capability_is_rechecked_before_adapter_call(self) -> None:
        cell = FIXTURE["cells"][0]
        document = adapter_document(cell)
        document["capabilities"] = [
            capability for capability in document["capabilities"] if capability != "tool.invoke"
        ]
        resign_configuration(document)
        calls = []
        fixture = ConfiguredRuntimeAdapter.from_dict(document, executable())
        ports = RuntimeInvocationPorts(
            lambda task_id, owner, lineage: {
                "task_id": task_id, "owner_id": owner.owner_id,
                "runtime_kind": lineage.runtime_kind,
                "runtime_lineage_id": lineage.lineage_id,
            },
            lambda request, owner, lineage, capabilities: reviewer_attestation(
                request, owner, lineage, capabilities,
                reviewer_id=f"reviewer:{cell['adapter_id']}", source_ref="reviewer-source:test",
            ),
            lambda request, _owner, _lineage: fixture.invoke_agent(request),
            lambda request, independence, _owner, _lineage: fixture.invoke_reviewer(
                request, {"author_id": independence["author_id"]}
            ),
            lambda request, _owner, _lineage: calls.append(request) or fixture.invoke_tool(request),
            lambda request, _owner, _lineage: fixture.request_human(request),
            lambda presentation, _owner, _lineage: presentation.receipt(("delivery:test",)),
        )
        active = RuntimeSession.establish(
            RuntimeAdapterFactory(runtime_resource_guard()).codex(
                document, executable(), ports
            ),
            raw_input(cell), compatibility(cell),
        )
        body = {
            "schema_version": "1.0", "request_id": "tool:no-capability",
            "task_id": "task:bound", "prepared_action_ref": "prepared:1",
            "prepared_action_digest": DIGEST,
        }
        request = ToolRequest.from_dict(signed("tool-request", "request_digest", body))
        with self.assertRaisesRegex(RuntimeSessionError, "capability|authorized"):
            active.invoke_tool(request)
        self.assertEqual(calls, [])

    def test_gew_rt_038_foreign_task_rejects_before_runtime_call(self) -> None:
        cell = FIXTURE["cells"][0]
        calls = []
        fixture = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
        ports = RuntimeInvocationPorts(
            lambda task_id, owner, lineage: None if task_id != "task:bound" else {
                "task_id": task_id, "owner_id": owner.owner_id,
                "runtime_kind": lineage.runtime_kind,
                "runtime_lineage_id": lineage.lineage_id,
            },
            lambda request, owner, lineage, capabilities: reviewer_attestation(
                request, owner, lineage, capabilities,
                reviewer_id=f"reviewer:{cell['adapter_id']}", source_ref="reviewer-source:test",
            ),
            lambda request, _owner, _lineage: calls.append(request) or fixture.invoke_agent(request),
            lambda request, independence, _owner, _lineage: fixture.invoke_reviewer(
                request, {"author_id": independence["author_id"]}
            ),
            lambda request, _owner, _lineage: fixture.invoke_tool(request),
            lambda request, _owner, _lineage: fixture.request_human(request),
            lambda presentation, _owner, _lineage: presentation.receipt(("delivery:test",)),
        )
        active = RuntimeSession.establish(
            RuntimeAdapterFactory(runtime_resource_guard()).codex(
                adapter_document(cell), executable(), ports
            ),
            raw_input(cell), compatibility(cell),
        )
        body = {
            "schema_version": "1.0", "request_id": "agent:foreign",
            "task_id": "task:foreign", "run_id": "run:1", "node_id": "node:1",
            "input_ref": "input:1", "input_digest": DIGEST,
        }
        request = AgentRequest.from_dict(signed("agent-request", "request_digest", body))
        with self.assertRaisesRegex(RuntimeSessionError, "authorized|task"):
            active.invoke_agent(request)
        self.assertEqual(calls, [])

    def test_gew_rt_039_independence_attestation_rejects_before_reviewer_call(self) -> None:
        for cell in FIXTURE["cells"]:
            calls = []
            fixture = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
            ports = RuntimeInvocationPorts(
                lambda task_id, owner, lineage: {
                    "task_id": task_id, "owner_id": owner.owner_id,
                    "runtime_kind": lineage.runtime_kind,
                    "runtime_lineage_id": lineage.lineage_id,
                },
                lambda request, owner, lineage, capabilities: reviewer_attestation(
                    request, owner, lineage, capabilities,
                    reviewer_id=request.author_id, source_ref="reviewer-source:substituted",
                ),
                lambda request, _owner, _lineage: fixture.invoke_agent(request),
                lambda request, independence, _owner, _lineage: calls.append(request) or fixture.invoke_reviewer(
                    request, {"author_id": independence["author_id"]}
                ),
                lambda request, _owner, _lineage: fixture.invoke_tool(request),
                lambda request, _owner, _lineage: fixture.request_human(request),
                lambda presentation, _owner, _lineage: presentation.receipt(("delivery:test",)),
            )
            adapter = (
                RuntimeAdapterFactory(runtime_resource_guard()).codex(
                    adapter_document(cell), executable(), ports
                )
                if cell["runtime_kind"] == "codex"
                else RuntimeAdapterFactory(runtime_resource_guard()).hermes(
                    adapter_document(cell), executable(), ports
                )
            )
            active = RuntimeSession.establish(adapter, raw_input(cell), compatibility(cell))
            body = {
                "schema_version": "1.0", "request_id": f"review:{cell['cell_id']}",
                "task_id": "task:bound", "run_id": "run:1",
                "candidate_ref": "candidate:1", "candidate_digest": DIGEST,
                "author_id": "author:1",
            }
            request = ReviewerRequest.from_dict(signed("reviewer-request", "request_digest", body))
            with self.subTest(cell=cell["cell_id"]), self.assertRaisesRegex(
                RuntimeSessionError, "independence|reviewer",
            ):
                active.invoke_reviewer(request, None)
            self.assertEqual(calls, [])

    def test_gew_rt_044_independence_attestation_cannot_cross_reviewer_request(self) -> None:
        mutations = {
            "request_id": "review:other",
            "task_id": "task:other",
            "run_id": "run:other",
            "candidate_ref": "candidate:other",
            "candidate_digest": "sha256-jcs-v1:" + "9" * 64,
        }
        for cell in FIXTURE["cells"]:
            for field, replacement in mutations.items():
                calls = []
                cached = []
                fixture = ConfiguredRuntimeAdapter.from_dict(
                    adapter_document(cell), executable(),
                )

                def attest(request, owner, lineage, capabilities):
                    if not cached:
                        cached.append(reviewer_attestation(
                            request, owner, lineage, capabilities,
                            reviewer_id=f"reviewer:{cell['adapter_id']}",
                            source_ref=f"reviewer-source:{cell['cell_id']}",
                        ))
                    return cached[0]

                ports = RuntimeInvocationPorts(
                    lambda task_id, owner, lineage: {
                        "task_id": task_id, "owner_id": owner.owner_id,
                        "runtime_kind": lineage.runtime_kind,
                        "runtime_lineage_id": lineage.lineage_id,
                    },
                    attest,
                    lambda request, _owner, _lineage: fixture.invoke_agent(request),
                    lambda request, independence, _owner, _lineage: calls.append(request) or fixture.invoke_reviewer(
                        request, {"author_id": independence["author_id"]}
                    ),
                    lambda request, _owner, _lineage: fixture.invoke_tool(request),
                    lambda request, _owner, _lineage: fixture.request_human(request),
                    lambda presentation, _owner, _lineage: presentation.receipt(("delivery:test",)),
                )
                factory = RuntimeAdapterFactory(runtime_resource_guard())
                adapter = (
                    factory.codex(adapter_document(cell), executable(), ports)
                    if cell["runtime_kind"] == "codex"
                    else factory.hermes(adapter_document(cell), executable(), ports)
                )
                active = RuntimeSession.establish(
                    adapter, raw_input(cell), compatibility(cell),
                )
                base = {
                    "schema_version": "1.0", "request_id": "review:base",
                    "task_id": "task:bound", "run_id": "run:base",
                    "candidate_ref": "candidate:base", "candidate_digest": DIGEST,
                    "author_id": "author:base",
                }
                first = ReviewerRequest.from_dict(
                    signed("reviewer-request", "request_digest", base)
                )
                active.invoke_reviewer(first, None)
                changed = {**base, field: replacement}
                second = ReviewerRequest.from_dict(
                    signed("reviewer-request", "request_digest", changed)
                )
                with self.subTest(cell=cell["cell_id"], field=field), self.assertRaisesRegex(
                    RuntimeSessionError, "independence|reviewer",
                ):
                    active.invoke_reviewer(second, None)
                self.assertEqual(calls, [first])

    def test_gew_rt_044a_resigned_independence_field_substitution_is_zero_call(self) -> None:
        replacements = {
            "request_id": "review:substituted",
            "task_id": "task:substituted",
            "run_id": "run:substituted",
            "candidate_ref": "candidate:substituted",
            "candidate_digest": "sha256-jcs-v1:" + "8" * 64,
            "request_digest": "sha256-jcs-v1:" + "7" * 64,
        }
        for cell in FIXTURE["cells"]:
            for field, replacement in replacements.items():
                calls = []
                fixture = ConfiguredRuntimeAdapter.from_dict(
                    adapter_document(cell), executable(),
                )

                def attest(request, owner, lineage, capabilities):
                    valid = reviewer_attestation(
                        request, owner, lineage, capabilities,
                        reviewer_id=f"reviewer:{cell['adapter_id']}",
                        source_ref=f"reviewer-source:{cell['cell_id']}",
                    ).to_dict()
                    valid[field] = replacement
                    body = {
                        key: value for key, value in valid.items()
                        if key != "attestation_digest"
                    }
                    return ReviewerIndependenceAttestation.from_dict({
                        **body,
                        "attestation_digest": runtime_record_digest(
                            "reviewer-independence-attestation", body,
                        ),
                    })

                ports = RuntimeInvocationPorts(
                    lambda task_id, owner, lineage: {
                        "task_id": task_id, "owner_id": owner.owner_id,
                        "runtime_kind": lineage.runtime_kind,
                        "runtime_lineage_id": lineage.lineage_id,
                    },
                    attest,
                    lambda request, _owner, _lineage: fixture.invoke_agent(request),
                    lambda request, independence, _owner, _lineage: calls.append(request) or fixture.invoke_reviewer(
                        request, {"author_id": independence["author_id"]}
                    ),
                    lambda request, _owner, _lineage: fixture.invoke_tool(request),
                    lambda request, _owner, _lineage: fixture.request_human(request),
                    lambda presentation, _owner, _lineage: presentation.receipt(("delivery:test",)),
                )
                factory = RuntimeAdapterFactory(runtime_resource_guard())
                adapter = (
                    factory.codex(adapter_document(cell), executable(), ports)
                    if cell["runtime_kind"] == "codex"
                    else factory.hermes(adapter_document(cell), executable(), ports)
                )
                active = RuntimeSession.establish(
                    adapter, raw_input(cell), compatibility(cell),
                )
                body = {
                    "schema_version": "1.0", "request_id": "review:exact",
                    "task_id": "task:bound", "run_id": "run:exact",
                    "candidate_ref": "candidate:exact", "candidate_digest": DIGEST,
                    "author_id": "author:exact",
                }
                request = ReviewerRequest.from_dict(
                    signed("reviewer-request", "request_digest", body)
                )
                with self.subTest(cell=cell["cell_id"], field=field), self.assertRaisesRegex(
                    RuntimeSessionError, "independence|reviewer",
                ):
                    active.invoke_reviewer(request, None)
                self.assertEqual(calls, [])

    def test_gew_rt_040_runtime_query_facade_seals_raw_show_search_and_list(self) -> None:
        cell = FIXTURE["cells"][0]
        active = RuntimeSession.establish(
            production_adapter(cell), raw_input(cell), compatibility(cell)
        )
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=SCHEMAS, context=WORK
            )
            identity = {
                "task_id": "task:owned", "owner_id": active.proof.owner_id,
                "runtime_kind": cell["runtime_kind"],
                "runtime_lineage_id": active.proof.lineage_id,
            }
            RuntimeMutationGateway.create(
                active, active.proof, identity,
                lambda runtime: application.execute(
                    "task:owned", TaskCommand("create", 0, {"identity": identity}), runtime,
                ),
                occurred_at="2026-08-15T00:00:00Z", lease_ttl_ns=10,
            )
            for raw_call in (
                lambda: application.show("task:owned"),
                lambda: application.search({}),
                application.list,
            ):
                with self.assertRaisesRegex(ApplicationError, "runtime query|authority"):
                    raw_call()
            view = RuntimeQueryGateway.show(active, active.proof, application, "task:owned")
            self.assertEqual(
                {key: view.snapshot.identity[key] for key in identity}, identity
            )
            listed = RuntimeQueryGateway.list(active, active.proof, application)
            self.assertEqual(tuple(row["task_id"] for row in listed), ("task:owned",))
            messages = []
            for task_id in ("task:missing", "task:foreign"):
                try:
                    RuntimeQueryGateway.show(active, active.proof, application, task_id)
                except RuntimeSessionError as error:
                    messages.append(str(error))
            self.assertEqual(messages, ["runtime query is not authorized"] * 2)

    def test_gew_rt_041_runtime_resource_policy_rejects_before_port_call(self) -> None:
        cell = FIXTURE["cells"][0]
        calls = []
        fixture = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
        ports = RuntimeInvocationPorts(
            lambda task_id, owner, lineage: {
                "task_id": task_id, "owner_id": owner.owner_id,
                "runtime_kind": lineage.runtime_kind,
                "runtime_lineage_id": lineage.lineage_id,
            },
            lambda request, owner, lineage, capabilities: reviewer_attestation(
                request, owner, lineage, capabilities,
                reviewer_id=f"reviewer:{cell['adapter_id']}", source_ref="reviewer-source:test",
            ),
            lambda request, _owner, _lineage: calls.append(request) or fixture.invoke_agent(request),
            lambda request, independence, _owner, _lineage: fixture.invoke_reviewer(
                request, {"author_id": independence["author_id"]}
            ),
            lambda request, _owner, _lineage: fixture.invoke_tool(request),
            lambda request, _owner, _lineage: fixture.request_human(request),
            lambda presentation, _owner, _lineage: calls.append(presentation) or presentation.receipt(("delivery:test",)),
        )
        active = RuntimeSession.establish(
            RuntimeAdapterFactory(runtime_resource_guard()).codex(
                adapter_document(cell), executable(), ports
            ), raw_input(cell), compatibility(cell),
        )
        body = {
            "schema_version": "1.0", "request_id": "agent:overbound",
            "task_id": "task:bound", "run_id": "run:1", "node_id": "node:1",
            "input_ref": "x" * 70000, "input_digest": DIGEST,
        }
        oversized = AgentRequest.from_dict(signed("agent-request", "request_digest", body))
        with self.assertRaisesRegex(Exception, "resource|bound|limit"):
            active.invoke_agent(oversized)
        presentation_body = {
            "schema_version": "1.0", "presentation_id": "present:overbound",
            "task_id": "task:bound", "kind": "result",
            "segments": [f"segment:{index}" for index in range(1025)],
            "content_digest": DIGEST,
        }
        presentation = DeliveryPresentation.from_dict(
            signed("delivery-presentation", "presentation_digest", presentation_body)
        )
        with self.assertRaisesRegex(Exception, "resource|bound|limit"):
            active.present(presentation)
        with self.assertRaisesRegex(Exception, "resource|bound|limit"):
            runtime_resource_guard(max_depth=2).validate(
                {"outer": {"inner": {"value": 1}}}, source_id="runtime-nested-input"
            )
        self.assertEqual(calls, [])
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            candidate = root / "graph-engineering"
            candidate.write_bytes(b"#!/bin/sh\nexit 0\n")
            candidate.chmod(0o700)
            origin = root
            locator = root / "locator.json"
            locator.write_text(json.dumps({
                "schema_version": "1.0", "executable": str(candidate.resolve()),
                "package_origin": str(origin.resolve()),
                "executable_digest": "sha256-raw-v1:" + hashlib.sha256(candidate.read_bytes()).hexdigest(),
                "release_manifest_digest": DIGEST, "expected_core_version": "0.1.0",
                "distribution_name": "graph-engineering-workflow",
                "distribution_version": "0.1.0",
                "distribution_origin": str(origin.resolve()),
            }))
            locator.chmod(0o600)
            with self.assertRaisesRegex(ExecutableLocatorError, "size policy"):
                ExecutableLocator(
                    runtime_resource_guard(max_executable_bytes=4),
                    running_distribution(
                        str(candidate.resolve()), str(origin.resolve()), str(origin.resolve())
                    ),
                ).resolve(locator.resolve())


if __name__ == "__main__":
    unittest.main()
