"""WP-08A live-session offline install ingress and durable ingest ledger."""

from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest

from graph_engineering.application.extensions import ExtensionInstallationApplication
from graph_engineering.application.runtime import RuntimeSession
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.extension_bundle import (
    ExtensionAttestationProductionPolicy,
    ExtensionInstallRequest,
)
from tests.integration.test_wp07_runtime_parity import (
    FIXTURE,
    adapter_document,
    compatibility,
    production_adapter_for_test,
    raw_input,
    resign_configuration,
    session as runtime_session,
)
from tests.support.wp03_repository import ROOT, repository_stack
from tests.support.runtime import runtime_context
from tests.support.wp08a_extension_bundle import (
    DIGEST,
    bundle_with_invalid_publisher_signature,
    trust_policy_chain,
    valid_bundle,
)
from tests.support.wp08a_trust import authorize_operations, operations_for_candidate


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


def _authorization(expected_head_digest: str) -> dict[str, object]:
    return {
        "transaction_id": "transaction.extension.install.policy",
        "expected_head_digest": expected_head_digest,
        "owner_identity": "owner-fixture",
        "owner_decision_digest": DIGEST,
        "owner_authority_digest": DIGEST,
        "ordered_operations_digest": DIGEST,
        "created_at": "2026-08-20T00:00:00Z",
    }


def _extension_session() -> RuntimeSession:
    cell = FIXTURE["cells"][0]
    document = copy.deepcopy(adapter_document(cell))
    document["capabilities"] = sorted([*document["capabilities"], "extension.install"])
    resign_configuration(document)
    return RuntimeSession.establish(
        production_adapter_for_test(cell, document), raw_input(cell), compatibility(cell)
    )


class ExtensionInstallTests(unittest.TestCase):
    def test_gew_ext_009_live_owner_session_is_the_only_install_mutation_ingress(self) -> None:
        from graph_engineering.adapters.extension_crypto import PycaEd25519CandidateVerifier
        from graph_engineering.storage.extension_bundle import ExtensionBundleReader
        from graph_engineering.storage.extension_install import ExtensionBundleInstaller
        from graph_engineering.storage.extensions import ExtensionTrustRepository

        bundle, metadata = valid_bundle()
        with tempfile.TemporaryDirectory(prefix="gew-extension-ingest-") as directory, repository_stack() as (
            _root, factory, _locks, _objects, _tasks, _leases,
        ):
            path = pathlib.Path(directory).resolve(strict=True) / "extension.gewx"
            path.write_bytes(bundle)
            installation_id = factory._test_installation_scope.context.installation_id
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            genesis, candidate = trust_policy_chain(installation_id)
            repository = ExtensionTrustRepository.initialize(
                manager,
                genesis,
                policy_document=json.loads(
                    (ROOT / "config/extensions/extension-storage-policy-v1.json").read_text()
                ),
                bootstrap_terminal_record_digest=DIGEST,
            )
            verifier = PycaEd25519CandidateVerifier.from_requirement(
                json.loads(
                    (ROOT / "config/supply-chain/extension-crypto-provider-requirement-v1.json").read_text()
                )
            )
            initial = repository.current()
            operations = operations_for_candidate(initial.policy, candidate)
            current = repository._commit_operations_issued(
                operations,
                authorization=authorize_operations(
                    _authorization(initial.head.head_digest), operations,
                ),
                runtime=runtime_context(
                    "owner-fixture", "test-runtime", "test-lineage", "test-actor",
                    "2026-08-20T00:00:00Z", 1,
                ),
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
                verifier=verifier,
            )
            installer = ExtensionBundleInstaller.create(
                repository,
                ExtensionBundleReader.from_dict(
                    json.loads(
                        (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
                    )
                ),
                verifier,
            )
            application = ExtensionInstallationApplication(installer)
            active = _extension_session()
            request = ExtensionInstallRequest.from_dict(
                _complete(
                    {
                        "schema_version": "1.0.0", "ingest_id": "ingest.example.1",
                        "installation_id": installation_id, "owner_id": active.proof.owner_id,
                        "runtime_kind": active.capabilities.runtime_kind,
                        "runtime_lineage_id": active.proof.lineage_id,
                        "bundle_path": str(path), "expected_bundle_raw_digest": raw_digest(bundle),
                        "expected_trust_head_digest": current.head.head_digest,
                        "expected_trust_policy_digest": current.policy.policy_digest,
                        "owner_decision_digest": DIGEST, "owner_authority_digest": DIGEST,
                        "requested_at": "2026-08-20T00:02:00Z",
                    },
                    "extension-install-request",
                    "request_digest",
                )
            )
            receipt = application.install(
                active, active.proof, request,
                occurred_at="2026-08-20T00:02:00Z", lease_ttl_ns=1,
            )
            self.assertEqual(receipt.ingest_id, "ingest.example.1")
            self.assertEqual(len(installer._test_records()), 1)

            invalid_bundle = bundle_with_invalid_publisher_signature()
            path.write_bytes(invalid_bundle)
            invalid_body = request.to_dict()
            invalid_body.update(
                ingest_id="ingest.example.invalid-signature",
                expected_bundle_raw_digest=raw_digest(invalid_bundle),
            )
            invalid_body.pop("request_digest")
            invalid_request = ExtensionInstallRequest.from_dict(
                _complete(
                    invalid_body, "extension-install-request", "request_digest"
                )
            )
            with self.assertRaisesRegex(ValueError, "SIGNATURE"):
                application.install(
                    active, active.proof, invalid_request,
                    occurred_at="2026-08-20T00:02:30Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(installer._test_records()), 1)

            expired_proof = active.proof
            active.close()
            with self.assertRaisesRegex(Exception, "missing|expired"):
                application.install(
                    active, expired_proof, request,
                    occurred_at="2026-08-20T00:03:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(installer._test_records()), 1)

            substituted = request.to_dict()
            substituted["runtime_lineage_id"] = "lineage.foreign"
            substituted.pop("request_digest")
            foreign = ExtensionInstallRequest.from_dict(
                _complete(substituted, "extension-install-request", "request_digest")
            )
            other = _extension_session()
            with self.assertRaisesRegex(ValueError, "unavailable"):
                application.install(
                    other, other.proof, foreign,
                    occurred_at="2026-08-20T00:03:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(installer._test_records()), 1)
            other.close()

            no_capability = runtime_session(FIXTURE["cells"][0])
            with self.assertRaisesRegex(ValueError, "unavailable"):
                application.install(
                    no_capability, no_capability.proof, request,
                    occurred_at="2026-08-20T00:04:00Z", lease_ttl_ns=1,
                )
            self.assertEqual(len(installer._test_records()), 1)
            no_capability.close()


if __name__ == "__main__":
    unittest.main()
