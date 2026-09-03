"""WP-07A disposable real-adapter exit fixture.

The E2E cells intentionally invoke the same real adapter/coordinator fixture
surfaces exercised by the lower-level suites.  They create fresh temporary
targets for every cell; no fake receipt or observation is accepted here.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
import warnings
import zipfile

from graph_engineering.adapters.action_adapters import builtin_implementation_digest
from graph_engineering.core.action_adapters import ActionAdapterRegistry

from tests.integration import test_wp07a_action_coordinator as coordinator_cells
from tests.integration import test_wp07a_command_runtime as command_cells
from tests.integration import test_wp07a_connector_unavailable as connector_cells
from tests.integration import test_wp07a_git_readonly as git_cells


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROVENANCE_RESOURCE = "graph_engineering/pyproject.toml"


class WP07ARealActionE2ETests(unittest.TestCase):
    def _run_real_cell(self, case_type: type[unittest.TestCase], method: str) -> None:
        result = unittest.TestResult()
        case_type(method).run(result)
        self.assertTrue(
            result.wasSuccessful(),
            f"real adapter cell failed: {result.failures!r} {result.errors!r}",
        )

    def test_gew_act_010_disposable_git_mutates_once_and_reconciles_with_raw_oracle(self) -> None:
        self._run_real_cell(
            coordinator_cells.WP07AConcreteActionCoordinatorTests,
            "test_gew_act_008_real_git_path_persists_typed_records_and_reconciles_before_completion",
        )

    def test_gew_act_010a_stale_expected_ref_is_zero_additional_mutation(self) -> None:
        self._run_real_cell(
            git_cells.WP07AGitReadOnlyTests,
            "test_gew_act_007_native_update_ref_uses_exact_expected_old_and_full_authority_binding",
        )

    def test_gew_act_010b_unavailable_connector_is_stable_and_never_calls_a_port(self) -> None:
        self._run_real_cell(
            connector_cells.WP07AUnavailableConnectorTests,
            "test_gew_act_009_unavailable_connector_returns_stable_self_digested_mismatch_without_port",
        )

    def test_gew_act_010c_secret_leak_timeout_and_malformed_output_remain_bounded(self) -> None:
        self._run_real_cell(
            command_cells.WP07ACommandRuntimeTests,
            "test_gew_act_006b_raw_and_encoded_secret_leaks_are_blocked_without_echo",
        )
        self._run_real_cell(
            command_cells.WP07ACommandRuntimeTests,
            "test_gew_act_006c_timeout_cancel_oversize_and_malformed_have_bounded_safe_results",
        )

    def test_gew_act_001c_clean_installed_wheel_resolves_exact_builtin_provenance(self) -> None:
        registry_document = json.loads(
            (ROOT / "config/contracts/action-adapter-registry-v1.json").read_text()
        )
        registry = ActionAdapterRegistry.from_dict(registry_document)
        expected = {
            entry.implementation_ref: builtin_implementation_digest(entry.implementation_ref)
            for entry in registry.entries
        }
        source_probe = subprocess.run(
            (
                sys.executable,
                "-I",
                "-X",
                "gew_installation_control_root="
                + os.environ["GEW_INSTALLATION_CONTROL_ROOT"],
                "-c",
                (
                    "import json,sys;sys.path[:0]=json.loads(sys.argv[1]);"
                    "from graph_engineering.adapters.action_adapters import "
                    "builtin_implementation_digest;"
                    "refs=json.loads(sys.argv[2]);"
                    "print(json.dumps({ref:builtin_implementation_digest(ref) "
                    "for ref in refs},sort_keys=True))"
                ),
                json.dumps([
                    os.fspath(ROOT / "adapters"),
                    os.fspath(ROOT / "application"),
                    os.fspath(ROOT / "core"),
                    os.fspath(ROOT / "storage"),
                    os.fspath(ROOT),
                ]),
                json.dumps(sorted(expected)),
            ),
            cwd=ROOT,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(source_probe.returncode, 0, source_probe.stderr)
        self.assertEqual(json.loads(source_probe.stdout), expected)
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-provenance-") as directory:
            temp = pathlib.Path(directory)
            dist = temp / "dist"
            dist.mkdir()
            built = subprocess.run(
                (sys.executable, os.fspath(ROOT / "scripts/build_wheel.py"), os.fspath(dist)),
                cwd=ROOT,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(archive.namelist().count(PROVENANCE_RESOURCE), 1)
                record_name = next(name for name in archive.namelist() if name.endswith(".dist-info/RECORD"))
                self.assertEqual(
                    archive.read(record_name).decode().count(f"{PROVENANCE_RESOURCE},"),
                    1,
                )
            installed = temp / "installed"
            installed.mkdir()
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(installed)
            probe = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import json,sys;sys.path.insert(0,sys.argv[1]);"
                        "from graph_engineering.adapters.action_adapters import builtin_implementation_digest;"
                        "refs=json.loads(sys.argv[2]);"
                        "print(json.dumps({ref:builtin_implementation_digest(ref) for ref in refs},sort_keys=True))"
                    ),
                    os.fspath(installed),
                    json.dumps(sorted(expected)),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(json.loads(probe.stdout), expected)

            configuration_root = temp / "configuration"
            shutil.copytree(ROOT / "config", configuration_root)
            factory_probe = temp / "factory-probe.py"
            factory_probe.write_text(textwrap.dedent("""
                import copy
                import hashlib
                import json
                import os
                import pathlib
                import platform
                import shutil
                import subprocess
                import sys

                installed = pathlib.Path(sys.argv[1]).resolve()
                configuration = pathlib.Path(sys.argv[2]).resolve()
                repository_root = pathlib.Path(sys.argv[3]).resolve()
                source_root = pathlib.Path(sys.argv[4]).resolve()
                if (installed / 'pyproject.toml').is_file():
                    sys.path[:0] = [
                        str(installed / responsibility)
                        for responsibility in ('adapters', 'application', 'core', 'storage')
                    ] + [str(installed)]
                else:
                    sys.path.insert(0, str(installed))

                from graph_engineering.adapters.action_adapters import (
                    ActionAdapterFactory,
                    ActionAdapterPorts,
                    ActionAdapterRejection,
                )
                from graph_engineering.adapters.command_native import (
                    CommandExecutionRequest,
                    CommandRegistry,
                    CommandRuntimePolicy,
                    SecretProviderPorts,
                    SecretProviderRegistry,
                )
                from graph_engineering.adapters.connector_unavailable import ConnectorUnavailable
                from graph_engineering.adapters.git_native import (
                    GitAdapterConfiguration,
                    GitTargetPlan,
                )
                from graph_engineering.core.action_adapters import ConnectorRegistry
                from graph_engineering.application.security import SecurityContextIssuer
                from graph_engineering.core.action_adapters import (
                    ActionAdapterRegistry,
                    ActionInvocation,
                    ConcreteActionPolicy,
                )
                from graph_engineering.core.actions import ActionPolicy
                from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
                from graph_engineering.core.contracts.resources import (
                    CostSchedule,
                    ResourceProfile,
                    WorkContext,
                )
                from graph_engineering.core.contracts.schema import SchemaProfilePolicy
                from graph_engineering.core.source_checkout import (
                    issue_source_checkout_attestation,
                )
                from graph_engineering.storage.codec import canonical_json
                from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor
                from graph_engineering.storage.locks import LockedFileRegistry
                from graph_engineering.storage.migration import InstallationMigrationRepository
                from graph_engineering.storage.objects import ObjectRepository
                from graph_engineering.storage.policy import RepositoryPolicy
                from graph_engineering.storage.security import SecurityStateRepository

                def load(relative):
                    return json.loads((configuration / relative).read_text())

                profile = ResourceProfile.from_dict(load('contracts/resource-profile-v1.json'))
                schedule = CostSchedule.from_dict(load('contracts/cost-schedule-v1.json'))
                context = WorkContext(profile, schedule)
                schema_manifest = load('contracts/security-schema-registry-v1.json')
                wanted = {item['schema_id'] for item in schema_manifest['resources']}
                bodies = {}
                for path in (configuration / 'contracts/schemas').glob('*.json'):
                    document = json.loads(path.read_text())
                    if document.get('$id') in wanted:
                        bodies[document['$id']] = path.read_bytes()
                schemas = ClosedSchemaRegistry.build(
                    schema_manifest,
                    bodies,
                    profile,
                    SchemaProfilePolicy.from_dict(load('contracts/schema-profile-v1.json')),
                    context,
                )
                system = platform.system()
                filesystem = 'apfs' if system == 'Darwin' else 'ext4'
                options = (filesystem, 'local', 'rw') if system == 'Darwin' else ('rw',)
                RepositoryDoctor._mount_observation = staticmethod(lambda root: {
                    'platform': system,
                    'mount_point': str(root),
                    'filesystem_type': filesystem,
                    'mount_options': options,
                    'filesystem_identity': f'installed-provenance:{system}:{filesystem}:{root}',
                })
                factory = ConnectionFactory.initialize(
                    repository_root,
                    RepositoryPolicy.from_dict(load('contracts/repository-policy-v1.json')),
                    'repository-installed-provenance-v1',
                )
                locks = LockedFileRegistry(factory)
                maintenance = factory._for_maintenance()
                objects = ObjectRepository(maintenance, locks)
                manager = InstallationMigrationRepository.initialize(
                    maintenance,
                    locks,
                    objects,
                    control_root=repository_root.parent / 'control',
                    policy_document=load('contracts/migration-storage-policy-v1.json'),
                )
                with manager.command_scope() as scope:
                    bound = factory.bind_command_scope(scope)
                    runtime = load('security/security-runtime-local-actions-v1.json')
                    runtime_registry = runtime['schema_registry']
                    with bound.open('application') as connection:
                        with connection.transaction():
                            connection.execute(
                                'INSERT INTO security_runtime_installation('
                                'singleton,manifest_json,manifest_id,manifest_digest,'
                                'schema_registry_id,schema_registry_digest) VALUES(1,?,?,?,?,?)',
                                (
                                    canonical_json(runtime),
                                    runtime['manifest_id'],
                                    runtime['manifest_digest'],
                                    runtime_registry['registry_id'],
                                    runtime_registry['registry_digest'],
                                ),
                            )
                    issuer = SecurityContextIssuer(
                        SecurityStateRepository(bound),
                        schema_registry=schemas,
                        context=context,
                    )
                    action_policy = ActionPolicy.from_dict(
                        load('actions/action-policy-local-actions-v1.json'),
                        schema_registry=schemas,
                        context=context,
                        runtime=issuer.runtime,
                    )
                    registry_document = load('contracts/action-adapter-registry-v1.json')
                    registry = ActionAdapterRegistry.from_dict(registry_document)
                    concrete_document = load('actions/concrete-action-policy-v1.json')
                    concrete = ConcreteActionPolicy.from_dict(
                        concrete_document,
                        registry=registry,
                    )
                    adapter_schemas = load('contracts/action-adapter-schema-registry-v1.json')
                    attestation = action_policy.issue_action_adapter_installation(
                        concrete_policy_id=concrete.policy_id,
                        concrete_policy_digest=concrete.policy_digest,
                        registry_id=registry.registry_id,
                        registry_digest=registry.registry_digest,
                        schema_registry_id=adapter_schemas['registry_id'],
                        schema_registry_digest=adapter_schemas['registry_digest'],
                        runtime=issuer.runtime,
                    )
                    executable = pathlib.Path(shutil.which('git')).resolve()
                    git_configuration = {
                        'schema_version': '1.0.0',
                        'configuration_id': 'git-installed-provenance',
                        'adapter_id': 'git-native-v1',
                        'executable': str(executable),
                        'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                        'max_output_bytes': 65536,
                        'timeout_seconds': 10,
                    }
                    git_configuration['configuration_digest'] = (
                        GitAdapterConfiguration.digest_document(git_configuration)
                    )
                    fixture_root = repository_root.parent / 'adapter-fixtures'
                    work = fixture_root / 'work'
                    work.mkdir(parents=True)
                    python_executable = pathlib.Path(sys.executable).resolve()
                    child = fixture_root / 'command-child.py'
                    child.write_text(
                        "import json,os;print(json.dumps({'secret_present':bool(os.environ.get('TOKEN')),'summary':'ok'},sort_keys=True))"
                    )
                    provider_registry = {
                        'schema_version': '1.0.0',
                        'registry_id': 'secret-provider-registry-installed',
                        'entries': [{
                            'provider_id': 'provider-installed',
                            'adapter_id': 'secret-provider-v1',
                            'implementation_ref': 'port:installed-secret-provider',
                            'allowed_references': [{
                                'schema_version': '1.0.0',
                                'provider_id': 'provider-installed',
                                'key_ref': 'project-token',
                                'version_ref': 'version-one',
                            }],
                        }],
                    }
                    provider_registry['registry_digest'] = SecretProviderRegistry.digest_document(
                        provider_registry
                    )
                    command_registry = {
                        'schema_version': '1.0.0',
                        'registry_id': 'command-registry-installed',
                        'entries': [{
                            'command_id': 'command-installed',
                            'adapter_id': 'project-command-v1',
                            'executable': str(python_executable),
                            'executable_sha256': hashlib.sha256(python_executable.read_bytes()).hexdigest(),
                            'allowed_root': str(fixture_root),
                            'cwd_relative': 'work',
                            'argv_prefix': [str(child)],
                            'parameter_order': ['mode'],
                            'parameter_values': {'mode': ['clean']},
                            'static_environment': {'LANG': 'C', 'LC_ALL': 'C'},
                            'secret_environment': {'TOKEN': {
                                'schema_version': '1.0.0',
                                'provider_id': 'provider-installed',
                                'key_ref': 'project-token',
                                'version_ref': 'version-one',
                            }},
                            'side_effect_class': 'local-mutation',
                            'idempotency_class': 'idempotent',
                        }],
                    }
                    command_registry['registry_digest'] = CommandRegistry.digest_document(
                        command_registry
                    )
                    runtime_policy = {
                        'schema_version': '1.0.0',
                        'policy_id': 'command-runtime-policy-installed',
                        'launcher_mode': 'structured-argv-shell-false',
                        'max_parameters': 4,
                        'max_parameter_bytes': 128,
                        'max_output_bytes': 4096,
                        'read_chunk_bytes': 256,
                        'timeout_ms': 1000,
                        'poll_interval_ms': 10,
                        'termination_grace_ms': 50,
                        'termination_force_wait_ms': 250,
                        'output_field_allowlist': ['secret_present', 'summary'],
                        'secret_encodings': ['base64', 'hex', 'json', 'raw', 'sha256', 'url'],
                    }
                    runtime_policy['policy_digest'] = CommandRuntimePolicy.digest_document(
                        runtime_policy
                    )
                    connector_registry = {
                        'schema_version': '1.0.0',
                        'registry_id': 'connector-registry-installed',
                        'entries': [{
                            'connector_id': 'connector-installed',
                            'adapter_id': 'connector-unavailable-v1',
                            'status': 'unavailable',
                            'declared_capabilities': ['remote-read'],
                            'reason_code': 'connector-not-installed',
                            'retryable': False,
                        }],
                    }
                    connector_registry['registry_digest'] = ConnectorRegistry.digest_document(
                        connector_registry
                    )
                    adapter_factory = ActionAdapterFactory(
                        concrete,
                        registry,
                        installation_attestation=attestation,
                        configuration_digests={
                            'git-adapter-configuration': git_configuration['configuration_digest'],
                            'secret-provider-registry': provider_registry['registry_digest'],
                            'command-registry': command_registry['registry_digest'],
                            'command-runtime-policy': runtime_policy['policy_digest'],
                            'connector-registry': connector_registry['registry_digest'],
                        },
                    )
                    query_calls = []
                    def invoke_query(invocation, payload):
                        query_calls.append((invocation.adapter_id, invocation.operation_id, payload))
                        return {
                            'result': 'succeeded',
                            'result_digest': invocation.payload_digest,
                        }
                    git_repository = fixture_root / 'git-project'
                    subprocess.run((str(executable), 'init', '--quiet', str(git_repository)), check=True)
                    subprocess.run((
                        str(executable), '-C', str(git_repository),
                        '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--quiet', '--allow-empty', '-m', 'installed provenance',
                    ), check=True)
                    git_target = {
                        'schema_version': '1.0.0',
                        'plan_id': 'git-target-installed',
                        'target_id': 'target-installed-provenance',
                        'target_digest': 'sha256-jcs-v1:' + '3' * 64,
                        'allowed_root': str(fixture_root),
                        'relative_path': 'git-project',
                    }
                    git_target['plan_digest'] = GitTargetPlan.digest_document(git_target)
                    git_expected = GitTargetPlan.from_dict(git_target)
                    git_adapter = adapter_factory.issue_git_native(git_configuration)
                    git_adapter.observe(git_target, expected=git_expected)

                    provider = adapter_factory.issue_secret_provider(
                        provider_registry,
                        SecretProviderPorts(resolve=lambda _reference: b'installed-secret'),
                    )
                    launcher = adapter_factory.issue_project_command(
                        command_registry,
                        runtime_policy,
                        provider=provider,
                    )
                    request = {
                        'schema_version': '1.0.0',
                        'request_id': 'command-request-installed',
                        'command_id': 'command-installed',
                        'parameters': {'mode': 'clean'},
                        'secret_references': [{
                            'schema_version': '1.0.0',
                            'provider_id': 'provider-installed',
                            'key_ref': 'project-token',
                            'version_ref': 'version-one',
                        }],
                    }
                    request['request_digest'] = CommandExecutionRequest.digest_document(request)
                    command_payload = dict(request)
                    command_invocation = {
                        'schema_version': '1.0.0',
                        'invocation_id': 'invocation-project-command-v1',
                        'task_id': 'task-installed-provenance',
                        'action_id': 'action-project-command-v1',
                        'prepared_action_digest': 'sha256-jcs-v1:' + '1' * 64,
                        'authority_digest': 'sha256-jcs-v1:' + '2' * 64,
                        'adapter_id': 'project-command-v1',
                        'operation_id': 'project.run',
                        'target_id': 'target-installed-provenance',
                        'target_digest': 'sha256-jcs-v1:' + '3' * 64,
                        'resources': ['target:installed-provenance', 'task:task-installed-provenance'],
                        'lease_id': 'lease-installed-provenance',
                        'fencing_tokens': [
                            {'resource_id': 'target:installed-provenance', 'token': 7},
                            {'resource_id': 'task:task-installed-provenance', 'token': 9},
                        ],
                        'idempotency_class': 'idempotent',
                        'idempotency_key': 'idempotency-project-command-v1',
                        'payload_digest': ActionInvocation.payload_digest_for(command_payload),
                        'disclosure_plan_digest': 'sha256-jcs-v1:' + '4' * 64,
                    }
                    command_invocation['invocation_digest'] = ActionInvocation.digest_document(
                        command_invocation
                    )
                    command_expected = ActionInvocation.from_dict(command_invocation)
                    command_result = launcher.execute(
                        command_invocation,
                        expected=command_expected,
                        request_document=request,
                    )

                    query_payload = {'operation': 'noop'}
                    query_invocation = dict(command_invocation)
                    query_invocation.update({
                        'invocation_id': 'invocation-target-query-v1',
                        'action_id': 'action-target-query-v1',
                        'adapter_id': 'target-query-v1',
                        'operation_id': 'target.observe',
                        'idempotency_key': 'idempotency-target-query-v1',
                        'payload_digest': ActionInvocation.payload_digest_for(query_payload),
                    })
                    query_invocation['invocation_digest'] = ActionInvocation.digest_document(
                        query_invocation
                    )
                    query_expected = ActionInvocation.from_dict(query_invocation)
                    query_adapter = adapter_factory.issue(
                        'target-query-v1',
                        ActionAdapterPorts(invoke=invoke_query),
                    )
                    query_adapter.dispatch(
                        query_invocation,
                        expected=query_expected,
                        payload=query_payload,
                    )

                    connector = adapter_factory.issue_unavailable_connector(
                        connector_registry,
                        'connector-installed',
                    )
                    connector_rejected = False
                    try:
                        connector.require_capability(
                            task_id='task-installed-provenance',
                            action_id='action-connector-unavailable-v1',
                            capability='remote-read',
                        )
                    except ConnectorUnavailable:
                        connector_rejected = True
                    issued = [
                        'git-native-v1', 'project-command-v1', 'target-query-v1',
                        'secret-provider-v1', 'connector-unavailable-v1',
                    ]
                    changed_registry = copy.deepcopy(registry_document)
                    changed_registry['entries'][0]['implementation_digest'] = (
                        'sha256-jcs-v1:' + '5' * 64
                    )
                    changed_registry['registry_digest'] = ActionAdapterRegistry.digest_document(
                        changed_registry
                    )
                    foreign_registry = ActionAdapterRegistry.from_dict(changed_registry)
                    changed_policy = copy.deepcopy(concrete_document)
                    changed_policy['registry_digest'] = foreign_registry.registry_digest
                    changed_policy['policy_digest'] = ConcreteActionPolicy.digest_document(
                        changed_policy
                    )
                    foreign_policy = ConcreteActionPolicy.from_dict(
                        changed_policy,
                        registry=foreign_registry,
                    )
                    rejected = False
                    try:
                        ActionAdapterFactory(
                            foreign_policy,
                            foreign_registry,
                            installation_attestation=attestation,
                        )
                    except ActionAdapterRejection:
                        rejected = True
                    result_payload = {
                        'issued': issued,
                        'git_queries': git_adapter.query_count,
                        'command_succeeded': command_result.outcome == 'succeeded',
                        'target_query_calls': len(query_calls),
                        'connector_rejected': connector_rejected,
                        'resign_rejected': rejected,
                    }
                source_attestation = issue_source_checkout_attestation(
                    source_root,
                    repository_root.parent / 'control',
                    authority=attestation,
                )
                result_payload['source_attested'] = source_attestation.is_file()
                print(json.dumps(result_payload, sort_keys=True))
                manager.close()
                objects.close()
                locks.close()
            """), encoding="utf-8")
            factory_result = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    os.fspath(factory_probe),
                    os.fspath(installed),
                    os.fspath(configuration_root),
                    os.fspath(temp / "repository"),
                    os.fspath(ROOT),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(factory_result.returncode, 0, factory_result.stderr)
            self.assertEqual(json.loads(factory_result.stdout), {
                "command_succeeded": True,
                "connector_rejected": True,
                "git_queries": 1,
                "issued": [
                    "git-native-v1",
                    "project-command-v1",
                    "target-query-v1",
                    "secret-provider-v1",
                    "connector-unavailable-v1",
                ],
                "resign_rejected": True,
                "source_attested": True,
                "target_query_calls": 1,
            })
            # The installed factory probe intentionally exercises the
            # production issuer.  Rebind the subsequent checkout probe with
            # the test authority's current exact protected-source closure so
            # this child validates the current checkout rather than the
            # smaller historical factory fixture projection.
            from tests.support.source_checkout_attestation import (
                issue_source_checkout_attestation as issue_test_source_attestation,
            )

            issue_test_source_attestation(ROOT, temp / "control")
            production_source_probe = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-X",
                    "gew_installation_control_root="
                    + os.fspath((temp / "control").resolve(strict=True)),
                    "-c",
                    (
                        "import json,sys;sys.path[:0]=json.loads(sys.argv[1]);"
                        "from graph_engineering.adapters.action_adapters import "
                        "builtin_implementation_digest;"
                        "refs=json.loads(sys.argv[2]);"
                        "print(json.dumps({ref:builtin_implementation_digest(ref) "
                        "for ref in refs},sort_keys=True))"
                    ),
                    json.dumps([
                        os.fspath(ROOT / "adapters"),
                        os.fspath(ROOT / "application"),
                        os.fspath(ROOT / "core"),
                        os.fspath(ROOT / "storage"),
                        os.fspath(ROOT),
                    ]),
                    json.dumps(sorted(expected)),
                ),
                cwd=temp,
                env={**os.environ, "GEW_INSTALLATION_CONTROL_ROOT": os.fspath(temp / "control")},
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                production_source_probe.returncode,
                0,
                production_source_probe.stderr,
            )
            self.assertEqual(json.loads(production_source_probe.stdout), expected)
            source_factory_root = temp / "source-factory"
            source_factory_root.mkdir()
            source_factory_result = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-X",
                    "gew_installation_control_root="
                    + os.environ["GEW_INSTALLATION_CONTROL_ROOT"],
                    os.fspath(factory_probe),
                    os.fspath(ROOT),
                    os.fspath(configuration_root),
                    os.fspath(source_factory_root / "repository"),
                    os.fspath(ROOT),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                source_factory_result.returncode,
                0,
                source_factory_result.stderr,
            )
            self.assertEqual(
                json.loads(source_factory_result.stdout)["issued"],
                [
                    "git-native-v1",
                    "project-command-v1",
                    "target-query-v1",
                    "secret-provider-v1",
                    "connector-unavailable-v1",
                ],
            )
            from graph_engineering.core.source_checkout import (
                SourceCheckoutAuthorityError,
                issue_source_checkout_attestation,
            )
            with self.assertRaises(SourceCheckoutAuthorityError):
                issue_source_checkout_attestation(
                    ROOT,
                    temp / "control",
                    authority={},  # type: ignore[arg-type]
                )
            zip_run = temp / "zip-run"
            zip_run.mkdir()
            zip_staging = zip_run / "staging"
            zip_staging.mkdir()
            zip_factory_result = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    os.fspath(factory_probe),
                    os.fspath(wheel),
                    os.fspath(configuration_root),
                    os.fspath(zip_run / "repository"),
                    os.fspath(ROOT),
                ),
                cwd=temp,
                env={**os.environ, "TMPDIR": os.fspath(zip_staging)},
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(zip_factory_result.returncode, 0, zip_factory_result.stderr)
            self.assertEqual(json.loads(zip_factory_result.stdout), {
                "command_succeeded": True,
                "connector_rejected": True,
                "git_queries": 1,
                "issued": [
                    "git-native-v1",
                    "project-command-v1",
                    "target-query-v1",
                    "secret-provider-v1",
                    "connector-unavailable-v1",
                ],
                "resign_rejected": True,
                "source_attested": True,
                "target_query_calls": 1,
            })
            self.assertEqual(list(zip_staging.glob("gew-validated-adapters-*")), [])
            zip_repeat_run = temp / "zip-repeat-run"
            zip_repeat_run.mkdir()
            zip_factory_repeat = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    os.fspath(factory_probe),
                    os.fspath(wheel),
                    os.fspath(configuration_root),
                    os.fspath(zip_repeat_run / "repository"),
                    os.fspath(ROOT),
                ),
                cwd=temp,
                env={**os.environ, "TMPDIR": os.fspath(zip_staging)},
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(zip_factory_repeat.returncode, 0, zip_factory_repeat.stderr)
            self.assertEqual(json.loads(zip_factory_repeat.stdout)["issued"], [
                "git-native-v1",
                "project-command-v1",
                "target-query-v1",
                "secret-provider-v1",
                "connector-unavailable-v1",
            ])
            self.assertEqual(list(zip_staging.glob("gew-validated-adapters-*")), [])
            for mutation, expected_error in (
                ("missing-resource", "pyproject.toml RECORD identity is unavailable"),
                ("missing-record", "__init__.py RECORD identity is unavailable"),
                ("missing-record-hash", "pyproject.toml RECORD hash is missing"),
                ("tampered-resource", "pyproject.toml RECORD hash changed"),
                ("tampered-record", "pyproject.toml RECORD hash changed"),
                ("duplicate-record", "pyproject.toml RECORD identity is not unique"),
                ("distribution-name", "distribution identity is unavailable"),
                ("distribution-version", "distribution binding changed"),
            ):
                with self.subTest(mutation=mutation):
                    attacked = temp / f"installed-{mutation}"
                    shutil.copytree(installed, attacked)
                    resource = attacked / PROVENANCE_RESOURCE
                    record = next(attacked.glob("*.dist-info/RECORD"))
                    metadata = next(attacked.glob("*.dist-info/METADATA"))
                    if mutation == "missing-resource":
                        resource.unlink()
                    elif mutation == "missing-record":
                        record.unlink()
                    elif mutation == "missing-record-hash":
                        lines = record.read_text().splitlines()
                        lines = [
                            f"{PROVENANCE_RESOURCE},,{resource.stat().st_size}"
                            if item.startswith(f"{PROVENANCE_RESOURCE},") else item
                            for item in lines
                        ]
                        record.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    elif mutation == "tampered-resource":
                        resource.write_bytes(resource.read_bytes() + b"\n")
                    elif mutation == "tampered-record":
                        lines = record.read_text().splitlines()
                        changed = []
                        for item in lines:
                            if item.startswith(f"{PROVENANCE_RESOURCE},"):
                                path, _digest, size = item.split(",")
                                item = f"{path},sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,{size}"
                            changed.append(item)
                        record.write_text("\n".join(changed) + "\n", encoding="utf-8")
                    elif mutation == "duplicate-record":
                        line = next(
                            item for item in record.read_text().splitlines()
                            if item.startswith(f"{PROVENANCE_RESOURCE},")
                        )
                        record.write_text(
                            record.read_text() + line + "\n",
                            encoding="utf-8",
                        )
                    elif mutation == "distribution-name":
                        metadata.write_text(
                            metadata.read_text().replace(
                                "Name: graph-engineering-workflow",
                                "Name: unrelated-distribution",
                            ),
                            encoding="utf-8",
                        )
                    else:
                        metadata.write_text(
                            metadata.read_text().replace(
                                "Version: 0.1.0",
                                "Version: 9.9.9",
                            ),
                            encoding="utf-8",
                        )
                    rejected = subprocess.run(
                        (
                            sys.executable,
                            "-I",
                            "-c",
                            (
                                "import sys;sys.path.insert(0,sys.argv[1]);"
                                "from graph_engineering.adapters.action_adapters import "
                                "builtin_implementation_digest;"
                                "builtin_implementation_digest('builtin:git-native-v1')"
                            ),
                            os.fspath(attacked),
                        ),
                        cwd=temp,
                        shell=False,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn(expected_error, rejected.stderr)

            metadata_absent = temp / "installed-metadata-absent"
            shutil.copytree(installed, metadata_absent)
            shutil.rmtree(next(metadata_absent.glob("*.dist-info")))
            missing_identity = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys;sys.path.insert(0,sys.argv[1]);"
                        "from graph_engineering.adapters.action_adapters import "
                        "builtin_implementation_digest;"
                        "builtin_implementation_digest('builtin:git-native-v1')"
                    ),
                    os.fspath(metadata_absent),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing_identity.returncode, 0)
            self.assertIn("distribution identity is unavailable", missing_identity.stderr)

            manufactured_source = temp / "manufactured-source"
            (manufactured_source / ".git").mkdir(parents=True)
            (manufactured_source / "scripts").mkdir()
            shutil.copy2(installed / PROVENANCE_RESOURCE, manufactured_source / "pyproject.toml")
            shutil.copytree(
                installed / "graph_engineering/adapters",
                manufactured_source / "adapters/graph_engineering/adapters",
            )
            shutil.copytree(
                installed / "graph_engineering/core",
                manufactured_source / "core/graph_engineering/core",
            )
            shutil.copy2(
                installed / "graph_engineering/__init__.py",
                manufactured_source / "core/graph_engineering/__init__.py",
            )
            def run_manufactured_source() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-c",
                        (
                            "import sys;sys.path[:0]=sys.argv[1:];"
                            "from graph_engineering.adapters.action_adapters import "
                            "builtin_implementation_digest;"
                            "builtin_implementation_digest('builtin:git-native-v1')"
                        ),
                        os.fspath(manufactured_source / "adapters"),
                        os.fspath(manufactured_source / "core"),
                    ),
                    cwd=temp,
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            copied_payload = run_manufactured_source()
            self.assertNotEqual(copied_payload.returncode, 0)
            self.assertIn("source checkout attestation", copied_payload.stderr)
            source_backend = manufactured_source / "scripts/build_backend.py"
            shutil.copy2(ROOT / "scripts/build_backend.py", source_backend)
            source_backend.write_bytes(source_backend.read_bytes() + b"\n")
            copied_payload = run_manufactured_source()
            self.assertNotEqual(copied_payload.returncode, 0)
            self.assertIn("source checkout attestation", copied_payload.stderr)
            shutil.copy2(ROOT / "scripts/build_backend.py", source_backend)
            source_manifest = manufactured_source / "pyproject.toml"
            source_manifest.write_bytes(source_manifest.read_bytes() + b"\n# copied\n")
            copied_payload = run_manufactured_source()
            self.assertNotEqual(copied_payload.returncode, 0)
            self.assertIn("source checkout attestation", copied_payload.stderr)
            shutil.copy2(installed / PROVENANCE_RESOURCE, source_manifest)
            source_module = (
                manufactured_source / "adapters/graph_engineering/adapters/__init__.py"
            )
            source_module.chmod(source_module.stat().st_mode | stat.S_IWGRP)
            copied_payload = run_manufactured_source()
            self.assertNotEqual(copied_payload.returncode, 0)
            self.assertIn("source checkout attestation", copied_payload.stderr)

            foreign_payload = temp / "installed-foreign-payload"
            shutil.copytree(installed, foreign_payload)
            shutil.rmtree(next(foreign_payload.glob("*.dist-info")))
            mismatched_root = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys;sys.path.insert(0,sys.argv[2]);"
                        "sys.path.insert(0,sys.argv[1]);"
                        "from graph_engineering.adapters.action_adapters import "
                        "builtin_implementation_digest;"
                        "builtin_implementation_digest('builtin:git-native-v1')"
                    ),
                    os.fspath(foreign_payload),
                    os.fspath(installed),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(mismatched_root.returncode, 0)
            self.assertIn("does not contain the loaded module", mismatched_root.stderr)

            duplicate_identity = temp / "installed-duplicate-identity"
            shutil.copytree(installed, duplicate_identity)
            duplicated = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys;sys.path.insert(0,sys.argv[2]);"
                        "sys.path.insert(0,sys.argv[1]);"
                        "from graph_engineering.adapters.action_adapters import "
                        "builtin_implementation_digest;"
                        "builtin_implementation_digest('builtin:git-native-v1')"
                    ),
                    os.fspath(installed),
                    os.fspath(duplicate_identity),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(duplicated.returncode, 0)
            self.assertIn("distribution identity is not unique", duplicated.stderr)

    def test_gew_act_001d_copied_source_payload_has_no_checkout_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-fake-source-") as directory:
            temp = pathlib.Path(directory)
            copied = temp / "copied"
            (copied / "scripts").mkdir(parents=True)
            shutil.copytree(ROOT / "core", copied / "core")
            shutil.copytree(ROOT / "adapters", copied / "adapters")
            shutil.copy2(ROOT / "pyproject.toml", copied / "pyproject.toml")
            shutil.copy2(ROOT / "scripts/build_backend.py", copied / "scripts/build_backend.py")
            shutil.copy2(
                ROOT / "core/graph_engineering/core/source_checkout.py",
                copied / "core/graph_engineering/core/source_checkout.py",
            )
            (copied / "config/security").mkdir(parents=True)
            shutil.copy2(
                ROOT / "config/security/security-runtime-local-actions-v1.json",
                copied / "config/security/security-runtime-local-actions-v1.json",
            )
            (copied / "config/actions").mkdir()
            (copied / "config/contracts").mkdir()
            for relative in (
                "config/actions/concrete-action-policy-v1.json",
                "config/contracts/action-adapter-registry-v1.json",
                "config/contracts/action-adapter-schema-registry-v1.json",
            ):
                shutil.copy2(ROOT / relative, copied / relative)
            from tests.support.source_checkout_attestation import SOURCE_FILES

            for relative in SOURCE_FILES:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    shutil.copy2(ROOT / relative, target)

            def probe_source(
                root: pathlib.Path,
                control_root: pathlib.Path | None = None,
            ) -> subprocess.CompletedProcess[str]:
                environment = dict(os.environ)
                configured_control = (
                    pathlib.Path(environment["GEW_INSTALLATION_CONTROL_ROOT"])
                    if control_root is None else control_root
                )
                return subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-X",
                        "gew_installation_control_root=" + os.fspath(configured_control),
                        "-c",
                        (
                            "import sys;sys.path[:0]=sys.argv[1:];"
                            "from graph_engineering.adapters.action_adapters import "
                            "builtin_implementation_digest;"
                            "builtin_implementation_digest('builtin:git-native-v1')"
                        ),
                        os.fspath(root / "adapters"),
                        os.fspath(root / "core"),
                    ),
                    cwd=temp,
                    env=environment,
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            for marker in ("empty", "file", "initialized"):
                with self.subTest(marker=marker):
                    attacked = temp / f"source-{marker}"
                    shutil.copytree(copied, attacked)
                    if marker == "empty":
                        (attacked / ".git").mkdir()
                    elif marker == "file":
                        (attacked / ".git").write_text("gitdir: fake-git\n", encoding="utf-8")
                    else:
                        initialized = subprocess.run(
                            ("git", "init", "--quiet", os.fspath(attacked)),
                            cwd=temp,
                            shell=False,
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(initialized.returncode, 0, initialized.stderr)
                    rejected = probe_source(attacked)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("source checkout attestation", rejected.stderr)

            from tests.support.source_checkout_attestation import (
                issue_source_checkout_attestation as issue_test_source_attestation,
            )

            control = temp / "issued-control"
            issue_test_source_attestation(copied, control)
            control = control.resolve(strict=True)
            accepted = probe_source(copied, control)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            replay_control = temp / "replayed-control"
            shutil.copytree(control, replay_control)
            replay_control = replay_control.resolve(strict=True)
            replayed = probe_source(copied, replay_control)
            self.assertNotEqual(replayed.returncode, 0)
            self.assertIn("source checkout attestation binding changed", replayed.stderr)

            attestation_path = control / "source-checkout-attestation-v1.json"
            attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
            attestation["source_root_inode"] += 1
            attestation_path.write_text(
                json.dumps(attestation, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(attestation_path, 0o600)
            substituted = probe_source(copied, control)
            self.assertNotEqual(substituted.returncode, 0)
            self.assertIn("source checkout attestation signature changed", substituted.stderr)

            issue_test_source_attestation(copied, control)
            displaced = temp / "displaced-source"
            copied.rename(displaced)
            shutil.copytree(displaced, copied)
            root_replaced = probe_source(copied, control)
            self.assertNotEqual(root_replaced.returncode, 0)
            self.assertIn("source checkout attestation binding changed", root_replaced.stderr)

    def test_gew_act_001e_zip_physical_protected_members_are_unique(self) -> None:
        protected = (
            "graph_engineering/__init__.py",
            "graph_engineering/pyproject.toml",
            "graph_engineering/adapters/__init__.py",
            "graph_engineering/adapters/action_adapters.py",
            "graph_engineering/adapters/command_native.py",
            "graph_engineering/adapters/connector_unavailable.py",
            "graph_engineering/adapters/git_native.py",
        )
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-zip-members-") as directory:
            temp = pathlib.Path(directory)
            dist = temp / "dist"
            dist.mkdir()
            built = subprocess.run(
                (sys.executable, os.fspath(ROOT / "scripts/build_wheel.py"), os.fspath(dist)),
                cwd=ROOT,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                record_name = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/RECORD")
                )
                metadata_name = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
                )
                wheel_name = next(
                    name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")
                )
            for member_name in (*protected, record_name, metadata_name, wheel_name):
                with self.subTest(member_name=member_name):
                    attacked = temp / (member_name.replace("/", "-") + ".whl")
                    shutil.copy2(wheel, attacked)
                    with zipfile.ZipFile(attacked) as archive:
                        member_body = archive.read(member_name)
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        with zipfile.ZipFile(attacked, "a") as archive:
                            archive.writestr(member_name, member_body)
                    rejected = subprocess.run(
                        (
                            sys.executable,
                            "-I",
                            "-c",
                            (
                                "import sys;sys.path.insert(0,sys.argv[1]);"
                                "from graph_engineering.adapters.action_adapters import "
                                "builtin_implementation_digest;"
                                "builtin_implementation_digest('builtin:git-native-v1')"
                            ),
                            os.fspath(attacked),
                        ),
                        cwd=temp,
                        shell=False,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("physical archive member is not unique", rejected.stderr)

    def test_gew_act_001f_source_uses_only_explicit_control_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-source-control-") as directory:
            temp = pathlib.Path(directory)

            def copy_source(destination: pathlib.Path) -> None:
                (destination / "scripts").mkdir(parents=True)
                shutil.copytree(ROOT / "core", destination / "core")
                shutil.copytree(ROOT / "adapters", destination / "adapters")
                shutil.copy2(ROOT / "pyproject.toml", destination / "pyproject.toml")
                shutil.copy2(
                    ROOT / "scripts/build_backend.py",
                    destination / "scripts/build_backend.py",
                )
                for relative in (
                    "config/actions/concrete-action-policy-v1.json",
                    "config/contracts/action-adapter-registry-v1.json",
                    "config/contracts/action-adapter-schema-registry-v1.json",
                    "config/security/security-runtime-local-actions-v1.json",
                ):
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / relative, target)
                from tests.support.source_checkout_attestation import SOURCE_FILES

                for relative in SOURCE_FILES:
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        shutil.copy2(ROOT / relative, target)

            source_a = temp / "source-a"
            source_b = temp / "source-b"
            copy_source(source_a)
            copy_source(source_b)
            from tests.support.source_checkout_attestation import (
                issue_source_checkout_attestation as issue_test_source_attestation,
            )
            control_a = temp / "control-a"
            control_b = temp / "control-b"
            issue_test_source_attestation(source_a, control_a)
            issue_test_source_attestation(source_b, control_b)
            control_a = control_a.resolve(strict=True)
            control_b = control_b.resolve(strict=True)
            refs = (
                "builtin:connector-unavailable-v1",
                "builtin:git-native-v1",
                "builtin:project-command-v1",
                "builtin:secret-provider-v1",
                "builtin:target-query-v1",
            )

            def probe(
                configured: str | tuple[str, ...] | None,
                *visible_controls: pathlib.Path,
            ) -> subprocess.CompletedProcess[str]:
                argv = [sys.executable, "-I"]
                if configured is not None:
                    values = (configured,) if isinstance(configured, str) else configured
                    for value in values:
                        argv.extend(("-X", f"gew_installation_control_root={value}"))
                argv.extend((
                    "-c",
                    (
                        "import json,sys;sys.path[:0]=sys.argv[1:];"
                        "from graph_engineering.adapters.action_adapters import "
                        "builtin_implementation_digest;"
                        f"refs={refs!r};"
                        "print(json.dumps([builtin_implementation_digest(ref) "
                        "for ref in refs]))"
                    ),
                    os.fspath(source_b / "adapters"),
                    os.fspath(source_b / "core"),
                    *(os.fspath(item) for item in visible_controls),
                ))
                return subprocess.run(
                    argv,
                    cwd=temp,
                    env={
                        **os.environ,
                        "GEW_INSTALLATION_CONTROL_ROOT": os.fspath(control_a),
                    },
                    shell=False,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            exact = probe(os.fspath(control_b), control_b)
            self.assertEqual(exact.returncode, 0, exact.stderr)
            self.assertEqual(len(json.loads(exact.stdout)), 5)
            for label, configured, visible in (
                ("missing", None, ()),
                ("configured-a-visible-b", os.fspath(control_a), (control_b,)),
                (
                    "multiple",
                    os.fspath(control_a) + os.pathsep + os.fspath(control_b),
                    (control_b,),
                ),
                (
                    "repeated",
                    (os.fspath(control_a), os.fspath(control_b)),
                    (control_b,),
                ),
            ):
                with self.subTest(label=label):
                    rejected = probe(configured, *visible)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertIn("source checkout attestation", rejected.stderr)
            linked = temp / "linked-control"
            linked.symlink_to(control_b, target_is_directory=True)
            symlinked = probe(os.fspath(linked), control_b)
            self.assertNotEqual(symlinked.returncode, 0)
            self.assertIn("source checkout attestation", symlinked.stderr)
            unsafe_control = temp / "unsafe-control"
            shutil.copytree(control_b, unsafe_control)
            unsafe_control = unsafe_control.resolve(strict=True)
            unsafe_control.chmod(0o755)
            unsafe = probe(os.fspath(unsafe_control))
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("source checkout attestation", unsafe.stderr)

    def test_gew_act_001g_direct_archive_never_stages_adapter_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-no-stage-") as directory:
            temp = pathlib.Path(directory)
            dist = temp / "dist"
            dist.mkdir()
            built = subprocess.run(
                (sys.executable, os.fspath(ROOT / "scripts/build_wheel.py"), os.fspath(dist)),
                cwd=ROOT,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl"))
            staging = temp / "staging"
            staging.mkdir(mode=0o700)
            probe = (
                sys.executable,
                "-I",
                "-c",
                (
                    "import os,sys;sys.path.insert(0,sys.argv[1]);"
                    "from graph_engineering.adapters.action_adapters import "
                    "builtin_implementation_digest;"
                    "refs=('builtin:connector-unavailable-v1','builtin:git-native-v1',"
                    "'builtin:project-command-v1','builtin:secret-provider-v1',"
                    "'builtin:target-query-v1');"
                    "[builtin_implementation_digest(ref) for ref in refs];"
                    "os._exit(0 if sys.argv[2]=='abrupt' else 9)"
                ),
                os.fspath(wheel),
                "abrupt",
            )
            crashed = subprocess.run(
                probe,
                cwd=temp,
                env={**os.environ, "TMPDIR": os.fspath(staging)},
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(crashed.returncode, 0, crashed.stderr)
            self.assertEqual(list(staging.glob("gew-validated-adapters-*")), [])
            restarted = subprocess.run(
                probe,
                cwd=temp,
                env={**os.environ, "TMPDIR": os.fspath(staging)},
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(restarted.returncode, 0, restarted.stderr)
            self.assertEqual(list(staging.glob("gew-validated-adapters-*")), [])

    def test_gew_act_001h_zip_loader_bytes_must_match_validated_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-loader-binding-") as directory:
            temp = pathlib.Path(directory)
            dist = temp / "dist"
            dist.mkdir()
            built = subprocess.run(
                (sys.executable, os.fspath(ROOT / "scripts/build_wheel.py"), os.fspath(dist)),
                cwd=ROOT,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl"))
            rejected = subprocess.run(
                (
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys;sys.path.insert(0,sys.argv[1]);"
                        "import graph_engineering.adapters.action_adapters as adapters;"
                        "import graph_engineering.adapters.git_native as target;"
                        "target.__loader__=type('ChangedLoader',(),"
                        "{'get_data':lambda self,path:b'changed-after-validation'})();"
                        "adapters.builtin_implementation_digest('builtin:git-native-v1')"
                    ),
                    os.fspath(wheel),
                ),
                cwd=temp,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("archive origin changed", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
