"""Synthetic fixtures that exercise real installation security resources."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from contextlib import contextmanager
import tempfile
import shutil
import subprocess
import sys
import os
import venv
import zipfile
import time

from graph_engineering.core.contracts import parse_json
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SchemaProfilePolicy

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTOR = "config/security/security-bootstrap-v1.json"


def work_context():
    profile = json.loads((ROOT / 'config/contracts/resource-profile-v1.json').read_bytes())
    schedule = json.loads((ROOT / 'config/contracts/cost-schedule-v1.json').read_bytes())
    return WorkContext(ResourceProfile.from_dict(profile), CostSchedule.from_dict(schedule))


def installed_bundle():
    import graph_engineering
    loader = getattr(graph_engineering, '_security_bootstrap_installation_resources', None)
    if not callable(loader):
        raise AssertionError('production security installation loader is absent')
    context = work_context()
    bodies = loader(context)
    descriptor = parse_json(bodies[0], context=context, source_id=DESCRIPTOR)
    paths = [DESCRIPTOR] + [row['path'] for row in descriptor['resources']]
    assert len(paths) == len(set(paths)) == len(bodies) == 31
    resources = dict(zip(paths, bodies, strict=True))
    documents = {p: parse_json(b, context=context, source_id=p) for p, b in resources.items()}
    profile = ResourceProfile.from_dict(documents['config/contracts/resource-profile-v1.json'])
    schema_policy = SchemaProfilePolicy.from_dict(documents['config/contracts/schema-profile-v1.json'])
    registries = {}
    for name in ('security-schema-registry-v1', 'security-bootstrap-schema-registry-v1'):
        manifest = documents[f'config/contracts/{name}.json']
        ids = {row['schema_id'] for row in manifest['resources']}
        schemas = {doc['$id']: resources[path] for path, doc in documents.items()
                   if doc.get('$id') in ids}
        registries[name] = ClosedSchemaRegistry.build(manifest, schemas, profile, schema_policy, context)
    return context, descriptor, resources, documents, registries


def raw_hash(body):
    return hashlib.sha256(body).hexdigest()


@contextmanager
def installation_stack(*, fault_hook=lambda _step: None, directory=None):
    """Use the real mount probe, repository clock, installation manager and locks."""
    from graph_engineering.storage.connection import ConnectionFactory
    from graph_engineering.storage.locks import LockedFileRegistry
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.policy import RepositoryPolicy
    from graph_engineering.storage.migration import InstallationMigrationRepository
    with tempfile.TemporaryDirectory(prefix='gew-security-', dir=directory) as temporary:
        base = Path(temporary).resolve()
        fixture_policies=base/'fixture-policies.json'
        fixture_policies.write_text(json.dumps(dict(
            repository=json.loads((ROOT/'config/contracts/repository-policy-v1.json').read_bytes()),
            migration=json.loads((ROOT/'config/contracts/migration-storage-policy-v1.json').read_bytes()))))
        fixture_policies.chmod(0o600)
        factory = ConnectionFactory.initialize(base / 'repository', RepositoryPolicy.from_dict(
            json.loads((ROOT/'config/contracts/repository-policy-v1.json').read_bytes())),
            'repository-security-synthetic')
        locks = LockedFileRegistry(factory)
        objects = ObjectRepository(factory._for_maintenance(), locks)
        manager = InstallationMigrationRepository.initialize(factory, locks, objects,
            control_root=base/'control', policy_document=json.loads(
                (ROOT/'config/contracts/migration-storage-policy-v1.json').read_bytes()),
            fault_hook=fault_hook)
        try:
            yield base, factory, locks, objects, manager
        finally:
            if not manager._control_lock._closed:
                manager.close()
            objects.close(); locks.close()


def bootstrap_rows(factory):
    """Read persisted facts only; no fixture trust inserts."""
    with factory._for_maintenance().open('doctor') as connection:
        tables = {row[0] for row in connection.execute('SELECT name FROM sqlite_master WHERE type=\'table\'')}
        result = {}
        for table in ('security_runtime_installation', 'security_bootstrap_installation_receipts',
                      'security_bootstrap_task_receipts', 'task_security_states'):
            result[table] = [] if table not in tables else connection.execute('SELECT * FROM '+table).fetchall()
        result['marker'] = connection.execute("SELECT * FROM schema_versions WHERE component='security-bootstrap'").fetchall()
        return result


def resource_refusal_probe(mode):
    from tests.support.source_checkout_attestation import (
        SOURCE_FILES, CONTROL_OPTION, CONTROL_ENVIRONMENT, issue_source_checkout_attestation)
    with tempfile.TemporaryDirectory(prefix='gew-security-source-') as temporary:
        base=Path(temporary).resolve();checkout=base/'source';checkout.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,checkout/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in SOURCE_FILES:
            target=checkout/relative
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
        control=base/'control';issue_source_checkout_attestation(checkout,control)
        probe='''
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
sys.path[:0]=[str(root/p) for p in ('core','application','storage','adapters')]
import graph_engineering
from graph_engineering.core.contracts.resources import ResourceProfile, CostSchedule, WorkContext
context=WorkContext(ResourceProfile.from_dict(json.loads((root/'config/contracts/resource-profile-v1.json').read_bytes())),
                    CostSchedule.from_dict(json.loads((root/'config/contracts/cost-schedule-v1.json').read_bytes())))
path=root/'config/security/disclosure-policy-v1.json'
if mode=='missing':path.unlink()
elif mode=='replaced':path.write_bytes(b'{}')
elif mode=='schema':
    path=root/'config/contracts/schemas/security-installation-receipt-1.0.0.json';path.write_bytes(b'{}')
else:
    path=root/'config/security/security-bootstrap-v1.json';path.write_bytes(b'{}')
try:graph_engineering._security_bootstrap_installation_resources(context)
except (graph_engineering.DistributionIdentityError,ValueError,OSError):print('PASS')
else:raise AssertionError('changed resource accepted')
'''
        child_environment=dict(os.environ);child_environment[CONTROL_ENVIRONMENT]=str(control)
        child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={control}',
                              '-c',probe,str(checkout),mode],cwd=checkout,env=child_environment,
                             capture_output=True,text=True,timeout=30)
        if child.returncode or child.stdout.strip()!='PASS':
            raise AssertionError('resource refusal probe failed')


def installation_crash(base, cut):
    from tests.support.source_checkout_attestation import CONTROL_OPTION
    probe='''
import json, os, pathlib, signal, sys
root=pathlib.Path(sys.argv[1]);base=pathlib.Path(sys.argv[2]);cut=sys.argv[3]
sys.path[:0]=[str(root)]+[str(root/p) for p in ('core','application','storage','adapters')]
from graph_engineering.storage.connection import ConnectionFactory
from graph_engineering.storage.policy import RepositoryPolicy
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
factory=ConnectionFactory._attach_existing_for_maintenance(base/'repository',RepositoryPolicy.from_dict(
    json.loads((root/'config/contracts/repository-policy-v1.json').read_bytes())),'repository-security-synthetic')
locks=LockedFileRegistry(factory);objects=ObjectRepository(factory,locks)
manager=InstallationMigrationRepository.attach_command_plane(factory,locks,objects,control_root=base/'control',
    policy_document=json.loads((root/'config/contracts/migration-storage-policy-v1.json').read_bytes()))
def fault(point):
    if point==cut:os.kill(os.getpid(),signal.SIGKILL)
manager._fault=fault
manager.initialize_security_storage()
raise AssertionError('crash point was not reached')
'''
    import graph_engineering
    module_path=Path(graph_engineering.__file__).resolve()
    source=graph_engineering._source_checkout_root(module_path) or module_path.parents[1]
    return subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
                           '-c',probe,str(source),str(base),cut],capture_output=True,timeout=30).returncode


def genuine_case(test, *, installed=False, variant=None):
    """A real owner-only entry point, distribution probe and locator; no seals."""
    if '--security-bootstrap-fixture' in sys.argv:
        return False
    from scripts import build_backend
    from tests.support.source_checkout_attestation import (CONTROL_OPTION, CONTROL_ENVIRONMENT,
        SOURCE_FILES, issue_source_checkout_attestation)
    with tempfile.TemporaryDirectory(prefix='gew-bootstrap-runtime-') as temporary:
        base=Path(temporary).resolve()
        source=base/'source';source.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,source/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in (*SOURCE_FILES,'config/contracts/repository-policy-v1.json','config/contracts/migration-storage-policy-v1.json'):
            target=source/relative
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
        if variant is not None:
            variants=json.loads((ROOT/'tests/fixtures/learning-report-config-variants-v1.json').read_bytes())['variants']
            change=next(row for row in variants if row['variant_id']==variant)
            for relative,key in (('config/learning/learning-policy-v3.json','policy_patch'),
                                 ('config/learning/learning-experiments-v2.json','experiments_patch')):
                path=source/relative;document=json.loads(path.read_bytes());document.update(change[key])
                path.write_text(json.dumps(document,indent=2)+'\n')
            for part in ('core','application','storage','adapters'):
                for path in (ROOT/part).rglob('*.py'):
                    assert raw_hash(path.read_bytes())==raw_hash((source/path.relative_to(ROOT)).read_bytes())
            import importlib.util
            specification=importlib.util.spec_from_file_location('security_bootstrap_fixture_builder',source/'scripts/build_backend.py')
            builder=importlib.util.module_from_spec(specification);specification.loader.exec_module(builder)
        else:builder=build_backend
        wheel=base/builder.build_wheel(temporary)
        control=base/'source-control';issue_source_checkout_attestation(source,control)
        environment=base/'environment';venv.EnvBuilder(with_pip=False,symlinks=True).create(environment)
        environment.chmod(0o700)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(next(environment.glob('lib/python*/site-packages')))
        probe=environment/'bin/security-bootstrap-fixture'
        probe.write_text('''
import pathlib, sys, unittest
root=pathlib.Path(sys.argv[1]);source=pathlib.Path(sys.argv[2])
if sys.argv[4]=='source':sys.path[:0]=[str(source/p) for p in ('core','application','storage','adapters')]
import graph_engineering
if sys.argv[4]=='source':assert pathlib.Path(graph_engineering.__file__).is_relative_to(source)
else:assert pathlib.Path(graph_engineering.__file__).is_relative_to(pathlib.Path(sys.prefix))
sys.path.insert(0,str(root))
suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[3])
assert suite.countTestCases()==1
result=unittest.TextTestRunner().run(suite)
assert result.testsRun==1 and not result.skipped
allowed=source if sys.argv[4]=='source' else pathlib.Path(sys.prefix)
for name,module in tuple(sys.modules.items()):
    if name=='graph_engineering' or name.startswith('graph_engineering.'):
        origin=getattr(module,'__file__',None)
        if origin is not None:assert pathlib.Path(origin).resolve().is_relative_to(allowed),(name,origin)
sys.exit(0 if result.wasSuccessful() else 1)
''');probe.chmod(0o700)
        child_environment=dict(os.environ);child_environment[CONTROL_ENVIRONMENT]=str(control)
        child=subprocess.run([str(environment/'bin/python'),'-B','-X',
            f'{CONTROL_OPTION}={control}',str(probe),str(ROOT),str(source),test.id(),'installed' if installed else 'source',
            '--security-bootstrap-fixture'],cwd=base,env=child_environment,capture_output=True,text=True,timeout=180)
        if child.returncode:
            # Only synthetic fixture errors; no owner or external source data.
            Path('/tmp/gew-bootstrap-runtime-diagnostic.txt').write_text(child.stderr)
            raise AssertionError('real runtime fixture case failed')
    return True


def genuine_runtime(base, cell_index=0, *, action_decision=None):
    from graph_engineering.adapters.runtime_locator import RunningDistributionProbe, ExecutableLocator
    from graph_engineering.adapters.runtime_adapters import RuntimeAdapterFactory, RuntimeInvocationPorts
    from graph_engineering.application.runtime import RuntimeSession
    from tests.support.runtime_resources import runtime_resource_guard
    from tests.integration.test_wp07_runtime_parity import FIXTURE, adapter_document, raw_input, compatibility
    running=RunningDistributionProbe().probe('graph-engineering-workflow')
    cell=FIXTURE['cells'][cell_index];configured=adapter_document(cell)
    if action_decision is not None:
        from tests.integration.test_wp07_runtime_parity import resign_configuration
        configured['capabilities']=sorted(set(configured['capabilities'])|{'human.action-decision.v1'})
        configured=resign_configuration(configured)
    locator=dict(schema_version='1.0',executable=running.executable,package_origin=running.package_origin,
        executable_digest='sha256-raw-v1:'+raw_hash(Path(running.executable).read_bytes()),
        release_manifest_digest=configured['release_manifest_digest'],expected_core_version=running.distribution_version,
        distribution_name=running.distribution_name,distribution_version=running.distribution_version,
        distribution_origin=running.distribution_origin)
    path=base/('locator-'+str(cell_index)+'.json');path.write_text(json.dumps(locator));path.chmod(0o600)
    verified=ExecutableLocator(runtime_resource_guard(),running).resolve(path)
    def unused(*_args): raise AssertionError('unused external invocation port')
    ports=RuntimeInvocationPorts(lambda task,owner,lineage:dict(task_id=task,owner_id=owner.owner_id,
        runtime_kind=lineage.runtime_kind,runtime_lineage_id=lineage.lineage_id),
        unused,unused,unused,unused,unused,unused,request_action_decision=action_decision)
    factory=RuntimeAdapterFactory(runtime_resource_guard())
    create=factory.codex if configured['runtime_kind']=='codex' else factory.hermes
    return RuntimeSession.establish(create(configured,verified,ports),raw_input(cell),compatibility(cell))


def invoke(active, operation, turn='security-bootstrap-turn'):
    from graph_engineering.application.runtime import RuntimeMutationGateway
    return RuntimeMutationGateway.invoke(active,active.proof,operation,occurred_at=turn,lease_ttl_ns=1000000000)


@contextmanager
def genuine_task_stack(*, approved=True, fault_hook=lambda _step:None, learning=False, graph=None, action_decision=None,
                       baseline_kind='prd'):
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.storage.codec import semantic_record_digest
    from tests.integration.test_wp04_application import contracts, TaskApplicationIntegrationTests as Fixtures
    with installation_stack() as (base,factory,locks,_objects,manager):
        manager.initialize_security_storage()
        if learning:manager.initialize_learning_storage()
        if action_decision is not None:manager.initialize_action_authority_storage()
        scope=manager.command_scope();scope.__enter__()
        try:
            bound=factory.bind_command_scope(scope);objects=ObjectRepository(bound,locks)
            repository=TaskRepository(bound,locks,objects,command_scope=scope,fault_hook=fault_hook)
            schemas,context=contracts()
            application=TaskApplication(repository,repository,ResourceLeaseRepository(bound,locks),
                                        schema_registry=schemas,context=context)
            active=genuine_runtime(base,action_decision=action_decision)
            identity=dict(task_id='task:security-synthetic',owner_id=active.proof.owner_id,
                          runtime_kind=active.capabilities.runtime_kind,runtime_lineage_id=active.proof.lineage_id)
            try:
                RuntimeMutationGateway.create(active,active.proof,identity,
                    lambda runtime:application.execute(identity['task_id'],TaskCommand('create',0,{'identity':identity}),runtime),
                    occurred_at='security:create',lease_ttl_ns=1000000000)
                if approved:
                    task_id=identity['task_id']
                    invoke(active,lambda runtime:application.execute_scope(task_id,TaskCommand('bind_project_scope',1,
                        {'project_scope_ref':Fixtures.scope('drafted')}),Fixtures.project_scope(),runtime),'security:scope')
                    invoke(active,lambda runtime:application.execute(task_id,TaskCommand('request_prd_approval',2,
                        {'prd_candidate_ref':'artifact:security-prd'}),runtime),'security:request')
                    approval=Fixtures.approval()
                    if graph is not None:
                        approval['graph_ref'].update(graph_id=graph.graph_id,graph_version=graph.graph_version,graph_digest=graph.digest)
                    approval['baseline_refs']=({**approval['baseline_refs'][0],'kind':baseline_kind,
                        'digest':semantic_record_digest({'intent':'synthetic security bootstrap'}),
                        'approved_by':active.proof.owner_id},)
                    if action_decision is not None:
                        approval['baseline_refs']+=({**approval['baseline_refs'][0],'kind':'intent',
                            'digest':semantic_record_digest({'action-intent':'synthetic bootstrap claim'})},)
                    invoke(active,lambda runtime:application.execute(task_id,TaskCommand('approve_prd',3,approval),runtime),
                           'security:approval')
                yield application,active,repository._factory,repository,base,manager
            finally:
                active.close();objects.close()
        finally:
            if not scope._closed:scope.__exit__(None,None,None)


def task_cas(factory, task_id='task:security-synthetic'):
    with factory.open('doctor') as connection:
        return connection.execute('SELECT revision,snapshot_digest FROM tasks WHERE task_id=?',(task_id,)).fetchone()


def task_issuer(application, factory):
    from graph_engineering.application.security import SecurityContextIssuer
    from graph_engineering.storage.security import SecurityStateRepository
    _context,_descriptor,_resources,_documents,registries=installed_bundle()
    return SecurityContextIssuer(SecurityStateRepository(factory),
        schema_registry=registries['security-schema-registry-v1'],context=application._context)


def bootstrap_task(application, active, factory, request='request:security-initial'):
    from graph_engineering.application.security_bootstrap import SecurityBootstrapService
    revision,digest=task_cas(factory)
    receipt=invoke(active,lambda runtime:SecurityBootstrapService(application).initialize_task(
        'task:security-synthetic',request,revision,digest,runtime))
    return receipt,revision,digest


def bootstrap_graph():
    from tests.contract.test_wp02_graph import complete,graph_candidate,graph_schemas,load_graph,work_context
    document=graph_candidate();document['nodes'][0]['invalidation_tags']=['target-api']
    return load_graph(complete(document),schemas=graph_schemas(),context=work_context())


def reapprove_scope(application,active,graph):
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.core.project import ProjectScope
    from tests.unit.test_wp06_project_scope import scope_document,load
    from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
    from graph_engineering.storage.codec import semantic_record_digest
    document=scope_document();document['version']=2
    document['target_bindings'][0]['verification_contract_ref']='verify-reapproved-synthetic'
    document['scope_digest']=ProjectScope.digest_document(document);candidate=load(document)
    revision=application._repository.load('task:security-synthetic')['domain']['task_revision']
    invoke(active,lambda runtime:application.execute('task:security-synthetic',TaskCommand('pause',revision,{}),runtime),'scope:pause')
    proposed=invoke(active,lambda runtime:application.propose_scope_change('task:security-synthetic',
        revision+1,candidate,graph,runtime),'scope:propose')
    approval=Fixtures.approval()
    approval['project_scope_ref']=dict(scope_id=candidate.scope_id,version=2,digest=candidate.scope_digest,status='frozen')
    approval['graph_ref'].update(graph_id=graph.graph_id,graph_version=graph.graph_version,graph_digest=graph.digest)
    approval['baseline_refs']=({**approval['baseline_refs'][0],'kind':'prd','version':2,'approved_by':active.proof.owner_id,
        'digest':semantic_record_digest({'intent':'reapproved synthetic security'})},)
    return invoke(active,lambda runtime:application.execute('task:security-synthetic',
        TaskCommand('approve_prd',proposed.task_revision,approval),runtime),'scope:reapproval')


_TASK_BOOTSTRAP_CHILD = '''
import json, os, pathlib, signal, sys, time
root=pathlib.Path(sys.argv[1]);base=pathlib.Path(sys.argv[2]);mode=sys.argv[3]
configuration=json.loads((base/'fixture-policies.json').read_bytes())
revision=int(sys.argv[4]);snapshot=sys.argv[5];request=sys.argv[6]
sys.path[:0]=[str(root/p) for p in ('core','application','storage','adapters')]+[sys.argv[7]]
import graph_engineering
assert pathlib.Path(graph_engineering.__file__).resolve().is_relative_to(root)
from tests.support.security_bootstrap import genuine_runtime,invoke
from tests.integration.test_wp04_application import contracts
from graph_engineering.storage.connection import ConnectionFactory
from graph_engineering.storage.policy import RepositoryPolicy
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.application.tasks import TaskApplication
from graph_engineering.application.security_bootstrap import SecurityBootstrapService
factory=ConnectionFactory._attach_existing_for_maintenance(base/'repository',RepositoryPolicy.from_dict(
    configuration['repository']),'repository-security-synthetic')
locks=LockedFileRegistry(factory);objects=ObjectRepository(factory,locks)
manager=InstallationMigrationRepository.attach_command_plane(factory,locks,objects,control_root=base/'control',
    policy_document=configuration['migration'])
with manager.command_scope() as scope:
    bound=factory.bind_command_scope(scope);owned=ObjectRepository(bound,locks)
    def fault(point):
        if point==mode:os.kill(os.getpid(),signal.SIGKILL)
    repository=TaskRepository(bound,locks,owned,command_scope=scope,fault_hook=fault)
    schemas,context=contracts()
    application=TaskApplication(repository,repository,ResourceLeaseRepository(bound,locks),schema_registry=schemas,context=context)
    with genuine_runtime(base) as active:
        if mode=='race':
            (base/('ready-'+str(os.getpid()))).write_text('ready')
            deadline=time.monotonic()+20
            while not (base/'race-gate').exists():
                if time.monotonic()>deadline:raise AssertionError('race gate absent')
                time.sleep(.01)
        receipt=invoke(active,lambda runtime:SecurityBootstrapService(application).initialize_task(
            'task:security-synthetic',request,revision,snapshot,runtime))
        from graph_engineering.core.contracts.immutable import thaw
        print(json.dumps(thaw(receipt),sort_keys=True))
'''


def task_bootstrap_process(base, mode, revision, snapshot, request):
    from tests.support.source_checkout_attestation import CONTROL_OPTION
    # The running fixture environment is private; this file is its actual entry point.
    probe=Path(sys.prefix)/'bin/security-bootstrap-task-child'
    if not probe.exists():
        probe.write_text(_TASK_BOOTSTRAP_CHILD);probe.chmod(0o700)
    import graph_engineering
    module_path=Path(graph_engineering.__file__).resolve()
    source=graph_engineering._source_checkout_root(module_path) or module_path.parents[1]
    return subprocess.Popen([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
        str(probe),str(source),str(base),mode,str(revision),snapshot,request,str(ROOT)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)


def race_gate(base, children):
    deadline=time.monotonic()+20
    while len(list(base.glob('ready-*')))<len(children):
        if any(child.poll() is not None for child in children) or time.monotonic()>deadline:
            for child in children:
                if child.poll() is None:child.kill()
            errors=[child.communicate(timeout=5)[1].decode() for child in children]
            Path('/tmp/gew-bootstrap-race-diagnostic.txt').write_text('\n'.join(errors))
            raise AssertionError('runtime race participants did not reach gate')
        time.sleep(.01)
    (base/'race-gate').write_text('start')


def task_source_rows(factory):
    with factory.open('doctor') as connection:
        return {table:connection.execute('SELECT * FROM '+table).fetchall() for table in (
            'tasks','events','transactions','project_scopes','project_scope_approvals','task_security_states',
            'security_bootstrap_task_receipts','security_bootstrap_installation_receipts')}


def corrupt_task_source(factory, mode):
    """Negative corruption after real create/approve, before any task trust exists."""
    from graph_engineering.storage.codec import canonical_json, semantic_record_digest
    from graph_engineering.core.contracts.digest import semantic_digest
    from graph_engineering.core.graph.state import SNAPSHOT_PROJECTION
    with factory.open('migration') as connection, connection.transaction():
        if mode=='missing-scope':
            connection.execute('DELETE FROM project_scope_approvals')
            connection.execute('DELETE FROM project_scope_metadata_history')
            connection.execute('DELETE FROM project_scopes')
        elif mode=='missing-approval':connection.execute('DELETE FROM project_scope_approvals')
        elif mode=='wrong-approval-record':
            row=connection.execute('SELECT record_json FROM project_scope_approvals').fetchone()
            record=json.loads(row[0]);record['owner_decision_ref']='decision:unapproved-substitution'
            connection.execute('UPDATE project_scope_approvals SET record_json=?,record_digest=?',
                (canonical_json(record),semantic_record_digest({'contract':'project-scope-approval-v1','value':record})))
        elif mode=='missing-event':connection.execute("DELETE FROM events WHERE event_type='project.scope_frozen'")
        elif mode=='invalid-head':connection.execute('UPDATE tasks SET head_digest=?',
            (semantic_record_digest({'invalid':'event head'}),))
        elif mode=='ambiguous-scope':
            connection.execute('ALTER TABLE project_scopes RENAME TO damaged_scope_original')
            connection.execute('CREATE TABLE project_scopes AS SELECT * FROM damaged_scope_original')
            connection.execute('INSERT INTO project_scopes SELECT * FROM damaged_scope_original')
        else:
            snapshot=json.loads(connection.execute('SELECT snapshot_json FROM tasks').fetchone()[0])
            domain=snapshot['domain']
            if mode=='duplicate-baseline':domain['baseline_refs'].append(dict(domain['baseline_refs'][0]))
            elif mode=='unapproved-baseline':domain['baseline_refs'][0]['approved_by']='owner:foreign'
            elif mode=='empty-baseline':domain['baseline_refs']=[]
            elif mode=='snapshot-substitution':domain['lifecycle']='paused'
            else:raise AssertionError('unknown negative corruption')
            unsigned={k:v for k,v in domain.items() if k!='snapshot_digest'}
            domain['snapshot_digest']=semantic_digest(unsigned,contract_type=SNAPSHOT_PROJECTION.contract_type,
                projection_id=SNAPSHOT_PROJECTION.projection_id,schema_id=SNAPSHOT_PROJECTION.schema_id)
            connection.execute('UPDATE tasks SET snapshot_json=?,snapshot_digest=?',(canonical_json(snapshot),
                semantic_record_digest({'contract':'repository-snapshot-v1','value':snapshot})))


def bounded_seed_probe(resource='config/contracts/resource-profile-v1.json'):
    """Fresh source attestation does not grant oversized bootstrap seed admission."""
    from tests.support.source_checkout_attestation import (
        SOURCE_FILES,CONTROL_OPTION,CONTROL_ENVIRONMENT,issue_source_checkout_attestation)
    with tempfile.TemporaryDirectory(prefix='gew-security-seed-') as temporary:
        base=Path(temporary).resolve();source=base/'source';source.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,source/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in SOURCE_FILES:
            target=source/relative
            if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
        profile=source/resource;body=profile.read_bytes()
        maximum=work_context().profile.limits['raw_document_bytes']
        profile.write_bytes(body+b' '*(maximum+1-len(body)))
        control=base/'control';issue_source_checkout_attestation(source,control)
        probe='''
import pathlib,sys
root=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root/p) for p in ('core','application','storage','adapters')]
import graph_engineering
from graph_engineering.storage.security import _bootstrap_bundle,SecurityBootstrapError
original=graph_engineering._attested_source_member
def capture(source,path,owner,**kwargs):
    if path==sys.argv[2]:raise AssertionError('oversized resource materialized')
    return original(source,path,owner,**kwargs)
graph_engineering._attested_source_member=capture
try:_bootstrap_bundle()
except SecurityBootstrapError as error:
    assert str(error)=='SECURITY_BOOTSTRAP_RESOURCE_LIMIT',str(error)
    print('PASS')
else:raise AssertionError('oversized seed accepted')
'''
        environment=dict(os.environ);environment[CONTROL_ENVIRONMENT]=str(control)
        child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={control}','-c',probe,str(source),resource],
            cwd=source,env=environment,capture_output=True,text=True,timeout=30)
        if child.returncode or child.stdout.strip()!='PASS':
            Path('/tmp/gew-security-seed-diagnostic.txt').write_text(child.stderr)
            raise AssertionError('bootstrap seed admission failed')


def bootstrap_action_preparation(application, factory):
    """Only prepare an action; this creates no executable authority."""
    from graph_engineering.core.actions import PreparedAction
    from graph_engineering.storage.actions import ActionJournalRepository
    from tests.support.wp05_actions import prepared_document
    issuer=task_issuer(application,factory)
    current=issuer.issue_task_context('task:security-synthetic')
    binding=current.binding;target=next(iter(binding.targets.values()))
    document=prepared_document(context=issuer._context)
    document.update(task_id=binding.task_id,action_id='action:bootstrap-claim',target_id=target.target_id,
        target_digest=target.target_digest,resources=sorted(['task:'+binding.task_id,'target:'+target.target_id]),
        baseline_digest=binding.baselines['intent'],snapshot_digest=binding.snapshot_digest)
    document['prepared_action_digest']=PreparedAction.digest_document(document,issuer._context)
    prepared=PreparedAction.from_dict(document,context=issuer._context)
    journal=ActionJournalRepository(factory,schema_registry=issuer._schemas,context=issuer._context)
    journal.record_prepared(prepared)
    revision,snapshot=task_cas(factory)
    request=dict(schema_version='1.0.0',request_id='request:bootstrap-claim',task_id=binding.task_id,
        action_id=prepared.action_id,expected_task_revision=revision,expected_snapshot_digest=snapshot,
        expected_security_digest=current.state_digest,expected_journal_revision=1)
    return issuer,journal,prepared,request


@contextmanager
def genuine_claimed_learning_stack():
    """A real approved/start transaction leaves a claim before any target call."""
    from graph_engineering.application.action_authority import ActionAuthorizationApplication
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.core.security.retention import RetentionPolicyRegistry
    from tests.unit.test_action_authority import decision
    requests=[]
    def human(request,_owner,_lineage):
        requests.append(request)
        return decision(request)
    with genuine_task_stack(learning=True,action_decision=human) as (application,active,factory,_repo,base,manager):
        bootstrap_task(application,active,factory)
        issuer,_journal,_prepared,request=bootstrap_action_preparation(application,factory)
        factory._command_scope.__exit__(None,None,None)
        service=ActionAuthorizationApplication(manager,schema_registry=issuer._schemas,context=issuer._context)
        assert service.authorize(active,request)['status']=='approved'
        assert len(requests)==1
        # This is the validated durable start boundary, with zero target/disclosure calls.
        genuine_unresolved_start(service,request)
        with manager.command_scope() as scope:
            _manifest,current=manager._current_factory(scope._control_token());bound=current.bind_command_scope(scope)
            objects=ObjectRepository(bound,manager._locks)
            try:
                repo=TaskRepository(bound,manager._locks,objects,command_scope=scope)
                issuer=task_issuer(application,repo._factory)
                _ctx,_descriptor,_resources,documents,_registries=installed_bundle()
                retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
                    schema_registry=issuer._schemas,context=issuer._context,runtime=issuer.runtime)
                secured=TaskApplication(repo,repo,ResourceLeaseRepository(repo._factory,manager._locks),
                    schema_registry=application._schemas,context=application._context,
                    learning_security_issuer=issuer,learning_retention_registry=retention)
                yield secured,active,repo._factory,repo,base,manager
            finally:objects.close()


def genuine_unresolved_start(service, request):
    """Use the normal ledger/journal/lease commit, stopping before target I/O."""
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository,make_event
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.ports import CommitBatch
    from graph_engineering.storage.clock import strict_trusted_now
    from graph_engineering.storage.security import SecurityStateRepository
    from graph_engineering.storage.codec import semantic_record_digest
    from graph_engineering.application.tasks import action_task_snapshot
    with service._scope() as (ledger,journal,_issuer):
        factory=ledger.factory;locks=service._manager._locks;objects=ObjectRepository(factory,locks)
        try:
            repo=TaskRepository(factory,locks,objects,command_scope=factory._command_scope,action_journal=journal)
            leases=ResourceLeaseRepository(repo._factory,locks)
            record=journal.load(request['action_id']);head=journal.current_task_head(request['task_id'])
            lease=leases.acquire_many(lease_id='lease:bootstrap-unresolved',task_id=request['task_id'],run_id='run:bootstrap',
                operation_id='operation:bootstrap',resources=record.prepared.resources,ttl_ns=1000000000)
            with factory.open('application') as connection,connection.transaction():
                occurred=SecurityStateRepository._clock_text(strict_trusted_now(connection))
            event=make_event(task_id=request['task_id'],sequence=head.sequence+1,event_id='event:bootstrap-started',
                event_type='action.execution_started',occurred_at=occurred,actor={'kind':'runtime','id':record.authority.runtime_lineage_id},
                expected_task_revision=head.revision,baseline_digests=[record.prepared.baseline_digest],previous_event_digest=head.head_digest,
                payload=dict(action_id=record.action_id,authority_digest=record.authority.authority_digest,
                    prepared_action_digest=record.prepared.prepared_action_digest,snapshot_digest=record.prepared.snapshot_digest,
                    lease_id=lease.lease_id,fencing_tokens=dict(lease.fencing_tokens),
                    disclosure_plan_digest=semantic_record_digest({'contract':'synthetic-nondisclosing-start-v1','action_id':record.action_id})))
            claim=leases.claim_action(claim_id='claim:bootstrap-unresolved',action_id=record.action_id,task_id=request['task_id'],
                lease=lease,started_event_digest=event['event_digest'])
            repo.commit(CommitBatch(transaction_id='transaction:bootstrap-start',task_id=request['task_id'],expected_task_revision=head.revision,
                events=(event,),snapshot=action_task_snapshot(head.snapshot,task_id=request['task_id'],revision=head.revision,action_state='executing'),
                catalog_delta={},lease_assertion=dict(lease_id=lease.lease_id,resource_id='task:'+request['task_id'],
                    fencing_token=dict(lease.fencing_tokens)['task:'+request['task_id']]),claim_delta=claim,action_journal_delta=journal.start_delta(record)))
        finally:objects.close()
