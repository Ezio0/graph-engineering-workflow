"""Production security bootstrap transactions in isolated synthetic repositories."""
from __future__ import annotations
import unittest
import json
import signal
from graph_engineering.storage.migration import InstallationMigrationRepository
from tests.support.security_bootstrap import (installation_stack, bootstrap_rows, installation_crash,
    genuine_case, genuine_task_stack, task_cas, invoke, task_bootstrap_process, race_gate, ROOT)


class InjectedBootstrapFailure(Exception):
    pass


class SecurityBootstrapIntegrationTests(unittest.TestCase):
    def test_genuine_learning_lifecycle(self):
        if genuine_case(self):return
        from tests.support.security_bootstrap import bootstrap_graph
        from tests.support.learning_reports import genuine_learning_stack,grant,complete_task,collect,report,learning_call,learning_request
        from graph_engineering.core.learning import LearningError
        graph=bootstrap_graph()
        with genuine_learning_stack(graph=graph) as (application,active,factory,repository,_base,_manager):
            grant(application,active)
            complete_task(application,active,repository,graph)
            collect(application,active,factory)
            result=report(application,active)
            self.assertEqual(result['observations'][0]['metrics']['completion']['value'],'completed')
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT state_json FROM task_security_states').fetchone()[0]
            state=json.loads(before);self.assertEqual(len(state['retention_subjects']),1)
            learning_call(application,active,learning_request('revoke_learning','learning:revoke',expected_generation=1))
            with self.assertRaises(LearningError):report(application,active,'learning:revoked-report')
            from unittest import mock
            import time
            # Controlled retention boundary only; all setup and native elapsed clocks remain real.
            future=time.time_ns()+7776001*10**9
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=future):
                purged=learning_call(application,active,learning_request('purge_learning','learning:purge',trigger='garbage-collect',expected_generation=2))
            self.assertEqual(purged['state'],'purged')
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone(),(0,))
                self.assertGreater(connection.execute('SELECT count(*) FROM pmf_tombstones').fetchone()[0],0)
            rows=bootstrap_rows(factory);receipt=json.loads(rows['security_bootstrap_task_receipts'][0][3])
            child=task_bootstrap_process(_base,'restart',receipt['initial_task_revision'],
                receipt['initial_snapshot_digest'],receipt['request_id'])
            out,err=child.communicate(timeout=30)
            self.assertEqual(child.returncode,0,err.decode()[-2000:]);self.assertEqual(json.loads(out),receipt)
            self.assertEqual(bootstrap_rows(factory),rows)
            factory._command_scope.__exit__(None,None,None)
            from graph_engineering.storage.migration import MigrationRepositoryError
            with self.assertRaisesRegex(MigrationRepositoryError,'learning'):
                _manager.export_bundle(_base/'purged-pmf-refused',export_id='export:purged-refused')
        from tests.support.learning_reports import genuine_cohort
        with genuine_cohort(['canceled']) as (application,active,_factory,_repo,tasks,_base,_manager):
            self.assertEqual(report(application,active,task_ids=tasks)['observations'][0]['metrics']['completion']['value'],'canceled')

    def test_migration_roundtrip(self):
        if genuine_case(self):return
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.storage.migration import InstallationMigrationRepository,MigrationRepositoryError
        from tests.integration.test_wp04_application import contracts
        with genuine_task_stack() as (application,active,factory,_repository,base,manager):
            receipt,_,_=bootstrap_task(application,active,factory)
            before=bootstrap_rows(factory)
            factory._command_scope.__exit__(None,None,None)
            bundle=manager.export_bundle(base/'bundle',export_id='export:security-synthetic')
            import shutil
            from graph_engineering.storage.codec import canonical_json
            for mode in ('origin','resource','task-reference'):
                damaged=base/('damaged-'+mode);shutil.copytree(bundle.root,damaged)
                path=damaged/manager._policy.bundle_records_filename;records=json.loads(path.read_bytes())
                if mode=='task-reference':records['security_bootstrap_task_receipts']['rows'][0][0]='task:foreign-transplant'
                else:
                    row=records['security_bootstrap_installation_receipts']['rows'][0]
                    receipt_body=json.loads(row[1])
                    if mode=='origin':receipt_body['origin_repository_id']='repository:foreign-origin'
                    else:receipt_body['resource_vector_digest']='sha256-jcs-v1:'+'0'*64
                    row[1]=canonical_json(receipt_body)
                path.write_text(canonical_json(records))
                destination_path=base/('refused-'+mode)
                with self.assertRaises(MigrationRepositoryError,msg=mode):
                    manager.import_bundle(damaged,destination_path,repository_id='repository-refused-'+mode)
                self.assertFalse(destination_path.exists(),mode)
            imported=manager.import_bundle(bundle.root,base/'destination',repository_id='repository-security-destination')
            try:
                destination=InstallationMigrationRepository.initialize(imported.factory,imported.locks,imported.objects,
                    control_root=base/'destination-control',policy_document=json.loads(
                        (ROOT/'config/contracts/migration-storage-policy-v1.json').read_bytes()))
                try:
                    self.assertEqual(bootstrap_rows(imported.factory),before)
                    installation=destination.initialize_security_storage()
                    self.assertEqual(installation['origin_repository_id'],'repository-security-synthetic')
                    with destination.command_scope() as scope:
                        bound=imported.factory.bind_command_scope(scope);objects=ObjectRepository(bound,imported.locks)
                        try:
                            repo=TaskRepository(bound,imported.locks,objects,command_scope=scope)
                            schemas,context=contracts();app=TaskApplication(repo,repo,ResourceLeaseRepository(bound,imported.locks),
                                schema_registry=schemas,context=context)
                            issuer=task_issuer(app,bound)
                            self.assertEqual(issuer.issue_task_context('task:security-synthetic').binding.owner_id,active.proof.owner_id)
                            self.assertEqual(bootstrap_rows(bound),before)
                        finally:objects.close()
                finally:destination.close()
            finally:imported.close()
        with genuine_task_stack(learning=True) as (_application,_active,factory,_repository,base,manager):
            factory._command_scope.__exit__(None,None,None)
            with self.assertRaisesRegex(MigrationRepositoryError,'learning'):
                manager.export_bundle(base/'forbidden-pmf-export',export_id='export:pmf-refused')

    def test_retry_preserves_evolved_state(self):
        if genuine_case(self):return
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.core.graph.state import TaskCommand
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        with genuine_task_stack(learning=True) as (application,active,factory,repository,_base,_manager):
            receipt,revision,digest=bootstrap_task(application,active,factory)
            issuer=task_issuer(application,factory)
            invoke(active,lambda runtime:application.execute('task:security-synthetic',TaskCommand('run',5,
                {'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),'evolution:run')
            invoke(active,lambda runtime:application.execute('task:security-synthetic',TaskCommand('pause',6,{}),runtime),'evolution:pause')
            from tests.support.learning_reports import grant,collect
            from tests.support.security_bootstrap import installed_bundle
            from graph_engineering.application.tasks import TaskApplication
            from graph_engineering.core.security.retention import RetentionPolicyRegistry
            _ctx,_descriptor,_resources,documents,_registries=installed_bundle()
            retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
                schema_registry=issuer._schemas,context=issuer._context,runtime=issuer.runtime)
            application=TaskApplication(repository,repository,application._leases,schema_registry=application._schemas,
                context=application._context,learning_security_issuer=issuer,learning_retention_registry=retention)
            grant(application,active);collect(application,active,factory)
            before=bootstrap_rows(factory)
            self.assertTrue(json.loads(before['task_security_states'][0][3])['retention_subjects'])
            current=issuer.issue_task_context('task:security-synthetic')
            self.assertEqual(current.binding.snapshot_digest,task_cas(factory)[1])
            self.assertEqual(invoke(active,lambda runtime:self.service_type()(application).initialize_task(
                'task:security-synthetic','request:security-initial',revision,digest,runtime)),receipt)
            with self.assertRaises(SecurityBootstrapError):
                invoke(active,lambda runtime:self.service_type()(application).initialize_task(
                    'task:security-synthetic','request:security-other',revision,digest,runtime))
            self.assertEqual(bootstrap_rows(factory),before)

    def test_legacy_roots_distinguishable(self):
        if genuine_case(self):return
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.application.security import SecurityIssuanceError
        # This historical SQL fixture is compatibility evidence only, never bootstrap evidence.
        from tests.integration.test_wp09_learning import secured_learning_stack
        with secured_learning_stack() as (historical,_active,legacy_factory,_repository):
            self.assertFalse(bootstrap_rows(legacy_factory)['marker'])
            self.assertEqual(historical._learning_security_issuer.issue_task_context('task:learning-1').binding.task_id,'task:learning-1')
        for mutation in ('marker-missing','tables-missing','receipt-missing'):
            with genuine_task_stack() as (application,active,factory,_repository,_base,_manager):
                bootstrap_task(application,active,factory);issuer=task_issuer(application,factory)
                with factory.open('migration') as connection,connection.transaction():
                    if mutation=='marker-missing':connection.execute("DELETE FROM schema_versions WHERE component='security-bootstrap'")
                    elif mutation=='tables-missing':
                        connection.execute('DROP TABLE security_bootstrap_task_receipts')
                        connection.execute('DROP TABLE security_bootstrap_installation_receipts')
                    else:
                        connection.execute('DROP TRIGGER security_bootstrap_task_receipts_no_delete')
                        connection.execute('DELETE FROM security_bootstrap_task_receipts')
                before=bootstrap_rows(factory)
                with self.assertRaises(SecurityIssuanceError):task_issuer(application,factory)
                for operation in (issuer.read_task_state,issuer.issue_task_context):
                    with self.assertRaises(SecurityIssuanceError):operation('task:security-synthetic')
                with factory.open('application') as connection,connection.transaction():
                    with self.assertRaises(SecurityIssuanceError):issuer._issue_task_context_locked(connection,'task:security-synthetic')
                self.assertEqual(bootstrap_rows(factory),before)

    def test_scope_reapproval_refused(self):
        if genuine_case(self):return
        from tests.support.security_bootstrap import bootstrap_task,task_issuer,bootstrap_graph,reapprove_scope
        from graph_engineering.application.security import SecurityIssuanceError
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        graph=bootstrap_graph()
        with genuine_task_stack(graph=graph) as (application,active,factory,_repository,_base,_manager):
            receipt,revision,digest=bootstrap_task(application,active,factory);issuer=task_issuer(application,factory)
            reapprove_scope(application,active,graph);before=bootstrap_rows(factory)
            with self.assertRaises(SecurityBootstrapError):
                invoke(active,lambda runtime:self.service_type()(application).initialize_task('task:security-synthetic',
                    'request:security-initial',revision,digest,runtime))
            for operation in (issuer.read_task_state,issuer.issue_task_context):
                with self.assertRaises(SecurityIssuanceError):operation('task:security-synthetic')
            with factory.open('application') as connection,connection.transaction():
                with self.assertRaises(SecurityIssuanceError):issuer._issue_task_context_locked(connection,'task:security-synthetic')
            self.assertEqual(bootstrap_rows(factory),before)

    def service_type(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('graph_engineering.application.security_bootstrap'),
                             'production task security initialization is absent')
        from graph_engineering.application.security_bootstrap import SecurityBootstrapService
        return SecurityBootstrapService

    def test_task_derivation_empty_authority(self):
        service_type=self.service_type()
        if genuine_case(self):return
        from graph_engineering.storage.codec import semantic_record_digest
        def unused_human(*_args):raise AssertionError('bootstrap action requested human authority')
        with genuine_task_stack(action_decision=unused_human) as (application,active,factory,repository,_base,_manager):
            service=service_type(application);revision,digest=task_cas(factory)
            before=repository.replay('task:security-synthetic')
            receipt=invoke(active,lambda runtime:service.initialize_task('task:security-synthetic',
                'request:security-initial',revision,digest,runtime))
            rows=bootstrap_rows(factory);self.assertEqual(len(rows['task_security_states']),1)
            state=json.loads(rows['task_security_states'][0][3]);binding=state['binding']
            snapshot=repository.load('task:security-synthetic')['domain']
            self.assertEqual(binding['owner_id'],active.proof.owner_id)
            self.assertEqual(binding['runtime_lineage_id'],active.proof.lineage_id)
            self.assertEqual(binding['baselines'],{ref['kind']:ref['digest'] for ref in snapshot['baseline_refs']})
            scope=snapshot['project_scope_ref']
            self.assertEqual(binding['targets'],[dict(target_id=scope['scope_id'],target_kind='project-scope',
                canonical_identity=scope['scope_id'],target_digest=scope['digest'])])
            for field in ('destinations','data_refs','evidence_expectations','retention_subjects'):
                self.assertEqual(state[field],{})
            self.assertEqual(state['authority_digests'],[])
            self.assertEqual(receipt['initial_state_digest'],semantic_record_digest({'contract':'task-security-state-v1','value':state}))
            self.assertEqual(repository.replay('task:security-synthetic'),before)
            self.assertEqual(task_cas(factory),(revision,digest))
            self.assertEqual(invoke(active,lambda runtime:service.initialize_task('task:security-synthetic',
                'request:security-initial',revision,digest,runtime)),receipt)
            self.assertEqual(bootstrap_rows(factory),rows)
            from tests.support.security_bootstrap import bootstrap_action_preparation,installed_bundle
            from graph_engineering.core.actions import AuthorityEnvelope
            from graph_engineering.core.action_authority import ActionAuthorityError
            from tests.support.wp05_actions import authority_document
            issuer,journal,prepared,_request=bootstrap_action_preparation(application,factory)
            current=issuer.issue_task_context(prepared.task_id)
            self.assertEqual(current.authority_digests,())
            authority=authority_document(prepared,context=issuer._context)
            import datetime
            issued=datetime.datetime.fromisoformat(current.current_time.replace('Z','+00:00'))
            authority.update(owner_id=current.binding.owner_id,runtime_kind=current.binding.runtime_kind,
                runtime_lineage_id=current.binding.runtime_lineage_id,issued_at=current.current_time,
                expires_at=(issued+datetime.timedelta(seconds=60)).isoformat().replace('+00:00','Z'))
            authority['authority_digest']=AuthorityEnvelope.digest_document(authority,issuer._context)
            well_formed=AuthorityEnvelope.from_dict(authority,context=issuer._context)
            with self.assertRaises(ActionAuthorityError) as refused:
                journal.record_authorized(well_formed)
            self.assertEqual(refused.exception.code,'stale_binding')
            self.assertEqual(journal.load(prepared.action_id).state,'prepared')
            from graph_engineering.core.security.disclosure import DisclosurePolicy,DataDisclosurePlan,DisclosureError
            from graph_engineering.core.security.privacy import RedactionPolicy,Redactor
            _ctx,_descriptor,_resources,documents,_registries=installed_bundle()
            policy=DisclosurePolicy.from_dict(documents['config/security/disclosure-policy-v1.json'],
                schema_registry=issuer._schemas,context=issuer._context,runtime=issuer.runtime)
            redaction=RedactionPolicy.from_dict(documents['config/security/redaction-policy-v1.json'],
                schema_registry=issuer._schemas,context=issuer._context,runtime=issuer.runtime)
            payload=Redactor.redact(dict(prepared.payload),field_allowlist=('/set',),transforms={},secret_materials=(),
                policy=redaction,context=issuer._context)
            plan=dict(schema_version='1.0.0',disclosure_id='disclosure:bootstrap',
                destination=dict(identity_ref=current.binding.owner_id,kind='owner',trust_boundary='owner-session'),
                purpose='owner-update',data_refs=[dict(ref_id='action-payload',digest=prepared.payload_digest,sensitivity='internal')],
                maximum_sensitivity='internal',field_allowlist=['/set'],redaction_transforms=[],retention_class='evidence-body',
                authority_digest=None,prepared_action_digest=prepared.prepared_action_digest,
                snapshot_digest=current.binding.snapshot_digest,payload_digest=payload.payload_digest,receipt_required=False)
            plan['plan_digest']=DataDisclosurePlan.digest_document(plan)
            self.assertFalse(issuer._schemas.validate('urn:gew:schema:data-disclosure-plan:1.0.0',plan,issuer._context))
            with self.assertRaisesRegex(DisclosureError,'destination identity is not authorized'):
                DataDisclosurePlan.from_dict(plan,policy=policy,runtime=issuer.runtime,task_context=current,
                    redacted_payload=payload,schema_registry=issuer._schemas,context=issuer._context)
            self.assertEqual(bootstrap_rows(factory),rows)
            self.assertEqual(repository.replay('task:security-synthetic'),before)
            with factory.open('doctor') as connection:
                for table in ('claims','disclosure_journal','action_authority_events'):
                    self.assertEqual(connection.execute('SELECT count(*) FROM '+table).fetchone(),(0,))

    def test_task_crash_restart(self):
        service_type=self.service_type()
        if genuine_case(self):return
        cuts=('security-bootstrap.task-before-insert','security-bootstrap.task-between-writes',
              'security-bootstrap.task-before-commit','security-bootstrap.task-after-commit')
        for cut in cuts:
            with genuine_task_stack() as (application,active,factory,repository,_base,_manager):
                service=service_type(application);revision,digest=task_cas(factory)
                def fail(point):
                    if point==cut:raise InjectedBootstrapFailure()
                repository._fault=fail
                with self.assertRaises(InjectedBootstrapFailure):
                    invoke(active,lambda runtime:service.initialize_task('task:security-synthetic',
                        'request:security-crash',revision,digest,runtime))
                rows=bootstrap_rows(factory)
                self.assertEqual(len(rows['task_security_states']),int(cut==cuts[-1]))
                self.assertEqual(len(rows['security_bootstrap_task_receipts']),int(cut==cuts[-1]))
                repository._fault=lambda _point:None
                reopened=service_type(application)
                receipt=invoke(active,lambda runtime:reopened.initialize_task('task:security-synthetic',
                    'request:security-crash',revision,digest,runtime))
                self.assertEqual(task_cas(factory),(revision,digest))
                if cut==cuts[-1]:self.assertEqual(bootstrap_rows(factory),rows)
                self.assertEqual(receipt['initial_snapshot_digest'],digest)
            with genuine_task_stack() as (application,active,factory,repository,base,_manager):
                revision,digest=task_cas(factory)
                child=task_bootstrap_process(base,cut,revision,digest,'request:security-process-crash')
                out,err=child.communicate(timeout=30)
                self.assertEqual(child.returncode,-signal.SIGKILL,err.decode()[-2000:])
                rows=bootstrap_rows(factory)
                self.assertEqual(len(rows['task_security_states']),int(cut==cuts[-1]))
                self.assertEqual(len(rows['security_bootstrap_task_receipts']),int(cut==cuts[-1]))
                receipt=invoke(active,lambda runtime:service_type(application).initialize_task('task:security-synthetic',
                    'request:security-process-crash',revision,digest,runtime))
                self.assertEqual(task_cas(factory),(revision,digest))
                if cut==cuts[-1]:self.assertEqual(bootstrap_rows(factory),rows)
                self.assertEqual(receipt['initial_snapshot_digest'],digest)

    def test_parallel_initialization(self):
        service_type=self.service_type()
        if genuine_case(self):return
        with genuine_task_stack() as (application,active,factory,_repository,base,_manager):
            revision,digest=task_cas(factory)
            children=[task_bootstrap_process(base,'race',revision,digest,'request:security-race') for _ in range(3)]
            try:
                race_gate(base,children)
                receipts=[]
                for child in children:
                    out,err=child.communicate(timeout=60)
                    self.assertEqual(child.returncode,0,err.decode()[-2000:]);receipts.append(json.loads(out))
                self.assertEqual(receipts,[receipts[0]]*3)
                rows=bootstrap_rows(factory)
                self.assertEqual(len(rows['task_security_states']),1)
                self.assertEqual(len(rows['security_bootstrap_task_receipts']),1)
                self.assertEqual(task_cas(factory),(revision,digest))
                receipt=invoke(active,lambda runtime:service_type(application).initialize_task(
                    'task:security-synthetic','request:security-race',revision,digest,runtime))
                self.assertEqual(dict(receipt),receipts[0])
                self.assertEqual(bootstrap_rows(factory),rows)
            finally:
                for child in children:
                    if child.poll() is None:child.kill()
                    child.communicate(timeout=5)

        with genuine_task_stack() as (application,active,factory,_repository,base,_manager):
            revision,digest=task_cas(factory)
            children=[task_bootstrap_process(base,'race',revision,digest,'request:contender-'+str(i)) for i in range(2)]
            try:
                race_gate(base,children)
                outcomes=[]
                for child in children:
                    out,err=child.communicate(timeout=60);outcomes.append((child.returncode,out,err))
                self.assertEqual(sorted(row[0] for row in outcomes),[0,1])
                winner=next(json.loads(out) for code,out,_err in outcomes if code==0)
                self.assertIn('SECURITY_BOOTSTRAP_CONFLICT',next(err.decode() for code,_out,err in outcomes if code==1))
                rows=bootstrap_rows(factory)
                self.assertEqual(len(rows['task_security_states']),1);self.assertEqual(len(rows['security_bootstrap_task_receipts']),1)
                self.assertEqual(task_cas(factory),(revision,digest))
                replay=invoke(active,lambda runtime:service_type(application).initialize_task('task:security-synthetic',
                    winner['request_id'],revision,digest,runtime))
                self.assertEqual(dict(replay),winner);self.assertEqual(bootstrap_rows(factory),rows)
            finally:
                for child in children:
                    if child.poll() is None:child.kill()
                    child.communicate(timeout=5)

    def require_initializer(self):
        self.assertTrue(callable(getattr(InstallationMigrationRepository, 'initialize_security_storage', None)),
                        'production installation security initialization is absent')

    def test_installation_atomic_replay(self):
        self.require_initializer()
        with installation_stack() as (_base, factory, _locks, _objects, manager):
            before = bootstrap_rows(factory)
            self.assertFalse(before['security_runtime_installation'])
            first = manager.initialize_security_storage()
            after = bootstrap_rows(factory)
            self.assertEqual(len(after['security_runtime_installation']), 1)
            self.assertEqual(len(after['security_bootstrap_installation_receipts']), 1)
            self.assertEqual(len(after['marker']), 1)
            self.assertFalse(after['task_security_states'])
            self.assertEqual(manager.initialize_security_storage(), first)
            self.assertEqual(bootstrap_rows(factory), after)
            with self.assertRaises(TypeError):
                manager.initialize_security_storage(manifest={})

    def test_installation_crash_restart(self):
        self.require_initializer()
        for cut in ('security-bootstrap.before-insert', 'security-bootstrap.between-installation-writes',
                    'security-bootstrap.before-commit', 'security-bootstrap.after-commit'):
            seen = []
            def fail(step):
                seen.append(step)
                if step == cut: raise InjectedBootstrapFailure()
            with installation_stack() as (base, factory, locks, objects, manager):
                manager._fault = fail
                with self.assertRaises(InjectedBootstrapFailure): manager.initialize_security_storage()
                self.assertIn(cut, seen)
                rows = bootstrap_rows(factory)
                durable = cut == 'security-bootstrap.after-commit'
                for table in ('security_runtime_installation', 'security_bootstrap_installation_receipts', 'marker'):
                    self.assertEqual(len(rows[table]), int(durable), (cut, table))
                manager.close()
                reopened = InstallationMigrationRepository.attach_command_plane(factory, locks, objects,
                    control_root=base/'control', policy_document=json.loads(
                        (ROOT/'config/contracts/migration-storage-policy-v1.json').read_bytes()))
                try:
                    receipt = reopened.initialize_security_storage()
                    self.assertEqual(len(bootstrap_rows(factory)['marker']), 1)
                    if durable: self.assertEqual(bootstrap_rows(factory), rows)
                    self.assertEqual(reopened.initialize_security_storage(), receipt)
                finally: reopened.close()
            with installation_stack() as (base,factory,_locks,_objects,manager):
                self.assertEqual(installation_crash(base,cut),-signal.SIGKILL)
                rows=bootstrap_rows(factory)
                for table in ('security_runtime_installation','security_bootstrap_installation_receipts','marker'):
                    self.assertEqual(len(rows[table]),int(cut=='security-bootstrap.after-commit'),(cut,table))
                receipt=manager.initialize_security_storage()
                self.assertEqual(manager.initialize_security_storage(),receipt)
                if cut=='security-bootstrap.after-commit':self.assertEqual(bootstrap_rows(factory),rows)
