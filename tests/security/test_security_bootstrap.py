"""Refusal cases use corruption only after genuine installation initialization."""
from __future__ import annotations
import unittest
from graph_engineering.storage.migration import InstallationMigrationRepository, MigrationRepositoryError
from tests.support.security_bootstrap import (installation_stack, bootstrap_rows, resource_refusal_probe,
    genuine_case, genuine_task_stack, genuine_runtime, task_cas, invoke)
from tests.support.security_bootstrap import corrupt_task_source, task_source_rows


class SecurityBootstrapSecurityTests(unittest.TestCase):
    def test_bounded_before_materialization(self):
        if genuine_case(self):return
        import graph_engineering
        from pathlib import Path
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        from graph_engineering.storage import repository as module
        from tests.support.security_bootstrap import bounded_seed_probe
        bounded_seed_probe()
        with genuine_task_stack() as (application,active,factory,_repository,_base,_manager):
            revision,digest=task_cas(factory)
            with factory.open('migration') as connection,connection.transaction():
                raw=connection.execute('SELECT snapshot_json FROM tasks').fetchone()[0]
                body=__import__('json').loads(raw);body['oversized']='x'*(application._context.profile.limits['raw_document_bytes']+1)
                connection.execute('UPDATE tasks SET snapshot_json=?',(__import__('json').dumps(body),))
            before=task_source_rows(factory);original=module._recovery_json
            def no_body(*args,**kwargs):
                if kwargs.get('source_id')=='security-bootstrap-sources':raise AssertionError('oversized source materialized')
                return original(*args,**kwargs)
            module._recovery_json=no_body
            try:
                with self.assertRaises(SecurityBootstrapError):
                    invoke(active,lambda runtime:self.service_type()(application).initialize_task('task:security-synthetic',
                        'request:security-bounded',revision,digest,runtime))
                self.assertEqual(task_source_rows(factory),before)
            finally:module._recovery_json=original
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.application.security import SecurityIssuanceError
        from graph_engineering.storage.codec import canonical_json
        from graph_engineering.core.contracts.resources import WorkContext
        for mode in ('receipt-bytes','source-count'):
            with genuine_task_stack() as (application,active,factory,_repository,_base,_manager):
                if mode=='receipt-bytes':bootstrap_task(application,active,factory)
                with factory.open('migration') as connection,connection.transaction():
                    if mode=='receipt-bytes':
                        table='security_bootstrap_task_receipts'
                        triggers=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",(table,)).fetchall()
                        for name,_sql in triggers:connection.execute('DROP TRIGGER '+name)
                        body=__import__('json').loads(connection.execute('SELECT receipt_json FROM '+table).fetchone()[0])
                        body['oversized']='x'*(application._context.profile.limits['raw_document_bytes']+1)
                        connection.execute('UPDATE '+table+' SET receipt_json=?',(canonical_json(body),))
                        for _name,sql in triggers:connection.execute(sql)
                    else:
                        row=list(connection.execute('SELECT * FROM events ORDER BY sequence LIMIT 1').fetchone())
                        head=connection.execute('SELECT max(sequence) FROM events').fetchone()[0]
                        for i in range(32):
                            extra=list(row);extra[1]=head+i+1;extra[2]='event:negative-count-'+str(i)
                            connection.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)',tuple(extra))
                before=task_source_rows(factory);original=module._recovery_json
                def no_allocation(encoded,context,budget,**kwargs):
                    source_id=kwargs.get('source_id','')
                    if (mode=='source-count' and source_id=='security-bootstrap-sources'
                            or mode=='receipt-bytes' and len(encoded)>context.profile.limits['raw_document_bytes']):
                        raise AssertionError('unadmitted bootstrap field materialized')
                    return original(encoded,context,budget,**kwargs)
                module._recovery_json=no_allocation
                try:
                    if mode=='receipt-bytes':
                        with self.assertRaises(SecurityIssuanceError):task_issuer(application,factory)
                    else:
                        from graph_engineering.application.tasks import TaskApplication
                        narrowed=application._context.profile.to_dict();narrowed['limits']['array_items']=31
                        context=WorkContext(application._context.profile.narrowed_by(narrowed),application._context.schedule)
                        limited=TaskApplication(_repository,_repository,application._leases,schema_registry=application._schemas,context=context)
                        revision,digest=task_cas(factory)
                        with self.assertRaises(SecurityBootstrapError):
                            invoke(active,lambda runtime:self.service_type()(limited).initialize_task('task:security-synthetic',
                                'request:bounded-count',revision,digest,runtime))
                    self.assertEqual(task_source_rows(factory),before)
                finally:module._recovery_json=original
        bounded_seed_probe('config/security/disclosure-policy-v1.json')

    def test_receipts_minimized_holds_preserved(self):
        if genuine_case(self):return
        from tests.support.learning_reports import genuine_learning_stack,grant,collect,report
        from tests.support.security_bootstrap import task_issuer
        with genuine_learning_stack() as (application,active,factory,_repository,_base,_manager):
            grant(application,active);collect(application,active,factory)
            before=bootstrap_rows(factory);state=__import__('json').loads(before['task_security_states'][0][3])
            self.assertTrue(state['retention_subjects'])
            receipt=__import__('json').loads(before['security_bootstrap_task_receipts'][0][3])
            revision=receipt['initial_task_revision'];digest=receipt['initial_snapshot_digest']
            invoke(active,lambda runtime:self.service_type()(application).initialize_task('task:security-synthetic',
                receipt['request_id'],revision,digest,runtime))
            self.assertEqual(bootstrap_rows(factory),before)
            for row in before['security_bootstrap_task_receipts']+before['security_bootstrap_installation_receipts']:
                encoded=str(row)
                for forbidden in ('retention_subjects','authority_digests','owner_id','/private/','raw_content'):
                    self.assertNotIn(forbidden,encoded)
            task_issuer(application,factory).issue_task_context('task:security-synthetic')
            from graph_engineering.core.learning import LearningError
            from tests.support.learning_reports import learning_call,learning_request
            # The genuine configured retention window protects these freshly persisted subjects.
            retained=learning_call(application,active,learning_request('purge_learning','learning:young-purge',
                expected_generation=1,trigger='garbage-collect'))
            self.assertEqual(retained['state'],'retain')
            self.assertEqual(bootstrap_rows(factory),before)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_aggregates').fetchone(),(1,))


        from tests.support.security_bootstrap import genuine_claimed_learning_stack,task_bootstrap_process
        from tests.support.learning_reports import learning_call,learning_request
        from unittest import mock
        import time,json
        with genuine_claimed_learning_stack() as (application,active,factory,_repository,base,_manager):
            grant(application,active);collect(application,active,factory)
            before=bootstrap_rows(factory);state=json.loads(before['task_security_states'][0][3])
            self.assertTrue(next(iter(state['retention_subjects'].values()))['unresolved_action'])
            with factory.open('doctor') as connection:
                claims=connection.execute('SELECT * FROM claims').fetchall()
                self.assertEqual(len(claims),1);self.assertEqual(claims[0][-2],'unresolved')
                aggregate=connection.execute('SELECT * FROM pmf_aggregates').fetchall()
            receipt=json.loads(before['security_bootstrap_task_receipts'][0][3])
            child=task_bootstrap_process(base,'restart',receipt['initial_task_revision'],receipt['initial_snapshot_digest'],receipt['request_id'])
            output,error=child.communicate(timeout=30);self.assertEqual(child.returncode,0,error.decode()[-2000:])
            self.assertEqual(json.loads(output),receipt);self.assertEqual(bootstrap_rows(factory),before)
            future=time.time_ns()+7776001*10**9
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=future):
                refused=learning_call(application,active,learning_request('purge_learning','learning:claim-blocked',
                    expected_generation=1,trigger='garbage-collect'))
            self.assertEqual(refused['state'],'blocked')
            self.assertEqual(bootstrap_rows(factory),before)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT * FROM claims').fetchall(),claims)
                self.assertEqual(connection.execute('SELECT * FROM pmf_aggregates').fetchall(),aggregate)
                self.assertEqual(connection.execute('SELECT count(*) FROM purge_authorizations').fetchone(),(0,))
                self.assertEqual(connection.execute('SELECT count(*) FROM pmf_tombstones').fetchone(),(0,))

    def test_stale_sources_race(self):
        if genuine_case(self):return
        import graph_engineering
        from pathlib import Path
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        from graph_engineering.application.security import SecurityIssuanceError
        # Corruption at the real precommit callback must roll back both new trust rows.
        from graph_engineering.storage.connection import _ISSUED_CONNECTION_OWNERS
        from graph_engineering.storage.codec import canonical_json,semantic_record_digest
        for mode in ('approval','baseline','scope','task-cas','activation'):
            with genuine_task_stack() as (application,active,factory,repository,_base,manager):
                revision,digest=task_cas(factory);before=task_source_rows(factory)
                manifest_path=manager._control/manager._policy.active_manifest_filename
                manifest_bytes=manifest_path.read_bytes()
                def change_source(point):
                    if point!='security-bootstrap.task-before-commit':return
                    if mode=='activation':
                        document=__import__('json').loads(manifest_bytes)
                        document['activation_epoch']+=1
                        manifest_path.write_text(canonical_json(document));return
                    candidates=[c for c,owner in tuple(_ISSUED_CONNECTION_OWNERS.items())
                                if owner is factory and c._role=='application' and c._in_transaction]
                    self.assertEqual(len(candidates),1);connection=candidates[0]
                    if mode=='scope':connection.execute("UPDATE project_scopes SET status='drafted'")
                    elif mode=='task-cas':connection.execute('UPDATE tasks SET revision=revision+1')
                    else:
                        record=__import__('json').loads(connection.execute('SELECT record_json FROM project_scope_approvals').fetchone()[0])
                        if mode=='baseline':record['baseline_refs'][0]['digest']=semantic_record_digest({'negative':'race-baseline'})
                        else:record['owner_decision_ref']='decision:race-substitution'
                        connection.execute('UPDATE project_scope_approvals SET record_json=?,record_digest=?',
                            (canonical_json(record),semantic_record_digest({'contract':'project-scope-approval-v1','value':record})))
                repository._fault=change_source
                try:
                    with self.assertRaises(SecurityBootstrapError,msg=mode):
                        invoke(active,lambda runtime:self.service_type()(application).initialize_task(
                            'task:security-synthetic','request:precommit-'+mode,revision,digest,runtime))
                finally:manifest_path.write_bytes(manifest_bytes);repository._fault=lambda _point:None
                self.assertEqual(task_source_rows(factory),before,mode)
        path=Path(graph_engineering.__file__).resolve().parents[2]/'config/security/disclosure-policy-v1.json'
        original=path.read_bytes()
        with genuine_task_stack() as (application,active,factory,repository,_base,_manager):
            revision,digest=task_cas(factory);before=bootstrap_rows(factory)
            def change(point):
                if point=='security-bootstrap.task-before-commit':path.write_bytes(original+b' ')
            repository._fault=change
            try:
                with self.assertRaises(SecurityBootstrapError):
                    invoke(active,lambda runtime:self.service_type()(application).initialize_task('task:security-synthetic',
                        'request:security-race',revision,digest,runtime))
                self.assertEqual(bootstrap_rows(factory),before)
            finally:path.write_bytes(original);repository._fault=lambda _point:None
            bootstrap_task(application,active,factory);issuer=task_issuer(application,factory)
            before=bootstrap_rows(factory);path.write_bytes(original+b' ')
            try:
                from graph_engineering.application.security import SecurityContextIssuer
                from graph_engineering.storage.security import SecurityStateRepository
                with self.assertRaises(SecurityIssuanceError):
                    SecurityContextIssuer(SecurityStateRepository(factory),schema_registry=issuer._schemas,context=issuer._context)
                for operation in (issuer.read_task_state,issuer.issue_task_context):
                    with self.assertRaises(SecurityIssuanceError):operation('task:security-synthetic')
                with factory.open('application') as connection,connection.transaction():
                    with self.assertRaises(SecurityIssuanceError):issuer._issue_task_context_locked(connection,'task:security-synthetic')
                self.assertEqual(bootstrap_rows(factory),before)
            finally:path.write_bytes(original)

    def service_type(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('graph_engineering.application.security_bootstrap'))
        from graph_engineering.application.security_bootstrap import SecurityBootstrapService
        return SecurityBootstrapService

    def test_foreign_unissued_runtime_refused(self):
        service_type=self.service_type()
        if genuine_case(self):return
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        with genuine_task_stack() as (application,active,factory,_repository,base,_manager):
            service=service_type(application);revision,digest=task_cas(factory);before=bootstrap_rows(factory)
            foreign=genuine_runtime(base,2);closed=False
            try:
                import graph_engineering.application.security_bootstrap as bootstrap_module
                original=bootstrap_module._security_bootstrap_sources_locked
                def forbidden(*_args):raise AssertionError('foreign runtime materialized task sources')
                bootstrap_module._security_bootstrap_sources_locked=forbidden
                try:
                    with self.assertRaisesRegex(SecurityBootstrapError,'SECURITY_BOOTSTRAP_AUTHORITY'):
                        invoke(foreign,lambda runtime:service.initialize_task('task:security-synthetic',
                            'request:security-foreign',revision,digest,runtime))
                finally:bootstrap_module._security_bootstrap_sources_locked=original
                captured=invoke(active,lambda runtime:runtime)
                for runtime in (None,{},captured):
                    with self.assertRaises(SecurityBootstrapError):
                        service.initialize_task('task:security-synthetic','request:security-unissued',revision,digest,runtime)
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=1) as pool:
                    def threaded(runtime):
                        with self.assertRaises(SecurityBootstrapError):
                            pool.submit(service.initialize_task,'task:security-synthetic','request:thread-invalid',
                                        revision,digest,runtime).result(timeout=5)
                    invoke(active,threaded)
                import os,select,signal
                def forked(runtime):
                    read,write=os.pipe();pid=os.fork()
                    if pid==0:
                        os.close(read)
                        try:
                            service.initialize_task('task:security-synthetic','request:pid-invalid',revision,digest,runtime)
                        except SecurityBootstrapError:os.write(write,b'PASS')
                        finally:os._exit(0)
                    os.close(write)
                    try:
                        self.assertTrue(select.select([read],[],[],10)[0]);self.assertEqual(os.read(read,4),b'PASS')
                    finally:
                        os.close(read);os.waitpid(pid,0)
                invoke(active,forked)
                foreign.close();closed=True
                with self.assertRaises((RuntimeError,ValueError)):
                    invoke(foreign,lambda runtime:service.initialize_task('task:security-synthetic',
                        'request:closed',revision,digest,runtime))
                self.assertEqual(bootstrap_rows(factory),before)
            finally:
                if not closed:foreign.close()

    def test_caller_trust_payload_refused(self):
        service_type=self.service_type()
        if genuine_case(self):return
        with genuine_task_stack() as (application,active,factory,_repository,_base,_manager):
            service=service_type(application);revision,digest=task_cas(factory);before=bootstrap_rows(factory)
            for field in ('state','targets','authority_digests','clock','issuer','schema_registry','manifest','policy','destinations','data_refs'):
                with self.assertRaises(TypeError):
                    invoke(active,lambda runtime:service.initialize_task('task:security-synthetic',
                        'request:security-override',revision,digest,runtime,**{field:{}}))
                self.assertEqual(bootstrap_rows(factory),before)

            from graph_engineering.application.security_bootstrap import SecurityBootstrapError
            from graph_engineering.storage.security import _initialize_security_bootstrap_locked
            with factory.open('application') as connection,connection.transaction():
                with self.assertRaises(SecurityBootstrapError):service._initialize_locked(connection,*([None]*10))
                with self.assertRaises(SecurityBootstrapError):_initialize_security_bootstrap_locked(connection,factory,None,None,lambda _point:None)
            from graph_engineering.core.security.attestation import TaskSecurityContext,SecurityRuntimeManifest
            for capability in (TaskSecurityContext,SecurityRuntimeManifest):
                with self.assertRaises(TypeError):capability({})
            self.assertEqual(bootstrap_rows(factory),before)

    def test_missing_replaced_resources_refused(self):
        for mode in ('missing','replaced','schema','descriptor'):
            resource_refusal_probe(mode)

    def test_partial_marker_corruption_refused(self):
        self.assertTrue(callable(getattr(InstallationMigrationRepository,'initialize_security_storage',None)))
        if genuine_case(self):return
        for mutation in ('remove-marker','unknown-marker','remove-receipt','remove-runtime'):
            with installation_stack() as (_base,factory,_locks,_objects,manager):
                manager.initialize_security_storage()
                with factory._for_maintenance().open('migration') as connection, connection.transaction():
                    if mutation=='remove-marker':
                        connection.execute("DELETE FROM schema_versions WHERE component='security-bootstrap'")
                    elif mutation=='unknown-marker':
                        connection.execute("UPDATE schema_versions SET version='2.0.0' WHERE component='security-bootstrap'")
                    else:
                        table = ('security_bootstrap_installation_receipts' if mutation=='remove-receipt'
                                 else 'security_runtime_installation')
                        for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?",(table,)).fetchall():
                            connection.execute('DROP TRIGGER '+name)
                        connection.execute('DELETE FROM '+table)
                before=bootstrap_rows(factory)
                with self.assertRaises(MigrationRepositoryError): manager.initialize_security_storage()
                self.assertEqual(bootstrap_rows(factory),before)
        from tests.support.security_bootstrap import bootstrap_task,task_issuer
        from graph_engineering.application.security import SecurityIssuanceError
        for mutation in ('unknown-marker','invalid-installation-digest','invalid-task-digest','wrong-initial-state','unreceipted-state'):
            with genuine_task_stack() as (application,active,factory,_repository,_base,_manager):
                bootstrap_task(application,active,factory);issuer=task_issuer(application,factory)
                with factory.open('migration') as connection,connection.transaction():
                    if mutation=='unknown-marker':connection.execute("UPDATE schema_versions SET version='9.0.0' WHERE component='security-bootstrap'")
                    else:
                        table='security_bootstrap_installation_receipts' if mutation=='invalid-installation-digest' else 'security_bootstrap_task_receipts'
                        triggers=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",(table,)).fetchall()
                        for trigger,_sql in triggers:connection.execute('DROP TRIGGER '+trigger)
                        if mutation=='unreceipted-state':connection.execute('DELETE FROM '+table)
                        elif mutation=='wrong-initial-state':
                            from graph_engineering.storage.security import _bootstrap_digest
                            from graph_engineering.storage.codec import canonical_json
                            body=__import__('json').loads(connection.execute('SELECT receipt_json FROM '+table).fetchone()[0])
                            body['initial_state_digest']='sha256-jcs-v1:'+'0'*64
                            body['receipt_digest']=_bootstrap_digest(body,'security-task-initialization-receipt',application._context)
                            connection.execute('UPDATE '+table+' SET receipt_json=?,receipt_digest=?',
                                (canonical_json(body),body['receipt_digest']))
                        else:connection.execute('UPDATE '+table+' SET receipt_digest=?',('sha256-jcs-v1:'+'0'*64,))
                        for _trigger,sql in triggers:connection.execute(sql)
                before=bootstrap_rows(factory)
                with self.assertRaises(SecurityIssuanceError,msg=mutation):task_issuer(application,factory)
                for entry in (issuer.read_task_state,issuer.issue_task_context):
                    with self.assertRaises(SecurityIssuanceError,msg=mutation):entry('task:security-synthetic')
                with factory.open('application') as connection,connection.transaction():
                    with self.assertRaises(SecurityIssuanceError,msg=mutation):issuer._issue_task_context_locked(connection,'task:security-synthetic')
                if mutation=='wrong-initial-state':
                    from graph_engineering.application.security_bootstrap import SecurityBootstrapError
                    from graph_engineering.storage.security import _bootstrap_migration_facts
                    body=__import__('json').loads(before['security_bootstrap_task_receipts'][0][3])
                    with self.assertRaises(SecurityBootstrapError):
                        invoke(active,lambda runtime:self.service_type()(application).initialize_task(
                            body['task_id'],body['request_id'],body['initial_task_revision'],body['initial_snapshot_digest'],runtime))
                    with factory.open('doctor') as connection:
                        with self.assertRaises(SecurityBootstrapError):_bootstrap_migration_facts(connection)
                self.assertEqual(bootstrap_rows(factory),before)
        service_type=self.service_type()
        from graph_engineering.application.security_bootstrap import SecurityBootstrapError
        # A real approval event with only an Intent baseline cannot replace an approved PRD.
        with genuine_task_stack(baseline_kind='intent') as (application,active,factory,_repository,_base,_manager):
            before=task_source_rows(factory);revision,digest=task_cas(factory)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute("SELECT json_extract(snapshot_json,'$.domain.baseline_refs[0].kind') "
                    "FROM tasks WHERE task_id='task:security-synthetic'").fetchone(),('intent',))
                self.assertEqual(connection.execute("SELECT count(*) FROM events WHERE event_type='task.prd_approved'").fetchone(),(1,))
            self.assertFalse(before['task_security_states']);self.assertFalse(before['security_bootstrap_task_receipts'])
            for _retry in range(2):
                with self.assertRaises(SecurityBootstrapError):
                    invoke(active,lambda runtime:service_type(application).initialize_task(
                        'task:security-synthetic','request:security-intent-only',revision,digest,runtime))
                self.assertEqual(task_source_rows(factory),before)
        for approved in (False,True):
            modes=(('no-prd','drafted-scope') if not approved else ('missing-scope','missing-approval','wrong-approval-record','missing-event',
                'ambiguous-scope','invalid-head','duplicate-baseline','unapproved-baseline','empty-baseline','snapshot-substitution'))
            for mode in modes:
                with genuine_task_stack(approved=approved) as (application,active,factory,_repository,_base,_manager):
                    if approved:corrupt_task_source(factory,mode)
                    elif mode=='drafted-scope':
                        from graph_engineering.core.graph.state import TaskCommand
                        from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
                        invoke(active,lambda runtime:application.execute_scope('task:security-synthetic',TaskCommand(
                            'bind_project_scope',1,{'project_scope_ref':Fixtures.scope('drafted')}),Fixtures.project_scope(),runtime))
                    before=task_source_rows(factory);revision,digest=task_cas(factory)
                    for _retry in range(2):
                        with self.assertRaises(SecurityBootstrapError):
                            invoke(active,lambda runtime:service_type(application).initialize_task(
                                'task:security-synthetic','request:security-invalid',revision,digest,runtime))
                        self.assertEqual(task_source_rows(factory),before,mode)
                        self.assertFalse(before['task_security_states']);self.assertFalse(before['security_bootstrap_task_receipts'])
