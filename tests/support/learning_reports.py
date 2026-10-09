"""Closed synthetic contract data; never completion or security authority."""
from __future__ import annotations

import copy
import json
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[2]


def learning_request(operation,request_id,task_id='task:security-synthetic',**fields):
    return dict(schema_version='1.0.0',operation=operation,request_id=request_id,task_id=task_id,**fields)


def learning_call(application,active,request):
    from tests.support.security_bootstrap import invoke
    return invoke(active,lambda runtime:application.learning(request,runtime),request['request_id'])


@contextmanager
def genuine_learning_stack(*,graph=None):
    from tests.support.security_bootstrap import genuine_task_stack,bootstrap_task,task_issuer,installed_bundle
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.core.security.retention import RetentionPolicyRegistry
    with genuine_task_stack(learning=True,graph=graph) as (application,active,factory,repository,base,manager):
        bootstrap_task(application,active,factory)
        issuer=task_issuer(application,factory)
        _ctx,_descriptor,_resources,documents,_registries=installed_bundle()
        retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
            schema_registry=issuer._schemas,context=issuer._context,runtime=issuer.runtime)
        secured=TaskApplication(repository,repository,application._leases,schema_registry=application._schemas,
            context=application._context,learning_security_issuer=issuer,learning_retention_registry=retention)
        yield secured,active,factory,repository,base,manager


def grant(application,active,request_id='learning:grant',*,task_id='task:security-synthetic',metrics=None,generation=0):
    import time
    from graph_engineering.core.learning import METRIC_IDS
    return learning_call(application,active,learning_request('grant_learning',request_id,task_id,
        expected_generation=generation,metric_ids=sorted(METRIC_IDS) if metrics is None else metrics,
        expires_at_ns=str(time.time_ns()+120_000_000_000)))


def collect(application,active,factory,request_id='learning:collect',*,task_id='task:security-synthetic',generation=1,context_version=0):
    with factory.open('doctor') as connection:
        head=connection.execute('SELECT head_digest FROM tasks WHERE task_id=?',(task_id,)).fetchone()[0]
    return learning_call(application,active,learning_request('collect_learning',request_id,task_id,
        expected_head=head,expected_generation=generation,expected_context_version=context_version))


def report(application,active,request_id='learning:report',*,task_ids=None):
    tasks=['task:security-synthetic'] if task_ids is None else task_ids
    return learning_call(application,active,learning_request('report_learning',request_id,min(tasks),
        experiment_id='synthetic-default',task_ids=tasks))


def cancel_task(application,active,task_id='task:security-synthetic'):
    from tests.support.security_bootstrap import invoke
    revision=application._repository.load(task_id)['domain']['task_revision']
    def operation(runtime):
        plan=application.prepare_retention_plan(task_id,'cancel',runtime)
        return application.cancel_with_retention(task_id,revision,plan['plan_id'],runtime)
    return invoke(active,operation,'learning:cancel:'+task_id)


def add_task(application,active,factory,task_id,graph):
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.application.security_bootstrap import SecurityBootstrapService
    from graph_engineering.storage.codec import semantic_record_digest
    from tests.support.security_bootstrap import invoke,task_cas
    from tests.integration.test_wp04_application import TaskApplicationIntegrationTests as Fixtures
    identity=dict(task_id=task_id,owner_id=active.proof.owner_id,runtime_kind=active.capabilities.runtime_kind,
                  runtime_lineage_id=active.proof.lineage_id)
    RuntimeMutationGateway.create(active,active.proof,identity,
        lambda runtime:application.execute(task_id,TaskCommand('create',0,{'identity':identity}),runtime),
        occurred_at='create:'+task_id,lease_ttl_ns=1000000000)
    invoke(active,lambda runtime:application.execute_scope(task_id,TaskCommand('bind_project_scope',1,
        {'project_scope_ref':Fixtures.scope('drafted')}),Fixtures.project_scope(),runtime),'scope:'+task_id)
    invoke(active,lambda runtime:application.execute(task_id,TaskCommand('request_prd_approval',2,
        {'prd_candidate_ref':'artifact:synthetic-prd'}),runtime),'request:'+task_id)
    approval=Fixtures.approval();approval['graph_ref'].update(graph_id=graph.graph_id,
        graph_version=graph.graph_version,graph_digest=graph.digest)
    approval['baseline_refs']=({**approval['baseline_refs'][0],'kind':'prd',
        'digest':semantic_record_digest({'intent':'synthetic security bootstrap'}),'approved_by':active.proof.owner_id},)
    invoke(active,lambda runtime:application.execute(task_id,TaskCommand('approve_prd',3,approval),runtime),'approval:'+task_id)
    revision,digest=task_cas(factory,task_id)
    invoke(active,lambda runtime:SecurityBootstrapService(application).initialize_task(task_id,'bootstrap:'+task_id,
        revision,digest,runtime),'bootstrap:'+task_id)


@contextmanager
def genuine_cohort(outcomes):
    """Every metric comes from genuine independent task events and normal consent."""
    from tests.support.security_bootstrap import bootstrap_graph
    graph=bootstrap_graph()
    with genuine_learning_stack(graph=graph) as (application,active,factory,repository,base,manager):
        tasks=['task:security-synthetic']+[f'task:cohort-{i}' for i in range(1,len(outcomes))]
        for index,(task_id,outcome) in enumerate(zip(tasks,outcomes,strict=True)):
            if index:add_task(application,active,factory,task_id,graph)
            metrics=['category'] if outcome=='excluded' else ['completion','category','abandonment']
            grant(application,active,'grant:'+task_id,task_id=task_id,metrics=metrics)
            if outcome=='completed':complete_task(application,active,repository,graph,task_id=task_id)
            elif outcome=='canceled':cancel_task(application,active,task_id)
            elif outcome not in ('unknown','excluded'):raise AssertionError('unsupported genuine outcome')
            collect(application,active,factory,'collect:'+task_id,task_id=task_id)
        yield application,active,factory,repository,tasks,base,manager


def validated_artifact(artifact_type,task_id,snapshot_digest,baselines,*,physical_body=None):
    """Public manifest and artifact validators bind real synthetic body bytes."""
    from tests.support.wp04a_artifacts import (loaded_golden,manifest_document,artifact_record,
        IDENTITY_PROJECTION,LOGICAL_BODY_MANIFEST_SCHEMA,ARTIFACT_RECORD_SCHEMA)
    from graph_engineering.core.artifacts import ArtifactValidator,LogicalBodyManifest
    from graph_engineering.core.contracts.digest import semantic_digest,raw_digest
    original,manifest,contracts,schemas,context,validation=loaded_golden(artifact_type)
    semantics=original['semantic_fields']
    if physical_body is not None:
        _body,document=manifest_document(original['artifact_id'],semantics)
        document['physical_body_digest']=raw_digest(physical_body)
        entry=document['entries'][0];entry['selector']['end']=len(physical_body)
        entry['extracted_body_digest']=raw_digest(physical_body)
        entry['entry_digest']=semantic_digest({k:v for k,v in entry.items() if k!='entry_digest'},
            contract_type='urn:gew:contract:logical-body-entry',projection_id=IDENTITY_PROJECTION,schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
        document['manifest_digest']=semantic_digest({k:v for k,v in document.items() if k!='manifest_digest'},
            contract_type='urn:gew:contract:logical-body-manifest',projection_id=IDENTITY_PROJECTION,schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
        manifest=LogicalBodyManifest.from_dict(document,physical_body,schema_registry=schemas,context=context)
    record,validation=artifact_record(artifact_type,contracts,manifest,semantics)
    record['task_id']=task_id;record['baseline_digests']=dict(baselines)
    baseline=next(iter(baselines.values()))
    for item in record['input_refs']:
        item.update(task_id=task_id,digest=snapshot_digest,baseline_digest=baseline)
    for item in record['target_refs']:item['task_id']=task_id
    validation.update(schema_registry=schemas,expected_task_id=task_id,expected_baselines=dict(baselines))
    for item in validation['known_inputs'].values():item.update(task_id=task_id,digest=snapshot_digest,baseline_digest=baseline)
    for item in validation['known_targets'].values():item['task_id']=task_id
    record['artifact_digest']=semantic_digest({k:v for k,v in record.items() if k!='artifact_digest'},
        contract_type='urn:gew:contract:artifact-record',projection_id=IDENTITY_PROJECTION,schema_id=ARTIFACT_RECORD_SCHEMA)
    return ArtifactValidator.load(record,context=context,**validation)


def complete_task(application,active,repository,graph,*,task_id='task:security-synthetic',reviewer=None,
                  candidate_body=None,expect_completion=True):
    """Real runner validation, LogicalBodyManifest, ArtifactValidator and CompletionGate."""
    from tests.support.security_bootstrap import invoke
    from tests.contract.test_wp02_graph import graph_schemas,loop_budgets,work_context
    from graph_engineering.application.runner import NodeCandidate,ValidationResult,ReviewResult,Finding
    from graph_engineering.core.contracts import parse_json
    from graph_engineering.core.graph.state import TaskCommand
    from graph_engineering.application.completion import CompletionGate
    view=repository.load(task_id)['domain'];baselines={ref['kind']:ref['digest'] for ref in view['baseline_refs']}
    class AgentOutput:
        def execute(self,node,*,run_id,attempt,runtime):
            body=(json.dumps(dict(schema_version='1.0.0',enabled=True,value=attempt)).encode()
                  if candidate_body is None else candidate_body)
            return NodeCandidate(body,'sha256:'+hashlib.sha256(body).hexdigest(),'author:'+node.node_id,
                                 {'from_output':json.loads(body)})
    class Validator:
        count=0
        def validate(self,node,candidate,*,context):
            failures=graph_schemas().validate(node.output_schema_ref,parse_json(candidate.body,context=context,source_id='synthetic-node-output'),context)
            if failures:return ValidationResult(False,('schema-rejected',),'candidate',Finding(
                'finding:'+node.node_id,'major',('schema-rejected',),'produce a schema-valid candidate',
                'validate the revised bytes',node.node_id))
            artifact=validated_artifact('implementation',task_id,view['snapshot_digest'],baselines,physical_body=candidate.body)
            assert artifact.artifact_id and artifact.body['logical_body_ref']['extracted_body_digest']=='sha256-raw-v1:'+hashlib.sha256(candidate.body).hexdigest()
            self.count+=1
            return ValidationResult(True,('schema-validation',artifact.artifact_digest),'validated')
    class Reviewer:
        def review(self,node,candidate,validation,*,runtime):
            return ReviewResult('PASS','reviewer:'+node.node_id)
    revision=view['task_revision']
    invoke(active,lambda runtime:application.execute(task_id,TaskCommand('run',revision,
        {'compatibility_evidence_ref':'evidence:compatible','lease_plan_ref':'lease-plan:none'}),runtime),'learning:run:'+task_id)
    context=work_context();runner=application.create_runner(repository._objects,
        loop_budgets(schemas=graph_schemas(),context=context),context=context)
    validator=Validator()
    result=invoke(active,lambda runtime:runner.run_until_stable(task_id,runtime,graph,AgentOutput(),validator,
        Reviewer() if reviewer is None else reviewer,max_steps=40),'learning:runner:'+task_id)
    if not expect_completion:
        assert result.status=='stable' and result.lifecycle=='awaiting_human' and validator.count==0,result
        return result
    if result.status!='completion_ready':
        Path('/tmp/gew-bootstrap-completion-diagnostic.json').write_text(json.dumps(repository.load(task_id),default=str))
        raise AssertionError(result)
    assert validator.count>=len(graph.nodes)
    invoke(active,lambda runtime:runner.begin_completion(task_id,runtime,graph),'learning:begin-completion:'+task_id)
    snapshot=invoke(active,lambda runtime:application.runtime_show(task_id,runtime),'learning:view:'+task_id).snapshot
    candidate=validated_artifact('candidate-review',task_id,snapshot.snapshot_digest,baselines)
    completion=validated_artifact('completion-record',task_id,snapshot.snapshot_digest,baselines)
    evidence=dict(task_id=task_id,snapshot_digest=snapshot.snapshot_digest,graph_digest=graph.digest,
        project_scope_digest=snapshot.project_scope_ref['digest'],baseline_digests=sorted(baselines.values()),
        authority_refs=sorted(snapshot.authorities),required_node_ids=sorted(graph.completion_nodes),
        passed_node_ids=sorted(graph.nodes),must_requirement_ids=['FR-13'],traced_requirement_ids=['FR-13'],
        required_gate_ids=['tests'],passed_gate_ids=['tests'],candidate_review=dict(artifact_id=candidate.artifact_id,
        artifact_digest=candidate.artifact_digest,verdict='PASS',author_id=candidate.body['author_id'],
        reviewer_id=candidate.body['reviewer_id'],trust='independently-reviewed'),required_external_action_ids=[],
        verified_external_action_ids=[],target_binding_ids=[],matched_target_binding_ids=[],open_blocking_finding_ids=[],
        unknown_side_effect_refs=[],live_node_lease_ids=[],live_tool_lease_ids=[],evidence_task_id=task_id,
        evidence_snapshot_digest=snapshot.snapshot_digest,evidence_baseline_digests=sorted(baselines.values()),
        completion_record=dict(artifact_id=completion.artifact_id,artifact_digest=completion.artifact_digest,
        status='accepted_for_next_node',snapshot_digest=snapshot.snapshot_digest))
    gate=CompletionGate(context=context)
    decision=invoke(active,lambda runtime:application.complete(gate,task_id,runtime,graph,evidence,
        candidate_review_record=candidate,completion_record=completion),'learning:complete:'+task_id)
    assert decision.passed,decision.failures
    assert repository.load(task_id)['domain']['lifecycle']=='completed'
    return decision


@contextmanager
def concurrent_revoke(base,task_id,*,revoke_first=False):
    """Real independent runtime, command scope and SQLite writer behind a barrier."""
    import os,select
    import graph_engineering
    from tests.support.security_bootstrap import _TASK_BOOTSTRAP_CHILD
    from tests.support.source_checkout_attestation import CONTROL_OPTION
    # Reuse only the setup before the bootstrap operation; the writer calls the learning service.
    setup=_TASK_BOOTSTRAP_CHILD[:_TASK_BOOTSTRAP_CHILD.index('        if mode==')]
    action='''
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.storage.security import SecurityStateRepository
        from graph_engineering.core.security.retention import RetentionPolicyRegistry
        from tests.support.security_bootstrap import installed_bundle
        from tests.support.learning_reports import learning_call,learning_request
        _ctx,_desc,_resources,documents,registries=installed_bundle()
        issuer=SecurityContextIssuer(SecurityStateRepository(repository._factory),
            schema_registry=registries['security-schema-registry-v1'],context=context)
        retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
            schema_registry=issuer._schemas,context=context,runtime=issuer.runtime)
        application=TaskApplication(repository,repository,application._leases,schema_registry=schemas,context=context,
            learning_security_issuer=issuer,learning_retention_registry=retention)
        print('READY',flush=True)
        assert sys.stdin.readline().strip()=='GO'
        print('BEGIN',flush=True)
        if mode=='revoke-first':
            def barrier(point):
                if point=='learning.before_commit':
                    print('LOCKED',flush=True)
                    assert sys.stdin.readline().strip()=='COMMIT'
            repository._fault=barrier
        learning_call(application,active,learning_request('revoke_learning','process:revoke',request,expected_generation=1))
        print('DONE',flush=True)
'''
    probe=Path(sys.prefix)/'bin/security-bootstrap-learning-writer';probe.write_text(setup+action);probe.chmod(0o700)
    module_path=Path(graph_engineering.__file__).resolve()
    source=graph_engineering._source_checkout_root(module_path) or module_path.parents[1]
    process=subprocess.Popen([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
        str(probe),str(source),str(base),'revoke-first' if revoke_first else 'none','0','none',task_id,str(ROOT)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    def line(expected):
        if not select.select([process.stdout],[],[],20)[0] or process.stdout.readline().strip()!=expected:
            raise AssertionError('learning writer barrier failed')
    def contend():
        process.stdin.write('GO\n');process.stdin.flush();line('BEGIN')
        assert not select.select([process.stdout],[],[],.05)[0] and process.poll() is None
    def finish_first(before_commit=lambda:None):
        process.stdin.write('GO\n');process.stdin.flush();line('BEGIN');line('LOCKED')
        before_commit()
        process.stdin.write('COMMIT\n');process.stdin.flush();line('DONE')
        assert process.wait(timeout=20)==0
    try:
        line('READY');yield finish_first if revoke_first else contend
        if not revoke_first:line('DONE');assert process.wait(timeout=20)==0
    finally:
        if process.poll() is None:process.kill()
        _out,error=process.communicate(timeout=5)
        if error:Path('/tmp/gew-learning-writer-diagnostic.txt').write_text(error)


@contextmanager
def concurrent_report(base,task_ids,request_id):
    """A separately issued reporting process must wait behind the revocation writer."""
    import select
    import graph_engineering
    from tests.support.security_bootstrap import _TASK_BOOTSTRAP_CHILD
    from tests.support.source_checkout_attestation import CONTROL_OPTION
    setup=_TASK_BOOTSTRAP_CHILD[:_TASK_BOOTSTRAP_CHILD.index('        if mode==')]
    action='''
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.storage.security import SecurityStateRepository
        from graph_engineering.core.security.retention import RetentionPolicyRegistry
        from graph_engineering.core.learning import LearningError
        from tests.support.security_bootstrap import installed_bundle
        from tests.support.learning_reports import report
        _ctx,_desc,_resources,documents,registries=installed_bundle()
        issuer=SecurityContextIssuer(SecurityStateRepository(repository._factory),
            schema_registry=registries['security-schema-registry-v1'],context=context)
        retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
            schema_registry=issuer._schemas,context=context,runtime=issuer.runtime)
        application=TaskApplication(repository,repository,application._leases,schema_registry=schemas,context=context,
            learning_security_issuer=issuer,learning_retention_registry=retention)
        arguments=json.loads(request)
        print('READY',flush=True)
        assert sys.stdin.readline().strip()=='GO'
        print('BEGIN',flush=True)
        try:report(application,active,arguments['request_id'],task_ids=arguments['tasks'])
        except LearningError as error:print(json.dumps(dict(refused=str(error))),flush=True)
        else:raise AssertionError('revoked report was published')
'''
    probe=Path(sys.prefix)/'bin/security-bootstrap-learning-reader';probe.write_text(setup+action);probe.chmod(0o700)
    module_path=Path(graph_engineering.__file__).resolve()
    source=graph_engineering._source_checkout_root(module_path) or module_path.parents[1]
    process=subprocess.Popen([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
        str(probe),str(source),str(base),'report','0','none',json.dumps(dict(tasks=task_ids,request_id=request_id)),str(ROOT)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    def line():
        if not select.select([process.stdout],[],[],20)[0]:raise AssertionError('report process barrier timeout')
        return process.stdout.readline().strip()
    def contend():
        process.stdin.write('GO\n');process.stdin.flush();assert line()=='BEGIN'
        assert not select.select([process.stdout],[],[],.05)[0] and process.poll() is None
    results=[]
    try:
        assert line()=='READY';yield contend,results
        results.append(json.loads(line()));assert process.wait(timeout=20)==0
    finally:
        if process.poll() is None:process.kill()
        _out,error=process.communicate(timeout=5)
        if error:Path('/tmp/gew-learning-reader-diagnostic.txt').write_text(error)


def learning_restart_probe(base,task_ids):
    """A new process attaches the real repository and attempts retained operations."""
    import graph_engineering
    from tests.support.security_bootstrap import _TASK_BOOTSTRAP_CHILD
    from tests.support.source_checkout_attestation import CONTROL_OPTION
    setup=_TASK_BOOTSTRAP_CHILD[:_TASK_BOOTSTRAP_CHILD.index('        if mode==')]
    action='''
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.storage.security import SecurityStateRepository
        from graph_engineering.core.security.retention import RetentionPolicyRegistry
        from graph_engineering.core.learning import LearningError
        from tests.support.security_bootstrap import installed_bundle
        from tests.support.learning_reports import learning_call,learning_request,report,collect
        _ctx,_desc,_resources,documents,registries=installed_bundle()
        issuer=SecurityContextIssuer(SecurityStateRepository(repository._factory),
            schema_registry=registries['security-schema-registry-v1'],context=context)
        retention=RetentionPolicyRegistry.from_dict(documents['config/security/retention-policies-v1.json'],
            schema_registry=issuer._schemas,context=context,runtime=issuer.runtime)
        application=TaskApplication(repository,repository,application._leases,schema_registry=schemas,context=context,
            learning_security_issuer=issuer,learning_retention_registry=retention)
        tasks=json.loads(request)
        with bound.open('doctor') as connection:
            before={table:connection.execute('SELECT * FROM '+table+' ORDER BY task_id').fetchall()
                    for table in ('pmf_consents','pmf_aggregates','pmf_owner_context','pmf_tombstones')}
        assert not before['pmf_aggregates'] and not before['pmf_owner_context']
        assert {row[0] for row in before['pmf_tombstones'] if row[2]=='purged'}==set(tasks)
        refusals=[]
        for task in tasks:
            for operation in (lambda:report(application,active,'restart:report:'+task,task_ids=tasks),
                              lambda:collect(application,active,bound,'collect:'+task,task_id=task)):
                try:operation()
                except LearningError as error:refusals.append(str(error))
                else:raise AssertionError('purged learning resurrected')
        with bound.open('doctor') as connection:
            after={table:connection.execute('SELECT * FROM '+table+' ORDER BY task_id').fetchall() for table in before}
        assert before==after
        print(json.dumps(dict(refusals=refusals,tombstones=before['pmf_tombstones'],unchanged=True)))
'''
    probe=Path(sys.prefix)/'bin/security-bootstrap-learning-restart';probe.write_text(setup+action);probe.chmod(0o700)
    module_path=Path(graph_engineering.__file__).resolve()
    source=graph_engineering._source_checkout_root(module_path) or module_path.parents[1]
    child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}',
        str(probe),str(source),str(base),'restart','0','none',json.dumps(task_ids),str(ROOT)],
        capture_output=True,text=True,timeout=30)
    if child.returncode:
        Path('/tmp/gew-learning-restart-diagnostic.txt').write_text(child.stderr)
        raise AssertionError('learning restart refusal probe failed')
    return json.loads(child.stdout)


def learning_variant_probe(variant_id,code,*arguments):
    """Fresh attested synthetic source configuration; every engine byte is unchanged."""
    from tests.support.source_checkout_attestation import SOURCE_FILES,CONTROL_OPTION,issue_source_checkout_attestation
    variant=next(v for v in document('tests/fixtures/learning-report-config-variants-v1.json')['variants']
                 if v['variant_id']==variant_id)
    with tempfile.TemporaryDirectory(prefix='gew-learning-variant-') as directory:
        base=Path(directory).resolve();source=base/'source';source.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,source/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in SOURCE_FILES:
            target=source/relative
            if not target.exists():target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
        for filename,key in (('config/learning/learning-policy-v3.json','policy_patch'),
                             ('config/learning/learning-experiments-v2.json','experiments_patch')):
            path=source/filename;value=json.loads(path.read_bytes());value.update(copy.deepcopy(variant[key]))
            path.write_text(json.dumps(value,indent=2)+'\n')
        engine={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                for part in ('core','application','storage','adapters') for p in (ROOT/part).rglob('*.py')}
        assert all(hashlib.sha256((source/p).read_bytes()).hexdigest()==digest for p,digest in engine.items())
        control=base/'control';issue_source_checkout_attestation(source,control)
        probe=Path(sys.prefix)/'bin/security-bootstrap-learning-variant'
        preamble="import pathlib,sys,json\nroot=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root/p) for p in ('core','application','storage','adapters')]+[sys.argv[2]]\n"
        postamble="\nfor name,module in tuple(sys.modules.items()):\n if name=='graph_engineering' or name.startswith('graph_engineering.'):\n  origin=getattr(module,'__file__',None)\n  if origin is not None:assert pathlib.Path(origin).resolve().is_relative_to(root),(name,origin)\n"
        probe.write_text(preamble+code+postamble);probe.chmod(0o700)
        child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={control}',str(probe),str(source),str(ROOT),
                              *map(str,arguments),'--security-bootstrap-fixture'],capture_output=True,text=True,timeout=90)
        if child.returncode:
            Path('/tmp/gew-learning-variant-diagnostic.txt').write_text(child.stderr)
            raise AssertionError('attested learning variant probe failed')
        return json.loads(child.stdout)


def attest_learning_variant(variant_id):
    """Re-attest only this test's private SOURCE checkout after a valid data change."""
    import graph_engineering
    from tests.support.source_checkout_attestation import CONTROL_OPTION,issue_source_checkout_attestation
    source=graph_engineering._source_checkout_root(Path(graph_engineering.__file__).resolve())
    assert source is not None and source.resolve()!=ROOT.resolve()
    variant=next(v for v in document('tests/fixtures/learning-report-config-variants-v1.json')['variants']
                 if v['variant_id']==variant_id)
    engines={p:hashlib.sha256(p.read_bytes()).hexdigest()
             for part in ('core','application','storage','adapters') for p in (source/part).rglob('*.py')}
    for filename,key in (('config/learning/learning-policy-v3.json','policy_patch'),
                         ('config/learning/learning-experiments-v2.json','experiments_patch')):
        path=source/filename;value=json.loads(path.read_bytes());value.update(copy.deepcopy(variant[key]))
        path.write_text(json.dumps(value,indent=2)+'\n')
    issue_source_checkout_attestation(source,Path(sys._xoptions[CONTROL_OPTION]))
    assert all(hashlib.sha256(p.read_bytes()).hexdigest()==digest for p,digest in engines.items())


def document(path):
    return json.loads((ROOT / path).read_bytes())


def contract_report():
    """Schema-only example, deliberately not genuine cohort acceptance evidence."""
    policy = document('config/learning/learning-policy-v3.json')
    experiments = document('config/learning/learning-experiments-v2.json')
    configured = experiments['experiments'][0]['hypotheses'][0]
    suggestion = next(row for row in experiments['suggested_experiments']
                      if row['experiment_id'] == configured['next_experiment_ids']['insufficient-data'])
    rule = policy['rules'][0]
    return dict(schema_version='1.2.0', policy_digest='sha256:'+'1'*64,
                experiment_id='synthetic-default', cohort_digest='sha256:'+'2'*64,
                cohort_vector=[], observations=[], eligible_count=0, unknown_count=0, excluded_count=0,
                rules=[dict(rule_id=rule['rule_id'], metric_id=rule['metric_id'],
                            predicate={k:rule[k] for k in ('comparator','numerator','denominator','min_samples')},
                            numerator=0, denominator=0, unknown_count=0, excluded_count=0,
                            counter_evidence_refs=[], verdict='insufficient-data')],
                hypotheses=[dict(hypothesis_id=configured['hypothesis_id'], required_rule_ids=copy.copy(configured['required_rule_ids']),
                                 verdict='insufficient-data', next_experiment_ref=copy.copy(suggestion), counter_evidence_refs=[])])


_CONFIG_PROBE = r'''
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
sys.path[:0]=[str(root/part) for part in ('core','application','storage','adapters')]
from graph_engineering.application.learning import LearningPolicyLoader
from graph_engineering.core.learning import LearningError
loader=LearningPolicyLoader.from_installation()
assert pathlib.Path(sys.modules['graph_engineering.application.learning'].__file__).is_relative_to(root)
value=loader.experiment_document()
loader.validate_experiment_document(value)
assert set(value['experiments'][0]['rule_ids'])==set(row['rule_id'] for row in loader.policy_document()['rules'])
value['experiments'][0]['hypotheses'][0]['required_rule_ids']=value['experiments'][0]['rule_ids'][:1]
try:
    loader.validate_experiment_document(value)
except LearningError as error:
    result={'complete_valid':True,'coverage_error':str(error)}
else:
    result={'complete_valid':True,'coverage_error':None}
print(json.dumps(result))
'''


def installed_coverage_probe(*, remove_coverage_guard=False):
    """Fresh exact resource attestation, with a separate negative code mutant.

    The genuine configuration case preserves every engine byte. The mutant is
    explicitly a test fault and never an accepted configuration variation.
    """
    from tests.support.source_checkout_attestation import issue_source_checkout_attestation, SOURCE_FILES, CONTROL_OPTION
    variant=next(row for row in document('tests/fixtures/learning-report-config-variants-v1.json')['variants']
                 if row['variant_id']=='two-known-rules')
    with tempfile.TemporaryDirectory(prefix='gew-learning-config-') as directory:
        root=Path(directory).resolve();checkout=root/'source';checkout.mkdir(mode=0o700)
        for part in ('core','application','storage','adapters'):
            shutil.copytree(ROOT/part,checkout/part,ignore=shutil.ignore_patterns('__pycache__'))
        for relative in SOURCE_FILES:
            source=ROOT/relative;target=checkout/relative
            if not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        for filename,patch in (('config/learning/learning-policy-v3.json',variant['policy_patch']),
                               ('config/learning/learning-experiments-v2.json',variant['experiments_patch'])):
            target=checkout/filename;value=json.loads(target.read_bytes());value.update(copy.deepcopy(patch))
            target.write_text(json.dumps(value,indent=2)+'\n')
        for part in ('core','application','storage','adapters'):
            for source in (ROOT/part).rglob('*.py'):
                if '__pycache__' not in source.parts:
                    assert hashlib.sha256(source.read_bytes()).digest()==hashlib.sha256((checkout/source.relative_to(ROOT)).read_bytes()).digest()
        if remove_coverage_guard:
            target=checkout/'application/graph_engineering/application/learning.py';text=target.read_text()
            guard="            if covered!=rules:raise LearningError('LEARNING_EXPERIMENT')"
            assert text.count(guard)==1;target.write_text(text.replace(guard,'            pass'))
        control=root/'control';issue_source_checkout_attestation(checkout,control)
        child=subprocess.run([sys.executable,'-B','-X',f'{CONTROL_OPTION}={control}','-c',_CONFIG_PROBE,str(checkout)],
                             cwd=checkout,capture_output=True,text=True,timeout=30)
        if child.returncode:raise AssertionError('isolated installed configuration probe failed')
        return json.loads(child.stdout)
