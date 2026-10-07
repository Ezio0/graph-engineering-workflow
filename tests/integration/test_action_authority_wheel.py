"""Isolated installed-wheel runtime ports and local approval separation."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
import zipfile

from tests.integration.test_wp07_runtime_parity import FIXTURE,adapter_document,compatibility,raw_input
from tests.unit.test_action_authority import challenge


_PROBE = r'''
import hashlib,json,pathlib,sys
import graph_engineering
from graph_engineering import _installation_owned_resources
from graph_engineering.core.contracts.resources import ResourceProfile,CostSchedule,WorkContext
from graph_engineering.core.runtime import RuntimeResourcePolicy,RuntimeResourceGuard,RuntimeCompatibilityRequest,runtime_record_digest,HumanDecisionRequest
from graph_engineering.core.action_authority import AuthorityChallenge,ActionHumanRequestV1,ActionHumanDecisionV1,ActionAuthorityError,signed
from graph_engineering.adapters.runtime_locator import RunningDistributionProbe,ExecutableLocator
from graph_engineering.adapters.runtime_adapters import RuntimeAdapterFactory,RuntimeInvocationPorts
from graph_engineering.application.runtime import RuntimeSession,RuntimeSessionError
from graph_engineering.storage.action_authority import installed_policy
root=pathlib.Path(sys.argv[1]);data=json.loads((root/'input.json').read_text())
assert pathlib.Path(graph_engineering.__file__).is_relative_to(pathlib.Path(sys.prefix))
assert installed_policy().max_requests==1024
profile,schedule=_installation_owned_resources(tuple('config/contracts/'+n for n in (
    'resource-profile-v1.json','cost-schedule-v1.json')))
policy=(root/'contracts/runtime-resource-policy-v1.json').read_bytes()
def guard():
    return RuntimeResourceGuard(RuntimeResourcePolicy.from_dict(json.loads(policy)),
        WorkContext(ResourceProfile.from_dict(json.loads(profile)),CostSchedule.from_dict(json.loads(schedule))))
running=RunningDistributionProbe().probe('graph-engineering-workflow')
locator=dict(schema_version='1.0',executable=running.executable,package_origin=running.package_origin,
    executable_digest='sha256-raw-v1:'+hashlib.sha256(pathlib.Path(running.executable).read_bytes()).hexdigest(),
    release_manifest_digest=data['cells'][0]['configuration']['release_manifest_digest'],expected_core_version=running.distribution_version,
    distribution_name=running.distribution_name,distribution_version=running.distribution_version,distribution_origin=running.distribution_origin)
locator_path=root/'locator.json';locator_path.write_text(json.dumps(locator));locator_path.chmod(0o600)
verified=ExecutableLocator(guard(),running).resolve(locator_path)
def make_request(session,task_id='task:wheel'):
    body={k:v for k,v in data['challenge'].items() if k!='challenge_digest'}
    body.update(task_id=task_id,owner_id=session.proof.owner_id,runtime_kind=session.capabilities.runtime_kind,
        runtime_lineage_id=session.proof.lineage_id)
    ch=AuthorityChallenge.from_dict(signed('challenge',body))
    return ActionHumanRequestV1.from_dict(signed('request',dict(schema_version='1.0.0',challenge=ch.to_dict(),
        invocation_nonce='a'*64,invocation_generation=1,session_id=session.proof.session_id,
        runtime_lineage_id=session.proof.lineage_id,dispatched_at_ns='1791244800000000001')))
def decision(req,owner,lineage):
    ch=req.challenge
    assert owner.owner_id==ch.owner_id and lineage.lineage_id==req.runtime_lineage_id
    return ActionHumanDecisionV1.from_dict(signed('decision',dict(schema_version='1.0.0',request_id=ch.request_id,
        task_id=ch.task_id,owner_id=ch.owner_id,decision_kind='action-authority',challenge_digest=ch.challenge_digest,
        request_digest=req.request_digest,invocation_nonce=req.invocation_nonce,invocation_generation=req.invocation_generation,
        session_id=req.session_id,runtime_lineage_id=req.runtime_lineage_id,status='approved',decision_ref='decision:wheel')))
def unavailable(*args):raise RuntimeError('unused port')
if data['mode']=='parity':
    for cell in data['cells']:
        configured=cell['configuration'];configured['capabilities']=sorted(set(configured['capabilities'])|{'human.action-decision.v1'})
        configured['configuration_digest']=runtime_record_digest('runtime-configuration',{k:v for k,v in configured.items() if k!='configuration_digest'})
        ports=RuntimeInvocationPorts(lambda task,owner,lineage:dict(task_id=task,owner_id=owner.owner_id,
            runtime_kind=lineage.runtime_kind,runtime_lineage_id=lineage.lineage_id),
            unavailable,unavailable,unavailable,unavailable,unavailable,unavailable,decision)
        factory=RuntimeAdapterFactory(guard());create=factory.codex if configured['runtime_kind']=='codex' else factory.hermes
        adapter=create(configured,verified,ports)
        with RuntimeSession.establish(adapter,cell['input'],RuntimeCompatibilityRequest.from_dict(cell['compatibility'])) as session:
            req=make_request(session)
            result=session.request_action_decision(req)
            result.require_request(req)
            assert result.status=='approved'
            try:session.request_action_decision(req.to_dict())
            except ActionAuthorityError:pass
            else:raise AssertionError('detached request accepted')
else:
    from graph_engineering.adapters.owner_turn_local import LocalOwnerTurnRuntime
    from graph_engineering.application.owner_turns import OwnerTurnRequest
    from graph_engineering.storage.connection import RepositoryDoctor
    from unittest import mock
    import platform
    resource_root=root/'contracts'
    cell=data['cells'][0];configured=cell['configuration']
    local=json.loads((resource_root/'runtime-local-port-policy-v1.json').read_text())
    local['human_status']='approved';local['policy_digest']=runtime_record_digest('local-runtime-port-policy',{k:v for k,v in local.items() if k!='policy_digest'})
    configured['runtime_local_port_policy_digest']=local['policy_digest']
    configured['capabilities']=sorted(set(configured['capabilities'])|{'human.action-decision.v1'})
    configured['configuration_digest']=runtime_record_digest('runtime-configuration',{k:v for k,v in configured.items() if k!='configuration_digest'})
    def mount(path):
        system=platform.system();fs='apfs' if system=='Darwin' else 'ext4'
        return dict(platform=system,mount_point=str(path),filesystem_type=fs,
            mount_options=(fs,'local','rw') if system=='Darwin' else ('rw',),filesystem_identity='synthetic:'+str(path))
    with mock.patch.object(RepositoryDoctor,'_mount_observation',side_effect=mount),LocalOwnerTurnRuntime(
            configuration=configured,executable=verified,guard=guard(),compatibility=RuntimeCompatibilityRequest.from_dict(cell['compatibility']),
            raw_input=cell['input'],repository_root=root/'repository',control_root=root/'control',
            repository_policy_path=resource_root/'repository-policy-v1.json',migration_policy_path=resource_root/'migration-storage-policy-v1.json',
            local_port_policy=local,schema_profile_path=resource_root/'schema-profile-v1.json',
            schema_manifest_path=resource_root/'graph-schema-registry-v1.json',schema_root=resource_root/'schemas') as local_runtime:
        with local_runtime.application._session_factory() as identity:
            owner=identity.proof.owner_id;lineage=identity.proof.lineage_id
        body=dict(schema_version='1.0',turn_id='turn:wheel',operation='create',task_id=None,owner_id=owner,
            runtime_kind=configured['runtime_kind'],runtime_lineage_id=lineage,payload=dict(occurred_at='synthetic',lease_ttl_ns=1000000000))
        result=local_runtime.application.execute(OwnerTurnRequest.from_dict({**body,'request_digest':runtime_record_digest('owner-turn-request',body)}))
        task_id=result['task_id']
        with local_runtime.application._session_factory() as session:
            assert 'human.action-decision.v1' not in session.capabilities.capabilities
            generic=dict(schema_version='1.0',request_id='human:generic',task_id=task_id,owner_id=owner,
                decision_kind='owner-review',decision_payload_ref='payload:synthetic',decision_payload_digest=data['challenge']['snapshot_digest'])
            generic=HumanDecisionRequest.from_dict({**generic,'request_digest':runtime_record_digest('human-decision-request',generic)})
            assert session.request_human(generic).status=='approved'
            try:session.request_action_decision(make_request(session,task_id))
            except RuntimeSessionError:pass
            else:raise AssertionError('local config authorized an action')
        body.update(turn_id='turn:status',operation='status',task_id=task_id,payload={})
        local_runtime.application.execute(OwnerTurnRequest.from_dict({**body,'request_digest':runtime_record_digest('owner-turn-request',body)}))
print('PASS')
'''


class ActionAuthorityWheelTests(unittest.TestCase):
    def _probe(self,mode):
        from scripts import build_backend
        with tempfile.TemporaryDirectory(prefix='gew-action-wheel-') as directory:
            root=pathlib.Path(directory).resolve()
            wheel=root/build_backend.build_wheel(directory)
            environment=root/'environment';venv.EnvBuilder(with_pip=False,symlinks=True).create(environment);environment.chmod(0o700)
            installed=next(environment.glob('lib/python*/site-packages'))
            with zipfile.ZipFile(wheel) as archive:archive.extractall(installed)
            probe=environment/'bin/action-authority-probe';probe.write_text(_PROBE);probe.chmod(0o700)
            data=dict(mode=mode,challenge=challenge().to_dict(),cells=[dict(configuration=adapter_document(cell),
                input=raw_input(cell),compatibility=compatibility(cell).to_dict()) for cell in FIXTURE['cells']])
            (root/'input.json').write_text(json.dumps(data))
            shutil.copytree(pathlib.Path(__file__).resolve().parents[2]/'config/contracts',root/'contracts')
            result=subprocess.run([str(environment/'bin/python'),'-I','-B',str(probe),str(root)],cwd=root,
                capture_output=True,text=True,timeout=120)
            self.assertEqual(result.returncode,0,result.stderr[-4000:])
            self.assertEqual(result.stdout.strip(),'PASS')

    def test_wheel_runtime_port_parity(self):
        self._probe('parity')

    def test_local_config_cannot_approve(self):
        self._probe('local')
