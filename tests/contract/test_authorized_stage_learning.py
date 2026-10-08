"""Versioned closed contracts and installation-owned authorization provenance."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

from graph_engineering.application.learning import LearningPolicyLoader
from graph_engineering.core.learning import LearningError
from tests.integration.test_authorized_stage_learning import bound_learning,collect,derived,grant,report
from tests.support.action_authority import registration_stack
from tests.unit.test_action_authority import decision

ROOT=Path(__file__).resolve().parents[2]


class AuthorizedStageContractTests(unittest.TestCase):
    def test_policy_v11_closed(self):
        loader=LearningPolicyLoader.from_installation();policy=loader.policy_document()
        self.assertEqual(policy['schema_version'],'1.1.0');loader.validate_policy_document(policy)
        for patch in ({'extra':'canary'},{'authorized_action_categories':{}},
                      {'authorized_action_categories':{'commit':'Bad Code'}},
                      {'authorized_action_categories':{f'kind{i}':'category' for i in range(65)}}):
            with self.subTest(patch=list(patch)),self.assertRaises(LearningError):loader.validate_policy_document({**policy,**patch})

    def test_record_v11_closed(self):
        loader=LearningPolicyLoader.from_installation()
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);collect(service,active)
            record=derived(service);loader.validate_record(record)
            with self.assertRaises(LearningError):loader.validate_record({**record,'raw_prompt':'CANARY'})
            for patch in ({'ordinal':True},{'activation_epoch':0},{'extra':'CANARY'}):
                bad=copy.deepcopy(record);bad['authorization_source']['watermark'].update(patch)
                with self.assertRaises(LearningError):loader.validate_record(bad)
            old=copy.deepcopy(record);old.pop('authorization_source');old['schema_version']='1.0.0';loader.validate_record(old)
            old['authorization_source']=None
            with self.assertRaises(LearningError):loader.validate_record(old)

    def test_report_v11_source_vector(self):
        from graph_engineering.storage.codec import canonical_json
        loader=LearningPolicyLoader.from_installation()
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);collect(service,active)
            value=report(service,active);loader.validate_report(value)
            self.assertEqual(value['cohort_vector'][0]['authorization_source'],value['observations'][0]['authorization_source'])
            self.assertEqual(value['cohort_digest'],'sha256:'+hashlib.sha256(canonical_json(value['cohort_vector']).encode()).hexdigest())
            for key in ('window_digest','category_mapping_digest','baseline_digest','prd_revision'):
                altered=copy.deepcopy(value['cohort_vector']);altered[0]['authorization_source'][key]=0
                self.assertNotEqual('sha256:'+hashlib.sha256(canonical_json(altered).encode()).hexdigest(),value['cohort_digest'])
            bad=copy.deepcopy(value);bad['cohort_vector'][0]['authorization_source']['extra']='CANARY'
            with self.assertRaises(LearningError):loader.validate_report(bad)

    def test_input_v10_unchanged(self):
        from tests.contract.test_wp09_learning_contracts import LearningContractTests
        LearningContractTests('test_six_operations').test_six_operations()
        loader=LearningPolicyLoader.from_installation()
        self.assertEqual(loader._schemas['input']['$id'],'urn:gew:schema:learning-input:1.0.0')

    def test_receipt_v10_unchanged(self):
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,request,_base):
            approved=service.authorize(active,request)
            with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                before=conn.execute('SELECT * FROM action_authority_events ORDER BY request_id,sequence').fetchall()
            service._manager.initialize_action_authority_order_storage()
            self.assertEqual(service.authorize(active,request),approved)
            self.assertEqual(approved['receipt']['schema_version'],'1.0.0')
            with service._scope() as (ledger,_journal,_issuer),ledger.factory.open('doctor') as conn:
                self.assertEqual(conn.execute('SELECT * FROM action_authority_events ORDER BY request_id,sequence').fetchall(),before)

    def test_old_policy_compatibility(self):
        loader=LearningPolicyLoader.from_installation();old=json.loads((ROOT/'config/learning/learning-policy-v1.json').read_text())
        loader.validate_policy_document(old);self.assertNotIn('authorized_action_categories',old)
        self.assertEqual(loader._schemas['record-old']['$id'],'urn:gew:schema:learning-record:1.0.0')
        self.assertEqual(loader._schemas['report-old']['$id'],'urn:gew:schema:learning-report:1.0.0')

    def test_resource_closure(self):
        from graph_engineering import _learning_installation_resources
        from tests.support.source_checkout_attestation import SOURCE_FILES
        resources=_learning_installation_resources();self.assertEqual(len(resources),10)
        paths=('config/learning/learning-policy-v2.json','config/contracts/schemas/learning-record-1.1.0.json',
               'config/contracts/schemas/learning-report-1.1.0.json','config/contracts/schemas/learning-policy-1.1.0.json')
        for path in paths:
            self.assertIn(path,SOURCE_FILES);self.assertIn((ROOT/path).read_bytes(),resources)
        import tomllib
        project=tomllib.loads((ROOT/'pyproject.toml').read_text())
        self.assertTrue(all(path in project['tool']['gew']['build']['owned-root-files'] for path in paths))

    def test_unknown_component_version(self):
        for damage in ("UPDATE schema_versions SET version='9.0' WHERE component='action-authority-order'",
                       "DELETE FROM schema_versions WHERE component='action-authority-order'"):
            with self.subTest(damage=damage),registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,base):
                service._manager.initialize_action_authority_order_storage()
                with base._for_maintenance().open('migration') as conn,conn.transaction():conn.execute(damage)
                with self.assertRaises(LearningError):grant(service,active)
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,_base):
            grant(service,active);collect(service,active)
            self.assertEqual(derived(service)['metrics']['authorized_stage']['availability'],'unavailable')

    def test_experiment_schema_compatibility(self):
        loader=LearningPolicyLoader.from_installation();experiment=loader.experiment_document()
        self.assertEqual(experiment['schema_version'],'1.0.0');loader.validate_experiment_document(experiment)
        with self.assertRaises(LearningError):loader.validate_policy_document(experiment)
        bad={**experiment,'authorized_action_categories':{'commit':'commit'}}
        with self.assertRaises(LearningError):loader.validate_experiment_document(bad)

    def test_mapping_change_requires_regrant(self):
        from tests.integration.test_authorized_stage_learning import persisted
        with registration_stack(lambda r,o,l:decision(r)) as (service,active,_request,_base):
            service._manager.initialize_action_authority_order_storage();grant(service,active);collect(service,active);report(service,active)
            before=persisted(service);original=LearningPolicyLoader.policy_document
            def changed(loader):
                value=original(loader);value['authorized_action_categories']['commit']='new-category';return value
            with mock.patch.object(LearningPolicyLoader,'policy_document',changed),self.assertRaises(LearningError):report(service,active)
            self.assertEqual(persisted(service),before)
