"""Bootstrap contracts; examples here do not issue positive task trust."""
from __future__ import annotations

import copy
import unittest

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.identity import SecurityBinding
from tests.support.security_bootstrap import installed_bundle, raw_hash


def digest(label):
    return semantic_digest({'label': label}, contract_type='urn:gew:contract:bootstrap-test',
                           projection_id='urn:gew:digest-projection:identity:1.0.0',
                           schema_id='urn:gew:schema:bootstrap-test:1.0.0')


class SecurityBootstrapContractTests(unittest.TestCase):
    def test_descriptor_closed(self):
        context, descriptor, resources, _documents, registries = installed_bundle()
        schemas = registries['security-bootstrap-schema-registry-v1']
        schema = 'urn:gew:schema:security-bootstrap:1.0.0'
        self.assertFalse(schemas.validate(schema, descriptor, context))
        self.assertEqual(len(descriptor['resources']), 30)
        self.assertEqual(len(resources), 31)
        self.assertNotIn('config/security/security-bootstrap-v1.json',
                         [row['path'] for row in descriptor['resources']])
        for row in descriptor['resources']:
            self.assertEqual(raw_hash(resources[row['path']]), row['raw_sha256'])
        for mutation in ('extra', 'duplicate', 'self', 'missing', 'bad-hash'):
            bad = copy.deepcopy(descriptor)
            if mutation == 'extra': bad['trust_override'] = {}
            elif mutation == 'duplicate': bad['resources'][1] = bad['resources'][0]
            elif mutation == 'self': bad['resources'][0]['path'] = 'config/security/security-bootstrap-v1.json'
            elif mutation == 'missing': bad['resources'].pop()
            else: bad['resources'][0]['raw_sha256'] = 'invalid'
            self.assertTrue(schemas.validate(schema, bad, context), mutation)

    def test_receipts_closed(self):
        context, _descriptor, _resources, _documents, registries = installed_bundle()
        schemas = registries['security-bootstrap-schema-registry-v1']
        installation = dict(schema_version='1.0.0', origin_installation_id='installation:synthetic',
            origin_repository_id='repository:synthetic', origin_activation_epoch=1,
            **{k: digest(k) for k in ('descriptor_digest', 'resource_vector_digest',
                                     'manifest_digest', 'schema_registry_digest', 'receipt_digest')})
        task = dict(schema_version='1.0.0', task_id='task:synthetic', request_id='request:synthetic',
            initial_task_revision=4, **{k: digest(k) for k in ('request_digest',
            'installation_receipt_digest', 'initial_snapshot_digest', 'initial_state_digest',
            'identity_digest', 'baseline_refs_digest', 'scope_approval_digest', 'receipt_digest')})
        for name, body in (('security-installation-receipt', installation),
                           ('security-task-initialization-receipt', task)):
            schema = f'urn:gew:schema:{name}:1.0.0'
            self.assertFalse(schemas.validate(schema, body, context))
            for field in body:
                bad = copy.deepcopy(body); del bad[field]
                self.assertTrue(schemas.validate(schema, bad, context), field)
            bad = copy.deepcopy(body); bad['authority_digests'] = [digest('unapproved')]
            self.assertTrue(schemas.validate(schema, bad, context))
            bad = copy.deepcopy(body); bad['receipt_digest'] = 'sha256:' + '0' * 64
            self.assertTrue(schemas.validate(schema, bad, context))

    def test_scope_target_projection(self):
        context, _descriptor, _resources, _documents, registries = installed_bundle()
        schemas = registries['security-schema-registry-v1']
        body = dict(schema_version='1.0.0', task_id='task:synthetic', owner_id='owner:synthetic',
            runtime_kind='codex', runtime_lineage_id='lineage:synthetic', scope_id='scope:synthetic',
            scope_digest=digest('scope'), baselines={'prd': digest('prd')},
            snapshot_digest=digest('snapshot'), targets=[dict(target_id='scope:synthetic',
            target_kind='project-scope', canonical_identity='scope:synthetic', target_digest=digest('scope'))])
        body['binding_digest'] = SecurityBinding.digest_document(body)
        schema = 'urn:gew:schema:security-binding:1.0.0'
        self.assertFalse(schemas.validate(schema, body, context))
        for field, value in (('targets', []), ('baselines', {}), ('baselines', {'prd': 'invalid'})):
            bad = copy.deepcopy(body); bad[field] = value
            self.assertTrue(schemas.validate(schema, bad, context))
        with self.assertRaises(ValueError):
            SecurityBinding.from_dict(body, schema_registry=schemas, context=context)

    def test_legacy_resource_bytes_preserved(self):
        _context, _descriptor, resources, _documents, _registries = installed_bundle()
        for path, expected in LEGACY_RESOURCE_HASHES.items():
            self.assertEqual(raw_hash(resources[path]), expected, path)


LEGACY_RESOURCE_HASHES = {'config/security/security-runtime-v1.json': '1ee3c20f2e94ba665a082524d0b2dd45e6cc5c0cffabfa52e964c864b1df4c9e', 'config/contracts/security-schema-registry-v1.json': '746da8cda357b8a469c78ab4017a457e88083ab8bcf4082d7a4a794219f8169b', 'config/contracts/resource-profile-v1.json': '8976f8fa464f06228a488e63346db8f266585b66407cedbaaffe203b43446812', 'config/contracts/cost-schedule-v1.json': 'f6ac2b7d9281358a112aee5ca902d41005c741c291f67176a6a29cefdb06e29f', 'config/contracts/schema-profile-v1.json': '9972a12f35471f542f8a9f8d990e18334a4beadc7cfb97a0388454447fb5eb63', 'config/actions/action-policy-v1.json': '732a04401b31b3c946126ed0b92cd881e3cd64905dfbab297106b300439ef489', 'config/security/disclosure-policy-v1.json': 'c6d1a5b753db5b34e389d8b26eda3c698f48b6d15f2bdcc320d57b9d8c502fea', 'config/security/evidence-policies-v1.json': 'ca61c0c85a4a428100a10c7f424b061c1ed652f63a8b82adedc1a37ee3132fb3', 'config/security/input-safety-policy-v1.json': 'f5383188a4610e1de974c8eda51e4bfe30bc430ccfdfe27e8511da025702db4e', 'config/security/redaction-policy-v1.json': '84f40c8f08c3cefacc50934b27d03acd9c61df060399510e1177fe2f6b6d6527', 'config/security/retention-policies-v1.json': 'b5ffdef6ec736cd56b62f9975e596c7fb2873b6d33c0c7d7adb6f673c6e10600', 'config/contracts/schemas/action-journal-entry-1.0.0.json': 'becb16a537c74de447ec3d9f3ab58bf1598a965796f3490f4c513dc15d722dec', 'config/contracts/schemas/action-policy-1.0.0.json': '9946a9ad46581a966163b0b53d7c55fb7200cf6e35f8736af1fa9654f0093a56', 'config/contracts/schemas/authority-envelope-1.0.0.json': '27bb9a5ef180225851b8aafb131ef1dd7cf4b12763e5c239600c3627e276efbb', 'config/contracts/schemas/data-disclosure-plan-1.0.0.json': '2cbc5d3ad7db8d1dc05e06f3d0fec1874e9a3cd70bbf4abe902b86ffa137486c', 'config/contracts/schemas/disclosure-policy-1.0.0.json': '4f3af7eaa36576ecb1950f6947290605e740fc3fcc3bed61c3b9a58356a17792', 'config/contracts/schemas/disclosure-receipt-1.0.0.json': 'f8f8ae943e04a453dcd09969bbceed58ec32c8e0fac27ed88eafbba6737ffe17', 'config/contracts/schemas/evidence-policy-registry-1.0.0.json': '38add7b1fe501d84ebac258c6b32eef92a921b1922068cf16e11a978bcede3e7', 'config/contracts/schemas/evidence-record-1.0.0.json': '4a0e7c46a6b7fa2701d9455614d56faaf08d7186f6d7ab9c6d4559f343b299f7', 'config/contracts/schemas/input-safety-policy-1.0.0.json': 'dc309b7d807ac0c13c4c2e5ba47e5f7ac6c1a9524b6637d4b73f4ff20da1d585', 'config/contracts/schemas/intent-baseline-1.0.0.json': '27409c9223027ce97c7f2bfdde247df534ca59dc602e087b4deafcb8faa9aa09', 'config/contracts/schemas/prepared-action-1.0.0.json': '65add08cfe44b5cdf853fae9926dd52f6b291b6be823b310f39d810bdf042211', 'config/contracts/schemas/redaction-policy-1.0.0.json': '4f5d026d01f7644cc1883340bcdf7a6064ffb43b5ca726f864e359a30c7920a5', 'config/contracts/schemas/retention-policy-registry-1.0.0.json': 'f0f1db1966006518811fa14e97d42a8a9441fe72078ed1a98f78ad60c3d32a52', 'config/contracts/schemas/security-binding-1.0.0.json': 'da04b6d4767ca2cde6907a71f5238ee782efd96a25957b389518b4b5927316a7', 'config/contracts/schemas/security-runtime-manifest-1.0.0.json': '09f95da2c4caf8e0ddf729ae05f0d78a1197643e2e5e41a756fc4c21cc286b07'}
