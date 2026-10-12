"""Closed release records and actual owned resource membership."""
import copy
import hashlib
import json
import unittest
from tests.support.release_installation import core, adapter, context, manifest, model, reseal, fixture, ROOT


class ReleaseInstallationContractTests(unittest.TestCase):
    def test_manifest_nested_closed(self):
        model()
        value=manifest()
        paths=[[],['product'],['platform'],['interpreter'],['installer'],['artifacts',0],['dependencies',0],['skills',0],['compatibility']]
        for path in paths:
            v=copy.deepcopy(value);row=v
            for key in path:row=row[key]
            row['unexpected']=True
            with self.assertRaises(ValueError):model(reseal(v))
        for key in value:
            v=copy.deepcopy(value);v.pop(key)
            with self.assertRaises(ValueError):model(v)

    def test_policy_closed(self):
        inputs=adapter().InstalledReleaseInputs.open_owned();p=inputs.policy
        core().validate_release_policy(p,context())
        for change in ('extra','missing','duplicate'):
            v=copy.deepcopy(p)
            if change=='extra':v['unexpected']=1
            elif change=='missing':v.pop('policy_id')
            else:v['allowed_license_ids']=['BSD-3-Clause','BSD-3-Clause']
            with self.assertRaises(ValueError):core().validate_release_policy(reseal(v,'policy','policy_digest'),context())
        self.assertEqual(p['source_ids'],[])
        self.assertEqual(inputs.trust['keys'],[])

    def test_registry_resource_closed(self):
        inputs=adapter().InstalledReleaseInputs.open_owned()
        for key in [k for k in inputs.limits if k.startswith('max_')]:
            for val in (True,0,-1,2**63):
                r=dict(inputs.limits,**{key:val})
                with self.assertRaises(ValueError):core().validate_resource_policy(reseal(r,'resource-policy','policy_digest'),context())
        r=copy.deepcopy(inputs.trust);r['extra']=1
        with self.assertRaises(ValueError):core().validate_trust_registry(reseal(r,'trust-registry','registry_digest'),context())

    def test_diagnostic_closed(self):
        value=core().diagnostic('blocked','doctor','phase_unavailable',[],[],context(),max_bytes=65536)
        core().validate_diagnostic(value,context())
        for change in ('extra','status','path','digest'):
            v=copy.deepcopy(value)
            if change=='extra':v['extra']=1
            elif change=='status':v['status']='installed'
            elif change=='path':v['refs']=['/secret']
            else:v['diagnostic_digest']='sha256-jcs-v1:'+'0'*64
            with self.assertRaises(ValueError):core().validate_diagnostic(v,context())

    def test_installed_resource_closure(self):
        inputs=adapter().InstalledReleaseInputs.open_owned()
        self.assertEqual(len(inputs.resource_paths),11)
        self.assertEqual(len(set(inputs.resource_paths)),11)
        self.assertEqual(inputs.require_current(),inputs.binding_digest)
        self.assertTrue(all((ROOT/p).is_file() for p in inputs.resource_paths))
        import tomllib
        mapping=tomllib.loads((ROOT/'pyproject.toml').read_text())['tool']['gew']['build']['owned-root-files']
        for p in inputs.resource_paths:self.assertEqual(mapping[p],'graph_engineering/'+p)

    def test_legacy_resources_preserved(self):
        for path,digest in fixture()['legacy_resource_hashes'].items():
            self.assertEqual(hashlib.sha256((ROOT/path).read_bytes()).hexdigest(),digest)
        from graph_engineering.application.learning import LearningPolicyLoader
        self.assertTrue(LearningPolicyLoader.from_installation())
