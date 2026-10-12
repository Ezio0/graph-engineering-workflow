"""Expected release semantics, independent of filesystem and installed authority."""
import copy
import unittest
from tests.support.release_installation import core, adapter, context, manifest, model, observed, framed, reseal, fixture


class ReleaseInstallationUnitTests(unittest.TestCase):
    def test_manifest_projection(self):
        value=manifest();actual=model(value)
        expected=framed('manifest',{k:v for k,v in value.items() if k not in ('manifest_digest','signature')})
        self.assertEqual(actual.manifest_digest,expected[1])
        self.assertEqual(core().manifest_signature_preimage(value,context()),expected[0])
        for key in ('release_id','signing_key_id'):
            changed=copy.deepcopy(value);changed[key]+='-changed'
            with self.assertRaises(ValueError):model(changed)
        self.assertNotEqual(framed('policy',{k:v for k,v in value.items() if k not in ('manifest_digest','signature')})[1],expected[1])

    def test_closure_order_invariance(self):
        value=manifest();m=model(value);facts=observed(value)
        first=core().compare_release_closure(m,facts,context())
        facts['artifacts'].reverse();facts['dependencies'].reverse()
        self.assertEqual(first,core().compare_release_closure(m,facts,context()))
        value['artifacts'].reverse()
        with self.assertRaises(ValueError):model(reseal(value))

    def test_graph_reachability(self):
        value=manifest();m=model(value);core().compare_release_closure(m,observed(value),context())
        for change in ('missing','extra','cycle','dangling'):
            v=copy.deepcopy(value)
            if change=='missing':v['dependencies']=v['dependencies'][:-1]
            elif change=='extra':v['artifacts'].append(dict(v['artifacts'][0],artifact_id='extra',relative_path='extra.whl'))
            else:v['dependencies'].append(dict(v['dependencies'][0],parent_artifact_id='cffi',child_artifact_id='core' if change=='cycle' else 'absent'))
            v['artifacts'].sort(key=lambda r:r['artifact_id']);v['dependencies'].sort(key=lambda r:(r['parent_artifact_id'],r['child_artifact_id'],r['requirement']))
            with self.assertRaises(ValueError):model(reseal(v))

    def test_duplicate_normalization(self):
        for field,value in [('distribution_name','synthetic_cffi'),('relative_path','CFFI.whl'),('artifact_id','cffi')]:
            v=manifest();r=next(x for x in v['artifacts'] if x['artifact_id']=='cffi');other=next(x for x in v['artifacts'] if x['artifact_id']=='crypto')
            if field=='relative_path':r[field]='cffi.whl'
            other[field]=value
            with self.assertRaises(ValueError):model(reseal(v))

    def test_marker_extras(self):
        f=fixture();a=adapter();environment=a.marker_environment(f['platform'],'3.12.12')
        rows=[('dep==1; sys_platform == "darwin"',True),('dep==1; sys_platform == "linux"',False),('dep==1; extra == "secure"',True)]
        for requirement,active in rows:self.assertEqual(a.requirement_active(requirement,environment,['secure']),active)
        with self.assertRaises(ValueError):a.requirement_active('dep @ https://invalid.example/x',environment,[])

    def test_compatibility_ranges(self):
        m=model();f=fixture();core().check_compatibility(m,f['versions'],f['capabilities'],context())
        for key in f['versions']:
            versions=dict(f['versions'],**{key:'9.0.0'})
            with self.assertRaises(ValueError):core().check_compatibility(m,versions,f['capabilities'],context())
        with self.assertRaises(ValueError):core().check_compatibility(m,f['versions'],[],context())
        value=manifest();value['skills'][0]['protocol_range']='>=9.0.0,<10.0.0'
        with self.assertRaises(ValueError):core().check_compatibility(model(reseal(value)),f['versions'],f['capabilities'],context())

    def test_diagnostic_budget(self):
        c=core();value=c.diagnostic('rejected','check','input_invalid',[],[],context(),max_bytes=65536)
        import json
        size=len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
        self.assertEqual(c.diagnostic('rejected','check','input_invalid',[],[],context(),max_bytes=size),value)
        with self.assertRaises(ValueError):c.diagnostic('rejected','check','input_invalid',[],[],context(),max_bytes=size-1)
        with self.assertRaises(ValueError):c.diagnostic('rejected','check','input_invalid',[],['secret/absolute-path'],context(),max_bytes=65536)

    def test_trust_purpose(self):
        c=core();m=model();key={'id':'fixture-key','public_key_hex':'1'*64,'purpose':'release','allowed_release_ids':['synthetic-v1']}
        registry={'schema_version':'1.0.0','registry_id':'fixture','generation':1,'keys':[key],'revoked_key_ids':[],'registry_digest':''}
        registry=reseal(registry,'trust-registry','registry_digest')
        self.assertEqual(c.select_release_key(m,registry,context()),'1'*64)
        for change in ('purpose','release','revoked','generation'):
            r=copy.deepcopy(registry)
            if change=='purpose':r['keys'][0]['purpose']='advisory'
            elif change=='release':r['keys'][0]['allowed_release_ids']=['other']
            elif change=='revoked':r['revoked_key_ids']=['fixture-key']
            else:r['generation']=False
            with self.assertRaises(ValueError):c.select_release_key(m,reseal(r,'trust-registry','registry_digest'),context())
