"""Built wheel in a private outside-checkout interpreter, with real resources."""
import json
import unittest
from tests.support.release_installation import ReleaseFixture,inventory,require_success


class ReleaseInstallationWheelTests(unittest.TestCase):
    def test_installed_check_doctor(self):
        import subprocess,os,tomllib
        from tests.unit.test_wp00_packaging import assert_direct_script_contract
        from tests.support.release_installation import ROOT
        assert_direct_script_contract(self,tomllib.loads((ROOT/"pyproject.toml").read_text()))
        for command in ('doctor','release-check'):
          with self.subTest(command=command),ReleaseFixture(installed=True) as f:
            self.assertEqual(require_success(self,f.check())['code'],'ok')
            before=inventory(f.environment)
            # Cold installed launcher intentionally has no -B/PYTHONDONTWRITEBYTECODE.
            child_env=dict(os.environ);child_env.pop('PYTHONDONTWRITEBYTECODE',None);child_env.pop('PYTHONPYCACHEPREFIX',None)
            args=[command,'--format','json']
            if command=='release-check':args+=['--bundle',str(f.bundle),'--manifest',str(f.manifest_path)]
            result=subprocess.run([str(f.launcher),*args],cwd=f.base,env=child_env,capture_output=True,text=True,timeout=90)
            self.assertEqual(result.returncode,3 if command=='doctor' else 0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['code'],'phase_unavailable' if command=='doctor' else 'ok');self.assertEqual(result.stderr,'')
            self.assertEqual(inventory(f.environment),before)
            result=f.run('import graph_engineering;assert pathlib.Path(graph_engineering.__file__).is_relative_to(pathlib.Path(sys.prefix));print(json.dumps({"owned":True}))')
            self.assertTrue(require_success(self,result)['owned'])

    def test_installed_owned_resource_substitution(self):
        for relative in ('config/release-installation/release-policy-v1.json','config/release-installation/release-trust-registry-v1.json','config/contracts/schemas/release-install-manifest-1.0.0.json'):
            with ReleaseFixture(installed=True) as f:
                self.assertEqual(require_success(self,f.check())['code'],'ok')
                path=f.product_root/relative;path.write_bytes(path.read_bytes()+b' ')
                self.assertNotEqual(f.check().returncode,0,relative)
        with ReleaseFixture(installed=True) as f:
            code='''from graph_engineering.adapters.release_installation import InstalledReleaseInputs
import os
x=InstalledReleaseInputs.open_owned();p=pathlib.Path(sys.argv[2]);q=p.with_name('replacement.json');q.write_bytes(p.read_bytes());os.replace(q,p)
try:x.require_current()
except ValueError:pass
else:raise AssertionError('same-byte owned resource replacement reused')
'''
            p=f.run(code,arguments=(f.product_root/'config/release-installation/release-policy-v1.json',))
            self.assertEqual(p.returncode,0,p.stderr)

    def test_outside_checkout_decoys(self):
        with ReleaseFixture(installed=True) as f:
            # Common-name decoys in cwd/PATH cannot become the installed product.
            for name in ('core','application','storage','adapters'):
                path=f.base/name;path.mkdir();(path/'__init__.py').write_text('raise RuntimeError("DECOY")')
            decoy=f.base/'bin';decoy.mkdir();p=decoy/'graph-engineering';p.write_text('#!/bin/sh\nexit 99\n');p.chmod(0o700)
            self.assertEqual(require_success(self,f.check(extra_env={'PATH':str(decoy)}))['code'],'ok')
            # A duplicate product distribution is an actual origin ambiguity.
            import shutil
            dist=next(f.product_root.parent.glob('graph_engineering_workflow-*.dist-info'))
            shutil.copytree(dist,dist.with_name('duplicate-0.1.0.dist-info'))
            self.assertNotEqual(f.check().returncode,0)

    def test_installed_fixture_config_variation(self):
        with ReleaseFixture(installed=True) as f:
            require_success(self,f.check());f.value['skills'][0]['protocol_range']='>=9.0.0,<10.0.0';f.sign()
            self.assertNotEqual(f.check().returncode,0)
        with ReleaseFixture(installed=True) as allowed,ReleaseFixture(installed=True,policy_patch={'source_ids':[]}) as refused:
            self.assertEqual(require_success(self,allowed.check())['code'],'ok');self.assertNotEqual(refused.check().returncode,0)
            for first in allowed.product_root.rglob('*.py'):
                second=refused.product_root/first.relative_to(allowed.product_root)
                self.assertEqual(first.read_bytes(),second.read_bytes())
            # Old process-local observation must reject freshly changed configuration.
            code='''from graph_engineering.adapters import release_installation as a
assert hasattr(a,'LocalReleaseVerifier'),'physical verifier absent'
o=a.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));p=pathlib.Path(sys.argv[4]);p.write_bytes(p.read_bytes()+b' ')
try:o.require_current()
except ValueError:pass
else:raise AssertionError('old admission survived changed installed configuration')
'''
            p=allowed.run(code,arguments=(allowed.bundle,allowed.manifest_path,allowed.product_root/'config/release-installation/release-policy-v1.json'))
            self.assertEqual(p.returncode,0,p.stderr)
