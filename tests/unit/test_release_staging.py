"""Independent closed planning behavior."""
import copy
import unittest
from tests.support.release_staging import core, request, context

class ReleaseStagingUnitTests(unittest.TestCase):
    def test_stage_request_closed_bounds(self):
        value=request()
        self.assertEqual(core().StageRequest.from_dict(value,context()).to_dict(),value)
        for change in ({'extra':True},{'preserve_data':False},{'target_refs':['candidate','candidate']},{'prior_tuple_digest':True}):
            with self.subTest(change=list(change)):
                with self.assertRaises(ValueError):core().StageRequest.from_dict(dict(value,**change),context())
        self.assertEqual(core().StageRequest.from_dict(dict(value,operation='upgrade'),context()).to_dict()['operation'],'upgrade')
        for key in value:
            missing=dict(value);missing.pop(key)
            with self.assertRaises(ValueError):core().StageRequest.from_dict(missing,context())
        for change in ({'request_id':False},{'release_manifest_digest':'sha256:bad'},{'target_refs':['/raw/path']},{'target_refs':['z','a']},{'target_refs':[]},{'preserve_data':1}):
            with self.assertRaises(ValueError):core().StageRequest.from_dict(dict(value,**change),context())
        from graph_engineering.core.contracts.resources import WorkContext,ResourceProfile
        c=context();p=c.profile.to_dict() if hasattr(c.profile,'to_dict') else None
        if p is None:
            import json
            from tests.support.release_staging import ROOT
            p=json.loads((ROOT/'config/contracts/resource-profile-v1.json').read_bytes())
        p['limits']['array_items']=1
        with self.assertRaises(ValueError):core().StageRequest.from_dict(value,WorkContext(ResourceProfile.from_dict(p),c.schedule))

    def test_install_plan_projection_policy(self):
        from tests.support.release_staging import plan_record,framed,seal
        v=plan_record();self.assertEqual(core().validate_plan(v,context()),v)
        self.assertEqual(v['plan_digest'],framed('plan',{k:x for k,x in v.items() if k!='plan_digest'})[1])
        for key in ('policy_digest','closure_digest','platform_digest','preserve_data'):
            bad=copy.deepcopy(v);bad[key]=False
            with self.assertRaises(ValueError):core().validate_plan(bad,context())
        bad=copy.deepcopy(v);bad['extra']=None
        with self.assertRaises(ValueError):core().validate_plan(bad,context())

    def test_context_and_envelope_projections(self):
        from tests.support.release_staging import plan_record,policies,seal,stage_framed
        s,p,r=policies();c=seal({'schema_version':'1.0.0','stage_policy_digest':s['policy_digest'],'installer_policy_digest':p['policy_digest'],
            'recipe_digest':r['recipe_digest'],'target_registry_digest':s['policy_digest'],'target_binding_digest':p['policy_digest']},'stage-context','context_digest')
        env=seal({'schema_version':'1.0.0','plan':plan_record(),'stage_context':c},'stage-plan-envelope','envelope_digest')
        self.assertEqual(core().validate_envelope(env,context()),env)
        for k,v in c.items():
            if k=='schema_version':continue
            bad=copy.deepcopy(env);bad['stage_context'][k]='sha256-jcs-v1:'+'9'*64
            with self.assertRaises(ValueError):core().validate_envelope(bad,context())
        self.assertEqual(core().stage_digest('stage-context',{k:v for k,v in c.items() if k!='context_digest'},context()),c['context_digest'])
        self.assertNotEqual(stage_framed('installer-policy',{k:v for k,v in c.items() if k!='context_digest'})[1],c['context_digest'])
        for target in ('stage_context','plan'):
            bad=copy.deepcopy(env);bad[target]['extra']=True
            with self.assertRaises(ValueError):core().validate_envelope(bad,context())
        for field in env:
            bad=copy.deepcopy(env);bad.pop(field)
            with self.assertRaises(ValueError):core().validate_envelope(bad,context())

    def test_recipe_exact_unique_selection(self):
        from tests.support.release_staging import policies,seal,manifest
        s,p,r=policies();v=manifest();v['installer']['argv_policy_digest']=r['recipe_digest']
        self.assertEqual(core().select_recipe(p,v,context()),r)
        for k in ('interpreter_version','installer_version','interpreter_artifact_id','installer_artifact_id','platform'):
            bad=copy.deepcopy(p);row=bad['recipes'][0]
            row[k]=dict(row[k],architecture='unavailable') if k=='platform' else ('9.0.0' if 'version' in k else 'missing')
            bad['recipes'][0]=seal(row,'installer-recipe','recipe_digest');bad=seal(bad,'installer-policy','policy_digest')
            with self.assertRaises(ValueError):core().select_recipe(bad,v,context())
        duplicate=copy.deepcopy(r);duplicate['recipe_id']='z-other';duplicate=seal(duplicate,'installer-recipe','recipe_digest')
        bad=seal(dict(p,recipes=[r,duplicate]),'installer-policy','policy_digest')
        with self.assertRaises(ValueError) as e:core().select_recipe(bad,v,context())
        self.assertEqual(e.exception.code,'platform_unavailable')
        with self.assertRaises(ValueError):core().select_recipe(seal(dict(p,recipes=[]),'installer-policy','policy_digest'),v,context())

    def test_recipe_argv_tokens_and_versions(self):
        from tests.support.release_staging import policies,seal
        s,p,r=policies();core().validate_installer_policy(p,context())
        for arg in ({'ref':'candidate-root'},{'ref':'unknown'},{'ref':'wheelhouse','extra':True},'@escape','$HOME','x;tool',False):
            bad=copy.deepcopy(p);bad['recipes'][0]['steps'][0]['argv']=[arg]
            bad['recipes'][0]=seal(bad['recipes'][0],'installer-recipe','recipe_digest');bad=seal(bad,'installer-policy','policy_digest')
            with self.subTest(arg=arg):
                with self.assertRaises(ValueError):core().validate_installer_policy(bad,context())
        for env in ({'name':'PYTHONPATH','value':'injected'},{'name':'DYLD_INSERT_LIBRARIES','value':'injected'}):
            bad=copy.deepcopy(p);bad['recipes'][0]['steps'][0]['environment']=[env]
            bad['recipes'][0]=seal(bad['recipes'][0],'installer-recipe','recipe_digest');bad=seal(bad,'installer-policy','policy_digest')
            with self.assertRaises(ValueError):core().validate_installer_policy(bad,context())
        for change in ({'executable_ref':'PATH'},{'cwd_ref':'/tmp'},{'argv':False},{'extra':True},
                       {'environment':[{'name':'Z','value':'ok'},{'name':'A','value':'ok'}]},
                       {'environment':[{'name':'A','value':'ok'},{'name':'A','value':'ok'}]}):
            bad=copy.deepcopy(p);bad['recipes'][0]['steps'][0].update(change)
            bad['recipes'][0]=seal(bad['recipes'][0],'installer-recipe','recipe_digest');bad=seal(bad,'installer-policy','policy_digest')
            with self.assertRaises(ValueError):core().validate_installer_policy(bad,context())
        bad=copy.deepcopy(p);bad['recipes'][0]['generated_files']=[{'logical_path':'../escape','kind':'script','template_digest':r['recipe_digest']}]
        bad['recipes'][0]=seal(bad['recipes'][0],'installer-recipe','recipe_digest');bad=seal(bad,'installer-policy','policy_digest')
        with self.assertRaises(ValueError):core().validate_installer_policy(bad,context())

    def test_diagnostic_budgets(self):
        import json
        from tests.support.release_staging import stage_framed,policies,seal
        c=core();v=c.stage_diagnostic('input_invalid','plan',context(),max_bytes=65536)
        size=len(json.dumps(v,sort_keys=True,separators=(',',':')).encode())
        self.assertEqual(c.stage_diagnostic('input_invalid','plan',context(),max_bytes=size),v)
        with self.assertRaises(ValueError):c.stage_diagnostic('input_invalid','plan',context(),max_bytes=size-1)
        self.assertEqual(v['diagnostic_digest'],stage_framed('stage-diagnostic',{k:x for k,x in v.items() if k!='diagnostic_digest'})[1])
        for field in ('status','phase','refs','capabilities'):
            bad=copy.deepcopy(v);bad[field]='staged' if field!='refs' else ['secret/path']
            with self.assertRaises(ValueError):c.validate_stage_diagnostic(bad,context())
        s,_,_=policies();c.validate_stage_policy(s,context())
        for key in ('max_stage_bytes','max_stage_files','max_process_seconds','max_output_bytes','max_failed_candidates','max_cleanup_entries'):
            for value in (0,True,-1,9007199254740992):
                with self.assertRaises(ValueError):c.validate_stage_policy(seal(dict(s,**{key:value}),'stage-policy','policy_digest'),context())
