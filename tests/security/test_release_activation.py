"""Declared data cannot manufacture authority/currentness or cause effects."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from tests.unit.test_release_activation import core,context,fixture,seal,check_chain,recovery,recovery_case,relink_chain,DUMMY

def seal_leaf(value):
    body=copy.deepcopy(value);body.pop('manifest_digest',None)
    frame=dict(algorithm='sha-256',body=body,canonicalizer='urn:gew:canonicalizer:jcs-input:1.0.0',
        contract_type='urn:gew:contract:active-repository-manifest',digest_domain='urn:gew:digest:semantic:1.0.0',
        projection_id='urn:gew:projection:active-repository-manifest:1.0.0',schema_id='urn:gew:schema:active-repository-manifest:1.0.0')
    body['manifest_digest']='sha256-jcs-v1:'+hashlib.sha256(json.dumps(frame,sort_keys=True,separators=(',',':')).encode()).hexdigest();return body

def rebind_tuple_links(value):
    c=copy.deepcopy(value);i,b,s,l=c['installed_manifest'],c['installation_binding'],c['stage_receipt'],c['repository_leaf']
    c['stage_receipt']=seal('stage-receipt',dict(s,installed_manifest_digest=i['installed_manifest_digest'],binding_digest=b['binding_digest']),'receipt_digest')
    c['tuple_record']=seal('release-tuple-manifest',dict(c['tuple_record'],installed_manifest_digest=i['installed_manifest_digest'],stage_receipt_digest=c['stage_receipt']['receipt_digest'],installation_binding_digest=b['binding_digest'],repository_leaf_digest=l['manifest_digest'],release_manifest_digest=c['stage_receipt']['release_manifest_digest']),'tuple_digest')
    return c

class ReleaseActivationSecurityTests(unittest.TestCase):
    def test_valid_records_confer_no_authority_or_io(self):
        from contextlib import ExitStack
        import ast
        import importlib.util
        import inspect
        from graph_engineering.application import release_staging as owner
        from graph_engineering.application import installation_authority as authority
        from graph_engineering.adapters import installation_authority as terminal
        c=core();f=fixture();ctx=context();calls=[]
        # C0 has no activation registration/issuer layer. Check its actual import
        # boundary and module inventory before the forbidden-effect observation.
        for layer in ('application','adapters'):
            self.assertIsNone(importlib.util.find_spec('graph_engineering.'+layer+'.release_activation'))
        syntax=ast.parse(inspect.getsource(c))
        imports=[node.module for node in ast.walk(syntax) if isinstance(node,ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith(('graph_engineering.application','graph_engineering.adapters')) for name in imports))
        self.assertFalse(any(name.startswith(('register','authorize','issue')) for name in vars(c)))
        before=copy.deepcopy(f)
        tables=[authority._GRANTS,authority._PERMITS,authority._ACTIVE,authority._RETIRED,owner._PLANS]
        registrations=[dict(table) for table in tables]
        def forbidden(*args,**kwargs):calls.append(True);raise AssertionError('forbidden effect')
        with ExitStack() as stack:
            for target in ('builtins.open','os.open','os.read','os.write','os.mkdir','os.replace','os.unlink','subprocess.Popen','time.time','time.time_ns','time.monotonic','time.monotonic_ns'):
                stack.enter_context(patch(target,forbidden))
            # Observe genuine grant/permit constructors, issuer aliases, owner
            # entry points and provider registration without fabricating consent.
            for obj,names in ((authority,('authorize','consume','bind_planning','_APPROVE','_APPROVAL_CONTEXT')),
                              (authority.InstallationAuthority,('__init__',)),(authority.StagePermit,('__init__',)),
                              (terminal,('approve','bind_providers')),(terminal.ApprovalSession,('__init__','decide')),
                              (owner,('_LOCAL_AUTHORIZE','_LOCAL_CONSUME')),
                              (owner.ReleaseInstaller,('plan','authorize_local','_consume_for_stage'))):
                for name in names:stack.enter_context(patch.object(obj,name,forbidden))
            for kind,value in f['records'].items():self.assertIsNone(c.validate_activation_record(kind,value,ctx))
            self.assertEqual(f,before)
            self.assertIsNone(c.validate_reference_successor(*f['chain']['reference_history'][:2],ctx))
            self.assertEqual(f,before)
            self.assertIsNone(c.validate_tuple_links(**f['linked_target'],context=ctx))
            self.assertEqual(f,before)
            self.assertIsNone(c.validate_transition_chain(**f['chain'],context=ctx))
            self.assertEqual(f,before)
        self.assertEqual(calls,[])
        self.assertEqual([dict(table) for table in tables],registrations)
        self.assertFalse(any(hasattr(c,n) for n in ('InstallationAuthority','StagePermit','OwnedActivationPlan','activate','authorize_activation')))
        class Poison(dict):
            def items(self):calls.append(True);raise AssertionError('user callback')
        with self.assertRaises(ValueError):c.validate_activation_record('activation-intent',Poison(f['records']['activation-intent']),context())
        with self.assertRaises(ValueError):c.validate_activation_record('activation-intent',dict(f['records']['activation-intent'],extra=[Poison()]),context())
        self.assertEqual(calls,[])

    def test_cross_installation_replay_and_conflicting_chains(self):
        c=core();f=fixture();links=f['linked_target'];self.assertIsNone(c.validate_tuple_links(**links,context=context()))
        # Restore compatible old software onto a fresh successor repository leaf.
        # Existing stage/installed/binding records retain their genuine contract
        # bytes; only the independently sealed new leaf and tuple are prepared.
        restored=copy.deepcopy(f['linked_old']);old=restored['repository_leaf'];latest=f['linked_target']['repository_leaf']
        restored['repository_leaf']=seal_leaf(dict(old,generation=latest['generation']+1,activation_epoch=latest['activation_epoch']+1,
            previous_manifest_digest=latest['manifest_digest'],fencing_high_water=[['resource',3]]))
        restored=rebind_tuple_links(restored)
        for key in ('installed_manifest','stage_receipt','installation_binding'):self.assertEqual(restored[key],f['linked_old'][key])
        self.assertNotEqual(restored['repository_leaf']['manifest_digest'],old['manifest_digest'])
        self.assertIsNone(c.validate_tuple_links(**restored,context=context()))
        restore_chain=recovery_case(recovery('restore_old'),target=restored['tuple_record'])
        self.assertEqual(restore_chain['intent']['target_tuple_digest'],restored['tuple_record']['tuple_digest'])
        self.assertEqual(restore_chain['records'][1]['candidate_leaf_digest'],restored['repository_leaf']['manifest_digest'])
        self.assertIsNone(check_chain(restore_chain))
        for item,kind,field,key in [('tuple_record','release-tuple-manifest','tuple_digest','installation_id'),('installed_manifest','installed-release-manifest','installed_manifest_digest','release_id'),('stage_receipt','stage-receipt','receipt_digest','plan_digest'),('installation_binding','installation-binding','binding_digest','installation_id')]:
            bad=copy.deepcopy(links);bad[item]=seal(kind,dict(bad[item],**{key:'foreign' if key.endswith('_id') else DUMMY}),field)
            bad=rebind_tuple_links(bad)
            with self.subTest(item=item),self.assertRaises(ValueError) as caught:c.validate_tuple_links(**bad,context=context())
            self.assertEqual(caught.exception.code,'closure_mismatch')
        bad=copy.deepcopy(links);bad['repository_leaf']=copy.deepcopy(f['linked_old']['repository_leaf'])
        with self.assertRaises(ValueError):c.validate_tuple_links(**rebind_tuple_links(bad),context=context())
        for key in ('installation_id','release_id'):
            bad=copy.deepcopy(links);bad['repository_leaf']=seal_leaf(dict(bad['repository_leaf'],**{key:'foreign'}))
            with self.assertRaises(ValueError):c.validate_tuple_links(**rebind_tuple_links(bad),context=context())
        self.assertIsNone(check_chain(f['chain']))
        for key in ('reference_history','tuples'):
            bad=copy.deepcopy(f['chain']);bad[key].append(copy.deepcopy(bad[key][-1]))
            with self.assertRaises(ValueError):check_chain(bad)
        for disposition in ('finish_new','restore_old'):
            bundle=recovery(disposition);self.assertIsNone(check_chain(bundle))
            for key,value in [('recovery_source_record_digest',DUMMY),('recovery_disposition','restore_old' if disposition=='finish_new' else 'finish_new'),('recovery_disposition','unsupported')]:
                bad=recovery_case(bundle,intent_patch={key:value})
                with self.subTest(disposition=disposition,key=key),self.assertRaises(ValueError):check_chain(bad)
            foreign_current=seal('active-release-reference',dict(bundle['reference_history'][0],journal_digest=DUMMY),'reference_digest')
            with self.assertRaises(ValueError):check_chain(recovery_case(bundle,base=foreign_current))
            source=bundle['recovery_source'];wrong_target=source['tuples'][0] if disposition=='finish_new' else source['tuples'][1]
            with self.assertRaises(ValueError):check_chain(recovery_case(bundle,target=wrong_target))
            bad=copy.deepcopy(bundle);bad['recovery_source']={key:copy.deepcopy(bundle[key]) for key in ('intent','records','reference_history','tuples','receipt')}
            bad=recovery_case(bad,intent_patch={'recovery_source_record_digest':bundle['records'][-1]['record_digest']})
            with self.assertRaises(ValueError):check_chain(bad)
        bad=relink_chain(f['chain'],reference_patches={2:{'generation':f['chain']['reference_history'][1]['generation'],'activation_epoch':f['chain']['reference_history'][1]['activation_epoch']}})
        with self.assertRaises(ValueError):check_chain(bad)
