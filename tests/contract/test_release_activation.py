"""Actual schema/package closure; no operational activation claims."""
import ast
import copy
import hashlib
import json
import tomllib
import unittest
from tests.unit.test_release_activation import ROOT,context,fixture,SELF_FIELDS

NAMES=('activation-intent','release-tuple-manifest','active-release-reference','release-transition-record','release-transition-receipt','activation-diagnostic')
RESOURCES=('config/contracts/release-activation-schema-registry-v1.json',)+tuple('config/contracts/schemas/'+n+'-1.0.0.json' for n in NAMES)

# Handwritten W10C-S5 field oracle, independent of schemas and core field maps.
SCHEMA_FIELDS={
    'activation-intent':'schema_version:Version request_id:T installation_id:T operation:O target_tuple_digest:D expected_reference_digest:D recovery_source_record_digest:D? recovery_disposition:Disposition? preserve_data:True intent_digest:D',
    'release-tuple-manifest':'schema_version:Version installation_id:T release_id:T release_manifest_digest:D installed_manifest_digest:D stage_receipt_digest:D installation_binding_digest:D repository_leaf_digest:D bootstrap_protocol:Bootstrap tuple_digest:D',
    'active-release-reference':'schema_version:Version installation_id:T generation:P activation_epoch:P mode:Mode tuple_digest:D previous_reference_digest:D? journal_digest:D reference_digest:D',
    'release-transition-record':'schema_version:Version installation_id:T request_id:T operation:O sequence:N state:S intent_digest:D plan_digest:D prior_reference_digest:D target_tuple_digest:D candidate_leaf_digest:D? observed_reference_digest:D? previous_record_digest:D? record_digest:D',
    'release-transition-receipt':'schema_version:Version installation_id:T request_id:T operation:O plan_digest:D terminal_record_digest:D selected_reference_digest:D outcome:Outcome receipt_digest:D',
    'activation-diagnostic':'schema_version:Version request_id:T phase:Phase status:Status code:Code refs:Refs capabilities:Capabilities next_route:Route diagnostic_digest:D',
}
SCHEMA_ENUMS={
    'O':['activate','upgrade','rollback','recover'],
    'Disposition':['finish_new','restore_old'],
    'Mode':['verifying','active','blocked'],
    'S':['prepared','repository_verified','verifying_prepared','verifying_published','active_prepared','active_published','completed','recovery_prepared','recovered_old','recovered_new','block_prepared','blocked','failed_before_switch'],
    'Outcome':['active','restored','blocked'],
    'Status':['proposed','rejected','blocked'],
    'Code':['input_invalid','trust_rejected','closure_mismatch','resource_limit','phase_unavailable'],
    'Route':['contract-review','supply-inputs','fresh-owner-decision','explicit-recovery','phase-implementation'],
}
CAPABILITY_KEYS=['activation-plan','activate','recover','rollback','uninstall']
SCHEMA_DIGEST='sha256-jcs-v1:'+'a'*64
SAFE_MAX=9007199254740991

def property_oracle(kind):
    token={'type':'string','minLength':1,'maxLength':128}
    digest={'type':'string','pattern':'^sha256-jcs-v1:[0-9a-f]{64}$'}
    if kind.endswith('?'):return {'anyOf':[property_oracle(kind[:-1]),{'type':'null'}]}
    if kind in SCHEMA_ENUMS:return {'enum':SCHEMA_ENUMS[kind]}
    if kind in ('T','D'):return token if kind=='T' else digest
    if kind in ('N','P'):return {'type':'integer','minimum':0 if kind=='N' else 1,'maximum':SAFE_MAX}
    if kind=='Refs':return {'type':'array','items':token,'maxItems':128,'uniqueItems':True}
    if kind=='Capabilities':return {'type':'object','properties':{k:{'const':'unavailable'} for k in CAPABILITY_KEYS},'required':CAPABILITY_KEYS,'additionalProperties':False}
    return {'const':{'Version':'1.0.0','Bootstrap':'release-dispatch-v1','Phase':'activation','True':True}[kind]}

def field_vectors(kind):
    """Valid scalar boundaries and invalid JSON types/values from the contract."""
    bad=[None,False,0,[],{}]
    if kind.endswith('?'):
        good,bad=field_vectors(kind[:-1]);return [None,*good],[v for v in bad if v is not None]
    if kind in SCHEMA_ENUMS:return SCHEMA_ENUMS[kind],bad+['unknown']
    if kind=='T':return ['a','a'*128],bad+['','a'*129]
    if kind=='D':return [SCHEMA_DIGEST],bad+['','0'*64,'sha256-jcs-v1:'+'g'*64,'sha256-jcs-v1:'+'A'*64,'sha256-jcs-v1:'+'a'*63]
    if kind in ('N','P'):return [0 if kind=='N' else 1,SAFE_MAX],[None,False,True,[],{},'3',-1,SAFE_MAX+1,1.5]+([0] if kind=='P' else [])
    if kind=='Refs':return [[],['a'],[f'ref{i:03d}' for i in range(128)]],[None,False,0,{},'a',['a']*2,['a']*129,*[[v] for v in (None,False,0,[],{},'','a'*129)]]
    if kind=='Capabilities':return [{k:'unavailable' for k in CAPABILITY_KEYS}],[None,False,0,[],'unavailable']
    good={'Version':'1.0.0','Bootstrap':'release-dispatch-v1','Phase':'activation','True':True}[kind]
    return [good],[None,False,0,1,[],{},'unknown']

def schema_field_case(name,original,key,value):
    """Keep other conditional fields valid while varying one field's shape."""
    body=copy.deepcopy(original)
    if name=='activation-intent':
        if key=='operation':
            body.update(recovery_source_record_digest=SCHEMA_DIGEST if value=='recover' else None,recovery_disposition='finish_new' if value=='recover' else None)
        elif key in ('recovery_source_record_digest','recovery_disposition'):
            body.update(operation='recover' if value is not None else 'activate',recovery_source_record_digest=SCHEMA_DIGEST if value is not None else None,recovery_disposition='finish_new' if value is not None else None)
    if name=='active-release-reference' and key in ('generation','previous_reference_digest'):
        first=(key=='previous_reference_digest' and value is None) or (key=='generation' and type(value) is int and value==1)
        body.update(generation=1 if first else 2,activation_epoch=1,previous_reference_digest=None if first else SCHEMA_DIGEST)
    if name=='release-transition-record' and key=='state' and value in ('recovery_prepared','recovered_old','recovered_new'):body['operation']='recover'
    if name=='release-transition-receipt' and key=='outcome' and value=='restored':body['operation']='recover'
    body[key]=value;return body

def source_members(path,name):
    tree=ast.parse(path.read_text())
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))

class ReleaseActivationContractTests(unittest.TestCase):
    def test_activation_schema_registry_closure(self):
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy
        from graph_engineering.core.contracts import parse_json
        doc=json.loads((ROOT/RESOURCES[0]).read_bytes());bodies={}
        for name in NAMES:
            raw=(ROOT/('config/contracts/schemas/'+name+'-1.0.0.json')).read_bytes();schema=json.loads(raw);bodies[schema['$id']]=raw
            fields=dict(part.split(':') for part in SCHEMA_FIELDS[name].split())
            self.assertEqual(set(schema['properties']),set(fields));self.assertEqual(set(schema['required']),set(fields));self.assertEqual(set(fields),set(fixture()['records'][name]))
            self.assertEqual(schema['type'],'object');self.assertFalse(schema['additionalProperties']);self.assertFalse(schema['unevaluatedProperties'])
            for key,kind in fields.items():self.assertEqual(schema['properties'][key],property_oracle(kind),(name,key))
        profile=SchemaProfilePolicy.from_dict(json.loads((ROOT/'config/contracts/schema-profile-v1.json').read_bytes()));ctx=context()
        registry=ClosedSchemaRegistry.build(doc,bodies,ctx.profile,profile,ctx)
        self.assertEqual(len(doc['resources']),6)
        for name in NAMES:
            value=fixture()['records'][name];sid='urn:gew:schema:'+name+':1.0.0'
            self.assertFalse(registry.validate(sid,value,context()),name)
            for key in value:
                bad=copy.deepcopy(value);bad.pop(key);self.assertTrue(registry.validate(sid,bad,context()),(name,key))
            self.assertTrue(registry.validate(sid,dict(value,extra=True),context()))
            for key,kind in dict(part.split(':') for part in SCHEMA_FIELDS[name].split()).items():
                good,bad=field_vectors(kind)
                # Diagnostic status/code/route have a separate exhaustive pair
                # oracle below; their independent property enums are checked above.
                if name=='activation-diagnostic' and key in ('status','code','next_route'):good=[]
                for candidate in good:
                    case=schema_field_case(name,value,key,candidate)
                    with self.subTest(record=name,field=key,valid=candidate):self.assertFalse(registry.validate(sid,case,context()))
                for candidate in bad:
                    case=schema_field_case(name,value,key,candidate)
                    with self.subTest(record=name,field=key,invalid=candidate):
                        self.assertTrue(registry.validate(sid,case,context()))
        intent=fixture()['records']['activation-intent'];sid='urn:gew:schema:activation-intent:1.0.0'
        for operation in SCHEMA_ENUMS['O']:
            for source in (None,SCHEMA_DIGEST):
                for disposition in (None,'finish_new','restore_old'):
                    case=dict(intent,operation=operation,recovery_source_record_digest=source,recovery_disposition=disposition)
                    valid=(source is not None and disposition is not None) if operation=='recover' else (source is None and disposition is None)
                    self.assertEqual(not bool(registry.validate(sid,case,context())),valid,(operation,source,disposition))
        reference=fixture()['records']['active-release-reference'];sid='urn:gew:schema:active-release-reference:1.0.0'
        for generation in (1,2):
            for epoch in (1,2):
                for previous in (None,SCHEMA_DIGEST):
                    case=dict(reference,generation=generation,activation_epoch=epoch,previous_reference_digest=previous)
                    valid=(epoch==1 and previous is None) if generation==1 else previous is not None
                    self.assertEqual(not bool(registry.validate(sid,case,context())),valid,(generation,epoch,previous))
        diagnostic=fixture()['records']['activation-diagnostic'];sid='urn:gew:schema:activation-diagnostic:1.0.0'
        allowed={('proposed','phase_unavailable','contract-review'),('blocked','phase_unavailable','phase-implementation'),*[('rejected',code,'supply-inputs') for code in ('input_invalid','trust_rejected','closure_mismatch','resource_limit')]}
        for status in SCHEMA_ENUMS['Status']:
            for code in SCHEMA_ENUMS['Code']:
                for route in SCHEMA_ENUMS['Route']:
                    case=dict(diagnostic,status=status,code=code,next_route=route)
                    self.assertEqual(not bool(registry.validate(sid,case,context())),(status,code,route) in allowed,(status,code,route))
        for key in CAPABILITY_KEYS:
            caps=dict(diagnostic['capabilities']);caps.pop(key)
            self.assertTrue(registry.validate(sid,dict(diagnostic,capabilities=caps),context()))
            for wrong in (None,False,1,[],{},'available','unknown'):
                caps=dict(diagnostic['capabilities'],**{key:wrong})
                self.assertTrue(registry.validate(sid,dict(diagnostic,capabilities=caps),context()))
        self.assertTrue(registry.validate(sid,dict(diagnostic,capabilities=dict(diagnostic['capabilities'],extra='unavailable')),context()))
        for mutation in ('missing','extra','swapped'):
            bad=dict(bodies)
            if mutation=='missing':bad.pop(next(iter(bad)))
            elif mutation=='extra':bad['urn:gew:schema:unexpected:1.0.0']=next(iter(bad.values()))
            else:
                keys=list(bad);bad[keys[0]],bad[keys[1]]=bad[keys[1]],bad[keys[0]]
            with self.assertRaises(ValueError):ClosedSchemaRegistry.build(doc,bad,ctx.profile,profile,context())
        with self.assertRaises(ValueError):parse_json(b'{"schema_version":"1.0.0","schema_version":"other"}',context=context(),source_id='activation-test')

    def test_packaged_source_resource_membership(self):
        import graph_engineering
        from tests.support.source_checkout_attestation import SOURCE_FILES
        config=tomllib.loads((ROOT/'pyproject.toml').read_text())['tool']['gew']['build']
        self.assertIn('core/graph_engineering/core/release_activation.py',SOURCE_FILES)
        paths,bodies=graph_engineering._release_activation_resources(context())
        self.assertEqual(tuple(paths),RESOURCES)
        self.assertEqual(tuple(bodies),tuple((ROOT/p).read_bytes() for p in RESOURCES))
        for p in RESOURCES:
            self.assertIn(p,SOURCE_FILES);self.assertEqual(config['owned-root-files'][p],'graph_engineering/'+p)
        declared=json.loads((ROOT/'config/verification/wp-00-targets.json').read_bytes())['files']
        for p in (*RESOURCES,'core/graph_engineering/core/release_activation.py'):self.assertIn(p,declared)

    def test_retained_resource_order_and_bytes(self):
        from tests.support.source_checkout_attestation import SOURCE_FILES
        f=fixture();old=f['baseline_source_order'];self.assertEqual([p for p in SOURCE_FILES if p in set(old)],old)
        actual=source_members(ROOT/'core/graph_engineering/__init__.py','_SOURCE_FILES');self.assertEqual(tuple(actual),SOURCE_FILES)
        mirrors=f['baseline_mirrors']
        for row in f['baseline_resources']:
            if row['path'] not in mirrors:
                self.assertEqual(hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest(),row['sha256'],row['path'])
        for path,old in mirrors.items():
            current=json.loads((ROOT/path).read_bytes());projected=copy.deepcopy(current)
            for key in ('bootstrap_digest','protected_closure_digest'):projected[key]=old[key]
            self.assertEqual(len(projected['protected_resources']),len(old['protected_resources']))
            for row,prior in zip(projected['protected_resources'],old['protected_resources'],strict=True):
                source=row.get('path',row.get('source'))
                self.assertEqual(row['raw_sha256'],hashlib.sha256((ROOT/source).read_bytes()).hexdigest())
                row['raw_sha256']=prior['raw_sha256']
                self.assertEqual(row,prior)
            self.assertEqual(projected,old,path)
        performance='config/performance/performance-benchmark-installation-bootstrap-v1.json'
        self.assertEqual(json.loads((ROOT/performance).read_bytes()),mirrors[performance])
        protected=json.loads((ROOT/'config/release-operations/release-operations-installation-bootstrap-v1.json').read_bytes())['protected_resources']
        for row in protected:self.assertEqual(row['raw_sha256'],hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest())
        config=tomllib.loads((ROOT/'pyproject.toml').read_text())
        self.assertEqual(config['project']['dependencies'],['cryptography==50.0.0','packaging==26.3'])
        self.assertEqual(config['build-system'],{'requires':[],'build-backend':'build_backend','backend-path':['scripts']})
        self.assertEqual(config['tool']['gew']['build']['direct-scripts'],{'graph-engineering':'graph_engineering.cli:main'})
