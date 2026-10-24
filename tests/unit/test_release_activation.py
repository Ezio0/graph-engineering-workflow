"""Independent closed-contract and transition vectors."""
import copy
import hashlib
import importlib
import json
import unittest
from pathlib import Path
from tests.support.release_staging import context

ROOT = Path(__file__).resolve().parents[2]

def core():
    return importlib.import_module('graph_engineering.core.release_activation')

def fixture():
    return json.loads((ROOT/'tests/fixtures/release-activation-contract-v1.json').read_bytes())

def seal(kind, body, field, *, frame_patch=None):
    body = copy.deepcopy(body)
    body.pop(field, None)
    frame = dict(algorithm='sha-256', body=body,
        canonicalizer='urn:gew:canonicalizer:jcs-input:1.0.0',
        contract_type='urn:gew:contract:release-'+kind+'-v1',
        digest_domain='urn:gew:digest:semantic:1.0.0',
        projection_id='urn:gew:digest-projection:release-'+kind+'-v1:1.0.0',
        schema_id='urn:gew:schema:'+kind+':1.0.0')
    frame.update(frame_patch or {})
    body[field] = 'sha256-jcs-v1:'+hashlib.sha256(json.dumps(frame,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    return body

class ReleaseActivationUnitTests(unittest.TestCase):
    def test_closed_record_fields_and_types(self):
        c = core()
        for name in ('validate_activation_record', 'validate_reference_successor',
                     'validate_tuple_links', 'validate_transition_chain'):
            self.assertTrue(callable(getattr(c,name)))
        with self.assertRaises(ValueError) as caught:
            c.validate_activation_record('activation-intent', {}, context())
        self.assertEqual(caught.exception.code,'input_invalid')
        f=fixture()
        for kind in ('unknown','uninstall','',None,False):
            with self.assertRaises(ValueError) as caught:c.validate_activation_record(kind,f['records']['activation-intent'],context())
            self.assertEqual(caught.exception.code,'input_invalid')
        for kind,value in f['records'].items():
            self.assertIsNone(c.validate_activation_record(kind,value,context()))
            for key in value:
                bad=copy.deepcopy(value);bad.pop(key)
                if key!=SELF_FIELDS[kind]:bad=seal(kind,bad,SELF_FIELDS[kind])
                with self.subTest(kind=kind,missing=key),self.assertRaises(ValueError) as caught:c.validate_activation_record(kind,bad,context())
                self.assertEqual(caught.exception.code,'input_invalid')
            for bad in (dict(value,extra=True),dict(value,schema_version='2.0.0')):
                bad=seal(kind,bad,SELF_FIELDS[kind])
                with self.assertRaises(ValueError) as caught:c.validate_activation_record(kind,bad,context())
                self.assertEqual(caught.exception.code,'input_invalid')
            for key in value:
                if key in ('schema_version',SELF_FIELDS[kind]):continue
                wrong_values=(None,False,3.5,[],{},'\x00')+ (('3',) if type(value[key]) is int else ())
                for wrong in wrong_values:
                    if type(wrong) is type(value[key]) and wrong==value[key]:continue
                    if wrong is None and kind=='release-transition-record' and key in ('candidate_leaf_digest','observed_reference_digest'):
                        self.assertIsNone(c.validate_activation_record(kind,seal(kind,dict(value,**{key:None}),SELF_FIELDS[kind]),context()))
                        continue  # Nullable shape; the chain enforces fact evolution.
                    with self.subTest(kind=kind,key=key,wrong=type(wrong).__name__),self.assertRaises(ValueError) as caught:
                        c.validate_activation_record(kind,seal(kind,dict(value,**{key:wrong}),SELF_FIELDS[kind]),context())
                    self.assertEqual(caught.exception.code,'resource_limit' if key in ('generation','activation_epoch','sequence','refs') and type(wrong) is not float else 'input_invalid')
        for kind,value in f['records'].items():
            for wrong in (None,False,1,[],{},'sha256-jcs-v1:'+'0'*64):
                with self.assertRaises(ValueError) as caught:c.validate_activation_record(kind,dict(value,**{SELF_FIELDS[kind]:wrong}),context())
                self.assertEqual(caught.exception.code,'trust_rejected' if type(wrong) is str else 'input_invalid')
        for operation in ('uninstall','unknown'):
            value=seal('activation-intent',dict(f['records']['activation-intent'],operation=operation),'intent_digest')
            with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-intent',value,context())
            self.assertEqual(caught.exception.code,'input_invalid')
        value=seal('release-tuple-manifest',dict(f['records']['release-tuple-manifest'],bootstrap_protocol='release-dispatch-v2'),'tuple_digest')
        with self.assertRaises(ValueError) as caught:c.validate_activation_record('release-tuple-manifest',value,context())
        self.assertEqual(caught.exception.code,'input_invalid')

    def test_domain_digest_known_vectors(self):
        from graph_engineering.core.release_staging import stage_digest
        f=fixture()
        for kind,value in f['records'].items():
            field=SELF_FIELDS[kind];body={k:v for k,v in value.items() if k!=field}
            self.assertEqual(seal(kind,body,field)[field],value[field])
            self.assertEqual(stage_digest(kind,body,context()),value[field])
            bad=dict(value,**{field:seal('different-domain',body,field)[field]})
            with self.assertRaises(ValueError):core().validate_activation_record(kind,bad,context())
            for domain in ('contract_type','projection_id','schema_id'):
                bad=seal(kind,body,field,frame_patch={domain:'urn:gew:test:other'})
                with self.subTest(kind=kind,domain=domain),self.assertRaises(ValueError) as caught:core().validate_activation_record(kind,bad,context())
                self.assertEqual(caught.exception.code,'trust_rejected')
            key='request_id' if 'request_id' in value else 'installation_id'
            with self.assertRaises(ValueError) as caught:core().validate_activation_record(kind,dict(value,**{key:'changed-token'}),context())
            self.assertEqual(caught.exception.code,'trust_rejected')
            for token in (value[key]+' ', ' '+value[key], value[key]+'\t'):
                bad=seal(kind,dict(value,**{key:token}),field)
                self.assertNotEqual(bad[field],value[field])
                with self.subTest(kind=kind,whitespace=repr(token)),self.assertRaises(ValueError) as caught:core().validate_activation_record(kind,bad,context())
                self.assertEqual(caught.exception.code,'input_invalid')

    def test_reference_successor_monotonicity(self):
        c=core();refs=fixture()['chain']['reference_history'];a,b=refs[:2]
        for a,b in zip(refs,refs[1:]):
            self.assertIsNone(c.validate_reference_successor(a,b,context()))
            for patch in ({'generation':a['generation']},{'generation':a['generation']+2},{'activation_epoch':a['activation_epoch']},{'activation_epoch':a['activation_epoch']+2},{'previous_reference_digest':DUMMY},{'installation_id':'foreign'},{'generation':True},{'generation':9007199254740992}):
                bad=seal('active-release-reference',dict(b,**patch),'reference_digest')
                with self.subTest(patch=patch),self.assertRaises(ValueError):c.validate_reference_successor(a,bad,context())
        # Both decreased counters remain valid later-generation records; only
        # their relation to the correctly bound predecessor is wrong.
        previous=seal('active-release-reference',dict(refs[-1],generation=4,activation_epoch=4),'reference_digest')
        for key in ('generation','activation_epoch'):
            body=dict(previous,generation=5,activation_epoch=5,previous_reference_digest=previous['reference_digest']);body[key]=3
            bad=seal('active-release-reference',body,'reference_digest')
            self.assertIsNone(c.validate_activation_record('active-release-reference',bad,context()))
            with self.subTest(decreased=key),self.assertRaises(ValueError) as caught:c.validate_reference_successor(previous,bad,context())
            self.assertEqual(caught.exception.code,'closure_mismatch')
        maximum=seal('active-release-reference',dict(b,generation=9007199254740991,activation_epoch=9007199254740991),'reference_digest')
        after_maximum=seal('active-release-reference',dict(b,previous_reference_digest=maximum['reference_digest']),'reference_digest')
        with self.assertRaises(ValueError) as caught:c.validate_reference_successor(maximum,after_maximum,context())
        self.assertEqual(caught.exception.code,'resource_limit')
        before_maximum=seal('active-release-reference',dict(b,generation=9007199254740990,activation_epoch=9007199254740990),'reference_digest')
        last=seal('active-release-reference',dict(maximum,previous_reference_digest=before_maximum['reference_digest']),'reference_digest')
        self.assertIsNone(c.validate_reference_successor(before_maximum,last,context()))

    def test_journal_routes_and_sticky_bindings(self):
        f=fixture();oracle=f['transition_oracle'];pairs=0
        self.assertEqual(len(oracle['states']),13)
        for scenario in oracle['scenarios']:
            operation=scenario['operation'];disposition=scenario['disposition']
            full=recovery(disposition) if operation=='recover' else normal_operation(operation)
            self.assertEqual([r['state'] for r in full['records']],scenario['path'])
            self.assertIsNone(check_chain(full))
            self.assertEqual(set(scenario['successors']),set(oracle['states']))
            prefixes={state:chain_prefix(full,i+1) for i,state in enumerate(scenario['path'])}
            for state in ('block_prepared','blocked','failed_before_switch'):
                prefixes[state]=edge_bundle(prefixes['prepared'],state)
            for old in oracle['states']:
                # Unreachable predecessor rows cannot form a valid prefix; every
                # destination is still enumerated and must remain rejected.
                reachable=old in prefixes
                before=prefixes[old] if reachable else edge_bundle(prefixes['prepared'],old)
                if reachable:self.assertIsNone(check_chain(before))
                else:
                    with self.assertRaises(ValueError):check_chain(before)
                for new in oracle['states']:
                    pairs+=1;bundle=edge_bundle(before,new)
                    with self.subTest(operation=operation,disposition=disposition,old=old,new=new):
                        if new in scenario['successors'][old]:
                            self.assertTrue(reachable);self.assertIsNone(check_chain(bundle))
                        else:
                            with self.assertRaises(ValueError):check_chain(bundle)
            # Every reachable nonterminal can block directly or publish a blocked
            # reference, retaining the selected tuple and candidate/observation.
            for state in scenario['path'][:-1]:
                before=prefixes[state]
                direct=edge_bundle(before,'blocked');self.assertIsNone(check_chain(direct))
                direct['receipt']=terminal_receipt(direct,'blocked')
                with self.assertRaises(ValueError):check_chain(direct)
                prepared=edge_bundle(before,'block_prepared');self.assertIsNone(check_chain(prepared))
                blocked=edge_bundle(prepared,'blocked');blocked['receipt']=terminal_receipt(blocked,'blocked')
                self.assertIsNone(check_chain(blocked))
                # block_prepared cannot declare a blocked publication without Rb.
                no_pointer=copy.deepcopy(prepared);append_record(no_pointer,'blocked')
                with self.assertRaises(ValueError):check_chain(no_pointer)
                # Terminal immutability also applies to receipt-bearing blocking.
                for new in oracle['states']:
                    with self.assertRaises(ValueError):check_chain(edge_bundle(blocked,new))
            # A preparation-linked selected pointer is a valid crash prefix, but
            # invalidates failed_before_switch even without a publication record.
            preparations=('recovery_prepared',) if operation=='recover' else ('verifying_prepared','active_prepared')
            for state in preparations:
                crash=edge_bundle(prefixes[state],scenario['successors'][state][0]);crash['records'].pop()
                self.assertIsNone(check_chain(crash))
                with self.assertRaises(ValueError):check_chain(edge_bundle(crash,'failed_before_switch'))
        self.assertEqual(pairs,845)
        for key,new in [('installation_id','foreign'),('request_id','other'),('operation','recover'),('intent_digest',DUMMY),('plan_digest',DUMMY),('target_tuple_digest',DUMMY),('prior_reference_digest',DUMMY),('candidate_leaf_digest',DUMMY),('candidate_leaf_digest',None),('observed_reference_digest',DUMMY),('observed_reference_digest',None),('previous_record_digest',DUMMY),('sequence',6)]:
            chain=relink_chain(f['chain'],record_patches={3:{key:new}})
            with self.subTest(key=key),self.assertRaises(ValueError):check_chain(chain)
        missing_start=copy.deepcopy(f['chain']);missing_start['records'].pop(0)
        with self.assertRaises(ValueError):check_chain(missing_start)
        # Rv cannot name Ja, nor Ra name Jv. Rv->Ja uses an immutable
        # independently sealed Ja snapshot, since an exact cyclic swap cannot be
        # constructed. Rebind every dependent hash so stale self hashes never
        # mask the preparation/reference/observation relation being tested.
        jv=f['chain']['records'][2]['record_digest'];ja=f['chain']['records'][4]['record_digest']
        for patches in ({1:{'journal_digest':ja}},{2:{'journal_digest':jv}},
                        {1:{'journal_digest':ja},2:{'journal_digest':jv}},
                        {1:{'mode':'active'}},{2:{'mode':'verifying'}},
                        {2:{'previous_reference_digest':f['chain']['reference_history'][0]['reference_digest']}}):
            bad=relink_chain(f['chain'],reference_patches=patches)
            for kind,values in (('release-transition-record',bad['records']),('active-release-reference',bad['reference_history'])):
                for value in values:self.assertIsNone(core().validate_activation_record(kind,value,context()))
            with self.subTest(publication_patch=patches),self.assertRaises(ValueError) as caught:check_chain(bad)
            self.assertEqual(caught.exception.code,'closure_mismatch')

    def test_receipt_terminal_consistency(self):
        c=fixture()['chain'];self.assertIsNone(check_chain(c))
        for bundle in [*[normal_operation(op) for op in ('activate','upgrade','rollback')],recovery('finish_new'),recovery('restore_old'),blocked_publication()]:
            self.assertIsNone(check_chain(bundle))
            for count in range(1,len(bundle['records'])):
                partial=chain_prefix(bundle,count);partial['receipt']=terminal_receipt(partial,bundle['receipt']['outcome'])
                with self.assertRaises(ValueError):check_chain(partial)
        for patch in ({'installation_id':'foreign'},{'request_id':'foreign'},{'operation':'recover'},{'terminal_record_digest':DUMMY},{'selected_reference_digest':DUMMY},{'plan_digest':DUMMY},{'outcome':'restored'}):
            bad=copy.deepcopy(c);bad['receipt']=seal('release-transition-receipt',dict(bad['receipt'],**patch),'receipt_digest')
            with self.assertRaises(ValueError):check_chain(bad)
        for count,refs in ((1,1),(3,2),(6,3)):
            bad=prefix(count,refs);bad['receipt']=c['receipt']
            with self.assertRaises(ValueError):check_chain(bad)
        for terminal in ('failed_before_switch','blocked'):
            bad=prefix(1,1);append_record(bad,terminal);self.assertIsNone(check_chain(bad))
            bad['receipt']=terminal_receipt(bad,'active' if terminal=='failed_before_switch' else 'blocked')
            self.assertIsNone(core().validate_activation_record('release-transition-receipt',bad['receipt'],context()))
            with self.assertRaises(ValueError) as caught:check_chain(bad)
            self.assertEqual(caught.exception.code,'closure_mismatch')
        # Every wrong outcome below is individually legal for the operation and
        # keeps the correct terminal, selected reference and all other bindings.
        for bundle,outcomes in ((normal_operation('activate'),('blocked',)),(recovery('finish_new'),('restored','blocked')),(recovery('restore_old'),('active','blocked')),(blocked_publication(),('active',))):
            self.assertIsNone(check_chain(bundle))
            for outcome in outcomes:
                bad=copy.deepcopy(bundle);bad['receipt']=terminal_receipt(bad,outcome)
                self.assertIsNone(core().validate_activation_record('release-transition-receipt',bad['receipt'],context()))
                with self.subTest(terminal=bad['records'][-1]['state'],outcome=outcome),self.assertRaises(ValueError) as caught:check_chain(bad)
                self.assertEqual(caught.exception.code,'closure_mismatch')
        self.assertIsNone(check_chain(blocked_publication()))

    def test_record_limits_and_cumulative_work(self):
        from graph_engineering.core.contracts.resources import WorkContext,ResourceProfile
        c=core();v=fixture()['records']['activation-intent'];size=len(json.dumps(v,sort_keys=True,separators=(',',':')).encode());base=context()
        def limited(limits=None,balance=None):
            values=dict(base.profile.limits);values.update(limits or {})
            return WorkContext(ResourceProfile(base.profile.profile_id,'1.0.0',values,base.profile.work_budget),base.schedule,initial_balance=balance)
        # The canonical result includes the explicit seven-member digest frame.
        # Its independently serialized byte count, not the implementation's
        # measured usage, supplies the accepting/refusing boundary.
        canonical_size=len(digest_preimage('activation-intent',v,'intent_digest'))
        self.assertGreater(canonical_size,size)
        self.assertIsNone(c.validate_activation_record('activation-intent',v,limited({'raw_document_bytes':size,'result_bytes':canonical_size})))
        self.assertIsNone(c.validate_activation_record('activation-intent',v,limited({'parse_tokens':len(v)+1})))
        # The independently specified digest envelope has seven members around
        # body-without-self, and reaches depth three for this flat record.
        for limits in ({'parse_depth':3},{'object_properties':len(v)-1+7}):
            self.assertIsNone(c.validate_activation_record('activation-intent',v,limited(limits)))
        for limits in ({'raw_document_bytes':size-1},{'parse_tokens':len(v)},{'parse_depth':2},{'object_properties':len(v)-1+6},{'utf8_scalars':1},{'result_bytes':canonical_size-1}):
            with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-intent',v,limited(limits))
            self.assertEqual(caught.exception.code,'resource_limit')
        ctx=context();before=ctx.balance;c.validate_activation_record('activation-intent',v,ctx);spent=before-ctx.balance;self.assertGreater(spent,0)
        exact=limited(balance=spent);c.validate_activation_record('activation-intent',v,exact);self.assertEqual(exact.balance,0)
        with self.assertRaises(ValueError):c.validate_activation_record('activation-intent',v,exact)
        with self.assertRaises(ValueError):c.validate_activation_record('activation-intent',dict(v,extra='x'*65536),context())
        cyc={};cyc['cycle']=cyc
        with self.assertRaises(ValueError):c.validate_activation_record('activation-intent',cyc,context())
        # Valid linked operations isolate cumulative work: every record hash and
        # relationship is correct. The recovery shares actual builtin reference
        # and tuple objects with its one-level source; occurrences still charge.
        for bundle in (fixture()['chain'],recovery('finish_new'),recovery('restore_old')):
            if bundle.get('recovery_source'):
                self.assertIs(bundle['reference_history'][0],bundle['recovery_source']['reference_history'][-1])
                self.assertIs(bundle['tuples'][0],bundle['recovery_source']['tuples'][1])
            entries=chain_records(bundle)
            expected=[len(digest_preimage(kind,record,SELF_FIELDS[kind])) for kind,record in entries]
            ctx=limited();initial=ctx.balance
            self.assertIsNone(c.validate_transition_chain(**bundle,context=ctx))
            charged={}
            for event in ctx.trace:
                if event['event_id']=='digest.input_byte':
                    path=tuple(event['operation_path']);charged[path]=charged.get(path,0)+int(event['count'])
            self.assertEqual(list(charged.values()),expected)
            used=initial-ctx.balance;self.assertGreater(used,spent)
            exact=limited(balance=used);self.assertIsNone(c.validate_transition_chain(**bundle,context=exact));self.assertEqual(exact.balance,0)
            short=limited(balance=used-1)
            with self.assertRaises(ValueError) as caught:c.validate_transition_chain(**bundle,context=short)
            self.assertEqual(caught.exception.code,'resource_limit')
            self.assertEqual(short.trace[-1]['event_id'],'digest.input_byte');self.assertEqual(short.trace[-1]['status'],'rejected')
            # Root six positions plus every nested collection are counted by
            # occurrence, including the same references in a recovery source.
            outer=[bundle.get(key) for key in ('intent','records','reference_history','tuples','receipt','recovery_source')]
            nodes,items=occurrences(outer)
            self.assertIsNone(c.validate_transition_chain(**bundle,context=limited({'parse_tokens':nodes,'array_items':items})))
            for limits in ({'parse_tokens':nodes-1},{'array_items':items-1}):
                with self.assertRaises(ValueError) as caught:c.validate_transition_chain(**bundle,context=limited(limits))
                self.assertEqual(caught.exception.code,'resource_limit')
        links=fixture()['linked_target'];ctx=limited();initial=ctx.balance
        self.assertIsNone(c.validate_tuple_links(**links,context=ctx));used=initial-ctx.balance
        exact=limited(balance=used);self.assertIsNone(c.validate_tuple_links(**links,context=exact));self.assertEqual(exact.balance,0)
        with self.assertRaises(ValueError) as caught:c.validate_tuple_links(**links,context=limited(balance=used-1))
        self.assertEqual(caught.exception.code,'resource_limit')
        # Count expanded occurrences before descent, even for shared builtin data.
        # The small case proves the initial traversal is charged; it precedes the
        # enormous expansion case so a broken implementation fails without a hang.
        for depth in (10,60):
            shared=None
            for _ in range(depth):shared=[shared,shared]
            bad=dict(v,extra=shared);ctx=limited({'array_items':4});before=ctx.balance
            with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-intent',bad,ctx)
            self.assertEqual(caught.exception.code,'resource_limit')
            self.assertLess(ctx.balance,before)
            visits=sum(int(event['count']) for event in ctx.trace if event['event_id']=='parse.token')
            self.assertGreater(visits,0);self.assertLessEqual(visits,len(v)+4)
            empty=limited(balance=0)
            with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-intent',bad,empty)
            self.assertEqual(caught.exception.code,'resource_limit')
            self.assertEqual(len(empty.trace),1);self.assertEqual(empty.trace[0]['status'],'rejected')

    def test_diagnostic_privacy_and_capabilities(self):
        c=core();v=fixture()['records']['activation-diagnostic'];field='diagnostic_digest'
        for status,code,route in [('proposed','phase_unavailable','contract-review'),('blocked','phase_unavailable','phase-implementation'),*[('rejected',code,'supply-inputs') for code in ('input_invalid','trust_rejected','closure_mismatch','resource_limit')]]:
            self.assertIsNone(c.validate_activation_record('activation-diagnostic',seal('activation-diagnostic',dict(v,status=status,code=code,next_route=route),field),context()))
        for refs in ([],[f'ref{i:03d}' for i in range(128)]):
            self.assertIsNone(c.validate_activation_record('activation-diagnostic',seal('activation-diagnostic',dict(v,refs=refs),field),context()))
        distinct=[f'ref{i:03d}' for i in range(129)]
        self.assertEqual(distinct,sorted(set(distinct)))
        with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-diagnostic',seal('activation-diagnostic',dict(v,refs=distinct),field),context())
        self.assertEqual(caught.exception.code,'resource_limit')
        # Keep the list shape, cardinality, order and self hash valid so only
        # the individual control-bearing ref violates the token/privacy rule.
        secret='fixture-control-secret'
        valid=seal('activation-diagnostic',dict(v,refs=['a-ref',secret+'tail']),field)
        self.assertIsNone(c.validate_activation_record('activation-diagnostic',valid,context()))
        for control in ('\x00','\n','\r','\t','\x1b','\x7f'):
            token=secret+control+'tail';refs=['a-ref',token]
            self.assertEqual(refs,sorted(set(refs)))
            bad=seal('activation-diagnostic',dict(v,refs=refs),field)
            self.assertEqual(bad[field],'sha256-jcs-v1:'+hashlib.sha256(digest_preimage('activation-diagnostic',bad,field)).hexdigest())
            with self.subTest(control=ord(control)),self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-diagnostic',bad,context())
            self.assertEqual(caught.exception.code,'input_invalid');self.assertEqual(str(caught.exception),'input_invalid')
            self.assertNotIn(token,str(caught.exception));self.assertNotIn(secret,str(caught.exception))
        for patch in ({'code':None,'next_route':None},{'code':'unknown','next_route':None},{'refs':['b','a']},{'refs':['a','a']},{'refs':['a']*129},{'refs':['/private/fixture-secret']},{'code':'authority_issued'},{'code':'staged'},{'capabilities':dict(v['capabilities'],activate='available')},{'capabilities':dict(v['capabilities'],extra='unavailable')},{'status':'proposed','next_route':'supply-inputs'}):
            with self.assertRaises(ValueError) as caught:c.validate_activation_record('activation-diagnostic',seal('activation-diagnostic',dict(v,**patch),field),context())
            self.assertNotIn('fixture-secret',str(caught.exception))

SELF_FIELDS={'activation-intent':'intent_digest','release-tuple-manifest':'tuple_digest','active-release-reference':'reference_digest','release-transition-record':'record_digest','release-transition-receipt':'receipt_digest','activation-diagnostic':'diagnostic_digest'}
DUMMY='sha256-jcs-v1:'+'d'*64

def digest_preimage(kind,record,field):
    frame=dict(algorithm='sha-256',body={k:v for k,v in record.items() if k!=field},canonicalizer='urn:gew:canonicalizer:jcs-input:1.0.0',
        contract_type='urn:gew:contract:release-'+kind+'-v1',digest_domain='urn:gew:digest:semantic:1.0.0',
        projection_id='urn:gew:digest-projection:release-'+kind+'-v1:1.0.0',schema_id='urn:gew:schema:'+kind+':1.0.0')
    return json.dumps(frame,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()

def chain_records(bundle):
    result=[('activation-intent',bundle['intent'])]
    for kind,key in (('release-transition-record','records'),('active-release-reference','reference_history'),('release-tuple-manifest','tuples')):
        result.extend((kind,record) for record in bundle[key])
    if bundle.get('recovery_source'):result.extend(chain_records(bundle['recovery_source']))
    if bundle['receipt'] is not None:result.append(('release-transition-receipt',bundle['receipt']))
    return result

def occurrences(value):
    children=list(value.values()) if type(value) is dict else value if type(value) is list else []
    nested=[occurrences(child) for child in children]
    return 1+sum(n for n,_ in nested),(len(value) if type(value) is list else 0)+sum(i for _,i in nested)

def check_chain(bundle):
    return core().validate_transition_chain(**bundle,context=context())

def prefix(n,refs):
    c=copy.deepcopy(fixture()['chain']);c['records']=c['records'][:n];c['reference_history']=c['reference_history'][:refs];c['receipt']=None;return c

def append_record(c,state,**patch):
    r=dict(c['records'][-1]);r.update(sequence=len(c['records']),state=state,previous_record_digest=c['records'][-1]['record_digest']);r.update(patch)
    c['records'].append(seal('release-transition-record',r,'record_digest'));return c['records'][-1]

def chain_prefix(full,count):
    c=copy.deepcopy(full);c['records']=c['records'][:count];c['receipt']=None
    observed={r['observed_reference_digest'] for r in c['records']}
    c['reference_history']=[r for i,r in enumerate(c['reference_history']) if i==0 or r['reference_digest'] in observed]
    retain_tuples(c);return c

def retain_tuples(c):
    used={r['tuple_digest'] for r in c['reference_history']}|{c['intent']['target_tuple_digest']}
    c['tuples']=[t for t in c['tuples'] if t['tuple_digest'] in used]

def edge_bundle(before,state):
    c=copy.deepcopy(before);c['receipt']=None;last=c['records'][-1]
    target=next(t for t in c['tuples'] if t['tuple_digest']==c['intent']['target_tuple_digest'])
    patch={}
    if state=='repository_verified':patch['candidate_leaf_digest']=target['repository_leaf_digest']
    # This is a fixture constructor, not the allowed-edge oracle. It supplies
    # consistent candidate publications even when the chosen edge is forbidden.
    modes={'verifying_published':'verifying','active_published':'active','recovered_old':'active','recovered_new':'active'}
    mode='blocked' if state=='blocked' and last['state']=='block_prepared' else modes.get(state)
    if mode:
        base=c['reference_history'][-1]
        reference=seal('active-release-reference',dict(base,generation=base['generation']+1,activation_epoch=base['activation_epoch']+1,
            previous_reference_digest=base['reference_digest'],mode=mode,journal_digest=last['record_digest'],
            tuple_digest=base['tuple_digest'] if mode=='blocked' else target['tuple_digest']),'reference_digest')
        c['reference_history'].append(reference);patch['observed_reference_digest']=reference['reference_digest']
    append_record(c,state,**patch);retain_tuples(c);return c

def terminal_receipt(c,outcome):
    terminal=c['records'][-1]
    body={k:terminal[k] for k in ('schema_version','installation_id','request_id','operation','plan_digest')}
    body.update(terminal_record_digest=terminal['record_digest'],selected_reference_digest=c['reference_history'][-1]['reference_digest'],outcome=outcome)
    return seal('release-transition-receipt',body,'receipt_digest')

def relink_chain(original,record_patches=None,reference_patches=None):
    c=copy.deepcopy(original);record_patches=record_patches or {};reference_patches=reference_patches or {}
    refs=[c['reference_history'][0]];records=[];mapping={refs[0]['reference_digest']:refs[0]['reference_digest']}
    for pos,old in enumerate(c['records']):
        r=dict(old,previous_record_digest=records[-1]['record_digest'] if records else None)
        if old['state'] in ('verifying_published','active_published','recovered_new','recovered_old') or old['state']=='blocked' and records[-1]['state']=='block_prepared':
            prior=c['reference_history'][len(refs)];nr=dict(prior,previous_reference_digest=refs[-1]['reference_digest'],journal_digest=records[-1]['record_digest'])
            nr.update(reference_patches.get(len(refs),{}));nr=seal('active-release-reference',nr,'reference_digest')
            mapping[prior['reference_digest']]=nr['reference_digest'];refs.append(nr)
        r['observed_reference_digest']=mapping.get(r['observed_reference_digest'],r['observed_reference_digest'])
        r.update(record_patches.get(pos,{}));records.append(seal('release-transition-record',r,'record_digest'))
    c['records']=records;c['reference_history']=refs
    c['receipt']=terminal_receipt(c,original['receipt']['outcome']) if original['receipt'] else None
    return c

def recovery_case(original,*,intent_patch=None,target=None,base=None):
    """Reseal a complete recovery bundle; relation negatives keep valid hashes."""
    c=copy.deepcopy(original)
    if target is not None:
        c['tuples'].append(copy.deepcopy(target));c['intent']['target_tuple_digest']=target['tuple_digest']
    if base is not None:
        c['reference_history'][0]=copy.deepcopy(base);c['intent']['expected_reference_digest']=base['reference_digest']
    c['intent'].update(intent_patch or {});c['intent']=seal('activation-intent',c['intent'],'intent_digest')
    target=next(t for t in c['tuples'] if t['tuple_digest']==c['intent']['target_tuple_digest'])
    refs=[c['reference_history'][0]];records=[]
    for old in c['records']:
        record=dict(old,intent_digest=c['intent']['intent_digest'],target_tuple_digest=target['tuple_digest'],prior_reference_digest=refs[0]['reference_digest'],previous_record_digest=records[-1]['record_digest'] if records else None)
        record['candidate_leaf_digest']=None if not records else target['repository_leaf_digest']
        if record['state'] in ('recovered_new','recovered_old'):
            previous=refs[-1]
            refs.append(seal('active-release-reference',dict(c['reference_history'][-1],generation=previous['generation']+1,activation_epoch=previous['activation_epoch']+1,previous_reference_digest=previous['reference_digest'],journal_digest=records[-1]['record_digest'],tuple_digest=target['tuple_digest']),'reference_digest'))
        record['observed_reference_digest']=refs[-1]['reference_digest'] if len(refs)>1 else None
        records.append(seal('release-transition-record',record,'record_digest'))
    c['records']=records;c['reference_history']=refs
    # Keep exactly one copy of every supplied, actually used tuple.
    c['tuples']=list({t['tuple_digest']:t for t in c['tuples']}.values());retain_tuples(c)
    c['receipt']=terminal_receipt(c,original['receipt']['outcome']);return c

def normal_operation(operation):
    c=copy.deepcopy(fixture()['chain']);c['intent']=seal('activation-intent',dict(c['intent'],operation=operation),'intent_digest')
    # Independent chronological rebinding using the fixture's documented state order.
    refs=[c['reference_history'][0]];records=[]
    for original in c['records']:
        r=dict(original,operation=operation,intent_digest=c['intent']['intent_digest'],previous_record_digest=None if not records else records[-1]['record_digest'])
        if r['state'] in ('verifying_published','active_published'):
            old=refs[-1];nr=seal('active-release-reference',dict(c['reference_history'][len(refs)],previous_reference_digest=old['reference_digest'],journal_digest=records[-1]['record_digest']),'reference_digest');refs.append(nr)
        r['observed_reference_digest']=refs[-1]['reference_digest'] if len(refs)>1 else None
        records.append(seal('release-transition-record',r,'record_digest'))
    c['records']=records;c['reference_history']=refs;c['receipt']=seal('release-transition-receipt',dict(c['receipt'],operation=operation,terminal_record_digest=records[-1]['record_digest'],selected_reference_digest=refs[-1]['reference_digest']),'receipt_digest');return c

def blocked_publication():
    c=prefix(1,1);j=append_record(c,'block_prepared');base=c['reference_history'][0]
    ref=seal('active-release-reference',dict(base,generation=2,activation_epoch=2,previous_reference_digest=base['reference_digest'],mode='blocked',journal_digest=j['record_digest']),'reference_digest');c['reference_history'].append(ref)
    terminal=append_record(c,'blocked',observed_reference_digest=ref['reference_digest'])
    c['receipt']=seal('release-transition-receipt',dict(fixture()['chain']['receipt'],terminal_record_digest=terminal['record_digest'],selected_reference_digest=ref['reference_digest'],outcome='blocked'),'receipt_digest');return c

def recovery(disposition='finish_new'):
    source=prefix(3,2);target=copy.deepcopy(source['tuples'][1])
    if disposition=='restore_old':target=seal('release-tuple-manifest',dict(source['tuples'][0],repository_leaf_digest=DUMMY),'tuple_digest')
    base=source['reference_history'][-1]
    intent=seal('activation-intent',dict(source['intent'],operation='recover',request_id='recover-'+disposition,target_tuple_digest=target['tuple_digest'],expected_reference_digest=base['reference_digest'],recovery_source_record_digest=source['records'][-1]['record_digest'],recovery_disposition=disposition),'intent_digest')
    first=dict(source['records'][0],request_id=intent['request_id'],operation='recover',intent_digest=intent['intent_digest'],prior_reference_digest=base['reference_digest'],target_tuple_digest=target['tuple_digest'])
    first=seal('release-transition-record',first,'record_digest')
    c=dict(intent=intent,records=[first],reference_history=[base],tuples=[source['tuples'][1]],receipt=None,recovery_source=source)
    if target['tuple_digest']!=source['tuples'][1]['tuple_digest']:c['tuples'].append(target)
    append_record(c,'repository_verified',candidate_leaf_digest=target['repository_leaf_digest']);j=append_record(c,'recovery_prepared')
    ref=seal('active-release-reference',dict(base,generation=base['generation']+1,activation_epoch=base['activation_epoch']+1,mode='active',tuple_digest=target['tuple_digest'],previous_reference_digest=base['reference_digest'],journal_digest=j['record_digest']),'reference_digest');c['reference_history'].append(ref)
    last=append_record(c,'recovered_new' if disposition=='finish_new' else 'recovered_old',observed_reference_digest=ref['reference_digest'])
    c['receipt']=seal('release-transition-receipt',dict(fixture()['chain']['receipt'],request_id=intent['request_id'],operation='recover',terminal_record_digest=last['record_digest'],selected_reference_digest=ref['reference_digest'],outcome='active' if disposition=='finish_new' else 'restored'),'receipt_digest');return c
