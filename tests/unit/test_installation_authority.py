"""Expected local approval contracts independent of live ownership."""
import copy
import hashlib
import importlib
import json
import unittest
from tests.support.release_staging import context,stage_framed,seal,plan_record,policies

def core():return importlib.import_module('graph_engineering.core.installation_authority')
def policy(**changes):
    return seal(dict(schema_version='1.0.0',policy_id='fixture-approval',max_prompt_bytes=8192,max_input_bytes=80,
                     max_wait_seconds=1,max_grant_seconds=1,**changes),'installation-approval-policy','policy_digest')
def envelope():
    s,p,r=policies();c=seal(dict(schema_version='1.0.0',stage_policy_digest=s['policy_digest'],installer_policy_digest=p['policy_digest'],
      recipe_digest=r['recipe_digest'],target_registry_digest=s['policy_digest'],target_binding_digest=p['policy_digest']),'stage-context','context_digest')
    return seal(dict(schema_version='1.0.0',plan=plan_record(),stage_context=c),'stage-plan-envelope','envelope_digest')
def challenge():
    e=envelope();v=dict(schema_version='1.0.0',request_id=e['plan']['request_id'],installation_id=e['plan']['installation_id'],operation='install',
      plan_digest=e['plan']['plan_digest'],context_digest=e['stage_context']['context_digest'],envelope_digest=e['envelope_digest'],policy_digest=policy()['policy_digest'],
      owner_id='42',invocation_nonce='a'*32,display_digest='sha256:'+'1'*64)
    return seal(v,'installation-approval-challenge','challenge_digest')

class InstallationAuthorityUnitTests(unittest.TestCase):
    def test_policy_closed_limits(self):
        c=core();v=policy();self.assertEqual(c.validate_policy(v,context()),v)
        for key in ('max_prompt_bytes','max_input_bytes','max_wait_seconds','max_grant_seconds'):
            for bad in (0,True,-1,9007199254740992,float('inf')):
                raw=dict(v,**{key:bad});raw.pop('policy_digest')
                if bad==float('inf'):
                    with self.assertRaises(ValueError):c.validate_policy(raw,context())
                else:
                    with self.assertRaises(ValueError):c.validate_policy(seal(raw,'installation-approval-policy','policy_digest'),context())
        for key in v:
            raw=dict(v);raw.pop(key)
            with self.assertRaises(ValueError):c.validate_policy(raw,context())
        with self.assertRaises(ValueError):c.validate_policy(dict(v,extra=True),context())

    def test_challenge_exact_bindings(self):
        c=core();v=challenge();self.assertEqual(c.validate_challenge(v,context()),v)
        self.assertEqual(v['challenge_digest'],stage_framed('installation-approval-challenge',{k:x for k,x in v.items() if k!='challenge_digest'})[1])
        for key in v:
            bad=dict(v);bad[key]=False
            with self.assertRaises(ValueError):c.validate_challenge(bad,context())
        for change in ({'owner_id':'042'},{'invocation_nonce':'A'*32},{'display_digest':v['plan_digest']},{'operation':'upgrade'},{'extra':1}):
            with self.assertRaises(ValueError):c.validate_challenge(seal(dict(v,**change),'installation-approval-challenge','challenge_digest'),context())

    def test_display_digest_and_safe_render(self):
        c=core();e=envelope();targets=[{'ref':'candidate','role':'candidate-parent','path':'/synthetic/\\n\x1b[0m'}]
        b=c.render_display(e,'42',targets,policy(),context());self.assertIs(type(b),bytes)
        self.assertNotIn(b'\x1b',b);self.assertIn(b'\\u001b',b)
        for x in (e['envelope_digest'],e['plan']['plan_digest'],e['stage_context']['context_digest']):self.assertIn(x.encode(),b)
        self.assertEqual(c.display_digest(b),'sha256:'+hashlib.sha256(b'urn:gew:display:installation-approval:1.0.0\x00'+b).hexdigest())
        small=dict(policy(),max_prompt_bytes=1);small=seal(small,'installation-approval-policy','policy_digest')
        with self.assertRaises(ValueError):c.render_display(e,'42',targets,small,context())

    def test_response_exact_grammar(self):
        c=core();nonce='a'*32;raw=b'APPROVE '+nonce.encode()+b'\n'
        self.assertTrue(c.parse_response(raw,nonce,len(raw)))
        for b in (raw[:-1],b' '+raw,raw+b'\n',raw.lower(),b'APPROVE '+b'b'*32+b'\n',b'',raw.replace(b'\n',b'\r\n'),b'APPROVE '+nonce.encode()+b'\xc2\xa0\n',b'APPROVE '+b'0'*32+b'\n'):
            with self.assertRaises(ValueError):c.parse_response(b,nonce,80)
        with self.assertRaises(ValueError):c.parse_response(raw,nonce,len(raw)-1)

        # Isolated I/O control traces exercise the production loops only. They do
        # not create an owned session, a human decision, a grant or a consumer.
        from graph_engineering.adapters import installation_authority as physical
        from unittest.mock import patch
        class Trace:
            def __init__(self):
                self.fd=7;self.deadline=100;self.tick=0;self.policy={'max_input_bytes':80}
            def require_current(self):
                self.tick+=1
                if self.tick>=self.deadline:raise TimeoutError('original deadline')
                return self.tick
            require_facts_current=require_current
            def _ready(self,write=False):return physical.ApprovalSession._ready(self,write)
        trace=Trace();remaining=[];written=[];events=iter([2,InterruptedError(),BlockingIOError(),3,100])
        def poll(read,write,error,timeout):
            remaining.append(timeout);return read,write,[]
        def write(fd,body):
            event=next(events)
            if isinstance(event,BaseException):raise event
            count=min(event,len(body));written.append(body[:count]);return count
        with patch.object(physical,'_POLL',poll),patch.object(physical,'_WRITE',write):
            physical.ApprovalSession._write_prompt(trace,b'complete-prompt')
        self.assertEqual(b''.join(written),b'complete-prompt');self.assertEqual(trace.deadline,100)
        self.assertTrue(all(a>b for a,b in zip(remaining,remaining[1:])))
        reads=iter([InterruptedError(),BlockingIOError(),b'APPROVE ',nonce.encode(),b'\n'])
        def read(fd,maximum):
            event=next(reads)
            if isinstance(event,BaseException):raise event
            self.assertLessEqual(len(event),maximum);return event
        with patch.object(physical,'_POLL',poll),patch.object(physical,'_READ',read):
            self.assertEqual(physical.ApprovalSession._read_line(Trace()),raw)
        with patch.object(physical,'_POLL',poll),patch.object(physical,'_READ',return_value=b'X'*81):
            with self.assertRaises(ValueError):physical.ApprovalSession._read_line(Trace())
        stalled=Trace();stalled.deadline=5
        with patch.object(physical,'_POLL',poll),patch.object(physical,'_WRITE',side_effect=BlockingIOError):
            with self.assertRaises(TimeoutError):physical.ApprovalSession._write_prompt(stalled,b'prompt')
        self.assertEqual(stalled.deadline,5)
        interrupted=Trace()
        with patch.object(physical,'_POLL',side_effect=InterruptedError):
            self.assertFalse(physical.ApprovalSession._ready(interrupted))
        self.assertEqual(interrupted.tick,1)

    def test_lifetime_state_transitions(self):
        c=core();state='admitted'
        for event,want in [('display','displayed'),('decide','decision'),('issue','issued'),('consume','consumed'),('close','closed')]:
            state=c.next_state(state,event);self.assertEqual(state,want)
        for state in ('admitted','displayed','decision','issued','consumed','closed'):
            self.assertEqual(c.next_state(state,'close'),'closed')
        allowed={('admitted','display'):'displayed',('displayed','decide'):'decision',('decision','issue'):'issued',('issued','consume'):'consumed'}
        for state in ('admitted','displayed','decision','issued','consumed','closed'):
            for event in ('display','decide','issue','consume','regress','expire','partial-transfer'):
                if (state,event) in allowed:self.assertEqual(c.next_state(state,event),allowed[(state,event)])
                else:
                    with self.assertRaises(ValueError):c.next_state(state,event)

    def test_diagnostic_bounds_privacy(self):
        from graph_engineering.application.installation_authority import _bootstrap
        self.assertEqual(core().validate_diagnostic(_bootstrap(),context())['code'],'trust_rejected')
        c=core();v=c.diagnostic('authority_issued',context());self.assertEqual(c.validate_diagnostic(v,context()),v)
        size=len(json.dumps(v,sort_keys=True,separators=(',',':')).encode());self.assertEqual(c.diagnostic('authority_issued',context(),maximum=size),v)
        with self.assertRaises(ValueError):c.diagnostic('authority_issued',context(),maximum=size-1)
        for change in ({'extra':'secret'},{'refs':['/private/secret']},{'capabilities':{}},{'phase':'stage'}):
            with self.assertRaises(ValueError):c.validate_diagnostic(dict(v,**change),context())
        for code in ('input_invalid','authority_required','currentness','resource_limit','trust_rejected','phase_unavailable'):
            result=c.diagnostic(code,context());self.assertNotEqual(result['status'],'approved')
            self.assertEqual(result['capabilities']['install-apply'],'unavailable')
