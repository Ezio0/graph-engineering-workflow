"""Local Owner decisions use real private terminal I/O and owned plans."""
import unittest
from tests.support.installation_authority import ApprovalFixture,inventory
from tests.support.release_staging import require_success

class InstallationAuthorityIntegrationTests(unittest.TestCase):
    def test_real_terminal_local_approval(self):
        with ApprovalFixture() as f:
            before=inventory(f.release.base);v=require_success(self,f.terminal())
            self.assertEqual(v['worker_exit'],0,v['value']);self.assertEqual(v['value']['code'],'authority_issued')
            self.assertTrue(v['responded']);self.assertTrue(v['display_verified']);self.assertEqual(inventory(f.release.base),before)

    def test_terminal_owner_foreground_refusals(self):
        code='''from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
owner=ReleaseInstaller();plan=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
assert type(plan) is StagePlanEnvelope
value=owner.authorize_local(plan);assert type(value) is dict and value['code']=='authority_required',value
plan.close();print(json.dumps(value))
'''
        with ApprovalFixture() as f:
            before=inventory(f.release.base);self.assertEqual(require_success(self,f.plan(code))['code'],'authority_required')
            for flag in ('ICANON','ECHO'):
                setup="import termios\na=termios.tcgetattr(0);a[3]&=~termios."+flag+";termios.tcsetattr(0,termios.TCSANOW,a)"
                v=require_success(self,f.terminal(before=setup));self.assertEqual(v['worker_exit'],0,v)
                self.assertFalse(v['responded']);self.assertEqual(v['value']['code'],'authority_required')
            background='''import signal
helper=os.fork()
if helper==0:
 os.setpgid(0,0);signal.pause();os._exit(2)
os.setpgid(helper,helper);signal.signal(signal.SIGTTOU,signal.SIG_IGN);os.tcsetpgrp(0,helper)
'''
            cleanup='''os.tcsetpgrp(0,os.getpgrp());os.kill(helper,signal.SIGKILL);os.waitpid(helper,0)'''
            v=require_success(self,f.terminal(before=background,after=cleanup));self.assertEqual(v['worker_exit'],0,v)
            self.assertFalse(v['responded']);self.assertEqual(v['value']['code'],'authority_required')
            self.assertEqual(inventory(f.release.base),before)
        # A real configured UID mismatch is refused by the owned planning boundary.
        from tests.support.release_staging import StageFixture
        def wrong_owner(v):v['roots'][0]['owner_id']=str(int(v['roots'][0]['owner_id'])+1)
        with StageFixture(registry_patch=wrong_owner) as f:
            v=require_success(self,f.plan());self.assertIn(v['status'],('rejected','blocked'))

    def test_response_io_limits_and_refusal(self):
        with ApprovalFixture() as f:
            before=inventory(f.release.base)
            for response,code in [('wrong','authority_required'),('eof','authority_required'),('long','resource_limit'),('two','authority_required'),('wait','authority_required')]:
                v=require_success(self,f.terminal(response=response));self.assertEqual(v['worker_exit'],0,v)
                self.assertTrue(v['responded'],v);self.assertEqual(v['value']['code'],code,v)
            v=require_success(self,f.terminal(preload=b'UNSOLICITED\n'));self.assertEqual(v['worker_exit'],0,v)
            self.assertFalse(v['responded']);self.assertEqual(v['value']['code'],'authority_required')
            self.assertEqual(inventory(f.release.base),before)

    def test_wait_input_currentness(self):
        with ApprovalFixture() as f:
            # The terminal peer changes actual admitted bytes only after seeing this invocation's prompt.
            paths=[f.release.manifest_path,f.release.source/'config/release-installation/installation-approval-policy-v1.json']
            for path in paths:
                original=path.read_bytes()
                try:
                    change='p=pathlib.Path('+repr(str(path))+');p.write_bytes(p.read_bytes()+b" ")'
                    v=require_success(self,f.terminal(mutate=change));self.assertEqual(v['worker_exit'],0,v)
                    self.assertTrue(v['responded']);self.assertIn(v['value']['code'],('currentness','trust_rejected'),v)
                finally:path.write_bytes(original)
            backup=f.candidates.with_name('candidates-before-wait')
            try:
                mutation='p=pathlib.Path('+repr(str(f.candidates))+');p.rename(pathlib.Path('+repr(str(backup))+'));p.mkdir(mode=0o700)'
                v=require_success(self,f.terminal(mutate=mutation));self.assertEqual(v['worker_exit'],0,v)
                self.assertTrue(v['responded']);self.assertEqual(v['value']['code'],'currentness')
            finally:
                f.candidates.rmdir();backup.rename(f.candidates)
            mutation='import termios\na=termios.tcgetattr(fd);a[3]&=~termios.ECHO;termios.tcsetattr(fd,termios.TCSANOW,a)'
            v=require_success(self,f.terminal(mutate=mutation));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['responded']);self.assertEqual(v['value']['code'],'currentness')
            before=inventory(f.release.base);v=require_success(self,f.terminal())
            self.assertEqual(v['value']['code'],'authority_issued',v);self.assertEqual(inventory(f.release.base),before)

    def test_grant_consumption_and_operation(self):
        exercise='''import copy,pickle
from graph_engineering.application.installation_authority import InstallationAuthority,StagePermit
for operation in (lambda:copy.copy(grant),lambda:copy.deepcopy(grant),lambda:pickle.dumps(grant),lambda:json.dumps(grant)):
 try:operation()
 except TypeError:pass
 else:raise AssertionError('grant copied or serialized')
value=grant.diagnostic();permit=owner._consume_for_stage(plan,grant)
for operation in (grant.require_current,lambda:owner._consume_for_stage(plan,grant)):
 try:operation()
 except ValueError:pass
 else:raise AssertionError('consumed grant admitted')
assert owner.authorize_local(plan)['code']=='currentness'
permit.require_current();permit.close()
assert owner.authorize_local(plan)['code']=='currentness'
try:permit.require_current()
except ValueError:pass
else:raise AssertionError('closed permit revived')
'''
        with ApprovalFixture() as f:
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertEqual(v['value']['code'],'authority_issued',v)
            # A different owner cannot consume the same live grant; failure revokes it permanently.
            exercise='''other=ReleaseInstaller()
try:other._consume_for_stage(plan,grant)
except ValueError:pass
else:raise AssertionError('foreign owner consumed grant')
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('failed consumption refunded grant')
value={'foreign_owner_refused':True}
'''
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['value']['foreign_owner_refused'])

            exercise='''req=json.loads(pathlib.Path(sys.argv[2]).read_bytes());bundle=BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4]))
fresh=owner.plan(req,bundle);assert type(fresh) is StagePlanEnvelope
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('plan rotation retained grant')
fresh.require_current();fresh.close();value={'rotation_refused':True}
'''
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['value']['rotation_refused'])
            exercise='''pid=os.fork()
if pid==0:
 try:grant.require_current()
 except ValueError:os._exit(0)
 os._exit(1)
assert os.waitpid(pid,0)[1]==0
permit=owner._consume_for_stage(plan,grant);permit.close();value={'fork_refused':True}
'''
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['value']['fork_refused'])

    def test_deadline_interrupt_and_cleanup(self):
        from tests.support.release_staging import seal,write_json
        def short(field):
            def patch(source):
                p=source/'config/release-installation/installation-approval-policy-v1.json'
                v=__import__('json').loads(p.read_bytes());v[field]=1;write_json(p,seal(v,'installation-approval-policy','policy_digest'))
            return patch
        # Pause only the test worker at an observed real deadline. Tracing does
        # not replace product code, clocks, providers or grant decisions.
        for field,code in (('max_wait_seconds','authority_required'),('max_grant_seconds','currentness')):
            before='''import sys,time
from graph_engineering.adapters import installation_authority as physical
held=[]
target_code=(physical.ApprovalSession.decide.__code__ if FIELD=='max_wait_seconds' else physical.ApprovalSession.require_current.__code__)
def hold_worker(frame,event,arg):
 if event!='call' or frame.f_code is not target_code:return None
 session=frame.f_locals['self']
 boundary=(FIELD=='max_wait_seconds' or session.issued)
 if boundary and not held:
  deadline=session.deadline;fd=session.fd
  time.sleep(max(0,(deadline-time.monotonic_ns())/1_000_000_000)+0.1)
  assert time.monotonic_ns()>=deadline and session.deadline==deadline
  held.append((session,fd,deadline));sys.settrace(None)
 return None
sys.settrace(hold_worker)
'''.replace('FIELD',repr(field))
            after='''sys.settrace(None)
assert len(held)==1,'real deadline was not observed'
session,fd,deadline=held[0]
assert session.deadline==deadline and session.closed and session.fd is None
try:os.fstat(fd)
except OSError:pass
else:raise AssertionError('short deadline descriptor leaked')
'''
            with ApprovalFixture(patch=short(field)) as f:
                before_inventory=inventory(f.release.base)
                v=require_success(self,f.terminal(before=before,after=after));self.assertEqual(v['worker_exit'],0,v)
                self.assertEqual(v['value']['code'],code,v)
                self.assertEqual(v['responded'],field=='max_grant_seconds')
                self.assertEqual(inventory(f.release.base),before_inventory)
        exercise='''import time,gc
from graph_engineering.application import installation_authority as local
session=local._GRANTS[id(grant)]['session'];fd=session.fd
value={'expired':False};time.sleep(16)
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('expired grant admitted')
assert session.closed and session.fd is None
try:os.fstat(fd)
except OSError:pass
else:raise AssertionError('expired descriptor leaked')
value['expired']=True
'''
        with ApprovalFixture() as f:
            before=inventory(f.release.base);v=require_success(self,f.terminal(exercise=exercise))
            self.assertEqual(v['worker_exit'],0,v);self.assertTrue(v['value']['expired']);self.assertEqual(inventory(f.release.base),before)

            v=require_success(self,f.terminal(response='wait',mutate='os.kill(pid,signal.SIGINT)'))
            self.assertTrue(v['responded']);self.assertEqual(v['worker_exit'],1,v)
            self.assertEqual(v['value']['worker_error'],'KeyboardInterrupt');self.assertEqual(inventory(f.release.base),before)
            exercise='''import gc,termios
from graph_engineering.application import installation_authority as local
session=local._GRANTS[id(grant)]['session'];fd=session.fd
assert termios.tcgetattr(0)==terminal_before
del grant;gc.collect();assert session.closed and session.fd is None
try:os.fstat(fd)
except OSError:pass
else:raise AssertionError('destructor descriptor leaked')
value={'destructor_closed':True}
'''
            v=require_success(self,f.terminal(before='import termios;terminal_before=termios.tcgetattr(0)',exercise=exercise))
            self.assertEqual(v['worker_exit'],0,v);self.assertTrue(v['value']['destructor_closed']);self.assertEqual(inventory(f.release.base),before)

    def test_producing_ports_and_runtime_refuse(self):
        code='''import os
from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope,install_apply_unavailable
owner=ReleaseInstaller();plan=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
assert type(plan) is StagePlanEnvelope
for fake in (True,False,None,{'approved':True},{'owner_id':str(os.getuid())},lambda:True):
 for operation in (owner.stage,owner.reopen_staged):
  v=operation(plan,fake);assert v['code']=='phase_unavailable' and v['capabilities']['stage']=='unavailable',v
 try:owner._consume_for_stage(plan,fake)
 except ValueError:pass
 else:raise AssertionError('unowned authority admitted')
v,exit_code=install_apply_unavailable();assert exit_code==3 and v['code']=='phase_unavailable'
plan.require_current();plan.close();print(json.dumps({'producing_ports_refused':True}))
'''
        with ApprovalFixture() as f:
            before=inventory(f.release.base);v=require_success(self,f.plan(code));self.assertTrue(v['producing_ports_refused'])
            self.assertEqual(inventory(f.release.base),before)
