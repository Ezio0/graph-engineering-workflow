"""Provider replacement must execute zero substituted calls; values never grant authority."""
import unittest
from tests.support.installation_authority import ApprovalFixture,inventory,provider_substitution_probe
from tests.support.release_staging import require_success

class InstallationAuthoritySecurityTests(unittest.TestCase):
    def test_provider_substitution_zero_calls(self):
        before='''from graph_engineering.adapters import installation_authority as physical
from graph_engineering.application import installation_authority as local
from graph_engineering.core import installation_authority as contracts
calls=[]
def spy(*args,**kwargs):calls.append(True);raise AssertionError('substituted provider called')
upstream=physical.planning.admission.ReleaseObservation._require_current
original_code=upstream.__code__;upstream.__code__=spy.__code__
try:
 rejected=owner.authorize_local(plan);assert rejected['code']=='trust_rejected',rejected
finally:upstream.__code__=original_code
assert not calls,'upstream method code executed'
for module,name in ((physical.stat,'S_ISCHR'),(contracts.json,'dumps'),(contracts.json.encoder,'INFINITY')):
 original=getattr(module,name);setattr(module,name,spy)
 try:
  rejected=owner.authorize_local(plan);assert rejected['code']=='trust_rejected',rejected
 finally:setattr(module,name,original)
 assert not calls,(name,len(calls))
for module,name in ((contracts,'measure'),(contracts,'stage_digest'),(physical,'_READ'),(physical,'_WRITE'),(physical,'_POLL'),(physical,'_CLOCK'),(physical,'_RANDOM'),(physical,'_CLOSE'),(physical,'_CONTEXT'),(local,'_APPROVE'),(local,'_DIAGNOSTIC'),(local,'_PLAN_CURRENT'),(local,'_GUARD'),(local._PLANNING,'_LOCAL_AUTHORIZE'),(local._PLANNING,'_LOCAL_CONSUME'),(physical.ApprovalSession,'decide'),(physical.ApprovalSession,'close'),(physical.installation,'_provenance_values'),(physical,'_RECORD_OP')):
 original=getattr(module,name);setattr(module,name,spy)
 try:
  try:rejected=owner.authorize_local(plan)
  except ValueError:pass
  else:assert rejected['code']=='trust_rejected',rejected
 finally:setattr(module,name,original)
 assert not calls,(name,len(calls))
# A new descriptor is also a substitution, even though no prior attribute exists.
physical.ApprovalSession.fd=property(spy)
try:
 rejected=owner.authorize_local(plan);assert rejected['code']=='trust_rejected',rejected
finally:del physical.ApprovalSession.fd
assert not calls
'''
        with ApprovalFixture() as f:
            for phase in ('acquisition','waiting','retained','consumption'):
                v=require_success(self,f.terminal(**provider_substitution_probe(phase,'guard_code')))
                self.assertEqual(v['worker_exit'],0,v)
                if phase in ('acquisition','waiting'):self.assertEqual(v['value']['code'],'trust_rejected')
                else:
                    self.assertEqual(v['value']['substituted_calls'],0)
                    self.assertTrue(v['value']['sticky'])
            v=require_success(self,f.terminal(before=before));self.assertEqual(v['worker_exit'],0,v)
            self.assertEqual(v['value']['code'],'authority_issued',v)
            exercise='''from graph_engineering.adapters import installation_authority as physical
from graph_engineering.application import installation_authority as local
calls=[];session=local._GRANTS[id(grant)]['session'];fd=session.fd
original=physical._CLOSE
def spy(*args,**kwargs):calls.append(True);raise AssertionError('changed cleanup called')
physical._CLOSE=spy
try:
 try:grant.require_current()
 except ValueError:pass
 else:raise AssertionError('changed cleanup admitted')
finally:physical._CLOSE=original
assert not calls and session.closed and session.fd is None
try:os.fstat(fd)
except OSError:pass
else:raise AssertionError('original cleanup not used')
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('provider restoration revived grant')
value={'substituted_calls':len(calls),'sticky':True}
'''
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertEqual(v['value']['substituted_calls'],0);self.assertTrue(v['value']['sticky'])

            before='''import signal
from graph_engineering.adapters import installation_authority as physical
calls=[];original=physical._READ
def spy(*args,**kwargs):calls.append(True);raise AssertionError('wait provider called')
def changed(signum,frame):physical._READ=spy
signal.signal(signal.SIGUSR1,changed)
'''
            after='''physical._READ=original
assert not calls and type(grant) is dict and grant['code']=='trust_rejected',grant
'''
            v=require_success(self,f.terminal(before=before,after=after,mutate='os.kill(pid,signal.SIGUSR1)'))
            self.assertEqual(v['worker_exit'],0,v);self.assertEqual(v['value']['code'],'trust_rejected')
            exercise='''from graph_engineering.core import installation_authority as contracts
original=contracts.measure.__code__;calls=[]
def substituted(*args,**kwargs):raise AssertionError('changed function code called')
contracts.measure.__code__=substituted.__code__
try:
 try:owner._consume_for_stage(plan,grant)
 except ValueError:pass
 else:raise AssertionError('changed consumer provider admitted')
finally:contracts.measure.__code__=original
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('consumer failure refunded grant')
value={'consume_substitution_refused':True}
'''
            v=require_success(self,f.terminal(exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['value']['consume_substitution_refused'])
            for phase in ('waiting','retained','consumption'):
                # Isolate each fault: one sealed dependency cannot mask a gap
                # in another dependency's check.
                for target in ('upstream','stat','json','cleanup_code','descriptor'):
                    v=require_success(self,f.terminal(**provider_substitution_probe(phase,target)))
                    self.assertEqual(v['worker_exit'],0,v)
                    if phase=='waiting':self.assertEqual(v['value']['code'],'trust_rejected')
                    else:
                        self.assertEqual(v['value']['substituted_calls'],0)
                        self.assertTrue(v['value']['sticky'])
            # Restoration requires a fresh real producer and consumer, never an old grant.
            v=require_success(self,f.terminal());self.assertEqual(v['worker_exit'],0,v)
            self.assertEqual(v['value']['code'],'authority_issued')

    def test_unowned_replayed_values_refuse(self):
        before='''from graph_engineering.application.installation_authority import InstallationAuthority,StagePermit
from graph_engineering.application import installation_authority as local
calls=[]
class Suspect:
 def __hash__(self):calls.append('hash');raise AssertionError('caller hash called')
 def __eq__(self,other):calls.append('equality');raise AssertionError('caller equality called')
 def __call__(self):calls.append('callback');raise AssertionError('caller callback called')
for fake in (Suspect(),True,False,{},plan.to_dict(),{'approved':True,'owner_id':str(os.getuid())},{'challenge_digest':'sha256-jcs-v1:'+'1'*64},{'decision':True,'policy':{},'clock':0,'descriptor':0},object.__new__(InstallationAuthority),object.__new__(StagePermit)):
 try:owner._consume_for_stage(plan,fake)
 except ValueError:pass
 else:raise AssertionError('unowned authority consumed')
assert not calls
'''
        exercise='''import threading
from graph_engineering.application import installation_authority as local
session=local._GRANTS[id(grant)]['session'];out=[]
def other_thread():
 try:grant.require_current()
 except ValueError:out.append('refused')
t=threading.Thread(target=other_thread);t.start();t.join(10)
assert not t.is_alive() and out==['refused'] and session.closed
try:owner._consume_for_stage(plan,grant)
except ValueError:pass
else:raise AssertionError('cross-thread invalidation did not stick')
value={'unowned_refused':True,'cross_thread_refused':True}
'''
        with ApprovalFixture() as f:
            before_inventory=inventory(f.release.base)
            v=require_success(self,f.terminal(before=before,exercise=exercise));self.assertEqual(v['worker_exit'],0,v)
            self.assertTrue(v['value']['unowned_refused']);self.assertTrue(v['value']['cross_thread_refused'])
            self.assertEqual(inventory(f.release.base),before_inventory)
