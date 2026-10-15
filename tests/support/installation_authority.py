"""Genuine disposable SOURCE/WHEEL plans with a bounded private terminal peer."""
from __future__ import annotations
import json
import os
import hashlib
from tests.support.release_staging import StageFixture,ROOT,seal,write_json,inventory,expected_envelope,stage_framed

def provider_substitution_probe(phase,target='upstream'):
    """Real worker fault after binding; never supply a product provider."""
    if target not in ('upstream','stat','json','cleanup','cleanup_code','guard_code','descriptor'):raise ValueError(target)
    setup='TARGET='+repr(target)+'\n'+'''from graph_engineering.adapters import installation_authority as physical
from graph_engineering.application import installation_authority as local
from graph_engineering.core import installation_authority as contracts
calls=[];upstream=physical.planning.admission.ReleaseObservation._require_current
if TARGET=='cleanup_code':upstream=physical.ApprovalSession.close
if TARGET=='guard_code':upstream=physical.ProviderSeal.require_current
original_code=upstream.__code__;original_global=upstream.__globals__.get('_h0_substitution_calls',None)
members={'upstream':(),'cleanup_code':(),'guard_code':(),'descriptor':(),'stat':((physical.stat,'S_ISCHR'),),'json':((contracts.json,'dumps'),),'cleanup':((physical,'_CLOSE'),)}[TARGET]
originals=[getattr(module,name) for module,name in members]
def spy(*args,**kwargs):calls.append(True);raise AssertionError('substituted module member called')
def changed_method(*args,**kwargs):_h0_substitution_calls.append(True);raise AssertionError('substituted upstream method called')
def install_attack():
 if TARGET=='descriptor':physical.ApprovalSession.fd=property(spy)
 if TARGET in ('upstream','cleanup_code','guard_code'):
  upstream.__globals__['_h0_substitution_calls']=calls;upstream.__code__=changed_method.__code__
 for module,name in members:setattr(module,name,spy)
def restore_attack():
 if TARGET=='descriptor':del physical.ApprovalSession.fd
 upstream.__code__=original_code
 if original_global is None:upstream.__globals__.pop('_h0_substitution_calls',None)
 else:upstream.__globals__['_h0_substitution_calls']=original_global
 for (module,name),original in zip(members,originals):setattr(module,name,original)
'''
    if phase=='acquisition':
        return {'before':setup+'install_attack()\n','after':"restore_attack();assert not calls and type(grant) is dict and grant['code']=='trust_rejected',grant\n"}
    if phase=='waiting':
        return {'before':setup+'''import signal
def changed(signum,frame):install_attack()
signal.signal(signal.SIGUSR1,changed)
''','mutate':'os.kill(pid,signal.SIGUSR1)','after':"restore_attack();assert not calls and type(grant) is dict and grant['code']=='trust_rejected',grant\n"}
    if phase not in ('retained','consumption'):raise ValueError(phase)
    operation='grant.require_current()' if phase=='retained' else 'owner._consume_for_stage(plan,grant)'
    exercise=setup+'''session=local._GRANTS[id(grant)]['session'];fd=session.fd
install_attack()
try:
 try:OPERATION
 except ValueError:pass
 else:raise AssertionError('substituted providers admitted')
finally:restore_attack()
assert not calls and session.closed and session.fd is None
try:os.fstat(fd)
except OSError:pass
else:raise AssertionError('captured cleanup did not close descriptor')
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('restoration revived invalid grant')
value={'substituted_calls':len(calls),'sticky':True}
'''.replace('OPERATION',operation)
    return {'exercise':exercise}

class ApprovalFixture(StageFixture):
    def __init__(self,*,installed=False,patch=None):
        limits=json.loads((ROOT/'tests/fixtures/installation-authority-v1.json').read_bytes())['approval_limits']
        def setup(source):
            p=source/'config/release-installation/installation-approval-policy-v1.json'
            v=json.loads(p.read_bytes());v.update(limits);write_json(p,seal(v,'installation-approval-policy','policy_digest'))
            if patch:patch(source)
        super().__init__(installed=installed,source_patch=setup)

    def terminal(self,*,response='approve',before='',after='',mutate='',exercise='',preload=b''):
        envelope=expected_envelope(self);plan=envelope['plan'];stage=envelope['stage_context']
        policy=json.loads((self.release.source/'config/release-installation/installation-approval-policy-v1.json').read_bytes())
        fields=[('operation',plan['operation']),('installation_id',plan['installation_id']),('request_id',plan['request_id'])]
        fields.extend((key,plan[key]) for key in ('release_manifest_digest','closure_digest','platform_digest','policy_digest','plan_digest'))
        fields.extend([('context_digest',stage['context_digest']),('envelope_digest',envelope['envelope_digest']),('approval_policy_digest',policy['policy_digest']),('preserve_data',True),('owner_id',str(os.getuid()))])
        targets=[{'ref':row['ref'],'role':row['role'],'path':row['path']} for row in self.registry['roots'] if row['ref'] in self.request['target_refs']]
        fields.extend(('target',row) for row in sorted(targets,key=lambda row:row['ref']))
        body=('Graph Engineering installation approval\n'+''.join(key+': '+json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(',',':'))+'\n' for key,value in fields)+'Staging, activation and release have not happened.\n').encode()
        challenge={'schema_version':'1.0.0','request_id':plan['request_id'],'installation_id':plan['installation_id'],'operation':plan['operation'],'plan_digest':plan['plan_digest'],'context_digest':stage['context_digest'],'envelope_digest':envelope['envelope_digest'],'policy_digest':policy['policy_digest'],'owner_id':str(os.getuid()),'display_digest':'sha256:'+hashlib.sha256(b'urn:gew:display:installation-approval:1.0.0\x00'+body).hexdigest()}
        program='''import os,pty,select,time,signal,re,hashlib
pid,fd=pty.fork()
if pid==0:
 try:
  from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope
  owner=ReleaseInstaller();plan=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
  assert type(plan) is StagePlanEnvelope,plan
  exec(BEFORE)
  grant=owner.authorize_local(plan)
  if type(grant) is dict:value=grant
  else:
   from graph_engineering.application import installation_authority as local
   actual=local._GRANTS[id(grant)]['session'].challenge
   expected=dict(CHALLENGE,invocation_nonce=actual['invocation_nonce'])
   digest_body={'algorithm':'sha-256','body':expected,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0','contract_type':'urn:gew:contract:release-installation-approval-challenge-v1','digest_domain':'urn:gew:digest:semantic:1.0.0','projection_id':'urn:gew:digest-projection:release-installation-approval-challenge-v1:1.0.0','schema_id':'urn:gew:schema:installation-approval-challenge:1.0.0'}
   expected['challenge_digest']='sha256-jcs-v1:'+hashlib.sha256(json.dumps(digest_body,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
   assert actual==expected,'independent challenge binding mismatch'
   if EXERCISE:exec(EXERCISE)
   else:
    value=grant.diagnostic()
    permit=owner._consume_for_stage(plan,grant);permit.close()
    try:owner._consume_for_stage(plan,grant)
    except ValueError:pass
    else:raise AssertionError('grant reused')
  exec(AFTER)
  plan.close();print('H0_RESULT '+json.dumps(value),flush=True);os._exit(0)
 except BaseException as e:
  import traceback
  frames=[{'file':pathlib.Path(x.filename).name,'line':x.lineno,'function':x.name} for x in traceback.extract_tb(e.__traceback__)]
  print('H0_RESULT '+json.dumps({'worker_error':type(e).__name__,'frames':frames}),flush=True);os._exit(1)
data=b'';sent=False;verified=False;limit=time.monotonic()+WALL_SECONDS;status=None;ended=False
if PRELOAD:os.write(fd,PRELOAD)
try:
 while time.monotonic()<limit:
  ready,_,_=select.select([] if ended else [fd],[],[],0.01)
  if ready:
   try:chunk=os.read(fd,16384-len(data)+1)
   except OSError:chunk=b''
   if not chunk:ended=True
   data+=chunk
   if len(data)>16384:raise AssertionError('terminal transcript budget')
   match=re.search(rb'Type APPROVE ([0-9a-f]{32}) followed by Enter',data)
   if match and not sent:
    expected_prompt=BODY+b'Type APPROVE '+match.group(1)+b' followed by Enter; any other response rejects.\\n'
    if len(data.replace(b'\\r\\n',b'\\n'))<len(expected_prompt):continue
    assert data.replace(b'\\r\\n',b'\\n')==expected_prompt,'independent full prompt mismatch'
    verified=True;exec(MUTATE)
    if RESPONSE=='approve':out=b'APPROVE '+match.group(1)+b'\\n'
    elif RESPONSE=='wrong':out=b'APPROVE '+b'0'*32+b'\\n'
    elif RESPONSE=='eof':out=b'\\x04'
    elif RESPONSE=='long':out=b'X'*81+b'\\n'
    elif RESPONSE=='two':out=b'APPROVE '+match.group(1)+b'\\nextra\\n'
    elif RESPONSE=='wait':out=b''
    else:out=RESPONSE.encode()
    if out:os.write(fd,out)
    sent=True
  got,st=os.waitpid(pid,os.WNOHANG)
  if got:status=st;break
 if status is None:
  got,st=os.waitpid(pid,os.WNOHANG)
  if got:status=st
finally:
 os.close(fd)
 if status is None:
  got,st=os.waitpid(pid,os.WNOHANG)
  if got:status=st
  else:
   try:os.killpg(pid,signal.SIGKILL)
   except PermissionError:
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
   except ProcessLookupError:pass
   _,status=os.waitpid(pid,0)
rows=re.findall(rb'H0_RESULT ([^\\r\\n]+)',data)
value=json.loads(rows[-1]) if rows else {'worker_error':'no-result'}
print(json.dumps({'value':value,'responded':sent,'display_verified':verified,'worker_exit':os.waitstatus_to_exitcode(status),'transcript_bytes':len(data),'transcript_sha256':hashlib.sha256(data).hexdigest()}))
'''
        wall=json.loads((ROOT/'tests/fixtures/installation-authority-v1.json').read_bytes())['test_worker_limits']['max_wall_seconds']
        params='BODY='+repr(body)+';CHALLENGE='+repr(challenge)+';PRELOAD='+repr(preload)+';WALL_SECONDS='+repr(wall)+';BEFORE='+repr(before)+';AFTER='+repr(after)+';MUTATE='+repr(mutate)+';RESPONSE='+repr(response)+';EXERCISE='+repr(exercise)+'\n'
        return self.plan(params+program)
