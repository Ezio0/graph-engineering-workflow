"""Genuine private signed bundles and PTYs; independent C installer and RECORD oracle."""
from __future__ import annotations
import base64
import copy
import csv
import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import uuid
import datetime
import tarfile
import zipfile
from pathlib import Path
from tests.support.installation_authority import ApprovalFixture
from tests.support.release_staging import ROOT,StageFixture,seal,request,write_json,inventory,require_success,expected_envelope,stage_framed
from tests.support.release_installation import json_bytes
from tests.support.source_checkout_attestation import issue_source_checkout_attestation

def fixture():return json.loads((ROOT/'tests/fixtures/staging-execution-v1.json').read_bytes())
def core():
    import importlib
    return importlib.import_module('graph_engineering.core.staging_execution')
def template(path,kind='RECORD',segments=None):
    return seal({'schema_version':'1.0.0','logical_path':path,'kind':kind,'segments':[] if segments is None else segments},'stage-generated-template','template_digest')

def native_helper():
    """One synchronous configured compiler, no downloads and no stage worker overlap."""
    compiler=shutil.which('cc')
    if compiler is None:raise AssertionError('configured native compiler unavailable; required tests blocked')
    limits=fixture()['compiler_limits']
    with tempfile.TemporaryDirectory(prefix='gew-stage-compile-') as directory:
        target=Path(directory)/'stage-process'
        process=subprocess.run([compiler,'-O2',str(ROOT/'tests/fixtures/staging_process_v1.c'),'-o',str(target)],capture_output=True,timeout=limits['max_wall_seconds'])
        if process.returncode:raise AssertionError('private helper compile failed: '+hashlib.sha256(process.stderr).hexdigest())
        raw=target.read_bytes()
        if len(raw)>limits['max_helper_executable_bytes']:raise AssertionError('helper exceeds approved executable limit')
        return raw

def archive(members):
    target=io.BytesIO()
    with tarfile.open(fileobj=target,mode='w',format=tarfile.USTAR_FORMAT) as out:
        for name,raw,mode in members:
            info=tarfile.TarInfo(name);info.size=len(raw);info.mode=mode;info.mtime=0;out.addfile(info,io.BytesIO(raw))
    return target.getvalue()

def add_script(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        bodies={i.filename:(source.read(i),i.external_attr>>16) for i in source.infolist()}
    dist=next(p.rsplit('/',1)[0] for p in bodies if p.endswith('.dist-info/RECORD'));record=dist+'/RECORD'
    script=dist[:-len('.dist-info')]+'.data/scripts/graph-engineering'
    bodies[script]=(b'#!python\nprint("private fixture")\n',0o100755)
    out=io.StringIO(newline='');writer=csv.writer(out,lineterminator='\n')
    for path,(body,mode) in sorted(bodies.items()):
        if path!=record:writer.writerow([path,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode(),str(len(body))])
    writer.writerow([record,'','']);bodies[record]=(out.getvalue().encode(),0o100600)
    target=io.BytesIO()
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_STORED) as out:
        for path,(body,mode) in sorted(bodies.items()):
            info=zipfile.ZipInfo(path,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=mode<<16;out.writestr(info,body)
    return target.getvalue()

def wheel_with_files(raw,members):
    """Independent signed fixture mutation with a fresh, complete wheel RECORD."""
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        bodies={i.filename:(source.read(i),i.external_attr>>16) for i in source.infolist()}
    record=next(p for p in bodies if p.endswith('.dist-info/RECORD'))
    for path,body in members.items():
        assert path not in bodies and type(body) is bytes
        bodies[path]=(body,0o100600)
    out=io.StringIO(newline='');writer=csv.writer(out,lineterminator='\n')
    for path,(body,mode) in sorted(bodies.items()):
        if path!=record:writer.writerow([path,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b'=').decode(),str(len(body))])
    writer.writerow([record,'','']);bodies[record]=(out.getvalue().encode(),0o100600)
    target=io.BytesIO()
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_STORED) as out:
        for path,(body,mode) in sorted(bodies.items()):
            info=zipfile.ZipInfo(path,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=mode<<16;out.writestr(info,body)
    return target.getvalue()

class ExecutionFixture(StageFixture):
    def terminal(self,*,decisions=1,**kwargs):
        if decisions==1:return ApprovalFixture.terminal(self,**kwargs)
        assert decisions==2
        original_plan=self.plan
        def peer(program=None):
            assert program is not None
            program=program.replace('status=None;ended=False',"status=None;ended=False;decision_count=0;prompt_cursor=0;observed_nonces=[];pending_echo=b''")
            program=program.replace("match=re.search(rb'Type APPROVE ([0-9a-f]{32}) followed by Enter',data)","fresh_match=re.search(rb'Type APPROVE ([0-9a-f]{32}) followed by Enter',data[prompt_cursor:]);match=fresh_match if fresh_match is not None else locals().get('match')")
            program=program.replace('if match and not sent:','if fresh_match and decision_count<2:')
            program=program.replace("data.replace(b'\\r\\n',b'\\n')","data[prompt_cursor:].replace(b'\\r\\n',b'\\n')")
            program='\n'.join(line.replace('data.replace(','data[prompt_cursor:].replace(')
                if line.lstrip().startswith(('if len(data.replace(','assert data.replace(')) else line
                for line in program.splitlines())+'\n'
            program=program.replace('verified=True;exec(MUTATE)',"assert match.group(1) not in observed_nonces;observed_nonces.append(match.group(1));verified=True;exec(MUTATE)")
            program=program.replace('sent=True',"sent=True;decision_count+=1;prompt_cursor=len(data);pending_echo=out.replace(b'\\n',b'\\r\\n')")
            echo="""if pending_echo:
    if len(data)-prompt_cursor<len(pending_echo):continue
    assert data[prompt_cursor:prompt_cursor+len(pending_echo)]==pending_echo,'independent response echo mismatch'
    prompt_cursor+=len(pending_echo);pending_echo=b''
   fresh_match="""
            program=program.replace('fresh_match=',echo,1)
            program=program.replace("'responded':sent","'responded':decision_count==2,'decision_count':decision_count")
            program=program.replace("'independent full prompt mismatch'","('independent full prompt mismatch',decision_count,len(data[prompt_cursor:]),len(expected_prompt))")
            return original_plan(program)
        self.plan=peer
        try:return ApprovalFixture.terminal(self,**kwargs)
        finally:del self.plan

    def cold_apply(self,arguments):
        """Exec the actual installed strict launcher in one private real PTY."""
        assert self.release.installed
        original_plan=self.plan
        def peer(program=None):
            assert program is not None
            start=program.index('if pid==0:');end=program.index("data=b'';sent=False",start)
            child="""if pid==0:
 child_env=dict(os.environ)
 for key in ('PYTHONPATH','PYTHONDONTWRITEBYTECODE','PYTHONPYCACHEPREFIX','GEW_INSTALLATION_CONTROL_ROOT'):child_env.pop(key,None)
 os.execve(LAUNCHER,[LAUNCHER,*CLI_ARGUMENTS],child_env)
"""
            program=program[:start]+child+program[end:]
            lines=program.splitlines()
            for i,line in enumerate(lines):
                if line.startswith('rows=re.findall('):lines[i]="rows=re.findall(rb'(?m)^(\\{[^\\r\\n]+\\})\\r?$',data)"
            program='\n'.join(lines)+'\n'
            return original_plan('LAUNCHER='+repr(str(self.release.launcher))+';CLI_ARGUMENTS='+repr(arguments)+'\n'+program)
        self.plan=peer
        try:return ApprovalFixture.terminal(self)
        finally:del self.plan
    def plan(self,code=None):
        if code is not None:
            if self.fixture_mode=='overdue':
                code=code.replace("data=b'';sent=False;verified=False;limit=time.monotonic()+WALL_SECONDS;status=None;ended=False", "data=b'';sent=False;verified=False;limit=time.monotonic()+WALL_SECONDS;status=None;ended=False;resume_at=None;resumed=False")
                anchor='  got,st=os.waitpid(pid,os.WNOHANG)\n  if got:status=st;break'
                pause='''  if not resumed:
   got_pause,paused=os.waitpid(pid,os.WNOHANG|os.WUNTRACED)
   if got_pause and os.WIFSTOPPED(paused):resume_at=time.monotonic()+5.0
   elif got_pause:status=paused;break
   if resume_at is not None and time.monotonic()>=resume_at:
    os.kill(pid,signal.SIGCONT);resumed=True
'''
                code=code.replace(anchor,pause+anchor)
            code=code.replace("{'worker_error':type(e).__name__,'frames':frames}","{'worker_error':type(e).__name__,'frames':frames,'actual_code':next((arg.get('code') for arg in e.args if type(arg) is dict),None),'process_diagnostics':stage_failure_diagnostics() if 'stage_failure_diagnostics' in globals() else None}")
            anchor="value=json.loads(rows[-1]) if rows else {'worker_error':'no-result'}"
            check=anchor+'''
if 'origin_challenge_digest' in value:
 expected=dict(CHALLENGE,invocation_nonce=match.group(1).decode())
 preimage={'algorithm':'sha-256','body':expected,'canonicalizer':'urn:gew:canonicalizer:jcs-input:1.0.0','contract_type':'urn:gew:contract:release-installation-approval-challenge-v1','digest_domain':'urn:gew:digest:semantic:1.0.0','projection_id':'urn:gew:digest-projection:release-installation-approval-challenge-v1:1.0.0','schema_id':'urn:gew:schema:installation-approval-challenge:1.0.0'}
 assert value['origin_challenge_digest']=='sha256-jcs-v1:'+hashlib.sha256(json.dumps(preimage,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),'parent origin challenge mismatch'
'''
            code=code.replace(anchor,check)
        return super().plan(code)
    def __init__(self,*,installed=False,mode='install',prefix='candidates',helper=None,patch=None,wheel_members=None):
        self.fixture_mode=mode
        super().__init__();f=self.release
        if prefix!='candidates':
            self.candidates.rmdir();self.candidates=f.base/prefix;self.candidates.mkdir(mode=0o700)
            self.registry['roots'][0]['path']=str(self.candidates);self.registry=seal(self.registry,'stage-target-registry','registry_digest')
            write_json(f.source/'config/release-installation/stage-target-registry-v1.json',self.registry)
        helper=native_helper() if helper is None else helper
        f.replace('core',add_script((f.bundle/f.row('core')['relative_path']).read_bytes()),sign=False)
        for ident,members in ({} if wheel_members is None else wheel_members).items():
            row=f.row(ident);assert row['kind'] in ('core-wheel','dependency-wheel')
            f.replace(ident,wheel_with_files((f.bundle/row['relative_path']).read_bytes(),members),sign=False)
        self.templates=[];entries=[];site='payload/tool/lib/python'+'.'.join(f.value['interpreter']['patch'].split('.')[:2])+'/site-packages'
        distributions=[a for a in f.value['artifacts'] if a['kind'] in ('core-wheel','dependency-wheel')]
        for owner,a in enumerate(distributions):
            with zipfile.ZipFile(f.bundle/a['relative_path']) as source:
                dist=next(i.filename.rsplit('/',1)[0] for i in source.infolist() if i.filename.endswith('.dist-info/RECORD'))
                self.templates.append(template(site+'/'+dist+'/RECORD'))
                for item in source.infolist():
                    path=item.filename;raw=source.read(item);kind=0
                    if path.endswith('.dist-info/RECORD'):dest=site+'/'+path;raw=b'';kind=2
                    elif '.data/scripts/' in path:
                        dest='payload/tool/bin/'+path.rsplit('/',1)[1];kind=1;raw=b'#!@interpreter@\nprint("private fixture")\n'
                        self.templates.append(template(dest,'launcher',[{'literal':'#!'},{'ref':'interpreter'},{'literal':'\nprint("private fixture")\n'}]))
                    else:dest=site+'/'+path
                    entries.append((stat_mode(item.external_attr>>16),kind,owner,dest,posixpath.relpath(dest,site),raw))
        mapping=str(len(entries)).encode()+b'\n'
        for mode_bits,kind,owner,path,record,raw in entries:
            p=path.encode();r=record.encode();mapping+=f'{mode_bits} {kind} {owner} {len(p)} {len(r)} {len(raw)}\n'.encode()+p+r+raw
        self.installer['recipes'][0]['generated_files']=sorted([{k:t[k] for k in ('logical_path','kind','template_digest')} for t in self.templates],key=lambda r:r['logical_path'])
        self.installer['recipes'][0]['steps'][0]['argv']=[mode]
        if mode=='cumulative':
            first=copy.deepcopy(self.installer['recipes'][0]['steps'][0]);first.update(step_id='emit',argv=['emit'])
            second=copy.deepcopy(first);second.update(step_id='install',argv=['install-emit'])
            self.installer['recipes'][0]['steps']=[first,second]
        self.installer['recipes'][0]=seal(self.installer['recipes'][0],'installer-recipe','recipe_digest')
        self.installer=seal(self.installer,'installer-policy','policy_digest');self.stage.update(fixture()['stage_limits']);self.stage['installer_policy_digest']=self.installer['policy_digest'];self.stage=seal(self.stage,'stage-policy','policy_digest')
        f.value['installer']['argv_policy_digest']=self.installer['recipes'][0]['recipe_digest']
        for index,t in enumerate(sorted(self.templates,key=lambda t:t['logical_path'])):
            ident='template-'+str(index);f.value['artifacts'].append({'artifact_id':ident,'kind':'build-input','relative_path':ident+'.json','distribution_name':None,'version':None,'size_bytes':0,'raw_sha256':'0'*64,'source_id':'synthetic-local','provenance_artifact_id':'provenance','license_ids':['BSD-3-Clause']})
            f.replace(ident,json_bytes(t),sign=False)
        f.value['artifacts'].sort(key=lambda r:r['artifact_id'])
        f.replace('python',archive([('bin/python',helper,0o700),('release-runtime.json',json_bytes(f.value['interpreter']),0o600)]),sign=False)
        f.replace('uv',archive([('bin/uv',helper,0o700),('release-runtime.json',json_bytes(f.value['installer']),0o600),('install-map.bin',mapping,0o600)]),sign=False)
        for name,doc in [('stage-policy',self.stage),('installer-policy',self.installer)]:write_json(f.source/('config/release-installation/'+name+'-v1.json'),doc)
        approval_path=f.source/'config/release-installation/installation-approval-policy-v1.json';approval=json.loads(approval_path.read_bytes());approval.update(fixture()['approval_limits']);write_json(approval_path,seal(approval,'installation-approval-policy','policy_digest'))
        f.refresh_closure();self.request=request(f.value);write_json(self.request_path,self.request)
        if patch:patch(self)
        issue_source_checkout_attestation(f.source,f.control)
        if installed:f.install();f.installed=True

    def execute_stage(self,exercise=None,**kwargs):
        exercise=exercise or '''from graph_engineering.application.staging_execution import StagedReleaseObservation
original=actual['challenge_digest'];result=owner.stage(plan,grant)
assert type(result) is StagedReleaseObservation,result
value=result.diagnostic();record=result.to_dict()
from graph_engineering.application import staging_execution as execution
session=execution._OBSERVATIONS[result][3]
assert session.result['stage-execution-binding']['challenge_digest']==original
value['origin_challenge_digest']=session.result['stage-execution-binding']['challenge_digest']
assert session.result['stage-receipt']['execution_binding_digest']==session.result['stage-execution-binding']['execution_binding_digest']
assert session.permit is None and not local._PERMITS and not local._GRANTS
result.require_current();result.close()
assert not execution._OBSERVATIONS
'''
        return self.terminal(exercise=exercise,**kwargs)

    def cli_reader(self,attack):
        """The real CLI owns the only plan and genuine terminal decision."""
        code=stage_reader_fault(attack,'cli-apply')
        start=code.index("if route=='cli-apply':\n supplied=plan.to_dict()")
        end=code.index('sys.settrace(trace)',start)
        code=code[:start]+"supplied="+repr(expected_envelope(self))+"\npath=pathlib.Path(sys.argv[2]).with_name('reader-plan.json');path.write_text(json.dumps(supplied));path.chmod(0o600)\n"+code[end:]
        original_plan=self.plan
        def peer(program=None):
            assert program is not None
            start=program.index('  from graph_engineering.application.release_staging import ReleaseInstaller,BundleRef,StagePlanEnvelope')
            end=program.index(' except BaseException as e:',start)
            worker="""  from graph_engineering.application.release_staging import BundleRef
  exec(EXERCISE)
  print('H0_RESULT '+json.dumps(value),flush=True);os._exit(0)
"""
            return original_plan(program[:start]+worker+program[end:])
        self.plan=peer
        try:return self.terminal(exercise=code)
        finally:del self.plan

    def __exit__(self,*args):
        if getattr(self,'unconfirmed_process',False):self.release.temporary._finalizer.detach()
        else:super().__exit__(*args)

def stat_mode(mode):return mode&0o777

def durability_fault(kind):
    """Fault real OS operations at original private worker trace boundaries."""
    assert kind in ('write','file-fsync','directory-fsync','receipt-last','final-barrier')
    return '''import dis
from graph_engineering.adapters import staging_execution as physical
from graph_engineering.application import staging_execution as application
kind=KIND;fired=[];order=[]
write_code=physical.StageSession._write.__code__
write_offset=next(i.offset for i in dis.get_instructions(write_code) if i.opname=='LOAD_GLOBAL' and i.argval=='_WRITE')
sync_offsets=[i.offset for i in dis.get_instructions(write_code) if i.opname=='LOAD_GLOBAL' and i.argval=='_FSYNC']
def local_fault(frame,event,arg):
 if event=='opcode' and not fired:
  values=frame.f_locals
  if (kind=='write' and frame.f_lasti==write_offset or kind=='file-fsync' and frame.f_lasti==sync_offsets[0] or kind=='directory-fsync' and frame.f_lasti==sync_offsets[1]):
   fired.append(kind);sys.settrace(None);os.close(values['parent'] if kind=='directory-fsync' else values['fd'])
 return local_fault
def select_fault(frame,event,arg):
 if event!='call' or not frame.f_code.co_filename.endswith('/adapters/staging_execution.py'):return None
 if frame.f_code is write_code:
  path=frame.f_locals['path']
  if path.startswith('metadata/'):order.append(path)
  if kind=='receipt-last' and path=='metadata/receipt.json':fired.append(kind);sys.settrace(None);raise OSError('private receipt-last fault')
  frame.f_trace_lines=False;frame.f_trace_opcodes=True;return local_fault
 if (kind=='final-barrier' and frame.f_code.co_name=='barrier' and frame.f_back.f_code.co_name=='persist' and 'result' in frame.f_locals['self'].__dict__):
  fired.append(kind);sys.settrace(None);raise OSError('private final barrier fault')
 return None
trace_owner=sys._getframe();previous_opcodes=trace_owner.f_trace_opcodes
if kind in ('write','file-fsync','directory-fsync'):trace_owner.f_trace_opcodes=True
sys.settrace(select_fault)
try:result=owner.stage(plan,grant)
finally:sys.settrace(None);trace_owner.f_trace_opcodes=previous_opcodes
assert fired and type(result) is dict and result['code']=='recovery_blocked',{'code':result.get('code') if type(result) is dict else 'owned-result','fault':kind,'fired':bool(fired),'order_count':len(order)}
assert not local._PERMITS and not local._GRANTS and not application._OBSERVATIONS
if kind in ('receipt-last','final-barrier'):assert order[-1]=='metadata/receipt.json',order
value={'code':result['code'],'fault_observed':True,'fault':kind}
'''.replace('KIND',repr(kind))

def provider_fault(attack,*,fresh=True):
    assert attack in ('alias','code','descriptor','guard','cleanup','retained','retained-reopen','reopen','admission')
    code='''from graph_engineering.adapters import staging_execution as physical
from graph_engineering.application import staging_execution as application
attack=ATTACK;calls=[];retained=None
if attack in ('retained','retained-reopen'):
 retained=owner.reopen_staged(plan,grant) if attack=='retained-reopen' else owner.stage(plan,grant);assert type(retained) is application.StagedReleaseObservation,retained
 retained_session=application._OBSERVATIONS[retained][3]
 retained_fds=(retained_session.root,retained_session.parent)
def spy(*args,**kwargs):W10E_SUBSTITUTED_CALLS.append(True);raise AssertionError('substituted provider invoked')
globals()['W10E_SUBSTITUTED_CALLS']=calls
if attack in ('alias','admission'):
 name='_POPEN' if attack=='alias' else 'validate_template_batch';previous=vars(physical)[name];setattr(physical,name,spy)
elif attack=='guard':name='_GUARD';previous=physical._GUARD;physical._GUARD=spy
elif attack=='code':
 target=physical.StageSession._write;previous=target.__code__;target.__globals__['W10E_SUBSTITUTED_CALLS']=calls;target.__code__=spy.__code__
elif attack in ('retained','retained-reopen'):
 name='closed';previous=vars(physical.StageSession).get(name);setattr(physical.StageSession,name,property(spy))
else:
 name='close' if attack=='cleanup' else '_write';previous=vars(physical.StageSession)[name]
 setattr(physical.StageSession,name,property(spy) if attack=='descriptor' else spy)
try:
 if retained is not None:
  try:retained.require_current()
  except ValueError:pass
  else:raise AssertionError('substituted retained provider admitted')
  for descriptor in retained_fds:
   try:os.fstat(descriptor)
   except OSError as error:assert error.errno==9
   else:raise AssertionError('retired observation descriptor remains open')
 else:
  if attack=='admission':assert type(ReleaseInstaller().plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))) is dict
  result=owner.reopen_staged(plan,grant) if attack=='reopen' else owner.stage(plan,grant)
  assert type(result) is dict,result
 assert not calls,'replacement executed'
finally:
 if attack=='code':target.__code__=previous;target.__globals__.pop('W10E_SUBSTITUTED_CALLS')
 elif attack in ('alias','guard','admission'):setattr(physical,name,previous)
 elif previous is None:delattr(physical.StageSession,name)
 else:setattr(physical.StageSession,name,previous)
 globals().pop('W10E_SUBSTITUTED_CALLS',None)
if retained is not None:
 try:retained.require_current()
 except ValueError:pass
 else:raise AssertionError('restoration revived retained result')
 retained.close()
try:grant.require_current()
except ValueError:pass
else:raise AssertionError('restoration revived retired grant')
plan.close();owner=ReleaseInstaller();plan=owner.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
assert type(plan) is StagePlanEnvelope,plan
fresh=owner.authorize_local(plan);assert type(fresh) is local.InstallationAuthority,fresh
result=owner.reopen_staged(plan,fresh) if attack in ('retained','reopen') else owner.stage(plan,fresh)
assert type(result) is application.StagedReleaseObservation,result
value={'zero_calls':len(calls),'fresh_restored':True};result.require_current();result.close()
'''.replace('ATTACK',repr(attack))
    if not fresh:
        code=code[:code.index('plan.close();owner=ReleaseInstaller()')]+"plan.close();value={'zero_calls':len(calls),'retired_closed':retained is not None}\n"
    return code

def running_provider_fault(attack):
    """Mutate real consumed providers only after the admitted child has started."""
    assert attack in ('poll-alias','liveness-code','signal-descriptor','popen-descriptor','signal-alias')
    return '''import signal,time
from graph_engineering.adapters import staging_execution as physical
from graph_engineering.application import staging_execution as application
attack=ATTACK;calls=[];started=[];saved=[];observed=[];signals=[]
def spy(*args,**kwargs):W10E_RUNNING_REPLACEMENTS.append(True);raise AssertionError('running replacement executed')
def restore():
 for target,name,value,kind in reversed(saved):
  if kind=='code':target.__code__=value
  else:setattr(target,name,value)
 globals().pop('W10E_RUNNING_REPLACEMENTS',None)
def inject(p):
 assert p.pid>0;started.append(p.pid)
 globals()['W10E_RUNNING_REPLACEMENTS']=calls
 if attack=='poll-alias':saved.append((physical,'_POLL',physical._POLL,'alias'));physical._POLL=spy
 elif attack=='liveness-code':
  target=physical.StageSession._group_alive;target.__globals__['W10E_RUNNING_REPLACEMENTS']=calls;saved.append((target,'',target.__code__,'code'));target.__code__=spy.__code__
 elif attack=='signal-alias':saved.append((physical,'_KILL',physical._KILL,'alias'));physical._KILL=spy
 elif attack=='popen-descriptor':saved.append((physical.subprocess.Popen,'poll',vars(physical.subprocess.Popen)['poll'],'descriptor'));physical.subprocess.Popen.poll=property(spy)
 else:
  saved.append((physical.StageSession,'_revoke',vars(physical.StageSession)['_revoke'],'descriptor'));physical.StageSession._revoke=property(spy)
def run_return(frame,event,arg):
 if event=='line' and not started and type(frame.f_locals.get('raw')) is bytes and b'W10E-READY\\n' in frame.f_locals['raw']:inject(frame.f_locals['process'])
 elif event=='return':
  p=frame.f_locals.get('process')
  if p is not None:
   confirmed=False
   try:os.killpg(p.pid,0)
   except ProcessLookupError:confirmed=p.returncode is not None
   except PermissionError:pass
   observed.append({'confirmed':confirmed,'final':frame.f_locals['final'],'ended':time.monotonic()})
 return run_return
def selected(frame,event,arg):
 if event=='call' and frame.f_code.co_name=='_run' and frame.f_code.co_filename.endswith('/adapters/staging_execution.py'):
  return run_return
 if event=='call' and frame.f_code.co_name=='_revoke' and frame.f_code.co_filename.endswith('/adapters/staging_execution.py'):signals.append(frame.f_locals['number'])
 return None
sys.settrace(selected)
try:result=owner.stage(plan,grant)
finally:
 sys.settrace(None);restore();vars(physical).pop('W10E_RUNNING_REPLACEMENTS',None)
assert started and type(result) is dict,result
assert not calls,'running replacement was consumed'
assert observed,'actual running-child outcome unobserved'
assert signal.SIGTERM in signals and signal.SIGKILL in signals,'original TERM/KILL sequence missing'
unknown=any(not row['confirmed'] for row in observed)
if unknown:assert result['code']=='recovery_blocked',result
assert all(row['ended']<=row['final']+0.25 for row in observed),'cleanup renewed original deadline'
value={'zero_calls':len(calls),'child_started':True,'original_term_kill':True,'unconfirmed_group':unknown,'code':result['code']}
'''.replace('ATTACK',repr(attack))

def reopen_rejection(test,f,filename,mutation):
    """Fresh real authority rejects tampered records without installer or repair."""
    root=next(f.candidates.iterdir());path=root/'metadata'/filename;original=path.read_bytes()
    try:
        if mutation=='missing':path.unlink()
        elif mutation=='malformed':path.write_bytes(b'{}')
        else:
            value=json.loads(original);field='challenge_digest' if filename=='execution-binding.json' else 'execution_binding_digest'
            value[field]='sha256-jcs-v1:'+'0'*64
            kind='stage-execution-binding' if filename=='execution-binding.json' else 'stage-receipt';digest='execution_binding_digest' if filename=='execution-binding.json' else 'receipt_digest'
            value=seal(value,kind,digest);path.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
        before=inventory(root)
        exercise='''starts=[]
def watch(frame,event,arg):
 if event=='call' and frame.f_code.co_name=='__init__' and frame.f_code.co_filename.endswith('/subprocess.py'):starts.append(True)
 return None
sys.settrace(watch)
try:result=owner.reopen_staged(plan,grant)
finally:sys.settrace(None)
assert type(result) is dict and result['code'] in ('closure_mismatch','recovery_blocked','currentness'),result
assert not starts,'reopen ran an installer'
assert not local._GRANTS and not local._PERMITS
value={'refused':True,'installer_calls':len(starts),'code':result['code']}
'''
        value=success(test,f,exercise=exercise);test.assertTrue(value['refused']);test.assertEqual(inventory(root),before)
    finally:path.write_bytes(original);path.chmod(0o600)

def admitted_members(f):
    """Independent expected payload derived before inspecting installed output."""
    files={};owners={};site='payload/tool/lib/python'+'.'.join(f.release.value['interpreter']['patch'].split('.')[:2])+'/site-packages'
    for artifact in f.release.value['artifacts']:
        raw=(f.release.bundle/artifact['relative_path']).read_bytes();kind=artifact['kind']
        if kind in ('interpreter','installer'):
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                for member in archive.getmembers():
                    if member.isfile():files['payload/'+kind+'/'+member.name]=archive.extractfile(member).read()
        elif kind in ('core-wheel','dependency-wheel'):
            files['payload/wheelhouse/'+artifact['relative_path'].rsplit('/',1)[-1]]=raw;owned=set()
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for name in archive.namelist():
                    target='payload/tool/bin/'+name.rsplit('/',1)[-1] if '.data/scripts/' in name else site+'/'+name
                    files[target]=None if target in {t['logical_path'] for t in f.templates} else archive.read(name);owned.add(target)
            owners[artifact['distribution_name']]=owned
        elif kind=='skill':
            skill=next(s for s in f.release.value['skills'] if s['artifact_id']==artifact['artifact_id'])
            prefix='payload/skills/'+skill['runtime_kind']+'/'+skill['skill_id']+'/'+skill['version']
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for name in archive.namelist():files[prefix+'/'+name]=archive.read(name)
    directories={prefix for name in files for prefix in ('/'.join(name.split('/')[:i]) for i in range(1,len(name.split('/'))))}
    return files,directories,owners

def standalone_template_fault(attack,*,route='verifier'):
    """Direct A producer and retained use; never imports B0 application first."""
    assert attack in ('parser-alias','parser-code','parser-binding','loader-alias','retained','retained-dict')
    assert route in ('verifier','application') and (route=='verifier' or not attack.startswith('retained'))
    return '''from graph_engineering.adapters import release_installation as admission
assert 'graph_engineering.application.release_staging' not in sys.modules
from graph_engineering.adapters import staging_execution as physical
attack=ATTACK;route=ROUTE;calls=[];retained=None
if route=='application':from graph_engineering.application.release_installation import release_check
if attack.startswith('retained'):
 retained=admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));provider=retained._provider
target=admission if hasattr(admission,'_template_batch') else physical
name=('_template_inputs' if target is admission else 'owned_inputs') if attack in ('loader-alias','retained','retained-dict') else ('_template_batch' if target is admission else 'validate_template_batch')
if attack=='parser-binding':name='parse_json'
previous=vars(target)[name]
def spy(*args,**kwargs):W10E_A_REPLACEMENTS.append(True);raise AssertionError('standalone replacement executed')
globals()['W10E_A_REPLACEMENTS']=calls
if attack=='parser-code':previous.__globals__['W10E_A_REPLACEMENTS']=calls;saved_code=previous.__code__;previous.__code__=spy.__code__
else:setattr(target,name,spy)
try:
 try:
  if retained is None:
   if route=='application':
    report,exit_code=release_check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));assert exit_code==4 and report['code'] in ('trust_rejected','closure_mismatch'),report
    raise ValueError('bounded application refusal')
   admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]))
  elif attack=='retained-dict':retained.to_dict()
  else:retained.require_current()
 except (ValueError,AssertionError):pass
 else:raise AssertionError('standalone template substitution admitted')
 assert not calls,'standalone replacement consumed'
 if retained is not None:assert provider._closed,'standalone provider remains open after rejection'
finally:
 if attack=='parser-code':previous.__code__=saved_code;previous.__globals__.pop('W10E_A_REPLACEMENTS',None)
 else:setattr(target,name,previous)
 globals().pop('W10E_A_REPLACEMENTS',None)
if retained is not None:
 for operation in (retained.to_dict,retained.require_current):
  try:operation()
  except ValueError:pass
  else:raise AssertionError('standalone restoration revived observation')
 retained.close()
if route=='application':
 report,exit_code=release_check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));assert exit_code==0 and report['status']=='preflight-valid',report
else:
 fresh=admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));fresh.require_current();fresh.close()
assert 'graph_engineering.application.release_staging' not in sys.modules
print(json.dumps({'zero_calls':len(calls),'fresh_restored':True}))
'''.replace('ATTACK',repr(attack)).replace('ROUTE',repr(route))

def standalone_reader_fault(attack,route):
    """Replace cleanup only after observing genuinely opened descriptors."""
    assert attack in ('descriptor','code') and route in ('admission','retained','doctor')
    return '''import os
from graph_engineering.adapters import release_installation as admission
assert 'graph_engineering.application.release_staging' not in sys.modules
attack=ATTACK;route=ROUTE;calls=[];fds=[];retained=None;provider=None;fired=[]
original=vars(admission._ReadFile)['close'];original_code=original.__code__
def spy(*args,**kwargs):W10E_READER_CALLS.append(True);raise AssertionError('reader replacement executed')
globals()['W10E_READER_CALLS']=calls
def substitute(items):
 assert items and all(item.fd>=0 for item in items)
 for item in items:fds.extend([item.fd,*item.descriptors])
 if attack=='code':original.__globals__['W10E_READER_CALLS']=calls;original.__code__=spy.__code__
 else:setattr(admission._ReadFile,'close',property(lambda self:spy))
 fired.append(True)
def probe(phase):
 global provider
 assert phase=='release.after-open'
 frame=sys._getframe(1);provider=frame.f_locals['provider'];substitute(frame.f_locals['opened'])
def trace(frame,event,arg):
 if event=='return' and frame.f_code is admission._ReadFile.__init__.__code__ and not fired:
  substitute([frame.f_locals['self']]);sys.settrace(None)
 return trace
if route=='retained':
 retained=admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));provider=retained._provider
if route in ('retained','doctor'):
 sys.settrace(trace)
try:
 try:
  if route=='doctor':
   report=admission.ReadOnlyDoctor().inspect(pathlib.Path(sys.argv[2]));assert report['status']=='blocked'
   raise ValueError('read-only doctor refusal')
  elif retained is None:admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]),_probe_hook=probe)
  else:retained.require_current()
 except (ValueError,AssertionError):pass
 else:raise AssertionError('reader substitution admitted')
 assert fired and fds,'reader substitution preceded actual opening'
 assert not calls,'reader replacement consumed'
 for fd in fds:
  try:os.fstat(fd)
  except OSError as error:assert error.errno==9
  else:raise AssertionError('reader descriptor remains open after rejection')
 if provider is not None:assert provider._closed,'reader provider remains open after rejection'
finally:
 sys.settrace(None)
 original.__code__=original_code;setattr(admission._ReadFile,'close',original)
 original.__globals__.pop('W10E_READER_CALLS',None);globals().pop('W10E_READER_CALLS',None)
if retained is not None:
 for operation in (retained.to_dict,retained.require_current):
  try:operation()
  except ValueError:pass
  else:raise AssertionError('reader restoration revived observation')
 retained.close()
fresh=admission.LocalReleaseVerifier().check(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]));fresh.require_current();fresh.close()
assert 'graph_engineering.application.release_staging' not in sys.modules
print(json.dumps({'zero_calls':len(calls),'descriptors_closed':True,'fresh_restored':True}))
'''.replace('ATTACK',repr(attack)).replace('ROUTE',repr(route))

def stage_reader_fault(attack,route):
    """Observe a real reader opening in each staging/CLI lifetime."""
    assert attack in ('descriptor','code') and route in ('prepare','retained','cli-plan','cli-apply')
    return '''import os
from graph_engineering.adapters import release_installation as admission
from graph_engineering.application import release_staging as app
from graph_engineering.application import staging_execution as execution
from graph_engineering.application import installation_authority as local
attack=ATTACK;route=ROUTE;calls=[];fds=[];fired=[];retained=None;provider=None;stage_fds=()
original=vars(admission._ReadFile)['close'];original_code=original.__code__
def spy(*args,**kwargs):W10E_STAGE_READER_CALLS.append(True);raise AssertionError('stage reader replacement executed')
globals()['W10E_STAGE_READER_CALLS']=calls
def substitute(opened):
 assert opened.fd>=0
 fds.extend([opened.fd,*opened.descriptors])
 if attack=='code':original.__globals__['W10E_STAGE_READER_CALLS']=calls;original.__code__=spy.__code__
 else:setattr(admission._ReadFile,'close',property(lambda self:spy))
 fired.append(True)
def trace(frame,event,arg):
 global provider
 if fired:return None
 if route=='cli-apply':
  if frame.f_code.co_name!='install_apply':return None
  if event=='line' and frame.f_code.co_name=='install_apply' and frame.f_locals.get('grant') is not None and type(frame.f_locals['grant']) is not dict:
   values=frame.f_locals;provider=app._PLANS[values['plan']][2]._release._provider
   fds.append(local._GRANTS[id(values['grant'])]['session'].fd)
   substitute(values['opened']);sys.settrace(None);raise ValueError('private CLI cleanup fault')
 else:
  if frame.f_code is not admission._ReadFile.__init__.__code__:return None
  if event=='return':
   expected={'prepare':'_prepare','retained':'require_execution_current','cli-plan':'install_plan'}[route]
   if frame.f_back.f_code.co_name==expected:substitute(frame.f_locals['self']);sys.settrace(None)
 return trace
if route in ('prepare','retained'):
 provider=app._PLANS[plan][2]._release._provider
if route=='retained':
 retained=owner.stage(plan,grant);assert type(retained) is execution.StagedReleaseObservation,retained
 session=execution._OBSERVATIONS[retained][3];stage_fds=(session.root,session.parent)
if route=='cli-apply':
 supplied=plan.to_dict();path=pathlib.Path(sys.argv[2]).with_name('reader-plan.json');path.write_text(json.dumps(supplied));path.chmod(0o600)
if route in ('cli-plan','cli-apply'):
 execution._GRANT_CLOSE(grant);plan.close()
sys.settrace(trace)
try:
 try:
  if route=='prepare':
   result=owner.stage(plan,grant);assert type(result) is dict,'stage reader substitution admitted'
  elif route=='retained':
   retained.require_current();raise AssertionError('retained reader substitution admitted')
  elif route=='cli-plan':
   result,code=app.install_plan('install',pathlib.Path(sys.argv[2]),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])));assert code!=0,'CLI reader substitution admitted'
  else:
   result,code=app.install_apply(path,BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])));assert code!=0,'CLI reader substitution admitted'
 except (ValueError,AssertionError):pass
 finally:sys.settrace(None)
 assert fired and fds,'stage reader substitution preceded actual opening'
 assert not calls,'stage reader replacement consumed'
 for fd in (*fds,*stage_fds):
  try:os.fstat(fd)
  except OSError as error:assert error.errno==9
  else:raise AssertionError('stage reader descriptor remains open')
 if provider is not None:assert provider._closed,'stage reader provider remains open'
 assert not local._GRANTS and not local._PERMITS and not execution._OBSERVATIONS,'stage reader owned resources remain registered'
 assert not app._PLANS,'stage reader plan remains registered'
finally:
 sys.settrace(None);original.__code__=original_code;setattr(admission._ReadFile,'close',original)
 original.__globals__.pop('W10E_STAGE_READER_CALLS',None);globals().pop('W10E_STAGE_READER_CALLS',None)
if retained is not None:
 for operation in (retained.to_dict,retained.require_current):
  try:operation()
  except ValueError:pass
  else:raise AssertionError('restoration revived staged reader observation')
 retained.close()
value={'zero_calls':len(calls),'descriptors_closed':True,'owned_resources_retired':True}
'''.replace('ATTACK',repr(attack)).replace('ROUTE',repr(route))

def source_fault(phase):
    assert phase in ('extraction','before-child','final')
    return '''from graph_engineering.adapters import staging_execution as physical
phase=PHASE;fired=[];starts=[]
def selected(frame,event,arg):
 if event!='call':return None
 if frame.f_code.co_name=='__init__' and frame.f_code.co_filename.endswith('/subprocess.py'):starts.append(True)
 if not frame.f_code.co_filename.endswith('/adapters/staging_execution.py') or fired:return None
 name=frame.f_code.co_name;values=frame.f_locals
 if phase=='extraction' and name=='_write':
  fired.append(True);parent=pathlib.Path(values['self'].parent_path);moved=parent.with_name(parent.name+'-retained');parent.rename(moved);parent.mkdir(mode=0o700)
 elif phase=='before-child' and name=='_run':
  fired.append(True);p=pathlib.Path(values['self'].path)/'payload/interpreter/bin/python';q=p.with_name('replacement');q.write_bytes(p.read_bytes());q.chmod(p.stat().st_mode&0o777);os.replace(q,p)
 elif phase=='final' and name=='barrier' and frame.f_back.f_code.co_name=='persist' and 'result' in values['self'].__dict__:
  fired.append(True);p=pathlib.Path(sys.argv[3])/'python.tar';p.write_bytes(p.read_bytes()+b'x')
 return None
sys.settrace(selected)
try:result=owner.stage(plan,grant)
finally:sys.settrace(None)
assert fired and type(result) is dict,result
assert result['code'] in ('currentness','trust_rejected','closure_mismatch','recovery_blocked'),result
if phase!='final':assert not starts,'child started after replaced input/root'
value={'code':result['code'],'fault_observed':True}
'''.replace('PHASE',repr(phase))


def process_failure_observer():
    """Read-only, bounded metadata; no exception text, locals or physical paths."""
    return '''process_exception_first=[];process_exception_recent=[];process_exception_count=0
def process_identifier(value,limit,qualified=False):
 if type(value) is not str or len(value)>limit or not value.isascii():return 'unavailable'
 parts=value.split('.') if qualified else [value]
 if not all(part.isidentifier() for part in parts):return 'unavailable'
 return value
def note_process_exception(frame,event,arg):
 global process_exception_count
 if event!='exception':return
 module=frame.f_globals.get('__name__','')
 if type(module) is not str or not module.startswith('graph_engineering.'):return
 error=arg[1]
 row={'module':process_identifier(module,96,True),'function':process_identifier(frame.f_code.co_name,64),'line':frame.f_lineno,'error_type':process_identifier(type(error).__name__,48)}
 fields=object.__getattribute__(error,'__dict__');code=fields.get('code')
 if type(code) is str and code in ('input_invalid','trust_rejected','closure_mismatch','resource_limit','currentness','authority_required','recovery_blocked','clock_unavailable','quiescence','phase_unavailable'):row['code']=code
 if isinstance(error,OSError):
  number=OSError.errno.__get__(error,OSError)
  if type(number) is int and -2147483648<=number<=2147483647:row['errno']=number
 process_exception_count=min(process_exception_count+1,2147483647)
 if len(process_exception_first)<16:process_exception_first.append(row)
 else:
  process_exception_recent.append(row)
  if len(process_exception_recent)>48:del process_exception_recent[0]
def stage_failure_diagnostics():
 rows=process_exception_first+process_exception_recent
 value={'exception_events':rows,'exception_count':process_exception_count,'truncated':process_exception_count>len(rows)}
 while len(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode())>6144:
  del rows[len(rows)//2];value['truncated']=True
 return value
'''

def check_process_failure_diagnostics(test):
    """Synthetic exceptions prove the observer before any private native fixture."""
    namespace={'json':json};exec(process_failure_observer(),namespace)
    source="def failure():\n raise OSError(5,'DO_NOT_RETAIN_NONCE_OR_PATH')\n"
    owned={'__name__':'graph_engineering.application.synthetic_diagnostic'}
    foreign={'__name__':'external.synthetic_diagnostic'}
    exec(compile(source,'/synthetic/private/path.py','exec'),owned)
    exec(compile(source,'/synthetic/private/path.py','exec'),foreign)
    def emit(function):
        try:function()
        except OSError as error:
            tb=error.__traceback__.tb_next
            namespace['note_process_exception'](tb.tb_frame,'exception',(type(error),error,tb))
    emit(foreign['failure']);test.assertEqual(namespace['stage_failure_diagnostics']()['exception_count'],0)
    emit(owned['failure']);first=namespace['stage_failure_diagnostics']()
    test.assertEqual(first,{'exception_events':[{'module':owned['__name__'],'function':'failure','line':2,'error_type':'OSError','errno':5}],'exception_count':1,'truncated':False})
    # Distinct line numbers make retention of both ends mechanically visible.
    for line in range(3,103):
        exec(compile('\n'*(line-2)+source,'/synthetic/private/path.py','exec'),owned);emit(owned['failure'])
    value=namespace['stage_failure_diagnostics']();raw=json.dumps(value,ensure_ascii=True,separators=(',',':'))
    test.assertEqual(value['exception_count'],101);test.assertTrue(value['truncated'])
    test.assertEqual(value['exception_events'][0]['line'],2);test.assertEqual(value['exception_events'][-1]['line'],102)
    test.assertLessEqual(len(value['exception_events']),64);test.assertLessEqual(len(raw.encode()),6144)
    test.assertNotIn('DO_NOT_RETAIN',raw);test.assertNotIn('/synthetic/private',raw)
    # Byte trimming is exercised separately with longest accepted identifiers.
    for row in namespace['process_exception_first']+namespace['process_exception_recent']:
        row.update(module='graph_engineering.'+'a'*78,function='b'*64,error_type='c'*48,code='authority_required',errno=2147483647)
    bounded=namespace['stage_failure_diagnostics']()
    test.assertLessEqual(len(json.dumps(bounded,ensure_ascii=True,separators=(',',':')).encode()),6144)
    test.assertTrue(bounded['truncated']);test.assertEqual(bounded['exception_events'][0]['line'],2);test.assertEqual(bounded['exception_events'][-1]['line'],102)

def process_observation():
    return process_failure_observer()+'''import signal,time,math
observed=[];signals=[]
def run_return(frame,event,arg):
 note_process_exception(frame,event,arg)
 if event=='return':
  values=frame.f_locals;process=values.get('process')
  if process is None:return None
  confirmed=False
  try:os.killpg(process.pid,0)
  except ProcessLookupError:confirmed=process.poll() is not None
  except PermissionError:pass
  start=values['start'];final=values['final'];span=final-start
  assert math.isclose(values['execute'],start+span/2,abs_tol=1e-8)
  assert math.isclose(values['kill'],start+span*3/4,abs_tol=1e-8)
  assert math.isclose(final,min(values['self'].deadline,start+PROCESS_SECONDS),abs_tol=1e-8)
  observed.append({'confirmed':confirmed,'output_bytes':values['count'],'returncode':process.returncode,'bounds_checked':True})
 return run_return
def selected(frame,event,arg):
 note_process_exception(frame,event,arg)
 if event=='call' and frame.f_code.co_filename.endswith('/adapters/staging_execution.py'):
  if frame.f_code.co_name=='_run':frame.f_trace_lines=False;return run_return
  if frame.f_code.co_name=='_revoke':signals.append(frame.f_locals['number'])
 if event=='call' and frame.f_globals.get('__name__','').startswith('graph_engineering.'):
  frame.f_trace_lines=False;return selected
 return None
sys.settrace(selected)
try:result=owner.stage(plan,grant)
finally:sys.settrace(None)
assert type(result) is dict and observed,result
unknown=any(not row['confirmed'] for row in observed)
assert result['code']=='recovery_blocked' if unknown else result['code'] in ('resource_limit','closure_mismatch'),result
value={'code':result['code'],'observations':observed,'term_observed':signal.SIGTERM in signals,'kill_observed':signal.SIGKILL in signals,'unconfirmed_group':unknown,'process_diagnostics':stage_failure_diagnostics()}
'''.replace('PROCESS_SECONDS',str(fixture()['stage_limits']['max_process_seconds']))

def concurrent_stage():
    return '''import dis,hashlib
from graph_engineering.adapters import staging_execution as physical
from graph_engineering.application import staging_execution as application
other=ReleaseInstaller();other_plan=other.plan(json.loads(pathlib.Path(sys.argv[2]).read_bytes()),BundleRef(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])))
assert type(other_plan) is StagePlanEnvelope,other_plan
other_grant=other.authorize_local(other_plan);assert type(other_grant) is local.InstallationAuthority,other_grant
second_challenge=local._GRANTS[id(other_grant)]['session'].challenge['challenge_digest']
code=physical.StageSession.acquire.__code__;offset=next(i.offset for i in dis.get_instructions(code) if i.opname=='LOAD_GLOBAL' and i.argval=='_MKDIR')
winner=[];root_snapshot=[];root=None
def snapshot(path):
 return [(str(p.relative_to(path)),p.stat().st_ino,p.stat().st_mode,p.read_bytes() if p.is_file() else None) for p in [path,*sorted(path.rglob('*'))]]
def pause(frame,event,arg):
 global root
 if event=='opcode' and frame.f_lasti==offset and not winner:
  sys.settrace(None)
  result=other.stage(other_plan,other_grant);assert type(result) is application.StagedReleaseObservation,result
  session=application._OBSERVATIONS[result][3];root=pathlib.Path(session.path)
  assert session.result['stage-execution-binding']['challenge_digest']==second_challenge
  root_snapshot.extend(snapshot(root));winner.append(True);result.close()
 return pause
def selected(frame,event,arg):
 if event=='call' and frame.f_code is code:frame.f_trace_lines=False;frame.f_trace_opcodes=True;return pause
 return None
trace_owner=sys._getframe();old_opcodes=trace_owner.f_trace_opcodes;trace_owner.f_trace_opcodes=True
sys.settrace(selected)
try:result=owner.stage(plan,grant)
finally:sys.settrace(None);trace_owner.f_trace_opcodes=old_opcodes
assert winner and type(result) is dict and result['code']=='recovery_blocked',result
assert snapshot(root)==root_snapshot,'loser changed winner'
assert not local._GRANTS and not local._PERMITS
value={'exclusive_winners':len(winner),'loser_refused':True,'origin_challenge_digest':second_challenge};other_plan.close()
'''


def success(test,f,*,expected_process_code=None,**kwargs):
    old=inventory(f.old_state)
    try:
        process=f.execute_stage(**kwargs)
        if process.returncode:f.unconfirmed_process=True
        result=require_success(test,process)
    except BaseException:
        f.unconfirmed_process=True
        raise
    peer_failed=result['worker_exit']!=0 or not result['display_verified'] or not result['responded']
    code_mismatch=expected_process_code is not None and result['value'].get('code')!=('recovery_blocked' if result['value'].get('unconfirmed_group') else expected_process_code)
    if peer_failed:f.unconfirmed_process=True
    if peer_failed or code_mismatch:
        # Keep failure diagnostics at first observation, rather than depending on
        # a replay reproducing timing. Never retain nonce, argv or raw output.
        d=ROOT/'.workflow/delivery/GEW-REMAINING54-V1/detached'
        record={'schema_version':'1.0','kind':'TEST_PEER_FAILURE_DIAGNOSIS_ONLY','selector':test.id(),'fixture_mode':f.fixture_mode,'recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'peer':result}
        with (d/('wp10-b1-peer-failure-'+uuid.uuid4().hex+'.json')).open('x') as output:json.dump(record,output,indent=2);output.write('\n')
    test.assertEqual(result['worker_exit'],0,result)
    test.assertTrue(result['display_verified']);test.assertTrue(result['responded']);test.assertEqual(inventory(f.old_state),old)
    test.assertLessEqual(result['transcript_bytes'],fixture()['test_worker_limits']['max_transient_transcript_bytes'])
    test.assertNotIn(str(f.release.base),json.dumps(result))
    if result['value'].get('unconfirmed_group'):f.unconfirmed_process=True
    return result['value']
