"""Descriptor-confined candidate files, trusted process lifetime and durability."""
from __future__ import annotations
import csv
import hashlib
import io
import os
import posixpath
import select
import signal
import stat
import subprocess
import threading
import time
import zipfile
import re
from types import ModuleType
from typing import Callable
import graph_engineering as installation
from graph_engineering.adapters import release_staging as planning
from graph_engineering.adapters import installation_authority as approval
from graph_engineering.core import staging_execution as contracts
from graph_engineering.core.contracts import parse_json
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.release_installation import fail,ReleaseInstallationError
from graph_engineering.core.release_staging import stage_digest,select_recipe

_RESOURCES=('config/contracts/staging-execution-schema-registry-v1.json',)+tuple(
 'config/contracts/schemas/'+name+'-1.0.0.json' for name in sorted(contracts.RECORD_FIELDS))
_OWNED=installation._installation_owned_resources
_CONTEXT=planning._CONTEXT;_NATIVE=planning._NATIVE;_ORIGIN=planning._ORIGIN
_OPEN=os.open;_CLOSE=os.close;_READ=os.read;_WRITE=os.write;_FSTAT=os.fstat;_STAT=os.stat
_MKDIR=os.mkdir;_FSYNC=os.fsync;_CHMOD=os.fchmod;_LIST=os.listdir
_POPEN=subprocess.Popen;_CLOCK=time.monotonic;_KILL=os.killpg;_POLL=select.select
_SETBLOCK=os.set_blocking;_PID=os.getpid;_THREAD=threading.get_ident;_DUP=os.dup;_SCAN=os.scandir
_NOFOLLOW=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
_SEAL=approval.ProviderSeal();_GUARD=approval._copy_cleanup(approval.ProviderSeal.require_current)
_METADATA={'installed-release-manifest':'installed-manifest.json','installation-binding':'binding.json',
    'stage-execution-binding':'execution-binding.json','stage-receipt':'receipt.json'}
_SCHEMA_PARSE_CACHE=[]

def owned_inputs(*,_guard: Callable=approval._copy_cleanup(approval.ProviderSeal.require_current),_seal: approval.ProviderSeal=planning.admission._TEMPLATE_SEAL,_inputs: Callable=planning.admission._template_inputs) -> tuple[ClosedSchemaRegistry,tuple]:
    _guard(_seal);return _inputs()

def validate_template_bytes(raw: bytes,context: WorkContext) -> tuple[dict[str,object],tuple]:
    values,binding=validate_template_batch((raw,),context)
    return values[0],binding

def validate_template_batch(raws: tuple[bytes,...],context: WorkContext,*,_guard: Callable=approval._copy_cleanup(approval.ProviderSeal.require_current),_seal: approval.ProviderSeal=planning.admission._TEMPLATE_SEAL,_batch: Callable=planning.admission._template_batch) -> tuple[tuple[dict[str,object],...],tuple]:
    _guard(_seal);return _batch(raws,context)

def _root_fact(s):
    return {'device':str(s.st_dev),'inode':str(s.st_ino),'mode':stat.S_IMODE(s.st_mode),'owner_id':str(s.st_uid)}

def _identity(s,ancestors):
    return {**{k:str(v) for k,v in (('device',s.st_dev),('inode',s.st_ino),('owner_id',s.st_uid),('mtime_ns',s.st_mtime_ns),('ctime_ns',s.st_ctime_ns))},'ancestors':ancestors}

def _ancestors(paths):
    result={'payload','payload/interpreter','payload/installer','payload/wheelhouse','payload/tool','payload/skills','metadata'}
    for p in paths:
        parts=p.split('/')
        result.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    return result

class StageSession:
    """Factory caller supplies an owned planning session and an already consumed permit."""
    def __init__(self,session,permit):
        if type(self) is not StageSession or type(session) is not planning.PlanningSession or type(permit) is not _PERMIT_TYPE:fail('authority_required')
        permit_current=_PERMIT_CURRENT;permit_facts=_PERMIT_FACTS
        self.parent=-1;self.root=-1;self.closed=False;self.session=session
        self.permit=permit;self.permit_current=permit_current;self.permit_facts=permit_facts
        self.pid=_PID();self.thread=_THREAD();self.created=False;self.accepted=False
        self.record=session.to_dict();self.plan=self.record['plan'];self.context=self.record['stage_context']
        self.policy=session._documents['config/release-installation/stage-policy-v1.json']
        self.manifest=session._manifest;self.recipe=select_recipe(session._documents['config/release-installation/installer-policy-v1.json'],self.manifest,_CONTEXT())
        self.registry,self.inputs=owned_inputs()
        facts=permit_facts(permit)
        self.challenge=facts['challenge_digest']
        if facts['planning_session'] is not session or session._release._template_binding!=self.inputs:fail('currentness')
        self.deadline=facts['deadline_ns']/1_000_000_000
        self.parent_path=next(r['path'] for r in session._registry['roots'] if r['role']=='candidate-parent' and r['ref'] in self.plan['target_refs'])
        self.name='stage-'+stage_digest('stage-candidate-name',{'request_id':self.plan['request_id'],'installation_id':self.plan['installation_id'],'envelope_digest':self.record['envelope_digest']},_CONTEXT()).split(':')[-1]
        self.path=self.parent_path+'/'+self.name
        self.refs={'interpreter':self.path+'/payload/interpreter/'+self.manifest['interpreter']['executable_member'],'tool':self.path+'/payload/tool','wheelhouse':self.path+'/payload/wheelhouse'}
        self.template_refs={k:self.refs[k] for k in ('interpreter','tool')}
        self.files={};self.distributions=[];self.templates={};self.raw_artifacts={};self.generated=set();self.normalized={};self.directory_facts={}
        self.metadata_facts={};self.extraction_native={};self.extraction_facts={};self.initial_directory_rows={};self.output_bytes=0
        self._prepare()
        self.directories=_ancestors(self.files)
        contracts.check_paths(sorted(self.files))
        contracts.check_paths(sorted([*self.files,*self.directories]),allow_directories=True)
        # Bound canonical physical identities by the admitted path depth and
        # unsigned 20-digit OS facts, plus four closed records. No disk quota claim.
        self.metadata_bound=sum(len(p.encode())+(len(p.split('/'))+1)*256+512 for p in self.files|dict.fromkeys(self.directories))+8192
        self.budget=contracts.StageBudget(self.policy)
        self.budget.reserve(sum(len(v['body']) if v['body'] is not None else v['maximum'] for v in self.files.values())+self.metadata_bound,len(self.files)+len(self.directories)+4)
        self.parent=self._open_parent();self.parent_fact=_root_fact(_FSTAT(self.parent));self.root_fact=None

    def _prepare(self,*,_reader_close=approval._copy_cleanup(planning.admission._READ_FILE_CLOSE)):
        limits=self.session._limits;budget=planning.admission._Budget(limits)
        snapshots={row[0]:row for row in self.session._release._files}
        for artifact in self.manifest['artifacts']:
            path=self.session._release._root/artifact['relative_path'];opened=planning.admission._ReadFile(path,limits['max_artifact_bytes'],budget,account_bundle=False)
            try:
                if opened.snapshot()!=snapshots[str(path)]:fail('currentness')
                self.raw_artifacts[artifact['artifact_id']]=opened.raw
            finally:_reader_close(opened)
        template_raws=tuple(self.raw_artifacts[a['artifact_id']] for a in self.manifest['artifacts'] if a['kind']=='build-input')
        values,binding=validate_template_batch(template_raws,_CONTEXT())
        if binding!=self.inputs:fail('currentness')
        for value in values:
            if value['logical_path'] in self.templates:fail('closure_mismatch')
            self.templates[value['logical_path']]=value
        declared={r['logical_path']:r for r in self.recipe['generated_files']}
        if set(declared)!=set(self.templates):fail('closure_mismatch')
        for path,template in self.templates.items():
            if {k:template[k] for k in ('logical_path','kind','template_digest')}!=declared[path]:fail('closure_mismatch')
        for artifact in self.manifest['artifacts']:
            raw=self.raw_artifacts[artifact['artifact_id']];kind=artifact['kind']
            if kind in ('interpreter','installer'):
                table=planning.admission._tar_structure(raw,budget)
                for member,(start,end) in table.items():
                    mode=int(raw[start-512+100:start-512+108].rstrip(b'\0 ').lstrip(b' ') or b'0',8)
                    if mode&0o7022 or mode>0o777:fail('closure_mismatch')
                    self._add('payload/'+kind+'/'+member,raw[start:end],mode,artifact['artifact_id'])
            elif kind in ('core-wheel','dependency-wheel'):
                self._add('payload/wheelhouse/'+artifact['relative_path'].split('/')[-1],raw,0o600,artifact['artifact_id'])
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    members=archive.namelist();mapping=contracts.map_wheel_members(artifact['distribution_name'],artifact['version'],self.manifest['interpreter']['patch'],members,_CONTEXT())
                    owned=[];record=None
                    for member in members:
                        body=archive.read(member);dest=mapping[member];mode=stat.S_IMODE(archive.getinfo(member).external_attr>>16) or 0o600
                        if mode&0o7022:fail('closure_mismatch')
                        if member.endswith('.dist-info/entry_points.txt') and body.strip():fail('phase_unavailable')
                        if member.endswith('.dist-info/RECORD'):
                            record=dest;self._add(dest,None,0o600,artifact['artifact_id'])
                        elif dest in self.templates:
                            if not member.startswith(re.sub('[-_.]+','_',artifact['distribution_name']).lower()+'-'+artifact['version']+'.data/scripts/') or not (body.startswith(b'#!python\n') or body==contracts.expand_template(self.templates[dest],self.template_refs,_CONTEXT())):fail('closure_mismatch')
                            self._add(dest,contracts.expand_template(self.templates[dest],self.template_refs,_CONTEXT()),mode,artifact['artifact_id']);self.generated.add(dest)
                        else:self._add(dest,body,mode,artifact['artifact_id'])
                        owned.append(dest)
                    if record is None or record not in self.templates or self.templates[record]['kind']!='RECORD':fail('closure_mismatch')
                    site=record.rsplit('/',2)[0];dist_dir=record.rsplit('/',1)[0]
                    for path,template in self.templates.items():
                        if path in owned:continue
                        if path in (dist_dir+'/INSTALLER',dist_dir+'/REQUESTED') and template['kind']=='script' and all('literal' in s for s in template['segments']):
                            self._add(path,contracts.expand_template(template,self.template_refs,_CONTEXT()),0o600,artifact['artifact_id']);owned.append(path);self.generated.add(path)
                    self.generated.add(record);self.distributions.append({'artifact':artifact,'site':site,'record':record,'paths':sorted(owned)})
                    self.files[record]['maximum']=sum(len(contracts.record_path(site,p).encode())+128 for p in owned)
            elif kind=='skill':
                skills=[r for r in self.manifest['skills'] if r['artifact_id']==artifact['artifact_id']]
                if len(skills)!=1:fail('phase_unavailable')
                s=skills[0];prefix='payload/skills/'+s['runtime_kind']+'/'+s['skill_id']+'/'+s['version']
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    for info in archive.infolist():
                        mode=stat.S_IMODE(info.external_attr>>16) or 0o600
                        if mode&0o7022:fail('closure_mismatch')
                        self._add(prefix+'/'+info.filename,archive.read(info),mode,artifact['artifact_id'])
        if set(self.templates)!=self.generated:fail('closure_mismatch')
        for path in ('payload/interpreter/'+self.manifest['interpreter']['executable_member'],'payload/installer/bin/uv'):
            if path not in self.files or not self.files[path]['mode']&0o100:fail('platform_unavailable')

    def _add(self,path,body,mode,owner):
        if path in self.files:fail('closure_mismatch')
        if not mode&0o400:fail('closure_mismatch')
        self.files[path]={'body':body,'mode':mode,'owner':owner,'maximum':0}

    def _open_parent(self):
        fd=_OPEN('/',_NOFOLLOW)
        try:
            for part in self.parent_path.split('/')[1:]:
                child=_OPEN(part,_NOFOLLOW,dir_fd=fd);_CLOSE(fd);fd=child
            return fd
        except BaseException:_CLOSE(fd);raise

    def barrier(self,*,mutating: bool=False,full: bool=False,_guard: Callable=_GUARD,_seal: object=_SEAL) -> None:
        _guard(_seal)
        if self.closed or self.pid!=_PID() or self.thread!=_THREAD():fail('currentness')
        if mutating:
            if self.permit is None:fail('authority_required')
            # Original execution_facts calls the original StagePermit currentness
            # path, which fully rechecks H0, its owned B0 session and A/schema
            # closure. Do not repeat the same chain three times at one barrier.
            facts=self.permit_facts(self.permit,full=full)
            if facts['planning_session'] is not self.session or facts['challenge_digest']!=self.challenge:fail('currentness')
            if facts['deadline_ns']/1_000_000_000!=self.deadline or _CLOCK()>=self.deadline:fail('authority_required')
        else:self.session.require_execution_current()
        if self.session._release._template_binding!=self.inputs:fail('currentness')
        other=self._open_parent()
        try:
            if _root_fact(_FSTAT(other))!=self.parent_fact or _root_fact(_FSTAT(self.parent))!=self.parent_fact:fail('currentness')
            if self.root>=0:
                s=_STAT(self.name,dir_fd=other,follow_symlinks=False)
                if _root_fact(s)!=self.root_fact or not stat.S_ISDIR(s.st_mode) or _root_fact(_FSTAT(self.root))!=self.root_fact:fail('currentness')
        finally:_CLOSE(other)

    def _directory(self,path):
        fd=_DUP(self.root)
        try:
            prefix=[]
            for part in path.split('/') if path else ():
                child=_OPEN(part,_NOFOLLOW,dir_fd=fd);_CLOSE(fd);fd=child
                prefix.append(part);logical='/'.join(prefix)
                if logical in self.directory_facts and _root_fact(_FSTAT(fd))!=self.directory_facts[logical]:fail('currentness')
            return fd
        except BaseException:_CLOSE(fd);raise

    def _write(self,path,raw,mode):
        self.barrier(mutating=True);parent=self._directory(path.rpartition('/')[0]);fd=-1
        try:
            fd=_OPEN(path.split('/')[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
            offset=0
            while offset<len(raw):
                self.barrier(mutating=True);n=_WRITE(fd,raw[offset:])
                if not n:fail('recovery_blocked')
                offset+=n
            self.barrier(mutating=True);_CHMOD(fd,mode);_FSYNC(fd);_FSYNC(parent)
            if path.startswith('metadata/'):self.metadata_facts[path]=planning.admission._stat_binding(_FSTAT(fd))
            else:self.extraction_native[path]=planning.admission._stat_binding(_FSTAT(fd))
        finally:
            if fd>=0:_CLOSE(fd)
            _CLOSE(parent)

    def acquire(self) -> None:
        self.barrier(mutating=True,full=True)
        failures=0
        with _SCAN(self.parent) as entries:
            for count,item in enumerate(entries,1):
                if count>self.policy['max_stage_files']:fail('resource_limit')
                if item.name.startswith('stage-'):
                    failures+=1
                    if failures>=self.policy['max_failed_candidates']:fail('recovery_blocked')
        self.barrier(mutating=True,full=True)
        try:_MKDIR(self.name,0o700,dir_fd=self.parent)
        except FileExistsError:fail('recovery_blocked')
        self.created=True;self.root=_OPEN(self.name,_NOFOLLOW,dir_fd=self.parent);self.root_fact=_root_fact(_FSTAT(self.root))
        if self.root_fact['mode']!=0o700 or self.root_fact['owner_id']!=str(os.getuid()):fail('currentness')
        for path in sorted(self.directories,key=lambda p:(p.count('/'),p)):
            self.barrier(mutating=True);parent=self._directory(path.rpartition('/')[0])
            try:
                _MKDIR(path.split('/')[-1],0o700,dir_fd=parent)
                child=_OPEN(path.split('/')[-1],_NOFOLLOW,dir_fd=parent)
                try:self.directory_facts[path]=_root_fact(_FSTAT(child))
                finally:_CLOSE(child)
                _FSYNC(parent)
            finally:_CLOSE(parent)
        for path,row in sorted(self.files.items()):
            if path.startswith('payload/tool/'):continue
            self._write(path,row['body'],row['mode'])

    def _group_alive(self,process,*,_state=object.__getattribute__,_wait=os.waitpid,_status=os.waitstatus_to_exitcode,_kill=_KILL,_nohang=os.WNOHANG):
        state=_state(process,'__dict__');pid=state['pid']
        if state['returncode'] is None:
            try:
                reaped,status=_wait(pid,_nohang)
                if reaped==pid:state['returncode']=_status(status)
            except (ChildProcessError,InterruptedError):pass
        try:_kill(pid,0)
        except ProcessLookupError:return False
        except PermissionError:return True
        return True

    def _revoke(self,process,number,*,_state=object.__getattribute__,_kill=_KILL):
        try:_kill(_state(process,'__dict__')['pid'],number)
        except (ProcessLookupError,PermissionError):
            # A denied signal is not proof of exit. In particular, an exiting
            # group can race signal permission checks. Keep the original K/D
            # bounds and let nonblocking reap/group observations decide.
            pass

    def _run(self,step,*,_guard=_GUARD,_seal=_SEAL,_clock=_CLOCK,_poll=_POLL,_read=_READ,
             _alive=approval._copy_cleanup(_group_alive),_revoke=approval._copy_cleanup(_revoke),
             _state=object.__getattribute__,_fileno=io.BufferedReader.fileno,_stream_close=io.BufferedReader.close,
             _term=signal.SIGTERM,_force=signal.SIGKILL,_fail=approval._copy_cleanup(fail)):
        self.barrier(mutating=True,full=True)
        extracted,bodies=self.inventory(complete=False,partial=True)
        for path,body in bodies.items():
            if self.files[path]['body'] is not None and body!=self.files[path]['body']:fail('closure_mismatch')
        current={r['logical_path']:r for r in extracted if r['kind']=='file' and not r['logical_path'].startswith('payload/tool/')}
        if self.extraction_facts and current!=self.extraction_facts:fail('currentness')
        if not self.extraction_facts:
            self.extraction_facts=current
            self.initial_directory_rows={r['logical_path']:r for r in extracted if r['kind']=='directory'}
        executable=self.refs[step['executable_ref']] if step['executable_ref']=='interpreter' else self.path+'/payload/installer/bin/uv'
        def arg(value: object) -> str:return value if type(value) is str else self.refs[value['ref']]
        argv=[executable,*[arg(v) for v in step['argv']]];environment={r['name']:arg(r['value']) for r in step['environment']}
        _guard(_seal)
        start=_clock();execute,kill,final=contracts.process_cutoffs(start,self.deadline,self.policy['max_process_seconds'])
        process=None;streams=[];failure: str|None=None;term_sent=False;kill_sent=False;count=self.output_bytes
        try:
            process=_POPEN(argv,executable=executable,cwd=self.path,env=environment,shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,start_new_session=True)
            state=_state(process,'__dict__');streams=[state['stdout'],state['stderr']]
            _guard(_seal)
            for stream in streams:_SETBLOCK(_fileno(stream),False)
            live={_fileno(stream) for stream in streams}
            while True:
                _guard(_seal)
                now=_clock();alive=_alive(self,process)
                if now>=execute and failure is None:failure='resource_limit'
                if failure is not None and alive and not term_sent:
                    _revoke(self,process,_term)
                    term_sent=True
                if alive and now>=kill and not kill_sent:
                    _revoke(self,process,_force)
                    kill_sent=True
                if now>=final:
                    confirmed=not _alive(self,process) and state['returncode'] is not None
                    fail(contracts.process_deadline_outcome(confirmed,failure or 'resource_limit'))
                ready,_,_=_poll(list(live),[],[],min(0.01,max(0,final-now)))
                for fd in ready:
                    try:raw=_read(fd,min(65536,self.policy['max_output_bytes']-count+1))
                    except (BlockingIOError,InterruptedError):continue
                    if raw:count+=len(raw);self.output_bytes=count
                    else:live.discard(fd)
                    if count>self.policy['max_output_bytes']:failure='resource_limit';live.clear();break
                if not alive and state['returncode'] is not None and not live:
                    if failure:fail(failure)
                    if state['returncode']!=0:fail('closure_mismatch')
                    break
            self.barrier(mutating=True,full=True)
        except BaseException:
            if process is not None and _alive(self,process):
                if not term_sent:
                    _revoke(self,process,_term)
                # Revocation uses the original cutoffs, never a fresh wait window.
                while _clock()<final and _alive(self,process):
                    now=_clock()
                    if now>=kill and not kill_sent:
                        _revoke(self,process,_force)
                        kill_sent=True
                    _poll([],[],[],min(0.01,max(0,final-now)))
                if not kill_sent:
                    _revoke(self,process,_force)
            if process is not None and (_alive(self,process) or _state(process,'__dict__')['returncode'] is None):_fail('recovery_blocked')
            raise
        finally:
            # No destructor-driven later reap/PID retry, even after an unknown
            # final outcome. Actual confirmation above is never manufactured.
            if process is not None:_state(process,'__dict__')['_child_created']=False
            for stream in streams:_stream_close(stream)

    def execute(self) -> None:
        # Reserve the remaining accepted allowance before a trusted child starts.
        self.budget.reserve(self.policy['max_stage_bytes']-self.budget.bytes,self.policy['max_stage_files']-self.budget.files)
        for step in self.recipe['steps']:self._run(step)

    def inventory(self,*,complete: bool,partial: bool=False) -> tuple[list[dict[str,object]],dict[str,bytes]]:
        result=[];bodies={};total=0;seen=set();expected_dirs=self.directories;observed_dirs={};observed_metadata={}
        expected_files=self.files
        def walk(fd: int,prefix: str,ancestors: list[dict[str,object]]) -> None:
            nonlocal total
            names=[]
            with _SCAN(fd) as entries:
                for item in entries:
                    if len(seen)+len(names)>=self.policy['max_stage_files']:fail('resource_limit')
                    names.append(item.name)
            for name in sorted(names):
                path=prefix+'/'+name if prefix else name
                if path.casefold() in seen:fail('closure_mismatch')
                seen.add(path.casefold());s=_STAT(name,dir_fd=fd,follow_symlinks=False);mode=stat.S_IMODE(s.st_mode)
                if s.st_uid!=os.getuid() or mode&0o7022 or s.st_nlink>1 and not stat.S_ISDIR(s.st_mode):fail('closure_mismatch')
                if stat.S_ISDIR(s.st_mode):
                    if path not in expected_dirs or mode!=0o700:fail('closure_mismatch')
                    if path in self.directory_facts and _root_fact(s)!=self.directory_facts[path]:fail('currentness')
                    observed_dirs[path]=_root_fact(s)
                    child=_OPEN(name,_NOFOLLOW,dir_fd=fd)
                    try:
                        if _root_fact(_FSTAT(child))!=_root_fact(s):fail('currentness')
                        if path!='metadata':result.append({'logical_path':path,'kind':'directory','raw_sha256':None,'size_bytes':0,'mode':mode,'physical_identity':_identity(s,ancestors)})
                        walk(child,path,[*ancestors,_root_fact(s)])
                    finally:_CLOSE(child)
                elif stat.S_ISREG(s.st_mode):
                    metadata=path in {'metadata/'+v for v in _METADATA.values()}
                    if path not in expected_files and not (complete and metadata):fail('closure_mismatch')
                    if metadata and mode!=0o600:fail('closure_mismatch')
                    if metadata:
                        observed_metadata[path]=planning.admission._stat_binding(s)
                        if path in self.metadata_facts and observed_metadata[path]!=self.metadata_facts[path]:fail('currentness')
                    if metadata and s.st_size>self.session._limits['max_manifest_bytes']:fail('resource_limit')
                    if path in self.files and mode!=self.files[path]['mode']:fail('closure_mismatch')
                    if path in self.extraction_native and planning.admission._stat_binding(s)!=self.extraction_native[path]:fail('currentness')
                    if path in self.files:
                        expected=self.files[path]
                        if expected['body'] is None and s.st_size>expected['maximum']:fail('resource_limit')
                        if expected['body'] is not None and s.st_size!=len(expected['body']):fail('closure_mismatch')
                    total+=s.st_size
                    if total>self.policy['max_stage_bytes']:fail('resource_limit')
                    child=_OPEN(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        before=planning.admission._stat_binding(_FSTAT(child));raw=b''
                        if before!=planning.admission._stat_binding(s):fail('currentness')
                        while chunk:=_READ(child,min(65536,self.policy['max_stage_bytes']-len(raw)+1)):
                            raw+=chunk
                            if len(raw)>s.st_size:fail('currentness')
                        if len(raw)!=s.st_size or planning.admission._stat_binding(_FSTAT(child))!=before or planning.admission._stat_binding(_STAT(name,dir_fd=fd,follow_symlinks=False))!=before:fail('currentness')
                        bodies[path]=raw
                        if not metadata:result.append({'logical_path':path,'kind':'file','raw_sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw),'mode':mode,'physical_identity':_identity(s,ancestors)})
                    finally:_CLOSE(child)
                else:fail('closure_mismatch')
        walk(self.root,'',[self.root_fact])
        expected=set(expected_files)|self.directories|({'metadata/'+n for n in _METADATA.values()} if complete else set())
        required=self.directories|{p for p in expected_files if not partial or not p.startswith('payload/tool/')}
        if complete:required|={'metadata/'+name for name in _METADATA.values()}
        if not {p.casefold() for p in required}<=seen<={p.casefold() for p in expected}:fail('closure_mismatch')
        self.observed_directories=observed_dirs
        self.observed_metadata=observed_metadata
        return sorted(result,key=lambda r:r['logical_path']),bodies

    def semantic_manifest(self,bodies: dict[str,bytes]) -> dict[str,object]:
        c=_CONTEXT();normalized={}
        for path,row in self.files.items():
            if row['body'] is not None and bodies[path]!=row['body']:fail('closure_mismatch')
            if path in self.generated and self.templates[path]['kind']!='RECORD':normalized[path]=contracts.normalize_template(self.templates[path],bodies[path],self.template_refs,c)
        distributions=[]
        for d in self.distributions:
            try:rows=list(csv.reader(io.StringIO(bodies[d['record']].decode('utf-8'),newline=''),strict=True))
            except (UnicodeError,csv.Error):fail('closure_mismatch')
            expected={contracts.record_path(d['site'],p):p for p in d['paths']};seen=set();logical=[]
            for row in rows:
                if len(row)!=3 or row[0] not in expected or row[0] in seen:fail('closure_mismatch')
                seen.add(row[0]);path=expected[row[0]]
                if path==d['record']:
                    if row[1:]!=['','']:fail('closure_mismatch')
                    logical.append([path,'',''])
                else:
                    raw=bodies[path]
                    if row[1:]!=[contracts.record_hash(raw),str(len(raw))]:fail('closure_mismatch')
                    body=normalized.get(path,raw);logical.append([path,contracts.record_hash(body),str(len(body))])
            if seen!=set(expected):fail('closure_mismatch')
            a=d['artifact'];distributions.append({'name':re.sub('[-_.]+','-',a['distribution_name']).lower(),'version':a['version'],'wheel_sha256':a['raw_sha256'],'installed_record_digest':stage_digest('installed-record',sorted(logical),c)})
        skills=[{**{k:s[k] for k in ('runtime_kind','skill_id','version','protocol_range')},'asset_digest':stage_digest('installed-skill',[
            {'logical_path':p,'raw_sha256':hashlib.sha256(raw).hexdigest(),'size_bytes':len(raw)} for p,raw in sorted(bodies.items()) if self.files.get(p,{}).get('owner')==s['artifact_id']],c)} for s in self.manifest['skills']]
        docs={key:parse_json(self.raw_artifacts[self.manifest[key]],context=c,source_id=key) for key in ('lock_artifact_id','sbom_artifact_id','security_evidence_artifact_id')}
        body={'schema_version':'1.0.0','release_id':self.manifest['release_id'],'platform':self.manifest['platform'],'interpreter_identity':self.manifest['interpreter'],'distributions':sorted(distributions,key=lambda r:r['name']),'skills':skills,
            'lock_digest':docs['lock_artifact_id']['export_digest'],'sbom_digest':docs['sbom_artifact_id']['sbom_digest'],'security_evidence_digest':planning.admission.semantic('security-evidence',{k:v for k,v in docs['security_evidence_artifact_id'].items() if k!='signature'},c),'policy_digest':self.manifest['policy_digest']}
        return contracts.seal('installed-release-manifest',body,c)

    def records(self,files: list[dict[str,object]],bodies: dict[str,bytes],*,origin: dict[str,object]|None=None) -> dict[str,dict[str,object]]:
        c=_CONTEXT();manifest=self.semantic_manifest(bodies);by_path={r['logical_path']:r for r in files}
        def executable(path: str) -> dict[str,object]:return {k:v for k,v in by_path[path].items() if k!='kind'}
        binding=contracts.seal('installation-binding',{'schema_version':'1.0.0','installation_id':self.plan['installation_id'],'request_id':self.plan['request_id'],'plan_digest':self.plan['plan_digest'],'stage_context_digest':self.context['context_digest'],
            'candidate_identity':self.root_fact,'interpreter_binding':executable('payload/interpreter/'+self.manifest['interpreter']['executable_member']),'installer_binding':executable('payload/installer/bin/uv'),'files':files},c)
        execution=origin or contracts.seal('stage-execution-binding',{'schema_version':'1.0.0','installation_id':self.plan['installation_id'],'request_id':self.plan['request_id'],'operation':'install','plan_digest':self.plan['plan_digest'],'stage_context_digest':self.context['context_digest'],'envelope_digest':self.record['envelope_digest'],'challenge_digest':self.challenge},c)
        if origin:
            contracts.validate_record('stage-execution-binding',origin,c)
            for k in ('installation_id','request_id','operation','plan_digest'):
                if origin[k]!=self.plan[k]:fail('closure_mismatch')
            if origin['stage_context_digest']!=self.context['context_digest'] or origin['envelope_digest']!=self.record['envelope_digest']:fail('closure_mismatch')
        receipt=contracts.seal('stage-receipt',{'schema_version':'1.0.0','request_id':self.plan['request_id'],'plan_digest':self.plan['plan_digest'],'release_manifest_digest':self.plan['release_manifest_digest'],'stage_context_digest':self.context['context_digest'],'installed_manifest_digest':manifest['installed_manifest_digest'],'binding_digest':binding['binding_digest'],'execution_binding_digest':execution['execution_binding_digest'],'status':'staged'},c)
        return {'installed-release-manifest':manifest,'installation-binding':binding,'stage-execution-binding':execution,'stage-receipt':receipt}

    def persist(self) -> None:
        self.barrier(mutating=True,full=True);files,bodies=self.inventory(complete=False);records=self.records(files,bodies)
        current={r['logical_path']:r for r in files if r['kind']=='file' and not r['logical_path'].startswith('payload/tool/')}
        if current!=self.extraction_facts:fail('currentness')
        self.dirty_directories={r['logical_path'] for r in files if r['kind']=='directory' and r!=self.initial_directory_rows.get(r['logical_path'])}
        raw={kind:contracts.canonical(doc) for kind,doc in records.items()}
        if any(len(body)>self.session._limits['max_manifest_bytes'] for body in raw.values()):fail('resource_limit')
        if sum(map(len,raw.values()))>self.metadata_bound:fail('resource_limit')
        for kind in ('stage-execution-binding','installed-release-manifest','installation-binding','stage-receipt'):
            if self.registry.validate('urn:gew:schema:'+kind+':1.0.0',records[kind],_CONTEXT()):fail('trust_rejected')
            self._write('metadata/'+_METADATA[kind],raw[kind],0o600)
        self.fsync(initial_stage=True);self.verify();self.barrier(mutating=True,full=True);self.accepted=True

    def fsync(self,*,initial_stage: bool=False) -> None:
        # Trusted installer-created payload files and all reopened coordinator
        # records must themselves reach durability; directory fsync is not enough.
        paths=[p for p in self.files if not initial_stage or p.startswith('payload/tool/')]
        if not initial_stage:paths+=['metadata/'+name for name in _METADATA.values()]
        for path in sorted(paths):
            self.barrier(mutating=True);parent=self._directory(path.rpartition('/')[0])
            try:
                fd=_OPEN(path.split('/')[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                try:_FSYNC(fd)
                finally:_CLOSE(fd)
            finally:_CLOSE(parent)
        directories=self.directories if not initial_stage else ({p.rpartition('/')[0] for p in paths}|self.dirty_directories|{'metadata'})
        for path in sorted(directories,key=lambda p:(-p.count('/'),p)):
            self.barrier(mutating=True);fd=self._directory(path)
            try:_FSYNC(fd)
            finally:_CLOSE(fd)
        self.barrier(mutating=True);_FSYNC(self.root);_FSYNC(self.parent)

    def reopen(self) -> None:
        self.barrier(mutating=True)
        try:self.root=_OPEN(self.name,_NOFOLLOW,dir_fd=self.parent)
        except FileNotFoundError:fail('recovery_blocked')
        self.root_fact=_root_fact(_FSTAT(self.root))
        if self.root_fact['mode']!=0o700 or self.root_fact['owner_id']!=str(os.getuid()):fail('currentness')
        self.verify();self.fsync();self.verify();self.barrier(mutating=True,full=True);self.accepted=True

    def verify(self) -> str:
        self.barrier();files,bodies=self.inventory(complete=True);c=_CONTEXT();records={}
        for kind,name in _METADATA.items():
            raw=bodies['metadata/'+name];doc=parse_json(raw,context=c,source_id='stage-'+kind)
            if contracts.canonical(doc)!=raw or self.registry.validate('urn:gew:schema:'+kind+':1.0.0',doc,c):fail('closure_mismatch')
            records[kind]=contracts.validate_record(kind,doc,c)
        actual=self.records(files,bodies,origin=records['stage-execution-binding'])
        if actual!=records:fail('closure_mismatch')
        if not self.directory_facts:self.directory_facts=dict(self.observed_directories)
        if not self.metadata_facts:self.metadata_facts=dict(self.observed_metadata)
        self.barrier();self.result=records
        return records['stage-receipt']['receipt_digest']

    def release_permit(self) -> None:self.permit=None
    def close(self,*,_close: Callable=_CLOSE,_state: Callable=object.__getattribute__) -> None:
        state=_state(self,'__dict__')
        if state.get('closed'):return
        state['closed']=True
        for name in ('root','parent'):
            fd=state.get(name,-1);state[name]=-1
            if fd>=0:
                try:_close(fd)
                except OSError:pass

def configure(local: ModuleType) -> None:
    global _PERMIT_TYPE,_PERMIT_CURRENT,_PERMIT_FACTS
    _PERMIT_TYPE=local.StagePermit;_PERMIT_CURRENT=local.StagePermit.require_current;_PERMIT_FACTS=local.execution_facts

def bind_providers(modules: tuple[ModuleType,...],classes: tuple[type,...]) -> None:
    import sys
    # Bind effective aliases as well as the originals captured for rejection
    # cleanup. A changed alias must invalidate the live child operation.
    if not all(callable(provider) for provider in (_CLOCK,_POLL,_READ,_KILL,_POPEN,_SETBLOCK,os.waitpid,os.waitstatus_to_exitcode,io.BufferedReader.fileno,io.BufferedReader.close)):fail('currentness')
    if type(os.WNOHANG) is not int or signal.SIGTERM==signal.SIGKILL:fail('currentness')
    _SEAL.freeze((sys.modules[__name__],contracts,*modules),(StageSession,subprocess.Popen,*classes))

