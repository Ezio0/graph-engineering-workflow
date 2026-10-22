"""Owned physical planning inputs; never creates roots or executes release artifacts."""
from __future__ import annotations
import hashlib
import os
import stat
import threading
import time
import weakref
from pathlib import Path
from typing import Callable
import graph_engineering as installation
from graph_engineering.adapters import release_installation as admission
from graph_engineering.core.contracts import parse_json, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.release_installation import ReleaseInstallManifest,ReleaseInstallationError,fail,semantic
from graph_engineering.core.release_staging import (
    StageRequest,stage_digest,validate_stage_policy,validate_installer_policy,
    validate_target_registry,select_recipe,validate_envelope,
)

_LOAD=installation._release_staging_resources
_OWNED=installation._installation_owned_resources
_CONTEXT=admission._fresh_context
_ORIGIN=admission._origin_binding
_NATIVE=admission._resource_native_binding
_VERIFIER=admission.LocalReleaseVerifier
_CHECK=_VERIFIER.check
_RELEASE=admission.ReleaseObservation
_RELEASE_CURRENT=_RELEASE.require_current
_RELEASE_DICT=_RELEASE.to_dict
_RELEASE_CLOSE=_RELEASE.close
_READ=admission._ReadFile
_BUDGET=admission._Budget
_HOST=admission._host_platform
_SOURCE=installation._source_checkout_root
_ADMISSION_INPUTS=admission.InstalledReleaseInputs
_ADMISSION_OPEN=vars(_ADMISSION_INPUTS)['open_owned']
_ADMISSION_LIMITS=vars(_ADMISSION_INPUTS)['limits']
_A_FUNCTIONS=tuple((name,vars(admission)[name]) for name in (
    '_capture','_release_backend','_stat_binding','_member_path','_zip_structure',
    '_tar_structure','_bundle_members','_json','_verify_signature','_security_check',
    'marker_environment','_CAPTURE_LOADER','_OWNED_LOADER','_SEED_LOADER','_PARSER_RESOURCES',
))
_A_METHODS=tuple((cls,name,vars(cls).get(name)) for cls,names in (
    (_ADMISSION_INPUTS,('__new__','__init__','open_owned','resource_paths','binding_digest',
        '_document','policy','trust','limits','require_current')),
    (_VERIFIER,('__new__','__init__','check','_check')),
    (_RELEASE,('require_current','_require_current','to_dict','close','__del__')),
    (_READ,('__new__','__init__','_read','_check_stat','recheck','snapshot','close')),
    (_BUDGET,('__new__','__init__','charge','ceiling')),
) for name in names)
_INPUTS=weakref.WeakKeyDictionary()
_INPUT_PARSE_CACHE=[]


def _providers():
    if (vars(admission).get('InstalledReleaseInputs') is not _ADMISSION_INPUTS
        or any(vars(admission).get(name) is not function for name,function in _A_FUNCTIONS)
        or any(vars(cls).get(name) is not method for cls,name,method in _A_METHODS)
        or installation._source_checkout_root is not _SOURCE
        or InstalledStageInputs is not _INPUT_TYPE or vars(_INPUT_TYPE).get('open_owned') is not _INPUT_OPEN
        or vars(_INPUT_TYPE).get('documents') is not _INPUT_DOCUMENTS or vars(_INPUT_TYPE).get('require_current') is not _INPUT_CURRENT
        or installation._release_staging_resources is not _LOAD or installation._installation_owned_resources is not _OWNED
        or admission._fresh_context is not _CONTEXT or admission._origin_binding is not _ORIGIN
        or admission._resource_native_binding is not _NATIVE or admission.LocalReleaseVerifier is not _VERIFIER
        or vars(_VERIFIER).get('check') is not _CHECK or admission.ReleaseObservation is not _RELEASE
        or vars(_RELEASE).get('require_current') is not _RELEASE_CURRENT
        or admission._ReadFile is not _READ or admission._Budget is not _BUDGET or admission._host_platform is not _HOST):fail('currentness')


def _capture():
    _providers();c=_CONTEXT();origin=_ORIGIN();paths,bodies=_LOAD(c)
    if type(paths) is not tuple or type(bodies) is not tuple or len(paths)!=12 or len(bodies)!=12 or len(set(paths))!=12:fail('trust_rejected')
    native=_NATIVE(paths);schema_profile=_OWNED(('config/contracts/schema-profile-v1.json',),context=c)[0]
    cache_key=(paths,bodies,schema_profile,c.profile,origin,native)
    if _INPUT_PARSE_CACHE and _INPUT_PARSE_CACHE[0][0]==cache_key:
        _providers()
        if _ORIGIN()!=origin or _NATIVE(paths)!=native:fail('currentness')
        return paths,bodies,_INPUT_PARSE_CACHE[0][1]
    documents=[parse_json(b,context=c,source_id=p) for p,b in zip(paths,bodies,strict=True)]
    bypath=dict(zip(paths,documents,strict=True))
    schema_bodies={x['$id']:b for x,b in zip(documents,bodies,strict=True) if '$id' in x}
    if len(schema_bodies)!=8:fail('trust_rejected')
    registry=ClosedSchemaRegistry.build(bypath['config/contracts/release-staging-schema-registry-v1.json'],schema_bodies,c.profile,
        SchemaProfilePolicy.from_dict(parse_json(schema_profile,context=c,source_id='stage-schema-profile')),c)
    for name,validator in (('stage-policy',validate_stage_policy),('installer-policy',validate_installer_policy),('stage-target-registry',validate_target_registry)):
        doc=bypath['config/release-installation/'+name+'-v1.json']
        if registry.validate('urn:gew:schema:'+name+':1.0.0',doc,c):fail('trust_rejected')
        validator(doc,c)
    if bypath['config/release-installation/stage-policy-v1.json']['installer_policy_digest']!=bypath['config/release-installation/installer-policy-v1.json']['policy_digest']:fail('trust_rejected')
    native=_NATIVE(paths);_providers()
    if _ORIGIN()!=origin or _NATIVE(paths)!=native:fail('currentness')
    binding=stage_digest('stage-input-binding',{'origin':origin,'native':native,'resources':[{'path':p,'raw_sha256':hashlib.sha256(b).hexdigest()} for p,b in zip(paths,bodies,strict=True)]},c)
    _INPUT_PARSE_CACHE[:]=[(cache_key,binding)]
    return paths,bodies,binding


_CAPTURE=_capture


class InstalledStageInputs:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('stage inputs require open_owned')

    @classmethod
    def open_owned(cls) -> InstalledStageInputs:
        if cls is not InstalledStageInputs:fail('trust_rejected')
        try:
            if _capture is not _CAPTURE:fail('currentness')
            v=_CAPTURE();result=object.__new__(cls);_INPUTS[result]=v;return result
        except ReleaseInstallationError:raise
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):fail('trust_rejected')

    def require_current(self) -> str:
        if type(self) is not InstalledStageInputs or self not in _INPUTS:fail('currentness')
        try:
            if _capture is not _CAPTURE or _CAPTURE()!=_INPUTS[self]:fail('currentness')
            return _INPUTS[self][2]
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):
            _INPUTS.pop(self,None);fail('currentness')
        except BaseException:
            _INPUTS.pop(self,None);raise

    @property
    def resource_paths(self) -> tuple[str,...]:
        _INPUT_CURRENT(self);return _INPUTS[self][0]

    def documents(self) -> dict[str,object]:
        _INPUT_CURRENT(self);paths,bodies,_=_INPUTS[self];c=_CONTEXT()
        return {p:parse_json(b,context=c,source_id=p) for p,b in zip(paths,bodies,strict=True)}


_INPUT_TYPE=InstalledStageInputs
_INPUT_CURRENT=InstalledStageInputs.require_current
_INPUT_DOCUMENTS=InstalledStageInputs.documents
_INPUT_OPEN=vars(InstalledStageInputs)['open_owned']


def _directory_fact(path,owner,*,absent):
    """Walk descriptors from /, reject symlinks, bind actual ancestor identities."""
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    descriptor=os.open('/',flags);facts=[];present=True
    try:
        parts=Path(path).parts[1:]
        for index,part in enumerate(parts):
            s=os.fstat(descriptor)
            facts.append({'logical_index':index,'device':str(s.st_dev),'inode':str(s.st_ino),'mode':stat.S_IMODE(s.st_mode),'owner_id':str(s.st_uid)})
            try:child=os.open(part,flags,dir_fd=descriptor)
            except FileNotFoundError:
                if not absent or index!=len(parts)-1:fail('platform_unavailable')
                present=False
                if owner is not None and (str(s.st_uid)!=owner or stat.S_IMODE(s.st_mode)&0o077):fail('trust_rejected')
                break
            os.close(descriptor);descriptor=child
        if present:
            s=os.fstat(descriptor)
            if absent:fail('recovery_blocked')
            if owner is not None and (str(s.st_uid)!=owner or stat.S_IMODE(s.st_mode)&0o077):fail('trust_rejected')
            facts.append({'logical_index':len(parts),'device':str(s.st_dev),'inode':str(s.st_ino),'mode':stat.S_IMODE(s.st_mode),'owner_id':str(s.st_uid)})
        return present,facts
    finally:os.close(descriptor)


def _target_binding(registry,request,context):
    validate_target_registry(registry,context)
    if registry['installation_id']!=request['installation_id']:fail('platform_unavailable')
    selected=[r for r in registry['roots'] if r['ref'] in request['target_refs']]
    if len(selected)!=len(request['target_refs']):fail('platform_unavailable')
    if sum(r['role']=='installation' for r in selected)!=1 or sum(r['role']=='candidate-parent' for r in selected)!=1:fail('platform_unavailable')
    rows=[];identities=set()
    # Every configured root participates even when its opaque ref is not requested.
    # String prefixes cannot establish isolation on a case-insensitive filesystem.
    for root in registry['roots']:
        present,ancestors=_DIRECTORY(root['path'],root['owner_id'],absent=root['role']=='installation')
        last=ancestors[-1];identity=(last['device'],last['inode'],'' if present else Path(root['path']).name.casefold())
        if identity in identities:fail('trust_rejected')
        identities.add(identity)
        rows.append({'ref':root['ref'],'role':root['role'],'normalized_path':root['path'],'owner_id':root['owner_id'],'present':present,'ancestors':ancestors})
    candidate_ref=next(r['ref'] for r in selected if r['role']=='candidate-parent')
    candidate=next(r for r in rows if r['ref']==candidate_ref)
    candidate_ids={(a['device'],a['inode']) for a in candidate['ancestors']}
    candidate_id=(candidate['ancestors'][-1]['device'],candidate['ancestors'][-1]['inode'])
    for root in rows:
        if root['ref']==candidate_ref:continue
        ancestors=root['ancestors'];root_id=(ancestors[-1]['device'],ancestors[-1]['inode'])
        if (candidate_id in {(a['device'],a['inode']) for a in ancestors}
            or root['present'] and root_id in candidate_ids):fail('trust_rejected')
    # The attested running source/tool root is also excluded. Its ownership/mode
    # admission belongs to the existing installation boundary, not target policy.
    module=Path(installation.__file__).resolve(strict=True);source=_SOURCE(module)
    _,owned=_DIRECTORY(str(source if source else module.parent),None,absent=False)
    if (candidate_id in {(a['device'],a['inode']) for a in owned}
        or (owned[-1]['device'],owned[-1]['inode']) in candidate_ids):fail('trust_rejected')
    body={'registry_digest':registry['registry_digest'],'requested_refs':request['target_refs'],'roots':rows,'prior_tuple_digest':None}
    return stage_digest('stage-target-binding',body,context)


_TARGET=_target_binding
_DIRECTORY=_directory_fact


class PlanningSession:
    """Read-only operation lifetime; adapter-private facts do not enter JSON."""
    def __init__(self,request: object,bundle: Path,manifest_path: Path,*,_reader_close: Callable=admission._copy_cleanup(admission._READ_FILE_CLOSE),_close: Callable|None=None):
        self._release=None;self._invalid=False;self._pid=os.getpid();self._thread=threading.get_ident()
        try:
            _providers();c=_CONTEXT();self._request=StageRequest.from_dict(request,c).to_dict()
            if self._request['operation']!='install':fail('phase_unavailable')
            self._inputs=_INPUT_OPEN.__get__(None,_INPUT_TYPE)();self._input_current=_INPUT_CURRENT.__get__(self._inputs,_INPUT_TYPE)
            self._documents=_INPUT_DOCUMENTS(self._inputs);self._binding=self._input_current()
            self._release=_CHECK(_VERIFIER(),bundle,manifest_path);_providers()
            if type(self._release) is not _RELEASE:fail('currentness')
            self._release_current=_RELEASE_CURRENT.__get__(self._release,_RELEASE)
            limits=self._release._limits;budget=admission._Budget(limits)
            opened=admission._ReadFile(manifest_path,limits['max_manifest_bytes'],budget)
            try:
                value=ReleaseInstallManifest.from_dict(parse_json(opened.raw,context=c,source_id='stage-manifest'),c).to_dict()
                self._manifest_snapshot=opened.snapshot()
            finally:_reader_close(opened)
            self._limits=limits;self._budget=budget
            _providers();report=_RELEASE_DICT(self._release)
            if value['manifest_digest']!=self._request['release_manifest_digest'] or value['manifest_digest'] not in report['refs']:fail('trust_rejected')
            self._manifest=value;policy=self._documents['config/release-installation/stage-policy-v1.json'];installer=self._documents['config/release-installation/installer-policy-v1.json']
            self._registry=self._documents['config/release-installation/stage-target-registry-v1.json'];recipe=select_recipe(installer,value,c)
            templates={t['logical_path']:t for t in self._release._templates}
            declarations={r['logical_path']:r for r in recipe['generated_files']}
            if set(templates)!=set(declarations) or any({k:templates[p][k] for k in ('logical_path','kind','template_digest')}!=declarations[p] for p in declarations):fail('closure_mismatch')
            if _target_binding is not _TARGET or _directory_fact is not _DIRECTORY:fail('currentness')
            binding=_TARGET(self._registry,self._request,c)
            ctx={'schema_version':'1.0.0','stage_policy_digest':policy['policy_digest'],'installer_policy_digest':installer['policy_digest'],
                'recipe_digest':recipe['recipe_digest'],'target_registry_digest':self._registry['registry_digest'],'target_binding_digest':binding}
            ctx['context_digest']=stage_digest('stage-context',ctx,c)
            closure=[x for x in report['refs'] if x!=value['manifest_digest']]
            if len(closure)!=1:fail('closure_mismatch')
            plan={**self._request,'policy_digest':value['policy_digest'],'closure_digest':closure[0],'platform_digest':semantic('platform',value['platform'],c)}
            plan['plan_digest']=semantic('plan',plan,c)
            record={'schema_version':'1.0.0','plan':plan,'stage_context':ctx};record['envelope_digest']=stage_digest('stage-plan-envelope',record,c)
            self._record=freeze(validate_envelope(record,c));self.require_current()
            # A write barrier needs the complete same byte closure, not repeated
            # nested loads of that closure. Preserve original full currentness at
            # trust transitions; batch actual resources at intermediate barriers.
            from graph_engineering.adapters import staging_execution as execution
            from graph_engineering.adapters import installation_authority as approval
            self._execution_approval_paths=approval._RESOURCES
            self._execution_paths=tuple(sorted(set(self._inputs.resource_paths+self._release._inputs.resource_paths+execution._RESOURCES+approval._RESOURCES+
                ('config/contracts/schema-profile-v1.json','config/contracts/resource-profile-v1.json','config/contracts/cost-schedule-v1.json'))))
            self._execution_work=c
            self._execution_bytes,self._execution_native=self._capture_execution()
            self._execution_origin=_ORIGIN()
            captured=dict(zip(self._execution_paths,self._execution_bytes,strict=True))
            old_paths,old_bodies,_=_INPUTS[self._inputs]
            for path,body in zip(old_paths,old_bodies,strict=True):
                if captured[path]!=body:fail('currentness')
            for path,body in zip(self._release._inputs._paths,self._release._inputs._bodies,strict=True):
                if captured[path]!=body:fail('currentness')
            if (parse_json(captured['config/contracts/resource-profile-v1.json'],context=c,source_id='execution-profile')!=c.profile.to_dict()
                or parse_json(captured['config/contracts/cost-schedule-v1.json'],context=c,source_id='execution-schedule')!=c.schedule.to_dict()):fail('currentness')
            if self._release._template_binding is not None:
                current_binding=(_ORIGIN(),_NATIVE(execution._RESOURCES),tuple(hashlib.sha256(captured[p]).hexdigest() for p in execution._RESOURCES))
                if current_binding!=self._release._template_binding:fail('currentness')
        except BaseException:
            _close(self);raise

    def require_current(self,*,_reader_close: Callable=admission._copy_cleanup(admission._READ_FILE_CLOSE),_close: Callable|None=None) -> str:
        try:
            if '_execution_bytes' in self.__dict__:
                return _EXECUTION_CURRENT(self)
            if self._invalid or self._pid!=os.getpid() or self._thread!=threading.get_ident():fail('currentness')
            _providers()
            if (vars(InstalledStageInputs).get('require_current') is not _INPUT_CURRENT
                or vars(InstalledStageInputs).get('documents') is not _INPUT_DOCUMENTS
                or vars(InstalledStageInputs).get('open_owned') is not _INPUT_OPEN
                or _target_binding is not _TARGET or _directory_fact is not _DIRECTORY):fail('currentness')
            if type(self._inputs) is not InstalledStageInputs or self._input_current()!=self._binding:fail('currentness')
            if type(self._release) is not _RELEASE:fail('currentness')
            self._release_current();path=self._manifest_snapshot[0]
            opened=admission._ReadFile(Path(path),self._limits['max_manifest_bytes'],self._budget,account_bundle=False)
            try:
                if opened.snapshot()!=self._manifest_snapshot:fail('currentness')
            finally:_reader_close(opened)
            if _TARGET(self._registry,self._request,_CONTEXT())!=self._record['stage_context']['target_binding_digest']:fail('currentness')
            self._input_current();self._release_current()
            return self._record['envelope_digest']
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):
            _close(self);fail('currentness')
        except BaseException:
            _close(self);raise

    def to_dict(self) -> dict[str,object]:
        self.require_current();return thaw(self._record)

    def _capture_execution(self):
        # Reserve actual document sizes before reading the closed resource batch.
        # Keep the separately attested code/provenance pipe separate so merging
        # buffers cannot exceed the configured temporary-memory allowance.
        paths=self._execution_paths;c=self._execution_work;native=_NATIVE(paths)
        sizes=tuple(int(row[-2]) for row in native[1::2])
        c.check_limit('array_items',len(paths),source_id='execution-currentness')
        for size in sizes:c.check_limit('raw_document_bytes',size,source_id='execution-currentness')
        c.check_limit('temporary_units',4*sum(sizes),source_id='execution-currentness')
        bodies=_OWNED(paths,maximum_sizes=sizes)
        if _NATIVE(paths)!=native:fail('currentness')
        return bodies,native

    def require_execution_current(self,*,approval_binding: tuple|None=None,_reader_close: Callable=admission._copy_cleanup(admission._READ_FILE_CLOSE),_close: Callable|None=None) -> str:
        """Fresh bytes/identity/closure in one batch; no cached validity or grant."""
        try:
            _providers()
            if self._invalid or self._pid!=os.getpid() or self._thread!=threading.get_ident():fail('currentness')
            bodies,native=self._capture_execution()
            if (bodies!=self._execution_bytes or native!=self._execution_native or _ORIGIN()!=self._execution_origin):fail('currentness')
            if approval_binding is not None:
                actual=dict(zip(self._execution_paths,bodies,strict=True))
                selected=(_ORIGIN(),_NATIVE(self._execution_approval_paths),
                    tuple(hashlib.sha256(actual[p]).hexdigest() for p in self._execution_approval_paths))
                if selected!=approval_binding:fail('currentness')
            release=self._release
            if tuple(admission._PARSER_RESOURCES())!=release._backend_binding or release._provider_current()!=release._parser:fail('currentness')
            if admission._bundle_members(release._root,release._limits)!=release._members:fail('currentness')
            for snapshot in (*release._files,self._manifest_snapshot):
                opened=_READ(Path(snapshot[0]),release._limits['max_artifact_bytes'],release._budget,account_bundle=False)
                try:
                    if opened.snapshot()!=snapshot:fail('currentness')
                finally:_reader_close(opened)
            issued,expiry,freshness=release._freshness;now=time.time_ns()//10**9
            if not issued<=now<=expiry or now-issued>freshness:fail('clock_unavailable')
            if _TARGET(self._registry,self._request,self._execution_work)!=self._record['stage_context']['target_binding_digest']:fail('currentness')
            _providers();return self._record['envelope_digest']
        except BaseException:_close(self);raise

    def approval_context(self) -> PlanningApprovalContext:
        # This snapshot is private data. Admission revalidates the full owned
        # planning session before opening or using a terminal.
        _providers()
        if self._invalid or self._pid!=os.getpid() or self._thread!=threading.get_ident():fail('currentness')
        owners={r['owner_id'] for r in self._registry['roots']}
        if len(owners)!=1:fail('authority_required')
        selected=[{'ref':r['ref'],'role':r['role'],'path':r['path']} for r in self._registry['roots'] if r['ref'] in self._request['target_refs']]
        result=object.__new__(PlanningApprovalContext)
        _APPROVAL_CONTEXTS[result]=(self,freeze({'owner_id':next(iter(owners)),'targets':selected,'record':thaw(self._record)}))
        return result

    def close(self,*,_state: Callable=object.__getattribute__,_release_close: Callable=admission._copy_cleanup(_RELEASE_CLOSE)) -> None:
        state=_state(self,'__dict__');state['_invalid']=True;release=state.get('_release')
        if release is not None:_release_close(release)


_PLANNING_CLOSE=admission._copy_cleanup(PlanningSession.close)
for _name in ('__init__','require_current','require_execution_current'):
    vars(PlanningSession)[_name].__kwdefaults__['_close']=_PLANNING_CLOSE

_PLANNING_CURRENT=PlanningSession.require_current
_EXECUTION_CURRENT=PlanningSession.require_execution_current
_APPROVAL_CONTEXTS=weakref.WeakKeyDictionary()

class PlanningApprovalContext:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('approval context requires owned planning session')
    def require_current(self) -> dict[str,object]:
        if type(self) is not PlanningApprovalContext or self not in _APPROVAL_CONTEXTS:fail('currentness')
        session,record=_APPROVAL_CONTEXTS[self]
        try:
            if PlanningSession.require_current is not _PLANNING_CURRENT:fail('currentness')
            _PLANNING_CURRENT(session);return thaw(record)
        except BaseException:
            _APPROVAL_CONTEXTS.pop(self,None);raise

    def require_execution_current(self,*,approval_binding: tuple|None=None) -> dict[str,object]:
        if type(self) is not PlanningApprovalContext or self not in _APPROVAL_CONTEXTS:fail('currentness')
        session,record=_APPROVAL_CONTEXTS[self]
        try:
            if PlanningSession.require_execution_current is not _EXECUTION_CURRENT:fail('currentness')
            _EXECUTION_CURRENT(session,approval_binding=approval_binding);return thaw(record)
        except BaseException:_APPROVAL_CONTEXTS.pop(self,None);raise
