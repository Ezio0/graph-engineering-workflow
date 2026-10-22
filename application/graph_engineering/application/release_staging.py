"""Owned release plans, local grants and private stage-only execution."""
from __future__ import annotations
import hashlib
import json
import os
import threading
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from graph_engineering.adapters import release_staging as physical
from graph_engineering.application import installation_authority as _LOCAL_AUTHORITY
from graph_engineering.core.release_installation import ReleaseInstallationError,fail
from graph_engineering.core.release_staging import stage_diagnostic

_PLANS=weakref.WeakKeyDictionary()
_SESSION=physical.PlanningSession
_SESSION_INIT=vars(_SESSION)['__init__']
_SESSION_NEW=vars(_SESSION).get('__new__')
_SESSION_CURRENT=_SESSION.require_current
_SESSION_DICT=_SESSION.to_dict
_SESSION_CLOSE=_SESSION.close


@dataclass(frozen=True,slots=True)
class BundleRef:
    bundle: Path
    manifest: Path


def bootstrap_stage_diagnostic(phase: str) -> dict[str,object]:
    if phase not in ('plan','stage'):raise ValueError('unsupported stage phase')
    v={'schema_version':'1.0.0','request_id':'stage-'+phase,'status':'rejected','phase':phase,'code':'trust_rejected','checks':[],'refs':[],
        'capabilities':{'install-plan':'available','install-apply':'unavailable','stage':'unavailable','reopen-staged':'unavailable','release':'unavailable'},'next_route':'inspect-inputs'}
    # Both closed bootstrap bodies are fixed. Refusal after a provider change
    # must not execute a changed serializer/hash provider to render that refusal.
    v['diagnostic_digest']='sha256-jcs-v1:'+('213fa9cb396c84160e4566cf8bd3811925b1fc2c861c44adca97fe2a25c1f74a' if phase=='plan' else '3265bd642700d029447169495e719c4ded22db79fc1812472252241345b8c944');return v


def _diagnostic(code,phase):
    try:
        if code=='trust_rejected':return bootstrap_stage_diagnostic(phase)
        physical._providers();c=physical._CONTEXT();return stage_diagnostic(code,phase,c,max_bytes=c.profile.limits['result_bytes'])
    except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):return bootstrap_stage_diagnostic(phase)


class StagePlanEnvelope:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('plan requires owned factory')

    def require_current(self) -> str:
        if type(self) is not StagePlanEnvelope or self not in _PLANS:fail('currentness')
        owner,operation,session,pid,thread=_PLANS[self]
        try:
            current=owner()
            if (current is None or current._operation is not operation or os.getpid()!=pid or threading.get_ident()!=thread
                or physical.PlanningSession is not _SESSION or vars(_SESSION).get('require_current') is not _SESSION_CURRENT
                or vars(_SESSION).get('__init__') is not _SESSION_INIT or vars(_SESSION).get('__new__') is not _SESSION_NEW
                or vars(_SESSION).get('to_dict') is not _SESSION_DICT or vars(_SESSION).get('close') is not _SESSION_CLOSE):fail('currentness')
            return _SESSION_CURRENT(session)
        except BaseException:
            self.close();raise

    def to_dict(self) -> dict[str,object]:
        self.require_current()
        from graph_engineering.core.contracts import thaw
        return thaw(_PLANS[self][2]._record)

    def close(self) -> None:
        if type(self) is StagePlanEnvelope:
            entry=_PLANS.pop(self,None)
            if entry is not None:_SESSION_CLOSE(entry[2])

    def __copy__(self):raise TypeError('owned plan is not copyable')
    def __deepcopy__(self,memo):raise TypeError('owned plan is not copyable')
    def __del__(self):
        try:self.close()
        except (AttributeError,ValueError,RuntimeError):pass


class ReleaseInstaller:
    def __init__(self):
        self._operation=object();self._pid=os.getpid();self._thread=threading.get_ident()

    def plan(self,request: object,bundle_ref: BundleRef) -> StagePlanEnvelope|dict[str,object]:
        session=None
        try:
            self._operation=object()
            if self._pid!=os.getpid() or self._thread!=threading.get_ident():fail('currentness')
            if type(bundle_ref) is not BundleRef or not isinstance(bundle_ref.bundle,Path) or not isinstance(bundle_ref.manifest,Path):fail()
            if (physical.PlanningSession is not _SESSION or vars(_SESSION).get('require_current') is not _SESSION_CURRENT
                or vars(_SESSION).get('__init__') is not _SESSION_INIT or vars(_SESSION).get('__new__') is not _SESSION_NEW
                or vars(_SESSION).get('to_dict') is not _SESSION_DICT or vars(_SESSION).get('close') is not _SESSION_CLOSE):fail('currentness')
            session=_SESSION(request,bundle_ref.bundle,bundle_ref.manifest);result=object.__new__(StagePlanEnvelope)
            _PLANS[result]=(weakref.ref(self),self._operation,session,self._pid,self._thread);return result
        except ReleaseInstallationError as e:
            if session is not None:_SESSION_CLOSE(session)
            return _diagnostic(e.code,'plan')
        except (OSError,ValueError,TypeError,RuntimeError,KeyError,AttributeError):
            if session is not None:_SESSION_CLOSE(session)
            return bootstrap_stage_diagnostic('plan')

    def stage(self,envelope: object,authority: object=None) -> dict[str,object]:return _diagnostic('phase_unavailable','stage')
    def reopen_staged(self,envelope: object,authority: object=None) -> dict[str,object]:return _diagnostic('phase_unavailable','stage')

    def authorize_local(self,envelope: StagePlanEnvelope) -> _LOCAL_AUTHORITY.InstallationAuthority|dict[str,object]:return _LOCAL_AUTHORIZE(self,envelope)
    def _consume_for_stage(self,envelope: StagePlanEnvelope,authority: object):return _LOCAL_CONSUME(self,envelope,authority)


def _exit_code(value):
    return 2 if value['code']=='input_invalid' else (3 if value['status']=='blocked' else 4)


def install_plan(operation: str,request_path: Path,bundle_ref: BundleRef,*,_reader_close: Callable=physical.admission._copy_cleanup(physical.admission._READ_FILE_CLOSE),_plan_close: Callable|None=None) -> tuple[dict[str,object],int]:
    result=None
    try:
        physical._providers();c=physical._CONTEXT()
        inputs=physical._ADMISSION_OPEN.__get__(None,physical._ADMISSION_INPUTS)()
        limits=physical._ADMISSION_LIMITS.__get__(inputs,physical._ADMISSION_INPUTS)
        physical._providers()
        budget=physical.admission._Budget(limits)
        opened=physical.admission._ReadFile(request_path,limits['max_manifest_bytes'],budget)
        try:
            from graph_engineering.core.contracts import parse_json
            request=parse_json(opened.raw,context=c,source_id='stage-request')
            if type(request) is not dict or request.get('operation')!=operation:fail()
            owner=ReleaseInstaller();result=owner.plan(request,bundle_ref)
            opened.recheck(budget)
            if type(result) is StagePlanEnvelope:return result.to_dict(),0
            return result,_exit_code(result)
        finally:_reader_close(opened)
    except ReleaseInstallationError as e:
        v=_diagnostic(e.code,'plan');return v,_exit_code(v)
    except (FileNotFoundError,ValueError,TypeError):
        v=_diagnostic('input_invalid','plan');return v,2
    except (OSError,RuntimeError,KeyError,AttributeError):return bootstrap_stage_diagnostic('plan'),4
    finally:
        if type(result) is StagePlanEnvelope:_plan_close(result)


def install_apply_unavailable() -> tuple[dict[str,object],int]:
    value=_diagnostic('phase_unavailable','stage');return value,_exit_code(value)

def install_apply(plan_path: Path,bundle_ref: BundleRef,*,_cleanup: Callable|None=None) -> tuple[dict[str,object],int]:
    """Reacquire and compare the full plan before the genuine local decision."""
    result=None;plan=None;opened=None;grant=None
    try:
        physical._providers();inputs=physical.InstalledStageInputs.open_owned();docs=inputs.documents()
        if not any(r['generated_files'] for r in docs['config/release-installation/installer-policy-v1.json']['recipes']):return install_apply_unavailable()
        c=physical._CONTEXT();limits=physical._ADMISSION_OPEN.__get__(None,physical._ADMISSION_INPUTS)().limits
        opened=physical.admission._ReadFile(plan_path,limits['max_manifest_bytes'],physical.admission._Budget(limits))
        from graph_engineering.core.contracts import parse_json
        from graph_engineering.core.release_staging import validate_envelope
        supplied=validate_envelope(parse_json(opened.raw,context=c,source_id='stage-apply-plan'),c)
        fields=('schema_version','request_id','operation','installation_id','release_manifest_digest','prior_tuple_digest','target_refs','preserve_data')
        request={k:supplied['plan'][k] for k in fields}
        owner=ReleaseInstaller();plan=owner.plan(request,bundle_ref)
        if type(plan) is not StagePlanEnvelope:return plan,_exit_code(plan)
        if plan.to_dict()!=supplied:fail('currentness')
        opened.recheck(physical.admission._Budget(limits));grant=owner.authorize_local(plan)
        if type(grant) is dict:
            value=_EXECUTION.contracts.diagnostic(grant['code'],supplied['plan']['request_id'],physical._CONTEXT());return value,_exit_code(value)
        opened.recheck(physical.admission._Budget(limits));result=owner.stage(plan,grant)
        if type(result) is _EXECUTION.StagedReleaseObservation:return result.diagnostic(),0
        return result,_exit_code(result)
    except ReleaseInstallationError as e:
        value=_EXECUTION.contracts.diagnostic(e.code,'stage-execution',physical._CONTEXT());return value,_exit_code(value)
    except (FileNotFoundError,TypeError,ValueError):
        value=_diagnostic('input_invalid','stage');return value,2
    except (OSError,RuntimeError,KeyError,AttributeError):return bootstrap_stage_diagnostic('stage'),4
    finally:
        _cleanup(result,plan,opened,grant)


from graph_engineering.application import installation_authority as _LOCAL_AUTHORITY
_LOCAL_AUTHORIZE=_LOCAL_AUTHORITY.authorize
_LOCAL_CONSUME=_LOCAL_AUTHORITY.consume
def _local_bridges():
    capture=_LOCAL_AUTHORITY.physical._copy_cleanup
    # Planning bindings finalize below; captured bridge code validates those
    # live bindings through its private original guard before consuming them.
    authorize=capture(_LOCAL_AUTHORIZE,freeze_globals=False);consume=capture(_LOCAL_CONSUME,freeze_globals=False)
    guard=capture(_LOCAL_AUTHORITY._GUARD);seal=_LOCAL_AUTHORITY._SEAL;diagnostic=capture(_LOCAL_AUTHORITY._diagnostic)
    def authorize_local(self,envelope: StagePlanEnvelope) -> _LOCAL_AUTHORITY.InstallationAuthority|dict[str,object]:
        try:guard(seal)
        except (ValueError,TypeError):return diagnostic('trust_rejected')
        return authorize(self,envelope)
    def consume_for_stage(self,envelope: StagePlanEnvelope,authority: object) -> _LOCAL_AUTHORITY.StagePermit:
        # The original consumer performs rejection cleanup even for a changed bridge alias.
        return consume(self,envelope,authority)
    return capture(authorize_local),capture(consume_for_stage)

ReleaseInstaller.authorize_local,ReleaseInstaller._consume_for_stage=_local_bridges()
from graph_engineering.application import staging_execution as _EXECUTION
_EXECUTION.configure(__import__(__name__,fromlist=['ReleaseInstaller']))
def _retire_cli(result,plan,opened,grant,*,_obs_type=_EXECUTION.StagedReleaseObservation,_plan_type=StagePlanEnvelope,
    _obs_close=_EXECUTION._CAPTURE(_EXECUTION.StagedReleaseObservation.close),_plan_close=_EXECUTION._PLAN_CLOSE,
    _reader_close=physical.admission._copy_cleanup(physical.admission._READ_FILE_CLOSE),_grant_close=_EXECUTION._GRANT_CLOSE,
    _cleanup=_EXECUTION._RETIRE_RESOURCES):
    resources=[]
    if type(result) is _obs_type:resources.append((_obs_close,result))
    if type(plan) is _plan_type:resources.append((_plan_close,plan))
    if opened is not None:resources.append((_reader_close,opened))
    if grant is not None:resources.append((_grant_close,grant))
    _cleanup(resources)

install_plan.__kwdefaults__['_plan_close']=_EXECUTION._PLAN_CLOSE
install_apply.__kwdefaults__['_cleanup']=physical.admission._copy_cleanup(_retire_cli)

def _guarded_plan():
    capture=_LOCAL_AUTHORITY.physical._copy_cleanup
    guard=capture(_LOCAL_AUTHORITY._GUARD);seal=_LOCAL_AUTHORITY._SEAL
    original=capture(ReleaseInstaller.plan,freeze_globals=False);fallback=capture(bootstrap_stage_diagnostic)
    def plan(self,request: object,bundle_ref: BundleRef) -> StagePlanEnvelope|dict[str,object]:
        try:guard(seal)
        except (ValueError,TypeError):return fallback('plan')
        return original(self,request,bundle_ref)
    return capture(plan)
ReleaseInstaller.plan=_guarded_plan()
def _guarded_apply():
    capture=_LOCAL_AUTHORITY.physical._copy_cleanup
    guard=capture(_LOCAL_AUTHORITY._GUARD);seal=_LOCAL_AUTHORITY._SEAL
    original=capture(install_apply,freeze_globals=False);fallback=capture(bootstrap_stage_diagnostic)
    def apply(plan_path: Path,bundle_ref: BundleRef) -> tuple[dict[str,object],int]:
        try:guard(seal)
        except (ValueError,TypeError):return fallback('stage'),4
        return original(plan_path,bundle_ref)
    return capture(apply)
install_apply=_guarded_apply()
_LOCAL_AUTHORITY.bind_planning(__import__(__name__,fromlist=['ReleaseInstaller']))
_EXECUTION.bind_providers(__import__(__name__,fromlist=['ReleaseInstaller']))
