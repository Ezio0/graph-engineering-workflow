"""Owned isolated-stage sequencing and read-only observation lifetime."""
from __future__ import annotations
import os
import threading
import weakref
from types import ModuleType
from typing import Callable
from graph_engineering.adapters import staging_execution as physical
from graph_engineering.application import installation_authority as local
from graph_engineering.core import staging_execution as contracts
from graph_engineering.core.contracts import thaw,freeze
from graph_engineering.core.release_installation import ReleaseInstallationError,fail

_OBSERVATIONS=weakref.WeakKeyDictionary()
_PID=os.getpid;_THREAD=threading.get_ident
_CAPTURE=local.physical._copy_cleanup
_GUARD=_CAPTURE(physical._GUARD);_SEAL=physical._SEAL
_PERMIT_CLOSE=_CAPTURE(local.StagePermit.close)
_GRANT_CLOSE=_CAPTURE(local.InstallationAuthority.close)
_SESSION_CLOSE=_CAPTURE(physical.StageSession.close)
_SESSION_VERIFY=physical.StageSession.verify
_SESSION=physical.StageSession
_SESSION_INIT=_CAPTURE(physical.StageSession.__init__,freeze_globals=False)
_RECORD_OP=local._RECORD_OP

def _retire_observation(self,*,_rows=_OBSERVATIONS,_state=object.__getattribute__,_call=weakref.ReferenceType.__call__):
    # Inspect the original weak table by identity. Rejection cleanup must not
    # invoke a substituted observation hash, class descriptor or table alias.
    state=_state(_rows,'__dict__');data=state['data']
    for key,row in tuple(data.items()):
        if _call(key) is self:
            state['_dirty_len']=True;data.pop(key,None);return row
    return None

_RETIRE=_CAPTURE(_retire_observation)

def _retire_resources(resources):
    failure=None
    for cleanup,resource in resources:
        try:cleanup(resource)
        except BaseException as error:
            if failure is None:failure=error
    if failure is not None:raise failure

_RETIRE_RESOURCES=_CAPTURE(_retire_resources)

class StagedReleaseObservation:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('staged observation requires owned factory')
    def require_current(self,*,_guard: Callable=_GUARD,_seal: object=_SEAL,_close: Callable=_SESSION_CLOSE,_retire: Callable=_RETIRE,_plan_close: Callable|None=None,_cleanup: Callable=_RETIRE_RESOURCES) -> str:
        try:
            _guard(_seal)
            if type(self) is not StagedReleaseObservation:fail('currentness')
            row=_OBSERVATIONS.get(self)
            if row is None:fail('currentness')
            owner,operation,plan,session,pid,thread=row;owner=owner()
            if owner is None or owner._operation is not operation or pid!=_PID() or thread!=_THREAD():fail('currentness')
            with _RECORD_OP():
                _PLAN_CURRENT(plan);return _SESSION_VERIFY(session)
        except BaseException:
            row=_retire(self)
            if row is not None:_cleanup(((_close,row[3]),(_plan_close,row[2])))
            raise
    def to_dict(self) -> dict[str,object]:
        _OBS_CURRENT(self);return thaw(freeze(_OBSERVATIONS[self][3].result['installed-release-manifest']))
    def diagnostic(self) -> dict[str,object]:
        _OBS_CURRENT(self);session=_OBSERVATIONS[self][3]
        return contracts.diagnostic('staged',session.plan['request_id'],physical._CONTEXT())
    def close(self,*,_close: Callable=_SESSION_CLOSE,_retire: Callable=_RETIRE) -> None:
        row=_retire(self)
        if row is not None:_close(row[3])
    def __copy__(self):raise TypeError('staged observation is not copyable')
    def __deepcopy__(self,memo):raise TypeError('staged observation is not copyable')
    def __reduce__(self):raise TypeError('staged observation is not serializable')
    def __del__(self,*,_close=_SESSION_CLOSE,_retire=_RETIRE):
        try:
            row=_retire(self)
            if row is not None:_close(row[3])
        except (AttributeError,ValueError,TypeError,OSError):pass

_OBS_CURRENT=_CAPTURE(StagedReleaseObservation.require_current,freeze_globals=False)

def _recovery_refusal():
    # Fixed owned body: reporting an unconfirmed child must not consume changed
    # serializers or hide the recovery state behind a generic trust refusal.
    return {'schema_version':'1.0.0','request_id':'stage-execution','status':'blocked','phase':'stage','code':'recovery_blocked','checks':[],'refs':[],
        'capabilities':{'install-plan':'available','install-apply':'stage-only','stage':'available','reopen-staged':'local-authority-only','release':'unavailable'},
        'next_route':'fresh-owner-decision','diagnostic_digest':'sha256-jcs-v1:30369fde9a54b1846f0346093a95adc74523afbbc99e58059b5947d3624ca393'}

def _perform(owner,envelope,authority,*,reopen=False,_guard=_GUARD,_seal=_SEAL,_close=_SESSION_CLOSE,_permit_close=_PERMIT_CLOSE,_grant_close=_GRANT_CLOSE,_blocked=_CAPTURE(_recovery_refusal),_state=object.__getattribute__,_plan_close=None,_cleanup=_RETIRE_RESOURCES):
    session=None;permit=None;keep=False;provider_valid=False;eligible=False
    try:
        _guard(_seal);provider_valid=True
        with _RECORD_OP():
            inputs=physical.planning.InstalledStageInputs.open_owned();documents=inputs.documents()
            if not any(r['generated_files'] for r in documents['config/release-installation/installer-policy-v1.json']['recipes']):return _OLD_DIAGNOSTIC('phase_unavailable','stage')
            eligible=True
            if type(owner) is not _OWNER or type(envelope) is not _PLAN or type(authority) is not local.InstallationAuthority:fail('authority_required')
            _PLAN_CURRENT(envelope);row=_PLANS.get(envelope)
            if row is None or row[0]() is not owner or row[1] is not owner._operation:fail('currentness')
            permit=_CONSUME(owner,envelope,authority)
            session=object.__new__(_SESSION);_SESSION_INIT(session,row[2],permit)
            if reopen:session.reopen()
            else:session.acquire();session.execute();session.persist()
            # No mutation authority survives acceptance or can be reconstructed
            # from the read-only result or its private provenance records.
            session.release_permit();_permit_close(permit);permit=None
            result=object.__new__(StagedReleaseObservation)
            _OBSERVATIONS[result]=(weakref.ref(owner),owner._operation,envelope,session,_PID(),_THREAD())
            keep=True;return result
    except ReleaseInstallationError as e:
        try:_guard(_seal);return contracts.diagnostic(e.code,'stage-execution',physical._CONTEXT())
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):
            provider_valid=False
            if _state(e,'__dict__').get('code')=='recovery_blocked':return _blocked()
            return _FALLBACK('stage')
    except OSError:
        if session is not None and session.created:
            try:_guard(_seal);return contracts.diagnostic('recovery_blocked','stage-execution',physical._CONTEXT())
            except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):pass
        try:_guard(_seal)
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):provider_valid=False
        return _FALLBACK('stage')
    except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):
        try:_guard(_seal)
        except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):provider_valid=False
        return _FALLBACK('stage')
    finally:
        resources=[]
        if authority is not None and (eligible or not provider_valid):resources.append((_grant_close,authority))
        if permit is not None:resources.append((_permit_close,permit))
        if session is not None and not keep:resources.append((_close,session))
        if not provider_valid:resources.append((_plan_close,envelope))
        _cleanup(resources)

def configure(planning: ModuleType) -> None:
    global _OWNER,_PLAN,_PLANS,_PLAN_CURRENT,_CONSUME,_FALLBACK,_OLD_DIAGNOSTIC,_PLAN_CLOSE
    _OWNER=planning.ReleaseInstaller;_PLAN=planning.StagePlanEnvelope;_PLANS=planning._PLANS
    _PLAN_CURRENT=planning.StagePlanEnvelope.require_current;_CONSUME=planning.ReleaseInstaller._consume_for_stage
    _FALLBACK=_CAPTURE(planning.bootstrap_stage_diagnostic)
    _OLD_DIAGNOSTIC=_CAPTURE(planning._diagnostic,freeze_globals=False)
    release_close=_CAPTURE(physical.planning._RELEASE_CLOSE)
    planning_close=_CAPTURE(physical.planning.PlanningSession.close)
    planning_close.__globals__['_RELEASE_CLOSE']=release_close
    _PLAN_CLOSE=_CAPTURE(planning.StagePlanEnvelope.close)
    _PLAN_CLOSE.__globals__['_SESSION_CLOSE']=planning_close
    StagedReleaseObservation.require_current.__kwdefaults__['_plan_close']=_PLAN_CLOSE
    _OBS_CURRENT.__kwdefaults__['_plan_close']=_PLAN_CLOSE
    _perform.__kwdefaults__['_plan_close']=_PLAN_CLOSE
    physical.configure(local)
    perform=_CAPTURE(_perform,freeze_globals=False)
    def stage(self,envelope: object,authority: object=None) -> StagedReleaseObservation|dict[str,object]:return perform(self,envelope,authority)
    def reopen(self,envelope: object,authority: object=None) -> StagedReleaseObservation|dict[str,object]:return perform(self,envelope,authority,reopen=True)
    planning.ReleaseInstaller.stage=_CAPTURE(stage);planning.ReleaseInstaller.reopen_staged=_CAPTURE(reopen)

def bind_providers(planning: ModuleType) -> None:
    import sys
    physical.bind_providers((sys.modules[__name__],planning,local),(StagedReleaseObservation,_OWNER,_PLAN,local.StagePermit,local.InstallationAuthority))
