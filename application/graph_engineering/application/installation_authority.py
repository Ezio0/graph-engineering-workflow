"""Owned local installation grants; consumption never executes a target action."""
from __future__ import annotations
import os
import threading
import weakref
from typing import Callable
from types import ModuleType
from graph_engineering.adapters import installation_authority as physical
from graph_engineering.core import installation_authority as contracts
from graph_engineering.core.release_installation import ReleaseInstallationError,fail

_GRANTS={};_PERMITS={};_ACTIVE={};_RETIRED=weakref.WeakKeyDictionary()
_PLANNING=None;_SEAL=physical.ProviderSeal();_GUARD=physical.ProviderSeal.require_current
_RECORD_OP=physical._RECORD_OP
_APPROVE=physical.approve;_SESSION=physical.ApprovalSession;_CURRENT=_SESSION.require_current;_FACTS_CURRENT=_SESSION.require_facts_current;_CLOSE=_SESSION.close
_EXECUTION_CURRENT=_SESSION.require_execution_current

def _close(handle,table,*,_close_session=physical._copy_cleanup(_CLOSE),_active=_ACTIVE):
    row=table.get(id(handle))
    if row is None or row['handle']() is not handle:return
    table.pop(id(handle))
    if row is not None:
        _close_session(row['session']);owner=row['owner']()
        active=None if owner is None else _active.get(id(owner))
        if active is not None and active[1]() is handle:_active.pop(id(owner),None)

def _plan_binding(owner,envelope):
    if type(owner) is not _OWNER or type(envelope) is not _PLAN:fail('input_invalid')
    row=_PLANS.get(envelope)
    if (row is None or row[0]() is not owner or row[1] is not owner._operation
        or row[3]!=os.getpid() or row[4]!=threading.get_ident()
        or owner._pid!=os.getpid() or owner._thread!=threading.get_ident()):fail('currentness')
    return row

def _current(handle,table,*,_guard=physical._copy_cleanup(_GUARD),_seal=_SEAL,_cleanup=physical._copy_cleanup(_close)):
    try:
        _guard(_seal)
        with _RECORD_OP():
            want=InstallationAuthority if table is _GRANTS else StagePermit
            if type(handle) is not want:fail('currentness')
            row=table.get(id(handle))
            if row is None or row['handle']() is not handle:fail('currentness')
            owner=row['owner']();plan=row['plan']()
            if (owner is None or plan is None or owner._operation is not row['operation']
                 or row['pid']!=os.getpid() or row['thread']!=threading.get_ident()):fail('currentness')
            _plan_binding(owner,plan);_CURRENT(row['session']);return row['session'].challenge['challenge_digest']
    except BaseException:_cleanup(handle,table);raise

class InstallationAuthority:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('installation authority requires local decision')
    def diagnostic(self) -> dict[str,object]:
        _PUBLIC_CURRENT(self);session=_GRANTS[id(self)]['session']
        return contracts.diagnostic('authority_issued',session.work,request_id=session.challenge['request_id'],maximum=session.policy['max_prompt_bytes'])
    def __copy__(self):raise TypeError('authority is not copyable')
    def __deepcopy__(self,memo):raise TypeError('authority is not copyable')
    def __reduce__(self):raise TypeError('authority is not serializable')

class StagePermit:
    __slots__=('__weakref__',)
    def __init__(self):raise TypeError('stage permit requires owned consumption')
    def __copy__(self):raise TypeError('permit is not copyable')
    def __deepcopy__(self,memo):raise TypeError('permit is not copyable')
    def __reduce__(self):raise TypeError('permit is not serializable')


def _handle_methods(table):
    validate=_current;cleanup=physical._copy_cleanup(_close);guard=physical._copy_cleanup(_GUARD);seal=_SEAL
    def current(self) -> str:
        try:guard(seal);return validate(self,table)
        except BaseException:cleanup(self,table);raise
    def close(self) -> None:cleanup(self,table)
    def destroy(self) -> None:
        try:cleanup(self,table)
        except (AttributeError,TypeError,ValueError):pass
    return current,close,destroy

InstallationAuthority.require_current,InstallationAuthority.close,InstallationAuthority.__del__=_handle_methods(_GRANTS)
StagePermit.require_current,StagePermit.close,StagePermit.__del__=_handle_methods(_PERMITS)
_PUBLIC_CURRENT=InstallationAuthority.require_current

def authorize(owner: object,envelope: object,*,_guard: Callable=physical._copy_cleanup(_GUARD),_seal: physical.ProviderSeal=_SEAL,_close_session: Callable=physical._copy_cleanup(_CLOSE)) -> InstallationAuthority|dict[str,object]:
    session=None
    try:
        _guard(_seal)
        with _RECORD_OP():
            row=_plan_binding(owner,envelope)
            if _RETIRED.get(owner) is owner._operation:fail('currentness')
            active=_ACTIVE.get(id(owner))
            if active is not None:
                retained=active[1]()
                if retained is not None:
                    if active[0]=='permit':fail('currentness')
                    _close(retained,_GRANTS)
                else:_ACTIVE.pop(id(owner),None)
            context=_APPROVAL_CONTEXT(row[2])
        session=_APPROVE(context);_guard(_seal)
        # The producer just completed fresh full input validation. Check live
        # ownership/terminal/deadline again before returning the opaque handle.
        _plan_binding(owner,envelope);_FACTS_CURRENT(session)
        handle=object.__new__(InstallationAuthority)
        _GRANTS[id(handle)]={'handle':weakref.ref(handle),'owner':weakref.ref(owner),'plan':weakref.ref(envelope),'operation':owner._operation,'session':session,'pid':os.getpid(),'thread':threading.get_ident()}
        _ACTIVE[id(owner)]=('grant',weakref.ref(handle));return handle
    except ReleaseInstallationError as e:
        if session is not None:_close_session(session)
        return _diagnostic(e.code)
    except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):
        if session is not None:_close_session(session)
        return _diagnostic('authority_required')
    except BaseException:
        if session is not None:_close_session(session)
        raise

def consume(owner: object,envelope: object,authority: object,*,_guard: Callable=physical._copy_cleanup(_GUARD),_seal: physical.ProviderSeal=_SEAL,_cleanup: Callable=physical._copy_cleanup(_close),_close_session: Callable=physical._copy_cleanup(_CLOSE)) -> StagePermit:
    row=None;permit=None
    try:
        _guard(_seal)
        if type(owner) is not _OWNER or type(envelope) is not _PLAN or type(authority) is not InstallationAuthority:fail('currentness')
        _PUBLIC_CURRENT(authority);row=_GRANTS[id(authority)]
        if row['owner']() is not owner or row['plan']() is not envelope or row['operation'] is not owner._operation:fail('currentness')
        _GRANTS.pop(id(authority));_ACTIVE.pop(id(owner),None);_RETIRED[owner]=owner._operation
        permit=object.__new__(StagePermit);row['handle']=weakref.ref(permit)
        _PERMITS[id(permit)]=row;_ACTIVE[id(owner)]=('permit',weakref.ref(permit));return permit
    except BaseException:
        _cleanup(authority,_GRANTS)
        if row is not None:_close_session(row['session'])
        if permit is not None:_cleanup(permit,_PERMITS)
        raise

def execution_facts(permit: object,*,full: bool=True,_guard: Callable=physical._copy_cleanup(_GUARD),_seal: physical.ProviderSeal=_SEAL,_cleanup: Callable=physical._copy_cleanup(_close)) -> dict[str,object]:
    """Original consumed-grant provenance; private facts never renew its deadline."""
    if type(full) is not bool or type(permit) is not StagePermit:fail('authority_required')
    if full:challenge=StagePermit.require_current(permit)
    else:
        try:
            _guard(_seal);row=_PERMITS.get(id(permit))
            if row is None or row['handle']() is not permit or row['pid']!=os.getpid() or row['thread']!=threading.get_ident():fail('currentness')
            owner=row['owner']();plan=row['plan']()
            if owner is None or plan is None or owner._operation is not row['operation']:fail('currentness')
            _plan_binding(owner,plan);_EXECUTION_CURRENT(row['session']);challenge=row['session'].challenge['challenge_digest']
        except BaseException:_cleanup(permit,_PERMITS);raise
    row=_PERMITS[id(permit)]
    owner=row['owner']();plan=row['plan']();binding=_plan_binding(owner,plan)
    session=row['session'];facts=session.challenge
    record=binding[2]._record
    if (facts['challenge_digest']!=challenge or facts['operation']!=record['plan']['operation']
        or facts['request_id']!=record['plan']['request_id'] or facts['installation_id']!=record['plan']['installation_id']
        or facts['plan_digest']!=record['plan']['plan_digest'] or facts['context_digest']!=record['stage_context']['context_digest']
        or facts['envelope_digest']!=record['envelope_digest']):fail('currentness')
    return {'challenge_digest':challenge,'deadline_ns':session.deadline,'planning_session':binding[2]}

def _bootstrap():
    return {'schema_version': '1.0.0', 'request_id': 'local-approval', 'phase': 'authorization', 'status': 'rejected', 'code': 'trust_rejected', 'refs': [], 'capabilities': {'local-authority': 'unavailable', 'runtime-authority': 'unavailable', 'install-apply': 'unavailable', 'stage': 'unavailable', 'reopen-staged': 'unavailable', 'release': 'unavailable'}, 'next_route': 'fresh-owner-decision', 'diagnostic_digest': 'sha256-jcs-v1:e685efd1136cf342e28555092ac06670a345b3db4629a909543569c13d81c34e'}

def _diagnostic(code,*,_guard=physical._copy_cleanup(_GUARD),_seal=_SEAL,_physical_guard=physical._copy_cleanup(physical._GUARD),_physical_seal=physical._SEAL,_fallback=physical._copy_cleanup(_bootstrap)):
    try:
        _guard(_seal);_physical_guard(_physical_seal);return _DIAGNOSTIC(code,_CONTEXT())
    except (ValueError,TypeError,OSError,RuntimeError,KeyError,AttributeError):return _fallback()

_DIAGNOSTIC=contracts.diagnostic;_CONTEXT=physical._CONTEXT

def bind_planning(planning: ModuleType) -> None:
    global _PLANNING,_OWNER,_PLAN,_PLANS,_PLAN_CURRENT,_APPROVAL_CONTEXT
    if _PLANNING is not None:raise RuntimeError('local authority already bound')
    _PLANNING=planning;_OWNER=planning.ReleaseInstaller;_PLAN=planning.StagePlanEnvelope
    _PLANS=planning._PLANS;_PLAN_CURRENT=planning._SESSION_CURRENT
    # Validate the public plan owner first; then use its original method for live binding.
    _PLAN_CURRENT=planning.StagePlanEnvelope.require_current
    _APPROVAL_CONTEXT=physical.planning.PlanningSession.approval_context
    physical.bind_providers()
    import sys
    _SEAL.freeze((sys.modules[__name__],planning),(InstallationAuthority,StagePermit,_OWNER,_PLAN,physical.ProviderSeal))
