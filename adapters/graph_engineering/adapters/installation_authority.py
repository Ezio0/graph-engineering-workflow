"""Owned foreground-terminal approval; no installer, caller decision or state writes."""
from __future__ import annotations
import hashlib
import os
import select
import stat
import termios
import threading
import time
import types
import dis
import sys
from typing import Callable
import graph_engineering as installation
from graph_engineering.adapters import release_staging as planning
from graph_engineering.core import installation_authority as contracts
from graph_engineering.core.contracts import parse_json
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.release_installation import fail
from graph_engineering.core.release_staging import stage_digest

_RESOURCES=('config/contracts/installation-approval-schema-registry-v1.json',
 'config/contracts/schemas/installation-approval-challenge-1.0.0.json',
 'config/contracts/schemas/installation-approval-diagnostic-1.0.0.json',
 'config/contracts/schemas/installation-approval-policy-1.0.0.json',
 'config/release-installation/installation-approval-policy-v1.json')
_IDENTITY_ERROR=installation.DistributionIdentityError
_OWNED=installation._installation_owned_resources
_RECORD_OP=installation._record_capture_operation
_CONTEXT=planning._CONTEXT;_NATIVE=planning._NATIVE;_ORIGIN=planning._ORIGIN
_CONTEXT_TYPE=planning.PlanningApprovalContext
_CONTEXT_CURRENT=_CONTEXT_TYPE.require_current
_CLOSE=os.close;_READ=os.read;_WRITE=os.write;_OPEN=os.open;_FSTAT=os.fstat
_POLL=select.select;_CLOCK=time.monotonic_ns;_RANDOM=os.urandom
_ATTR=termios.tcgetattr;_PID=os.getpid;_THREAD=threading.get_ident
_UID=os.getuid;_EUID=os.geteuid;_PGRP=os.getpgrp;_SID=os.getsid;_FG=os.tcgetpgrp
_ABSENT=object()

def _copy_cleanup(function: types.FunctionType,*,freeze_globals: bool=True) -> types.FunctionType:
    """Capture owned code; guards/cleanup also snapshot effective bindings."""
    namespace=dict(function.__globals__) if freeze_globals else function.__globals__
    if freeze_globals:
        builtins=namespace.get('__builtins__',{})
        namespace['__builtins__']=dict(vars(builtins) if type(builtins) is types.ModuleType else builtins)
    result=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
    result.__kwdefaults__=dict(function.__kwdefaults__ or {})
    return result

class ProviderChanged(ValueError):
    """A sealed provider changed before use."""

class ProviderSeal:
    """Bind functions, their effective globals and original class descriptors."""
    def __init__(self):self._records=None
    def freeze(self,modules: tuple[types.ModuleType,...],classes: tuple[type,...]=(),*,_vars: Callable=vars,_type: type=type) -> None:
        if self._records is not None:raise RuntimeError('provider seal already frozen')
        attrs=[];functions=[];class_names=[];pending_classes=list(classes)
        seen_classes=set();seen_members=set()
        def dependency(value: object) -> None:
            if _type(value) is types.FunctionType:functions.append(value)
            elif isinstance(value,type) and value.__module__!='builtins':pending_classes.append(value)
            elif _type(value).__module__ not in ('builtins','types'):pending_classes.append(_type(value))
        def members(module: types.ModuleType,names: set[str]) -> None:
            mapping=_vars(module)
            for name in names:
                if name not in mapping or (id(module),name) in seen_members:continue
                seen_members.add((id(module),name));value=mapping[name]
                attrs.append((mapping,name,value));dependency(value)
        for module in modules:
            for name,value in tuple(_vars(module).items()):
                if _type(value) is types.FunctionType:
                    attrs.append((_vars(module),name,value));functions.append(value)
        for module,names in ((os,('open','close','read','write','fstat','lstat','isatty','getuid','geteuid','getpid','getpgrp','getsid','tcgetpgrp','urandom','O_RDONLY','O_RDWR','O_DIRECTORY','O_NOFOLLOW','O_NOCTTY','O_CLOEXEC','O_NONBLOCK')),
             (select,('select',)),(time,('monotonic_ns',)),(stat,('S_ISCHR',)),(termios,('tcgetattr','ICANON','ECHO')),(threading,('get_ident',)),(hashlib,('sha256',))):
            attrs.extend((_vars(module),n,_vars(module).get(n)) for n in names)
        facts=[];seen=set()
        while functions or pending_classes:
            while pending_classes:
                cls=pending_classes.pop()
                if id(cls) in seen_classes:continue
                seen_classes.add(id(cls));mapping=_vars(cls)
                class_names.append((mapping,tuple(mapping)))
                attrs.extend((mapping,name,value) for name,value in mapping.items())
                for base in cls.__bases__:dependency(base)
                for value in mapping.values():
                    if _type(value) in (classmethod,staticmethod):dependency(value.__func__)
                    elif _type(value) is property:
                        for fn in (value.fget,value.fset,value.fdel):dependency(fn)
                    else:dependency(value)
            if not functions:continue
            fn=functions.pop()
            if id(fn) in seen or _type(fn) is not types.FunctionType:continue
            seen.add(id(fn));g=fn.__globals__;b=g.get('__builtins__',{})
            if _type(b) is types.ModuleType:b=_vars(b)
            names=set();codes=[fn.__code__];imports=[]
            while codes:
                code=codes.pop();names.update(code.co_names)
                codes.extend(c for c in code.co_consts if _type(c) is types.CodeType)
                imports.extend(i.argval for i in dis.get_instructions(code) if i.opname=='IMPORT_NAME')
            # Local imports have no effective global binding. Resolve only
            # already loaded modules; binding must never execute an import.
            for name in imports:
                module=sys.modules.get(name)
                if _type(module) is types.ModuleType:
                    attrs.append((sys.modules,name,module));members(module,names)
            dependencies=[]
            for name in names:
                if name in g:
                    value=g[name]
                    # This library observation cache is populated by a normal
                    # platform read. All other effective bindings, including
                    # library constants and encoder objects, remain exact.
                    if not (fn.__module__=='platform' and name=='_uname_cache'):
                        dependencies.append((g,name,value))
                    dependency(value)
                    if _type(value) is types.ModuleType:members(value,names)
                elif name in b:
                    dependencies.append((g,name,_ABSENT));dependencies.append((b,name,b[name]))
            cells=tuple((cell,cell.cell_contents) for cell in (fn.__closure__ or ()))
            for value in (*(fn.__defaults__ or ()),*(fn.__kwdefaults__ or {}).values(),*(value for cell,value in cells)):
                dependency(value)
            facts.append((fn,fn.__code__,fn.__defaults__,fn.__kwdefaults__,tuple((fn.__kwdefaults__ or {}).items()),cells,tuple(dependencies)))
        self._records=(tuple(attrs),tuple(facts),tuple(class_names))
    def require_current(self,*,_type: type=type,_missing: object=_ABSENT,_error: type[ValueError]=ValueError,_id: Callable=id,_state: Callable=object.__getattribute__) -> None:
        records=_state(self,'__dict__')['_records']
        if records is None:raise _error('unbound providers')
        attrs,facts,class_names=records
        for mapping,names in class_names:
            if len(mapping)!=len(names):raise _error('changed class namespace')
            for key in mapping:
                if _type(key) is not str:raise _error('invalid class namespace')
            for name in names:
                if name not in mapping:raise _error('changed class namespace')
        namespaces={}
        for mapping,name,value in attrs:
            if _id(mapping) not in namespaces:
                for key in mapping:
                    if _type(key) is not str:raise _error('invalid provider namespace')
                namespaces[_id(mapping)]=True
            if mapping.get(name,_missing) is not value:raise _error('changed provider')
        for fn,code,defaults,kwdefaults,kwitems,cells,deps in facts:
            if fn.__code__ is not code or fn.__defaults__ is not defaults or fn.__kwdefaults__ is not kwdefaults:raise _error('changed function')
            if kwdefaults is not None:
                if len(kwdefaults)!=len(kwitems):raise _error('changed keyword defaults')
                for key in kwdefaults:
                    if _type(key) is not str:raise _error('invalid keyword defaults')
                for key,value in kwitems:
                    if kwdefaults.get(key,_missing) is not value:raise _error('changed keyword default')
            for cell,value in cells:
                if cell.cell_contents is not value:raise _error('changed closure')
            for mapping,name,value in deps:
                if _id(mapping) not in namespaces:
                    for key in mapping:
                        if _type(key) is not str:raise _error('invalid effective namespace')
                    namespaces[_id(mapping)]=True
                if mapping.get(name,_missing) is not value:raise _error('changed effective binding')

_SEAL=ProviderSeal()
_GUARD=ProviderSeal.require_current

def _capture(*,_guard=_copy_cleanup(_GUARD),_seal=_SEAL):
    _guard(_seal)
    try:
        with _RECORD_OP():
            planning._providers();c=_CONTEXT();origin=_ORIGIN()
            bodies=_OWNED(_RESOURCES,context=c);native=_NATIVE(_RESOURCES)
            docs=[parse_json(b,context=c,source_id=p) for p,b in zip(_RESOURCES,bodies,strict=True)]
            reg=ClosedSchemaRegistry.build(docs[0],{x['$id']:b for x,b in zip(docs[1:4],bodies[1:4],strict=True)},c.profile,
                  SchemaProfilePolicy.from_dict(parse_json(_OWNED(('config/contracts/schema-profile-v1.json',),context=c)[0],context=c,source_id='approval-schema-profile')),c)
            if reg.validate('urn:gew:schema:installation-approval-policy:1.0.0',docs[4],c):fail('trust_rejected')
            contracts.validate_policy(docs[4],c);_guard(_seal)
            if _ORIGIN()!=origin or _NATIVE(_RESOURCES)!=native:fail('currentness')
            return c,docs[4],(origin,native,tuple(hashlib.sha256(b).hexdigest() for b in bodies))
    except (_IDENTITY_ERROR,OSError):fail('trust_rejected')

def _termattrs(fd):
    a=_ATTR(fd)
    if not a[3]&termios.ICANON or not a[3]&termios.ECHO:fail('authority_required')
    return tuple(tuple(x) if type(x) is list else x for x in a)

def _facts(fd,*,_is_char=stat.S_ISCHR,_is_tty=os.isatty):
    s=_FSTAT(fd)
    if not _is_char(s.st_mode) or not _is_tty(fd) or _FG(fd)!=_PGRP():fail('authority_required')
    return (s.st_dev,s.st_ino,s.st_rdev,s.st_mode,_UID(),_EUID(),_PID(),_THREAD(),_SID(0),_PGRP(),_FG(fd),_termattrs(fd))


def _close_session(self,*,_close_fd=_CLOSE,_get_state=object.__getattribute__):
    # An added class descriptor must not run even on the rejection path.
    state=_get_state(self,'__dict__');fd=state.get('fd')
    state['closed']=True;state['fd']=None
    if fd is not None:
        try:_close_fd(fd)
        except OSError:pass

class ApprovalSession:
    """Private terminal descriptor and finite decision/grant lifetime."""
    def __init__(self,context,*,_guard=_copy_cleanup(_GUARD),_seal=_SEAL,_cleanup=_copy_cleanup(_close_session),_state=object.__getattribute__):
        state=_state(self,'__dict__')
        state['fd']=None;state['closed']=False;state['deadline']=None;state['last']=None;state['issued']=False
        try:
            _guard(_seal)
            with _RECORD_OP():
                if type(context) is not _CONTEXT_TYPE:fail('currentness')
                state['context']=context;state['record']=_CONTEXT_CURRENT(context)
                if state['record']['owner_id']!=str(_UID()) or _UID()!=_EUID():fail('authority_required')
                state['work'],state['policy'],state['binding']=_capture()
                flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NOCTTY|os.O_CLOEXEC|os.O_NONBLOCK
                directory=_OPEN('/dev',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    s=_FSTAT(directory);state['dev']=(s.st_dev,s.st_ino,s.st_mode)
                    state['fd']=_OPEN('tty',flags,dir_fd=directory)
                finally:_CLOSE(directory)
                state['facts']=_facts(state['fd']);state['last']=_CLOCK();state['deadline']=state['last']+state['policy']['max_wait_seconds']*1_000_000_000
        except BaseException:_cleanup(self);raise

    def require_facts_current(self,*,_guard: Callable=_copy_cleanup(_GUARD),_seal: ProviderSeal=_SEAL,_cleanup: Callable=_copy_cleanup(_close_session),_state: Callable=object.__getattribute__) -> int:
        state=_state(self,'__dict__')
        try:
            _guard(_seal)
            if state['closed'] or state['fd'] is None:fail('currentness')
            now=_CLOCK()
            if now<state['last']:fail('currentness')
            if now>=state['deadline']:fail('currentness' if state['issued'] else 'authority_required')
            state['last']=now
            try:facts=_facts(state['fd'])
            except (OSError,ValueError):fail('currentness')
            if facts!=state['facts'] or str(_UID())!=state['record']['owner_id'] or _UID()!=_EUID():fail('currentness')
            s=os.lstat('/dev')
            if (s.st_dev,s.st_ino,s.st_mode)!=state['dev']:fail('currentness')
            return now
        except BaseException:_cleanup(self);raise

    def require_current(self,*,_guard: Callable=_copy_cleanup(_GUARD),_seal: ProviderSeal=_SEAL,_cleanup: Callable=_copy_cleanup(_close_session),_state: Callable=object.__getattribute__) -> int:
        state=_state(self,'__dict__')
        try:
            _guard(_seal)
            with _RECORD_OP():
                now=self.require_facts_current()
                if _CONTEXT_CURRENT(state['context'])!=state['record'] or _capture()[2]!=state['binding']:fail('currentness')
                end=_CLOCK()
                if end<now:fail('currentness')
                if end>=state['deadline']:fail('currentness' if state['issued'] else 'authority_required')
                state['last']=end;return end
        except BaseException:_cleanup(self);raise

    def _ready(self,write=False,*,_state=object.__getattribute__):
        state=_state(self,'__dict__')
        # Polling cannot read a response or publish a prompt. Revalidate all
        # owned bytes after readiness and immediately before each actual I/O.
        now=self.require_facts_current()
        try:
            r,w,_=_POLL([] if write else [state['fd']],[state['fd']] if write else [],[],max(0,(state['deadline']-now)/1_000_000_000))
        except InterruptedError:return False
        self.require_current();return bool(w if write else r)

    def _write_prompt(self,prompt,*,_state=object.__getattribute__):
        state=_state(self,'__dict__')
        offset=0
        while offset<len(prompt):
            if not self._ready(True):continue
            try:n=_WRITE(state['fd'],prompt[offset:])
            except (BlockingIOError,InterruptedError):continue
            if not n:fail('authority_required')
            offset+=n

    def _read_line(self,*,_state=object.__getattribute__):
        state=_state(self,'__dict__')
        result=b''
        while b'\n' not in result:
            if not self._ready():continue
            try:b=_READ(state['fd'],state['policy']['max_input_bytes']+1-len(result))
            except (BlockingIOError,InterruptedError):continue
            if not b:fail('authority_required')
            result+=b
            if len(result)>state['policy']['max_input_bytes']:fail('resource_limit')
        return result

    def decide(self,*,_guard: Callable=_copy_cleanup(_GUARD),_seal: ProviderSeal=_SEAL,_cleanup: Callable=_copy_cleanup(_close_session),_state: Callable=object.__getattribute__) -> ApprovalSession:
        state=_state(self,'__dict__')
        try:
            _guard(_seal)
            if state['issued']:fail('currentness')
            self.require_facts_current()
            if _POLL([state['fd']],[],[],0)[0]:fail('authority_required')
            nonce=_RANDOM(16).hex();e=state['record']['record'];p=e['plan']
            body=contracts.render_display(e,state['record']['owner_id'],state['record']['targets'],state['policy'],state['work'])
            prompt=body+b'Type APPROVE '+nonce.encode()+b' followed by Enter; any other response rejects.\n'
            if len(prompt)>state['policy']['max_prompt_bytes']:fail('resource_limit')
            challenge={'schema_version':'1.0.0','request_id':p['request_id'],'installation_id':p['installation_id'],'operation':p['operation'],
             'plan_digest':p['plan_digest'],'context_digest':e['stage_context']['context_digest'],'envelope_digest':e['envelope_digest'],'policy_digest':state['policy']['policy_digest'],
             'owner_id':state['record']['owner_id'],'invocation_nonce':nonce,'display_digest':contracts.display_digest(body)}
            challenge['challenge_digest']=stage_digest('installation-approval-challenge',challenge,state['work']);contracts.validate_challenge(challenge,state['work'])
            self._write_prompt(prompt);result=self._read_line()
            contracts.parse_response(result,nonce,state['policy']['max_input_bytes']);decision_time=_CLOCK()
            if decision_time<state['last']:fail('currentness')
            if decision_time>=state['deadline']:fail('authority_required')
            if _POLL([state['fd']],[],[],0)[0]:fail('authority_required')
            state['challenge']=challenge;state['deadline']=decision_time+state['policy']['max_grant_seconds']*1_000_000_000;state['issued']=True
            # Post-decision source/target revalidation spends the grant's fixed
            # lifetime; no work after the exact decision renews either budget.
            self.require_current()
            return self
        except BaseException:_cleanup(self);raise

    close=_close_session

    def __del__(self,*,_cleanup=_copy_cleanup(_close_session)):
        try:_cleanup(self)
        except (AttributeError,OSError):pass

def approve(context: planning.PlanningApprovalContext,*,_guard: Callable=_copy_cleanup(_GUARD),_seal: ProviderSeal=_SEAL) -> ApprovalSession:
    _guard(_seal);return ApprovalSession(context).decide()

def bind_providers() -> None:
    import sys
    _SEAL.freeze((sys.modules[__name__],contracts,planning),
       (ProviderSeal,ApprovalSession,_CONTEXT_TYPE,planning.PlanningSession,ClosedSchemaRegistry,SchemaProfilePolicy))
