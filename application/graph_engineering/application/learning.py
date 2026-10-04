"""Installed, closed learning resources and authenticated learning operations."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import inspect
from types import MappingProxyType

from graph_engineering.core.learning import LearningError, closed_request
from graph_engineering.core.contracts.schema import (
    SchemaProfilePolicy, validate_instance, validate_schema_profile,
)


def _strict_document(body: bytes) -> dict[str,object]:
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise LearningError('LEARNING_RESOURCE')
            result[key]=value
        return result
    def invalid(_value):raise LearningError('LEARNING_RESOURCE')
    try:
        value=json.loads(body,object_pairs_hook=pairs,parse_constant=invalid)
    except (ValueError,UnicodeError,RecursionError):
        raise LearningError('LEARNING_RESOURCE') from None
    if type(value) is not dict:raise LearningError('LEARNING_RESOURCE')
    return value


class LearningPolicyLoader:
    """Fresh installed-byte checks; mutable document copies never confer trust."""
    def __init__(self):
        raise TypeError('learning policy is installation-owned')

    @classmethod
    def from_installation(cls) -> LearningPolicyLoader:
        from graph_engineering import _learning_installation_resources
        bodies=_learning_installation_resources()
        self=object.__new__(cls)
        self._digest='sha256:'+hashlib.sha256(b''.join(len(b).to_bytes(8,'big')+b for b in bodies)).hexdigest()
        self._policy=_strict_document(bodies[0])
        self._experiments=_strict_document(bodies[1])
        self._schemas={name:_strict_document(body) for name,body in zip(('input','record','report','policy'),bodies[2:],strict=True)}
        profile=SchemaProfilePolicy.from_dict({'profile_id':'urn:gew:schema-profile:default:1.0.0','schema_version':'1.0.0','dialect_id':'https://json-schema.org/draft/2020-12/schema'})
        try:
            for schema in self._schemas.values():validate_schema_profile(schema,profile)
        except ValueError:raise LearningError('LEARNING_SCHEMA') from None
        self.validate_policy_document(self._policy)
        self.validate_experiment_document(self._experiments)
        self.limits=MappingProxyType(dict(self._policy['limits']))
        return self

    @property
    def digest(self) -> str:return self._digest

    def _validate(self,name,value):
        if validate_instance(self._schemas[name],value,source_id=self._schemas[name]['$id']):
            raise LearningError('LEARNING_SCHEMA')

    def validate_policy_document(self,value):
        self._validate('policy',value)
        if value.get('kind') != 'learning-policy':raise LearningError('LEARNING_POLICY')
        boundaries=value['elapsed_buckets_ns']
        if boundaries != sorted(boundaries):raise LearningError('LEARNING_POLICY')
        rules=value['rules']
        if len(rules)>value['limits']['max_rules'] or len({r['rule_id'] for r in rules})!=len(rules):
            raise LearningError('LEARNING_POLICY')
        if any(r['metric_id'] not in value['metric_ids'] for r in rules):raise LearningError('LEARNING_POLICY')

    def validate_experiment_document(self,value):
        self._validate('policy',value)
        if value.get('kind') != 'learning-experiments':raise LearningError('LEARNING_EXPERIMENT')
        known={r['rule_id'] for r in self._policy['rules']}
        rows=value['experiments']
        if len({r['experiment_id'] for r in rows})!=len(rows) or any(not set(r['rule_ids'])<=known for r in rows):
            raise LearningError('LEARNING_EXPERIMENT')

    def validate_request(self,value):
        # Enforce installed admission bounds before copying or iterating input.
        if type(value) is not dict or len(value) > 8:
            raise LearningError('LEARNING_REQUEST')
        if 'task_ids' in value and (
            type(value['task_ids']) is not list
            or len(value['task_ids']) > self.limits['max_tasks']
        ):
            raise LearningError('LEARNING_BOUND')
        result=closed_request(value)
        self._validate('input',result)
        if 'task_ids' in result and len(result['task_ids'])>self.limits['max_tasks']:
            raise LearningError('LEARNING_BOUND')
        if 'metric_ids' in result and not set(result['metric_ids'])<=set(self._policy['metric_ids']):
            raise LearningError('LEARNING_METRICS')
        return result

    def validate_record(self,value):self._validate('record',value)
    def observation_capacity(self):
        """Conservative UTF-8 JSON ceiling from the installed closed schema."""
        def bound(schema):
            if 'anyOf' in schema:return max(map(bound,schema['anyOf']))
            if 'const' in schema:return len(json.dumps(schema['const']).encode())
            if 'enum' in schema:return max(len(json.dumps(v).encode()) for v in schema['enum'])
            kind=schema.get('type')
            if kind=='null':return 4
            if kind=='integer':return len(str(schema['maximum']))+1
            if kind=='string':
                length=schema.get('maxLength')
                if length is None and schema.get('pattern')=='^sha256:[0-9a-f]{64}$':length=71
                if length is None:raise LearningError('LEARNING_SCHEMA')
                return 2+6*length
            if kind=='object' and schema.get('additionalProperties') is False:
                return 2+sum(len(json.dumps(k).encode())+2+bound(v) for k,v in schema['properties'].items())
            raise LearningError('LEARNING_SCHEMA')
        return bound(self._schemas['record']['oneOf'][0])
    def validate_report(self,value):self._validate('report',value)
    def policy_document(self):return json.loads(json.dumps(self._policy))
    def experiment_document(self):return json.loads(json.dumps(self._experiments))

    def require_current(self):
        if self.from_installation().digest != self.digest:raise LearningError('LEARNING_POLICY_STALE')
        return self.digest


class _CommitObservation:
    __slots__=()
    def __new__(cls):
        raise TypeError('learning observations are application-issued')


_COMMIT_OBSERVATIONS={}


def _commit_observed(application, batch, runtime, **commit_options):
    """Issue a one-use source ticket only at the two validated task commit sites."""
    from graph_engineering.application.tasks import TaskApplication, RuntimeContext
    from graph_engineering.storage.codec import semantic_record_digest
    frame=inspect.currentframe()
    try:
        caller=None if frame is None else frame.f_back
        if (type(application) is not TaskApplication or type(runtime) is not RuntimeContext
                or caller is None or caller.f_code not in {TaskApplication._execute.__code__,TaskApplication._commit_internal.__code__}
                or caller.f_locals.get('self') is not application):
            raise LearningError('LEARNING_SOURCE_AUTH')
    finally:
        del frame,caller
    runtime.require_issued()
    repository=application._repository
    token=object.__new__(_CommitObservation)
    digest=semantic_record_digest(repository._request_value(batch))
    _COMMIT_OBSERVATIONS[id(token)]=(token,repository,batch,digest,runtime,os.getpid(),threading.get_ident())
    try:
        return repository.commit(batch,learning_observation=token,**commit_options)
    finally:
        _COMMIT_OBSERVATIONS.pop(id(token),None)


def _consume_observation(token,repository,batch):
    from graph_engineering.storage.codec import semantic_record_digest
    issued=_COMMIT_OBSERVATIONS.pop(id(token),None)
    if (type(token) is not _CommitObservation or issued is None or issued[0] is not token
            or issued[1] is not repository or issued[2] is not batch
            or issued[5:]!=(os.getpid(),threading.get_ident())
            or issued[3]!=semantic_record_digest(repository._request_value(batch))):
        raise LearningError('LEARNING_SOURCE_AUTH')
    issued[4].require_issued()
    return issued[4]
