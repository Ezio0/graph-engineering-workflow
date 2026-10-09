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
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result={}
        for key,value in items:
            if key in result:raise LearningError('LEARNING_RESOURCE')
            result[key]=value
        return result
    def invalid(_value: str) -> None:raise LearningError('LEARNING_RESOURCE')
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
        self._schemas={name:_strict_document(body) for name,body in zip(('input','record','report-v11','policy-v11'),bodies[2:6],strict=True)}
        self._schemas.update({name:_strict_document(body) for name,body in zip(('record-old','report-old','policy-old'),bodies[6:9],strict=True)})
        self._schemas.update({name:_strict_document(body) for name,body in zip(('policy','experiments','report'),bodies[12:15],strict=True)})
        profile=SchemaProfilePolicy.from_dict({'profile_id':'urn:gew:schema-profile:default:1.0.0','schema_version':'1.0.0','dialect_id':self._schemas['input']['$schema']})
        try:
            for schema in self._schemas.values():validate_schema_profile(schema,profile)
        except ValueError:raise LearningError('LEARNING_SCHEMA') from None
        if self._policy.get('schema_version')!='1.2.0' or self._experiments.get('schema_version')!='1.1.0':
            raise LearningError('LEARNING_VERSION')
        self.validate_policy_document(self._policy)
        self.validate_experiment_document(self._experiments)
        self.limits=MappingProxyType(dict(self._policy['limits']))
        return self

    @property
    def digest(self) -> str:return self._digest

    def _validate(self,name,value):
        if validate_instance(self._schemas[name],value,source_id=self._schemas[name]['$id']):
            raise LearningError('LEARNING_SCHEMA')

    def validate_policy_document(self,value: dict[str, object]) -> None:
        if type(value) is not dict:raise LearningError('LEARNING_SCHEMA')
        version=value.get('schema_version')
        schema={'1.0.0':'policy-old','1.1.0':'policy-v11','1.2.0':'policy'}.get(version)
        if schema is None:raise LearningError('LEARNING_SCHEMA')
        if version=='1.2.0':
            self._admit_list(value.get('rules'),64)
            self._admit_list(value.get('elapsed_buckets_ns'),64)
        self._validate(schema,value)
        if value.get('kind') != 'learning-policy':raise LearningError('LEARNING_POLICY')
        if version in ('1.1.0','1.2.0'):
            from graph_engineering.core.learning import authorization_mapping
            authorization_mapping(value['authorized_action_categories'])
        boundaries=value['elapsed_buckets_ns']
        if boundaries != sorted(boundaries):raise LearningError('LEARNING_POLICY')
        rules=value['rules']
        if len(rules)>value['limits']['max_rules'] or len({r['rule_id'] for r in rules})!=len(rules):
            raise LearningError('LEARNING_POLICY')
        if any(r['metric_id'] not in value['metric_ids'] for r in rules):raise LearningError('LEARNING_POLICY')
        if version=='1.2.0':
            from graph_engineering.core.learning import _identifier
            for row in rules:_identifier(row['rule_id'])

    def validate_experiment_document(self,value: dict[str, object]) -> None:
        if type(value) is not dict:raise LearningError('LEARNING_SCHEMA')
        version=value.get('schema_version')
        if version=='1.0.0':
            self._validate('policy-old',value)
        elif version=='1.1.0':
            limits=self._policy['limits']
            self._admit_list(value.get('experiments'),64)
            self._admit_list(value.get('suggested_experiments'),limits['max_suggested_experiments'])
            total=0
            for row in value['experiments']:
                if type(row) is not dict:raise LearningError('LEARNING_SCHEMA')
                self._admit_list(row.get('rule_ids'),limits['max_rules'])
                self._admit_list(row.get('hypotheses'),limits['max_hypotheses'])
                total+=len(row['hypotheses'])
                if total>limits['max_hypotheses']:raise LearningError('LEARNING_BOUND')
                for hypothesis in row['hypotheses']:
                    if type(hypothesis) is not dict:raise LearningError('LEARNING_SCHEMA')
                    self._admit_list(hypothesis.get('required_rule_ids'),limits['max_rules'])
            self._validate('experiments',value)
        else:raise LearningError('LEARNING_SCHEMA')
        if value.get('kind') != 'learning-experiments':raise LearningError('LEARNING_EXPERIMENT')
        known={r['rule_id'] for r in self._policy['rules']}
        rows=value['experiments']
        if len({r['experiment_id'] for r in rows})!=len(rows) or any(not set(r['rule_ids'])<=known for r in rows):
            raise LearningError('LEARNING_EXPERIMENT')
        if version=='1.0.0':return
        from graph_engineering.core.learning import _identifier
        for row in value['suggested_experiments']:_identifier(row['experiment_id'])
        reportable={row['experiment_id'] for row in rows}
        catalog={row['experiment_id'] for row in value['suggested_experiments']}
        if len(catalog)!=len(value['suggested_experiments']) or catalog & reportable:
            raise LearningError('LEARNING_EXPERIMENT')
        hypotheses=set()
        for row in rows:
            _identifier(row['experiment_id'])
            covered=set();rules=set(row['rule_ids'])
            for rule_id in row['rule_ids']:_identifier(rule_id)
            for hypothesis in row['hypotheses']:
                _identifier(hypothesis['hypothesis_id'])
                for rule_id in hypothesis['required_rule_ids']:_identifier(rule_id)
                for ref in hypothesis['next_experiment_ids'].values():_identifier(ref)
                if hypothesis['hypothesis_id'] in hypotheses:raise LearningError('LEARNING_EXPERIMENT')
                hypotheses.add(hypothesis['hypothesis_id'])
                required=set(hypothesis['required_rule_ids'])
                if not required<=rules or not set(hypothesis['next_experiment_ids'].values())<=catalog:
                    raise LearningError('LEARNING_EXPERIMENT')
                covered.update(required)
            if covered!=rules:raise LearningError('LEARNING_EXPERIMENT')

    @staticmethod
    def _admit_list(value: object, maximum: int) -> None:
        if type(value) is not list:raise LearningError('LEARNING_SCHEMA')
        if not 1<=len(value)<=maximum:raise LearningError('LEARNING_BOUND')

    def validate_request(self,value: object) -> dict[str, object]:
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

    def validate_record(self,value: object) -> None:
        self._validate('record-old' if type(value) is dict and value.get('schema_version')=='1.0.0' else 'record',value)
    def observation_capacity(self) -> int:
        """Conservative UTF-8 JSON ceiling from the installed closed schema."""
        def bound(schema: dict[str, object]) -> int:
            if 'anyOf' in schema:return max(map(bound,schema['anyOf']))
            if 'const' in schema:return len(json.dumps(schema['const']).encode())
            if 'enum' in schema:return max(len(json.dumps(v).encode()) for v in schema['enum'])
            kind=schema.get('type')
            if kind=='null':return 4
            if kind=='boolean':return 5
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
    def validate_report(self,value: object) -> None:
        if type(value) is not dict:raise LearningError('LEARNING_SCHEMA')
        schema={'1.0.0':'report-old','1.1.0':'report-v11','1.2.0':'report'}.get(value.get('schema_version'))
        if schema is None:raise LearningError('LEARNING_SCHEMA')
        self._validate(schema,value)
        if value.get('schema_version')=='1.2.0':
            from graph_engineering.core.learning import _identifier
            for hypothesis in value['hypotheses']:
                _identifier(hypothesis['hypothesis_id'])
                _identifier(hypothesis['next_experiment_ref']['experiment_id'])
                for rule_id in hypothesis['required_rule_ids']:_identifier(rule_id)
                for task_id in hypothesis['counter_evidence_refs']:_identifier(task_id)

    def admit_report(self, experiment: dict[str, object], cohort_size: int) -> int:
        """Reserve the whole output before cohort reads or summary allocation.

        The vector is a subset of the bounded derived aggregate plus its digest.
        Six bytes per identifier character cover JSON escaping, including UTF-8.
        Count fields use the existing 53-bit schema ceiling.
        """
        from graph_engineering.core.learning import require_bound
        require_bound(cohort_size,self.limits['max_tasks'])
        self._admit_list(experiment['rule_ids'],self.limits['max_rules'])
        self._admit_list(experiment['hypotheses'],self.limits['max_hypotheses'])
        capacity=512+6*len(experiment['experiment_id'])
        capacity+=cohort_size*(2*self.limits['max_aggregate_bytes']+128)
        configured={row['rule_id']:row for row in self._policy['rules']}
        counter_capacity=cohort_size*(2+6*128+1)
        for rule_id in experiment['rule_ids']:
            rule=configured[rule_id]
            capacity+=512+6*(len(rule_id)+len(rule['metric_id']))+counter_capacity
        catalog={row['experiment_id']:row for row in self._experiments['suggested_experiments']}
        for hypothesis in experiment['hypotheses']:
            self._admit_list(hypothesis['required_rule_ids'],self.limits['max_rules'])
            suggestion=max(6*(len(catalog[ref]['experiment_id'])+len(catalog[ref]['purpose_code']))
                           for ref in hypothesis['next_experiment_ids'].values())
            capacity+=512+6*len(hypothesis['hypothesis_id'])+suggestion+counter_capacity
            capacity+=sum(3+6*len(rule_id) for rule_id in hypothesis['required_rule_ids'])
        if capacity>min(self.limits['max_report_bytes'],self.limits['max_capture_bytes']):
            raise LearningError('LEARNING_BOUND')
        return capacity
    def policy_document(self) -> dict[str, object]:return json.loads(json.dumps(self._policy))
    def experiment_document(self) -> dict[str, object]:return json.loads(json.dumps(self._experiments))

    def require_current(self) -> str:
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
