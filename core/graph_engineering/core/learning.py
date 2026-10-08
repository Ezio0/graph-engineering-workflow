"""Platform-neutral closed learning requests and deterministic pure projections."""
from __future__ import annotations

import hashlib
import json
import re


class LearningError(ValueError):
    """Stable failure code; rejected content is never part of the error."""


METRIC_IDS = frozenset({'category','risk_path','completion','abandonment','revision_count','human_interruption_count','elapsed_bucket','failure','recovery_attempt','repeat_use','authorized_stage'})
_REQUEST_FIELDS = {
    'grant_learning': frozenset({'expected_generation','metric_ids','expires_at_ns'}),
    'revoke_learning': frozenset({'expected_generation'}),
    'record_learning_context': frozenset({'expected_generation','expected_context_version','abandonment_code','prior_task_id'}),
    'collect_learning': frozenset({'expected_head','expected_generation','expected_context_version'}),
    'report_learning': frozenset({'experiment_id','task_ids'}),
    'purge_learning': frozenset({'trigger','expected_generation'}),
}
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}\Z')


def require_bound(value: object, bound: int) -> int:
    if type(value) is not int or type(bound) is not int or not 0 <= value <= bound:
        raise LearningError('LEARNING_BOUND')
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or len(value) > 128 or _ID.fullmatch(value) is None:
        raise LearningError('LEARNING_ID')
    return value


def closed_request(value: object) -> dict[str,object]:
    if type(value) is not dict or type(value.get('operation')) is not str:
        raise LearningError('LEARNING_REQUEST')
    operation=value['operation']
    if operation not in _REQUEST_FIELDS or set(value) != _REQUEST_FIELDS[operation] | {'schema_version','operation','request_id','task_id'}:
        raise LearningError('LEARNING_REQUEST')
    if value['schema_version'] != '1.0.0':raise LearningError('LEARNING_VERSION')
    _identifier(value['request_id']); _identifier(value['task_id'])
    for field in ('expected_generation','expected_context_version'):
        if field in value:require_bound(value[field],2**53-1)
    if operation == 'grant_learning':
        metrics=value['metric_ids']
        if type(metrics) is not list or not 1 <= len(metrics) <= len(METRIC_IDS) or any(type(x) is not str or x not in METRIC_IDS for x in metrics) or len(set(metrics)) != len(metrics):
            raise LearningError('LEARNING_METRICS')
        decimal_ns(value['expires_at_ns'])
    elif operation == 'record_learning_context':
        if value['abandonment_code'] not in ('abandoned','not-stated'):
            raise LearningError('LEARNING_CONTEXT')
        if value['prior_task_id'] is not None:
            _identifier(value['prior_task_id'])
            if value['prior_task_id'] == value['task_id']:
                raise LearningError('LEARNING_RELATION')
    elif operation == 'collect_learning':
        head=value['expected_head']
        if type(head) is not str or len(head)!=78 or re.fullmatch(r'sha256-jcs-v1:[0-9a-f]{64}',head) is None:
            raise LearningError('LEARNING_HEAD')
    elif operation == 'purge_learning':
        _identifier(value['trigger'])
    elif operation == 'report_learning':
        _identifier(value['experiment_id'])
        tasks=value['task_ids']
        if type(tasks) is not list or not tasks:
            raise LearningError('LEARNING_TASKS')
        for task in tasks:_identifier(task)
        if len(set(tasks)) != len(tasks):raise LearningError('LEARNING_TASKS')
    return json.loads(json.dumps(value,allow_nan=False))


def metric_count(count: int, *, complete: bool) -> dict[str,object]:
    require_bound(count,2**63-1)
    if type(complete) is not bool:raise LearningError('LEARNING_WINDOW')
    return {'value':count if complete else None,'availability':'observed' if complete else 'incomplete-window'}


def evaluate_rule(numerator: int | None, denominator: int | None, rule: object) -> str:
    if type(rule) is not dict or set(rule) != {'comparator','numerator','denominator','min_samples'} or rule['comparator'] not in ('gte','lte'):
        raise LearningError('LEARNING_RULE')
    for k in ('numerator','denominator','min_samples'):require_bound(rule[k],2**63-1)
    if rule['denominator'] == 0 or rule['min_samples'] == 0:raise LearningError('LEARNING_RULE')
    for value in (numerator,denominator):
        if value is not None:require_bound(value,2**63-1)
    if numerator is None or denominator is None or denominator == 0 or denominator < rule['min_samples']:
        return 'insufficient-data'
    if numerator > denominator:raise LearningError('LEARNING_DENOMINATOR')
    left=numerator*rule['denominator'];right=denominator*rule['numerator']
    support=left>=right if rule['comparator']=='gte' else left<=right
    return 'supports' if support else 'counter-evidence'


def elapsed_bucket(duration_ns: int | None, boundaries: tuple[int,...]) -> int | None:
    if type(boundaries) is not tuple or not boundaries:
        raise LearningError('LEARNING_BUCKETS')
    previous=-1
    for boundary in boundaries:
        require_bound(boundary,2**63-1)
        if boundary<=previous:raise LearningError('LEARNING_BUCKETS')
        previous=boundary
    if duration_ns is None:return None
    require_bound(duration_ns,2**63-1)
    return sum(duration_ns>=b for b in boundaries)


_IDENTITY_FIELDS=frozenset({'task_id','source_head','consent_generation','context_version','context_digest','relation_vector','policy_digest'})


def observation_identity(value: object) -> str:
    if type(value) is not dict or set(value) != _IDENTITY_FIELDS:
        raise LearningError('LEARNING_IDENTITY')
    _identifier(value['task_id'])
    for name in ('source_head','context_digest','policy_digest'):
        _identifier(value[name])
    for name in ('consent_generation','context_version'):require_bound(value[name],2**63-1)
    vector=value['relation_vector']
    if type(vector) is not list:raise LearningError('LEARNING_RELATION')
    seen=set()
    for row in vector:
        if type(row) is not list or len(row)!=5:raise LearningError('LEARNING_RELATION')
        for i in (0,1,4):_identifier(row[i])
        for i in (2,3):require_bound(row[i],2**63-1)
        if row[0] in seen or row[0]==value['task_id']:raise LearningError('LEARNING_RELATION')
        seen.add(row[0])
    normalized=dict(value,relation_vector=sorted(vector,key=lambda row:row[0]))
    return 'sha256:'+hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def unique_observations(values: list[dict[str,object]]) -> tuple[dict[str,object],...]:
    unique={}
    for value in values:
        key=observation_identity(value)
        unique[key]=json.loads(json.dumps(value,allow_nan=False))
    return tuple(unique[key] for key in sorted(unique))


def request_digest(value: object) -> str:
    body=closed_request(value)
    return 'sha256:'+hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def require_replay_match(prior_digest: str, current_digest: str) -> None:
    import hmac
    if type(prior_digest) is not str or type(current_digest) is not str or not hmac.compare_digest(prior_digest,current_digest):
        raise LearningError('LEARNING_REQUEST_CONFLICT')


def decimal_ns(value: object) -> int:
    if type(value) is not str or not 1 <= len(value) <= 19 or not value.isascii() or not value.isdigit() or (len(value)>1 and value[0]=='0'):
        raise LearningError('LEARNING_TIME')
    return require_bound(int(value),2**63-1)


_AUTHORIZATION_WATERMARK_FIELDS = frozenset({
    'order_epoch','ordinal','order_digest','anchor_digest',
    'installation_id','repository_id','activation_epoch',
})


def authorization_watermark(value: object) -> dict[str, object]:
    """Closed minimized cursor; validation never turns it into an authority."""
    if type(value) is not dict or set(value) != _AUTHORIZATION_WATERMARK_FIELDS:
        raise LearningError('LEARNING_SOURCE')
    for name in ('order_epoch','order_digest','anchor_digest'):
        if type(value[name]) is not str or re.fullmatch(r'sha256-jcs-v1:[0-9a-f]{64}',value[name]) is None:
            raise LearningError('LEARNING_SOURCE')
    for name in ('installation_id','repository_id'):_identifier(value[name])
    require_bound(value['ordinal'],2**53-1)
    require_bound(value['activation_epoch'],2**53-1)
    if value['activation_epoch']==0:raise LearningError('LEARNING_SOURCE')
    return dict(value)


def authorization_mapping(value: object) -> dict[str,str]:
    if type(value) is not dict or not 1 <= len(value) <= 64:
        raise LearningError('LEARNING_POLICY')
    for key,category in value.items():
        for code in (key,category):
            if type(code) is not str or len(code)>64 or re.fullmatch(r'[a-z][a-z0-9._-]*',code) is None:
                raise LearningError('LEARNING_POLICY')
    return {key:value[key] for key in sorted(value)}


def authorized_category_count(validated_approvals: list[str], category_mapping: object) -> int | None:
    """Consume validated approval-kind facts, independent of current grant heads."""
    mapping=authorization_mapping(category_mapping)
    if type(validated_approvals) is not list:raise LearningError('LEARNING_SOURCE')
    categories=set()
    for kind in validated_approvals:
        if type(kind) is not str:raise LearningError('LEARNING_SOURCE')
        if kind not in mapping:return None
        categories.add(mapping[kind])
    return len(categories)


def authorization_event_eligible(event: dict[str,object], identity: dict[str,object], boundary: dict[str,object]) -> bool:
    """Predicate for already validated body/digest chains and proven PRD revision."""
    if event.get('event_kind')!='approved':return False
    challenge=event['challenge']
    return (all(challenge.get(key)==value for key,value in identity.items())
        and challenge.get('baseline_digest')==boundary['baseline_digest']
        and type(challenge.get('task_revision')) is int
        and challenge['task_revision']>=boundary['prd_revision'])
