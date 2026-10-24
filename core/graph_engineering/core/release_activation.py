"""Bounded untrusted release contracts. Success is None, never execution authority."""
from __future__ import annotations

from functools import wraps
from graph_engineering.core.contracts.canonical import canonical_byte_length, MAX_SAFE_INTEGER
from graph_engineering.core.contracts.errors import ContractError
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.release_installation import closed, measure, token, digest, integer, fail, ReleaseInstallationError
from graph_engineering.core.release_staging import stage_digest
from graph_engineering.core.staging_execution import validate_record as validate_stage_record
from graph_engineering.core.migration import ActiveRepositoryManifest

FIELDS = {
    'activation-intent': ('request_id','installation_id','operation','target_tuple_digest','expected_reference_digest','recovery_source_record_digest','recovery_disposition','preserve_data','intent_digest'),
    'release-tuple-manifest': ('installation_id','release_id','release_manifest_digest','installed_manifest_digest','stage_receipt_digest','installation_binding_digest','repository_leaf_digest','bootstrap_protocol','tuple_digest'),
    'active-release-reference': ('installation_id','generation','activation_epoch','mode','tuple_digest','previous_reference_digest','journal_digest','reference_digest'),
    'release-transition-record': ('installation_id','request_id','operation','sequence','state','intent_digest','plan_digest','prior_reference_digest','target_tuple_digest','candidate_leaf_digest','observed_reference_digest','previous_record_digest','record_digest'),
    'release-transition-receipt': ('installation_id','request_id','operation','plan_digest','terminal_record_digest','selected_reference_digest','outcome','receipt_digest'),
    'activation-diagnostic': ('request_id','phase','status','code','refs','capabilities','next_route','diagnostic_digest'),
}
SELF = {k:v[-1] for k,v in FIELDS.items()}
OPERATIONS = ('activate','upgrade','rollback','recover')
TERMINALS = ('completed','recovered_old','recovered_new','blocked','failed_before_switch')
NORMAL = ('prepared','repository_verified','verifying_prepared','verifying_published','active_prepared','active_published','completed')
STATES = (*NORMAL,'recovery_prepared','recovered_old','recovered_new','block_prepared','blocked','failed_before_switch')
CAPABILITIES = {k:'unavailable' for k in ('activation-plan','activate','recover','rollback','uninstall')}
PREPARATIONS = {'verifying_prepared':'verifying','active_prepared':'active','recovery_prepared':'active','block_prepared':'blocked'}
PUBLICATIONS = {'verifying_published':'verifying_prepared','active_published':'active_prepared','recovered_old':'recovery_prepared','recovered_new':'recovery_prepared'}
LEAF_FIELDS = ('installation_id','generation','activation_epoch','repository_id','repository_digest','repository_locator_ref','repository_locator_digest','release_id','contract_id','mode','previous_manifest_digest','fencing_high_water','restore_gap_digest','manifest_digest')


def _bounded(function):
    @wraps(function)
    def run(*args: object, **kwargs: object) -> None:
        try:
            return function(*args, **kwargs)
        except ReleaseInstallationError:
            raise
        except ContractError:
            fail('resource_limit')
        except (TypeError, ValueError, KeyError, OverflowError, RecursionError):
            fail('input_invalid')
    return run


def _charge(value, context, *, record=False):
    if type(context) is not WorkContext:
        fail('resource_limit')
    # Preflight is itself bounded and charged before expanding children. Count
    # occurrences, not identities: shared containers cannot hide exponential work.
    # Exact builtins avoid user Mapping/iterator/property callbacks.
    nodes = members = items = scalars = 0
    path = context.child_path(())

    def strings(count: int) -> None:
        nonlocal scalars
        scalars += count
        context.check_limit('utf8_scalars', scalars, source_id='activation')
        context.emit('parse.string_scalar', count, source_id='activation', operation_path=path)

    def plain(v: object, depth: int) -> None:
        nonlocal nodes, members, items
        context.check_limit('parse_depth', depth, source_id='activation')
        nodes += 1
        context.check_limit('parse_tokens', nodes, source_id='activation')
        context.emit('parse.token', 1, source_id='activation', operation_path=path)
        context.acquire_temporary(1, source_id='activation', operation_path=path)
        try:
            t = type(v)
            if t is dict:
                members += len(v)
                context.check_limit('object_properties', members, source_id='activation')
                context.emit('parse.container', 1, source_id='activation', operation_path=path)
                context.emit('parse.member', len(v), source_id='activation', operation_path=path)
                for k, item in v.items():
                    if type(k) is not str:
                        fail()
                    strings(len(k))
                    plain(item, depth+1)
            elif t is list:
                items += len(v)
                context.check_limit('array_items', items, source_id='activation')
                context.emit('parse.container', 1, source_id='activation', operation_path=path)
                context.emit('parse.item', len(v), source_id='activation', operation_path=path)
                for item in v:
                    plain(item, depth+1)
            elif t is str:
                strings(len(v))
            elif t not in (int, bool, type(None)):
                fail()
        finally:
            context.release_temporary(1)
    plain(value, 1)
    measure(value, context)
    size = canonical_byte_length(value)
    context.check_limit('raw_document_bytes', size, source_id='activation')
    if record and size > 65536:
        fail('resource_limit')
    context.emit('parse.input_byte', size, source_id='activation', operation_path=context.child_path(()))


def _equal(a, b):
    if a != b:
        fail('closure_mismatch')


def _record(kind, value, context):
    if type(kind) is not str or kind not in FIELDS or type(value) is not dict:
        fail()
    _charge(value, context, record=True)
    closed(value, ('schema_version', *FIELDS[kind]))
    if value['schema_version'] != '1.0.0':
        fail()
    for k in ('request_id','installation_id','release_id'):
        if k in value:
            token(value[k])
    nullable = {'recovery_source_record_digest','previous_reference_digest','candidate_leaf_digest','observed_reference_digest','previous_record_digest'}
    for k,v in value.items():
        if k.endswith('_digest') and not (k in nullable and v is None):
            digest(v)
    if 'operation' in value and value['operation'] not in OPERATIONS:
        fail()
    if kind == 'activation-intent':
        if value['preserve_data'] is not True:
            fail()
        recovering = value['operation'] == 'recover'
        if recovering:
            if value['recovery_source_record_digest'] is None or value['recovery_disposition'] not in ('finish_new','restore_old'):
                fail()
        elif value['recovery_source_record_digest'] is not None or value['recovery_disposition'] is not None:
            fail()
    elif kind == 'release-tuple-manifest':
        if value['bootstrap_protocol'] != 'release-dispatch-v1':
            fail()
    elif kind == 'active-release-reference':
        for k in ('generation','activation_epoch'):
            integer(value[k], positive=True)
        if value['mode'] not in ('verifying','active','blocked'):
            fail()
        if value['generation'] == 1:
            if value['activation_epoch'] != 1 or value['previous_reference_digest'] is not None:
                fail()
        elif value['previous_reference_digest'] is None:
            fail()
    elif kind == 'release-transition-record':
        integer(value['sequence'])
        if value['state'] not in STATES:
            fail()
        if value['sequence'] == 0:
            if value['state'] != 'prepared' or any(value[k] is not None for k in ('previous_record_digest','candidate_leaf_digest','observed_reference_digest')):
                fail()
        elif value['state'] == 'prepared' or value['previous_record_digest'] is None:
            fail()
        if value['state'] in ('recovery_prepared','recovered_old','recovered_new') and value['operation'] != 'recover':
            fail()
        if value['operation'] == 'recover' and value['state'] in NORMAL[2:]:
            fail()
    elif kind == 'release-transition-receipt':
        if value['outcome'] not in ('active','restored','blocked') or (value['outcome'] == 'restored' and value['operation'] != 'recover'):
            fail()
    elif kind == 'activation-diagnostic':
        if value['phase'] != 'activation' or type(value['capabilities']) is not dict or value['capabilities'] != CAPABILITIES:
            fail()
        refs = value['refs']
        if type(refs) is not list or len(refs) > 128:
            fail('resource_limit')
        for r in refs:
            token(r)
        if refs != sorted(set(refs)):
            fail()
        pairs = {'proposed': {'phase_unavailable': 'contract-review'},
                 'blocked': {'phase_unavailable': 'phase-implementation'},
                 'rejected': {k:'supply-inputs' for k in ('input_invalid','trust_rejected','closure_mismatch','resource_limit')}}
        if (type(value['status']) is not str or value['status'] not in pairs
                or type(value['code']) is not str or value['code'] not in pairs[value['status']]
                or type(value['next_route']) is not str
                or pairs[value['status']][value['code']] != value['next_route']):
            fail()
    field = SELF[kind]
    if stage_digest(kind, {k:v for k,v in value.items() if k != field}, context) != value[field]:
        fail('trust_rejected')


@_bounded
def validate_activation_record(kind: str, value: object, context: WorkContext) -> None:
    _record(kind, value, context)


def _successor(previous, current):
    _equal(current['installation_id'], previous['installation_id'])
    _equal(current['previous_reference_digest'], previous['reference_digest'])
    if previous['generation'] == MAX_SAFE_INTEGER or previous['activation_epoch'] == MAX_SAFE_INTEGER:
        fail('resource_limit')
    _equal(current['generation'], previous['generation']+1)
    _equal(current['activation_epoch'], previous['activation_epoch']+1)


@_bounded
def validate_reference_successor(previous: object, current: object, context: WorkContext) -> None:
    _record('active-release-reference', previous, context)
    _record('active-release-reference', current, context)
    _successor(previous, current)


def _leaf(value, context):
    _charge(value, context, record=True)
    closed(value, LEAF_FIELDS)
    for k in ('generation','activation_epoch'):
        integer(value[k], positive=True)
    fences = value['fencing_high_water']
    if type(fences) is not list or any(type(r) is not list or len(r) != 2 for r in fences):
        fail()
    for resource, counter in fences:
        token(resource); integer(counter)
    # The original core constructor owns canonical field, chain and fence validation.
    context.emit('digest.input_byte', canonical_byte_length(value)+512, source_id='activation-leaf', operation_path=context.child_path(()))
    fields = {k:v for k,v in value.items() if k != 'manifest_digest'}
    fields['fencing_high_water'] = tuple(tuple(r) for r in fences)
    result = ActiveRepositoryManifest.create(**fields)
    _equal(result.manifest_digest, value['manifest_digest'])
    if result.mode != 'active' or result.restore_gap_digest is not None:
        fail('closure_mismatch')


@_bounded
def validate_tuple_links(tuple_record: object, installed_manifest: object, stage_receipt: object, installation_binding: object, repository_leaf: object, context: WorkContext) -> None:
    _charge([tuple_record, installed_manifest, stage_receipt, installation_binding, repository_leaf], context)
    _record('release-tuple-manifest', tuple_record, context)
    for k,v in (('installed-release-manifest', installed_manifest),('stage-receipt', stage_receipt),('installation-binding', installation_binding)):
        validate_stage_record(k, v, context)
    _leaf(repository_leaf, context)
    t,i,s,b,l = tuple_record, installed_manifest, stage_receipt, installation_binding, repository_leaf
    for a,z in ((t['installation_id'], b['installation_id']), (t['installation_id'], l['installation_id']),
                (t['release_id'], i['release_id']), (t['release_id'], l['release_id']),
                (t['installed_manifest_digest'], i['installed_manifest_digest']), (t['installed_manifest_digest'], s['installed_manifest_digest']),
                (t['stage_receipt_digest'], s['receipt_digest']), (t['installation_binding_digest'], b['binding_digest']),
                (t['installation_binding_digest'], s['binding_digest']), (t['release_manifest_digest'], s['release_manifest_digest']),
                (t['repository_leaf_digest'], l['manifest_digest'])):
        _equal(a,z)
    for k in ('request_id','plan_digest','stage_context_digest'):
        _equal(s[k],b[k])


def _chain(intent, records, reference_history, tuples, receipt, context, recovery_source, *, source=False):
    _record('activation-intent', intent, context)
    if any(type(v) is not list or not v for v in (records, reference_history, tuples)):
        fail()
    for r in records:
        _record('release-transition-record', r, context)
    for r in reference_history:
        _record('active-release-reference', r, context)
    for t in tuples:
        _record('release-tuple-manifest', t, context)
    for values,key in ((records,'record_digest'),(reference_history,'reference_digest'),(tuples,'tuple_digest')):
        if len({v[key] for v in values}) != len(values):
            fail('closure_mismatch')
    for a,b in zip(reference_history, reference_history[1:]):
        _successor(a,b)
    tm = {t['tuple_digest']:t for t in tuples}
    wanted = {r['tuple_digest'] for r in reference_history} | {intent['target_tuple_digest']}
    _equal(set(tm), wanted)
    for v in (*reference_history, *tuples):
        _equal(v['installation_id'], intent['installation_id'])
    base = reference_history[0]
    _equal(base['reference_digest'], intent['expected_reference_digest'])
    target = tm[intent['target_tuple_digest']]
    recovering = intent['operation'] == 'recover'
    if recovering:
        if source or type(recovery_source) is not dict:
            fail()
        closed(recovery_source, ('intent','records','reference_history','tuples','receipt'))
        if type(recovery_source['intent']) is not dict or recovery_source['intent'].get('operation') == 'recover':
            fail()
        _chain(**recovery_source, context=context, recovery_source=None, source=True)
        si, sr = recovery_source['intent'], recovery_source['records']
        _equal(si['installation_id'], intent['installation_id'])
        if si['request_id'] == intent['request_id']:
            fail('closure_mismatch')
        _equal(sr[-1]['record_digest'], intent['recovery_source_record_digest'])
        _equal(recovery_source['reference_history'][-1]['reference_digest'], base['reference_digest'])
        if intent['recovery_disposition'] == 'finish_new':
            _equal(intent['target_tuple_digest'], si['target_tuple_digest'])
        else:
            source_base = recovery_source['reference_history'][0]['tuple_digest']
            old = next(t for t in recovery_source['tuples'] if t['tuple_digest'] == source_base)
            for k in FIELDS['release-tuple-manifest']:
                if k not in ('tuple_digest','repository_leaf_digest'):
                    _equal(target[k],old[k])
            if target['repository_leaf_digest'] == old['repository_leaf_digest']:
                fail('closure_mismatch')
    elif recovery_source is not None or base['mode'] != 'active':
        fail('closure_mismatch')
    path = ('prepared','repository_verified','recovery_prepared',
            'recovered_new' if intent['recovery_disposition'] == 'finish_new' else 'recovered_old') if recovering else NORMAL
    edges = dict(zip(path,path[1:]))
    previous = None
    index = 1
    current_ref = base
    plan = records[0]['plan_digest']
    blocked_publication = False

    def publication(preparation: dict[str, object], reference: dict[str, object], mode: str) -> None:
        _equal(reference['journal_digest'], preparation['record_digest'])
        _equal(reference['mode'], mode)
        _equal(reference['tuple_digest'], current_ref['tuple_digest'] if mode == 'blocked' else target['tuple_digest'])
        _successor(current_ref, reference)

    for pos,r in enumerate(records):
        for k in ('installation_id','request_id','operation','target_tuple_digest'):
            _equal(r[k],intent[k])
        _equal(r['intent_digest'],intent['intent_digest'])
        _equal(r['plan_digest'],plan)
        _equal(r['prior_reference_digest'],base['reference_digest'])
        _equal(r['sequence'],pos)
        state = r['state']
        if previous is None:
            _equal(state,'prepared')
        else:
            ps = previous['state']
            if ps in TERMINALS:
                fail('closure_mismatch')
            if ps == 'block_prepared':
                _equal(state,'blocked')
            elif state == 'failed_before_switch':
                if ps not in ('prepared','repository_verified','verifying_prepared','recovery_prepared') or index != 1 or len(reference_history) != 1:
                    fail('closure_mismatch')
            elif state not in ('blocked','block_prepared') and edges.get(ps) != state:
                fail('closure_mismatch')
            _equal(r['previous_record_digest'], previous['record_digest'])
            candidate = target['repository_leaf_digest'] if state == 'repository_verified' else previous['candidate_leaf_digest']
            _equal(r['candidate_leaf_digest'], candidate)
            pub = state in PUBLICATIONS or state == 'blocked' and ps == 'block_prepared'
            if pub:
                expected_preparation = 'block_prepared' if state == 'blocked' else PUBLICATIONS[state]
                _equal(ps, expected_preparation)
                if index >= len(reference_history):
                    fail('closure_mismatch')
                reference = reference_history[index]
                publication(previous, reference, PREPARATIONS[ps])
                _equal(r['observed_reference_digest'], reference['reference_digest'])
                current_ref = reference; index += 1
                blocked_publication = state == 'blocked'
            else:
                _equal(r['observed_reference_digest'],previous['observed_reference_digest'])
        previous = r
    # Recognize one pointer-published/preparation-only crash prefix; never a receipt.
    if index < len(reference_history) and records[-1]['state'] in PREPARATIONS and index+1 == len(reference_history):
        publication(records[-1],reference_history[index],PREPARATIONS[records[-1]['state']])
        current_ref = reference_history[index]; index += 1
    _equal(index,len(reference_history))
    if receipt is not None:
        _record('release-transition-receipt', receipt, context)
        terminal = records[-1]
        expected = {'completed':'active','recovered_new':'active','recovered_old':'restored'}
        if blocked_publication:
            expected['blocked'] = 'blocked'
        if terminal['state'] not in expected:
            fail('closure_mismatch')
        for k in ('installation_id','request_id','operation','plan_digest'):
            _equal(receipt[k], terminal[k])
        _equal(receipt['terminal_record_digest'],terminal['record_digest'])
        _equal(receipt['selected_reference_digest'],current_ref['reference_digest'])
        _equal(receipt['outcome'],expected[terminal['state']])
        _equal(current_ref['mode'],'blocked' if blocked_publication else 'active')
        if not blocked_publication:
            _equal(current_ref['tuple_digest'],target['tuple_digest'])


@_bounded
def validate_transition_chain(intent: object, records: object, reference_history: object, tuples: object, receipt: object, context: WorkContext, *, recovery_source: object = None) -> None:
    _charge([intent,records,reference_history,tuples,receipt,recovery_source], context)
    _chain(intent,records,reference_history,tuples,receipt,context,recovery_source)
