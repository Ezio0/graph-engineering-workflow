"""Local PMF storage; schema maintenance is installation-exclusive and explicit."""
from __future__ import annotations

import sqlite3

from graph_engineering.core.learning import LearningError, decimal_ns, request_digest, require_replay_match
from .clock import strict_trusted_now
from .connection import ManagedConnection
from .codec import canonical_json, parse_canonical_json, semantic_record_digest


PMF_SCHEMA_VERSION = "1.0.0"
PMF_TABLES = ("pmf_consents", "pmf_aggregates", "pmf_owner_context", "pmf_tombstones")
_SCHEMA = (
    """CREATE TABLE pmf_consents (
        task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
        binding_digest TEXT NOT NULL,
        generation INTEGER NOT NULL CHECK(generation > 0),
        state TEXT NOT NULL CHECK(state IN ('granted','revoked')),
        metric_ids_json TEXT NOT NULL,
        grant_sequence INTEGER NOT NULL CHECK(grant_sequence >= 0),
        expires_at_ns TEXT NOT NULL,
        policy_digest TEXT NOT NULL,
        request_id TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        receipts_json TEXT NOT NULL
    ) STRICT""",
    """CREATE TABLE pmf_aggregates (
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        policy_digest TEXT NOT NULL,
        consent_generation INTEGER NOT NULL CHECK(consent_generation > 0),
        observation_json TEXT NOT NULL,
        observation_digest TEXT NOT NULL,
        derived_json TEXT,
        derived_digest TEXT,
        retained_at_ns TEXT NOT NULL,
        retained_epochs_json TEXT NOT NULL,
        PRIMARY KEY(task_id,policy_digest),
        CHECK((derived_json IS NULL) = (derived_digest IS NULL))
    ) STRICT""",
    """CREATE TABLE pmf_owner_context (
        task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
        consent_generation INTEGER NOT NULL CHECK(consent_generation > 0),
        version INTEGER NOT NULL CHECK(version > 0),
        context_json TEXT NOT NULL,
        context_digest TEXT NOT NULL,
        request_id TEXT NOT NULL,
        request_digest TEXT NOT NULL
    ) STRICT""",
    """CREATE TABLE pmf_tombstones (
        task_id TEXT NOT NULL REFERENCES tasks(task_id),
        consent_generation INTEGER NOT NULL CHECK(consent_generation > 0),
        action TEXT NOT NULL CHECK(action IN ('revoked','purged')),
        policy_digest TEXT NOT NULL,
        trusted_time_ns TEXT NOT NULL,
        purge_authorization_digest TEXT,
        PRIMARY KEY(task_id,consent_generation,policy_digest,action),
        CHECK((action = 'purged') = (purge_authorization_digest IS NOT NULL))
    ) STRICT""",
)


def schema_present(connection: ManagedConnection) -> bool:
    """No row reads, schema mutation, or payload allocation on this probe."""
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE lower(name) IN (?,?,?,?) LIMIT 1", PMF_TABLES,
    ).fetchone()
    marker = connection.execute(
        "SELECT 1 FROM schema_versions WHERE lower(component)='pmf' LIMIT 1"
    ).fetchone()
    return table is not None or marker is not None


def require_schema(connection: ManagedConnection) -> None:
    """Reject partial, unknown, or replaced layouts without trying to repair them."""
    marker = connection.execute(
        "SELECT version FROM schema_versions WHERE component='pmf'"
    ).fetchone()
    if marker != (PMF_SCHEMA_VERSION,):
        raise LearningError("LEARNING_SCHEMA_UNAVAILABLE")
    for name, expected in zip(PMF_TABLES, _SCHEMA, strict=True):
        # Compare inside SQLite so a corrupt oversized DDL is not materialized.
        valid = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? AND sql=?", (name, expected),
        ).fetchone()
        if valid is None:
            raise LearningError("LEARNING_SCHEMA_UNAVAILABLE")


def _initialize_schema(connection: ManagedConnection, fault) -> None:
    """Called only inside the maintenance manager's exclusive transaction."""
    try:
        if schema_present(connection):
            require_schema(connection)
            return
        applied_at = str(strict_trusted_now(connection))
        for index, statement in enumerate(_SCHEMA):
            connection.execute(statement)
            fault(f"learning.after_table.{index}")
        connection.execute(
            "INSERT INTO schema_versions(component,version,applied_at) VALUES('pmf',?,?)",
            (PMF_SCHEMA_VERSION, applied_at),
        )
        fault("learning.after_version")
        require_schema(connection)
    except sqlite3.DatabaseError:
        raise LearningError("LEARNING_SCHEMA_UNAVAILABLE") from None


def _binding(runtime) -> str:
    from graph_engineering.application.tasks import RuntimeContext
    if type(runtime) is not RuntimeContext:
        raise LearningError("LEARNING_AUTH")
    runtime.require_issued()
    return semantic_record_digest({"owner_id":runtime.owner_id,
        "runtime_kind":runtime.runtime_kind,"runtime_lineage_id":runtime.runtime_lineage_id})


def _authorized_head(connection, task_id, runtime):
    """Project identity/head only; foreign callers never receive snapshot bodies."""
    _binding(runtime)
    row = connection.execute(
        "SELECT revision,head_sequence,head_digest FROM tasks WHERE task_id=? "
        "AND integrity_status='ok' AND length(CAST(head_digest AS BLOB))<=128 "
        "AND json_extract(snapshot_json,'$.domain.identity.owner_id')=? "
        "AND json_extract(snapshot_json,'$.domain.identity.runtime_kind')=? "
        "AND json_extract(snapshot_json,'$.domain.identity.runtime_lineage_id')=?",
        (task_id,runtime.owner_id,runtime.runtime_kind,runtime.runtime_lineage_id),
    ).fetchone()
    if row is None:
        raise LearningError("LEARNING_AUTH")
    return row


def _owner_endpoint(connection,task_id,runtime):
    """Read-only endpoint authority: same owner, endpoint's own runtime binding."""
    _binding(runtime)
    row=connection.execute("SELECT revision,head_sequence,head_digest,"
        "json_extract(snapshot_json,'$.domain.identity.runtime_kind'),"
        "json_extract(snapshot_json,'$.domain.identity.runtime_lineage_id') FROM tasks "
        "WHERE task_id=? AND integrity_status='ok' "
        "AND json_extract(snapshot_json,'$.domain.identity.owner_id')=? "
        "AND length(CAST(head_digest AS BLOB))<=128 "
        "AND length(CAST(json_extract(snapshot_json,'$.domain.identity.runtime_kind') AS BLOB))<=128 "
        "AND length(CAST(json_extract(snapshot_json,'$.domain.identity.runtime_lineage_id') AS BLOB))<=128",
        (task_id,runtime.owner_id)).fetchone()
    if row is None:raise LearningError('LEARNING_AUTH')
    identity={'task_id':task_id,'owner_id':runtime.owner_id,'runtime_kind':row[3],'runtime_lineage_id':row[4]}
    binding=semantic_record_digest({key:value for key,value in identity.items() if key!='task_id'})
    return row[:3],identity,binding


def _consent(connection, task_id, policy):
    size = connection.execute(
        "SELECT length(CAST(metric_ids_json AS BLOB))+length(CAST(receipts_json AS BLOB)) "
        "+length(binding_digest)+length(state)+length(expires_at_ns)+length(policy_digest)"
        "+length(request_id)+length(request_digest) "
        "FROM pmf_consents WHERE task_id=?", (task_id,),
    ).fetchone()
    if size is None:
        return None
    if type(size[0]) is not int or size[0] > policy.limits['max_row_bytes']:
        raise LearningError("LEARNING_BOUND")
    row = connection.execute(
        "SELECT binding_digest,generation,state,metric_ids_json,grant_sequence,expires_at_ns,"
        "policy_digest,request_id,request_digest,receipts_json FROM pmf_consents WHERE task_id=?",(task_id,),
    ).fetchone()
    keys=('binding','generation','state','metrics_json','grant_sequence','expires_at_ns',
        'policy_digest','request_id','request_digest','receipts_json')
    value=dict(zip(keys,row,strict=True))
    value['receipts']=parse_canonical_json(value.pop('receipts_json'))
    if type(value['receipts']) is not list or len(value['receipts'])>policy.limits['max_rows_per_task']:
        raise LearningError("LEARNING_SOURCE")
    return value


def _new_observation(head, generation, metrics):
    return {'schema_version':'1.0.0','grant_sequence':head[1],
        'last_observed_sequence':head[1],'last_transaction_id':f'consent:{generation}',
        'last_head_digest':head[2],'current_prd_sequence':None,'current_baseline_digest':None,
        'revision_count':0,'human_interruption_count':0,
        'failure_count':0,'recovery_attempt_count':0,'pending_failure':False,'start_sample':None,'terminal_sample':None,
        'start_event_sequence':None,'clock_availability':'not-started',
        'availability':'missing-prd','terminal':('incomplete' if set(metrics)&{
            'elapsed_bucket','completion','failure','recovery_attempt'} else 'unavailable')}


def _prd_boundary(repository,connection,task_id,head,policy,observation):
    """Prove only the durable current approval boundary, never historical counts."""
    if head[1]>policy.limits['max_rows_per_task']:
        return
    # JSON extraction stays in SQLite until the complete selected proof is
    # admitted. Missing or oversized proof leaves the observation unknown.
    source=""" FROM tasks t JOIN project_scopes s ON s.task_id=t.task_id
        AND s.status='frozen' AND s.scope_digest=json_extract(t.snapshot_json,'$.domain.project_scope_ref.digest')
        JOIN project_scope_approvals a ON a.task_id=s.task_id AND a.scope_digest=s.scope_digest
        WHERE t.task_id=?"""
    columns=("s.scope_id,s.version,s.scope_digest,s.approved_transaction_id,s.approved_event_digest,"
        "a.transaction_id,a.record_json,a.record_digest,"
        "json_extract(t.snapshot_json,'$.domain.project_scope_ref'),"
        "json_extract(t.snapshot_json,'$.domain.baseline_refs')")
    size=connection.execute('SELECT length(CAST(a.record_json AS BLOB))+'
        'length(CAST(s.scope_id AS BLOB))+length(CAST(s.scope_digest AS BLOB))+'
        'length(CAST(s.approved_transaction_id AS BLOB))+length(CAST(s.approved_event_digest AS BLOB))+'
        'length(CAST(a.transaction_id AS BLOB))+length(CAST(a.record_digest AS BLOB))+'
        "length(CAST(json_extract(t.snapshot_json,'$.domain.project_scope_ref') AS BLOB))+"
        "length(CAST(json_extract(t.snapshot_json,'$.domain.baseline_refs') AS BLOB))"+source,(task_id,)).fetchone()
    if size is None or size[0] is None or size[0]>policy.limits['max_row_bytes']:
        return
    rows=connection.execute('SELECT '+columns+source+' LIMIT 2',(task_id,)).fetchmany(2)
    if len(rows)!=1:return
    row=rows[0]
    record=parse_canonical_json(row[6])
    fields={'schema_version','task_id','scope_digest','transaction_id','scope_event_digest',
        'approval_event_digest','owner_decision_ref','baseline_refs','graph_ref','authority_refs',
        'authority_expansion','change_digest'}
    if (type(record) is not dict or set(record)!=fields or record['schema_version']!='1.0'
            or record['task_id']!=task_id or record['scope_digest']!=row[2]
            or record['transaction_id']!=row[3] or row[3]!=row[5]
            or record['scope_event_digest']!=row[4]
            or semantic_record_digest({'contract':'project-scope-approval-v1','value':record})!=row[7]):
        return
    scope={'scope_id':row[0],'version':row[1],'digest':row[2],'status':'frozen'}
    if parse_canonical_json(row[8])!=scope or parse_canonical_json(row[9])!=record['baseline_refs']:
        return
    proved=[]
    for digest,kinds in ((record['scope_event_digest'],{'project.scope_frozen','project.scope_rebased'}),
                         (record['approval_event_digest'],{'task.prd_approved','task.prd_reapproved'})):
        size=connection.execute('SELECT length(CAST(body_json AS BLOB))+'
            'length(CAST(event_type AS BLOB))+length(CAST(event_digest AS BLOB))+'
            'coalesce(length(CAST(previous_event_digest AS BLOB)),0) FROM events '
            'WHERE task_id=? AND event_digest=?',(task_id,digest)).fetchone()
        if size is None or size[0]>policy.limits['max_row_bytes']:return
        event_row=connection.execute('SELECT e.sequence,e.event_type,e.body_json,e.previous_event_digest,'
            'e.event_digest,x.revision,p.event_digest FROM events e '
            'JOIN transactions x ON x.transaction_id=e.transaction_id AND x.task_id=e.task_id '
            'LEFT JOIN events p ON p.task_id=e.task_id AND p.sequence=e.sequence-1 '
            'WHERE e.task_id=? AND e.event_digest=? AND e.transaction_id=?',
            (task_id,digest,row[3])).fetchone()
        if event_row is None or event_row[1] not in kinds or event_row[0]>head[1]:return
        event=parse_canonical_json(event_row[2])
        repository._validate_event(event,task_id=task_id,sequence=event_row[0],
            expected_revision=event_row[5]-1,previous_digest=event_row[6])
        if (event['event_type']!=event_row[1] or event['event_digest']!=digest
                or event_row[3]!=event_row[6]):return
        proved.append(event)
    frozen,approved=proved
    if frozen['payload'].get('project_scope_ref')!=scope:return
    for name in ('owner_decision_ref','baseline_refs','graph_ref','authority_refs'):
        if not record[name] or approved['payload'].get(name)!=record[name]:return
    observation['current_prd_sequence']=approved['sequence']
    observation['current_baseline_digest']=semantic_record_digest(record['baseline_refs'])
    observation['availability']='complete'


def _require_live(consent, binding, policy, now):
    if (consent is None or consent['binding']!=binding or consent['state']!='granted'
            or consent['policy_digest']!=policy.digest or decimal_ns(consent['expires_at_ns'])<=now):
        raise LearningError("LEARNING_CONSENT")


def _relation_vector(connection,task_id,body,runtime,policy,budget,allowed_tasks=None):
    """Capture only the explicitly owner-named endpoint; never expand its links."""
    if body is None or body['prior_task_id'] is None:return []
    prior=body['prior_task_id']
    if prior==task_id or (allowed_tasks is not None and prior not in allowed_tasks):
        raise LearningError('LEARNING_RELATION')
    head,_identity,binding=_owner_endpoint(connection,prior,runtime)
    reserve=2*policy.limits['max_row_bytes']+512
    if reserve>budget[0]:raise LearningError('LEARNING_BOUND')
    budget[0]-=reserve
    consent=_consent(connection,prior,policy)
    _require_live(consent,binding,policy,strict_trusted_now(connection))
    if 'repeat_use' not in parse_canonical_json(consent['metrics_json']):raise LearningError('LEARNING_CONSENT')
    size=connection.execute('SELECT length(CAST(context_json AS BLOB))+length(context_digest)+512 '
        'FROM pmf_owner_context WHERE task_id=?',(prior,)).fetchone()
    if size is not None and size[0]>policy.limits['max_row_bytes']:raise LearningError('LEARNING_BOUND')
    row=connection.execute('SELECT consent_generation,version,context_json,context_digest FROM pmf_owner_context WHERE task_id=?',(prior,)).fetchone()
    version=0;digest=semantic_record_digest({})
    if row is not None and row[0]==consent['generation']:
        value=parse_canonical_json(row[2])
        _validate_owner_context(value)
        if semantic_record_digest(value)!=row[3]:raise LearningError('LEARNING_SOURCE')
        version,digest=row[1],row[3]
    return [[prior,head[2],consent['generation'],version,digest]]


def _validate_owner_context(body):
    import re
    if (type(body) is not dict or set(body)!={'abandonment_code','prior_task_id'}
            or body['abandonment_code'] not in ('abandoned','not-stated')):raise LearningError('LEARNING_SOURCE')
    prior=body['prior_task_id']
    if prior is not None and (type(prior) is not str or len(prior)>128
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}',prior) is None):raise LearningError('LEARNING_SOURCE')


def _require_relation_live(connection,captured,runtime,policy):
    for prior,head,generation,version,digest in captured['relation_vector']:
        _head,_identity,binding=_owner_endpoint(connection,prior,runtime)
        consent=_consent(connection,prior,policy)
        _require_live(consent,binding,policy,strict_trusted_now(connection))
        if consent['generation']!=generation:raise LearningError('LEARNING_STALE')


def _capture_current_observation(application,request,runtime,policy):
    """Acquire the repository's own connection; never accept a caller's DB."""
    from .errors import RepositoryIntegrityError
    try:
        with application._repository._factory.open('application') as connection:
            with connection.transaction():
                return _capture_current_observation_locked(application,connection,request,runtime,policy)
    except LearningError:
        raise
    except (RepositoryIntegrityError,sqlite3.DatabaseError,RecursionError,ValueError,KeyError,TypeError):
        raise LearningError('LEARNING_SOURCE') from None


def _capture_current_observation_locked(application,connection,request,runtime,policy,capture_budget=None,consent_reserved=False,allowed_tasks=None,endpoint_read=False):
    """Private read projection, not a publishable report or write authority.

    The caller owns one SQL transaction spanning admission and capture. Full
    event bodies are transient integrity inputs; historical metrics are never
    reconstructed from them. No CAS object or recursive relation is loaded.
    """
    from .errors import RepositoryIntegrityError
    from .codec import require_jcs_digest
    from graph_engineering.core.graph.state import TaskSnapshot, TASK_TRANSITIONS
    repository=application._repository
    repository.command_scope.require_current()
    repository._factory._require_owned_transaction(connection)
    task_id=request['task_id']
    if endpoint_read:
        head,expected_identity,consent_binding=_owner_endpoint(connection,task_id,runtime)
    else:
        head=_authorized_head(connection,task_id,runtime)
        expected_identity={'task_id':task_id,'owner_id':runtime.owner_id,'runtime_kind':runtime.runtime_kind,
            'runtime_lineage_id':runtime.runtime_lineage_id}
        consent_binding=_binding(runtime)
    require_schema(connection)
    consent=_consent(connection,task_id,policy)
    _require_live(consent,consent_binding,policy,strict_trusted_now(connection))
    if request['expected_generation']!=consent['generation'] or request['expected_head']!=head[2]:
        raise LearningError('LEARNING_STALE')
    # LEFT JOIN makes a missing transaction visible instead of filtering it out.
    source=' FROM events e LEFT JOIN transactions x ON x.transaction_id=e.transaction_id WHERE e.task_id=?'
    fields=('e.sequence','e.body_json','e.event_id','e.event_type','e.previous_event_digest',
        'e.event_digest','e.transaction_id','x.task_id','x.revision','x.head_digest','x.request_digest')
    size='+'.join('coalesce(length(CAST('+field+' AS BLOB)),0)' for field in fields)
    count,total,maximum=connection.execute('SELECT count(*),coalesce(sum('+size+'),0),'
        'coalesce(max('+size+'),0)'+source,(task_id,)).fetchone()
    if count>policy.limits['max_rows_per_task'] or maximum>policy.limits['max_row_bytes']:
        raise LearningError('LEARNING_BOUND')
    if count!=head[1]:raise LearningError('LEARNING_SOURCE')
    snapshot_size=connection.execute('SELECT length(CAST(snapshot_json AS BLOB))+length(snapshot_digest) '
        'FROM tasks WHERE task_id=?',(task_id,)).fetchone()[0]
    aggregate_size=connection.execute('SELECT length(CAST(observation_json AS BLOB))+'
        'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB))+512 '
        'FROM pmf_aggregates WHERE task_id=? AND policy_digest=? AND consent_generation=?',
        (task_id,policy.digest,consent['generation'])).fetchone()
    context_size=connection.execute('SELECT length(CAST(context_json AS BLOB))+length(context_digest)+512 '
        'FROM pmf_owner_context WHERE task_id=?',(task_id,)).fetchone()
    if aggregate_size is None:raise LearningError('LEARNING_SOURCE')
    context_bytes=0 if context_size is None else context_size[0]
    captured_bytes=total+snapshot_size+aggregate_size[0]+context_bytes+policy.limits['max_row_bytes']
    if capture_budget is not None:
        if consent_reserved:captured_bytes-=policy.limits['max_row_bytes']
        if captured_bytes>capture_budget[0]:raise LearningError('LEARNING_BOUND')
        capture_budget[0]-=captured_bytes
    if (snapshot_size>policy.limits['max_row_bytes'] or context_bytes>policy.limits['max_row_bytes']
            or aggregate_size[0]>policy.limits['max_aggregate_bytes']
            or total+snapshot_size+aggregate_size[0]+context_bytes+policy.limits['max_row_bytes']
                >policy.limits['max_capture_bytes']):
        raise LearningError('LEARNING_BOUND')
    try:
        previous=None
        transaction=None
        transaction_head=None
        revision=0
        sequence=0
        domain_count=0
        previous_action=False
        domain_types={kind for _state,kind in TASK_TRANSITIONS}|application._RUNNER_EVENT_TYPES
        latest_prd=None
        approved_graph={}
        for row in connection.execute('SELECT '+','.join(fields)+source+' ORDER BY e.sequence',(task_id,)):
            sequence+=1
            if row[7]!=task_id or type(row[8]) is not int or type(row[6]) is not str:
                raise LearningError('LEARNING_SOURCE')
            require_jcs_digest(row[9]);require_jcs_digest(row[10])
            same_transaction=transaction==row[6]
            if not same_transaction:
                if (transaction is not None and previous!=transaction_head) or row[8]!=revision+1:
                    raise LearningError('LEARNING_SOURCE')
                transaction,transaction_head,revision=row[6],row[9],row[8]
            elif row[8]!=revision or row[9]!=transaction_head:
                raise LearningError('LEARNING_SOURCE')
            event=repository._validate_event(parse_canonical_json(row[1]),task_id=task_id,
                sequence=sequence,expected_revision=revision-1,previous_digest=previous,_copy=False)
            if (row[0]!=sequence or row[2]!=event['event_id'] or row[3]!=event['event_type']
                    or row[4]!=event['previous_event_digest'] or row[5]!=event['event_digest']):
                raise LearningError('LEARNING_SOURCE')
            kind=event['event_type']
            is_action=kind in application._ACTION_EVENT_TYPES
            if (kind not in domain_types|application._ACTION_EVENT_TYPES
                    or same_transaction and (is_action or previous_action)):
                raise LearningError('LEARNING_SOURCE')
            domain_count+=int(not is_action)
            previous_action=is_action
            previous=event['event_digest']
            if event['event_type'] in {'task.prd_approved','task.prd_reapproved'}:
                latest_prd=(sequence,semantic_record_digest(event['payload'].get('baseline_refs')))
                approved_graph=event['payload'].get('graph_ref')
        if (sequence!=head[1] or revision!=head[0] or previous!=head[2]
                or previous!=transaction_head):raise LearningError('LEARNING_SOURCE')
        raw,digest=connection.execute('SELECT snapshot_json,snapshot_digest FROM tasks WHERE task_id=?',
            (task_id,)).fetchone()
        snapshot=parse_canonical_json(raw)
        if semantic_record_digest({'contract':'repository-snapshot-v1','value':snapshot})!=digest:
            raise LearningError('LEARNING_SOURCE')
        domain=TaskSnapshot.from_dict(snapshot['domain'],schema_registry=application._schemas,context=application._context)
        if (snapshot['task_id']!=task_id or snapshot['revision']!=head[0]
                or domain.last_event_seq!=domain_count or domain.task_revision!=domain_count
                or dict(domain.identity)!=expected_identity):raise LearningError('LEARNING_SOURCE')
        if snapshot['domain']['graph_ref']!=approved_graph:
            raise LearningError('LEARNING_SOURCE')
        raw,digest=connection.execute('SELECT observation_json,observation_digest FROM pmf_aggregates '
            'WHERE task_id=? AND policy_digest=?',(task_id,policy.digest)).fetchone()
        observation=parse_canonical_json(raw)
        policy.validate_record(observation)
        expected_transaction=(f"consent:{consent['generation']}" if head[1]==consent['grant_sequence'] else transaction)
        if (semantic_record_digest(observation)!=digest or observation['grant_sequence']!=consent['grant_sequence']
                or observation['last_observed_sequence']!=head[1] or observation['last_head_digest']!=head[2]
                or observation['last_transaction_id']!=expected_transaction):raise LearningError('LEARNING_STALE')
        if observation['availability']=='complete' and (
                latest_prd!=(observation['current_prd_sequence'],observation['current_baseline_digest'])
                or observation['current_baseline_digest']!=semantic_record_digest(snapshot['domain']['baseline_refs'])):
            raise LearningError('LEARNING_SOURCE')
        context=connection.execute('SELECT consent_generation,version,context_json,context_digest '
            'FROM pmf_owner_context WHERE task_id=?',(task_id,)).fetchone()
        version=0
        context_digest=semantic_record_digest({})
        owner_context=None
        if context is not None and context[0]==consent['generation']:
            body=parse_canonical_json(context[2])
            if (type(body) is not dict or set(body)!={'abandonment_code','prior_task_id'}
                    or semantic_record_digest(body)!=context[3]):raise LearningError('LEARNING_SOURCE')
            _validate_owner_context(body)
            version,context_digest=context[1],context[3]
            owner_context=body
        if request['expected_context_version']!=version:raise LearningError('LEARNING_STALE')
    except LearningError:
        raise
    except (RepositoryIntegrityError,ValueError,KeyError,TypeError):
        raise LearningError('LEARNING_SOURCE') from None
    if capture_budget is None:capture_budget=[policy.limits['max_capture_bytes']-captured_bytes]
    relations=_relation_vector(connection,task_id,owner_context,runtime,policy,capture_budget,allowed_tasks)
    if relations and 'repeat_use' not in parse_canonical_json(consent['metrics_json']):raise LearningError('LEARNING_CONSENT')
    runtime.require_issued()
    policy.require_current()
    return {'relation_vector':relations,'task_id':task_id,'source_head':head[2],'source_revision':head[0],
        'consent_generation':consent['generation'],'context_version':version,
        'context_digest':context_digest,'policy_digest':policy.digest,'observation':observation,
        'metric_ids':parse_canonical_json(consent['metrics_json']),'owner_context':owner_context,
        'graph_ref':snapshot['domain']['graph_ref']}


def _collect_locked(application,connection,request,runtime,policy,captured):
    from graph_engineering.core.learning import METRIC_IDS,metric_count,elapsed_bucket
    from .learning_clock import clock_duration_ns
    from graph_engineering.application.security import SecurityIssuanceError
    issuer=application._learning_security_issuer
    if issuer is None:raise LearningError('LEARNING_SECURITY')
    observation=captured['observation']
    selected=set(captured['metric_ids'])
    metrics={name:{'value':None,'availability':'unavailable'} for name in sorted(METRIC_IDS)}
    for name in ('revision_count','human_interruption_count'):
        if name in selected:
            metrics[name]=metric_count(observation[name],complete=observation['availability']=='complete')
    configured=policy.policy_document()
    graph_ref=captured['graph_ref'] or {}
    for name,source,codes in (('category','profile_id','category_codes'),('risk_path','risk_path','risk_path_codes')):
        value=graph_ref.get(source)
        if name in selected and observation['availability']=='complete' and value in configured[codes]:
            metrics[name]={'value':value,'availability':'observed'}
    for name,source in (('failure','failure_count'),('recovery_attempt','recovery_attempt_count')):
        if name in selected:
            metrics[name]=metric_count(observation[source],complete=observation['availability']=='complete')
    if observation['availability']!='source-gap':
        if 'completion' in selected and observation['terminal']!='unavailable':
            metrics['completion']={'value':observation['terminal'],'availability':'observed'}
        if 'elapsed_bucket' in selected and observation['clock_availability']=='observed':
            def part(value: dict[str, object]) -> dict[str, object]:
                return {k:int(value[k]) if k=='ticks_ns' else value[k] for k in ('clock_kind','clock_domain_digest','ticks_ns')}
            duration=clock_duration_ns(part(observation['start_sample']),part(observation['terminal_sample']))
            if duration is not None:
                metrics['elapsed_bucket']={'value':elapsed_bucket(duration,tuple(policy.policy_document()['elapsed_buckets_ns'])),
                    'availability':'observed'}
    if 'abandonment' in selected and captured['owner_context'] is not None:
        metrics['abandonment']={'value':captured['owner_context']['abandonment_code'],'availability':'owner-reported'}
    derived={k:captured[k] for k in ('task_id','source_head','source_revision','consent_generation',
        'context_version','context_digest','policy_digest')}
    if 'repeat_use' in selected and captured['relation_vector']:
        metrics['repeat_use']={'value':1,'availability':'owner-reported'}
    derived.update(schema_version='1.0.0',relation_vector=captured['relation_vector'],metrics=metrics,
        provenance={'grant_sequence':observation['grant_sequence'],
            'window_start':max(observation['grant_sequence'],observation['current_prd_sequence'] or 0),
            'window_end':observation['last_observed_sequence'],
            'baseline_digest':observation['current_baseline_digest']})
    policy.validate_record(derived)
    body=canonical_json(derived)
    retained=connection.execute('SELECT length(CAST(retained_epochs_json AS BLOB)) FROM pmf_aggregates '
        'WHERE task_id=? AND policy_digest=?',(request['task_id'],policy.digest)).fetchone()[0]
    if policy.observation_capacity()+retained+len(body.encode())+512>policy.limits['max_aggregate_bytes']:
        raise LearningError('LEARNING_BOUND')
    security_size=connection.execute('SELECT length(CAST(state_json AS BLOB)) FROM task_security_states WHERE task_id=?',
        (request['task_id'],)).fetchone()
    if security_size is None:raise LearningError('LEARNING_SECURITY')
    if security_size[0]>policy.limits['max_row_bytes']:raise LearningError('LEARNING_BOUND')
    digest=semantic_record_digest(derived)
    now=strict_trusted_now(connection)
    _require_live(_consent(connection,request['task_id'],policy),_binding(runtime),policy,now)
    connection.execute('UPDATE pmf_aggregates SET derived_json=?,derived_digest=?,retained_at_ns=? '
        'WHERE task_id=? AND policy_digest=? AND consent_generation=?',
        (body,digest,str(now),request['task_id'],policy.digest,captured['consent_generation']))
    try:
        subject=issuer._register_learning_subject_locked(connection,request['task_id'],runtime,policy.digest,policy.limits['max_row_bytes'])
    except (SecurityIssuanceError,ValueError):
        raise LearningError('LEARNING_SECURITY') from None
    return {'operation':'collect_learning','generation':captured['consent_generation'],'state':'collected',
        'source_sequence':observation['last_observed_sequence'],'aggregate_ref':digest,'retention_subject_ref':subject}


def _require_learning_subject(application,connection,task_id,runtime,policy,endpoint_read=False):
    import hashlib
    issuer=application._learning_security_issuer
    if issuer is None:raise LearningError('LEARNING_SECURITY')
    current=issuer._issue_task_context_locked(connection,task_id)
    expected={'owner_id':runtime.owner_id,'runtime_kind':runtime.runtime_kind,'runtime_lineage_id':runtime.runtime_lineage_id}
    if endpoint_read:
        _head,identity,_binding_digest=_owner_endpoint(connection,task_id,runtime)
        expected={key:identity[key] for key in expected}
    if any(getattr(current.binding,key)!=value for key,value in expected.items()):raise LearningError('LEARNING_SECURITY')
    ref='learning:'+hashlib.sha256(policy.digest.encode()).hexdigest()
    subject=current.retention_subjects.get(ref)
    if (subject is None or subject.get('category')!='pmf-aggregate'
            or subject.get('snapshot_digest')!=current.binding.snapshot_digest
            or type(subject.get('revision')) is not int or not 1<=subject['revision']<=2**53-1
            or any(type(subject.get(flag)) is not bool for flag in ('legal_hold','rollback_dependency','unresolved_action'))):
        raise LearningError('LEARNING_SECURITY')
    return current


def _current_derived(connection,captured,policy):
    """An integrity digest is useful only after every current binding matches."""
    row=connection.execute('SELECT derived_json,derived_digest FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',
        (captured['task_id'],policy.digest)).fetchone()
    if row is None or row[0] is None:raise LearningError('LEARNING_STALE')
    value=parse_canonical_json(row[0])
    policy.validate_record(value)
    if semantic_record_digest(value)!=row[1]:raise LearningError('LEARNING_SOURCE')
    for name in ('task_id','source_head','source_revision','consent_generation','context_version','context_digest','policy_digest'):
        if value[name]!=captured[name]:raise LearningError('LEARNING_STALE')
    if value['relation_vector']!=captured['relation_vector']:raise LearningError('LEARNING_STALE')
    return value,row[1]


def _report_locked(application,connection,request,runtime,policy):
    """Revalidate an explicit cohort in one transaction and return a bounded view."""
    import hashlib
    from graph_engineering.core.learning import evaluate_rule
    task_ids=sorted(request['task_ids'])
    if request['task_id'] not in task_ids:raise LearningError('LEARNING_TASKS')
    experiments={row['experiment_id']:row for row in policy.experiment_document()['experiments']}
    experiment=experiments.get(request['experiment_id'])
    if experiment is None:raise LearningError('LEARNING_EXPERIMENT')
    issuer=application._learning_security_issuer
    if issuer is None:raise LearningError('LEARNING_SECURITY')
    endpoints={task_id:_owner_endpoint(connection,task_id,runtime) for task_id in task_ids}
    heads={task_id:value[0] for task_id,value in endpoints.items()}
    # Reserve every consent row before allocating any cohort receipt bodies.
    consent_reserve=len(task_ids)*policy.limits['max_row_bytes']
    if consent_reserve>policy.limits['max_capture_bytes']:raise LearningError('LEARNING_BOUND')
    # No source body is read before every explicit endpoint has live consent.
    consents={task_id:_consent(connection,task_id,policy) for task_id in task_ids}
    now=strict_trusted_now(connection)
    for task_id,consent in consents.items():_require_live(consent,endpoints[task_id][2],policy,now)
    budget=[policy.limits['max_capture_bytes']-consent_reserve]
    observations=[]
    vector=[]
    selected={}
    output_bytes=0
    for task_id in task_ids:
        consent=consents[task_id]
        context=connection.execute('SELECT consent_generation,version FROM pmf_owner_context WHERE task_id=?',(task_id,)).fetchone()
        version=context[1] if context is not None and context[0]==consent['generation'] else 0
        captured=_capture_current_observation_locked(application,connection,{'task_id':task_id,
            'expected_head':heads[task_id][2],'expected_generation':consent['generation'],
            'expected_context_version':version},runtime,policy,budget,consent_reserved=True,allowed_tasks=set(task_ids),endpoint_read=True)
        size=connection.execute('SELECT length(CAST(state_json AS BLOB)) FROM task_security_states WHERE task_id=?',(task_id,)).fetchone()
        if size is None:raise LearningError('LEARNING_SECURITY')
        if size[0]>policy.limits['max_row_bytes'] or size[0]>budget[0]:raise LearningError('LEARNING_BOUND')
        budget[0]-=size[0]
        _require_learning_subject(application,connection,task_id,runtime,policy,endpoint_read=True)
        value,digest=_current_derived(connection,captured,policy)
        output_bytes+=len(canonical_json(value).encode())
        if output_bytes>policy.limits['max_report_bytes']:raise LearningError('LEARNING_BOUND')
        observations.append(value)
        selected[task_id]=set(captured['metric_ids'])
        vector.append({**{key:value[key] for key in ('task_id','source_head','source_revision',
            'consent_generation','context_version','context_digest','relation_vector')},'aggregate_digest':digest})
    cohort='sha256:'+hashlib.sha256(canonical_json(vector).encode()).hexdigest()
    rules=[]
    eligible=set();unknown=set();excluded=set()
    configured={row['rule_id']:row for row in policy.policy_document()['rules']}
    for rule_id in sorted(experiment['rule_ids']):
        rule=configured[rule_id]
        numerator=denominator=missing=omitted=0
        counter=[]
        for value in observations:
            task_id=value['task_id'];metric=value['metrics'][rule['metric_id']]
            if rule['metric_id'] not in selected[task_id]:
                omitted+=1;excluded.add(task_id);continue
            # The installed completion hypothesis has a defined Bernoulli event.
            # Other mappings remain unknown until an approved mapping exists.
            if (rule['metric_id']!='completion' or metric['availability']!='observed'
                    or metric['value'] not in ('completed','canceled','failed')):
                missing+=1;unknown.add(task_id);continue
            denominator+=1;eligible.add(task_id)
            success=metric['value']=='completed'
            numerator+=int(success)
            if (not success and rule['comparator']=='gte') or (success and rule['comparator']=='lte'):
                counter.append(task_id)
        predicate={key:rule[key] for key in ('comparator','numerator','denominator','min_samples')}
        rules.append({'rule_id':rule_id,'metric_id':rule['metric_id'],'predicate':predicate,
            'numerator':numerator,'denominator':denominator,'unknown_count':missing,'excluded_count':omitted,
            'counter_evidence_refs':counter,'verdict':evaluate_rule(numerator,denominator,predicate)})
    report={'schema_version':'1.0.0','policy_digest':policy.digest,'experiment_id':request['experiment_id'],
        'cohort_digest':cohort,'cohort_vector':vector,'eligible_count':len(eligible),
        'unknown_count':len(unknown-eligible),'excluded_count':len(excluded-eligible-unknown),
        'observations':observations,'rules':rules}
    policy.validate_report(report)
    if len(canonical_json(report).encode())>policy.limits['max_report_bytes']:raise LearningError('LEARNING_BOUND')
    anchor=consents[request['task_id']]
    receipts=anchor['receipts'];digest=request_digest(request);replay=False
    for prior in receipts:
        if type(prior) is not dict or set(prior)!={'request_id','request_digest','result'}:raise LearningError('LEARNING_SOURCE')
        if prior['request_id']==request['request_id']:
            require_replay_match(prior['request_digest'],digest)
            if prior['result']!={'operation':'report_learning','cohort_digest':cohort}:raise LearningError('LEARNING_STALE')
            replay=True;break
    if not replay:
        if len(receipts)>=policy.limits['max_rows_per_task']-2:raise LearningError('LEARNING_BOUND')
        receipts.append({'request_id':request['request_id'],'request_digest':digest,
            'result':{'operation':'report_learning','cohort_digest':cohort}})
        body=canonical_json(receipts)
        if len(body.encode())+len(anchor['metrics_json'].encode())+512>policy.limits['max_row_bytes']-2048:
            raise LearningError('LEARNING_BOUND')
        connection.execute('UPDATE pmf_consents SET receipts_json=? WHERE task_id=?',(body,request['task_id']))
    application._repository._fault('learning.before_commit')
    policy.require_current();runtime.require_issued()
    now=strict_trusted_now(connection)
    for task_id,consent in consents.items():_require_live(consent,endpoints[task_id][2],policy,now)
    return report


def _purge_locked(application,connection,request,runtime,policy,consent):
    """Delete PMF payloads only after the existing retention fence is consumed."""
    issuer=application._learning_security_issuer
    registry=application._learning_retention_registry
    if issuer is None or registry is None:raise LearningError('LEARNING_SECURITY')
    if consent is None:raise LearningError('LEARNING_CONSENT')
    if request['trigger'] not in registry.resolve('pmf-aggregate')['purge_triggers']:
        raise LearningError('LEARNING_TRIGGER')
    row=connection.execute('SELECT length(CAST(observation_json AS BLOB))+'
        'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB)),retained_at_ns '
        'FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',(request['task_id'],policy.digest)).fetchone()
    if row is None:return {'operation':'purge_learning','state':'absent','generation':consent['generation']}
    if row[0]+512>policy.limits['max_aggregate_bytes']:raise LearningError('LEARNING_BOUND')
    size=connection.execute('SELECT length(CAST(state_json AS BLOB)) FROM task_security_states WHERE task_id=?',
        (request['task_id'],)).fetchone()
    if size is None:raise LearningError('LEARNING_SECURITY')
    if size[0]>policy.limits['max_row_bytes']:raise LearningError('LEARNING_BOUND')
    # The core retention engine has second precision. This exact lower bound
    # prevents truncation from deleting even one nanosecond too early.
    now=strict_trusted_now(connection)
    age=registry.resolve('pmf-aggregate')['max_age_seconds']*10**9
    if now<decimal_ns(row[1])+age:
        return {'operation':'purge_learning','state':'retain','generation':consent['generation']}
    state,authorization=issuer._authorize_learning_purge_locked(connection,request['task_id'],runtime,policy,registry,request['trigger'])
    result={'operation':'purge_learning','state':state,'generation':consent['generation']}
    if state!='purged':return result
    connection.execute('DELETE FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',(request['task_id'],policy.digest))
    connection.execute('DELETE FROM pmf_owner_context WHERE task_id=?',(request['task_id'],))
    connection.execute('INSERT INTO pmf_tombstones VALUES(?,?,?,?,?,?)',
        (request['task_id'],consent['generation'],'purged',policy.digest,str(now),authorization))
    application._repository._fault('learning.after_purge_delete')
    result['purge_authorization_digest']=authorization
    return result


def _record_context(connection,request,runtime,consent,policy,now):
    _require_live(consent,_binding(runtime),policy,now)
    metrics=parse_canonical_json(consent['metrics_json'])
    if (request['abandonment_code']!='not-stated' and 'abandonment' not in metrics
            or request['prior_task_id'] is not None and 'repeat_use' not in metrics):
        raise LearningError('LEARNING_CONSENT')
    current=connection.execute('SELECT consent_generation,version FROM pmf_owner_context WHERE task_id=?',
        (request['task_id'],)).fetchone()
    version=0 if current is None or current[0]!=consent['generation'] else current[1]
    if request['expected_context_version']!=version:
        raise LearningError('LEARNING_CONFLICT')
    prior=request['prior_task_id']
    if prior is not None:
        identity=connection.execute("SELECT json_extract(snapshot_json,'$.domain.identity.runtime_kind'),"
            "json_extract(snapshot_json,'$.domain.identity.runtime_lineage_id') FROM tasks WHERE task_id=? "
            "AND integrity_status='ok' AND json_extract(snapshot_json,'$.domain.identity.owner_id')=?",
            (prior,runtime.owner_id)).fetchone()
        if identity is None:
            raise LearningError('LEARNING_RELATION')
        other=_consent(connection,prior,policy)
        other_binding=semantic_record_digest({'owner_id':runtime.owner_id,
            'runtime_kind':identity[0],'runtime_lineage_id':identity[1]})
        _require_live(other,other_binding,policy,now)
        if 'repeat_use' not in parse_canonical_json(other['metrics_json']):
            raise LearningError('LEARNING_CONSENT')
    version+=1
    if version>2**53-1:
        raise LearningError('LEARNING_BOUND')
    context={'abandonment_code':request['abandonment_code'],'prior_task_id':prior}
    body=canonical_json(context)
    context_digest=semantic_record_digest(context)
    connection.execute('INSERT INTO pmf_owner_context VALUES(?,?,?,?,?,?,?) '
        'ON CONFLICT(task_id) DO UPDATE SET consent_generation=excluded.consent_generation,'
        'version=excluded.version,context_json=excluded.context_json,context_digest=excluded.context_digest,'
        'request_id=excluded.request_id,request_digest=excluded.request_digest',
        (request['task_id'],consent['generation'],version,body,context_digest,request['request_id'],request_digest(request)))
    return version,context_digest


def _execute_owner_request(application, request, runtime, policy):
    """Authenticated, bounded receipt and consent mutation in one DB transaction."""
    binding=_binding(runtime)
    repository=application._repository
    repository.command_scope.require_current()
    with repository._factory.open('application') as connection:
        with connection.transaction():
            head=_authorized_head(connection,request['task_id'],runtime)
            require_schema(connection)
            if request['operation']=='report_learning':
                return _report_locked(application,connection,request,runtime,policy)
            consent=_consent(connection,request['task_id'],policy)
            if consent is not None and consent['binding']!=binding:
                raise LearningError('LEARNING_AUTH')
            captured=None
            if request['operation']=='collect_learning':
                captured=_capture_current_observation_locked(application,connection,request,runtime,policy)
                issuer=application._learning_security_issuer
                if issuer is None:raise LearningError('LEARNING_SECURITY')
                security_size=connection.execute('SELECT length(CAST(state_json AS BLOB)) FROM task_security_states WHERE task_id=?',
                    (request['task_id'],)).fetchone()
                if security_size is None:raise LearningError('LEARNING_SECURITY')
                if security_size[0]>policy.limits['max_row_bytes']:raise LearningError('LEARNING_BOUND')
                issuer._issue_task_context_locked(connection,request['task_id'])
            digest=request_digest(request)
            receipts=[] if consent is None else consent['receipts']
            for prior in receipts:
                if type(prior) is not dict or set(prior)!={'request_id','request_digest','result'}:
                    raise LearningError('LEARNING_SOURCE')
                if prior['request_id']==request['request_id']:
                    require_replay_match(prior['request_digest'],digest)
                    if request['operation']=='collect_learning':
                        _require_learning_subject(application,connection,request['task_id'],runtime,policy)
                        _value,current_digest=_current_derived(connection,captured,policy)
                        if prior['result'].get('aggregate_ref')!=current_digest:raise LearningError('LEARNING_STALE')
                        _require_live(consent,binding,policy,strict_trusted_now(connection))
                    policy.require_current()
                    runtime.require_issued()
                    if request['operation']=='collect_learning':
                        _require_live(consent,binding,policy,strict_trusted_now(connection))
                        _require_relation_live(connection,captured,runtime,policy)
                    return prior['result']
            generation=0 if consent is None else consent['generation']
            if request.get('expected_generation')!=generation:
                raise LearningError('LEARNING_CONFLICT')
            operation=request['operation']
            # Keep separate terminal capacity for suppression and physical purge.
            reserve=0 if operation=='purge_learning' else 1 if operation=='revoke_learning' else 2
            if len(receipts)>=policy.limits['max_rows_per_task']-reserve:
                raise LearningError('LEARNING_BOUND')
            now=strict_trusted_now(connection)
            if operation not in {'grant_learning','revoke_learning','record_learning_context','collect_learning','purge_learning'}:
                raise LearningError('LEARNING_OPERATION_UNAVAILABLE')
            generation+=int(operation in {'grant_learning','revoke_learning'})
            if generation>2**53-1:
                raise LearningError('LEARNING_BOUND')
            source_sequence=head[1]
            context_result=None
            if operation=='purge_learning':
                result=_purge_locked(application,connection,request,runtime,policy,consent)
                if result['state'] not in {'purged','absent'}:
                    reserve=1+int(consent['state']=='granted')
                    if len(receipts)>=policy.limits['max_rows_per_task']-reserve:raise LearningError('LEARNING_BOUND')
                expiry=decimal_ns(consent['expires_at_ns'])
                metrics_json=consent['metrics_json']
                state=consent['state']
                source_sequence=consent['grant_sequence']
            elif operation=='collect_learning':
                result=_collect_locked(application,connection,request,runtime,policy,captured)
                expiry=decimal_ns(consent['expires_at_ns'])
                metrics_json=consent['metrics_json']
                state=consent['state']
                source_sequence=consent['grant_sequence']
            elif operation=='record_learning_context':
                version,context_digest=_record_context(connection,request,runtime,consent,policy,now)
                context_result={'context_version':version,'context_digest':context_digest}
                expiry=decimal_ns(consent['expires_at_ns'])
                metrics_json=consent['metrics_json']
                state=consent['state']
                source_sequence=consent['grant_sequence']
            elif operation=='grant_learning':
                if generation>=2**53-1:
                    raise LearningError('LEARNING_BOUND')
                expiry=decimal_ns(request['expires_at_ns'])
                if not now<expiry<=now+policy.limits['retention_seconds']*10**9:
                    raise LearningError('LEARNING_CONSENT')
                metrics_json=canonical_json(request['metric_ids'])
                state='granted'
                observation=_new_observation(head,generation,request['metric_ids'])
                _prd_boundary(repository,connection,request['task_id'],head,policy,observation)
                policy.validate_record(observation)
                body=canonical_json(observation)
                if len(body.encode())>policy.limits['max_aggregate_bytes']:
                    raise LearningError('LEARNING_BOUND')
                # Regrant starts a fresh view but never physically purges old
                # observations. Retained epochs share the same bounded row and
                # can only be removed by the eventual authorized purge path.
                old_size=connection.execute('SELECT length(CAST(observation_json AS BLOB))+'
                    'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB)) '
                    'FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',
                    (request['task_id'],policy.digest)).fetchone()
                epochs=[]
                if old_size is not None:
                    if old_size[0]>policy.limits['max_aggregate_bytes']:
                        raise LearningError('LEARNING_BOUND')
                    old=connection.execute('SELECT consent_generation,observation_json,derived_json,retained_at_ns,retained_epochs_json '
                        'FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',(request['task_id'],policy.digest)).fetchone()
                    epochs=parse_canonical_json(old[4])
                    epochs.append({'generation':old[0],'observation':parse_canonical_json(old[1]),
                        'derived':None if old[2] is None else parse_canonical_json(old[2]),'retained_at_ns':old[3]})
                archived=canonical_json(epochs)
                # Reserve every schema-admitted future observation, plus fixed
                # row identity/digest columns, before retaining another epoch.
                if policy.observation_capacity()+len(archived.encode())+512>policy.limits['max_aggregate_bytes']:
                    raise LearningError('LEARNING_BOUND')
                connection.execute(
                    'INSERT INTO pmf_aggregates VALUES(?,?,?,?,?,NULL,NULL,?,?) '
                    'ON CONFLICT(task_id,policy_digest) DO UPDATE SET '
                    'consent_generation=excluded.consent_generation,observation_json=excluded.observation_json,'
                    'observation_digest=excluded.observation_digest,derived_json=NULL,derived_digest=NULL,'
                    'retained_at_ns=excluded.retained_at_ns,retained_epochs_json=excluded.retained_epochs_json',
                    (request['task_id'],policy.digest,generation,body,semantic_record_digest(observation),str(now),archived),
                )
            else:
                expiry=now
                metrics_json='[]'
                state='revoked'
                connection.execute('INSERT INTO pmf_tombstones VALUES(?,?,?,?,?,NULL)',
                    (request['task_id'],generation,'revoked',policy.digest,str(now)))
            if operation not in {'collect_learning','purge_learning'}:
                result={'operation':operation,'generation':generation,'state':state,'source_sequence':head[1]}
            if context_result is not None:
                result.update(context_result)
            if operation not in {'collect_learning','purge_learning'}:
                from .security import SecurityStateRepository
                if operation!='revoke_learning':
                    connection.execute('UPDATE pmf_aggregates SET retained_at_ns=? WHERE task_id=? AND policy_digest=?',
                        (str(now),request['task_id'],policy.digest))
                from .errors import RepositoryIntegrityError
                try:
                    SecurityStateRepository._refresh_learning_subject_locked(connection,request['task_id'],policy.digest,
                        None if operation=='revoke_learning' else now,policy.limits['max_row_bytes'])
                except RepositoryIntegrityError:
                    if operation!='revoke_learning':raise
                    # Suppression is independent of whether retained data can
                    # currently pass security validation for eventual deletion.
                    result['retention_status']='blocked'
            receipts.append({'request_id':request['request_id'],'request_digest':digest,'result':result})
            receipts_json=canonical_json(receipts)
            if len(receipts_json.encode())+len(metrics_json.encode())+512>policy.limits['max_row_bytes']-1024*reserve:
                raise LearningError('LEARNING_BOUND')
            connection.execute('INSERT INTO pmf_consents VALUES(?,?,?,?,?,?,?,?,?,?,?) '
                'ON CONFLICT(task_id) DO UPDATE SET binding_digest=excluded.binding_digest,'
                'generation=excluded.generation,state=excluded.state,metric_ids_json=excluded.metric_ids_json,'
                'grant_sequence=excluded.grant_sequence,expires_at_ns=excluded.expires_at_ns,'
                'policy_digest=excluded.policy_digest,request_id=excluded.request_id,'
                'request_digest=excluded.request_digest,receipts_json=excluded.receipts_json',
                (request['task_id'],binding,generation,state,metrics_json,source_sequence,str(expiry),policy.digest,
                    request['request_id'],digest,receipts_json))
            policy.require_current()
            runtime.require_issued()
            repository._fault('learning.before_commit')
            if operation=='collect_learning':
                _require_live(_consent(connection,request['task_id'],policy),binding,policy,strict_trusted_now(connection))
                _require_relation_live(connection,captured,runtime,policy)
            return result


def _observe_task_commit(repository,connection,batch,events,before,after,ticket):
    """Advance observation with the task, never in a later best-effort write."""
    from graph_engineering.application.learning import LearningPolicyLoader, _consume_observation
    from .learning_clock import NativeLearningClock, ClockUnavailable, clock_duration_ns
    runtime=None if ticket is None else _consume_observation(ticket,repository,batch)
    if not schema_present(connection):
        return
    try:
        require_schema(connection)
    except LearningError:
        # Unsupported/partial PMF storage cannot create trusted observations,
        # and must not disable an ordinary task. Explicit learning still rejects it.
        return
    # The minimal gate precedes policy, history, observation and native clock reads.
    gate=connection.execute(
        "SELECT state,expires_at_ns FROM pmf_consents WHERE task_id=?",(batch.task_id,),
    ).fetchone()
    if gate is None or gate[0]!='granted':
        return
    from .errors import RepositoryIntegrityError
    try:
        now=strict_trusted_now(connection)
    except RepositoryIntegrityError:
        # Consent freshness cannot be established. Do not read measurements;
        # the unchanged cursor makes the missing transition detectable later.
        return
    if decimal_ns(gate[1])<=now:
        return
    policy=LearningPolicyLoader.from_installation()
    consent=_consent(connection,batch.task_id,policy)
    if consent['policy_digest']!=policy.digest:
        return
    length=connection.execute(
        'SELECT length(CAST(observation_json AS BLOB))+'
        'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB))+512 FROM pmf_aggregates '
        'WHERE task_id=? AND policy_digest=? AND consent_generation=?',
        (batch.task_id,policy.digest,consent['generation']),
    ).fetchone()
    if length is None:
        # No historical backfill. A later explicit capture must reject this epoch.
        return
    if length[0]>policy.limits['max_aggregate_bytes']:
        return
    raw,digest=connection.execute(
        'SELECT observation_json,observation_digest FROM pmf_aggregates WHERE task_id=? AND policy_digest=?',
        (batch.task_id,policy.digest),
    ).fetchone()
    observation=parse_canonical_json(raw)
    if semantic_record_digest(observation)!=digest:
        raise LearningError('LEARNING_SOURCE')
    policy.validate_record(observation)
    sequence=events[0]['sequence']-1
    prior_digest=events[0]['previous_event_digest']
    if (runtime is None or _binding(runtime)!=consent['binding']
            or observation['last_observed_sequence']!=sequence
            or observation['last_head_digest']!=prior_digest):
        observation['availability']='source-gap'
        observation['clock_availability']='unavailable'
    else:
        old_domain={} if before is None else before.get('domain',{})
        new_domain=after.get('domain',{})
        identity=new_domain.get('identity',{})
        if identity!={'task_id':batch.task_id,'owner_id':runtime.owner_id,
                'runtime_kind':runtime.runtime_kind,'runtime_lineage_id':runtime.runtime_lineage_id}:
            raise LearningError('LEARNING_SOURCE_AUTH')
        types=[event['event_type'] for event in events]
        metrics=parse_canonical_json(consent['metrics_json'])
        for event in events:
            kind=event['event_type']
            if kind in {'task.prd_approved','task.prd_reapproved'}:
                refs=event['payload'].get('baseline_refs')
                if not refs or new_domain.get('baseline_refs')!=refs:
                    observation['availability']='source-gap'
                    continue
                observation['current_prd_sequence']=event['sequence']
                observation['current_baseline_digest']=semantic_record_digest(refs)
                observation['revision_count']=0
                observation['human_interruption_count']=0
                observation['failure_count']=0
                observation['recovery_attempt_count']=0
                observation['pending_failure']=False
                if observation['availability']!='source-gap':
                    observation['availability']='complete'
            if observation['availability']=='complete' and observation['current_prd_sequence'] is not None:
                if set(metrics)&{'failure','recovery_attempt'}:
                    failed_run=old_domain.get('node_runs',{}).get(event['payload'].get('run_id'),{})
                    # A blocked review is not a runtime failure. Only the issued
                    # runner transition from running, or task.failed, qualifies.
                    failure=(kind=='task.failed' or kind=='node.blocked' and failed_run.get('status')=='running')
                    if failure:
                        if 'failure' in metrics:observation['failure_count']+=1
                        if 'recovery_attempt' in metrics:observation['pending_failure']=True
                    if ('recovery_attempt' in metrics and kind=='task.resumed' and observation['pending_failure']
                            and old_domain.get('lifecycle') in ('blocked','failed')):
                        observation['recovery_attempt_count']+=1
                        observation['pending_failure']=False
                if kind=='task.human_decision_required' and 'human_interruption_count' in metrics:
                    if old_domain.get('lifecycle')=='running' and new_domain.get('lifecycle')=='awaiting_human':
                        observation['human_interruption_count']+=1
                    else:
                        observation['availability']='source-gap'
                if kind=='node.review_recorded' and 'revision_count' in metrics:
                    old_history=before['runner']['review_history']
                    new_history=after['runner']['review_history']
                    if len(new_history)!=len(old_history)+1 or new_history[:-1]!=old_history:
                        observation['availability']='source-gap'
                    else:
                        review=new_history[-1]
                        run=old_domain.get('node_runs',{}).get(event['payload'].get('run_id'),{})
                        output=before['runner']['node_outputs'].get(review['node_id'],{})
                        if (review['run_id']!=event['payload'].get('run_id')
                                or run.get('status')!='reviewing'
                                or run.get('node_id')!=review['node_id']
                                or run.get('attempt')!=review['attempt']
                                or output.get('run_id')!=review['run_id']
                                or output.get('attempt')!=review['attempt']
                                or output.get('body_digest')!=review['body_digest']
                                or output.get('trust')!='validated'
                                or output.get('verdict') is not None
                                or output.get('author_id','').casefold()==review['reviewer_id'].casefold()):
                            observation['availability']='source-gap'
                        elif review['verdict']=='REVISE':
                            observation['revision_count']+=1
        terminal={'task.completed':'completed','task.category_assessed':'completed',
            'task.canceled':'canceled','task.failed':'failed'}
        starts=('elapsed_bucket' in metrics and 'task.run_started' in types and observation['start_event_sequence'] is None
            and observation['terminal']=='incomplete')
        ends=next((terminal[kind] for kind in types if kind in terminal),None)
        first_end=ends is not None and observation['terminal']=='incomplete'
        if starts:
            observation['start_event_sequence']=next(event['sequence'] for event in events if event['event_type']=='task.run_started')
        if 'elapsed_bucket' in metrics and (starts or first_end and observation['start_sample'] is not None):
            scope=repository.command_scope.context
            try:
                sample=NativeLearningClock(scope.installation_id,scope.repository_locator_digest).sample()
                sample['ticks_ns']=str(sample['ticks_ns'])
                if starts:
                    start=next(event for event in events if event['event_type']=='task.run_started')
                    observation['start_sample']={**sample,'event_sequence':start['sequence'],'event_digest':start['event_digest']}
                if first_end:
                    end=next(event for event in events if event['event_type'] in terminal)
                    observation['terminal_sample']={**sample,'event_sequence':end['sequence'],'event_digest':end['event_digest']}
                observation['clock_availability']='sampled'
                if first_end:
                    def clock_part(value: dict[str, object]) -> dict[str, object]:
                        return {key:(int(value[key]) if key=='ticks_ns' else value[key])
                            for key in ('clock_kind','clock_domain_digest','ticks_ns')}
                    duration=clock_duration_ns(clock_part(observation['start_sample']),clock_part(observation['terminal_sample']))
                    observation['clock_availability']='observed' if duration is not None else 'incompatible-endpoints'
            except ClockUnavailable:
                # Clock failure never manufactures a duration or blocks valid work.
                if starts:observation['start_sample']=None
                observation['clock_availability']='unavailable'
        if ends is not None and observation['terminal']=='incomplete':
            observation['terminal']=ends
            if 'elapsed_bucket' in metrics and observation['start_event_sequence'] is None:
                observation['clock_availability']='missing-start'
    observation['last_observed_sequence']=events[-1]['sequence']
    observation['last_head_digest']=events[-1]['event_digest']
    observation['last_transaction_id']=batch.transaction_id
    policy.validate_record(observation)
    body=canonical_json(observation)
    if length[0]-len(raw.encode())+len(body.encode())>policy.limits['max_aggregate_bytes']:
        # Corrupt or obsolete rows cannot block the ordinary task. Their stale
        # cursor prevents any later capture from treating the window as complete.
        return
    connection.execute('UPDATE pmf_aggregates SET observation_json=?,observation_digest=?,retained_at_ns=? '
        'WHERE task_id=? AND policy_digest=? AND consent_generation=?',
        (body,semantic_record_digest(observation),str(now),batch.task_id,policy.digest,consent['generation']))
    from .security import SecurityStateRepository
    SecurityStateRepository._refresh_learning_subject_locked(connection,batch.task_id,policy.digest,now,policy.limits['max_row_bytes'])
    policy.require_current()
