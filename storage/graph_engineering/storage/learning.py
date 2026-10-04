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
        'revision_count':0,'human_interruption_count':0,'start_sample':None,'terminal_sample':None,
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


def _execute_owner_request(repository, request, runtime, policy):
    """Authenticated, bounded receipt and consent mutation in one DB transaction."""
    binding=_binding(runtime)
    repository.command_scope.require_current()
    with repository._factory.open('application') as connection:
        with connection.transaction():
            head=_authorized_head(connection,request['task_id'],runtime)
            require_schema(connection)
            consent=_consent(connection,request['task_id'],policy)
            if consent is not None and consent['binding']!=binding:
                raise LearningError('LEARNING_AUTH')
            digest=request_digest(request)
            receipts=[] if consent is None else consent['receipts']
            for prior in receipts:
                if type(prior) is not dict or set(prior)!={'request_id','request_digest','result'}:
                    raise LearningError('LEARNING_SOURCE')
                if prior['request_id']==request['request_id']:
                    require_replay_match(prior['request_digest'],digest)
                    policy.require_current()
                    runtime.require_issued()
                    return prior['result']
            generation=0 if consent is None else consent['generation']
            if request.get('expected_generation')!=generation:
                raise LearningError('LEARNING_CONFLICT')
            operation=request['operation']
            # A live grant always leaves one bounded receipt slot for revocation.
            reserve=0 if operation=='revoke_learning' else 1
            if len(receipts)>=policy.limits['max_rows_per_task']-reserve:
                raise LearningError('LEARNING_BOUND')
            now=strict_trusted_now(connection)
            if operation not in {'grant_learning','revoke_learning','record_learning_context'}:
                raise LearningError('LEARNING_OPERATION_UNAVAILABLE')
            generation+=int(operation!='record_learning_context')
            if generation>2**53-1:
                raise LearningError('LEARNING_BOUND')
            source_sequence=head[1]
            context_result=None
            if operation=='record_learning_context':
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
            result={'operation':operation,'generation':generation,'state':state,'source_sequence':head[1]}
            if context_result is not None:
                result.update(context_result)
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
                if observation['availability']!='source-gap':
                    observation['availability']='complete'
            if observation['availability']=='complete' and observation['current_prd_sequence'] is not None:
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
                    def clock_part(value):
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
    connection.execute('UPDATE pmf_aggregates SET observation_json=?,observation_digest=? '
        'WHERE task_id=? AND policy_digest=? AND consent_generation=?',
        (body,semantic_record_digest(observation),batch.task_id,policy.digest,consent['generation']))
    policy.require_current()
