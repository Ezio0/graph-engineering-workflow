"""Bounded append-only action decision history in the repository transaction."""
from __future__ import annotations

import json
import sqlite3

from graph_engineering.core.action_authority import (
    ActionAuthorityError, ActionAuthorityPolicy, AuthorityChallenge, AuthorityReceipt,
    ActionHumanRequestV1, ActionHumanDecisionV1, require_transition, require_epoch,
    signed, _bounded_shape,
)
from .codec import canonical_json, parse_canonical_json, semantic_record_digest
from .connection import ConnectionFactory


_TABLE = '''CREATE TABLE action_authority_events (
request_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=1),
event_kind TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>=0),
body_json TEXT NOT NULL, event_digest TEXT NOT NULL,
PRIMARY KEY(request_id,sequence))'''
_INDEXES = (
    "CREATE INDEX action_authority_task ON action_authority_events(json_extract(body_json,'$.challenge.task_id'),json_extract(body_json,'$.challenge.action_id'))",
    "CREATE INDEX action_authority_digest ON action_authority_events(json_extract(body_json,'$.authority.authority_digest'))",
)
_FIELDS = frozenset(('schema_version request_id sequence event_kind generation previous_event_digest '
    'challenge invocation decision authority post_security_digest post_journal_revision').split())


def installed_policy() -> ActionAuthorityPolicy:
    from graph_engineering import _action_authority_installation_policy
    raw = _action_authority_installation_policy()
    if len(raw) > 65536:
        raise ActionAuthorityError('capacity_exhausted')
    try:
        return ActionAuthorityPolicy.from_dict(json.loads(raw))
    except (UnicodeError, json.JSONDecodeError):
        raise ActionAuthorityError('integrity_error') from None


def _require_schema(connection):
    marker = connection.execute("SELECT version FROM schema_versions WHERE component='action-authority'").fetchone()
    if marker != ('1.0',):
        raise ActionAuthorityError('upgrade_required')
    expected = {'action_authority_events':_TABLE,
        'action_authority_task':_INDEXES[0], 'action_authority_digest':_INDEXES[1]}
    for name, sql in expected.items():
        row = connection.execute('SELECT sql FROM sqlite_master WHERE name=?',(name,)).fetchone()
        if row is None or row[0] != sql:
            raise ActionAuthorityError('integrity_error')


def _initialize_schema(connection, fault):
    marker = connection.execute("SELECT version FROM schema_versions WHERE component='action-authority'").fetchone()
    present = connection.execute("SELECT name FROM sqlite_master WHERE name IN ('action_authority_events','action_authority_task','action_authority_digest')").fetchall()
    if marker is not None or present:
        _require_schema(connection)
        return
    connection.execute(_TABLE)
    for sql in _INDEXES:
        connection.execute(sql)
    fault('action_authority.schema_before_marker')
    connection.execute("INSERT INTO schema_versions(component,version,applied_at) VALUES('action-authority','1.0','initial')")
    _require_schema(connection)


class ActionAuthorityLedger:
    """Private write helpers require a caller-owned repository transaction."""

    def __init__(self, factory: ConnectionFactory, policy: ActionAuthorityPolicy) -> None:
        if type(factory) is not ConnectionFactory or type(policy) is not ActionAuthorityPolicy:
            raise ActionAuthorityError('invalid_request')
        self.factory = factory
        self.policy = policy

    def _epoch(self):
        from .migration import InstallationCommandScope
        scope = self.factory._command_scope
        if type(scope) is not InstallationCommandScope:
            raise ActionAuthorityError('epoch_changed')
        scope.require_current()
        return (scope.installation_id, scope.repository_id, scope.activation_epoch)

    def _read_locked(self, connection, request_id):
        _require_schema(connection)
        sizes = connection.execute('SELECT length(CAST(body_json AS BLOB)),length(CAST(event_kind AS BLOB)),length(CAST(event_digest AS BLOB)) FROM action_authority_events WHERE request_id=? ORDER BY sequence LIMIT ?',
            (request_id,self.policy.max_events+1)).fetchall()
        if len(sizes)>self.policy.max_events or any(n[0]>self.policy.max_record_bytes or n[1]>32 or n[2]>78 for n in sizes):
            raise ActionAuthorityError('capacity_exhausted')
        rows=connection.execute('SELECT sequence,event_kind,generation,body_json,event_digest FROM action_authority_events WHERE request_id=? ORDER BY sequence LIMIT ?',
            (request_id,self.policy.max_events+1)).fetchall()
        events=[]
        for sequence,kind,generation,raw,digest in rows:
            try:
                body=parse_canonical_json(raw)
                _bounded_shape(body)
            except (ValueError,TypeError,RecursionError):
                raise ActionAuthorityError('integrity_error') from None
            if (type(body) is not dict or set(body)!=_FIELDS or body['schema_version']!='1.0.0'
                    or sequence != len(events)+1 or body['sequence']!=sequence
                    or body['request_id']!=request_id or body['event_kind']!=kind
                    or type(generation) is not int or body['generation']!=generation
                    or body['previous_event_digest']!=(events[-1]['event_digest'] if events else None)
                    or semantic_record_digest(body)!=digest):
                raise ActionAuthorityError('integrity_error')
            ch=AuthorityChallenge.from_dict(body['challenge'])
            if ch.request_id!=request_id:
                raise ActionAuthorityError('integrity_error')
            if events:
                prior=events[-1]
                AuthorityChallenge.from_dict(prior['challenge']).require_same(ch)
                require_transition(prior['event_kind'],kind)
                expected=prior['generation']+(kind in {'attempt','revoked','expired'})
                if generation != expected:
                    raise ActionAuthorityError('integrity_error')
            elif kind!='created' or generation!=0:
                raise ActionAuthorityError('integrity_error')
            invocation=body['invocation']
            if invocation is not None:
                req=ActionHumanRequestV1.from_dict(invocation)
                req.challenge.require_same(ch)
                if req.invocation_generation > generation:
                    raise ActionAuthorityError('integrity_error')
            if body['decision'] is not None:
                if invocation is None:
                    raise ActionAuthorityError('integrity_error')
                ActionHumanDecisionV1.from_dict(body['decision']).require_request(req)
            if kind in {'approved','pending','rejected'} and (
                    body['decision'] is None or body['decision']['status']!=kind):
                raise ActionAuthorityError('integrity_error')
            if kind in {'created','attempt','pending','rejected'} and body['authority'] is not None:
                raise ActionAuthorityError('integrity_error')
            if kind=='approved' and body['authority'] is None:
                raise ActionAuthorityError('integrity_error')
            self._require_evolution(body,events[-1] if events else None)
            self._require_grant(body,ch)
            self.receipt({**body,'event_digest':digest})
            events.append({**body,'event_digest':digest})
        return events

    @staticmethod
    def _require_grant(body, ch):
        if body['event_kind']=='approved' and body['post_journal_revision']!=ch.journal_revision+1:
            raise ActionAuthorityError('integrity_error')
        if body['authority'] is None:
            return
        import datetime
        from graph_engineering import _installation_owned_resources
        from graph_engineering.core.actions import AuthorityEnvelope
        from graph_engineering.core.action_authority import timestamp_ns
        from graph_engineering.core.contracts.resources import ResourceProfile, CostSchedule, WorkContext
        profile,schedule=_installation_owned_resources(('config/contracts/resource-profile-v1.json',
            'config/contracts/cost-schedule-v1.json'))
        context=WorkContext(ResourceProfile.from_dict(json.loads(profile)),CostSchedule.from_dict(json.loads(schedule)))
        try:
            authority=AuthorityEnvelope.from_dict(body['authority'],context=context)
            def stamp(value: str) -> str:
                return datetime.datetime.fromtimestamp(timestamp_ns(value)//1_000_000_000,
                    datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
            expected_id='authority:'+semantic_record_digest(dict(installation_id=ch.installation_id,
                repository_id=ch.repository_id,activation_epoch=ch.activation_epoch,
                request_id=ch.request_id)).split(':')[-1]
            if (authority.authority_id!=expected_id or authority.status!='active'
                    or authority.task_id!=ch.task_id or authority.owner_id!=ch.owner_id
                    or authority.runtime_kind!=ch.runtime_kind or authority.runtime_lineage_id!=ch.runtime_lineage_id
                    or authority.prepared_action_digest!=ch.prepared_action_digest
                    or authority.authorized_action_kind!=ch.action_kind
                    or tuple(authority.authorized_resources)!=tuple(ch.resources)
                    or authority.baseline_digest!=ch.baseline_digest or authority.snapshot_digest!=ch.snapshot_digest
                    or authority.issued_at!=stamp(ch.created_at_ns) or authority.expires_at!=stamp(ch.expires_at_ns)):
                raise ValueError('authority challenge binding differs')
        except (ValueError,TypeError,OverflowError):
            raise ActionAuthorityError('integrity_error') from None

    @staticmethod
    def _require_evolution(body, prior):
        kind=body['event_kind']
        grant=('authority','post_security_digest','post_journal_revision')
        if kind=='created':
            valid=all(body[k] is None for k in ('invocation','decision',*grant))
        elif kind=='attempt':
            invocation=body['invocation']
            valid=(invocation is not None and invocation['invocation_generation']==body['generation']
                and body['decision'] is None and all(body[k] is None for k in grant)
                and (prior['invocation'] is None
                     or invocation['invocation_nonce']!=prior['invocation']['invocation_nonce']))
        elif kind in {'pending','approved','rejected'}:
            valid=(prior['event_kind']=='attempt' and body['invocation']==prior['invocation']
                and body['decision'] is not None and body['decision']['status']==kind
                and (all(body[k] is not None for k in grant) if kind=='approved'
                     else all(body[k] is None for k in grant)))
        else:
            valid=(all(body[k]==prior[k] for k in ('invocation','decision','authority'))
                and (all(body[k] is None for k in grant) if body['authority'] is None
                     else all(body[k] is not None for k in grant)))
        if not valid:
            raise ActionAuthorityError('integrity_error')

    def _validate_order_locked(self, connection, capture_budget=None, *, max_rows=None):
        proofs=_order_proofs_locked(connection,self.policy,max_rows=max_rows,capture_budget=capture_budget)
        if proofs is None:return None
        chain=_partition(proofs,self._epoch())
        return {'watermark':_watermark(chain,self._epoch()),'chain':chain}

    def _order_watermark_locked(self, connection, capture_budget=None, *, max_rows=None):
        value=self._validate_order_locked(connection,capture_budget,max_rows=max_rows)
        return None if value is None else value['watermark']

    def _append_order_locked(self, connection, event, prior):
        self.factory._require_owned_transaction(connection)
        chain=prior['chain'];epoch=self._epoch();ordinal=len(chain)
        if ordinal>2**53-1:raise ActionAuthorityError('capacity_exhausted')
        body=dict(schema_version='1.0.0',kind='event',order_epoch=_order_epoch(epoch),ordinal=ordinal,
            previous_order_digest=chain[-1]['order_digest'],request_id=event['request_id'],
            request_sequence=event['sequence'],ledger_event_digest=event['event_digest'])
        connection.execute('INSERT INTO action_authority_order VALUES(?,?,?,?,?,?,?,?,?)',
            (_order_epoch(epoch),ordinal,'event',event['request_id'],event['sequence'],event['event_digest'],
             body['previous_order_digest'],canonical_json(body),semantic_record_digest(body)))

    def _insert_locked(self, connection, body):
        prior=self._validate_order_locked(connection)
        if prior is not None and connection.execute("SELECT count(*) FROM action_authority_order").fetchone()[0]>=self.policy.max_requests*self.policy.max_events:
            raise ActionAuthorityError('capacity_exhausted')
        _bounded_shape(body,max_bytes=self.policy.max_record_bytes)
        raw=canonical_json(body)
        if len(raw.encode())>self.policy.max_record_bytes:
            raise ActionAuthorityError('capacity_exhausted')
        digest=semantic_record_digest(body)
        if prior is not None:
            if len(body['request_id'].encode())+len(digest)+64>1024:
                raise ActionAuthorityError('capacity_exhausted')
            projected=dict(schema_version='1.0.0',kind='event',order_epoch=prior['watermark']['order_epoch'],
                ordinal=len(prior['chain']),previous_order_digest=prior['watermark']['order_digest'],
                request_id=body['request_id'],request_sequence=body['sequence'],ledger_event_digest=digest)
            if len(canonical_json(projected).encode())>1024:
                raise ActionAuthorityError('capacity_exhausted')
        try:
            connection.execute('INSERT INTO action_authority_events(request_id,sequence,event_kind,generation,body_json,event_digest) VALUES(?,?,?,?,?,?)',
                (body['request_id'],body['sequence'],body['event_kind'],body['generation'],raw,digest))
        except sqlite3.IntegrityError:
            raise ActionAuthorityError('stale_binding') from None
        event={**body,'event_digest':digest}
        if prior is not None:self._append_order_locked(connection,event,prior)
        return event

    def _create_locked(self, connection, challenge):
        self.factory._require_owned_transaction(connection)
        if type(challenge) is not AuthorityChallenge:
            raise ActionAuthorityError('invalid_request')
        _require_schema(connection)
        require_epoch((challenge.installation_id,challenge.repository_id,challenge.activation_epoch),self._epoch())
        existing=self._read_locked(connection,challenge.request_id)
        if existing:
            AuthorityChallenge.from_dict(existing[0]['challenge']).require_same(challenge)
            if existing[-1]['event_kind'] in {'rejected','revoked','expired'}:
                raise ActionAuthorityError('terminal_request')
            return existing[-1]
        identities=connection.execute('SELECT request_id FROM action_authority_events GROUP BY request_id LIMIT ?',
            (self.policy.max_requests,)).fetchall()
        self.policy.require_admission(request_count=len(identities),event_count=0,attempt_count=0)
        return self._insert_locked(connection,dict(schema_version='1.0.0',request_id=challenge.request_id,
            sequence=1,event_kind='created',generation=0,previous_event_digest=None,
            challenge=challenge.to_dict(),invocation=None,decision=None,authority=None,
            post_security_digest=None,post_journal_revision=None))

    def _append_locked(self, connection, previous, kind, **updates):
        self.factory._require_owned_transaction(connection)
        current=self._read_locked(connection,previous['request_id'])
        if not current or current[-1]['event_digest']!=previous['event_digest']:
            raise ActionAuthorityError('stale_binding')
        require_transition(previous['event_kind'],kind)
        count=len(current)
        if count>=self.policy.max_events or (kind in {'attempt','pending'} and count+2>=self.policy.max_events):
            raise ActionAuthorityError('capacity_exhausted')
        if kind=='attempt' and sum(e['event_kind']=='attempt' for e in current)>=self.policy.max_attempts:
            raise ActionAuthorityError('capacity_exhausted')
        if set(updates)-{'invocation','decision','authority','post_security_digest','post_journal_revision'}:
            raise ActionAuthorityError('invalid_request')
        body={k:v for k,v in previous.items() if k!='event_digest'}
        body.update(updates)
        body.update(sequence=count+1,event_kind=kind,
            generation=previous['generation']+(kind in {'attempt','revoked','expired'}),
            previous_event_digest=previous['event_digest'])
        self._require_evolution(body,previous)
        self._require_grant(body,AuthorityChallenge.from_dict(body['challenge']))
        self.receipt({**body,'event_digest':semantic_record_digest(body)})
        return self._insert_locked(connection,body)

    @staticmethod
    def receipt(event: dict[str,object]) -> AuthorityReceipt:
        ch=event['challenge']
        status=event['event_kind']
        if status in {'created','attempt'}:
            status='pending'
        authority=event['authority']
        return AuthorityReceipt.from_dict(signed('receipt',dict(schema_version='1.0.0',
            request_id=event['request_id'],task_id=ch['task_id'],action_id=ch['action_id'],
            status=status,generation=event['generation'],ledger_sequence=event['sequence'],
            event_digest=event['event_digest'],authority_digest=None if authority is None else authority['authority_digest'],
            post_security_digest=event['post_security_digest'],post_journal_revision=event['post_journal_revision'],
            installation_id=ch['installation_id'],repository_id=ch['repository_id'],activation_epoch=ch['activation_epoch'])))

    def _validate_authorized_locked(self, connection, journal, action_id):
        """Re-read one grant under writer serialization; membership alone is insufficient."""
        from .security import SecurityStateRepository
        from .clock import strict_trusted_now
        from graph_engineering.core.action_authority import timestamp_ns
        from graph_engineering.core.security.identity import SecurityBinding
        self.factory._require_owned_transaction(connection)
        _require_schema(connection)
        record=journal._load(connection,action_id)
        if record.state!='authorized' or record.authority is None:
            raise ActionAuthorityError('stale_binding')
        authority=record.authority
        rows=connection.execute("SELECT DISTINCT request_id FROM action_authority_events WHERE json_extract(body_json,'$.authority.authority_digest')=? LIMIT 2",
            (authority.authority_digest,)).fetchall()
        if len(rows)!=1:
            raise ActionAuthorityError('stale_binding')
        history=self._read_locked(connection,rows[0][0])
        head=history[-1]
        ch=AuthorityChallenge.from_dict(head['challenge'])
        if head['event_kind']!='approved' or head['authority']!=journal.authority_document(authority):
            raise ActionAuthorityError('terminal_request')
        require_epoch((ch.installation_id,ch.repository_id,ch.activation_epoch),self._epoch())
        if ch.policy_digest!=self.policy.policy_digest or timestamp_ns(ch.expires_at_ns)<=strict_trusted_now(connection):
            raise ActionAuthorityError('expired')
        state,_=SecurityStateRepository._load_task_state(connection,ch.task_id,journal._context)
        binding=state['binding'];prepared=record.prepared
        if (binding.get('binding_digest')!=SecurityBinding.digest_document(binding)
                or binding.get('owner_id')!=ch.owner_id or binding.get('runtime_kind')!=ch.runtime_kind
                or binding.get('runtime_lineage_id')!=ch.runtime_lineage_id
                or binding.get('baselines',{}).get('intent')!=ch.baseline_digest
                or binding.get('snapshot_digest')!=ch.snapshot_digest
                or state['task_snapshot_digest']!=ch.snapshot_digest
                or authority.authority_digest not in state['authority_digests']
                or prepared.action_id!=ch.action_id or prepared.task_id!=ch.task_id
                or prepared.prepared_action_digest!=ch.prepared_action_digest
                or prepared.action_kind!=ch.action_kind or list(prepared.resources)!=list(ch.resources)
                or prepared.baseline_digest!=ch.baseline_digest or prepared.snapshot_digest!=ch.snapshot_digest
                or authority.prepared_action_digest!=ch.prepared_action_digest
                or authority.owner_id!=ch.owner_id or authority.runtime_kind!=ch.runtime_kind
                or authority.runtime_lineage_id!=ch.runtime_lineage_id
                or authority.authorized_action_kind!=ch.action_kind
                or list(authority.authorized_resources)!=list(ch.resources)
                or authority.snapshot_digest!=ch.snapshot_digest or authority.baseline_digest!=ch.baseline_digest):
            raise ActionAuthorityError('stale_binding')
        return record,head

    def _validate_start_locked(self, connection, journal, batch):
        delta=batch.action_journal_delta
        if type(delta) is not dict or delta.get('operation') not in {'start','compensation_start'}:
            raise ActionAuthorityError('invalid_request')
        record,head=self._validate_authorized_locked(connection,journal,delta.get('action_id'))
        if (record.task_id!=batch.task_id or delta.get('expected_revision')!=record.revision
                or delta.get('expected_state')!='authorized'
                or delta.get('authority_digest')!=record.authority.authority_digest
                or delta.get('prepared_digest')!=record.prepared.prepared_action_digest):
            raise ActionAuthorityError('stale_binding')
        if len(batch.events)!=1:
            raise ActionAuthorityError('invalid_request')
        event=batch.events[0];payload=event.get('payload',{})
        if delta['operation']=='start':
            if (batch.claim_delta is None or batch.claim_delta.get('action_id')!=record.action_id
                    or payload.get('action_id')!=record.action_id
                    or payload.get('authority_digest')!=record.authority.authority_digest
                    or payload.get('prepared_action_digest')!=record.prepared.prepared_action_digest
                    or event.get('event_type')!='action.execution_started'):
                raise ActionAuthorityError('invalid_request')
        else:
            if (record.prepared.action_kind!='rollback' or batch.claim_compensation_delta is None
                    or batch.claim_compensation_delta.get('operation')!='start_claim_compensation'
                    or batch.claim_delta is not None
                    or event.get('event_type')!='action.compensation_execution_started'
                    or payload.get('compensation_action_id')!=record.action_id
                    or payload.get('compensation_authority_digest')!=record.authority.authority_digest
                    or payload.get('compensation_prepared_digest')!=record.prepared.prepared_action_digest):
                raise ActionAuthorityError('invalid_request')
        if payload.get('snapshot_digest')!=head['challenge']['snapshot_digest']:
            raise ActionAuthorityError('stale_binding')


_ORDER_TABLE = '''CREATE TABLE action_authority_order (
order_epoch TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0 AND ordinal<=9007199254740991),
kind TEXT NOT NULL CHECK(kind IN ('anchor','event')), request_id TEXT, request_sequence INTEGER,
ledger_event_digest TEXT, previous_order_digest TEXT, body_json TEXT NOT NULL, order_digest TEXT NOT NULL,
PRIMARY KEY(order_epoch,ordinal), UNIQUE(order_epoch,request_id,request_sequence)) STRICT'''
_ORDER_COLUMNS = ['order_epoch','ordinal','kind','request_id','request_sequence',
                  'ledger_event_digest','previous_order_digest','body_json','order_digest']


def _order_schema(connection):
    marker=connection.execute("SELECT version FROM schema_versions WHERE component='action-authority-order'").fetchone()
    present=connection.execute("SELECT sql FROM sqlite_master WHERE name='action_authority_order'").fetchone()
    if marker is None and present is None:return False
    if marker!=('1.0',) or present!=(_ORDER_TABLE,):
        raise ActionAuthorityError('upgrade_required')
    _require_schema(connection)
    return True


def _order_epoch(epoch):
    return semantic_record_digest(dict(zip(('installation_id','repository_id','activation_epoch'),epoch,strict=True)))


def _legacy_seal(rows):
    return semantic_record_digest({'contract':'action-authority-legacy-seal-v1',
        'columns':['request_id','sequence','event_digest'],'rows':rows})


def _order_proofs_locked(connection, policy, *, max_rows=None, capture_budget=None):
    """Global metadata only: never select original ledger body_json."""
    if not _order_schema(connection):return None
    bound=policy.max_requests*policy.max_events
    row_limit=bound if max_rows is None else min(bound,max_rows)
    ledger_size=connection.execute('SELECT count(*),coalesce(sum(length(CAST(request_id AS BLOB))+length(CAST(event_digest AS BLOB))+64),0),'
        'coalesce(max(length(CAST(request_id AS BLOB))+length(CAST(event_digest AS BLOB))+64),0) FROM action_authority_events').fetchone()
    order_size=connection.execute('SELECT count(*),coalesce(sum(length(CAST(body_json AS BLOB))+'
        'length(CAST(order_epoch AS BLOB))+coalesce(length(CAST(request_id AS BLOB)),0)+'
        'coalesce(length(CAST(ledger_event_digest AS BLOB)),0)+coalesce(length(CAST(previous_order_digest AS BLOB)),0)+'
        'length(CAST(order_digest AS BLOB))+128),0),'
        'coalesce(max(max(length(CAST(body_json AS BLOB)),length(CAST(order_epoch AS BLOB)),'
        'coalesce(length(CAST(request_id AS BLOB)),0),coalesce(length(CAST(ledger_event_digest AS BLOB)),0),'
        'coalesce(length(CAST(previous_order_digest AS BLOB)),0),length(CAST(order_digest AS BLOB)))),0) '
        'FROM action_authority_order').fetchone()
    if ledger_size[0]>row_limit or order_size[0]>row_limit or ledger_size[2]>1024 or order_size[2]>1024:
        raise ActionAuthorityError('capacity_exhausted')
    charge=2*ledger_size[1]+order_size[1]+512
    if capture_budget is not None:
        if charge>capture_budget[0]:raise ActionAuthorityError('capacity_exhausted')
        capture_budget[0]-=charge
    # The lengths/counts above precede both body-free metadata materializations.
    metadata=connection.execute('SELECT request_id,sequence,event_digest FROM action_authority_events ORDER BY request_id COLLATE BINARY,sequence').fetchall()
    by_pointer={(request,seq):digest for request,seq,digest in metadata}
    groups={}
    from .codec import require_jcs_digest
    from .errors import RepositoryIntegrityError
    try:
        for row in connection.execute('SELECT '+','.join(_ORDER_COLUMNS)+' FROM action_authority_order ORDER BY order_epoch,ordinal'):
            epoch,ordinal,kind,request,seq,event_digest,previous,raw,digest=row
            body=parse_canonical_json(raw)
            require_jcs_digest(epoch);require_jcs_digest(digest)
            if semantic_record_digest(body)!=digest:raise ValueError('order digest')
            chain=groups.setdefault(epoch,[])
            if ordinal!=len(chain):raise ValueError('order gap')
            if kind=='anchor':
                fields={'schema_version','kind','installation_id','repository_id','activation_epoch','legacy_rows_digest','legacy_row_count'}
                if (ordinal!=0 or set(body)!=fields or body['kind']!='anchor' or body['schema_version']!='1.0.0'
                        or any(x is not None for x in (request,seq,event_digest,previous))
                        or type(body['legacy_row_count']) is not int or not 0<=body['legacy_row_count']<=bound
                        or type(body['activation_epoch']) is not int or not 1<=body['activation_epoch']<=2**53-1
                        or any(type(body[k]) is not str or not 1<=len(body[k])<=128 for k in ('installation_id','repository_id'))
                        or _order_epoch(tuple(body[k] for k in ('installation_id','repository_id','activation_epoch')))!=epoch):
                    raise ValueError('order anchor')
                require_jcs_digest(body['legacy_rows_digest'])
            else:
                fields={'schema_version','kind','order_epoch','ordinal','previous_order_digest','request_id','request_sequence','ledger_event_digest'}
                expected=dict(schema_version='1.0.0',kind='event',order_epoch=epoch,ordinal=ordinal,
                    previous_order_digest=previous,request_id=request,request_sequence=seq,ledger_event_digest=event_digest)
                if (not chain or set(body)!=fields or body!=expected or previous!=chain[-1]['order_digest']
                        or type(seq) is not int or seq<1 or by_pointer.get((request,seq))!=event_digest):
                    raise ValueError('order pointer')
                require_jcs_digest(event_digest)
            chain.append({**body,'order_digest':digest})
    except (ValueError,TypeError,KeyError,RepositoryIntegrityError):
        raise ActionAuthorityError('integrity_error') from None
    if not groups:raise ActionAuthorityError('integrity_error')
    # Anchors seal the complete ledger at activation. Epoch intervals therefore
    # partition the monotone row count, even when several empty epochs share it.
    all_pointers=set()
    for chain in groups.values():
        for event in chain[1:]:
            pointer=(event['request_id'],event['request_sequence'])
            if pointer in all_pointers:raise ActionAuthorityError('integrity_error')
            all_pointers.add(pointer)
    historic={pointer for pointer in by_pointer if pointer not in all_pointers}
    for count in sorted({chain[0]['legacy_row_count'] for chain in groups.values()}):
        peers=[chain for chain in groups.values() if chain[0]['legacy_row_count']==count]
        if count!=len(historic) or sum(bool(chain[1:]) for chain in peers)>1:
            raise ActionAuthorityError('integrity_error')
        legacy=[[request,seq,digest] for request,seq,digest in metadata if (request,seq) in historic]
        seal=_legacy_seal(legacy)
        if any(chain[0]['legacy_rows_digest']!=seal for chain in peers):
            raise ActionAuthorityError('integrity_error')
        for chain in peers:
            historic.update((event['request_id'],event['request_sequence']) for event in chain[1:])
    if historic!=set(by_pointer):raise ActionAuthorityError('integrity_error')
    return {'groups':groups,'metadata':metadata}


def _partition(proofs,epoch):
    chain=proofs['groups'].get(_order_epoch(epoch))
    if chain is None:raise ActionAuthorityError('epoch_changed')
    pointers={(row['request_id'],row['request_sequence']) for row in chain[1:]}
    legacy=[[request,seq,digest] for request,seq,digest in proofs['metadata'] if (request,seq) not in pointers]
    if len(legacy)!=chain[0]['legacy_row_count'] or _legacy_seal(legacy)!=chain[0]['legacy_rows_digest']:
        raise ActionAuthorityError('integrity_error')
    return chain


def _watermark(chain,epoch):
    return dict(order_epoch=_order_epoch(epoch),ordinal=len(chain)-1,order_digest=chain[-1]['order_digest'],
        anchor_digest=chain[0]['order_digest'],**dict(zip(('installation_id','repository_id','activation_epoch'),epoch,strict=True)))


def _initialize_order_schema(connection,factory,epoch,fault):
    """Exclusive installation maintenance; original bodies remain immutable."""
    from .connection import ManagedConnection, _ISSUED_CONNECTION_OWNERS
    if (type(connection) is not ManagedConnection or not connection._in_transaction
            or connection._role!='migration' or _ISSUED_CONNECTION_OWNERS.get(connection) is not factory):
        raise ActionAuthorityError('invalid_request')
    connection._check()
    _require_schema(connection)
    policy=installed_policy()
    enabled=_order_schema(connection)
    if enabled:
        proofs=_order_proofs_locked(connection,policy)
        if _order_epoch(epoch) in proofs['groups']:
            _partition(proofs,epoch)
            return
    else:
        connection.execute(_ORDER_TABLE)
        fault('action_authority.order_after_table')
    # Only this maintenance path validates all original request bodies.
    sizes=connection.execute('SELECT count(*),coalesce(max(length(CAST(body_json AS BLOB))),0),'
        'coalesce(max(length(CAST(request_id AS BLOB))+length(CAST(event_digest AS BLOB))+64),0) FROM action_authority_events').fetchone()
    if sizes[0]>policy.max_requests*policy.max_events or sizes[1]>policy.max_record_bytes or sizes[2]>1024:
        raise ActionAuthorityError('capacity_exhausted')
    ids=connection.execute('SELECT DISTINCT request_id FROM action_authority_events LIMIT ?', (policy.max_requests+1,)).fetchall()
    if len(ids)>policy.max_requests:raise ActionAuthorityError('capacity_exhausted')
    ledger=ActionAuthorityLedger(factory,policy)
    for (request,) in ids:ledger._read_locked(connection,request)
    metadata=connection.execute('SELECT request_id,sequence,event_digest FROM action_authority_events ORDER BY request_id COLLATE BINARY,sequence').fetchall()
    body=dict(schema_version='1.0.0',kind='anchor',**dict(zip(('installation_id','repository_id','activation_epoch'),epoch,strict=True)),
        legacy_rows_digest=_legacy_seal([list(row) for row in metadata]),legacy_row_count=len(metadata))
    connection.execute('INSERT INTO action_authority_order VALUES(?,0,\'anchor\',NULL,NULL,NULL,NULL,?,?)',
        (_order_epoch(epoch),canonical_json(body),semantic_record_digest(body)))
    fault('action_authority.order_after_anchor')
    if not enabled:
        connection.execute("INSERT INTO schema_versions(component,version,applied_at) VALUES('action-authority-order','1.0','initial')")
    fault('action_authority.order_after_marker')
    _partition(_order_proofs_locked(connection,policy),epoch)
