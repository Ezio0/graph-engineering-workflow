"""Closed action-decision data contracts, never standalone authority credentials."""
from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from typing import Self

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.runtime import runtime_record_digest


class ActionAuthorityError(ValueError):
    """Stable failure code without echoing untrusted decision content."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def signed(kind: str, body: Mapping[str, object]) -> dict[str, object]:
    return {**body, kind + '_digest': runtime_record_digest('action-authority-' + kind, body)}


def _integer(value: object, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise ActionAuthorityError('invalid_request')
    return value


def timestamp_ns(value: object) -> int:
    """Canonical decimal strings avoid truncation beyond JCS's safe integers."""
    if (type(value) is not str or re.fullmatch(r'0|[1-9][0-9]{0,18}', value) is None
            or int(value) > 2**63 - 1):
        raise ActionAuthorityError('invalid_request')
    return int(value)


def _text(value: object) -> str:
    if (type(value) is not str or not value or value != value.strip()
            or not value.isascii() or '\x00' in value):
        raise ActionAuthorityError('invalid_request')
    return value


def _digest(value: object) -> str:
    value = _text(value)
    if re.fullmatch(r'sha256-jcs-v1:[0-9a-f]{64}', value) is None:
        raise ActionAuthorityError('invalid_request')
    return value


def _bounded_shape(value: object, *, max_bytes: int = 65536) -> None:
    """Stop before serializing or copying a payload beyond the wire ceiling."""
    remaining = max_bytes

    def visit(item: object, depth: int) -> None:
        nonlocal remaining
        if depth > 8 or remaining <= 0:
            raise ActionAuthorityError('capacity_exhausted')
        remaining -= 1
        if isinstance(item, Mapping):
            if len(item) > remaining:
                raise ActionAuthorityError('capacity_exhausted')
            for key, child in item.items():
                if type(key) is not str:
                    raise ActionAuthorityError('invalid_request')
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif type(item) in {list, tuple}:
            if len(item) > remaining:
                raise ActionAuthorityError('capacity_exhausted')
            for child in item:
                visit(child, depth + 1)
        elif type(item) is str:
            if len(item) > remaining:
                raise ActionAuthorityError('capacity_exhausted')
            for char in item:
                remaining -= (6 if ord(char) < 32 else 2 if char in {'"', '\\'}
                              else len(char.encode('utf-8')))
                if remaining < 0:
                    raise ActionAuthorityError('capacity_exhausted')
        elif item is not None and type(item) not in {int, bool}:
            raise ActionAuthorityError('invalid_request')
        elif type(item) is int and not -(2**53 - 1) <= item <= 2**53 - 1:
            raise ActionAuthorityError('invalid_request')
    try:
        visit(value, 0)
    except UnicodeError:
        raise ActionAuthorityError('invalid_request') from None


class _ClosedRecord:
    __slots__ = ('_data',)
    KIND = ''
    FIELDS: frozenset[str] = frozenset()
    INTEGERS: frozenset[str] = frozenset()
    NULLABLE: frozenset[str] = frozenset()

    def __init__(self, *args: object, **kwargs: object):
        raise TypeError('use from_dict')

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError('immutable record')

    def __getattr__(self, name: str):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name) from None

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and self.to_dict() == other.to_dict()

    def to_dict(self) -> dict[str, object]:
        return thaw(self._data)

    @classmethod
    def from_dict(cls, value: object) -> Self:
        if not isinstance(value, Mapping) or len(value) != len(cls.FIELDS) or set(value) != cls.FIELDS:
            raise ActionAuthorityError('invalid_request')
        _bounded_shape(value)
        row = dict(value)
        try:
            size = len(canonical_bytes(row))
        except (TypeError, ValueError, RecursionError):
            raise ActionAuthorityError('invalid_request') from None
        if size > 65536:
            raise ActionAuthorityError('capacity_exhausted')
        if row['schema_version'] != '1.0.0':
            raise ActionAuthorityError('unsupported_contract')
        for key, item in row.items():
            if key in cls.NULLABLE and item is None:
                continue
            if key.endswith('_at_ns'):
                timestamp_ns(item)
            elif key in cls.INTEGERS:
                _integer(item)
            elif key in {'challenge', 'resources'}:
                continue
            elif key.endswith('_digest'):
                _digest(item)
            else:
                _text(item)
        field = cls.KIND + '_digest'
        unsigned = {k:v for k,v in row.items() if k != field}
        if not hmac.compare_digest(row[field], signed(cls.KIND, unsigned)[field]):
            raise ActionAuthorityError('integrity_error')
        cls._validate(row)
        result = object.__new__(cls)
        object.__setattr__(result, '_data', freeze(row))
        return result

    @classmethod
    def _validate(cls, row: dict[str, object]) -> None:
        del row


class AuthorityChallenge(_ClosedRecord):
    KIND = 'challenge'
    FIELDS = frozenset(('schema_version request_id task_id action_id owner_id runtime_kind '
        'runtime_lineage_id prepared_action_digest action_kind resources baseline_digest '
        'snapshot_digest task_revision journal_revision security_state_digest installation_id '
        'repository_id activation_epoch policy_digest created_at_ns expires_at_ns challenge_digest').split())
    INTEGERS = frozenset(('task_revision journal_revision activation_epoch created_at_ns expires_at_ns').split())

    @classmethod
    def _validate(cls, row):
        resources = row['resources']
        if (type(resources) is not list or not resources
                or any(type(v) is not str for v in resources)
                or resources != sorted(set(resources))):
            raise ActionAuthorityError('invalid_request')
        for value in resources:
            _text(value)
        if timestamp_ns(row['created_at_ns']) >= timestamp_ns(row['expires_at_ns']) or row['activation_epoch'] < 1:
            raise ActionAuthorityError('invalid_request')

    def require_same(self, other: AuthorityChallenge) -> None:
        if type(other) is not AuthorityChallenge or self != other:
            raise ActionAuthorityError('request_conflict')


class ActionHumanRequestV1(_ClosedRecord):
    KIND = 'request'
    FIELDS = frozenset(('schema_version challenge invocation_nonce invocation_generation '
        'session_id runtime_lineage_id dispatched_at_ns request_digest').split())
    INTEGERS = frozenset({'invocation_generation', 'dispatched_at_ns'})

    @property
    def challenge(self) -> AuthorityChallenge:
        return AuthorityChallenge.from_dict(thaw(self._data['challenge']))

    @classmethod
    def _validate(cls, row):
        challenge = AuthorityChallenge.from_dict(row['challenge'])
        if (re.fullmatch(r'[0-9a-f]{64}', row['invocation_nonce']) is None
                or row['invocation_generation'] < 1
                or row['runtime_lineage_id'] != challenge.runtime_lineage_id
                or not timestamp_ns(challenge.created_at_ns) <= timestamp_ns(row['dispatched_at_ns']) < timestamp_ns(challenge.expires_at_ns)):
            raise ActionAuthorityError('decision_mismatch')


class ActionHumanDecisionV1(_ClosedRecord):
    KIND = 'decision'
    FIELDS = frozenset(('schema_version request_id task_id owner_id decision_kind challenge_digest '
        'request_digest invocation_nonce invocation_generation session_id runtime_lineage_id '
        'status decision_ref decision_digest').split())
    INTEGERS = frozenset({'invocation_generation'})

    @classmethod
    def _validate(cls, row):
        if (row['decision_kind'] != 'action-authority'
                or row['status'] not in {'pending','rejected','approved'}
                or re.fullmatch(r'[0-9a-f]{64}', row['invocation_nonce']) is None
                or row['invocation_generation'] < 1):
            raise ActionAuthorityError('decision_mismatch')

    def require_request(self, request: ActionHumanRequestV1) -> None:
        if type(request) is not ActionHumanRequestV1:
            raise ActionAuthorityError('decision_mismatch')
        for key in ('request_id','task_id','owner_id','challenge_digest'):
            if getattr(self,key) != getattr(request.challenge,key):
                raise ActionAuthorityError('decision_mismatch')
        for key in ('request_digest','invocation_nonce','invocation_generation','session_id','runtime_lineage_id'):
            if getattr(self,key) != getattr(request,key):
                raise ActionAuthorityError('decision_mismatch')


class AuthorityReceipt(_ClosedRecord):
    KIND = 'receipt'
    FIELDS = frozenset(('schema_version request_id task_id action_id status generation ledger_sequence '
        'event_digest authority_digest post_security_digest post_journal_revision installation_id '
        'repository_id activation_epoch receipt_digest').split())
    INTEGERS = frozenset({'generation','ledger_sequence','post_journal_revision','activation_epoch'})
    NULLABLE = frozenset({'authority_digest','post_security_digest','post_journal_revision'})

    @classmethod
    def _validate(cls, row):
        if row['status'] not in {'pending','approved','rejected','revoked','expired'}:
            raise ActionAuthorityError('invalid_request')
        grant = tuple(row[k] is not None for k in sorted(cls.NULLABLE))
        if (any(grant) != all(grant)
                or row['status'] == 'approved' and not all(grant)
                or row['status'] in {'pending', 'rejected'} and any(grant)):
            raise ActionAuthorityError('invalid_request')
        if row['ledger_sequence'] < 1 or row['activation_epoch'] < 1:
            raise ActionAuthorityError('invalid_request')


class ActionAuthorityPolicy(_ClosedRecord):
    KIND = 'policy'
    FIELDS = frozenset(('schema_version policy_id max_requests max_attempts max_events '
        'max_record_bytes max_validity_seconds policy_digest').split())
    INTEGERS = frozenset({'max_requests','max_attempts','max_events','max_record_bytes','max_validity_seconds'})

    @classmethod
    def _validate(cls, row):
        if (any(row[k] < 1 for k in cls.INTEGERS) or row['max_record_bytes'] > 65536
                or row['max_events'] < 2 * row['max_attempts'] + 3):
            raise ActionAuthorityError('invalid_request')

    def require_admission(self, *, request_count: int, event_count: int, attempt_count: int) -> None:
        for n in (request_count,event_count,attempt_count):
            _integer(n)
        if (request_count >= self.max_requests or event_count + 2 >= self.max_events
                or attempt_count >= self.max_attempts):
            raise ActionAuthorityError('capacity_exhausted')


def require_transition(previous: str, following: str) -> None:
    transitions = {'created':{'attempt','revoked','expired'},
        'attempt':{'attempt','pending','approved','rejected','revoked','expired'},
        'pending':{'attempt','revoked','expired'}, 'approved':{'revoked','expired'}}
    if following not in transitions.get(previous,set()):
        raise ActionAuthorityError('terminal_request')


def require_epoch(expected: tuple[str,str,int], actual: tuple[str,str,int]) -> None:
    if (type(expected) is not tuple or type(actual) is not tuple or len(expected)!=3
            or len(actual)!=3 or type(expected[2]) is not int or type(actual[2]) is not int
            or expected != actual):
        raise ActionAuthorityError('epoch_changed')
