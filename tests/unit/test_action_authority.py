"""Closed action decision contracts; none of these values is a credential."""
from __future__ import annotations

import unittest
from unittest import mock

from graph_engineering.core.action_authority import (
    ActionAuthorityError, ActionAuthorityPolicy, ActionHumanRequestV1,
    ActionHumanDecisionV1, AuthorityChallenge, AuthorityReceipt,
    require_epoch, require_transition, signed,
)

D = 'sha256-jcs-v1:' + '1' * 64


def challenge(**changes):
    body = dict(schema_version='1.0.0', request_id='request:1', task_id='task:1',
        action_id='action:1', owner_id='owner:1', runtime_kind='codex',
        runtime_lineage_id='lineage:1', prepared_action_digest=D, action_kind='commit',
        resources=['repo:1'], baseline_digest=D, snapshot_digest=D, task_revision=1,
        journal_revision=1, security_state_digest=D, installation_id='installation:1',
        repository_id='repository:1', activation_epoch=1, policy_digest=D,
        created_at_ns='1791244800000000000', expires_at_ns='1791245400000000000')
    body.update(changes)
    return AuthorityChallenge.from_dict(signed('challenge', body))


def request(**changes):
    body = dict(schema_version='1.0.0', challenge=challenge().to_dict(),
        invocation_nonce='a' * 64, invocation_generation=1, session_id='session:1',
        runtime_lineage_id='lineage:1', dispatched_at_ns='1791244800000000001')
    body.update(changes)
    return ActionHumanRequestV1.from_dict(signed('request', body))


def decision(req, **changes):
    ch = req.challenge
    body = dict(schema_version='1.0.0', request_id=ch.request_id, task_id=ch.task_id,
        owner_id=ch.owner_id, decision_kind='action-authority',
        challenge_digest=ch.challenge_digest, request_digest=req.request_digest,
        invocation_nonce=req.invocation_nonce, invocation_generation=req.invocation_generation,
        session_id=req.session_id, runtime_lineage_id=req.runtime_lineage_id,
        status='approved', decision_ref='decision:1')
    body.update(changes)
    return ActionHumanDecisionV1.from_dict(signed('decision', body))


class ActionAuthorityContractTests(unittest.TestCase):
    def test_closed_contracts(self):
        good = challenge().to_dict()
        for bad in ({**good, 'approved': True}, {k:v for k,v in good.items() if k!='owner_id'},
                    {**good, 'schema_version':'1.0'}):
            with self.subTest(bad=tuple(bad)):
                with self.assertRaises(ActionAuthorityError):AuthorityChallenge.from_dict(bad)
        with self.assertRaises(ActionAuthorityError):challenge(task_revision=True)
        for bad in (1791244800000000000, '01', '-1', '9223372036854775808'):
            with self.assertRaises((ActionAuthorityError, ValueError)):challenge(created_at_ns=bad)
        with self.assertRaises(ActionAuthorityError):challenge(resources=['z','a'])
        for oversized in ('x' * 65537, ['r'] * 65537):
            bad = {**good, 'resources': oversized}
            with mock.patch('graph_engineering.core.action_authority.canonical_bytes', side_effect=AssertionError('must bound first')):
                with self.assertRaises(ActionAuthorityError) as error:
                    AuthorityChallenge.from_dict(bad)
            self.assertEqual(error.exception.code,'capacity_exhausted')
        nested = []
        for _ in range(10):nested = [nested]
        with self.assertRaises(ActionAuthorityError) as error:
            AuthorityChallenge.from_dict({**good,'resources':nested})
        self.assertEqual(error.exception.code,'capacity_exhausted')


    def test_digest_binding(self):
        req=request();value=decision(req).to_dict();value['owner_id']='owner:2'
        with self.assertRaises(ActionAuthorityError):ActionHumanDecisionV1.from_dict(value)
        value=req.to_dict();value['challenge']['action_kind']='push'
        with self.assertRaises(ActionAuthorityError):ActionHumanRequestV1.from_dict(value)

    def test_nonce_session_binding(self):
        req=request();decision(req).require_request(req)
        for fields in ({'invocation_nonce':'b'*64},{'session_id':'session:2'},
                       {'invocation_generation':2},{'runtime_lineage_id':'lineage:2'},
                       {'task_id':'task:2'},{'request_digest':D}):
            with self.subTest(fields=fields):
                with self.assertRaises(ActionAuthorityError):decision(req,**fields).require_request(req)
        with self.assertRaises(ActionAuthorityError):decision(req,decision_kind='generic')

    def test_terminal_transitions(self):
        for state in ('rejected','revoked','expired'):
            with self.assertRaises(ActionAuthorityError):require_transition(state,'attempt')
            with self.assertRaises(ActionAuthorityError):require_transition(state,'approved')
        require_transition('approved','revoked')
        require_transition('attempt','pending')
        with self.assertRaises(ActionAuthorityError):require_transition('created','approved')

    def test_exact_request_conflict(self):
        a=challenge();self.assertEqual(a,challenge())
        self.assertNotEqual(a.challenge_digest,challenge(action_kind='push').challenge_digest)
        with self.assertRaises(ActionAuthorityError):a.require_same(challenge(action_kind='push'))

    def test_policy_bounds(self):
        body=dict(schema_version='1.0.0',policy_id='authority:default',max_requests=1024,
            max_attempts=16,max_events=40,max_record_bytes=65536,max_validity_seconds=600)
        policy=ActionAuthorityPolicy.from_dict(signed('policy',body))
        policy.require_admission(request_count=1023,event_count=37,attempt_count=15)
        for fields in ({'request_count':1024},{'event_count':38},{'attempt_count':16}):
            values=dict(request_count=0,event_count=0,attempt_count=0);values.update(fields)
            with self.assertRaises(ActionAuthorityError):policy.require_admission(**values)
        with self.assertRaises(ActionAuthorityError):ActionAuthorityPolicy.from_dict(signed('policy',{**body,'max_attempts':True}))

    def test_receipt_status(self):
        body=dict(schema_version='1.0.0',request_id='request:1',task_id='task:1',action_id='action:1',
            status='pending',generation=1,ledger_sequence=3,event_digest=D,authority_digest=None,
            post_security_digest=None,post_journal_revision=None,installation_id='installation:1',
            repository_id='repository:1',activation_epoch=1)
        AuthorityReceipt.from_dict(signed('receipt',body))
        with self.assertRaises(ActionAuthorityError):AuthorityReceipt.from_dict(signed('receipt',{**body,'status':'approved'}))
        full = dict(authority_digest=D,post_security_digest=D,post_journal_revision=2)
        for status in ('pending','rejected'):
            with self.assertRaises(ActionAuthorityError):
                AuthorityReceipt.from_dict(signed('receipt',{**body,**full,'status':status}))
        for status in ('revoked','expired'):
            AuthorityReceipt.from_dict(signed('receipt',{**body,'status':status}))
            AuthorityReceipt.from_dict(signed('receipt',{**body,**full,'status':status}))
            with self.assertRaises(ActionAuthorityError):
                AuthorityReceipt.from_dict(signed('receipt',{**body,'status':status,'authority_digest':D}))


    def test_epoch_tuple(self):
        expected=('installation:1','repository:1',2)
        require_epoch(expected,expected)
        for other in (('installation:1','repository:1',1),('installation:2','repository:1',2)):
            with self.assertRaises(ActionAuthorityError):require_epoch(expected,other)
