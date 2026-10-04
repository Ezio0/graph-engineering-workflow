"""Learning isolation exercised through issued runtime sessions and real SQLite."""
from __future__ import annotations

import unittest
from unittest import mock

from graph_engineering.core.learning import LearningError
from tests.integration.test_wp09_learning import learning_stack, learning_request, learning_call
from tests.integration.test_wp07_runtime_parity import session, FIXTURE


class LearningPrivacyTests(unittest.TestCase):
    def test_expired_consent_no_read(self):
        from tests.integration.test_wp09_learning_metric_sources import cancel
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','expiry:grant',expected_generation=0,
                metric_ids=['elapsed_bucket'],expires_at_ns='1000'))
            with factory.open('doctor') as connection:
                before=connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0]
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=1001):
                with mock.patch('graph_engineering.storage.learning._consent') as consent, mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                    cancel(application,active)
                    consent.assert_not_called()
                    sample.assert_not_called()
                with self.assertRaisesRegex(LearningError,'^LEARNING_CONSENT$'):
                    learning_call(application,active,learning_request('record_learning_context','expiry:context',expected_generation=1,
                        expected_context_version=0,abandonment_code='not-stated',prior_task_id=None))
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0],before)

    def test_preallocation_bounds(self):
        with learning_stack() as (application,active,factory,_repository):
            learning_call(application,active,learning_request('grant_learning','bound:grant',expected_generation=0,
                metric_ids=['abandonment'],expires_at_ns='1000'))
            # Fill only via genuine owner operations. Admission must stop before
            # the reserved revocation capacity is consumed, without evicting receipts.
            reached=False
            for version in range(300):
                request=learning_request('record_learning_context',f'bound:context:{version}',expected_generation=1,
                    expected_context_version=version,abandonment_code='not-stated',prior_task_id=None)
                try:learning_call(application,active,request)
                except LearningError as error:
                    self.assertEqual(str(error),'LEARNING_BOUND')
                    reached=True
                    break
            self.assertTrue(reached)
            revoked=learning_call(application,active,learning_request('revoke_learning','bound:revoke',expected_generation=1))
            self.assertEqual(revoked['state'],'revoked')
            with factory.open('doctor') as connection:
                self.assertLessEqual(connection.execute('SELECT length(CAST(receipts_json AS BLOB)) FROM pmf_consents').fetchone()[0],65536)
        # Retained epochs stop a new grant before they consume the maximum
        # future observation. The already granted task must remain usable.
        from tests.integration.test_wp09_learning_metric_sources import approve
        with learning_stack() as (application,active,factory,_repository):
            reached=False
            for generation in range(40):
                try:
                    learning_call(application,active,learning_request('grant_learning',f'epoch:{generation}',
                        expected_generation=generation,metric_ids=['revision_count'],expires_at_ns='1000'))
                except LearningError as error:
                    self.assertEqual(str(error),'LEARNING_BOUND')
                    reached=True
                    break
            self.assertTrue(reached)
            approve(application,active)
            with factory.open('doctor') as connection:
                size=connection.execute('SELECT length(CAST(observation_json AS BLOB))+'
                    'coalesce(length(CAST(derived_json AS BLOB)),0)+length(CAST(retained_epochs_json AS BLOB))+512 '
                    'FROM pmf_aggregates').fetchone()[0]
                self.assertLessEqual(size,16384)
                self.assertEqual(connection.execute('SELECT head_sequence FROM tasks').fetchone()[0],5)

    def test_foreign_identity_before_read(self):
        with learning_stack() as (application, _active, factory, _repository):
            foreign=session(FIXTURE['cells'][1])
            try:
                request=learning_request('grant_learning','foreign:grant',expected_generation=0,
                    metric_ids=['revision_count'],expires_at_ns='1000')
                with mock.patch('graph_engineering.storage.learning._consent') as consent:
                    with self.assertRaisesRegex(LearningError,'^LEARNING_AUTH$'):
                        learning_call(application,foreign,request)
                    consent.assert_not_called()
                with factory.open('doctor') as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM pmf_consents').fetchone()[0],0)
            finally:
                foreign.close()

    def test_clock_rollback(self):
        from graph_engineering.storage.errors import RepositoryIntegrityError
        with learning_stack() as (application,active,factory,_repository):
            request=learning_request('grant_learning','clock:grant',expected_generation=0,
                metric_ids=['revision_count'],expires_at_ns='1000')
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=100):
                learning_call(application,active,request)
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=99):
                with self.assertRaises(RepositoryIntegrityError):
                    learning_call(application,active,learning_request('revoke_learning','clock:revoke',expected_generation=1))
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state,generation FROM pmf_consents').fetchone(),('granted',1))
            from tests.integration.test_wp09_learning_metric_sources import cancel
            with mock.patch('graph_engineering.storage.clock.time.time_ns',return_value=99):
                with mock.patch('graph_engineering.storage.learning_clock.NativeLearningClock.sample') as sample:
                    cancel(application,active)
                    sample.assert_not_called()
            with factory.open('doctor') as connection:
                self.assertGreater(connection.execute('SELECT head_sequence FROM tasks').fetchone()[0],
                    __import__('json').loads(connection.execute('SELECT observation_json FROM pmf_aggregates').fetchone()[0])['last_observed_sequence'])


if __name__=='__main__':
    unittest.main()
