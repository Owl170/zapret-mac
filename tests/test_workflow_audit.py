import io
import unittest

from scripts.release_state import classify
from scripts.run_tests import counts, run_suite


class WorkflowAuditTests(unittest.TestCase):
    def test_skipped_and_expected_failure_tests_are_not_reported_as_passed(self):
        calls = []

        class Fixture(unittest.TestCase):
            def test_success(self):
                calls.append('success')

            @unittest.skip('not supported')
            def test_skip(self):
                raise AssertionError('a skipped test must not run')

            @unittest.expectedFailure
            def test_expected_failure(self):
                self.fail('known limitation')

        result = run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Fixture), io.StringIO())
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(counts(result)['run'], 3)
        self.assertEqual(counts(result)['passed'], 1)
        self.assertEqual(counts(result)['skipped'], 1)
        self.assertEqual(counts(result)['expected_failures'], 1)
        self.assertEqual(calls, ['success'])

    def test_failed_subtests_do_not_corrupt_successful_test_count(self):
        class Fixture(unittest.TestCase):
            def test_success(self):
                pass

            def test_two_failures(self):
                for value in range(2):
                    with self.subTest(value=value):
                        self.fail('failure')

        result = run_suite(unittest.defaultTestLoader.loadTestsFromTestCase(Fixture), io.StringIO())
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(counts(result)['run'], 2)
        self.assertEqual(counts(result)['failures'], 2)
        self.assertEqual(counts(result)['passed'], 1)

    def test_original_source_commit_starts_a_new_release(self):
        self.assertEqual(classify('source', 'source', 'previous', 'fix: UDP path', '0.2.4'), '')

    def test_rerun_after_bot_push_resumes_the_same_version(self):
        self.assertEqual(classify('source', 'bot', 'source', 'chore(release): v0.2.5', '0.2.5'), '0.2.5')

    def test_manual_dispatch_on_bot_commit_resumes_existing_version(self):
        self.assertEqual(classify('bot', 'bot', 'source', 'chore(release): v0.2.5', '0.2.5'), '0.2.5')

    def test_stale_run_cannot_modify_unrelated_new_main(self):
        self.assertIsNone(classify('old-source', 'new-source', 'old-source', 'fix: unrelated', '0.2.4'))
        self.assertIsNone(classify('old-source', 'bot', 'new-source', 'chore(release): v0.2.5', '0.2.5'))

    def test_resume_rejects_version_inconsistent_with_commit(self):
        with self.assertRaisesRegex(ValueError, 'VERSION disagree'):
            classify('source', 'bot', 'source', 'chore(release): v0.2.5', '0.2.6')

    def test_lookalike_commit_is_not_a_release_resume(self):
        for subject in ['chore(release): v0.02.5', 'chore(release): v0.2.5-beta',
                        'chore(release): v0.2.5 extra', 'chore: release v0.2.5']:
            with self.subTest(subject=subject):
                self.assertIsNone(classify('source', 'other', 'source', subject, '0.2.5'))


if __name__ == '__main__':
    unittest.main()
