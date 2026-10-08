import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.release_state import changed_files, classify
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
        self.assertEqual(classify('source', 'bot', 'source', 'chore(release): v0.2.5', '0.2.5',
                                 ['VERSION', 'README.md', 'VOICE.md', 'PROVENANCE.json']), '0.2.5')

    def test_bot_subject_cannot_reuse_native_gate_after_executable_changes(self):
        for name in ['zapret.py', 'discord_udp.py', 'scripts/package.py', '.github/workflows/release.yml']:
            with self.subTest(name=name):
                self.assertIsNone(classify('source', 'bot', 'source', 'chore(release): v0.2.5', '0.2.5', ['VERSION', name]))

    def test_explicit_first_stable_commit_publishes_exact_requested_version(self):
        self.assertEqual(classify('stable', 'stable', 'previous', 'chore(release): v1.0.0', '1.0.0',
                                 ['zapret.py', 'VERSION']), '1.0.0')

    def test_renamed_executable_cannot_hide_its_deleted_path_as_metadata(self):
        if shutil.which('git') is None:
            self.skipTest('Git CLI unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()

            git('init', '-q')
            git('config', 'user.name', 'Release test')
            git('config', 'user.email', 'release-test@example.invalid')
            (root / 'zapret.py').write_text('# executable source\n', encoding='utf-8')
            git('add', '.')
            git('commit', '-qm', 'source')
            source = git('rev-parse', 'HEAD')
            (root / 'zapret.py').rename(root / 'README.md')
            git('add', '-A')
            git('commit', '-qm', 'chore(release): v1.0.0')
            head = git('rev-parse', 'HEAD')
            changed = changed_files(root, source, head)
            self.assertIn('zapret.py', changed)
            self.assertIn('README.md', changed)
            self.assertIsNone(classify(source, head, source, 'chore(release): v1.0.0', '1.0.0', changed))

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
