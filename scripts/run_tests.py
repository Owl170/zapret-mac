#!/usr/bin/env python3
"""Run release tests once and report successful, skipped and failed counts."""
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class CountingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = 0

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passed += 1


def run_suite(suite, stream=None):
    return unittest.TextTestRunner(stream=stream, verbosity=2,
                                   resultclass=CountingResult).run(suite)


def counts(result):
    return dict(passed=result.passed, run=result.testsRun, skipped=len(result.skipped),
                expected_failures=len(result.expectedFailures), failures=len(result.failures),
                errors=len(result.errors), unexpected_successes=len(result.unexpectedSuccesses))


def main():
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    result = run_suite(suite)
    totals = counts(result)
    print('Test results:', json.dumps(totals, sort_keys=True))
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8', newline='\n') as output:
            for name, value in totals.items():
                output.write(f'{name}={value}\n')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
