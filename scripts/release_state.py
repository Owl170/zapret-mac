#!/usr/bin/env python3
"""Identify a source commit or its verified automatic version commit on main."""
import argparse
import os
from pathlib import Path
import re
import subprocess

PATTERN = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'
METADATA_FILES = {'VERSION', 'PROVENANCE.json', 'README.md', 'VOICE.md'}


def classify(event_sha, head_sha, parent_sha, subject, version, changed_paths=()):
    """Return None for unrelated main, '' for source, or a version to resume."""
    match = re.fullmatch(r'chore\(release\): v(' + PATTERN + r')', subject)
    if head_sha != event_sha and not (match and parent_sha == event_sha):
        return None
    if head_sha != event_sha and not set(changed_paths).issubset(METADATA_FILES):
        # Native CI tested the event SHA. Its bot child may only change release
        # metadata; changed executable sources require a new native CI run.
        return None
    if match:
        if match.group(1) != version:
            raise ValueError('Automatic release commit and VERSION disagree.')
        return version
    return ''


def changed_files(root, parent, head):
    # Rename detection reports only the new name; include deleted executable
    # paths as well when enforcing the metadata-only continuation rule.
    return subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', parent, head],
                                   cwd=root, text=True).splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=root, text=True).rstrip('\n')

    head = git('rev-parse', 'HEAD')
    parents = git('rev-list', '--parents', '-n', '1', 'HEAD').split()
    parent = parents[1] if len(parents) == 2 else ''
    subject = git('show', '-s', '--format=%s', 'HEAD')
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    changed = changed_files(root, parent, head) if parent and head != args.event else []
    resume = classify(args.event, head, parent, subject, version, changed)
    ready = resume is not None
    with Path(os.environ['GITHUB_OUTPUT']).open('a', encoding='utf-8', newline='\n') as output:
        output.write('ready=' + str(ready).lower() + '\n')
        output.write('resume_version=' + (resume or '') + '\n')
    if not ready:
        print('Main has an unrelated newer commit; this stale run will not modify it. '
              'Use workflow_dispatch on current main if publication is needed.')


if __name__ == '__main__':
    main()
