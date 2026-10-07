#!/usr/bin/env python3
"""Synchronize the release version and provenance before committing or packaging."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.package import package_files

PATTERN = r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)'


def version_tuple(value):
    if not re.fullmatch(PATTERN, value):
        raise ValueError('Версия должна иметь вид 0.2.1 без префикса v.')
    return tuple(int(part) for part in value.split('.'))


def write_text(path, text):
    with path.open('w', encoding='utf-8', newline='\n') as output:
        output.write(text)


def document_updates(root, version):
    replacements = [('README.md', r'^Текущая версия: \*\*' + PATTERN + r'\*\*\.$',
                     f'Текущая версия: **{version}**.'),
                    ('VOICE.md', r'^# Голос Discord на Mac: версия ' + PATTERN + r'$',
                     f'# Голос Discord на Mac: версия {version}')]
    results = {}
    for name, pattern, replacement in replacements:
        source = (root / name).read_text(encoding='utf-8')
        target, count = re.subn(pattern, replacement, source, flags=re.M)
        if count != 1:
            raise ValueError(f'В {name} должна быть ровно одна строка текущей версии.')
        results[name] = target
    return results


def sync(root, version, check=False, test_count=None, platform=''):
    version_tuple(version)
    current = (root / 'VERSION').read_text(encoding='utf-8').strip()
    if version_tuple(version) < version_tuple(current):
        raise ValueError('Понижение версии запрещено.')
    documents = document_updates(root, version)
    manifest = json.loads((root / 'PROVENANCE.json').read_text(encoding='utf-8'))
    if test_count is not None and (test_count < 1 or not platform):
        raise ValueError('Для подтверждённых тестов нужны количество и платформа.')
    if check:
        if current != version or manifest['version'] != version:
            raise ValueError('Версии VERSION и PROVENANCE.json не совпадают с релизом.')
        for name, expected in documents.items():
            if (root / name).read_text(encoding='utf-8') != expected:
                raise ValueError(f'Несогласованная версия: {name}')
    else:
        write_text(root / 'VERSION', version + '\n')
        for name, target in documents.items():
            write_text(root / name, target)
        manifest['version'] = version
        if test_count is not None:
            manifest['tested_on'] = f'{platform}: {test_count} Python tests passed'
            manifest.setdefault('validation', {})['python_tests_passed'] = test_count
            manifest['validation']['python_tests_platform'] = platform
    hashes = {file.relative_to(root).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
              for file in package_files(root) if file.name != 'PROVENANCE.json'}
    if check:
        if manifest['sha256'] != hashes:
            raise ValueError('Контрольные суммы не совпадают. Выполните синхронизацию версии.')
    else:
        manifest['sha256'] = dict(sorted(hashes.items()))
        write_text(root / 'PROVENANCE.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('version')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--tests-passed', type=int)
    parser.add_argument('--platform', default='')
    args = parser.parse_args()
    sync(args.root, args.version, args.check, args.tests_passed, args.platform)
    print('Версия и контрольные суммы согласованы:', args.version)


if __name__ == '__main__':
    main()
