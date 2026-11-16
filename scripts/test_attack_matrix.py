#!/usr/bin/env python3
"""DE: Katalogvertrag und negative Grenzfälle. EN: Catalogue contract and negative boundaries."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import check_attack_matrix as checker


class AttackMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, text in {
            'tests/sample.rs': '#[test]\nfn assertion() {}\n',
            'src/secret.rs': '/// ```compile_fail\n/// code\n/// ```\npub struct Secret;\n',
            'scripts/test_sample.py': 'def test_assertion(): pass\n',
            'fuzz/sample.rs': 'fuzz_target!(|data: &[u8]| {});\n',
            '.github/workflows/ci.yml': 'jobs:\n  test:\n    runs-on: ubuntu-latest\n  other:\n    runs-on: windows-latest\n',
            'docs/V2_TESTS.md': '| C01 | assertion |\n',
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        original = checker.load(checker.ROOT / 'docs/security/attack-matrix.json')['cases'][0]
        self.cases = []
        for category in ('CRY', 'FMT', 'FS', 'MEM', 'ISO', 'REC', 'API', 'PLT'):
            item = copy.deepcopy(original)
            item.update(id=f'QA1-{category}-001', component_paths=['src/secret.rs'],
                        platforms=['linux-x86_64'], features=['default'], evidence_refs=[],
                        test_refs=[{'path': 'tests/sample.rs', 'symbol': 'assertion',
                                    'kind': 'rust-integration', 'stage': 'existing'}],
                        ci_refs=[{'workflow': '.github/workflows/ci.yml', 'job': 'test',
                                  'matrix_filter': ['ubuntu-latest'], 'gate': 'optional', 'stage': 'existing'}])
            self.cases.append(item)
        self.matrix = {'schema_version': 1, 'matrix_version': '1.0.0',
                       'reviewed_source_commit': 'a' * 40, 'cases': self.cases}
        record = copy.deepcopy(checker.load(checker.ROOT / 'docs/security/attack-baseline.json')['evidence'][0])
        record.update(id='proof', source_commit='a' * 40, platform='linux-x86_64',
                      scope=[{'case_id': self.cases[0]['id'], 'test_refs': copy.deepcopy(self.cases[0]['test_refs'])}])
        self.cases[0]['evidence_refs'] = ['proof']
        self.baseline = {'schema_version': 1, 'baseline_version': '1.0.0',
                         'matrix_version': '1.0.0', 'evidence': [record]}

    def validate(self):
        return checker.validate(self.root, self.matrix, self.baseline)

    def invalid(self):
        with self.assertRaises(ValueError):
            self.validate()

    def test_repository_catalogue(self):
        matrix = checker.load(checker.ROOT / 'docs/security/attack-matrix.json')
        baseline = checker.load(checker.ROOT / 'docs/security/attack-baseline.json')
        result = checker.validate(checker.ROOT, matrix, baseline)
        self.assertEqual(len(matrix['cases']), sum(result.values()))

    def test_valid_fixture(self):
        self.assertEqual({'covered': 8}, self.validate())

    def test_missing_bilingual_text(self):
        for value in ({'de': 'Text'}, {'de': 'Text', 'en': ''}, {'de': 'Text', 'en': 2}):
            with self.subTest(value=value):
                self.cases[0]['scenario'] = value
                self.invalid()

    def test_duplicate_case_and_evidence_ids(self):
        self.cases.append(copy.deepcopy(self.cases[0]))
        self.invalid()
        self.cases.pop()
        self.baseline['evidence'].append(copy.deepcopy(self.baseline['evidence'][0]))
        self.invalid()

    def test_duplicate_json_keys(self):
        for text in ('{"id": 1, "id": 2}', '{"case": {"de": "a", "de": "b"}}'):
            with self.assertRaises(ValueError):
                json.loads(text, object_pairs_hook=checker.pairs)

    def test_invalid_status_missing_fields_and_types(self):
        original = copy.deepcopy(self.cases[1])
        for key, value in [('coverage_status', 'green'), ('issues', [True]), ('platforms', 'linux-x86_64'),
                           ('test_refs', {}), ('retired', 1), ('component_paths', []), ('priority', 'P0')]:
            with self.subTest(key=key):
                self.cases[1] = copy.deepcopy(original)
                self.cases[1][key] = value
                self.invalid()
        self.cases[1] = copy.deepcopy(original)
        del self.cases[1]['expected_behavior']
        self.invalid()
        self.cases[1] = copy.deepcopy(original)
        self.cases[1]['typo'] = 'value'
        self.invalid()

    def test_version_and_sha_boundaries(self):
        for field, value in [('schema_version', True), ('schema_version', 2), ('matrix_version', '01.0.0'),
                             ('matrix_version', '1.0'), ('reviewed_source_commit', 'short')]:
            old = self.matrix[field]
            self.matrix[field] = value
            self.invalid()
            self.matrix[field] = old
        self.baseline['matrix_version'] = '1.1.0'
        self.invalid()

    def test_missing_evidence_and_reciprocal_scope(self):
        self.cases[0]['evidence_refs'] = ['absent']
        self.invalid()
        self.cases[0]['evidence_refs'] = []
        self.invalid()
        self.cases[0]['evidence_refs'] = ['proof']
        self.baseline['evidence'][0]['scope'][0]['case_id'] = self.cases[1]['id']
        self.invalid()

    def test_unrelated_evidence_test(self):
        self.baseline['evidence'][0]['scope'][0]['test_refs'][0]['symbol'] = 'other'
        self.invalid()

    def test_passed_requires_concrete_ci_identity(self):
        record = self.baseline['evidence'][0]
        for field, value in [('run_id', None), ('job_id', True), ('attempt', 0), ('url', 'https://example.com'),
                             ('observed_utc', 'yesterday'), ('source_commit', ''), ('result', 'green')]:
            with self.subTest(field=field):
                old = record[field]
                record[field] = value
                self.invalid()
                record[field] = old

    def test_local_evidence_has_no_ci_identity(self):
        record = self.baseline['evidence'][0]
        record['origin'] = 'local'
        self.invalid()
        record.update(run_id=None, job_id=None, attempt=None, url=None)
        self.validate()

    def test_unjustified_not_applicable(self):
        self.cases[1]['coverage_status'] = 'not-applicable'
        self.invalid()

    def test_missing_test_cannot_be_covered(self):
        self.cases[1]['test_refs'] = []
        self.invalid()
        self.cases[1]['test_refs'] = [{'path': 'future.rs', 'symbol': 'future',
                                     'kind': 'rust-integration', 'stage': 'planned'}]
        self.invalid()

    def test_planned_reference_is_not_execution(self):
        target = self.cases[0]
        target.update(coverage_status='partial', gap={'de': 'Fehlt', 'en': 'Missing'},
                      next_evidence={'de': 'Prüfen', 'en': 'Check'})
        target['test_refs'][0]['stage'] = 'planned'
        record = self.baseline['evidence'][0]
        record['scope'][0]['test_refs'] = copy.deepcopy(target['test_refs'])
        self.invalid()
        record['result'] = 'not-run'
        self.validate()

    def test_no_evidence_is_allowed_for_a_documented_gap(self):
        target = self.cases[1]
        target.update(coverage_status='missing', test_refs=[], automation='automatable',
                      gap={'de': 'Fehlt', 'en': 'Missing'}, next_evidence={'de': 'Prüfen', 'en': 'Check'})
        self.validate()

    def test_dead_symbol_and_missing_path(self):
        for field, value in [('symbol', 'absent'), ('path', 'tests/missing.rs')]:
            ref = self.cases[1]['test_refs'][0]
            old = ref[field]
            ref[field] = value
            self.invalid()
            ref[field] = old

    def test_workflow_job_and_matrix_reference(self):
        ref = self.cases[1]['ci_refs'][0]
        for field, value in [('job', 'missing'), ('matrix_filter', ['windows-latest']),
                             ('workflow', 'tests/sample.rs')]:
            old = ref[field]
            ref[field] = value
            self.invalid()
            ref[field] = old

    def test_all_supported_reference_kinds(self):
        ref = self.cases[1]['test_refs'][0]
        for path, symbol, kind in [('src/secret.rs', 'Secret', 'doctest'),
                                   ('scripts/test_sample.py', 'test_assertion', 'python'),
                                   ('fuzz/sample.rs', 'fuzz_target!', 'fuzz')]:
            ref.update(path=path, symbol=symbol, kind=kind)
            self.validate()
            ref['symbol'] = 'absent'
            self.invalid()

    def test_unsafe_paths_in_all_reference_positions(self):
        for value in ('../escape.rs', '/tmp/escape.rs', 'C:/escape.rs', 'a\\escape.rs',
                      'tests/../tests/sample.rs', '.', './tests/sample.rs'):
            with self.subTest(value=value):
                ref = self.cases[1]['test_refs'][0]
                old = ref['path']
                ref['path'] = value
                self.invalid()
                ref['path'] = old
                old = self.cases[1]['component_paths']
                self.cases[1]['component_paths'] = [value]
                self.invalid()
                self.cases[1]['component_paths'] = old
                old = self.cases[1]['ci_refs'][0]['workflow']
                self.cases[1]['ci_refs'][0]['workflow'] = value
                self.invalid()
                self.cases[1]['ci_refs'][0]['workflow'] = old

    @unittest.skipUnless(os.name == 'posix', 'DE/EN: Unix-Symlink-Probe / Unix symlink probe')
    def test_symlink_escape_including_planned_path(self):
        with tempfile.TemporaryDirectory() as outside:
            (self.root / 'link').symlink_to(outside, target_is_directory=True)
            ref = self.cases[1]['test_refs'][0]
            ref.update(path='link/future.rs', stage='planned')
            self.invalid()

    def test_missing_category_and_reused_retired_id(self):
        self.cases.pop()
        self.invalid()
        self.cases.append(copy.deepcopy(self.cases[0]))
        self.cases[-1].update(retired=True, replacement=self.cases[0]['id'])
        self.invalid()

    def test_retired_case_keeps_id_and_valid_replacement(self):
        item = self.cases[1]
        item.update(retired=True, replacement=self.cases[0]['id'])
        self.validate()
        item['replacement'] = 'QA1-FMT-999'
        self.invalid()

    def test_v2_catalogue_reference(self):
        self.cases[1]['v2_ids'] = ['C01']
        self.validate()
        self.cases[1]['v2_ids'] = ['C99']
        self.invalid()

    def test_platform_mismatch_and_duplicate_scope(self):
        record = self.baseline['evidence'][0]
        record['platform'] = 'windows-x86_64'
        self.invalid()
        record['platform'] = 'linux-x86_64'
        record['scope'].append(copy.deepcopy(record['scope'][0]))
        self.invalid()

    def test_compilation_is_not_no_default_runtime_evidence(self):
        self.cases[0]['features'] = ['no-default']
        self.invalid()
        self.baseline['evidence'][0]['features'] = 'no-default'
        self.validate()


if __name__ == '__main__':
    unittest.main()
