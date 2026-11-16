#!/usr/bin/env python3
"""DE: Offline-Referenzprüfung, kein Testlauf. EN: Offline reference validation, not execution."""

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
STATUSES = {'covered', 'partial', 'missing', 'manual', 'not-applicable'}
PLATFORMS = {'linux-x86_64', 'linux-arm64', 'windows-x86_64', 'windows-arm64'}
CASE_KEYS = set('id category component_paths scenario expected_behavior boundary implementation_state '
                'coverage_status automation platforms features preconditions test_refs ci_refs priority '
                'issues v2_ids evidence_refs gap next_evidence retired replacement'.split())
REF_KEYS = {'path', 'symbol', 'kind', 'stage'}
EVIDENCE_KEYS = set('id source_commit observed_utc origin result run_id job_id attempt url platform '
                    'runner features environment scope limits'.split())
KINDS = {'rust-integration', 'rust-unit', 'doctest', 'python', 'fuzz', 'manual'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def shape(value, keys):
    require(isinstance(value, dict) and set(value) == keys, 'Felder / fields: ' + ', '.join(sorted(keys)))


def nonempty(value):
    require(isinstance(value, str) and bool(value.strip()), 'Text fehlt / missing text')


def bilingual(value):
    shape(value, {'de', 'en'})
    for text in value.values():
        nonempty(text)


def selection(value, choices):
    require(isinstance(value, str) and value in choices, 'Ungültiger Wert / invalid value')


def sequence(value, minimum=0):
    require(isinstance(value, list) and len(value) >= minimum, 'Liste fehlt / missing list')


def strings(value, minimum=0):
    sequence(value, minimum)
    for item in value:
        nonempty(item)
    require(len(set(value)) == len(value), 'Doppelte Werte / duplicate values')


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', value),
            'Ungültige Version / invalid version')


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value), 'Commit-SHA / commit SHA')


def safe_path(root, value, existing=True):
    nonempty(value)
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and not any(x in value for x in ('\\', ':'))
            and '..' not in relative.parts and value == relative.as_posix() and value != '.',
            'Unsicherer Pfad / unsafe path')
    resolved = (root / value).resolve()
    require(resolved.is_relative_to(root.resolve()), 'Pfad außerhalb / path escapes root')
    if existing:
        require(resolved.is_file(), 'Datei fehlt / missing file: ' + value)
    return resolved


def unique(items):
    sequence(items)
    ids = []
    for item in items:
        require(isinstance(item, dict), 'Objekt fehlt / missing object')
        nonempty(item.get('id'))
        ids.append(item['id'])
    require(len(ids) == len(set(ids)), 'Doppelte ID / duplicate ID')
    return {item['id']: item for item in items}


def reference(root, ref):
    shape(ref, REF_KEYS)
    selection(ref['kind'], KINDS)
    selection(ref['stage'], {'existing', 'planned'})
    nonempty(ref['symbol'])
    path = safe_path(root, ref['path'], ref['stage'] == 'existing')
    if ref['stage'] == 'planned' or ref['kind'] == 'manual':
        return
    text = path.read_text(encoding='utf-8')
    # DE: Nur Symbol-Präsenz, kein Rust-/Python-Parser. EN: Symbol presence, not a language parser.
    symbol = re.escape(ref['symbol'])
    if ref['kind'] == 'fuzz':
        found = ref['symbol'] == 'fuzz_target!' and 'fuzz_target!(' in text
    elif ref['kind'] == 'doctest':
        found = re.search(r'\bstruct\s+' + symbol + r'\b', text) and '```compile_fail' in text
    else:
        keyword = 'def' if ref['kind'] == 'python' else 'fn'
        found = re.search(r'\b' + keyword + r'\s+' + symbol + r'\s*\(', text)
    require(found, 'Testsymbol fehlt / missing test symbol: ' + ref['path'] + '::' + ref['symbol'])


def ci_reference(root, ref):
    shape(ref, {'workflow', 'job', 'matrix_filter', 'gate', 'stage'})
    selection(ref['stage'], {'existing', 'planned'})
    selection(ref['gate'], {'optional', 'required-except-arm64', 'none'})
    nonempty(ref['job'])
    strings(ref['matrix_filter'], 1)
    path = safe_path(root, ref['workflow'], ref['stage'] == 'existing')
    require(ref['workflow'].startswith('.github/workflows/') and path.suffix in {'.yml', '.yaml'},
            'Workflow-Pfad / workflow path')
    if ref['stage'] == 'planned':
        return
    text = path.read_text(encoding='utf-8')
    # DE: Bekannte Repo-Form, kein allgemeiner YAML-Parser. EN: Known repository form, not YAML parsing.
    match = re.search(r'^  ' + re.escape(ref['job']) + r':\s*\n(.*?)(?=^  [\w-]+:|\Z)', text, re.M | re.S)
    require(match, 'CI-Job fehlt / missing CI job')
    for runner in ref['matrix_filter']:
        require(runner in match[1], 'CI-Matrix fehlt / missing CI matrix value')


def case(root, item):
    shape(item, CASE_KEYS)
    require(re.fullmatch(r'QA1-(CRY|FMT|FS|MEM|ISO|REC|API|PLT)-\d{3}', item['id']), 'Fall-ID / case ID')
    nonempty(item['category'])
    strings(item['component_paths'], 1)
    for path in item['component_paths']:
        safe_path(root, path)
    for field in ('scenario', 'expected_behavior', 'boundary', 'preconditions'):
        bilingual(item[field])
    selection(item['implementation_state'], {'implemented', 'documented-only', 'not-implemented', 'not-applicable'})
    selection(item['coverage_status'], STATUSES)
    selection(item['automation'], {'automated', 'automatable', 'manual', 'not-applicable'})
    strings(item['platforms'], 1)
    require(set(item['platforms']) <= PLATFORMS, 'Plattform / platform')
    strings(item['features'], 1)
    require(set(item['features']) <= {'default', 'no-default', 'api'}, 'Features / features')
    for field, check in [('test_refs', reference), ('ci_refs', ci_reference)]:
        sequence(item[field])
        require(len({json.dumps(r, sort_keys=True) for r in item[field]}) == len(item[field]), 'Doppelter Verweis / duplicate reference')
        for ref in item[field]:
            check(root, ref)
    if item['coverage_status'] == 'covered':
        require(item['automation'] == 'automated' and any(r['stage'] == 'existing' and r['kind'] != 'manual'
                for r in item['test_refs']), 'Covered ohne Test / covered without test')
        require(item['gap'] is None and item['next_evidence'] is None, 'Covered mit Lücke / covered with gap')
    else:
        bilingual(item['gap'])
        bilingual(item['next_evidence'])
    selection(item['priority'], {'P1', 'P2', 'P3'})
    sequence(item['issues'], 1)
    require(all(type(n) is int and n > 0 for n in item['issues']), 'Issue / issue')
    strings(item['v2_ids'])
    v2 = (root / 'docs/V2_TESTS.md').read_text(encoding='utf-8')
    for ident in item['v2_ids']:
        require(re.search(r'^\| ' + re.escape(ident) + r' \|', v2, re.M), 'v2-ID fehlt / missing v2 ID')
    strings(item['evidence_refs'])
    require(type(item['retired']) is bool, 'Stilllegung / retirement')
    require(item['replacement'] is None or isinstance(item['replacement'], str), 'Ersatz / replacement')


def evidence(root, item, cases):
    shape(item, EVIDENCE_KEYS)
    sha(item['source_commit'])
    nonempty(item['observed_utc'])
    require(item['observed_utc'].endswith('Z'), 'UTC-Zeit / UTC timestamp')
    datetime.fromisoformat(item['observed_utc'].replace('Z', '+00:00'))
    selection(item['origin'], {'local', 'ci'})
    selection(item['result'], {'passed', 'failed', 'skipped', 'not-run', 'unknown'})
    selection(item['platform'], PLATFORMS)
    selection(item['features'], {'default', 'no-default', 'api'})
    nonempty(item['runner'])
    shape(item['environment'], {'kernel', 'page_size', 'toolchain'})
    for key in ('kernel', 'toolchain'):
        nonempty(item['environment'][key])
    page = item['environment']['page_size']
    require(page == 'unknown' or type(page) is int and page > 0, 'Seitengröße / page size')
    if item['origin'] == 'ci':
        for field in ('run_id', 'job_id', 'attempt'):
            require(type(item[field]) is int and item[field] > 0, 'CI-Identität / CI identity')
        expected = f"https://github.com/SpecterAoD/pqkeep/actions/runs/{item['run_id']}/job/{item['job_id']}"
        require(item['url'] == expected, 'CI-URL / CI URL')
    else:
        require(all(item[k] is None for k in ('run_id', 'job_id', 'attempt', 'url')), 'Lokaler Lauf / local run')
    bilingual(item['limits'])
    sequence(item['scope'], 1)
    seen = set()
    for scope in item['scope']:
        shape(scope, {'case_id', 'test_refs'})
        require(scope['case_id'] in cases and scope['case_id'] not in seen, 'Nachweis-Fall / evidence case')
        seen.add(scope['case_id'])
        target = cases[scope['case_id']]
        require(item['platform'] in target['platforms'] and item['id'] in target['evidence_refs'], 'Nachweis-Zuordnung / evidence mapping')
        require(('no-default' in target['features']) if item['features'] == 'no-default'
                else bool({'api', 'default'} & set(target['features'])), 'Feature-Zuordnung / feature mapping')
        sequence(scope['test_refs'], 1)
        for ref in scope['test_refs']:
            require(ref in target['test_refs'], 'Fremder Test / unrelated test')
            reference(root, ref)
            if item['result'] == 'passed':
                require(ref['stage'] == 'existing' and ref['kind'] != 'manual'
                        and target['coverage_status'] != 'not-applicable', 'Unbelegter Erfolg / unsupported pass')


def validate(root, matrix, baseline):
    shape(matrix, {'schema_version', 'matrix_version', 'reviewed_source_commit', 'cases'})
    shape(baseline, {'schema_version', 'baseline_version', 'matrix_version', 'evidence'})
    for document in (matrix, baseline):
        require(type(document['schema_version']) is int and document['schema_version'] == 1, 'Schema / schema')
        version(document['matrix_version'])
    version(baseline['baseline_version'])
    require(matrix['matrix_version'] == baseline['matrix_version'], 'Versionskonflikt / version mismatch')
    sha(matrix['reviewed_source_commit'])
    cases = unique(matrix['cases'])
    require(bool(cases), 'Leerer Katalog / empty catalogue')
    require({x.split('-')[1] for x in cases} == {'CRY', 'FMT', 'FS', 'MEM', 'ISO', 'REC', 'API', 'PLT'}, 'Kategorien fehlen / missing categories')
    records = unique(baseline['evidence'])
    for item in cases.values():
        case(root, item)
        for ident in item['evidence_refs']:
            require(ident in records and any(s['case_id'] == item['id'] for s in records[ident]['scope']), 'Nachweis fehlt / missing evidence')
        if item['replacement'] is not None:
            require(item['retired'] and item['replacement'] in cases and item['replacement'] != item['id'], 'Ersatz-ID / replacement ID')
    for item in records.values():
        evidence(root, item, cases)
    return Counter(c['coverage_status'] for c in cases.values())


def pairs(items):
    # DE: JSON-Duplikate nicht still überschreiben. EN: Never silently overwrite duplicate JSON keys.
    result = {}
    for key, value in items:
        require(key not in result, 'Doppelter JSON-Schlüssel / duplicate JSON key')
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', action='store_true', help='DE/EN: Fallübersicht / case summary')
    args = parser.parse_args()
    matrix = load(ROOT / 'docs/security/attack-matrix.json')
    baseline = load(ROOT / 'docs/security/attack-baseline.json')
    counts = validate(ROOT, matrix, baseline)
    print('OK: Angriffsmatrix / attack matrix:', dict(sorted(counts.items())))
    if args.summary:
        print('| ID | Status | DE | EN |')
        print('|---|---|---|---|')
        for item in matrix['cases']:
            text = [item['scenario'][lang].replace('|', '\\|').replace('\n', ' ') for lang in ('de', 'en')]
            print(f"| {item['id']} | {item['coverage_status']} | {text[0]} | {text[1]} |")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError, AttributeError) as error:
        print(f'FEHLER / ERROR: {error}', file=sys.stderr)
        sys.exit(1)
