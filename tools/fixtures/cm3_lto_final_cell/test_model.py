"""Synthetic pure fixed-route accounting controls; no compiler or ELF parsing."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COVERAGE = HERE.parent / 'ordinary_final_cell/coverage.py'
COVERAGE_SHA = 'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9'
OPENED = {path: path.read_bytes() for path in (HERE / 'model.py', Path(__file__).resolve(), COVERAGE)}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(OPENED[path], str(path), 'exec'), module.__dict__)
    return module


if sha(OPENED[COVERAGE]) != COVERAGE_SHA:
    raise RuntimeError('frozen ordinary coverage source mismatch')
m = load('fixed_cm3_lto_cell_model', HERE / 'model.py')
c = load('fixed_ordinary_coverage_dependency', COVERAGE)
COMMON = ['cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity']
RUNTIME = ['forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls']
COMPANION = ['companion-gateway-abi', 'paired-image-contract',
             'generated-assembly-reference-parity', 'negative-link-controls']
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
KEY = (COHORT, 'runtime', 'final', 'O2-lto', 'direct')
ROLES = ('Inventory', 'Native', 'Reference', 'Join', 'Bindings', 'ABIControls',
         'Isolation', 'CommonAttributes', 'PortPolicy')


def catalog():
    return dict(SchemaVersion=1, Route='CM3/O2-lto/direct', Bundles={role: dict(
        Build='C:/synthetic/' + role, ReceiptSha256='A' * 64, ArtifactsSha256='B' * 64) for role in ROLES})


def plan():
    cells = [dict(zip(m.KEY_FIELDS, KEY), SourceGroup='CM3', CohortSha256=m.COHORT_SHA256,
                  Retained=dict(Values=['unchanged']))]
    for index in range(2773):
        cells.append(dict(Cohort='synthetic-%04d' % index, ArtifactRole=('common', 'runtime', 'secure_companion')[index % 3],
            Representation='final' if index % 2 else 'object', Mode='Os-lto' if index % 2 else 'O0',
            Linkage='archive' if index % 2 else 'none', SourceGroup='synthetic', CohortSha256='C' * 64))
    required = dict(SchemaVersion=1, ExpectedOnly=True, Execution='NOT_RUN', GlobalFreezeQualified=False,
        RequiredCellCount=2774, InventoryManifestSha256='D' * 64, ObjectModes=['O0', 'Og', 'O2', 'Os', 'O3'],
        FinalModes=['O0', 'Og', 'O2', 'Os', 'O3', 'O2-lto', 'Os-lto'],
        PlannedProofRequirements=dict(common=list(COMMON), runtime=list(RUNTIME), secure_companion=list(COMPANION)),
        RequiredCells=cells)
    backlog = [dict(id='synthetic-backlog-%02d' % index, status='Pending' if index < 23 else 'ReferenceOnly',
                    Retained=dict(Values=[index])) for index in range(26)]
    return required, backlog


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.required, self.backlog = plan()

    def coverage(self, keys, *, dependency=c):
        return m.coverage(self.required, self.backlog, keys, coverage_module=dependency)

    def test_contract_fixed_selector_and_fresh_metadata(self):
        first = m.contract()
        self.assertEqual(tuple(first[name] for name in m.KEY_FIELDS), KEY)
        self.assertEqual(first['Route'], 'CM3/O2-lto/direct')
        self.assertEqual(first['SourceGroup'], 'CM3')
        self.assertEqual(first['CohortSha256'], 'C7C37950A2C7391B8E9C719A828CE9A288A5634FBEB6C3934A41F5AF6177C700')
        self.assertEqual(first['SourceInventorySha256'], '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313')
        self.assertIs(first['LTO'], True)
        self.assertIs(first['MetadataOnly'], True)
        self.assertIs(first['ProofExecutor'], False)
        self.assertIs(first['RequiredCellSatisfied'], False)
        self.assertIs(type(first['RequiredCellsSatisfied']), int)
        self.assertEqual(first['RequiredCellsSatisfied'], 0)
        for name in ('FullABIProof', 'FullSemanticABIProof', 'InputAuthenticationProof', 'CpuExecution',
                     'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified'):
            self.assertIs(first[name], False)
        self.assertEqual(json.loads(json.dumps(first)), first)
        first['CommonRequirements'].clear()
        first['RuntimeRequirements'].append('not-authority')
        self.assertEqual(m.contract()['CommonRequirements'], COMMON)
        self.assertEqual(m.contract()['RuntimeRequirements'], RUNTIME)

    def test_catalog_exact_roles_and_independent_copy(self):
        value = catalog()
        before = deepcopy(value)
        result = m.validate_catalog(value)
        self.assertEqual(result, value)
        self.assertEqual(set(result['Bundles']), set(ROLES))
        result['Bundles']['Inventory']['Build'] = 'output-only'
        self.assertEqual(value, before)
        # Path existence, normalization and aliases are deliberately caller obligations.
        value['Bundles']['Native']['Build'] = 'relative/../Native'
        self.assertEqual(m.validate_catalog(value), value)

    def test_catalog_closed_top_level_and_literal_version(self):
        for change in ('extra', 'missing', 'bool', 'float', 'wrong', 'not-dict'):
            value = catalog()
            if change == 'extra':
                value['Profile'] = 'CM3'
            elif change == 'missing':
                del value['Route']
            elif change in ('bool', 'float', 'wrong'):
                value['SchemaVersion'] = {'bool': True, 'float': 1.0, 'wrong': 2}[change]
            else:
                value = list(value)
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                m.validate_catalog(value)

    def test_catalog_no_implicit_or_foreign_selector(self):
        for route in ('CM3/O2/direct', 'CM3/Os-lto/direct', 'CM3/O2-lto/archive', 'CM4/O2-lto/direct', None, True):
            value = catalog()
            value['Route'] = route
            with self.subTest(route=route), self.assertRaises(m.Rejected):
                m.validate_catalog(value)
        for change in ('missing', 'extra', 'rename', 'not-dict'):
            value = catalog()
            if change == 'missing':
                value['Bundles'].pop('PortPolicy')
            elif change == 'extra':
                value['Bundles']['PriorJoin'] = deepcopy(value['Bundles']['Join'])
            elif change == 'rename':
                value['Bundles']['native'] = value['Bundles'].pop('Native')
            else:
                value['Bundles'] = []
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                m.validate_catalog(value)

    def test_descriptor_closed_fields_types_digests_and_control_free_text(self):
        changes = [('Build', value) for value in ('', ' path', 'path ', 'path\x00tail', 'path\nnext', 'path\ttail', False, 4.0)]
        changes += [('ReceiptSha256', value) for value in ('A' * 63, 'G' * 64, 'a' * 64, False, 4.0, ['A' * 64])]
        changes += [('ArtifactsSha256', None)]
        for role in ROLES:
            for field, value in changes:
                candidate = catalog()
                candidate['Bundles'][role][field] = value
                with self.subTest(role=role, field=field, value=value), self.assertRaises(m.Rejected):
                    m.validate_catalog(candidate)
            for change in ('missing', 'extra', 'not-dict'):
                candidate = catalog()
                row = candidate['Bundles'][role]
                if change == 'missing':
                    row.pop('ReceiptSha256')
                elif change == 'extra':
                    row['Status'] = 'PASS'
                else:
                    candidate['Bundles'][role] = []
                with self.subTest(role=role, change=change), self.assertRaises(m.Rejected):
                    m.validate_catalog(candidate)

    def test_exact_single_lto_key_preserves_all_required_rows(self):
        before = deepcopy((self.required, self.backlog))
        covered, missing = self.coverage([KEY])
        self.assertEqual(len(covered['Cells']), 2774)
        self.assertEqual(len(missing['Cells']), 2773)
        self.assertEqual(covered['RequiredCellsSatisfied'], 1)
        self.assertEqual(covered['PlannedProofRequirements']['common'], COMMON)
        self.assertEqual(covered['PlannedProofRequirements']['runtime'], RUNTIME)
        for original, row in zip(self.required['RequiredCells'], covered['Cells']):
            for field, value in original.items():
                self.assertEqual(row[field], value)
            passed = tuple(row[field] for field in m.KEY_FIELDS) == KEY
            self.assertIs(row['RequiredCellSatisfied'], passed)
            self.assertEqual(row['Status'], 'BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING')
        self.assertEqual((self.required, self.backlog), before)

    def test_empty_verified_list_revokes_credit_and_preserves_nonclaims(self):
        self.coverage([KEY])
        self.required['RequiredCells'][0].update(Status='PASS', RequiredCellSatisfied=True)
        covered, missing = self.coverage([])
        self.assertEqual(len(missing['Cells']), 2774)
        for result in (covered, missing):
            self.assertIs(type(result['RequiredCellsSatisfied']), int)
            self.assertEqual(result['RequiredCellsSatisfied'], 0)
            self.assertIs(result['ProofExecutor'], False)
            for flag in ('FullABIProof', 'FullSemanticABIProof', 'GlobalFreezeQualified', 'HostedCIQualified', 'CpuExecution', 'BoardExecution'):
                self.assertIs(result[flag], False)
        self.assertTrue(all(row['RequiredCellSatisfied'] is False for row in covered['Cells']))

    def test_outputs_do_not_alias_inputs_each_other_or_later_calls(self):
        before = deepcopy((self.required, self.backlog))
        covered, missing = self.coverage([])
        covered['Cells'][0]['Retained']['Values'].append('output-only')
        covered['Cells'][0]['MissingWholeCellRequirements'].clear()
        covered['PlannedProofRequirements']['common'].clear()
        missing['Backlog'][0]['Retained']['Values'].append('output-only')
        self.assertEqual(len(missing['Cells'][0]['MissingWholeCellRequirements']), 8)
        self.assertEqual((self.required, self.backlog), before)
        self.assertEqual(self.coverage([])[0]['PlannedProofRequirements']['common'], COMMON)

    def test_verified_keys_strict_shape_unique_and_fixed_axes(self):
        for value in (None, (), (KEY,), KEY, False, 1, [list(KEY)], [KEY, KEY], [()], [True],
                      [KEY[:3] + ('Os-lto', 'direct')], [KEY[:4] + ('archive',)],
                      [('foreign',) + KEY[1:]], [KEY[:1] + ('secure_companion',) + KEY[2:]],
                      [KEY[:2] + ('object',) + KEY[3:]], [KEY[:3] + (2.0, 'direct')]):
            with self.subTest(value=value), self.assertRaises(m.Rejected):
                self.coverage(value)

    def test_selected_row_source_group_and_cohort_fingerprint_are_bound(self):
        for field, value in (('SourceGroup', 'CM4'), ('SourceGroup', False), ('CohortSha256', 'A' * 64),
                             ('CohortSha256', False), ('Cohort', 'foreign'), ('Mode', 'O2'), ('Linkage', 'archive')):
            self.required, self.backlog = plan()
            self.required['RequiredCells'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(m.Rejected):
                self.coverage([])

    def test_required_count_empty_truncation_duplicates_and_forged_count(self):
        for change in ('empty', 'truncated', 'duplicate', 'forged', 'bool', 'float'):
            self.required, self.backlog = plan()
            if change == 'empty':
                self.required['RequiredCells'] = []
            elif change == 'truncated':
                self.required['RequiredCells'].pop()
            elif change == 'duplicate':
                self.required['RequiredCells'][-1] = deepcopy(self.required['RequiredCells'][0])
            else:
                self.required['RequiredCellCount'] = {'forged': 2773, 'bool': True, 'float': 2774.0}[change]
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                self.coverage([])

    def test_required_schema_axes_roles_and_json_types_reject(self):
        changes = [('SchemaVersion', True), ('SchemaVersion', 1.0), ('ExpectedOnly', 1),
                   ('Execution', 'PASS'), ('GlobalFreezeQualified', 0), ('InventoryManifestSha256', 'Z' * 64),
                   ('ObjectModes', ['O2']), ('FinalModes', ['O2-lto']), ('arbitrary_float', 0.0)]
        for field, value in changes:
            self.required, self.backlog = plan()
            self.required[field] = value
            with self.subTest(field=field), self.assertRaises(m.Rejected):
                self.coverage([])
        for field, value in (('ArtifactRole', 'foreign'), ('Mode', 'O1'), ('Representation', 'foreign'),
                             ('Linkage', 'direct'), ('SourceGroup', True), ('CohortSha256', 'bad')):
            self.required, self.backlog = plan()
            self.required['RequiredCells'][1][field] = value
            with self.subTest(row_field=field), self.assertRaises(m.Rejected):
                self.coverage([])

    def test_all_common_runtime_and_companion_requirements_are_mandatory(self):
        for role in ('common', 'runtime', 'secure_companion'):
            for change in ('empty', 'reordered', 'extra'):
                self.required, self.backlog = plan()
                rows = self.required['PlannedProofRequirements'][role]
                if change == 'empty':
                    rows.clear()
                elif change == 'reordered':
                    rows.reverse()
                else:
                    rows.append('invented-proof')
                with self.subTest(role=role, change=change), self.assertRaises(m.Rejected):
                    self.coverage([])

    def test_all_backlog_rows_and_23_pending_three_referenceonly_are_preserved(self):
        missing = self.coverage([KEY])[1]
        self.assertEqual(missing['Backlog'], self.backlog)
        self.assertEqual(sum(row['status'] == 'Pending' for row in missing['Backlog']), 23)
        self.assertEqual(sum(row['status'] == 'ReferenceOnly' for row in missing['Backlog']), 3)
        for change in ('empty', 'truncated', 'duplicate', 'status', 'counts', 'float'):
            self.required, self.backlog = plan()
            if change == 'empty':
                self.backlog = []
            elif change == 'truncated':
                self.backlog.pop()
            elif change == 'duplicate':
                self.backlog[-1]['id'] = self.backlog[0]['id']
            elif change == 'status':
                self.backlog[0]['status'] = 'PASS'
            elif change == 'counts':
                self.backlog[0]['status'] = 'ReferenceOnly'
            else:
                self.backlog[0]['float'] = 1.0
            with self.subTest(change=change), self.assertRaises(m.Rejected):
                self.coverage([])

    def test_only_frozen_plan_predicate_is_used_without_global_mutations(self):
        calls = []
        before = deepcopy((c.MODES, c._SELECTORS, c.COMMON, c.RUNTIME))
        def validate(required, backlog):
            calls.append((required is self.required, backlog is self.backlog))
            return c._plan(required, backlog)
        dependency = types.SimpleNamespace(_plan=validate)
        self.assertEqual(self.coverage([KEY], dependency=dependency)[0]['RequiredCellsSatisfied'], 1)
        self.assertEqual(calls, [(True, True)])
        self.assertEqual((c.MODES, c._SELECTORS, c.COMMON, c.RUNTIME), before)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize):
        raise SystemExit('use fresh unoptimized -I -S -B Python')
    output = args.output_dir.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    drift = [str(path) for path, raw in OPENED.items() if path.read_bytes() != raw]
    report = dict(Status='PASS' if result.wasSuccessful() and not drift else 'FAIL', Tests=result.testsRun,
        Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes={str(path): sha(raw) for path, raw in OPENED.items()}, SourceDrift=drift,
        SyntheticPlanOnly=True, InventoryAuthenticationProof=False, ProofExecutor=False,
        CompilerInvoked=False, ActualELFQualified=False, CpuExecution=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'results.json').write_bytes((json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'))
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
