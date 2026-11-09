"""Independent metadata accounting tests; no cell admission or proof execution."""
import argparse
import builtins
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MODEL = HERE / 'cell_model.py'
MODEL_SHA = 'E9CA01CA5DF0E459E2F8FCDF0FA3C4C2CFF725E0330EA03571F336664D5EEA53'
COVERAGE = HERE.parent / 'ordinary_final_cell/coverage.py'
COVERAGE_SHA = 'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9'
INVENTORY = Path('C:/fzin-20261104-e9')
FIXTURE_PINS = {
    'results.json': '1910B53001FD37DF4B6DC57805EE49E4381B2529E1E3ECB47FDB312EB43A4DFC',
    'artifacts.json': '640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA',
    'required-cells.json': '3AFBE9C8B5534AA64CC333F7D4519F2B88E74A72485BD97E2916DAB9ECCB6E4C',
    'inputs/tools/freeze_cohorts.json': 'BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE',
}
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
COHORT_SHA = 'C7C37950A2C7391B8E9C719A828CE9A288A5634FBEB6C3934A41F5AF6177C700'
SOURCE_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
FIELDS = ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')
KEY = (COHORT, 'runtime', 'final', 'Os-lto', 'direct')
COMMON = ['cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity']
RUNTIME = ['forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls']
COMPANION = ['companion-gateway-abi', 'paired-image-contract',
             'generated-assembly-reference-parity', 'negative-link-controls']
OBLIGATIONS = dict(common=COMMON, runtime=RUNTIME, secure_companion=COMPANION)
METHODS = 25
EXPECTED_METHOD_NAMES = (
    'test_actual_complete_fixture_and_selected_identity',
    'test_actual_model_calls_need_no_io_process_or_dynamic_loading',
    'test_backlog_exact_26_rows_and_statuses_preserved',
    'test_backlog_shape_identity_status_and_json_corruptions',
    'test_complete_plan_missing_extra_duplicate_rows_on_zero_and_one',
    'test_contract_calls_return_fresh_requirement_lists',
    'test_contract_exact_fixed_metadata_and_nonclaims',
    'test_frozen_plan_is_called_once_with_both_original_inputs',
    'test_harness_rejects_vacuous_skipped_or_failed_runs',
    'test_helper_shape_rejection_is_explicit_and_keeps_inputs',
    'test_inherited_flags_never_grant_zero_credit',
    'test_mode_axes_and_all_three_obligation_catalogs_are_exact',
    'test_model_does_not_mutate_helper_or_its_fixed_catalogs',
    'test_only_exact_os_key_and_axes_can_receive_credit',
    'test_outputs_deep_copy_input_siblings_and_later_calls',
    'test_plan_schema_literal_counts_flags_and_json_types',
    'test_required_row_missing_malformed_axes_and_identity',
    'test_revocation_does_not_mutate_prior_success_or_cache_credit',
    'test_selected_key_absence_cannot_be_normalized',
    'test_selected_source_group_and_cohort_hash_bound_even_for_zero',
    'test_single_credit_preserves_all_rows_and_exact_missing_work',
    'test_verified_list_and_key_have_literal_types',
    'test_well_formed_unselected_metadata_is_not_a_profile_oracle',
    'test_wrong_helper_api_has_explicit_model_rejection',
    'test_zero_credit_full_plan_and_all_pending_obligations',
)
OPENED = {}
m = c = REQUIRED = BACKLOG = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def first_read(path, expected=None):
    raw = path.read_bytes()
    if expected is not None and sha(raw) != expected:
        raise ValueError('pinned source/fixture mismatch: ' + str(path))
    if path in OPENED and OPENED[path] != raw:
        raise ValueError('conflicting first-seen bytes: ' + str(path))
    OPENED[path] = raw
    return raw


def unique_pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def invalid_json_number(value):
    raise ValueError('noninteger fixture JSON number: ' + value)


def structured(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_float=invalid_json_number, parse_constant=invalid_json_number)


def load_buffer(name, path, raw):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def initialize():
    global m, c, REQUIRED, BACKLOG
    first_read(Path(__file__).resolve())
    model_bytes = first_read(MODEL, MODEL_SHA)
    coverage_bytes = first_read(COVERAGE, COVERAGE_SHA)
    fixtures = {name: structured(first_read(INVENTORY / name, digest))
                for name, digest in FIXTURE_PINS.items()}
    receipt, artifacts = fixtures['results.json'], fixtures['artifacts.json']['Artifacts']
    for name in ('results.json', 'required-cells.json', 'inputs/tools/freeze_cohorts.json'):
        if artifacts.get(name) != FIXTURE_PINS[name]:
            raise ValueError('fixture manifest join: ' + name)
    if (receipt['RequiredCellsSha256'] != FIXTURE_PINS['required-cells.json']
            or receipt['ManifestSha256'] != FIXTURE_PINS['inputs/tools/freeze_cohorts.json']
            or receipt['SourceInventorySha256'] != SOURCE_SHA):
        raise ValueError('fixture receipt/plan/manifest identity')
    REQUIRED = fixtures['required-cells.json']
    BACKLOG = fixtures['inputs/tools/freeze_cohorts.json']['scope_backlog']
    m = load_buffer('independent_os_cell_model', MODEL, model_bytes)
    c = load_buffer('independent_ordinary_coverage_plan', COVERAGE, coverage_bytes)


def shared(count):
    return dict(RequiredCellCount=2774, RequiredCellsSatisfied=count,
                MetadataOnly=True, ProofExecutor=False, InputAuthenticationProof=False,
                Qualification=False, GlobalFreezeQualified=False, FullABIProof=False,
                FullSemanticABIProof=False, CpuExecution=False, BoardExecution=False,
                HostedCIQualified=False)


def catalog_matches(names, count):
    return (type(count) is int and count == METHODS
            and len(EXPECTED_METHOD_NAMES) == len(set(EXPECTED_METHOD_NAMES)) == METHODS
            and tuple(names) == tuple(sorted(EXPECTED_METHOD_NAMES)))


def complete_tests(result):
    return (result is not None and type(result.testsRun) is int and result.testsRun == METHODS
            and result.wasSuccessful() and not result.failures and not result.errors
            and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)


class ListAlias(list):
    pass


class TupleAlias(tuple):
    pass


class TextAlias(str):
    pass


class CellModelTests(unittest.TestCase):
    def setUp(self):
        self.required, self.backlog = deepcopy((REQUIRED, BACKLOG))
        self.selected = next(index for index, row in enumerate(self.required['RequiredCells'])
                             if tuple(row[field] for field in FIELDS) == KEY)

    def equal_typed(self, actual, expected, location='value'):
        self.assertIs(type(actual), type(expected), location)
        if type(expected) is dict:
            self.assertEqual(set(actual), set(expected), location)
            for key, value in expected.items():
                self.equal_typed(actual[key], value, location + '.' + key)
        elif type(expected) in (list, tuple):
            self.assertEqual(len(actual), len(expected), location)
            for index, (left, right) in enumerate(zip(actual, expected)):
                self.equal_typed(left, right, location + '[%d]' % index)
        else:
            self.assertEqual(actual, expected, location)

    def coverage(self, keys, dependency=None):
        return m.coverage(self.required, self.backlog, keys,
                          coverage_module=c if dependency is None else dependency)

    def rejects(self, required, backlog, keys):
        before = deepcopy((required, backlog, keys))
        with self.assertRaises(m.Rejected):
            m.coverage(required, backlog, keys, coverage_module=c)
        self.equal_typed((required, backlog, keys), before)

    def test_contract_exact_fixed_metadata_and_nonclaims(self):
        expected = dict(SchemaVersion=1, Route='CM3/Os-lto/direct', Profile='CM3', Mode='Os-lto',
            Cohort=COHORT, CohortSha256=COHORT_SHA, SourceGroup='CM3', ArtifactRole='runtime',
            Representation='final', Linkage='direct', LTO=True, SourceInventorySha256=SOURCE_SHA,
            CommonRequirements=COMMON, RuntimeRequirements=RUNTIME, MetadataOnly=True,
            ProofExecutor=False, InputAuthenticationProof=False, Qualification=False,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False,
            FullSemanticABIProof=False, SourceIRProof=False, PolicyEquivalence=False,
            InstructionEquivalence=False, CpuExecution=False, BoardExecution=False,
            HostedCIQualified=False, GlobalFreezeQualified=False)
        self.equal_typed(m.contract(), expected)
        self.equal_typed(structured(json.dumps(m.contract()).encode('ascii')), expected)

    def test_contract_calls_return_fresh_requirement_lists(self):
        first, second = m.contract(), m.contract()
        first['CommonRequirements'].clear()
        first['RuntimeRequirements'].append('foreign')
        first['RequiredCellsSatisfied'] = 1
        self.equal_typed(second, m.contract())
        self.equal_typed(second['CommonRequirements'], COMMON)
        self.equal_typed(second['RuntimeRequirements'], RUNTIME)

    def test_actual_complete_fixture_and_selected_identity(self):
        self.assertEqual(len(self.required['RequiredCells']), 2774)
        self.assertEqual(len(self.backlog), 26)
        row = self.required['RequiredCells'][self.selected]
        self.equal_typed(tuple(row[field] for field in FIELDS), KEY)
        self.equal_typed((row['SourceGroup'], row['CohortSha256']), ('CM3', COHORT_SHA))
        self.assertNotEqual(COHORT_SHA, SOURCE_SHA)
        self.equal_typed(self.required['PlannedProofRequirements'], OBLIGATIONS)

    def test_single_credit_preserves_all_rows_and_exact_missing_work(self):
        before = deepcopy((self.required, self.backlog))
        covered, missing = self.coverage([KEY])
        self.equal_typed({key: covered[key] for key in shared(1)}, shared(1))
        self.equal_typed({key: missing[key] for key in shared(1)}, shared(1))
        self.assertEqual(set(covered), set(shared(1)) | {'Cells', 'PlannedProofRequirements'})
        self.assertEqual(set(missing), set(shared(1)) | {'Cells', 'Backlog'})
        self.assertEqual(len(covered['Cells']), 2774)
        expected_missing = []
        for original, row in zip(self.required['RequiredCells'], covered['Cells']):
            key = tuple(original[field] for field in FIELDS)
            passed = key == KEY
            expected = deepcopy(original)
            remaining = [] if passed else OBLIGATIONS[original['ArtifactRole']]
            expected.update(Status='BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING',
                            RequiredCellSatisfied=passed, MissingWholeCellRequirements=remaining)
            self.equal_typed(row, expected)
            if not passed:
                expected_missing.append(dict(Key=list(key), MissingWholeCellRequirements=remaining))
        self.equal_typed(missing['Cells'], expected_missing)
        self.assertEqual(len(missing['Cells']), 2773)
        self.equal_typed(covered['PlannedProofRequirements'], OBLIGATIONS)
        self.equal_typed((self.required, self.backlog), before)

    def test_zero_credit_full_plan_and_all_pending_obligations(self):
        covered, missing = self.coverage([])
        for value in (covered, missing):
            self.equal_typed({key: value[key] for key in shared(0)}, shared(0))
        self.assertEqual(len(covered['Cells']), 2774)
        self.assertEqual(len(missing['Cells']), 2774)
        for row in covered['Cells']:
            self.assertIs(row['RequiredCellSatisfied'], False)
            self.assertEqual(row['Status'], 'PENDING')
            self.equal_typed(row['MissingWholeCellRequirements'], OBLIGATIONS[row['ArtifactRole']])

    def test_inherited_flags_never_grant_zero_credit(self):
        self.required.update(Status='PASS', RequiredCellSatisfied=True, RequiredCellsSatisfied=1)
        for row in self.required['RequiredCells']:
            row.update(Status='BOUNDED_STATIC_CELL_VERIFIED', RequiredCellSatisfied=True,
                       MissingWholeCellRequirements=[])
        before = deepcopy((self.required, self.backlog))
        covered, missing = self.coverage([])
        self.assertEqual(covered['RequiredCellsSatisfied'], 0)
        self.assertEqual(len(missing['Cells']), 2774)
        for row in covered['Cells']:
            self.assertIs(row['RequiredCellSatisfied'], False)
            self.assertEqual(row['Status'], 'PENDING')
            self.equal_typed(row['MissingWholeCellRequirements'], OBLIGATIONS[row['ArtifactRole']])
        self.equal_typed((self.required, self.backlog), before)

    def test_revocation_does_not_mutate_prior_success_or_cache_credit(self):
        first = self.coverage([KEY])
        before = deepcopy(first)
        revoked = self.coverage([])
        self.equal_typed(first, before)
        self.assertEqual(revoked[0]['RequiredCellsSatisfied'], 0)
        self.assertEqual(len(revoked[1]['Cells']), 2774)
        self.assertEqual(self.coverage([KEY])[0]['RequiredCellsSatisfied'], 1)

    def test_backlog_exact_26_rows_and_statuses_preserved(self):
        missing = self.coverage([KEY])[1]
        self.equal_typed(missing['Backlog'], self.backlog)
        self.assertEqual(sum(row['status'] == 'Pending' for row in missing['Backlog']), 23)
        self.assertEqual(sum(row['status'] == 'ReferenceOnly' for row in missing['Backlog']), 3)

    def test_outputs_deep_copy_input_siblings_and_later_calls(self):
        self.required['RequiredCells'][0]['TestRetained'] = {'Values': ['original']}
        before = deepcopy((self.required, self.backlog))
        covered, missing = self.coverage([])
        missing_before = deepcopy(missing)
        covered['Cells'][0]['TestRetained']['Values'].append('output-only')
        covered['Cells'][0]['MissingWholeCellRequirements'].clear()
        covered['PlannedProofRequirements']['common'].clear()
        self.equal_typed(missing, missing_before)
        missing['Backlog'][0]['refs'].append('output-only')
        missing['Cells'][0]['MissingWholeCellRequirements'].clear()
        self.assertNotEqual(covered['Cells'][1]['MissingWholeCellRequirements'], [])
        self.equal_typed((self.required, self.backlog), before)
        self.equal_typed(self.coverage([])[0]['PlannedProofRequirements'], OBLIGATIONS)
        self.equal_typed(self.coverage([])[1]['Backlog'], before[1])

    def test_well_formed_unselected_metadata_is_not_a_profile_oracle(self):
        row = self.required['RequiredCells'][0]
        row.update(Cohort='caller-authenticated-unselected-shape', SourceGroup='CallerGroup',
                   CohortSha256='A' * 64, TestRetained={'Values': ['caller']})
        expected = deepcopy(row)
        covered, missing = self.coverage([KEY])
        expected.update(Status='PENDING', RequiredCellSatisfied=False,
                        MissingWholeCellRequirements=OBLIGATIONS[row['ArtifactRole']])
        self.equal_typed(covered['Cells'][0], expected)
        self.assertEqual(covered['RequiredCellsSatisfied'], 1)
        self.assertEqual(len(missing['Cells']), 2773)

    def test_verified_list_and_key_have_literal_types(self):
        values = (None, False, 0, 1, (), KEY, (KEY,), ListAlias(), ListAlias([KEY]),
                  [list(KEY)], [TupleAlias(KEY)], [()], [True], [1], [KEY, KEY],
                  [KEY, KEY[:3] + ('O2-lto', 'direct')],
                  [(TextAlias(COHORT),) + KEY[1:]])
        for value in values:
            with self.subTest(value=repr(value)):
                self.rejects(self.required, self.backlog, value)

    def test_only_exact_os_key_and_axes_can_receive_credit(self):
        values = [('foreign',) + KEY[1:], KEY[:1] + ('common',) + KEY[2:],
                  KEY[:1] + ('secure_companion',) + KEY[2:],
                  KEY[:2] + ('object',) + KEY[3:], KEY[:3] + ('O2-lto', 'direct'),
                  KEY[:3] + ('Os', 'direct'), KEY[:4] + ('archive',),
                  KEY[:3] + (True, 'direct'), KEY[:3] + (2.0, 'direct'),
                  (COHORT.upper(),) + KEY[1:], (COHORT + ' ',) + KEY[1:],
                  KEY[:4] + ('direct\x00',)]
        for value in values:
            with self.subTest(value=value):
                self.rejects(self.required, self.backlog, [value])

    def test_selected_source_group_and_cohort_hash_bound_even_for_zero(self):
        for field, value in (('SourceGroup', 'CM4'), ('SourceGroup', True),
                             ('CohortSha256', SOURCE_SHA), ('CohortSha256', 'A' * 64),
                             ('CohortSha256', COHORT_SHA.lower()), ('CohortSha256', False)):
            for keys in ([], [KEY]):
                required = deepcopy(self.required)
                required['RequiredCells'][self.selected][field] = value
                with self.subTest(field=field, value=value, keys=keys):
                    self.rejects(required, self.backlog, keys)

    def test_selected_key_absence_cannot_be_normalized(self):
        for field, value in (('Cohort', 'foreign'), ('Mode', 'O2-lto'),
                             ('Linkage', 'archive'), ('ArtifactRole', 'common')):
            required = deepcopy(self.required)
            row = required['RequiredCells'][self.selected]
            row[field] = value
            # Keep the replacement well formed and unique, without claiming canonical authority.
            row['Cohort'] = 'selected-key-removed'
            with self.subTest(field=field):
                self.rejects(required, self.backlog, [])

    def test_complete_plan_missing_extra_duplicate_rows_on_zero_and_one(self):
        for change in ('missing', 'extra', 'duplicate', 'empty', 'not-list'):
            required = deepcopy(self.required)
            rows = required['RequiredCells']
            if change == 'missing':
                rows.pop(0)
            elif change == 'extra':
                rows.append(deepcopy(rows[0]))
            elif change == 'duplicate':
                rows[1] = deepcopy(rows[0])
            elif change == 'empty':
                rows.clear()
            else:
                required['RequiredCells'] = tuple(rows)
            for keys in ([], [KEY]):
                with self.subTest(change=change, keys=keys):
                    self.rejects(required, self.backlog, keys)

    def test_plan_schema_literal_counts_flags_and_json_types(self):
        changes = [('SchemaVersion', True), ('SchemaVersion', 1.0), ('SchemaVersion', 2),
                   ('RequiredCellCount', True), ('RequiredCellCount', 2774.0),
                   ('RequiredCellCount', 2773), ('RequiredCellCount', 2775),
                   ('ExpectedOnly', 1), ('Execution', 'PASS'), ('GlobalFreezeQualified', 0),
                   ('InventoryManifestSha256', 'g' * 64), ('TestFloat', 0.0)]
        for field, value in changes:
            required = deepcopy(self.required)
            required[field] = value
            with self.subTest(field=field, value=value):
                self.rejects(required, self.backlog, [])
        for value in (None, False, [], tuple(self.required)):
            with self.subTest(required_type=type(value).__name__):
                self.rejects(value, self.backlog, [])

    def test_required_row_missing_malformed_axes_and_identity(self):
        changes = [('ArtifactRole', 'foreign'), ('Representation', 'unknown'),
                   ('Mode', 'O1'), ('Linkage', 'direct'), ('SourceGroup', False),
                   ('CohortSha256', False), ('CohortSha256', 'bad'), ('Cohort', ' spaced '),
                   ('Cohort', ''), ('Cohort', True), ('Mode', 'Os-lto')]
        for field, value in changes:
            required = deepcopy(self.required)
            required['RequiredCells'][0][field] = value
            with self.subTest(field=field, value=value):
                self.rejects(required, self.backlog, [])
        for field in (*FIELDS, 'SourceGroup', 'CohortSha256'):
            required = deepcopy(self.required)
            del required['RequiredCells'][0][field]
            with self.subTest(missing=field):
                self.rejects(required, self.backlog, [])

    def test_mode_axes_and_all_three_obligation_catalogs_are_exact(self):
        for field in ('ObjectModes', 'FinalModes'):
            for change in ('missing', 'extra', 'reordered', 'bool'):
                required = deepcopy(self.required)
                if change == 'missing':
                    required[field].pop()
                elif change == 'extra':
                    required[field].append('O1')
                elif change == 'reordered':
                    required[field].reverse()
                else:
                    required[field][0] = False
                with self.subTest(field=field, change=change):
                    self.rejects(required, self.backlog, [])
        for role in OBLIGATIONS:
            for change in ('missing', 'extra', 'reordered', 'bool', 'missing-role', 'extra-role'):
                required = deepcopy(self.required)
                rows = required['PlannedProofRequirements']
                if change == 'missing':
                    rows[role].pop()
                elif change == 'extra':
                    rows[role].append('foreign')
                elif change == 'reordered':
                    rows[role].reverse()
                elif change == 'bool':
                    rows[role][0] = True
                elif change == 'missing-role':
                    del rows[role]
                else:
                    rows['foreign'] = []
                with self.subTest(role=role, change=change):
                    self.rejects(required, self.backlog, [])

    def test_backlog_shape_identity_status_and_json_corruptions(self):
        for change in ('missing', 'extra', 'duplicate', 'empty', 'not-list', 'status',
                       'status-count', 'id-bool', 'id-missing', 'row-type', 'float'):
            backlog = deepcopy(self.backlog)
            if change == 'missing':
                backlog.pop()
            elif change == 'extra':
                backlog.append(deepcopy(backlog[0]))
            elif change == 'duplicate':
                backlog[-1]['id'] = backlog[0]['id']
            elif change == 'empty':
                backlog.clear()
            elif change == 'not-list':
                backlog = tuple(backlog)
            elif change == 'status':
                backlog[0]['status'] = 'PASS'
            elif change == 'status-count':
                row = next(row for row in backlog if row['status'] == 'Pending')
                row['status'] = 'ReferenceOnly'
            elif change == 'id-bool':
                backlog[0]['id'] = True
            elif change == 'id-missing':
                del backlog[0]['id']
            elif change == 'row-type':
                backlog[0] = []
            else:
                backlog[0]['TestFloat'] = 1.0
            with self.subTest(change=change):
                self.rejects(self.required, backlog, [])

    def test_wrong_helper_api_has_explicit_model_rejection(self):
        for helper in (None, object(), {}, {'_plan': c._plan},
                       types.SimpleNamespace(), types.SimpleNamespace(_plan=None),
                       types.SimpleNamespace(_plan=True), types.SimpleNamespace(_plan=[])):
            with self.subTest(helper=repr(helper)), self.assertRaises(m.Rejected):
                m.coverage(self.required, self.backlog, [], coverage_module=helper)

    def test_frozen_plan_is_called_once_with_both_original_inputs(self):
        calls = []
        def planner(required, backlog):
            calls.append((required is self.required, backlog is self.backlog))
            return c._plan(required, backlog)
        result = self.coverage([KEY], types.SimpleNamespace(_plan=planner))
        self.equal_typed(calls, [(True, True)])
        self.assertEqual(result[0]['RequiredCellsSatisfied'], 1)

    def test_helper_shape_rejection_is_explicit_and_keeps_inputs(self):
        before = deepcopy((self.required, self.backlog))
        for keys in ([], [KEY]):
            def reject(required, backlog):
                raise c.Rejected('synthetic malformed complete plan')
            with self.subTest(keys=keys), self.assertRaises(m.Rejected) as caught:
                self.coverage(keys, types.SimpleNamespace(_plan=reject))
            self.assertIsInstance(caught.exception.__cause__, c.Rejected)
        self.equal_typed((self.required, self.backlog), before)

    def test_harness_rejects_vacuous_skipped_or_failed_runs(self):
        names = sorted(EXPECTED_METHOD_NAMES)
        self.assertIs(catalog_matches(names, METHODS), True)
        for changed in (names[:-1], names + [names[0]], ['foreign'] + names[1:]):
            with self.subTest(catalog=changed):
                self.assertIs(catalog_matches(changed, METHODS), False)
        for count in (0, METHODS - 1, METHODS + 1, True, float(METHODS)):
            self.assertIs(catalog_matches(names, count), False)
            candidate = unittest.TestResult()
            candidate.testsRun = count
            self.assertIs(complete_tests(candidate), False)
        for field in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            candidate = unittest.TestResult()
            candidate.testsRun = METHODS
            self.assertIs(complete_tests(candidate), True)
            getattr(candidate, field).append(('synthetic test', 'synthetic detail'))
            with self.subTest(field=field):
                self.assertIs(complete_tests(candidate), False)
        self.assertIs(complete_tests(None), False)

    def test_model_does_not_mutate_helper_or_its_fixed_catalogs(self):
        names = ('MODES', '_SELECTORS', 'COMMON', 'RUNTIME', 'COMPANION', 'KEY_FIELDS',
                 'REQUIRED_CELL_COUNT', 'BACKLOG_COUNT', 'SOURCE_INVENTORY_SHA256')
        before = deepcopy({name: getattr(c, name) for name in names})
        model_names = ('KEY', 'KEY_FIELDS', 'COMMON', 'RUNTIME', 'COHORT', 'COHORT_SHA256',
                       'SOURCE_INVENTORY_SHA256', 'REQUIRED_CELL_COUNT', 'ROUTE')
        model_before = deepcopy({name: getattr(m, name) for name in model_names})
        for keys in ([], [KEY], []):
            self.coverage(keys)
        self.equal_typed({name: getattr(c, name) for name in names}, before)
        self.equal_typed({name: getattr(m, name) for name in model_names}, model_before)

    def test_actual_model_calls_need_no_io_process_or_dynamic_loading(self):
        def forbidden(*args, **kwargs):
            raise AssertionError('pure model attempted I/O, a process or module loading')
        targets = [(io, 'open'), (os, 'open'), (os, 'stat'), (os, 'lstat'),
                   (os, 'listdir'), (os, 'scandir'), (os, 'system'), (os, 'popen'),
                   (subprocess, 'Popen'), (subprocess, 'run'), (importlib, 'import_module')]
        targets += [(Path, name) for name in ('open', 'read_bytes', 'read_text', 'write_bytes',
                    'write_text', 'exists', 'stat', 'lstat', 'resolve', 'iterdir', 'mkdir')]
        with ExitStack() as stack:
            for target, name in targets:
                stack.enter_context(patch.object(target, name, forbidden))
            stack.enter_context(patch.object(builtins, 'open', forbidden))
            stack.enter_context(patch.object(builtins, '__import__', forbidden))
            contract = m.contract()
            zero = self.coverage([])
            one = self.coverage([KEY])
            self.assertRaises(m.Rejected, self.coverage, [KEY, KEY])
        self.assertIs(contract['MetadataOnly'], True)
        self.assertEqual(zero[0]['RequiredCellsSatisfied'], 0)
        self.assertEqual(one[0]['RequiredCellsSatisfied'], 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and not sys.flags.optimize):
        raise SystemExit('use fresh unoptimized python -I -S -B')
    output = args.output_dir.resolve()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    if output == INVENTORY or INVENTORY in output.parents or output in INVENTORY.parents:
        raise SystemExit('output must be disjoint from fixture inventory')
    result, error, error_traceback, initialized = None, None, None, False
    names, loaded_count, valid_catalog = [], 0, False
    try:
        initialize()
        initialized = True
        names = unittest.defaultTestLoader.getTestCaseNames(CellModelTests)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CellModelTests)
        loaded_count = suite.countTestCases()
        valid_catalog = catalog_matches(names, loaded_count)
        if not valid_catalog:
            raise ValueError('exact fixed method catalog and %d loaded tests required' % METHODS)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    except Exception as caught:
        error = type(caught).__name__ + ': ' + str(caught)
        error_traceback = traceback.format_exc()
    drift, closed = [], set()
    for path, raw in OPENED.items():
        try:
            if path.read_bytes() != raw:
                drift.append(str(path))
            else:
                closed.add(path)
        except OSError as caught:
            drift.append(str(path) + ': ' + type(caught).__name__)
    sources = {MODEL, COVERAGE, Path(__file__).resolve()}
    fixtures = {INVENTORY / name for name in FIXTURE_PINS}
    complete_closing = set(OPENED) == sources | fixtures and closed == sources | fixtures
    successful = (initialized and valid_catalog and complete_tests(result)
                  and complete_closing and not drift and error is None)
    report = dict(Status='PASS' if successful else 'FAIL', Tests=result.testsRun if result else 0,
        ExpectedTests=METHODS, LoadedTests=loaded_count, MethodCatalog=names,
        ExactMethodCatalogVerified=valid_catalog,
        Failures=len(result.failures) if result else 0, Errors=len(result.errors) if result else 1,
        Skipped=len(result.skipped) if result else 0,
        ExpectedFailures=len(result.expectedFailures) if result else 0,
        UnexpectedSuccesses=len(result.unexpectedSuccesses) if result else 0,
        FailureDetails=[dict(Test=str(test), Traceback=detail) for test, detail in result.failures] if result else [],
        ErrorDetails=[dict(Test=str(test), Traceback=detail) for test, detail in result.errors] if result else [],
        SkipDetails=[dict(Test=str(test), Reason=reason) for test, reason in result.skipped] if result else [],
        ExpectedFailureDetails=[dict(Test=str(test), Traceback=detail)
                                for test, detail in result.expectedFailures] if result else [],
        UnexpectedSuccessDetails=[str(test) for test in result.unexpectedSuccesses] if result else [],
        Error=error, ErrorTraceback=error_traceback, SourceDrift=drift,
        ClosingBytesExpected=7, ClosingBytesVerified=len(closed), CompleteClosingVerified=complete_closing,
        SourceFilesExpected=3, SourceFilesClosed=len(sources & closed),
        FixtureFilesExpected=4, FixtureFilesClosed=len(fixtures & closed),
        SourceHashes={str(path): sha(raw) for path, raw in OPENED.items()
                      if path in (MODEL, COVERAGE, Path(__file__).resolve())},
        FixtureHashes={str(path): sha(raw) for path, raw in OPENED.items() if path.is_relative_to(INVENTORY)},
        FixtureInventory=str(INVENTORY),
        FixtureRequiredRows=len(REQUIRED['RequiredCells']) if REQUIRED is not None else 0,
        FixtureBacklogRows=len(BACKLOG) if BACKLOG is not None else 0,
        FixtureHashBindingsChecked=initialized, CompleteInventoryTreeAuthenticated=False,
        PlanShapeNotCanonicalProfileOracle=True, SyntheticCorruptionsOnly=True,
        MetadataAccountingOnly=True, VerifiedKeysCallerAuthorityOnly=True,
        InputAuthenticationProof=False, ActualAdmission=False, ProofExecutor=False,
        ActualELFQualified=False, Qualification=False, CellContractSatisfied=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CompilerInvocations=0,
        ToolInvocations=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    target = output / 'results.json'
    if target.write_bytes(raw) != len(raw) or target.read_bytes() != raw:
        raise RuntimeError('incomplete standalone test receipt')
    print(json.dumps(dict(Status=report['Status'], Tests=report['Tests'], Failures=report['Failures'],
        Errors=report['Errors'], SourceDrift=drift, Receipt=str(target), ReceiptSha256=sha(raw)),
        sort_keys=True), flush=True)
    return 0 if successful else 1


if __name__ == '__main__':
    raise SystemExit(main())
