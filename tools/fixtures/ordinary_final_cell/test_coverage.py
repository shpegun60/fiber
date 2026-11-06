"""Pure accounting controls over an authenticated E9 data copy; no tool runs."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SUBJECT = HERE / 'coverage.py'
PROFILE = HERE / 'profiles.py'
INVENTORY = Path('C:/fzin-20261104-e9')
PROFILE_SHA = 'BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD'
MANIFEST_SHA = '640C2CAC37DFC0A10F5A6E8538E7A9F81C7967DEEDEAA4B2924A15CAA1600CEA'
RAW_MANIFEST_SHA = 'BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE'
NAMES = ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM3', 'CM4', 'CM7')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
COMMON = ['cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity']
RUNTIME = ['forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls']
FIELDS = ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(path, raw):
    module = types.ModuleType('_pure_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def key(row):
    return tuple(row[field] for field in FIELDS)


class CoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.opened = {path: path.read_bytes() for path in
                      (SUBJECT, Path(__file__).resolve(), PROFILE, INVENTORY / 'artifacts.json')}
        if sha(cls.opened[PROFILE]) != PROFILE_SHA or sha(cls.opened[INVENTORY / 'artifacts.json']) != MANIFEST_SHA:
            raise AssertionError('opening profile/inventory authority')
        artifacts = json.loads(cls.opened[INVENTORY / 'artifacts.json'])['Artifacts']
        for relative in ('required-cells.json', 'inputs/tools/freeze_cohorts.json'):
            path = INVENTORY / relative
            raw = path.read_bytes()
            if sha(raw) != artifacts[relative]:
                raise AssertionError('same-buffer authenticated inventory data')
            cls.opened[path] = raw
        if sha(cls.opened[INVENTORY / 'inputs/tools/freeze_cohorts.json']) != RAW_MANIFEST_SHA:
            raise AssertionError('raw manifest authority is not its canonical fingerprint')
        cls.required = json.loads(cls.opened[INVENTORY / 'required-cells.json'])
        cls.backlog = json.loads(cls.opened[INVENTORY / 'inputs/tools/freeze_cohorts.json'])['scope_backlog']
        cls.c = load(SUBJECT, cls.opened[SUBJECT])
        cls.p = load(PROFILE, cls.opened[PROFILE])

    @classmethod
    def tearDownClass(cls):
        for path, raw in cls.opened.items():
            if path.read_bytes() != raw:
                raise AssertionError('closing fixture/source drift: ' + str(path))

    def setUp(self):
        self.plan = deepcopy(self.required)
        self.queue = deepcopy(self.backlog)
        self.contracts = [self.p.profile(name, mode) for name in NAMES for mode in MODES]

    def call(self, verified, contracts=None):
        return self.c.coverage(self.plan, self.queue,
                               self.contracts if contracts is None else contracts, verified)

    def test_each_thirty_route_has_only_its_exact_key_credited(self):
        original = [key(row) for row in self.plan['RequiredCells']]
        for contract in self.contracts:
            with self.subTest(route=contract['Route']):
                covered, missing = self.call([key(contract)], [contract])
                self.assertEqual([key(row) for row in covered['Cells']], original)
                passed = [row for row in covered['Cells'] if row['RequiredCellSatisfied']]
                self.assertEqual(len(passed), 1)
                self.assertEqual(key(passed[0]), key(contract))
                self.assertEqual(passed[0]['SourceGroup'], contract['SourceGroup'])
                self.assertEqual(passed[0]['MissingWholeCellRequirements'], [])
                self.assertEqual(covered['RequiredCellsSatisfied'], 1)
                self.assertEqual(len(missing['Cells']), 2773)

    def test_all_contracts_preserve_plan_order_and_role_obligations(self):
        verified = [key(row) for row in reversed(self.contracts)]
        covered, missing = self.call(verified)
        self.assertEqual(covered['RequiredCellsSatisfied'], 30)
        self.assertEqual(len(missing['Cells']), 2744)
        self.assertEqual(covered['PlannedProofRequirements']['common'], COMMON)
        self.assertEqual(covered['PlannedProofRequirements']['runtime'], RUNTIME)
        wanted_missing = []
        for original, row in zip(self.plan['RequiredCells'], covered['Cells']):
            for field, value in original.items():
                self.assertEqual(row[field], value)
            remaining = [] if key(original) in verified else self.plan['PlannedProofRequirements'][original['ArtifactRole']]
            self.assertEqual(row['MissingWholeCellRequirements'], remaining)
            if remaining:
                wanted_missing.append(dict(Key=list(key(original)), MissingWholeCellRequirements=remaining))
        self.assertEqual(missing['Cells'], wanted_missing)

    def test_empty_final_verified_list_revokes_all_prior_credit(self):
        keys = [key(contract) for contract in self.contracts]
        prior = self.call(keys)
        revoked = self.call([])
        self.assertEqual(prior[0]['RequiredCellsSatisfied'], 30)
        self.assertEqual(revoked[0]['RequiredCellsSatisfied'], 0)
        self.assertEqual(len(revoked[1]['Cells']), 2774)
        self.assertTrue(all(row['RequiredCellSatisfied'] is False for row in revoked[0]['Cells']))
        for contract in self.contracts:
            contract.update(Status='PASS', Verdict='PASS', PriorReceipt='PASS')
        self.assertEqual(self.call([])[0]['RequiredCellsSatisfied'], 0)
        self.assertEqual(self.call([], [])[0]['RequiredCellsSatisfied'], 0)

    def test_inputs_outputs_and_all_twenty_six_backlog_records_are_independent(self):
        self.queue[0]['retained_annotation'] = {'nested': ['unchanged']}
        before = deepcopy((self.plan, self.queue, self.contracts))
        covered, missing = self.call([key(self.contracts[0])])
        self.assertEqual((self.plan, self.queue, self.contracts), before)
        self.assertEqual(missing['Backlog'], self.queue)
        self.assertEqual(sum(row['status'] == 'Pending' for row in missing['Backlog']), 23)
        self.assertEqual(sum(row['status'] == 'ReferenceOnly' for row in missing['Backlog']), 3)
        missing['Backlog'][0]['retained_annotation']['nested'].append('output-only')
        covered['Cells'][0]['SourceGroup'] = 'output-only'
        covered['PlannedProofRequirements']['runtime'].clear()
        self.assertEqual((self.plan, self.queue, self.contracts), before)
        self.assertNotEqual(covered['Cells'][0]['MissingWholeCellRequirements'], [])
        self.assertEqual(len(missing['Cells'][0]['MissingWholeCellRequirements']), 8)

    def test_duplicate_or_incomplete_required_inventory_rejects(self):
        for mutation in ('count', 'missing', 'duplicate', 'unknown-key', 'unknown-role'):
            self.plan = deepcopy(self.required)
            if mutation == 'count':
                self.plan['RequiredCellCount'] = 2755
            elif mutation == 'missing':
                self.plan['RequiredCells'].pop()
            elif mutation == 'duplicate':
                self.plan['RequiredCells'][-1] = deepcopy(self.plan['RequiredCells'][0])
            elif mutation == 'unknown-key':
                self.plan['RequiredCells'][0]['Mode'] = 'O1'
            else:
                self.plan['RequiredCells'][0]['ArtifactRole'] = 'unknown'
            with self.subTest(mutation=mutation), self.assertRaises(self.c.Rejected):
                self.call([])

    def test_exact_common_runtime_and_companion_obligations_required(self):
        for role in ('common', 'runtime', 'secure_companion'):
            for change in ('missing', 'reorder', 'extra'):
                self.plan = deepcopy(self.required)
                rows = self.plan['PlannedProofRequirements'][role]
                if change == 'missing':
                    rows.pop()
                elif change == 'reorder':
                    rows.reverse()
                else:
                    rows.append('invented-proof')
                with self.subTest(role=role, change=change), self.assertRaises(self.c.Rejected):
                    self.call([])

    def test_source_group_and_each_selected_route_axis_are_bound(self):
        for field, value in (('SourceGroup', 'CM4'), ('Cohort', 'foreign'), ('Profile', 'CM55'),
                             ('Mode', 'O2-lto'), ('Route', 'CM0/O2/archive'), ('Linkage', 'archive'),
                             ('Representation', 'object'), ('ArtifactRole', 'secure_companion'),
                             ('SourceInventorySha256', 'A' * 64)):
            contract = self.p.profile('CM0', 'O2')
            contract[field] = value
            with self.subTest(field=field), self.assertRaises(self.c.Rejected):
                self.call([], [contract])
        target = key(self.contracts[0])
        row = next(row for row in self.plan['RequiredCells'] if key(row) == target)
        row['SourceGroup'] = 'CM4'
        with self.assertRaises(self.c.Rejected):
            self.call([], [self.contracts[0]])

    def test_malformed_duplicate_and_promoted_contracts_reject(self):
        for field, value in (('LTO', 0), ('RequiredCellsSatisfied', False), ('RequiredCellSatisfied', 0),
                             ('MetadataOnly', 1), ('FullABIProof', True), ('FullSemanticABIProof', True),
                             ('CpuExecution', 0), ('GlobalFreezeQualified', True), ('CommonRequirements', []),
                             ('CohortArtifact', {'role': 'runtime', 'source_group_id': 'CM4', 'abi_contract': 'forward8'})):
            contract = deepcopy(self.contracts[0])
            contract[field] = value
            with self.subTest(field=field), self.assertRaises(self.c.Rejected):
                self.call([], [contract])
        for contracts in ([self.contracts[0], deepcopy(self.contracts[0])], [None], [{}], self.contracts[0]):
            with self.subTest(contracts_type=type(contracts).__name__), self.assertRaises(self.c.Rejected):
                self.call([], contracts)

    def test_verified_keys_are_unique_literal_tuples_selected_in_this_call(self):
        first = key(self.contracts[0])
        foreign = (first[0], 'runtime', 'final', 'Os-lto', 'direct')
        for verified in ([first, first], [list(first)], [foreign], [first[:-1]], ['PASS'],
                         [(first[0], 'runtime', 'final', True, 'direct')], {first}, True, (first,)):
            with self.subTest(verified_type=type(verified).__name__), self.assertRaises(self.c.Rejected):
                self.call(verified, [self.contracts[0]])
        with self.assertRaises(self.c.Rejected):
            self.call([key(self.contracts[-1])], [self.contracts[0]])

    def test_integer_boolean_aliases_and_non_json_values_reject(self):
        for field, value in (('RequiredCellCount', True), ('RequiredCellCount', 2774.0),
                             ('SchemaVersion', True), ('SchemaVersion', 1.0), ('ExpectedOnly', 1),
                             ('GlobalFreezeQualified', 0), ('ObjectModes', tuple(MODES))):
            self.plan = deepcopy(self.required)
            self.plan[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(self.c.Rejected):
                self.call([])

    def test_backlog_missing_duplicate_wrong_status_or_count_rejects(self):
        for change in ('missing', 'duplicate', 'status', 'counts'):
            self.queue = deepcopy(self.backlog)
            if change == 'missing':
                self.queue.pop()
            elif change == 'duplicate':
                self.queue[-1]['id'] = self.queue[0]['id']
            elif change == 'status':
                self.queue[0]['status'] = 'Qualified'
            else:
                self.queue[0]['status'] = 'ReferenceOnly'
            with self.subTest(change=change), self.assertRaises(self.c.Rejected):
                self.call([])

    def test_pure_no_fs_or_process_and_no_broad_proof_promotion(self):
        with patch('builtins.open', side_effect=AssertionError('no file I/O')), \
             patch.object(Path, 'read_bytes', side_effect=AssertionError('no file I/O')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('no process')):
            result = self.call([key(self.contracts[0])], [self.contracts[0]])
        for report in result:
            for name in ('GlobalFreezeQualified', 'FullABIProof', 'FullSemanticABIProof',
                         'CpuExecution', 'BoardExecution', 'HostedCIQualified'):
                self.assertIs(report[name], False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
