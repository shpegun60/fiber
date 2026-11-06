"""Pure composition accounting and fail-closed controls; no compiler or ELF proof."""
import copy
import importlib.util
import importlib.machinery
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).with_name('compose.py')
SOURCE = PATH.read_bytes()
SPEC = importlib.util.spec_from_file_location('_cm0_compose_pure', PATH)
c = importlib.util.module_from_spec(SPEC)
exec(compile(SOURCE, str(PATH), 'exec'), c.__dict__)

COMMON = ['cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity']
RUNTIME = ['forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls']
DIFFERENCES = ['FAP-COMMON-START', 'FAP-COMMON-PROVENANCE', 'FAP-CM0-STAGED-FRAME',
               'FAP-COMMON-SCHEDULER', 'FAP-COMMON-MASK-RESTORE']


def fixture():
    rows = [dict(Cohort='other-' + str(index), ArtifactRole='runtime', Representation='object',
                 Mode='O0', Linkage='none', SourceGroup='OTHER') for index in range(2773)]
    rows.insert(15, dict(Cohort='cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default',
        ArtifactRole='runtime', Representation='final', Mode='O2', Linkage='direct', SourceGroup='CM0'))
    return (dict(RequiredCellCount=2774, RequiredCells=rows,
                 PlannedProofRequirements=dict(common=COMMON, runtime=RUNTIME)),
            [dict(Id='pending-' + str(index), Status='Pending') for index in range(26)])


def ledger():
    return ('# Ledger\n\n' + ''.join('### ' + name + '\n\nA distinct documented reason.\n\n'
                                   for name in DIFFERENCES)).encode('ascii')


class ComposeTests(unittest.TestCase):
    def test_exact_cell_is_only_credit_without_dropping_plan_or_backlog(self):
        required, backlog = fixture()
        before = copy.deepcopy((required, backlog))
        coverage, missing = c.coverage(required, backlog, True)
        self.assertEqual(coverage['RequiredCellsSatisfied'], 1)
        self.assertEqual(len(coverage['Cells']), 2774)
        selected = [row for row in coverage['Cells'] if row['RequiredCellSatisfied']]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['SourceGroup'], 'CM0')
        self.assertEqual(selected[0]['Status'], 'BOUNDED_STATIC_CELL_VERIFIED')
        self.assertEqual(len(missing['Cells']), 2773)
        self.assertEqual(missing['Backlog'], backlog)
        self.assertIs(coverage['GlobalFreezeQualified'], False)
        self.assertIs(missing['GlobalFreezeQualified'], False)
        self.assertEqual([c.cell_key(row) for row in coverage['Cells']],
                         [c.cell_key(row) for row in required['RequiredCells']])
        self.assertEqual((required, backlog), before)

    def test_incomplete_closure_keeps_all_cells_pending(self):
        required, backlog = fixture()
        coverage, missing = c.coverage(required, backlog, False)
        self.assertEqual(coverage['RequiredCellsSatisfied'], 0)
        self.assertEqual(len(missing['Cells']), 2774)
        self.assertTrue(all(row['Status'] == 'PENDING' and row['RequiredCellSatisfied'] is False
                            and row['MissingWholeCellRequirements'] == RUNTIME for row in coverage['Cells']))

    def test_wrong_count_duplicate_key_and_wrong_exact_source_group_reject(self):
        for kind in ('count', 'bool-count', 'length', 'duplicate', 'source-group', 'mode', 'requirements', 'backlog'):
            required, backlog = fixture()
            if kind == 'count':
                required['RequiredCellCount'] = 2773
            elif kind == 'bool-count':
                required['RequiredCellCount'] = True
            elif kind == 'length':
                required['RequiredCells'].pop()
            elif kind == 'duplicate':
                required['RequiredCells'][0] = required['RequiredCells'][1]
            elif kind == 'source-group':
                required['RequiredCells'][15]['SourceGroup'] = 'FOREIGN'
            elif kind == 'mode':
                required['RequiredCells'][15]['Mode'] = 'O3'
            elif kind == 'requirements':
                required['PlannedProofRequirements']['runtime'] = RUNTIME[:-1]
            else:
                backlog.pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                c.coverage(required, backlog, True)
        required, backlog = fixture()
        for numeric in (0, 1, None, 'true'):
            with self.subTest(numeric=numeric), self.assertRaises(ValueError):
                c.coverage(required, backlog, numeric)

    def test_output_containers_are_not_shared_or_aliases_of_input(self):
        required, backlog = fixture()
        first, missing = c.coverage(required, backlog, True)
        first['Cells'][0]['Mode'] = 'MUTANT'
        missing['Backlog'][0]['Status'] = 'MUTANT'
        second, missing2 = c.coverage(required, backlog, True)
        self.assertEqual(second['Cells'][0]['Mode'], 'O0')
        self.assertEqual(missing2['Backlog'][0]['Status'], 'Pending')

    def test_five_unique_nonempty_rationales_are_bound_to_bytes(self):
        raw = ledger()
        rows = c.rationale_facts(raw, DIFFERENCES)
        self.assertEqual([row['Id'] for row in rows], DIFFERENCES)
        self.assertTrue(all(row['RationaleSha256'] == c.sha(b'A distinct documented reason.') for row in rows))
        self.assertEqual(c.rationale_facts(raw.replace(b'\n', b'\r\n'), DIFFERENCES), rows)

    def test_missing_duplicate_empty_or_foreign_ledger_rationale_rejects(self):
        raw = ledger()
        variants = (raw.replace(b'### FAP-COMMON-START', b'### FOREIGN', 1),
                    raw + b'### FAP-COMMON-START\n\nDuplicate.\n',
                    raw.replace(b'A distinct documented reason.', b'', 1))
        for value in variants:
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                c.rationale_facts(value, DIFFERENCES)
        with self.assertRaises(ValueError):
            c.rationale_facts(raw, DIFFERENCES[::-1])

    def test_late_failure_revokes_each_credit_and_obligation(self):
        report = dict(Status='PASS', CellContractSatisfied=True, RequiredCellSatisfied=True,
            RequiredCellsSatisfied=1, InputClosureVerified=True, OutputSealVerified=True,
            CommonPrerequisites={name: dict(Satisfied=True) for name in COMMON},
            RuntimeObligations={name: dict(Satisfied=True) for name in RUNTIME})
        c.revoke(report, RuntimeError('late output drift'))
        self.assertEqual(report['Status'], 'FAIL')
        self.assertEqual(report['RequiredCellsSatisfied'], 0)
        self.assertEqual(report['PrimaryError'], 'RuntimeError: late output drift')
        for name in ('CellContractSatisfied', 'RequiredCellSatisfied', 'InputClosureVerified', 'OutputSealVerified'):
            self.assertIs(report[name], False)
        self.assertTrue(all(row['Satisfied'] is False for group in ('CommonPrerequisites', 'RuntimeObligations')
                            for row in report[group].values()))

    def test_readonly_pilot_receives_original_source_authority(self):
        sources = [dict(Source='source-' + str(index), Object='object-' + str(index),
                        ObjectSha256='hash-' + str(index)) for index in range(9)]
        received = []

        class Pilot:
            def prelink(self):
                received.append(copy.deepcopy(self.report['Sources']))
                self.report['StartupPredicate'] = 'matched'

            def audit_final(self, path):
                received.append(path)

        result = dict(Sources=sources, StartupPredicate='matched', Links=[dict(Path='a.elf'), dict(Path='b.elf')])
        native_api = SimpleNamespace(Pilot=Pilot, selection=lambda *_: (None, None, 'arm_cm0'),
                                     require_manifest_selection=lambda *_: dict(target=dict(vtor=False)))
        native = dict(Result=result, Root=Path('fixture'))
        c.recheck_pilot(native, native_api, object(), object(), {})
        self.assertEqual(received, [sources, Path('a.elf'), Path('b.elf')])
        self.assertEqual(result['Sources'], sources)

    def test_recovery_persists_fail_before_a_coverage_write_error(self):
        required, backlog = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            receipt = output / 'results.json'
            receipt.write_bytes(c.encoded(dict(Status='PASS', RequiredCellsSatisfied=1)))
            report = dict(ClosingErrors=[], CommonPrerequisites={}, RuntimeObligations={})
            c.revoke(report, RuntimeError('late seal failure'))
            actual_write = Path.write_bytes
            observed = []

            def write(path, raw):
                observed.append(path.name)
                if path.name == 'coverage.json':
                    self.assertEqual(json.loads(receipt.read_bytes())['Status'], 'FAIL')
                    raise OSError('coverage blocked')
                return actual_write(path, raw)

            api = SimpleNamespace(files_under=lambda root: {p.name: p for p in root.iterdir() if p.is_file()})
            with patch.object(Path, 'write_bytes', write):
                c.recover(api, output, report, required, backlog)
            stored = json.loads(receipt.read_bytes())
            self.assertEqual(observed[0], 'results.json')
            self.assertEqual(stored['Status'], 'FAIL')
            self.assertEqual(stored['RequiredCellsSatisfied'], 0)
            self.assertEqual(stored['PrimaryError'], 'RuntimeError: late seal failure')
            self.assertTrue(any('coverage blocked' in value for value in stored['ClosingErrors']))
            self.assertEqual(json.loads((output / 'missing-work.json').read_bytes())['RequiredCellsSatisfied'], 0)
            manifest = json.loads((output / 'artifacts.json').read_bytes())['Artifacts']
            self.assertEqual(manifest['results.json'], c.sha(receipt.read_bytes()))

    def test_recovery_retries_failed_receipt_and_records_manifest_error(self):
        required, backlog = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            receipt = output / 'results.json'
            receipt.write_bytes(c.encoded(dict(Status='PASS', RequiredCellsSatisfied=1)))
            report = dict(ClosingErrors=[], CommonPrerequisites={}, RuntimeObligations={})
            c.revoke(report, RuntimeError('original failure'))
            actual_write, attempts = Path.write_bytes, []

            def write(path, raw):
                attempts.append(path.name)
                if path.name == 'results.json' and attempts.count(path.name) == 1:
                    raise OSError('first receipt write')
                return actual_write(path, raw)

            def files(_):
                raise OSError('manifest enumeration')

            with patch.object(Path, 'write_bytes', write):
                c.recover(SimpleNamespace(files_under=files), output, report, required, backlog)
            stored = json.loads(receipt.read_bytes())
            self.assertEqual(stored['Status'], 'FAIL')
            self.assertEqual(stored['PrimaryError'], 'RuntimeError: original failure')
            self.assertTrue(any('first receipt write' in value for value in stored['ClosingErrors']))
            self.assertTrue(any('manifest enumeration' in value for value in stored['ClosingErrors']))
            self.assertEqual(attempts.count('results.json'), 3)

    def test_immutable_readers_ignore_transient_input_and_helper_replacement(self):
        loader = c.ROOT / 'tools/fixtures/cm3_final_roots/reference_witness.py'
        pin = 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'
        api = SimpleNamespace(LOADER=loader.relative_to(c.ROOT).as_posix(), SOURCE_PINS={loader.relative_to(c.ROOT).as_posix(): pin})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, helper = root / 'input.elf', root / 'helper.py'
            artifact.write_bytes(b'admitted ELF bytes\r\n')
            helper.write_bytes(b'value = 71\n')
            snapshots = {path.resolve(): path.read_bytes() for path in (loader, artifact, helper)}

            class Watch:
                hashes = {path: c.sha(raw) for path, raw in snapshots.items()}

                def read(self, path, expected):
                    raw = Path(path).read_bytes()
                    if c.sha(raw) != expected:
                        raise ValueError('fixture drift before capture')
                    return raw

            copies = root / 'copies'
            copies.mkdir()
            original_write = Path.write_bytes
            try:
                with c.immutable_reads(api, Watch(), copies, (root, c.ROOT)) as evidence:
                    original_write(artifact, b'transient bad ELF')
                    original_write(helper, b'raise RuntimeError("transient helper")\n')
                    self.assertEqual(artifact.read_bytes(), snapshots[artifact])
                    self.assertEqual(artifact.read_text(), 'admitted ELF bytes\n')
                    code = importlib.machinery.SourceFileLoader('frozen_test', str(helper)).get_code('frozen_test')
                    namespace = {}
                    exec(code, namespace)
                    self.assertEqual(namespace['value'], 71)
                    spec = importlib.util.spec_from_file_location('frozen_spec', helper)
                    loaded = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(loaded)
                    self.assertEqual(loaded.value, 71)
                    copied = copies / 'copy.elf'
                    copied.write_bytes(snapshots[artifact])
                    original_write(copied, b'transient bad copy')
                    self.assertEqual(copied.read_bytes(), snapshots[artifact])
                    with self.assertRaises(ValueError):
                        (copies / 'unadmitted').write_bytes(b'new unadmitted data')
                    unknown = root / 'unknown'
                    with self.assertRaises(ValueError):
                        unknown.read_bytes()
                    with self.assertRaises(ValueError):
                        artifact.write_bytes(snapshots[artifact])
                    original_write(copied, snapshots[artifact])
            finally:
                original_write(artifact, snapshots[artifact])
                original_write(helper, snapshots[helper])
            self.assertEqual(artifact.read_bytes(), snapshots[artifact])
            self.assertEqual(helper.read_bytes(), snapshots[helper])
            self.assertEqual(len(evidence['PackageCode']), 1)
            self.assertEqual(len(evidence['HelperCode']), 1)
            self.assertEqual(len(evidence['CaptureAliases']), 1)

    def test_nonclaims_are_independent_of_bounded_static_cell_credit(self):
        for name in ('FullSemanticABIProof', 'WholeProviderEquivalence', 'InstructionEquivalence',
                     'PolicyEquivalence', 'SourceIRProof', 'CpuExecution', 'BoardExecution',
                     'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified'):
            self.assertIn(name, c.NONCLAIMS)
        self.assertNotIn('CellContractSatisfied', c.NONCLAIMS)
        self.assertEqual(PATH.read_bytes(), SOURCE)

    def test_buffered_path_resolution_cannot_redirect_to_another_admitted_input(self):
        loader = c.ROOT / 'tools/fixtures/cm3_final_roots/reference_witness.py'
        pin = 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'
        api = SimpleNamespace(LOADER=loader.relative_to(c.ROOT).as_posix(), SOURCE_PINS={loader.relative_to(c.ROOT).as_posix(): pin})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first, second = root / 'first.elf', root / 'second.elf'
            helper, other = root / 'helper.py', root / 'other.py'
            for path, raw in ((first, b'first ELF'), (second, b'second ELF'),
                              (helper, b'value = 71\n'), (other, b'value = 99\n')):
                path.write_bytes(raw)
            snapshots = {path.resolve(): path.read_bytes() for path in (loader, first, second, helper, other)}

            class Watch:
                hashes = {path: c.sha(raw) for path, raw in snapshots.items()}

                def read(self, path, expected):
                    raw = Path(path).read_bytes()
                    if c.sha(raw) != expected:
                        raise ValueError('fixture drift before capture')
                    return raw

            copies = root / 'copies'
            copies.mkdir()
            with c.immutable_reads(api, Watch(), copies, (root, c.ROOT)) as evidence:
                def redirected(path, **_):
                    return str({first: second, helper: other}.get(Path(path), Path(path)))

                with patch.object(c.os.path, 'realpath', side_effect=redirected) as physical:
                    self.assertEqual(first.resolve(strict=True), first)
                    self.assertEqual(first.read_bytes(), b'first ELF')
                    self.assertEqual(second.read_bytes(), b'second ELF')
                    self.assertEqual((root / 'missing/../first.elf').resolve(), first)
                    namespace = {}
                    code = importlib.machinery.SourceFileLoader('identity_test', str(helper)).get_code('identity_test')
                    exec(code, namespace)
                    self.assertEqual(namespace['value'], 71)
                    spec = importlib.util.spec_from_file_location('identity_spec', helper)
                    loaded = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(loaded)
                    self.assertEqual(loaded.value, 71)
                    (copies / 'first.elf').write_bytes(b'first ELF')
                    self.assertEqual((copies / 'first.elf').read_bytes(), b'first ELF')
                    physical.assert_not_called()
            self.assertEqual(first.resolve(strict=True), first)
            self.assertEqual(evidence['PathResolution'], 'LEXICAL_ONLY_WITH_REAL_PHYSICAL_CLOSING_OUTSIDE_SCOPE')


if __name__ == '__main__':
    unittest.main(verbosity=2)
