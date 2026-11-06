"""Synthetic ABI-attempt orchestration controls; no compiler or ELF execution."""

import argparse
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'abi_attempt.py'
RECIPES = HERE / 'batch_recipes.py'
RUNNER = HERE / 'runner.py'
PINS = {RECIPES: 'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B',
        RUNNER: '1B4BFC82D20398FA4F128B368104360C888C27DDBF5104ED74A80819F4371716'}
FACTS = ('ABIControlsBuilt', 'PositiveLinkRevalidated', 'FiveLinkControlsValidated',
         'TypedDeclarationProbesValidated', 'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified',
         'NegativeLinkControlsExecuted')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'CurrentSlotIsolationProven', 'CanonicalProtocolValidated', 'FinalRootRelocationProof',
    'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven',
    'FinalReferenceParity', 'CompleteObjectProof', 'PolicyEquivalence', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'KernelRuntimeProof',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified',
    'RequiredCellSatisfied', 'CellContractSatisfied', 'ProducerCompilersReexecuted')
EXPECTED_METHODS = 20
BUFFERS, subject, recipes, runner = {}, None, None, None
GCC = 'C:/synthetic/toolchain/bin/arm-none-eabi-gcc.exe'


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def commands():
    return [dict(Label=row['Label'], State='TERMINAL', TimedOut=False,
        Status='EXPECTED-NONZERO' if row['ExpectedExit'] else 'PASS', Exit=row['ExpectedExit'],
        ExpectedExit=row['ExpectedExit'], JournalErrors=[], Argv=[GCC, 'synthetic-only'])
        for row in recipes.batch_plan()['Commands'][:41]]


def completed():
    return dict(Status=subject.PASS, Scope=subject.SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        LTO=True, Commands=commands(), Phases=[dict(Name='ABIControls', First=0, Stop=41, Commands=41)],
        RequiredCellCount=2774, RequiredCellsSatisfied=0, Error=None, PrimaryError=None, ClosingErrors=[],
        **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))


class FakeSuite:
    """Only filesystem/journal scaffolding, never a qualified command executor."""
    def __init__(self, output):
        self.output, self.commands, self.expected = output, [], {}
        self.tools = dict(gcc=Path(GCC))
        self.report = completed()
        self.report.update(Status='FAIL', **dict.fromkeys(FACTS, False))
        self.events = []
        self.verify_objects = Mock(side_effect=lambda: self.events.append('objects'))
        self.checks = 0
        self.after_check = None
        self.before_save = None

    def start(self):
        self.events.append('start')
        self.output.mkdir()
        self._save('results.json', self.report)
        self._save('commands.json', [])

    def build(self, suite, helpers):
        if suite is not self:
            raise AssertionError('wrong synthetic suite')
        self.events.append('build')
        self.commands = commands()
        self.report.update(NegativeLinkControlsExecuted=True, **dict.fromkeys(FACTS[:4], True))
        self._save('commands.json', self.commands)

    def _save(self, name, value):
        self.events.append('save ' + name)
        if self.before_save is not None:
            self.before_save(name, value)
        raw = encoded(value)
        (self.output / name).write_bytes(raw)
        self.expected[name] = sha(raw)

    def _verify_outputs(self):
        self.checks += 1
        self.events.append('outputs ' + str(self.checks))
        actual = {path.name: sha(path.read_bytes()) for path in self.output.iterdir() if path.is_file()}
        if actual != self.expected:
            raise ValueError('synthetic declared-output drift')
        if self.after_check is not None:
            self.after_check(self.checks)


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='os-abi-attempt-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.suite = FakeSuite(Path(self.temporary.name) / 'attempt')
        self.witness = SimpleNamespace(output=self.suite.output,
            watch=SimpleNamespace(hashes={Path('C:/synthetic/input'): 'A' * 64}),
            _physical=lambda path: (1, 2, 1, 3), close=Mock())
        self.witness.replay_api = SimpleNamespace(files_under=lambda root:
            {path.relative_to(root).as_posix(): path for path in root.rglob('*') if path.is_file()})
        self.environment = dict(Witness=self.witness)
        self.build = Mock(side_effect=self.suite.build)
        self.helpers = dict(recipes=recipes, abi_controls=SimpleNamespace(build=self.build))

    def replay(self, unused_runner, environment, suite):
        self.assertIs(environment, self.environment)
        self.assertIs(suite, self.suite)
        suite.events.append('replay')
        suite.report.update(PositiveLinkRevalidated=True, ImmutableInputsConsumed=True)

    def run_attempt(self, replay_effect=None):
        with patch.object(subject, 'replay', side_effect=self.replay if replay_effect is None else replay_effect), \
                redirect_stdout(io.StringIO()):
            return subject.run(runner, self.environment, self.helpers, self.suite)

    def failure_receipt(self):
        value = json.loads((self.suite.output / 'results.json').read_bytes())
        self.assertEqual(value['Status'], 'FAIL')
        self.assertIs(value['InputClosureVerified'], False)
        self.assertIs(value['OutputSealVerified'], False)
        self.assertIs(value['ABIControlsBuilt'], False)
        self.assertIs(value['PositiveLinkRevalidated'], False)
        self.assertEqual(value['RequiredCellsSatisfied'], 0)
        return value

    def test_exact_closed_plan_and_literal_facts_are_accepted_without_mutation(self):
        value = completed()
        before = copy.deepcopy(value)
        subject.require_completed(value, self.helpers)
        self.assertEqual(value, before)
        self.assertEqual(len(value['Commands']), 41)
        self.assertEqual(sum(row['ExpectedExit'] for row in value['Commands']), 8)

    def test_wrong_disposition_route_mode_and_lto_types_reject(self):
        for key, bad in (('Status', 'PASS'), ('Scope', 'whole-cell'), ('Profile', 'CM4'), ('Mode', 'O2-lto'),
                         ('Linkage', 'archive'), ('LTO', 1), ('LTO', False)):
            value = completed()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)

    def test_required_proof_facts_must_be_present_literal_true(self):
        for key in FACTS:
            for bad in (None, False, 1, 'true'):
                value = completed()
                value[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    subject.require_completed(value, self.helpers)

    def test_every_command_label_order_and_cardinality_are_exact(self):
        for kind in ('empty', 'short', 'extra', 'order', 'label'):
            value = completed()
            if kind == 'empty':
                value['Commands'] = []
            elif kind == 'short':
                value['Commands'].pop()
            elif kind == 'extra':
                value['Commands'].append(copy.deepcopy(value['Commands'][0]))
            elif kind == 'order':
                value['Commands'][0], value['Commands'][1] = value['Commands'][1], value['Commands'][0]
            else:
                value['Commands'][0]['Label'] = 'foreign command'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)

    def test_command_terminal_timeout_exit_status_and_journal_faults_reject(self):
        for key, bad in (('State', 'ATTEMPT'), ('TimedOut', True), ('TimedOut', 0), ('Exit', False),
                ('Exit', 0.0), ('ExpectedExit', False), ('Status', 'FAIL'), ('JournalErrors', ['write fault'])):
            value = completed()
            value['Commands'][0][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)
        value = completed()
        row = next(row for row in value['Commands'] if row['ExpectedExit'] == 1)
        row.update(Exit=0, ExpectedExit=0, Status='PASS')
        with self.assertRaises(ValueError):
            subject.require_completed(value, self.helpers)

    def test_phase_boundaries_and_required_counters_reject_numeric_aliases(self):
        for key, bad in (('First', False), ('First', 0.0), ('Stop', 41.0), ('Commands', 41.0)):
            value = completed()
            value['Phases'][0][key] = bad
            with self.subTest(phase=key, bad=bad), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)
        for key, bad in (('RequiredCellsSatisfied', False), ('RequiredCellsSatisfied', 0.0),
                         ('RequiredCellsSatisfied', 1), ('RequiredCellCount', 2774.0),
                         ('RequiredCellCount', True), ('RequiredCellCount', 0)):
            value = completed()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)

    def test_all_stronger_nonclaims_are_present_literal_false(self):
        for key in NONCLAIMS:
            for bad in (True, 0, None):
                value = completed()
                value[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    subject.require_completed(value, self.helpers)

    def test_error_fields_and_closing_errors_have_exact_clean_types(self):
        for key, bad in (('Error', False), ('Error', ''), ('Error', []), ('PrimaryError', 0),
                         ('PrimaryError', ''), ('ClosingErrors', {}), ('ClosingErrors', False),
                         ('ClosingErrors', None), ('ClosingErrors', ['late failure'])):
            value = completed()
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_completed(value, self.helpers)

    def test_bootstrap_wrong_hash_rejects_before_module_execution(self):
        with patch.object(Path, 'read_bytes', return_value=b'foreign helper bytes'), \
                patch.object(subject, 'load') as load, self.assertRaisesRegex(ValueError, 'entrypoint'):
            subject.prepare(SimpleNamespace())
        load.assert_not_called()
        self.assertFalse(self.suite.output.exists())

    def test_missing_leaf_pin_rejects_before_constructor_and_output(self):
        with patch.object(Path, 'read_bytes', return_value=BUFFERS[RUNNER]), \
                patch.object(subject, 'load', return_value=SimpleNamespace()) as load, \
                patch.object(subject, 'LEAF_PINS', {}), self.assertRaisesRegex(ValueError, 'leaf pins'):
            subject.prepare(SimpleNamespace())
        self.assertEqual(load.call_count, 1)
        self.assertFalse(self.suite.output.exists())

    def test_mocked_success_is_sealed_once_without_running_qualified_stages(self):
        result = self.run_attempt()
        subject.require_completed(result, self.helpers)
        self.assertEqual(self.build.call_count, 1)
        self.assertLess(self.suite.events.index('build'), self.suite.events.index('replay'))
        self.assertEqual(self.suite.checks, 2)
        disk = json.loads((self.suite.output / 'results.json').read_bytes())
        self.assertEqual(disk, result)
        manifest = json.loads((self.suite.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertNotIn('artifacts.json', manifest)
        for name, digest in manifest.items():
            self.assertEqual(sha((self.suite.output / name).read_bytes()), digest)

    def test_start_failure_never_builds_or_promotes(self):
        def fail_start():
            self.suite.output.mkdir()
            raise OSError('initial output fault')
        with patch.object(self.suite, 'start', side_effect=fail_start), \
                self.assertRaisesRegex(OSError, 'initial output fault'):
            self.run_attempt()
        self.build.assert_not_called()
        self.failure_receipt()

    def test_build_failure_retains_first_primary_and_never_replays_or_retries(self):
        self.suite.report['PrimaryError'] = 'first managed command failure'
        self.build.side_effect = ValueError('phase failure')
        with patch.object(subject, 'replay') as replay, self.assertRaisesRegex(ValueError, 'phase failure'):
            subject.run(runner, self.environment, self.helpers, self.suite)
        replay.assert_not_called()
        self.assertEqual(self.build.call_count, 1)
        self.assertEqual(self.failure_receipt()['PrimaryError'], 'first managed command failure')

    def test_reader_rejection_never_reaches_sealed_success(self):
        with self.assertRaisesRegex(ValueError, 'immutable replay rejected'):
            self.run_attempt(ValueError('immutable replay rejected'))
        self.suite.verify_objects.assert_not_called()
        self.assertIn('immutable replay rejected', self.failure_receipt()['PrimaryError'])

    def test_input_closing_failure_is_terminal_and_nonpromoting(self):
        self.witness.close.side_effect = ValueError('late input drift')
        with self.assertRaisesRegex(ValueError, 'late input drift'):
            self.run_attempt()
        self.assertEqual(self.build.call_count, 1)
        self.assertIn('late input drift', self.failure_receipt()['PrimaryError'])

    def test_post_pass_output_check_failure_revokes_written_pass(self):
        def fail_final(count):
            if count == 2:
                self.assertEqual(json.loads((self.suite.output / 'results.json').read_bytes())['Status'], subject.PASS)
                raise ValueError('late output drift')
        self.suite.after_check = fail_final
        with self.assertRaisesRegex(ValueError, 'late output drift'):
            self.run_attempt()
        self.assertIn('late output drift', self.failure_receipt()['PrimaryError'])

    def test_pass_receipt_or_manifest_write_failure_gets_fail_recovery(self):
        for target in ('results.json', 'artifacts.json'):
            with self.subTest(target=target):
                self.suite = FakeSuite(Path(self.temporary.name) / target.replace('.', '-'))
                self.witness.output = self.suite.output
                self.build.side_effect = self.suite.build
                def fail_save(name, value):
                    if name == target and (name != 'results.json' or value.get('Status') == subject.PASS):
                        raise OSError('seal write fault ' + name)
                self.suite.before_save = fail_save
                with self.assertRaisesRegex(OSError, 'seal write fault'):
                    self.run_attempt()
                self.failure_receipt()
                self.assertEqual(self.build.call_count, 1)
                self.build.reset_mock()

    def test_summary_stdout_failure_after_pass_downgrades_without_retry(self):
        with patch('builtins.print', side_effect=BrokenPipeError('summary closed')), \
                self.assertRaisesRegex(BrokenPipeError, 'summary closed'):
            self.run_attempt()
        self.assertIn('summary closed', self.failure_receipt()['PrimaryError'])
        self.assertEqual(self.build.call_count, 1)

    def test_recovery_attempts_receipt_and_manifest_independently(self):
        self.suite.start()
        self.suite._save('results.json', completed())
        subject.revoke(runner, self.suite.report, ValueError('original primary'))
        original = Path.write_bytes
        attempts = []
        def faulty_write(path, raw):
            attempts.append(path.name)
            if len(attempts) == 1:
                raise OSError('first recovery receipt unavailable')
            return original(path, raw)
        with patch.object(Path, 'write_bytes', faulty_write):
            runner.recover(self.environment, self.suite.report)
        self.assertEqual(attempts, ['results.json', 'artifacts.json', 'results.json', 'artifacts.json'])
        record = self.failure_receipt()
        self.assertEqual(record['PrimaryError'], 'ValueError: original primary')
        self.assertTrue(any('first recovery receipt unavailable' in row for row in record['ClosingErrors']))

    def test_manifest_enumeration_fault_cannot_leave_earlier_pass_receipt(self):
        self.suite.start()
        self.suite._save('results.json', completed())
        subject.revoke(runner, self.suite.report, ValueError('primary before recovery'))
        normal = self.witness.replay_api.files_under
        self.witness.replay_api.files_under = Mock(side_effect=[OSError('manifest enumeration fault'), normal(self.suite.output)])
        runner.recover(self.environment, self.suite.report)
        record = self.failure_receipt()
        self.assertIn('primary before recovery', record['PrimaryError'])
        self.assertTrue(any('manifest enumeration fault' in row for row in record['ClosingErrors']))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT, RECIPES, RUNNER)
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_ABI_ATTEMPT_CONTROLS_ONLY', Tests=0,
        ExpectedTestMethods=EXPECTED_METHODS, Errors=0, Failures=0, Skipped=0, SourceHashes={},
        SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticFixtures=True,
        QualifiedStagesMocked=True, ActualCompilerExecuted=False, ActualELFTested=False,
        CpuExecution=False, BoardExecution=False, Qualification=False, RequiredCellsSatisfied=0,
        GlobalFreezeQualified=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('isolated unoptimized -I -S -B host Python required')
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, expected in PINS.items():
            if sha(BUFFERS[path]) != expected:
                raise ValueError('fixed pure helper source pin: ' + str(path))
        global subject, recipes, runner
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls cannot execute processes')), \
                patch('os.system', side_effect=AssertionError('pure controls cannot execute shell commands')):
            modules = []
            for name, path in (('subject', SUBJECT), ('recipes', RECIPES), ('runner', RUNNER)):
                module = ModuleType('_abi_attempt_test_' + name)
                module.__file__ = str(path)
                exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
                modules.append(module)
            subject, recipes, runner = modules
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(AttemptTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact twenty implemented methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report['ClosingFilesVerified'] += 1
                else:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(paths) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
