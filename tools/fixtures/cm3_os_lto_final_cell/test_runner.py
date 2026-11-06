"""Synthetic orchestration regressions; no real capture, compiler or target."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


subject = load('_cm3_os_staged_runner_test', HERE / 'runner.py')
replay_path = ROOT / 'tools/freeze_replay.py'
if hashlib.sha256(replay_path.read_bytes()).hexdigest().upper() != \
        '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275':
    raise ValueError('fixed filesystem closure helper required')
replay = load('_cm3_os_staged_runner_closure', replay_path)


def report():
    return dict(Status=subject.PASS, Scope=subject.SCOPE, Profile='CM3', Mode='Os-lto',
        Linkage='direct', SourceInventorySha256=subject.SOURCE, Error=None, PrimaryError=None,
        ClosingErrors=[], RequiredCellCount=2774, RequiredCellsSatisfied=0,
        InputClosureVerified=True, OutputSealVerified=True, ImmutableInputsConsumed=True,
        RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True,
        Links=[dict(Kind=kind, Proof={'Synthetic': True}) for kind in ('ordinary', 'emit-relocs')],
        **dict.fromkeys(subject.NONCLAIMS, False))


def argv():
    return [part for name in subject.ARGUMENTS for part in ('--' + name, 'synthetic')]


def synthetic_leaf(proof, *, emit_relocs):
    if type(emit_relocs) is not bool or type(proof) is not dict or proof != {'Synthetic': True}:
        raise ValueError('synthetic leaf schema failure')


ABI = SimpleNamespace(require_result=synthetic_leaf)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cm3-os-runner-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def environment(self):
        source = self.root / 'input.bin'
        source.write_bytes(b'authenticated synthetic bytes')
        witness = SimpleNamespace(output=self.root / 'output', replay_api=replay,
            watch=SimpleNamespace(hashes={source: subject.sha(source.read_bytes())}),
            close=Mock(), _physical=lambda path: (path.stat().st_dev, path.stat().st_ino, path.stat().st_nlink))
        witness.output.mkdir()
        return dict(Witness=witness, Modules=dict(abi=ABI))

    def invoke(self, *, run=None, stdout=None):
        environment = self.environment()
        value = report()
        out, err = io.StringIO() if stdout is None else stdout, io.StringIO()
        with patch.object(subject, 'prepare', return_value=environment), \
                patch.object(subject, 'run', run or Mock(return_value=value)), \
                redirect_stdout(out), redirect_stderr(err):
            status = subject.main(argv())
        return status, environment, value, out, err.getvalue()

    def test_all_ten_arguments_are_required_and_abbreviations_or_extras_fail(self):
        full = argv()
        invalid = [full[:index] + full[index + 2:] for index in range(0, len(full), 2)]
        invalid += [full + ['--unexpected', 'value'], ['--native-b', 'x', *full[2:]]]
        for args in invalid:
            with self.subTest(args=args), patch.object(subject, 'prepare') as prepare, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                subject.main(args)
            self.assertEqual(error.exception.code, 2)
            prepare.assert_not_called()

    def test_prepare_rejects_wrong_interpreter_before_reading_sources(self):
        for values in (dict(optimize=1, isolated=1, no_site=1),
                       dict(optimize=0, isolated=0, no_site=1), dict(optimize=0, isolated=1, no_site=0)):
            with self.subTest(values=values), patch.object(subject.sys, 'flags', SimpleNamespace(**values)), \
                    patch.object(Path, 'read_bytes') as read, self.assertRaisesRegex(ValueError, '-I -S -B'):
                subject.prepare(SimpleNamespace())
            read.assert_not_called()

    def test_prepare_rejects_inherited_parser_and_bytecode_before_io(self):
        for name in ('elftools', 'elftools.elf.elffile'):
            with self.subTest(name=name), patch.dict(sys.modules, {name: SimpleNamespace()}), \
                    patch.object(Path, 'read_bytes') as read, self.assertRaisesRegex(ValueError, 'inherited parser'):
                subject.prepare(SimpleNamespace())
            read.assert_not_called()
        with patch.object(subject.sys, 'dont_write_bytecode', False), \
                patch.object(Path, 'read_bytes') as read, self.assertRaisesRegex(ValueError, '-I -S -B'):
            subject.prepare(SimpleNamespace())
        read.assert_not_called()

    def test_prepare_authenticates_every_helper_and_contract_before_exec(self):
        all_pins = list(subject.PINS.values()) + list(subject.DOCUMENTS.items())
        real = Path.read_bytes
        for relative, digest in all_pins:
            target = subject.ROOT / relative
            def altered(path):
                return real(path) + b'\naltered\n' if path == target else real(path)
            with self.subTest(relative=relative), patch.object(Path, 'read_bytes', altered), \
                    patch.object(subject, 'load') as load_mock, self.assertRaisesRegex(ValueError, 'authenticated'):
                subject.prepare(SimpleNamespace())
            load_mock.assert_not_called()

    def test_own_os_constructor_receives_exact_authenticated_buffers_and_arguments(self):
        args, buffers = SimpleNamespace(), {}
        real = Path.read_bytes
        def read(path):
            raw = real(path)
            buffers[path] = raw
            return raw
        factory, constructor = Mock(), Mock(return_value=object())
        factory.return_value = constructor
        modules = {name: SimpleNamespace() for name in subject.PINS}
        modules['admission'].witness_type = factory
        def imported(name, path, raw):
            self.assertEqual(raw, buffers[path])
            return modules[next(key for key, row in subject.PINS.items() if subject.ROOT / row[0] == path)]
        with patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=imported):
            environment = subject.prepare(args)
        factory.assert_called_once_with(modules['legacy'], modules['capture'], extra_sources=buffers)
        constructor.assert_called_once_with(args)
        self.assertIs(environment['Witness'], constructor.return_value)

    def test_os_roles_reject_an_o2_capture_before_accessing_any_file(self):
        witness = SimpleNamespace(groups={'Native': dict(Root=self.root, Artifacts={},
            Result=dict(Profile='CM3', Mode='O2-lto', Linkage='direct'))})
        with patch.object(Path, 'samefile') as samefile, self.assertRaisesRegex(ValueError, 'actual Os'):
            subject.roles(dict(Witness=witness))
        samefile.assert_not_called()

    def test_succeeded_requires_exact_route_typed_credit_and_all_nonclaims(self):
        self.assertTrue(subject.succeeded(report(), abi_rules=ABI))
        for key, value in (('Mode', 'O2-lto'), ('Scope', 'generic'), ('Profile', 'CM4'),
                ('SourceInventorySha256', '0' * 64), ('Linkage', 'archive'), ('Status', 'PASS'),
                ('RequiredCellsSatisfied', False), ('RequiredCellsSatisfied', 0.0), ('RequiredCellsSatisfied', 1),
                ('RequiredCellCount', True), ('RequiredCellCount', 2773), ('Error', 'fault'),
                ('PrimaryError', 'fault'), ('ClosingErrors', ['fault']), ('Links', [])):
            with self.subTest(key=key, value=value):
                self.assertFalse(subject.succeeded(dict(report(), **{key: value}), abi_rules=ABI))
        for key in subject.NONCLAIMS:
            with self.subTest(nonclaim=key):
                self.assertFalse(subject.succeeded(dict(report(), **{key: True}), abi_rules=ABI))
        for key in ('InputClosureVerified', 'OutputSealVerified', 'ImmutableInputsConsumed',
                'FinalLinkContractValidated', 'RuntimeProviderBindingsValidated'):
            with self.subTest(required=key):
                self.assertFalse(subject.succeeded(dict(report(), **{key: False}), abi_rules=ABI))
        for value in (None, {}, dict(Synthetic=False), dict(Synthetic=True, Mode='O2-lto')):
            for index in (0, 1):
                changed = report()
                changed['Links'][index]['Proof'] = value
                with self.subTest(invalid_leaf=value, index=index):
                    self.assertFalse(subject.succeeded(changed, abi_rules=ABI))

    def test_seal_binds_exact_outputs_inputs_and_physical_identities(self):
        environment = self.environment()
        value, expected = report(), {}
        subject.seal(environment, value, expected)
        witness = environment['Witness']
        self.assertTrue(subject.succeeded(value, abi_rules=ABI))
        self.assertEqual(json.loads((witness.output / 'results.json').read_bytes()), value)
        self.assertEqual(json.loads((witness.output / 'artifacts.json').read_bytes()), dict(Artifacts=expected))
        self.assertEqual(value['ClosingFilesVerified'], 1)
        self.assertEqual(len(value['InputPhysicalIdentities']), 1)
        self.assertEqual(witness.close.call_count, 2)

    def test_unexpected_output_member_or_late_input_fault_revokes_persisted_pass(self):
        for unexpected in (True, False):
            with self.subTest(unexpected=unexpected):
                environment = self.environment()
                witness, value = environment['Witness'], report()
                if unexpected:
                    (witness.output / 'surplus.bin').write_bytes(b'not declared')
                else:
                    witness.close.side_effect = [None, ValueError('late synthetic input drift')]
                with self.assertRaises(ValueError) as failure:
                    subject.seal(environment, value, {})
                subject.revoke(value, failure.exception)
                subject.recover(environment, value)
                recorded = json.loads((witness.output / 'results.json').read_bytes())
                self.assertEqual(recorded['Status'], 'FAIL')
                self.assertIs(recorded['OutputSealVerified'], False)
                self.assertIs(recorded['RuntimeProviderBindingsValidated'], False)
                self.assertEqual(recorded['RequiredCellsSatisfied'], 0)
                for path in sorted(witness.output.iterdir()):
                    path.unlink()
                witness.output.rmdir()

    def test_stdout_failure_revokes_a_successful_report_and_returns_nonzero(self):
        class Broken(io.StringIO):
            def flush(self):
                raise BrokenPipeError('synthetic summary flush failure')
        status, environment, value, out, err = self.invoke(stdout=Broken())
        self.assertEqual(status, 1)
        self.assertIn('summary flush failure', err)
        recorded = json.loads((environment['Witness'].output / 'results.json').read_bytes())
        self.assertEqual(recorded['Status'], 'FAIL')
        self.assertIs(recorded['InputClosureVerified'], False)
        self.assertIn('summary flush failure', recorded['PrimaryError'])
        self.assertIs(value['RuntimeProviderBindingsValidated'], False)

    def test_roots_stage_late_schema_or_stdout_failure_revokes_existing_pass(self):
        class Broken(io.StringIO):
            def flush(self):
                raise BrokenPipeError('synthetic roots flush failure')
        for late_schema in (True, False):
            with self.subTest(late_schema=late_schema):
                environment = self.environment()
                witness = environment['Witness']
                value = dict(report(), Status='SYNTHETIC-ROOT-PASS', CanonicalProtocolValidated=True,
                    FinalRootRelocationProof=True)
                witness.report = value
                def passed():
                    (witness.output / 'results.json').write_bytes(subject.encoded(value))
                    return True
                witness.run = Mock(side_effect=passed)
                require = Mock(side_effect=ValueError('synthetic late root schema')) if late_schema else Mock()
                environment['Modules'] = dict(frontend=SimpleNamespace(require_result=require),
                    legacy=SimpleNamespace(PASS='SYNTHETIC-ROOT-PASS'))
                out, err = (io.StringIO() if late_schema else Broken()), io.StringIO()
                with patch.object(subject, 'prepare', return_value=environment), \
                        redirect_stdout(out), redirect_stderr(err):
                    status = subject.main(argv() + ['--stage', 'roots'])
                self.assertEqual(status, 1)
                recorded = json.loads((witness.output / 'results.json').read_bytes())
                self.assertEqual(recorded['Status'], 'FAIL')
                self.assertIs(recorded['CanonicalProtocolValidated'], False)
                self.assertIs(recorded['FinalRootRelocationProof'], False)
                self.assertEqual(recorded['RequiredCellsSatisfied'], 0)
                witness.run.assert_called_once_with()
                for path in witness.output.iterdir():
                    path.unlink()
                witness.output.rmdir()

    def test_primary_failure_is_preserved_if_recovery_persistence_also_fails(self):
        environment, value = self.environment(), report()
        subject.revoke(value, ValueError('first failure'))
        subject.revoke(value, OSError('secondary failure'))
        original = Path.write_bytes
        def fail_manifest(path, raw):
            if path.name == 'artifacts.json':
                raise OSError('synthetic manifest persistence')
            return original(path, raw)
        with patch.object(Path, 'write_bytes', fail_manifest):
            subject.recover(environment, value)
        self.assertEqual(value['PrimaryError'], 'ValueError: first failure')
        self.assertEqual(value['Error'], 'ValueError: first failure')
        self.assertEqual(len(value['ClosingErrors']), 2)
        recorded = json.loads((environment['Witness'].output / 'results.json').read_bytes())
        self.assertEqual(recorded['Status'], 'FAIL')
        self.assertEqual(recorded['PrimaryError'], 'ValueError: first failure')

    def test_legacy_roots_report_without_closing_errors_survives_transient_fail_write(self):
        environment, value = self.environment(), report()
        del value['ClosingErrors']
        subject.revoke(value, ValueError('root primary failure'))
        original, attempts = Path.write_bytes, []
        def transient(path, raw):
            if path.name == 'results.json':
                attempts.append(raw)
                if len(attempts) == 1:
                    raise OSError('synthetic first FAIL-write error')
            return original(path, raw)
        with patch.object(Path, 'write_bytes', transient):
            subject.recover(environment, value)
        self.assertEqual(len(attempts), 2)
        recorded = json.loads((environment['Witness'].output / 'results.json').read_bytes())
        self.assertEqual(recorded['Status'], 'FAIL')
        self.assertIn('root primary failure', recorded['PrimaryError'])
        self.assertTrue(any('first FAIL-write error' in row for row in recorded['ClosingErrors']))

    def test_main_success_prints_only_narrow_summary_without_credit(self):
        status, environment, value, out, err = self.invoke()
        self.assertEqual((status, err), (0, ''))
        summary = json.loads(out.getvalue())
        self.assertEqual(summary['Status'], subject.PASS)
        self.assertIs(type(summary['RequiredCellsSatisfied']), int)
        self.assertEqual(summary['RequiredCellsSatisfied'], 0)
        self.assertEqual(len(summary), 7)

    def test_main_forbids_process_and_shell_launches_during_run(self):
        import os
        import subprocess
        for function in (lambda *args: subprocess.Popen(['never-executed']),
                         lambda *args: os.system('never-executed')):
            with self.subTest(function=function):
                status, environment, value, out, err = self.invoke(run=Mock(side_effect=function))
                self.assertEqual(status, 1)
                self.assertIn('cannot execute', err)
                environment['Witness'].output.rmdir()


if __name__ == '__main__':
    with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn processes')), \
            patch('os.system', side_effect=AssertionError('pure tests cannot execute shell commands')):
        unittest.main(verbosity=2)
