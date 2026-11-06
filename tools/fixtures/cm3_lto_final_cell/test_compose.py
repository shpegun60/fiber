"""Synthetic orchestration/failure controls; no actual ELF or compiler proof."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
OPENED = {path: path.read_bytes() for path in (HERE / 'compose.py', HERE / 'model.py',
    HERE.parent / 'cm0_final_cell/compose.py', HERE.parents[1] / 'freeze_replay.py', Path(__file__).resolve())}


def load(name, path):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(OPENED[path], str(path), 'exec'), result.__dict__)
    return result


c = load('synthetic_cm3_lto_composer', HERE / 'compose.py')
m = load('synthetic_cm3_lto_model', HERE / 'model.py')
q = load('synthetic_cm3_lto_seal', HERE.parent / 'cm0_final_cell/compose.py')
api = load('synthetic_cm3_lto_api', HERE.parents[1] / 'freeze_replay.py')
if c.sha(OPENED[HERE.parent / 'cm0_final_cell/compose.py']) != c.PINS['qualified'][1]:
    raise RuntimeError('frozen seal changed')
if c.sha(OPENED[HERE.parents[1] / 'freeze_replay.py']) != c.PINS['api'][1]:
    raise RuntimeError('frozen admission changed')


def report():
    return dict(Status='PASS', Scope=c.SCOPE, Route=m.ROUTE, Error=None, PrimaryError=None, ClosingErrors=[],
        RequiredCellCount=2774, RequiredCellsSatisfied=1, RequiredCellSatisfied=True, CellContractSatisfied=True,
        InputClosureVerified=True, OutputSealVerified=True,
        CommonPrerequisites={name: dict(Satisfied=True) for name in m.COMMON},
        RuntimeObligations={name: dict(Satisfied=True) for name in m.RUNTIME}, **dict.fromkeys(c.NONCLAIMS, False))


class Controls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='c3-lto-composer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / 'output'
        self.output.mkdir()
        self.coverage_calls = []
        def coverage(required, backlog, verified, *, coverage_module):
            self.coverage_calls.append(list(verified))
            return dict(RequiredCellsSatisfied=len(verified)), dict(RequiredCellsSatisfied=len(verified), Backlog=backlog)
        self.model = SimpleNamespace(coverage=coverage)
        self.environment = dict(Output=self.output, Api=api,
            Modules=dict(model=self.model, qualified=q, coverage=object()),
            Current=dict(Required=object(), Manifest=dict(scope_backlog=['retained synthetic backlog'])))

    def persist_pass(self, value):
        for name, row in (('results.json', value), ('coverage.json', dict(RequiredCellsSatisfied=1)),
                          ('missing-work.json', dict(RequiredCellsSatisfied=1))):
            (self.output / name).write_bytes(c.encoded(row))

    def test_literal_success_surface_and_every_nonclaim(self):
        self.assertTrue(c.succeeded(report()))
        for field in ('Status', 'Scope', 'Route', 'Error', 'PrimaryError', 'ClosingErrors',
                      'CellContractSatisfied', 'RequiredCellSatisfied', 'InputClosureVerified', 'OutputSealVerified',
                      'RequiredCellCount', 'RequiredCellsSatisfied', *c.NONCLAIMS):
            value = report()
            value[field] = True if field in c.NONCLAIMS else 'synthetic error' if field in ('Error', 'PrimaryError') else None
            with self.subTest(field=field):
                self.assertFalse(c.succeeded(value))
        value = report()
        value['RequiredCellsSatisfied'] = True
        self.assertFalse(c.succeeded(value))

    def test_all_common_and_runtime_obligations_required(self):
        for field, keys in (('CommonPrerequisites', m.COMMON), ('RuntimeObligations', m.RUNTIME)):
            for key in keys:
                value = report()
                value[field][key]['Satisfied'] = False
                with self.subTest(field=field, key=key):
                    self.assertFalse(c.succeeded(value))
            value = report()
            value[field]['extra'] = dict(Satisfied=True)
            self.assertFalse(c.succeeded(value))

    def test_recovery_revokes_persisted_pass_coverage_and_all_obligations(self):
        value = report()
        value.update(Error='original cause', PrimaryError='original cause')
        self.persist_pass(value)
        c.recover(self.environment, value)
        saved = json.loads((self.output / 'results.json').read_bytes())
        self.assertEqual((saved['Status'], saved['Error'], saved['PrimaryError']), ('FAIL', 'original cause', 'original cause'))
        self.assertEqual(saved['RequiredCellsSatisfied'], 0)
        self.assertFalse(saved['OutputSealVerified'])
        self.assertTrue(all(not row['Satisfied'] for field in ('CommonPrerequisites', 'RuntimeObligations')
            for row in saved[field].values()))
        self.assertEqual(self.coverage_calls, [[]])
        self.assertEqual(json.loads((self.output / 'coverage.json').read_bytes())['RequiredCellsSatisfied'], 0)
        manifest = json.loads((self.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertEqual(manifest['results.json'], c.sha((self.output / 'results.json').read_bytes()))

    def test_recovery_manifest_fault_is_persisted_without_losing_primary(self):
        value = report()
        value.update(Error='original cause', PrimaryError='original cause')
        self.persist_pass(value)
        real = api.files_under
        count = 0
        def first_failure(root):
            nonlocal count
            count += 1
            if count == 1:
                raise OSError('synthetic manifest fault')
            return real(root)
        with patch.object(api, 'files_under', first_failure):
            c.recover(self.environment, value)
        saved = json.loads((self.output / 'results.json').read_bytes())
        self.assertEqual(saved['PrimaryError'], 'original cause')
        self.assertTrue(any('synthetic manifest fault' in error for error in saved['ClosingErrors']))
        self.assertEqual(count, 2)
        manifest = json.loads((self.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertEqual(manifest['results.json'], c.sha((self.output / 'results.json').read_bytes()))

    def test_main_post_pass_stdout_fault_revokes_files(self):
        value = report()
        self.persist_pass(value)
        real_print = print
        calls = 0
        def fail_stdout(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise BrokenPipeError('synthetic post-PASS stdout fault')
            return real_print(*args, **kwargs)
        with patch.object(c, 'prepare', return_value=self.environment), patch.object(c, 'compose', return_value=value), \
                patch('builtins.print', fail_stdout):
            status = c.main(['--catalog', 'synthetic', '--catalog-sha256', 'A' * 64, '--output-dir', str(self.output)])
        self.assertEqual(status, 1)
        saved = json.loads((self.output / 'results.json').read_bytes())
        self.assertEqual(saved['Status'], 'FAIL')
        self.assertEqual(saved['RequiredCellsSatisfied'], 0)
        self.assertIn('post-PASS stdout fault', saved['PrimaryError'])

    def inspector(self, result):
        tool, machine, final = (self.root / name for name in ('objdump.exe', 'machine.o', 'image.elf'))
        for path in (tool, machine, final):
            path.write_bytes(path.name.encode('ascii'))
        watch = api.Closure()
        watch.read(tool)
        process = SimpleNamespace(run=Mock(side_effect=result if isinstance(result, BaseException) else None,
            return_value=None if isinstance(result, BaseException) else result))
        suite = SimpleNamespace(tools=dict(objdump=tool), process=process, environment={})
        environment = dict(Api=api, Watch=watch, Output=self.output, Suites=dict(ABIControls=suite))
        rows, writes = [], {}
        def write(name, raw):
            writes[name] = raw
            return self.output / name
        return environment, dict(zip(('Machine', 'Final'), (machine, final))), rows, writes, write, process

    def test_nonzero_inspection_primary_survives_stream_write_fault(self):
        environment, roles, rows, writes, write, process = self.inspector(
            SimpleNamespace(returncode=7, timed_out=False, stdout=b'partial', stderr=b'real tool failure'))
        def broken(name, raw):
            if name.endswith('.stdout'):
                raise OSError('synthetic stdout storage fault')
            return write(name, raw)
        with self.assertRaisesRegex(ValueError, 'exit=7'):
            c.inspect_commands(environment, {'emit-relocs': roles}, broken, rows)
        self.assertEqual(process.run.call_count, 1)
        self.assertIn('inspection/00.attempt.json', writes)
        self.assertIn('inspection/00.stderr', writes)
        terminal = json.loads(writes['inspection/00.json'])
        self.assertEqual((terminal['State'], terminal['Exit']), ('TERMINAL', 7))
        self.assertIn('exit=7', terminal['PrimaryError'])
        self.assertTrue(terminal['JournalErrors'])

    def test_timeout_with_zero_exit_is_not_accepted(self):
        environment, roles, rows, writes, write, process = self.inspector(
            SimpleNamespace(returncode=0, timed_out=True, stdout=b'data', stderr=b''))
        with self.assertRaisesRegex(ValueError, 'timeout=True'):
            c.inspect_commands(environment, {'emit-relocs': roles}, write, rows)
        self.assertEqual(process.run.call_count, 1)
        self.assertTrue(json.loads(writes['inspection/00.json'])['TimedOut'])

    def test_launch_exception_is_journaled_without_retry(self):
        environment, roles, rows, writes, write, process = self.inspector(OSError('synthetic launch fault'))
        with self.assertRaisesRegex(OSError, 'synthetic launch fault'):
            c.inspect_commands(environment, {'emit-relocs': roles}, write, rows)
        self.assertEqual(process.run.call_count, 1)
        self.assertEqual(json.loads(writes['inspection/00.json'])['State'], 'LAUNCH-FAILED')

    def test_successful_inspection_is_exactly_two_read_only_commands(self):
        environment, roles, rows, writes, write, process = self.inspector(
            SimpleNamespace(returncode=0, timed_out=False, stdout=b'complete disassembly', stderr=b''))
        records, paths = c.inspect_commands(environment, {'emit-relocs': roles}, write, rows)
        self.assertEqual(process.run.call_count, 2)
        self.assertEqual([row['Role'] for row in records], ['Machine', 'Final'])
        self.assertEqual(set(paths), {'Machine', 'Final'})
        self.assertTrue(all(row['Argv'][1:3] == ['-drwC', '-z'] and not row['JournalErrors'] for row in records))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize):
        raise SystemExit('use fresh unoptimized -I -S -B Python')
    output = args.output_dir.resolve()
    if output.exists() or HERE.parents[2] == output or HERE.parents[2] in output.parents:
        raise SystemExit('fresh external output directory required')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    drift = [str(path) for path, raw in OPENED.items() if path.read_bytes() != raw]
    evidence = dict(Status='PASS' if result.wasSuccessful() and not drift else 'FAIL', Tests=result.testsRun,
        Errors=len(result.errors), Failures=len(result.failures), SourceDrift=drift,
        SourceHashes={str(path): hashlib.sha256(raw).hexdigest().upper() for path, raw in OPENED.items()},
        SyntheticOrchestrationOnly=True, CompilerExecuted=False, ActualELFQualified=False,
        CpuExecution=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'results.json').write_bytes(c.encoded(evidence))
    print(json.dumps(evidence, sort_keys=True), flush=True)
    return 0 if evidence['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
