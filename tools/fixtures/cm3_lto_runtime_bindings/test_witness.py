"""Pure frontend/failure controls; no capture admission, ELF parser or tools run."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'witness.py'
RECOVERY = HERE.with_name('cm3_current_lto_replay') / 'witness.py'
RECOVERY_SHA = '7AFE40E8344E0E9329004BB4D9682606251C9FB05E7B17A3233BF16F1798AC4A'
subject = recovery = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    value = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def positive():
    result = dict(Status=subject.PASS, Scope=subject.SCOPE, Error=None, PrimaryError=None, ClosingErrors=[],
        Profile='CM3', Mode='O2-lto', Linkage='direct', RequiredCellCount=2774,
        SourceInventorySha256='69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313',
        InputClosureVerified=True, OutputSealVerified=True, RuntimeProviderBindingsValidated=True,
        FinalLinkContractValidated=True, ImmutableInputsConsumed=True, CommandsReconstructed=57,
        RequiredCellsSatisfied=0, RequiredCellSatisfied=False)
    result.update(dict.fromkeys(('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof',
        'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence',
        'CanonicalProtocolValidated', 'FinalRootRelocationProof', 'CompleteObjectProof', 'CpuExecution',
        'BoardExecution', 'GlobalFreezeQualified', 'HostedCIQualified', 'ProducerCompilersReexecuted'), False))
    return result


class FrontendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def argv(self):
        return [item for name, value in (('capture-build', 'capture'), ('capture-receipt-sha256', 'A' * 64),
            ('capture-artifacts-sha256', 'B' * 64), ('inventory', 'inventory'),
            ('inventory-receipt-sha256', 'C' * 64), ('inventory-artifacts-sha256', 'D' * 64),
            ('output-dir', str(self.root / 'output'))) for item in ('--' + name, value)]

    def witness(self):
        cls = subject.witness_type(dict(legacy=SimpleNamespace(Witness=object), capture=None, recipe=None), {})
        value = object.__new__(cls)
        value.output = self.root / 'output'
        value.output.mkdir(exist_ok=True)
        value.created_output = True
        value.report = positive()
        value.expected = {'results.json', 'artifacts.json', 'data.bin'}
        (value.output / 'data.bin').write_bytes(b'bounded synthetic diagnostic payload\n')
        value.api = SimpleNamespace(files_under=lambda root: {p.relative_to(root).as_posix(): p
            for p in root.rglob('*') if p.is_file()}, same=lambda a, b, why: self.assertEqual(a, b, why))
        value.replay_api = value.api
        value.close = Mock()
        value.run = Mock(return_value=True)
        return value

    def invoke(self, witness=None, prepare=None, success=None):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(subject, 'prepare', prepare or Mock(return_value=(witness, dict(recovery=recovery)))), \
                patch.object(subject, 'succeeded', success or subject.succeeded), \
                redirect_stdout(output), redirect_stderr(errors):
            result = subject.main(self.argv())
        return result, output.getvalue(), errors.getvalue()

    def bootstrap(self):
        entries = dict(PINS={}, BUFFER_PINS={})
        buffers = {}
        for field in entries:
            for name, (relative, unused) in getattr(subject, field).items():
                raw = ('synthetic immutable ' + relative).encode('ascii')
                entries[field][name] = (relative, sha(raw))
                buffers[subject.ROOT / relative] = raw
        buffers[SUBJECT] = b'synthetic executing runner buffer'
        return entries, buffers

    def test_cli_requires_exact_seven_named_arguments(self):
        for args in ([], self.argv()[:-2], [*self.argv(), '--mode', 'Os-lto'],
                     ['--capture-b', 'capture', *self.argv()[2:]]):
            with self.subTest(args=args), patch.object(subject, 'prepare') as prepare, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                subject.main(args)
            self.assertEqual(error.exception.code, 2)
            prepare.assert_not_called()

    def test_prepare_requires_isolation_before_any_io(self):
        for field, value in (('optimize', 1), ('isolated', 0), ('no_site', 0)):
            flags = dict(optimize=0, isolated=1, no_site=1)
            flags[field] = value
            with self.subTest(field=field), patch.object(subject.sys, 'flags', SimpleNamespace(**flags)), \
                    patch.object(Path, 'read_bytes') as read, self.assertRaisesRegex(ValueError, 'isolated'):
                subject.prepare(SimpleNamespace())
            read.assert_not_called()

    def test_prepare_rejects_inherited_parser_before_io(self):
        for name in ('elftools', 'elftools.synthetic'):
            with self.subTest(name=name), patch.dict(sys.modules, {name: object()}), \
                    patch.object(Path, 'read_bytes') as read, self.assertRaisesRegex(ValueError, 'inherited parser'):
                subject.prepare(SimpleNamespace())
            read.assert_not_called()

    def test_prepare_authenticates_all_pins_before_exec(self):
        entries, buffers = self.bootstrap()
        for changed in tuple(buffers)[:-1]:
            selected = dict(buffers)
            selected[changed] += b' drift'
            with self.subTest(changed=changed), patch.multiple(subject, **entries), \
                    patch.object(Path, 'read_bytes', lambda path: selected[path]), \
                    patch.object(subject, 'module') as execute, self.assertRaisesRegex(ValueError, 'authenticated'):
                subject.prepare(SimpleNamespace())
            execute.assert_not_called()

    def test_prepare_uses_exact_authenticated_buffers_and_factory(self):
        entries, buffers = self.bootstrap()
        events, args, sentinel = [], SimpleNamespace(), object()
        def read(path):
            events.append(('read', path))
            return buffers[path]
        def execute(name, path, raw):
            self.assertEqual(raw, buffers[path])
            self.assertTrue(all(('read', p) in events for p in buffers))
            return SimpleNamespace(name=name)
        factory = Mock(return_value=sentinel)
        with patch.multiple(subject, **entries), patch.object(Path, 'read_bytes', read), \
                patch.object(subject, 'module', side_effect=execute), \
                patch.object(subject, 'witness_type', return_value=factory) as make:
            witness, modules = subject.prepare(args)
        self.assertIs(witness, sentinel)
        self.assertEqual(set(modules), set(entries['PINS']))
        self.assertEqual(make.call_args.args, (modules, buffers))
        factory.assert_called_once_with(args)

    def test_module_executes_supplied_bytes_not_file_contents(self):
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('unexpected reread')):
            loaded = subject.module('_runtime_bindings_synthetic_buffer', self.root / 'absent.py', b'answer = 41\n')
        self.assertEqual(loaded.answer, 41)

    def test_o2_command_projection_uses_seed_flags_without_mutating_raw_capture(self):
        rows = [dict(Source='source/%d.c' % i, SourceSha256='A' * 64, CompileFlags=['-O2', '-flto'])
                for i in range(9)]
        seed = [dict(Source=row['Source'], SourceSha256=row['SourceSha256'], CompileFlags=['-O2', '-g0'])
                for row in rows]
        raw = dict(Sources=rows, Commands=[dict(Label='retained raw command')])
        before = copy.deepcopy(raw)
        view, projection = subject.command_view(raw, seed)
        self.assertEqual(raw, before)
        self.assertEqual(view['Commands'], raw['Commands'])
        self.assertIsNot(view['Commands'], raw['Commands'])
        self.assertEqual(len(projection['AddedFields']), 9)
        self.assertIs(projection['RawCaptureChanged'], False)
        for row, original in zip(view['Sources'], seed):
            self.assertEqual(row['SeedCompileFlags'], original['CompileFlags'])
            self.assertIsNot(row['SeedCompileFlags'], original['CompileFlags'])
        for change in ('foreign provider', 'existing invented field', 'untyped flags'):
            result, selected = copy.deepcopy(raw), copy.deepcopy(seed)
            if change == 'foreign provider':
                selected[0]['Source'] += '.foreign'
            elif change == 'existing invented field':
                result['Sources'][0]['SeedCompileFlags'] = ['-O2']
            else:
                selected[0]['CompileFlags'] = ['-O2', True]
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.command_view(result, selected)

    def test_succeeded_rejects_wrong_route_nonliteral_counts_and_broad_claims(self):
        self.assertTrue(subject.succeeded(positive()))
        for field, value in (('Status', 'PASS'), ('Scope', 'other'), ('Profile', 'CM4'), ('Mode', 'Os-lto'),
            ('Linkage', 'archive'), ('CommandsReconstructed', 57.0), ('RequiredCellCount', 2774.0),
            ('RequiredCellsSatisfied', False), ('RequiredCellSatisfied', 0), ('PrimaryError', 'earlier'),
            ('ClosingErrors', ['late']), ('CpuExecution', True), ('FullABIProof', True),
            ('FinalRootRelocationProof', True), ('InputClosureVerified', 1), ('OutputSealVerified', False)):
            report = positive()
            report[field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(subject.succeeded(report))

    def test_leaf_requires_complete_named_evidence_and_literal_counts(self):
        proof = dict(Status='CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED',
            Scope='NATIVE_CM3_O2_LTO_DIRECT_MERGED_MACHINE_RUNTIME_BINDINGS_ONLY',
            Profile='CM3', Mode='O2-lto', Linkage='direct', EmitRelocs=True,
            RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True,
            OriginalStartupVectorRelocationsAudited=True, MandatoryDefinitionCount=30, AdditionalConsumerCount=3,
            ForwardProviderCount=8, ReverseProviderCount=4, ReverseReferenceCount=5, ReverseBLReferences=4,
            TaskReturnABS32References=1, ColdAnchorReadCount=2, StartupVectorReferenceCount=3,
            OriginalBindingRelocations=10, AppliedBindingRelocations=10, RequiredCellsSatisfied=0,
            RequiredCellSatisfied=False)
        proof.update(dict.fromkeys(('Qualification', 'TypedABIProof', 'FullABIProof', 'FullSemanticABIProof',
            'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
            'CanonicalProtocolValidated', 'InstructionEquivalence', 'PolicyEquivalence', 'FinalReferenceParity',
            'CompleteObjectProof', 'KernelRuntimeProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'), False))
        symbol = lambda name: dict(Name=name, Original=dict(name=name), Final=dict(name=name))
        fixed = {name: symbol(name) for name in (*subject.FORWARD, *('synthetic-%d' % i for i in range(18)))}
        reverse = [symbol(name) for name in subject.REVERSE]
        proof['LinkContract'] = dict(Status='CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
            Scope='NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY', Profile='CM3', Mode='O2-lto',
            Linkage='direct', EmitRelocs=True, FinalLinkContractValidated=True, Symbols=fixed)
        proof['MandatoryDefinitions'] = dict(fixed, **{row['Name']: row for row in reverse})
        proof['ForwardProviders'] = [fixed[name] for name in subject.FORWARD]
        proof['ReverseProviders'] = reverse
        for key, count in (('ReverseReferences', 5), ('ColdAnchorReads', 2), ('StartupVectors', 3)):
            proof[key] = [dict(Synthetic=True) for unused in range(count)]
        proof['AdditionalConsumerOrigins'] = [symbol(name) for name in (
            'fiber_port_scheduler_pick_first_from_start', 'fiber_port_scheduler_pick_next_from_pendsv',
            'fiber_port_init_context_frame')]
        self.assertIs(subject.require_bindings_result(proof, emit_relocs=True), proof)
        bad = [None, {}, dict(proof, Status='FAIL'), dict(proof, MandatoryDefinitionCount=30.0),
               dict(proof, ReverseReferences=[]), dict(proof, ForwardProviders=[{}] * 8),
               dict(proof, LinkContract={}), dict(proof, RequiredCellsSatisfied=False),
               dict(proof, CpuExecution=True), dict(proof, AdditionalConsumerOrigins=[dict(junk=True)] * 3)]
        for selected in bad:
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                subject.require_bindings_result(selected, emit_relocs=True)

    def test_main_success_is_single_invocation(self):
        witness = self.witness()
        before = copy.deepcopy(witness.report)
        status, output, errors = self.invoke(witness)
        self.assertEqual((status, errors), (0, ''))
        self.assertEqual(json.loads(output)['Status'], subject.PASS)
        self.assertEqual(witness.report, before)
        witness.run.assert_called_once_with()

    def test_main_blocks_processes_in_prepare_run_and_result_check(self):
        import subprocess
        for stage in ('prepare', 'run', 'result'):
            witness = self.witness()
            call = lambda *unused: subprocess.Popen(['never-executed'])
            prepare = Mock(side_effect=call) if stage == 'prepare' else None
            success = Mock(side_effect=call) if stage == 'result' else None
            if stage == 'run':
                witness.run.side_effect = call
            with self.subTest(stage=stage):
                status, output, errors = self.invoke(witness, prepare, success)
            self.assertEqual((status, output), (1, ''))
            self.assertIn('cannot execute processes', errors)

    def test_main_rejects_nonliteral_success_without_replay_retry(self):
        for returned in (False, 1, None):
            witness = self.witness()
            witness.run.return_value = returned
            with self.subTest(returned=returned):
                status, output, errors = self.invoke(witness)
            self.assertEqual((status, output), (1, ''))
            self.assertTrue(errors)
            self.assertEqual(json.loads((witness.output / 'results.json').read_bytes())['Status'], 'FAIL')
            witness.run.assert_called_once_with()

    def test_unowned_output_is_never_revoked(self):
        witness = self.witness()
        witness.created_output = False
        original = subject.encoded(positive())
        (witness.output / 'results.json').write_bytes(original)
        witness.run.side_effect = OSError('not our output')
        status, output, errors = self.invoke(witness)
        self.assertEqual((status, output), (1, ''))
        self.assertIn('not our output', errors)
        self.assertEqual((witness.output / 'results.json').read_bytes(), original)

    def test_seal_binds_intended_receipt_manifest_and_complete_membership(self):
        witness = self.witness()
        witness._seal()
        raw = (witness.output / 'results.json').read_bytes()
        self.assertEqual(raw, subject.encoded(witness.report))
        manifest = json.loads((witness.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertEqual(set(manifest), {'data.bin', 'results.json'})
        self.assertEqual(manifest['results.json'], sha(raw))
        witness.close.assert_called_once_with()
        (witness.output / 'unknown.bin').write_bytes(b'undeclared')
        with self.assertRaisesRegex(ValueError, 'membership'):
            witness._seal()

    def test_late_close_error_revokes_written_pass_and_retains_primary(self):
        witness = self.witness()
        witness.close.side_effect = ValueError('late physical closing')
        witness.run.side_effect = lambda: witness._seal() or True
        status, output, errors = self.invoke(witness)
        self.assertEqual((status, output), (1, ''))
        self.assertIn('late physical closing', errors)
        raw = (witness.output / 'results.json').read_bytes()
        report = json.loads(raw)
        self.assertEqual(report['Status'], 'FAIL')
        self.assertIn('late physical closing', report['PrimaryError'])
        self.assertIs(report['InputClosureVerified'], False)
        self.assertIs(report['OutputSealVerified'], False)
        self.assertIs(report['RuntimeProviderBindingsValidated'], False)
        manifest = json.loads((witness.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertEqual(manifest['results.json'], sha(raw))
        witness.run.assert_called_once_with()

    def test_partial_receipt_write_is_detected_and_revoked(self):
        witness = self.witness()
        real_write, damaged = Path.write_bytes, []
        def write(path, raw):
            if path == witness.output / 'results.json' and not damaged:
                damaged.append(True)
                return real_write(path, raw[:-1])
            return real_write(path, raw)
        witness.run.side_effect = lambda: witness._seal() or True
        with patch.object(Path, 'write_bytes', write):
            status, output, errors = self.invoke(witness)
        self.assertEqual((status, output), (1, ''))
        self.assertIn('intended receipt bytes', errors)
        report = json.loads((witness.output / 'results.json').read_bytes())
        self.assertEqual(report['Status'], 'FAIL')
        self.assertIs(report['OutputSealVerified'], False)
        witness.run.assert_called_once_with()

    def test_throwing_failure_hook_cannot_retain_new_binding_verdicts(self):
        witness = self.witness()
        def failed_hook(message):
            witness.report.update(RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True)
            raise OSError('secondary failure hook')
        witness._fail = Mock(side_effect=failed_hook)
        witness.run.side_effect = ValueError('primary bindings failure')
        status, output, errors = self.invoke(witness)
        self.assertEqual((status, output), (1, ''))
        self.assertIn('primary bindings failure', errors)
        self.assertIn('secondary failure hook', errors)
        raw = (witness.output / 'results.json').read_bytes()
        report = json.loads(raw)
        self.assertEqual(report['Status'], 'FAIL')
        self.assertIs(report['RuntimeProviderBindingsValidated'], False)
        self.assertIs(report['FinalLinkContractValidated'], False)
        self.assertIn('primary bindings failure', report['PrimaryError'])
        self.assertEqual(json.loads((witness.output / 'artifacts.json').read_bytes())['Artifacts']['results.json'], sha(raw))
        witness.run.assert_called_once_with()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT, RECOVERY)
    report = dict(Status='FAIL', Tests=0, Failures=0, Errors=0, Skipped=0,
        Scope='PURE_SYNTHETIC_CURRENT_CM3_LTO_BINDINGS_FRONTEND_CONTROLS_ONLY', SyntheticInputs=True,
        ActualCaptureAdmitted=False, ActualELFTested=False, ToolInvocations=0, RequiredCellsSatisfied=0,
        Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        SourceHashes={}, SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized host Python required')
        buffers = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        if sha(buffers[RECOVERY]) != RECOVERY_SHA:
            raise ValueError('unchanged authenticated recovery helper required')
        global subject, recovery
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic tests spawned a process')), \
                patch('os.system', side_effect=AssertionError('synthetic tests used shell')):
            subject = load('_bindings_frontend_under_test', SUBJECT, buffers[SUBJECT])
            recovery = load('_bindings_frontend_fixed_recovery', RECOVERY, buffers[RECOVERY])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(FrontendTests)
            if suite.countTestCases() != 17:
                raise ValueError('exact seventeen implemented frontend methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == 17 and not result.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
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
    receipt.write_bytes((json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
