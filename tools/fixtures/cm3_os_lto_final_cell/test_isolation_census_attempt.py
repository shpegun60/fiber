"""Synthetic one-reader isolation-driver tests, not an actual capture replay."""

import argparse
import ast
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 15
BASE_PIN = '62A9F1B8963B3247650BB6BBE2EB33923EEDFBEC4B3C3C581C8230BDDA65CB72'
subject = controls = composition = normal = machine = builder = guard = fixture = abi_fixture = Model = None
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def literals(raw):
    result = {}
    for n in ast.parse(raw).body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            try: result[n.targets[0].id] = ast.literal_eval(n.value)
            except (ValueError, TypeError): pass
    return result


class IsolationModel:
    def __init__(self, case):
        super().__init__(case)
        self.isolation_visited = []
        self.census['OriginalInputs'].update(
            OriginalFinal=dict(Path=str(self.final), Sha256=sha(self.final.read_bytes())),
            OriginalLtrans=dict(Path=str(self.worker), Sha256=sha(self.worker.read_bytes())))
        self.census['DumpInputs'] = {r['Role']: dict(Path=r['Path'], Sha256=r['Sha256'])
            for r in self.handoff['OriginalDisassemblies']}
        self.handoff['OriginalCensus'] = copy.deepcopy(self.census)
        self.isolation = dict(Status='SYNTHETIC-12-ISOLATION', CommandsReplayed=12,
            Inputs={role: copy.deepcopy(self.census['OriginalInputs'][original]) for role, original in
                (('OriginalOrdinaryELF', 'OrdinaryFinal'), ('OriginalEmitELF', 'OriginalFinal'),
                 ('OriginalMachine', 'OriginalLtrans'))},
            LoadImageComparisons=dict(OriginalTwins=copy.deepcopy(self.census['Twins'])),
            OriginalDumps=copy.deepcopy(self.census['DumpInputs']),
            SlotProofs=dict(Status='SYNTHETIC-TWO-SLOT-PROOFS'),
            Qualification=False, IRImportClosureValidated=False, RequiredCellsSatisfied=0)
        for i in range(41, 53):
            p = self.batch_root / ('commands/%03d.json' % i)
            raw = encoded(dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
            self.put(p, raw)
            self.hashes[p] = self.roles[p] = sha(raw)
            self.identities[p] = self.physical(p)
            self.seed_bytes[p] = raw
        self.reseal()
        self.isolation_leaf = NS(inspect=Mock(side_effect=self.inspect_isolation),
            require_result=Mock(side_effect=lambda p: guard._same(p, self.isolation, 'strict synthetic isolation')))
        self.helpers.update(isolation_replay=self.isolation_leaf,
            isolation_slots=NS(require_result=Mock(side_effect=lambda p:
                guard._same(p, self.isolation['SlotProofs'], 'strict synthetic slot result'))),
            controls_composition=NS(admit_normal=Mock(wraps=controls.admit_normal)))
        for name in ('ownership', 'isolation_slots', 'os_slot', 'neutral_slot'):
            self.markers[name] = NS(Role=name)
        for name in ('isolation_replay', 'ownership', 'isolation_slots', 'os_slot', 'neutral_slot'):
            self.environment['HelperPlans'][name] = ('tools/synthetic/' + name + '.py', 'E' * 64)

    def inspect_isolation(self, batch, native, root, core, helpers, read, *, original_dumps):
        self.case.assertTrue(self.inside)
        self.case.assertIs(core, self.core)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertEqual(set(helpers), {'deps', 'recipes', 'probes', 'ownership', 'guard', 'transport',
            'controls_replay', 'isolation_slots', 'os_slot', 'neutral_slot'})
        self.case.assertIs(helpers['controls_replay'], self.loaded['controls_replay'])
        self.case.assertEqual(set(original_dumps), {'Final', 'Machine'})
        for i in range(41, 53):
            self.case.assertEqual(self.suite.report.get('RecordedIsolationCommandsReplayed', 0), 0)
            row = json.loads(read(root / ('commands/%03d.json' % i)))
            self.case.assertEqual(row, dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
            self.isolation_visited.append(i)
            if self.fault == ('isolation', i): raise ValueError('synthetic isolation failure/' + str(i))
        if self.fault == 'isolation-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        if self.fault == 'isolation-escape': read(self.root / 'unowned.h')
        self.events.append('isolation')
        return copy.deepcopy(self.isolation)

    def admit_handoff(self):
        return subject.admit_normal(self.args, self.runner, self.environment, self.batch_root,
            self.batch, self.roles, self.helpers)

    @contextmanager
    def reader(self, environment, groups):
        self.case.assertEqual(set(groups), {'CensusABIAndIsolation'})
        with super().reader(environment, {'CensusAndABIControls': groups['CensusABIAndIsolation']}) as values:
            yield values

    @contextmanager
    def frozen(self):
        modules = dict(self.markers, machine=self.facade, normal_entry=normal, normal=self.normal_leaf,
            abi_replay=self.abi_leaf, controls_replay=self.controls_leaf, isolation_replay=self.isolation_leaf,
            guard=guard, transport=NS())
        self.loaded = {}
        class Loader:
            def create_module(self, spec): return None
            def exec_module(loader, module):
                name = module.__name__.removeprefix('_os_isolation_census_frozen_')
                module.__dict__.update(vars(modules[name]))
                self.loaded[name] = module
        with patch.dict(sys.modules), patch.object(subject.importlib.util, 'spec_from_file_location',
                side_effect=lambda name, path: importlib.util.spec_from_loader(name, Loader())):
            yield

    def run(self):
        with self.frozen(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, builder, self.helpers, {}, {})

    def replay(self):
        self.admit_handoff()
        with self.frozen():
            return subject.replay(self.runner, self.environment, self.batch_root, self.batch, self.handoff_root,
                self.handoff, self.roles, self.targets, self.inspection_tool)

    def failed(self):
        result = json.loads((self.output / 'results.json').read_bytes())
        self.case.assertEqual(result['Status'], 'FAIL')
        for key in subject.FACTS + subject.NONCLAIMS: self.case.assertIs(result[key], False)
        self.case.assertIs(type(result['RecordedABICommandsReplayed']), int)
        self.case.assertEqual(result['RecordedABICommandsReplayed'], 0)
        self.case.assertIs(type(result['RecordedIsolationCommandsReplayed']), int)
        self.case.assertEqual(result['RecordedIsolationCommandsReplayed'], 0)
        return result


class DriverTests(unittest.TestCase):
    def test_one_reader_all_four_leaves_and_separate_command_counts(self):
        m = Model(self)
        report = m.run()
        self.assertEqual((m.entries, m.exits), (1, 1))
        self.assertEqual(m.visited, list(range(41)))
        self.assertEqual(m.isolation_visited, list(range(41, 53)))
        self.assertEqual(m.events, ['batch-admit', 'construct', 'census', 'abi', 'controls', 'isolation'])
        for leaf in (m.normal_leaf, m.abi_leaf, m.controls_leaf, m.isolation_leaf): leaf.inspect.assert_called_once()
        self.assertEqual(tuple(report[k] for k in ('ToolInvocations', 'CompilerInvocations',
            'RecordedInspectionInvocations', 'RecordedABICommandsReplayed', 'RecordedIsolationCommandsReplayed')),
            (0, 0, 2, 41, 12))
        self.assertEqual(report['Commands'], [])
        m.suite.command.assert_not_called()
        self.assertEqual(m.seed_bytes, {p: p.read_bytes() for p in m.seed_bytes})

    def test_admission_uses_frozen_control_composition_and_explicit_tool_header_roles(self):
        m = Model(self)
        before = set(m.roles)
        m.admit_handoff()
        expected = set(m.project) | set(m.control_inputs) | {m.handoff_root / n for n in m.artifacts}
        expected.add(m.handoff_root / 'artifacts.json')
        self.assertEqual(set(m.roles) - before, expected - before)
        m.helpers['controls_composition'].admit_normal.assert_called_once()
        m.helpers['composition'].admit_normal.assert_called_once()

    def test_isolation_failure_at_start_middle_end_revokes_both_component_credits(self):
        for i in (41, 47, 52):
            m = Model(self)
            m.fault = ('isolation', i)
            with self.subTest(index=i), self.assertRaisesRegex(ValueError, 'synthetic isolation failure/'):
                m.run()
            self.assertEqual(m.isolation_visited, list(range(41, i + 1)))
            self.assertEqual(m.visited, list(range(41)))
            m.runner.seal.assert_not_called()
            m.failed()

    def test_prior_leaf_failures_or_forged_result_do_not_reach_later_components(self):
        for name in ('normal_leaf', 'abi_leaf', 'controls_leaf', 'isolation_leaf'):
            m = Model(self)
            getattr(m, name).inspect.side_effect = None
            getattr(m, name).inspect.return_value = dict(Forged=True)
            with self.subTest(leaf=name), self.assertRaises(ValueError): m.run()
            m.runner.seal.assert_not_called()
            m.failed()

    def test_all_composition_joins_reject_forged_individually_valid_components(self):
        old = [('abi', 'Inputs', 'OriginalELF'), ('abi', 'PositiveAuthority', 'LoadImageComparison'),
            ('controls', 'Inputs', 'OriginalELF'), ('controls', 'Inputs', 'ReproducedELF'),
            ('controls', 'PositiveAuthority', 'LoadImageComparison')]
        new = [('isolation', 'Inputs', key) for key in ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine')]
        new += [('isolation', 'LoadImageComparisons', 'OriginalTwins')]
        new += [('isolation', 'OriginalDumps', key) for key in ('Final', 'Machine')]
        for owner, group, key in old + new:
            m = Model(self)
            getattr(m, owner)[group][key] = dict(Foreign=True)
            with self.subTest(owner=owner, key=key), self.assertRaisesRegex(ValueError, 'shared'): m.run()
            m.failed()

    def test_result_rechecks_isolation_joins_independently(self):
        m = Model(self)
        report = m.run()
        for group, field in [('Inputs', k) for k in ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine')] + [
                ('LoadImageComparisons', 'OriginalTwins'), ('OriginalDumps', 'Final'), ('OriginalDumps', 'Machine')]:
            forged = copy.deepcopy(report)
            forged['IsolationComponent'][group][field] = dict(Foreign=True)
            h = dict(m.helpers, isolation_replay=NS(require_result=lambda p: None))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(forged, h)

    def test_result_invokes_detailed_slot_validator_not_only_component_subset_check(self):
        m = Model(self)
        valid = m.run()
        forged = copy.deepcopy(valid)
        forged['IsolationComponent']['SlotProofs']['UnexpectedClaim'] = True
        h = dict(m.helpers, isolation_replay=NS(require_result=lambda p: None))
        with self.assertRaisesRegex(ValueError, 'strict synthetic slot result'):
            subject.require_result(forged, h)

    def test_reader_escape_altered_journal_and_immutable_receipt_mismatch_reject(self):
        for fault in ('isolation-escape', 'journal', 'immutable'):
            m = Model(self)
            m.admit_handoff()
            if fault == 'journal': (m.batch_root / 'commands/052.json').write_bytes(b'forged')
            elif fault == 'immutable': m.fault = ('immutable', m.batch_root / 'results.json')
            else: m.fault = fault
            with self.subTest(fault=fault), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)

    def test_direct_replay_blocks_processes_at_entry_leaf_and_closing(self):
        for fault in ('reader-enter-process', 'isolation-process', 'closing-process'):
            m = Model(self)
            m.admit_handoff()
            m.fault = fault
            with self.subTest(fault=fault), m.frozen(), patch('subprocess.Popen', return_value=object()) as process, \
                    self.assertRaisesRegex(AssertionError, 'immutable isolation/census replay cannot start processes'):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            process.assert_not_called()

    def test_closing_seal_summary_recovery_failures_revoke_all_credit(self):
        for fault in ('objects', 'close', 'output', 'seal', 'manifest', 'summary', 'recovery'):
            m = Model(self)
            if fault == 'close': m.after_reader = lambda: setattr(m, 'fault', 'close')
            else: m.fault = fault
            if fault == 'recovery': m.isolation_leaf.inspect.side_effect = ValueError('primary isolation failure')
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary failed')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)): m.run()
            m.failed()
            m.runner.recover.assert_called_once()

    def test_output_root_substitution_prevents_seal_and_every_recovery_write(self):
        m = Model(self)
        def replace():
            m.output.rename(m.root / 'retired')
            m.put(m.output / 'marker', b'foreign root')
        m.after_reader = replace
        with self.assertRaises(ValueError): m.run()
        self.assertEqual({p.name for p in m.output.iterdir()}, {'marker'})
        self.assertEqual((m.output / 'marker').read_bytes(), b'foreign root')
        m.runner.seal.assert_not_called()
        m.runner.recover.assert_not_called()
        self.assertEqual(m.suite.report['RecordedABICommandsReplayed'], 0)
        self.assertEqual(m.suite.report['RecordedIsolationCommandsReplayed'], 0)

    def test_exact_disposition_facts_counters_nonclaims_and_clean_errors(self):
        m = Model(self)
        valid = m.run()
        changes = [('Status', 'PASS'), ('Scope', 'whole-cell'), ('LTO', 1), ('Profile', 'CM4'),
            ('Mode', 'O2'), ('Linkage', 'archive'), ('ToolInvocations', False), ('ToolInvocations', 1),
            ('CompilerInvocations', 1), ('RecordedInspectionInvocations', 0), ('RecordedABICommandsReplayed', 134),
            ('RecordedIsolationCommandsReplayed', 0), ('RecordedIsolationCommandsReplayed', 12.0),
            ('RecordedIsolationCommandsReplayed', True), ('Commands', [{}]), ('RequiredCellsSatisfied', 1),
            ('ProjectSourceReaderRoles', True)] + [(k, 1) for k in subject.FACTS]
        changes += [(k, v) for k in subject.NONCLAIMS for v in (True, 0, None)]
        for k, v in changes:
            forged = copy.deepcopy(valid)
            forged[k] = v
            with self.subTest(key=k, value=v), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)
        for k in ('Error', 'PrimaryError', 'ClosingErrors', 'IsolationComponent'):
            forged = copy.deepcopy(valid)
            del forged[k]
            with self.subTest(missing=k), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def graph(self, bad=False, late=False):
        names = {'builder': subject.BATCH[0], 'metadata': builder.METADATA[0],
            'reader_entry': 'tools/fixtures/cm3_os_lto_final_cell/runner.py',
            'normal_metadata': subject.NORMAL[0], 'composition_metadata': subject.COMPOSITION[0],
            'controls_metadata': subject.CONTROLS[0]}
        modules = {name: NS(**literals(BUFFERS[ROOT / relative])) for name, relative in names.items()}
        modules['builder']._pins = builder._pins
        wanted = {Path(subject.__file__).resolve()}
        for relative in names.values(): wanted.add(ROOT / relative)
        for n in ('metadata', 'builder', 'normal_metadata', 'composition_metadata', 'controls_metadata'):
            for relative, _ in modules[n].PINS.values(): wanted.add(ROOT / relative)
        for relative, _ in modules['metadata'].LEAF_PINS.values(): wanted.add(ROOT / relative)
        for relative, _ in modules['reader_entry'].PINS.values(): wanted.add(ROOT / relative)
        for n in ('metadata', 'reader_entry', 'normal_metadata', 'composition_metadata', 'controls_metadata'):
            for relative in modules[n].DOCUMENTS: wanted.add(ROOT / relative)
        for relative, _ in subject.PINS.values(): wanted.add(ROOT / relative)
        for relative in subject.DOCUMENTS: wanted.add(ROOT / relative)
        data = {p: BUFFERS[p] for p in wanted}
        state = NS(constructed=False, enrolled={}, reads=[])
        constructor = Mock(side_effect=lambda args: setattr(state, 'constructed', True) or object())
        def factory(legacy, capture, *, extra_sources):
            self.assertEqual(extra_sources, data)
            state.enrolled.update(extra_sources)
            return constructor
        state.factory = Mock(side_effect=factory)
        new_path = ROOT / subject.PINS['isolation_replay'][0]
        def read(p):
            if state.constructed: raise AssertionError('late physical bootstrap read')
            state.reads.append(p)
            return b'wrong new pin' if bad and p == new_path else data[p]
        def load(name, path, raw):
            key = name.removeprefix('_os_isolation_census_')
            if key in modules: return modules[key]
            if key == 'admission_admission': return NS(witness_type=state.factory)
            if key.startswith('bootstrap_') and late: (ROOT / 'tools/unknown.py').read_bytes()
            return NS()
        with patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=load):
            yield state, constructor

    def test_complete_bootstrap_enrollment_precedes_witness_and_preserves_35_opening(self):
        with self.graph() as (state, constructor): prepared = subject.prepare(NS())
        self.assertEqual(prepared[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        self.assertEqual(len(prepared[4]), 35)
        self.assertTrue({'controls_composition', 'isolation_replay', 'isolation_slots', 'os_slot', 'neutral_slot'} <= set(prepared[3]))
        state.factory.assert_called_once()
        constructor.assert_called_once()

    def test_bad_new_pin_rejects_before_admission_and_unknown_late_source_never_reads_disk(self):
        with self.graph(bad=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin/'):
            subject.prepare(NS())
        state.factory.assert_not_called()
        with self.graph(late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(NS())
        constructor.assert_called_once()


class CliTests(unittest.TestCase):
    def test_abbreviations_rejected_and_all_stages_block_process_and_shell(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'synthetic'])
        prepare.assert_not_called()
        for stage in ('prepare', 'admission', 'reader', 'close', 'seal', 'summary'):
            for kind in ('process', 'shell'):
                m = Model(self)
                def attempt(*args, **kwargs):
                    if kind == 'process':
                        import subprocess
                        subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
                    else:
                        import os
                        os.system('SYNTHETIC-NEVER-EXECUTED')
                def prepare(args):
                    if stage == 'prepare': attempt()
                    return m.runner, m.environment, builder, m.helpers, {}, {}
                @contextmanager
                def reader(*args):
                    attempt()
                    yield None
                if stage == 'admission': m.facade.admit_batch.side_effect = attempt
                elif stage == 'reader': m.runner.reader = reader
                elif stage == 'close': m.witness.close.side_effect = attempt
                elif stage == 'seal': m.runner.seal.side_effect = attempt
                argv = [v for name in subject.ARGUMENTS for v in ('--' + name,
                    str(getattr(m.args, name.replace('-', '_'), 'synthetic')))]
                printer = patch('builtins.print', side_effect=attempt) if stage == 'summary' else nullcontext()
                with self.subTest(stage=stage, kind=kind), m.frozen(), printer, \
                        patch.object(subject, 'prepare', side_effect=prepare), \
                        patch('subprocess.Popen', return_value=object()) as process, \
                        patch('os.system', return_value=0) as shell, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(subject.main(argv), 1)
                    process.assert_not_called()
                    shell.assert_not_called()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='SYNTHETIC_ISOLATION_COMPOSITION_DRIVER_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, ActualCaptureAdmitted=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        global subject, controls, composition, normal, machine, builder, guard, fixture, abi_fixture, Model
        names = ('isolation_census_attempt', 'controls_census_attempt', 'abi_census_attempt', 'normal_attempt',
            'machine_attempt', 'batch_attempt', 'batch_guard', 'test_controls_census_attempt', 'test_abi_census_attempt')
        loaded = []
        for name in names:
            p = HERE / (name + '.py')
            BUFFERS[p] = p.read_bytes()
            m = ModuleType('_isolation_driver_test_' + name)
            m.__file__ = str(p)
            exec(compile(BUFFERS[p], str(p), 'exec'), m.__dict__)
            loaded.append(m)
        subject, controls, composition, normal, machine, builder, guard, fixture, abi_fixture = loaded
        if sha(BUFFERS[HERE / 'test_controls_census_attempt.py']) != BASE_PIN:
            raise ValueError('frozen controls fixture pin')
        if sha(BUFFERS[HERE / 'test_abi_census_attempt.py']) != fixture.BASE_SHA256:
            raise ValueError('frozen ABI fixture pin')
        fixture.subject, fixture.composition, fixture.normal, fixture.machine = controls, composition, normal, machine
        fixture.builder, fixture.guard, fixture.base = builder, guard, abi_fixture
        abi_fixture.subject, abi_fixture.normal, abi_fixture.machine = composition, normal, machine
        abi_fixture.builder, abi_fixture.guard = builder, guard
        class Model(IsolationModel, fixture.ControlsModel, abi_fixture.Model):
            pass
        rows = [subject.BATCH, subject.NORMAL, subject.COMPOSITION, subject.CONTROLS, builder.METADATA]
        metadata_path = ROOT / builder.METADATA[0]
        BUFFERS[metadata_path] = metadata_path.read_bytes()
        metadata = literals(BUFFERS[metadata_path])
        BUFFERS[HERE / 'runner.py'] = (HERE / 'runner.py').read_bytes()
        runner = literals(BUFFERS[HERE / 'runner.py'])
        rows.append(('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata['RUNNER_SHA256']))
        for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner['PINS'], normal.PINS,
                         composition.PINS, controls.PINS, subject.PINS): rows.extend(registry.values())
        for registry in (runner['DOCUMENTS'], metadata['DOCUMENTS'], normal.DOCUMENTS,
                         composition.DOCUMENTS, controls.DOCUMENTS, subject.DOCUMENTS): rows.extend(registry.items())
        for relative, h in rows:
            p = ROOT / relative
            if p not in BUFFERS: BUFFERS[p] = p.read_bytes()
            if sha(BUFFERS[p]) != h: raise ValueError('frozen source pin/' + relative)
        BUFFERS[Path(__file__).resolve()] = Path(__file__).read_bytes()
        report['SourceHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items()}
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (DriverTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for p, raw in BUFFERS.items():
            try:
                if p.read_bytes() != raw: report['SourceDrift'].append(str(p))
            except OSError: report['SourceDrift'].append(str(p))
        report['SourceClosureVerified'] = bool(report['SourceHashes']) and not report['SourceDrift']
        if not report['SourceClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
