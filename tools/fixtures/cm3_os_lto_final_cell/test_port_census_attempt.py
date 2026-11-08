"""Synthetic six-component driver controls; never actual producer replay."""

import argparse
import ast
from contextlib import ExitStack, contextmanager, nullcontext, redirect_stderr, redirect_stdout
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


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 27
FIXTURE_PIN = '6CCAA547AA06004085D5B3C904C7F3542F6D96C0336BAAB3AE2357FDFCF60401'
PEER_FIXTURE = ('tools/fixtures/cm3_os_lto_final_cell/test_port_replay.py',
                '6ED57F709E5244BC7A8BF96F153D95B3154AAAEE2F73811613FAC5C8CB005A2D')
COMMON_FIXTURES = {
    'C:/fzoscommon-census-20261108-e1/results.json':
        'A9407CE1B0C30E97A2D267CC9E922516837D57E328BBB00408B7FF303FEB398C',
    'C:/fzoscommon-census-20261108-e1/artifacts.json':
        '1400ED75666684A566C481EDAC75627DA35971BD76BE489AA718A55551E7A506',
}
BUFFERS, FIXTURE_BUFFERS = {}, {}
subject = fixture = Model = peer_fixture = common_proof = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def module_from_bytes(name, path, raw):
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class PortModel:
    def __init__(self, case):
        super().__init__(case)
        self.port_visited = []
        self.common['ToolBindings'] = dict(Gcc=dict(Path=str(self.root / 'gcc.exe'), Sha256='A' * 64))
        objects = [dict(Index=i, Path=str(self.native_root / ('objects/%02d.o' % i)), Sha256='B' * 64) for i in range(9)]
        self.isolation['NativeObjectBindings'] = objects
        self.isolation['Inputs']['StartupObject'] = {k: objects[8][k] for k in ('Path', 'Sha256')}
        self.isolation['AuthorityInputs']['LinkScript'] = dict(Path=str(self.source_root / 'link.ld'), Sha256='C' * 64)
        self.port = {k: copy.deepcopy(self.common[k]) for k in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort',
            'SourceInventorySha256', 'SourceOwnership', 'SourceOwnershipInputs', 'ToolBindings')}
        self.port['AuthorityInputs'] = copy.deepcopy(self.common['AuthorityInputs'])
        self.port['AuthorityInputs']['LinkScript'] = copy.deepcopy(self.isolation['AuthorityInputs']['LinkScript'])
        self.port.update(Status='SYNTHETIC-36-PORT', CommandsReplayed=36, NativeObjectBindings=copy.deepcopy(objects),
            Inputs={'Final/Startup': dict(Role='Final/Startup', **self.isolation['Inputs']['StartupObject'])},
            LoweredProofs=dict(Status='SYNTHETIC-FOUR-WORKERS-EIGHT-IMAGES'), Qualification=False)
        for i in range(98, 134):
            p = self.batch_root / ('commands/%03d.json' % i)
            raw = encoded(dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
            self.put(p, raw)
            self.hashes[p] = self.roles[p] = sha(raw)
            self.identities[p] = self.physical(p)
            self.seed_bytes[p] = raw
            self.handoff['InputHashes'][str(p)] = sha(raw)
            self.handoff['InputPhysicalIdentities'][str(p)] = list(self.physical(p))
        self.handoff['ClosingFilesVerified'] = len(self.handoff['InputHashes'])
        self.reseal()
        self.port_leaf = NS(inspect=Mock(side_effect=self.inspect_port), require_result=Mock(
            side_effect=lambda p: fixture.guard._same(p, self.port, 'strict synthetic port')))
        self.port_adapter = NS(require_result=Mock(side_effect=self.require_port_lowered))
        self.helpers.update(port_replay=self.port_leaf, port_lowered=self.port_adapter,
                            common_composition=fixture.subject)
        self.markers['port_policy'] = NS(Role='port_policy')
        self.environment['HelperPlans']['port_policy'] = ('tools/synthetic/port_policy.py', 'E' * 64)
        for name in ('common_composition', 'port_replay', 'port_lowered'):
            self.environment['HelperPlans'][name] = ('tools/synthetic/' + name + '.py', 'E' * 64)
        self.environment['HelperPlans']['transport'] = self.environment['Modules']['capture'].PINS['api']
        for alias, original in subject.ALIASES.items():
            self.markers[alias] = self.markers[original]
            self.helpers[alias] = self.markers[alias]
            self.environment['HelperPlans'][alias] = self.environment['HelperPlans'][original]
        for name in subject.PORT_HELPERS:
            if name not in self.helpers:
                self.helpers[name] = self.markers[name]

    def require_port_lowered(self, proof, helpers):
        self.case.assertEqual(set(helpers), set(subject.LOWERED_HELPERS))
        fixture.guard._same(proof, self.port['LoweredProofs'], 'strict synthetic port lowered')

    def inspect_port(self, batch, native, root, core, helpers, read):
        self.case.assertTrue(self.inside)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertIs(core, self.core)
        self.case.assertEqual(set(helpers), set(subject.PORT_HELPERS))
        self.case.assertIs(helpers['port_lowered'], self.loaded['port_lowered'])
        for i in range(98, 134):
            for key, _ in subject.COUNTERS:
                credit = self.suite.report.get(key, 0)
                self.case.assertIs(type(credit), int)
                self.case.assertEqual(credit, 0)
            row = json.loads(read(root / ('commands/%03d.json' % i)))
            self.case.assertEqual(row, dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
            self.port_visited.append(i)
            if self.fault == ('port', i): raise ValueError('synthetic port failure/' + str(i))
        if self.fault == 'port-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        if self.fault == 'port-shell':
            import os
            os.system('SYNTHETIC-NEVER-EXECUTED')
        if self.fault == 'port-escape': read(self.root / 'unowned.h')
        self.events.append('port')
        return copy.deepcopy(self.port)

    @contextmanager
    def reader(self, environment, groups):
        self.case.assertEqual(set(groups), {'CensusABIIsolationCommonAndPort'})
        with super().reader(environment, {'CensusABIIsolationAndCommon': groups['CensusABIIsolationCommonAndPort']}) as values:
            yield values

    @contextmanager
    def frozen(self):
        modules = dict(self.markers, machine=self.facade, normal_entry=fixture.normal, normal=self.normal_leaf,
            abi_replay=self.abi_leaf, controls_replay=self.controls_leaf, isolation_replay=self.isolation_leaf,
            isolation_slots=self.helpers['isolation_slots'], common_replay=self.common_leaf, common_lowered=self.lowered,
            common_composition=fixture.subject, port_replay=self.port_leaf, port_lowered=self.port_adapter, guard=fixture.guard)
        self.loaded = {}
        class Loader:
            def create_module(self, spec): return None
            def exec_module(loader, module):
                name = module.__name__.removeprefix('_os_port_census_frozen_')
                module.__dict__.update(vars(modules[name]))
                self.loaded[name] = module
        with patch.dict(sys.modules), patch.object(subject.importlib.util, 'spec_from_file_location',
                side_effect=lambda name, path: importlib.util.spec_from_loader(name, Loader())):
            yield

    def admit_handoff(self):
        return subject.admit_normal(self.args, self.runner, self.environment, self.batch_root,
                                   self.batch, self.roles, self.helpers)

    def run(self):
        with self.frozen(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, fixture.builder, self.helpers, {}, {})

    def failed(self):
        report = json.loads((self.output / 'results.json').read_bytes())
        self.case.assertEqual(report['Status'], 'FAIL')
        for key in subject.FACTS + subject.NONCLAIMS: self.case.assertIs(report[key], False)
        for key, _ in subject.COUNTERS:
            self.case.assertIs(type(report[key]), int)
            self.case.assertEqual(report[key], 0)
        self.case.assertIs(report['CommonAttributionClosed'], False)
        return report


class DriverTests(unittest.TestCase):
    def test_one_reader_six_fresh_components_and_four_separate_counters(self):
        m = Model(self); report = m.run()
        self.assertEqual((m.entries, m.exits), (1, 1))
        self.assertEqual(m.events, ['batch-admit', 'construct', 'census', 'abi', 'controls', 'isolation', 'common', 'port'])
        self.assertEqual(m.visited + m.isolation_visited + m.common_visited + m.port_visited, list(range(134)))
        for leaf in (m.normal_leaf, m.abi_leaf, m.controls_leaf, m.isolation_leaf, m.common_leaf, m.port_leaf):
            leaf.inspect.assert_called_once()
        self.assertEqual(tuple(report[k] for k, _ in subject.COUNTERS), (41, 12, 45, 36))
        self.assertEqual((report['ToolInvocations'], report['CompilerInvocations'], report['RequiredCellsSatisfied']), (0, 0, 0))
        self.assertEqual(report['Commands'], [])
        m.suite.command.assert_not_called()
        self.assertEqual(m.seed_bytes, {p: p.read_bytes() for p in m.seed_bytes})

    def test_pending_is_exact_common_projection_without_port_or_policy_promotion(self):
        m = Model(self)
        pending = [dict(Group='positive', Role='Machine', Evidence=[dict(Function='ctxrt_v1_set_dispatcher')])]
        m.common['LoweredProofs'].update(UnresolvedAttribution=pending, CommonAttributionClosed=False)
        report = m.run()
        self.assertEqual(report['Status'], subject.PENDING)
        self.assertEqual(report['UnresolvedAttribution'], pending)
        self.assertIs(report['CommonAttributionClosed'], False)
        for key in subject.FACTS: self.assertIs(report[key], True)
        for key in subject.NONCLAIMS: self.assertIs(report[key], False)

    def test_port_failure_start_middle_end_revokes_ten_facts_and_four_counters(self):
        for i in (98, 116, 133):
            m = Model(self); m.fault = ('port', i)
            with self.subTest(index=i), self.assertRaisesRegex(ValueError, 'synthetic port failure/'): m.run()
            self.assertEqual(m.port_visited, list(range(98, i + 1)))
            m.runner.seal.assert_not_called(); m.failed()

    def test_forged_earlier_components_cannot_reach_port(self):
        for name in ('normal_leaf', 'abi_leaf', 'controls_leaf', 'isolation_leaf', 'common_leaf'):
            m = Model(self); leaf = getattr(m, name)
            leaf.inspect.side_effect = None; leaf.inspect.return_value = dict(Forged=True)
            with self.subTest(leaf=name), self.assertRaises(ValueError): m.run()
            m.port_leaf.inspect.assert_not_called(); m.failed()

    def test_existing_composition_and_new_port_joins_reject_cross_wiring(self):
        cases = [('abi', 'Inputs', 'OriginalELF'), ('controls', 'Inputs', 'ReproducedELF'),
            ('isolation', 'OriginalDumps', 'Final'), ('common', 'AuthorityInputs', 'BatchReceipt')]
        cases += [('port', None, k) for k in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256',
            'SourceOwnership', 'SourceOwnershipInputs', 'ToolBindings', 'NativeObjectBindings')]
        cases += [('port', 'AuthorityInputs', k) for k in ('BatchReceipt', 'NativeReceipt', 'Manifest', 'CommandJournal', 'LinkScript')]
        cases += [('port', 'Inputs', 'Final/Startup')]
        for owner, group, key in cases:
            m = Model(self); target = getattr(m, owner)
            (target if group is None else target[group])[key] = dict(Path='C:/foreign', Sha256='F' * 64)
            with self.subTest(owner=owner, key=key), self.assertRaises((ValueError, KeyError)): m.run()
            m.failed()

    def test_outer_validator_repeats_port_joins_without_leaf_help(self):
        m = Model(self); valid = m.run()
        for group, key in [(None, k) for k in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256',
                'SourceOwnership', 'SourceOwnershipInputs', 'ToolBindings', 'NativeObjectBindings')] + [
                ('AuthorityInputs', k) for k in ('BatchReceipt', 'NativeReceipt', 'Manifest', 'CommandJournal', 'LinkScript')] + [
                ('Inputs', 'Final/Startup')]:
            report = copy.deepcopy(valid); p = report['PortPolicyComponent']
            (p if group is None else p[group])[key] = (dict(Role=key, Path='C:/foreign/startup.o', Sha256='F' * 64)
                if key == 'Final/Startup' else dict(Foreign=True))
            helpers = dict(m.helpers, port_replay=NS(require_result=lambda p: None))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(report, helpers)

    def test_full_port_adapter_validator_runs_after_leaf_validator(self):
        m = Model(self); report = copy.deepcopy(m.run())
        report['PortPolicyComponent']['LoweredProofs']['ForeignClaim'] = True
        helpers = dict(m.helpers, port_replay=NS(require_result=lambda p: None))
        with self.assertRaisesRegex(ValueError, 'strict synthetic port lowered'): subject.require_result(report, helpers)

    def test_pending_projection_and_status_remain_strict(self):
        m = Model(self); valid = m.run()
        for key, value in (('Status', subject.PENDING), ('CommonAttributionClosed', False),
                           ('CommonAttributionClosed', 1), ('UnresolvedAttribution', [dict(Foreign=True)])):
            report = copy.deepcopy(valid); report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): subject.require_result(report, m.helpers)

    def test_outer_authority_cannot_be_substituted(self):
        m = Model(self); valid = m.run()
        for key in ('Cohort', 'SourceInventorySha256'):
            report = copy.deepcopy(valid); report[key] = 'foreign'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'result shared'): subject.require_result(report, m.helpers)
        for group, key in (('Batch', 'ReceiptSha256'), ('Batch', 'ArtifactsSha256')):
            report = copy.deepcopy(valid); report[group][key] = 'F' * 64
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'result shared'): subject.require_result(report, m.helpers)

    def test_all_false_fields_facts_counters_and_errors_are_literal(self):
        m = Model(self); valid = m.run()
        changes = [(key, value) for key in subject.NONCLAIMS for value in (True, 0, None)]
        changes += [(key, 1) for key in subject.FACTS]
        changes += [(key, value) for key, _ in subject.COUNTERS for value in (0, True, 36.0)]
        changes += [('LTO', 1), ('ToolInvocations', False), ('CompilerInvocations', 1), ('RequiredCellsSatisfied', 1), ('Commands', [{}])]
        for key, value in changes:
            report = copy.deepcopy(valid); report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): subject.require_result(report, m.helpers)
        for key in (*subject.NONCLAIMS, 'Error', 'PrimaryError', 'ClosingErrors', 'PortPolicyComponent'):
            report = copy.deepcopy(valid); del report[key]
            with self.subTest(missing=key), self.assertRaises((ValueError, KeyError)): subject.require_result(report, m.helpers)
        self.assertEqual(len(subject.FACTS), 10); self.assertEqual(len(subject.COUNTERS), 4)
        self.assertTrue(set(fixture.subject.NONCLAIMS) <= set(subject.NONCLAIMS))

    def test_closing_seal_summary_and_recovery_failures_revoke_every_credit(self):
        for fault in ('objects', 'close', 'output', 'seal', 'manifest', 'summary', 'recovery'):
            m = Model(self)
            if fault == 'close': m.after_reader = lambda: setattr(m, 'fault', 'close')
            else: m.fault = fault
            if fault == 'recovery': m.port_leaf.inspect.side_effect = ValueError('primary port failure')
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary failed')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)): m.run()
            m.failed(); m.runner.recover.assert_called_once()

    def test_output_substitution_blocks_seal_and_recovery(self):
        m = Model(self)
        def replace():
            m.output.rename(m.root / 'retired'); m.put(m.output / 'marker', b'foreign root')
        m.after_reader = replace
        with self.assertRaises(ValueError): m.run()
        self.assertEqual({p.name for p in m.output.iterdir()}, {'marker'})
        m.runner.seal.assert_not_called(); m.runner.recover.assert_not_called()
        for key, _ in subject.COUNTERS: self.assertEqual(m.suite.report[key], 0)

    def test_admission_retains_all_fourteen_control_roles(self):
        m = Model(self); before = set(m.roles); m.admit_handoff()
        self.assertEqual(len(m.control_inputs), 14)
        self.assertTrue(set(m.control_inputs) <= set(m.roles))
        self.assertTrue(set(m.project) <= set(m.roles))
        self.assertTrue(set(m.roles) - before)
        m.helpers['isolation_composition'].admit_normal.assert_called_once()
        m.helpers['controls_composition'].admit_normal.assert_called_once()

    def test_reader_escape_changed_journal_and_receipt_reject(self):
        for fault in ('port-escape', 'journal', 'immutable'):
            m = Model(self); m.admit_handoff()
            if fault == 'journal': (m.batch_root / 'commands/133.json').write_bytes(b'forged')
            elif fault == 'immutable': m.fault = ('immutable', m.batch_root / 'results.json')
            else: m.fault = fault
            with self.subTest(fault=fault), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)

    def test_direct_replay_guards_entry_port_and_close(self):
        for fault in ('reader-enter-process', 'port-process', 'port-shell', 'closing-process'):
            m = Model(self); m.admit_handoff(); m.fault = fault
            with self.subTest(fault=fault), m.frozen(), patch('subprocess.Popen') as process, patch('os.system') as shell, \
                    self.assertRaisesRegex(AssertionError, 'immutable port/census replay cannot'):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            process.assert_not_called(); shell.assert_not_called()


@contextmanager
def bootstrap(case, *, bad=None, zero=False, missing=None, mismatch=False, late=False):
    state = NS(constructed=False, reads=[], enrolled={}, events=[])
    physical_read, real_load = Path.read_bytes, subject.load
    bad_path = ROOT / (subject.PINS[bad][0] if bad in subject.PINS else next(iter(subject.DOCUMENTS))) if bad else None
    def read(path):
        if state.constructed: raise AssertionError('late physical bootstrap read')
        state.reads.append(path)
        return b'corrupted synthetic source' if path == bad_path else physical_read(path)
    def construct(args):
        state.constructed = True; state.events.append('witness'); return NS(SyntheticWitness=True)
    constructor = Mock(side_effect=construct)
    def factory(legacy, capture, *, extra_sources):
        state.enrolled = dict(extra_sources)
        for path, raw in extra_sources.items(): case.assertEqual(raw, BUFFERS[path])
        case.assertIn('transport', state.events)
        return constructor
    state.factory = Mock(side_effect=factory)
    def load(name, path, raw):
        module = real_load(name, path, raw)
        if name == '_os_port_census_admission_admission': module.witness_type = state.factory
        if name == '_os_port_census_admission_capture' and mismatch:
            module.PINS = dict(module.PINS, api=(module.PINS['api'][0], 'F' * 64))
        if name == '_os_port_census_bootstrap_transport':
            case.assertFalse(state.constructed); state.events.append('transport')
        if name == '_os_port_census_bootstrap_machine' and late: (ROOT / 'tools/unadmitted-port.py').read_bytes()
        return module
    pins = dict(subject.PINS)
    if zero: pins['port_replay'] = (pins['port_replay'][0], '0' * 64)
    if missing: del pins[missing]
    with patch.dict(sys.modules), patch.object(subject, 'PINS', pins), patch.object(Path, 'read_bytes', read), \
            patch.object(subject, 'load', side_effect=load):
        yield state, constructor


class BootstrapTests(unittest.TestCase):
    def test_original_35_and_all_sources_aliases_and_transport_precede_witness(self):
        with bootstrap(self) as (state, constructor): prepared = subject.prepare(NS())
        runner, environment, builder, helpers, opening, buffers = prepared
        metadata = fixture.literals(BUFFERS[ROOT / builder.METADATA[0]])
        old = {ROOT / subject.BATCH[0], ROOT / builder.METADATA[0], HERE / 'runner.py'}
        for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner.PINS): old.update(ROOT / v[0] for v in registry.values())
        for docs in (metadata['DOCUMENTS'], runner.DOCUMENTS): old.update(ROOT / p for p in docs)
        self.assertEqual(len(opening), 35)
        self.assertEqual(opening, {str(p): sha(BUFFERS[p]) for p in old})
        self.assertEqual(buffers, state.enrolled); self.assertEqual(set(state.reads), set(buffers))
        for alias, original in subject.ALIASES.items():
            self.assertEqual(environment['HelperPlans'][alias], environment['HelperPlans'][original])
        self.assertEqual(environment['HelperPlans']['transport'], environment['Modules']['capture'].PINS['api'])
        self.assertTrue(set(subject.PORT_HELPERS) | set(subject.LOWERED_HELPERS) <= set(helpers))
        self.assertEqual(state.events, ['transport', 'witness'])
        constructor.assert_called_once()

    def test_bad_frozen_parents_peer_sources_and_contract_reject_before_witness(self):
        for role in ('common_composition', 'sealed_composition', 'port_replay', 'port_lowered', 'contract'):
            with self.subTest(role=role), bootstrap(self, bad=role) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin'):
                subject.prepare(NS())
            state.factory.assert_not_called(); constructor.assert_not_called()

    def test_zero_peer_pin_rejects_before_witness(self):
        with bootstrap(self, zero=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin'): subject.prepare(NS())
        state.factory.assert_not_called(); constructor.assert_not_called()
        for name in ('port_replay', 'port_lowered'):
            with self.subTest(missing=name), bootstrap(self, missing=name) as (state, constructor), \
                    self.assertRaisesRegex(ValueError, 'complete authenticated component helper plan'):
                subject.prepare(NS())
            state.factory.assert_not_called(); constructor.assert_not_called()

    def test_transport_api_mismatch_rejects_before_witness(self):
        with bootstrap(self, mismatch=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'same authenticated capture transport'):
            subject.prepare(NS())
        state.factory.assert_not_called(); constructor.assert_not_called()

    def test_no_physical_fallback_for_late_unadmitted_helper_read(self):
        with bootstrap(self, late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(NS())
        constructor.assert_called_once(); self.assertNotIn(ROOT / 'tools/unadmitted-port.py', state.reads)

    def test_no_parent_prepare_run_or_replay_call_in_new_bootstrap(self):
        tree = ast.parse(BUFFERS[Path(subject.__file__).resolve()])
        prepare = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare')
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ('prepare', 'run', 'replay') for n in ast.walk(prepare)))
        for name in ('elftools', 'elftools.elf.elffile'):
            with self.subTest(parser=name), bootstrap(self) as (state, constructor), \
                    patch.dict(sys.modules, {name: ModuleType(name)}), self.assertRaisesRegex(ValueError, 'initially unimported parser'):
                subject.prepare(NS())
            self.assertEqual(state.reads, []); constructor.assert_not_called()


@contextmanager
def validators_only(helpers):
    with ExitStack() as stack:
        for name in ('read_bytes', 'read_text', 'open', 'stat', 'lstat', 'exists', 'iterdir', 'glob', 'rglob', 'resolve'):
            stack.enter_context(patch.object(Path, name, side_effect=AssertionError('validator filesystem disabled')))
        for name in ('builtins.open', 'os.open', 'os.stat', 'os.lstat', 'subprocess.Popen', 'os.system'):
            stack.enter_context(patch(name, side_effect=AssertionError('validator I/O disabled')))
        for helper in helpers.values():
            for name in ('inspect', 'inspect_lowered', 'inspect_final', 'inspect_stress', 'worker_chain'):
                if callable(getattr(helper, name, None)):
                    stack.enter_context(patch.object(helper, name, side_effect=AssertionError('producer predicate disabled')))
        yield


class RealHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with bootstrap(unittest.TestCase()): cls.prepared = subject.prepare(NS())
        cls.helpers = cls.prepared[3]
        cls.proof = peer_fixture.synthetic_result(cls.helpers)
        sources = getattr(peer_fixture, 'BUFFERS', None)
        if type(sources) is not dict or not sources:
            raise ValueError('synthetic peer fixture must retain its executed source buffers')
        for path, raw in sources.items():
            if not isinstance(path, Path) or not path.is_absolute() or type(raw) is not bytes:
                raise ValueError('synthetic peer source buffer schema')
            if path in BUFFERS and BUFFERS[path] != raw:
                raise ValueError('synthetic peer source buffer disagreement')
            BUFFERS[path] = raw

    def test_real_returned_prepare_helpers_pass_both_real_port_validators(self):
        with validators_only(self.helpers):
            subject.port_result(copy.deepcopy(self.proof), self.helpers)
            prior = self.helpers['common_composition']
            self.assertEqual(prior.common_result(copy.deepcopy(common_proof), self.helpers), [])
            missing = dict(self.helpers); del missing['transport']
            with self.assertRaises(KeyError) as caught:
                prior.common_result(copy.deepcopy(common_proof), missing)
            self.assertEqual(caught.exception.args, ('transport',))

    def test_missing_each_port_helper_rejects_without_marker_substitutes(self):
        for name in set(subject.PORT_HELPERS) | {'port_replay'}:
            helpers = dict(self.helpers); del helpers[name]
            with self.subTest(helper=name), validators_only(self.helpers), self.assertRaises((KeyError, ValueError)):
                subject.port_result(copy.deepcopy(self.proof), helpers)

    def test_real_detailed_validator_rejects_nested_foreign_claim_even_if_leaf_bypassed(self):
        proof = copy.deepcopy(self.proof); proof['LoweredProofs']['ForeignClaim'] = True
        helpers = dict(self.helpers, port_replay=NS(require_result=lambda p: None))
        with validators_only(self.helpers), self.assertRaises(ValueError): subject.port_result(proof, helpers)

    def test_postseal_missing_alias_revokes_all_facts_and_counters(self):
        for name in subject.LOWERED_HELPERS:
            m = Model(self); del m.helpers[name]
            with self.subTest(helper=name), self.assertRaises((KeyError, ValueError)): m.run()
            m.runner.seal.assert_called_once(); m.runner.recover.assert_called_once(); m.failed()


class ApiTests(unittest.TestCase):
    def test_peer_signatures_and_exact_helper_sets(self):
        for filename, expected, signatures in (('port_replay.py', subject.PORT_HELPERS,
                {'inspect': ['batch', 'native', 'root', 'core', 'helpers', 'read'], 'require_result': ['proof']}),
                ('port_lowered.py', subject.LOWERED_HELPERS,
                {'inspect': ['core', 'read', 'plans', 'native', 'helpers'], 'require_result': ['proof', 'helpers']})):
            tree = ast.parse(BUFFERS[HERE / filename])
            assignment = next(n for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'HELPERS' for t in n.targets))
            self.assertEqual(set(ast.literal_eval(assignment.value.args[0])), set(expected))
            functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
            for name, args in signatures.items(): self.assertEqual([a.arg for a in functions[name].args.args], args)
        self.assertEqual(len(subject.PORT_HELPERS), 13); self.assertEqual(len(subject.LOWERED_HELPERS), 7)


class CliTests(unittest.TestCase):
    def test_guards_bootstrap_through_exception_diagnostics_and_no_abbreviations(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): subject.main(['--batch-b', 'x'])
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
                    return m.runner, m.environment, fixture.builder, m.helpers, {}, {}
                @contextmanager
                def reader(*args):
                    attempt(); yield None
                if stage == 'admission': m.facade.admit_batch.side_effect = attempt
                elif stage == 'reader': m.runner.reader = reader
                elif stage == 'close': m.witness.close.side_effect = attempt
                elif stage == 'seal': m.runner.seal.side_effect = attempt
                argv = [v for name in subject.ARGUMENTS for v in ('--' + name, str(getattr(m.args, name.replace('-', '_'), 'synthetic')))]
                printer = patch('builtins.print', side_effect=attempt) if stage == 'summary' else nullcontext()
                with self.subTest(stage=stage, kind=kind), m.frozen(), printer, patch.object(subject, 'prepare', side_effect=prepare), \
                        patch('subprocess.Popen') as process, patch('os.system') as shell, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(subject.main(argv), 1); process.assert_not_called(); shell.assert_not_called()


def initialize():
    global subject, fixture, Model, peer_fixture, common_proof
    own, child, old = Path(__file__).resolve(), HERE / 'port_census_attempt.py', HERE / 'test_common_census_attempt.py'
    for path in (own, child, old): BUFFERS[path] = path.read_bytes()
    if sha(BUFFERS[old]) != FIXTURE_PIN: raise ValueError('frozen common fixture pin')
    fixture = module_from_bytes('_port_driver_frozen_fixture', old, BUFFERS[old]); fixture.initialize()
    BUFFERS.update(fixture.BUFFERS)
    subject = module_from_bytes('_port_driver_subject', child, BUFFERS[child])
    Model = type('Model', (PortModel, fixture.Model), {})
    for relative, digest in (*subject.PINS.values(), *subject.DOCUMENTS.items()):
        if digest == '0' * 64: raise ValueError('final peer/contract source pins required; no PASS with placeholders')
        path = ROOT / relative; raw = path.read_bytes(); BUFFERS[path] = raw
        if sha(raw) != digest: raise ValueError('final source pin/' + relative)
    sealed = module_from_bytes('_port_driver_sealed_metadata', ROOT / subject.SEALED[0], BUFFERS[ROOT / subject.SEALED[0]])
    for relative, digest in (*sealed.PINS.values(), *sealed.DOCUMENTS.items()):
        path = ROOT / relative; raw = path.read_bytes(); BUFFERS[path] = raw
        if sha(raw) != digest: raise ValueError('frozen sealed source pin/' + relative)
    relative, digest = PEER_FIXTURE
    path = ROOT / relative
    if digest == '0' * 64: raise ValueError('final synthetic peer fixture pin required')
    BUFFERS[path] = path.read_bytes()
    if sha(BUFFERS[path]) != digest: raise ValueError('synthetic peer fixture source pin')
    peer_fixture = module_from_bytes('_port_driver_peer_fixture', path, BUFFERS[path])
    for name, digest in COMMON_FIXTURES.items():
        path = Path(name); raw = path.read_bytes()
        if sha(raw) != digest: raise ValueError('fixed failed common receipt/manifest fixture pin')
        FIXTURE_BUFFERS[path] = raw
    old_failure = fixture.normal.structured(FIXTURE_BUFFERS[Path(next(iter(COMMON_FIXTURES)))])
    if old_failure['Status'] != 'FAIL' or old_failure['Error'] != "KeyError: 'transport'":
        raise ValueError('failed common fixture must not inherit completed credit')
    common_proof = old_failure['CommonAttributes']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='SYNTHETIC_PORT_CENSUS_DRIVER_ONLY', Tests=0, ExpectedTestMethods=METHODS,
        Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, FinalPinsVerified=False,
        FixtureHashes={}, FixtureDrift=[], FixtureClosureVerified=False,
        ActualCaptureAdmitted=False, ActualProducerPredicatesReplayed=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        initialize()
        report.update(FinalPinsVerified=True, SourceHashes={str(p): sha(raw) for p, raw in BUFFERS.items()},
            FixtureHashes={str(p): sha(raw) for p, raw in FIXTURE_BUFFERS.items()})
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (DriverTests, BootstrapTests, RealHelperTests, ApiTests, CliTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        if report['FinalPinsVerified']:
            report['SourceHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items()}
        for path, raw in BUFFERS.items():
            try:
                if path.read_bytes() != raw: report['SourceDrift'].append(str(path))
            except OSError: report['SourceDrift'].append(str(path))
        for path, raw in FIXTURE_BUFFERS.items():
            try:
                if path.read_bytes() != raw: report['FixtureDrift'].append(str(path))
            except OSError: report['FixtureDrift'].append(str(path))
        report['SourceClosureVerified'] = bool(report['SourceHashes']) and not report['SourceDrift']
        report['FixtureClosureVerified'] = bool(report['FixtureHashes']) and not report['FixtureDrift']
        if not report['SourceClosureVerified'] or not report['FixtureClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'; receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
