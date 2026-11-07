"""Synthetic controls-driver composition tests; no real admission or controls replay."""

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
METHODS = 22
BASE_SHA256 = '85726443E182DA9D8C2E1F55C77E9CC71EC10C60C85C29912BD5FF70D76B5D7A'
DEPS_SHA256 = 'CB463BE1E7CD98D254E0F5DB7E67283014EAA67FA10C01E2AEEA8913E4E6B9A6'
subject = composition = normal = machine = builder = guard = base = Model = None
BUFFERS = {}
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
         'ABIControlsReplayed', 'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof', 'IsolationReplayed',
    'FinalReferenceParity', 'FinalRootTransferProtocolsValidated', 'CompleteCellProof', 'RequiredCellSatisfied',
    'CellContractSatisfied', 'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification', 'CpuExecution',
    'BoardExecution', 'ProducerCompilersReexecuted', 'OsProcessTraceVerified', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'PolicyEquivalence', 'PriorReaderVerdictInherited')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def literals(raw):
    def value(n):
        if isinstance(n, ast.Dict): return {value(k): value(v) for k, v in zip(n.keys, n.values)}
        if isinstance(n, ast.Tuple): return tuple(value(x) for x in n.elts)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult): return value(n.left) * value(n.right)
        return ast.literal_eval(n)
    result = {}
    for n in ast.parse(raw).body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            try: result[n.targets[0].id] = value(n.value)
            except (ValueError, TypeError): pass
    return result


class ControlsModel:
    """Extend the frozen small-file fixture, not its published tests or globals."""
    def __init__(self, case):
        super().__init__(case)
        self.visited = []
        self.positive = self.batch_root / 'positive.elf'
        self.put(self.positive, self.original.read_bytes())
        self.abi['Inputs']['ReproducedELF'] = dict(Path=str(self.positive), Sha256=sha(self.positive.read_bytes()))
        failures = {4, 8, 12, 16, 20, 36, 38, 40}
        self.journals = [dict(Index=i, Label='SYNTHETIC ABI %02d' % i, State='TERMINAL',
            Exit=int(i in failures), ExpectedExit=int(i in failures),
            Status='EXPECTED-NONZERO' if i in failures else 'PASS') for i in range(41)]
        added = {self.positive: self.positive.read_bytes(), self.batch_root / 'commands.json': encoded(self.journals)}
        for i, row in enumerate(self.journals):
            added[self.batch_root / ('commands/%03d.json' % i)] = encoded(row)
        compiler = self.native_root / 'arm-none-eabi-gcc.exe'
        tools = (compiler, compiler.with_name('arm-none-eabi-nm.exe'), compiler.with_name('arm-none-eabi-readelf.exe'),
                 self.native_root / 'ld.exe', self.native_root / 'plugin.dll')
        self.headers = tuple(self.root / ('external/header-%d.h' % i) for i in range(9))
        self.control_inputs = {p: ('SYNTHETIC control input ' + p.name).encode('ascii') for p in (*tools, *self.headers)}
        self.native.update(CapturedCompiler=str(compiler), ResolvedWorkers=dict(ld=dict(Path=str(tools[3]))),
            LTOPlugin=dict(Path=str(tools[4])), InputHashes={str(p): sha(raw)
                for p, raw in {**self.project, **self.control_inputs}.items()})
        self.native['Sources'] = []
        for i, header in enumerate(self.headers):
            obj = self.native_root / ('object-%d.o' % i)
            added[obj] = ('SYNTHETIC object ' + str(i)).encode('ascii')
            self.native['Sources'].append(dict(Object=str(obj), ActualCompileDependencies=[
                dict(Path=str(p), Sha256=sha(raw)) for p, raw in self.project.items()] +
                [dict(Path=str(header), Sha256=sha(self.control_inputs[header]))]))
        added.update(self.control_inputs)
        added[self.native_root / 'results.json'] = encoded(self.native)
        self.batch['InputHashes'].update(self.native['InputHashes'])
        self.batch['Commands'] = copy.deepcopy(self.journals)
        added[self.batch_root / 'results.json'] = encoded(self.batch)
        for p, raw in added.items():
            self.put(p, raw)
            self.hashes[p] = self.roles[p] = sha(raw)
            self.identities[p] = self.physical(p)
            self.seed_bytes[p] = raw
            self.handoff['InputHashes'][str(p)] = sha(raw)
            self.handoff['InputPhysicalIdentities'][str(p)] = list(self.physical(p))
        # Captured bytes and hash admission deliberately do not imply a reader role.
        for p in self.control_inputs:
            self.roles.pop(p)
        self.available_buffers = dict(self.control_inputs)
        self.witness.buffers = dict(self.available_buffers)
        self.args.batch_receipt_sha256 = self.hashes[self.batch_root / 'results.json']
        self.handoff['Batch']['ReceiptSha256'] = self.args.batch_receipt_sha256
        self.handoff['ClosingFilesVerified'] = len(self.handoff['InputHashes'])
        self.reseal()
        self.controls = dict(Status='SYNTHETIC-41-CONTROLS', CommandsReplayed=41,
            Inputs=copy.deepcopy(self.abi['Inputs']), PositiveAuthority=copy.deepcopy(self.abi['PositiveAuthority']),
            Qualification=False, RequiredCellsSatisfied=0)
        self.controls_leaf = NS(inspect=Mock(side_effect=self.inspect_controls),
            require_result=Mock(side_effect=lambda p: guard._same(p, self.controls, 'strict synthetic controls')))
        self.helpers.update(controls_replay=self.controls_leaf,
            composition=NS(admit_normal=Mock(wraps=composition.admit_normal)))
        self.markers = {name: NS(Role=name) for name in ('deps', 'recipes', 'diagnostics', 'probes', 'plan',
                                                        'workers', 'declarations', 'ordinary', 'census', 'policy')}
        for name in (*self.markers, 'controls_replay'):
            self.environment['HelperPlans'][name] = ('tools/synthetic/' + name + '.py', 'E' * 64)

    def inspect_controls(self, batch, native, root, core, helpers, read):
        self.case.assertTrue(self.inside)
        self.case.assertIs(core, self.core)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertEqual(set(helpers), {'deps', 'recipes', 'declarations', 'ordinary', 'plan',
            'diagnostics', 'probes', 'guard', 'transport', 'port_runner'})
        for name in ('deps', 'recipes', 'diagnostics', 'probes', 'plan', 'declarations', 'ordinary'):
            self.case.assertEqual(helpers[name].Role, name)
        self.case.assertEqual(helpers['port_runner'].Role, 'workers')
        for p, raw in self.control_inputs.items(): self.case.assertEqual(read(p), raw)
        self.case.assertEqual(json.loads(read(root / 'commands.json')), self.journals)
        for i, expected in enumerate(self.journals):
            credit = self.suite.report.get('RecordedABICommandsReplayed', 0)
            self.case.assertIs(type(credit), int)
            self.case.assertEqual(credit, 0)
            self.case.assertEqual(json.loads(read(root / ('commands/%03d.json' % i))), expected)
            self.visited.append(i)
            if self.fault == ('control', i): raise ValueError('synthetic control failure/' + str(i))
        for p, raw in self.project.items(): self.case.assertEqual(read(p), raw)
        if self.fault == 'controls-escape': read(self.root / 'unowned.h')
        if self.fault == 'controls-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        self.case.assertEqual(read(self.positive), self.seed_bytes[self.positive])
        self.events.append('controls')
        self.trip('controls')
        return copy.deepcopy(self.controls)

    def admit_handoff(self):
        return subject.admit_normal(self.args, self.runner, self.environment, self.batch_root,
                                    self.batch, self.roles, self.helpers)

    @contextmanager
    def reader(self, environment, groups):
        self.case.assertEqual(set(groups), {'CensusAndABIControls'})
        with super().reader(environment, {'CensusAndABI': groups['CensusAndABIControls']}) as values:
            role_read = Path.read_bytes
            def available(p):
                return self.available_buffers[p] if p in self.available_buffers else role_read(p)
            with patch.object(Path, 'read_bytes', available):
                yield values

    @contextmanager
    def frozen(self):
        modules = dict(self.markers, machine=self.facade, normal_entry=normal, normal=self.normal_leaf,
            abi_replay=self.abi_leaf, controls_replay=self.controls_leaf, guard=guard, transport=NS())
        self.loaded = {}
        class Loader:
            def create_module(self, spec): return None
            def exec_module(loader, module):
                name = module.__name__.removeprefix('_os_controls_census_frozen_')
                module.__dict__.update(vars(modules[name]))
                self.loaded[name] = module
        with patch.dict(sys.modules), patch.object(subject.importlib.util, 'spec_from_file_location',
                side_effect=lambda name, path: importlib.util.spec_from_loader(name, Loader())):
            yield

    def replay(self):
        self.admit_handoff()
        with self.frozen():
            return subject.replay(self.runner, self.environment, self.batch_root, self.batch, self.handoff_root,
                                  self.handoff, self.roles, self.targets, self.inspection_tool)

    def run(self):
        with self.frozen(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, builder, self.helpers, {}, {})

    def failed(self):
        result = super().failed()
        for key in FACTS: self.case.assertIs(result[key], False)
        self.case.assertIs(type(result['RecordedABICommandsReplayed']), int)
        self.case.assertEqual(result['RecordedABICommandsReplayed'], 0)
        return result


class DriverTests(unittest.TestCase):
    def test_handoff_delegates_to_frozen_composition_and_enrolls_all_project_roles(self):
        m = Model(self)
        result = m.admit_handoff()
        m.helpers['composition'].admit_normal.assert_called_once_with(m.args, m.runner, m.environment,
            m.batch_root, m.batch, m.roles, m.helpers)
        self.assertEqual(result[-1], len(m.project))
        self.assertTrue(set(m.project) <= set(m.roles))

    def test_control_roles_enroll_exact_14_authorized_inputs_not_merely_available_buffers(self):
        m = Model(self)
        before = set(m.roles)
        self.assertTrue(set(m.control_inputs) <= set(m.witness.buffers))
        self.assertTrue(set(m.control_inputs).isdisjoint(before))
        self.assertEqual(subject.admit_control_roles(m.witness, m.batch, m.roles, m.helpers), 14)
        self.assertEqual(set(m.roles) - before, set(m.control_inputs))
        for p, raw in m.control_inputs.items():
            self.assertEqual(m.roles[p], sha(raw))
            self.assertEqual(m.identities[p], m.physical(p))
        m.witness.close.assert_called_once()
        self.assertFalse(m.output.exists())

    def test_control_role_admission_rejects_authority_count_conflict_bytes_and_identity_drift(self):
        for fault in ('native-authority', 'batch-authority', 'role', 'bytes', 'identity', 'sources', 'headers', 'tools'):
            m = Model(self)
            p = m.headers[0]
            if fault == 'native-authority': del m.native['InputHashes'][str(p)]
            elif fault == 'batch-authority': m.batch['InputHashes'][str(p)] = '0' * 64
            elif fault == 'role': m.roles[p] = '0' * 64
            elif fault == 'bytes': p.write_bytes(b'changed header')
            elif fault == 'identity': m.identities[p] = (1, 999, 1)
            elif fault == 'sources': m.native['Sources'].pop()
            elif fault == 'headers': m.native['Sources'][-1]['ActualCompileDependencies'].pop()
            else: m.native['ResolvedWorkers']['ld']['Path'] = m.native['CapturedCompiler']
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                subject.admit_control_roles(m.witness, m.batch, m.roles, m.helpers)
            self.assertFalse(m.output.exists())

    def test_available_header_or_tool_buffer_is_rejected_without_its_explicit_reader_role(self):
        for kind in ('header', 'tool'):
            m = Model(self)
            m.admit_handoff()
            missing = m.headers[0] if kind == 'header' else Path(m.native['CapturedCompiler'])
            del m.roles[missing]
            inspect = m.controls_leaf.inspect.side_effect
            def available_but_not_admitted(*args):
                self.assertEqual(missing.read_bytes(), m.available_buffers[missing])
                return inspect(*args)
            m.controls_leaf.inspect.side_effect = available_but_not_admitted
            with (self.subTest(kind=kind), m.frozen(),
                  self.assertRaisesRegex(ValueError, 'caller-admitted reader roles')):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            m.controls_leaf.inspect.assert_called_once()
            self.assertEqual(m.visited, [])

    def test_all_41_rows_and_three_leafs_use_one_fresh_reader_without_new_tools(self):
        m = Model(self)
        report = m.run()
        self.assertEqual((m.entries, m.exits), (1, 1))
        self.assertEqual(m.visited, list(range(41)))
        self.assertEqual(m.events, ['batch-admit', 'construct', 'census', 'abi', 'controls'])
        for leaf in (m.normal_leaf, m.abi_leaf, m.controls_leaf): leaf.inspect.assert_called_once()
        self.assertIs(m.controls_leaf.inspect.call_args.args[4]['port_runner'], m.loaded['workers'])
        self.assertEqual((report['ToolInvocations'], report['CompilerInvocations'],
            report['RecordedInspectionInvocations'], report['RecordedABICommandsReplayed']), (0, 0, 2, 41))
        self.assertIs(report['ABIControlsReplayed'], True)
        self.assertEqual(report['Commands'], [])
        m.suite.command.assert_not_called()
        self.assertEqual(m.seed_bytes, {p: p.read_bytes() for p in m.seed_bytes})
        self.assertEqual(m.suite._verify_outputs.call_count, 1)

    def test_control_failures_at_start_middle_and_end_stop_without_retry_and_revoke(self):
        for i in (0, 20, 40):
            m = Model(self)
            m.fault = ('control', i)
            with self.subTest(index=i), self.assertRaisesRegex(ValueError, 'synthetic control failure/'):
                m.run()
            self.assertEqual(m.visited, list(range(i + 1)))
            m.controls_leaf.inspect.assert_called_once()
            m.failed()

    def test_invalid_leaf_result_fails_before_seal_without_retaining_41_credit(self):
        for leaf in ('normal_leaf', 'abi_leaf', 'controls_leaf'):
            m = Model(self)
            getattr(m, leaf).inspect.side_effect = None
            getattr(m, leaf).inspect.return_value = dict(Forged=True)
            with self.subTest(leaf=leaf), self.assertRaises(ValueError): m.run()
            m.runner.seal.assert_not_called()
            m.failed()

    def test_forged_prior_census_is_not_reused_in_place_of_a_new_inspection(self):
        m = Model(self)
        m.handoff['OriginalCensus']['Original'] = 1
        m.normal_leaf.require_result.side_effect = lambda value: None
        m.reseal()
        with self.assertRaisesRegex(ValueError, 'recomputed original census comparison'): m.run()
        m.normal_leaf.inspect.assert_called_once()
        m.controls_leaf.inspect.assert_not_called()
        m.failed()

    def test_each_of_the_five_shared_image_joins_rejects_inconsistent_leaf_facts(self):
        cases = (('abi', 'Inputs', 'OriginalELF'), ('abi', 'PositiveAuthority', 'LoadImageComparison'),
            ('controls', 'Inputs', 'OriginalELF'), ('controls', 'Inputs', 'ReproducedELF'),
            ('controls', 'PositiveAuthority', 'LoadImageComparison'))
        for owner, group, field in cases:
            m = Model(self)
            getattr(m, owner)[group][field] = dict(Foreign=True)
            with self.subTest(owner=owner, field=field), self.assertRaisesRegex(ValueError, 'shared'):
                m.run()
            m.failed()

    def test_result_rechecks_all_five_joins_even_with_individually_valid_leaf_results(self):
        m = Model(self)
        valid = m.run()
        for owner, group, field in (('DeferredABI', 'Inputs', 'OriginalELF'),
            ('DeferredABI', 'PositiveAuthority', 'LoadImageComparison'), ('ABIControls', 'Inputs', 'OriginalELF'),
            ('ABIControls', 'Inputs', 'ReproducedELF'), ('ABIControls', 'PositiveAuthority', 'LoadImageComparison')):
            forged = copy.deepcopy(valid)
            forged[owner][group][field] = dict(Foreign=True)
            helpers = dict(m.helpers)
            for name, key in (('normal', 'OriginalCensus'), ('abi_replay', 'DeferredABI'), ('controls_replay', 'ABIControls')):
                helpers[name] = NS(require_result=Mock(side_effect=lambda value, expected=forged[key]:
                    guard._same(value, expected, 'independent synthetic leaf result')))
            with self.subTest(owner=owner, field=field), self.assertRaisesRegex(ValueError, 'result'):
                subject.require_result(forged, helpers)
            for name in ('normal', 'abi_replay', 'controls_replay'): helpers[name].require_result.assert_called_once()

    def test_immutable_receipt_mismatch_rejects_before_controls_consumption(self):
        for root in ('batch_root', 'native_root', 'handoff_root'):
            m = Model(self)
            m.admit_handoff()
            m.fault = ('immutable', getattr(m, root) / 'results.json')
            with self.subTest(root=root), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            m.controls_leaf.inspect.assert_not_called()

    def test_unowned_reader_path_or_altered_saved_journal_cannot_escape_bindings(self):
        for fault in ('escape', 'journal'):
            m = Model(self)
            m.admit_handoff()
            if fault == 'escape': m.fault = 'controls-escape'
            else: (m.batch_root / 'commands/040.json').write_bytes(b'forged row')
            with self.subTest(fault=fault), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)

    def test_direct_replay_blocks_processes_at_reader_entry_leaf_and_closing(self):
        for fault in ('reader-enter-process', 'controls-process', 'closing-process'):
            m = Model(self)
            m.admit_handoff()
            m.fault = fault
            with (self.subTest(fault=fault), m.frozen(), patch('subprocess.Popen', return_value=object()) as process,
                  self.assertRaisesRegex(AssertionError, 'immutable controls/census replay cannot start processes')):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            process.assert_not_called()

    def test_disposition_literal_facts_and_distinct_0_2_41_counters_are_strict(self):
        m = Model(self)
        valid = m.run()
        changes = [('Status', 'PASS'), ('Scope', 'whole-cell'), ('LTO', 1), ('Profile', 'CM4'),
            ('Mode', 'O2'), ('Linkage', 'archive'), ('ToolInvocations', False), ('ToolInvocations', 2),
            ('CompilerInvocations', 1), ('RecordedInspectionInvocations', 0), ('RecordedInspectionInvocations', 2.0),
            ('RecordedABICommandsReplayed', 0), ('RecordedABICommandsReplayed', 134),
            ('RecordedABICommandsReplayed', 41.0), ('RecordedABICommandsReplayed', True),
            ('RequiredCellCount', 2774.0), ('RequiredCellsSatisfied', False), ('Commands', [{}]),
            ('ProjectSourceReaderRoles', True), ('ProjectSourceReaderRoles', 0)] + [(k, 1) for k in FACTS]
        for key, value in changes:
            forged = copy.deepcopy(valid)
            forged[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)

    def test_nonclaims_clean_errors_and_all_three_leaf_results_are_mandatory(self):
        m = Model(self)
        valid = m.run()
        for key in NONCLAIMS:
            for value in (True, 0, None):
                forged = copy.deepcopy(valid)
                forged[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)
        for key in ('Error', 'PrimaryError', 'ClosingErrors', 'OriginalCensus', 'DeferredABI', 'ABIControls'):
            forged = copy.deepcopy(valid)
            del forged[key]
            with self.subTest(missing=key), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)

    def test_admission_authority_and_preexisting_root_fail_without_unowned_recovery(self):
        for fault in ('admission', 'authority', 'preexisting'):
            m = Model(self)
            if fault == 'admission': m.fault = fault
            elif fault == 'authority': m.handoff['Batch'] = {}; m.reseal()
            else: m.put(m.output / 'marker', b'unowned')
            with self.subTest(fault=fault), self.assertRaises((ValueError, FileExistsError)): m.run()
            m.runner.recover.assert_not_called()
            m.controls_leaf.inspect.assert_not_called()
            if fault == 'preexisting': self.assertEqual({p.name for p in m.output.iterdir()}, {'marker'})
            else: self.assertFalse(m.output.exists())

    def test_output_root_replacement_blocks_seal_and_every_recovery_write(self):
        m = Model(self)
        def replace():
            m.output.rename(m.root / 'retired-output')
            m.put(m.output / 'marker', b'foreign root')
        m.after_reader = replace
        with self.assertRaises(ValueError): m.run()
        self.assertEqual({p.name for p in m.output.iterdir()}, {'marker'})
        self.assertEqual((m.output / 'marker').read_bytes(), b'foreign root')
        m.runner.seal.assert_not_called()
        m.runner.recover.assert_not_called()
        self.assertEqual(m.suite.report['RecordedABICommandsReplayed'], 0)
        self.assertTrue(any('identity changed' in x for x in m.suite.report['ClosingErrors']))

    def test_closing_output_and_partial_seal_failures_revoke_component_credit(self):
        for fault in ('controls', 'objects', 'close', 'output', 'seal', 'manifest'):
            m = Model(self)
            if fault == 'close': m.after_reader = lambda: setattr(m, 'fault', 'close')
            else: m.fault = fault
            with self.subTest(fault=fault), self.assertRaises(ValueError): m.run()
            m.failed()
            m.runner.recover.assert_called_once()

    def test_summary_and_secondary_recovery_failures_keep_primary_and_revoke_41(self):
        for fault in ('summary', 'recovery', 'recovery-outside'):
            m = Model(self)
            m.fault = fault
            if fault != 'summary': m.controls_leaf.inspect.side_effect = ValueError('primary controls failure')
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary failed')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)) as caught: m.run()
            self.assertEqual(m.failed()['PrimaryError'], str(caught.exception))
            self.assertFalse((m.root / 'unowned.json').exists())
            if fault != 'summary': self.assertTrue(m.suite.report['ClosingErrors'])


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def graph(self, bad=False, late=False):
        b = NS(**literals(BUFFERS[ROOT / subject.BATCH[0]]), _pins=builder._pins)
        a = NS(**literals(BUFFERS[ROOT / b.METADATA[0]]))
        r = NS(**literals(BUFFERS[HERE / 'runner.py']))
        n = NS(**literals(BUFFERS[ROOT / subject.NORMAL[0]]))
        c = NS(**literals(BUFFERS[ROOT / subject.COMPOSITION[0]]))
        control_path = ROOT / subject.PINS['controls_replay'][0]
        payload = b'SYNTHETIC controls leaf metadata; not executed'
        pins = {name: (p, sha(payload) if name == 'controls_replay' else sha(BUFFERS[ROOT / p]))
                for name, (p, _) in subject.PINS.items()}
        docs = {p: sha(BUFFERS[ROOT / p]) for p in subject.DOCUMENTS}
        data = {p: raw for p, raw in BUFFERS.items() if p not in
                (Path(__file__).resolve(), HERE / 'test_abi_census_attempt.py')}
        data[control_path] = payload
        state = NS(constructed=False, enrolled={}, reads=[])
        constructor = Mock(side_effect=lambda args: setattr(state, 'constructed', True) or object())
        def factory(legacy, capture, *, extra_sources):
            self.assertEqual(extra_sources, data)
            state.enrolled.update(extra_sources)
            return constructor
        state.factory = Mock(side_effect=factory)
        def read(p):
            if state.constructed: raise AssertionError('late physical bootstrap read')
            state.reads.append(p)
            return b'wrong pin' if bad and p == control_path else data[p]
        modules = dict(builder=b, metadata=a, reader_entry=r, normal_metadata=n, composition_metadata=c)
        def load(name, path, raw):
            key = name.removeprefix('_os_controls_census_')
            if key in modules: return modules[key]
            if key == 'admission_admission': return NS(witness_type=state.factory)
            if key.startswith('bootstrap_'):
                self.assertEqual((ROOT / subject.PINS['deps'][0]).read_bytes(), data[ROOT / subject.PINS['deps'][0]])
                if late: (ROOT / 'tools/synthetic/unknown.py').read_bytes()
            return NS()
        with (patch.object(subject, 'PINS', pins), patch.object(subject, 'DOCUMENTS', docs),
              patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=load)):
            yield state, constructor

    def test_all_helpers_contracts_and_composition_precede_constructor_with_exact_35_opening(self):
        with self.graph() as (state, constructor): prepared = subject.prepare(NS())
        self.assertEqual(prepared[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        self.assertEqual(len(prepared[4]), 35)
        b = literals(BUFFERS[ROOT / subject.BATCH[0]])
        a = literals(BUFFERS[ROOT / b['METADATA'][0]])
        r = literals(BUFFERS[HERE / 'runner.py'])
        rows = [subject.BATCH, b['METADATA'], ('tools/fixtures/cm3_os_lto_final_cell/runner.py', a['RUNNER_SHA256'])]
        for registry in (a['PINS'], a['LEAF_PINS'], b['PINS'], r['PINS']): rows.extend(registry.values())
        for registry in (r['DOCUMENTS'], a['DOCUMENTS']): rows.extend(registry.items())
        self.assertEqual(prepared[4], {str(ROOT / p): h for p, h in rows})
        self.assertTrue({'deps', 'controls_replay', 'composition', 'abi_replay', 'normal_entry'} <= set(prepared[3]))
        state.factory.assert_called_once()
        constructor.assert_called_once()

    def test_bad_new_leaf_pin_is_preadmission_and_unknown_late_helper_never_reads_disk(self):
        with self.graph(bad=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin/'):
            subject.prepare(NS())
        state.factory.assert_not_called()
        constructor.assert_not_called()
        with self.graph(late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(NS())
        constructor.assert_called_once()


class CliTests(unittest.TestCase):
    def test_argument_boundary_and_no_process_or_shell_through_summary_error_path(self):
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
                with (self.subTest(stage=stage, kind=kind), m.frozen(), printer,
                      patch.object(subject, 'prepare', side_effect=prepare), patch('subprocess.Popen', return_value=object()) as process,
                      patch('os.system', return_value=0) as shell, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO())):
                    self.assertEqual(subject.main(argv), 1)
                    process.assert_not_called()
                    shell.assert_not_called()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CONTROLS_CENSUS_DRIVER_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticBootstrapGraph=True, BootstrapPinsOverridden=True,
        SyntheticABICommandRows=41, ActualCaptureAdmitted=False, ActualControlsLeafExecuted=False,
        ExternalToolsExecuted=0, Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        global subject, composition, normal, machine, builder, guard, base, Model
        paths = [Path(__file__).resolve(), HERE / 'controls_census_attempt.py', HERE / 'abi_census_attempt.py',
            HERE / 'normal_attempt.py', HERE / 'machine_attempt.py', HERE / 'batch_attempt.py', HERE / 'batch_guard.py',
            HERE / 'test_abi_census_attempt.py']
        for p in paths: BUFFERS[p] = p.read_bytes()
        if sha(BUFFERS[paths[-1]]) != BASE_SHA256: raise ValueError('frozen inherited fixture pin')
        with (patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot execute tools')),
              patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell commands'))):
            modules = []
            for p in paths[1:]:
                module = ModuleType('_controls_driver_test_' + p.stem)
                module.__file__ = str(p)
                exec(compile(BUFFERS[p], str(p), 'exec'), module.__dict__)
                modules.append(module)
            subject, composition, normal, machine, builder, guard, base = modules
            base.subject, base.normal, base.machine, base.builder, base.guard = composition, normal, machine, builder, guard
            class Model(ControlsModel, base.Model):
                pass
            metadata_path = ROOT / builder.METADATA[0]
            BUFFERS[metadata_path] = metadata_path.read_bytes()
            metadata = literals(BUFFERS[metadata_path])
            BUFFERS[HERE / 'runner.py'] = (HERE / 'runner.py').read_bytes()
            runner = literals(BUFFERS[HERE / 'runner.py'])
            rows = [subject.BATCH, subject.NORMAL, subject.COMPOSITION, builder.METADATA,
                    ('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata['RUNNER_SHA256']),
                    ('tools/fixtures/cm3_os_lto_final_cell/dependency_bytes.py', DEPS_SHA256)]
            for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner['PINS'], normal.PINS, composition.PINS):
                rows.extend(registry.values())
            for registry in (runner['DOCUMENTS'], metadata['DOCUMENTS'], normal.DOCUMENTS, composition.DOCUMENTS):
                rows.extend(registry.items())
            for relative, h in rows:
                p = ROOT / relative
                if p not in BUFFERS: BUFFERS[p] = p.read_bytes()
                if sha(BUFFERS[p]) != h: raise ValueError('frozen source pin/' + relative)
            for relative in subject.DOCUMENTS:
                p = ROOT / relative
                BUFFERS[p] = p.read_bytes()
            report['SourceHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items()}
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (DriverTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact implemented method count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for p, raw in BUFFERS.items():
            try:
                if sha(p.read_bytes()) != sha(raw): report['SourceDrift'].append(str(p))
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
