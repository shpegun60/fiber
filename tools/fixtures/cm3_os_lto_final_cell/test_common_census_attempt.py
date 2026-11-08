"""Synthetic five-leaf driver controls, never an actual capture qualification."""

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


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 23
ISOLATION_FIXTURE_SHA256 = 'CC01C46EDCF1714BC1D4E2A7C2739B44F8063CA22A541C72B500A8746EB0B394'
subject = isolation = controls = composition = normal = machine = builder = guard = None
isolation_fixture = controls_fixture = abi_fixture = Model = None
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def literals(raw):
    def value(node):
        if isinstance(node, ast.Dict): return {value(k): value(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Tuple): return tuple(value(x) for x in node.elts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult): return value(node.left) * value(node.right)
        return ast.literal_eval(node)
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try: result[node.targets[0].id] = value(node.value)
            except (ValueError, TypeError): pass
    return result


class CommonModel:
    def base(self):
        result = super().base()
        result['ProducerBindings'] = [dict(Side='Native', Build=str(self.native_root),
            ReceiptSha256=self.hashes.get(self.native_root / 'results.json', 'C' * 64))]
        return result

    def __init__(self, case):
        super().__init__(case)
        self.common_visited = []
        self.native.update(Cohort=abi_fixture.AUTHORITY['Cohort'],
                           SourceInventorySha256=abi_fixture.AUTHORITY['SourceInventorySha256'])
        added = {self.native_root / 'results.json': encoded(self.native),
                 self.batch_root / 'artifacts.json': encoded(dict(Artifacts={}))}
        for i in range(53, 98):
            added[self.batch_root / ('commands/%03d.json' % i)] = encoded(
                dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
        for path, raw in added.items():
            self.put(path, raw)
            self.hashes[path] = self.roles[path] = sha(raw)
            self.identities[path] = self.physical(path)
            self.seed_bytes[path] = raw
            self.handoff['InputHashes'][str(path)] = sha(raw)
            self.handoff['InputPhysicalIdentities'][str(path)] = list(self.physical(path))
        self.args.batch_artifacts_sha256 = self.hashes[self.batch_root / 'artifacts.json']
        self.handoff['Batch']['ArtifactsSha256'] = self.args.batch_artifacts_sha256
        self.handoff['ProducerBindings'] = self.base()['ProducerBindings']
        self.handoff['ClosingFilesVerified'] = len(self.handoff['InputHashes'])
        self.reseal()
        authorities = dict(Manifest=dict(Path=str(self.batch_root / 'artifacts.json'),
                Sha256=self.hashes[self.batch_root / 'artifacts.json']),
            CommandJournal=dict(Path=str(self.batch_root / 'commands.json'),
                Sha256=self.hashes[self.batch_root / 'commands.json']),
            NativeReceipt=dict(Path=str(self.native_root / 'results.json'),
                Sha256=self.hashes[self.native_root / 'results.json']))
        self.isolation.update(Root=str(self.batch_root), SourceRoot=str(self.source_root),
            CaptureRoot=str(self.native_root), Cohort=self.native['Cohort'],
            SourceInventorySha256=self.native['SourceInventorySha256'], AuthorityInputs=authorities,
            SourceOwnership=dict(Status='SYNTHETIC-SOURCE-OWNERSHIP'),
            SourceOwnershipInputs=[dict(Source='synthetic', Path=str(self.source), Sha256=self.hashes[self.source])])
        self.common = {key: copy.deepcopy(self.isolation[key]) for key in ('Root', 'SourceRoot',
            'CaptureRoot', 'Cohort', 'SourceInventorySha256', 'AuthorityInputs', 'SourceOwnership', 'SourceOwnershipInputs')}
        self.common['AuthorityInputs']['BatchReceipt'] = dict(Path=str(self.batch_root / 'results.json'),
            Sha256=self.hashes[self.batch_root / 'results.json'])
        self.common.update(Status='SYNTHETIC-45-COMMON', CommandsReplayed=45,
            LoweredProofs=dict(Status='SYNTHETIC-LOWERED', UnresolvedAttribution=[], CommonAttributionClosed=True),
            Qualification=False, AllProtectedBodiesClean=False, IRImportClosureValidated=False)
        self.common_leaf = NS(inspect=Mock(side_effect=self.inspect_common),
            require_result=Mock(side_effect=lambda p: guard._same(p, self.common, 'strict synthetic common')))
        self.lowered = NS(require_result=Mock(side_effect=self.require_lowered))
        self.helpers.update(common_replay=self.common_leaf, common_lowered=self.lowered,
            isolation_composition=NS(admit_normal=Mock(wraps=isolation.admit_normal)))
        for name in ('attributes_phase', 'attributes', 'attribute_runner', 'common_workers', 'common_effects', 'transport'):
            self.markers[name] = NS(Role=name)
            self.helpers[name] = self.markers[name]
        for name in (*subject.COMMON_HELPERS, 'common_replay'):
            self.environment['HelperPlans'][name] = ('tools/synthetic/' + name + '.py', 'E' * 64)

    def require_lowered(self, proof, helpers):
        self.case.assertEqual(set(helpers), set(subject.LOWERED_HELPERS))
        guard._same(proof, self.common['LoweredProofs'], 'strict synthetic lowered')

    def inspect_common(self, batch, native, root, core, helpers, read):
        self.case.assertTrue(self.inside)
        self.case.assertIs(core, self.core)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertEqual(set(helpers), set(subject.COMMON_HELPERS))
        self.case.assertNotIn('machine', helpers)
        self.case.assertIs(helpers['controls_replay'], self.loaded['controls_replay'])
        for i in range(53, 98):
            for key, _ in subject.COUNTERS:
                credit = self.suite.report.get(key, 0)
                self.case.assertIs(type(credit), int)
                self.case.assertEqual(credit, 0)
            row = json.loads(read(root / ('commands/%03d.json' % i)))
            self.case.assertEqual(row, dict(Index=i, State='TERMINAL', Exit=0, ExpectedExit=0, Status='PASS'))
            self.common_visited.append(i)
            if self.fault == ('common', i): raise ValueError('synthetic common failure/' + str(i))
        if self.fault == 'common-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        if self.fault == 'common-shell':
            import os
            os.system('SYNTHETIC-NEVER-EXECUTED')
        if self.fault == 'common-escape': read(self.root / 'unowned.h')
        self.events.append('common')
        return copy.deepcopy(self.common)

    @contextmanager
    def reader(self, environment, groups):
        self.case.assertEqual(set(groups), {'CensusABIIsolationAndCommon'})
        with super().reader(environment, {'CensusABIAndIsolation': groups['CensusABIIsolationAndCommon']}) as values:
            yield values

    @contextmanager
    def frozen(self):
        modules = dict(self.markers, machine=self.facade, normal_entry=normal, normal=self.normal_leaf,
            abi_replay=self.abi_leaf, controls_replay=self.controls_leaf, isolation_replay=self.isolation_leaf,
            isolation_slots=self.helpers['isolation_slots'], common_replay=self.common_leaf,
            common_lowered=self.lowered, guard=guard)
        self.loaded = {}
        class Loader:
            def create_module(self, spec): return None
            def exec_module(loader, module):
                name = module.__name__.removeprefix('_os_common_census_frozen_')
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
            return subject.run(self.args, self.runner, self.environment, builder, self.helpers, {}, {})

    def replay(self):
        self.admit_handoff()
        with self.frozen():
            return subject.replay(self.runner, self.environment, self.batch_root, self.batch, self.handoff_root,
                self.handoff, self.roles, self.targets, self.inspection_tool)

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
    def test_one_reader_five_fresh_leaves_and_three_separate_counters(self):
        m = Model(self)
        report = m.run()
        self.assertEqual((m.entries, m.exits), (1, 1))
        self.assertEqual(m.events, ['batch-admit', 'construct', 'census', 'abi', 'controls', 'isolation', 'common'])
        self.assertEqual(m.visited + m.isolation_visited + m.common_visited, list(range(98)))
        for leaf in (m.normal_leaf, m.abi_leaf, m.controls_leaf, m.isolation_leaf, m.common_leaf):
            leaf.inspect.assert_called_once()
        self.assertEqual(tuple(report[k] for k, _ in subject.COUNTERS), (41, 12, 45))
        self.assertEqual((report['ToolInvocations'], report['CompilerInvocations'], report['RequiredCellsSatisfied']), (0, 0, 0))
        self.assertEqual(report['Commands'], [])
        m.suite.command.assert_not_called()
        self.assertEqual(m.seed_bytes, {p: p.read_bytes() for p in m.seed_bytes})

    def test_pending_is_completed_replay_not_failure_or_policy_credit(self):
        m = Model(self)
        pending = [dict(Group='positive', Role='Machine', Evidence=[dict(Function='ctxrt_v1_set_dispatcher', AttributionValidated=False)])]
        m.common['LoweredProofs'].update(UnresolvedAttribution=pending, CommonAttributionClosed=False)
        report = m.run()
        self.assertEqual(report['Status'], subject.PENDING)
        self.assertEqual(report['UnresolvedAttribution'], pending)
        self.assertIs(report['CommonAttributionClosed'], False)
        for key in subject.FACTS: self.assertIs(report[key], True)
        for key in subject.NONCLAIMS: self.assertIs(report[key], False)
        self.assertNotIn('UnresolvedAttribution', report['CommonAttributes'])
        self.assertNotIn('CommonAttributionClosed', report['CommonAttributes'])

    def test_common_failure_start_middle_end_revokes_nine_facts_and_three_counters(self):
        for i in (53, 75, 97):
            m = Model(self)
            m.fault = ('common', i)
            with self.subTest(index=i), self.assertRaisesRegex(ValueError, 'synthetic common failure/'): m.run()
            self.assertEqual(m.common_visited, list(range(53, i + 1)))
            self.assertEqual(m.visited + m.isolation_visited, list(range(53)))
            m.runner.seal.assert_not_called()
            m.failed()

    def test_earlier_forged_components_cannot_reach_common(self):
        for name in ('normal_leaf', 'abi_leaf', 'controls_leaf', 'isolation_leaf'):
            m = Model(self)
            leaf = getattr(m, name)
            leaf.inspect.side_effect = None
            leaf.inspect.return_value = dict(Forged=True)
            with self.subTest(leaf=name), self.assertRaises(ValueError): m.run()
            m.common_leaf.inspect.assert_not_called()
            m.runner.seal.assert_not_called()
            m.failed()

    def test_preceding_eleven_composition_joins_remain_enforced(self):
        cases = [('abi', 'Inputs', 'OriginalELF'), ('abi', 'PositiveAuthority', 'LoadImageComparison'),
            ('controls', 'Inputs', 'OriginalELF'), ('controls', 'Inputs', 'ReproducedELF'),
            ('controls', 'PositiveAuthority', 'LoadImageComparison')]
        cases += [('isolation', 'Inputs', key) for key in ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine')]
        cases += [('isolation', 'LoadImageComparisons', 'OriginalTwins'),
                  ('isolation', 'OriginalDumps', 'Final'), ('isolation', 'OriginalDumps', 'Machine')]
        for owner, group, key in cases:
            m = Model(self)
            getattr(m, owner)[group][key] = dict(Foreign=True)
            with self.subTest(owner=owner, key=key), self.assertRaisesRegex(ValueError, 'shared'): m.run()
            m.failed()

    def test_common_source_receipt_seed_inventory_and_native_joins(self):
        cases = [(None, k) for k in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256',
                                      'SourceOwnership', 'SourceOwnershipInputs')]
        cases += [('AuthorityInputs', k) for k in ('BatchReceipt', 'NativeReceipt', 'Manifest', 'CommandJournal')]
        for group, key in cases:
            m = Model(self)
            (m.common if group is None else m.common[group])[key] = dict(Foreign=True)
            with self.subTest(group=group, key=key), self.assertRaisesRegex(ValueError, 'shared'): m.run()
            m.failed()

    def test_outer_validator_rechecks_common_joins_without_leaf_help(self):
        m = Model(self)
        valid = m.run()
        cases = [(None, k) for k in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256',
                                      'SourceOwnership', 'SourceOwnershipInputs')]
        cases += [('AuthorityInputs', k) for k in ('BatchReceipt', 'NativeReceipt', 'Manifest', 'CommandJournal')]
        for group, key in cases:
            forged = copy.deepcopy(valid)
            common = forged['CommonAttributes']
            (common if group is None else common[group])[key] = dict(Foreign=True)
            h = dict(m.helpers, common_replay=NS(require_result=lambda p: None))
            with self.subTest(group=group, key=key), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(forged, h)

    def test_full_delegated_validator_called_even_when_leaf_validator_is_bypassed(self):
        m = Model(self)
        forged = copy.deepcopy(m.run())
        forged['CommonAttributes']['LoweredProofs']['UnexpectedClaim'] = True
        h = dict(m.helpers, common_replay=NS(require_result=lambda p: None))
        with self.assertRaisesRegex(ValueError, 'strict synthetic lowered'): subject.require_result(forged, h)

    def test_pending_projection_and_disposition_cannot_be_changed(self):
        m = Model(self)
        valid = m.run()
        for key, value in (('Status', subject.PENDING), ('CommonAttributionClosed', False),
                           ('CommonAttributionClosed', 1), ('UnresolvedAttribution', [dict(Foreign=True)])):
            forged = copy.deepcopy(valid)
            forged[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)

    def test_outer_batch_native_and_inventory_authorities_cannot_be_substituted(self):
        m = Model(self)
        valid = m.run()
        for key in ('Cohort', 'SourceInventorySha256'):
            forged = copy.deepcopy(valid)
            forged[key] = 'foreign'
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(forged, m.helpers)
        for key in ('Build', 'ReceiptSha256', 'ArtifactsSha256'):
            forged = copy.deepcopy(valid)
            forged['Batch'][key] = str(m.root / 'foreign') if key == 'Build' else 'F' * 64
            with self.subTest(batch=key), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(forged, m.helpers)
        for key in ('Build', 'ReceiptSha256'):
            forged = copy.deepcopy(valid)
            forged['ProducerBindings'][0][key] = str(m.root / 'foreign') if key == 'Build' else 'F' * 64
            with self.subTest(native=key), self.assertRaisesRegex(ValueError, 'result shared'):
                subject.require_result(forged, m.helpers)
        forged = copy.deepcopy(valid)
        forged['ProducerBindings'].append(copy.deepcopy(forged['ProducerBindings'][0]))
        with self.assertRaisesRegex(ValueError, 'one native producer'): subject.require_result(forged, m.helpers)

    def test_pending_evidence_does_not_turn_a_closing_failure_into_completed_pending(self):
        m = Model(self)
        pending = [dict(Group='positive', Role='Machine', Evidence=[dict(Function='ctxrt_v1_set_dispatcher')])]
        m.common['LoweredProofs'].update(UnresolvedAttribution=pending, CommonAttributionClosed=False)
        m.fault = 'objects'
        with self.assertRaises(ValueError): m.run()
        report = m.failed()
        self.assertEqual(report['UnresolvedAttribution'], pending)
        self.assertNotEqual(report['Status'], subject.PENDING)

    def test_all_inherited_false_fields_are_explicitly_accounted_for(self):
        raw = BUFFERS[HERE / 'runner.py']
        tree = ast.parse(raw)
        base = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'base_report')
        false_fields = {kw.arg for node in ast.walk(base) if isinstance(node, ast.Call)
            for kw in node.keywords if kw.arg and isinstance(kw.value, ast.Constant) and kw.value.value is False}
        false_fields.update(literals(raw)['NONCLAIMS'])
        self.assertEqual(len(false_fields), 30)
        self.assertEqual(false_fields & set(subject.FACTS),
                         {'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified'})
        self.assertEqual(false_fields - set(subject.FACTS) - set(subject.NONCLAIMS), set())
        self.assertEqual(set(subject.FACTS) & set(subject.NONCLAIMS), set())
        self.assertEqual(len(subject.FACTS), 9)
        self.assertEqual(len(subject.COUNTERS), 3)

    def test_peer_callback_signatures_and_exact_helper_names_match_shared_sources(self):
        for filename, helpers, signatures in (
                ('common_replay.py', subject.COMMON_HELPERS,
                 {'inspect': ['batch', 'native', 'root', 'core', 'helpers', 'read'], 'require_result': ['proof']}),
                ('common_lowered.py', subject.LOWERED_HELPERS,
                 {'inspect': ['core', 'read', 'lowerings', 'native', 'helpers'], 'require_result': ['proof', 'helpers']})):
            tree = ast.parse(BUFFERS[HERE / filename])
            assignment = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == 'HELPERS' for t in n.targets))
            self.assertIsInstance(assignment.value, ast.Call)
            self.assertEqual(assignment.value.func.id, 'frozenset')
            self.assertEqual(set(ast.literal_eval(assignment.value.args[0])), set(helpers))
            functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
            for name, expected in signatures.items():
                self.assertEqual([arg.arg for arg in functions[name].args.args], expected)

    def test_reader_escape_changed_journal_and_immutable_receipt_reject(self):
        for fault in ('common-escape', 'journal', 'immutable'):
            m = Model(self)
            m.admit_handoff()
            if fault == 'journal': (m.batch_root / 'commands/097.json').write_bytes(b'forged')
            elif fault == 'immutable': m.fault = ('immutable', m.batch_root / 'results.json')
            else: m.fault = fault
            with self.subTest(fault=fault), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)

    def test_direct_replay_guards_entry_common_leaf_and_close(self):
        for fault in ('reader-enter-process', 'common-process', 'common-shell', 'closing-process'):
            m = Model(self)
            m.admit_handoff()
            m.fault = fault
            with self.subTest(fault=fault), m.frozen(), patch('subprocess.Popen') as process, \
                    patch('os.system') as shell, self.assertRaisesRegex(AssertionError, 'immutable common/census replay cannot'):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                    m.handoff, m.roles, m.targets, m.inspection_tool)
            process.assert_not_called()
            shell.assert_not_called()

    def test_closing_seal_summary_recovery_failures_revoke_every_credit(self):
        for fault in ('objects', 'close', 'output', 'seal', 'manifest', 'summary', 'recovery'):
            m = Model(self)
            if fault == 'close': m.after_reader = lambda: setattr(m, 'fault', 'close')
            else: m.fault = fault
            if fault == 'recovery': m.common_leaf.inspect.side_effect = ValueError('primary common failure')
            printer = patch('builtins.print', side_effect=BrokenPipeError('summary failed')) if fault == 'summary' else nullcontext()
            with self.subTest(fault=fault), printer, self.assertRaises((ValueError, BrokenPipeError)): m.run()
            m.failed()
            m.runner.recover.assert_called_once()

    def test_output_substitution_blocks_seal_and_recovery_writes(self):
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
        for key, _ in subject.COUNTERS: self.assertEqual(m.suite.report[key], 0)

    def test_admission_reuses_frozen_isolation_wrapper_and_fourteen_control_roles(self):
        m = Model(self)
        before = set(m.roles)
        m.admit_handoff()
        expected = set(m.project) | set(m.control_inputs) | {m.handoff_root / n for n in m.artifacts}
        expected.add(m.handoff_root / 'artifacts.json')
        self.assertEqual(set(m.roles) - before, expected - before)
        m.helpers['isolation_composition'].admit_normal.assert_called_once()
        m.helpers['controls_composition'].admit_normal.assert_called_once()

    def test_all_false_fields_counters_facts_and_clean_errors_are_strict(self):
        m = Model(self)
        valid = m.run()
        changes = [(key, value) for key in subject.NONCLAIMS for value in (True, 0, None)]
        changes += [(key, 1) for key in subject.FACTS]
        changes += [(key, value) for key, _ in subject.COUNTERS for value in (0, True, 45.0)]
        changes += [('LTO', 1), ('ToolInvocations', False), ('CompilerInvocations', 1),
                    ('RequiredCellsSatisfied', 1), ('Commands', [{}]), ('ProjectSourceReaderRoles', True)]
        for key, value in changes:
            forged = copy.deepcopy(valid)
            forged[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): subject.require_result(forged, m.helpers)
        for key in (*subject.NONCLAIMS, 'Error', 'PrimaryError', 'ClosingErrors', 'CommonAttributes'):
            forged = copy.deepcopy(valid)
            del forged[key]
            with self.subTest(missing=key), self.assertRaises((ValueError, KeyError)):
                subject.require_result(forged, m.helpers)


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def graph(self, bad=False, late=False, zero=False):
        names = {'builder': subject.BATCH[0], 'metadata': builder.METADATA[0],
            'reader_entry': 'tools/fixtures/cm3_os_lto_final_cell/runner.py',
            'normal_metadata': subject.NORMAL[0], 'composition_metadata': subject.COMPOSITION[0],
            'controls_metadata': subject.CONTROLS[0], 'isolation_metadata': subject.ISOLATION[0]}
        modules = {name: NS(**literals(BUFFERS[ROOT / relative])) for name, relative in names.items()}
        modules['builder']._pins = builder._pins
        own = Path(subject.__file__).resolve()
        old = {ROOT / names[n] for n in ('builder', 'metadata', 'reader_entry')}
        for n in ('metadata', 'builder', 'reader_entry'):
            old.update(ROOT / row[0] for row in modules[n].PINS.values())
        old.update(ROOT / row[0] for row in modules['metadata'].LEAF_PINS.values())
        for n in ('metadata', 'reader_entry'): old.update(ROOT / p for p in modules[n].DOCUMENTS)
        wanted = set(old) | {own} | {ROOT / relative for relative in names.values()}
        for n in ('normal_metadata', 'composition_metadata', 'controls_metadata', 'isolation_metadata'):
            wanted.update(ROOT / row[0] for row in modules[n].PINS.values())
            wanted.update(ROOT / p for p in modules[n].DOCUMENTS)
        wanted.update(ROOT / row[0] for row in subject.PINS.values())
        wanted.update(ROOT / p for p in subject.DOCUMENTS)
        data = {p: BUFFERS[p] for p in wanted}
        pins = {name: (row[0], sha(data[ROOT / row[0]])) for name, row in subject.PINS.items()}
        if zero: pins['common_replay'] = (pins['common_replay'][0], '0' * 64)
        docs = {p: sha(data[ROOT / p]) for p in subject.DOCUMENTS}
        state = NS(constructed=False, enrolled={}, reads=[], opening={str(p): sha(data[p]) for p in old})
        constructor = Mock(side_effect=lambda args: setattr(state, 'constructed', True) or object())
        def factory(legacy, capture, *, extra_sources):
            self.assertEqual(extra_sources, data)
            state.enrolled.update(extra_sources)
            return constructor
        state.factory = Mock(side_effect=factory)
        new_path = ROOT / subject.PINS['common_replay'][0]
        def read(p):
            if state.constructed: raise AssertionError('late physical bootstrap read')
            state.reads.append(p)
            return b'wrong new source' if bad and p == new_path else data[p]
        def load(name, path, raw):
            key = name.removeprefix('_os_common_census_')
            if key in modules: return modules[key]
            if key == 'admission_admission': return NS(witness_type=state.factory)
            if key.startswith('bootstrap_') and late: (ROOT / 'tools/unknown.py').read_bytes()
            return NS()
        with patch.object(subject, 'PINS', pins), patch.object(subject, 'DOCUMENTS', docs), \
                patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=load):
            yield state, constructor

    def test_exact_35_opening_and_all_expanded_sources_precede_witness(self):
        with self.graph() as (state, constructor): prepared = subject.prepare(NS())
        self.assertEqual(len(prepared[4]), 35)
        self.assertEqual(prepared[4], state.opening)
        self.assertEqual(prepared[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        self.assertTrue({'isolation_composition', 'common_workers', 'common_effects', 'common_replay',
                         'common_lowered'} <= set(prepared[3]))
        state.factory.assert_called_once()
        constructor.assert_called_once()

    def test_bad_or_zero_peer_pin_rejects_before_witness(self):
        for key in ('bad', 'zero'):
            with self.subTest(kind=key), self.graph(**{key: True}) as (state, constructor), \
                    self.assertRaisesRegex(ValueError, 'source pin'):
                subject.prepare(NS())
            state.factory.assert_not_called()
            constructor.assert_not_called()

    def test_unknown_late_source_is_not_read_from_disk(self):
        with self.graph(late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(NS())
        constructor.assert_called_once()


class CliTests(unittest.TestCase):
    def test_no_abbreviations_and_process_shell_guards_cover_failure_diagnostics(self):
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
                        patch.object(subject, 'prepare', side_effect=prepare), patch('subprocess.Popen') as process, \
                        patch('os.system') as shell, redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertEqual(subject.main(argv), 1)
                    process.assert_not_called()
                    shell.assert_not_called()


def initialize():
    global subject, isolation, controls, composition, normal, machine, builder, guard
    global isolation_fixture, controls_fixture, abi_fixture, Model
    names = ('common_census_attempt', 'isolation_census_attempt', 'controls_census_attempt',
        'abi_census_attempt', 'normal_attempt', 'machine_attempt', 'batch_attempt', 'batch_guard',
        'test_isolation_census_attempt', 'test_controls_census_attempt', 'test_abi_census_attempt')
    modules = []
    for name in names:
        p = HERE / (name + '.py')
        BUFFERS[p] = p.read_bytes()
        module = ModuleType('_common_driver_test_' + name)
        module.__file__ = str(p)
        exec(compile(BUFFERS[p], str(p), 'exec'), module.__dict__)
        modules.append(module)
    (subject, isolation, controls, composition, normal, machine, builder, guard,
        isolation_fixture, controls_fixture, abi_fixture) = modules
    if sha(BUFFERS[HERE / 'test_isolation_census_attempt.py']) != ISOLATION_FIXTURE_SHA256:
        raise ValueError('frozen isolation fixture pin')
    if sha(BUFFERS[HERE / 'test_controls_census_attempt.py']) != isolation_fixture.BASE_PIN:
        raise ValueError('frozen controls fixture pin')
    if sha(BUFFERS[HERE / 'test_abi_census_attempt.py']) != controls_fixture.BASE_SHA256:
        raise ValueError('frozen ABI fixture pin')
    for name, value in dict(subject=isolation, controls=controls, composition=composition, normal=normal,
            machine=machine, builder=builder, guard=guard, fixture=controls_fixture, abi_fixture=abi_fixture).items():
        setattr(isolation_fixture, name, value)
    for name, value in dict(subject=controls, composition=composition, normal=normal,
            machine=machine, builder=builder, guard=guard, base=abi_fixture).items(): setattr(controls_fixture, name, value)
    for name, value in dict(subject=composition, normal=normal, machine=machine,
                           builder=builder, guard=guard).items(): setattr(abi_fixture, name, value)
    class Model(CommonModel, isolation_fixture.IsolationModel, controls_fixture.ControlsModel, abi_fixture.Model):
        pass
    rows = [subject.BATCH, subject.NORMAL, subject.COMPOSITION, subject.CONTROLS, subject.ISOLATION, builder.METADATA]
    meta_path = ROOT / builder.METADATA[0]
    BUFFERS[meta_path] = meta_path.read_bytes()
    metadata = literals(BUFFERS[meta_path])
    runner_path = HERE / 'runner.py'
    BUFFERS[runner_path] = runner_path.read_bytes()
    runner = literals(BUFFERS[runner_path])
    rows.append(('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata['RUNNER_SHA256']))
    for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner['PINS'], normal.PINS,
                     composition.PINS, controls.PINS, isolation.PINS): rows.extend(registry.values())
    for registry in (runner['DOCUMENTS'], metadata['DOCUMENTS'], normal.DOCUMENTS,
                     composition.DOCUMENTS, controls.DOCUMENTS, isolation.DOCUMENTS): rows.extend(registry.items())
    for relative, digest in rows:
        p = ROOT / relative
        if p not in BUFFERS: BUFFERS[p] = p.read_bytes()
        if sha(BUFFERS[p]) != digest: raise ValueError('frozen source pin/' + relative)
    for relative, _ in (*subject.PINS.values(), *subject.DOCUMENTS.items()):
        p = ROOT / relative
        BUFFERS[p] = p.read_bytes() if p.exists() else b'"""Synthetic unavailable draft peer."""\n'
    BUFFERS[Path(__file__).resolve()] = Path(__file__).read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='SYNTHETIC_COMMON_CENSUS_DRIVER_ONLY', Tests=0, ExpectedTestMethods=METHODS,
        Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[], SourceClosureVerified=False,
        FinalPinsVerified=False, ActualCaptureAdmitted=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        initialize()
        for relative, digest in (*subject.PINS.values(), *subject.DOCUMENTS.items()):
            if digest == '0' * 64: raise ValueError('final peer/contract pins required; no test PASS with placeholders')
            if sha(BUFFERS[ROOT / relative]) != digest: raise ValueError('final source pin/' + relative)
        report['FinalPinsVerified'] = True
        report['SourceHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items()}
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot start processes')), \
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell')):
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (DriverTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
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
