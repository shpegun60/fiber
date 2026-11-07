"""Bounded synthetic ABI/census driver tests; no real admission, tools or ELF replay."""

import argparse
import ast
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 21
subject = normal = machine = builder = guard = None
BUFFERS = {}
CENSUS = dict(Status='SYNTHETIC-CENSUS', Original=True, RequiredCellsSatisfied=0, Qualification=False)
ABI = dict(Status='SYNTHETIC-DEFERRED-ABI', Providers=9, RequiredCellsSatisfied=0, Qualification=False)
AUTHORITY = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', Cohort='synthetic-cm3',
    ReferenceCommit='a' * 40, SourceInventorySha256='A' * 64,
    CurrentInventory=dict(Build='synthetic-inventory'), CurrentCaptureProducer=dict(Sha256='B' * 64),
    ProducerBindings=[dict(Side='Native', ReceiptSha256='C' * 64)])
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
         'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity', 'FinalRootTransferProtocolsValidated',
    'CompleteCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied', 'GlobalFreezeQualified',
    'HostedCIQualified', 'ArchiveQualification', 'CpuExecution', 'BoardExecution',
    'ProducerCompilersReexecuted', 'OsProcessTraceVerified', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'PolicyEquivalence', 'PriorReaderVerdictInherited')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def literals(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                result[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    return result


class Model:
    def __init__(self, case):
        temp = tempfile.TemporaryDirectory(prefix='os-abi-census-synthetic-')
        case.addCleanup(temp.cleanup)
        self.case, self.root = case, Path(temp.name)
        self.batch_root, self.native_root, self.handoff_root, self.output, self.inventory = (
            self.root / name for name in ('batch', 'native', 'handoff', 'output', 'inventory'))
        self.hashes, self.identities, self.events = {}, {}, []
        self.inside, self.entries, self.exits, self.fault = False, 0, 0, None
        self.source_root = self.root / 'seed/source'
        self.project = {self.source_root / name: ('synthetic ' + name).encode('ascii')
                        for name in ('unit.c', 'api.h', 'nested/extra.h')}
        self.original, self.final, self.worker, self.tool, self.source = (self.native_root / name for name in
            ('ordinary.elf', 'emit.elf', 'emit.elf.ltrans0.ltrans.o', 'arm-none-eabi-objdump.exe', 'helper.py'))
        for path in (self.original, self.final, self.worker, self.tool, self.source):
            self.put(path, ('SYNTHETIC NOT EXECUTABLE: ' + path.name).encode('ascii'))
        for path, raw in self.project.items():
            self.put(path, raw)
        self.native = dict(SeedBuild=str(self.source_root.parent), CapturedCompiler=str(self.tool.with_name('gcc.exe')),
            Sources=[], Links=[dict(Kind='ordinary', Path=str(self.original)),
            dict(Kind='emit-relocs', Path=str(self.final), Machine=str(self.worker))])
        self.batch = dict(SourceSeed=str(self.source_root.parent),
            InputHashes={str(p): sha(raw) for p, raw in self.project.items()},
            IsolationDeferredReader=dict(Inputs=[dict(Role=role, Path=str(p), Sha256=sha(p.read_bytes()))
                for role, p in (('OriginalEmitELF', self.final), ('OriginalMachine', self.worker))]))
        self.put(self.native_root / 'results.json', encoded(self.native))
        self.put(self.batch_root / 'results.json', encoded(self.batch))
        self.seed_bytes = {p: p.read_bytes() for p in (*self.project, self.original, self.final, self.worker,
            self.tool, self.source, self.native_root / 'results.json', self.batch_root / 'results.json')}
        self.hashes.update({p: sha(raw) for p, raw in self.seed_bytes.items()})
        self.identities.update({p: self.physical(p) for p in self.hashes})
        self.roles = {p: h for p, h in self.hashes.items() if p not in self.project}
        self.witness = NS(output=self.output, identities=self.identities, _physical=self.physical,
            api=NS(regular=self.regular), watch=NS(read=self.read, tree=self.tree, hashes=self.hashes),
            replay_api=NS(checked_path=self.checked, digest=self.digest, relative_name=self.relative),
            groups=dict(Native=dict(Root=self.native_root, Result=self.native,
                Artifacts={p.relative_to(self.native_root).as_posix(): h for p, h in self.hashes.items()
                           if p.is_relative_to(self.native_root)})))
        self.witness.close = Mock(side_effect=self.close)
        self.targets = normal.original_targets(self.witness, self.batch, self.roles, machine)
        self.inspection_tool = dict(Path=str(self.tool), Sha256=self.hashes[self.tool])
        original = dict(Path=str(self.original), Sha256=self.hashes[self.original])
        self.census = dict(copy.deepcopy(CENSUS), OriginalInputs=dict(OrdinaryFinal=original),
                           Twins=dict(Identical=True, Segments=1))
        self.abi = dict(copy.deepcopy(ABI), Inputs=dict(OriginalELF=copy.deepcopy(original)),
                       PositiveAuthority=dict(LoadImageComparison=copy.deepcopy(self.census['Twins'])))
        commands, records = [], []
        for i, target in enumerate(self.targets):
            prefix = 'commands/%03d' % i
            stdout = ('synthetic zero-inclusive ' + target['Role']).encode('ascii')
            row = dict(Label='disassemble original ' + target['Role'],
                Argv=[str(self.tool), '-drwC', '-z', target['Path']], Cwd=str(self.handoff_root),
                Exit=0, ExpectedExit=0, State='TERMINAL', Status='PASS', TimedOut=False, Seconds=0.01,
                Stdout=prefix + '.stdout', Stderr=prefix + '.stderr', StdoutSha256=sha(stdout), StderrSha256=sha(b''))
            commands.append(row)
            for name, raw in ((row['Stdout'], stdout), (row['Stderr'], b''), (prefix + '.json', encoded(row))):
                self.put(self.handoff_root / name, raw)
            dump = self.handoff_root / ('normal/original-' + target['Role'].lower() + '.dis')
            self.put(dump, stdout)
            records.append(dict(Role=target['Role'], CommandIndex=i, Target=copy.deepcopy(target),
                                Path=str(dump), Sha256=sha(stdout), Tool=self.inspection_tool.copy()))
        self.put(self.handoff_root / 'commands.json', encoded(commands))
        captured = self.handoff_root / 'source-buffers/helper.py'
        self.put(captured, self.source.read_bytes())
        self.artifacts = {p.relative_to(self.handoff_root).as_posix(): sha(p.read_bytes())
                          for p in self.handoff_root.rglob('*') if p.is_file()}
        all_inputs = dict(self.hashes, **{str(self.handoff_root / p): h for p, h in self.artifacts.items()})
        self.handoff = dict(self.base(), Status=normal.PASS, Scope=normal.SCOPE,
            **dict.fromkeys(normal.NONCLAIMS, False))
        self.handoff.update(**dict.fromkeys(('OriginalDisassembliesCollected', 'OriginalCensusReplayed',
            'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified'), True))
        self.handoff.update(Batch=dict(Build=str(self.batch_root),
            ReceiptSha256=self.hashes[self.batch_root / 'results.json'], ArtifactsSha256='D' * 64),
            OriginalTargets=copy.deepcopy(self.targets), InspectionTool=self.inspection_tool.copy(),
            Commands=commands, CommandsSha256=self.artifacts['commands.json'], OriginalDisassemblies=records,
            OriginalCensus=copy.deepcopy(self.census), ToolInvocations=2,
            InputHashes={str(p): h for p, h in all_inputs.items()},
            InputPhysicalIdentities={str(p): list(self.physical(Path(p))) for p in all_inputs},
            ClosingFilesVerified=len(all_inputs), CapturedSources=[dict(Original=str(self.source),
            Captured=str(captured), Sha256=self.hashes[self.source])])
        self.args = NS(normal_build=str(self.handoff_root), inventory=str(self.inventory),
            batch_receipt_sha256=self.handoff['Batch']['ReceiptSha256'], batch_artifacts_sha256='D' * 64)
        self.reseal()
        self.normal_leaf = NS(inspect=Mock(side_effect=lambda *a: self.inspect('census', *a)),
                              require_result=Mock(side_effect=lambda p: guard._same(p, self.census, 'strict synthetic census')))
        self.abi_leaf = NS(inspect=Mock(side_effect=lambda *a: self.inspect('abi', *a)),
                           require_result=Mock(side_effect=lambda p: guard._same(p, self.abi, 'strict synthetic ABI')))
        self.facade = NS(admit_batch=Mock(side_effect=self.admit), retain_identity=machine.retain_identity,
                         immutable_view=machine.immutable_view)
        self.helpers = dict(machine=self.facade, normal_entry=normal, normal=self.normal_leaf, abi_replay=self.abi_leaf,
            guard=guard, utility=object(), lto=object(), session=NS(suite_type=lambda *a: self.construct))
        wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
                  'declarations', 'ordinary', 'abi_replay')
        self.environment = dict(Witness=self.witness, HelperPlans={name: ('tools/synthetic/' + name + '.py', 'E' * 64)
            for name in wanted}, Modules=dict(capture=NS(PINS=dict(api=('tools/synthetic/transport.py', 'F' * 64)))))
        self.suite = NS(output=self.output, expected={}, commands=[], report={}, _started=False)
        self.suite.start = Mock(side_effect=self.start)
        self.suite._save = lambda name, value: self.write_output(name, encoded(value))
        self.suite.command = Mock(side_effect=AssertionError('no new commands permitted'))
        self.suite.verify_objects = Mock(side_effect=lambda: self.trip('objects'))
        self.suite._verify_outputs = Mock(side_effect=self.verify_outputs)
        self.runner = NS(base_report=lambda w: self.base(), reader=self.reader,
            seal=Mock(side_effect=self.seal), revoke=Mock(side_effect=self.revoke), recover=Mock(side_effect=self.recover))

    @staticmethod
    def physical(path):
        s = path.lstat()
        return s.st_dev, s.st_ino, s.st_nlink

    @staticmethod
    def put(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    @staticmethod
    def relative(name):
        if type(name) is not str or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('unsafe synthetic relative path')

    @staticmethod
    def checked(name, directory=False):
        p = Path(name)
        if not p.is_absolute() or '..' in p.parts or not (p.is_dir() if directory else p.is_file()):
            raise ValueError('unsafe synthetic absolute path')
        return p

    def regular(self, path):
        return self.checked(path)

    @staticmethod
    def digest(value):
        if type(value) is not str or not re.fullmatch('[0-9A-F]{64}', value):
            raise ValueError('unsafe synthetic digest')
        return value

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes()
        h = sha(raw)
        if (expected is not None and h != expected) or (path in self.hashes and self.hashes[path] != h):
            raise ValueError('synthetic hash drift')
        self.hashes[path] = h
        return raw

    def tree(self, root, members):
        actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        guard._same(sorted(actual), sorted(members), 'synthetic exact tree membership')
        for name, h in members.items():
            self.read(root / name, h)

    def reseal(self):
        raw = encoded(self.handoff)
        self.put(self.handoff_root / 'results.json', raw)
        self.artifacts['results.json'] = sha(raw)
        manifest = encoded(dict(Artifacts=self.artifacts))
        self.put(self.handoff_root / 'artifacts.json', manifest)
        self.args.normal_receipt_sha256, self.args.normal_artifacts_sha256 = sha(raw), sha(manifest)

    def base(self):
        return dict(copy.deepcopy(AUTHORITY), Status='FAIL', LTO=True, RequiredCellCount=2774,
            RequiredCellsSatisfied=0, CompilerInvocations=0, ToolInvocations=0,
            Error=None, PrimaryError=None, ClosingErrors=[])

    def trip(self, stage):
        if self.fault == stage:
            raise ValueError('synthetic ' + stage + ' failure')

    def close(self):
        if self.fault == 'closing-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        self.trip('close')
        for p, h in list(self.hashes.items()):
            self.read(p, h)
            if p in self.identities and self.physical(p) != self.identities[p]:
                raise ValueError('synthetic physical drift')

    def admit(self, *args):
        self.events.append('batch-admit')
        self.trip('admission')
        return self.batch_root, copy.deepcopy(self.batch), self.roles

    def admit_handoff(self):
        return subject.admit_normal(self.args, self.runner, self.environment, self.batch_root,
                                    self.batch, self.roles, self.helpers)

    def construct(self, *args):
        self.events.append('construct')
        return self.suite

    def start(self):
        self.output.mkdir(exist_ok=False)
        self.suite.output_identity = self.physical(self.output)[:2]
        self.suite._started = True
        self.write_output('results.json', encoded(self.suite.report))

    def write_output(self, name, raw):
        guard.require_owned_output(self.suite)
        self.put(self.output / name, raw)
        self.suite.expected[name] = sha(raw)

    def inspect(self, kind, batch, native, root, core, helpers, read, *dumps):
        self.case.assertTrue(self.inside)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertIs(core, self.core)
        self.case.assertEqual(set(helpers), {'census', 'policy', 'port_runner', 'guard'} if kind == 'census'
                              else {'declarations', 'ordinary', 'guard'})
        for p, raw in self.project.items():
            self.case.assertEqual(read(p), raw)
        if kind == 'census':
            self.case.assertEqual(set(dumps[0]), {'Final', 'Machine'})
        self.events.append(kind)
        self.trip(kind)
        if self.fault == 'reader-escape':
            read(self.root / 'unenrolled.h')
        if self.fault == 'reader-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        return copy.deepcopy(self.census if kind == 'census' else self.abi)

    @contextmanager
    def reader(self, environment, groups):
        if self.fault == 'reader-enter-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        self.case.assertEqual(set(groups), {'CensusAndABI'})
        paths = list(groups['CensusAndABI'].values())
        self.case.assertTrue(set(self.project) <= set(paths))
        snapshot = {p: self.read(p) for p in paths}
        if isinstance(self.fault, tuple) and self.fault[0] == 'immutable':
            snapshot[self.fault[1]] = encoded(dict(Foreign=True))
        self.entries += 1
        self.inside, self.core = True, object()
        def read(p):
            if p not in snapshot:
                raise ValueError('synthetic immutable role escape')
            return snapshot[p]
        try:
            with (patch.object(Path, 'read_bytes', read), patch.object(Path, 'write_bytes', side_effect=AssertionError('reader write')),
                    patch.object(Path, 'stat', side_effect=AssertionError('reader stat')),
                    patch.object(Path, 'lstat', side_effect=AssertionError('reader lstat')),
                    patch.object(Path, 'resolve', side_effect=AssertionError('reader resolve'))):
                yield self.core, None, dict(SyntheticOnly=True, OneImmutableReaderScope=True)
        finally:
            self.inside = False
            self.exits += 1
            if getattr(self, 'after_reader', None):
                self.after_reader()

    @contextmanager
    def frozen(self):
        modules = dict(machine=self.facade, normal_entry=normal, normal=self.normal_leaf, abi_replay=self.abi_leaf,
            guard=guard, census=NS(), policy=NS(), workers=NS(), declarations=NS(), ordinary=NS(), transport=NS())
        class Loader:
            def create_module(self, spec):
                return None

            def exec_module(self, module):
                module.__dict__.update(vars(modules[module.__name__.removeprefix('_os_abi_census_frozen_')]))
        with patch.dict(sys.modules), patch.object(subject.importlib.util, 'spec_from_file_location',
                side_effect=lambda name, path: importlib.util.spec_from_loader(name, Loader())):
            yield

    def replay(self):
        self.admit_handoff()
        with self.frozen():
            return subject.replay(self.runner, self.environment, self.batch_root, self.batch, self.handoff_root,
                                  self.handoff, self.roles, self.targets, self.inspection_tool)

    def verify_outputs(self):
        self.trip('output')
        actual = {p.relative_to(self.output).as_posix(): sha(p.read_bytes()) for p in self.output.rglob('*') if p.is_file()}
        guard._same(actual, self.suite.expected, 'synthetic owned output ledger')

    def seal(self, environment, report, expected):
        report.update(InputClosureVerified=True, OutputSealVerified=True)
        self.trip('seal')
        self.write_output('results.json', encoded(report))
        self.trip('manifest')
        self.put(self.output / 'artifacts.json', encoded(dict(Artifacts=dict(expected))))

    @staticmethod
    def revoke(report, error):
        report.update(Status='FAIL', Error=str(error), PrimaryError=report.get('PrimaryError') or str(error),
                      InputClosureVerified=False, OutputSealVerified=False, RequiredCellsSatisfied=0)

    def recover(self, environment, report):
        (self.output / 'results.json').write_bytes(encoded(report))
        if self.fault == 'recovery-outside':
            (self.root / 'unowned.json').write_bytes(b'forbidden')
        self.trip('recovery')
        (self.output / 'artifacts.json').write_bytes(encoded(dict(Artifacts={})))

    def run(self):
        with self.frozen(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, builder, self.helpers, {}, {})

    def failed(self):
        r = json.loads((self.output / 'results.json').read_bytes())
        self.case.assertEqual(r['Status'], 'FAIL')
        for k in FACTS + NONCLAIMS:
            self.case.assertIs(r[k], False)
        self.case.assertEqual((r['ToolInvocations'], r['CompilerInvocations'], r['RequiredCellsSatisfied']), (0, 0, 0))
        return r


class HandoffTests(unittest.TestCase):
    def test_complete_handoff_checks_every_hash_identity_snapshot_and_project_role(self):
        m = Model(self)
        root, report, targets, tool, count = m.admit_handoff()
        self.assertEqual((root, report, targets, tool, count), (m.handoff_root, m.handoff, m.targets, m.inspection_tool, 3))
        for p, raw in m.project.items():
            self.assertEqual(m.roles[p], sha(raw))
            self.assertEqual(m.identities[p], m.physical(p))
        self.assertTrue({m.handoff_root / name for name in m.artifacts} <= set(m.roles))
        m.witness.close.assert_called_once()

    def test_foreign_authority_batch_targets_tool_and_overlapping_roots_reject(self):
        for key in (*AUTHORITY, 'Batch', 'OriginalTargets', 'InspectionTool'):
            m = Model(self)
            m.handoff[key] = 'foreign'
            m.reseal()
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.admit_handoff()
        for root in ('batch_root', 'native_root', 'output', 'inventory'):
            m = Model(self)
            m.args.normal_build = str(getattr(m, root))
            with self.subTest(root=root), self.assertRaises(ValueError):
                m.admit_handoff()

    def test_manifest_exact_membership_hash_and_relative_path_guards(self):
        for fault in ('extra', 'missing', 'hash', 'self', 'receipt', 'traversal'):
            m = Model(self)
            if fault == 'extra':
                m.put(m.handoff_root / 'unmapped', b'extra')
            elif fault == 'missing':
                (m.handoff_root / 'normal/original-final.dis').unlink()
            elif fault == 'hash':
                m.args.normal_receipt_sha256 = '0' * 64
            else:
                m.artifacts[{'self': 'artifacts.json', 'receipt': 'results.json', 'traversal': '../foreign'}[fault]] = '0' * 64
                raw = encoded(dict(Artifacts=m.artifacts))
                m.put(m.handoff_root / 'artifacts.json', raw)
                m.args.normal_artifacts_sha256 = sha(raw)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.admit_handoff()

    def test_all_input_hashes_physical_tuples_and_literal_closing_count(self):
        for fault in ('bytes', 'hash', 'physical', 'boolean-identity', 'tuple-length', 'missing-identity', 'count'):
            m = Model(self)
            name = str(m.source)
            if fault == 'bytes':
                m.source.write_bytes(b'changed original')
            elif fault == 'hash':
                m.handoff['InputHashes'][name] = '0' * 64
            elif fault in ('physical', 'boolean-identity', 'tuple-length'):
                m.handoff['InputPhysicalIdentities'][name] = {'physical': [1, 999, 1],
                    'boolean-identity': [True, 2, 1], 'tuple-length': [1, 2, 1, 0]}[fault]
            elif fault == 'missing-identity':
                del m.handoff['InputPhysicalIdentities'][name]
            else:
                m.handoff['ClosingFilesVerified'] = float(m.handoff['ClosingFilesVerified'])
            m.reseal()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.admit_handoff()

    def test_captured_source_pair_shape_duplicate_location_and_binding_reject(self):
        for fault in ('empty', 'duplicate', 'shape', 'outside', 'digest', 'snapshot-bytes'):
            m = Model(self)
            row = m.handoff['CapturedSources'][0]
            if fault == 'empty': m.handoff['CapturedSources'] = []
            elif fault == 'duplicate': m.handoff['CapturedSources'].append(copy.deepcopy(row))
            elif fault == 'shape': row['Extra'] = True
            elif fault == 'outside': row['Captured'] = str(m.source)
            elif fault == 'digest': row['Sha256'] = '0' * 64
            else: Path(row['Captured']).write_bytes(b'changed snapshot')
            m.reseal()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.admit_handoff()

    def test_saved_inspections_reject_wrong_flags_target_terminal_and_recorded_credit(self):
        for fault in ('zero-inclusive', 'target', 'terminal', 'typed-exit', 'count', 'dump'):
            m = Model(self)
            if fault == 'count': m.handoff['ToolInvocations'] = 0
            elif fault == 'dump': m.handoff['OriginalDisassemblies'][0]['Sha256'] = '0' * 64
            else:
                c = m.handoff['Commands'][0]
                if fault == 'zero-inclusive': c['Argv'].remove('-z')
                elif fault == 'target': c['Argv'][-1] = str(m.original)
                elif fault == 'terminal': c['State'] = 'STARTED'
                else: c['Exit'] = False
                # Keep raw journals consistent so rejection must reach the typed command predicate.
                for name, value in (('commands.json', m.handoff['Commands']), ('commands/000.json', c)):
                    raw = encoded(value)
                    m.put(m.handoff_root / name, raw)
                    m.artifacts[name] = sha(raw)
                    p = str(m.handoff_root / name)
                    m.handoff['InputHashes'][p] = sha(raw)
                m.handoff['CommandsSha256'] = m.artifacts['commands.json']
            m.reseal()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.admit_handoff()

    def test_project_roles_empty_conflicting_or_foreign_seed_reject(self):
        for fault in ('empty', 'conflict', 'seed'):
            m = Model(self)
            if fault == 'empty': m.batch['InputHashes'] = {}
            elif fault == 'conflict': m.roles[next(iter(m.project))] = '0' * 64
            else: m.batch['SourceSeed'] = str(m.root / 'foreign-seed')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.admit_handoff()


class ReplayTests(unittest.TestCase):
    def test_both_leafs_recompute_in_one_reader_from_explicit_original_inputs(self):
        m = Model(self)
        self.assertEqual(m.replay()[:2], (m.census, m.abi))
        self.assertEqual((m.entries, m.exits), (1, 1))
        self.assertEqual(m.events, ['census', 'abi'])
        m.normal_leaf.inspect.assert_called_once()
        m.abi_leaf.inspect.assert_called_once()

    def test_forged_prior_census_is_only_comparison_target_not_inherited_verdict(self):
        m = Model(self)
        m.handoff['OriginalCensus']['Original'] = 1
        m.normal_leaf.require_result.side_effect = lambda p: None
        m.reseal()
        with self.assertRaisesRegex(ValueError, 'recomputed original census comparison'):
            m.replay()
        m.normal_leaf.inspect.assert_called_once()
        m.abi_leaf.inspect.assert_not_called()
        for field in ('ordinary', 'comparison'):
            m = Model(self)
            if field == 'ordinary': m.abi['Inputs']['OriginalELF']['Sha256'] = '0' * 64
            else: m.abi['PositiveAuthority']['LoadImageComparison']['Identical'] = 1
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'shared original'):
                m.replay()
            m.abi_leaf.require_result.assert_called_once()

    def test_immutable_receipts_byte_drift_and_unenrolled_reads_reject(self):
        for which in ('batch', 'native', 'handoff', 'escape'):
            m = Model(self)
            m.admit_handoff()
            m.fault = 'reader-escape' if which == 'escape' else ('immutable',
                {'batch': m.batch_root, 'native': m.native_root, 'handoff': m.handoff_root}[which] / 'results.json')
            with self.subTest(which=which), m.frozen(), self.assertRaises(ValueError):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                               m.handoff, m.roles, m.targets, m.inspection_tool)
            m.abi_leaf.inspect.assert_not_called()

    def test_process_blocker_covers_reader_entry_leaf_and_physical_close(self):
        for fault in ('reader-enter-process', 'reader-process', 'closing-process'):
            m = Model(self)
            m.admit_handoff()
            m.fault = fault
            with (self.subTest(fault=fault), m.frozen(), patch('subprocess.Popen', return_value=object()) as escape,
                    self.assertRaisesRegex(AssertionError, 'immutable ABI/census replay cannot start processes')):
                subject.replay(m.runner, m.environment, m.batch_root, m.batch, m.handoff_root,
                               m.handoff, m.roles, m.targets, m.inspection_tool)
            escape.assert_not_called()


class ResultTests(unittest.TestCase):
    def test_disposition_facts_separate_literal_counters_and_no_new_commands(self):
        m = Model(self)
        report = m.run()
        changes = [('Status', 'PASS'), ('Scope', 'whole-cell'), ('Profile', 'CM4'), ('Mode', 'O2-lto'),
            ('Linkage', 'archive'), ('LTO', 1), ('ToolInvocations', False), ('ToolInvocations', 2),
            ('CompilerInvocations', 0.0), ('RecordedInspectionInvocations', True),
            ('RecordedInspectionInvocations', 0), ('RequiredCellCount', 2774.0),
            ('RequiredCellsSatisfied', False), ('CompilerInvocations', 1), ('Commands', [{}]),
            ('Error', 'failure'), ('PrimaryError', 'failure'), ('ClosingErrors', ['failure']), ('ProjectSourceReaderRoles', True),
            ('ProjectSourceReaderRoles', 0)] + [(k, 1) for k in FACTS]
        for key, value in changes:
            forged = copy.deepcopy(report)
            forged[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                subject.require_result(forged, m.helpers)

    def test_nonclaims_explicit_errors_and_both_leaf_results_are_required(self):
        m = Model(self)
        report = m.run()
        for key in NONCLAIMS + ('Error', 'PrimaryError', 'ClosingErrors', 'OriginalCensus', 'DeferredABI'):
            forged = copy.deepcopy(report)
            del forged[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                subject.require_result(forged, m.helpers)
        for key in NONCLAIMS:
            for bad in (True, 0, None):
                forged = copy.deepcopy(report)
                forged[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    subject.require_result(forged, m.helpers)


class DriverTests(unittest.TestCase):
    def test_success_has_zero_new_tools_two_recorded_calls_and_unchanged_inputs(self):
        m = Model(self)
        report = m.run()
        self.assertEqual(report['Status'], subject.PASS)
        self.assertEqual((report['ToolInvocations'], report['CompilerInvocations'], report['RecordedInspectionInvocations']), (0, 0, 2))
        self.assertEqual(report['Commands'], [])
        m.suite.command.assert_not_called()
        self.assertEqual(m.seed_bytes, {p: p.read_bytes() for p in m.seed_bytes})
        self.assertEqual((m.entries, m.exits, m.suite._verify_outputs.call_count), (1, 1, 1))
        self.assertEqual(json.loads((m.output / 'commands.json').read_bytes()), [])

    def test_leaf_output_and_closing_failures_revoke_every_completed_fact(self):
        for fault in ('census', 'abi', 'objects', 'close', 'output'):
            m = Model(self)
            if fault == 'close': m.after_reader = lambda: setattr(m, 'fault', 'close')
            else: m.fault = fault
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                m.run()
            m.failed()
            m.runner.recover.assert_called_once()

    def test_admission_failure_and_preexisting_output_never_recover_unowned(self):
        for fault in ('admission', 'handoff', 'preexisting'):
            m = Model(self)
            if fault == 'admission': m.fault = fault
            elif fault == 'handoff': m.args.normal_receipt_sha256 = '0' * 64
            else: m.put(m.output / 'marker', b'unowned')
            with self.subTest(fault=fault), self.assertRaises((ValueError, FileExistsError)):
                m.run()
            m.runner.recover.assert_not_called()
            m.suite.command.assert_not_called()
            self.assertEqual(list(m.output.iterdir()) if m.output.exists() else [],
                             [m.output / 'marker'] if fault == 'preexisting' else [])

    def test_root_replacement_blocks_seal_and_all_recovery_writes(self):
        m = Model(self)
        def replace():
            m.output.rename(m.root / 'retired-output')
            m.put(m.output / 'marker', b'foreign replacement')
        m.after_reader = replace
        with self.assertRaises(ValueError):
            m.run()
        self.assertEqual({p.name for p in m.output.iterdir()}, {'marker'})
        self.assertEqual((m.output / 'marker').read_bytes(), b'foreign replacement')
        m.runner.seal.assert_not_called()
        m.runner.recover.assert_not_called()
        self.assertTrue(any('identity changed' in x for x in m.suite.report['ClosingErrors']))

    def test_seal_summary_and_bounded_secondary_recovery_preserve_primary(self):
        for fault in ('seal', 'manifest', 'summary', 'recovery', 'recovery-outside'):
            m = Model(self)
            m.fault = fault
            if fault.startswith('recovery'): m.abi_leaf.inspect.side_effect = ValueError('primary ABI failure')
            with self.subTest(fault=fault):
                if fault == 'summary':
                    with patch('builtins.print', side_effect=BrokenPipeError('summary failed')), self.assertRaises(BrokenPipeError):
                        m.run()
                else:
                    with self.assertRaises(ValueError): m.run()
                report = m.failed()
                self.assertIn('primary ABI failure' if fault.startswith('recovery') else fault, report['PrimaryError'])
                if fault.startswith('recovery'):
                    self.assertTrue(m.suite.report['ClosingErrors'])
                self.assertFalse((m.root / 'unowned.json').exists())


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def graph(self, bad=False, late=False):
        batch = NS(**literals(BUFFERS[ROOT / subject.BATCH[0]]), _pins=builder._pins)
        metadata = NS(**literals(BUFFERS[ROOT / batch.METADATA[0]]))
        runner = NS(**literals(BUFFERS[HERE / 'runner.py']))
        entry = NS(**literals(BUFFERS[ROOT / subject.NORMAL[0]]))
        pin = next(iter(subject.PINS.values()))[0]
        payload = b'SYNTHETIC abi_replay bootstrap bytes; never executed'
        pins = dict(abi_replay=(pin, sha(payload)))
        docs = {p: sha(BUFFERS[ROOT / p]) for p in subject.DOCUMENTS}
        data = {p: raw for p, raw in BUFFERS.items() if p != Path(__file__).resolve()}
        data[ROOT / pin] = payload
        state = NS(constructed=False, reads=[], enrolled={}, witness=object())
        constructor = Mock(side_effect=lambda args: setattr(state, 'constructed', True) or state.witness)
        def factory(legacy, capture, *, extra_sources):
            self.assertEqual(extra_sources, data)
            state.enrolled.update(extra_sources)
            return constructor
        state.factory = Mock(side_effect=factory)
        def read(p):
            if state.constructed: raise AssertionError('physical helper read after constructor')
            state.reads.append(p)
            return b'wrong pin' if bad and p == ROOT / pin else data[p]
        def load(name, path, raw):
            if name == '_os_abi_census_builder': return batch
            if name == '_os_abi_census_metadata': return metadata
            if name == '_os_abi_census_reader_entry': return runner
            if name == '_os_abi_census_normal_metadata': return entry
            if name == '_os_abi_census_admission_admission': return NS(witness_type=state.factory)
            if name.startswith('_os_abi_census_bootstrap_'):
                self.assertEqual((ROOT / subject.BATCH[0]).read_bytes(), BUFFERS[ROOT / subject.BATCH[0]])
                if late: (ROOT / 'tools/synthetic/not-enrolled.py').read_bytes()
            return NS()
        with (patch.object(subject, 'PINS', pins), patch.object(subject, 'DOCUMENTS', docs),
                patch.object(Path, 'read_bytes', read), patch.object(subject, 'load', side_effect=load)):
            yield state, constructor

    def test_entire_source_registry_precedes_constructor_and_original_opening_is_35(self):
        with self.graph() as (state, constructor):
            prepared = subject.prepare(NS())
        self.assertEqual(len(prepared), 6)
        self.assertEqual(prepared[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        self.assertEqual(len(prepared[4]), 35)
        metadata = literals(BUFFERS[ROOT / subject.BATCH[0]])
        abi = literals(BUFFERS[ROOT / metadata['METADATA'][0]])
        runner = literals(BUFFERS[HERE / 'runner.py'])
        rows = [subject.BATCH, metadata['METADATA'], ('tools/fixtures/cm3_os_lto_final_cell/runner.py', abi['RUNNER_SHA256'])]
        for registry in (abi['PINS'], abi['LEAF_PINS'], metadata['PINS'], runner['PINS']): rows.extend(registry.values())
        for registry in (runner['DOCUMENTS'], abi['DOCUMENTS']): rows.extend(registry.items())
        self.assertEqual(prepared[4], {str(ROOT / p): h for p, h in rows})
        state.factory.assert_called_once()
        constructor.assert_called_once()

    def test_bad_pin_rejects_before_admission_and_late_unknown_has_no_disk_fallback(self):
        with self.graph(bad=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'source pin/'):
            subject.prepare(NS())
        state.factory.assert_not_called()
        constructor.assert_not_called()
        with self.graph(late=True) as (state, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(NS())
        constructor.assert_called_once()


class CliTests(unittest.TestCase):
    def test_required_arguments_and_process_shell_guards_cover_all_cli_phases(self):
        argv = [value for name in subject.ARGUMENTS for value in ('--' + name, 'SYNTHETIC')]
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'SYNTHETIC'])
        prepare.assert_not_called()
        for phase in ('prepare', 'admission', 'reader', 'close', 'seal', 'summary'):
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
                    if phase == 'prepare': attempt()
                    return m.runner, m.environment, builder, m.helpers, {}, {}
                @contextmanager
                def reader(*args):
                    attempt()
                    yield None
                if phase == 'admission': m.facade.admit_batch.side_effect = attempt
                elif phase == 'reader': m.runner.reader = reader
                elif phase == 'close': m.witness.close.side_effect = attempt
                elif phase == 'seal': m.runner.seal.side_effect = attempt
                current = [v for name in subject.ARGUMENTS for v in
                    ('--' + name, str(getattr(m.args, name.replace('-', '_'), 'SYNTHETIC')))]
                printer = patch('builtins.print', side_effect=attempt) if phase == 'summary' else nullcontext()
                with (self.subTest(phase=phase, kind=kind), m.frozen(), printer,
                        patch.object(subject, 'prepare', side_effect=prepare),
                        patch('subprocess.Popen', return_value=object()) as process,
                        patch('os.system', return_value=0) as shell, redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO())):
                    self.assertEqual(subject.main(current), 1)
                process.assert_not_called()
                shell.assert_not_called()
        with patch.object(subject, 'prepare', return_value=(None,) * 6), patch.object(subject, 'run'), redirect_stderr(io.StringIO()):
            self.assertEqual(subject.main(argv), 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_ABI_CENSUS_ATTEMPT_DRIVER_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticBootstrapGraph=True, BootstrapPinsOverridden=True,
        ActualCaptureAdmitted=False, ActualELFCensusExecuted=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        global subject, normal, machine, builder, guard
        paths = [Path(__file__).resolve(), HERE / 'abi_census_attempt.py', HERE / 'normal_attempt.py',
                 HERE / 'machine_attempt.py', HERE / 'batch_attempt.py', HERE / 'batch_guard.py']
        for p in paths: BUFFERS[p] = p.read_bytes()
        with (patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot execute tools')),
                patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell commands'))):
            modules = []
            for p in paths[1:]:
                module = ModuleType('_abi_census_test_' + p.stem)
                module.__file__ = str(p)
                exec(compile(BUFFERS[p], str(p), 'exec'), module.__dict__)
                modules.append(module)
            subject, normal, machine, builder, guard = modules
            metadata_path = ROOT / builder.METADATA[0]
            BUFFERS[metadata_path] = metadata_path.read_bytes()
            metadata = literals(BUFFERS[metadata_path])
            runner_path = HERE / 'runner.py'
            BUFFERS[runner_path] = runner_path.read_bytes()
            runner = literals(BUFFERS[runner_path])
            rows = [subject.BATCH, subject.NORMAL, builder.METADATA,
                    ('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata['RUNNER_SHA256'])]
            for registry in (metadata['PINS'], metadata['LEAF_PINS'], builder.PINS, runner['PINS'], normal.PINS):
                rows.extend(registry.values())
            for registry in (runner['DOCUMENTS'], metadata['DOCUMENTS'], normal.DOCUMENTS): rows.extend(registry.items())
            for relative, h in rows:
                p = ROOT / relative
                if p not in BUFFERS: BUFFERS[p] = p.read_bytes()
                if sha(BUFFERS[p]) != h: raise ValueError('published source pin/' + relative)
            for relative in subject.DOCUMENTS:
                p = ROOT / relative
                BUFFERS[p] = p.read_bytes()
            report['SourceHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items()}
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                for c in (HandoffTests, ReplayTests, ResultTests, DriverTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS: raise ValueError('exact test method count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for p, h in report['SourceHashes'].items():
            try:
                if sha(Path(p).read_bytes()) != h: report['SourceDrift'].append(p)
            except OSError: report['SourceDrift'].append(p)
        report['SourceClosureVerified'] = bool(report['SourceHashes']) and not report['SourceDrift']
        if not report['SourceClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
