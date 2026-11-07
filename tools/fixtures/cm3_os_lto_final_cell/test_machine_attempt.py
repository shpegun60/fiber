"""Bounded synthetic CLI controls, not capture, ELF or qualification evidence."""

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'machine_attempt.py'
SOURCES = (Path(__file__).resolve(), SUBJECT, HERE / 'batch_attempt.py',
           HERE / 'batch_guard.py', HERE / 'batch_recipes.py', HERE / 'test_batch_guard.py')
METHODS = 35
SOURCE_BUFFERS = {}
subject = builder = guard = recipes = catalog_fixture = None
COMMON = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic',
          'stress-protected', 'stress-unprotected')
PORT = ('selected', 'stress-supported', 'stress-raw', 'Final')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'IRDefinitionProvenanceValidated',
    'CompleteCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification', 'CpuExecution',
    'BoardExecution', 'ProducerCompilersReexecuted', 'OsProcessTraceVerified',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence')
MACHINE_NONCLAIMS = ('WorkerOptionsValidated', 'WorkerExecutionProvenanceValidated',
    'IRDefinitionProvenanceValidated', 'FinalRootTransferProtocolsValidated', 'ABIControlsReplayed',
    'IsolationReplayed', 'FinalReferenceParity', 'CompleteCellProof', 'Qualification',
    'GlobalFreezeQualified', 'HostedCIQualified', 'CPUExecution', 'BoardExecution')
FACTS = ('MachineComponentsReplayed', 'WorkerChainsReplayed', 'ImmutableInputsConsumed',
         'InputClosureVerified', 'OutputSealVerified')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def relative_name(value):
    if (type(value) is not str or not value or '\\' in value or ':' in value or '\0' in value
            or PurePosixPath(value).is_absolute() or any(part in ('', '.', '..') for part in value.split('/'))):
        raise ValueError('synthetic unsafe relative member')
    return value


def result_record(pending=False):
    """Structurally complete invented records; no leaf is presented as actual ELF."""
    common = []
    for group in COMMON:
        pair = [dict(Role=role, Proof=dict(SyntheticOnly=True, UnresolvedAttribution=[]),
            OriginalProtectedPredicateRejected=group in
            ('mutant-engine', 'mutant-state', 'mutant-panic', 'stress-unprotected'))
            for role in ('Object', 'Machine')]
        common.append(dict(Group=group, Machines=pair))
    unresolved = []
    if pending:
        for value in common[0]['Machines']:
            evidence = [dict(Reason='SYNTHETIC unresolved cold attribution', Offset=0)]
            value['Proof']['UnresolvedAttribution'] = evidence
            unresolved.append(dict(Group='positive', Role=value['Role'], Evidence=copy.deepcopy(evidence)))
    machine = dict(Status='MACHINE-REPLAY-PENDING-ATTRIBUTION' if pending else 'MACHINE-COMPONENTS-REPLAYED',
        Scope='CM3_OS_LTO_COMMON_AND_PORT_MACHINE_COMPONENTS_ONLY', Profile='CM3', Mode='Os-lto',
        CommonMachines=common, PortMachines=[dict(Group=group, Role=role, Proof=dict(SyntheticOnly=True))
            for group in PORT for role in (('ELF', 'Machine') if group == 'Final' else ('Aggregate', 'Machine'))],
        UnresolvedAttribution=unresolved, MachineRoles=20, CommonMachineRoles=12, PortMachineRoles=8,
        CommonAttributionClosed=not pending, CallerOwnsAdmissionAndImmutableScope=True,
        RequiredCellsSatisfied=0, **dict.fromkeys(MACHINE_NONCLAIMS, False))
    workers = []
    for component, group in [('CommonAttributes', group) for group in COMMON] + [('PortPolicy', group) for group in PORT]:
        proof = dict(MachineSha256=sha((group + ' machine').encode('ascii')),
            IntermediateSha256=sha((group + ' intermediate').encode('ascii')),
            Execution=dict(CompilerReportedWorkerExecutionVerified=True, OsProcessTraceVerified=False,
                TranscriptSha256=sha((group + ' diagnostics').encode('ascii')),
                WorkerInvocations=[dict(Stage=stage) for stage in ('-fwpa', '-fltrans')]))
        if component == 'CommonAttributes':
            proof.update(SavedArgumentOsOptionsValidated=True, ActualInvocationOsOptionsValidated=True, Qualification=False)
        else:
            proof.update(SupportedPolicy=group != 'stress-raw', EffectiveOptionsVerified=True)
        workers.append(dict(Component=component, Group=group, Proof=proof))
    return dict(Scope='CURRENT_CM3_OS_LTO_BATCH_MACHINE_AND_WORKER_COMPONENTS_ONLY',
        Status='MACHINE-WORKER-REPLAY-PENDING-ATTRIBUTION' if pending else
        'MACHINE-WORKER-COMPONENTS-REPLAYED-NOT-QUALIFIED', Profile='CM3', Mode='Os-lto', Linkage='direct',
        RequiredCellCount=2774, RequiredCellsSatisfied=0, ToolInvocations=0, CompilerInvocations=0,
        Machine=machine, Workers=workers, Error=None, PrimaryError=None, ClosingErrors=[],
        **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))


class MemoryBatch:
    """A small virtual tree; admission uses real batch/catalog predicates only."""
    def __init__(self):
        self.base = Path('C:/synthetic-os-batch-guard')
        self.root = self.base / 'output'
        self.data, self.physical, self.reads = {}, {}, []
        self.report = catalog_fixture.make_report()
        for name in self.report['InputHashes']:
            self.put(Path(name), ('SYNTHETIC NOT ELF: ' + Path(name).relative_to(self.base).as_posix()).encode('ascii'))
        self.expected = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', Cohort=builder.COHORT,
            ReferenceCommit='SYNTHETIC-REFERENCE', SourceInventorySha256=builder.SOURCE,
            CurrentInventory=dict(SyntheticOnly=True), CurrentCaptureProducer=dict(SyntheticOnly=True),
            ProducerBindings=dict(SyntheticOnly=True))
        self.report.update(copy.deepcopy(self.expected), Status=builder.STATUS, Scope=builder.SCOPE, LTO=True,
            RequiredCellCount=2774, RequiredCellsSatisfied=0, ToolInvocations=134, Error=None,
            PrimaryError=None, ClosingErrors=[], **dict.fromkeys(builder.NONCLAIMS, False))
        self.report.update(**dict.fromkeys((*builder.BUILT, 'FiveLinkControlsValidated',
            'TypedDeclarationProbesValidated', 'NegativeLinkControlsExecuted', 'FinalReaderRequired',
            'InputClosureVerified', 'OutputSealVerified'), True))
        self.report['Commands'] = [dict(Label=row['Label'], Argv=['SYNTHETIC-NOT-A-TOOL'], State='TERMINAL',
            TimedOut=False, Exit=row['ExpectedExit'], ExpectedExit=row['ExpectedExit'], Seconds=0.01,
            JournalErrors=[], Error=None, Status='EXPECTED-NONZERO' if row['ExpectedExit'] else 'PASS')
            for row in recipes.batch_plan()['Commands']]
        self.report['Phases'] = [dict(Name=name, First=first, Stop=stop, Commands=stop-first)
            for name, _, first, stop in builder.PHASES]
        original = self.base / 'source/original.py'
        captured = self.root / 'source-buffers/original.py'
        self.put(original, b'SYNTHETIC builder source')
        self.put(captured, self.data[original])
        self.opening = {str(original): sha(self.data[original])}
        self.report['OpeningSourceBuffers'] = dict(self.opening)
        self.report['InputHashes'][str(original)] = sha(self.data[original])
        common_plan = [('positive', index) for index in range(3)] + [
            ('mutant-engine', 0), ('mutant-state', 1), ('mutant-panic', 2),
            ('stress-protected', 0), ('stress-unprotected', 0)]
        port_plan = [('selected', index) for index in (3, 4, 5)] + [
            ('stress-supported', 3), ('stress-raw', 3)]
        compilation_rows = {}
        for component, plan in (('CommonAttributes', common_plan), ('PortPolicy', port_plan)):
            rows = []
            for group, index in plan:
                path = self.base / 'compilation-sources' / component / group / ('%02d.c' % index)
                self.put(path, ('SYNTHETIC original ' + component + ' ' + group + ' ' + str(index)).encode('ascii'))
                digest = sha(self.data[path])
                self.report['InputHashes'][str(path)] = digest
                rows.append(dict(Group=group, TemplateIndex=index, Source=str(path),
                                 SourceSha256=digest, SyntheticOnly=True))
            compilation_rows[component] = rows
        self.report['CommonAttributesDeferredReader']['Compilations'] = compilation_rows['CommonAttributes']
        self.report['PortPolicyCompilations'] = compilation_rows['PortPolicy']
        components = self.report['PendingFinalReader']['Components']
        components['CommonAttributes'] = copy.deepcopy(self.report['CommonAttributesDeferredReader'])
        components['PortPolicy']['PortPolicyCompilations'] = copy.deepcopy(self.report['PortPolicyCompilations'])
        self.report['InputPhysicalIdentities'] = {name: list(self.physical[Path(name)]) for name in self.report['InputHashes']}
        self.report['ClosingFilesVerified'] = len(self.report['InputHashes'])
        self.report['CapturedSources'] = [dict(Original=str(original), Captured=str(captured), Sha256=sha(self.data[original]))]
        self.native = dict(Sources=[], ResolvedWorkers={})
        for index in range(9):
            path = self.base / ('native/objects/%02d.o' % index)
            self.put(path, ('SYNTHETIC native ' + str(index)).encode('ascii'))
            self.native['Sources'].append(dict(Object=str(path), ObjectSha256=sha(self.data[path])))
        for name in ('lto1', 'as'):
            path = self.base / ('native/workers/' + name)
            self.put(path, ('SYNTHETIC worker ' + name).encode('ascii'))
            self.native['ResolvedWorkers'][name] = dict(Path=str(path), Sha256=sha(self.data[path]))
        native_root = self.base / 'native'
        self.put(native_root / 'results.json', encoded(self.native))
        self.helpers = dict(guard=guard, recipes=recipes)
        self.witness = SimpleNamespace(output=self.base / 'separate-reader-output', identities={},
            api=SimpleNamespace(regular=self.regular), _physical=lambda path: self.physical[path],
            replay_api=SimpleNamespace(checked_path=self.checked_path, digest=self.digest, relative_name=relative_name),
            watch=SimpleNamespace(read=self.read, structured=self.structured, tree=self.tree),
            groups=dict(Native=dict(Result=self.native, Root=native_root,
                ReceiptSha256=sha(self.data[native_root / 'results.json']))), close=Mock())
        self.runner = SimpleNamespace(base_report=lambda witness: copy.deepcopy(self.expected))
        self.environment = dict(Witness=self.witness)
        self.args = SimpleNamespace(batch_build=str(self.root))
        self.seal()

    def put(self, path, raw):
        self.data[path] = raw
        self.physical.setdefault(path, (7, len(self.physical) + 1, 1))

    def checked_path(self, name, directory=False):
        path = Path(name)
        if not path.is_absolute() or '..' in path.parts or (directory and path != self.root):
            raise ValueError('synthetic noncanonical path')
        return path

    def regular(self, name):
        path = self.checked_path(name)
        if path not in self.data:
            raise ValueError('synthetic missing regular member')
        return path

    def digest(self, value):
        if type(value) is not str or re.fullmatch('[0-9A-F]{64}', value) is None:
            raise ValueError('synthetic literal digest')
        return value

    def read(self, path, digest=None):
        path = Path(path)
        raw = self.data[path]
        self.reads.append((path, digest))
        if digest is not None and sha(raw) != digest:
            raise ValueError('synthetic byte drift')
        return raw

    def structured(self, path, digest):
        return json.loads(self.read(path, digest))

    def tree(self, root, expected):
        actual = {path.relative_to(root).as_posix(): sha(raw) for path, raw in self.data.items()
                  if path.is_relative_to(root)}
        if actual != expected:
            raise ValueError('synthetic exact tree mismatch')

    def seal(self):
        commands = encoded(self.report['Commands'])
        self.put(self.root / 'commands.json', commands)
        self.report['CommandsSha256'] = sha(commands)
        self.put(self.root / 'results.json', encoded(self.report))
        artifacts = {path.relative_to(self.root).as_posix(): sha(raw) for path, raw in self.data.items()
                     if path.is_relative_to(self.root) and path != self.root / 'artifacts.json'}
        self.put(self.root / 'artifacts.json', encoded(dict(Artifacts=artifacts)))
        self.args.batch_receipt_sha256 = sha(self.data[self.root / 'results.json'])
        self.args.batch_artifacts_sha256 = sha(self.data[self.root / 'artifacts.json'])

    def admit(self):
        return subject.admit_batch(self.args, self.runner, self.environment, builder, self.helpers, self.opening)


class ViewTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / 'synthetic-reader-role.bin'
        self.raw = b'\x00SYNTHETIC\xff bytes\n'
        self.native = dict(Sources=[dict(Object=str(self.path))])
        self.view = subject.immutable_view(self.native, {self.path: sha(self.raw)}, object())

    def test_exact_bytes_expected_digest_and_only_declared_capabilities(self):
        with patch.object(Path, 'read_bytes', return_value=self.raw) as read, \
                patch.object(Path, 'stat', side_effect=AssertionError('no physical API')):
            self.assertEqual(self.view.watch.read(self.path, sha(self.raw)), self.raw)
            read.assert_called_once_with()
            self.assertEqual(self.view.api.checked_path(str(self.path)), self.path)
            self.assertEqual(self.view.admitted.base.stable_path(self.path), self.path)
        self.assertEqual(set(vars(self.view.watch)), {'read'})
        self.assertEqual(set(vars(self.view.api)), {'checked_path'})
        self.assertEqual(set(vars(self.view.admitted.base)), {'stable_path'})
        self.assertIs(self.view.result, self.native)
        self.assertEqual(self.view.objects, (self.path,))

    def test_undeclared_relative_and_traversal_paths_never_read(self):
        bad = (self.path.with_name('unknown.bin'), Path(self.path.name),
               str(self.path.parent / '..' / self.path.parent.name / self.path.name), str(self.path) + '\0', 4)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('must reject before reading')) as read:
            for value in bad:
                for method in (self.view.watch.read, self.view.api.checked_path):
                    with self.subTest(value=value, method=method), self.assertRaises(ValueError):
                        method(value)
            read.assert_not_called()

    def test_stable_worker_path_normalizes_dots_without_physical_access(self):
        worker = self.path.with_name('lto1.exe')
        dotted = worker.parent / 'subdir' / '..' / worker.name
        view = subject.immutable_view(dict(Sources=[]), {worker: sha(self.raw)}, object())
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('no reader byte access')), \
                patch.object(Path, 'stat', side_effect=AssertionError('no physical stat')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('no physical lstat')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('no physical resolution')):
            self.assertEqual(view.admitted.base.stable_path(dotted), worker)
            self.assertEqual(view.admitted.base.stable_path(str(dotted)), worker)
            for method in (view.api.checked_path, view.watch.read):
                with self.subTest(method=method), self.assertRaises(ValueError):
                    method(dotted)
            for value in (worker.with_name('unknown.exe'), dotted.with_name('unknown.exe'),
                          Path('lto1.exe'), str(worker) + '\0', 4):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    view.admitted.base.stable_path(value)

    def test_changed_bytes_and_wrong_requested_digest_reject(self):
        for raw, digest in ((b'changed', None), (self.raw, 'A' * 64), (self.raw, True)):
            with self.subTest(raw=raw, digest=digest), patch.object(Path, 'read_bytes', return_value=raw), \
                    self.assertRaises(ValueError):
                self.view.watch.read(self.path, digest)


class ResultTests(unittest.TestCase):
    def reject(self, report):
        with self.assertRaises(ValueError):
            subject.require_result(report)

    def test_complete_replayed_and_pending_records_roundtrip_without_mutation(self):
        for pending in (False, True):
            report = result_record(pending)
            saved = copy.deepcopy(report)
            subject.require_result(report)
            subject.require_result(json.loads(encoded(report)))
            self.assertEqual(report, saved)
            self.assertFalse(report['Qualification'])
            self.assertEqual(report['RequiredCellsSatisfied'], 0)

    def test_identity_counts_and_literal_boolean_facts(self):
        for key, bad in [('Status', 'PASS'), ('Scope', 'whole-cell'), ('Mode', 'O2-lto'), ('Profile', 'CM4'),
                ('Linkage', 'archive'), ('RequiredCellCount', 2774.0), ('RequiredCellsSatisfied', False),
                ('ToolInvocations', False), ('CompilerInvocations', 0.0), ('ToolInvocations', 1)]:
            report = result_record()
            report[key] = bad
            with self.subTest(key=key, bad=bad):
                self.reject(report)
        for key in FACTS:
            for bad in (False, 1, None):
                report = result_record()
                report[key] = bad
                with self.subTest(key=key, bad=bad):
                    self.reject(report)

    def test_every_outer_nonclaim_is_required_literal_false(self):
        for key in NONCLAIMS:
            for bad in (True, 0, None):
                report = result_record()
                report[key] = bad
                with self.subTest(key=key, bad=bad):
                    self.reject(report)

    def test_counts_without_actual_structured_components_reject(self):
        for defect in ('shallow-machine', 'null-workers', 'empty-worker-proof', 'short-common', 'short-port'):
            report = result_record()
            if defect == 'shallow-machine':
                report['Machine'] = dict(MachineRoles=20, UnresolvedAttribution=[])
            elif defect == 'null-workers':
                report['Workers'] = [None] * 10
            elif defect == 'empty-worker-proof':
                report['Workers'][0]['Proof'] = {}
            else:
                report['Machine']['CommonMachines' if defect == 'short-common' else 'PortMachines'].pop()
            with self.subTest(defect=defect):
                self.reject(report)

    def test_common_port_and_worker_roles_cannot_duplicate_or_reorder(self):
        for key in ('CommonMachines', 'PortMachines', 'Workers'):
            for duplicate in (False, True):
                report = result_record()
                rows = report['Workers'] if key == 'Workers' else report['Machine'][key]
                if duplicate:
                    rows[1] = copy.deepcopy(rows[0])
                else:
                    rows.reverse()
                with self.subTest(key=key, duplicate=duplicate):
                    self.reject(report)
        report = result_record()
        report['Machine']['CommonMachines'][0]['Machines'].reverse()
        self.reject(report)

    def test_machine_counters_nonclaims_and_mutant_selectors(self):
        for key in ('MachineRoles', 'CommonMachineRoles', 'PortMachineRoles', 'RequiredCellsSatisfied'):
            report = result_record()
            report['Machine'][key] = float(report['Machine'][key])
            with self.subTest(key=key):
                self.reject(report)
        for key in MACHINE_NONCLAIMS:
            report = result_record()
            report['Machine'][key] = True
            with self.subTest(key=key):
                self.reject(report)
        report = result_record()
        report['Machine']['CommonMachines'][1]['Machines'][0]['OriginalProtectedPredicateRejected'] = 1
        self.reject(report)

    def test_pending_must_preserve_full_typed_leaf_attribution_projection(self):
        for defect in ('cut', 'numeric-alias', 'promotion', 'hidden-leaf'):
            report = result_record(True)
            if defect == 'cut':
                report['Machine']['UnresolvedAttribution'].pop()
            elif defect == 'numeric-alias':
                report['Machine']['UnresolvedAttribution'][0]['Evidence'][0]['Offset'] = False
            elif defect == 'promotion':
                report['Status'] = subject.REPLAYED
            else:
                report['Machine']['CommonMachines'][0]['Machines'][0]['Proof']['UnresolvedAttribution'] = []
            with self.subTest(defect=defect):
                self.reject(report)

    def test_machine_pending_status_and_closed_flag_cannot_contradict_leaves(self):
        for pending in (False, True):
            for key, bad in (('Status', 'MACHINE-COMPONENTS-REPLAYED' if pending else 'MACHINE-REPLAY-PENDING-ATTRIBUTION'),
                             ('CommonAttributionClosed', pending), ('CommonAttributionClosed', int(not pending))):
                report = result_record(pending)
                report['Machine'][key] = bad
                with self.subTest(pending=pending, key=key, bad=bad):
                    self.reject(report)

    def test_worker_hash_execution_stage_and_supported_flags_are_literal(self):
        for key, bad in (('MachineSha256', True), ('IntermediateSha256', 'a' * 64),
                         ('SavedArgumentOsOptionsValidated', 1), ('ActualInvocationOsOptionsValidated', False),
                         ('Qualification', True)):
            report = result_record()
            report['Workers'][0]['Proof'][key] = bad
            with self.subTest(key=key):
                self.reject(report)
        for key, bad in (('CompilerReportedWorkerExecutionVerified', 1), ('OsProcessTraceVerified', 0),
                         ('TranscriptSha256', 'bad'), ('WorkerInvocations', [dict(Stage='-fltrans'), dict(Stage='-fwpa')])):
            report = result_record()
            report['Workers'][0]['Proof']['Execution'][key] = bad
            with self.subTest(key=key):
                self.reject(report)
        for index, key, bad in ((8, 'SupportedPolicy', True), (9, 'SupportedPolicy', 1), (6, 'EffectiveOptionsVerified', False)):
            report = result_record()
            report['Workers'][index]['Proof'][key] = bad
            with self.subTest(index=index, key=key):
                self.reject(report)

    def test_explicit_clean_error_keys_are_mandatory(self):
        for key in ('Error', 'PrimaryError', 'ClosingErrors'):
            report = result_record()
            del report[key]
            with self.subTest(missing=key):
                self.reject(report)
        for key, bad in (('Error', False), ('PrimaryError', ''), ('ClosingErrors', {}), ('ClosingErrors', ['late failure'])):
            report = result_record()
            report[key] = bad
            with self.subTest(key=key):
                self.reject(report)


class WorkerTests(unittest.TestCase):
    def model(self):
        root, raw = ROOT / 'synthetic-workers', {}
        def binding(name):
            path = root / name
            raw[path] = ('SYNTHETIC ' + name).encode('ascii')
            return dict(Path=str(path), Sha256=sha(raw[path]))
        plans, common_results, common_calls = [], [], []
        view = SimpleNamespace(result=dict(SyntheticOnly=True),
            watch=SimpleNamespace(read=Mock(side_effect=lambda path, digest=None: raw[path])))
        attributes, attr_runner, port_view = object(), object(), object()
        for group in COMMON:
            output, inp, specs, diag = (binding(group + '/' + name)
                for name in ('aggregate.o', 'input.o', 'specs', 'stderr'))
            output, objects, specs = Path(output['Path']), [Path(inp['Path'])], Path(specs['Path'])
            machine = Path(str(output) + '.ltrans0.ltrans.o')
            raw[machine] = ('SYNTHETIC machine ' + group).encode('ascii')
            proof = dict(SyntheticOnly=True, Group=group, MachineSha256=sha(raw[machine]))
            diagnostics = raw[Path(diag['Path'])]
            plans.append(dict(Component='CommonAttributes', Group=group, Output=output, Objects=objects,
                Specs=specs, Diagnostics=diagnostics, Supported=None, StoredWorker=None))
            common_results.append((machine, proof))
            common_calls.append(call(view, output, objects, specs, diagnostics, attr_runner))
        port_results, port_calls = [], []
        for group in PORT:
            output, inp, diag = (binding(group + '/' + name) for name in ('output', 'input.o', 'stderr'))
            specs = binding(group + '/specs') if group == 'stress-raw' else None
            proof = dict(SyntheticOnly=True, DriverSpecs=specs, Group=group)
            output, objects = Path(output['Path']), [Path(inp['Path'])]
            specs = None if specs is None else Path(specs['Path'])
            diagnostics, supported = raw[Path(diag['Path'])], group != 'stress-raw'
            plans.append(dict(Component='PortPolicy', Group=group, Output=output, Objects=objects,
                Specs=specs, Diagnostics=diagnostics, Supported=supported, StoredWorker=copy.deepcopy(proof)))
            port_results.append(proof)
            port_calls.append(call(port_view, output, objects, diagnostics, supported=supported, specs=specs))
        helpers = dict(common_workers=SimpleNamespace(worker_chain=Mock(side_effect=common_results)),
            workers=SimpleNamespace(worker_chain=Mock(side_effect=port_results)),
            worker_bindings=SimpleNamespace(bind=Mock(return_value=plans)),
            attributes=attributes, attribute_runner=attr_runner,
            port_policy=SimpleNamespace(_worker_view=Mock(return_value=port_view)), guard=guard)
        events = Mock()
        for name, method in (('bind', helpers['worker_bindings'].bind),
                ('adapter', helpers['port_policy']._worker_view), ('common', helpers['common_workers'].worker_chain),
                ('port', helpers['workers'].worker_chain)):
            events.attach_mock(method, name)
        batch = dict(SyntheticOnly=True)
        return root, view, helpers, batch, common_calls, port_calls, events

    def test_actual_ten_helper_calls_exact_order_and_supported_raw_flags(self):
        root, view, helpers, batch, common_calls, port_calls, events = self.model()
        rows = subject.replay_workers(batch, root, view, helpers)
        bind_helpers = {name: helpers[name] for name in ('attributes', 'port_policy', 'attribute_runner', 'guard')}
        helpers['worker_bindings'].bind.assert_called_once_with(batch, root, view.result, view.watch.read, bind_helpers)
        self.assertEqual(helpers['common_workers'].worker_chain.call_args_list, common_calls)
        self.assertEqual(helpers['workers'].worker_chain.call_args_list, port_calls)
        helpers['port_policy']._worker_view.assert_called_once_with(view)
        self.assertEqual(events.mock_calls,
            [call.bind(batch, root, view.result, view.watch.read, bind_helpers), call.adapter(view)]
            + [call.common(*value.args, **value.kwargs) for value in common_calls]
            + [call.port(*value.args, **value.kwargs) for value in port_calls])
        self.assertEqual([(row['Component'], row['Group']) for row in rows],
            [('CommonAttributes', group) for group in COMMON] + [('PortPolicy', group) for group in PORT])

    def test_helper_failure_stops_without_retry_or_port_fallback(self):
        for stage in ('bind', 'common'):
            root, view, helpers, batch, _, _, events = self.model()
            failing = helpers['worker_bindings'].bind if stage == 'bind' else helpers['common_workers'].worker_chain
            failing.side_effect = ValueError('synthetic ' + stage + ' failure')
            with self.subTest(stage=stage), self.assertRaisesRegex(ValueError, 'synthetic ' + stage + ' failure'):
                subject.replay_workers(batch, root, view, helpers)
            self.assertEqual(helpers['worker_bindings'].bind.call_count, 1)
            self.assertEqual(events.mock_calls[0][0], 'bind')
            if stage == 'bind':
                helpers['common_workers'].worker_chain.assert_not_called()
                helpers['port_policy']._worker_view.assert_not_called()
                self.assertEqual(len(events.mock_calls), 1)
            else:
                self.assertEqual(helpers['common_workers'].worker_chain.call_count, 1)
            helpers['workers'].worker_chain.assert_not_called()


class AdmissionTests(unittest.TestCase):
    def test_retain_identity_never_overwrites_previous_inode_or_builder_record(self):
        path, original = ROOT / 'synthetic-retained-input.bin', (7, 2, 1)
        witness = SimpleNamespace(identities={}, _physical=Mock(return_value=original))
        subject.retain_identity(witness, path, list(original))
        self.assertIs(witness.identities[path], original)
        subject.retain_identity(witness, path)
        self.assertIs(witness.identities[path], original)
        witness._physical.return_value = (7, 999, 1)
        for expected in (None, [7, 999, 1]):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, 'previously admitted physical identity'):
                subject.retain_identity(witness, path, expected)
            self.assertIs(witness.identities[path], original)
        witness._physical.return_value = original
        with self.assertRaisesRegex(ValueError, 'original builder physical identity'):
            subject.retain_identity(witness, path, [7, 999, 1])
        self.assertIs(witness.identities[path], original)

    def test_admission_role_reenrollment_rechecks_retained_physical_identity(self):
        model = MemoryBatch()
        path = Path(model.report['ABIProbes']['types.c']['Object'])
        original, reads = model.physical[path], []
        def physical(value):
            if value == path:
                reads.append(value)
                return original if len(reads) == 1 else (7, 999, 1)
            return model.physical[value]
        model.witness._physical = physical
        with patch.object(subject, 'retain_identity', wraps=subject.retain_identity) as retain, \
                self.assertRaisesRegex(ValueError, 'previously admitted physical identity'):
            model.admit()
        self.assertEqual([value for value in retain.call_args_list if value.args[1] == path],
                         [call(model.witness, path, list(original)), call(model.witness, path)])
        self.assertEqual(model.witness.identities[path], original)
        self.assertEqual(len(reads), 2)
        model.witness.close.assert_not_called()

    def test_bounded_sealed_batch_admits_and_preserves_physical_identity(self):
        model = MemoryBatch()
        with patch.object(Path, 'write_bytes', side_effect=AssertionError('admission is read-only')):
            root, report, roles = model.admit()
        self.assertEqual(root, model.root)
        self.assertEqual(report, model.report)
        self.assertEqual(report['PendingFinalReader']['InputRoleCount'], 142)
        self.assertTrue(all(type(row) is tuple and len(row) == 3 for row in model.witness.identities.values()))
        self.assertIn(model.root / 'artifacts.json', roles)
        self.assertEqual(roles[model.root / 'results.json'], model.args.batch_receipt_sha256)
        model.witness.close.assert_called_once_with()

    def test_same_admitted_authority_source_cohort_and_projection_reject_corruption(self):
        for defect in ('producer', 'source-cohort', 'component', 'pending-role'):
            model = MemoryBatch()
            if defect == 'producer':
                model.report['ProducerBindings'] = dict(Foreign=True)
            elif defect == 'source-cohort':
                model.report['OpeningSourceBuffers'] = {}
            elif defect == 'component':
                model.report['PendingFinalReader']['Components']['Isolation']['IsolatedCommon'][0]['ObjectSha256'] = 'A' * 64
            else:
                model.report['PendingFinalReader']['Inputs'].pop()
                model.report['PendingFinalReader']['InputRoleCount'] -= 1
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                model.admit()

    def test_input_physical_identity_is_three_nonnegative_literal_integers(self):
        for bad in ([7, 1], [7, 1, 1, 4], [True, 1, 1], [7, -1, 1], [7, 999999, 1], (7, 1, 1)):
            model = MemoryBatch()
            name = next(iter(model.report['InputHashes']))
            model.report['InputPhysicalIdentities'][name] = bad
            if type(bad) is tuple:
                # JSON represents tuples as arrays; exercise the loaded shape explicitly instead.
                model.structured = lambda path, digest: model.report if path.name == 'results.json' else json.loads(model.read(path, digest))
                model.witness.watch.structured = model.structured
            model.seal()
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                model.admit()

    def test_hash_identity_set_count_and_canonical_path_corruption_reject(self):
        for defect in ('missing-identity', 'count-bool', 'count-short', 'path-alias', 'bad-hash'):
            model = MemoryBatch()
            name = next(iter(model.report['InputHashes']))
            if defect == 'missing-identity':
                del model.report['InputPhysicalIdentities'][name]
            elif defect in ('count-bool', 'count-short'):
                model.report['ClosingFilesVerified'] = False if defect == 'count-bool' else 1
            elif defect == 'bad-hash':
                model.report['InputHashes'][name] = True
            else:
                original = next(iter(model.opening))
                alias = original.replace('\\', '/')
                model.report['InputHashes'][alias] = model.report['InputHashes'].pop(original)
                model.report['InputPhysicalIdentities'][alias] = model.report['InputPhysicalIdentities'].pop(original)
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                model.admit()

    def test_captured_sources_must_bind_unique_original_and_owned_manifest_bytes(self):
        for defect in ('duplicate', 'outside', 'extra-field', 'wrong-hash', 'missing-opening'):
            model = MemoryBatch()
            row = model.report['CapturedSources'][0]
            if defect == 'duplicate':
                model.report['CapturedSources'].append(copy.deepcopy(row))
            elif defect == 'outside':
                row['Captured'] = row['Original']
            elif defect == 'extra-field':
                row['PriorVerdict'] = 'PASS'
            elif defect == 'wrong-hash':
                row['Sha256'] = 'B' * 64
            else:
                model.report['CapturedSources'] = []
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                model.admit()

    def test_receipt_manifest_and_journal_bindings_reject_resealed_corruption(self):
        for defect in ('receipt', 'manifest-self', 'unsafe-member', 'journal'):
            model = MemoryBatch()
            if defect == 'journal':
                commands = copy.deepcopy(model.report['Commands'])
                commands[0]['Label'] = 'foreign sealed journal'
                model.put(model.root / 'commands.json', encoded(commands))
                model.report['CommandsSha256'] = sha(encoded(commands))
                model.put(model.root / 'results.json', encoded(model.report))
                model.args.batch_receipt_sha256 = sha(model.data[model.root / 'results.json'])
            manifest = json.loads(model.data[model.root / 'artifacts.json'])
            if defect == 'receipt':
                manifest['Artifacts']['results.json'] = 'A' * 64
            elif defect == 'manifest-self':
                manifest['Artifacts']['artifacts.json'] = 'A' * 64
            elif defect == 'unsafe-member':
                manifest['Artifacts']['../outside'] = 'A' * 64
            else:
                manifest['Artifacts']['results.json'] = model.args.batch_receipt_sha256
                manifest['Artifacts']['commands.json'] = model.report['CommandsSha256']
            model.put(model.root / 'artifacts.json', encoded(manifest))
            model.args.batch_artifacts_sha256 = sha(model.data[model.root / 'artifacts.json'])
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                model.admit()

    def test_output_must_be_disjoint_and_input_bytes_must_close(self):
        for defect in ('inside', 'ancestor', 'byte-drift', 'close'):
            model = MemoryBatch()
            if defect == 'inside':
                model.witness.output = model.root / 'nested-output'
            elif defect == 'ancestor':
                model.witness.output = model.base
            elif defect == 'byte-drift':
                original = Path(next(iter(model.opening)))
                model.data[original] = b'changed actual original'
            else:
                model.witness.close.side_effect = ValueError('synthetic closing drift')
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                model.admit()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='os-machine-attempt-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'output'
        self.witness = SimpleNamespace(output=self.output, buffers={}, watch=SimpleNamespace(read=Mock()))
        self.witness.replay_api = SimpleNamespace(relative_name=relative_name)
        self.environment = dict(Witness=self.witness)
        self.report = result_record()
        def revoke(report, error):
            report.update(Status='FAIL', Error=str(error), PrimaryError=str(error),
                          RequiredCellsSatisfied=0, InputClosureVerified=False, OutputSealVerified=False)
        def recover(environment, report):
            (self.output / 'results.json').write_bytes(encoded(report))
            (self.output / 'artifacts.json').write_bytes(encoded(dict(Artifacts={})))
        self.runner = SimpleNamespace(base_report=lambda witness: self.report, revoke=Mock(side_effect=revoke),
                                      recover=Mock(side_effect=recover))

    def run_failure(self, error, admitted=True):
        admission = dict(return_value=(ROOT / 'synthetic-batch', {}, {})) if admitted else dict(side_effect=error)
        with patch.object(subject, 'admit_batch', **admission), \
                patch.object(subject, 'replay', side_effect=error):
            return subject.run(SimpleNamespace(batch_receipt_sha256='A' * 64, batch_artifacts_sha256='B' * 64),
                self.runner, self.environment, builder, dict(guard=guard), {})

    def test_admission_failure_never_claims_or_recovers_output(self):
        with patch.object(builder, 'recover_owned', wraps=builder.recover_owned) as recover, \
                self.assertRaisesRegex(ValueError, 'admission failed'):
            self.run_failure(ValueError('admission failed'), admitted=False)
        recover.assert_not_called()
        self.runner.recover.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_preexisting_unowned_output_is_untouched(self):
        self.output.mkdir()
        marker = self.output / 'results.json'
        marker.write_bytes(b'unrelated preexisting receipt')
        with self.assertRaises(FileExistsError):
            self.run_failure(ValueError('should not reach replay'))
        self.assertEqual(marker.read_bytes(), b'unrelated preexisting receipt')
        self.assertFalse((self.output / 'artifacts.json').exists())
        self.runner.recover.assert_not_called()

    def test_owned_failure_persists_zero_credit_without_worker_claims(self):
        with self.assertRaisesRegex(ValueError, 'machine predicate failed'):
            self.run_failure(ValueError('machine predicate failed'))
        report = json.loads((self.output / 'results.json').read_bytes())
        self.assertEqual(report['Status'], 'FAIL')
        self.assertIs(report['MachineComponentsReplayed'], False)
        self.assertIs(report['WorkerChainsReplayed'], False)
        self.assertTrue(all(report[key] is False for key in NONCLAIMS))
        self.assertEqual(report['RequiredCellsSatisfied'], 0)
        self.runner.recover.assert_called_once()

    def test_replaced_output_refuses_writes_and_preserves_primary_failure(self):
        primary = ValueError('original replay failure')
        def replace(*args):
            self.output.rename(self.output.with_name('retired-owned-output'))
            self.output.mkdir()
            (self.output / 'marker.bin').write_bytes(b'unrelated replacement')
            raise primary
        with patch.object(subject, 'admit_batch', return_value=(ROOT / 'synthetic-batch', {}, {})), \
                patch.object(subject, 'replay', side_effect=replace), self.assertRaises(ValueError) as caught:
            subject.run(SimpleNamespace(batch_receipt_sha256='A' * 64, batch_artifacts_sha256='B' * 64),
                self.runner, self.environment, builder, dict(guard=guard), {})
        self.assertIs(caught.exception, primary)
        self.assertEqual((self.output / 'marker.bin').read_bytes(), b'unrelated replacement')
        self.assertEqual({path.name for path in self.output.iterdir()}, {'marker.bin'})
        self.assertEqual(self.report['PrimaryError'], str(primary))
        self.assertTrue(any('identity changed' in error for error in self.report['ClosingErrors']))
        self.runner.recover.assert_not_called()

    def test_summary_print_failure_revokes_sealed_owned_component_result(self):
        primary = BrokenPipeError('synthetic summary failure')
        replayed, sealed = result_record(), []
        def seal(environment, report, expected):
            self.assertIs(environment, self.environment)
            report.update(InputClosureVerified=True, OutputSealVerified=True)
            subject.require_result(report)
            sealed.append(copy.deepcopy(report))
            raw = encoded(report)
            (self.output / 'results.json').write_bytes(raw)
            (self.output / 'artifacts.json').write_bytes(encoded(dict(Artifacts={'results.json': sha(raw)})))
        with patch.object(subject, 'admit_batch', return_value=(ROOT / 'synthetic-batch', {}, {})), \
                patch.object(subject, 'replay', return_value=(replayed['Machine'], replayed['Workers'], 'synthetic reader')), \
                patch.object(self.runner, 'seal', side_effect=seal, create=True), \
                patch('builtins.print', side_effect=primary), self.assertRaises(BrokenPipeError) as caught:
            subject.run(SimpleNamespace(batch_receipt_sha256='A' * 64, batch_artifacts_sha256='B' * 64),
                self.runner, self.environment, builder, dict(guard=guard), {})
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(sealed), 1)
        self.assertEqual(sealed[0]['Status'], subject.REPLAYED)
        self.assertIs(sealed[0]['MachineComponentsReplayed'], True)
        self.assertIs(sealed[0]['WorkerChainsReplayed'], True)
        report = json.loads((self.output / 'results.json').read_bytes())
        self.assertEqual(report['Status'], 'FAIL')
        self.assertEqual(report['PrimaryError'], str(primary))
        for key in ('MachineComponentsReplayed', 'WorkerChainsReplayed', 'InputClosureVerified', 'OutputSealVerified'):
            self.assertIs(report[key], False)
        self.assertTrue(all(report[key] is False for key in NONCLAIMS))
        self.assertEqual(report['RequiredCellsSatisfied'], 0)
        self.runner.revoke.assert_called_once_with(self.report, primary)
        self.runner.recover.assert_called_once_with(self.environment, self.report)


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def bootstrap(self, *, corrupt=None, late_read=None):
        """Execute authenticated modules, replacing only the witness factory."""
        read_bytes, load = Path.read_bytes, subject.load
        state = SimpleNamespace(events=[], loaded={}, enrolled={}, constructed=False,
            late_reads=[], expected_opening={}, witness=object(), args=SimpleNamespace(SyntheticOnly=True))

        def physical_read(path):
            path = Path(path)
            if state.constructed:
                raise AssertionError('fresh physical helper read after constructor: ' + str(path))
            if any('cm33f_secure_transfer_reference' in part or 'm55_secure_closed_parity' in part for part in path.parts):
                raise AssertionError('protected unrelated source read')
            raw = read_bytes(path)
            if path in SOURCE_BUFFERS:
                self.assertEqual(raw, SOURCE_BUFFERS[path], 'opening provider bytes changed')
            else:
                SOURCE_BUFFERS[path] = raw
            state.events.append(('read', path))
            return b'SYNTHETIC incorrect source buffer' if path == corrupt else raw

        def construct(args):
            self.assertIs(args, state.args)
            state.events.append(('construct', None))
            state.constructed = True
            return state.witness

        state.constructor = Mock(side_effect=construct)

        def factory(legacy, capture, *, extra_sources):
            self.assertIs(legacy, state.loaded['_os_machine_admission_legacy'])
            self.assertIs(capture, state.loaded['_os_machine_admission_capture'])
            batch = state.loaded['_os_machine_batch_metadata']
            metadata = state.loaded['_os_machine_abi_metadata']
            runner = state.loaded['_os_machine_reader_entry']
            original_pins = (subject.BATCH, batch.METADATA,
                ('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256),
                *runner.PINS.values(), *metadata.PINS.values(), *metadata.LEAF_PINS.values(),
                *batch.PINS.values(), *runner.DOCUMENTS.items(), *metadata.DOCUMENTS.items())
            state.expected_opening = {str(ROOT / relative): digest for relative, digest in original_pins}
            expected = {ROOT / relative: digest for relative, digest in
                (*original_pins, *subject.PINS.values(), *subject.DOCUMENTS.items())}
            expected[SUBJECT] = sha(SOURCE_BUFFERS[SUBJECT])
            self.assertEqual({path: sha(raw) for path, raw in extra_sources.items()}, expected)
            self.assertTrue(all(path in SOURCE_BUFFERS and SOURCE_BUFFERS[path] == raw
                                for path, raw in extra_sources.items()))
            state.enrolled.update(extra_sources)
            state.events.append(('factory', None))
            return state.constructor

        state.factory = Mock(side_effect=factory)

        def loader(name, path, raw):
            state.events.append(('load', name))
            if state.constructed and name.startswith('_os_machine_bootstrap_') and late_read is not None and not state.late_reads:
                state.late_reads.append((late_read, late_read.read_bytes()))
            module = load(name, path, raw)
            state.loaded[name] = module
            if name == '_os_machine_admission_admission':
                module.witness_type = state.factory
            return module

        with patch.dict(sys.modules), patch.object(Path, 'read_bytes', physical_read), \
                patch.object(subject, 'load', side_effect=loader), \
                patch.object(Path, 'write_bytes', side_effect=AssertionError('bootstrap cannot write output')):
            yield state

    def test_all_current_sources_and_exact_builder_opening_precede_constructor(self):
        with self.bootstrap() as state:
            runner, environment, batch, helpers, opening = subject.prepare(state.args)
        self.assertIs(environment['Witness'], state.witness)
        self.assertIs(runner, state.loaded['_os_machine_reader_entry'])
        self.assertIs(batch, state.loaded['_os_machine_batch_metadata'])
        self.assertEqual(opening, state.expected_opening)
        self.assertTrue(helpers)
        state.factory.assert_called_once()
        state.constructor.assert_called_once_with(state.args)
        cutoff = next(index for index, value in enumerate(state.events) if value[0] == 'factory')
        self.assertEqual({value[1] for value in state.events[:cutoff] if value[0] == 'read'}, set(state.enrolled))
        self.assertFalse(any(value[0] == 'read' for value in state.events[cutoff:]))
        for relative, digest in (*subject.PINS.values(), *subject.DOCUMENTS.items()):
            self.assertEqual(sha(state.enrolled[ROOT / relative]), digest)
        self.assertTrue(set(opening) < {str(path) for path in state.enrolled})

    def test_after_constructor_known_helper_bytes_are_cached_unknown_reads_reject(self):
        known = ROOT / subject.BATCH[0]
        with self.bootstrap(late_read=known) as state:
            subject.prepare(state.args)
        self.assertEqual(state.late_reads, [(known, state.enrolled[known])])
        state.constructor.assert_called_once()
        unknown = ROOT / 'tools/synthetic/never-admitted-helper.py'
        with self.bootstrap(late_read=unknown) as state, \
                self.assertRaisesRegex(ValueError, 'bootstrap source outside opening authenticated buffers'):
            subject.prepare(state.args)
        state.constructor.assert_called_once()
        self.assertFalse(any(kind == 'read' and path == unknown for kind, path in state.events))
        self.assertNotIn(unknown, SOURCE_BUFFERS)

    def test_wrong_current_source_or_document_pin_rejects_before_admission(self):
        for relative, _ in (subject.BATCH, *subject.PINS.values(), *subject.DOCUMENTS.items()):
            with self.subTest(relative=relative), self.bootstrap(corrupt=ROOT / relative) as state, \
                    self.assertRaisesRegex(ValueError, 'source pin/' + re.escape(relative)):
                subject.prepare(state.args)
            state.factory.assert_not_called()
            state.constructor.assert_not_called()
            self.assertEqual(state.enrolled, {})
            self.assertFalse(any(kind == 'load' and name.startswith('_os_machine_bootstrap_')
                                 for kind, name in state.events))


class CliTests(unittest.TestCase):
    def argv(self):
        names = (*subject.ARGUMENTS, 'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
            'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256', 'inventory',
            'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
        return [value for name in names for value in ('--' + name, 'SYNTHETIC')]

    def test_cli_dispatch_and_errors_without_real_admission(self):
        for fail in (False, True):
            with patch.object(subject, 'prepare', return_value=('runner', 'environment', 'builder', 'helpers', 'opening')) as prepare, \
                    patch.object(subject, 'run', side_effect=ValueError('synthetic CLI failure') if fail else None) as run, \
                    redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(subject.main(self.argv()), 1 if fail else 0)
            self.assertEqual(prepare.call_count, 1)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[1:], ('runner', 'environment', 'builder', 'helpers', 'opening'))
            self.assertEqual('synthetic CLI failure' in stderr.getvalue(), fail)

    def test_cli_no_abbreviations_and_no_process_or_shell_escape(self):
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'SYNTHETIC'])
        prepare.assert_not_called()
        for route in ('process', 'shell'):
            def escape(*args):
                if route == 'process':
                    import subprocess
                    subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
                else:
                    import os
                    os.system('SYNTHETIC-NEVER-EXECUTED')
            with patch.object(subject, 'prepare', return_value=(None,) * 5), \
                    patch.object(subject, 'run', side_effect=escape), redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(subject.main(self.argv()), 1)
            self.assertIn('machine replay cannot execute', stderr.getvalue())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_MACHINE_ATTEMPT_CLI_CONTROLS_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Errors=0, Failures=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticControlsOnly=True,
        ActualCaptureAdmitted=False, ActualMachineBytesValidated=False, ActualCompilerExecuted=False,
        FinalReaderExecuted=False, Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False,
        BoardExecution=False, GlobalFreezeQualified=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('isolated unoptimized -I -S -B Python required')
        buffers = {path: path.read_bytes() for path in SOURCES}
        SOURCE_BUFFERS.clear()
        SOURCE_BUFFERS.update(buffers)
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        global subject, builder, guard, recipes, catalog_fixture
        modules = []
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot execute tools')), \
                patch('os.system', side_effect=AssertionError('pure tests cannot execute shell commands')):
            for path in SOURCES[1:]:
                module = ModuleType('_os_machine_attempt_test_' + path.stem)
                module.__file__ = str(path)
                exec(compile(buffers[path], str(path), 'exec'), module.__dict__)
                modules.append(module)
            subject, builder, guard, recipes, catalog_fixture = modules
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case) for case in
                (ViewTests, ResultTests, WorkerTests, AdmissionTests, RecoveryTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS:
                raise ValueError('exact implemented method count required: ' + str(suite.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in SOURCE_BUFFERS.items()}
        report['SourceFiles'] = len(SOURCE_BUFFERS)
        for name, expected in report['SourceHashes'].items():
            try:
                if sha(Path(name).read_bytes()) == expected:
                    report['ClosingFilesVerified'] += 1
                else:
                    report['SourceDrift'].append(name)
            except OSError:
                report['SourceDrift'].append(name)
        report['SourceClosureVerified'] = (set(SOURCES) <= set(SOURCE_BUFFERS)
            and report['ClosingFilesVerified'] == len(SOURCE_BUFFERS) and not report['SourceDrift'])
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
