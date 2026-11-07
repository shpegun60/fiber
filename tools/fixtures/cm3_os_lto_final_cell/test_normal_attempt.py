"""Bounded synthetic normal-driver tests: no tools, real admission or ELF census."""

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCES = (Path(__file__).resolve(), HERE / 'normal_attempt.py', HERE / 'machine_attempt.py',
           HERE / 'batch_attempt.py', HERE / 'batch_guard.py')
METHODS = 20
subject = machine = builder = guard = None
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'ABIControlsReplayed', 'IsolationReplayed', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'CompleteCellProof', 'RequiredCellSatisfied',
    'CellContractSatisfied', 'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveQualification',
    'CpuExecution', 'BoardExecution', 'ProducerCompilersReexecuted', 'OsProcessTraceVerified',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence')
FACTS = ('OriginalDisassembliesCollected', 'OriginalCensusReplayed', 'ImmutableInputsConsumed',
         'InputClosureVerified', 'OutputSealVerified')
PROOF = dict(Status='SYNTHETIC-ORIGINAL-CENSUS', Roles=['Final', 'Machine'],
             Qualification=False, RequiredCellsSatisfied=0)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('synthetic duplicate key')
        result[key] = value
    return result


class Model:
    """A few TEMP files and a two-command stand-in for the managed session."""
    def __init__(self, case):
        temp = tempfile.TemporaryDirectory(prefix='os-normal-attempt-synthetic-')
        case.addCleanup(temp.cleanup)
        self.root, self.case = Path(temp.name), case
        self.output, self.native_root, self.batch_root = (self.root / name for name in ('output', 'native', 'batch'))
        self.events, self.hashes, self.identities = [], {}, {}
        self.fault, self.inside, self.reader_entries, self.reader_exits = None, False, 0, 0
        self.ordinary, self.final, self.worker, self.tool = (self.native_root / name for name in
            ('ordinary.elf', 'emit.elf', 'emit.elf.ltrans0.ltrans.o', 'objdump.exe'))
        for path in (self.ordinary, self.final, self.worker, self.tool):
            self.put(path, ('SYNTHETIC NOT ELF OR EXECUTABLE: ' + path.name).encode('ascii'))
        self.native = dict(Sources=[], Links=[dict(Kind='ordinary', Path=str(self.ordinary)),
            dict(Kind='emit-relocs', Path=str(self.final), Machine=str(self.worker))])
        self.batch = dict(Status='BUILT-PENDING-READER', ToolInvocations=134,
            IsolationDeferredReader=dict(Inputs=[dict(Role=role, Path=str(path), Sha256=sha(path.read_bytes()))
                for role, path in (('OriginalEmitELF', self.final), ('OriginalMachine', self.worker))]))
        self.put(self.native_root / 'results.json', encoded(self.native))
        self.put(self.batch_root / 'results.json', encoded(self.batch))
        inputs = (self.ordinary, self.final, self.worker, self.tool,
                  self.native_root / 'results.json', self.batch_root / 'results.json')
        self.original_bytes = {path: path.read_bytes() for path in inputs}
        self.hashes.update({path: sha(raw) for path, raw in self.original_bytes.items()})
        self.identities.update({path: self.physical(path) for path in inputs})
        # The real batch admission owns tool authentication; run must explicitly add its reader role.
        self.roles = {path: digest for path, digest in self.hashes.items() if path != self.tool}
        self.witness = SimpleNamespace(output=self.output, buffers={}, identities=self.identities,
            _physical=self.physical, api=SimpleNamespace(regular=self.regular),
            watch=SimpleNamespace(read=self.read, hashes=self.hashes),
            replay_api=SimpleNamespace(relative_name=self.relative_name),
            groups=dict(Native=dict(Root=self.native_root, Result=self.native,
                ReceiptSha256=self.hashes[self.native_root / 'results.json'],
                Artifacts={path.relative_to(self.native_root).as_posix(): digest
                    for path, digest in self.hashes.items() if path.is_relative_to(self.native_root)})))
        self.witness.close = Mock(side_effect=self.close)
        self.suite = SimpleNamespace(output=self.output, tools=dict(objdump=self.tool), commands=[],
            expected={}, _started=False, report={})
        self.suite.start = Mock(side_effect=self.start)
        self.suite.command = Mock(side_effect=self.command)
        self.suite.write_input = self.write_input
        self.suite.verify_objects = Mock(side_effect=self.close)
        self.suite._verify_outputs = Mock(side_effect=self.verify_outputs)
        self.normal = SimpleNamespace(inspect=Mock(side_effect=self.inspect), require_result=Mock(side_effect=self.require_proof))
        self.facade = SimpleNamespace(retain_identity=machine.retain_identity, immutable_view=machine.immutable_view,
            admit_batch=Mock(side_effect=self.admit))
        self.helpers = dict(machine=self.facade, guard=guard, normal=self.normal,
            session=SimpleNamespace(suite_type=lambda utility, lto: self.construct), utility=object(), lto=object())
        self.runner = SimpleNamespace(base_report=lambda witness: self.base_report(), reader=self.reader,
            seal=Mock(side_effect=self.seal), revoke=Mock(side_effect=self.revoke), recover=Mock(side_effect=self.recover))
        self.environment = dict(Witness=self.witness, HelperPlans=builder.PINS,
            Modules=dict(capture=SimpleNamespace(PINS=dict(api=('tools/synthetic/transport.py', 'A' * 64)))))
        self.args = SimpleNamespace(batch_receipt_sha256=self.hashes[self.batch_root / 'results.json'],
                                   batch_artifacts_sha256='B' * 64)

    @staticmethod
    def physical(path):
        value = path.lstat()
        return value.st_dev, value.st_ino, value.st_nlink

    @staticmethod
    def relative_name(name):
        if type(name) is not str or not name or '\\' in name or ':' in name or any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError('synthetic unsafe member')
        return name

    def put(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def regular(self, name):
        path = Path(name)
        if not path.is_absolute() or '..' in path.parts or not path.is_file():
            raise ValueError('synthetic nonregular role')
        return path

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes()
        digest = sha(raw)
        if (expected is not None and digest != expected) or (path in self.hashes and self.hashes[path] != digest):
            raise ValueError('synthetic byte drift')
        self.hashes[path] = digest
        return raw

    def close(self):
        if self.fault == 'closing-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        if self.fault == 'close':
            raise ValueError('synthetic closing failure')
        for path, digest in list(self.hashes.items()):
            self.read(path, digest)
            if path in self.identities and self.physical(path) != self.identities[path]:
                raise ValueError('synthetic physical drift')

    def base_report(self):
        return dict(Status='FAIL', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            RequiredCellCount=2774, RequiredCellsSatisfied=0, ToolInvocations=0, CompilerInvocations=0,
            Error=None, PrimaryError=None, ClosingErrors=[], **dict.fromkeys(FACTS, False),
            **dict.fromkeys(NONCLAIMS, False))

    def admit(self, *args):
        self.events.append('admit')
        if self.fault == 'admission':
            raise ValueError('synthetic admission failure')
        for root in (self.batch_root, self.native_root):
            if self.witness.output.is_relative_to(root) or root.is_relative_to(self.witness.output):
                raise ValueError('synthetic output overlap')
        return self.batch_root, copy.deepcopy(self.batch), dict(self.roles)

    def construct(self, environment, helpers, buffers):
        self.case.assertIs(environment, self.environment)
        self.case.assertIs(helpers, self.helpers)
        self.events.append('construct')
        return self.suite

    def start(self):
        self.suite.output.mkdir(exist_ok=False)
        self.suite._started = True
        info = self.output.lstat()
        self.suite.output_identity = info.st_dev, info.st_ino
        self.write_input('results.json', encoded(self.suite.report))
        self.write_input('commands.json', encoded([]))

    def write_input(self, name, raw):
        self.relative_name(name)
        path = self.output / name
        self.put(path, raw)
        self.suite.expected[name] = sha(raw)
        return path

    def journals(self):
        for index, row in enumerate(self.suite.commands):
            self.write_input('commands/%03d.json' % index, encoded(row))
        self.write_input('commands.json', encoded(self.suite.commands))

    def command(self, argv, label):
        index = len(self.suite.commands)
        if self.inside or index >= 2:
            raise AssertionError('inspection escaped two-command collection')
        self.events.append('tool' + str(index))
        stdout, stderr = ('SYNTHETIC zero-inclusive dump ' + str(index)).encode('ascii'), b''
        if self.fault == ('empty', index):
            stdout = b''
        if self.fault == ('stderr', index):
            stderr = b'synthetic diagnostic'
        prefix = 'commands/%03d' % index
        row = dict(Label=label, Argv=list(argv), Cwd=str(self.output), State='TERMINAL', Status='PASS',
            Exit=0, ExpectedExit=0, TimedOut=False, Error=None, JournalErrors=[], Seconds=0.01,
            Stdout=prefix + '.stdout', Stderr=prefix + '.stderr', StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
        self.suite.commands.append(row)
        self.write_input(row['Stdout'], stdout)
        self.write_input(row['Stderr'], stderr)
        self.journals()
        if self.fault in (('exit', index), ('timeout', index)):
            raise ValueError('synthetic managed tool failure')
        return SimpleNamespace(stdout=stdout, stderr=stderr)

    def targets(self):
        return subject.original_targets(self.witness, self.batch, self.roles, machine)

    def collected(self):
        targets = self.targets()
        self.start()
        tool, records = subject.collect(self.suite, self.witness, self.helpers, targets)
        return tool, targets, records

    def validate(self, tool, targets, records):
        return subject.validate_inspections(self.output, tool, targets, records, self.suite.commands,
                                            lambda path: Path(path).read_bytes(), guard._same)

    def require_proof(self, proof):
        guard._same(proof, PROOF, 'synthetic normal proof')

    def inspect(self, batch, native, root, core, helpers, read, dumps):
        self.case.assertTrue(self.inside)
        self.case.assertEqual((batch, native, root), (self.batch, self.native, self.batch_root))
        self.case.assertEqual(set(helpers), {'census', 'policy', 'port_runner', 'guard'})
        self.case.assertEqual(set(dumps), {'Final', 'Machine'})
        for role, path in (('Final', self.final), ('Machine', self.worker)):
            self.case.assertEqual(read(path), self.original_bytes[path])
            self.case.assertEqual(read(dumps[role][0]), dumps[role][1])
        if self.fault == 'census':
            raise ValueError('synthetic census failure')
        if self.fault == 'reader-escape':
            read(self.root / 'not-admitted.bin')
        if self.fault == 'reader-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        return copy.deepcopy(PROOF)

    @contextmanager
    def reader(self, environment, roles):
        if self.fault == 'reader-enter-process':
            import subprocess
            subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
        self.case.assertEqual(len(self.suite.commands), 2)
        paths = list(roles['OriginalCensus'].values())
        self.case.assertIn(self.tool, paths)
        snapshot = {path: self.read(path) for path in paths}
        if self.fault == 'immutable-receipt':
            snapshot[self.batch_root / 'results.json'] = encoded(dict(Foreign=True))
        self.reader_entries += 1
        self.events.append('reader-enter')
        self.inside = True
        def read(path):
            if path not in snapshot:
                raise ValueError('synthetic immutable read escaped roles')
            return snapshot[path]
        try:
            with patch.object(Path, 'read_bytes', read), \
                    patch.object(Path, 'write_bytes', side_effect=AssertionError('no reader writes')), \
                    patch.object(Path, 'stat', side_effect=AssertionError('no reader stat')), \
                    patch.object(Path, 'lstat', side_effect=AssertionError('no reader lstat')), \
                    patch.object(Path, 'resolve', side_effect=AssertionError('no reader resolution')):
                yield object(), None, dict(SyntheticOnly=True)
        finally:
            self.inside = False
            self.reader_exits += 1
            self.events.append('reader-exit')
            if getattr(self, 'after_reader', None) is not None:
                self.after_reader()

    @contextmanager
    def frozen_modules(self):
        modules = dict(machine=self.facade, normal=self.normal, guard=guard,
            transport=SimpleNamespace(unique_object=unique_object), census=object(), policy=object(), port_runner=object())
        class Loader:
            def create_module(self, spec):
                return None

            def exec_module(self, module):
                value = modules[module.__name__.removeprefix('_os_normal_frozen_')]
                module.__dict__.update(vars(value) if hasattr(value, '__dict__') else {})
        def spec(name, location):
            return importlib.util.spec_from_loader(name, Loader())
        with patch.dict(sys.modules), patch.object(subject.importlib.util, 'spec_from_file_location', side_effect=spec):
            yield

    def verify_outputs(self):
        if self.fault == 'output':
            raise ValueError('synthetic output closure failure')
        actual = {path.relative_to(self.output).as_posix(): sha(path.read_bytes())
                  for path in self.output.rglob('*') if path.is_file()}
        if actual != self.suite.expected:
            raise ValueError('synthetic output mismatch')

    def seal(self, environment, report, expected):
        report.update(InputClosureVerified=True, OutputSealVerified=True)
        if self.fault == 'seal':
            raise OSError('synthetic seal failure')
        self.write_input('results.json', encoded(report))
        if self.fault == 'manifest':
            raise OSError('synthetic manifest failure')
        self.put(self.output / 'artifacts.json', encoded(dict(Artifacts=dict(expected))))

    def revoke(self, report, error):
        primary = report.get('PrimaryError') or str(error)
        report.update(Status='FAIL', Error=primary, PrimaryError=primary, InputClosureVerified=False,
                      OutputSealVerified=False, ImmutableInputsConsumed=False, RequiredCellsSatisfied=0)

    def recover(self, environment, report):
        (self.output / 'results.json').write_bytes(encoded(report))
        if self.fault == 'recovery':
            raise OSError('synthetic recovery failure')
        (self.output / 'artifacts.json').write_bytes(encoded(dict(Artifacts={})))

    def run(self):
        with self.frozen_modules(), redirect_stdout(io.StringIO()):
            return subject.run(self.args, self.runner, self.environment, builder, self.helpers, {}, {})

    def failure(self):
        report = json.loads((self.output / 'results.json').read_bytes())
        self.case.assertEqual(report['Status'], 'FAIL')
        for key in FACTS:
            self.case.assertIs(report[key], False)
        self.case.assertTrue(all(report[key] is False for key in NONCLAIMS))
        self.case.assertEqual(report['RequiredCellsSatisfied'], 0)
        return report


class DriverTests(unittest.TestCase):
    def test_exact_two_objdump_calls_preserve_original_batch_and_targets(self):
        model = Model(self)
        report = model.run()
        self.assertEqual(model.suite.command.call_args_list, [
            call([str(model.tool), '-drwC', '-z', str(path)], 'disassemble original ' + role)
            for role, path in (('Final', model.final), ('Machine', model.worker))])
        self.assertEqual((report['ToolInvocations'], report['CompilerInvocations']), (2, 0))
        self.assertTrue(report['LTO'])
        self.assertEqual(report['Status'], subject.PASS)
        self.assertEqual(model.original_bytes, {path: path.read_bytes() for path in model.original_bytes})
        self.assertEqual(report['OriginalTargets'], model.targets())

    def test_original_targets_reject_native_isolation_and_physical_substitutions(self):
        for fault in ('native-order', 'isolated-path', 'duplicate-role', 'hash', 'role-map', 'physical'):
            model = Model(self)
            if fault == 'native-order':
                model.native['Links'].reverse()
            elif fault == 'isolated-path':
                model.batch['IsolationDeferredReader']['Inputs'][0]['Path'] = str(model.ordinary)
            elif fault == 'duplicate-role':
                model.batch['IsolationDeferredReader']['Inputs'].append(copy.deepcopy(model.batch['IsolationDeferredReader']['Inputs'][0]))
            elif fault == 'hash':
                model.batch['IsolationDeferredReader']['Inputs'][0]['Sha256'] = 'A' * 64
            elif fault == 'role-map':
                model.roles[model.final] = 'A' * 64
            else:
                model.identities[model.final] = (1, 999, 1)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                model.targets()
            model.suite.command.assert_not_called()

    def test_collection_plan_is_fresh_exact_and_bounded_to_two(self):
        for fault in ('short', 'reverse', 'duplicate', 'extra', 'not-fresh'):
            model = Model(self)
            targets = model.targets()
            model.start()
            if fault == 'short':
                targets.pop()
            elif fault == 'reverse':
                targets.reverse()
            elif fault == 'duplicate':
                targets[1] = copy.deepcopy(targets[0])
            elif fault == 'extra':
                targets.append(copy.deepcopy(targets[0]))
            else:
                model.suite.commands.append({})
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                subject.collect(model.suite, model.witness, model.helpers, targets)
            model.suite.command.assert_not_called()

    def test_terminal_journal_types_flags_cwd_and_two_command_limit(self):
        changes = (('Exit', False), ('ExpectedExit', 0.0), ('TimedOut', 0), ('State', 'ATTEMPT'),
            ('Status', 'FAIL'), ('Seconds', True), ('Seconds', float('inf')), ('Seconds', -1),
            ('JournalErrors', {}), ('Error', False), ('Cwd', 'foreign'), ('Label', 'foreign'),
            ('Argv', ['gcc', '-c']), ('Argv', ['objdump', '-drwC']), ('Argv', []))
        for key, bad in changes:
            model = Model(self)
            tool, targets, records = model.collected()
            model.suite.commands[0][key] = bad
            if key == 'Seconds' and bad == float('inf'):
                for index, row in enumerate(model.suite.commands):
                    model.put(model.output / ('commands/%03d.json' % index),
                        json.dumps(row).replace('Infinity', '1e999').encode('ascii'))
                model.put(model.output / 'commands.json',
                    json.dumps(model.suite.commands).replace('Infinity', '1e999').encode('ascii'))
            else:
                model.journals()
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                model.validate(tool, targets, records)
        for count in (1, 3):
            model = Model(self)
            tool, targets, records = model.collected()
            model.suite.commands[:] = model.suite.commands[:1] if count == 1 else model.suite.commands + [dict(model.suite.commands[0])]
            model.journals()
            with self.subTest(count=count), self.assertRaises(ValueError):
                model.validate(tool, targets, records)

    def test_journal_raw_stream_dump_tool_and_target_byte_bindings(self):
        for fault in ('aggregate', 'per-command', 'stdout', 'stderr', 'dump', 'tool', 'target', 'stream-name'):
            model = Model(self)
            tool, targets, records = model.collected()
            paths = dict(aggregate=model.output / 'commands.json', **{'per-command': model.output / 'commands/000.json'},
                stdout=model.output / 'commands/000.stdout', stderr=model.output / 'commands/000.stderr',
                dump=Path(records[0]['Path']), tool=model.tool, target=model.final)
            if fault == 'stream-name':
                model.suite.commands[0]['Stdout'] = '../foreign.stdout'
                model.journals()
            else:
                model.put(paths[fault], b'{}' if fault in ('aggregate', 'per-command') else b'changed bytes')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                model.validate(tool, targets, records)

    def test_inspection_record_binding_and_target_identity_types(self):
        for field, bad in (('CommandIndex', False), ('Role', 'Machine'), ('Sha256', 'A' * 64),
                           ('Path', 'relative.dis'), ('Tool', {}), ('Target', {})):
            model = Model(self)
            tool, targets, records = model.collected()
            records[0][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                model.validate(tool, targets, records)
        model = Model(self)
        tool, targets, records = model.collected()
        targets[0]['PhysicalIdentity'][0] = True
        with self.assertRaises(ValueError):
            model.validate(tool, targets, records)

    def test_duplicate_and_nonfinite_inspection_json_reject(self):
        for raw in (b'{"Exit":0,"Exit":1}', b'{"nested":{"a":1,"a":2}}', b'[NaN]', b'[Infinity]', b'[-Infinity]',
                    b'1e999', b'-1e999', b'{"nested":[{"Seconds":1e999}]}', b'{"nested":[-1e999]}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                subject.structured(raw)
        self.assertEqual(subject.structured(b'{"Exit":0}'), dict(Exit=0))
        self.assertEqual(subject.structured(b'{"Seconds":1.25e2}'), dict(Seconds=125.0))
        with self.assertRaises(ValueError):
            subject.structured('{"Exit":0}')

    def test_one_immutable_census_uses_originals_and_explicit_objdump_role(self):
        model = Model(self)
        model.run()
        self.assertEqual((model.reader_entries, model.reader_exits), (1, 1))
        model.normal.inspect.assert_called_once()
        self.assertEqual(model.events, ['admit', 'construct', 'tool0', 'tool1', 'reader-enter', 'reader-exit'])
        self.assertGreaterEqual(model.normal.require_result.call_count, 2)

    def test_immutable_receipt_escape_and_closing_faults_revoke(self):
        for fault in ('immutable-receipt', 'reader-escape', 'close', 'output'):
            model = Model(self)
            model.fault = fault
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                model.run()
            model.failure()
            self.assertEqual(model.suite.command.call_count, 2)
        for fault in ('reader-enter-process', 'reader-process', 'closing-process'):
            model = Model(self)
            model.fault = fault
            # A harmless outer spy proves replay installs its own blocker, not just the test runner's.
            with self.subTest(fault=fault), patch('subprocess.Popen', return_value=object()) as escape, \
                    self.assertRaisesRegex(AssertionError, 'immutable replay cannot start processes'):
                model.run()
            escape.assert_not_called()
            model.failure()
            self.assertEqual(model.suite.command.call_count, 2)

    def test_managed_tool_failure_empty_or_noisy_output_stops_without_retry(self):
        for index in (0, 1):
            for fault in ('exit', 'timeout', 'empty', 'stderr'):
                model = Model(self)
                model.fault = fault, index
                with self.subTest(index=index, fault=fault), self.assertRaises(ValueError):
                    model.run()
                self.assertEqual(model.suite.command.call_count, index + 1)
                self.assertEqual(model.reader_entries, 0)
                self.assertEqual(model.failure()['ToolInvocations'], index + 1)

    def test_result_scope_lto_facts_and_typed_separate_counters(self):
        model = Model(self)
        report = model.run()
        changes = [('Status', 'PASS'), ('Scope', 'whole-cell'), ('Mode', 'O2-lto'), ('Profile', 'CM4'),
            ('Linkage', 'archive'), ('LTO', 1), ('ToolInvocations', 134), ('ToolInvocations', 2.0),
            ('CompilerInvocations', False), ('CompilerInvocations', 2), ('RequiredCellCount', 2774.0),
            ('RequiredCellsSatisfied', False), ('Commands', []), ('OriginalDisassemblies', [])]
        changes += [(key, 1) for key in FACTS]
        for key, bad in changes:
            value = copy.deepcopy(report)
            value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_result(value, model.normal)

    def test_result_nonclaims_explicit_errors_and_leaf_validation(self):
        model = Model(self)
        report = model.run()
        for key in NONCLAIMS:
            for bad in (True, 0, None):
                value = copy.deepcopy(report)
                value[key] = bad
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    subject.require_result(value, model.normal)
        for key in ('Error', 'PrimaryError', 'ClosingErrors'):
            value = copy.deepcopy(report)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                subject.require_result(value, model.normal)
        value = copy.deepcopy(report)
        value['OriginalCensus'] = None
        with self.assertRaises(ValueError):
            subject.require_result(value, model.normal)

    def test_admission_and_preexisting_output_never_write_unowned_receipts(self):
        for fault in ('admission', 'preexisting', 'overlap'):
            model = Model(self)
            if fault == 'preexisting':
                model.output.mkdir()
                model.put(model.output / 'results.json', b'unrelated receipt')
            elif fault == 'overlap':
                model.witness.output = model.native_root / 'nested-output'
            else:
                model.fault = fault
            with self.subTest(fault=fault), self.assertRaises((ValueError, FileExistsError)):
                model.run()
            model.runner.recover.assert_not_called()
            model.suite.command.assert_not_called()
            if fault == 'preexisting':
                self.assertEqual((model.output / 'results.json').read_bytes(), b'unrelated receipt')
            else:
                self.assertFalse(model.output.exists())

    def test_census_failure_persists_only_owned_failed_zero_credit_result(self):
        model = Model(self)
        model.fault = 'census'
        with self.assertRaisesRegex(ValueError, 'synthetic census failure'):
            model.run()
        self.assertEqual(model.failure()['PrimaryError'], 'synthetic census failure')
        model.runner.recover.assert_called_once()
        self.assertEqual(model.suite.command.call_count, 2)

    def test_replaced_output_refuses_recovery_writes_and_preserves_primary(self):
        model = Model(self)
        primary = ValueError('synthetic census failure')
        def replace(*args):
            model.output.rename(model.root / 'retired-output')
            model.output.mkdir()
            model.put(model.output / 'marker', b'unrelated replacement')
            raise primary
        model.after_reader = replace
        with self.assertRaises(ValueError) as caught:
            model.run()
        self.assertIs(caught.exception, primary)
        self.assertEqual({path.name for path in model.output.iterdir()}, {'marker'})
        self.assertEqual((model.output / 'marker').read_bytes(), b'unrelated replacement')
        model.runner.recover.assert_not_called()
        self.assertTrue(any('identity changed' in value for value in model.suite.report['ClosingErrors']))

    def test_seal_manifest_and_secondary_recovery_failures_preserve_primary(self):
        for fault in ('seal', 'manifest', 'recovery'):
            model = Model(self)
            model.fault = fault
            if fault == 'recovery':
                model.normal.inspect.side_effect = ValueError('first census failure')
            with self.subTest(fault=fault), self.assertRaises((ValueError, OSError)) as caught:
                model.run()
            report = model.failure()
            self.assertEqual(report['PrimaryError'], str(caught.exception))
            if fault == 'recovery':
                self.assertTrue(any('synthetic recovery failure' in value for value in model.suite.report['ClosingErrors']))

    def test_summary_print_failure_revokes_already_sealed_owned_success(self):
        model = Model(self)
        primary = BrokenPipeError('synthetic summary failure')
        with patch('builtins.print', side_effect=primary), self.assertRaises(BrokenPipeError) as caught:
            model.run()
        self.assertIs(caught.exception, primary)
        model.runner.seal.assert_called_once()
        self.assertEqual(model.failure()['PrimaryError'], str(primary))
        model.runner.recover.assert_called_once()


class BootstrapTests(unittest.TestCase):
    @contextmanager
    def graph(self, *, bad=False, late=False):
        payload, digest = b'SYNTHETIC pinned module bytes', sha(b'SYNTHETIC pinned module bytes')
        row = lambda name: ('tools/synthetic/' + name + '.py', digest)
        pins = {name: (path, digest) for name, (path, _) in subject.PINS.items()}
        documents = {path: digest for path in subject.DOCUMENTS}
        batch = SimpleNamespace(METADATA=row('metadata'), PINS={name: row(name) for name in ('session', 'utility', 'lto', 'policy', 'workers', 'guard')}, _pins=builder._pins)
        metadata = SimpleNamespace(RUNNER_SHA256=digest, PINS=dict(native=row('native')),
            LEAF_PINS=dict(abi_controls=row('abi_controls')), DOCUMENTS={'tools/synthetic/builder.md': digest})
        runner = SimpleNamespace(PINS={name: row(name) for name in ('admission', 'legacy', 'capture')}, DOCUMENTS={})
        opening_rows = (row('builder'), batch.METADATA,
            ('tools/fixtures/cm3_os_lto_final_cell/runner.py', digest), *batch.PINS.values(),
            *metadata.PINS.values(), *metadata.LEAF_PINS.values(), *runner.PINS.values(), *metadata.DOCUMENTS.items())
        expected_opening = {str(ROOT / path): value for path, value in opening_rows}
        data = {ROOT / path: payload for path, _ in (*opening_rows, *pins.values(), *documents.items())}
        data[SOURCES[1]] = b'SYNTHETIC driver buffer'
        state = SimpleNamespace(enrolled={}, reads=[], constructed=False, witness=object())
        args = SimpleNamespace(SyntheticOnly=True)
        def construct(value):
            self.assertIs(value, args)
            state.constructed = True
            return state.witness
        constructor = Mock(side_effect=construct)
        def factory(legacy, capture, *, extra_sources):
            self.assertEqual(extra_sources, data)
            state.enrolled.update(extra_sources)
            return constructor
        state.factory = Mock(side_effect=factory)
        def read(path):
            if state.constructed:
                raise AssertionError('late physical bootstrap read')
            state.reads.append(path)
            raw = data[path]
            return b'wrong pinned bytes' if bad and path == ROOT / pins['normal'][0] else raw
        def load(name, path, raw):
            if name == '_os_normal_builder_metadata':
                return batch
            if name == '_os_normal_abi_metadata':
                return metadata
            if name == '_os_normal_reader_entry':
                return runner
            if name == '_os_normal_admission_admission':
                return SimpleNamespace(witness_type=state.factory)
            if name.startswith('_os_normal_bootstrap_'):
                self.assertEqual((ROOT / subject.BATCH[0]).read_bytes(), payload)
                if late:
                    (ROOT / 'tools/synthetic/unknown.py').read_bytes()
            return SimpleNamespace()
        with patch.object(subject, 'BATCH', row('builder')), patch.object(subject, 'PINS', pins), \
                patch.object(subject, 'DOCUMENTS', documents), patch.object(Path, 'read_bytes', read), \
                patch.object(subject, 'load', side_effect=load):
            yield state, args, expected_opening, constructor

    def test_all_sources_precede_constructor_and_exact_opening_uses_cached_bytes(self):
        with self.graph() as (state, args, expected, constructor):
            prepared = subject.prepare(args)
        self.assertEqual(len(prepared), 6)
        self.assertIs(prepared[1]['Witness'], state.witness)
        self.assertEqual(prepared[4], expected)
        self.assertEqual(prepared[5], state.enrolled)
        self.assertEqual(set(state.reads), set(state.enrolled))
        state.factory.assert_called_once()
        constructor.assert_called_once_with(args)

    def test_bad_pin_preadmission_and_unknown_late_helper_have_no_disk_fallback(self):
        with self.graph(bad=True) as (state, args, _, constructor), self.assertRaisesRegex(ValueError, 'source pin/'):
            subject.prepare(args)
        state.factory.assert_not_called()
        constructor.assert_not_called()
        with self.graph(late=True) as (state, args, _, constructor), self.assertRaisesRegex(ValueError, 'bootstrap helper outside'):
            subject.prepare(args)
        constructor.assert_called_once_with(args)


class CliTests(unittest.TestCase):
    def test_cli_required_arguments_dispatch_failures_and_process_boundaries(self):
        argv = [value for name in subject.ARGUMENTS for value in ('--' + name, 'SYNTHETIC')]
        with patch.object(subject, 'prepare') as prepare, redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            subject.main(['--batch-b', 'synthetic'])
        prepare.assert_not_called()
        for fault in (None, 'prepare', 'run', 'process', 'shell'):
            def prepare(args):
                if fault == 'prepare':
                    raise ValueError('synthetic prepare failure')
                if fault == 'process':
                    import subprocess
                    subprocess.Popen(['SYNTHETIC-NEVER-EXECUTED'])
                return (None,) * 6
            def run(*args):
                if fault == 'run':
                    raise ValueError('synthetic run failure')
                if fault == 'shell':
                    import os
                    os.system('SYNTHETIC-NEVER-EXECUTED')
            with self.subTest(fault=fault), patch.object(subject, 'prepare', side_effect=prepare), \
                    patch.object(subject, 'run', side_effect=run), redirect_stderr(io.StringIO()):
                self.assertEqual(subject.main(argv), 0 if fault is None else 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP output directory required')
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_NORMAL_ATTEMPT_DRIVER_CONTROLS_ONLY',
        Tests=0, ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticBootstrapGraph=True, BootstrapPinsOverridden=True,
        ActualCaptureAdmitted=False, ActualELFCensusExecuted=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('isolated unoptimized -I -S -B Python required')
        buffers = {path: path.read_bytes() for path in SOURCES}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        global subject, machine, builder, guard
        modules = []
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic tests cannot execute tools')), \
                patch('os.system', side_effect=AssertionError('synthetic tests cannot execute shell commands')):
            for path in SOURCES[1:]:
                module = ModuleType('_normal_driver_test_' + path.stem)
                module.__file__ = str(path)
                exec(compile(buffers[path], str(path), 'exec'), module.__dict__)
                modules.append(module)
            subject, machine, builder, guard = modules
            for path, digest in (subject.PINS['machine'], subject.BATCH, builder.PINS['guard']):
                if sha(buffers[ROOT / path]) != digest:
                    raise ValueError('published dependency authentication: ' + path)
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(case)
                                       for case in (DriverTests, BootstrapTests, CliTests))
            if suite.countTestCases() != METHODS:
                raise ValueError('exact implemented method count required: ' + str(suite.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for path, digest in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) != digest:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(SOURCES) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
