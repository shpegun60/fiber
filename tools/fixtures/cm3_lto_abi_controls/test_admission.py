"""Synthetic LTO recipe, Suite admission and orchestration controls only."""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'controls.py'
FILES = (Path(__file__).resolve(), SUBJECT, HERE / 'CONTRACT.md')
EXPECTED_METHODS = 17
CONTROL_NAMES = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor',
                 'duplicate-svc', 'duplicate-pendsv')
PROBE_NAMES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
SOURCE_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
buffers = {}
subject = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def same(actual, expected, message):
    if encoded(actual) != encoded(expected):
        raise ValueError('synthetic binding: ' + message)


def stable(path):
    return Path(os.path.abspath(path))


def setUpModule():
    global buffers, subject
    if not buffers:
        buffers = {path: path.read_bytes() for path in FILES}
    spec = importlib.util.spec_from_file_location('_lto_abi_controls_admission_subject', SUBJECT)
    subject = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = subject
    exec(compile(buffers[SUBJECT], str(SUBJECT), 'exec'), subject.__dict__)


class Watch:
    def __init__(self, fixture):
        self.fixture, self.hashes = fixture, {}

    def read(self, path, expected=None):
        path = stable(path)
        raw = self.fixture.memory[path]
        value = sha(raw)
        if expected is not None and expected != value:
            raise ValueError('synthetic expected hash mismatch')
        if path in self.hashes and self.hashes[path] != value:
            raise ValueError('synthetic input drift')
        self.hashes[path] = value
        return raw

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected))

    def close(self):
        if self.fixture.fail_close:
            raise ValueError('synthetic closing refusal')
        for path, value in tuple(self.hashes.items()):
            self.read(path, value)


class Fixture:
    """Invented metadata and in-memory files; no real admission/ELF semantics."""
    def __init__(self):
        self.root = stable(Path(tempfile.gettempdir()) / ('lto-abi-admission-virtual-' + uuid.uuid4().hex))
        self.capture, self.base, self.output = (self.root / name for name in ('capture', 'seed', 'output'))
        self.memory, self.events, self.fail_close = dict(buffers), [], False
        self.sources = dict(buffers)
        self.args = SimpleNamespace(capture_build=str(self.capture), capture_receipt_sha256='A' * 64,
            capture_artifacts_sha256='B' * 64, inventory=str(self.root / 'inventory'),
            inventory_receipt_sha256='C' * 64, inventory_artifacts_sha256='D' * 64, output_dir=str(self.output))
        self.watch = Watch(self)
        self.rows, self.objects = [], []
        cpu = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2']
        for index in range(9):
            source = self.base / 'source' / ('unit-%d.' % index + ('S' if index == 8 else 'c'))
            obj = self.capture / 'objects' / ('%02d-unit.o' % index)
            self.memory[obj] = ('invented object %d, not an ELF' % index).encode('ascii')
            self.watch.read(obj)
            self.rows.append(dict(Source=str(source), SourceSha256=sha(b'invented source'), Object=str(obj),
                ObjectSha256=sha(self.memory[obj]), SlimIR=index != 8,
                CompileFlags=list(cpu) if index == 8 else cpu + ['-flto', '-fno-fat-lto-objects']))
            self.objects.append(obj)
        tool_root = self.capture / 'toolchain'
        self.tools = {name: tool_root / 'bin' / ('arm-none-eabi-' + name + '.exe')
                      for name in ('gcc', 'nm', 'objdump', 'readelf', 'ld')}
        self.plugin = tool_root / 'libexec/liblto_plugin.dll'
        for path in (*self.tools.values(), self.plugin):
            self.memory[path] = ('invented tool ' + path.name).encode('ascii')
            self.watch.read(path)
        original = self.capture / 'ordinary/image.elf'
        argv = [str(self.tools['gcc']), *cpu, '-flto', '-flto-partition=one', '-save-temps=obj', '-v',
            '-Wl,-plugin-opt=-save-temps', '-nostdlib', '-Wl,--gc-sections,--no-undefined,--build-id=none',
            '-T', str(self.base / 'source/link.ld'), *(str(path) for path in self.objects),
            '-Wl,-Map=' + str(self.capture / 'ordinary/image.map'), '-o', str(original)]
        self.result = dict(Profile='CM3', Mode='O2-lto', Linkage='direct', LTO=True,
            SeedBuild=str(self.base), SourceInventorySha256=SOURCE_SHA, Sources=self.rows,
            CapturedCompiler=str(self.tools['gcc']), ResolvedWorkers=dict(ld=dict(Path=str(self.tools['ld']))),
            LTOPlugin=dict(Path=str(self.plugin)), Commands=[dict(Label='link ordinary', Argv=argv)],
            Links=[dict(Kind='ordinary', Path=str(original))])
        self.memory[self.base / 'artifacts.json'] = encoded(dict(Artifacts={}))
        self.memory[self.capture / 'environment.json'] = encoded(dict(PATH='synthetic captured tools',
            TEMP=str(self.capture / 'tmp'), TMP=str(self.capture / 'tmp')))
        self.api = SimpleNamespace(checked_path=self.checked, files_under=self.files_under, same=same)
        self.sections = [dict(Index=0, Name='', Size=0, Flags=''),
            dict(Index=1, Name='.gnu.lto_example', Size=4, Flags='E'), dict(Index=2, Name='.text', Size=0, Flags='AX')]
        self.transport = SimpleNamespace(require_elf32le=lambda raw: dict(SectionCount=3),
                                         section_records=lambda text: copy.deepcopy(self.sections))
        self.admitted = SimpleNamespace(replay_api=self.api, watch=self.watch, root=self.capture,
            authority=SimpleNamespace(result=self.result), api=self.transport, buffers={},
            report=dict(CurrentInventory=dict(Build=str(self.root / 'inventory'), ReceiptSha256='C' * 64,
                ArtifactsSha256='D' * 64), SeedAuthority=dict(Build=str(self.base), ReceiptSha256='E' * 64,
                ArtifactsSha256='F' * 64), CurrentCaptureProducer=dict(Path='synthetic/capture.py',
                Sha256='1' * 64), CommandsReconstructed=57, Interpreter=dict(Synthetic=True)),
            identity=lambda path: dict(Device=1, Inode=1, Links=1, Size=len(self.memory[stable(path)])))
        fixture = self

        class UtilitySuite:
            def __init__(self, *args, **kwargs):
                raise AssertionError('qualified ordinary constructor must not run')

            def verify_objects(self):
                for row in self.sources:
                    self.watch.read(row['Object'], row['ObjectSha256'])

            def _failure(self, error):
                fixture.events.append(('failure-write', copy.deepcopy(self.report)))
                self.report.update(Status='FAIL', Error=str(error), InputClosureVerified=False, OutputSealVerified=False)
                self._save('results.json', self.report)

            def _save(self, name, value):
                return self._write(name, encoded(value))

            def _write(self, name, raw):
                path = self.output / name
                fixture.memory[path] = raw
                self.expected[name] = sha(raw)
                return path

            def _verify_outputs(self):
                for name, value in self.expected.items():
                    if sha(fixture.memory[self.output / name]) != value:
                        raise ValueError('synthetic generated output drift')

            def record_output(self, path, *, required=True):
                path = stable(path)
                value = sha(fixture.memory[path])
                self.expected[path.relative_to(self.output).as_posix()] = value
                return dict(Path=str(path), Sha256=value)

            def command(self, argv, label, expected_failure=False):
                fixture.events.append(('mock-command', label))
                return SimpleNamespace(stdout=b'synthetic inspection stdout', stderr=b'', returncode=0,
                                       timed_out=False, elapsed=0)

            def _link(self, name, objects, expected_failure=False):
                elf = self.output / 'links' / name / 'image.elf'
                directory = elf.parent
                names = ('image.elf', 'image.map', 'image.elf.ltrans.out', 'image.elf.ltrans0.ltrans.args.0',
                    'image.elf.ltrans0.ltrans.o', 'image.elf.ltrans0.ltrans.s', 'image.elf.ltrans0.ltrans_args',
                    'image.elf.ltrans0.o', 'image.elf.ltrans_args', 'image.elf.res', 'image.elf.wpa.args.0')
                for item in names:
                    fixture.memory[directory / item] = ('synthetic link output ' + item).encode('ascii')
                fixture.wrapper_args = self.output / (''.join(elf.parts[1:]) + '.lto_wrapper_args')
                fixture.memory[fixture.wrapper_args] = b'synthetic actual-cwd wrapper arguments'
                self.record_output(elf)
                self.record_output(directory / 'image.map')
                return SimpleNamespace(returncode=0), elf, directory / 'image.map'

        self.utility = SimpleNamespace(Suite=UtilitySuite)
        self.modules = dict(native=SimpleNamespace(), process=SimpleNamespace(run=Mock(
            side_effect=AssertionError('real managed process forbidden in synthetic tests'))),
            plan=SimpleNamespace(terminal_success=lambda rows: bool(rows)), utility=self.utility)

    def checked(self, value, *, directory=False, fresh=False):
        path = stable(value)
        if fresh:
            if path in self.memory or path == self.base:
                raise ValueError('synthetic fresh path')
        elif directory:
            if path not in (self.base, self.output):
                raise ValueError('synthetic admitted source directory')
        elif path not in self.memory:
            raise ValueError('synthetic admitted file')
        return path

    def files_under(self, root):
        root = stable(root)
        return {path.relative_to(root).as_posix(): path for path in self.memory if path.is_relative_to(root)}

    def construct(self):
        return subject.suite_type(self.utility)(self.args, self.admitted, self.modules, self.sources)

    @contextlib.contextmanager
    def io(self, *, fail_first=False, changed_identity=False, linked_destination=False):
        self.direct_writes = []
        failed = False
        def write(path, raw):
            nonlocal failed
            path = stable(path)
            self.direct_writes.append(path)
            if fail_first and path == self.output / 'results.json' and not failed:
                failed = True
                raise OSError('synthetic first FAIL write refused')
            self.memory[path] = raw
            return len(raw)
        def stat(path, **kwargs):
            path = stable(path)
            if path != self.output and path not in self.memory:
                raise FileNotFoundError(str(path))
            return SimpleNamespace(st_dev=7, st_ino=9 if changed_identity else 8,
                st_nlink=2 if linked_destination and path.name == 'results.json' else 1)
        with patch.object(Path, 'read_bytes', lambda path: self.memory[stable(path)]), \
                patch.object(Path, 'write_bytes', write), patch.object(Path, 'stat', stat), \
                patch.object(Path, 'exists', lambda path: stable(path) == self.output or stable(path) in self.memory):
            yield


def good_report():
    expected_nonzero = ('link stale-nvic-expectation', 'link stale-storage-application',
        'link stale-reverse-anchor', 'link duplicate-svc', 'link duplicate-pendsv',
        'compile probe slot-read', 'compile probe slot-write', 'compile probe slot-address')
    commands = [dict(Label=name, State='TERMINAL', Status='EXPECTED-NONZERO', Exit=1,
        ExpectedExit=1, TimedOut=False, JournalErrors=[]) for name in expected_nonzero]
    commands.extend(dict(Label='synthetic successful command %d' % index, State='TERMINAL', Status='PASS',
        Exit=0, ExpectedExit=0, TimedOut=False, JournalErrors=[]) for index in range(33))
    return dict(Status=subject.PASS, Scope=subject.SCOPE, Profile='CM3', Mode='O2-lto', Linkage='direct', LTO=True,
        Error=None, PrimaryError=None, ClosingErrors=[], InputClosureVerified=True, OutputSealVerified=True,
        PositiveLinkRevalidated=True, TypedDeclarationProbesValidated=True, FiveLinkControlsValidated=True,
        IntendedLinkRejects=5, CommandsReconstructed=57, Commands=commands,
        RequiredCellsSatisfied=0, RequiredCellSatisfied=False, RequiredCellCount=2774,
        Qualification=False, CellContractSatisfied=False, FullABIProof=False, FullSemanticABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, FinalReferenceParity=False, WholeSlotAccessIsolation=False,
        PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        HostedCIQualified=False, ArchiveExtraction=False,
        Controls=[dict(Name=name, Status='INTENDED-LINK-REJECTION-PASS', FinalImageAbsent=True) for name in CONTROL_NAMES],
        ABIProbes={name: dict(Classification=dict(AcceptedCompile=index < 2, ObjectAbsent=index >= 2),
                             **({'SlimIR': dict(SlimIR=True)} if index < 2 else {}))
                   for index, name in enumerate(PROBE_NAMES)})


class Controls(unittest.TestCase):
    def setUp(self):
        self.popen = self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('no processes in pure controls')))
        self.shell = self.enterContext(patch('os.system', side_effect=AssertionError('no shell in pure controls')))
        self.mkdir = self.enterContext(patch.object(Path, 'mkdir', side_effect=AssertionError('no constructor output creation')))

    def tearDown(self):
        self.popen.assert_not_called()
        self.shell.assert_not_called()

    def test_link_recipe_removes_only_verbose_and_keeps_genuine_lto(self):
        fixture = Fixture()
        raw = encoded(fixture.result)
        recipe = subject.link_recipe(fixture.result, fixture.objects)
        expected = [flag for flag in fixture.result['Commands'][0]['Argv'] if flag != '-v']
        self.assertEqual(recipe, expected)
        self.assertIn('-Wl,-plugin-opt=-save-temps', recipe)
        self.assertIn('-flto-partition=one', recipe)
        self.assertEqual(encoded(fixture.result), raw)

    def test_link_recipe_rejects_flags_cardinality_and_provider_order(self):
        for flag in ('-v', '-flto', '-flto-partition=one', '-save-temps=obj'):
            for change in ('missing', 'duplicate'):
                with self.subTest(flag=flag, change=change):
                    fixture = Fixture()
                    argv = fixture.result['Commands'][0]['Argv']
                    argv.remove(flag) if change == 'missing' else argv.append(flag)
                    with self.assertRaises(ValueError):
                        subject.link_recipe(fixture.result, fixture.objects)
        fixture = Fixture()
        with self.assertRaises(ValueError):
            subject.link_recipe(fixture.result, list(reversed(fixture.objects)))
        fixture.result['Commands'].append(copy.deepcopy(fixture.result['Commands'][0]))
        with self.assertRaises(ValueError):
            subject.link_recipe(fixture.result, fixture.objects)

    def test_suite_admits_lto_objects_with_separate_source_copy_authority(self):
        fixture = Fixture()
        raw = encoded(fixture.result)
        suite = fixture.construct()
        self.assertEqual(suite.base, fixture.base)
        self.assertEqual(suite.objects, tuple(fixture.objects))
        self.assertEqual(suite.sources, fixture.rows)
        self.assertIsNot(suite.sources, fixture.rows)
        self.assertEqual(suite.environment['TEMP'], str(fixture.output / 'tmp'))
        self.assertEqual(suite.environment['TMP'], str(fixture.output / 'tmp'))
        self.assertEqual(suite.report['Mode'], 'O2-lto')
        self.assertIs(suite.report['LTO'], True)
        self.assertEqual(suite.report['RequiredCellsSatisfied'], 0)
        self.assertFalse(suite._started)
        self.assertEqual(encoded(fixture.result), raw)
        self.mkdir.assert_not_called()

    def test_suite_rejects_provider_count_or_nonliteral_slim_roles(self):
        for change in ('short', 'long', 'c-native', 'startup-ir', 'integer-alias'):
            with self.subTest(change=change):
                fixture = Fixture()
                if change == 'short':
                    fixture.rows.pop()
                elif change == 'long':
                    fixture.rows.append(copy.deepcopy(fixture.rows[-1]))
                elif change == 'c-native':
                    fixture.rows[0]['SlimIR'] = False
                elif change == 'startup-ir':
                    fixture.rows[8]['SlimIR'] = True
                else:
                    fixture.rows[0]['SlimIR'] = 1
                with self.assertRaises(ValueError):
                    fixture.construct()
                self.mkdir.assert_not_called()

    def test_suite_rejects_unadmitted_tools_buffer_drift_and_output_overlap(self):
        for change in ('tool', 'buffer', 'overlap', 'close'):
            with self.subTest(change=change):
                fixture = Fixture()
                if change == 'tool':
                    fixture.watch.hashes.pop(fixture.tools['nm'])
                elif change == 'buffer':
                    fixture.sources[SUBJECT] += b'\n# unadmitted\n'
                elif change == 'overlap':
                    fixture.args.output_dir = str(fixture.capture / 'new-child')
                else:
                    fixture.fail_close = True
                with self.assertRaises(ValueError):
                    fixture.construct()
                self.mkdir.assert_not_called()

    def test_prepare_authenticates_all_buffers_before_admission(self):
        fixture = Fixture()
        paths = {name: fixture.root / (name + '.py') for name in ('admission', 'utility')}
        memory = {path: ('# synthetic ' + name).encode('ascii') for name, path in paths.items()}
        memory[SUBJECT] = buffers[SUBJECT]
        events = []
        admission = SimpleNamespace(prepare=Mock(return_value=(fixture.admitted, {})))
        utility = SimpleNamespace()
        def read(path):
            events.append(('read', stable(path)))
            return memory[stable(path)]
        def load(name, path, raw):
            self.assertEqual(raw, memory[stable(path)])
            self.assertTrue(all(('read', item) in events for item in paths.values()))
            events.append(('load', stable(path)))
            return admission if stable(path) == paths['admission'] else utility
        selected = Mock(return_value='synthetic-suite')
        with patch.object(subject, 'ROOT', fixture.root), \
                patch.object(subject, 'PINS', {name: (path.name, sha(memory[path])) for name, path in paths.items()}), \
                patch.object(subject, 'LOCAL_PINS', {}), patch.object(subject, 'BUFFER_PINS', {}), \
                patch.object(Path, 'read_bytes', read), \
                patch.object(subject, 'load', side_effect=load), patch.object(subject, 'suite_type', return_value=selected), \
                patch.object(sys, 'flags', SimpleNamespace(optimize=0, isolated=1, no_site=1)):
            suite, modules = subject.prepare(fixture.args)
        self.assertEqual(suite, 'synthetic-suite')
        admission.prepare.assert_called_once_with(fixture.args)
        self.assertIs(modules['utility'], utility)
        self.assertEqual(selected.call_args.args[:2], (fixture.args, fixture.admitted))

    def phase_suite(self, failure=None):
        fixture = Fixture()
        root = fixture.base / 'source'
        suite = SimpleNamespace(base=fixture.base, admitted=fixture.admitted, api=SimpleNamespace(checked_path=stable),
            bundle=dict(Artifacts={}), watch=SimpleNamespace(read=lambda path, *unused: b'synthetic admitted data'),
            report=dict(RequiredCellsSatisfied=0), events=[])
        suite.start = lambda: suite.events.append('start')
        def links():
            suite.events.append('links')
            suite.report.update(PositiveAuthority=dict(Synthetic=True), Controls=[], FiveLinkControlsValidated=True)
        suite.run_link_controls = links
        suite.inspect_ir = lambda path: dict(SlimIR=True)
        suite.write_input = lambda name, raw: suite.events.append(name)
        suite.finish = Mock(side_effect=lambda error=None: dict(Error=error, RequiredCellsSatisfied=0))
        def compile_probe(selected, name, probe):
            suite.events.append(name)
            if failure == name:
                raise ValueError('synthetic probe rejection')
            return dict(Object=str(fixture.output / (name + '.o')), Preprocessed=str(fixture.output / (name + '.i')))
        def providers(*args, **kwargs):
            suite.events.append('providers')
            if failure == 'providers':
                raise ValueError('synthetic provider admission rejection')
            return dict(Synthetic=True)
        modules = dict(abi=SimpleNamespace(inspect_provider_dependencies=providers,
            emit_probes=lambda: {name: dict(Synthetic=True) for name in PROBE_NAMES},
            inspect_preprocessed_attributes=lambda raw: dict(CanonicalHeaders=dict(
                forward=str(root / 'context/context_port_abi.h'), reverse=str(root / 'context/context_runtime_port_abi.h')))),
            probes=SimpleNamespace(compile_probe=compile_probe))
        return suite, modules

    def test_run_executes_fixed_phases_once_and_keeps_zero_credit(self):
        suite, modules = self.phase_suite()
        result = subject.run(suite, modules)
        self.assertEqual(suite.events, ['start', 'providers', 'links', *PROBE_NAMES, 'component-facts.json'])
        self.assertTrue(suite.report['TypedDeclarationProbesValidated'])
        suite.finish.assert_called_once_with(None)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_run_forwards_provider_or_probe_error_to_finish_without_retry(self):
        for failed in ('providers', 'slot_write.c'):
            with self.subTest(failed=failed):
                suite, modules = self.phase_suite(failed)
                result = subject.run(suite, modules)
                self.assertIsInstance(result['Error'], ValueError)
                suite.finish.assert_called_once()
                self.assertEqual(suite.events.count('start'), 1)
                self.assertLessEqual(suite.events.count(failed), 1)
                self.assertNotIn('component-facts.json', suite.events)

    def test_finish_error_revokes_phase_flags_before_failure_persistence(self):
        fixture = Fixture()
        suite = fixture.construct()
        suite.report.update(TypedDeclarationProbesValidated=True, FiveLinkControlsValidated=True)
        result = suite.finish(ValueError('synthetic primary'))
        writes = [row for event, row in fixture.events if event == 'failure-write']
        self.assertTrue(writes)
        self.assertTrue(all(row['TypedDeclarationProbesValidated'] is False
                            and row['FiveLinkControlsValidated'] is False for row in writes))
        self.assertEqual(result['Status'], 'FAIL')
        self.assertFalse(result['TypedDeclarationProbesValidated'])
        self.assertFalse(result['FiveLinkControlsValidated'])
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_finish_closing_fault_cannot_keep_success_flags(self):
        fixture = Fixture()
        suite = fixture.construct()
        suite._started = suite._controls_done = True
        suite.report.update(TypedDeclarationProbesValidated=True, FiveLinkControlsValidated=True, PositiveLinkRevalidated=True)
        suite.commands = [dict(Status='PASS')]
        fixture.fail_close = True
        result = suite.finish()
        self.assertEqual(result['Status'], 'FAIL')
        for name in ('TypedDeclarationProbesValidated', 'FiveLinkControlsValidated',
                     'InputClosureVerified', 'OutputSealVerified'):
            self.assertIs(result[name], False)

    def test_ir_section_table_must_cover_actual_header_count(self):
        fixture = Fixture()
        suite = fixture.construct()
        fixture.sections.pop()
        with self.assertRaises(ValueError):
            suite.inspect_ir(fixture.objects[0])

    def test_link_enrolls_actual_cwd_wrapper_args_not_only_link_directory(self):
        fixture = Fixture()
        suite = fixture.construct()
        with fixture.io():
            suite._link('positive', fixture.objects)
        self.assertIn(fixture.wrapper_args.relative_to(suite.output).as_posix(), suite.expected)

    def main_call(self, returned=None, error=None, *, hook_error=False, fail_first=False):
        fixture = Fixture()
        suite = fixture.construct()
        suite.report = good_report()
        suite._started, suite.output_identity = True, (7, 8)
        fixture.memory[fixture.output / 'results.json'] = subject.encoded(suite.report)
        fixture.memory[fixture.output / 'artifacts.json'] = subject.encoded(dict(Artifacts={
            'results.json': sha(fixture.memory[fixture.output / 'results.json'])}))
        if hook_error:
            suite._failure = Mock(side_effect=ValueError('synthetic delegated failure hook refused'))
        result = suite.report if returned is None else returned
        argv = [item for name, value in vars(fixture.args).items() for item in ('--' + name.replace('_', '-'), value)]
        with patch.object(subject, 'prepare', return_value=(suite, {})) as prepared, \
                patch.object(subject, 'run', return_value=result, side_effect=error) as run, \
                fixture.io(fail_first=fail_first), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = subject.main(argv)
        self.assertEqual(prepared.call_count, 1)
        self.assertEqual(run.call_count, 1)
        suite.test_fixture = fixture
        return code, suite

    def test_main_requires_complete_literal_zero_credit_phase_result(self):
        self.assertEqual(self.main_call()[0], 0)
        for field, value in (('Status', 'FAIL'), ('InputClosureVerified', False), ('OutputSealVerified', False),
                             ('TypedDeclarationProbesValidated', False), ('FiveLinkControlsValidated', False),
                             ('PositiveLinkRevalidated', False), ('RequiredCellsSatisfied', 1),
                             ('RequiredCellsSatisfied', False), ('RequiredCellCount', 2774.0),
                             ('CommandsReconstructed', True), ('Qualification', True)):
            with self.subTest(field=field, value=value):
                report = good_report()
                report[field] = value
                self.assertEqual(self.main_call(report)[0], 1)
        for change in ('command-count', 'nonzero-label', 'exit-bool', 'timedout', 'probe-object', 'final-present'):
            with self.subTest(change=change):
                report = good_report()
                if change == 'command-count':
                    report['Commands'].pop()
                elif change == 'nonzero-label':
                    report['Commands'][0]['Label'] = 'unrelated failure'
                elif change == 'exit-bool':
                    report['Commands'][0]['Exit'] = True
                elif change == 'timedout':
                    report['Commands'][0]['TimedOut'] = True
                elif change == 'probe-object':
                    report['ABIProbes']['slot_read.c']['Classification']['ObjectAbsent'] = False
                else:
                    report['Controls'][0]['FinalImageAbsent'] = False
                self.assertEqual(self.main_call(report)[0], 1)

    def test_main_escaped_failure_revokes_report_without_replaying(self):
        code, suite = self.main_call(error=ValueError('synthetic escaped finish failure'),
                                     hook_error=True, fail_first=True)
        self.assertEqual(code, 1)
        self.assertEqual(suite.report['Status'], 'FAIL')
        self.assertFalse(suite.report['TypedDeclarationProbesValidated'])
        self.assertFalse(suite.report['FiveLinkControlsValidated'])
        self.assertEqual(suite.report['RequiredCellsSatisfied'], 0)
        fixture = suite.test_fixture
        written = json.loads(fixture.memory[fixture.output / 'results.json'])
        self.assertEqual(written, suite.report)
        self.assertEqual(written['PrimaryError'], 'ValueError: synthetic escaped finish failure')
        self.assertEqual(len(written['ClosingErrors']), 2)
        self.assertIn('failure hook:', written['ClosingErrors'][0])
        self.assertIn('failure persistence 1:', written['ClosingErrors'][1])
        self.assertEqual(fixture.direct_writes.count(fixture.output / 'results.json'), 2)
        manifest = json.loads(fixture.memory[fixture.output / 'artifacts.json'])['Artifacts']
        self.assertEqual(manifest, {'results.json': sha(fixture.memory[fixture.output / 'results.json'])})

    def test_success_stdout_write_or_flush_failure_revokes_written_pass(self):
        for failed in ('write', 'flush'):
            with self.subTest(failed=failed):
                fixture = Fixture()
                suite = fixture.construct()
                suite.report = good_report()
                suite._started, suite.output_identity = True, (7, 8)
                receipt_path = fixture.output / 'results.json'
                manifest_path = fixture.output / 'artifacts.json'
                fixture.memory[receipt_path] = subject.encoded(suite.report)
                fixture.memory[manifest_path] = subject.encoded(dict(Artifacts={
                    'results.json': sha(fixture.memory[receipt_path])}))
                calls = []
                case = self

                class FailingStdout:
                    def write(self, text):
                        calls.append('write')
                        case.assertTrue(subject.succeeded(json.loads(fixture.memory[receipt_path])))
                        if failed == 'write':
                            raise BrokenPipeError('synthetic success stdout write refused')
                        return len(text)

                    def flush(self):
                        calls.append('flush')
                        case.assertTrue(subject.succeeded(json.loads(fixture.memory[receipt_path])))
                        raise OSError('synthetic success stdout flush refused')

                argv = [item for name, value in vars(fixture.args).items()
                        for item in ('--' + name.replace('_', '-'), value)]
                with patch.object(subject, 'prepare', return_value=(suite, {})) as prepared, \
                        patch.object(subject, 'run', return_value=suite.report) as run, \
                        patch.object(suite, 'command', side_effect=AssertionError('no process retry')) as command, \
                        fixture.io(), contextlib.redirect_stdout(FailingStdout()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    code = subject.main(argv)
                self.assertEqual(code, 1)
                self.assertEqual(prepared.call_count, 1)
                self.assertEqual(vars(prepared.call_args.args[0]), vars(fixture.args))
                run.assert_called_once_with(suite, {})
                command.assert_not_called()
                self.assertEqual(calls, ['write'] if failed == 'write' else ['write', 'write', 'flush'])
                written = json.loads(fixture.memory[receipt_path])
                self.assertEqual(written, suite.report)
                self.assertEqual(written['Status'], 'FAIL')
                for flag in ('TypedDeclarationProbesValidated', 'FiveLinkControlsValidated',
                             'InputClosureVerified', 'OutputSealVerified'):
                    self.assertIs(written[flag], False)
                self.assertIs(type(written['RequiredCellsSatisfied']), int)
                self.assertEqual(written['RequiredCellsSatisfied'], 0)
                message = ('BrokenPipeError' if failed == 'write' else 'OSError') + \
                    ': synthetic success stdout ' + failed + ' refused'
                self.assertEqual(written['PrimaryError'], message)
                self.assertEqual(written['Error'], 'synthetic success stdout ' + failed + ' refused')
                self.assertEqual(json.loads(fixture.memory[manifest_path])['Artifacts'],
                                 {'results.json': sha(fixture.memory[receipt_path])})

    def test_failure_persistence_rejects_replaced_output_and_linked_destination(self):
        for changed, linked in ((True, False), (False, True)):
            with self.subTest(changed=changed, linked=linked):
                fixture = Fixture()
                suite = fixture.construct()
                suite.report, suite.output_identity = good_report(), (7, 8)
                fixture.memory[fixture.output / 'results.json'] = b'prior synthetic PASS'
                with fixture.io(changed_identity=changed, linked_destination=linked):
                    with self.assertRaises(ValueError):
                        subject.persist_failure(suite)
                self.assertEqual(fixture.direct_writes, [])
                self.assertEqual(suite.report['Status'], 'FAIL')
                self.assertIs(suite.report['OutputSealVerified'], False)

    def test_reader_uses_lexical_aliases_and_restores_physical_hooks(self):
        fixture = Fixture()
        helper = fixture.base / 'loader.py'
        core = fixture.base / 'reader.py'
        package = fixture.base / 'python/elftools/__init__.py'
        binary = fixture.objects[0]
        fake_sources = {helper: b'# synthetic loader', core: b'# synthetic reader', package: b'# synthetic parser'}
        fixture.admitted.buffers = fake_sources
        fixture.admitted.base = SimpleNamespace(LOADER=helper, stable_path=stable)
        fixture.admitted.authority.core_path = core
        physical_resolve, physical_read = Path.resolve, Path.read_bytes
        events = []
        class Graph:
            def __init__(self, sources):
                self.sources = {path.resolve(): raw for path, raw in sources.items()}
                events.append('init')
            @contextlib.contextmanager
            def active(self):
                yield
            def load(self, name, path):
                self.sources[path.resolve()]
                events.append('load')
                return SimpleNamespace(Synthetic=True)
        def load(name, path, raw):
            self.assertEqual(raw, fake_sources[helper])
            return SimpleNamespace(FrozenSources=Graph)
        close = fixture.watch.close
        def physical_close():
            self.assertIs(Path.resolve, physical_resolve)
            events.append('physical-close')
            close()
        with patch.object(fixture.watch, 'close', physical_close), patch.object(subject, 'load', side_effect=load):
            with subject.reader(fixture.admitted, (binary,)) as (api, graph):
                self.assertTrue(api.Synthetic)
                self.assertEqual((binary.parent / 'unused/..' / binary.name).read_bytes(), fixture.memory[binary])
                self.assertEqual((core.parent / 'unused/..' / core.name).read_bytes(), fake_sources[core])
                with self.assertRaises(ValueError):
                    (fixture.root / 'not-admitted').read_bytes()
                with self.assertRaises(ValueError):
                    binary.resolve(strict=True)
        self.assertIs(Path.resolve, physical_resolve)
        self.assertIs(Path.read_bytes, physical_read)
        self.assertEqual(events, ['physical-close', 'init', 'load'])
        with patch.object(subject, 'load', side_effect=load):
            with self.assertRaisesRegex(ValueError, 'synthetic reader body refusal'):
                with subject.reader(fixture.admitted, (binary,)):
                    raise ValueError('synthetic reader body refusal')
        self.assertIs(Path.resolve, physical_resolve)
        self.assertIs(Path.read_bytes, physical_read)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir')
    args = parser.parse_args(argv)
    opening = {path: path.read_bytes() for path in FILES}
    global buffers
    buffers = dict(opening)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    drift = [str(path) for path, raw in opening.items() if path.read_bytes() != raw]
    passed = result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped and not drift
    receipt = dict(Status='PASS' if passed else 'FAIL',
        Scope='PURE_SYNTHETIC_CURRENT_CM3_O2_LTO_ABI_CONTROLS_ADMISSION_AND_LIFECYCLE_ONLY',
        Tests=result.testsRun, ExpectedTestMethods=EXPECTED_METHODS, Failures=len(result.failures), Errors=len(result.errors),
        Skipped=len(result.skipped), FailureDetails=[dict(Test=str(test), Detail=detail)
            for test, detail in result.failures + result.errors], SourceHashes={str(path): sha(raw) for path, raw in opening.items()},
        SourceDrift=drift, SourceClosureVerified=not drift, ClosingFilesVerified=len(opening), SyntheticInputs=True,
        AdmissionMocked=True, ProcessBoundaryMocked=True, ActualCaptureAdmitted=False, ActualELFTested=False,
        ActualParserExecuted=False, ToolInvocations=0, TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False,
        Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    if args.output_dir:
        output = Path(args.output_dir).resolve(strict=False)
        if output.exists() or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
            raise ValueError('fresh external test receipt directory required')
        output.mkdir(parents=True)
        (output / 'results.json').write_bytes((json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode('ascii'))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
