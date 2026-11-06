"""Synthetic session controls; fake tool files never execute."""
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
ROOT = HERE.parents[2]


def load(name, path, expected=None):
    raw = path.read_bytes()
    if expected is not None and hashlib.sha256(raw).hexdigest().upper() != expected:
        raise ValueError('fixed session helper required')
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


subject = load('_os_batch_session_subject', HERE / 'batch_session.py')
utility = load('_os_batch_session_utility', ROOT / 'tools/fixtures/cm0_final_cell/controls.py',
    '9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A')
lto = load('_os_batch_session_lto', ROOT / 'tools/fixtures/cm3_lto_abi_controls/controls.py',
    '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F')
api = load('_os_batch_session_api', ROOT / 'tools/freeze_replay.py',
    '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275')


class Watch:
    def __init__(self):
        self.closure = api.Closure()
        self.hashes = self.closure.hashes

    def read(self, path, expected=None):
        return self.closure.read(path, expected)

    def structured(self, path):
        return api.structured(self.read(path))

    def close(self):
        return self.closure.close()


class Fixture:
    def __init__(self, root):
        self.root, self.watch = root, Watch()
        seed, capture = root / 'seed', root / 'capture'
        output = root / 'output'
        self.write(capture / 'environment.json', b'{"PATH":"synthetic","TEMP":"unused"}\n')
        self.sources = []
        for index in range(9):
            source = self.write(seed / 'source' / ('source-%d.c' % index), b'synthetic source\n')
            obj = self.write(capture / 'objects' / ('source-%d.o' % index), b'synthetic IR/object\n')
            self.sources.append(dict(Source=str(source), Object=str(obj), ObjectSha256=self.watch.hashes[obj],
                CompileFlags=['-Os', '-flto'] if index < 8 else ['-Os'], SlimIR=index < 8))
        self.write(seed / 'artifacts.json', b'{"Artifacts":{}}\n')
        tools = {}
        for name in ('gcc', 'nm', 'objdump', 'readelf', 'ld'):
            tools[name] = self.write(capture / 'toolchain/bin' / ('arm-none-eabi-' + name + '.exe'),
                b'not an executable; no tool may run\n')
        plugin = self.write(capture / 'toolchain/lib/plugin.dll', b'not a real plugin\n')
        bootstrap = self.write(root / 'bootstrap.py', b'# synthetic enrolled helper\n')
        own = HERE / 'batch_session.py'
        self.buffers = {bootstrap: bootstrap.read_bytes(), own: self.watch.read(own)}
        self.record = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            Sources=self.sources, SeedBuild=str(seed), CapturedCompiler=str(tools['gcc']),
            LTOPlugin=dict(Path=str(plugin)), ResolvedWorkers=dict(ld=dict(Path=str(tools['ld']))),
            SourceInventorySha256='A' * 64,
            Links=[dict(Kind='ordinary', Path=str(capture / 'ordinary/image.elf'))])
        self.witness = SimpleNamespace(replay_api=api, api=SimpleNamespace(), output=output,
            watch=self.watch, buffers=self.buffers, report=dict(CurrentInventory={'Synthetic': True}),
            groups=dict(Native=dict(Result=self.record, Root=capture, Seed=SimpleNamespace(root=seed),
                ReceiptSha256='B' * 64, ManifestSha256='C' * 64)))
        recipes = SimpleNamespace(compile_flags=self.flags, link_recipe=self.link)
        self.process = SimpleNamespace(run=Mock(return_value=SimpleNamespace(stdout=b'synthetic stream\n',
            stderr=b'', returncode=0, timed_out=False, elapsed=0.0)))
        self.modules = dict(recipes=recipes, native=SimpleNamespace(), process=self.process)
        self.environment = dict(Witness=self.witness)

    def write(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.watch.read(path, subject.sha(raw))
        return path

    def flags(self, record, index):
        if record['Mode'] != 'Os-lto' or '-Os' not in record['Sources'][index]['CompileFlags']:
            raise ValueError('synthetic Os flags guard')
        return list(record['Sources'][index]['CompileFlags'])

    def link(self, record, objects):
        return [record['CapturedCompiler'], '-Os', '-flto', *(str(path) for path in objects),
            '-o', record['Links'][0]['Path']]

    def session(self):
        return subject.suite_type(utility, lto)(self.environment, self.modules, self.buffers)


def terminal(**changes):
    return dict(State='TERMINAL', Status='PASS', Exit=0, ExpectedExit=0, TimedOut=False, **changes)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cm3-os-session-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name))

    def test_constructor_uses_os_model_without_o2_constructor_or_recipe(self):
        with patch.object(utility.Suite, '__init__', side_effect=AssertionError('ordinary ctor forbidden')), \
                patch.object(lto, 'link_recipe', side_effect=AssertionError('O2 recipe forbidden')):
            session = self.fixture.session()
        self.assertEqual(session.report['Mode'], 'Os-lto')
        self.assertEqual(session.report['Scope'], subject.SCOPE)
        self.assertFalse(session.output.exists())
        self.assertEqual(session.commands, [])
        self.assertIs(session.report['RequiredCellSatisfied'], False)
        self.assertEqual(session.report['RequiredCellsSatisfied'], 0)
        self.fixture.process.run.assert_not_called()

    def test_constructor_rejects_foreign_mode_missing_object_or_unenrolled_source(self):
        original = self.fixture.record['Mode']
        self.fixture.record['Mode'] = 'O2-lto'
        with self.assertRaisesRegex(ValueError, 'Os flags'):
            self.fixture.session()
        self.fixture.record['Mode'] = original
        self.fixture.sources[1]['Object'] = self.fixture.sources[0]['Object']
        with self.assertRaisesRegex(ValueError, 'distinct'):
            self.fixture.session()

    def test_bootstrap_must_already_belong_to_closed_capture_buffers(self):
        self.fixture.buffers.clear()
        with self.assertRaisesRegex(ValueError, 'bootstrap buffers'):
            self.fixture.session()
        self.assertFalse(self.fixture.witness.output.exists())

    def test_start_captures_sources_and_uses_own_lifecycle(self):
        session = self.fixture.session()
        session.start()
        self.assertTrue((session.output / 'tmp').is_dir())
        self.assertEqual(len(session.report['CapturedSources']), 2)
        self.assertEqual(json.loads((session.output / 'results.json').read_bytes())['Mode'], 'Os-lto')
        self.assertTrue(session.environment['TEMP'].startswith(str(session.output)))
        with self.assertRaises(ValueError):
            session.start()
        self.fixture.process.run.assert_not_called()

    def test_frozen_mode_specific_drivers_and_finish_are_explicitly_forbidden(self):
        session = self.fixture.session()
        for method in (session.finish, session.run_link_controls):
            with self.subTest(method=method.__name__), self.assertRaisesRegex(ValueError, 'Os batch must'):
                method()
        self.fixture.process.run.assert_not_called()

    def test_phase_ranges_are_ordered_exact_and_never_credit_a_cell(self):
        session = self.fixture.session().start()
        budgets = (41, 12, 45, 36)
        for phase, count in zip(subject.PHASES, budgets):
            session.begin_phase(phase)
            with self.assertRaises(ValueError):
                session.begin_phase(phase)
            session.commands.extend(terminal() for _ in range(count))
            session.end_phase()
        self.assertEqual([(row['First'], row['Stop']) for row in session.phases],
            [(0, 41), (41, 53), (53, 98), (98, 134)])
        self.assertEqual(session.report['Status'], 'FAIL')
        self.assertIs(session.report['CellContractSatisfied'], False)
        self.assertEqual(session.report['RequiredCellsSatisfied'], 0)
        with self.assertRaises(ValueError):
            session.begin_phase('ABIControls')

    def test_phase_rejects_wrong_order_short_or_nonterminal_or_boolean_exit(self):
        session = self.fixture.session().start()
        with self.assertRaises(ValueError):
            session.begin_phase('Isolation')
        session.begin_phase('ABIControls')
        session.commands = [terminal() for _ in range(40)]
        with self.assertRaises(ValueError):
            session.end_phase()
        session.commands.append(terminal())
        for changes in (dict(State='ATTEMPT'), dict(Status='FAIL'), dict(Exit=False),
                        dict(ExpectedExit=True), dict(TimedOut=True), dict(JournalErrors=['fault'])):
            original = dict(session.commands[0])
            session.commands[0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                session.end_phase()
            session.commands[0] = original
        session.end_phase()

    def test_managed_command_records_attempt_terminal_and_streams_without_real_tools(self):
        session = self.fixture.session().start()
        with patch('subprocess.Popen', side_effect=AssertionError('no actual child')):
            result = session.command([str(session.tools['gcc']), '--version'], 'synthetic compiler version')
        self.fixture.process.run.assert_called_once()
        self.assertEqual(result.stdout, b'synthetic stream\n')
        row = session.commands[0]
        self.assertEqual((row['State'], row['Status'], row['Exit']), ('TERMINAL', 'PASS', 0))
        self.assertEqual((session.output / row['Stdout']).read_bytes(), result.stdout)
        self.assertEqual(row['StdoutSha256'], subject.sha(result.stdout))

    def test_changed_original_object_is_caught_before_managed_process(self):
        session = self.fixture.session().start()
        session.objects[0].write_bytes(b'drift')
        with self.assertRaises(ValueError):
            session.command([str(session.tools['gcc']), '--version'], 'never launched')
        self.fixture.process.run.assert_not_called()

    def test_timeout_preserves_terminal_nonpass_without_retry(self):
        session = self.fixture.session().start()
        self.fixture.process.run.return_value = SimpleNamespace(stdout=b'partial', stderr=b'timeout',
            returncode=1, timed_out=True, elapsed=1.0)
        with self.assertRaises(ValueError):
            session.command([str(session.tools['gcc']), '--version'], 'synthetic timeout')
        self.fixture.process.run.assert_called_once()
        self.assertEqual(session.commands[0]['State'], 'TERMINAL')
        self.assertEqual(session.commands[0]['Status'], 'FAIL')
        self.assertTrue(session.commands[0]['TimedOut'])


if __name__ == '__main__':
    with patch('subprocess.Popen', side_effect=AssertionError('synthetic suite cannot spawn')), \
            patch('os.system', side_effect=AssertionError('synthetic suite cannot execute shell commands')):
        unittest.main(verbosity=2)
