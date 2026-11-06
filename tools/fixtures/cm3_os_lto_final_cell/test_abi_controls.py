"""Pure build-orchestration fakes plus frozen diagnostic/probe predicates.

No actual compiler, ELF parser, capture, constructor or reader is executed.
Generated files and command results are synthetic and have no cell authority.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
PATHS = dict(subject=HERE / 'abi_controls.py', recipes=HERE / 'batch_recipes.py',
    plan=HERE.parent / 'ordinary_final_cell/controls.py',
    probes=HERE.parent / 'cm0_final_cell/components.py',
    diagnostics=HERE.parent / 'cm3_lto_abi_controls/diagnostics.py')
PINS = dict(recipes='C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B',
    plan='10F8203B7AA24502BDCA2274DA8C5B7A8763EF7630E8FE8350C64AC50699F18A',
    probes='16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7',
    diagnostics='0A1CD4EB14172C3E3FF1E5B05A733C7837404E7DD95C8D6953323EB26FEA250C')
METHODS = 12
LOADED = {}
SLOT = 'fiber_internal_runtime_current_context_slot'
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
PRIVATE = 'fiber_port_context_cohort_armv7m_example_g4_aapcs'
STORAGE = 'fiber_port_storage_cohort_arm_cm3_v999_r0'


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def os_facts(**extra):
    return dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, **extra)


class Watch:
    def __init__(self):
        self.hashes, self.close_calls, self.fail_close = {}, 0, False

    def read(self, path, expected=None):
        path = Path(path).resolve()
        raw = path.read_bytes()
        digest = sha(raw)
        if expected is not None and expected != digest:
            raise ValueError('synthetic expected input hash')
        if path in self.hashes and self.hashes[path] != digest:
            raise ValueError('synthetic input drift')
        self.hashes[path] = digest
        return raw

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise ValueError('synthetic physical close failure')
        for path, digest in self.hashes.items():
            if sha(path.read_bytes()) != digest:
                raise ValueError('synthetic input drift')


class FakeDeclarations:
    def __init__(self, suite, ordinary):
        self.suite, self.ordinary, self.calls = suite, ordinary, []
        self.bad_stage = self.bad_header = None

    def facts(self, stage, ordinary, **extra):
        if ordinary is not self.ordinary:
            raise AssertionError('explicit ordinary helper identity')
        self.calls.append(stage)
        record = os_facts(**extra)
        if self.bad_stage == stage:
            record['Mode'] = 'O2-lto'
        return record

    def inspect_provider_dependencies(self, sources, receipt, *, source_root, capture_root, ordinary):
        if not sources or receipt != b'{"synthetic":true}' or Path(source_root) != self.suite.base / 'source' \
                or Path(capture_root) != self.suite.capture:
            raise AssertionError('same synthetic capture/source authority')
        return self.facts('providers', ordinary, DeclaredProviderDependenciesBound=True,
                          Providers=[dict(ObjectIndex=index) for index in range(9)])

    def emit_probes(self, *, ordinary):
        self.facts('emit', ordinary)
        result = {}
        for name in ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c'):
            accepted = name in ('types.c', 'attributes.c')
            if accepted:
                raw = ('void synthetic_' + name[:-2] + '(void) {}\n').encode('ascii')
            else:
                parameters, statement = {
                    'slot_read.c': ('void', '(void)' + SLOT + ';'),
                    'slot_write.c': ('struct FiberContext *value', SLOT + ' = value;'),
                    'slot_address.c': ('void', '(void)&' + SLOT + ';'),
                }[name]
                raw = ('#include "context/context_port_abi.h"\n'
                       '#include "context/context_runtime_port_abi.h"\nvoid cm0_abi_' + name[:-2]
                       + '(' + parameters + ')\n{\n    ' + statement + '\n}\n').encode('ascii')
            result[name] = os_facts(Source=raw.decode('ascii'), SourceSha256=sha(raw),
                RequiredCFlags=['-std=gnu11', '-Werror=incompatible-pointer-types', '-Werror=attributes'],
                ExpectedCompile=accepted, DiagnosticIdentifier=None if accepted else SLOT)
            if self.bad_stage == 'probe':
                result[name]['Mode'] = 'O2-lto'
        return result

    def inspect_preprocessed_attributes(self, raw, *, ordinary):
        if raw != b'synthetic accepted CPP':
            raise AssertionError('same synthetic successful CPP bytes')
        root = self.suite.base / 'source/context'
        headers = dict(forward=str(root / 'context_port_abi.h'), reverse=str(root / 'context_runtime_port_abi.h'))
        if self.bad_header:
            headers['reverse'] = str(root / 'unrelated.h')
        return self.facts('cpp', ordinary, CanonicalHeaders=headers)


class FakeRecipes:
    def __init__(self, suite):
        self.suite = suite

    def require_capture_sources(self, result):
        if result is not self.suite.result or result['Mode'] != 'Os-lto':
            raise ValueError('synthetic capture admission')

    def compile_flags(self, result, index):
        return self.suite.sources[index]['CompileFlags'][:]

    def link_recipe(self, result, objects):
        if tuple(objects) != self.suite.objects:
            raise ValueError('synthetic objects')
        return self.suite.expected_link[:]

    def batch_plan(self):
        return LOADED['recipes'].batch_plan()


class FakeSuite:
    """Managed-tool/byte-provider fake, deliberately not an ELF authority."""
    def __init__(self, root):
        self.root, self.base, self.capture, self.output = root, root / 'seed', root / 'capture', root / 'out'
        self.output.mkdir()
        self.watch = Watch()
        self.api = SimpleNamespace(checked_path=lambda path: Path(path).resolve())
        self.tools = {name: root / ('fake-' + name + '.exe') for name in ('gcc', 'ld', 'readelf', 'nm')}
        self.plugin = root / 'fake-plugin.dll'
        self.sources, self.bundle, self.depmap = [], dict(Artifacts={}), {}
        for index, relative in enumerate(LOADED['recipes'].SOURCES):
            path = self.base / 'source' / relative
            self.put(path, ('synthetic source ' + relative).encode())
            digest = sha(path.read_bytes())
            self.bundle['Artifacts']['source/' + relative] = digest
            obj = self.capture / ('objects/%02d-%s.o' % (index, path.stem))
            self.put(obj, b'synthetic original IR ' + bytes([index]))
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os']
            if index != 8:
                flags += ['-flto', '-fno-fat-lto-objects']
            self.sources.append(dict(Source=str(path), SourceSha256=digest, Object=str(obj),
                ObjectSha256=sha(obj.read_bytes()), CompileFlags=flags))
        for name in ('context_port_abi.h', 'context_runtime_port_abi.h'):
            path = self.base / 'source/context' / name
            self.put(path, b'synthetic canonical header')
            self.bundle['Artifacts']['source/context/' + name] = sha(path.read_bytes())
        self.put(self.capture / 'results.json', b'{"synthetic":true}')
        self.original = self.capture / 'ordinary/image.elf'
        self.put(self.original, b'synthetic original load image')
        self.objects = tuple(Path(row['Object']) for row in self.sources)
        self.result = os_facts(Sources=self.sources, Links=[dict(Path=str(self.original))])
        self.expected_link = [str(self.tools['gcc']), '-Os', '-flto', *map(str, self.objects), '-o', str(self.original)]
        self.link_argv = self.expected_link[:]
        self.commands, self.phases, self.selected, self.saves = [], [], {}, []
        self._started, self._finished = True, False
        self.report = os_facts(Status='FAIL', RequiredCellsSatisfied=0, Controls=[], Compilations=[],
                               PrimaryError=None, ClosingErrors=[], Qualification=False)
        self.fail_compile = self.bad_diagnostic = self.bad_anchor = self.bad_command = self.fail_save = None
        self.transport = SimpleNamespace(require_elf32le=self.require_fake_elf)
        self.native = SimpleNamespace(read_dependencies=lambda path: self.depmap[Path(path)],
            require_compile_dependencies=lambda before, after: None if before == after else self.fail('fake dependency drift'))
        ordinary = object()
        self.declarations = FakeDeclarations(self, ordinary)
        self.modules = dict(recipes=FakeRecipes(self), declarations=self.declarations, ordinary=ordinary,
            probes=LOADED['probes'], plan=LOADED['plan'], diagnostics=LOADED['diagnostics'])
        self.witness = SimpleNamespace(groups={'Native': dict(Root=self.capture)})

    @staticmethod
    def fail(message):
        raise ValueError(message)

    def put(self, path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def write_input(self, name, raw):
        path = self.put(self.output / name, raw)
        self.watch.read(path, sha(raw))
        return path

    def record_output(self, path):
        return dict(Path=str(path), Sha256=sha(Path(path).read_bytes()))

    def _save(self, name, value):
        if self.fail_save:
            raise OSError('synthetic journal close error')
        self.saves.append(name)

    def source(self, index):
        return copy.deepcopy(self.sources[index])

    def begin_phase(self, name):
        self.active_phase = name

    def end_phase(self):
        if self.bad_command:
            self.fail('synthetic end-phase should not run after malformed row')
        self.phases.append(dict(Name=self.active_phase, First=0, Stop=len(self.commands), Commands=41))

    def verify_objects(self):
        for row in self.sources:
            self.watch.read(row['Object'], row['ObjectSha256'])

    def command(self, argv, label, expected_failure=False):
        row = dict(Label=label, Argv=[str(value) for value in argv], State='TERMINAL',
                   Status='EXPECTED-NONZERO' if expected_failure else 'PASS', Exit=1 if expected_failure else 0,
                   ExpectedExit=1 if expected_failure else 0, TimedOut=False)
        if self.bad_command == label:
            row['Exit'] = bool(row['Exit'])
        self.commands.append(row)
        if '-MF' in argv:
            dep = Path(argv[argv.index('-MF') + 1])
            source = Path(argv[argv.index('-c') + 1] if '-c' in argv else argv[-1])
            self.put(dep, b'synthetic dependency file')
            self.depmap[dep] = [source, self.base / 'source/context/context_port_abi.h',
                               self.base / 'source/context/context_runtime_port_abi.h']
        if '-c' in argv:
            obj = Path(argv[argv.index('-o') + 1])
            if not expected_failure:
                self.put(obj, b'synthetic slim object')
                self.put(obj.with_suffix('.i'), b'synthetic accepted CPP')
                self.put(obj.with_suffix('.s'), b'synthetic accepted assembly')
            else:
                lines = source.read_text(encoding='ascii').splitlines()
                column = lines[4].index(SLOT) + 1
                location = str(source) + ':5:' + str(column)
                suggestion = 'fiber_internal_runtime_require_current_context'
                marker = '      | ' + ' ' * (column - 1)
                diagnostics = [str(source) + ": In function 'cm0_abi_" + source.stem + "':",
                    location + ": error: '" + SLOT + "' undeclared (first use in this function); did you mean '" + suggestion + "'?",
                    '    5 | ' + lines[4], marker + '^' + '~' * (len(SLOT) - 1), marker + suggestion,
                    location + ': note: each undeclared identifier is reported only once for each function it appears in']
                return SimpleNamespace(returncode=1, timed_out=False, stdout=b'',
                                       stderr=('\n'.join(diagnostics) + '\n').encode())
        return SimpleNamespace(returncode=1 if expected_failure else 0, timed_out=False, stdout=b'', stderr=b'')

    def compile_tuple(self, index, *, name, mutations=(), source_bytes=None):
        self.command(['fake-discover'], 'discover ' + name)
        if self.fail_compile == name:
            raise ValueError('synthetic control compile failed')
        original = Path(self.sources[index]['Source'])
        source = self.write_input('compilations/' + name + '/' + (name.replace('-', '_') + '.c'
                                  if source_bytes is not None else original.name), source_bytes or b'synthetic mutated source')
        obj = source.with_name('%02d-' % index + source.stem + '.o')
        self.put(obj, b'synthetic mutated slim IR')
        self.command(['fake-compile'], 'compile ' + name)
        record = dict(Source=str(source), Object=str(obj), ObjectSha256=sha(obj.read_bytes()),
            SourceDeltas=[dict(Count=1, Before='00', After='01')] if mutations else [dict(Kind='ADDED-CONTROL-TU')])
        self.report['Compilations'].append(record)
        return record

    def inspect_ir(self, obj):
        self.command(['fake-readelf', '-hSW', str(obj)], 'inspect slim ' + obj.stem)
        return dict(Object=str(obj), Sha256=sha(self.watch.read(obj)), SlimIR=True)

    def _definitions(self, obj, name):
        self.command(['fake-plugin-nm', str(obj)], 'definitions ' + name)
        if name == 'original-runtime':
            return [dict(Name=PRIVATE, Kind='D')]
        if name == 'stale-reverse-anchor':
            rows = [dict(Name='fiber_internal_runtime_port_abi_v2_anchor', Kind='D')]
            if self.bad_anchor == 'defines-v1':
                rows.append(dict(Name=ANCHOR, Kind='D'))
            if self.bad_anchor == 'kind':
                rows[0]['Kind'] = 'T'
            return rows
        return [dict(Name='SVC_Handler' if name == 'duplicate-svc' else 'PendSV_Handler', Kind='T')]

    def _undefined(self, obj, name):
        self.command(['fake-plugin-nm', str(obj)], 'imports ' + name)
        imports = [ANCHOR] if self.bad_anchor == 'imports-v1' else []
        return imports, dict(Object=str(obj), Imports=imports)

    def _imports(self, obj, name, prefix):
        self.command(['fake-plugin-nm', str(obj)], 'imports ' + name)
        expected = (ANCHOR if name == 'unchanged-boot-v1' else STORAGE if 'storage' in name
                    else PRIVATE.replace('_g4_', '_g5_'))
        return expected, dict(Object=str(obj), ExpectedImport=expected)

    @staticmethod
    def require_fake_elf(raw):
        if raw != b'synthetic saved ELF32 REL':
            raise ValueError('synthetic saved machine bytes')

    def _link(self, name, objects, expected_failure=False):
        self.selected[name] = list(objects)
        result = self.command(['fake-link', *map(str, objects)], 'link ' + name, expected_failure)
        directory = self.output / 'links' / name
        elf, link_map = directory / 'image.elf', directory / 'image.map'
        self.put(link_map, b'synthetic map')
        if not expected_failure:
            self.put(elf, b'synthetic different ELF, comparison deferred')
            return result, elf, link_map
        expected = (PRIVATE.replace('_g4_', '_g5_') if name == 'stale-nvic-expectation' else
                    STORAGE if name == 'stale-storage-application' else ANCHOR if name == 'stale-reverse-anchor'
                    else 'SVC_Handler' if name == 'duplicate-svc' else 'PendSV_Handler')
        ld = str(self.tools['ld'])
        if name.startswith('duplicate-'):
            lines = [ld + ': ' + str(objects[-1]) + " (symbol from plugin): in function `" + expected + "':",
                "(.text+0x0): multiple definition of `" + expected + "'; " + str(self.objects[3])
                + ' (symbol from plugin):(.text+0x0): first defined here']
        else:
            machine = Path(str(elf) + '.ltrans0.ltrans.o')
            self.put(machine, b'synthetic saved ELF32 REL')
            if name == 'stale-reverse-anchor':
                lines = [ld + ': ' + str(machine) + ": in function `fiber_port_context_init':",
                    "<artificial>:(.text+0x0): undefined reference to `" + expected + "'"]
            else:
                lines = [ld + ': ' + str(machine)
                    + ":(.fiber_port_context_cohort_expectation+0x0): undefined reference to `" + expected + "'"]
        lines.append('collect2.exe: error: ld returned 1 exit status')
        if self.bad_diagnostic == name:
            lines.insert(0, 'unrelated infrastructure failure')
        result.stderr = ('\n'.join(lines) + '\n').encode()
        return result, elf, link_map


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='cm3-os-abi-build-model-')
        self.addCleanup(self.temporary.cleanup)
        self.suite = FakeSuite(Path(self.temporary.name))
        self.subject = LOADED['subject']

    def build(self):
        return self.subject.build(self.suite, self.suite.modules)

    def test_full_41_command_order_and_deferred_positive_no_reader(self):
        with patch('subprocess.Popen', side_effect=AssertionError('no external tools')):
            record = self.build()
        wanted = LOADED['recipes'].batch_plan()['Components'][0]['Labels']
        self.assertEqual([row['Label'] for row in self.suite.commands], wanted)
        self.assertEqual(sum(row['ExpectedExit'] == 1 for row in self.suite.commands), 8)
        self.assertEqual(record['Status'], 'BUILT-PENDING-READER')
        self.assertEqual(len(self.suite.phases), 1)
        self.assertIs(self.suite.report['PositiveLinkRevalidated'], False)
        authority = self.suite.report['PositiveAuthority']
        self.assertIs(authority['ValidationDeferred'], True)
        self.assertIsNone(authority['LoadImageComparison'])
        self.assertIs(authority['RawElfByteIdentical'], False)
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertIs(type(record['RequiredCellsSatisfied']), int)
        self.assertEqual(record['RequiredCellsSatisfied'], 0)

    def test_o2_other_routes_and_typed_zero_reject_before_commands(self):
        for field, value in (('Mode', 'O2-lto'), ('Profile', 'CM4'), ('LTO', 1)):
            original = self.suite.result[field]
            self.suite.result[field] = value
            with self.subTest(field=field), self.assertRaises(self.subject.Rejected):
                self.build()
            self.suite.result[field] = original
        self.suite.report['RequiredCellsSatisfied'] = False
        with self.assertRaises(self.subject.Rejected):
            self.build()
        self.assertEqual(self.suite.commands, [])

    def test_phase_is_first_no_retry_no_missing_authenticated_modules(self):
        del self.suite.modules['ordinary']
        with self.assertRaises(self.subject.Rejected):
            self.build()
        self.assertEqual(self.suite.commands, [])
        self.suite.modules['ordinary'] = self.suite.declarations.ordinary
        self.build()
        before = len(self.suite.commands)
        with self.assertRaises(self.subject.Rejected):
            self.build()
        self.assertEqual(len(self.suite.commands), before)

    def test_failed_variant_compile_never_counts_as_link_negative(self):
        self.suite.fail_compile = 'stale-storage-application'
        with self.assertRaisesRegex(ValueError, 'control compile failed'):
            self.build()
        self.assertNotIn('stale-storage-application', self.suite.selected)
        self.assertEqual([row['Status'] for row in self.suite.report['Controls']],
                         ['INTENDED-LINK-REJECTION-PASS', 'FAIL'])
        self.assertIs(self.suite.report['FiveLinkControlsValidated'], False)

    def test_foreign_failure_diagnostic_cannot_count_as_intended(self):
        self.suite.bad_diagnostic = 'stale-nvic-expectation'
        with self.assertRaises(LOADED['diagnostics'].Rejected):
            self.build()
        self.assertEqual(self.suite.report['Controls'][0]['Status'], 'FAIL')
        self.assertIs(self.suite.report['ABIControlsBuilt'], False)

    def test_reverse_anchor_definition_kind_and_import_near_misses(self):
        for changed in ('kind', 'defines-v1', 'imports-v1'):
            with tempfile.TemporaryDirectory(prefix='cm3-os-anchor-model-') as directory:
                suite = FakeSuite(Path(directory)); suite.bad_anchor = changed
                with self.subTest(changed=changed), self.assertRaises(self.subject.Rejected):
                    self.subject.build(suite, suite.modules)
                self.assertNotIn('stale-reverse-anchor', suite.selected)

    def test_replacements_append_roles_and_provenance_are_retained(self):
        self.build()
        for index, name in ((6, 'stale-nvic-expectation'), (7, 'stale-storage-application'),
                            (1, 'stale-reverse-anchor')):
            selected = self.suite.selected[name]
            self.assertEqual(len(selected), 9)
            self.assertEqual([at for at, pair in enumerate(zip(selected, self.suite.objects)) if pair[0] != pair[1]], [index])
        for name in ('duplicate-svc', 'duplicate-pendsv'):
            self.assertEqual(self.suite.selected[name][:-1], list(self.suite.objects))
            self.assertEqual(len(self.suite.selected[name]), 10)
        for row in self.suite.report['Controls']:
            self.assertTrue(row['Compilation']['SourceDeltas'])
            self.assertIs(row['FinalImageAbsent'], True)
            self.assertTrue(row['Classification']['ClosedGrammarValidated'])
            self.assertTrue(row['ConsumedObjects'])

    def test_real_probe_helper_requires_same_attempt_headers_and_diagnostics(self):
        self.build()
        probes = self.suite.report['ABIProbes']
        self.assertEqual(tuple(probes), ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c'))
        for name, row in probes.items():
            self.assertIn('-Os', row['CompileFlags'])
            self.assertIn('-flto', row['CompileFlags'])
            self.assertTrue(row['CompileDependenciesVerified'])
            if name in ('types.c', 'attributes.c'):
                self.assertTrue(row['Classification']['AcceptedCompile'])
                self.assertTrue(row['SlimIR']['SlimIR'])
                self.assertIn('-save-temps=obj', row['CompileFlags'])
            else:
                self.assertIs(row['Classification']['AcceptedCompile'], False)
                self.assertEqual(row['Classification']['UndeclaredIdentifier'], SLOT)
                self.assertIsNone(row['Object'])

    def test_cpp_canonical_origin_must_be_the_accepted_header(self):
        self.suite.declarations.bad_header = True
        with self.assertRaisesRegex(self.subject.Rejected, 'canonical declaration header'):
            self.build()
        self.assertIs(self.suite.report['TypedDeclarationProbesValidated'], False)

    def test_declaration_dependency_emit_and_cpp_do_not_relabel_o2(self):
        for stage in ('providers', 'probe', 'cpp'):
            with tempfile.TemporaryDirectory(prefix='cm3-os-decl-model-') as directory:
                suite = FakeSuite(Path(directory)); suite.declarations.bad_stage = stage
                with self.subTest(stage=stage), self.assertRaisesRegex(self.subject.Rejected, 'Os declaration metadata'):
                    self.subject.build(suite, suite.modules)
                self.assertEqual(suite.report['Status'], 'FAIL')
        self.assertEqual(self.suite.declarations.calls, [])

    def test_typed_exit_and_terminal_journal_cannot_complete_phase(self):
        self.suite.bad_command = 'link positive'
        with self.assertRaisesRegex(self.subject.Rejected, 'typed terminal'):
            self.build()
        self.assertEqual(self.suite.phases, [])
        self.assertIs(self.suite.report['ABIControlsBuilt'], False)

    def test_late_close_failure_preserves_primary_and_does_not_retry_tools(self):
        original = self.suite.end_phase
        def failed_end():
            self.suite.report['PrimaryError'] = 'original independent primary'
            self.suite.fail_save = True
            raise ValueError('synthetic late phase failure')
        self.suite.end_phase = failed_end
        with self.assertRaisesRegex(ValueError, 'late phase failure'):
            self.build()
        self.assertEqual(len(self.suite.commands), 41)
        self.assertEqual(self.suite.report['PrimaryError'], 'original independent primary')
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertIs(self.suite.report['ABIControlsBuilt'], False)
        self.assertTrue(any('late phase' in row for row in self.suite.report['ClosingErrors']))
        self.assertTrue(any('journal close' in row for row in self.suite.report['ClosingErrors']))
        self.suite.end_phase = original
        with self.assertRaises(self.subject.Rejected):
            self.build()
        self.assertEqual(len(self.suite.commands), 41)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()) \
            or output.is_relative_to(HERE.parents[2]):
        parser.error('fresh external TEMP directory required')
    paths = dict(PATHS, tests=Path(__file__).resolve())
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_ABI_PHASE_ORCHESTRATION_ONLY',
        Tests=0, ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, ActualELFParsed=False, ActualCaptureRead=False,
        ExternalToolsExecuted=0, SyntheticManagedCommands=True, Qualification=False,
        FullABIProof=False, FullSemanticABIProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        with patch('subprocess.Popen', side_effect=AssertionError('no process in pure controls')):
            for name in PATHS:
                if name != 'subject' and sha(buffers[name]) != PINS[name]:
                    raise ValueError('authenticated neutral helper: ' + name)
                module = ModuleType('_cm3_os_abi_phase_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                LOADED[name] = module
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(BuildTests)
            if suite.countTestCases() != METHODS:
                raise ValueError('exact twelve focused methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    for path, digest in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != digest:
                report['SourceDrift'].append(path)
        except OSError:
            report['SourceDrift'].append(path)
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 6 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
