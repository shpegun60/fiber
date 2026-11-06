"""Pure Os isolation build controls: fake tools, real neutral predicates only."""

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
ROOT = HERE.parents[2]
PATHS = dict(subject=HERE / 'isolation.py', recipes=HERE / 'batch_recipes.py',
    probes=HERE.parent / 'cm0_final_cell/components.py', ownership=HERE.parent / 'cm0_final_cell/ownership.py')
SOURCE_NAMES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
                'tools/runtime_sources.json')
METHODS = 12
LOADED, SOURCE_BUFFERS = {}, {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def files_under(root):
    return {path.relative_to(root).as_posix(): path for path in root.rglob('*') if path.is_file()}


class Watch:
    def __init__(self):
        self.hashes, self.fail_close = {}, False

    def read(self, path, expected=None):
        path = Path(path).resolve()
        raw = path.read_bytes()
        digest = sha(raw)
        if expected is not None and digest != expected or path in self.hashes and self.hashes[path] != digest:
            raise ValueError('synthetic physical/hash drift')
        self.hashes[path] = digest
        return raw

    def close(self):
        if self.fail_close:
            raise ValueError('synthetic late input closing failure')
        for path, digest in self.hashes.items():
            if sha(path.read_bytes()) != digest:
                raise ValueError('synthetic input changed')


class Recipes:
    def __init__(self, suite):
        self.suite = suite
        self.flags = [row['CompileFlags'][:] for row in suite.sources]

    def require_capture_sources(self, result):
        if result is not self.suite.result:
            raise ValueError('synthetic wrong capture')

    def compile_flags(self, result, index):
        return self.flags[index][:]

    def link_recipe(self, result, objects):
        if tuple(objects) != self.suite.objects:
            raise ValueError('synthetic wrong objects')
        return self.suite.original_link[:]

    def batch_plan(self):
        return LOADED['recipes'].batch_plan()


class Suite:
    """No ELF is constructed or parsed; saved-output bytes are explicit fakes."""
    def __init__(self, root):
        self.base, self.capture, self.output = root / 'seed', root / 'capture', root / 'out'
        self.output.mkdir()
        self.watch, self.depmap, self.sources = Watch(), {}, []
        self.bundle = dict(Artifacts={})
        self.tools = {name: root / ('fake-' + name + '.exe') for name in ('gcc', 'objdump', 'readelf')}
        self.api = SimpleNamespace(checked_path=lambda path: Path(path).resolve(), files_under=files_under)
        self._started, self._finished = True, False
        self.fail_label = self.bad_dependency = self.dirty_label = self.bad_slim = self.bad_exit = None
        self.selected, self.saves = {}, []
        source_root = self.base / 'source'
        for index, name in enumerate(LOADED['recipes'].SOURCES):
            path = self.put(source_root / name, SOURCE_BUFFERS.get(name, b'synthetic selected/facade source'))
            obj = self.put(self.capture / ('objects/%02d-%s.o' % (index, path.stem)), b'synthetic original IR' + bytes([index]))
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-std=gnu11',
                '-DFIBER_PORT_ARMV7M=1', '-I' + str(source_root / 'context'),
                '-I' + str(source_root / 'fiber/port/ARM_CM3'), '-I' + str(self.base / 'cmsis'),
                '-include', str(source_root / 'tools/fixtures/classic_final_image/main.h'),
                '-flto', '-fno-fat-lto-objects']
            self.sources.append(dict(Source=str(path), SourceSha256=sha(path.read_bytes()),
                Object=str(obj), ObjectSha256=sha(obj.read_bytes()), CompileFlags=flags, SlimIR=index != 8))
            self.bundle['Artifacts']['source/' + name] = sha(path.read_bytes())
        manifest = self.put(source_root / 'tools/runtime_sources.json', SOURCE_BUFFERS['tools/runtime_sources.json'])
        self.bundle['Artifacts']['source/tools/runtime_sources.json'] = sha(manifest.read_bytes())
        self.header = self.put(source_root / 'context/synthetic.h', b'synthetic CPU-independent header')
        self.cmsis = self.put(self.base / 'cmsis/core_cm3.h', b'synthetic CMSIS header')
        self.selected_header = self.put(source_root / 'fiber/port/ARM_CM3/fiber_port_private.h', b'synthetic port header')
        for row in self.sources:
            row['ActualCompileDependencies'] = [dict(Path=str(path), Sha256=sha(path.read_bytes()))
                for path in (Path(row['Source']), self.header, self.cmsis, self.selected_header)]
        self.objects = tuple(Path(row['Object']) for row in self.sources)
        links = []
        for kind in ('ordinary', 'emit-relocs'):
            final = self.capture / kind / 'image.elf'
            machine, link_map = Path(str(final) + '.ltrans0.ltrans.o'), final.parent / 'image.map'
            for path in (final, machine, link_map, Path(str(final) + '.dis'), Path(str(final) + '.ltrans0.ltrans.s')):
                self.put(path, ('synthetic retained ' + path.name).encode())
            links.append(dict(Kind=kind, Path=str(final), Machine=str(machine), Map=str(link_map)))
        self.result = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Links=links)
        self.original_link = [str(self.tools['gcc']), '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft',
            '-Os', '-flto', '-flto-partition=one', '-save-temps=obj', '-nostdlib',
            '-Wl,-plugin-opt=-save-temps', *map(str, self.objects), '-Wl,-Map=' + links[0]['Map'], '-o', links[0]['Path']]
        self.link_argv = self.original_link[:]
        self.report = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Status='FAIL',
            ABIControlsBuilt=True, RequiredCellsSatisfied=0, PrimaryError=None, ClosingErrors=[])
        plan = LOADED['recipes'].batch_plan()['Commands'][:41]
        self.commands = [dict(Label=row['Label'], Exit=row['ExpectedExit'], ExpectedExit=row['ExpectedExit'],
            State='TERMINAL', TimedOut=False, Status='EXPECTED-NONZERO' if row['ExpectedExit'] else 'PASS') for row in plan]
        self.phases = [dict(Name='ABIControls', First=0, Stop=41, Commands=41)]
        self.modules = dict(recipes=Recipes(self), probes=LOADED['probes'], ownership=LOADED['ownership'])
        self.native = SimpleNamespace(read_dependencies=lambda path: self.depmap[Path(path)],
            require_compile_dependencies=self.same_dependencies)

    @staticmethod
    def same_dependencies(before, after):
        if before != after:
            raise ValueError('synthetic discovery/compile dependency-set mismatch')

    @staticmethod
    def put(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def source(self, index):
        return copy.deepcopy(self.sources[index])

    def begin_phase(self, name):
        self.active_phase = name

    def end_phase(self):
        self.phases.append(dict(Name=self.active_phase, First=41, Stop=len(self.commands), Commands=12))

    def _save(self, name, value):
        self.saves.append(name)

    def record_output(self, path):
        return dict(Path=str(path), Sha256=sha(Path(path).read_bytes()))

    def write_input(self, name, raw):
        path = self.put(self.output / name, raw)
        self.watch.read(path, sha(raw))
        return path

    def verify_objects(self):
        for path, row in zip(self.objects, self.sources):
            self.watch.read(path, row['ObjectSha256'])

    def command(self, argv, label, expected_failure=False):
        if expected_failure:
            raise AssertionError('Isolation has no expected-negative command')
        if label == self.fail_label:
            raise ValueError('synthetic compile/tool failure')
        row = dict(Label=label, Argv=list(argv), State='TERMINAL', Status='PASS', Exit=0,
                   ExpectedExit=0, TimedOut=False)
        if self.bad_exit == label:
            row['Exit'] = False
        self.commands.append(row)
        if '-MF' in argv:
            dep = Path(argv[argv.index('-MF') + 1])
            source = Path(argv[argv.index('-c') + 1] if '-c' in argv else argv[-1])
            self.put(dep, b'synthetic dependency output')
            paths = [source, self.header]
            if self.bad_dependency == 'cmsis':
                paths.append(self.cmsis)
            elif self.bad_dependency == 'selected':
                paths.append(self.selected_header)
            elif self.bad_dependency == 'missing-source':
                paths.remove(source)
            elif self.bad_dependency == 'duplicate':
                paths.append(source)
            elif self.bad_dependency == 'foreign':
                paths.append(self.put(self.base / 'foreign.h', b'foreign'))
            elif self.bad_dependency == 'drift' and '-c' in argv:
                paths.remove(self.header)
            self.depmap[dep] = paths
        if '-c' in argv:
            self.put(Path(argv[argv.index('-o') + 1]), b'synthetic isolated slim IR')
        if label == 'link isolated-common-emit':
            elf = Path(argv[argv.index('-o') + 1])
            self.link_outputs(elf)
        stdout = b'synthetic full zero-inclusive disassembly\n' if label.startswith('disassemble ') else b''
        return SimpleNamespace(stdout=stdout, stderr=b'dirty diagnostic' if label == self.dirty_label else b'',
                               returncode=0, timed_out=False)

    def inspect_ir(self, obj):
        self.command([str(self.tools['readelf']), '-hSW', str(obj)], 'inspect slim ' + obj.stem)
        return dict(Object=str(obj), Sha256=sha(self.watch.read(obj)), SlimIR=False if self.bad_slim else True,
                    Sections=[dict(Name='.gnu.lto_fake', Size=1)])

    def link_outputs(self, elf):
        for name in ('image.elf', 'image.map', 'image.elf.ltrans.out', 'image.elf.ltrans0.ltrans.args.0',
                'image.elf.ltrans0.ltrans.o', 'image.elf.ltrans0.ltrans.s', 'image.elf.ltrans0.ltrans_args',
                'image.elf.ltrans0.o', 'image.elf.ltrans_args', 'image.elf.res', 'image.elf.wpa.args.0'):
            self.put(elf.parent / name, ('synthetic generated ' + name).encode())
        wrapper = self.output / (''.join(elf.parts[1:]) + '.lto_wrapper_args')
        self.put(wrapper, b'synthetic captured wrapper argv')

    def _link(self, name, objects):
        self.selected[name] = list(objects)
        self.command(['fake-link', *map(str, objects)], 'link ' + name)
        elf = self.output / 'links' / name / 'image.elf'
        self.link_outputs(elf)
        return SimpleNamespace(stdout=b'', stderr=b''), elf, elf.parent / 'image.map'


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='osi-')
        self.addCleanup(self.directory.cleanup)
        self.suite = Suite(Path(self.directory.name))
        self.subject = LOADED['subject']

    def build(self):
        return self.subject.build(self.suite, self.suite.modules)

    def test_neutral_include_transform_keeps_os_target_lto_and_no_hidden_override(self):
        original = self.suite.source(0)['CompileFlags']
        before = original[:]
        root = self.suite.base / 'source'
        flags = self.subject.common_flags(LOADED['probes'], original, root)
        self.assertEqual(original, before)
        self.assertEqual(flags[-3:], ['-I' + str(root / 'context'), '-I' + str(root / 'fiber'), '-I' + str(root)])
        self.assertNotIn('-include', flags)
        self.assertFalse(any('cmsis' in flag.lower() or 'fiber/port' in flag.replace('\\', '/') for flag in flags))
        self.assertEqual([flag for flag in flags if not flag.startswith('-I')],
            ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-std=gnu11',
             '-DFIBER_PORT_ARMV7M=1', '-flto', '-fno-fat-lto-objects'])

    def test_o2_extra_optimization_counter_lto_and_malformed_flags_reject(self):
        flags = self.suite.source(0)['CompileFlags']
        for bad in (flags + ['-O2'], flags + ['-Os'], flags + ['-fno-lto'],
                    flags + ['-ffat-lto-objects'], flags + [False], flags[:-2]):
            with self.subTest(bad=bad), self.assertRaises(self.subject.Rejected):
                self.subject.common_flags(LOADED['probes'], bad, self.suite.base / 'source')
        flags = [flag for flag in flags if flag != '-Os'] + ['-O2']
        with self.assertRaises(self.subject.Rejected):
            self.subject.common_flags(LOADED['probes'], flags, self.suite.base / 'source')

    def test_full_twelve_command_range_preserves_other_six_and_stays_pending(self):
        record = self.build()
        self.assertEqual(len(self.suite.commands), 53)
        self.assertEqual(tuple(row['Label'] for row in self.suite.commands[41:]), self.subject.command_plan())
        self.assertEqual(self.suite.phases[-1], dict(Name='Isolation', First=41, Stop=53, Commands=12))
        self.assertEqual(self.suite.selected['isolated-common'][3:], list(self.suite.objects[3:]))
        self.assertEqual(record['Status'], 'BUILT-PENDING-READER')
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertEqual(record['RequiredCellsSatisfied'], 0)
        self.assertIs(type(record['RequiredCellsSatisfied']), int)
        self.assertIs(record['CpuFreeCommonValidated'], False)
        pending = self.suite.report['IsolationDeferredReader']
        self.assertEqual(len(pending['Inputs']), 18)
        self.assertEqual(len({row['Role'] for row in pending['Inputs']}), 18)
        for row in pending['Inputs']:
            self.assertEqual(sha(Path(row['Path']).read_bytes()), row['Sha256'])
        self.assertEqual([row['Name'] for row in pending['LoadImageComparisons']],
                         ['OriginalToIsolated', 'IsolatedTwins', 'OriginalTwins'])
        self.assertEqual([row['Kind'] for row in pending['SlotProofs']], ['Original', 'Isolated'])
        self.assertIs(pending['WholeSlotAccessIsolation'], False)

    def test_common_discovery_compile_actualdeps_flags_and_indices_bound(self):
        self.build()
        for index, row in enumerate(self.suite.report['IsolatedCommon']):
            self.assertEqual(row['TemplateIndex'], index)
            self.assertEqual(row['CommandIndices'], list(range(41 + index * 3, 44 + index * 3)))
            self.assertEqual(row['Dependencies'], row['DiscoveryDependencies'])
            self.assertEqual(row['ObjectSha256'], sha(Path(row['Object']).read_bytes()))
            self.assertIn('-Os', row['CompileFlags'])
            self.assertIs(row['RawIRIdentityClaim'], False)
            self.assertIs(row['IRImportClosureValidated'], False)
            for command in self.suite.commands[41 + index * 3:43 + index * 3]:
                argv = command['Argv']
                self.assertEqual(argv[argv.index('-MT') + 1], 'pilot-source-' + str(index))

    def test_dependency_cmsis_selected_and_foreign_consumption_reject(self):
        for bad in ('cmsis', 'selected', 'foreign'):
            with tempfile.TemporaryDirectory(prefix='osi-dep-') as directory:
                suite = Suite(Path(directory)); suite.bad_dependency = bad
                with self.subTest(bad=bad), self.assertRaises(LOADED['probes'].Rejected):
                    self.subject.build(suite, suite.modules)
                self.assertNotIn('isolated-common', suite.selected)

    def test_dependency_ownsource_duplicate_sets_and_hash_tampering_reject(self):
        for bad in ('missing-source', 'duplicate', 'drift'):
            with tempfile.TemporaryDirectory(prefix='osi-dep-') as directory:
                suite = Suite(Path(directory)); suite.bad_dependency = bad
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    self.subject.build(suite, suite.modules)
        self.suite.sources[0]['ActualCompileDependencies'][0]['Sha256'] = '0' * 64
        with self.assertRaises(self.subject.Rejected):
            self.build()

    def test_compile_failure_is_not_expected_negative_and_cannot_retry(self):
        self.suite.fail_label = 'compile isolated context_runtime_state'
        with self.assertRaisesRegex(ValueError, 'compile/tool failure'):
            self.build()
        count = len(self.suite.commands)
        self.assertNotIn('isolated-common', self.suite.selected)
        self.assertIs(self.suite.report['IsolationBuilt'], False)
        with self.assertRaisesRegex(self.subject.Rejected, 'cannot retry'):
            self.build()
        self.assertEqual(len(self.suite.commands), count)

    def test_emit_recipe_exact_order_one_added_flag_and_full_disassembly(self):
        self.build()
        row = next(row for row in self.suite.commands if row['Label'] == 'link isolated-common-emit')
        self.assertEqual(row['Argv'].count('-Wl,--emit-relocs'), 1)
        self.assertEqual(row['Argv'][-1], '-Wl,--emit-relocs')
        objects = [flag for flag in row['Argv'] if flag.endswith('.o')]
        self.assertEqual(objects, [item['Object'] for item in self.suite.report['IsolatedCommon']]
                         + list(map(str, self.suite.objects[3:])))
        dis = self.suite.commands[-1]['Argv']
        self.assertEqual(dis[1:3], ['-drwC', '-z'])
        self.assertEqual(dis[0], str(self.suite.tools['objdump']))
        self.assertEqual(self.suite.report['EmitLinkDelta'], ['-Wl,--emit-relocs'])

    def test_source_ownership_runs_real_fixed_predicate_not_a_cached_boolean(self):
        path = self.suite.base / 'source/context/context_core.c'
        raw = path.read_bytes() + b'\nvoid extra(void) { __asm__("nop"); }\n'
        path.write_bytes(raw)
        self.suite.bundle['Artifacts']['source/context/context_core.c'] = sha(raw)
        with self.assertRaises(LOADED['ownership'].Rejected):
            self.build()
        self.assertEqual(len(self.suite.commands), 41)

    def test_bad_prior_range_scope_credit_or_unbuilt_abi_refuses_without_commands(self):
        for changed, value in (('Mode', 'O2-lto'), ('RequiredCellsSatisfied', False), ('ABIControlsBuilt', False)):
            original = self.suite.report[changed]
            self.suite.report[changed] = value
            with self.subTest(changed=changed), self.assertRaises(self.subject.Rejected):
                self.build()
            self.suite.report[changed] = original
        self.suite.phases[0]['First'] = False
        with self.assertRaises(self.subject.Rejected):
            self.build()
        self.assertEqual(len(self.suite.commands), 41)

    def test_dirty_compile_non_slim_and_boolean_exit_cannot_promote(self):
        for case in ('dirty', 'slim', 'exit'):
            with tempfile.TemporaryDirectory(prefix='osi-output-') as directory:
                suite = Suite(Path(directory))
                if case == 'dirty':
                    suite.dirty_label = 'compile isolated context_core'
                elif case == 'slim':
                    suite.bad_slim = True
                else:
                    suite.bad_exit = 'disassemble isolated-common-emit'
                with self.subTest(case=case), self.assertRaises(self.subject.Rejected):
                    self.subject.build(suite, suite.modules)
                self.assertEqual(suite.report['Status'], 'FAIL')
                self.assertEqual(suite.report['RequiredCellsSatisfied'], 0)

    def test_late_failure_retains_primary_and_does_not_finish_or_retry(self):
        def late_failure():
            self.suite.report['PrimaryError'] = 'existing batch primary'
            raise OSError('synthetic late phase journal')
        self.suite.end_phase = late_failure
        with self.assertRaisesRegex(OSError, 'late phase journal'):
            self.build()
        self.assertEqual(len(self.suite.commands), 53)
        self.assertEqual(self.suite.report['PrimaryError'], 'existing batch primary')
        self.assertTrue(any('late phase journal' in item for item in self.suite.report['ClosingErrors']))
        self.assertIs(self.suite.report['WholeSlotAccessIsolation'], False)
        self.assertIs(self.suite.report['OutputSealVerified'], False)
        self.assertIs(self.suite._finished, False)
        with self.assertRaises(self.subject.Rejected):
            self.build()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()) \
            or output.is_relative_to(ROOT):
        parser.error('fresh external TEMP output required')
    paths = dict(PATHS, tests=Path(__file__).resolve())
    paths.update({name: ROOT / name for name in SOURCE_NAMES})
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_ISOLATION_BUILD_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, RealSourceOwnershipPredicate=True,
        ActualELFParsed=False, ActualCaptureRead=False, SyntheticTools=True, ExternalToolsExecuted=0,
        IndependentMachineProof=False, Qualification=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls cannot spawn tools')):
            for name in PATHS:
                if name != 'subject':
                    relative, expected = LOADED['subject'].HELPER_PINS[name]
                    if paths[name] != ROOT / relative or sha(buffers[name]) != expected:
                        raise ValueError('authenticated neutral helper: ' + name)
                module = ModuleType('_os_isolation_build_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                LOADED[name] = module
            SOURCE_BUFFERS.update({name: buffers[name] for name in SOURCE_NAMES})
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(IsolationTests)
            if suite.countTestCases() != METHODS:
                raise ValueError('exact twelve synthetic methods required')
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
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 9 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
