"""Synthetic build orchestration controls; no compiler, parser or target runs."""

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
PINS = {
    'recipes': ('tools/fixtures/cm3_os_lto_final_cell/batch_recipes.py',
        'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B'),
    'workers': ('tools/fixtures/cm3_lto_port_policy/runner.py',
        'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB'),
    'policy': ('tools/fixtures/cm3_lto_port_policy/policy.py',
        '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'attributes': ('tools/fixtures/cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
}
METHODS = 12
LOADED = {}
RAW = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
       '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
COUNTERS = ('-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs',
            '-fno-test-coverage', '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc', '-mgeneral-regs-only')
RUNTIME = ('fiber_port_init_context_frame', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_memory_barrier',
    'fiber_port_runtime_prepare_start', 'fiber_port_runtime_schedule', 'fiber_port_runtime_select_first',
    'fiber_port_runtime_start_first', 'fiber_port_scheduler_pick_first_from_start',
    'fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
BOOT = ('fiber_fallback_initial_msp', 'fiber_port_runtime_prepare', 'fiber_port_boot_prepare_msp_for_start',
    'fiber_port_boot_record_compute_hash', 'fiber_port_boot_record_fast_check', 'fiber_port_boot_record_check',
    'fiber_port_boot_create', 'fiber_port_boot_check', 'fiber_port_require_start_environment',
    'fiber_port_context_init', 'fiber_port_context_validate_save_current', 'fiber_port_context_validate_restore',
    'fiber_port_context_prepare_first_start', 'fiber_port_require_start_interrupt_state')
EXCEPTION = ('fiber_exception_runtime_check', 'fiber_pendsv_init_lowest_priority')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def files_under(root):
    return {path.relative_to(root).as_posix(): path for path in root.rglob('*') if path.is_file()}


class Watch:
    def __init__(self):
        self.hashes = {}
        self.fail_close = False

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes()
        digest = sha(raw)
        if (expected is not None and expected != digest) or self.hashes.get(path, digest) != digest:
            raise ValueError('synthetic input hash drift')
        self.hashes[path] = digest
        return raw

    def close(self):
        if self.fail_close:
            raise ValueError('synthetic late closing failure')
        for path, expected in self.hashes.items():
            if sha(path.read_bytes()) != expected:
                raise ValueError('synthetic closing byte drift')


class Recipes:
    def __init__(self, suite):
        self.suite = suite
        self.flags = [copy.deepcopy(row['CompileFlags']) for row in suite.sources]

    def compile_flags(self, report, index):
        if report is not self.suite.result:
            raise ValueError('synthetic capture identity')
        return self.flags[index][:]

    def require_capture_sources(self, report):
        if report is not self.suite.result:
            raise ValueError('synthetic capture identity')

    def link_recipe(self, report, objects):
        if tuple(objects) != self.suite.objects:
            raise ValueError('synthetic original object order')
        return [arg for arg in self.suite.original_link if arg != '-v']

    def batch_plan(self):
        return LOADED['recipes'].batch_plan()


class Suite:
    """Generated fake bytes only. Real neutral worker/definition parsers are used."""
    def __init__(self, root):
        self.output, self.base, self.capture = root / 'out', root / 'seed', root / 'capture'
        self.output.mkdir(parents=True)
        self.watch, self.depmap, self.sources = Watch(), {}, []
        self._started, self._finished = True, False
        self.fail_label = self.dirty_label = self.bad_exit = self.bad_slim = None
        self.bad_dependency = self.bad_definitions = self.bad_worker = None
        self.fail_save = self.fail_end = False
        self.saves = []
        self.tools = {name: self.put(root / ('fake-' + name + '.exe'), b'synthetic tool identity')
                      for name in ('gcc', 'nm', 'readelf', 'objdump')}
        self.plugin = self.put(root / 'fake-plugin.dll', b'synthetic plugin')
        self.lto1 = self.put(root / 'workers/lto1.exe', b'synthetic lto1')
        self.assembler = self.put(root / 'workers/as.exe', b'synthetic assembler')
        self.api = SimpleNamespace(checked_path=lambda path: Path(path).resolve(), files_under=files_under)
        self.transport = SimpleNamespace(require_elf32le=self.synthetic_machine)
        self.bundle = dict(Artifacts={})
        self.header = self.put(self.base / 'source/context/synthetic.h', b'synthetic shared header')
        self.bundle['Artifacts']['source/context/synthetic.h'] = sha(self.header.read_bytes())
        for index, name in enumerate(LOADED['recipes'].SOURCES):
            source = self.put(self.base / 'source' / name, ('synthetic source ' + name).encode('ascii'))
            obj = self.put(self.capture / ('objects/%02d-%s.o' % (index, source.stem)), b'original object ' + bytes([index]))
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-std=gnu11',
                '-I' + str(self.base / 'source/context'), '-I' + str(self.base / 'cmsis'),
                '-include', str(self.base / 'source/tools/fixtures/classic_final_image/main.h'),
                '-flto', '-fno-fat-lto-objects']
            self.sources.append(dict(Source=str(source), SourceSha256=sha(source.read_bytes()),
                Object=str(obj), ObjectSha256=sha(obj.read_bytes()), CompileFlags=flags,
                ActualCompileDependencies=[dict(Path=str(path), Sha256=sha(path.read_bytes()))
                                           for path in (source, self.header)]))
            self.bundle['Artifacts']['source/' + name] = sha(source.read_bytes())
        self.objects = tuple(Path(row['Object']) for row in self.sources)
        final = self.capture / 'ordinary/image.elf'
        link_map = final.parent / 'image.map'
        self.original_link = [str(self.tools['gcc']), '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft',
            '-Os', '-flto', '-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
            '-nostdlib', *map(str, self.objects), '-Wl,-Map=' + str(link_map), '-o', str(final)]
        self.result = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            Commands=[dict(Label='link ordinary', Argv=self.original_link[:])], Links=[dict(Path=str(final))],
            ResolvedWorkers={name: dict(Path=str(path), Sha256=sha(path.read_bytes()))
                             for name, path in (('lto1', self.lto1), ('as', self.assembler))})
        self.link_argv = [arg for arg in self.original_link if arg != '-v']
        self.report = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Status='FAIL',
            ABIControlsBuilt=True, IsolationBuilt=True, CommonAttributesBuilt=True,
            RequiredCellsSatisfied=0, PrimaryError=None, ClosingErrors=[])
        self.commands = [dict(Label=row['Label'], Exit=row['ExpectedExit'], ExpectedExit=row['ExpectedExit'],
            State='TERMINAL', TimedOut=False, Status='EXPECTED-NONZERO' if row['ExpectedExit'] else 'PASS')
            for row in LOADED['recipes'].batch_plan()['Commands'][:98]]
        self.phases = [dict(Name=name, First=start, Stop=stop, Commands=stop-start)
            for name, start, stop in (('ABIControls', 0, 41), ('Isolation', 41, 53), ('CommonAttributes', 53, 98))]
        self.native = SimpleNamespace(read_dependencies=lambda path: self.depmap[Path(path)],
                                      require_compile_dependencies=self.same_dependencies)
        self.modules = dict(recipes=Recipes(self), workers=LOADED['workers'],
                            policy=LOADED['policy'], attributes=LOADED['attributes'])

    @staticmethod
    def put(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    @staticmethod
    def synthetic_machine(raw):
        if raw != b'synthetic machine':
            raise ValueError('synthetic machine marker')
        return dict(Synthetic=True)

    @staticmethod
    def same_dependencies(before, after):
        if before != after:
            raise ValueError('synthetic compile dependencies differ')

    def source(self, index):
        return copy.deepcopy(self.sources[index])

    def begin_phase(self, name):
        self.active_phase = name

    def end_phase(self):
        if self.fail_end:
            raise ValueError('synthetic terminal phase persistence failure')
        self.phases.append(dict(Name=self.active_phase, First=98, Stop=len(self.commands), Commands=36))

    def _save(self, name, value):
        self.saves.append(copy.deepcopy(value))
        if self.fail_save:
            raise OSError('synthetic receipt write failure')

    def record_output(self, path, required=True):
        if not Path(path).exists() and not required:
            return None
        return dict(Path=str(path), Sha256=sha(self.watch.read(path)))

    def write_input(self, name, raw):
        path = self.put(self.output / name, raw)
        self.watch.read(path, sha(raw))
        return path

    def verify_objects(self):
        for row in self.sources:
            self.watch.read(row['Object'], row['ObjectSha256'])

    def definitions(self, stem):
        names = {'fiber_port': RUNTIME, 'fiber_port_boot': BOOT, 'fiber_port_exception': EXCEPTION}[stem]
        rows = [(name, 'W' if name == 'fiber_fallback_initial_msp' else 'T') for name in names]
        if stem == 'fiber_port':
            rows += [(LOADED['policy'].PRIVATE, 'D'), (LOADED['policy'].STORAGE, 'D')]
        if self.bad_definitions == 'missing':
            rows = rows[:-1]
        if self.bad_definitions == 'kind':
            rows[0] = (rows[0][0], 'D')
        return ''.join('%s %s 0 \n' % row for row in rows).encode('ascii')

    def command(self, argv, label, expected_failure=False):
        if expected_failure:
            raise AssertionError('port policy has no expected-negative tool command')
        argv = list(map(str, argv))
        if label == self.fail_label:
            raise RuntimeError('synthetic tool failure: ' + label)
        row = dict(Label=label, Argv=argv, State='TERMINAL', Status='PASS', Exit=0,
                   ExpectedExit=0, TimedOut=False)
        if label == self.bad_exit:
            row['Exit'] = False
        self.commands.append(row)
        stdout, stderr = b'', b''
        if label == 'dump compiler specs':
            stdout = b'*lib:\n%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}\n'
        elif label.startswith('definitions '):
            stdout = self.definitions(label.split()[-1])
        elif label.startswith('disassemble '):
            if argv[1:3] != ['-drwC', '-z']:
                raise AssertionError('complete zero-inclusive disassembly recipe')
            stdout = b'synthetic complete disassembly (not an actual ELF)\n'
        if '-MF' in argv:
            dep = self.put(Path(argv[argv.index('-MF') + 1]), b'synthetic dependencies')
            source = Path(argv[argv.index('-c') + 1] if '-c' in argv else argv[-1])
            paths = [source, self.header]
            if self.bad_dependency == 'missing':
                paths.remove(source)
            elif self.bad_dependency == 'duplicate':
                paths.append(source)
            elif self.bad_dependency == 'foreign':
                paths.append(self.put(self.base / 'foreign.h', b'foreign'))
            elif self.bad_dependency == 'changed' and '-c' in argv:
                paths.remove(self.header)
            self.depmap[dep] = paths
        if '-c' in argv:
            self.put(Path(argv[argv.index('-o') + 1]), b'synthetic generated slim IR')
        if label.startswith('lower ') or label == 'link final-supported':
            output = Path(argv[argv.index('-o') + 1])
            stderr = self.worker_files(output, argv)
        if label == self.dirty_label:
            stderr = b'warning: synthetic unwanted diagnostic'
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0, timed_out=False)

    def inspect_ir(self, obj):
        self.command([self.tools['readelf'], '-hSW', obj], 'inspect slim ' + obj.stem)
        return dict(Object=str(obj), Sha256=sha(self.watch.read(obj)), SlimIR=False if self.bad_slim else True)

    def _undefined(self, obj, label):
        self.command([self.tools['nm'], '--plugin', self.plugin, '-u', obj], 'imports ' + label)
        return ['fiber_panic'], dict(Object=str(obj), Names=['fiber_panic'], Synthetic=True)

    def worker_files(self, output, argv):
        raw = 'stress-raw' in output.parts
        flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os',
                 '-mlibarch=armv7-m', '-march=armv7-m', '-Os', *RAW]
        if not raw:
            flags += list(COUNTERS)
        specs = [arg for arg in argv if arg.startswith('-specs=')]
        flags += ['-mlibarch=armv7-m', '-march=armv7-m', *specs]
        objects = [arg for arg in argv if arg.endswith('.o') and arg != str(output)]
        ir = [arg for arg in objects if arg != str(self.objects[8])]
        prefix = str(output)
        intermediate, machine = prefix + '.ltrans0.o', prefix + '.ltrans0.ltrans.o'
        saved = {
            '.ltrans_args': flags + ir,
            '.wpa.args.0': ir,
            '.ltrans0.ltrans_args': flags + ['-o', machine, intermediate],
            '.ltrans0.ltrans.args.0': [intermediate],
            '.ltrans.out': ['0', intermediate],
        }
        for suffix, values in saved.items():
            if suffix == '.wpa.args.0' and self.bad_worker == 'wpa-order':
                values = list(reversed(values))
            self.put(Path(prefix + suffix), ('\n'.join(values) + '\n').encode('ascii'))
        for suffix, value in (('', b'synthetic aggregate or executable'), ('.ltrans0.o', b'synthetic WPA IR'),
                ('.ltrans0.ltrans.o', b'synthetic machine'), ('.ltrans0.ltrans.s', b'synthetic assembly'),
                ('.res', b'synthetic plugin resolution'), ('.lto_wrapper_args', b'synthetic wrapper argv')):
            self.put(Path(prefix + suffix), value)
        if output.suffix == '.elf':
            self.put(output.parent / 'image.map', b'synthetic final section map')
        if self.bad_worker == 'foreign-executable':
            lto1 = self.put(self.output / 'foreign/lto1.exe', b'foreign compiler')
        else:
            lto1 = self.lto1
        # Actual reported argv may group GRO before the six counter -f options.
        actual = [flag for flag in flags if flag != '-mgeneral-regs-only']
        if not raw:
            actual.insert(0, '-mgeneral-regs-only')
        return (' ' + str(lto1) + ' ' + ' '.join(actual) + ' -fwpa @' + prefix + '.wpa.args.0\n'
            + ' ' + str(lto1) + ' ' + ' '.join(actual) + ' -fltrans -o ' + prefix + '.ltrans0.ltrans.s @'
            + prefix + '.ltrans0.ltrans.args.0\n' + ' ' + str(self.assembler) + ' -o ' + machine + ' '
            + prefix + '.ltrans0.ltrans.s\n').encode('ascii')


class PortPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='os-port-pure-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.suite = Suite(self.root)
        self.subject = LOADED['subject']

    def build(self):
        return self.subject.build(self.suite, self.suite.modules)

    def initialize(self):
        self.suite.report.update(PortPolicyCompilations=[], PortPolicyLowerings=[])

    def test_complete_36_command_build_deferred_zero_credit(self):
        original_globals = dict(LOADED['workers'].__dict__)
        record = self.build()
        self.assertEqual(len(self.suite.commands), 134)
        self.assertEqual(tuple(row['Label'] for row in self.suite.commands[98:]), self.subject.command_plan())
        self.assertEqual(record['Status'], 'BUILT-PENDING-READER')
        self.assertEqual((record['First'], record['Stop'], record['Commands']), (98, 134, 36))
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertIs(type(self.suite.report['RequiredCellsSatisfied']), int)
        self.assertEqual(self.suite.report['RequiredCellsSatisfied'], 0)
        deferred = self.suite.report['PortPolicyDeferredReader']
        self.assertEqual(len(deferred['Inputs']), 18)
        self.assertEqual(len({row['Role'] for row in deferred['Inputs']}), 18)
        self.assertIs(deferred['ValidationDeferred'], True)
        self.assertIs(deferred['WholeCellProof'], False)
        self.assertEqual(LOADED['workers'].__dict__, original_globals)

    def test_exact_source_flags_and_no_override(self):
        flags = self.subject.flags_for(self.suite, self.suite.modules, 3)
        self.assertEqual(flags, self.suite.sources[3]['CompileFlags'] + list(RAW) + list(COUNTERS))
        self.assertEqual(flags.count('-Os'), 1)
        for value in (True, 0, 2, 6):
            with self.subTest(index=value), self.assertRaises(self.subject.Rejected):
                self.subject.flags_for(self.suite, self.suite.modules, value)
        for flag in ('-O2', '-march=armv7-m', '-mno-general-regs-only', '-fno-lto', '-fsanitize=address'):
            with self.subTest(flag=flag):
                original = self.suite.sources[3]['CompileFlags'][:]
                self.suite.sources[3]['CompileFlags'].append(flag)
                self.suite.modules['recipes'].flags[3].append(flag)
                with self.assertRaises(self.subject.Rejected):
                    self.subject.flags_for(self.suite, self.suite.modules, 3)
                self.suite.sources[3]['CompileFlags'] = original
                self.suite.modules['recipes'].flags[3] = original[:]

    def test_effective_options_actual_grouping_and_canonicalization(self):
        target = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os']
        grouped = [*target, '-mgeneral-regs-only', *COUNTERS[:-1]]
        proof = self.subject.require_effective_options(grouped, supported=True)
        self.assertEqual(proof['CanonicalizedRawAbsent'], list(RAW))
        self.assertIs(proof['AttributeEffectsValidated'], False)
        self.subject.require_effective_options(target + list(RAW), supported=False)
        canonical = ['-Os', '-mlibarch=armv7-m', '-march=armv7-m'] * 2
        self.subject.require_effective_options(grouped + canonical, supported=True)
        self.subject.require_effective_options(target + list(RAW) + canonical, supported=False)
        for argv, supported in ((grouped + [RAW[0]], True), (target + list(COUNTERS[:-1]), True),
                (target + list(RAW) + ['-mgeneral-regs-only'], False), (target + list(RAW), 1),
                (target + list(RAW) + ['-fsanitize=alignment'], False),
                *((grouped + [flag], True) for flag in ('-march=armv7e-m', '-march', '-march=armv7-m+fp',
                    '-mlibarch=armv8-m.main', '-mlibarch'))):
            with self.subTest(argv=argv, supported=supported), self.assertRaises(self.subject.Rejected):
                self.subject.require_effective_options(argv, supported=supported)

    def test_mode_phase_identity_and_typed_guards_before_commands(self):
        cases = (lambda s: s.result.update(Mode='O2-lto'), lambda s: s.report.update(LTO=1),
            lambda s: s.report.update(RequiredCellsSatisfied=False), lambda s: s.report.update(IsolationBuilt=1),
            lambda s: s.phases[0].update(First=False), lambda s: s.commands.pop())
        for index, change in enumerate(cases):
            with self.subTest(case=index):
                suite = Suite(self.root / ('guard%d' % index))
                change(suite)
                count = len(suite.commands)
                with self.assertRaises(self.subject.Rejected):
                    self.subject.build(suite, suite.modules)
                self.assertEqual(len(suite.commands), count)

    def test_dependency_and_plugin_definition_records(self):
        self.build()
        rows = self.suite.report['PortPolicyCompilations']
        self.assertEqual([row['TemplateIndex'] for row in rows], [3, 4, 5, 3, 3])
        self.assertEqual(len(self.suite.report['PortPolicyIRDefinitionSurface']['Definitions']), 31)
        for row in rows:
            self.assertIs(row['SlimIR']['SlimIR'], True)
            self.assertEqual(row['DiscoveryDependencies'], row['Dependencies'])
            for index in row['CommandIndices'][:2]:
                argv = self.suite.commands[index]['Argv']
                self.assertEqual(argv[argv.index('-MT') + 1], 'pilot-source-' + str(row['TemplateIndex']))
        definitions = LOADED['workers'].parse_ir_definitions(b'name T 0 \nweak W 0\t\n')
        self.assertEqual(definitions, [dict(Name='name', Kind='T', Value=0, Size=None),
                                      dict(Name='weak', Kind='W', Value=0, Size=None)])

    def test_unadmitted_or_changed_dependencies_fail_before_lowering(self):
        for index, defect in enumerate(('foreign', 'missing', 'duplicate', 'changed')):
            with self.subTest(defect=defect):
                suite = Suite(self.root / ('deps%d' % index))
                suite.bad_dependency = defect
                with self.assertRaises((self.subject.Rejected, ValueError)):
                    self.subject.build(suite, suite.modules)
                self.assertFalse(any(row['Label'].startswith('lower ') for row in suite.commands[98:]))
                self.assertEqual(suite.report['Status'], 'FAIL')

    def test_incomplete_definitions_or_non_slim_input_rejected(self):
        for index, defect in enumerate(('missing', 'kind', 'slim')):
            with self.subTest(defect=defect):
                suite = Suite(self.root / ('defs%d' % index))
                if defect == 'slim':
                    suite.bad_slim = True
                else:
                    suite.bad_definitions = defect
                with self.assertRaises((self.subject.Rejected, LOADED['policy'].Rejected)):
                    self.subject.build(suite, suite.modules)
                self.assertIs(suite.report['PortPolicyBuilt'], False)
                self.assertFalse(any(row['Label'].startswith('lower ') for row in suite.commands[98:]))

    def test_paired_stress_only_counter_difference_and_raw_specs(self):
        self.build()
        rows = self.suite.report['PortPolicyCompilations'][3:]
        self.assertEqual(Path(rows[0]['Source']).read_bytes(), Path(rows[1]['Source']).read_bytes())
        self.assertEqual(rows[0]['SourceSha256'], rows[1]['SourceSha256'])
        self.assertEqual(rows[0]['CompileFlags'], rows[1]['CompileFlags'] + list(COUNTERS))
        lowers = self.suite.report['PortPolicyLowerings']
        self.assertIsNone(lowers[0]['ActualWorker']['DriverSpecs'])
        self.assertIsNone(lowers[1]['ActualWorker']['DriverSpecs'])
        specs = lowers[2]['ActualWorker']['DriverSpecs']
        self.assertNotIn(b'-lgcov', Path(specs['Path']).read_bytes())
        self.assertEqual(Path(specs['Path']).read_bytes(),
            Path(self.suite.report['PortPolicyDriverAdapter']['OriginalPath']).read_bytes().replace(b'-lgcov', b''))
        self.assertIs(self.suite.report['PortPolicyPairedStress']['StressActivationValidated'], False)

    def test_real_neutral_worker_chain_rejects_foreign_executable_or_ir_order(self):
        for index, defect in enumerate(('foreign-executable', 'wpa-order')):
            with self.subTest(defect=defect):
                suite = Suite(self.root / ('worker%d' % index))
                suite.bad_worker = defect
                message = 'actual worker executable/stage/response' if defect == 'foreign-executable' else 'actual WPA response object order'
                with self.assertRaisesRegex(ValueError, message):
                    self.subject.build(suite, suite.modules)
                self.assertIs(suite.report['PortPolicyBuilt'], False)
                self.assertEqual(suite.report['Status'], 'FAIL')

    def test_final_replaces_only_three_with_global_policy_scope(self):
        self.build()
        final = self.suite.report['PortPolicyFinalLink']
        compiled = self.suite.report['PortPolicyCompilations'][:3]
        expected = list(map(str, self.suite.objects))
        expected[3:6] = [row['Object'] for row in compiled]
        self.assertEqual(final['Objects'], expected)
        self.assertEqual([row['Index'] for row in final['UnchangedOtherSixObjects']], [0, 1, 2, 6, 7, 8])
        self.assertEqual(final['Argv'].count('-Wl,--emit-relocs'), 1)
        self.assertIn('-v', final['Argv'])
        self.assertIs(final['GlobalSupportedCounterPolicy'], True)
        self.assertIs(final['UnchangedOtherSixGeneratedBodies'], False)
        self.assertIs(final['RawCommonAttributesAloneProved'], False)
        self.assertEqual(len(final['ActualWorker']['WpaInputs']), 8)
        self.assertIs(final['ActualWorker']['Execution']['OsProcessTraceVerified'], False)

    def test_failed_compilation_never_counts_negative_or_retries(self):
        label = 'compile selected fiber_port'
        self.suite.fail_label = label
        self.suite.report['PrimaryError'] = 'original managed failure'
        self.suite.fail_save = True
        with self.assertRaisesRegex(RuntimeError, 'synthetic tool failure'):
            self.build()
        count = len(self.suite.commands)
        self.assertEqual(self.suite.report['PrimaryError'], 'original managed failure')
        self.assertTrue(any('synthetic tool failure' in item for item in self.suite.report['ClosingErrors']))
        self.assertTrue(any('receipt write failure' in item for item in self.suite.report['ClosingErrors']))
        with self.assertRaisesRegex(self.subject.Rejected, 'cannot retry'):
            self.build()
        self.assertEqual(len(self.suite.commands), count)
        self.assertIs(self.suite.report['PortPolicyBuilt'], False)

    def test_terminal_and_late_failure_never_promote(self):
        for index, defect in enumerate(('exit-bool', 'dirty', 'close', 'phase', 'save')):
            with self.subTest(defect=defect):
                suite = Suite(self.root / ('late%d' % index))
                if defect == 'exit-bool':
                    suite.bad_exit = 'compile selected fiber_port'
                elif defect == 'dirty':
                    suite.dirty_label = 'disassemble selected'
                elif defect == 'close':
                    suite.watch.fail_close = True
                elif defect == 'phase':
                    suite.fail_end = True
                else:
                    suite.fail_save = True
                with self.assertRaises((ValueError, OSError)):
                    self.subject.build(suite, suite.modules)
                self.assertEqual(suite.report['Status'], 'FAIL')
                self.assertIs(suite.report['PortPolicyBuilt'], False)
                self.assertIs(suite.report['SelectedPortAttributePolicyProven'], False)
                self.assertEqual(suite.report['RequiredCellsSatisfied'], 0)
                self.assertTrue(suite.report['PrimaryError'])
                self.assertLessEqual(len(suite.commands), 134)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('fresh external output directory required')
    paths = dict(subject=HERE / 'port_policy_phase.py', tests=Path(__file__).resolve(),
                 **{name: ROOT / relative for name, (relative, _) in PINS.items()})
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_PORT_POLICY_BUILD_CONTROLS',
        Tests=0, ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticTools=True, ActualELFParsed=False, ActualCaptureRead=False,
        ExternalToolsExecuted=0, TargetExecution=False, IndependentMachineProof=False,
        Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        # Authenticate every helper buffer before executing ANY imported helper.
        for name, (_, expected) in PINS.items():
            if sha(buffers[name]) != expected:
                raise ValueError('helper hash before execution: ' + name)
        with patch('subprocess.Popen', side_effect=AssertionError('no external processes in pure controls')):
            for name in ('subject', *PINS):
                module = ModuleType('_os_port_policy_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                LOADED[name] = module
            if LOADED['subject'].HELPER_PINS != PINS:
                raise ValueError('independent helper pin registry mismatch')
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(PortPolicyTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact twelve pure methods required')
            result = unittest.TextTestRunner(verbosity=2).run(tests)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    for path, expected in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != expected:
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
