"""Synthetic Os attribute-build controls; no native tool or ELF execution."""

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
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATHS = dict(subject=HERE / 'attributes_phase.py', recipes=HERE / 'batch_recipes.py',
    attributes=HERE.parent / 'cm3_lto_attributes/attributes.py',
    attribute_runner=HERE.parent / 'cm3_lto_attributes/runner.py',
    ownership=HERE.parent / 'cm0_final_cell/ownership.py', probes=HERE.parent / 'cm0_final_cell/components.py')
SOURCE_NAMES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'tools/runtime_sources.json', 'context/context_api_decl.h', 'context/context_api_attributes.h',
    'context/context_api_types.h', 'context/context_port_abi.h', 'context/context_runtime_port_abi.h',
    'context/context_runtime_state.h', 'context/context_panic.h', 'fiber/fiber_api_attributes.h')
METHODS = 14
LOADED, BUFFERS = {}, {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def os_facts(**extra):
    return dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, **extra)


class Watch:
    def __init__(self):
        self.hashes, self.fail_close = {}, False

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes()
        digest = sha(raw)
        if expected is not None and digest != expected:
            raise ValueError('synthetic expected hash mismatch')
        if path in self.hashes and self.hashes[path] != digest:
            raise ValueError('synthetic input drift')
        self.hashes[path] = digest
        return raw

    def close(self):
        if self.fail_close:
            raise ValueError('synthetic physical closing failure')
        for path, digest in self.hashes.items():
            if sha(path.read_bytes()) != digest:
                raise ValueError('synthetic input drift')


class FakeSuite:
    """Materialize explicitly fake compiler products, not ARM artifacts."""
    def __init__(self, root):
        self.base, self.output = root / 'seed', root / 'output'
        self.output.mkdir()
        self.watch = Watch()
        self.tools = dict(gcc=root / 'gcc.exe', objdump=root / 'objdump.exe')
        self._started, self._finished, self.phase_start = True, False, None
        self.phases = [dict(Name='ABIControls', First=0, Stop=41, Commands=41),
                       dict(Name='Isolation', First=41, Stop=53, Commands=12)]
        self.commands = [dict(Label='synthetic previous phase') for unused in range(53)]
        self.result, self.report = os_facts(), os_facts(Status='FAIL', RequiredCellsSatisfied=0, Compilations=[],
            Error=None, PrimaryError=None, ClosingErrors=[], InputClosureVerified=False, OutputSealVerified=False)
        self.bundle, self.sources = dict(Artifacts={}), []
        for name in SOURCE_NAMES:
            path = self.base / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = BUFFERS[ROOT / name]
            path.write_bytes(raw)
            self.bundle['Artifacts']['source/' + name] = sha(raw)
            self.watch.read(path)
        for name in LOADED['subject'].COMMON:
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-std=gnu11',
                '-g0', '-ffreestanding', '-flto', '-fno-fat-lto-objects', '-I' + str(self.base / 'source/context'),
                '-I' + str(self.base / 'source/fiber'), '-I' + str(self.base / 'source'),
                '-I' + str(self.base / 'cmsis'), '-include',
                str(self.base / 'source/tools/fixtures/classic_final_image/main.h')]
            deps = [dict(Path=str(self.base / 'source' / item), Sha256=sha(BUFFERS[ROOT / item])) for item in SOURCE_NAMES]
            self.sources.append(dict(Source=str(self.base / 'source' / name), CompileFlags=flags,
                                     ActualCompileDependencies=deps))
        self.api = SimpleNamespace(checked_path=lambda path: Path(path), files_under=lambda root:
            {path.relative_to(root).as_posix(): path for path in root.rglob('*') if path.is_file()})
        self.native = SimpleNamespace(read_dependencies=lambda path: [Path(name) for name in json.loads(path.read_bytes())],
            require_compile_dependencies=self.same_dependencies)
        self.verify_objects = Mock()
        self.fail_label = self.extra_lower = self.missing_lower = self.dual_wrapper = None
        self.bad_dependencies, self.bad_imports, self.bad_specs = False, False, False
        self.optional_gcno = False
        self.recorded, self.unknown_source, self.save_failure = set(), False, False
        self.modules = {key: value for key, value in LOADED.items() if key != 'subject'}
        self.modules['recipes'] = SimpleNamespace(batch_plan=LOADED['recipes'].batch_plan,
            compile_flags=lambda report, index: copy.deepcopy(self.sources[index]['CompileFlags']),
            require_capture_sources=self.require_capture)

    def source(self, index):
        return copy.deepcopy(self.sources[index])

    def require_capture(self, report):
        if report is not self.result or report.get('Mode') != 'Os-lto':
            raise ValueError('synthetic capture admission')

    def same_dependencies(self, before, after):
        if before != after:
            raise ValueError('synthetic discovery/compile dependency mismatch')

    def write_input(self, name, raw):
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.recorded.add(path)
        self.watch.read(path)
        return path

    def record_output(self, path, required=True):
        if not path.exists() and not required:
            return None
        self.recorded.add(path)
        return dict(Path=str(path), Sha256=sha(path.read_bytes()))

    def _save(self, name, value):
        if self.save_failure:
            raise OSError('synthetic diagnostic receipt write failed')
        path = self.output / name
        path.write_bytes((json.dumps(value, sort_keys=True) + '\n').encode('ascii'))

    def begin_phase(self, name):
        if name != 'CommonAttributes' or self.phase_start is not None:
            raise AssertionError('wrong synthetic phase')
        self.phase_start = name, len(self.commands)

    def end_phase(self):
        if self.phase_start != ('CommonAttributes', 53) or len(self.commands) != 98:
            raise AssertionError('wrong synthetic phase range')
        self.phases.append(dict(Name='CommonAttributes', First=53, Stop=98, Commands=45))
        self.phase_start = None

    def command(self, argv, label):
        if self.fail_label == label:
            raise ValueError('synthetic managed stage failure: ' + label)
        index = len(self.commands)
        stdout, stderr = b'', b''
        if label == 'dump compiler specs':
            stdout = b'prefix %{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov} suffix\n'
            if self.bad_specs:
                stdout += stdout
        elif label.startswith(('discover ', 'compile ')):
            source = Path(argv[-1] if '-M' in argv else argv[argv.index('-c') + 1])
            dep = Path(argv[argv.index('-MF') + 1])
            names = [str(source)]
            if self.bad_dependencies:
                names += [str(self.base / 'cmsis/foreign.h')]
            dep.write_bytes(json.dumps(names).encode('ascii'))
            if '-c' in argv:
                obj = Path(argv[argv.index('-o') + 1])
                obj.write_bytes(b'SYNTHETIC SLIM INPUT, NOT ELF')
                if self.optional_gcno:
                    obj.with_suffix('.gcno').write_bytes(b'synthetic optional gcno')
        elif label.startswith('lower '):
            obj = Path(argv[-1])
            for suffix in ('', '.ltrans.out', '.ltrans0.ltrans.args.0', '.ltrans0.ltrans.o',
                    '.ltrans0.ltrans.s', '.ltrans0.ltrans_args', '.ltrans0.o', '.ltrans_args', '.res', '.wpa.args.0'):
                Path(str(obj) + suffix).write_bytes(b'SYNTHETIC LOWER ROLE, NOT ELF OR WORKER EVIDENCE')
            (obj.parent / 'aggregate.o.lto_wrapper_args').write_bytes(b'synthetic wrapper')
            if self.extra_lower:
                (obj.parent / 'foreign.bin').write_bytes(b'unowned output')
            if self.missing_lower:
                Path(str(obj) + '.ltrans0.ltrans.o').unlink()
            if self.dual_wrapper:
                (self.output / (''.join(obj.parts[1:]) + '.lto_wrapper_args')).write_bytes(b'synthetic duplicate')
            stderr = b'synthetic verbose transcript, not compiler execution evidence'
        elif label.startswith('disassemble '):
            stdout = b'synthetic disassembly, not machine evidence'
        self.commands.append(dict(Label=label, Argv=argv, State='TERMINAL', Status='PASS', Exit=0,
            ExpectedExit=0, TimedOut=False, JournalErrors=[]))
        path = self.output / ('commands/%03d.stderr' % index)
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(stderr)
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0, timed_out=False)

    def inspect_ir(self, obj):
        self.command(['synthetic-readelf', str(obj)], 'inspect slim ' + obj.stem)
        return dict(SlimIR=True, NativeFallback=False)

    def _undefined(self, obj, label):
        self.command(['synthetic-nm', str(obj)], 'imports ' + label)
        attrs = LOADED['attributes']
        if label.startswith('stress-'):
            names = []
        elif obj.stem == 'context_core':
            names = sorted((set(attrs.FORWARD) - {attrs.FORWARD[1], attrs.FORWARD[2]})
                | {attrs.PANIC, attrs.STATE[0], attrs.STATE[2], attrs.STATE[4], attrs.STATE[5], attrs.COLD})
        elif obj.stem == 'context_runtime_state':
            names = sorted({attrs.PANIC, attrs.FORWARD[1]} | attrs.GCOV_IMPORTS)
        else:
            names = [attrs.FORWARD[1], attrs.FORWARD[2]]
        if label.startswith('mutant-'):
            names = sorted(set(names) | attrs.GCOV_IMPORTS)
        if self.bad_imports:
            names.append('foreign_runtime_dependency')
        return names, dict(SyntheticOnly=True)


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='os-attributes-phase-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.suite = FakeSuite(Path(self.temporary.name))
        self.subject = LOADED['subject']

    def build(self):
        with patch.object(LOADED['attributes'], 'inspect_lowered', side_effect=AssertionError('machine predicate ran')), \
                patch.object(LOADED['attributes'], 'require_hostile_options', side_effect=AssertionError('O2 options predicate ran')), \
                patch.object(LOADED['attribute_runner'], 'run', side_effect=AssertionError('O2 driver ran')), \
                patch.object(LOADED['attribute_runner'], 'prepare', side_effect=AssertionError('O2 constructor ran')):
            return self.subject.build(self.suite, self.suite.modules)

    def test_plan_exactly_matches_fixed_45_command_range(self):
        self.assertEqual(len(self.subject.command_plan()), 45)
        self.assertEqual(self.subject.command_plan(), LOADED['attribute_runner'].command_plan())
        plan = LOADED['recipes'].batch_plan()['Commands'][53:98]
        self.assertEqual(tuple(row['Label'] for row in plan), self.subject.command_plan())
        self.assertEqual([row['ExpectedExit'] for row in plan], [0] * 45)

    def test_os_cpu_free_flags_keep_slim_and_all_six_raw_without_counters(self):
        before = self.suite.source(0)['CompileFlags']
        root = self.suite.output / 'private-root'
        flags = self.subject.flags_for(self.suite, 0, root, self.suite.modules)
        self.assertEqual(flags[-6:], list(self.subject.RAW_FLAGS))
        self.assertEqual(flags.count('-Os'), 1)
        self.assertIn('-flto', flags)
        self.assertIn('-fno-fat-lto-objects', flags)
        self.assertNotIn('-include', flags)
        self.assertFalse(any('cmsis' in flag for flag in flags))
        self.assertIn('-I' + str(root / 'context'), flags)
        self.assertEqual(self.suite.source(0)['CompileFlags'], before)

    def test_flags_reject_boolean_role_o2_optimization_or_repeated_hostile(self):
        for index in (True, -1, 3):
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.subject.flags_for(self.suite, index, self.suite.base / 'source', self.suite.modules)
        for flag in ('-O2', '-O3', '-finstrument-functions'):
            original = copy.deepcopy(self.suite.sources[0]['CompileFlags'])
            self.suite.sources[0]['CompileFlags'].append(flag)
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.subject.flags_for(self.suite, 0, self.suite.base / 'source', self.suite.modules)
            self.suite.sources[0]['CompileFlags'] = original

    def test_complete_synthetic_build_records_all_roles_but_never_proves_effects(self):
        record = self.build()
        self.assertEqual((len(self.suite.commands), record['Commands']), (98, 45))
        self.assertEqual(tuple(row['Group'] for row in record['Lowerings']), self.subject.LOWERS)
        self.assertEqual(len(record['Compilations']), 8)
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertEqual(self.suite.report['RequiredCellsSatisfied'], 0)
        self.assertEqual(record['Status'], 'BUILT-PENDING-READER')
        self.assertIs(record['DeferredReaderRequired'], True)
        for name in self.subject.DEFERRED:
            self.assertIs(record[name], False)
            self.assertIs(self.suite.report[name], False)
        for row in record['Lowerings']:
            self.assertIs(row['WorkerOptionsValidated'], False)
            self.assertIs(row['EffectsValidated'], False)
            self.assertEqual(len(row['Roles']), 14)
            for binding in row['Roles'].values():
                self.assertEqual(sha(Path(binding['Path']).read_bytes()), binding['Sha256'])

    def test_mutants_replace_one_ir_and_preserve_unchanged_cohort(self):
        record = self.build()
        original = [row['Path'] for row in record['Lowerings'][0]['Inputs']]
        for index, row in enumerate(record['Lowerings'][1:4]):
            actual = [item['Path'] for item in row['Inputs']]
            self.assertEqual([pos for pos in range(3) if actual[pos] != original[pos]], [index])
            control = record['AnnotationControls'][index]
            self.assertEqual(len(control['Edits']), 2)
            self.assertIs(control['Detected'], False)
            self.assertIs(control['OriginalProtectedPredicateRejected'], False)

    def test_stress_pair_retains_same_body_and_separate_true_false_roles(self):
        record = self.build()
        rows = record['Lowerings'][-2:]
        self.assertEqual([row['Stress'] for row in rows], [True, True])
        self.assertEqual([row['Mutation'] for row in rows], [None, 'ctxrt_attribute_stress'])
        self.assertNotEqual(record['PairedStress']['ProtectedSha256'], record['PairedStress']['UnprotectedSha256'])
        for row in rows:
            self.assertEqual(len(row['Inputs']), 1)

    def test_wrong_prefix_phase_count_types_or_order_reject_before_commands(self):
        for kind in ('short', 'phase-order', 'float'):
            before = copy.deepcopy(self.suite.phases)
            if kind == 'short':
                self.suite.commands.pop()
            elif kind == 'phase-order':
                self.suite.phases.reverse()
            else:
                self.suite.phases[0]['Stop'] = 41.0
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.build()
            self.suite.phases = before
            self.suite.commands = [dict(Label='synthetic previous phase') for unused in range(53)]

    def test_wrong_mode_and_promoted_entry_reject_before_tools(self):
        for key, bad in (('Mode', 'O2-lto'), ('LTO', 1), ('Linkage', 'archive')):
            self.suite.result[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build()
            self.suite.result = os_facts()
        self.suite.report['Status'] = 'PASS'
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(len(self.suite.commands), 53)

    def test_plan_labels_and_exit_alias_mutations_are_not_accepted(self):
        self.build()
        for key, bad in (('Label', 'foreign'), ('Exit', False), ('ExpectedExit', 0.0),
                         ('State', 'ATTEMPT'), ('TimedOut', True), ('JournalErrors', ['fault'])):
            row = self.suite.commands[53]
            before = copy.deepcopy(row)
            row[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.subject._commands(self.suite, self.suite.modules['recipes'])
            row.clear()
            row.update(before)

    def test_compile_failure_preserves_primary_and_records_receipt_failure(self):
        self.suite.fail_label = 'compile positive context_core'
        self.suite.report['PrimaryError'] = 'first process failure'
        self.suite.save_failure = True
        with self.assertRaisesRegex(ValueError, 'managed stage failure'):
            self.build()
        self.assertEqual(self.suite.report['PrimaryError'], 'first process failure')
        self.assertIs(self.suite.report['CommonAttributesBuilt'], False)
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertTrue(any('receipt write failed' in item for item in self.suite.report['ClosingErrors']))

    def test_unadmitted_cpu_dependency_and_foreign_ir_import_reject(self):
        self.suite.bad_dependencies = True
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertFalse(any(row.get('Label', '').startswith('lower ') for row in self.suite.commands))
        temporary = tempfile.TemporaryDirectory(prefix='os-attributes-import-mutant-')
        self.addCleanup(temporary.cleanup)
        self.suite = FakeSuite(Path(temporary.name))
        self.suite.bad_imports = True
        with self.assertRaises(ValueError):
            self.build()
        self.assertIs(self.suite.report['CommonAttributesBuilt'], False)

    def test_unknown_missing_and_duplicate_wrapper_outputs_reject(self):
        for option in ('extra_lower', 'missing_lower', 'dual_wrapper'):
            with self.subTest(option=option):
                temporary = tempfile.TemporaryDirectory(prefix='os-attributes-output-mutant-')
                self.addCleanup(temporary.cleanup)
                self.suite = FakeSuite(Path(temporary.name))
                setattr(self.suite, option, True)
                with self.assertRaises(ValueError):
                    self.build()
                self.assertIs(self.suite.report['CommonAttributesBuilt'], False)

    def test_optional_gcno_is_retained_and_phase_cannot_retry(self):
        self.suite.optional_gcno = True
        record = self.build()
        self.assertTrue(all(row['CoverageNotes'] is not None for row in record['Compilations']))
        count = len(self.suite.commands)
        with self.assertRaisesRegex(ValueError, 'cannot retry'):
            self.build()
        self.assertEqual(len(self.suite.commands), count)

    def test_specs_ambiguity_and_final_closing_fault_leave_unpromoted_failure(self):
        self.suite.bad_specs = True
        with self.assertRaises(ValueError):
            self.build()
        self.assertEqual(len(self.suite.commands), 54)
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        temporary = tempfile.TemporaryDirectory(prefix='os-attributes-closing-fault-')
        self.addCleanup(temporary.cleanup)
        self.suite = FakeSuite(Path(temporary.name))
        original, calls = self.suite.watch.close, []
        def fail_final_close():
            calls.append(True)
            if len(calls) == 7:
                raise ValueError('synthetic final closing fault')
            return original()
        self.suite.watch.close = fail_final_close
        with self.assertRaisesRegex(ValueError, 'final closing fault'):
            self.build()
        self.assertEqual(len(self.suite.commands), 98)
        self.assertIs(self.suite.report['CommonAttributesBuilt'], False)
        self.assertIs(self.suite.report['InputClosureVerified'], False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), *PATHS.values(), *(ROOT / name for name in SOURCE_NAMES))
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CM3_OS_COMMON_ATTRIBUTES_BUILD_CONTROLS_ONLY',
        Tests=0, ExpectedTestMethods=METHODS, Errors=0, Failures=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticCompilerOutputs=True,
        ActualCompilerExecuted=False, ActualELFTested=False, MachineEffectsInspected=False,
        Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('isolated unoptimized -I -S -B host Python required')
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic controls cannot spawn')), \
                patch('os.system', side_effect=AssertionError('synthetic controls cannot execute tools')):
            for name, path in PATHS.items():
                if name != 'subject' and sha(BUFFERS[path]) != LOADED['subject'].HELPER_PINS[name]:
                    raise ValueError('frozen helper source identity: ' + name)
                module = ModuleType('_os_attributes_phase_' + name)
                module.__file__ = str(path)
                exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
                LOADED[name] = module
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(PhaseTests)
            if suite.countTestCases() != METHODS:
                raise ValueError('exact fourteen implemented methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report['ClosingFilesVerified'] += 1
                else:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(paths) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
