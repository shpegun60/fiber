"""Synthetic recipe/plan controls; optional retained JSON replay is metadata only."""

import argparse
import ast
import copy
import hashlib
import json
import math
import ntpath
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SUBJECT = HERE / 'batch_recipes.py'
PLAN_PINS = {
    'Isolation': (HERE.with_name('cm3_lto_isolation') / 'isolation.py',
        '6EC1242D0ABBB120E2D684B30389B81043A67D267DE6F01F63F400FEC3E76524', ('COMMON',)),
    'CommonAttributes': (HERE.with_name('cm3_lto_attributes') / 'runner.py',
        '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A', ('COMMON', 'LOWERS')),
    'PortPolicy': (HERE.with_name('cm3_lto_port_policy') / 'runner.py',
        'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB', ('SELECTED',)),
}
SOURCE_NAMES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
EXPECTED_METHODS = 20
subject = None
plan_helpers = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def join(root, relative):
    return ntpath.join(root, *relative.split('/'))


def seed_flags(seed, relative, index):
    target = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2']
    if index == 8:
        return target + ['-g0', '-DPILOT_HAS_VTOR=1']
    root = join(seed, 'source')
    includes = ['tools/fixtures/classic_final_image', 'fiber/port/ARM_CM3',
                'fiber/port', 'fiber', 'context', '']
    return target + ['-std=gnu11', '-g0', '-ffreestanding', '-ffunction-sections', '-fdata-sections',
        '-Wall', '-Wextra', '-Werror=implicit-function-declaration', '-Werror=attributes',
        '-Werror=ignored-attributes', '-DFIBER_PORT_ARMV7M=1', '-DFIBER_PORT_BUILD_SELECTED=1',
        '-DFIBER_SCHEDULER_BASEPRI=16'] + ['-I' + (join(root, value) if value else root) for value in includes] + [
        '-I' + join(seed, 'cmsis'), '-include', join(root, 'tools/fixtures/classic_final_image/main.h'),
        '-I' + join(root, relative.rsplit('/', 1)[0])]


def capture_fixture():
    """Independent synthetic metadata, not a fabricated actual-capture receipt."""
    seed, root = r'C:\synthetic\seed', r'C:\synthetic\capture'
    gcc = join(root, 'toolchain/bin/arm-none-eabi-gcc.exe')
    report = dict(Status='PASS', Scope='NATIVE_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY', Profile='CM3',
        Mode='Os-lto', Linkage='direct', SeedMode='O2', LTO=True,
        Cohort='cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default',
        SourceInventorySha256='69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313',
        TranslationUnits=9, SlimIRObjects=8, SeedBuild=seed, CapturedCompiler=gcc,
        Qualification=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        Error=None, PrimaryError=None, ClosingErrors=[], InputClosureVerified=True,
        OutputSealVerified=True, Sources=[], Commands=[], Links=[])
    for index, relative in enumerate(SOURCE_NAMES):
        source = join(seed, 'source/' + relative)
        stem = relative.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        obj = join(root, 'objects/%02d-%s.o' % (index, stem))
        flags = seed_flags(seed, relative, index)
        actual = ['-Os' if value == '-O2' else value for value in flags]
        if index < 8:
            actual += ['-flto', '-fno-fat-lto-objects']
        row = dict(Source=source, SourceSha256='A' * 64, Object=obj, ObjectSha256='B' * 64,
            DependencyFile=obj[:-2] + '.d', SlimIR=index < 8, SeedCompileFlags=flags,
            CompileFlags=actual, CompileDependenciesVerified=True,
            ActualCompileDependencies=[dict(Path=source, Sha256='A' * 64)])
        report['Sources'].append(row)
        report['Commands'].append(dict(Label='compile ' + relative.rsplit('/', 1)[-1],
            Argv=[gcc, *actual, '-MD', '-MF', row['DependencyFile'], '-MT', 'pilot-source-' + str(index),
                  '-c', source, '-o', obj], State='TERMINAL', Status='PASS', Exit=0, TimedOut=False, Seconds=0.25))
    for kind in ('ordinary', 'emit-relocs'):
        path = join(root, kind + '/image.elf')
        link_map = join(root, kind + '/image.map')
        report['Links'].append(dict(Kind=kind, Path=path, Map=link_map,
            Machine=path + '.ltrans0.ltrans.o', Sha256='C' * 64))
        argv = [gcc, '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-flto',
            '-flto-partition=one', '-save-temps=obj', '-v', '-nostdlib', '-Wl,-plugin-opt=-save-temps',
            '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
            '-T', join(seed, 'source/tools/fixtures/classic_final_image/link.ld'),
            *(row['Object'] for row in report['Sources'])]
        if kind == 'emit-relocs':
            argv += ['-Wl,--emit-relocs']
        argv += ['-Wl,-Map=' + link_map, '-o', path]
        report['Commands'].append(dict(Label='link ' + kind, Argv=argv, State='TERMINAL',
            Status='PASS', Exit=0, TimedOut=False, Seconds=1.5))
    return report


def command(report, label):
    return next(row for row in report['Commands'] if row['Label'] == label)


class RecipeTests(unittest.TestCase):
    def rejects(self, report):
        with self.assertRaises(subject.Rejected):
            subject.require_capture_sources(report)

    def test_all_nine_real_os_flag_shapes_and_fresh_return(self):
        report = capture_fixture()
        self.assertIsNone(subject.require_capture_sources(report))
        for index in range(9):
            flags = subject.compile_flags(report, index)
            self.assertEqual(flags, report['Sources'][index]['CompileFlags'])
            self.assertEqual([x for x in flags if x.startswith('-O')], ['-Os'])
            self.assertEqual('-flto' in flags, index < 8)
            flags.append('mutated-return-only')
            self.assertNotIn('mutated-return-only', report['Sources'][index]['CompileFlags'])

    def test_link_recipe_only_removes_single_verbose_preserving_raw_order(self):
        report = capture_fixture()
        objects = [row['Object'] for row in report['Sources']]
        original = command(report, 'link ordinary')['Argv']
        self.assertEqual(subject.link_recipe(report, objects), [value for value in original if value != '-v'])
        self.assertEqual(subject.link_recipe(report, tuple(PureWindowsPath(x) for x in objects)),
                         [value for value in original if value != '-v'])
        self.assertIn('-v', original)

    def test_route_scope_inventory_and_literal_counters(self):
        mutations = [('Mode', 'O2-lto'), ('Profile', 'CM7'), ('Linkage', 'archive'), ('SeedMode', 'Os'),
                     ('Scope', 'anything'), ('SourceInventorySha256', 'A' * 64), ('Cohort', 'foreign'),
                     ('Status', 'FAIL'), ('LTO', 1), ('Qualification', 0), ('RequiredCellSatisfied', 0)]
        mutations += [(key, value) for key, count in (('TranslationUnits', 9), ('SlimIRObjects', 8),
                       ('RequiredCellsSatisfied', 0)) for value in (float(count), False, str(count))]
        for key, value in mutations:
            report = capture_fixture()
            report[key] = value
            with self.subTest(key=key, value=value):
                self.rejects(report)

    def test_incomplete_capture_or_failure_declarations_reject(self):
        for key, value in (('Error', 'failed'), ('PrimaryError', 'late failure'), ('ClosingErrors', ['drift']),
                           ('ClosingErrors', ()), ('InputClosureVerified', 1), ('OutputSealVerified', False)):
            report = capture_fixture()
            report[key] = value
            with self.subTest(key=key):
                self.rejects(report)

    def test_source_count_order_and_cross_role_aliases_reject(self):
        for change in ('empty', 'short', 'extra', 'swap', 'object-alias', 'source-alias'):
            report = capture_fixture()
            rows = report['Sources']
            if change == 'empty':
                report['Sources'] = []
            elif change == 'short':
                rows.pop()
            elif change == 'extra':
                rows.append(copy.deepcopy(rows[-1]))
            elif change == 'swap':
                rows[0], rows[1] = rows[1], rows[0]
            elif change == 'object-alias':
                rows[1]['Object'] = rows[0]['Object']
            else:
                rows[1]['Source'] = rows[0]['Source']
            with self.subTest(change=change):
                self.rejects(report)

    def test_literal_index_and_slim_roles(self):
        for value in (True, False, 0.0, '0', -1, 9):
            with self.subTest(index=value), self.assertRaises(subject.Rejected):
                subject.compile_flags(capture_fixture(), value)
        for index in (0, 8):
            for value in (int(index < 8), not (index < 8)):
                report = capture_fixture()
                report['Sources'][index]['SlimIR'] = value
                with self.subTest(index=index, slim=value):
                    self.rejects(report)

    def test_coherent_extra_counter_or_target_flags_reject(self):
        for flag in ('-mcpu=cortex-m7', '-mfpu=fpv4-sp-d16', '-fno-instrument-functions', '-DUNDECLARED=1'):
            report = capture_fixture()
            row = report['Sources'][0]
            row['SeedCompileFlags'].append(flag)
            row['CompileFlags'].insert(-2, flag)
            compile_command = command(report, 'compile context_core.c')
            at = compile_command['Argv'].index('-MD')
            compile_command['Argv'].insert(at - 2, flag)
            with self.subTest(flag=flag):
                self.rejects(report)

    def test_actual_flags_are_only_seed_transform_not_flag_set_equivalence(self):
        for change in ('O2', 'foreign-Os', 'duplicate', 'reorder', 'fat', 'startup-lto'):
            report = capture_fixture()
            flags = report['Sources'][8 if change == 'startup-lto' else 0]['CompileFlags']
            if change == 'O2':
                flags[3] = '-O2'
            elif change == 'foreign-Os':
                flags.append('-O3')
            elif change == 'duplicate':
                flags.append('-Os')
            elif change == 'reorder':
                flags[0], flags[1] = flags[1], flags[0]
            elif change == 'fat':
                flags[-1] = '-ffat-lto-objects'
            else:
                flags += ['-flto', '-fno-fat-lto-objects']
            with self.subTest(change=change):
                self.rejects(report)

    def test_dependency_shape_own_source_hash_and_aliases(self):
        for change in ('empty', 'own-hash', 'duplicate', 'extra-key', 'bad-hash', 'not-verified'):
            report = capture_fixture()
            row = report['Sources'][0]
            deps = row['ActualCompileDependencies']
            if change == 'empty':
                row['ActualCompileDependencies'] = []
            elif change == 'own-hash':
                deps[0]['Sha256'] = 'F' * 64
            elif change == 'duplicate':
                deps.append(dict(deps[0], Path=deps[0]['Path'].upper()))
            elif change == 'extra-key':
                deps[0]['Unexpected'] = True
            elif change == 'bad-hash':
                row['ObjectSha256'] = 'short'
            else:
                row['CompileDependenciesVerified'] = 1
            with self.subTest(change=change):
                self.rejects(report)

    def test_actual_compile_argv_labels_and_compiler_counts(self):
        for change in ('missing', 'duplicate', 'flags', 'output', 'MT', 'extra-compile'):
            report = capture_fixture()
            row = command(report, 'compile context_core.c')
            if change == 'missing':
                report['Commands'].remove(row)
            elif change == 'duplicate':
                report['Commands'].append(copy.deepcopy(row))
            elif change == 'flags':
                row['Argv'][4] = '-O2'
            elif change == 'output':
                row['Argv'][-1] = report['Sources'][1]['Object']
            elif change == 'MT':
                row['Argv'][row['Argv'].index('-MT') + 1] = 'foreign-target'
            else:
                report['Commands'].append(dict(row, Label='unaccounted compiler source'))
            with self.subTest(change=change):
                self.rejects(report)
        report = capture_fixture()
        report['Commands'].append(dict(Label='provenance git', Argv=[r'C:\git\git.exe', '-c', 'safe.directory=x',
            '-C', r'C:\reference', 'rev-parse', 'HEAD']))
        subject.require_capture_sources(report)

    def test_command_terminal_exit_duration_and_journal_types(self):
        for key, value in (('State', 'ATTEMPT'), ('Status', 'FAIL'), ('Exit', False), ('Exit', 0.0),
                ('TimedOut', 0), ('Seconds', False), ('Seconds', math.inf), ('Seconds', math.nan),
                ('Seconds', -1), ('JournalErrors', ['write error'])):
            report = capture_fixture()
            command(report, 'compile startup.S')[key] = value
            with self.subTest(key=key, value=value):
                self.rejects(report)

    def test_twin_membership_and_applied_reloc_flag_position(self):
        for change in ('missing', 'reverse', 'foreign-map', 'machine-role', 'missing-emit', 'emit-order'):
            report = capture_fixture()
            if change == 'missing':
                report['Links'].pop()
            elif change == 'reverse':
                report['Links'].reverse()
            elif change == 'foreign-map':
                report['Links'][1]['Map'] = report['Links'][0]['Map']
            elif change == 'machine-role':
                report['Links'][1]['Machine'] = report['Links'][0]['Machine']
            else:
                argv = command(report, 'link emit-relocs')['Argv']
                argv.remove('-Wl,--emit-relocs')
                if change == 'emit-order':
                    argv.append('-Wl,--emit-relocs')
            with self.subTest(change=change):
                self.rejects(report)

    def test_link_recipe_rejects_extra_flags_wrong_order_and_missing_retention(self):
        for change in ('object-order', 'foreign-object', 'counter', 'missing-plugin', 'missing-v', 'double-v', 'O2'):
            report = capture_fixture()
            argv = command(report, 'link ordinary')['Argv']
            if change == 'object-order':
                left = argv.index(report['Sources'][0]['Object'])
                argv[left], argv[left + 1] = argv[left + 1], argv[left]
            elif change == 'foreign-object':
                argv[argv.index(report['Sources'][0]['Object'])] = r'C:\foreign\object.o'
            elif change == 'counter':
                argv.insert(2, '-fno-sanitize=all')
            elif change == 'missing-plugin':
                argv.remove('-Wl,-plugin-opt=-save-temps')
            elif change == 'missing-v':
                argv.remove('-v')
            elif change == 'double-v':
                argv.append('-v')
            else:
                argv[argv.index('-Os')] = '-O2'
            with self.subTest(change=change):
                self.rejects(report)

    def test_explicit_link_objects_cannot_be_substituted_or_boolean(self):
        report = capture_fixture()
        original = [row['Object'] for row in report['Sources']]
        for objects in ([], original[:-1], list(reversed(original)), [True, *original[1:]],
                        [original[1], *original[1:]]):
            with self.subTest(objects=objects), self.assertRaises(subject.Rejected):
                subject.link_recipe(report, objects)

    def test_lexical_path_ambiguities_and_foreign_compiler(self):
        for field, value in (('SeedBuild', r'C:relative'), ('SeedBuild', r'C:\seed\..\other'),
                ('SeedBuild', r'C:\seed\trailing.'), ('CapturedCompiler', r'C:\tool\clang.exe'),
                ('SeedBuild', '\\\\server\\share\\seed')):
            report = capture_fixture()
            report[field] = value
            with self.subTest(field=field, value=value):
                self.rejects(report)

    def test_all_four_plans_and_exact_half_open_ranges(self):
        plan = subject.batch_plan(plan_helpers=plan_helpers)
        self.assertEqual(subject.component_ranges(), [dict(Name=name, Start=start, Stop=stop, Count=count)
            for name, start, stop, count in (('ABIControls', 0, 41, 41), ('Isolation', 41, 53, 12),
                ('CommonAttributes', 53, 98, 45), ('PortPolicy', 98, 134, 36))])
        self.assertEqual(plan['TotalCommands'], 134)
        self.assertEqual([row['Index'] for row in plan['Commands']], list(range(134)))
        self.assertEqual(sum(row['ExpectedExit'] == 1 for row in plan['Commands']), 8)
        self.assertEqual(plan['PlannedExpectedNonzeroCommands'], 8)
        self.assertEqual(plan['Route'], 'CM3/Os-lto/direct')

    def test_frozen_plan_drift_missing_helper_and_wrong_types_reject(self):
        good = dict(plan_helpers)
        for change in ('missing', 'extra', 'wrong-list-type', 'truncated', 'same-count-wrong-label'):
            helpers = dict(good)
            if change == 'missing':
                del helpers['Isolation']
            elif change == 'extra':
                helpers['Unknown'] = helpers['Isolation']
            else:
                actual = helpers['Isolation'].command_plan()
                altered = list(actual) if change == 'wrong-list-type' else actual[:-1] if change == 'truncated' else ('foreign', *actual[1:])
                helpers['Isolation'] = SimpleNamespace(command_plan=lambda value=altered: value)
            with self.subTest(change=change), self.assertRaises(subject.Rejected):
                subject.batch_plan(plan_helpers=helpers)

    def test_plan_returns_fresh_metadata_without_promotions(self):
        plan = subject.batch_plan()
        plan['Components'][0]['Labels'].clear()
        plan['Commands'][0]['Label'] = 'mutated'
        fresh = subject.batch_plan()
        self.assertEqual(len(fresh['Components'][0]['Labels']), 41)
        self.assertEqual(fresh['Commands'][0]['Label'], 'link positive')
        self.assertIs(fresh['PlanOnly'], True)
        for key in ('CaptureAdmissionPerformed', 'ExecutionPerformed', 'Qualification', 'CellContractSatisfied',
                    'RequiredCellSatisfied', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
            self.assertIs(fresh[key], False)
        self.assertIs(type(fresh['RequiredCellsSatisfied']), int)
        self.assertEqual(fresh['RequiredCellsSatisfied'], 0)

    def test_model_does_not_access_files_processes_or_mutate_inputs(self):
        report = capture_fixture()
        before = copy.deepcopy(report)
        with patch('builtins.open', side_effect=AssertionError('model file I/O')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('model path I/O')):
            subject.compile_flags(report, 0)
            subject.link_recipe(report, [row['Object'] for row in report['Sources']])
            subject.batch_plan(plan_helpers=plan_helpers)
        self.assertEqual(report, before)

    def test_module_has_no_dynamic_loading_or_process_facility(self):
        self.assertFalse(any(name in vars(subject) for name in ('open', 'Path', 'subprocess', 'importlib', 'os')))
        self.assertEqual(subject.SOURCES, SOURCE_NAMES)


def load_plans(raw, path, constants):
    tree = ast.parse(raw, filename=str(path))
    chosen = [node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id in constants for target in node.targets)]
    chosen += [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'command_plan']
    if len(chosen) != len(constants) + 1:
        raise ValueError('exact frozen plan function/constants')
    namespace = dict(Path=PurePosixPath)
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(path), 'exec'), namespace)
    return SimpleNamespace(command_plan=namespace['command_plan'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--capture-report', type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT, *(row[0] for row in PLAN_PINS.values()))
    report = dict(Status='FAIL', Scope='PURE_CM3_OS_LTO_BATCH_RECIPE_MODEL_CONTROLS_ONLY', Tests=0,
        ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, InputHashes={},
        SourceDrift=[], ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticInputs=True,
        RetainedMetadataReplayed=False, QualifiedParserExecuted=False, ActualELFTested=False,
        ToolInvocations=0, ExecutionPerformed=False, Qualification=False, CellContractSatisfied=False,
        RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        buffers = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        global subject, plan_helpers
        subject = ModuleType('_os_batch_recipe_subject')
        subject.__file__ = str(SUBJECT)
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls cannot spawn')), \
                patch('os.system', side_effect=AssertionError('pure controls cannot execute tools')):
            exec(compile(buffers[SUBJECT], str(SUBJECT), 'exec'), subject.__dict__)
            plan_helpers = {}
            for name, (path, expected, constants) in PLAN_PINS.items():
                if sha(buffers[path]) != expected:
                    raise ValueError('frozen plan source pin: ' + str(path))
                plan_helpers[name] = load_plans(buffers[path], path, constants)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(RecipeTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact twenty implemented pure methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
                Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                    for case, detail in result.failures + result.errors])
            if args.capture_report:
                path = args.capture_report.resolve()
                raw = path.read_bytes()
                report['InputHashes'][str(path)] = sha(raw)
                value = json.loads(raw)
                subject.require_capture_sources(value)
                subject.link_recipe(value, [row['Object'] for row in value['Sources']])
                report['RetainedMetadataReplayed'] = True
            if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
                report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
    finally:
        for path, expected in {**report['SourceHashes'], **report['InputHashes']}.items():
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
    receipt.write_bytes((json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
