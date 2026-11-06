"""Pure actual-format Os worker controls; all bytes/paths below are invented."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HELPER = ROOT / 'tools/fixtures/cm3_lto_attributes/runner.py'
HELPER_SHA = '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'
RAW = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
       '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
METHODS = 13
API = HELPERS = HELPER_MODULE = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded_arguments(values):
    # Genuine GCC saved format doubles Windows path separators, one arg/line.
    return ('\n'.join(value.replace('\\', '\\\\') for value in values) + '\n').encode('ascii')


class Watch:
    def __init__(self):
        self.raw, self.reads = {}, []

    def read(self, path, expected=None):
        path = Path(path)
        if path not in self.raw:
            raise ValueError('synthetic unadmitted read: ' + str(path))
        raw = self.raw[path]
        if expected is not None and sha(raw) != expected:
            raise ValueError('synthetic admitted hash mismatch')
        self.reads.append((path, expected))
        return raw


class Fixture:
    """No actual files, ELF parsing, compiler execution or captured receipts."""
    def __init__(self, *, stress=False):
        self.root = Path('C:/synthetic-os-common-workers')
        self.lowered = self.root / 'lowered/aggregate.o'
        self.specs = self.root / 'driver/no-auto-gcov.specs'
        self.objects = [self.root / 'ir' / name for name in
                        (('stress.o',) if stress else ('context_core.o', 'context_runtime_state.o', 'context_panic.o'))]
        self.intermediate = Path(str(self.lowered) + '.ltrans0.o')
        self.machine = Path(str(self.lowered) + '.ltrans0.ltrans.o')
        self.assembly = Path(str(self.lowered) + '.ltrans0.ltrans.s')
        self.wpa_path = Path(str(self.lowered) + '.ltrans_args')
        self.ltrans_path = Path(str(self.lowered) + '.ltrans0.ltrans_args')
        self.wpa_response = Path(str(self.lowered) + '.wpa.args.0')
        self.ltrans_response = Path(str(self.lowered) + '.ltrans0.ltrans.args.0')
        self.partition_path = Path(str(self.lowered) + '.ltrans.out')
        self.lto1 = self.root / 'toolchain/libexec/lto1.exe'
        self.assembler = self.root / 'toolchain/bin/as.exe'
        self.watch = Watch()
        flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', *RAW]
        lower = ['-flto-partition=one', '-nostdlib', '-r', '-flinker-output=nolto-rel']
        self.wpa = [*flags, *lower, '-specs=' + str(self.specs), '-fwpa', *map(str, self.objects)]
        self.ltrans = [*flags, *lower, '-specs=' + str(self.specs), '-fltrans', '-o', str(self.machine), str(self.intermediate)]
        self.actual_wpa = [str(self.lto1), *flags, '-fwpa', '@' + str(self.wpa_response)]
        self.actual_ltrans = [str(self.lto1), *flags, '-fltrans', '-o', str(self.assembly), '@' + str(self.ltrans_response)]
        self.actual_as = [str(self.assembler), '-o', str(self.machine), str(self.assembly)]
        self.watch.raw.update({self.specs: b'synthetic no-auto-gcov specs',
            self.lto1: b'synthetic admitted lto1 executable', self.assembler: b'synthetic admitted as executable',
            self.intermediate: b'synthetic WPA IR, not machine', self.machine: b'synthetic actual machine marker'})
        self.watch.raw.update({path: ('synthetic original IR ' + path.name).encode('ascii') for path in self.objects})
        self.write_saved()
        self.result = dict(ResolvedWorkers={name: dict(Path=str(path), Sha256=sha(self.watch.raw[path]))
            for name, path in (('lto1', self.lto1), ('as', self.assembler))})
        self.suite = SimpleNamespace(watch=self.watch,
            api=SimpleNamespace(checked_path=lambda path: Path(path)), result=self.result,
            transport=SimpleNamespace(require_elf32le=self.synthetic_header),
            admitted=SimpleNamespace(base=SimpleNamespace(stable_path=lambda path: Path(path))))

    @staticmethod
    def synthetic_header(raw):
        if raw != b'synthetic actual machine marker':
            raise ValueError('synthetic ELF-machine marker rejected')
        return dict(Synthetic=True, NotAnActualELF=True)

    def write_saved(self):
        self.watch.raw.update({self.wpa_path: encoded_arguments(self.wpa),
            self.ltrans_path: encoded_arguments(self.ltrans),
            self.wpa_response: encoded_arguments(list(map(str, self.objects))),
            self.ltrans_response: encoded_arguments([str(self.intermediate)]),
            self.partition_path: ('1\n' + str(self.intermediate) + '\n').encode('ascii')})

    def diagnostics(self):
        return ''.join(' ' + ' '.join(row) + '\n' for row in
                       (self.actual_wpa, self.actual_ltrans, self.actual_as)).encode('ascii')

    def run(self):
        return API.worker_chain(self.suite, self.lowered, self.objects, self.specs, self.diagnostics(), HELPERS)


class WorkerTests(unittest.TestCase):
    def test_complete_three_ir_and_stress_worker_chains(self):
        for stress in (False, True):
            with self.subTest(stress=stress):
                fixture = Fixture(stress=stress)
                machine, proof = fixture.run()
                self.assertEqual(machine, fixture.machine)
                self.assertEqual(proof['Mode'], 'Os-lto')
                self.assertEqual(proof['Scope'], 'NATIVE_CM3_OS_LTO_COMMON_RAW_WORKER_CHAIN_ONLY')
                self.assertEqual([row['Path'] for row in proof['WpaInputs']], list(map(str, fixture.objects)))
                self.assertIs(proof['ActualHostileOptionsVerified'], True)
                self.assertIs(proof['SavedArgumentOsOptionsValidated'], True)
                self.assertIs(proof['ActualInvocationOsOptionsValidated'], True)
                self.assertEqual(len(proof['ActualInvocationOptions']), 2)
                self.assertIs(proof['Execution']['OsProcessTraceVerified'], False)

    def test_saved_options_sole_os_target_and_raw_six(self):
        for flag in ('-O2', '-O0', '-mcpu=cortex-m7', '-mfloat-abi=hard', '-mfpu=fpv4-sp-d16',
                     '-march=armv6-m', '-mlibarch=armv8-m.main', '-march', '-mlibarch',
                     '-march=', '-mlibarch=', '-marcharmv7-m', '-mlibarcharmv7-m',
                     '--march=armv7-m', '--mlibarch=armv7-m', '-march=armv7-m+nofp',
                     '-marm', '-flto-partition=none', '-ffat-lto-objects'):
            with self.subTest(flag=flag):
                fixture = Fixture()
                fixture.ltrans.insert(0, flag)
                fixture.write_saved()
                with self.assertRaises(API.Rejected):
                    fixture.run()
        for flag in RAW:
            fixture = Fixture()
            fixture.wpa.remove(flag)
            fixture.write_saved()
            with self.subTest(missing=flag), self.assertRaises(API.Rejected):
                fixture.run()

    def test_canonical_repeated_os_and_armv7_m_worker_forms(self):
        fixture = Fixture()
        prefix = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft',
                  '-mlibarch=armv7-m', '-march=armv7-m', '-Os']
        architecture = ['-mlibarch=armv7-m', '-march=armv7-m']
        for values, tail in ((fixture.wpa, len(fixture.objects)), (fixture.ltrans, 1)):
            values[:0] = prefix
            position = len(values) - tail
            values[position:position] = architecture
        for values in (fixture.actual_wpa, fixture.actual_ltrans):
            values[1:1] = prefix
            values[-1:-1] = architecture
        fixture.write_saved()
        machine, proof = fixture.run()
        self.assertEqual(machine, fixture.machine)
        self.assertIs(proof['SavedArgumentOsOptionsValidated'], True)
        self.assertIs(proof['ActualInvocationOsOptionsValidated'], True)
        for values in (fixture.wpa, fixture.ltrans, fixture.actual_wpa, fixture.actual_ltrans):
            self.assertEqual(values.count('-Os'), 2)
            self.assertEqual(values.count('-march=armv7-m'), 2)
            self.assertEqual(values.count('-mlibarch=armv7-m'), 2)

    def test_all_counter_and_contradictory_stress_options_rejected(self):
        for flag in ('-fno-instrument-functions', '-finstrument-functions-exclude-function-list=ctxrt',
                '-fno-stack-protector', '-fno-profile-arcs', '-fno-test-coverage', '-fno-sanitize=all',
                '-fno-sanitize-coverage=trace-pc', '-mgeneral-regs-only', '-mno-general-regs-only',
                '-fno-lto', '-fstack-protector', '-fsanitize=alignment', '-fsanitize-coverage=trace-cmp', '-lgcov'):
            fixture = Fixture()
            fixture.wpa.insert(0, flag)
            fixture.write_saved()
            with self.subTest(flag=flag), self.assertRaises(API.Rejected):
                fixture.run()

    def test_actual_reported_options_checked_not_only_saved_intent(self):
        for flag in ('-O2', '-fno-sanitize=all', '-fno-instrument-functions', '-mfloat-abi=hard',
                     '-mgeneral-regs-only', '-march=armv6-m', '-mlibarch=armv8-m.main',
                     '-march', '-mlibarch', '-march=', '-mlibarch=',
                     '--march=armv7-m', '--mlibarch=armv7-m'):
            fixture = Fixture()
            fixture.actual_ltrans.insert(1, flag)
            with self.subTest(flag=flag), self.assertRaises(API.Rejected):
                fixture.run()
        fixture = Fixture()
        fixture.actual_wpa.remove('-Os')
        with self.assertRaises(API.Rejected):
            fixture.run()
        for flag in RAW:
            fixture = Fixture()
            fixture.actual_ltrans.remove(flag)
            with self.subTest(missing=flag), self.assertRaises(API.Rejected):
                fixture.run()

    def test_specs_adapter_exact_no_extra_missing_or_duplicate(self):
        for defect in ('missing', 'extra', 'duplicate', 'long-form', 'split'):
            fixture = Fixture()
            expected = '-specs=' + str(fixture.specs)
            if defect == 'missing':
                fixture.wpa.remove(expected)
            elif defect == 'extra':
                fixture.wpa.append('-specs=C:/foreign.specs')
            elif defect == 'duplicate':
                fixture.wpa.append(expected)
            elif defect == 'long-form':
                fixture.wpa.append('--specs=C:/foreign.specs')
            else:
                fixture.wpa.extend(('-specs', 'C:/foreign.specs'))
            fixture.write_saved()
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                fixture.run()

    def test_ordered_ir_cohort_and_response_binding(self):
        for defect in ('response-order', 'saved-order', 'duplicate', 'foreign-response', 'indirect'):
            fixture = Fixture()
            if defect == 'response-order':
                fixture.watch.raw[fixture.wpa_response] = encoded_arguments(list(map(str, reversed(fixture.objects))))
            elif defect == 'saved-order':
                fixture.wpa[-3:] = list(map(str, reversed(fixture.objects)))
                fixture.write_saved()
            elif defect == 'duplicate':
                fixture.wpa.append(str(fixture.objects[0]))
                fixture.write_saved()
            elif defect == 'foreign-response':
                fixture.watch.raw[fixture.wpa_response] = encoded_arguments(['C:/foreign.o'])
            else:
                fixture.wpa.append('@C:/foreign.args')
                fixture.write_saved()
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                fixture.run()

    def test_exact_ltrans_input_output_and_partition(self):
        for defect in ('input', 'output', 'response', 'partition', 'stage'):
            fixture = Fixture()
            if defect == 'input':
                fixture.ltrans[-1] = 'C:/foreign-intermediate.o'
                fixture.write_saved()
            elif defect == 'output':
                fixture.ltrans[fixture.ltrans.index('-o') + 1] = 'C:/foreign-machine.o'
                fixture.write_saved()
            elif defect == 'response':
                fixture.watch.raw[fixture.ltrans_response] = encoded_arguments(['C:/foreign-intermediate.o'])
            elif defect == 'partition':
                fixture.watch.raw[fixture.partition_path] += b'C:/second-partition.o\n'
            else:
                fixture.ltrans.append('-fwpa')
                fixture.write_saved()
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                fixture.run()

    def test_actual_worker_executable_responses_and_assembler_chain(self):
        for defect in ('worker', 'response', 'extra-response', 'assembly-output', 'assembler', 'assembler-input'):
            fixture = Fixture()
            if defect == 'worker':
                fixture.actual_wpa[0] = 'C:/foreign/lto1.exe'
            elif defect == 'response':
                fixture.actual_wpa[-1] = '@C:/foreign.args'
            elif defect == 'extra-response':
                fixture.actual_ltrans.append('@C:/foreign.args')
            elif defect == 'assembly-output':
                fixture.actual_ltrans[fixture.actual_ltrans.index('-o') + 1] = 'C:/foreign.s'
            elif defect == 'assembler':
                fixture.actual_as[0] = 'C:/foreign/as.exe'
            else:
                fixture.actual_as[-1] = 'C:/foreign.s'
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                fixture.run()

    def test_transcript_grammar_warnings_extra_workers_and_hash_drift(self):
        fixture = Fixture()
        for raw in (fixture.diagnostics() + b' warning: not clean\n',
                    fixture.diagnostics() + (' ' + ' '.join(fixture.actual_wpa) + '\n').encode('ascii'),
                    fixture.diagnostics() + b'\0', b'', b'not an actual transcript\n'):
            with self.subTest(raw=raw[:35]), self.assertRaises(API.Rejected):
                API.worker_chain(fixture.suite, fixture.lowered, fixture.objects, fixture.specs, raw, HELPERS)
        fixture = Fixture()
        fixture.watch.raw[fixture.lto1] = b'changed actual worker'
        with self.assertRaises(API.Rejected):
            fixture.run()
        fixture = Fixture()
        fixture.watch.raw[fixture.machine] = b'IR substitute or invalid machine'
        with self.assertRaises(API.Rejected):
            fixture.run()

    def test_saved_windows_escaping_raw_hashes_and_malformed_lines(self):
        fixture = Fixture()
        self.assertIn(b'\\\\', fixture.watch.raw[fixture.wpa_path])
        machine, proof = fixture.run()
        self.assertEqual(proof['Stages'][0]['ArgumentsSha256'], sha(fixture.watch.raw[fixture.wpa_path]))
        self.assertEqual(proof['Stages'][1]['ArgumentsSha256'], sha(fixture.watch.raw[fixture.ltrans_path]))
        self.assertEqual(proof['MachineSha256'], sha(fixture.watch.raw[machine]))
        self.assertEqual(proof['DriverSpecsSha256'], sha(fixture.watch.raw[fixture.specs]))
        self.assertEqual(proof['Execution']['TranscriptSha256'], sha(fixture.diagnostics()))
        for malformed in (b'', b'\0', b'\xff\n', b' leading\n', b'trailing \n', b'one\n\ntwo\n'):
            fixture = Fixture()
            fixture.watch.raw[fixture.wpa_path] = malformed
            with self.subTest(malformed=malformed), self.assertRaises(API.Rejected):
                fixture.run()

    def test_literal_paths_and_fixed_one_or_three_object_domains(self):
        fixture = Fixture()
        for objects in ([], fixture.objects[:2], fixture.objects + [fixture.objects[0]],
                        [fixture.objects[0], fixture.objects[0], fixture.objects[1]], [True]):
            with self.subTest(objects=objects), self.assertRaises(API.Rejected):
                API.worker_chain(fixture.suite, fixture.lowered, objects, fixture.specs, fixture.diagnostics(), HELPERS)
        for lowered in (str(fixture.lowered), Path('relative.o'), Path('C:/synthetic/../other.o')):
            with self.subTest(lowered=lowered), self.assertRaises(API.Rejected):
                API.worker_chain(fixture.suite, lowered, fixture.objects, fixture.specs, fixture.diagnostics(), HELPERS)

    def test_inputs_modules_and_nonclaims_unchanged(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.result, fixture.watch.raw, fixture.objects))
        globals_before = dict(HELPER_MODULE.__dict__)
        suite_members = dict(fixture.suite.__dict__)
        machine, proof = fixture.run()
        self.assertEqual(before, (fixture.result, fixture.watch.raw, fixture.objects))
        self.assertEqual(globals_before, HELPER_MODULE.__dict__)
        self.assertEqual(suite_members, fixture.suite.__dict__)
        self.assertFalse(hasattr(fixture.suite, 'modules'))
        for name in ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof',
                     'FullSemanticABIProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'AttributeEffectsValidated'):
            self.assertIs(proof[name], False)
        self.assertIs(type(proof['RequiredCellsSatisfied']), int)
        self.assertEqual(proof['RequiredCellsSatisfied'], 0)


def main(argv=None):
    global API, HELPERS, HELPER_MODULE
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('fresh external output directory required')
    paths = dict(subject=HERE / 'common_workers.py', tests=Path(__file__).resolve(), helpers=HELPER)
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_COMMON_WORKER_CHAIN_CONTROLS', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, ActualCaptureRead=False, ActualELFParsed=False,
        ActualOsCodegenValidated=False, ExternalToolsExecuted=0, Qualification=False,
        CpuExecution=False, BoardExecution=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        if sha(buffers['helpers']) != HELPER_SHA:
            raise ValueError('helper pin before execution')
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn tools')):
            modules = {}
            for name in ('subject', 'helpers'):
                module = ModuleType('_os_common_workers_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                modules[name] = module
            API, HELPER_MODULE = modules['subject'], modules['helpers']
            if API.HELPER_SHA256 != HELPER_SHA:
                raise ValueError('subject helper identity')
            HELPERS = SimpleNamespace(**{name: getattr(HELPER_MODULE, name)
                for name in ('worker_chain', 'argument_lines', 'worker_diagnostics')})
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(WorkerTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact thirteen methods required')
            result = unittest.TextTestRunner(verbosity=2).run(tests)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception as error:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=type(error).__name__ + ': ' + str(error))
    for path, expected in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != expected:
                report['SourceDrift'].append(path)
        except OSError:
            report['SourceDrift'].append(path)
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 3 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
