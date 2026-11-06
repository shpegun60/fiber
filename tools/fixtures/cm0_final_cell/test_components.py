"""Pure orchestration controls; no compiler, ELF, or component qualification."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).with_name('components.py')
SOURCE = PATH.read_bytes()
SPEC = importlib.util.spec_from_file_location('_cm0_components_pure', PATH)
c = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = c
with patch.object(subprocess, 'Popen', side_effect=AssertionError('no processes in pure controls')):
    exec(compile(SOURCE, str(PATH), 'exec'), c.__dict__)

ROOT = PATH.resolve().parent / '_synthetic' / 'source'
HEADER = ROOT / 'tools/fixtures/classic_final_image/main.h'
FLAGS = ['-mcpu=cortex-m0', '-mthumb', '-mfloat-abi=soft', '-O2', '-std=gnu11',
         '-DFIBER_PORT_ARMV6M=1', '-DFIBER_PORT_BUILD_SELECTED=1', '-I' + str(ROOT / 'context'),
         '-I' + str(ROOT / 'fiber/port/ARM_CM0'), '-I' + str(ROOT.parent / 'cmsis'), '-include', str(HEADER)]


def negative_source(name):
    functions = {
        'slot_read.c': 'void cm0_abi_slot_read(void)\n{\n    (void)' + c.SLOT + ';\n}\n',
        'slot_write.c': 'void cm0_abi_slot_write(struct FiberContext *value)\n{\n    ' + c.SLOT + ' = value;\n}\n',
        'slot_address.c': 'void cm0_abi_slot_address(void)\n{\n    (void)&' + c.SLOT + ';\n}\n',
    }
    return ('#include "context/context_port_abi.h"\n#include "context/context_runtime_port_abi.h"\n'
            + functions[name]).encode('ascii')


def diagnostic(name='slot_read.c', source_path=None):
    path = ROOT.parent / 'output/abi' / name if source_path is None else Path(source_path)
    column = {'slot_read.c': 11, 'slot_write.c': 5, 'slot_address.c': 12}[name]
    location = str(path) + ':5:' + str(column)
    marker = '      | ' + ' ' * (column - 1)
    lines = [str(path) + ": In function 'cm0_abi_" + path.stem + "':",
        location + ": error: '" + c.SLOT + "' undeclared (first use in this function); did you mean 'fiber_internal_runtime_require_current_context'?",
        '    5 | ' + negative_source(name).decode('ascii').splitlines()[4],
        marker + '^' + '~' * 42, marker + 'fiber_internal_runtime_require_current_context',
        location + ': note: each undeclared identifier is reported only once for each function it appears in']
    return ('\n'.join(lines) + '\n').encode('utf-8')


def result(stderr=None, *, name='slot_read.c', source_path=None, **changes):
    fields = dict(returncode=1, stdout=b'', stderr=diagnostic(name, source_path) if stderr is None else stderr, timed_out=False)
    fields.update(changes)
    return SimpleNamespace(**fields)


def probe(name='types.c'):
    accepted = name in c.PROBES[:2]
    raw = b'void synthetic_probe(void) {}\n' if accepted else negative_source(name)
    return dict(Source=raw.decode('ascii'), SourceSha256=c.sha(raw), ExpectedCompile=accepted,
                DiagnosticIdentifier=None if accepted else c.SLOT, RequiredCFlags=list(c.REQUIRED_FLAGS))


class FakeSuite:
    """Only in-memory metadata; no real helper or compiler is invoked."""
    def __init__(self, accepted):
        self.base = ROOT.parent
        self.output = ROOT.parent / 'output'
        self.commands, self.outputs, self.data = [], [], {}
        self.accepted = accepted
        self.tools = dict(gcc=ROOT.parent / 'gcc.exe')
        self.header = ROOT / 'context/context_port_abi.h'
        self.reverse = ROOT / 'context/context_runtime_port_abi.h'
        self.data[self.header] = b'canonical synthetic header\n'
        self.data[self.reverse] = b'canonical synthetic reverse header\n'
        self.watch = SimpleNamespace(hashes={path: c.sha(raw) for path, raw in self.data.items()}, read=self.read)
        self.api = SimpleNamespace(checked_path=Path)
        self.native = SimpleNamespace(read_dependencies=self.dependencies, require_compile_dependencies=self.same_dependencies)

    def read(self, path):
        return self.data[Path(path)]

    def source(self, index):
        if index != 0:
            raise AssertionError('probe template must be source zero')
        return dict(CompileFlags=list(FLAGS))

    def write_input(self, name, raw):
        self.source_path = self.output / name
        self.data[self.source_path] = raw
        self.watch.hashes[self.source_path] = c.sha(raw)
        return self.source_path

    def dependencies(self, path):
        return [self.source_path, self.header, self.reverse]

    @staticmethod
    def same_dependencies(before, after):
        if before != after:
            raise c.Rejected('synthetic dependency mismatch')

    def record_output(self, path):
        self.outputs.append(path)

    def command(self, argv, label, expected_failure=False):
        self.commands.append(dict(Argv=argv, Label=label, ExpectedFailure=expected_failure))
        if '-c' in argv and not self.accepted:
            return result(name=self.source_path.name, source_path=self.source_path)
        return result(b'', returncode=0)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        self.no_process = patch.object(subprocess, 'Popen', side_effect=AssertionError('pure tests cannot start processes'))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)

    def classify(self, value=None, *, name='slot_read.c', **changes):
        arguments = dict(identifier=c.SLOT, object_exists=False, source_path=ROOT.parent / 'output/abi' / name,
                         source_bytes=negative_source(name))
        arguments.update(changes)
        return c.classify_undeclared(result(name=name) if value is None else value, **arguments)

    def test_undeclared_positive_is_only_diagnostic_evidence(self):
        for name in c.PROBES[2:]:
            for raw in (diagnostic(name), diagnostic(name).replace(b'\n', b'\r\n')):
                with self.subTest(name=name, crlf=b'\r' in raw):
                    evidence = self.classify(result(raw), name=name)
                    self.assertEqual(evidence, dict(AcceptedCompile=False, UndeclaredIdentifier=c.SLOT,
                        DiagnosticSha256=hashlib.sha256(raw).hexdigest().upper(), ObjectAbsent=True))
                    self.assertNotIn('FullABIProof', evidence)

    def test_negative_requires_exact_result_types_and_no_object(self):
        for changes in (dict(returncode=True), dict(returncode=1.0), dict(returncode=0), dict(returncode=2),
                        dict(timed_out=True), dict(timed_out=0), dict(stdout=b'output'), dict(stdout=''), dict(stderr='error')):
            with self.subTest(changes=changes), self.assertRaises(c.Rejected):
                self.classify(result(**changes))
        for value in (True, 0, None):
            with self.subTest(object_exists=value), self.assertRaises(c.Rejected):
                self.classify(object_exists=value)

    def test_wrong_identifier_extra_errors_and_unrelated_failures_reject(self):
        raw = result().stderr
        cases = [raw.replace(c.SLOT.encode('ascii'), (c.SLOT + '_alias').encode('ascii')),
                 raw.replace(b'undeclared', b'incompatible', 1), b'', raw + raw,
                 raw + b'probe.c:1:1: error: another cause\n', raw + b'\x00']
        cases += [raw + value + b'\n' for value in (b'warning: extra', b'fatal error: missing.h', b'internal compiler error',
                  b'segmentation fault', b'unrecognized command-line option', b'sorry, not implemented',
                  b'cc1.exe: out of memory allocating 1024 bytes', b'unclassified text')]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(c.Rejected):
                self.classify(result(value))
        with self.assertRaises(c.Rejected):
            self.classify(identifier='other_slot')

    def test_closed_diagnostic_binds_source_function_location_excerpt_marker_and_note(self):
        raw = diagnostic()
        for before, after in ((b'slot_read.c', b'foreign.c'), (b'cm0_abi_slot_read', b'cm0_abi_slot_write'),
                              (b':5:11:', b':6:11:'), (b':5:11:', b':5:12:'), (b'(void)', b'(long)'),
                              (b'^~~', b' ~~'), (b'reported only once', b'reported twice'),
                              (b'fiber_internal_runtime_require_current_context', b'foreign_suggestion')):
            with self.subTest(before=before), self.assertRaises(c.Rejected):
                self.classify(result(raw.replace(before, after)))
        for value in (raw.split(b'\n', 1)[1], raw.rsplit(b'\n', 2)[0] + b'\n', raw[:-1],
                      raw.replace(b'\n', b'\r'), raw.replace(str(ROOT.parent).encode('utf-8'), b'C:/foreign')):
            with self.subTest(raw=value), self.assertRaises(c.Rejected):
                self.classify(result(value))

    def test_diagnostic_rejects_foreign_source_binding_and_changed_probe_bytes(self):
        for changes in (dict(source_path=ROOT / 'foreign/slot_read.c'), dict(source_path=Path('slot_read.c')),
                        dict(source_bytes=negative_source('slot_write.c')), dict(source_bytes=negative_source('slot_read.c') + b'// extra\n')):
            with self.subTest(changes=changes), self.assertRaises(c.Rejected):
                self.classify(**changes)

    def test_probe_flags_preserve_target_order_and_save_temps_only_on_compile(self):
        original = list(FLAGS)
        for accepted in (False, True):
            discovery, actual = c.probe_flags(FLAGS, list(c.REQUIRED_FLAGS), accepted)
            self.assertEqual(discovery[:len(FLAGS)], FLAGS)
            self.assertEqual(discovery.count('-std=gnu11'), 1)
            self.assertNotIn('-save-temps=obj', discovery)
            self.assertEqual(actual, discovery + (['-save-temps=obj'] if accepted else []))
        self.assertEqual(FLAGS, original)

    def test_foreign_probe_flags_and_numeric_dispositions_reject(self):
        for required in ([], list(reversed(c.REQUIRED_FLAGS)), [*c.REQUIRED_FLAGS, '-flto'], ['-Wno-attributes']):
            with self.subTest(required=required), self.assertRaises(c.Rejected):
                c.probe_flags(FLAGS, required, True)
        for accepted in (1, 0, None):
            with self.subTest(accepted=accepted), self.assertRaises(c.Rejected):
                c.probe_flags(FLAGS, list(c.REQUIRED_FLAGS), accepted)

    def test_isolation_removes_only_includes_and_preserves_target_defines(self):
        before = list(FLAGS)
        expected = FLAGS[:7] + ['-I' + str(ROOT / name) for name in ('context', 'fiber')] + ['-I' + str(ROOT)]
        self.assertEqual(c.isolated_flags(FLAGS, ROOT), expected)
        separated = FLAGS[:7] + ['-I', str(ROOT / 'context'), '-include', str(HEADER)]
        self.assertEqual(c.isolated_flags(separated, ROOT), expected)
        self.assertEqual(FLAGS, before)

    def test_isolation_rejects_missing_foreign_and_ambiguous_include_arguments(self):
        cases = [FLAGS[:-2], FLAGS[:-1], [*FLAGS, '-include', str(HEADER)],
                 [*FLAGS[:-1], str(ROOT / 'foreign.h')], [*FLAGS, '-I'], [*FLAGS, '-I', '-O3']]
        cases += [[*FLAGS, flag] for flag in ('-includeother.h', '-imacros', '-isystem', '-iquote', '-idirafter')]
        for value in cases:
            with self.subTest(flags=value), self.assertRaises(c.Rejected):
                c.isolated_flags(value, ROOT)

    def test_common_dependencies_are_an_authenticated_subset_not_equal_to_forced_header_set(self):
        paths = [ROOT / 'context/context_core.c', ROOT / 'context/context_port_abi.h']
        admitted = {path: c.sha(str(path).encode('utf-8')) for path in [*paths, HEADER]}
        before = dict(admitted)
        self.assertEqual(c.isolated_dependencies(paths, admitted, root=ROOT, cmsis=ROOT.parent / 'cmsis'),
                         [dict(Path=str(path), Sha256=admitted[path]) for path in paths])
        self.assertEqual(admitted, before)

    def test_empty_duplicate_foreign_cmsis_or_port_dependencies_reject(self):
        common = ROOT / 'context/context_core.c'
        port, cmsis = ROOT / 'fiber/port/private.h', ROOT.parent / 'cmsis/core_cm0.h'
        admitted = {path: 'A' * 64 for path in (common, port, cmsis)}
        for paths in ([], [common, common], [ROOT / 'foreign.h'], [Path('relative.h')], [common, port], [common, cmsis]):
            with self.subTest(paths=paths), self.assertRaises(c.Rejected):
                c.isolated_dependencies(paths, admitted, root=ROOT, cmsis=ROOT.parent / 'cmsis')

    def test_probe_compile_uses_fresh_matching_deps_and_exact_mt_for_two_accepted_probes(self):
        for name in c.PROBES[:2]:
            with self.subTest(name=name):
                suite = FakeSuite(True)
                evidence = c.compile_probe(suite, name, probe(name))
                self.assertEqual(evidence['Classification'], dict(AcceptedCompile=True))
                self.assertEqual(evidence['CommandIndices'], [0, 1])
                self.assertTrue(evidence['CompileDependenciesVerified'])
                self.assertEqual(len(suite.outputs), 5)
                for row in suite.commands:
                    self.assertEqual(row['Argv'][row['Argv'].index('-MT') + 1], 'pilot-source-0')
                    self.assertFalse(row['ExpectedFailure'])
                self.assertNotIn('-save-temps=obj', suite.commands[0]['Argv'])
                self.assertIn('-save-temps=obj', suite.commands[1]['Argv'])
                self.assertEqual(evidence['CompileFlags'], suite.commands[1]['Argv'][1:-9])

    def test_three_slot_probes_only_accept_intended_failures_without_saved_temps(self):
        for name in c.PROBES[2:]:
            with self.subTest(name=name), patch.object(Path, 'exists', return_value=False):
                suite = FakeSuite(False)
                evidence = c.compile_probe(suite, name, probe(name))
                self.assertIsNone(evidence['Object'])
                self.assertIsNone(evidence['Preprocessed'])
                self.assertEqual(evidence['Classification']['UndeclaredIdentifier'], c.SLOT)
                self.assertFalse(suite.commands[0]['ExpectedFailure'])
                self.assertTrue(suite.commands[1]['ExpectedFailure'])
                self.assertNotIn('-save-temps=obj', suite.commands[1]['Argv'])

    def test_wrong_probe_hash_disposition_and_unadmitted_dependency_fail_before_compile(self):
        for field, value in (('SourceSha256', '0' * 64), ('ExpectedCompile', 1), ('ExpectedCompile', False),
                             ('DiagnosticIdentifier', c.SLOT)):
            item, suite = probe(), FakeSuite(True)
            item[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(c.Rejected):
                c.compile_probe(suite, 'types.c', item)
            self.assertEqual(suite.commands, [])
        suite = FakeSuite(True)
        del suite.watch.hashes[suite.header]
        with self.assertRaisesRegex(c.Rejected, 'admitted probe dependency'):
            c.compile_probe(suite, 'types.c', probe())
        self.assertEqual(len(suite.commands), 1)

    def test_discovery_actual_dependency_mismatch_is_not_success(self):
        suite = FakeSuite(True)
        extra = ROOT / 'context/other.h'
        suite.data[extra] = b'other authenticated header\n'
        suite.watch.hashes[extra] = c.sha(suite.data[extra])
        suite.native.read_dependencies = lambda path: suite.dependencies(path) + ([extra] if '.discovery.' in str(path) else [])
        with self.assertRaisesRegex(c.Rejected, 'dependency mismatch'):
            c.compile_probe(suite, 'types.c', probe())

    def test_each_probe_inventory_requires_source_and_both_canonical_headers(self):
        for name in ('types.c', 'slot_read.c'):
            for missing in ('source', 'forward', 'reverse'):
                for stage in ('discovery', 'compile', 'both'):
                    suite = FakeSuite(name == 'types.c')
                    def dependencies(path):
                        rows = suite.dependencies(path)
                        if stage == 'both' or '.' + stage + '.' in str(path):
                            target = {'source': suite.source_path, 'forward': suite.header, 'reverse': suite.reverse}[missing]
                            rows.remove(target)
                        return rows
                    suite.native.read_dependencies = dependencies
                    with self.subTest(name=name, missing=missing, stage=stage), \
                         self.assertRaisesRegex(c.Rejected, 'probe source and both same-attempt canonical ABI headers'):
                        c.compile_probe(suite, name, probe(name))
                    self.assertEqual(len(suite.commands), 2 if stage == 'compile' else 1)

    def test_admitted_headers_from_other_attempt_do_not_satisfy_probe_dependencies(self):
        for direction in ('forward', 'reverse'):
            suite = FakeSuite(True)
            original = suite.header if direction == 'forward' else suite.reverse
            foreign = ROOT.parent / 'other-attempt/source/context' / original.name
            suite.data[foreign] = suite.data[original]
            suite.watch.hashes[foreign] = c.sha(suite.data[foreign])
            suite.native.read_dependencies = lambda path: [foreign if item == original else item for item in suite.dependencies(path)]
            with self.subTest(direction=direction), self.assertRaisesRegex(c.Rejected, 'same-attempt canonical ABI headers'):
                c.compile_probe(suite, 'types.c', probe())

    def test_isolated_common_rejects_foreign_and_boolean_indices_before_any_operation(self):
        for index in (True, False, -1, 3, 1.0, '0'):
            with self.subTest(index=index), self.assertRaises(c.Rejected):
                c.isolated_common(None, index)

    def test_all_helper_hashes_are_validated_before_any_exec(self):
        originals = {name: (c.HERE / (name + '.py')).read_bytes() for name in c.PINS}
        for name, raw in originals.items():
            self.assertEqual(c.sha(raw), c.PINS[name])
        for bad in c.PINS:
            buffers = dict(originals)
            buffers[bad] += b'\n# different bytes\n'
            with self.subTest(bad=bad), patch.object(c, 'exec', create=True) as execute:
                # All reads occur first, even when the final helper is bad.
                with patch.object(Path, 'read_bytes', autospec=True, side_effect=lambda path: buffers[path.stem]), \
                     self.assertRaisesRegex(c.Rejected, 'fixed helper'):
                    c.load_helpers()
                execute.assert_not_called()

    def test_loader_executes_exact_once_read_buffers_without_tools(self):
        originals = {name: (c.HERE / (name + '.py')).read_bytes() for name in c.PINS}
        with patch.object(Path, 'read_bytes', autospec=True, side_effect=lambda path: originals[path.stem]) as read:
            modules, buffers = c.load_helpers()
        self.assertEqual(read.call_count, 4)
        self.assertEqual(buffers, originals)
        self.assertEqual(tuple(modules), tuple(c.PINS))
        self.assertTrue(callable(modules['controls'].Suite))

    def test_cli_requires_complete_sealed_components_and_never_upgrades_closing_failure(self):
        args = ['--native-build', str(ROOT), '--native-receipt-sha256', 'A' * 64,
                '--native-artifacts-sha256', 'B' * 64, '--output-dir', str(ROOT.parent / 'new')]
        report = dict(Status='CM0-O2-DIRECT-LINK-CONTROLS-PASS', ComponentPhasesComplete=True,
                      InputClosureVerified=True, OutputSealVerified=True, RequiredCellsSatisfied=0)
        with patch.object(c, 'run_components', return_value=report), patch('builtins.print'):
            self.assertEqual(c.main(args), 0)
        for field in ('Status', 'ComponentPhasesComplete', 'InputClosureVerified', 'OutputSealVerified'):
            altered = copy.deepcopy(report)
            altered[field] = 'FAIL' if field == 'Status' else False
            with self.subTest(field=field), patch.object(c, 'run_components', return_value=altered), patch('builtins.print'):
                self.assertEqual(c.main(args), 1)
        self.assertEqual(report['RequiredCellsSatisfied'], 0)

    def test_tested_source_still_matches_opening_bytes(self):
        self.assertEqual(PATH.read_bytes(), SOURCE)


if __name__ == '__main__':
    unittest.main(verbosity=2)
