"""Pure adapter/loader controls; synthetic stage results are not native proof."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).with_name('components.py').resolve()
SOURCE = PATH.read_bytes()
SPEC = importlib.util.spec_from_file_location('_ordinary_components_pure', PATH)
c = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = c
exec(compile(SOURCE, str(PATH), 'exec'), c.__dict__)
BASE = Path(PATH.anchor) / '_ordinary_components_synthetic_paths'
PROFILES = ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM3', 'CM4', 'CM7')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
SLOT_SOURCE = ('void SVC_Handler(void) { __asm(\n'
    '"ldr r0, =' + c.SLOT + ' \\n"\n"ldr r0, [r0] \\n"); }\n'
    'void PendSV_Handler(void) { __asm(\n'
    '"ldr r1, =' + c.SLOT + ' \\n"\n"ldr r1, [r1] \\n"); }\n').encode('ascii')
SLOT_ASSEMBLY = ('SVC_Handler:\n ldr r0, =' + c.SLOT + '\n ldr r0, [r0]\n .size SVC_Handler, .-SVC_Handler\n'
    'PendSV_Handler:\n ldr r1, =' + c.SLOT + '\n ldr r1, [r1]\n .size PendSV_Handler, .-PendSV_Handler\n').encode('ascii')
SLOT_OBJECT = b'\x7fELF\x01\x01\x01synthetic placeholder, not a decoded ELF'


def with_slot_gap(gap):
    return SLOT_SOURCE.replace(b'\\n"\n"ldr r1', b'\\n"' + gap + b'"ldr r1', 1)


def case(profile='CM3', mode='Os'):
    root, output = BASE / 'Native', BASE / 'new'
    data, trace = {PATH: SOURCE}, []
    def add(path, raw):
        data[path] = raw
        return c.sha(raw)
    def read(path, expected=None):
        raw = data[Path(path)]
        if expected is not None and c.sha(raw) != expected:
            raise ValueError('synthetic input hash mismatch')
        return raw
    watch = SimpleNamespace(read=read)
    add(root / 'source/common.c', b'common source')
    add(root / 'results.json', b'authenticated synthetic native receipt')
    source, obj, original, assembly = (root / 'source/runtime.c', output / 'runtime.o', root / 'objects/runtime.o', output / 'runtime.s')
    deps = [dict(Path=str(source), Sha256=add(source, SLOT_SOURCE))]
    replay = dict(Source=str(source), SourceSha256=data[source] and c.sha(data[source]), Object=str(obj),
        ObjectSha256=add(obj, b'identical synthetic object'), OriginalObject=str(original),
        OriginalObjectSha256=add(original, b'identical synthetic object'), Dependencies=deps,
        Assembly=dict(Path=str(assembly), Sha256=add(assembly, b'two synthetic generated references')))
    preprocessed = output / 'abi/attributes.i'
    add(preprocessed, b'synthetic CPP declarations')
    bundle = dict(Root=root, Artifacts={'source/common.c': c.sha(data[root / 'source/common.c'])})
    inventory = dict(SourceInventorySha256='A' * 64)
    report = dict(Profile=profile, Mode=mode, RequiredCellsSatisfied=0, CellContractSatisfied=False,
        FullABIProof=False, FullSemanticABIProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, PrimaryError=None, ClosingErrors=[])
    suite = SimpleNamespace(base=root, output=output, report=report, api=SimpleNamespace(checked_path=Path))
    suite.source = lambda index: dict(Dependencies=copy.deepcopy(deps))
    suite.start = lambda: trace.append('start')
    suite.run_link_controls = lambda: trace.append('five fresh links')
    def compile_tuple(index, **kwargs):
        if index != 3 or kwargs != dict(name='runtime-slot-replay', save_temps=True):
            raise AssertionError('exact selected runtime/save-temps recipe')
        trace.append('runtime replay')
        return copy.deepcopy(replay)
    suite.compile_tuple = compile_tuple
    suite.write_input = lambda name, raw: trace.append((name, json.loads(raw)))
    def finish(error):
        trace.append('finish')
        report.update(Status='FAIL' if error else 'ORDINARY-DIRECT-LINK-CONTROLS-PASS',
            Error=None if error is None else str(error), PrimaryError=None if error is None else str(error),
            InputClosureVerified=error is None, OutputSealVerified=error is None)
        return copy.deepcopy(report)
    suite.finish = finish
    def same(actual, expected, message):
        if actual != expected:
            raise ValueError(message)
    common = dict(Scope='CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY', Detail=['same canonical common source'], RequiredCellsSatisfied=0)
    slot_record = dict(Scope='CM0_TWO_DIRECT_SLOT_LOADS_ONLY', GeneratedReferences=2, RequiredCellsSatisfied=0)
    def abi_profile(value):
        if type(value) is not str or value != profile:
            raise AssertionError('ABI requires the exact profile STRING')
    def providers(value, sources, receipt, *, source_root):
        abi_profile(value)
        if source_root != str(root / 'source') or receipt != data[root / 'results.json']:
            raise AssertionError('same admitted provider attempt')
        return dict(Profile=profile, Mode=mode, Scope=dict(FullSemanticABIProof=False))
    def probes(value):
        abi_profile(value)
        return {name: dict(Name=name) for name in c.PROBES}
    def cpp(value, raw):
        abi_profile(value)
        return dict(CanonicalHeaders=dict(forward=str(root / 'source/context/context_port_abi.h'),
            reverse=str(root / 'source/context/context_runtime_port_abi.h')))
    def compile_probe(selected, name, probe):
        if selected is not suite or probe != dict(Name=name):
            raise AssertionError('exact selected probe')
        trace.append(name)
        return dict(Preprocessed=str(preprocessed) if name == 'attributes.c' else None)
    def isolate(selected, index):
        trace.append(('isolated', index))
        return dict(Index=index, WholeObjectByteIdentical=True)
    def slot_check(raw, *_):
        record = copy.deepcopy(slot_record)
        record['SourceSha256'] = c.sha(raw)
        return record
    helpers = dict(controls=SimpleNamespace(create_suite=lambda *_, **__: suite),
        ownership=SimpleNamespace(REQUIRED_SOURCES=('common.c',), validate_common_sources=lambda _: common),
        abi=SimpleNamespace(inspect_provider_dependencies=providers, emit_probes=probes, inspect_preprocessed_attributes=cpp),
        slot=SimpleNamespace(SLOT=c.SLOT, check_generated=slot_check),
        cm0_components=SimpleNamespace(compile_probe=compile_probe, isolated_common=isolate),
        cm0_controls=SimpleNamespace(same=same, encoded=lambda value: json.dumps(value).encode('ascii')))
    kwargs = dict(profile=profile, mode=mode, inventory=inventory, helpers=helpers, watch=watch, output_dir=output)
    return SimpleNamespace(bundle=bundle, kwargs=kwargs, suite=suite, helpers=helpers, trace=trace,
                           common=common, slot_record=slot_record, replay=replay, data=data)


class ComponentTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(subprocess, 'Popen', side_effect=AssertionError('no compiler/process in pure controls'))
        guard.start()
        self.addCleanup(guard.stop)

    def qualified_slot(self):
        relative, digest = c.LOCAL_PINS['slot']
        path = c.HERE.parent / relative
        raw = path.read_bytes()
        self.assertEqual(c.sha(raw), digest)
        return c.module('_ordinary_components_pure_qualified_slot', path, raw)

    def test_all_thirty_routes_pass_profile_string_to_abi_and_reuse_one_suite(self):
        for profile in PROFILES:
            for mode in MODES:
                with self.subTest(profile=profile, mode=mode):
                    item = case(profile, mode)
                    report = c.run_components(item.bundle, **item.kwargs)
                    self.assertTrue(c.succeeded(report))
                    self.assertEqual(item.trace.count('five fresh links'), 1)
                    self.assertEqual([value for value in item.trace if value in c.PROBES], list(c.PROBES))
                    self.assertEqual(report['GeneratedSlot']['Profile'], profile)
                    self.assertEqual(report['GeneratedSlot']['Mode'], mode)
                    self.assertEqual(report['GeneratedSlot']['Scope'], 'ORDINARY_TWO_DIRECT_SLOT_LOADS_ONLY')
                    self.assertEqual(len(report['IsolatedCommon']), 3)
                    self.assertEqual(report['RequiredCellsSatisfied'], 0)

    def test_scoping_copies_underlying_record_and_never_changes_frozen_helper_globals(self):
        item = case('CM7', 'O3')
        before = copy.deepcopy((item.common, item.slot_record))
        report = c.run_components(item.bundle, **item.kwargs)
        self.assertEqual((item.common, item.slot_record), before)
        self.assertEqual(report['GeneratedSlot']['UnderlyingScope'], 'CM0_TWO_DIRECT_SLOT_LOADS_ONLY')
        report['SourceOwnership']['Detail'].append('mutant')
        self.assertEqual(item.common['Detail'], ['same canonical common source'])
        self.assertFalse(report['FullSemanticABIProof'])

    def test_wrong_provider_mode_fails_before_output_start(self):
        item = case()
        item.helpers['abi'].inspect_provider_dependencies = lambda *_args, **_kw: dict(Profile='CM3', Mode='O2')
        with self.assertRaisesRegex(ValueError, 'same provider profile and mode'):
            c.run_components(item.bundle, **item.kwargs)
        self.assertEqual(item.trace, [])

    def test_runtime_dependency_mismatch_downgrades_and_stops_before_abi(self):
        item = case()
        item.suite.source = lambda index: dict(Dependencies=[])
        report = c.run_components(item.bundle, **item.kwargs)
        self.assertEqual(report['Status'], 'FAIL')
        self.assertFalse(report['ComponentPhasesComplete'])
        self.assertNotIn('types.c', item.trace)

    def test_missing_or_foreign_preprocessed_header_origin_downgrades(self):
        for origins in ({'forward': 'foreign.h'}, {'forward': 'foreign.h', 'reverse': 'foreign.h'}):
            item = case('CM4', 'Og')
            item.helpers['abi'].inspect_preprocessed_attributes = lambda *_: dict(CanonicalHeaders=origins)
            report = c.run_components(item.bundle, **item.kwargs)
            self.assertEqual(report['Status'], 'FAIL')
            self.assertFalse(report['ComponentPhasesComplete'])
            self.assertFalse(any(isinstance(value, tuple) and value[0] == 'isolated' for value in item.trace))

    def test_missing_probe_or_probe_rejection_cannot_promote(self):
        for change in ('missing', 'failure'):
            item = case()
            if change == 'missing':
                item.helpers['abi'].emit_probes = lambda _: dict(types=dict(Name='types'))
            else:
                def fail(*_):
                    raise RuntimeError('actual intended diagnostic did not match')
                item.helpers['cm0_components'].compile_probe = fail
            report = c.run_components(item.bundle, **item.kwargs)
            self.assertEqual(report['Status'], 'FAIL')
            self.assertFalse(report['ComponentPhasesComplete'])
            self.assertEqual(report['RequiredCellsSatisfied'], 0)

    def test_component_facts_remain_nonpromoting(self):
        item = case()
        report = c.run_components(item.bundle, **item.kwargs)
        facts = next(value[1] for value in item.trace if isinstance(value, tuple) and value[0] == 'component-facts.json')
        self.assertEqual(facts['ComponentScope'], c.SCOPE)
        self.assertNotIn('Status', facts)
        self.assertFalse(report['CellContractSatisfied'])

    def test_success_requires_complete_error_free_closing_and_integer_zero_credit(self):
        item = case()
        report = c.run_components(item.bundle, **item.kwargs)
        self.assertTrue(c.succeeded(report))
        for key, value in (('ComponentPhasesComplete', 1), ('InputClosureVerified', False), ('OutputSealVerified', False),
                           ('Status', 'FAIL'), ('Error', 'late failure'), ('PrimaryError', 'earlier failure'),
                           ('ClosingErrors', ['late drift']), ('RequiredCellsSatisfied', False), ('RequiredCellsSatisfied', 1)):
            with self.subTest(key=key, value=value):
                self.assertFalse(c.succeeded(dict(report, **{key: value})))

    def test_all_actual_source_pins_load_without_tools(self):
        helpers, watch = c.load_helpers()
        self.assertTrue(callable(helpers['controls'].create_suite))
        self.assertEqual(helpers['profiles'].profile('CM7', 'O3')['Target']['nvic_priority_bits'], 4)
        for name, (relative, digest) in c.LOCAL_PINS.items():
            self.assertEqual(watch.hashes[c.HERE.parent / relative], digest)
        watch.close()

    def test_cli_has_all_nine_explicit_arguments_and_preserves_profile_mode(self):
        item = case('CM7', 'O3')
        args = []
        for key, value in (('native-build', 'N'), ('native-receipt-sha256', 'A' * 64), ('native-artifacts-sha256', 'B' * 64),
                           ('profile', 'CM7'), ('mode', 'O3'), ('inventory', 'I'), ('inventory-receipt-sha256', 'C' * 64),
                           ('inventory-artifacts-sha256', 'D' * 64), ('output-dir', 'O')):
            args.extend(['--' + key, value])
        with patch.object(c, 'prepare', return_value=(item.bundle, item.kwargs['inventory'], item.helpers, item.kwargs['watch'])), \
             patch('builtins.print'):
            self.assertEqual(c.main(args), 0)
        self.assertEqual(item.suite.report['Profile'], 'CM7')
        self.assertEqual(item.suite.report['Mode'], 'O3')

    def test_admission_exception_never_invokes_components(self):
        args = [value for key in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256', 'profile', 'mode',
                                  'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
                for value in ('--' + key, 'synthetic')]
        with patch.object(c, 'prepare', side_effect=ValueError('bad input hash')), patch.object(c, 'run_components') as run, \
             patch('builtins.print'):
            self.assertEqual(c.main(args), 1)
        run.assert_not_called()

    def test_subject_opening_and_closing_source_bytes_match(self):
        self.assertEqual(PATH.read_bytes(), SOURCE)

    def test_slot_comment_gap_has_original_and_qualified_hashes_and_exact_transform(self):
        slot = self.qualified_slot()
        source = with_slot_gap(b' /* r1 = &current context */\n')
        with self.assertRaises(slot.Rejected):
            slot.check_generated(source, SLOT_ASSEMBLY, SLOT_OBJECT, SLOT_OBJECT)
        calls = []
        def check(*args):
            calls.append(args)
            return slot.check_generated(*args)
        wrapped = SimpleNamespace(SLOT=slot.SLOT, check_generated=check)
        record = c.check_slot(wrapped, source, SLOT_ASSEMBLY, SLOT_OBJECT, SLOT_OBJECT, profile='CM4', mode='O2')
        normalized = calls[0][0]
        self.assertIs(calls[0][1], SLOT_ASSEMBLY)
        self.assertIs(calls[0][2], SLOT_OBJECT)
        self.assertIs(calls[0][3], SLOT_OBJECT)
        self.assertEqual(record['SourceSha256'], c.sha(source))
        self.assertEqual(record['OriginalSourceSha256'], c.sha(source))
        self.assertEqual(record['QualifiedNormalizedSourceSha256'], c.sha(normalized))
        self.assertEqual(record['QualifiedSourceCheck']['SourceSha256'], c.sha(normalized))
        self.assertNotEqual(c.sha(source), c.sha(normalized))
        changes = record['SourceTrivia']['Transformations']
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['Register'], 'r1')
        self.assertEqual(changes[0]['BlockComments'], 1)
        restored = bytearray(normalized)
        for change in changes:
            start, end = change['Offset'], change['Offset'] + change['Size']
            self.assertEqual(normalized[start:end].hex(), change['QualifiedHex'])
            self.assertEqual(source[start:end].hex(), change['OriginalHex'])
            restored[start:end] = bytes.fromhex(change['OriginalHex'])
        self.assertEqual(bytes(restored), source)
        self.assertEqual(record['AssemblySha256'], c.sha(SLOT_ASSEMBLY))
        self.assertEqual(record['OriginalObjectSha256'], record['ReplayedObjectSha256'])
        self.assertFalse(record['RequiredCellSatisfied'])
        self.assertEqual(record['RequiredCellsSatisfied'], 0)

    def test_slot_whitespace_identity_and_comments_outside_gaps_are_unchanged(self):
        slot = self.qualified_slot()
        normalized, trivia = c.slot_source_trivia(SLOT_SOURCE)
        self.assertEqual(normalized, SLOT_SOURCE)
        self.assertEqual(trivia['Transformations'], [])
        for gap in (b'/**/', b' /* a */\t/* b */\r\n'):
            original = b'/* untouched outside the matched gaps */\n' + with_slot_gap(gap)
            normalized, trivia = c.slot_source_trivia(original)
            self.assertTrue(normalized.startswith(b'/* untouched outside the matched gaps */\n'))
            self.assertEqual(len(normalized), len(original))
            self.assertEqual(normalized.count(b'\n'), original.count(b'\n'))
            self.assertEqual(trivia['OriginalSlotMentions'], 2)
            self.assertEqual(trivia['ExactSourceStringPairs'], 2)
            self.assertEqual(trivia['Transformations'][0]['BlockComments'], gap.count(b'/*'))
            slot.check_generated(normalized, SLOT_ASSEMBLY, SLOT_OBJECT, SLOT_OBJECT)

    def test_slot_adapter_rejects_extra_mentions_and_real_c_access_with_two_mentions(self):
        symbol = c.SLOT.encode('ascii')
        additions = [b'\nextern void *' + symbol + b';\n', b'\nvoid f(void) { (void)' + symbol + b'; }\n',
                     b'\nvoid f(void) { void *p = &' + symbol + b'; }\n', b'\n/* ' + symbol + b' */\n']
        for extra in additions:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                c.slot_source_trivia(SLOT_SOURCE + extra)
        pair = b'"ldr r1, =' + symbol + b' \\n"\n"ldr r1, [r1] \\n"'
        for replacement in (b'"not an assembly pair"; (void)' + symbol,
                            b'"not a pair"; void *p = &' + symbol,
                            b'"not a pair"; extern void *' + symbol):
            mutant = SLOT_SOURCE.replace(pair, replacement, 1)
            self.assertEqual(mutant.count(symbol), 2)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                c.slot_source_trivia(mutant)

    def test_slot_adapter_rejects_nontrivia_between_strings_and_phase_two_escapes(self):
        for gap in (b';', b' + ', b' /* comment */ escape(); ', b'// line comment\n', b'"mov r2, r1 \\n"',
                    b'\n#if 1\n', b'/* unterminated\n', b'/* splice \\\n */\n', b'/* splice *\\\n/ escape(); /* */',
                    b'/* first */ + /* last */', b'/* first */ macro_token /* last */'):
            self.assertEqual(with_slot_gap(gap).count(c.SLOT.encode('ascii')), 2)
            with self.subTest(gap=gap), self.assertRaises(ValueError):
                c.slot_source_trivia(with_slot_gap(gap))
        for replacement in (b'str r1, [r1]', b'ldr r0, [r1]', b'ldr r1, [r1, #4]'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                c.slot_source_trivia(with_slot_gap(b'/**/').replace(b'ldr r1, [r1]', replacement))

    def test_qualified_generated_and_whole_object_predicates_remain_strict(self):
        slot = self.qualified_slot()
        source = with_slot_gap(b' /* r1 = &current context */\n')
        for assembly, replayed in ((SLOT_ASSEMBLY.replace(b'ldr r1, [r1]', b'str r1, [r1]'), SLOT_OBJECT),
                                   (SLOT_ASSEMBLY + b' ldr r2, =' + c.SLOT.encode('ascii') + b'\n', SLOT_OBJECT),
                                   (SLOT_ASSEMBLY, SLOT_OBJECT + b'changed')):
            with self.subTest(assembly=assembly, replayed=replayed), self.assertRaises(slot.Rejected):
                c.check_slot(slot, source, assembly, SLOT_OBJECT, replayed, profile='CM7', mode='O3')


if __name__ == '__main__':
    unittest.main(verbosity=2)
