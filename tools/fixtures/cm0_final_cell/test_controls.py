"""Pure duplicate-diagnostic controls, not compiler/linker or cell evidence.

The headed positive spelling follows the retained E1 duplicate-SVC/PendSV
streams. Paths and result objects below are synthetic; no tool or ELF is run.
"""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


PATH = Path(__file__).with_name('controls.py')
SOURCE_BYTES = PATH.read_bytes()
SOURCE_SHA = hashlib.sha256(SOURCE_BYTES).hexdigest().upper()
SPEC = importlib.util.spec_from_file_location('cm0_cell_duplicate_pure_controls', PATH)
controls = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controls
with patch.object(subprocess, 'Popen', side_effect=AssertionError('pure controls cannot start processes')):
    exec(compile(SOURCE_BYTES, str(PATH), 'exec'), controls.__dict__)

BASE = PATH.resolve().parent / '_synthetic_classifier_paths'
LINKER = BASE / 'toolchain/bin/ld.exe'
ORIGINAL = BASE / 'retained/objects/03-fiber_port.o'
TRAILER = 'collect2.exe: error: ld returned 1 exit status'


def inputs(symbol='SVC_Handler'):
    stem = 'duplicate_svc' if symbol == 'SVC_Handler' else 'duplicate_pendsv'
    return BASE / 'compilations' / stem / ('03-' + stem + '.o'), BASE / (stem + '.c')


def diagnostic(symbol='SVC_Handler', *, direct=False, newline='\n'):
    obj, source = inputs(symbol)
    section = '(.text.' + symbol + '+0x0)'
    detail = (source.name + ':' + section + ": multiple definition of `" + symbol
              + "'; " + str(ORIGINAL) + ':fiber_port.c:' + section + ': first defined here')
    if direct:
        detail = str(obj) + detail[len(source.name):]
        lines = [str(LINKER) + ': ' + detail, TRAILER]
    else:
        lines = [str(LINKER) + ': ' + str(obj) + ": in function `" + symbol + "':", detail, TRAILER]
    return (newline.join(lines) + newline).encode('utf-8')


def result(stderr=None, **changes):
    fields = dict(returncode=1, stdout=b'', stderr=diagnostic() if stderr is None else stderr, timed_out=False)
    fields.update(changes)
    return SimpleNamespace(**fields)


class DuplicateClassifierTests(unittest.TestCase):
    def classify(self, value=None, symbol='SVC_Handler', **changes):
        obj, source = inputs(symbol)
        arguments = dict(expected=symbol, linker=LINKER, added_object=obj, original_object=ORIGINAL, added_source=source)
        arguments.update(changes)
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('classifier cannot execute tools')):
            return controls.classify_duplicate(value if value is not None else result(diagnostic(symbol)), **arguments)

    def test_actual_headed_pattern_both_handlers_has_exact_identity_evidence(self):
        for symbol in ('SVC_Handler', 'PendSV_Handler'):
            with self.subTest(symbol=symbol):
                evidence = self.classify(symbol=symbol)
                obj, _ = inputs(symbol)
                self.assertEqual(evidence['DuplicateSymbols'], [symbol])
                self.assertEqual(evidence['AddedObject'], str(obj))
                self.assertEqual(evidence['OriginalObject'], str(ORIGINAL))
                self.assertEqual(evidence['Linker'], str(LINKER))
                self.assertEqual(evidence['DiagnosticTextSha256'], hashlib.sha256(diagnostic(symbol)).hexdigest().upper())
                self.assertEqual(evidence['DiagnosticNormalization'], 'CRLF-TO-LF-ONLY')
                self.assertNotIn('CellContractSatisfied', evidence)
                self.assertNotIn('FullABIProof', evidence)

    def test_supported_direct_pattern_requires_same_two_provider_identities(self):
        for symbol in ('SVC_Handler', 'PendSV_Handler'):
            with self.subTest(symbol=symbol):
                self.assertEqual(self.classify(result(diagnostic(symbol, direct=True)), symbol)['DuplicateSymbols'], [symbol])
                with self.assertRaises(controls.Rejected):
                    self.classify(result(diagnostic(symbol, direct=True)), symbol, added_object=BASE / 'foreign.o')

    def test_crlf_normalization_only_retains_same_text_hash(self):
        for symbol in ('SVC_Handler', 'PendSV_Handler'):
            with self.subTest(symbol=symbol):
                lf = self.classify(symbol=symbol)
                crlf = self.classify(result(diagnostic(symbol, newline='\r\n')), symbol)
                self.assertEqual(lf, crlf)

    def test_wrong_added_original_and_source_identity_reject(self):
        for changes in (dict(added_object=BASE / 'other-added.o'), dict(original_object=BASE / 'other-original.o'),
                        dict(added_source=BASE / 'other-source.c')):
            with self.subTest(changes=changes), self.assertRaises(controls.Rejected):
                self.classify(**changes)
        for before, after in ((str(inputs()[0]), str(BASE / 'forged-added.o')),
                              (str(ORIGINAL), str(BASE / 'forged-original.o'))):
            with self.subTest(before=before), self.assertRaises(controls.Rejected):
                self.classify(result(diagnostic().replace(before.encode('utf-8'), after.encode('utf-8'))))

    def test_wrong_linker_and_heading_function_reject(self):
        with self.assertRaises(controls.Rejected):
            self.classify(linker=BASE / 'foreign/ld.exe')
        for raw in (diagnostic().replace(str(LINKER).encode('utf-8'), str(BASE / 'forged/ld.exe').encode('utf-8')),
                    diagnostic().replace(b"in function `SVC_Handler':", b"in function `other_function':")):
            with self.subTest(raw=raw[:100]), self.assertRaises(controls.Rejected):
                self.classify(result(raw))

    def test_wrong_expected_or_unsupported_duplicate_symbol_reject(self):
        for expected in ('PendSV_Handler', 'SysTick_Handler', '', 'SVC_Handler extra'):
            with self.subTest(expected=expected), self.assertRaises(controls.Rejected):
                self.classify(result(), expected=expected)
        with self.assertRaises(controls.Rejected):
            self.classify(result(diagnostic('PendSV_Handler')))

    def test_missing_changed_or_repeated_trailer_reject(self):
        raw = diagnostic()
        for changed in (raw.removesuffix((TRAILER + '\n').encode('ascii')),
                        raw.replace(b'ld returned 1 exit status', b'ld returned 2 exit status'),
                        raw.replace(b'collect2.exe:', b'collect2:'), raw + (TRAILER + '\n').encode('ascii'),
                        raw[:-1], raw + b'\n'):
            with self.subTest(changed=changed[-100:]), self.assertRaises(controls.Rejected):
                self.classify(result(changed))

    def test_multiple_or_unrelated_diagnostic_causes_reject(self):
        raw = diagnostic()
        before, trailer = raw.rsplit((TRAILER + '\n').encode('ascii'), 1)
        self.assertEqual(trailer, b'')
        for extra in (b"unrelated.o:(.text+0x0): undefined reference to `another_symbol'\n",
                      b"another.o:(.text+0x0): multiple definition of `PendSV_Handler'\n",
                      b'warning: unrelated linker warning\n'):
            with self.subTest(extra=extra), self.assertRaises(controls.Rejected):
                self.classify(result(before + extra + (TRAILER + '\n').encode('ascii')))
        mixed = raw.replace(b': first defined here', b": first defined here; undefined reference to `another_symbol'")
        with self.assertRaises(controls.Rejected):
            self.classify(result(mixed))

    def test_stdout_is_not_an_allowed_diagnostic_channel(self):
        for stdout in (b'linker output\n', b'PASS\n', ''):
            with self.subTest(stdout=stdout), self.assertRaises(controls.Rejected):
                self.classify(result(stdout=stdout))

    def test_timeout_and_boolean_numeric_exit_aliases_reject(self):
        for timed_out in (True, 0, None):
            with self.subTest(timed_out=timed_out), self.assertRaises(controls.Rejected):
                self.classify(result(timed_out=timed_out))
        for returncode in (True, False, 0, 2, -1, 1.0, '1', None):
            with self.subTest(returncode=returncode), self.assertRaises(controls.Rejected):
                self.classify(result(returncode=returncode))

    def test_lone_cr_nul_nonbytes_or_bad_utf8_reject(self):
        for raw in (diagnostic().replace(b'\n', b'\r', 1), diagnostic() + b'\x00',
                    diagnostic() + b'\xff', bytearray(diagnostic())):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises((controls.Rejected, UnicodeDecodeError)):
                self.classify(result(raw))

    def test_wrong_section_or_original_source_context_reject(self):
        for raw in (diagnostic().replace(b'(.text.SVC_Handler', b'(.text.other_handler', 1),
                    diagnostic().replace(b':fiber_port.c:', b':another_provider.c:'),
                    diagnostic().replace(b'duplicate_svc.c:', b'other_fixture.c:')):
            with self.subTest(raw=raw[:100]), self.assertRaises(controls.Rejected):
                self.classify(result(raw))


if __name__ == '__main__':
    outcome = unittest.main(verbosity=2, exit=False)
    unchanged = PATH.read_bytes() == SOURCE_BYTES
    if not unchanged:
        print('FAIL controls.py source drift', file=sys.stderr)
    raise SystemExit(0 if outcome.result.wasSuccessful() and unchanged else 1)
