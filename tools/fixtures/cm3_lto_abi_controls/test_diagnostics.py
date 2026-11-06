"""Pure synthetic controls for the closed GCC14 LTO diagnostic classifier."""

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


SUBJECT = Path(__file__).resolve().with_name('diagnostics.py')
REPO = SUBJECT.parents[3]
SUBJECT_SHA = '0A1CD4EB14172C3E3FF1E5B05A733C7837404E7DD95C8D6953323EB26FEA250C'
EXPECTED_METHODS = 18
LD = 'C:/tool chain/bin/../arm-none-eabi/bin/ld.exe'
MACHINE = 'C:/private negative/image.elf.ltrans0.ltrans.o'
ADDED = 'C:/private negative/duplicate_svc.o'
ORIGINAL = 'C:/admitted/03-fiber_port.o'
SOURCE = 'C:/private negative/duplicate_svc.c'
PRIVATE = ('fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_f0_e0_h1_j1_v1_d0_r0_'
           'z8u_y0_w2_g5_u00010000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
STORAGE = 'fiber_port_storage_cohort_arm_cm3_v999_r0'
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
TABLE = '.fiber_port_context_cohort_expectation'
TRAILER = 'collect2.exe: error: ld returned 1 exit status'
subject = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def result(text, **changes):
    record = SimpleNamespace(returncode=1, stdout=b'', stderr=text.encode('utf-8'), timed_out=False)
    for key, value in changes.items():
        setattr(record, key, value)
    return record


def undefined(symbol=PRIVATE, *, function='fiber_port_context_init', machine=MACHINE,
              ld=LD, section='.text', offset='18', source='<artificial>'):
    if function is None:
        lines = [f"{ld}: {machine}:({section}+0x{offset}): undefined reference to `{symbol}'"]
    else:
        lines = [f"{ld}: {machine}: in function `{function}':",
                 f"{source}:({section}+0x{offset}): undefined reference to `{symbol}'"]
    return '\n'.join(lines + [TRAILER]) + '\n'


def duplicate(symbol='SVC_Handler', *, ld=LD, added=ADDED, original=ORIGINAL):
    return (f"{ld}: {added} (symbol from plugin): in function `{symbol}':\n"
            f"(.text+0x0): multiple definition of `{symbol}'; {original} (symbol from plugin):"
            f"(.text+0x0): first defined here\n{TRAILER}\n")


class DiagnosticTests(unittest.TestCase):
    def undef(self, text=None, expected=PRIVATE, **kwargs):
        kwargs.setdefault('machine', MACHINE)
        return subject.classify_undefined(result(undefined() if text is None else text), expected, LD, **kwargs)

    def dup(self, text=None, symbol='SVC_Handler', **kwargs):
        arguments = dict(ld=LD, added=ADDED, original=ORIGINAL, source=SOURCE)
        arguments.update(kwargs)
        return subject.classify_duplicate(result(duplicate(symbol) if text is None else text),
                                          symbol, **arguments)

    def rejected_undefined(self, record, expected=PRIVATE, **kwargs):
        with self.assertRaises(subject.Rejected):
            subject.classify_undefined(record, expected, LD, machine=MACHINE, **kwargs)

    def test_private_function_and_expectation_references(self):
        pieces = [undefined(function='fiber_exception_runtime_check', offset='b48'),
                  undefined(offset='1168'), undefined(function=None, section=TABLE, offset='0')]
        text = ''.join(piece.removesuffix(TRAILER + '\n') for piece in pieces) + TRAILER + '\n'
        proof = self.undef(text)
        self.assertEqual(proof['Classification'], 'INTENDED-LTO-UNDEFINED')
        self.assertEqual(proof['MissingSymbols'], [PRIVATE])
        self.assertEqual(proof['ReferenceCount'], 3)
        self.assertEqual([row['Function'] for row in proof['References']],
                         ['fiber_exception_runtime_check', 'fiber_port_context_init', None])
        self.assertEqual([row['Offset'] for row in proof['References']], [0xb48, 0x1168, 0])
        self.assertIs(proof['MachinePathCallerBound'], True)

    def test_storage_uses_same_context_expectation_section(self):
        text = undefined(STORAGE, function=None, section=TABLE, offset='4')
        proof = self.undef(text, STORAGE)
        self.assertEqual(proof['Family'], 'storage')
        self.assertEqual(proof['References'][0]['Section'], TABLE)
        self.rejected_undefined(result(text.replace(TABLE, '.fiber_port_storage_cohort_expectation')), STORAGE)
        self.rejected_undefined(result(undefined(STORAGE)), STORAGE)

    def test_reverse_anchor_only_approved_function_groups(self):
        for function in ('fiber_port_context_init', 'fiber_port_runtime_prepare_start'):
            with self.subTest(function=function):
                proof = self.undef(undefined(ANCHOR, function=function), ANCHOR)
                self.assertEqual(proof['Family'], 'anchor')
        for text in (undefined(ANCHOR, function=None, section=TABLE),
                     undefined(ANCHOR, function='fiber_exception_runtime_check')):
            with self.subTest(text=text):
                self.rejected_undefined(result(text), ANCHOR)

    def test_exact_expected_name_and_closed_symbol_families(self):
        for expected in (STORAGE, ANCHOR, PRIVATE + '_foreign', '', True, 1, None,
                         'fiber_panic', 'fiber_port_storage_cohort_arm_cm7_v999_r0', PRIVATE + '\n'):
            with self.subTest(expected=expected):
                self.rejected_undefined(result(undefined()), expected)
        for foreign in ('fiber_panic', PRIVATE + '_other'):
            self.rejected_undefined(result(undefined(foreign)))

    def test_machine_exact_path_partition_and_ir_not_substitutable(self):
        for machine in ('D:/private negative/image.elf.ltrans0.ltrans.o',
                        MACHINE.replace('ltrans0', 'ltrans1'), MACHINE.replace('.ltrans.o', '.o'),
                        'relative/image.elf.ltrans0.ltrans.o'):
            with self.subTest(machine=machine):
                self.rejected_undefined(result(undefined(machine=machine)))
        proof = subject.classify_undefined(result(undefined()), PRIVATE, LD)
        self.assertIs(proof['MachinePathCallerBound'], False)
        mixed = undefined().removesuffix(TRAILER + '\n') + undefined(
            function=None, section=TABLE, machine='D:/image.elf.ltrans0.ltrans.o')
        with self.assertRaises(subject.Rejected):
            subject.classify_undefined(result(mixed), PRIVATE, LD)

    def test_quoted_windows_drive_paths_and_lexical_identity(self):
        windows_ld = '"c:\\tool chain\\ARM-NONE-EABI\\BIN\\ld.exe"'
        windows_machine = "'c:\\PRIVATE NEGATIVE\\image.elf.ltrans0.ltrans.o'"
        proof = self.undef(undefined(ld=windows_ld, machine=windows_machine))
        self.assertEqual(proof['ReferenceCount'], 1)
        for ld in ('D:/arm-none-eabi/bin/ld.exe', 'C:arm-none-eabi/bin/ld.exe',
                   'C:/toolchain/ld.exe:injected', '\\server\\share\\ld.exe',
                   '"C:/arm-none-eabi/bin/ld.exe'):
            with self.subTest(ld=ld):
                self.rejected_undefined(result(undefined(ld=ld)))
        apostrophe = "C:/owner's directory/image.elf.ltrans0.ltrans.o"
        proof = subject.classify_undefined(result(undefined(machine=apostrophe)), PRIVATE, LD, machine=apostrophe)
        self.assertEqual(proof['ReferenceCount'], 1)

    def test_optional_source_paths_are_explicit_not_fallback(self):
        source = 'C:/project source/context.c'
        text = undefined(source='"C:\\project source\\context.c"')
        proof = self.undef(text, sources=[source])
        self.assertEqual(proof['References'][0]['Source'], '"C:\\project source\\context.c"')
        for sources in ((), ['D:/context.c'], [source, source.upper()], source, None):
            with self.subTest(sources=sources):
                self.rejected_undefined(result(text), sources=sources)
        self.rejected_undefined(result(undefined(source=source + ':23')), sources=[source])

    def test_result_returncode_and_phase_types_are_literal(self):
        for key, values in {
            'returncode': (True, False, 1.0, 0, 2, -1, '1', None),
            'State': ('ATTEMPT', 'PENDING', True, None),
            'Status': ('PASS', 'ATTEMPT', True, None),
            'state': ('ATTEMPT',), 'status': ('PASS',),
            'Error': ('process setup failed', False), 'error': ('cleanup failed',),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.rejected_undefined(result(undefined(), **{key: value}))
        proof = subject.classify_undefined(result(undefined(), State='TERMINAL', Status='FAIL', Error=None),
                                           PRIVATE, LD, machine=MACHINE)
        self.assertEqual(proof['LinkerExitRecords'], 1)

    def test_stdout_timeout_and_stderr_types_reject_for_both_apis(self):
        for changes in ({'stdout': b'noise'}, {'stdout': ''}, {'stdout': bytearray()},
                        {'timed_out': True}, {'timed_out': 0}, {'timed_out': None},
                        {'stderr': ''}, {'stderr': b''}, {'stderr': bytearray(b'failure')}):
            for is_duplicate in (False, True):
                with self.subTest(changes=changes, duplicate=is_duplicate):
                    record = result(duplicate() if is_duplicate else undefined(), **changes)
                    with self.assertRaises(subject.Rejected):
                        if is_duplicate:
                            subject.classify_duplicate(record, 'SVC_Handler', LD, ADDED, ORIGINAL, SOURCE)
                        else:
                            subject.classify_undefined(record, PRIVATE, LD, machine=MACHINE)

    def test_extra_compiler_plugin_verbose_and_foreign_errors_reject(self):
        extra_lines = ('cc1.exe: out of memory allocating 1024 bytes',
                       'lto-wrapper.exe: fatal error: compilation terminated',
                       'lto-wrapper: warning: using serial compilation of 1 LTRANS jobs',
                       'COLLECT_GCC=C:/toolchain/gcc.exe', 'Reading specs from C:/foreign.specs',
                       'warning: unrelated diagnostic',
                       f"{LD}: other.o:(.text+0x0): undefined reference to `foreign'")
        for extra in extra_lines:
            for specimen in (undefined(), duplicate()):
                for position in ('before', 'after'):
                    text = (extra + '\n' + specimen if position == 'before' else
                            specimen.replace(TRAILER + '\n', extra + '\n' + TRAILER + '\n'))
                    with self.subTest(extra=extra, position=position, duplicate=specimen == duplicate()):
                        with self.assertRaises(subject.Rejected):
                            if specimen == duplicate():
                                self.dup(text)
                            else:
                                self.undef(text)

    def test_order_repeated_sites_and_exact_terminal_trailer(self):
        lines = undefined().splitlines()
        variants = ('\n'.join([lines[0], lines[-1]]) + '\n',
                    '\n'.join([lines[1], lines[0], lines[-1]]) + '\n',
                    '\n'.join([lines[0], lines[0], lines[1], lines[-1]]) + '\n',
                    '\n'.join([lines[0], lines[1], lines[1], lines[-1]]) + '\n',
                    undefined() + TRAILER + '\n', undefined() + 'tail\n',
                    undefined().replace('1 exit status', '2 exit status'), undefined().rstrip('\n'),
                    undefined().replace(TRAILER, '\n' + TRAILER), TRAILER + '\n')
        for text in variants:
            with self.subTest(text=text):
                self.rejected_undefined(result(text))
        self.rejected_undefined(result(undefined(function=None, section='.text')))

    def test_duplicate_both_strong_handlers_observed_plugin_form(self):
        for symbol in ('SVC_Handler', 'PendSV_Handler'):
            with self.subTest(symbol=symbol):
                proof = self.dup(symbol=symbol)
                self.assertEqual(proof['Classification'], 'INTENDED-LTO-DUPLICATE')
                self.assertEqual(proof['DuplicateSymbols'], [symbol])
                self.assertIs(proof['PluginObjectDiagnostic'], True)
                self.assertIs(proof['SourcePathPresent'], False)
                self.assertIs(proof['SourceOwnershipProven'], False)

    def test_duplicate_exact_provider_objects_linker_and_handler(self):
        for kwargs in ({'added': 'D:/duplicate.o'}, {'original': 'D:/runtime.o'},
                       {'ld': 'D:/ld.exe'}, {'source': 'relative.c'}, {'source': SOURCE + '.o'},
                       {'added': ORIGINAL}, {'original': ADDED}, {'added': ADDED + '.ir'}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(subject.Rejected):
                    self.dup(**kwargs)
        for symbol in ('SVC_Handler_foreign', 'fiber_panic', '', True):
            with self.subTest(symbol=symbol):
                with self.assertRaises(subject.Rejected):
                    self.dup(symbol=symbol)
        for text in (duplicate().replace('SVC_Handler', 'PendSV_Handler', 1),
                     duplicate().replace(ORIGINAL, 'D:/unrelated/runtime.o')):
            with self.assertRaises(subject.Rejected):
                self.dup(text)

    def test_duplicate_no_extra_cause_plain_object_or_offset_relaxation(self):
        specimens = (duplicate().replace('(symbol from plugin)', '', 1),
                     duplicate().replace('(.text+0x0)', '(.text+0x4)', 1),
                     duplicate().replace('first defined here', 'first defined here; another cause'),
                     duplicate().replace(TRAILER, duplicate().splitlines()[1] + '\n' + TRAILER),
                     duplicate().replace('(.text+0x0)', '(.text.foreign+0x0)'),
                     duplicate().replace('multiple definition', 'undefined reference'),
                     duplicate().replace(TRAILER, 'collect2.exe: error: ld returned 0 exit status'))
        for text in specimens:
            with self.subTest(text=text):
                with self.assertRaises(subject.Rejected):
                    self.dup(text)

    def test_duplicate_quoted_paths_drive_parsing_and_source_nonclaim(self):
        text = duplicate(ld='"C:/tool chain/arm-none-eabi/bin/ld.exe"',
                         added="'c:\\PRIVATE NEGATIVE\\duplicate_svc.o'",
                         original='"c:\\ADMITTED\\03-fiber_port.o"')
        proof = self.dup(text)
        self.assertIs(proof['SourceOwnershipProven'], False)
        other = self.dup(source='D:/declared different source/source.c')
        self.assertEqual(other['DeclaredAddedSource'], 'D:/declared different source/source.c')
        self.assertIs(other['SourceOwnershipProven'], False)
        for bad in ('C:relative.o', '//server/share/added.o', 'C:/bad.o:4',
                    'C:/line\nbreak.o', '"C:/unclosed.o'):
            with self.subTest(added=bad):
                with self.assertRaises(subject.Rejected):
                    self.dup(added=bad)

    def test_byte_decoding_crlf_only_and_closed_control_characters(self):
        lf = self.undef()
        record = result(undefined().replace('\n', '\r\n'))
        crlf = subject.classify_undefined(record, PRIVATE, LD, machine=MACHINE)
        self.assertEqual(lf['DiagnosticTextSha256'], crlf['DiagnosticTextSha256'])
        self.assertNotEqual(lf['DiagnosticSha256'], crlf['DiagnosticSha256'])
        self.assertEqual(crlf['DiagnosticSha256'], sha(record.stderr))
        for raw in (undefined().encode() + b'\xff', b'\xff' + undefined().encode(),
                    undefined().replace('\n', '\r', 1).encode(),
                    undefined().replace('<artificial>', '<artificial>\x00').encode(),
                    b'\x1b[31m' + undefined().encode(), undefined().encode() + b'\x7f'):
            with self.subTest(raw=raw):
                self.rejected_undefined(result('', stderr=raw))

    def test_pure_classifiers_do_not_read_write_or_mutate_results(self):
        records = (result(undefined()), result(duplicate()))
        before = copy.deepcopy([vars(row) for row in records])
        with patch('builtins.open', side_effect=AssertionError('classifier file I/O')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('classifier path read')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('classifier text read')), \
                patch.object(Path, 'write_bytes', side_effect=AssertionError('classifier path write')), \
                patch('subprocess.Popen', side_effect=AssertionError('classifier process')):
            subject.classify_undefined(records[0], PRIVATE, LD, machine=MACHINE)
            subject.classify_duplicate(records[1], 'SVC_Handler', LD, ADDED, ORIGINAL, SOURCE)
        self.assertEqual([vars(row) for row in records], before)

    def test_classification_is_not_provenance_or_qualification(self):
        for proof in (self.undef(), self.dup()):
            self.assertIs(proof['ClosedGrammarValidated'], True)
            for field in ('CommandProvenanceVerified', 'PhysicalIdentityChecked', 'FullABIProof',
                          'Qualification', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified',
                          'RequiredCellSatisfied'):
                with self.subTest(field=field):
                    self.assertIs(proof[field], False)
            self.assertIs(type(proof['RequiredCellsSatisfied']), int)
            self.assertEqual(proof['RequiredCellsSatisfied'], 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT)
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CM3_LTO_DIAGNOSTIC_GRAMMAR_CONTROLS_ONLY',
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        SyntheticInputs=True, ActualToolTranscriptReplayed=False, NativeCommandsExecuted=0,
        Qualification=False, FullABIProof=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized host Python required')
        buffers = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        if sha(buffers[SUBJECT]) != SUBJECT_SHA:
            raise ValueError('frozen classifier source pin mismatch')
        global subject
        subject = ModuleType('_cm3_lto_diagnostics_test_subject')
        subject.__file__ = str(SUBJECT)
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn processes')), \
                patch('os.system', side_effect=AssertionError('pure tests cannot execute commands')):
            exec(compile(buffers[SUBJECT], str(SUBJECT), 'exec'), subject.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(DiagnosticTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact eighteen implemented methods required')
            outcome = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=outcome.testsRun, Failures=len(outcome.failures), Errors=len(outcome.errors),
            Skipped=len(outcome.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in outcome.failures + outcome.errors])
        if outcome.wasSuccessful() and outcome.testsRun == EXPECTED_METHODS and not outcome.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
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
    target = output / 'results.json'
    target.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', target, sha(target.read_bytes()))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
