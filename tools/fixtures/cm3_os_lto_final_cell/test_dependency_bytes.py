"""Synthetic dependency grammar controls and ten read-only sealed ABI samples."""

import argparse
import builtins
from contextlib import ExitStack
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback
from types import ModuleType
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 18
BATCH_RECEIPT = '3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7'
BATCH_MANIFEST = '35E2A0B0895AD8458F8476C8E6F672176E39687B69137804E3342DDC663BD635'
subject = None
SAMPLES = {}
BUFFERS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def rule(body, target='pilot-source-0'):
    return (target + ': ' + body).encode('utf-8')


class GrammarTests(unittest.TestCase):
    def parse(self, raw, target='pilot-source-0'):
        return subject.parse(raw, target=target)

    def rejects(self, raws):
        for raw in raws:
            with self.subTest(raw=raw), self.assertRaises(subject.Rejected):
                self.parse(raw)

    def test_returns_sorted_tuple_of_canonical_absolute_paths(self):
        result = self.parse(rule('C:/z.h C:/a.h C:/nested/../b.h'))
        self.assertIs(type(result), tuple)
        self.assertEqual(result, (Path('C:/a.h'), Path('C:/b.h'), Path('C:/z.h')))
        self.assertTrue(all(isinstance(p, Path) and p.is_absolute() and '..' not in p.parts for p in result))
        self.assertEqual(self.parse(rule('C:/z.h C:/a.h')), (Path('C:/a.h'), Path('C:/z.h')))

    def test_target_is_explicit_typed_exact_and_keyword_only(self):
        for index in range(9):
            target = 'pilot-source-' + str(index)
            self.assertEqual(self.parse(rule('C:/a.h', target), target), (Path('C:/a.h'),))
        for target in (None, 0, True, b'pilot-source-0', 'pilot-source-9', 'pilot-source-00',
                       'pilot-source-0\n', 'pilot-source-0: C:/a.h'):
            with self.subTest(target=target), self.assertRaises(subject.Rejected):
                subject.parse(rule('C:/a.h'), target=target)
        with self.assertRaises(subject.Rejected):
            self.parse(rule('C:/a.h'), 'pilot-source-1')
        with self.assertRaises(TypeError):
            subject.parse(rule('C:/a.h'))
        with self.assertRaises(TypeError):
            subject.parse(rule('C:/a.h'), 'pilot-source-0')

    def test_literal_bytes_required_without_mutable_or_implicit_decoding(self):
        class ByteSubclass(bytes):
            pass
        for raw in (None, '', 'pilot-source-0: C:/a.h', bytearray(rule('C:/a.h')),
                    memoryview(rule('C:/a.h')), ByteSubclass(rule('C:/a.h'))):
            with self.subTest(raw=type(raw)), self.assertRaises(subject.Rejected):
                self.parse(raw)

    def test_strict_utf8_supports_unicode_filenames_but_not_bad_encoding_or_bom(self):
        body = 'C:/caf\u00e9/\u03b1.h'
        self.assertEqual(self.parse(rule(body)), (Path(body),))
        self.rejects((b'pilot-source-0: C:/\xff.h', b'pilot-source-0: C:/\xc0\x80.h',
                      b'pilot-source-0: C:/\xed\xa0\x80.h', b'\xef\xbb\xbfpilot-source-0: C:/a.h'))

    def test_controls_are_rejected_except_grammar_newlines_and_tabs(self):
        for code in (*range(9), *range(11, 13), *range(14, 32), *range(127, 160)):
            with self.subTest(code=code), self.assertRaises(subject.Rejected):
                self.parse(rule('C:/a' + chr(code) + '.h'))
        self.assertEqual(self.parse(rule('C:/a.h\tC:/b.h')), (Path('C:/a.h'), Path('C:/b.h')))

    def test_lf_crlf_and_no_terminal_newline_agree(self):
        raw = rule('C:/a.h C:/b.h')
        for suffix in (b'', b'\n', b'\r\n'):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.parse(raw + suffix), (Path('C:/a.h'), Path('C:/b.h')))
        self.rejects((raw + b'\r', raw + b'\r\r\n', raw + b'\n\n'))

    def test_gcc_continuations_fold_with_both_endings_like_the_producer(self):
        for eol in ('\n', '\r\n'):
            raw = rule('C:/a.h \\' + eol + ' C:/b.h \\' + eol + '\tC:/c.h' + eol)
            self.assertEqual(self.parse(raw), (Path('C:/a.h'), Path('C:/b.h'), Path('C:/c.h')))
            self.assertEqual(self.parse(rule('C:/head\\' + eol + 'er.h')), (Path('C:/header.h'),))

    def test_escaped_spaces_tabs_and_hashes_are_decoded_not_comments(self):
        raw = rule('C:/space\\ name/a.h C:/tab\\\tname/b.h C:/hash\\#name/c.h')
        self.assertEqual(self.parse(raw), tuple(sorted(map(Path,
            ('C:/space name/a.h', 'C:/tab\tname/b.h', 'C:/hash#name/c.h')))))
        self.assertEqual(self.parse(rule(r'C:\dir\space\ name.h')), (Path('C:/dir/space name.h'),))
        self.assertEqual(self.parse(rule(r'C:\\#root.h')), (Path('C:/#root.h'),))

    def test_literal_windows_backslashes_and_mixed_toolchain_parent_spelling(self):
        raw = rule(r'C:\toolchain\bin\../lib/gcc/include/stdint.h C:/project\context/../fiber/api.h')
        self.assertEqual(self.parse(raw), tuple(sorted((Path('C:/toolchain/lib/gcc/include/stdint.h'),
                                                       Path('C:/project/fiber/api.h')))))
        self.assertEqual(self.parse(rule(r'C:\new\test\folder\file.h')), (Path('C:/new/test/folder/file.h'),))

    def test_duplicates_are_removed_only_after_lexical_normalization(self):
        raw = rule(r'C:/root/a.h C:\root\a.h C:/root/sub/../a.h C:/root/./a.h C:/root/a.h')
        self.assertEqual(self.parse(raw), (Path('C:/root/a.h'),))
        self.assertEqual(self.parse(rule(r'C:/A.h c:\a.h')), (Path('C:/A.h'),))

    def test_relative_drive_relative_unc_device_and_stream_paths_reject(self):
        paths = ('header.h', './header.h', '../header.h', '/header.h', r'\header.h', 'C:header.h',
            r'C:dir\header.h', '//server/share/a.h', r'\\server\share\a.h', r'\\?\C:\a.h',
            r'\\.\C:\a.h', 'C:/a.h:stream', 'CC:/a.h', '1:/a.h')
        self.rejects(rule(p) for p in paths)

    def test_single_rule_target_separator_and_nonempty_inventory_are_required(self):
        self.rejects((b'', b'pilot-source-0: ', b'pilot-source-0:\tC:/a.h', b' pilot-source-0: C:/a.h',
            b'pilot-source-0 pilot-source-1: C:/a.h', b'pilot-source-0:: C:/a.h',
            rule('C:/a.h\npilot-source-1: C:/b.h'), rule('C:/a.h pilot-source-1: C:/b.h'),
            rule('C:/a.h\nC:/other.h: C:/b.h'), rule('C:/a.h\n C:/b.h')))

    def test_make_comments_expansion_order_only_and_recipes_are_not_interpreted(self):
        self.rejects(rule(p) for p in ('C:/a.h #comment', 'C:/a#b.h', '$(shell something)',
            'C:/$(VAR).h', 'C:/$$name.h', 'C:/a.h | C:/b.h', 'C:/a.h; echo ignored',
            'C:/a.h\n\techo ignored'))

    def test_malformed_continuations_and_dangling_backslashes_reject(self):
        self.rejects((rule('C:/a.h \\'), rule('C:/a.h\\'), rule('C:/a.h \\\n'),
            rule('C:/a.h \\\r\n '), rule('C:/a.h \\ \n C:/b.h'),
            rule('C:/a.h \\\r C:/b.h'), rule('C:/a.h \\\r\r\n C:/b.h')))

    def test_root_escape_is_lexical_not_a_claim_of_outer_admission(self):
        self.assertEqual(self.parse(rule('C:/admitted/../../elsewhere/header.h')),
                         (Path('C:/elsewhere/header.h'),))
        self.assertEqual(self.parse(rule('D:/unowned/header.h')), (Path('D:/unowned/header.h'),))

    def test_parse_never_reads_writes_resolves_imports_or_starts_processes(self):
        forbidden = AssertionError('parser performed a physical or execution operation')
        with ExitStack() as stack:
            for name in ('resolve', 'absolute', 'stat', 'lstat', 'exists', 'is_file', 'is_dir', 'samefile',
                         'open', 'read_bytes', 'read_text', 'write_bytes', 'write_text', 'iterdir', 'glob', 'rglob', 'mkdir'):
                stack.enter_context(patch.object(Path, name, side_effect=forbidden))
            for name in ('stat', 'lstat', 'open', 'getcwd', 'chdir', 'system'):
                stack.enter_context(patch.object(os, name, side_effect=forbidden))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=forbidden))
            stack.enter_context(patch.object(importlib, 'import_module', side_effect=forbidden))
            stack.enter_context(patch.object(builtins, 'open', side_effect=forbidden))
            stack.enter_context(patch.object(builtins, '__import__', side_effect=forbidden))
            result = self.parse(rule(r'C:\toolchain\bin\../lib/a.h C:/toolchain/lib/a.h'))
            rejected = False
            try:
                self.parse(rule('../unowned.h'))
            except subject.Rejected:
                rejected = True
        self.assertEqual(result, (Path('C:/toolchain/lib/a.h'),))
        self.assertTrue(rejected)


class RealSamples(unittest.TestCase):
    def agreement(self, kind):
        count = 0
        for name, row in sorted(SAMPLES['Report']['ABIProbes'].items()):
            path = Path(row['DiscoveryDependencyFile' if kind == 'discovery' else 'CompileDependencyFile'])
            raw = BUFFERS[path]
            target = raw.decode('utf-8').partition(': ')[0]
            self.assertRegex(target, r'^pilot-source-[0-8]$')
            result = subject.parse(raw, target=target)
            expected = tuple(sorted({Path(x['Path']) for x in row['Dependencies']}))
            with self.subTest(name=name, kind=kind):
                self.assertEqual(result, expected)
                self.assertEqual(sha(raw), SAMPLES['Artifacts'][path.relative_to(SAMPLES['Root']).as_posix()])
                self.assertEqual(sha(raw), SAMPLES['Report']['InputHashes'][str(path)])
                for dependency in row['Dependencies']:
                    self.assertEqual(SAMPLES['Report']['InputHashes'][dependency['Path']], dependency['Sha256'])
            count += 1
        self.assertEqual(count, 5)

    def test_all_five_sealed_abi_discovery_files_match_bound_metadata(self):
        self.agreement('discovery')

    def test_all_five_sealed_abi_compile_files_match_bound_metadata(self):
        self.agreement('compile')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--batch-build', type=Path, default=Path('C:/fzosbatch-20261107-e1'))
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary) or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
        parser.error('fresh external TEMP receipt directory required')
    report = dict(Status='FAIL', Scope='PURE_DEPENDENCY_BYTE_GRAMMAR_AND_READ_ONLY_ABI_SAMPLES',
        Tests=0, ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0, SourceHashes={}, InputHashes={},
        SourceDrift=[], SourceClosureVerified=False, ActualDependencyFilesRead=0,
        ProducerDependencyParserExecuted=False, ActualCaptureAdmitted=False, ExternalToolsExecuted=0,
        Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('fresh unoptimized -I -S -B interpreter required')
        sources = (Path(__file__).resolve(), HERE / 'dependency_bytes.py')
        for p in sources: BUFFERS[p] = p.read_bytes()
        report['SourceHashes'] = {str(p): sha(BUFFERS[p]) for p in sources}
        batch = args.batch_build
        for p, digest in ((batch / 'results.json', BATCH_RECEIPT), (batch / 'artifacts.json', BATCH_MANIFEST)):
            BUFFERS[p] = p.read_bytes()
            if sha(BUFFERS[p]) != digest: raise ValueError('sealed sample descriptor mismatch/' + str(p))
        record = json.loads(BUFFERS[batch / 'results.json'])
        artifacts = json.loads(BUFFERS[batch / 'artifacts.json'])['Artifacts']
        if artifacts['results.json'] != BATCH_RECEIPT or record['Phases'][0] != dict(Name='ABIControls', First=0, Stop=41, Commands=41):
            raise ValueError('exact recorded 41-command ABI phase required')
        sample_paths = {Path(row[field]) for row in record['ABIProbes'].values()
                        for field in ('DiscoveryDependencyFile', 'CompileDependencyFile')}
        if len(sample_paths) != 10: raise ValueError('exact ten ABI dependency samples required')
        for p in sample_paths:
            if not p.is_relative_to(batch / 'abi'): raise ValueError('sample outside ABI directory')
            BUFFERS[p] = p.read_bytes()
        if {p for p in artifacts if p.startswith('abi/') and p.endswith('.d')} != {p.relative_to(batch).as_posix() for p in sample_paths}:
            raise ValueError('exact ABI dependency artifact membership')
        report['InputHashes'] = {str(p): sha(raw) for p, raw in BUFFERS.items() if p not in sources}
        report['ActualDependencyFilesRead'] = len(sample_paths)
        SAMPLES.update(Root=batch, Report=record, Artifacts=artifacts)
        global subject
        with patch.object(subprocess, 'Popen', side_effect=AssertionError('no tool execution')), \
                patch.object(os, 'system', side_effect=AssertionError('no shell execution')):
            subject = ModuleType('_dependency_bytes_tests')
            subject.__file__ = str(sources[1])
            exec(compile(BUFFERS[sources[1]], str(sources[1]), 'exec'), subject.__dict__)
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (GrammarTests, RealSamples))
            if suite.countTestCases() != METHODS: raise ValueError('exact implemented method count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            Details=[dict(Test=str(case), Error=error) for case, error in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped: report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for p, raw in BUFFERS.items():
            try:
                if sha(p.read_bytes()) != sha(raw): report['SourceDrift'].append(str(p))
            except OSError: report['SourceDrift'].append(str(p))
        report['SourceClosureVerified'] = len(report['SourceHashes']) == 2 and not report['SourceDrift']
        if not report['SourceClosureVerified']: report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
