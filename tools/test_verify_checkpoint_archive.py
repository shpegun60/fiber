"""Small synthetic ZIP tests only; no checkpoint replay or original-path reads."""
import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile


PIN = 'D13CE0F9C60598BAB20BFE88E211DCD4AE9A7D3011542D6E869ED0033F44F005'
SUBJECT = Path(__file__).with_name('verify_checkpoint_archive.py')
METHODS = (
    'test_required_members_and_default_writestr_mode',
    'test_all_builder_optional_members_and_fields',
    'test_regular_file_modes_and_nonregular_rejection',
    'test_unsafe_and_unknown_member_names',
    'test_duplicate_and_case_alias_members',
    'test_manifest_exact_membership',
    'test_manifest_row_schema_and_types',
    'test_manifest_hash_size_and_payload_content_address',
    'test_provenance_schema_and_optional_types',
    'test_alternate_and_distinct_historical_versions',
    'test_missing_mismatch_are_incomplete',
    'test_resolved_provenance_bindings',
    'test_checkpoint_metadata_not_a_counts_or_claim_oracle',
    'test_duplicate_nonfinite_and_overflow_json',
    'test_crc_corruption_after_sidecar_rebinding',
    'test_local_headers_and_encryption',
    'test_malformed_and_missing_archives',
    'test_required_sidecar_format_and_digest',
    'test_windows_path_handle_ctime_difference',
    'test_path_handle_and_content_drift_rejected',
    'test_historical_paths_not_accessed_no_extraction',
    'test_cli_statuses_explicit_sidecar_and_stdout_failure',
)
v = None


def encoded(value):
    return json.dumps(value, sort_keys=True).encode('ascii')


def hashed(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


def changed_stat(info, **changes):
    fields = ('st_dev', 'st_ino', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    return SimpleNamespace(**(dict((key, getattr(info, key)) for key in fields) | changes))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='checkpoint-archive-synthetic-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'fixture.zip'
        self.data = b'opaque synthetic preserved bytes\x00\xff'
        self.digest = v.sha(self.data)
        self.row = dict(OriginalPath='Z:/NEVER-ACCESS/original.py',
                        ExpectedSha256=self.digest, Status='captured',
                        Payload='payload/' + self.digest,
                        ActualSourcePath='Z:/NEVER-ACCESS/original.py',
                        ActualSha256=self.digest, Roles=['synthetic:fixture'])

    def files(self, rows=None):
        return {'checkpoint.json': b'{"ArbitraryMetadata":true,"Counts":999}',
                'provenance.json': encoded(dict(Schema=v.PROVENANCE_SCHEMA,
                    Records=copy.deepcopy([self.row] if rows is None else rows))),
                'README.txt': b'synthetic archive only',
                'verify_checkpoint_archive.py': b'INTENTIONALLY NOT VALID PYTHON !!!',
                'payload/' + self.digest: self.data}

    def manifest(self, files):
        return dict(Schema=v.SCHEMA, Files=[dict(Path=name, Bytes=len(data), Sha256=v.sha(data))
                                          for name, data in files.items()])

    def write(self, files=None, manifest=None, extras=(), mode=None, compression=zipfile.ZIP_STORED):
        files = self.files() if files is None else files
        manifest = self.manifest(files) if manifest is None else manifest
        with warnings.catch_warnings(), zipfile.ZipFile(self.path, 'w', compression=compression) as archive:
            warnings.simplefilter('ignore', UserWarning)
            for name, data in list(files.items()) + [('MANIFEST.json', encoded(manifest))] + list(extras):
                if mode is None or name != 'README.txt':
                    archive.writestr(name, data)
                else:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = mode
                    archive.writestr(info, data)
        self.sidecar()

    def sidecar(self):
        Path(str(self.path) + '.sha256').write_bytes(
            (hashed(self.path) + '  ' + self.path.name + '\n').encode('ascii'))

    def check(self, status='FAIL', phrase=None):
        report = v.verify_archive(self.path)
        self.assertEqual(report['Status'], status, report)
        self.assertIs(report['Complete'], status == 'PASS')
        self.assertIs(report['Qualification'], False)
        self.assertIs(report['HistoricalPathsAccessed'], False)
        if status == 'FAIL':
            self.assertTrue(report['Errors'], report)
        if phrase:
            self.assertIn(phrase, '\n'.join(report['Errors']))
        return report

    def test_required_members_and_default_writestr_mode(self):
        self.write(compression=zipfile.ZIP_DEFLATED)
        report = self.check('PASS')
        self.assertEqual(report['Counts']['ZIPFiles'], 6)
        self.assertEqual(report['Counts']['CRCVerifiedFiles'], 6)
        self.assertEqual(report['Counts']['SHA256VerifiedFiles'], 5)
        self.assertEqual(report['Counts']['OptionalSourceTar'], 0)
        with zipfile.ZipFile(self.path) as archive:
            self.assertTrue(all(stat.S_IFMT(info.external_attr >> 16) == 0 for info in archive.infolist()))

    def test_all_builder_optional_members_and_fields(self):
        row = dict(self.row, HistoricalHash=True, OriginalObservedSha256=self.digest,
                   AlternateDisclosure='Synthetic disclosure, not restored identity.')
        files = self.files([row])
        files.update({name: b'opaque optional bytes' for name in v.OPTIONAL})
        self.write(files)
        report = self.check('PASS')
        self.assertEqual(report['Counts']['ZIPFiles'], 12)
        self.assertEqual(report['Counts']['OptionalSourceTar'], 1)
        row['HistoricalHash'] = False
        self.write(self.files([row]))
        self.check('PASS')

    def test_regular_file_modes_and_nonregular_rejection(self):
        for mode in (0o600, (stat.S_IFREG | 0o600) << 16):
            with self.subTest(accepted=mode):
                self.write(mode=mode)
                self.check('PASS')
        for kind in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK):
            with self.subTest(rejected=kind):
                self.write(mode=(kind | 0o600) << 16)
                self.check()
        self.write(mode=(0o600 << 16) | 0x10)
        self.check(phrase='DOS directory')

    def test_unsafe_and_unknown_member_names(self):
        for name in ('../escape', '/absolute', 'C:/drive', 'payload/../escape', 'payload//empty',
                     'payload/./dot', 'payload\\backslash', 'README.txt:stream', 'README.txt.',
                     'README.txt ', 'payload/\x01control', 'payload/', 'unlisted-new-name.txt'):
            with self.subTest(name=name):
                self.write(extras=[(name, b'foreign')])
                self.check()

    def test_duplicate_and_case_alias_members(self):
        for name in ('README.txt', 'readme.TXT'):
            with self.subTest(name=name):
                self.write(extras=[(name, b'foreign')])
                self.check(phrase='duplicate' if name == 'README.txt' else 'case-alias')

    def test_manifest_exact_membership(self):
        files = self.files()
        for change in ('unlisted', 'absent', 'self', 'duplicate'):
            with self.subTest(change=change):
                manifest = self.manifest(files)
                if change == 'unlisted':
                    manifest['Files'].pop()
                elif change == 'absent':
                    manifest['Files'].append(dict(Path='commands.json', Bytes=0, Sha256=v.sha(b'')))
                elif change == 'self':
                    manifest['Files'].append(dict(Path='MANIFEST.json', Bytes=0, Sha256=v.sha(b'')))
                else:
                    manifest['Files'].append(dict(manifest['Files'][0]))
                self.write(files, manifest)
                self.check()
        files.pop('README.txt')
        self.write(files)
        self.check(phrase='missing required')

    def test_manifest_row_schema_and_types(self):
        for field, value in (('Bytes', True), ('Bytes', -1), ('Bytes', 1.0),
                             ('Sha256', 'a' * 64), ('Foreign', False), ('Path', '../bad')):
            with self.subTest(field=field, value=value):
                manifest = self.manifest(self.files())
                manifest['Files'][0][field] = value
                self.write(manifest=manifest)
                self.check()
        manifest['Schema'] = 'foreign'
        self.write(manifest=manifest)
        self.check()

    def test_manifest_hash_size_and_payload_content_address(self):
        for field, value in (('Bytes', 999), ('Sha256', 'F' * 64)):
            with self.subTest(field=field):
                manifest = self.manifest(self.files())
                manifest['Files'][0][field] = value
                self.write(manifest=manifest)
                self.check(phrase='manifest size/SHA256')
        files = self.files()
        files['payload/' + self.digest] = b'wrong content, honestly hashed by manifest'
        self.write(files)
        self.check(phrase='payload filename')

    def test_provenance_schema_and_optional_types(self):
        for field, value in (('HistoricalHash', 1), ('OriginalObservedSha256', 'a' * 64),
                             ('OriginalObservedSha256', None), ('AlternateDisclosure', ''),
                             ('AlternateDisclosure', True), ('Foreign', False), ('Roles', 'not-list'),
                             ('Roles', [False]), ('ExpectedSha256', 'bad'), ('Status', 'PASS')):
            with self.subTest(field=field, value=value):
                self.write(self.files([dict(self.row, **{field: value})]))
                self.check()
        row = dict(self.row)
        del row['Payload']
        self.write(self.files([row]))
        self.check()
        self.write(self.files([self.row, self.row]))
        self.check(phrase='duplicate provenance')

    def test_alternate_and_distinct_historical_versions(self):
        alternate = dict(self.row, Status='alternate', ActualSourcePath='Y:/opaque/alternate',
                         OriginalObservedSha256=v.sha(b'other bytes'),
                         AlternateDisclosure='Exact bytes from another capture, not original identity.')
        newer = dict(self.row, ExpectedSha256=v.sha(b'new version'), Status='missing',
                     Payload=None, ActualSha256=None, ActualSourcePath=None)
        self.write(self.files([alternate]))
        report = self.check('PASS')
        self.assertEqual(report['Counts']['Alternate'], 1)
        self.assertEqual(report['AlternateRecords'], [alternate])
        self.write(self.files([alternate, newer]))
        report = self.check('INCOMPLETE')
        self.assertEqual(report['Counts']['Records'], 2)

    def test_missing_mismatch_are_incomplete(self):
        for status in ('missing', 'mismatch'):
            with self.subTest(status=status):
                row = dict(self.row, Status=status, Payload=None, ActualSha256=None, ActualSourcePath=None)
                self.write(self.files([row]))
                report = self.check('INCOMPLETE')
                self.assertEqual(report['UnresolvedRecords'], [row])
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(v.main([str(self.path)]), 1)
                self.assertEqual(json.loads(output.getvalue())['Status'], 'INCOMPLETE')

    def test_resolved_provenance_bindings(self):
        for field, value in (('Payload', None), ('Payload', 'payload/' + 'F' * 64),
                             ('ActualSha256', 'F' * 64), ('ActualSourcePath', None),
                             ('ExpectedSha256', 'F' * 64)):
            with self.subTest(field=field):
                self.write(self.files([dict(self.row, **{field: value})]))
                self.check()

    def test_checkpoint_metadata_not_a_counts_or_claim_oracle(self):
        files = self.files()
        files['checkpoint.json'] = b'{"ForeignUnknownMetadata":{},"Records":-999,"Qualification":true}'
        self.write(files)
        report = self.check('PASS')
        self.assertEqual(report['Counts']['Records'], 1)
        self.assertIs(report['CheckpointCountsTrusted'], False)
        self.assertIs(report['CheckpointMetadataJSONOnly'], True)
        files['checkpoint.json'] = b'[]'
        self.write(files)
        self.check()

    def test_duplicate_nonfinite_and_overflow_json(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":-Infinity}', b'{"x":1e999}', b'not-json'):
            with self.subTest(raw=raw):
                files = self.files()
                files['checkpoint.json'] = raw
                self.write(files)
                self.check()
        files = self.files()
        files['provenance.json'] = b'{"Schema":"x","Schema":"y","Records":[]}'
        self.write(files)
        self.check(phrase='duplicate JSON key')

    def test_crc_corruption_after_sidecar_rebinding(self):
        self.write()
        with zipfile.ZipFile(self.path) as archive:
            info = archive.getinfo('README.txt')
        raw = bytearray(self.path.read_bytes())
        name_size, extra_size = struct.unpack_from('<HH', raw, info.header_offset + 26)
        raw[info.header_offset + 30 + name_size + extra_size] ^= 1
        self.path.write_bytes(raw)
        self.sidecar()
        self.check(phrase='CRC')

    def test_local_headers_and_encryption(self):
        for offset, replacement in ((6, b'\x01\x00'), (8, b'\x08\x00'),
                                    (14, b'\x00\x00\x00\x00'), (30, b'X')):
            with self.subTest(offset=offset):
                self.write()
                raw = bytearray(self.path.read_bytes())
                raw[offset:offset + len(replacement)] = replacement
                self.path.write_bytes(raw)
                self.sidecar()
                self.check(phrase='local/central')
        self.write()
        raw = bytearray(self.path.read_bytes())
        central = raw.index(b'PK\x01\x02')
        struct.pack_into('<H', raw, central + 8, 1)
        struct.pack_into('<H', raw, 6, 1)
        self.path.write_bytes(raw)
        self.sidecar()
        self.check(phrase='encrypted')

    def test_malformed_and_missing_archives(self):
        self.check()
        self.path.write_bytes(b'not a ZIP')
        self.sidecar()
        self.check()
        self.write()
        self.path.write_bytes(self.path.read_bytes()[:-22])
        self.sidecar()
        self.check()

    def test_required_sidecar_format_and_digest(self):
        self.write()
        sidecar = Path(str(self.path) + '.sha256')
        for raw in (b'', (hashed(self.path).lower() + '  fixture.zip\n').encode(),
                    (hashed(self.path) + '  foreign.zip\n').encode(),
                    (hashed(self.path) + ' fixture.zip\n').encode(),
                    (hashed(self.path) + '  fixture.zip').encode(),
                    ('F' * 64 + '  fixture.zip\n').encode()):
            with self.subTest(raw=raw):
                sidecar.write_bytes(raw)
                self.check()
        sidecar.unlink()
        self.check()

    def test_windows_path_handle_ctime_difference(self):
        self.write()
        original = Path.stat
        def path_stat(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            return changed_stat(info, st_ctime_ns=1) if path == self.path else info
        with patch.object(Path, 'stat', path_stat):
            self.check('PASS')

    def test_path_handle_and_content_drift_rejected(self):
        self.write()
        original_path, original_handle = Path.stat, v.os.fstat
        for field in ('st_ctime_ns', 'st_ino', 'st_mtime_ns', 'st_size'):
            with self.subTest(path_field=field):
                calls = 0
                def path_stat(path, *args, **kwargs):
                    nonlocal calls
                    info = original_path(path, *args, **kwargs)
                    if path == self.path:
                        calls += 1
                        if calls > 1:
                            return changed_stat(info, **{field: getattr(info, field) + 1})
                    return info
                with patch.object(Path, 'stat', path_stat):
                    self.check(phrase='archive changed')
        calls = 0
        def handle_stat(fd):
            nonlocal calls
            calls += 1
            info = original_handle(fd)
            return changed_stat(info, st_ctime_ns=info.st_ctime_ns + 1) if calls > 1 else info
        with patch.object(v.os, 'fstat', handle_stat):
            self.check(phrase='archive changed')
        real_stream_sha = v._stream_sha
        calls = 0
        def stream_sha(stream):
            nonlocal calls
            result = real_stream_sha(stream)
            if getattr(stream, 'name', None) == str(self.path):
                calls += 1
                if calls == 2:
                    return 'F' * 64, result[1]
            return result
        with patch.object(v, '_stream_sha', stream_sha):
            self.check(phrase='archive changed')

    def test_historical_paths_not_accessed_no_extraction(self):
        self.write()
        original_open, original_stat = Path.open, Path.stat
        def guarded_open(path, *args, **kwargs):
            self.assertNotIn('NEVER-ACCESS', str(path))
            return original_open(path, *args, **kwargs)
        def guarded_stat(path, *args, **kwargs):
            self.assertNotIn('NEVER-ACCESS', str(path))
            return original_stat(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded_open), patch.object(Path, 'stat', guarded_stat), \
             patch.object(zipfile.ZipFile, 'extract', side_effect=AssertionError('no extraction')), \
             patch.object(zipfile.ZipFile, 'extractall', side_effect=AssertionError('no extraction')):
            report = self.check('PASS')
        self.assertIs(report['Extracted'], False)
        self.assertIs(report['ArchivedCodeExecuted'], False)

    def test_cli_statuses_explicit_sidecar_and_stdout_failure(self):
        self.write()
        sidecar = Path(str(self.path) + '.sha256')
        alternate = self.path.with_name('independent.sha256')
        sidecar.rename(alternate)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(v.main([str(self.path), '--sha256', str(alternate)]), 0)
        self.assertEqual(json.loads(output.getvalue())['Status'], 'PASS')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(v.main([str(self.path)]), 2)
        self.assertEqual(json.loads(output.getvalue())['Status'], 'FAIL')
        with patch('builtins.print', side_effect=OSError('controlled stdout failure')):
            self.assertEqual(v.main([str(self.path), '--sha256', str(alternate)]), 2)


def main(argv=None):
    global v
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    sources = (Path(__file__).absolute(), SUBJECT.absolute())
    before = {str(path): hashed(path) for path in sources}
    if before[str(SUBJECT.absolute())] != PIN:
        raise ValueError('verifier source pin differs')
    spec = importlib.util.spec_from_file_location('checkpoint_archive_subject', SUBJECT)
    v = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v)
    actual = tuple(unittest.defaultTestLoader.getTestCaseNames(ArchiveTests))
    if set(actual) != set(METHODS) or len(actual) != len(METHODS):
        raise ValueError('exact test catalog differs')
    suite = unittest.TestSuite(ArchiveTests(name) for name in METHODS)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    after = {str(path): hashed(path) for path in sources}
    complete = (result.wasSuccessful() and result.testsRun == len(METHODS) == 22
                and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses and before == after)
    report = dict(Status='PASS' if complete else 'FAIL', ExpectedTests=22, TestsRun=result.testsRun,
                  Failures=len(result.failures), Errors=len(result.errors), Skips=len(result.skipped),
                  Methods=list(METHODS), FailureDetails=[dict(Test=str(test), Traceback=trace)
                      for test, trace in result.failures + result.errors],
                  SourceHashes=before, ClosingSourceHashes=after, SourceDrift=before != after,
                  ClosingBytesVerified=2, Fixtures='Small synthetic ZIPs only; no historical evidence read',
                  HistoricalFixturesRead=0, Admission=False, Qualification=False)
    receipt = args.output_dir / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print(json.dumps(dict(Status=report['Status'], Receipt=str(receipt), Sha256=hashed(receipt))))
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
