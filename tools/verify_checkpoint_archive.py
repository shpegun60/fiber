"""Offline integrity verifier for fiber-checkpoint-archive-v1 ZIP files.

Reads only the supplied archive and SHA256 sidecar. Historical provenance
paths are opaque metadata: no source lookup, extraction or archived-code
execution occurs. PASS describes the declared archive, not checkpoint
qualification, original source availability or provenance authenticity.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import zipfile


SCHEMA = 'fiber-checkpoint-archive-v1'
PROVENANCE_SCHEMA = 'fiber-checkpoint-provenance-v1'
REPORT_SCHEMA = 'fiber-checkpoint-archive-verification-v1'
REQUIRED = frozenset(('MANIFEST.json', 'checkpoint.json', 'provenance.json',
                      'README.txt', 'verify_checkpoint_archive.py'))
OPTIONAL = frozenset(('missing.json', 'commands.json', 'toolchain.json',
                      'archive_checkpoint.py', 'checkpoint-commit.txt', 'source-d005a36.tar'))
CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
HASH = re.compile(r'[0-9A-F]{64}\Z')
PAYLOAD = re.compile(r'payload/([0-9A-F]{64})\Z')
RECORD_FIELDS = frozenset(('OriginalPath', 'ExpectedSha256', 'Status', 'Payload',
                           'ActualSourcePath', 'ActualSha256', 'Roles'))
OPTIONAL_RECORD_FIELDS = frozenset(('HistoricalHash', 'OriginalObservedSha256', 'AlternateDisclosure'))


class InvalidArchive(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise InvalidArchive(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def _digest(value, label):
    need(type(value) is str and HASH.fullmatch(value) is not None, label + ': uppercase SHA256 required')
    return value


def _text(value, label):
    need(type(value) is str and bool(value)
         and not any(ord(char) < 32 or ord(char) == 127 for char in value), label + ': nonempty control-free text required')
    return value


def _keys(value, fields, label):
    need(type(value) is dict and set(value) == set(fields), label + ': exact fields required')


def _pairs(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'duplicate JSON key: ' + key)
        value[key] = item
    return value


def _constant(value):
    raise InvalidArchive('nonfinite JSON number: ' + value)


def _float(value):
    result = float(value)
    need(math.isfinite(result), 'overflow/nonfinite JSON number: ' + value)
    return result


def _json(raw, label):
    need(len(raw) <= MAX_JSON_BYTES, label + ': JSON exceeds 64 MiB metadata limit')
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidArchive(label + ': ' + str(error)) from error


def _name(value):
    _text(value, 'ZIP member name')
    need('\\' not in value and ':' not in value and not value.startswith('/'),
         'absolute, drive, alternate-stream or backslash ZIP member: ' + value)
    parts = value.split('/')
    need(all(part and part not in ('.', '..') and part == part.rstrip(' .') for part in parts),
         'noncanonical/traversal ZIP member: ' + value)
    return value


def _stamp(info):
    # Windows path stat and handle fstat can expose different ctime semantics.
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns)


def _stream_sha(stream):
    digest, size = hashlib.sha256(), 0
    while True:
        raw = stream.read(CHUNK_BYTES)
        if not raw:
            return digest.hexdigest().upper(), size
        digest.update(raw)
        size += len(raw)


def _local_header(stream, info):
    stream.seek(info.header_offset)
    raw = stream.read(30)
    need(len(raw) == 30, 'truncated local ZIP header: ' + info.filename)
    signature, version, flags, compression, time, date, crc, compressed, size, name_size, extra_size = struct.unpack(
        '<4s5H3I2H', raw)
    need(signature == b'PK\x03\x04', 'invalid local ZIP header: ' + info.filename)
    need(flags == info.flag_bits and compression == info.compress_type,
         'local/central ZIP flags or compression differ: ' + info.filename)
    need(not flags & ((1 << 0) | (1 << 6) | (1 << 13)), 'encrypted ZIP member: ' + info.filename)
    local_name = stream.read(name_size).decode('utf-8' if flags & 0x800 else 'cp437')
    need(local_name == info.filename, 'local/central ZIP names differ: ' + info.filename)
    if not flags & 8:
        need(crc == info.CRC, 'local/central CRC differs: ' + info.filename)
        need(size in (info.file_size, 0xFFFFFFFF) and compressed in (info.compress_size, 0xFFFFFFFF),
             'local/central ZIP sizes differ: ' + info.filename)


def _members(archive, stream):
    rows, folded = {}, {}
    for info in archive.infolist():
        name = _name(info.orig_filename)
        need(info.filename == name, 'truncated/NUL ZIP member name')
        need(name not in rows, 'duplicate ZIP member: ' + name)
        alias = name.casefold()
        need(alias not in folded, 'case-alias ZIP members: ' + folded.get(alias, '') + ' / ' + name)
        folded[alias] = name
        need(not info.is_dir(), 'directory ZIP entries are forbidden: ' + name)
        need(not info.external_attr & 0x10, 'DOS directory ZIP member: ' + name)
        mode = (info.external_attr >> 16) & 0xFFFF
        need(stat.S_IFMT(mode) in (0, stat.S_IFREG), 'symlink/directory/nonregular ZIP member: ' + name)
        need(not info.flag_bits & ((1 << 0) | (1 << 6) | (1 << 13)), 'encrypted ZIP member: ' + name)
        need(name in REQUIRED or name in OPTIONAL or PAYLOAD.fullmatch(name) is not None,
             'unexpected ZIP member namespace: ' + name)
        _local_header(stream, info)
        rows[name] = info
    need(REQUIRED <= set(rows), 'missing required ZIP members: ' + ', '.join(sorted(REQUIRED - set(rows))))
    return rows


def _read_json_member(archive, info):
    need(info.file_size <= MAX_JSON_BYTES, info.filename + ': JSON exceeds 64 MiB metadata limit')
    return _json(archive.read(info), info.filename)


def _manifest(archive, members):
    value = _read_json_member(archive, members['MANIFEST.json'])
    _keys(value, ('Schema', 'Files'), 'MANIFEST.json')
    need(value['Schema'] == SCHEMA and type(value['Schema']) is str, 'unsupported manifest Schema')
    need(type(value['Files']) is list, 'manifest Files must be a list')
    expected, folded = {}, set()
    for row in value['Files']:
        _keys(row, ('Path', 'Bytes', 'Sha256'), 'manifest file row')
        name = _name(row['Path'])
        need(name != 'MANIFEST.json', 'manifest self-entry is forbidden')
        need(name not in expected and name.casefold() not in folded, 'duplicate/case-alias manifest Path: ' + name)
        need(type(row['Bytes']) is int and row['Bytes'] >= 0, 'manifest Bytes must be a nonnegative integer: ' + name)
        _digest(row['Sha256'], 'manifest file/' + name)
        expected[name] = row
        folded.add(name.casefold())
    need(set(expected) == set(members) - {'MANIFEST.json'},
         'exact manifest/ZIP membership differs; missing=' + repr(sorted(set(expected) - set(members)))
         + '; unlisted=' + repr(sorted(set(members) - {'MANIFEST.json'} - set(expected))))
    return expected


def _provenance(value, expected):
    _keys(value, ('Schema', 'Records'), 'provenance.json')
    need(type(value['Schema']) is str and value['Schema'] == PROVENANCE_SCHEMA, 'unsupported provenance Schema')
    need(type(value['Records']) is list and value['Records'], 'provenance Records must be a nonempty list')
    counts = dict(Records=0, Captured=0, Alternate=0, Missing=0, Mismatch=0)
    unresolved, alternates, seen, referenced = [], [], set(), set()
    for row in value['Records']:
        need(type(row) is dict and RECORD_FIELDS <= set(row)
             and set(row) <= RECORD_FIELDS | OPTIONAL_RECORD_FIELDS,
             'provenance record: required fields plus declared optional fields only')
        if 'HistoricalHash' in row:
            need(type(row['HistoricalHash']) is bool, 'HistoricalHash must be a boolean')
        if 'OriginalObservedSha256' in row:
            _digest(row['OriginalObservedSha256'], 'OriginalObservedSha256')
        if 'AlternateDisclosure' in row:
            _text(row['AlternateDisclosure'], 'AlternateDisclosure')
        original = _text(row['OriginalPath'], 'OriginalPath')
        digest = _digest(row['ExpectedSha256'], 'ExpectedSha256')
        identity = original, digest
        need(identity not in seen, 'duplicate provenance path/hash expectation: ' + original)
        seen.add(identity)
        status = row['Status']
        need(type(status) is str and status in ('captured', 'alternate', 'missing', 'mismatch'), 'unknown provenance Status')
        need(type(row['Roles']) is list, 'provenance Roles must be a list')
        for role in row['Roles']:
            _text(role, 'provenance role')
        if row['ActualSourcePath'] is not None:
            _text(row['ActualSourcePath'], 'ActualSourcePath')
        if row['ActualSha256'] is not None:
            _digest(row['ActualSha256'], 'ActualSha256')
        payload = row['Payload']
        if payload is not None:
            _name(payload)
            match = PAYLOAD.fullmatch(payload)
            need(match is not None and payload in expected, 'provenance Payload absent from manifest: ' + str(payload))
            need(expected[payload]['Sha256'] == match.group(1), 'content-addressed payload/manifest hash differs')
            if row['ActualSha256'] is not None:
                need(match.group(1) == row['ActualSha256'], 'Payload and ActualSha256 differ')
            referenced.add(payload)
        if status in ('captured', 'alternate'):
            need(payload == 'payload/' + digest, 'resolved Payload must match ExpectedSha256: ' + original)
            need(row['ActualSha256'] == digest and type(row['ActualSourcePath']) is str,
                 'resolved record requires matching ActualSha256 and declared ActualSourcePath')
        if status in ('missing', 'mismatch'):
            unresolved.append(dict(row))
        if status == 'alternate':
            alternates.append(dict(row))
        counts['Records'] += 1
        counts[status.capitalize()] += 1
    return counts, unresolved, alternates, referenced


def verify_archive(archive_path, sha256_path=None):
    """Return PASS, INCOMPLETE or FAIL; never look up provenance source paths."""
    archive_path = Path(archive_path)
    sidecar = Path(sha256_path) if sha256_path is not None else Path(str(archive_path) + '.sha256')
    report = dict(Schema=REPORT_SCHEMA, Status='FAIL', Complete=False,
        Archive=str(archive_path.absolute()), Sidecar=str(sidecar.absolute()), Errors=[], Counts={},
        UnresolvedRecords=[], AlternateRecords=[], UnreferencedPayloads=[],
        CheckpointMetadataJSONOnly=True, CheckpointCountsTrusted=False,
        HistoricalPathsAccessed=False, Extracted=False, ArchivedCodeExecuted=False,
        Admission=False, Qualification=False)
    try:
        sidecar_raw = sidecar.read_bytes()
        match = re.fullmatch(r'([0-9A-F]{64})  ([^\r\n]+)\n', sidecar_raw.decode('utf-8'))
        need(match is not None and match.group(2) == archive_path.name,
             'SHA256 sidecar must be UPPER64, two spaces, exact archive basename and LF')
        wanted = match.group(1)
        report.update(ExpectedArchiveSha256=wanted, SidecarSha256=sha(sidecar_raw))
        path_initial = archive_path.stat()
        with archive_path.open('rb') as stream:
            initial = os.fstat(stream.fileno())
            need(_stamp(path_initial) == _stamp(initial), 'archive identity changed while opening')
            actual, archive_size = _stream_sha(stream)
            report.update(ArchiveSha256=actual, ArchiveBytes=archive_size)
            need(actual == wanted, 'archive SHA256 does not match required sidecar')
            stream.seek(0)
            with zipfile.ZipFile(stream, 'r') as archive:
                members = _members(archive, stream)
                expected = _manifest(archive, members)
                verified, uncompressed = 0, 0
                for name, info in members.items():
                    with archive.open(info, 'r') as member:
                        digest, size = _stream_sha(member)
                    need(size == info.file_size, 'ZIP member size differs: ' + name)
                    if name != 'MANIFEST.json':
                        need(size == expected[name]['Bytes'] and digest == expected[name]['Sha256'],
                             'manifest size/SHA256 differs: ' + name)
                    payload = PAYLOAD.fullmatch(name)
                    if payload is not None:
                        need(digest == payload.group(1), 'payload filename does not match actual bytes: ' + name)
                    verified += 1
                    uncompressed += size
                checkpoint = _read_json_member(archive, members['checkpoint.json'])
                need(type(checkpoint) is dict, 'checkpoint.json must be a JSON object; its metadata is not replayed')
                counts, unresolved, alternates, referenced = _provenance(
                    _read_json_member(archive, members['provenance.json']), expected)
                payloads = {name for name in members if PAYLOAD.fullmatch(name)}
                counts.update(ZIPFiles=len(members), ManifestFiles=len(expected), CRCVerifiedFiles=verified,
                              SHA256VerifiedFiles=len(expected), PayloadFiles=len(payloads),
                              UncompressedBytes=uncompressed, OptionalSourceTar=int('source-d005a36.tar' in members))
                report.update(Counts=counts, UnresolvedRecords=unresolved, AlternateRecords=alternates,
                              UnreferencedPayloads=sorted(payloads - referenced))
            stream.seek(0)
            closing_sha, closing_size = _stream_sha(stream)
            handle_final = os.fstat(stream.fileno())
            path_final = archive_path.stat()
            need((closing_sha, closing_size) == (actual, archive_size)
                 and _stamp(handle_final) == _stamp(initial) == _stamp(path_initial) == _stamp(path_final)
                 and initial.st_ctime_ns == handle_final.st_ctime_ns
                 and path_initial.st_ctime_ns == path_final.st_ctime_ns,
                 'archive changed during verification')
        need(sidecar.read_bytes() == sidecar_raw, 'SHA256 sidecar changed during verification')
        report.update(Status='INCOMPLETE' if report['UnresolvedRecords'] else 'PASS',
                      Complete=not report['UnresolvedRecords'])
    except Exception as error:
        report['Errors'].append(type(error).__name__ + ': ' + str(error))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('zip', type=Path)
    parser.add_argument('--sha256', type=Path)
    args = parser.parse_args(argv)
    report = verify_archive(args.zip, args.sha256)
    try:
        print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False), flush=True)
    except (OSError, ValueError):
        return 2
    return 0 if report['Status'] == 'PASS' else 1 if report['Status'] == 'INCOMPLETE' else 2


if __name__ == '__main__':
    raise SystemExit(main())
