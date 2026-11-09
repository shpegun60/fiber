"""Archive existing d005a36 evidence; never run a compiler or qualification.

Payloads are content addressed. Historical receipts remain byte-for-byte intact;
the provenance index is a new, explicitly archive-time description of copies.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from datetime import datetime, timezone
import zipfile


CHECKPOINT = 'd005a3604248b34e577417cda0acfb83ecb47ff8'
PROTECTED = ('cm33f_secure_transfer_reference', 'm55_secure_closed_parity')
HEX = re.compile(r'[0-9A-F]{64}\Z')
VERSION_BYTES = (
    ('C8FCAFEA64559054BBFA87917182598892F81B41706B003C5A93FA7542355908', 0xDAE49, '14.3.1 20250623'),
    ('C8FCAFEA64559054BBFA87917182598892F81B41706B003C5A93FA7542355908', 0xDAEC0,
     '(GNU Tools for STM32 14.3.rel1.20251027-0700) '),
    ('DC7E0A6647954EA4DFA259A60DEAF3EEAAD43CB8506893BE01CE75E19731A198', 0x1719D18, '14.3.1 20250623'),
    ('FEEC2C213BD8BCC8ACE26651B00FF196D5900AAB609CF0945CAD86E104BE9677', 0x107520,
     '(GNU Tools for STM32 14.3.rel1.20251027-0700) 2.44.0.20250616'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def read_stable(path):
    path = Path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f'not a regular file: {path}')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read()
        closed = os.fstat(stream.fileno())
    after = path.stat()
    # Windows path stat and handle fstat expose different ctime semantics.
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
    identities = [tuple(getattr(s, f) for f in fields) for s in (before, opened, closed, after)]
    if (len(set(identities)) != 1 or len(data) != before.st_size
            or before.st_ctime_ns != after.st_ctime_ns
            or opened.st_ctime_ns != closed.st_ctime_ns):
        raise ValueError(f'changed during archival read: {path}')
    return data


class Inventory:
    def __init__(self):
        self.entries = {}
        self.roots = []

    def add(self, path, sha, role, historical=True):
        path = str(Path(path).absolute())
        if any(token in path.lower() for token in PROTECTED):
            raise ValueError(f'protected unrelated WIP in input: {path}')
        sha = sha.upper()
        if not HEX.fullmatch(sha):
            raise ValueError(f'invalid expected digest: {path}')
        key = (os.path.normcase(path), sha)
        item = self.entries.setdefault(key, {
            'OriginalPath': path, 'ExpectedSha256': sha, 'Roles': [],
            'HistoricalHash': historical,
        })
        if role not in item['Roles']:
            item['Roles'].append(role)
        item['HistoricalHash'] |= historical
        return item

    def seed(self, path, sha, role):
        self.add(path, sha, role)
        try:
            data = read_stable(path)
        except FileNotFoundError as error:
            raise ValueError(f'missing discovery seed; dependency closure unknown: {path}') from error
        if digest(data) != sha:
            raise ValueError(f'mismatched discovery seed; dependency closure unknown: {path}')
        return json.loads(data)

    def bundle(self, root, receipt_sha, manifest_sha, role):
        root = Path(root)
        report = self.seed(root / 'results.json', receipt_sha, role + ':receipt')
        manifest = self.seed(root / 'artifacts.json', manifest_sha, role + ':manifest')
        self.roots.append({'Path': str(root), 'Role': role, 'ManifestSha256': manifest_sha})
        if manifest is not None:
            for name, sha in manifest['Artifacts'].items():
                relative = PurePosixPath(name)
                if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name:
                    raise ValueError(f'unsafe historical member: {name}')
                self.add(root.joinpath(*relative.parts), sha, role + ':artifact')
        return report

    def test_receipt(self, path, sha, role):
        report = self.seed(path, sha, role + ':receipt')
        if report is not None:
            for field in ('SourceHashes', 'FixtureHashes'):
                for original, value in report.get(field, {}).items():
                    sha = value['Sha256'] if isinstance(value, dict) else value
                    self.add(original, sha, role + ':' + field)
        return report

    def supplementary_tree(self, root, role):
        # These bytes are observed now, not retroactively historically attested.
        root = Path(root)
        if root.is_dir():
            for path in sorted(root.rglob('*')):
                if path.is_symlink():
                    raise ValueError(f'link in supplementary tree: {path}')
                if path.is_file():
                    self.add(path, digest(read_stable(path)), role, historical=False)


def collect(temp):
    inv = Inventory()
    main = inv.bundle('C:/fzoscell-20261109-e1',
        'A81DC41D4C80832120150B166AB4CA8D442D8EDDBEAA2CB382F0B55BDD6EF9BF',
        '4B7720F1FD6D76B2EA5CA67FAD1D1CB70F03699BC0749383DD0E5F81194BA219', 'qualified-cell')
    if main is not None:
        for path, sha in main['InputHashes'].items():
            inv.add(path, sha, 'qualified-cell:InputHashes')
        dependencies = [('inventory', main['CurrentInventory']), ('batch', main['Batch']),
                        ('normal', main['OriginalCensusHandoff'])]
        dependencies.extend((p['Side'].lower(), p) for p in main['ProducerBindings'])
        for role, binding in dependencies:
            report = inv.bundle(binding['Build'], binding['ReceiptSha256'], binding['ArtifactsSha256'], role)
            if role in ('native', 'reference') and report is not None:
                seed = report['SeedAuthority']
                inv.bundle(seed['Build'], seed['ReceiptSha256'], seed['ArtifactsSha256'], role + '-seed')
    inv.bundle('C:/fzosfinalcontrols-census-20261109-e3',
        'A81B23B024B5DD770B061BC6BD9BAF21B3922EADA6452CA49DA45FBF023E9621',
        'E3EDA80F1976C653D47C3D5CF89F6FDAB563C49886F0753191605F4E1F16DA15', 'fresh-nine-baseline')
    tests = [
        ('os-cell-qualifier-parent-20261109-e1/results.json', 'CCA3EB1AB5D010CCE452E9562FF76907B74E23B04022239A796C521A59639DD4', 'parent-final33'),
        ('os-cell-qualifier-owner-20261109-e1/results.json', '959E05B20C71DA569F0CDB99CE84A1EC79FE29FD824EA0B2F58447ACA4E03E98', 'owner-historical33'),
        ('os-cell-qualifier-focused-owner-20261109-e1/results.json', '6300D5E77B34F16FD77D26E643818721ECD37A99C8254CACF20A6E617DD4A0E0', 'focused-final2'),
        ('cm3-cell-qualifier-owner-smoke-20261109-e1-h6mtq825/report.json', 'CCE8F9367BF62197A2115BBD75D424A42564E20D227CD4974321F7F2F6F98E51', 'physical-owner-smoke5'),
    ]
    for relative, sha, role in tests:
        path = temp / relative
        inv.test_receipt(path, sha, role)
        inv.supplementary_tree(path.parent, role + ':archive-time-supplement')
    for name in ('os-cell-qualifier-raw-audit-20261109-e1', 'os-cell-qualifier-raw-parent-20261109-e1'):
        inv.seed(temp / name / 'report.json',
            '78CDAE52295FCCD4E6F2C3EAA58BCA8E82D5F7775639F3EA227D21933F00FEA7', name)
        inv.supplementary_tree(temp / name, name + ':archive-time-supplement')
    scripts = {
        'test_cell_qualifier.D76D552C-owner-e1-20261109.py': 'D76D552CB57AB4D62C387F8E93D3CF53EF64E7B4904CDE63B825E8C20809FB27',
        'cm3-os-cell-qualifier-focused-20261109.py': '0D9C915BD58A66B76A9773A7AFBB776FA5D219C290AFCD4986E7D5DFEDA6ED5A',
        'cm3-cell-qualifier-owner-smoke-20261109.py': '8783FFA9CA4AE36BD7AEF22767A30B6CCA12EC52F0C7ED0DD1F0E2A00328FD27',
        'cm3-finalcontrols-raw-accounting-20261109-e4.py': '20120E05A4229623C6FCABDA3ED21C3EBF227056E1F2316CA8731624B97D367B',
    }
    for name, sha in scripts.items():
        inv.add(temp / name, sha, 'historical-script')
    return inv, main


README = '''Software checkpoint d005a36 - archival-only package

This ZIP copies existing evidence. It does not rerun qualification, compile code,
program hardware, or establish a new CI/board/global-freeze claim. Historical
receipts and command journals are raw payloads, not rewritten reports.

Run the accompanying verify_checkpoint_archive.py with Python 3.10+:
  python -I -S -B verify_checkpoint_archive.py software-checkpoint-d005a36.zip
The adjacent .zip.sha256 sidecar binds the whole ZIP. MANIFEST.json binds every
member except itself. The offline verifier reads only ZIP + sidecar; it never
opens historical paths, executes archived files, compiles, or extracts anything.
The hash/CRC checks prove preservation, not truth of historical test assertions.
Keep the sidecar digest separately if authenticity against deliberate replacement
is needed; an unsigned ZIP and co-located hash are not a digital signature.

Use provenance.json to map original paths to payload/<SHA256>. Identical bytes
are deduplicated. An alternate means exact expected bytes were available at
another documented path; it does NOT recreate the original physical identity.
The D76 owner test is a previously reconstructed, byte-verified historical cut,
not the later DEC6 file at its original path. Missing/mismatched files are listed
explicitly; none are synthesized. archive-time supplements have no historical
hash attestation. Raw physical tuples in receipts are historical observations,
not identities of the copied files. Original absolute paths are provenance text,
never offline dependencies.

source-d005a36.tar is generated now from the checkpoint Git commit. It excludes
untracked WIP. checkpoint.json separates archive-time Git status from the unknown
standalone qualification-time status. Tool versions absent from historical logs
are not invented by running tools now. tools/command information is indexed from
existing receipts, whose raw bytes remain authoritative. The captured GCC layout
identifies 14.3.1, not a new independently captured --version invocation.

No TEMP deletion is performed by the builder or verifier. Do not clear all TEMP.
Only explicitly inventoried, fully archived, unchanged owned directories are
cleanup candidates after a verified second copy. Shared parser/source trees stay.
'''


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def build(repo, output):
    repo, output = Path(repo).resolve(), Path(output).absolute()
    if output.exists() or Path(str(output) + '.sha256').exists():
        raise ValueError('output or sidecar already exists; use a fresh destination')
    if git(repo, 'rev-parse', CHECKPOINT).decode().strip() != CHECKPOINT:
        raise ValueError('checkpoint is unavailable')
    inv, _ = collect(Path(os.environ['TEMP']))
    output.parent.mkdir(parents=True, exist_ok=True)
    unresolved = []
    captured = {}
    members = []
    records = []
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        def put(name, data):
            archive.writestr(name, data)
            members.append({'Path': name, 'Bytes': len(data), 'Sha256': digest(data)})

        for index, item in enumerate(inv.entries.values(), 1):
            path = Path(item['OriginalPath'])
            record = dict(item, Status='missing', Payload=None, ActualSourcePath=None, ActualSha256=None)
            try:
                data = read_stable(path)
                actual = digest(data)
                record['OriginalObservedSha256'] = actual
                if actual == item['ExpectedSha256']:
                    member = 'payload/' + actual
                    if actual not in captured:
                        put(member, data)
                        captured[actual] = str(path)
                    record.update(Status='captured', Payload=member, ActualSourcePath=str(path), ActualSha256=actual)
                else:
                    record['Status'] = 'mismatch'
                    unresolved.append(record)
            except FileNotFoundError:
                unresolved.append(record)
            records.append(record)
            if index % 1000 == 0:
                print(f'Archived input {index}/{len(inv.entries)}', flush=True)
        for record in unresolved:
            sha = record['ExpectedSha256']
            if sha in captured:
                record.update(Status='alternate', Payload='payload/' + sha,
                              ActualSourcePath=captured[sha], ActualSha256=sha)
                record['AlternateDisclosure'] = 'Expected bytes copied from another path; original physical identity not restored.'
                if sha.startswith('D76D552C'):
                    record['AlternateDisclosure'] += ' Historical source reconstructed and byte-verified before this archival operation.'

        status = git(repo, 'status', '--porcelain=v1', '--untracked-files=normal').decode('utf-8')
        identity = {
            'CheckpointCommit': CHECKPOINT, 'CheckpointBranch': 'v2',
            'CheckpointCommitObjectSha256': digest(git(repo, 'cat-file', 'commit', CHECKPOINT)),
            'ArchiveTimeUtc': datetime.now(timezone.utc).isoformat(),
            'ArchiveTimeHead': git(repo, 'rev-parse', 'HEAD').decode().strip(),
            'ArchiveTimeBranch': git(repo, 'branch', '--show-current').decode().strip(),
            'ArchiveTimeGitStatus': status,
            'QualificationTimeGitStatus': 'NOT_SEPARATELY_RECORDED; no clean-checkout claim',
            'QualificationSourceCheckpoint': '16371b6a0f8cbff2aaf87dd7c6eb084962df9961',
            'Claim': 'Preservation of existing bounded software evidence, not requalification',
            'HistoricalResultSummary': {'FinalTests': '33/33', 'RawAuditInputs': '7999/7999',
                'Cell': 'CM3/runtime/final/Os-lto/direct', 'Satisfied': 1, 'Required': 2774},
            'SoftwareQualificationRerun': False, 'CompilerExecuted': False,
            'HardwareValidation': False, 'HostedCIValidation': False,
            'Records': len(records), 'UniquePayloads': len(captured),
            'MissingOrMismatched': sum(r['Status'] in ('missing', 'mismatch') for r in records),
            'AlternateCopies': sum(r['Status'] == 'alternate' for r in records),
            'ArchiveHashIsNotSignature': True,
        }
        commands = []
        toolchains = []
        for root in inv.roots:
            role = root['Role']
            expected = next(r for r in records if r['OriginalPath'] == str(Path(root['Path']) / 'results.json') and role + ':receipt' in r['Roles'])
            if expected['Payload']:
                report = json.loads(archive.read(expected['Payload']))
                commands.append({'Role': role, 'ReceiptPayload': expected['Payload'], 'Commands': report.get('Commands', [])})
                toolchains.append({'Role': role, 'ReceiptPayload': expected['Payload'],
                    'CapturedCompiler': report.get('CapturedCompiler'), 'ResolvedWorkers': report.get('ResolvedWorkers'),
                    'LTOPlugin': report.get('LTOPlugin'), 'Interpreter': report.get('Interpreter'),
                    'VersionDisclosure': 'No new --version command; use raw historical journals and captured layout.'})
        put('README.txt', README.encode('ascii'))
        put('checkpoint.json', encoded(identity))
        put('provenance.json', encoded({'Schema': 'fiber-checkpoint-provenance-v1', 'Records': records}))
        put('missing.json', encoded([r for r in records if r['Status'] in ('missing', 'mismatch')]))
        put('commands.json', encoded(commands))
        version_rows = []
        for sha, offset, text in VERSION_BYTES:
            member = 'payload/' + sha
            if sha in captured:
                raw = archive.read(member)
                value = text.encode('ascii')
                if raw[offset:offset + len(value)] != value:
                    raise ValueError('embedded version observation differs from captured binary')
                version_rows.append({'Payload': member, 'Offset': offset, 'ASCII': text,
                                     'Basis': 'Archive-time read of historical hash-bound binary; not tool execution'})
        version_sha = '36564787BB996D34EB3F2150D338D925A103B10F9C8D1E6B5510BDC56B5AEA20'
        if version_sha in captured:
            version_rows.append({'Payload': 'payload/' + version_sha, 'Offset': 0, 'ASCII': '14.3.1\r\n',
                                 'Basis': 'Raw historical seed -dumpfullversion stdout'})
        put('toolchain.json', encoded({'Records': toolchains, 'VersionObservations': version_rows}))
        put('verify_checkpoint_archive.py', read_stable(repo / 'tools/verify_checkpoint_archive.py'))
        put('archive_checkpoint.py', read_stable(Path(__file__)))
        put('checkpoint-commit.txt', git(repo, 'cat-file', 'commit', CHECKPOINT))
        put('source-d005a36.tar', git(repo, 'archive', '--format=tar', CHECKPOINT))
        manifest = {'Schema': 'fiber-checkpoint-archive-v1', 'Files': sorted(members, key=lambda x: x['Path'])}
        archive.writestr('MANIFEST.json', encoded(manifest))
    archive_sha = digest(read_stable(output))
    with Path(str(output) + '.sha256').open('xb') as sidecar:
        sidecar.write((archive_sha + '  ' + output.name + '\n').encode('ascii'))
    print(json.dumps(dict(identity, Archive=str(output), Sha256=archive_sha, Bytes=output.stat().st_size), indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.repo, args.output)


if __name__ == '__main__':
    main()
