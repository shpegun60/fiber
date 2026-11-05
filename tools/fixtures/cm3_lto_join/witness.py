"""Join two independently captured CM3 LTO mechanisms; no tools or targets."""
import argparse
import ast
import ctypes
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
UTILITY = ROOT / 'tools/fixtures/cm3_lto_transport/probe.py'
UTILITY_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
LEDGER = ROOT / 'tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md'
LEDGER_SHA = '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019'
FIXED = {
    'tools/fixtures/classic_final_image/elf.py': '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809',
    'tools/fixtures/cm3_final_roots/reference_witness.py': 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C',
    'tools/fixtures/cm55_tfm_parity/elf.py': '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D',
    'tools/fixtures/cm3_freeze_parity/check.py': 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A',
    'tools/fixtures/cm3_lto_roots/native.py': 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D',
    'tools/fixtures/cm3_lto_roots/witness.py': '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713',
    'tools/fixtures/cm3_lto_roots/mutations.py': '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353',
    'tools/fixtures/cm3_lto_protocol/protocol.py': 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419',
    'tools/fixtures/cm3_lto_protocol/witness.py': '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'tools/fixtures/cm3_reference_lto_roots/reference.py': '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D',
    'tools/fixtures/cm3_reference_lto_roots/witness.py': '3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54',
    'tools/fixtures/cm3_reference_lto_roots/mutations.py': 'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C',
    'tools/fixtures/cm3_reference_lto_protocol/protocol.py': '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798',
    'tools/fixtures/cm3_reference_lto_protocol/witness.py': 'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
    'tools/fixtures/cm3_reference_lto_transport/probe.py': '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3',
    'tools/fixtures/cm3_reference_lto_transport/admission.py': '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC',
}
SIDES = ('Native', 'Reference')
ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly')
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PASS = 'CM3-LTO-JOIN-PASS-NOT-QUALIFIED'


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(value, message):
    if not value:
        raise ValueError('cm3-lto-join-witness: ' + message)


def stable(path):
    return Path(os.path.abspath(os.fspath(path)))


def safe(path):
    value = Path(path)
    protected = {'cm33f_secure_transfer_reference', 'm55_secure_closed_parity',
                 'test_cm33f_secure_transfer_reference.ps1', 'test_m55_secure_closed_parity.ps1'}
    need(not protected.intersection(part.lower() for part in value.parts), 'protected unrelated input')
    return value


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def interpreter_path():
    if os.name != 'nt':
        return Path(sys.executable).resolve(strict=True)
    b = ctypes.create_unicode_buffer(32768)
    api = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    api.argtypes, api.restype = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32), ctypes.c_uint32
    size = api(None, b, len(b))
    need(0 < size < len(b), 'actual interpreter module path')
    return Path(b.value).resolve(strict=True)


class Witness:
    def __init__(self, args):
        utility_bytes = UTILITY.read_bytes()
        need(sha(utility_bytes) == UTILITY_SHA, 'fixed self-trusted closure utilities')
        self.api = load('cm3_lto_join_closure_utilities', UTILITY, utility_bytes)
        self.watch, self.buffers, self.groups = self.api.Closure(), {}, {}
        for side in SIDES:
            prefix = side.lower()
            root = self.api.checked_path(safe(getattr(args, prefix + '_build')))
            receipt_sha = self.api.digest_text(getattr(args, prefix + '_receipt_sha256'))
            manifest_sha = self.api.digest_text(getattr(args, prefix + '_artifacts_sha256'))
            r = self.watch.structured(root / 'results.json', receipt_sha)
            artifacts = self.watch.structured(root / 'artifacts.json', manifest_sha)['Artifacts']
            need(type(artifacts) is dict and artifacts.get('results.json') == receipt_sha, 'caller-bound manifest/receipt')
            self.watch.tree(root, dict(artifacts, **{'artifacts.json': manifest_sha}))
            self._require_record(side, r)
            for path, expected in r['InputHashes'].items():
                self.watch.read(safe(path), expected)
            need(type(r['ClosingFilesVerified']) is int and r['ClosingFilesVerified'] == len(r['InputHashes']),
                 'complete prior closing-file count')
            for row in r['CapturedSourceBuffers']:
                original, captured = self.api.regular(safe(row['Original'])), self.api.regular(safe(row['Captured']))
                need(captured.is_relative_to(root) and artifacts[captured.relative_to(root).as_posix()] == row['Sha256'],
                     'captured source/manifest binding')
                data = self.watch.read(captured, row['Sha256'])
                need(self.watch.read(original, row['Sha256']) == data, 'original/captured source identity')
                need(original.suffix == '.py' and (original not in self.buffers or self.buffers[original] == data),
                     'Python source role or shared-buffer conflict')
                self.buffers[original] = data
            capture_root = self.api.checked_path(safe(r['CaptureBuild']))
            capture = self.watch.structured(capture_root / 'results.json', r['CaptureReceiptSha256'])
            self._evidence_tree(capture_root, r['CaptureReceiptSha256'], r['CaptureArtifactsSha256'])
            self.api.same([capture['Status'], capture['Profile'], capture['Mode'], capture['Cohort'], capture['Linkage'],
                           capture['TranslationUnits'], capture['SlimIRObjects'], capture['FinalExecutableLinks'], capture['SavedMachineObjects']],
                          ['PASS', 'CM3', 'O2-lto', self.api.COHORT, 'direct', 9 if side == 'Native' else 4,
                           8 if side == 'Native' else 3, 2, 2], 'fixed actual producer scope')
            if side == 'Reference':
                need(capture['ReferenceCommit'] == PIN, 'pinned reference producer required')
            inventory = self.api.checked_path(safe(capture['SourceInventoryReceipt']))
            seed_root = self.api.checked_path(safe(capture['SeedBuild']))
            self._evidence_tree(seed_root, capture['SeedReceiptSha256'], capture['SeedArtifactsSha256'])
            self._evidence_tree(inventory, r['InputHashes'][str(inventory / 'results.json')],
                                r['InputHashes'][str(inventory / 'artifacts.json')])
            ledger = inventory / 'inputs/FREERTOS_ASM_PARITY.md'
            need(str(ledger) in r['InputHashes'], 'captured master ledger is prior authenticated input')
            ledger_bytes = self.watch.read(ledger, r['InputHashes'][str(ledger)])
            binaries = self._roles(root, artifacts, r, capture_root, capture)
            self.groups[side] = dict(Root=root, Result=r, Capture=capture, CaptureRoot=capture_root,
                ReceiptSha256=receipt_sha, ManifestSha256=manifest_sha, Roles=binaries, Inventory=inventory,
                Artifacts=artifacts, MasterLedger=ledger, MasterLedgerBytes=ledger_bytes,
                Package=Path(capture['SeedBuild']) / 'python/elftools')
        native, reference = (self.groups[side] for side in SIDES)
        need(native['Root'] != reference['Root'] and native['CaptureRoot'] != reference['CaptureRoot']
             and native['Inventory'] == reference['Inventory'] and native['MasterLedgerBytes'] == reference['MasterLedgerBytes'],
             'two independent producer groups and one captured source inventory')
        files = [(side, role, row['Path']) for side, group in self.groups.items() for role, row in group['Roles'].items()]
        need(len(files) == 14 and all(not path.samefile(other) for i, (_, _, path) in enumerate(files)
                                    for _, _, other in files[:i]), 'fourteen distinct physical binary/provider roles')
        need(native['Roles']['Machine']['Bytes'] != reference['Roles']['Machine']['Bytes'], 'distinct actual machine authorities')
        for name, expected in FIXED.items():
            path = ROOT / name
            need(path in self.buffers and sha(self.buffers[path]) == expected, 'fixed admitted helper source cohort: ' + name)
        need(self.buffers[UTILITY] == utility_bytes, 'executed closure helper must match captured source')
        for side, group in self.groups.items():
            self._require_controls(side, group)
        self.policy = self.watch.read(LEDGER, LEDGER_SHA)
        interpreter = self.api.regular(interpreter_path())
        self.watch.read(interpreter)
        self.output = self.api.checked_path(safe(args.output_dir), must_exist=False)
        denied = {ROOT, *(group['Root'] for group in self.groups.values()), *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
             for path in denied), 'fresh output outside all authenticated input roots')
        for path in (Path(__file__).resolve(), HERE / 'join.py'):
            self.buffers[path] = self.watch.read(path)
        self.watch.close()
        self.expected = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Error=None, Scope='CM3_O2_LTO_SIX_BODY_MECHANISM_JOIN_ONLY',
            Profile='CM3', Mode='O2-lto', Cohort=self.api.COHORT, ReferenceCommit=PIN,
            Qualification=False, FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False,
            SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CompleteObjectProof=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0,
            ProducerCompilersReexecuted=False, MutantsReexecuted=False, NativeCommandsExecuted=0,
            Interpreter=dict(ReportedExecutable=sys.executable, ModulePath=str(interpreter), Version=sys.version,
                             Sha256=self.watch.hashes[interpreter]))

    def _evidence_tree(self, root, receipt_sha, manifest_sha):
        manifest = self.watch.structured(root / 'artifacts.json', manifest_sha)['Artifacts']
        need(type(manifest) is dict and manifest.get('results.json') == receipt_sha,
             'nested evidence tree manifest/receipt binding')
        for name in manifest:
            safe(root / name)
        self.watch.tree(root, dict(manifest, **{'artifacts.json': manifest_sha}))

    def _require_record(self, side, r):
        expected_status = 'MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED' if side == 'Native' else 'REFERENCE-MACHINE-ROOT-PASS-NOT-QUALIFIED'
        need(r['Status'] == expected_status and r['Error'] is None
             and r['Scope'] == side.upper() + '_CM3_O2_LTO_MACHINE_AND_CANONICAL_PROTOCOL_COMPOSITION_ONLY', 'exact side composition scope')
        for name in ('InputClosureVerified', 'OutputSealVerified', 'ImmutablePositiveInputsConsumed', 'CanonicalProtocolValidated'):
            need(r.get(name) is True, 'literal complete prior marker: ' + name)
        for name in ('Qualification', 'FinalReferenceParity', 'FullABIProof', 'SourceToMachineSemanticProof',
                     'CompleteObjectProof', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
            need(r.get(name) is False, 'literal bounded prior nonclaim: ' + name)
        need(type(r.get('RequiredCellsSatisfied')) is int and r['RequiredCellsSatisfied'] == 0
             and type(r['NativeCommandsExecuted']) is int and r['NativeCommandsExecuted'] == 0
             and not r['UnexpectedOutputMembers'] and not r['MissingDeclaredOutputMembers'], 'prior scope/closure counters')
        p = r['ProtocolProof']
        canonical_names = (['fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler'] if side == 'Native'
                           else ['prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler'])
        transport_names = ([canonical_names[1], canonical_names[2], canonical_names[0]] if side == 'Native' else canonical_names)
        need(type(r['Roots']) is list and all(type(row) is dict and type(row.get('Name')) is str for row in r['Roots'])
             and [row['Name'] for row in r['Roots']] == transport_names, 'exact unique ordered top-level transport roots')
        need(p['Status'] == ('NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED' if side == 'Native'
                             else 'REFERENCE-CANONICAL-PASS-NOT-PAIRED-QUALIFIED')
             and p['CanonicalProtocolValidated'] is True and type(p['ClosedBodies']) is int and p['ClosedBodies'] == 3
             and len(p['Roots']) == len(p['MatchEvidence']) == len(r['Roots']) == 3
             and all(type(row['TailNops']) is int and row['TailNops'] == 0 for row in p['MatchEvidence']), 'three exact prior protocols')
        need(all(type(row) is dict and type(row.get('Name')) is str for row in p['Roots'])
             and [row['Name'] for row in p['Roots']] == canonical_names
             and [(row['Side'], row['Name']) for row in p['MatchEvidence']] == [(side, name) for name in canonical_names],
             'exact unique ordered prior canonical roots')
        need(len(r['Mutants']) == 16 and len({row['Name'] for row in r['Mutants']}) == 16
             and all(row['Status'] == 'PASS' and row['ImmutableInputBuffersConsumed'] is True
                     and type(row['ClosingFilesVerified']) is int and row['ClosingFilesVerified'] == 5
                     and len(row['Files']) == 5 and row['Edits'] for row in r['Mutants']), 'sixteen prior actual transport controls')
        need(len(r['ProtocolControls']) == 1, 'one prior actual canonical control')
        c = r['ProtocolControls'][0]
        need(c['Status'] == 'PASS' and c['TransportPreservationAccepted'] is True
             and c['ImmutableInputBuffersConsumed'] is True and type(c['ClosingFilesVerified']) is int and c['ClosingFilesVerified'] == 6
             and len(c['Files']) == 6 and c['TwinComparisonExecuted'] is False and c['SourceAuthorityPreserved'] is False,
             'complete prior independent canonical control')

    def _require_controls(self, side, group):
        folder = 'cm3_lto_roots' if side == 'Native' else 'cm3_reference_lto_roots'
        path = ROOT / 'tools/fixtures' / folder / 'mutations.py'
        tree = ast.parse(self.buffers[path], filename=str(path))
        definitions = [node.value for node in tree.body if isinstance(node, ast.Assign)
                       and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'CASES']
        need(len(definitions) == 1, 'one pinned literal mutation catalog')
        catalog = ast.literal_eval(definitions[0])
        need(type(catalog) is tuple and len(catalog) == 16 and all(type(row) is tuple and len(row) == 2
             and all(type(value) is str for value in row) for row in catalog), 'sixteen fixed source catalog entries')
        r = group['Result']
        self.api.same([(row['Name'], row['Expected']) for row in r['Mutants']], list(catalog), 'exact prior pinned case catalog')

        def files(rows, directory, roles):
            need(type(rows) is list and len(rows) == len(roles) and {row['Role'] for row in rows} == set(roles),
                 'exact unique prior private file roles')
            result = {}
            for row in rows:
                path = self.api.regular(safe(row['Path']))
                expected = directory / (row['Role'] + group['Roles'][row['Role']]['Path'].suffix)
                need(path == expected and path.is_relative_to(group['Root'])
                     and group['Artifacts'][path.relative_to(group['Root']).as_posix()] == row['Sha256'],
                     'prior private role/path/hash/manifest binding')
                result[row['Role']] = self.watch.read(path, row['Sha256'])
                if side == 'Reference' and directory.parent.name == 'mutants':
                    identity, physical = row['PhysicalIdentity'], path.stat()
                    need(all(type(identity[key]) is int for key in ('Device', 'FileId', 'Links'))
                         and (identity['Device'], identity['FileId'], identity['Links'])
                         == (physical.st_dev, physical.st_ino, physical.st_nlink), 'prior retained physical private identity')
            need({path for path in directory.iterdir()} == {directory / (role + group['Roles'][role]['Path'].suffix) for role in roles},
                 'exact prior private directory membership')
            return result

        for row, (name, expected) in zip(r['Mutants'], catalog):
            need(row.get('Error') is None and type(row.get('Rejection')) is str
                 and re.search('^REJECT:' + expected + ':', row['Rejection']) is not None,
                 'prior actual control must retain its intended rejection')
            if name in ('coherent-callee-entry', 'coherent-slot-in-bss'):
                need(row.get('ImmutableOriginControlCoherenceChecked') is True, 'prior coherent-origin control marker')
            files(row['Files'], group['Root'] / 'mutants' / name, ROLES[:5])
        c = r['ProtocolControls'][0]
        first = 'fiber_port_start_first_context' if side == 'Native' else 'prvPortStartFirstTask'
        token = 27 if side == 'Native' else 8
        need(c['Name'] == 'coherent-svc-immediate' and c['Expected'] == 'CM3-CLOSED-ROOTS'
             and c.get('Error') is None and c['Rejection'] == 'REJECT:CM3-CLOSED-ROOTS:' + side + '/' + first
             + '/token-' + str(token) + '/complete protocol mismatch', 'exact prior canonical rejection')
        private = files(c['Files'], group['Root'] / 'protocol-mutants/coherent-svc-immediate', (*ROLES[:5], 'MachineDisassembly'))
        edits = c['Edits']
        need(type(edits) is list and len(edits) == 4 and {row['Role'] for row in edits}
             == {'Machine', 'Final', 'Disassembly', 'MachineDisassembly'}, 'four exact prior SVC edits')
        before, after = (bytes.fromhex('46df'), bytes.fromhex('47df')) if side == 'Native' else (bytes.fromhex('00df'), bytes.fromhex('01df'))
        for edit in edits:
            role = edit['Role']
            if role in ('Machine', 'Final'):
                offset = edit['FileOffset']
                need(type(offset) is int and offset >= 0 and edit['Before'] == before.hex() and edit['After'] == after.hex()
                     and group['Roles'][role]['Bytes'][offset:offset + 2] == before and private[role][offset:offset + 2] == after,
                     'prior actual binary SVC edit binds original and private fields')
            else:
                need(edit['BeforeSha256'] == group['Roles'][role]['Sha256'] and edit['AfterSha256'] == sha(private[role])
                     and edit['BeforeSha256'] != edit['AfterSha256'], 'prior actual disassembly edit hashes')

    def _roles(self, root, artifacts, r, capture_root, capture):
        rows = [*r['BinaryInputs'], dict(r['MachineDisassemblyInput'], Role='MachineDisassembly')]
        need(len(rows) == 7 and {row['Role'] for row in rows} == set(ROLES), 'seven exact side input roles')
        emit = capture_root / 'emit-relocs'
        expected_paths = dict(Machine=emit / 'image.elf.ltrans0.ltrans.o', Final=emit / 'image.elf',
            Disassembly=emit / 'image.elf.dis', LinkMap=emit / 'image.map', Startup=Path(capture['Sources'][-1]['Object']),
            Plain=capture_root / 'ordinary/image.elf', MachineDisassembly=emit / 'image.elf.ltrans0.ltrans.o.dis')
        result = {}
        for row in rows:
            original, copied = self.api.regular(safe(row['Original'])), self.api.regular(safe(row['Captured']))
            need(original == expected_paths[row['Role']] and copied.is_relative_to(root)
                 and artifacts[copied.relative_to(root).as_posix()] == row['Sha256'], 'fixed actual binary/provider role')
            data = self.watch.read(original, row['Sha256'])
            need(self.watch.read(copied, row['Sha256']) == data, 'original/copied side binary binding')
            result[row['Role']] = dict(Path=original, Captured=copied, Bytes=data, Sha256=row['Sha256'])
        return result

    def declare(self, path):
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected, 'duplicate declared output')
        self.expected.add(name)

    def _read(self):
        loader_path = ROOT / 'tools/fixtures/cm3_final_roots/reference_witness.py'
        loader = load('cm3_lto_join_immutable_loader', loader_path, self.buffers[loader_path])
        graph = loader.FrozenSources(self.buffers)
        packages = []
        for group in self.groups.values():
            package = group['Package']
            members = {path.relative_to(package).as_posix(): sha(data) for path, data in self.buffers.items()
                       if path.is_relative_to(package)}
            need('__init__.py' in members, 'captured parser package required')
            packages.append((package, members))
        self.api.same(packages[0][1], packages[1][1], 'identical source parser packages on both sides')
        modules = {}
        for path in self.buffers:
            if path.is_relative_to(packages[0][0]):
                parts = list(path.relative_to(packages[0][0].parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'ambiguous parser source')
                modules[name] = path, is_package
        need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules), 'closed fresh parser package')
        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname != 'elftools' and not fullname.startswith('elftools.'):
                    return None
                need(fullname in modules and target is None, 'unknown parser import')
                source, is_package = modules[fullname]
                spec = graph.spec(fullname, source)
                if is_package:
                    spec.submodule_search_locations = [str(source.parent)]
                return spec
        copies, binary_copies = [], []
        snapshots = {stable(path): data for path, data in self.buffers.items()}
        for index, (path, data) in enumerate(sorted(self.buffers.items())):
            target = self.output / 'source-buffers' / ('%04d-' % index + path.name)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
            copies.append(dict(Original=str(path), Captured=str(target), Sha256=sha(data)))
        for side, group in self.groups.items():
            for role, row in group['Roles'].items():
                path = row['Path']
                target = self.output / 'binary-inputs' / (side + '-' + role + path.suffix)
                self.declare(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(row['Bytes'])
                self.watch.read(target, row['Sha256'])
                snapshots[stable(path)] = row['Bytes']
                binary_copies.append(dict(Side=side, Role=role, Original=str(path), Captured=str(target), Sha256=row['Sha256']))
        for name, data in (('MasterLedger.md', self.groups['Native']['MasterLedgerBytes']), ('PolicyLedger.md', self.policy)):
            target = self.output / 'ledgers' / name
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
        def fixed_read(path):
            key = stable(path)
            need(key in snapshots, 'unknown join reader input outside immutable buffers')
            return snapshots[key]
        def fixed_text(path, encoding=None, errors=None, newline=None):
            need(newline is None and encoding in (None, 'utf-8', 'ascii') and errors in (None, 'strict'), 'exact join text decoding')
            return fixed_read(path).decode(encoding or 'utf-8', errors or 'strict')
        old_meta = list(sys.meta_path)
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text), \
                    patch('subprocess.Popen', side_effect=AssertionError('join cannot execute child processes')):
                core = graph.load('cm3_lto_join_core', ROOT / 'tools/fixtures/classic_final_image/elf.py')
                decoder = graph.load('cm3_lto_join_decoder', ROOT / 'tools/fixtures/cm55_tfm_parity/elf.py')
                checker = graph.load('cm3_lto_join_checker', ROOT / 'tools/fixtures/cm3_freeze_parity/check.py')
                native_adapter = graph.load('cm3_lto_join_native_transport', ROOT / 'tools/fixtures/cm3_lto_roots/native.py')
                reference_adapter = graph.load('cm3_lto_join_reference_transport', ROOT / 'tools/fixtures/cm3_reference_lto_roots/reference.py')
                native_protocol = graph.load('cm3_lto_join_native_protocol', ROOT / 'tools/fixtures/cm3_lto_protocol/protocol.py')
                reference_protocol = graph.load('cm3_lto_join_reference_protocol', ROOT / 'tools/fixtures/cm3_reference_lto_protocol/protocol.py')
                join = graph.load('cm3_lto_join_composition', HERE / 'join.py')
                views = {}
                recomputed = {}
                for side, adapter, protocol in (('Native', native_adapter, native_protocol), ('Reference', reference_adapter, reference_protocol)):
                    group = self.groups[side]
                    roles = {role: row['Path'] for role, row in group['Roles'].items()}
                    factory = adapter.NativeCM3LTOImage if side == 'Native' else adapter.ReferenceCM3LTOImage
                    image = factory(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                        provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
                        link_map=roles['LinkMap'])
                    decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
                    composition = protocol.check_native if side == 'Native' else protocol.check_reference
                    fresh = composition(decoded, image, checker)
                    self.api.same(fresh, group['Result']['ProtocolProof'], 'complete recomputed ' + side + ' canonical evidence')
                    self.api.same({row['Name']: image.function(row['Name']) for row in group['Result']['Roots']},
                                  {row['Name']: row for row in group['Result']['Roots']}, 'complete recomputed ' + side + ' transport records')
                    twin = core.compare_load_images(roles['Plain'], roles['Final'])
                    self.api.same(twin, group['Result']['Twins'], 'independently recomputed ' + side + ' load twins')
                    view = protocol.NativeProtocolView if side == 'Native' else protocol.ReferenceProtocolView
                    views[side] = view(decoded, image)
                    recomputed[side] = dict(Canonical=fresh, Twins=twin)
                proof = join.check_join(views['Native'], views['Reference'], checker, self.policy.decode('ascii'))
                master = join.require_ledger(self.groups['Native']['MasterLedgerBytes'].decode('ascii'), proof['ProtocolProof'])
            self.report.update(JoinProof=proof, RecomputedSides=recomputed, MasterDifferenceRationales=master,
                MasterLedgerSha256=sha(self.groups['Native']['MasterLedgerBytes']), PolicyLedgerSha256=sha(self.policy),
                CapturedSourceBuffers=copies, BinaryInputs=binary_copies, ExecutedSourceBuffers=graph.executed,
                ImmutableInputsConsumed=True, PriorTransportControlsAuthenticated=32, PriorCanonicalControlsAuthenticated=2,
                ProducerBindings=[dict(Side=side, Build=str(group['Root']), ReceiptSha256=group['ReceiptSha256'],
                    ArtifactsSha256=group['ManifestSha256'], CaptureBuild=str(group['CaptureRoot'])) for side, group in self.groups.items()])
        finally:
            sys.meta_path[:] = old_meta

    def _seal(self):
        success = self.report['Status'] == PASS
        if success:
            members = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
            planned = self.expected - {'results.json', 'artifacts.json'}
            self.report.update(UnexpectedOutputMembers=sorted(members - planned), MissingDeclaredOutputMembers=sorted(planned - members))
            need(members == planned, 'predetermined join output membership')
        self.report['OutputSealVerified'] = True
        self.api.save(self.output / 'results.json', self.report)
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
        if success:
            need(set(self.sealed) == self.expected - {'artifacts.json'}, 'exact planned seal membership')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        data = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(data, object_pairs_hook=self.api.unique_object), manifest, 'written join manifest value')
        self.manifest_sha = sha(data)
        self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name != 'artifacts.json'}, self.sealed, 'post-manifest output closure')

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read()
            self.watch.close()
            self.report.update(Status=PASS, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes))
        except BaseException as error:
            self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
        self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.watch.close()
            self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                           if name != 'artifacts.json'}, self.sealed, 'late join output closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.manifest_sha, 'late join manifest drift')
        except BaseException as error:
            self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; closing: ' + str(error), InputClosureVerified=False)
            try:
                self._seal()
            except BaseException as failure:
                self.report.update(OutputSealVerified=False, SealError=str(failure))
                self.api.save(self.output / 'results.json', self.report)
        return self.report['Status'] == PASS


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
                 'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
