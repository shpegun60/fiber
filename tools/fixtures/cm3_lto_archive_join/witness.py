"""Independent paired CM3 O2-lto archive roots and protocols; no native tools."""

import argparse
import copy
import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CM3-LTO-ARCHIVE-JOIN-PASS-NOT-QUALIFIED'
SCOPE = 'CM3_O2_LTO_P4_B16_ARCHIVE_SIX_CLOSED_ROOT_JOIN_ONLY'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
NATIVE = 'tools/fixtures/cm3_lto_archive_roots/witness.py'
REFERENCE = 'tools/fixtures/cm3_reference_lto_archive/probe.py'
REF_ADMISSION = 'tools/fixtures/cm3_reference_lto_transport/admission.py'
REF_TRANSPORT = 'tools/fixtures/cm3_reference_lto_transport/probe.py'
REF_ADAPTER = 'tools/fixtures/cm3_reference_lto_roots/reference.py'
REF_PROTOCOL = 'tools/fixtures/cm3_reference_lto_protocol/protocol.py'
REF_MUTATIONS = 'tools/fixtures/cm3_reference_lto_roots/mutations.py'
REF_CONTROL = 'tools/fixtures/cm3_reference_lto_protocol/witness.py'
FROZEN_JOIN = 'tools/fixtures/cm3_lto_join/join.py'
POLICY = 'tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md'
POLICY_SHA = '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019'
FIXED = {
    NATIVE: '7D65BACFC6CDCFA4B02324905693675A1CA26AEDF92008415CC77645A94E1A6A',
    REFERENCE: '966501D5AB3F8D5EC33375514FC9CA5E43833564DBFA6684D0C1A4E61702BB3B',
    REF_ADMISSION: '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC',
    REF_TRANSPORT: '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3',
    REF_ADAPTER: '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D',
    REF_PROTOCOL: '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798',
    REF_MUTATIONS: 'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C',
    REF_CONTROL: 'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
    'tools/fixtures/cm3_reference_lto_roots/witness.py': '3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54',
    FROZEN_JOIN: 'F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3',
}


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-archive-join: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def same(actual, expected, message):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    need(encode(actual) == encode(expected), message)


def stable(path):
    return Path(os.path.abspath(os.fspath(path)))


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def require_reference_scope(row):
    need(type(row) is dict, 'literal reference capture result')
    same([row.get(key) for key in ('Status', 'Scope', 'Profile', 'Mode', 'SeedMode', 'SeedSide', 'Cohort', 'Linkage',
          'TranslationUnits', 'SlimIRObjects', 'FinalExecutableLinks', 'SavedMachineObjects', 'ReferenceCommit')],
         ['PASS', 'PINNED_REFERENCE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY', 'CM3', 'O2-lto', 'O2', 'Reference',
          'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'archive', 4, 3, 2, 2, PIN], 'exact pinned reference archive scope')
    need(row.get('Error') is None, 'successful reference capture')
    for key in ('LTO', 'ReferenceBuilt', 'ArchiveCaptureComplete', 'NoForcedExtraction', 'InputClosureVerified',
                'OutputSealVerified', 'TwinLoadImageCompared', 'TwinLoadImageIdentical', 'TwinAllocatedSectionsIdentical'):
        need(row.get(key) is True, 'literal reference completion: ' + key)
    for key in ('NativeBuilt', 'ReferenceKernelAvailable', 'SchedulerSemanticsProven', 'CSourceSemanticProof', 'HandlerRoutingProven',
                'Qualification', 'ArchiveExtraction', 'ArchiveExtractionQualified', 'WeakAliasPrecedenceProven',
                'CanonicalProtocolValidated', 'FinalRootRelocationProof', 'FinalReferenceParity', 'FullABIProof', 'SourceIRProof',
                'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'CompleteObjectProof', 'PolicyEquivalence',
                'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
        need(row.get(key) is False, 'literal reference nonclaim: ' + key)
    need(type(row.get('RequiredCellsSatisfied')) is int and row['RequiredCellsSatisfied'] == 0, 'zero reference qualification credit')
    same(row['ArchiveMemberIndices'], [0], 'one pinned port member')
    same(row['ExplicitObjectIndices'], [3, 2, 1], 'startup/consumer/typed provider order')
    need(row.get('Providers') == 'TYPED-FAILSTOP-FIXTURE; NOT A REAL FREERTOS KERNEL', 'fixture is not a real kernel')


def required_reference_provider_order(objects, archive):
    need(type(objects) in (list, tuple) and len(objects) == 4
         and all(isinstance(path, (str, Path)) for path in (*objects, archive)), 'four actual object paths and archive')
    objects, archive = [str(path) for path in objects], str(archive)
    need(len(set(objects)) == 4 and archive not in objects and all(objects) and archive, 'unique provider paths')
    return [objects[3], objects[2], objects[1], archive]


def check_archive_pair(native_view, reference_view, checker, master_ledger, policy_ledger, frozen_join):
    f = frozen_join
    need(f.COHORT == 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'fixed CM3 p4/b16 cohort predicates')
    need(native_view is not reference_view, 'distinct real protocol views')
    native_machine, reference_machine = f._machine(native_view, 'Native'), f._machine(reference_view, 'Reference')
    need(native_machine != reference_machine, 'distinct independently preserved actual machines')
    need(type(checker._NATIVE) is dict and tuple(checker._NATIVE) == tuple(f.NATIVE_ROOTS)
         and type(checker._REFERENCE) is dict and tuple(checker._REFERENCE) == tuple(f.REFERENCE_ROOTS), 'unchanged six-root checker membership')
    need(type(master_ledger) is str and master_ledger.isascii() and type(policy_ledger) is str and policy_ledger.isascii()
         and sha(policy_ledger.encode('ascii')) == POLICY_SHA, 'captured master plus exact fixed policy ledger')
    proof = checker.check_pair(native_view, reference_view)
    f._proof(proof)
    need(f._machine(native_view, 'Native') == native_machine and f._machine(reference_view, 'Reference') == reference_machine,
         'machine bytes changed while matching full protocols')
    roots, transports = {}, {}
    roots['Native'], transports['Native'] = f._evidence(native_view, 'Native', tuple(f.NATIVE_ROOTS), proof['RootEvidence'][:3])
    roots['Reference'], transports['Reference'] = f._evidence(reference_view, 'Reference', tuple(f.REFERENCE_ROOTS), proof['RootEvidence'][3:])
    return dict(Status=PASS, Scope=SCOPE, Profile='CM3', Mode='O2-lto', Cohort=f.COHORT, Linkage='archive', LTO=True,
        ClosedBodies=6, Mechanisms=copy.deepcopy(proof['Mechanisms']), DifferenceIds=copy.deepcopy(proof['DifferenceIds']),
        ProtocolProof=copy.deepcopy(proof), Roots=roots, RawTransportRoots=transports,
        DifferenceRationales=f.require_ledger(master_ledger, proof), PolicyDifferenceRationales=f.require_ledger(policy_ledger, proof),
        MasterLedgerSha256=sha(master_ledger.encode('ascii')), PolicyLedgerSha256=POLICY_SHA,
        MachineSha256=dict(Native=sha(native_machine), Reference=sha(reference_machine)), OriginalTransportRecordsUnmodified=True,
        FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR', ReferenceCoreSlots=8,
            ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False),
        CanonicalProtocolValidated=True, Qualification=False, FinalReferenceParity=False, FullABIProof=False,
        FinalElfProof=False, CompleteObjectProof=False, InstructionEquivalence=False, PolicyEquivalence=False,
        SourceIRProof=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, KernelRuntimeProof=False, HandlerRoutingProven=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)


class Witness:
    def __init__(self, args):
        need(not sys.flags.optimize and __debug__, 'unoptimized interpreter required before helper execution or output')
        raw = (ROOT / NATIVE).read_bytes()
        need(sha(raw) == FIXED[NATIVE], 'fixed native archive admission source')
        self.base = load('paired_archive_native_admission', ROOT / NATIVE, raw)
        utility_path = ROOT / self.base.UTILITY
        utility_bytes = utility_path.read_bytes()
        need(sha(utility_bytes) == self.base.FIXED[self.base.UTILITY], 'fixed closure bootstrap utility')
        bootstrap = load('paired_archive_capture_bootstrap', utility_path, utility_bytes)
        capture_watch = bootstrap.Closure()
        # Authenticate both whole capture trees before either Seed loads helpers.
        for side in ('native', 'reference'):
            root = bootstrap.checked_path(getattr(args, side + '_build'))
            receipt = bootstrap.digest_text(getattr(args, side + '_receipt_sha256'))
            manifest = bootstrap.digest_text(getattr(args, side + '_artifacts_sha256'))
            capture_watch.read(root / 'results.json', receipt)
            artifacts = capture_watch.structured(root / 'artifacts.json', manifest)['Artifacts']
            need(type(artifacts) is dict and artifacts and artifacts.get('results.json') == receipt, 'both caller receipt/manifest bindings')
            for name, digest in artifacts.items():
                bootstrap.portable_name(name)
                bootstrap.digest_text(digest)
            capture_watch.tree(root, dict(artifacts, **{'artifacts.json': manifest}))
        native_args = SimpleNamespace(capture_build=args.native_build, capture_receipt_sha256=args.native_receipt_sha256,
                                     capture_artifacts_sha256=args.native_artifacts_sha256, output_dir=args.output_dir)
        self.native = self.base.Witness(native_args)
        self.api, self.output = self.native.api, self.native.output
        self.watch, self.buffers, self.identities = capture_watch, dict(self.native.buffers), dict(self.native.identities)
        for path, digest in self.native.watch.hashes.items():
            self.watch.read(path, digest)
        self._buffer(ROOT / NATIVE, raw)
        for relative, digest in FIXED.items():
            self._buffer(ROOT / relative, self.watch.read(ROOT / relative, digest))
        self.groups = dict(Native=dict(Root=self.native.root, Result=self.native.result, Artifacts=self.native.artifacts,
            Seed=self.native.seed, Roles=self.native.roles, ReceiptSha256=args.native_receipt_sha256,
            ManifestSha256=args.native_artifacts_sha256, CommandsAuthenticated=66))
        self._admit_reference(args)
        n, r = self.groups['Native'], self.groups['Reference']
        need(n['Root'] != r['Root'] and n['Seed'].inventory == r['Seed'].inventory, 'distinct captures and same authenticated source inventory')
        files = [row['Path'] for group in self.groups.values() for row in group['Roles'].values()]
        need(len(files) == 14 and all(not path.samefile(other) for index, path in enumerate(files) for other in files[:index]),
             'fourteen physically distinct actual binary roles')
        need(n['Roles']['Machine']['Bytes'] != r['Roles']['Machine']['Bytes'], 'distinct native/reference machine bytes')
        ledger = n['Seed'].inventory / 'inputs/FREERTOS_ASM_PARITY.md'
        need(ledger in n['Seed'].originals and ledger in r['Seed'].originals, 'shared captured master ledger is an actual input')
        same(n['Seed'].originals[ledger]['Sha256'], r['Seed'].originals[ledger]['Sha256'], 'same master ledger fingerprint')
        self.master = self.watch.read(ledger, n['Seed'].originals[ledger]['Sha256'])
        self.policy = self.watch.read(ROOT / POLICY, POLICY_SHA)
        self._buffer(Path(__file__).resolve(), self.watch.read(Path(__file__).resolve()))
        git_rows = [row for row in r['Seed'].commands if row['Label'] == 'reference git rev-parse']
        need(len(git_rows) == 2 and git_rows[0]['Argv'][0] == git_rows[1]['Argv'][0], 'one authenticated reference Git provenance tool')
        self.provenance_git = self.api.regular(git_rows[0]['Argv'][0])
        need(self.provenance_git in r['Seed'].originals and self.provenance_git in self.watch.hashes
             and not any(self.provenance_git.is_relative_to(group['Root']) for group in self.groups.values()), 'external nonexecuted Git provenance role')
        interpreter = self.api.regular(self.base.interpreter_path())
        self.watch.read(interpreter)
        denied = {ROOT, interpreter.parent, *(group['Root'] for group in self.groups.values()), *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
             for path in denied), 'fresh output outside all authenticated evidence/tool roots')
        for path in self.watch.hashes:
            self.identities[path] = self._physical(path)
        self.close()
        self.expected = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Error=None, Scope=SCOPE, Profile='CM3', Mode='O2-lto', Linkage='archive',
            Cohort=self.api.COHORT, ReferenceCommit=PIN, ClosedBodies=0, CanonicalProtocolValidated=False,
            FinalRootRelocationProof=False, OrdinaryRootPreservationProven=False, FinalReferenceParity=False,
            ArchiveExtractionQualified=False, WeakAliasPrecedenceProven=False, Qualification=False, FullABIProof=False,
            CompleteObjectProof=False, SourceIRProof=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
            OriginalTranslationUnitOwnership=False, InstructionEquivalence=False, PolicyEquivalence=False,
            KernelRuntimeProof=False, HandlerRoutingProven=False, CpuExecution=False, BoardExecution=False,
            GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0, HostedCIQualified=False,
            NativeCommandsExecuted=0, ProducerCompilersReexecuted=False, NativeControlsReused=False, MutantsReexecuted=False,
            InputClosureVerified=False, OutputSealVerified=False,
            NonexecutedGitProvenanceTool=dict(Path=str(self.provenance_git), Sha256=self.watch.hashes[self.provenance_git],
                PhysicalIdentity=self.identities[self.provenance_git]),
            Interpreter=dict(ModulePath=str(interpreter), Sha256=self.watch.hashes[interpreter], Version=sys.version))

    def _buffer(self, path, data):
        path = stable(path)
        need(path not in self.buffers or self.buffers[path] == data, 'conflicting immutable helper bytes')
        self.buffers[path] = data

    def _physical(self, path):
        info = self.api.regular(path).stat()
        need(info.st_nlink >= 1 and (info.st_nlink == 1 or path == self.provenance_git), 'unexpected hard-linked role: ' + str(path))
        return info.st_dev, info.st_ino, info.st_nlink

    def _artifact(self, group, path, expected=None):
        path = self.api.regular(path)
        need(path.is_relative_to(group['Root']), 'capture artifact escaped owning build')
        digest = group['Artifacts'][path.relative_to(group['Root']).as_posix()]
        need(expected is None or digest == expected, 'actual capture artifact/record hash binding')
        return self.watch.read(path, digest)

    def _json(self, group, path):
        return json.loads(self._artifact(group, path), object_pairs_hook=self.api.unique_object)

    def _admit_reference(self, args):
        root = self.api.checked_path(args.reference_build)
        receipt = self.api.digest_text(args.reference_receipt_sha256)
        manifest = self.api.digest_text(args.reference_artifacts_sha256)
        artifacts = self.watch.structured(root / 'artifacts.json', manifest)['Artifacts']
        need(type(artifacts) is dict and artifacts and artifacts.get('results.json') == receipt, 'reference caller receipt/manifest binding')
        for name, digest in artifacts.items():
            self.api.portable_name(name)
            self.api.digest_text(digest)
        self.watch.tree(root, dict(artifacts, **{'artifacts.json': manifest}))
        result = self.watch.structured(root / 'results.json', receipt)
        require_reference_scope(result)
        same(result['CaptureProducer'], dict(Path=str(ROOT / REFERENCE), Sha256=FIXED[REFERENCE]), 'actual fixed reference archive producer')
        same(result['FrozenCaptureHelpers'], [dict(Path=str(ROOT / relative), Sha256=digest) for relative, digest in (
            (self.base.UTILITY, self.base.FIXED[self.base.UTILITY]), (REF_TRANSPORT, FIXED[REF_TRANSPORT]),
            (REF_ADMISSION, FIXED[REF_ADMISSION]), (self.base.PRODUCER, self.base.FIXED[self.base.PRODUCER]),
            (self.base.LOADER, self.base.FIXED[self.base.LOADER]), (self.base.BINDING, self.base.FIXED[self.base.BINDING]))],
            'reference producer immutable helper sources')
        group = dict(Root=root, Result=result, Artifacts=artifacts, ReceiptSha256=receipt, ManifestSha256=manifest,
                     CommandsAuthenticated=41)
        inputs = self._json(group, root / 'inputs.json')
        need(type(inputs['Files']) is list and inputs['Files'] and type(inputs['Watched']) is list and inputs['Watched'], 'reference input closure')
        for row in inputs['Files']:
            original, captured = self.api.regular(row['Original']), self.api.regular(row['Captured'])
            digest = self.api.digest_text(row['Sha256'])
            data = self._artifact(group, captured, digest)
            need(self.watch.read(original, digest) == data, 'reference original/captured input bytes')
            if original.suffix == '.py':
                self._buffer(original, data)
                self._buffer(captured, data)
        watched = [self.api.regular(row['Path']) for row in inputs['Watched']]
        need(len(watched) == len(set(watched)), 'unique reference watched input identities')
        for row in inputs['Watched']:
            self.watch.read(row['Path'], self.api.digest_text(row['Sha256']))
        need(type(result['ClosingFilesVerified']) is int and result['ClosingFilesVerified'] == len(watched), 'literal reference closing coverage')
        admission = load('paired_archive_reference_seed', ROOT / REF_ADMISSION, self.buffers[ROOT / REF_ADMISSION])
        translated = SimpleNamespace(reference_build=result['SeedBuild'], reference_receipt_sha256=result['SeedReceiptSha256'],
            reference_artifacts_sha256=result['SeedArtifactsSha256'], output_dir=str(self.output))
        raw_read = Path.read_bytes
        def seed_read(path):
            key = stable(path)
            if key.suffix == '.py':
                need(key in self.buffers, 'unknown reference Seed helper source')
                return self.buffers[key]
            return raw_read(path)
        with patch.object(Path, 'read_bytes', seed_read):
            seed = admission.Seed(self.api, translated)
        for path, digest in seed.closure.hashes.items():
            self.watch.read(path, digest)
        for path, data in seed.buffers.items():
            self._buffer(path, data)
        group['Seed'] = seed
        producer = load('paired_archive_reference_capture', ROOT / REFERENCE, self.buffers[ROOT / REFERENCE])
        transport = load('paired_archive_reference_symbols', ROOT / REF_TRANSPORT, self.buffers[ROOT / REF_TRANSPORT])
        self._reference_commands(group, producer, transport)
        emit = root / 'emit-relocs'
        roles = dict(Machine=emit / 'image.elf.ltrans0.ltrans.o', Final=emit / 'image.elf', Disassembly=emit / 'image.elf.dis',
            LinkMap=emit / 'image.map', Startup=Path(result['Sources'][3]['Object']), Plain=root / 'ordinary/image.elf',
            MachineDisassembly=emit / 'image.elf.ltrans0.ltrans.o.dis')
        group['Roles'] = {role: dict(Path=path, Bytes=self._artifact(group, path),
            Sha256=artifacts[path.relative_to(root).as_posix()]) for role, path in roles.items()}
        self.groups['Reference'] = group

    def _reference_commands(self, group, producer, transport):
        root, result, seed = group['Root'], group['Result'], group['Seed']
        records = result['Commands']
        need(type(records) is list and len(records) == 41, 'complete forty-one reference commands')
        same(self._json(group, root / 'commands.json'), records, 'reference complete command catalog')
        same(result['SeedCohortArtifact'], seed.artifact, 'exact reference cohort/target/defines')
        same(result['SourceInventoryReceipt'], str(seed.inventory), 'exact reference inventory authority')
        same(result['ReferenceFileBindings'], seed.result['ReferenceFileBindings'], 'actual pinned worktree/blob/capture authority')
        same(result['FixtureHandlerInstallationCheck'], 1, 'reference installation check remains enabled')
        tool_root = root / 'toolchain'
        expected_tools = {tool_root / path.relative_to(seed.tool_root): row['Sha256'] for path, row in seed.originals.items()
                          if path.is_relative_to(seed.tool_root)}
        source_ar = self.api.regular(seed.gcc.with_name('arm-none-eabi-ar.exe'))
        ar = tool_root / source_ar.relative_to(seed.tool_root)
        expected_tools[ar] = self.base.ARCHIVER_SHA
        self.watch.read(source_ar, self.base.ARCHIVER_SHA)
        gcc = tool_root / seed.gcc.relative_to(seed.tool_root)
        plugin = tool_root / seed.plugin.relative_to(seed.tool_root)
        workers = {name: tool_root / path.relative_to(seed.tool_root) for name, path in seed.workers.items()}
        info = source_ar.stat()
        same(result['Archiver'], dict(Path=str(source_ar), Sha256=self.base.ARCHIVER_SHA,
            Identity=dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink),
            Admission='CALLER-SHA256; SAME-TOOLCHAIN-COMPILER-SIBLING', PresentInSeedInputs=source_ar in seed.originals,
            Captured=str(ar), CapturedSha256=self.base.ARCHIVER_SHA, ExplicitPlugin=str(plugin), PluginSha256=expected_tools[plugin]),
            'reference caller-bound sibling archiver and actual plugin')
        need(set(self.api.files_under(tool_root).values()) == set(expected_tools), 'exact reference cloned toolchain membership')
        for path, digest in expected_tools.items():
            self._artifact(group, path, digest)
        same(result['CapturedCompiler'], str(gcc), 'reference cloned compiler')
        same(result['ResolvedWorkers'], {name: dict(Path=str(path), Sha256=expected_tools[path]) for name, path in workers.items()}, 'reference workers')
        same(result['LTOPlugin'], dict(Path=str(plugin), Sha256=expected_tools[plugin]), 'reference plugin')
        environment = self._json(group, root / 'environment.json')
        need(type(environment) is dict and all(type(k) is str and type(v) is str for k, v in environment.items()), 'literal reference environment')
        same(seed.native.process_environment(environment), environment, 'reference sanitized environment policy')
        need(environment.get('TEMP') == environment.get('TMP') == str(root / 'tmp'), 'private reference temporary directory')
        search = [str(gcc.parent), *(str(path.parent) for path in workers.values())]
        system = next((value for key, value in environment.items() if key.upper() == 'SYSTEMROOT'), None)
        if system:
            search.append(str(Path(system) / 'System32'))
        need(environment.get('PATH') == os.pathsep.join(dict.fromkeys(search)), 'canonical reference tool PATH')
        expected, streams, traces = [], {}, {}

        def command(label, argv, cwd=root, stdout=None):
            index = len(expected)
            expected.append((label, [str(value) for value in argv], str(cwd)))
            if stdout is not None:
                streams[index] = stdout

        def inspect(path):
            for tool, flags, suffix in (('readelf', ['-hSWsrA', '-lW'], '.readelf'), ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
                    ('nm', ['--plugin', str(plugin), '-P', '-S', '--defined-only'], '.nm')):
                command('inspect ' + path.name + suffix, [gcc.with_name('arm-none-eabi-' + tool + '.exe'), *flags, path],
                        stdout=Path(str(path) + suffix))

        for name in workers:
            command('resolve ' + name, [gcc, '-print-prog-name=' + name])
        command('resolve LTO plugin', [gcc, '-print-file-name=' + plugin.name])
        need(type(result['Sources']) is list and len(result['Sources']) == 4, 'four exact reference source rows')
        objects = []
        for index, (row, admitted) in enumerate(zip(result['Sources'], seed.sources)):
            source = self.api.regular(admitted['Source'])
            obj = root / 'objects' / ('%02d-' % index + source.stem + '.o')
            dependency = obj.with_suffix('.d')
            flags = admitted['CompileFlags'] if index == 3 else self.api.mode_flags(admitted['CompileFlags'])
            same([row['Source'], row['SourceSha256'], row['CompileFlags'], row['Object'], row['DependencyFile'], row['SlimIR'],
                  row['CompileDependenciesVerified']], [str(source), admitted['SourceSha256'], flags, str(obj), str(dependency),
                  index != 3, True], 'exact pinned reference source/compile recipe')
            data = self._artifact(group, obj, row['ObjectSha256'])
            header = self.api.require_elf32le(data)
            same(row['ELFHeader'], header, 'actual reference input ELF header')
            sections = self.api.section_records(self._artifact(group, Path(str(obj) + '.readelf')).decode('utf-8'))
            same(row['Sections'], sections, 'actual reference input sections')
            same([item['Index'] for item in sections], list(range(header['SectionCount'])), 'complete reference input section inventory')
            if index == 3:
                need(not any(item['Name'].startswith('.gnu.lto_') for item in sections), 'native reference startup')
            else:
                need(any(item['Name'].startswith('.gnu.lto_') for item in sections)
                     and not any(item['Size'] and 'X' in item['Flags'] for item in sections), 'reference slim IR without fat fallback')
            dep_bytes = self._artifact(group, dependency)
            def dependency_text(path, encoding=None, errors=None):
                need(stable(path) == dependency and encoding == 'utf-8' and errors is None, 'only authenticated reference dependency text')
                return dep_bytes.decode('utf-8')
            with patch.object(Path, 'read_text', dependency_text):
                actual = set(seed.native.read_dependencies(dependency))
            declared = {self.api.regular(item['Path']) for item in admitted['Dependencies']}
            declared = {tool_root / path.relative_to(seed.tool_root) if path.is_relative_to(seed.tool_root) else path for path in declared}
            need(actual == declared and all(path in self.watch.hashes for path in actual), 'same admitted actual reference dependencies')
            same(row['ActualCompileDependencies'], [dict(Path=str(path), Sha256=self.watch.hashes[path]) for path in sorted(actual)], 'reference dependency bytes')
            command('compile ' + source.name, [gcc, *flags, '-MD', '-MF', dependency, '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj])
            inspect(obj)
            objects.append(obj)

        archive, copies = root / 'archive/libfreertos_cm3.a', root / 'archive/members'
        archive_bytes = self._artifact(group, archive)
        parsed = producer.archive_records(archive_bytes)
        evidence = result['Archive']
        same(self._json(group, root / 'archive/archive.json'), evidence, 'reference raw archive metadata')
        for key in parsed:
            if key != 'Members':
                same(evidence[key], parsed[key], 'reference raw archive/index binding: ' + key)
        need(len(evidence['Members']) == len(parsed['Members']) == 1, 'one actual reference archive member')
        raw_member, member = parsed['Members'][0], evidence['Members'][0]
        same({key: member[key] for key in raw_member}, raw_member, 'complete reference raw member fields')
        same([member['SourceIndex'], member['Object'], member['Source'], member['Captured'], evidence['MemberCount'], evidence['Path'], member['Sha256']],
             [0, str(objects[0]), result['Sources'][0]['Source'], str(copies / '00-port.o'), 1, str(archive), result['Sources'][0]['ObjectSha256']],
             'sole pinned port member/source/path/hash binding')
        need(set(self.api.files_under(copies)) == {'00-port.o'}, 'only the one extracted port file')
        need(self._artifact(group, copies / '00-port.o') == self._artifact(group, objects[0])
             == archive_bytes[member['DataOffset']:member['DataOffset'] + member['Size']], 'complete raw/extracted/compiled port bytes')
        listing, index_text = root / 'archive/members.txt', root / 'archive/index.nm'
        same([evidence['MemberListing'], evidence['MemberListingSha256'], evidence['IndexInspection'], evidence['IndexInspectionSha256']],
             [str(listing), sha(self._artifact(group, listing)), str(index_text), sha(self._artifact(group, index_text))], 'reference raw ar/index stream bindings')
        same(self._artifact(group, listing).decode('ascii').splitlines(), ['00-port.o'], 'sole actual listed port')
        need(self._artifact(group, index_text).strip() and evidence['RepeatedBuildByteDeterminismProven'] is False, 'index retained without determinism overclaim')
        same(evidence['CreationFlags'], ['--plugin', str(plugin), 'rcsD'], 'explicit reference plugin indexing')
        command('create indexed archive', [ar, '--plugin', plugin, 'rcsD', archive, objects[0]])
        command('list archive members', [ar, '--plugin', plugin, 't', archive], stdout=listing)
        command('inspect archive index', [gcc.with_name('arm-none-eabi-nm.exe'), '--plugin', plugin, '--print-armap', '-P', '-S', '--defined-only', archive], stdout=index_text)
        command('extract archive member 00-port.o', [ar, '--plugin', plugin, 'x', archive, '00-port.o'], copies)
        same([row['Kind'] for row in result['Links']], ['ordinary', 'emit-relocs'], 'two actual ordered reference archive twins')
        for kind, emit in (('ordinary', False), ('emit-relocs', True)):
            directory = root / kind
            image, link_map, machine = directory / 'image.elf', directory / 'image.map', directory / 'image.elf.ltrans0.ltrans.o'
            row = result['Links'][0 if kind == 'ordinary' else 1]
            providers = required_reference_provider_order(objects, archive)
            same(row['LinkInputs'], providers, 'reference explicit startup/consumer/providers then port archive')
            flags = producer.link_flags(self.api, seed.artifact, objects, archive, seed.script, image, link_map, emit)
            same(flags, self.api.link_flags(seed.artifact, providers, seed.script, image, link_map, emit), 'exact unchanged reference link flags')
            traces[len(expected)] = row['VerboseObservedTools']
            command('link ' + kind, [gcc, *flags], directory)
            inspect(machine)
            inspect(image)
            same([row['Path'], row['Machine'], row['Map'], row['Archive'], row['ArchiveSha256']],
                 [str(image), str(machine), str(link_map), str(archive), parsed['Sha256']], 'own reference final/machine/map/archive')
            data = self._artifact(group, machine, row['MachineSha256'])
            header = self.api.require_elf32le(data)
            same(row['MachineHeader'], header, 'actual reference saved machine')
            same(row['FinalHeader'], self.api.require_elf32le(self._artifact(group, image, row['Sha256']), 'EXEC'), 'actual reference final')
            text = self._artifact(group, Path(str(machine) + '.readelf')).decode('utf-8')
            sections = self.api.section_records(text)
            same(row['MachineSections'], sections, 'reference complete machine sections')
            same([item['Index'] for item in sections], list(range(header['SectionCount'])), 'all reference machine sections')
            need(not any(item['Name'].startswith('.gnu.lto_') for item in sections)
                 and any(item['Size'] and 'X' in item['Flags'] for item in sections), 'real reference machine, not WPA IR')
            same(row['MachineSymbols'], [dict(item, Artifact=str(machine), ArtifactSha256=sha(data)) for item in transport.symbol_records(text, sections)], 'reference actual symbol facts')
            need({path for path in directory.iterdir() if re.fullmatch(r'image[.]elf[.]ltrans[0-9]+[.]ltrans[.]o', path.name)} == {machine}, 'single reference machine partition')
            map_bytes = self._artifact(group, link_map, row['MapSha256'])
            extraction = producer.extraction_rows(map_bytes.decode('utf-8'), archive, ['00-port.o'])
            same(row['ArchiveExtractionRows'], extraction, 'actual reference port extraction rows')
            same(self._json(group, directory / 'archive-extraction.json'), dict(Archive=str(archive), ArchiveSha256=parsed['Sha256'],
                 Map=str(link_map), MapSha256=sha(map_bytes), Rows=extraction, PerOriginalTranslationUnitMachineOwnership=False,
                 WeakAliasPrecedenceProven=False), 'reference retained extraction evidence')
            for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                need(self._artifact(group, Path(str(image) + suffix)), 'retained actual reference LTO raw record: ' + suffix)
            same({name: sha(self._artifact(group, path)) for name, path in self.api.files_under(directory).items()}, row['EntireDirectoryArtifacts'], 'complete reference link tree')
        need(len(expected) == len(records) == 41, 'complete reconstructed reference argv catalog')
        context = SimpleNamespace(tool_hashes=expected_tools, tools={'gcc': gcc}, workers=workers, plugin=plugin)
        for index, (row, (label, argv, cwd)) in enumerate(zip(records, expected)):
            same([row['Label'], row['Argv'], row['Cwd']], [label, argv, cwd], 'full ordered reference command binding')
            need(row['Status'] == 'PASS' and type(row['Exit']) is int and row['Exit'] == 0 and row['TimedOut'] is False
                 and row.get('Error') is None and type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds'])
                 and row['Seconds'] >= 0, 'literal successful reference terminal command')
            target = root / ('command-%04d.json' % index)
            same(self._json(group, target), row, 'reference terminal sidecar')
            stdout, stderr = self._artifact(group, target.with_suffix('.stdout')), self._artifact(group, target.with_suffix('.stderr'))
            if index in streams:
                need(stdout == self._artifact(group, streams[index]), 'reference raw inspector/artifact stream equality')
            elif index < 7:
                need(self.api.regular(stdout.decode('utf-8').strip()) == (list(workers.values())[index] if index < 6 else plugin), 'actual reference resolver bytes')
            if index in traces:
                same(self.api.Probe.trace_identities(context, stderr), traces[index], 'reference actual verbose tool chain')
        same(result['ObjectChecks'], [dict(Stage=stage, Status='PASS') for stage in ('after-compile', 'before-archive', 'after-archive',
             'before-link-ordinary', 'after-link-ordinary', 'before-link-emit-relocs', 'after-link-emit-relocs', 'closing')], 'reference object checkpoints')
        same(result['ArchiveChecks'], [dict(Stage=stage, Status='PASS', Sha256=parsed['Sha256']) for stage in ('after-archive',
             'before-link-ordinary', 'after-link-ordinary', 'before-link-emit-relocs', 'after-link-emit-relocs', 'closing')], 'reference archive freeze checkpoints')

    def close(self):
        self.watch.close()
        self.native.close()
        self.groups['Reference']['Seed'].closure.close()
        for path, identity in self.identities.items():
            need(self._physical(path) == identity, 'physical identity drift: ' + str(path))

    def declare(self, path):
        path = stable(path)
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected, 'duplicate output declaration')
        self.expected.add(name)

    def _bind_controls(self, side, rows, roles):
        for control in rows:
            same([row['Role'] for row in control['Files']], list(roles), 'complete ordered private control roles')
            directory = self.output / 'controls' / side / ('mutants' if len(roles) == 5 else 'protocol-mutants') / control['Name']
            wanted = {directory / (role + self.groups[side]['Roles'][role]['Path'].suffix) for role in roles}
            need(set(self.api.files_under(directory).values()) == wanted, 'exact private control membership')
            for row in control['Files']:
                path = self.api.regular(row['Path'])
                need(path == directory / (row['Role'] + self.groups[side]['Roles'][row['Role']]['Path'].suffix)
                     and path.relative_to(self.output).as_posix() in self.expected, 'fixed private control side/role/path')
                self.watch.read(path, self.api.digest_text(row['Sha256']))
                identity = self._physical(path)
                if 'PhysicalIdentity' in row:
                    value = row['PhysicalIdentity']
                    need(type(value) is dict and all(type(value.get(key)) is int for key in ('Device', 'FileId', 'Links'))
                         and tuple(value[key] for key in ('Device', 'FileId', 'Links')) == identity, 'actual returned private physical identity')
                need(path not in self.identities or self.identities[path] == identity, 'private identity changed before outer binding')
                self.identities[path] = identity

    def _read(self):
        loader_path = ROOT / self.base.LOADER
        loader = load('paired_archive_immutable_loader', loader_path, self.buffers[loader_path])
        graph = loader.FrozenSources(self.buffers)
        packages = []
        for group in self.groups.values():
            package = group['Seed'].root / 'python/elftools'
            members = {path.relative_to(package).as_posix(): sha(data) for path, data in self.buffers.items() if path.is_relative_to(package)}
            need('__init__.py' in members, 'complete captured parser source package')
            packages.append((package, members))
        same(packages[0][1], packages[1][1], 'identical authenticated native/reference parser packages')
        modules = {}
        for path in self.buffers:
            if path.is_relative_to(packages[0][0]):
                parts = list(path.relative_to(packages[0][0].parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'unique parser source module')
                modules[name] = path, is_package
        need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules), 'initially unimported parser package')

        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(inner, fullname, path=None, target=None):
                if fullname != 'elftools' and not fullname.startswith('elftools.'):
                    return None
                need(fullname in modules and target is None, 'unknown captured parser module')
                source, is_package = modules[fullname]
                spec = graph.spec(fullname, source)
                if is_package:
                    spec.submodule_search_locations = [str(source.parent)]
                return spec

        snapshots = dict(self.buffers)
        source_copies, binary_copies = [], []
        for index, (path, data) in enumerate(sorted(self.buffers.items())):
            target = self.output / 'source-buffers' / ('%04d-' % index + path.name)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
            source_copies.append(dict(Original=str(path), Captured=str(target), Sha256=sha(data)))
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
            twin_path = group['Root'] / 'load-image.json'
            need(group['Result']['TwinLoadImagesPath'] == str(twin_path), 'fixed actual saved twin evidence path')
            snapshots[stable(twin_path)] = self._artifact(group, twin_path, group['Result']['TwinLoadImagesSha256'])
        for name, data in (('MasterLedger.md', self.master), ('PolicyLedger.md', self.policy)):
            target = self.output / 'ledgers' / name
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
        catalogs, mutable = {}, set()
        transport_roles = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')
        canonical_roles = (*transport_roles, 'MachineDisassembly')
        for side, relative in (('Native', self.base.MUTATIONS), ('Reference', REF_MUTATIONS)):
            catalog = graph.load('paired_archive_catalog_' + side, ROOT / relative)
            need(type(catalog.CASES) is tuple and len(catalog.CASES) == 16, 'fixed sixteen-control catalog per side')
            catalogs[side] = catalog
            for name, reason in catalog.CASES:
                for role in transport_roles:
                    path = self.output / 'controls' / side / 'mutants' / name / (role + self.groups[side]['Roles'][role]['Path'].suffix)
                    self.declare(path)
                    mutable.add(stable(path))
            for role in canonical_roles:
                path = self.output / 'controls' / side / 'protocol-mutants/coherent-svc-immediate' / (role + self.groups[side]['Roles'][role]['Path'].suffix)
                self.declare(path)
                mutable.add(stable(path))
        raw_read = Path.read_bytes

        def fixed_read(path):
            key = stable(path)
            if key in snapshots:
                return snapshots[key]
            need(key in mutable and Path(path).is_absolute() and Path(path) == key,
                 'unknown reader input outside immutable positives or predetermined private files')
            return raw_read(path)

        def fixed_text(path, encoding=None, errors=None, newline=None):
            need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'), 'strict reader text decoding')
            return fixed_read(path).decode(encoding or 'utf-8', errors or 'strict')

        previous = list(sys.meta_path)
        recomputed, views, controls = {}, {}, {}
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text), \
                    patch('subprocess.Popen', side_effect=AssertionError('archive join cannot execute processes')), \
                    patch('os.system', side_effect=AssertionError('archive join cannot execute shell commands')):
                core = graph.load('paired_archive_core', ROOT / self.base.CORE)
                decoder = graph.load('paired_archive_decoder', ROOT / self.base.DECODER)
                checker = graph.load('paired_archive_checker', ROOT / self.base.CHECKER)
                frozen_join = graph.load('paired_archive_frozen_join_predicates', ROOT / FROZEN_JOIN)
                for side, adapter_path, protocol_path, control_path in (
                        ('Native', self.base.ADAPTER, self.base.PROTOCOL, self.base.CONTROL),
                        ('Reference', REF_ADAPTER, REF_PROTOCOL, REF_CONTROL)):
                    group = self.groups[side]
                    roles = {role: row['Path'] for role, row in group['Roles'].items()}
                    adapter = graph.load('paired_archive_adapter_' + side, ROOT / adapter_path)
                    protocol = graph.load('paired_archive_protocol_' + side, ROOT / protocol_path)
                    factory = adapter.NativeCM3LTOImage if side == 'Native' else adapter.ReferenceCM3LTOImage
                    image = factory(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                        provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']}, link_map=roles['LinkMap'])
                    roots = [image.function(name) for name in adapter.ROOTS]
                    need(len(roots) == 3 and all(row['GeneratedMachineBoundRootPreservation'] is True
                         and row['CanonicalProtocolValidated'] is False for row in roots), 'three complete actual emitted roots per side')
                    decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
                    view = protocol.NativeProtocolView if side == 'Native' else protocol.ReferenceProtocolView
                    views[side] = view(decoded, image)
                    twins = core.compare_load_images(roles['Plain'], roles['Final'])
                    need(twins.get('Identical') is True, 'actual own-side archive twins must match')
                    same(twins, group['Result']['TwinLoadImages'], 'fresh/captured own-side twins')
                    same(json.loads(snapshots[stable(group['Root'] / 'load-image.json')], object_pairs_hook=self.api.unique_object), twins,
                         'actual saved own-side twin evidence')
                    recomputed[side] = dict(Roots=roots, Twins=twins, OrdinaryRootPreservationProven=False)
                    cases = catalogs[side].run_cases(core, adapter, image, {role: roles[role] for role in transport_roles}, self.output / 'controls' / side)
                    same([(row['Name'], row['Expected']) for row in cases], list(catalogs[side].CASES), 'complete ordered actual control catalog')
                    need(all(row['Status'] == 'PASS' and row['ImmutableInputBuffersConsumed'] is True and row['Edits']
                         and type(row['ClosingFilesVerified']) is int and row['ClosingFilesVerified'] == 5 for row in cases), 'sixteen actual expected rejections per side')
                    self._bind_controls(side, cases, transport_roles)
                    control = graph.load('paired_archive_svc_control_' + side, ROOT / control_path)
                    control_type = control.witness_type()
                    def declared(path):
                        need(stable(path).relative_to(self.output).as_posix() in self.expected, 'predetermined coherent control output')
                    facade = SimpleNamespace(output=self.output / 'controls' / side, watch=self.watch, report={}, declare=declared, declare_output=declared)
                    control_type._constant_control(facade, core, adapter, decoder, checker, protocol,
                        {role: roles[role] for role in canonical_roles}, snapshots, image)
                    canonical = facade.report['ProtocolControls']
                    need(len(canonical) == 1 and canonical[0]['Name'] == 'coherent-svc-immediate' and canonical[0]['Status'] == 'PASS'
                         and canonical[0]['TransportPreservationAccepted'] is True and canonical[0]['ImmutableInputBuffersConsumed'] is True
                         and type(canonical[0]['ClosingFilesVerified']) is int and canonical[0]['ClosingFilesVerified'] == 6,
                         'actual coherent SVC drift must preserve all three roots then fail canonical protocol')
                    self._bind_controls(side, canonical, canonical_roles)
                    controls[side] = dict(Transport=cases, Canonical=canonical)
                proof = check_archive_pair(views['Native'], views['Reference'], checker, self.master.decode('ascii'), self.policy.decode('ascii'), frozen_join)
            self.report.update(JoinProof=proof, ProtocolProof=proof['ProtocolProof'], RecomputedSides=recomputed, Controls=controls,
                Mechanisms=proof['Mechanisms'], DifferenceIds=proof['DifferenceIds'], CapturedSourceBuffers=source_copies,
                BinaryInputs=binary_copies, ExecutedSourceBuffers=graph.executed, ImmutableInputsConsumed=True,
                TransportControlsExecuted=32, CanonicalControlsExecuted=2, MutantsReexecuted=True,
                ProducerBindings=[dict(Side=side, Build=str(group['Root']), ReceiptSha256=group['ReceiptSha256'],
                    ArtifactsSha256=group['ManifestSha256'], CommandsAuthenticated=group['CommandsAuthenticated'],
                    ArchiveSha256=group['Result']['Archive']['Sha256']) for side, group in self.groups.items()])
        finally:
            sys.meta_path[:] = previous
        for path in mutable:
            need(path.is_file(), 'every predetermined private file must exist')
            self.watch.read(path)
        for path in self.watch.hashes:
            if path not in self.identities:
                self.identities[path] = self._physical(path)

    def _seal(self):
        success = self.report['Status'] == PASS
        if success:
            actual = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
            need(actual == self.expected - {'results.json', 'artifacts.json'}, 'exact predetermined output membership')
        self.report['OutputSealVerified'] = True
        intended = (json.dumps(self.report, indent=2, sort_keys=True, allow_nan=False) + '\n').replace('\n', os.linesep).encode('ascii')
        self.api.save(self.output / 'results.json', self.report)
        need((self.output / 'results.json').read_bytes() == intended, 'written receipt differs from intended platform bytes')
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name not in ('results.json', 'artifacts.json')}
        self.sealed['results.json'] = sha(intended)
        if success:
            need(set(self.sealed) == self.expected - {'artifacts.json'}, 'all planned output artifacts must exist')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        raw = (self.output / 'artifacts.json').read_bytes()
        same(json.loads(raw, object_pairs_hook=self.api.unique_object), manifest, 'actual written manifest must equal intended value')
        self.output_manifest_sha = sha(raw)
        same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'},
             self.sealed, 'post-manifest complete output closure')

    def _fail(self, error):
        self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; ' + str(error),
            CanonicalProtocolValidated=False, FinalRootRelocationProof=False, InputClosureVerified=False,
            OutputSealVerified=False, ImmutableInputsConsumed=False, MutantsReexecuted=False, ClosedBodies=0)

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read()
            self.close()
            self.report.update(Status=PASS, CanonicalProtocolValidated=True, FinalRootRelocationProof=True,
                ClosedBodies=6, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes))
        except BaseException as error:
            self._fail(type(error).__name__ + ': ' + str(error))
        self.report['InputHashes'] = {str(path): digest for path, digest in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.close()
            same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'},
                 self.sealed, 'late complete output closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.output_manifest_sha, 'late manifest drift')
        except BaseException as error:
            self._fail('sealing: ' + type(error).__name__ + ': ' + str(error))
            try:
                self._seal()
            except BaseException as final_error:
                self.report.update(OutputSealVerified=False, SealError=type(final_error).__name__ + ': ' + str(final_error))
                try:
                    self.api.save(self.output / 'results.json', self.report)
                    self.api.save(self.output / 'artifacts.json', dict(Artifacts={name: sha(path.read_bytes())
                        for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}))
                except BaseException:
                    pass
        return self.report['Status'] == PASS


def main(argv=None):
    need(not sys.flags.optimize and __debug__, 'unoptimized interpreter required before admission')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256', 'reference-build',
                 'reference-receipt-sha256', 'reference-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
