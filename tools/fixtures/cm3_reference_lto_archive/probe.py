"""Pinned CM3 O2-lto one-port archive capture, not kernel or root qualification."""

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import struct
import sys
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent
COMMON = FIXTURES / 'cm3_lto_transport/probe.py'
REFERENCE = FIXTURES / 'cm3_reference_lto_transport/probe.py'
ADMISSION = REFERENCE.with_name('admission.py')
NATIVE_ARCHIVE = FIXTURES / 'cm3_lto_archive/probe.py'
LOADER = FIXTURES / 'cm3_final_roots/reference_witness.py'
BINDING = FIXTURES / 'classic_final_join/join.py'
FIXED = {
    COMMON: 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626',
    REFERENCE: '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3',
    ADMISSION: '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC',
    NATIVE_ARCHIVE: 'E2E068AEBEE77E344EA924B08CCE61E0B57D0B5B2F04652D9391680351655FF7',
    LOADER: 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C',
    BINDING: '2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013',
}
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
ARCHIVER_SHA = 'F90685490B207A237A5BD0D32CDC35A8653E682D9313BBE12907712D128299A5'
SCOPE = 'PINNED_REFERENCE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY'
ARCHIVE_INDICES = (0,)
EXPLICIT_INDICES = (3, 2, 1)


def need(condition, message):
    if not condition:
        raise ValueError('cm3-reference-lto-archive: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load(name, path, data):
    need(sha(data) == FIXED[path], 'fixed helper source: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def archive_records(data):
    """One GNU32 index, optional name table and one fixed short-name object."""
    need(type(data) is bytes and data.startswith(b'!<arch>\n'), 'regular GNU archive; thin archives forbidden')
    records, offset = [], 8
    while offset < len(data):
        need(offset % 2 == 0 and offset + 60 <= len(data), 'complete aligned GNU ar header')
        header = data[offset:offset + 60]
        need(header[58:] == b'`\n', 'exact ar header terminator')
        fields = [header[a:b].decode('ascii').strip() for a, b in ((0, 16), (16, 28), (28, 34), (34, 40), (40, 48), (48, 58))]
        name, date, uid, gid, mode, size = fields
        need(re.fullmatch(r'0|[1-9][0-9]*', size) is not None, 'canonical archive payload size')
        size = int(size)
        start, end = offset + 60, offset + 60 + size
        need(end <= len(data), 'complete archive payload')
        special = name in ('/', '//')
        need(all(value in ('', '0') if special else value == '0' for value in (date, uid, gid)), 'deterministic archive metadata')
        need((special and not mode) or re.fullmatch(r'[0-7]+', mode) is not None, 'octal archive member mode')
        records.append(dict(RawName=name, HeaderOffset=offset, HeaderSha256=sha(header), DataOffset=start,
                            Size=size, Sha256=sha(data[start:end]), Mode=mode))
        offset = end
        if size & 1:
            need(data[offset:offset + 1] == b'\n', 'exact GNU member padding')
            offset += 1
    need(offset == len(data) and len(records) in (2, 3) and records[0]['RawName'] == '/',
         'one leading index, optional name table and one actual member only')
    if len(records) == 3:
        need(records[1]['RawName'] == '//', 'only one optional GNU name table')
    row = records[-1]
    need(row['RawName'] == '00-port.o/', 'only the bounded pinned short-name port object')
    member = dict(row, Name='00-port.o', Ordinal=0)
    index = records[0]
    payload = data[index['DataOffset']:index['DataOffset'] + index['Size']]
    need(len(payload) >= 4, 'complete 32-bit GNU index count')
    count = struct.unpack_from('>I', payload)[0]
    need(0 < count and 4 + 4 * count < len(payload), 'bounded nonempty GNU symbol index')
    targets = struct.unpack_from('>' + 'I' * count, payload, 4)
    cursor, symbols = 4 + 4 * count, []
    for target in targets:
        end = payload.find(b'\0', cursor)
        need(end > cursor, 'complete nonempty NUL-terminated symbol name')
        name = payload[cursor:end].decode('ascii')
        need(re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', name) is not None, 'bounded archive-index symbol')
        need(target == member['HeaderOffset'], 'every index entry must identify the sole actual port member')
        symbols.append(dict(Name=name, HeaderOffset=target, Member=member['Name']))
        cursor = end + 1
    need(payload[cursor:] == (b'' if cursor % 2 == 0 else b'\0'), 'exact GNU index alignment NUL')
    return dict(Format='GNU-ar-regular-32bit-index', Size=len(data), Sha256=sha(data), Records=records,
                Members=[member], Index=symbols, DeterministicHeaderMetadata=True)


def extraction_rows(text, archive, members):
    need(type(text) is str and '\0' not in text, 'literal GNU link map')
    need(type(members) in (list, tuple) and list(members) == ['00-port.o'], 'one exact pinned port member')
    heading = 'Archive member included to satisfy reference by file (symbol)'
    lines = text.splitlines()
    need(lines.count(heading) == 1, 'one concrete GNU archive-inclusion table')
    expected = str(archive).replace('\\', '/').casefold()
    rows, pending, finished = [], False, False
    for line in lines[lines.index(heading) + 1:]:
        if line in ('Merging program properties', 'Discarded input sections', 'Memory Configuration'):
            need(not pending, 'unfinished wrapped archive inclusion')
            finished = True
            break
        if not line.strip():
            continue
        if pending:
            match = re.fullmatch(r'\s+(.+?)\s+\(([^()\s]+)\)\s*', line)
            need(match is not None, 'wrapped archive reference row')
            source, symbol = match.groups()
            rows.append(dict(Member='00-port.o', ReferenceBy=source, Symbol=symbol))
            pending = False
            continue
        match = re.fullmatch(r'\s*(.+[.]a)\(([^()]+)\)(?:\s+(.+?)\s+\(([^()\s]+)\))?\s*', line)
        need(match is not None, 'unparsed archive-inclusion row')
        path, member, source, symbol = match.groups()
        need(path.replace('\\', '/').casefold() == expected and member == '00-port.o', 'only the bound archive port may be extracted')
        if source is None:
            pending = True
        else:
            rows.append(dict(Member=member, ReferenceBy=source, Symbol=symbol))
    need(finished and not pending and len(rows) == 1, 'exactly one actual pinned-port extraction')
    return rows


def required_provider_order(objects, archive):
    need(type(objects) in (list, tuple) and len(objects) == 4
         and all(isinstance(path, (str, Path)) for path in (*objects, archive)), 'four exact object paths and archive')
    objects, archive = [str(path) for path in objects], str(archive)
    need(len(set(objects)) == 4 and archive not in objects and all(objects) and archive, 'unique reference/archive provider paths')
    return [objects[3], objects[2], objects[1], archive]


def link_flags(api, artifact, objects, archive, script, output, map, emit):
    return api.link_flags(artifact, required_provider_order(objects, archive), script, output, map, emit)


def probe_type(api, reference_api, archive_api):
    base = reference_api.probe_type(api)
    archive_helpers = archive_api.probe_type(api)

    class Probe(base):
        def __init__(self, seed, args):
            super().__init__(seed, args)
            self.archive = self.archive_hash = None
            self.report.update(Scope=SCOPE, Linkage='archive', SeedMode='O2', ReferenceCommit=PIN,
                ArchiveMemberIndices=list(ARCHIVE_INDICES), ExplicitObjectIndices=list(EXPLICIT_INDICES),
                ArchiveExtraction=False, ArchiveExtractionQualified=False, ArchiveCaptureComplete=False,
                NoForcedExtraction=True, WeakAliasPrecedenceProven=False, Qualification=False, FullABIProof=False,
                SourceIRProof=False, OriginalTranslationUnitOwnership=False, CompleteObjectProof=False,
                Providers='TYPED-FAILSTOP-FIXTURE; NOT A REAL FREERTOS KERNEL',
                ReferenceKernelAvailable=False, SchedulerSemanticsProven=False, CSourceSemanticProof=False,
                HandlerRoutingProven=False, CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
                FinalReferenceParity=False, PolicyEquivalence=False, CpuExecution=False, BoardExecution=False,
                GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)

        def prepare(self):
            need(hasattr(self.seed, 'archive_tool'), 'archiver must be admitted before preparation')
            original = api.regular(self.seed.archive_tool['Path'])
            self.seed.closure.read(original, self.seed.archive_tool['Sha256'])
            super().prepare()
            target = self.tool_root / original.relative_to(self.seed.tool_root)
            raw = self.seed.closure.read(original, self.seed.archive_tool['Sha256'])
            need(not target.exists() or sha(target.read_bytes()) == self.seed.archive_tool['Sha256'],
                 'additional archiver may not replace a different captured tool')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            self.tool_hashes[target] = self.seed.archive_tool['Sha256']
            self.tools['ar'] = target
            info = target.stat()
            self.archiver_identity = (info.st_dev, info.st_ino, info.st_nlink)
            self.report['Archiver'] = dict(self.seed.archive_tool, Captured=str(target),
                CapturedSha256=self.tool_hashes[target], ExplicitPlugin=str(self.plugin),
                PluginSha256=self.tool_hashes[self.plugin])
            self.verify_tools()

        def verify_tools(self):
            super().verify_tools()
            if 'ar' in self.tools:
                original = api.regular(self.seed.archive_tool['Path'])
                info = original.stat()
                api.same(dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink),
                         self.seed.archive_tool['Identity'], 'original archiver identity')
                need(sha(original.read_bytes()) == self.seed.archive_tool['Sha256'], 'original archiver hash drift')
                info = api.regular(self.tools['ar']).stat()
                need((info.st_dev, info.st_ino, info.st_nlink) == self.archiver_identity, 'cloned archiver identity drift')

        def verify_archive(self, stage):
            # This frozen method has no super() or fixed native member count.
            archive_helpers.verify_archive(self, stage)

        def make_archive(self):
            self.verify_objects('before-archive')
            directory = self.output / 'archive'
            directory.mkdir()
            archive, obj = directory / 'libfreertos_cm3.a', self.objects[0]
            need(obj.name == '00-port.o' and not archive.exists(), 'fresh single pinned-port archive')
            self.command([self.tools['ar'], '--plugin', self.plugin, 'rcsD', archive, obj], 'create indexed archive')
            raw = api.regular(archive).read_bytes()
            evidence = archive_records(raw)
            api.same([row['Name'] for row in evidence['Members']], [obj.name], 'one raw pinned-port member')
            listing = self.command([self.tools['ar'], '--plugin', self.plugin, 't', archive], 'list archive members')
            (directory / 'members.txt').write_bytes(listing.stdout)
            api.same(listing.stdout.decode('ascii').splitlines(), [obj.name], 'one actual listed port member')
            index = self.command([self.tools['nm'], '--plugin', self.plugin, '--print-armap', '-P', '-S',
                                  '--defined-only', archive], 'inspect archive index')
            need(index.stdout.strip(), 'nonempty actual plugin-aware symbol-index inspection')
            (directory / 'index.nm').write_bytes(index.stdout)
            copies = directory / 'members'
            copies.mkdir()
            extracted = archive_api.extract_member(api, self.command, self.tools['ar'], self.plugin,
                                                   archive, obj.name, copies)
            row = evidence['Members'][0]
            expected = api.regular(obj).read_bytes()
            payload = raw[row['DataOffset']:row['DataOffset'] + row['Size']]
            need(extracted == payload == expected and sha(expected) == self.object_hashes[obj],
                 'whole raw/extracted member bytes must equal the freshly compiled pinned port')
            row.update(SourceIndex=0, Object=str(obj), Captured=str(copies / obj.name), Source=self.report['Sources'][0]['Source'])
            evidence.update(Path=str(archive), CreationFlags=['--plugin', str(self.plugin), 'rcsD'], MemberCount=1,
                MemberListing=str(directory / 'members.txt'), MemberListingSha256=sha(listing.stdout),
                IndexInspection=str(directory / 'index.nm'), IndexInspectionSha256=sha(index.stdout),
                RepeatedBuildByteDeterminismProven=False)
            api.save(directory / 'archive.json', evidence)
            self.archive, self.archive_hash = archive, evidence['Sha256']
            info = archive.stat()
            self.archive_identity = (info.st_dev, info.st_ino, info.st_nlink)
            self.report['Archive'] = evidence
            self.verify_objects('after-archive')
            self.verify_archive('after-archive')
            self.seed.closure.tree(directory, {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()})

        def build(self):
            need(len(self.seed.sources) == 4 and self.seed.sources[0]['Source'] == str(self.seed.root / 'freertos/portable/GCC/ARM_CM3/port.c'),
                 'exact four reference source providers and pinned port source')
            self.prepare()
            self.compile()
            self.make_archive()
            for kind, emit in (('ordinary', False), ('emit-relocs', True)):
                directory = self.output / kind
                directory.mkdir()
                image, link_map = directory / 'image.elf', directory / 'image.map'
                self.seed.closure.close()
                self.verify_objects('before-link-' + kind)
                self.verify_archive('before-link-' + kind)
                try:
                    result = self.command([self.tools['gcc'], *link_flags(api, self.seed.artifact, self.objects,
                        self.archive, self.seed.script, image, link_map, emit)], 'link ' + kind, cwd=directory)
                finally:
                    self.verify_objects('after-link-' + kind)
                    self.verify_archive('after-link-' + kind)
                machine = api.require_saved_machine_name(directory / 'image.elf.ltrans0.ltrans.o', image)
                need({path for path in directory.iterdir()
                      if re.fullmatch(r'image[.]elf[.]ltrans[0-9]+[.]ltrans[.]o', path.name)} == {machine},
                     'one actual saved machine partition; WPA IR cannot substitute')
                machine_bytes = api.regular(machine).read_bytes()
                header = api.require_elf32le(machine_bytes)
                text = self.inspect(machine)
                need(re.search(r'^\s*Type:\s+REL\b', text, re.MULTILINE)
                     and re.search(r'^\s*Machine:\s+ARM\s*$', text, re.MULTILINE), 'actual ARM saved machine ET_REL')
                sections = api.section_records(text)
                api.same([row['Index'] for row in sections], list(range(header['SectionCount'])), 'complete saved-machine sections')
                need(not any(row['Name'].startswith('.gnu.lto_') for row in sections)
                     and any(row['Size'] and 'X' in row['Flags'] for row in sections), 'real executable saved machine, not GIMPLE')
                symbols = [dict(row, Artifact=str(machine), ArtifactSha256=sha(machine_bytes))
                           for row in reference_api.symbol_records(text, sections)]
                self.inspect(image)
                final_header = api.require_elf32le(api.regular(image).read_bytes(), 'EXEC')
                for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                    need(api.regular(Path(str(image) + suffix)).stat().st_size > 0, 'actual retained LTO record: ' + suffix)
                map_bytes = api.regular(link_map).read_bytes()
                extraction = extraction_rows(map_bytes.decode('utf-8'), self.archive, ['00-port.o'])
                api.save(directory / 'archive-extraction.json', dict(Archive=str(self.archive), ArchiveSha256=self.archive_hash,
                    Map=str(link_map), MapSha256=sha(map_bytes), Rows=extraction,
                    PerOriginalTranslationUnitMachineOwnership=False, WeakAliasPrecedenceProven=False))
                observed = self.trace_identities(result.stderr)
                captured = {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()}
                self.seed.closure.tree(directory, captured)
                self.report['Links'].append(dict(Kind=kind, Path=str(image), Sha256=sha(image.read_bytes()),
                    Map=str(link_map), MapSha256=sha(map_bytes), Machine=str(machine), MachineSha256=sha(machine_bytes),
                    MachineHeader=header, FinalHeader=final_header, MachineSections=sections, MachineSymbols=symbols,
                    Archive=str(self.archive), ArchiveSha256=self.archive_hash, ArchiveExtractionRows=extraction,
                    LinkInputs=required_provider_order(self.objects, self.archive), VerboseObservedTools=observed,
                    EntireDirectoryArtifacts=captured, MachineOwner='ACTUAL-LTRANS-OBJECT; NOT ORIGINAL PORT-TU',
                    OrdinarySymbolPredicatesApplied=False))
                self.report['FinalExecutableLinks'] += 1
                self.report['SavedMachineObjects'] += 1
            self.verify_objects('closing')
            self.verify_archive('closing')
            self.compare_twins()
            need(len(self.report['Commands']) == 41, 'exact forty-one recorded capture commands')
            self.report.update(ReferenceBuilt=True, ArchiveCaptureComplete=True)
            self.complete = True

        def close_inputs(self):
            super().close_inputs()
            if self.archive is not None:
                self.verify_archive('close-inputs')

        def write_seal(self):
            # The shared intended-receipt sealer is independent of source counts.
            return archive_helpers.write_seal(self)

    return Probe


def main(argv=None):
    need(not sys.flags.optimize and __debug__, 'unoptimized Python required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256', 'archiver-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    buffers = {path: path.read_bytes() for path in FIXED}
    for path, digest in FIXED.items():
        need(sha(buffers[path]) == digest, 'fixed helper source: ' + str(path))
    api = load('reference_archive_frozen_transport', COMMON, buffers[COMMON])
    reference_api = load('reference_archive_frozen_reference', REFERENCE, buffers[REFERENCE])
    archive_api = load('reference_archive_frozen_archive_helpers', NATIVE_ARCHIVE, buffers[NATIVE_ARCHIVE])
    admission = load('reference_archive_frozen_admission', ADMISSION, buffers[ADMISSION])
    need(api.digest_text(args.archiver_sha256) == ARCHIVER_SHA, 'fixed caller-authenticated same-toolchain archiver')
    raw_read = Path.read_bytes
    def seed_read(path):
        selected = Path(os.path.abspath(path))
        return buffers[selected] if selected in buffers else raw_read(path)
    with patch.object(Path, 'read_bytes', seed_read):
        seed = admission.Seed(api, args)
    for path, digest in FIXED.items():
        seed.closure.read(path, digest)
    seed.archive_tool = archive_api.admit_archiver(api, seed, args.archiver_sha256)
    script = api.regular(__file__)
    seed.closure.read(script)
    seed.closure.close()
    seed.output.mkdir(parents=True)
    probe = probe_type(api, reference_api, archive_api)(seed, args)
    probe.report['CaptureProducer'] = dict(Path=str(script), Sha256=seed.closure.hashes[script])
    probe.report['FrozenCaptureHelpers'] = [dict(Path=str(path), Sha256=digest) for path, digest in FIXED.items()]
    error = None
    try:
        probe.build()
    except BaseException as failure:
        error = failure
    passed = probe.finish(error)
    print(probe.report['Status'], probe.report.get('Error') or '', str(seed.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
