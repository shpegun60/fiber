"""Native CM3 O2-lto indexed-archive capture only, never qualification."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
COMMON = HERE.with_name('cm3_lto_transport') / 'probe.py'
COMMON_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
LOADER = HERE.with_name('cm3_final_roots') / 'reference_witness.py'
LOADER_SHA = 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'
PARSER_BINDING = HERE.with_name('classic_final_join') / 'join.py'
PARSER_BINDING_SHA = '2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013'
ARCHIVE_INDICES = (0, 1, 2, 3, 4, 5)
EXPLICIT_INDICES = (8, 7, 6)
SCOPE = 'NATIVE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY'


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-archive: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load(name, path, expected, *, data=None):
    if data is None:
        data = path.read_bytes()
    need(sha(data) == expected, 'fixed helper source: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def archive_records(data):
    """Account for every byte of a regular GNU ar archive and its 32-bit index."""
    need(type(data) is bytes and data.startswith(b'!<arch>\n'), 'regular archive magic; thin archives forbidden')
    offset, raw, long_names = 8, [], None
    while offset < len(data):
        need(offset % 2 == 0 and offset + 60 <= len(data), 'complete aligned ar header')
        header = data[offset:offset + 60]
        need(header[58:] == b'`\n', 'exact ar header terminator')
        fields = [header[a:b].decode('ascii') for a, b in ((0, 16), (16, 28), (28, 34), (34, 40), (40, 48), (48, 58))]
        name, date, uid, gid, mode, size = (value.strip() for value in fields)
        need(re.fullmatch(r'0|[1-9][0-9]*', size) is not None, 'canonical ar payload size')
        size = int(size)
        start, end = offset + 60, offset + 60 + size
        need(end <= len(data), 'ar member payload bounds')
        special = name in ('/', '//')
        need(all(value in ('', '0') if special else value == '0' for value in (date, uid, gid)),
             'deterministic zero timestamp/uid/gid')
        need((special and not mode) or re.fullmatch(r'[0-7]+', mode) is not None, 'octal ar member mode')
        raw.append(dict(RawName=name, HeaderOffset=offset, HeaderSha256=sha(header),
                        DataOffset=start, Size=size, Sha256=sha(data[start:end]), Mode=mode))
        if name == '//':
            need(long_names is None, 'one GNU long-name table')
            long_names = data[start:end]
        offset = end
        if size & 1:
            need(data[offset:offset + 1] == b'\n', 'exact ar odd-payload padding')
            offset += 1
    need(offset == len(data) and raw and raw[0]['RawName'] == '/', 'complete archive with leading symbol index')
    need(sum(row['RawName'] == '/' for row in raw) == 1, 'one 32-bit GNU archive symbol index')
    members = []
    for row in raw:
        name = row['RawName']
        if name in ('/', '//'):
            continue
        if re.fullmatch(r'/[0-9]+', name):
            at = int(name[1:])
            need(long_names is not None and at < len(long_names)
                 and (at == 0 or long_names[at - 1:at] == b'\n'), 'GNU long-name offset boundary')
            end = long_names.find(b'/\n', at)
            need(end > at, 'complete GNU archive long name')
            name = long_names[at:end].decode('ascii')
        else:
            need(name.endswith('/') and not name.startswith('/'), 'bounded GNU archive member name')
            name = name[:-1]
        need(re.fullmatch(r'[A-Za-z0-9_.-]+[.]o', name) is not None, 'plain object member basename')
        members.append(dict(row, Name=name, Ordinal=len(members)))
    need(len(members) == 6 and len({row['Name'] for row in members}) == 6, 'six unique engine/port object members')
    index = raw[0]
    payload = data[index['DataOffset']:index['DataOffset'] + index['Size']]
    need(len(payload) >= 4, 'complete ar index count')
    count = struct.unpack_from('>I', payload)[0]
    need(0 < count and 4 + 4 * count < len(payload), 'bounded nonempty ar symbol index')
    offsets = struct.unpack_from('>' + 'I' * count, payload, 4)
    cursor, names = 4 + 4 * count, []
    for _ in range(count):
        end = payload.find(b'\0', cursor)
        need(end > cursor, 'complete nonempty NUL-terminated ar index name')
        names.append(payload[cursor:end])
        cursor = end + 1
    need(payload[cursor:] == (b'' if cursor % 2 == 0 else b'\0'), 'exact GNU symbol-index alignment padding')
    by_offset = {row['HeaderOffset']: row['Name'] for row in members}
    symbols = []
    for target, name in zip(offsets, names):
        need(target in by_offset, 'ar index target must be an actual object header')
        decoded = name.decode('ascii')
        need(re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', decoded) is not None, 'bounded archive-index symbol')
        symbols.append(dict(Name=decoded, HeaderOffset=target, Member=by_offset[target]))
    need(set(offsets) == set(by_offset), 'every engine/port member represented in actual index')
    return dict(Format='GNU-ar-regular-32bit-index', Size=len(data), Sha256=sha(data),
                Records=raw, Members=members, Index=symbols, DeterministicHeaderMetadata=True)


def extraction_rows(text, archive, members):
    """Capture GNU ld's inclusion table, not per-TU machine ownership."""
    need(type(text) is str and '\0' not in text, 'literal GNU link map text')
    names = list(members)
    need(len(names) == 6 and len(set(names)) == 6, 'exact six archive member names')
    heading = 'Archive member included to satisfy reference by file (symbol)'
    lines = text.splitlines()
    need(lines.count(heading) == 1, 'one concrete archive-inclusion table')
    expected = str(archive).replace('\\', '/').casefold()
    rows, pending, finished = [], None, False
    for line in lines[lines.index(heading) + 1:]:
        if line in ('Merging program properties', 'Discarded input sections', 'Memory Configuration'):
            need(pending is None, 'unfinished wrapped archive inclusion')
            finished = True
            break
        if not line.strip():
            continue
        if pending is not None:
            match = re.fullmatch(r'\s+(.+?)\s+\(([^()\s]+)\)\s*', line)
            need(match is not None, 'wrapped archive reference line')
            source, symbol = match.groups()
            rows.append(dict(Member=pending, ReferenceBy=source, Symbol=symbol))
            pending = None
            continue
        match = re.fullmatch(r'\s*(.+[.]a)\(([^()]+)\)(?:\s+(.+?)\s+\(([^()\s]+)\))?\s*', line)
        need(match is not None, 'unparsed archive-inclusion row')
        path, member, source, symbol = match.groups()
        need(path.replace('\\', '/').casefold() == expected and member in names, 'only the bound archive and member may be extracted')
        if source is None:
            pending = member
        else:
            rows.append(dict(Member=member, ReferenceBy=source, Symbol=symbol))
    need(finished and pending is None and len(rows) == 6
         and {row['Member'] for row in rows} == set(names), 'six actual unique engine/port extraction records')
    return rows


def link_flags(api, artifact, objects, archive, script, output, map, emit):
    need(type(objects) in (list, tuple) and len(objects) == 9
         and len({str(path) for path in objects}) == 9, 'exact nine source objects')
    providers = [*(objects[index] for index in EXPLICIT_INDICES), archive]
    return api.link_flags(artifact, providers, script, output, map, emit)


def extract_member(api, command, ar, plugin, archive, name, directory):
    need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]+[.]o', name) is not None,
         'plain extraction member basename')
    captured = directory / name
    need(not captured.exists() and not captured.is_symlink(), 'fresh extraction file required')
    # Windows ar may translate LF on stdout; extracted files retain binary bytes.
    command([ar, '--plugin', plugin, 'x', archive, name], 'extract archive member ' + name, cwd=directory)
    return api.regular(captured).read_bytes()


def admit_archiver(api, seed, expected_sha256):
    source = api.regular(seed.gcc.with_name('arm-none-eabi-ar.exe'))
    expected = api.digest_text(expected_sha256)
    need(source.is_relative_to(seed.tool_root) and source.parent == seed.gcc.parent,
         'archiver must be the admitted compiler sibling')
    data = seed.closure.read(source, expected)
    info = source.stat()
    return dict(Path=str(source), Sha256=sha(data),
                Identity=dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink),
                Admission='CALLER-SHA256; SAME-TOOLCHAIN-COMPILER-SIBLING',
                PresentInSeedInputs=source in seed.originals)


def probe_type(api):
    class Probe(api.Probe):
        def __init__(self, seed, args):
            super().__init__(seed, args)
            self.archive = None
            self.archive_hash = None
            self.report.update(Scope=SCOPE, Linkage='archive', SeedMode='O2',
                ArchiveExtraction=False, ArchiveExtractionQualified=False, ArchiveCaptureComplete=False,
                Qualification=False, FullABIProof=False, SourceIRProof=False, CanonicalProtocolValidated=False,
                OriginalTranslationUnitOwnership=False, ArchiveMemberIndices=list(ARCHIVE_INDICES),
                ExplicitObjectIndices=list(EXPLICIT_INDICES), NoForcedExtraction=True,
                WeakAliasPrecedenceProven=False)

        def prepare(self):
            need(hasattr(self.seed, 'archive_tool'), 'archiver must be admitted before prepare')
            original = api.regular(self.seed.archive_tool['Path'])
            self.seed.closure.read(original, self.seed.archive_tool['Sha256'])
            super().prepare()
            target = self.tool_root / original.relative_to(self.seed.tool_root)
            raw = self.seed.closure.read(original, self.seed.archive_tool['Sha256'])
            need(not target.exists() or sha(target.read_bytes()) == self.seed.archive_tool['Sha256'],
                 'archiver clone may not replace another captured tool')
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
                         self.seed.archive_tool['Identity'], 'original archiver physical identity')
                need(sha(original.read_bytes()) == self.seed.archive_tool['Sha256'], 'original archiver hash drift')
                info = api.regular(self.tools['ar']).stat()
                need((info.st_dev, info.st_ino, info.st_nlink) == self.archiver_identity, 'archiver clone physical identity')

        def verify_archive(self, stage):
            need(self.archive is not None and self.archive_hash is not None, 'indexed archive must exist')
            need(sha(api.regular(self.archive).read_bytes()) == self.archive_hash, 'archive drift: ' + stage)
            info = self.archive.stat()
            need((info.st_dev, info.st_ino, info.st_nlink) == self.archive_identity, 'archive physical identity: ' + stage)
            for row in self.report['Archive']['Members']:
                obj = self.objects[row['SourceIndex']]
                need(sha(api.regular(obj).read_bytes()) == row['Sha256'], 'archived source-object drift: ' + stage)
            if stage != 'close-inputs':
                self.report.setdefault('ArchiveChecks', []).append(dict(Stage=stage, Status='PASS', Sha256=self.archive_hash))

        def make_archive(self):
            self.verify_objects('before-archive')
            directory = self.output / 'archive'
            directory.mkdir()
            archive = directory / 'libcm3_context.a'
            members = [self.objects[index] for index in ARCHIVE_INDICES]
            need(not archive.exists(), 'fresh regular archive only')
            self.command([self.tools['ar'], '--plugin', self.plugin, 'rcsD', archive, *members], 'create indexed archive')
            raw = api.regular(archive).read_bytes()
            evidence = archive_records(raw)
            api.same([row['Name'] for row in evidence['Members']], [path.name for path in members],
                     'raw archive member order must equal six engine/port providers')
            listing = self.command([self.tools['ar'], '--plugin', self.plugin, 't', archive], 'list archive members')
            (directory / 'members.txt').write_bytes(listing.stdout)
            api.same(listing.stdout.decode('ascii').splitlines(), [path.name for path in members],
                     'actual ar listing must equal exact raw member order')
            index = self.command([self.tools['nm'], '--plugin', self.plugin, '--print-armap', '-P', '-S',
                                  '--defined-only', archive], 'inspect archive index')
            need(index.stdout.strip(), 'nonempty actual plugin-aware archive index inspection')
            (directory / 'index.nm').write_bytes(index.stdout)
            copies = directory / 'members'
            copies.mkdir()
            for source_index, row, obj in zip(ARCHIVE_INDICES, evidence['Members'], members):
                expected = api.regular(obj).read_bytes()
                extracted = extract_member(api, self.command, self.tools['ar'], self.plugin,
                                           archive, row['Name'], copies)
                payload = raw[row['DataOffset']:row['DataOffset'] + row['Size']]
                need(extracted == payload == expected and sha(expected) == self.object_hashes[obj],
                     'complete raw/extracted member bytes must equal freshly compiled object')
                captured = copies / row['Name']
                row.update(SourceIndex=source_index, Object=str(obj), Captured=str(captured),
                           Source=self.report['Sources'][source_index]['Source'])
            evidence.update(Path=str(archive), CreationFlags=['--plugin', str(self.plugin), 'rcsD'],
                MemberCount=6, MemberListing=str(directory / 'members.txt'),
                MemberListingSha256=sha(listing.stdout), IndexInspection=str(directory / 'index.nm'),
                IndexInspectionSha256=sha(index.stdout), RepeatedBuildByteDeterminismProven=False)
            api.save(directory / 'archive.json', evidence)
            self.archive, self.archive_hash = archive, evidence['Sha256']
            info = archive.stat()
            self.archive_identity = (info.st_dev, info.st_ino, info.st_nlink)
            self.report['Archive'] = evidence
            self.verify_objects('after-archive')
            self.verify_archive('after-archive')
            captured = {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()}
            self.seed.closure.tree(directory, captured)

        def build(self):
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
                     'one actual saved machine partition; WPA IR may not substitute')
                machine_bytes = api.regular(machine).read_bytes()
                header = api.require_elf32le(machine_bytes)
                text = self.inspect(machine)
                need(re.search(r'^\s*Type:\s+REL\b', text, re.MULTILINE)
                     and re.search(r'^\s*Machine:\s+ARM\s*$', text, re.MULTILINE), 'actual ARM saved machine ET_REL')
                sections = api.section_records(text)
                api.same([row['Index'] for row in sections], list(range(header['SectionCount'])), 'complete saved-machine sections')
                need(not any(row['Name'].startswith('.gnu.lto_') for row in sections)
                     and any('X' in row['Flags'] and row['Size'] for row in sections), 'real executable saved machine, not GIMPLE')
                symbols = [dict(row, Artifact=str(machine), ArtifactSha256=sha(machine_bytes))
                           for row in api.symbol_records(text, sections)]
                self.inspect(image)
                final_header = api.require_elf32le(api.regular(image).read_bytes(), 'EXEC')
                for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                    need(api.regular(Path(str(image) + suffix)).stat().st_size > 0, 'actual LTO record: ' + suffix)
                map_bytes = api.regular(link_map).read_bytes()
                extraction = extraction_rows(map_bytes.decode('utf-8'), self.archive,
                                             [row['Name'] for row in self.report['Archive']['Members']])
                api.save(directory / 'archive-extraction.json', dict(Archive=str(self.archive),
                    ArchiveSha256=self.archive_hash, Map=str(link_map), MapSha256=sha(map_bytes), Rows=extraction,
                    PerOriginalTranslationUnitMachineOwnership=False, WeakAliasPrecedenceProven=False))
                observed = self.trace_identities(result.stderr)
                captured = {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()}
                self.seed.closure.tree(directory, captured)
                self.report['Links'].append(dict(Kind=kind, Path=str(image), Sha256=sha(image.read_bytes()),
                    Map=str(link_map), MapSha256=sha(map_bytes), Machine=str(machine), MachineSha256=sha(machine_bytes),
                    MachineHeader=header, FinalHeader=final_header, MachineSections=sections, MachineSymbols=symbols,
                    Archive=str(self.archive), ArchiveSha256=self.archive_hash, ArchiveExtractionRows=extraction,
                    LinkInputs=[*(str(self.objects[index]) for index in EXPLICIT_INDICES), str(self.archive)],
                    VerboseObservedTools=observed, EntireDirectoryArtifacts=captured,
                    MachineOwner='ACTUAL-LTRANS-OBJECT; NOT ORIGINAL PORT-TU', OrdinarySymbolPredicatesApplied=False))
                self.report['FinalExecutableLinks'] += 1
                self.report['SavedMachineObjects'] += 1
            self.verify_objects('closing')
            self.verify_archive('closing')
            self.compare_twins()
            self.report['ArchiveCaptureComplete'] = True
            self.complete = True

        def close_inputs(self):
            super().close_inputs()
            if self.archive is not None:
                self.verify_archive('close-inputs')

        def write_seal(self):
            self.report['OutputSealVerified'] = True
            intended = (json.dumps(self.report, indent=2, sort_keys=True, allow_nan=False) + '\n').replace('\n', os.linesep).encode('ascii')
            api.save(self.output / 'results.json', self.report)
            need((self.output / 'results.json').read_bytes() == intended, 'written receipt must equal intended platform bytes')
            expected = {name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items()
                        if name not in ('artifacts.json', 'results.json')}
            expected['results.json'] = sha(intended)
            manifest = dict(Artifacts=expected)
            api.save(self.output / 'artifacts.json', manifest)
            raw = (self.output / 'artifacts.json').read_bytes()
            api.same(json.loads(raw, object_pairs_hook=api.unique_object), manifest, 'written artifact manifest value')
            self.manifest_hash = sha(raw)
            api.same({name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items()
                      if name != 'artifacts.json'}, expected, 'post-manifest complete output closure')
            return expected

    return Probe


def main(argv=None):
    need(not sys.flags.optimize and __debug__, 'unoptimized Python required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256', 'archiver-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    common_bytes = COMMON.read_bytes()
    api = load('cm3_archive_frozen_transport', COMMON, COMMON_SHA, data=common_bytes)
    loader_bytes, binding_bytes = LOADER.read_bytes(), PARSER_BINDING.read_bytes()
    need(sha(loader_bytes) == LOADER_SHA and sha(binding_bytes) == PARSER_BINDING_SHA, 'fixed loader/parser binding sources')
    fixed = {COMMON: common_bytes, LOADER: loader_bytes, PARSER_BINDING: binding_bytes}
    raw_read = Path.read_bytes
    def seed_read(path):
        selected = Path(os.path.abspath(path))
        return fixed[selected] if selected in fixed else raw_read(path)
    with patch.object(Path, 'read_bytes', seed_read):
        seed = api.Seed(args)
    for path, digest in ((COMMON, COMMON_SHA), (LOADER, LOADER_SHA), (PARSER_BINDING, PARSER_BINDING_SHA)):
        seed.closure.read(path, digest)
    seed.archive_tool = admit_archiver(api, seed, args.archiver_sha256)
    script = api.regular(__file__)
    seed.closure.read(script)
    seed.closure.close()
    seed.output.mkdir(parents=True)
    probe = probe_type(api)(seed, args)
    probe.report['CaptureProducer'] = dict(Path=str(script), Sha256=seed.closure.hashes[script])
    probe.report['FrozenCaptureHelpers'] = [dict(Path=str(path), Sha256=digest)
        for path, digest in ((COMMON, COMMON_SHA), (LOADER, LOADER_SHA), (PARSER_BINDING, PARSER_BINDING_SHA))]
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
