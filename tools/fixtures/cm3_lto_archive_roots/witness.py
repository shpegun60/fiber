"""Independent native CM3 O2-lto archive root replay; no tools or targets."""

import argparse
import ctypes
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
PASS = 'CM3-LTO-ARCHIVE-ROOTS-PASS-NOT-QUALIFIED'
UTILITY = 'tools/fixtures/cm3_lto_transport/probe.py'
LOADER = 'tools/fixtures/cm3_final_roots/reference_witness.py'
PRODUCER = 'tools/fixtures/cm3_lto_archive/probe.py'
CORE = 'tools/fixtures/classic_final_image/elf.py'
ADAPTER = 'tools/fixtures/cm3_lto_roots/native.py'
MUTATIONS = 'tools/fixtures/cm3_lto_roots/mutations.py'
PROTOCOL = 'tools/fixtures/cm3_lto_protocol/protocol.py'
CONTROL = 'tools/fixtures/cm3_lto_protocol/witness.py'
DECODER = 'tools/fixtures/cm55_tfm_parity/elf.py'
CHECKER = 'tools/fixtures/cm3_freeze_parity/check.py'
BINDING = 'tools/fixtures/classic_final_join/join.py'
ARCHIVER_SHA = 'F90685490B207A237A5BD0D32CDC35A8653E682D9313BBE12907712D128299A5'
FIXED = {
    UTILITY: 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626',
    LOADER: 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C',
    PRODUCER: 'E2E068AEBEE77E344EA924B08CCE61E0B57D0B5B2F04652D9391680351655FF7',
    CORE: '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809',
    ADAPTER: 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D',
    MUTATIONS: '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353',
    PROTOCOL: 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419',
    CONTROL: '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    DECODER: '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D',
    CHECKER: 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A',
    BINDING: '2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013',
    'tools/fixtures/cm3_lto_roots/witness.py': '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713',
}
ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-archive-roots: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def same(actual, expected, message):
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
    need(encode(actual) == encode(expected), message)


def require_capture_scope(row):
    need(type(row) is dict, 'literal capture result')
    same([row.get(key) for key in ('Status', 'Scope', 'Profile', 'Mode', 'SeedMode', 'Cohort', 'Linkage',
         'TranslationUnits', 'SlimIRObjects', 'FinalExecutableLinks', 'SavedMachineObjects')],
         ['PASS', 'NATIVE_CM3_O2_LTO_INDEXED_ARCHIVE_CAPTURE_ONLY', 'CM3', 'O2-lto', 'O2',
          'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'archive', 9, 8, 2, 2],
         'exact archive capture scope and counts')
    need(row.get('Error') is None, 'successful capture only')
    for key in ('LTO', 'InputClosureVerified', 'OutputSealVerified', 'ArchiveCaptureComplete', 'NoForcedExtraction',
                'TwinLoadImageCompared', 'TwinLoadImageIdentical', 'TwinAllocatedSectionsIdentical'):
        need(row.get(key) is True, 'literal producer completion: ' + key)
    for key in ('ArchiveExtraction', 'ArchiveExtractionQualified', 'WeakAliasPrecedenceProven', 'Qualification',
                'CanonicalProtocolValidated', 'FinalRootRelocationProof', 'FinalReferenceParity', 'ReferenceBuilt',
                'FullABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
                'CompleteObjectProof', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified',
                'RequiredCellSatisfied'):
        need(row.get(key) is False, 'literal producer nonclaim: ' + key)
    need(type(row.get('RequiredCellsSatisfied')) is int and row['RequiredCellsSatisfied'] == 0, 'no required-cell credit')
    same(row['ArchiveMemberIndices'], [0, 1, 2, 3, 4, 5], 'six ordered archived providers')
    same(row['ExplicitObjectIndices'], [8, 7, 6], 'startup/application/expectation explicit link order')


def required_provider_order(objects, archive):
    need(type(objects) in (list, tuple) and len(objects) == 9
         and all(isinstance(path, (str, Path)) for path in (*objects, archive)), 'nine exact object paths and archive')
    objects, archive = [str(path) for path in objects], str(archive)
    need(len(set(objects)) == 9 and archive not in objects and all(objects) and archive, 'unique object/archive provider paths')
    return [objects[8], objects[7], objects[6], archive]


def require_archive_members(parsed, declared, sources, extracted):
    need(type(parsed) is dict and type(declared) is dict and type(sources) is list and len(sources) == 9
         and type(extracted) is dict, 'raw archive and nine source records required')
    for key in parsed:
        if key != 'Members':
            same(declared[key], parsed[key], 'raw archive metadata/index binding: ' + key)
    need(type(parsed['Members']) is list and type(declared['Members']) is list
         and len(parsed['Members']) == len(declared['Members']) == 6, 'six actual ordered member records')
    same(declared['MemberCount'], 6, 'literal member count')
    names = [row['Name'] for row in parsed['Members']]
    need(len(set(names)) == 6 and set(extracted) == set(names), 'complete unique extracted member names')
    for index, (raw, row) in enumerate(zip(parsed['Members'], declared['Members'])):
        same({key: row[key] for key in raw}, raw, 'complete raw member fields')
        source = sources[index]
        same([row['SourceIndex'], row['Object'], row['Source'], row['Ordinal'], row['Sha256']],
             [index, source['Object'], source['Source'], index, source['ObjectSha256']], 'member/source role binding')
        need(type(extracted[raw['Name']]) is bytes and sha(extracted[raw['Name']]) == raw['Sha256']
             and len(extracted[raw['Name']]) == raw['Size'], 'complete extracted member bytes')


def stable(path):
    return Path(os.path.abspath(os.fspath(path)))


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def interpreter_path():
    if os.name != 'nt':
        return stable(sys.executable)
    buffer = ctypes.create_unicode_buffer(32768)
    function = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    function.argtypes, function.restype = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32), ctypes.c_uint32
    size = function(None, buffer, len(buffer))
    need(0 < size < len(buffer), 'actual interpreter module path')
    return stable(buffer.value)


class Witness:
    def __init__(self, args):
        raw = (ROOT / UTILITY).read_bytes()
        need(sha(raw) == FIXED[UTILITY], 'fixed capture utility source')
        self.api = load('archive_root_capture_utility', ROOT / UTILITY, raw)
        self.watch, self.buffers, self.identities = self.api.Closure(), {}, {}
        self.output = self.api.checked_path(args.output_dir, must_exist=False)
        self.root = self.api.checked_path(args.capture_build)
        self.receipt_sha = self.api.digest_text(args.capture_receipt_sha256)
        self.manifest_sha = self.api.digest_text(args.capture_artifacts_sha256)
        self.result = self.watch.structured(self.root / 'results.json', self.receipt_sha)
        self.artifacts = self.watch.structured(self.root / 'artifacts.json', self.manifest_sha)['Artifacts']
        need(type(self.artifacts) is dict and self.artifacts and self.artifacts.get('results.json') == self.receipt_sha,
             'caller receipt/artifact binding')
        for name, digest in self.artifacts.items():
            self.api.portable_name(name)
            self.api.digest_text(digest)
        self.watch.tree(self.root, dict(self.artifacts, **{'artifacts.json': self.manifest_sha}))
        self._record(self.result)
        inputs = self._json(self.root / 'inputs.json')
        need(type(inputs['Files']) is list and inputs['Files'] and type(inputs['Watched']) is list and inputs['Watched'],
             'nonempty producer input closure')
        for row in inputs['Files']:
            original, captured = self.api.regular(row['Original']), self.api.regular(row['Captured'])
            digest = self.api.digest_text(row['Sha256'])
            raw = self._artifact(captured, digest)
            need(self.watch.read(original, digest) == raw, 'original/captured input bytes')
            if original.suffix == '.py':
                self._buffer(original, raw)
                self._buffer(captured, raw)
        watched = [self.api.regular(row['Path']) for row in inputs['Watched']]
        need(len(watched) == len(set(watched)), 'unique producer watched paths')
        for row in inputs['Watched']:
            self.watch.read(row['Path'], self.api.digest_text(row['Sha256']))
        need(type(self.result['ClosingFilesVerified']) is int
             and self.result['ClosingFilesVerified'] == len(watched), 'literal complete producer closing count')
        for relative, digest in FIXED.items():
            self._buffer(ROOT / relative, self.watch.read(ROOT / relative, digest))
        translated = SimpleNamespace(native_build=self.result['SeedBuild'],
            native_receipt_sha256=self.result['SeedReceiptSha256'],
            native_artifacts_sha256=self.result['SeedArtifactsSha256'], output_dir=str(self.output))
        raw_read = Path.read_bytes
        def seed_read(path):
            key = stable(path)
            if key.suffix == '.py':
                need(key in self.buffers, 'unknown Seed helper source outside admitted immutable buffers')
                return self.buffers[key]
            return raw_read(path)
        with patch.object(Path, 'read_bytes', seed_read):
            self.seed = self.api.Seed(translated)
        for path, digest in self.seed.closure.hashes.items():
            self.watch.read(path, digest)
        for path, raw in self.seed.buffers.items():
            self._buffer(path, raw)
        producer = load('archive_root_fixed_capture', ROOT / PRODUCER, self.buffers[ROOT / PRODUCER])
        self._commands(producer)
        self._buffer(Path(__file__).resolve(), self.watch.read(Path(__file__).resolve()))
        self.roles = self._roles()
        paths = [row['Path'] for row in self.roles.values()]
        need(len(paths) == 7 and all(not path.samefile(other) for index, path in enumerate(paths) for other in paths[:index]),
             'seven physically distinct positive roles')
        interpreter = self.api.regular(interpreter_path())
        self.watch.read(interpreter)
        denied = {ROOT, self.root, self.seed.root, self.seed.inventory, self.seed.tool_root, interpreter.parent,
                  *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
             for path in denied), 'fresh output outside all authenticated input/tool roots')
        for path in self.watch.hashes:
            self.identities[path] = self._physical(path)
        self.close()
        self.expected = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Error=None, Scope='NATIVE_CM3_O2_LTO_ARCHIVE_MACHINE_AND_CANONICAL_PROTOCOL_ONLY',
            Profile='CM3', Mode='O2-lto', Linkage='archive', Cohort=self.api.COHORT, ClosedBodies=0,
            CaptureBuild=str(self.root), CaptureReceiptSha256=self.receipt_sha, CaptureArtifactsSha256=self.manifest_sha,
            CommandsAuthenticated=66, CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
            OrdinaryRootPreservationProven=False, FinalReferenceParity=False, ReferenceBuilt=False,
            ArchiveExtractionQualified=False, WeakAliasPrecedenceProven=False, Qualification=False,
            FullABIProof=False, CompleteObjectProof=False, SourceIRProof=False, SourceToMachineSemanticProof=False,
            OriginalTranslationUnitOwnership=False, PolicyEquivalence=False, CpuExecution=False,
            BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
            NativeCommandsExecuted=0, MutantsReexecuted=False, InputClosureVerified=False, OutputSealVerified=False,
            Interpreter=dict(ModulePath=str(interpreter), Sha256=self.watch.hashes[interpreter], Version=sys.version))

    def _buffer(self, path, data):
        path = stable(path)
        need(path not in self.buffers or self.buffers[path] == data, 'conflicting immutable source bytes')
        self.buffers[path] = data

    def _artifact(self, path, expected=None):
        path = self.api.regular(path)
        need(path.is_relative_to(self.root), 'artifact escaped capture')
        digest = self.artifacts[path.relative_to(self.root).as_posix()]
        need(expected is None or digest == expected, 'artifact manifest/hash binding')
        return self.watch.read(path, digest)

    def _json(self, path):
        return json.loads(self._artifact(path), object_pairs_hook=self.api.unique_object)

    def _physical(self, path):
        info = self.api.regular(path).stat()
        need(info.st_nlink == 1, 'positive/source/private file must have one physical link')
        return info.st_dev, info.st_ino, info.st_nlink

    def _record(self, row):
        require_capture_scope(row)
        self.api.same(row['CaptureProducer'], dict(Path=str(ROOT / PRODUCER), Sha256=FIXED[PRODUCER]), 'fixed archive producer')
        self.api.same(row['FrozenCaptureHelpers'], [dict(Path=str(ROOT / key), Sha256=FIXED[key])
                      for key in (UTILITY, LOADER, BINDING)], 'fixed producer helper sources')

    def _roles(self):
        emit = self.root / 'emit-relocs'
        paths = dict(Machine=emit / 'image.elf.ltrans0.ltrans.o', Final=emit / 'image.elf',
            Disassembly=emit / 'image.elf.dis', LinkMap=emit / 'image.map',
            Startup=Path(self.result['Sources'][8]['Object']), Plain=self.root / 'ordinary/image.elf',
            MachineDisassembly=emit / 'image.elf.ltrans0.ltrans.o.dis')
        return {role: dict(Path=path, Bytes=self._artifact(path), Sha256=self.artifacts[path.relative_to(self.root).as_posix()])
                for role, path in paths.items()}

    def _commands(self, producer):
        root, seed, result = self.root, self.seed, self.result
        records = result['Commands']
        need(type(records) is list and len(records) == 66, 'complete sixty-six-command capture')
        same(self._json(root / 'commands.json'), records, 'complete command sidecar catalog')
        tool_root = root / 'toolchain'
        expected_tools = {tool_root / path.relative_to(seed.tool_root): row['Sha256']
                          for path, row in seed.originals.items() if path.is_relative_to(seed.tool_root)}
        source_ar = self.api.regular(seed.gcc.with_name('arm-none-eabi-ar.exe'))
        ar = tool_root / source_ar.relative_to(seed.tool_root)
        expected_tools[ar] = ARCHIVER_SHA
        self.watch.read(source_ar, ARCHIVER_SHA)
        info = source_ar.stat()
        gcc = tool_root / seed.gcc.relative_to(seed.tool_root)
        plugin = tool_root / seed.plugin.relative_to(seed.tool_root)
        workers = {name: tool_root / path.relative_to(seed.tool_root) for name, path in seed.workers.items()}
        same(result['Archiver'], dict(Path=str(source_ar), Sha256=ARCHIVER_SHA,
             Identity=dict(Device=info.st_dev, FileId=info.st_ino, Links=info.st_nlink),
             Admission='CALLER-SHA256; SAME-TOOLCHAIN-COMPILER-SIBLING', PresentInSeedInputs=source_ar in seed.originals,
             Captured=str(ar), CapturedSha256=ARCHIVER_SHA, ExplicitPlugin=str(plugin),
             PluginSha256=expected_tools[plugin]), 'exact admitted additional archiver/plugin')
        need(set(self.api.files_under(tool_root).values()) == set(expected_tools), 'complete cloned toolchain including additional ar')
        for path, digest in expected_tools.items():
            self._artifact(path, digest)
        same(result['CapturedCompiler'], str(gcc), 'actual cloned compiler identity')
        same(result['ResolvedWorkers'], {name: dict(Path=str(path), Sha256=expected_tools[path])
             for name, path in workers.items()}, 'captured actual workers')
        same(result['LTOPlugin'], dict(Path=str(plugin), Sha256=expected_tools[plugin]), 'captured actual plugin')
        environment = self._json(root / 'environment.json')
        need(type(environment) is dict and all(type(k) is str and type(v) is str for k, v in environment.items()), 'literal environment')
        same(seed.native.process_environment(environment), environment, 'frozen sanitized environment policy')
        need(environment.get('TEMP') == environment.get('TMP') == str(root / 'tmp'), 'private temporary directory')
        search = [str(gcc.parent), *(str(path.parent) for path in workers.values())]
        system = next((value for key, value in environment.items() if key.upper() == 'SYSTEMROOT'), None)
        if system:
            search.append(str(Path(system) / 'System32'))
        need(environment.get('PATH') == os.pathsep.join(dict.fromkeys(search)), 'canonical compiler/worker/System32 PATH')
        expected, stdout_bindings, traces = [], {}, {}

        def command(label, argv, cwd=root, stdout=None):
            index = len(expected)
            expected.append((label, [str(value) for value in argv], str(cwd)))
            if stdout is not None:
                stdout_bindings[index] = stdout

        def inspect(path):
            for tool, flags, suffix in (('readelf', ['-hSWsrA', '-lW'], '.readelf'),
                    ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
                    ('nm', ['--plugin', str(plugin), '-P', '-S', '--defined-only'], '.nm')):
                command('inspect ' + path.name + suffix, [gcc.with_name('arm-none-eabi-' + tool + '.exe'), *flags, path],
                        stdout=Path(str(path) + suffix))

        for name in workers:
            command('resolve ' + name, [gcc, '-print-prog-name=' + name])
        command('resolve LTO plugin', [gcc, '-print-file-name=' + plugin.name])
        need(type(result['Sources']) is list and len(result['Sources']) == 9, 'nine compiled source rows')
        objects = []
        for index, (row, admitted) in enumerate(zip(result['Sources'], seed.sources)):
            source = self.api.regular(admitted['Source'])
            obj = root / 'objects' / ('%02d-' % index + source.stem + '.o')
            dependency = obj.with_suffix('.d')
            flags = admitted['CompileFlags'] if index == 8 else self.api.mode_flags(admitted['CompileFlags'])
            same([row['Source'], row['SourceSha256'], row['CompileFlags'], row['Object'], row['DependencyFile'],
                  row['SlimIR'], row['CompileDependenciesVerified']],
                 [str(source), admitted['SourceSha256'], flags, str(obj), str(dependency), index != 8, True], 'source/recipe/role binding')
            raw = self._artifact(obj, row['ObjectSha256'])
            header = self.api.require_elf32le(raw)
            same(row['ELFHeader'], header, 'actual source ELF header')
            sections = self.api.section_records(self._artifact(Path(str(obj) + '.readelf')).decode('utf-8'))
            same(row['Sections'], sections, 'actual source section records')
            same([item['Index'] for item in sections], list(range(header['SectionCount'])), 'complete source ELF section inventory')
            if index == 8:
                need(not any(item['Name'].startswith('.gnu.lto_') for item in sections), 'native startup only')
            else:
                need(any(item['Name'].startswith('.gnu.lto_') for item in sections)
                     and not any(item['Size'] and 'X' in item['Flags'] for item in sections), 'genuine slim IR without fat fallback')
            dep_bytes = self._artifact(dependency)
            def dependency_text(path, encoding=None, errors=None):
                need(stable(path) == dependency and encoding == 'utf-8' and errors is None, 'only authenticated compile dependency text')
                return dep_bytes.decode('utf-8')
            with patch.object(Path, 'read_text', dependency_text):
                actual = set(seed.native.read_dependencies(dependency))
            declared = {self.api.regular(item['Path']) for item in admitted['Dependencies']}
            declared = {tool_root / path.relative_to(seed.tool_root) if path.is_relative_to(seed.tool_root) else path for path in declared}
            need(actual == declared and all(path in self.watch.hashes for path in actual), 'exact admitted/discovered compile dependencies')
            same(row['ActualCompileDependencies'], [dict(Path=str(path), Sha256=self.watch.hashes[path])
                 for path in sorted(actual)], 'actual dependency bytes')
            command('compile ' + source.name, [gcc, *flags, '-MD', '-MF', dependency,
                    '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj])
            inspect(obj)
            objects.append(obj)

        archive = root / 'archive/libcm3_context.a'
        raw_archive = self._artifact(archive)
        parsed = producer.archive_records(raw_archive)
        evidence = result['Archive']
        same(self._json(root / 'archive/archive.json'), evidence, 'retained archive metadata')
        need(evidence['Path'] == str(archive), 'fixed archive path')
        copies = root / 'archive/members'
        extracted = {obj.name: self._artifact(copies / obj.name) for obj in objects[:6]}
        require_archive_members(parsed, evidence, result['Sources'], extracted)
        need(set(self.api.files_under(copies)) == set(extracted), 'exact six extracted-file members')
        for row, obj in zip(evidence['Members'], objects[:6]):
            same(row['Captured'], str(copies / obj.name), 'binary extraction path')
            need(raw_archive[row['DataOffset']:row['DataOffset'] + row['Size']] == extracted[obj.name] == self._artifact(obj),
                 'archive payload/extracted file/compiled object complete bytes')
        listing, index_text = root / 'archive/members.txt', root / 'archive/index.nm'
        same([evidence['MemberListing'], evidence['MemberListingSha256'], evidence['IndexInspection'], evidence['IndexInspectionSha256']],
             [str(listing), sha(self._artifact(listing)), str(index_text), sha(self._artifact(index_text))], 'archive raw inspection bindings')
        same(self._artifact(listing).decode('ascii').splitlines(), [obj.name for obj in objects[:6]], 'raw ar listing order')
        need(self._artifact(index_text).strip(), 'retained plugin-aware index inspection')
        same(evidence['CreationFlags'], ['--plugin', str(plugin), 'rcsD'], 'deterministic explicit plugin index recipe')
        need(evidence['RepeatedBuildByteDeterminismProven'] is False, 'single capture is not repeated-build determinism')
        command('create indexed archive', [ar, '--plugin', plugin, 'rcsD', archive, *objects[:6]])
        command('list archive members', [ar, '--plugin', plugin, 't', archive], stdout=listing)
        command('inspect archive index', [gcc.with_name('arm-none-eabi-nm.exe'), '--plugin', plugin,
                '--print-armap', '-P', '-S', '--defined-only', archive], stdout=index_text)
        for obj in objects[:6]:
            command('extract archive member ' + obj.name, [ar, '--plugin', plugin, 'x', archive, obj.name], copies)

        same([row['Kind'] for row in result['Links']], ['ordinary', 'emit-relocs'], 'two ordered actual archive twins')
        self.raw_link_records = []
        for kind, emit in (('ordinary', False), ('emit-relocs', True)):
            directory = root / kind
            image, link_map, machine = directory / 'image.elf', directory / 'image.map', directory / 'image.elf.ltrans0.ltrans.o'
            row = result['Links'][0 if kind == 'ordinary' else 1]
            providers = required_provider_order(objects, archive)
            same(row['LinkInputs'], providers, 'actual archive provider order; no direct archived duplicates')
            flags = producer.link_flags(self.api, seed.artifact, objects, archive, seed.script, image, link_map, emit)
            same(flags, self.api.link_flags(seed.artifact, providers, seed.script, image, link_map, emit), 'unchanged exact LTO link flags')
            traces[len(expected)] = row['VerboseObservedTools']
            command('link ' + kind, [gcc, *flags], directory)
            inspect(machine)
            inspect(image)
            same([row['Path'], row['Machine'], row['Map'], row['Archive'], row['ArchiveSha256']],
                 [str(image), str(machine), str(link_map), str(archive), parsed['Sha256']], 'own image/machine/map/archive bindings')
            raw = self._artifact(machine, row['MachineSha256'])
            header = self.api.require_elf32le(raw)
            same(row['MachineHeader'], header, 'actual saved machine ELF32 little endian')
            same(row['FinalHeader'], self.api.require_elf32le(self._artifact(image, row['Sha256']), 'EXEC'), 'actual final ELF32 little endian')
            text = self._artifact(Path(str(machine) + '.readelf')).decode('utf-8')
            sections = self.api.section_records(text)
            same(row['MachineSections'], sections, 'saved machine sections')
            same([item['Index'] for item in sections], list(range(header['SectionCount'])), 'complete saved machine inventory')
            need(not any(item['Name'].startswith('.gnu.lto_') for item in sections)
                 and any(item['Size'] and 'X' in item['Flags'] for item in sections), 'real saved executable machine, not WPA IR')
            same(row['MachineSymbols'], [dict(item, Artifact=str(machine), ArtifactSha256=sha(raw))
                 for item in self.api.symbol_records(text, sections)], 'actual saved machine symbols without ordinary ownership assumptions')
            need({path for path in directory.iterdir() if re.fullmatch(r'image[.]elf[.]ltrans[0-9]+[.]ltrans[.]o', path.name)} == {machine},
                 'one actual saved machine partition')
            map_bytes = self._artifact(link_map, row['MapSha256'])
            extraction = producer.extraction_rows(map_bytes.decode('utf-8'), archive, [obj.name for obj in objects[:6]])
            same(row['ArchiveExtractionRows'], extraction, 'all actual archive extraction rows')
            same(self._json(directory / 'archive-extraction.json'), dict(Archive=str(archive), ArchiveSha256=parsed['Sha256'],
                 Map=str(link_map), MapSha256=sha(map_bytes), Rows=extraction,
                 PerOriginalTranslationUnitMachineOwnership=False, WeakAliasPrecedenceProven=False), 'raw map extraction evidence')
            retained = []
            for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                path = Path(str(image) + suffix)
                data = self._artifact(path)
                need(data, 'complete nonempty raw link record: ' + suffix)
                retained.append(dict(Path=str(path), Sha256=sha(data), Bytes=len(data)))
            self.raw_link_records.append(dict(Kind=kind, Records=retained, ArchiveExtractionRows=extraction))
            same({name: sha(self._artifact(path)) for name, path in self.api.files_under(directory).items()},
                 row['EntireDirectoryArtifacts'], 'complete own link-temp artifact tree')
        need(len(expected) == len(records) == 66, 'exact reconstructed command count')
        context = SimpleNamespace(tool_hashes=expected_tools, tools={'gcc': gcc}, plugin=plugin, workers=workers)
        for index, (row, (label, argv, cwd)) in enumerate(zip(records, expected)):
            same([row['Label'], row['Argv'], row['Cwd']], [label, argv, cwd], 'full ordered command binding')
            need(row['Status'] == 'PASS' and type(row['Exit']) is int and row['Exit'] == 0
                 and row['TimedOut'] is False and row.get('Error') is None, 'successful literal terminal command')
            need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0, 'finite nonnegative command duration')
            target = root / ('command-%04d.json' % index)
            same(self._json(target), row, 'terminal command sidecar')
            stdout, stderr = self._artifact(target.with_suffix('.stdout')), self._artifact(target.with_suffix('.stderr'))
            if index in stdout_bindings:
                need(stdout == self._artifact(stdout_bindings[index]), 'raw inspector stream/artifact equality')
            elif index < 7:
                resolved = list(workers.values())[index] if index < 6 else plugin
                need(self.api.regular(stdout.decode('utf-8').strip()) == resolved, 'actual worker/plugin resolution')
            if index in traces:
                same(self.api.Probe.trace_identities(context, stderr), traces[index], 'actual verbose tools/plugin identity')
        same(result['ObjectChecks'], [dict(Stage=stage, Status='PASS') for stage in ('after-compile', 'before-archive', 'after-archive',
             'before-link-ordinary', 'after-link-ordinary', 'before-link-emit-relocs', 'after-link-emit-relocs', 'closing')], 'exact object checkpoints')
        same(result['ArchiveChecks'], [dict(Stage=stage, Status='PASS', Sha256=parsed['Sha256']) for stage in ('after-archive',
             'before-link-ordinary', 'after-link-ordinary', 'before-link-emit-relocs', 'after-link-emit-relocs', 'closing')], 'exact archive freeze checkpoints')

    def close(self):
        self.watch.close()
        self.seed.closure.close()
        for path, identity in self.identities.items():
            need(self._physical(path) == identity, 'physical input identity changed: ' + str(path))

    def declare(self, path):
        path = stable(path)
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected, 'duplicate private output declaration')
        self.expected.add(name)

    def _bind_control_files(self, controls, roles):
        for control in controls:
            same([row['Role'] for row in control['Files']], list(roles), 'complete ordered private control roles')
            directory = self.output / 'controls' / ('protocol-mutants' if len(roles) == 6 else 'mutants') / control['Name']
            wanted = {directory / (role + self.roles[role]['Path'].suffix) for role in roles}
            need(set(self.api.files_under(directory).values()) == wanted, 'exact private case membership')
            for row in control['Files']:
                path = self.api.regular(row['Path'])
                need(path == directory / (row['Role'] + self.roles[row['Role']]['Path'].suffix)
                     and path.relative_to(self.output).as_posix() in self.expected, 'fixed private case role/path')
                self.watch.read(path, self.api.digest_text(row['Sha256']))
                identity = self._physical(path)
                if 'PhysicalIdentity' in row:
                    value = row['PhysicalIdentity']
                    need(type(value) is dict and all(type(value.get(key)) is int for key in ('Device', 'FileId', 'Links'))
                         and tuple(value[key] for key in ('Device', 'FileId', 'Links')) == identity, 'control physical identity')
                need(path not in self.identities or self.identities[path] == identity, 'private control identity drift')
                self.identities[path] = identity

    def _read_roots(self):
        loader = load('archive_root_immutable_loader', ROOT / LOADER, self.buffers[ROOT / LOADER])
        graph = loader.FrozenSources(self.buffers)
        package, modules = self.seed.root / 'python/elftools', {}
        for path in self.buffers:
            if path.is_relative_to(package):
                parts = list(path.relative_to(package.parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'unique captured parser module')
                modules[name] = path, is_package
        need('elftools' in modules and not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
             'complete initially unimported captured parser package')

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
        for role, row in self.roles.items():
            path = row['Path']
            target = self.output / 'binary-inputs' / (role + path.suffix)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(row['Bytes'])
            self.watch.read(target, row['Sha256'])
            snapshots[stable(path)] = row['Bytes']
            binary_copies.append(dict(Role=role, Original=str(path), Captured=str(target), Sha256=row['Sha256']))
        twin_path = self.root / 'load-image.json'
        need(self.result['TwinLoadImagesPath'] == str(twin_path), 'fixed captured twin-evidence path')
        snapshots[stable(twin_path)] = self._artifact(twin_path, self.result['TwinLoadImagesSha256'])
        catalog = graph.load('archive_root_fixed_control_catalog', ROOT / MUTATIONS)
        need(type(catalog.CASES) is tuple and len(catalog.CASES) == 16, 'fixed sixteen-case catalog')
        transport_roles = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')
        canonical_roles = (*transport_roles, 'MachineDisassembly')
        mutable = set()
        for name, reason in catalog.CASES:
            for role in transport_roles:
                path = self.output / 'controls/mutants' / name / (role + self.roles[role]['Path'].suffix)
                self.declare(path)
                mutable.add(stable(path))
        for role in canonical_roles:
            path = self.output / 'controls/protocol-mutants/coherent-svc-immediate' / (role + self.roles[role]['Path'].suffix)
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
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text), \
                    patch('subprocess.Popen', side_effect=AssertionError('archive witness cannot execute processes')), \
                    patch('os.system', side_effect=AssertionError('archive witness cannot execute shell commands')):
                core = graph.load('archive_root_core', ROOT / CORE)
                adapter = graph.load('archive_root_transport', ROOT / ADAPTER)
                decoder = graph.load('archive_root_decoder', ROOT / DECODER)
                checker = graph.load('archive_root_checker', ROOT / CHECKER)
                protocol = graph.load('archive_root_protocol', ROOT / PROTOCOL)
                roles = {role: row['Path'] for role, row in self.roles.items()}
                image = adapter.NativeCM3LTOImage(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                    provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
                    link_map=roles['LinkMap'])
                roots = [image.function(name) for name in adapter.ROOTS]
                need(len(roots) == 3 and all(row['GeneratedMachineBoundRootPreservation'] is True
                     and row['CanonicalProtocolValidated'] is False for row in roots), 'three complete emitted transport roots')
                decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
                proof = protocol.check_native(decoded, image, checker)
                need(proof['Status'] == 'NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED'
                     and proof['CanonicalProtocolValidated'] is True
                     and type(proof['ClosedBodies']) is int and proof['ClosedBodies'] == 3, 'three complete native canonical protocols')
                same([row['Name'] for row in proof['Roots']], list(checker._NATIVE), 'complete ordered canonical root evidence')
                same([row['Name'] for row in proof['MatchEvidence']], list(checker._NATIVE), 'complete ordered canonical matches')
                need(all(type(row['TailNops']) is int and row['TailNops'] == 0 for row in proof['MatchEvidence']), 'exact zero O2-lto tail NOPs')
                same({row['Name']: row['TransportRecord'] for row in proof['Roots']},
                     {row['Name']: row for row in roots}, 'same raw transport roots and separately labelled canonical projection')
                twins = core.compare_load_images(roles['Plain'], roles['Final'])
                need(twins.get('Identical') is True, 'fresh own archive twins must match structurally')
                same(twins, self.result['TwinLoadImages'], 'captured/fresh structured twin equality')
                same(json.loads(snapshots[stable(twin_path)], object_pairs_hook=self.api.unique_object), twins, 'actual saved twin evidence')
                cases = catalog.run_cases(core, adapter, image, {role: roles[role] for role in transport_roles}, self.output / 'controls')
                same([(row['Name'], row['Expected']) for row in cases], list(catalog.CASES), 'complete ordered fixed negative catalog')
                need(all(row['Status'] == 'PASS' and row['ImmutableInputBuffersConsumed'] is True and row['Edits']
                     and type(row['ClosingFilesVerified']) is int and row['ClosingFilesVerified'] == 5 for row in cases),
                     'all sixteen actual private transport controls must reject')
                self._bind_control_files(cases, transport_roles)
                control_module = graph.load('archive_root_fixed_svc_control', ROOT / CONTROL)
                control_type = control_module.witness_type()
                def declared(path):
                    need(stable(path).relative_to(self.output).as_posix() in self.expected, 'predetermined canonical control output')
                facade = SimpleNamespace(output=self.output / 'controls', watch=self.watch, report={}, declare_output=declared)
                control_type._constant_control(facade, core, adapter, decoder, checker, protocol,
                    {role: roles[role] for role in canonical_roles}, snapshots, image)
                canonical = facade.report['ProtocolControls']
                need(len(canonical) == 1 and canonical[0]['Name'] == 'coherent-svc-immediate'
                     and canonical[0]['Status'] == 'PASS' and canonical[0]['TransportPreservationAccepted'] is True
                     and canonical[0]['ImmutableInputBuffersConsumed'] is True
                     and type(canonical[0]['ClosingFilesVerified']) is int and canonical[0]['ClosingFilesVerified'] == 6,
                     'coherent SVC drift must preserve transport and fail the canonical protocol')
                self._bind_control_files(canonical, canonical_roles)
            self.report.update(Roots=roots, ProtocolProof=proof, ProtocolControls=canonical, Controls=cases,
                TwinLoadImages=twins, TwinLoadImageCompared=True, TwinLoadImageIdentical=True,
                CapturedSourceBuffers=source_copies, BinaryInputs=binary_copies, ExecutedSourceBuffers=graph.executed,
                RawLinkRecords=self.raw_link_records, ArchiveCaptureEvidence=self.result['Archive'],
                ImmutableInputsConsumed=True, TransportControlsExecuted=16, CanonicalControlsExecuted=1, MutantsReexecuted=True)
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
        need((self.output / 'results.json').read_bytes() == intended, 'written receipt differs from intended serialized bytes')
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name not in ('artifacts.json', 'results.json')}
        self.sealed['results.json'] = sha(intended)
        if success:
            need(set(self.sealed) == self.expected - {'artifacts.json'}, 'all planned output artifacts must exist')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        raw = (self.output / 'artifacts.json').read_bytes()
        same(json.loads(raw, object_pairs_hook=self.api.unique_object), manifest, 'written manifest must equal intended hash map')
        self.output_manifest_sha = sha(raw)
        same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
              if name != 'artifacts.json'}, self.sealed, 'post-manifest complete membership/hash closure')

    def _fail(self, error):
        self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; ' + str(error),
            CanonicalProtocolValidated=False, FinalRootRelocationProof=False, InputClosureVerified=False,
            OutputSealVerified=False, ImmutableInputsConsumed=False, MutantsReexecuted=False, ClosedBodies=0)

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read_roots()
            self.close()
            self.report.update(Status=PASS, CanonicalProtocolValidated=True, FinalRootRelocationProof=True,
                               ClosedBodies=3, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes))
        except BaseException as error:
            self._fail(type(error).__name__ + ': ' + str(error))
        self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.close()
            same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                  if name != 'artifacts.json'}, self.sealed, 'late complete output closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.output_manifest_sha, 'late manifest bytes changed')
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
    need(not sys.flags.optimize and __debug__, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
