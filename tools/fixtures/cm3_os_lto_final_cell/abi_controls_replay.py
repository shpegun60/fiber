"""Pure full 41-command Os ABI component replay, never a cell qualifier.

The caller admits exact artifact membership, all immutable read roles, helpers
and the core parser/comparator scope. Manifest absence is not physical absence.
No driver, compiler, module loader, process or filesystem inspection runs here.
"""

import copy
import hashlib
import json
import math
from pathlib import Path
import re
import struct
from types import SimpleNamespace


STATUS = 'CM3-OS-LTO-ABI-CONTROLS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_41_COMMAND_ABI_COMPONENT_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
HELPERS = frozenset(('deps', 'recipes', 'declarations', 'ordinary', 'plan', 'diagnostics',
                     'probes', 'port_runner', 'guard', 'transport'))
CONTROLS = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor',
            'duplicate-svc', 'duplicate-pendsv')
PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
ORDER = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
FIRSTS = (3, 8, 13, 19, 24)
LINKS = (7, 12, 18, 23, 28)
PROBE_FIRSTS = (29, 32, 35, 37, 39)
REJECTS = LINKS + (36, 38, 40)
SLIMS = (5, 10, 15, 21, 26, 31, 34)
NMS = (1, 2, 6, 11, 16, 17, 22, 27)
LABELS = ('link positive', 'definitions original-runtime', 'imports unchanged-boot-v1',
    'discover stale-nvic-expectation', 'compile stale-nvic-expectation', 'inspect slim 06-fiber_port_context_cohort_expectation',
    'imports stale-nvic-expectation', 'link stale-nvic-expectation', 'discover stale-storage-application',
    'compile stale-storage-application', 'inspect slim 07-application', 'imports stale-storage-application',
    'link stale-storage-application', 'discover stale-reverse-anchor', 'compile stale-reverse-anchor',
    'inspect slim 01-context_runtime_state', 'definitions stale-reverse-anchor', 'imports stale-reverse-anchor',
    'link stale-reverse-anchor', 'discover duplicate-svc', 'compile duplicate-svc', 'inspect slim 03-duplicate_svc',
    'definitions duplicate-svc', 'link duplicate-svc', 'discover duplicate-pendsv', 'compile duplicate-pendsv',
    'inspect slim 03-duplicate_pendsv', 'definitions duplicate-pendsv', 'link duplicate-pendsv',
    'discover probe types', 'compile probe types', 'inspect slim types', 'discover probe attributes',
    'compile probe attributes', 'inspect slim attributes', 'discover probe slot-read', 'compile probe slot-read',
    'discover probe slot-write', 'compile probe slot-write', 'discover probe slot-address', 'compile probe slot-address')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
POSITIVE_SCOPE = 'SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_ONLY'
COUNTS = dict(BatchCommands=134, CommandsReplayed=41, SuccessfulCommands=33, IntendedRejections=8,
    IntendedLinkRejections=5, UndeclaredSlotCompiles=3, AcceptedProbes=2, SlimIRInspections=7,
    PluginNMInspections=8, DependencyFiles=20, NativeObjects=9, DiagnosticMachines=3,
    RequiredCellsSatisfied=0)
FACTS = ('ABIControlsReplayed', 'FiveLinkControlsReplayed', 'AcceptedProbeCommandsReplayed',
    'UndeclaredSlotCompilesReplayed', 'RecordedCommandProvenanceReplayed', 'PositiveLinkRevalidated',
    'DeclaredProviderDependenciesReplayed', 'PreprocessedAttributesReplayed',
    'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsExactManifestMembership', 'CallerOwnsCoreImmutableBinding')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'CellContractSatisfied', 'RequiredCellSatisfied', 'CompleteCellProof', 'IsolationReplayed',
    'CanonicalProtocolValidated', 'FinalRootTransferProtocolsValidated', 'FinalReferenceParity',
    'OriginalTranslationUnitOwnership', 'SourceToIRSemanticProof', 'SourceToMachineSemanticProof',
    'AttributeEffectsProven', 'GeneralRegistersOnlyEffectProved', 'PublishedAttributeBundleProven',
    'FullInstructionSemantics', 'LTOTransformationSemanticsProven', 'ProducerCompilersReexecuted',
    'NativeCaptureProvenanceReplayed', 'PhysicalAbsenceChecked', 'OsProcessTraceVerified',
    'CompilerExecuted', 'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
DECLARATION_NONCLAIMS = ('CompilerExecuted', 'DeclarationTypesProven', 'DeclarationAttributesProven',
    'PublishedAttributeBundleProven', 'ProviderObjectIdentityProven', 'ActualDependencyClosureProven',
    'SourceBodyIsolationProven', 'GeneratedSlotIsolationProven', 'ColdAnchorReadProven',
    'FullABIProof', 'FullSemanticABIProof', 'WholeProviderEquivalence', 'InstructionEquivalence',
    'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof', 'KernelRuntimeProof',
    'HandlerRoutingProven', 'CpuExecution', 'BoardExecution', 'HostedCIQualified',
    'ArchiveQualification', 'GlobalFreezeQualified', 'CellContractSatisfied', 'RequiredCellSatisfied')
DIAGNOSTIC_FIELDS = frozenset(('DiagnosticSha256', 'DiagnosticTextSha256', 'DiagnosticNormalization',
    'ClosedGrammarValidated', 'CommandProvenanceVerified', 'PhysicalIdentityChecked', 'FullABIProof',
    'Qualification', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified',
    'RequiredCellSatisfied', 'RequiredCellsSatisfied'))
UNDEFINED_FIELDS = DIAGNOSTIC_FIELDS | frozenset(('Classification', 'MissingSymbols', 'Family',
    'ReferenceCount', 'References', 'FunctionHeaders', 'Linker', 'Machine', 'MachinePathCallerBound', 'LinkerExitRecords'))
DUPLICATE_FIELDS = DIAGNOSTIC_FIELDS | frozenset(('Classification', 'DuplicateSymbols', 'Linker',
    'AddedObject', 'OriginalObject', 'DeclaredAddedSource', 'PluginObjectDiagnostic', 'SourcePathPresent',
    'SourceOwnershipProven', 'LinkerExitRecords'))
FIELDS = frozenset(COUNTS) | frozenset(FACTS + NONCLAIMS) | frozenset(('Status', 'Scope', 'Profile',
    'Mode', 'Linkage', 'LTO', 'Cohort', 'SourceInventorySha256', 'Root', 'SourceRoot', 'CaptureRoot',
    'Inputs', 'ToolBindings', 'NativeObjectBindings', 'ProjectSources', 'ProjectSourceFiles',
    'MutationCopies', 'CommandBindings', 'DependencyBindings', 'AcceptedSaves', 'AbsentOutputs',
    'Controls', 'ABIProbes', 'DeclaredProviders', 'PreprocessedAttributes', 'PositiveAuthority',
    'OriginalPrivate', 'AlternatePrivate', 'AnchorConsumer', 'ReadInputs', 'ReadFiles'))


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-CONTROLS-REPLAY:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    value = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', value) is not None and not any(c in value for c in '\0\r\n'), 'absolute drive path')
    parts = value[3:].replace('\\', '/').split('/')
    need(parts and all(part and part not in ('.', '..') and ':' not in part and part == part.rstrip(' .')
                       for part in parts), 'canonical lexical path')
    return Path(value)


def _relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value
         and not any(c in value for c in '\0\r\n') and all(part and part not in ('.', '..')
         and part == part.rstrip(' .') for part in value.split('/')), 'canonical relative path')
    return value


def _json(raw):
    sha(raw)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def floating(text):
        value = float(text)
        need(math.isfinite(value), 'nonfinite JSON number')
        return value

    def constant(text):
        raise Rejected('REJECT:CM3-OS-LTO-ABI-CONTROLS-REPLAY:nonfinite JSON/' + text)

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=floating, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-CONTROLS-REPLAY:JSON grammar') from error


def _equal(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _identity(record):
    need(type(record) is dict, 'Os metadata')
    for key, value in (('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
                       ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(record.get(key)) is str and record[key] == value, 'Os identity/' + key)
    need(record.get('LTO') is True, 'literal LTO')


def _binary_sections(raw, header):
    """Bind the neutral readelf records to bounded ELF32 section headers/names."""
    count, offset = header['SectionCount'], header['SectionOffset']
    rows = [struct.unpack_from('<10I', raw, offset + index * 40) for index in range(count)]
    strings_index = struct.unpack_from('<H', raw, 50)[0]
    need(0 < strings_index < count and rows[strings_index][1] == 3, 'section-name string table')
    strings = rows[strings_index]
    need(strings[4] + strings[5] <= len(raw), 'bounded section-name bytes')
    names = raw[strings[4]:strings[4] + strings[5]]
    kinds = {0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 8: 'NOBITS',
             9: 'REL', 17: 'GROUP', 0x70000003: 'ARM_ATTRIBUTES'}
    flags = ((1, 'W'), (2, 'A'), (4, 'X'), (16, 'M'), (32, 'S'), (64, 'I'),
             (128, 'L'), (256, 'O'), (512, 'G'), (1024, 'T'), (2048, 'C'), (0x80000000, 'E'))
    result = []
    for index, row in enumerate(rows):
        name, kind, bits, address, position, size = row[:6]
        need(kind in kinds and bits & ~sum(bit for bit, _ in flags) == 0 and name < len(names), 'closed section header')
        end = names.find(b'\0', name)
        need(end >= name and (kind == 8 or position + size <= len(raw)), 'bounded section payload/name')
        try:
            text = names[name:end].decode('ascii')
        except UnicodeError as error:
            raise Rejected('REJECT:CM3-OS-LTO-ABI-CONTROLS-REPLAY:ASCII section name') from error
        result.append(dict(Index=index, Name=text, Type=kinds[kind], Address=address, Offset=position,
                           Size=size, Flags=''.join(letter for bit, letter in flags if bits & bit)))
    need(rows[0] == (0,) * 10, 'null section header')
    return result


def _readelf_metadata(text, raw, header):
    """Bind columns omitted by the neutral section-record projection."""
    lines = text.splitlines()
    need(lines.count('Section Headers:') == 1 and lines.count('Key to Flags:') == 1,
         'one complete readelf section-header block')
    start, end = lines.index('Section Headers:') + 1, lines.index('Key to Flags:')
    need(start < end, 'complete readelf section-header block')
    pattern = (r'\s*\[\s*([0-9]+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)'
               r'\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([A-Za-z]*)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*')
    indices = []
    for line in lines[start:end]:
        if not line.strip() or re.fullmatch(r'\s*\[Nr\]\s+Name\s+Type\s+Addr\s+Off\s+Size\s+ES\s+Flg\s+Lk\s+Inf\s+Al\s*', line):
            continue
        if re.fullmatch(r'\s*\[\s*0\]\s+NULL\s+0+\s+0+\s+0+\s+0+\s+0\s+0\s+0\s*', line):
            index, extra = 0, (0, 0, 0, 0)
        else:
            match = re.fullmatch(pattern, line)
            need(match is not None and 0 < int(match[1]) < header['SectionCount']
                 and match[3] != 'NULL', 'readelf section-row grammar')
            index = int(match[1])
            extra = (int(match[7], 16), int(match[9]), int(match[10]), int(match[11]))
        row = struct.unpack_from('<10I', raw, header['SectionOffset'] + index * 40)
        need(extra == (row[9], row[6], row[7], row[8]), 'readelf/actual section metadata correspondence')
        indices.append(index)
    need(indices == list(range(header['SectionCount'])), 'complete ordered readelf section indices')


class _Reader:
    def __init__(self, batch, root, helpers, read):
        self.root, self.helpers, self.read = root, helpers, read
        self.authority, self.consumed, self.artifacts, self.bound = {}, {}, {}, {}
        need(type(batch.get('InputHashes')) is dict and batch['InputHashes'], 'input authority')
        for name, digest in batch['InputHashes'].items():
            path = _path(name)
            need(path not in self.authority, 'ambiguous input role')
            self.authority[path] = _hash(digest)
        path = root / 'artifacts.json'
        raw = read(path, self.authority.get(path))
        if path in self.authority:
            need(sha(raw) == self.authority[path], 'manifest hash')
        self.consumed[path] = raw
        manifest = _json(raw)
        need(type(manifest) is dict and set(manifest) == {'Artifacts'} and type(manifest['Artifacts']) is dict
             and manifest['Artifacts'], 'admitted exact artifact manifest')
        for name, digest in manifest['Artifacts'].items():
            _relative(name)
            item = root.joinpath(*name.split('/'))
            need(item != path and item not in self.artifacts, 'ambiguous artifact role')
            self.artifacts[item] = _hash(digest)
            if item in self.authority:
                self.same(self.authority[item], digest, 'manifest/input hash')
        self.commands = batch.get('Commands')
        self.same(_json(self.raw(root / 'commands.json', batch.get('CommandsSha256'))), self.commands, 'aggregate command journal')
        need(type(self.commands) is list and len(self.commands) == 134, '134 batch commands')
        self.plan = helpers['recipes'].batch_plan()['Commands'][:41]
        need(len(self.plan) == 41 and tuple(row['Label'] for row in self.plan) == LABELS
             and [row['ExpectedExit'] for row in self.plan] == [1 if i in REJECTS else 0 for i in range(41)], 'full ABI command plan')

    def same(self, left, right, label):
        if type(right) is bytes:
            need(type(left) is bytes and left == right, label)
            return
        try:
            self.helpers['guard']._same(left, right, label)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-ABI-CONTROLS-REPLAY:' + label) from error

    def raw(self, path, expected=None):
        path = _path(path)
        registry = self.artifacts if path.is_relative_to(self.root) else self.authority
        digest = _hash(registry.get(path))
        if expected is not None:
            self.same(digest, _hash(expected), 'explicit role hash')
        raw = self.read(path, digest)
        need(sha(raw) == digest and (path not in self.consumed or self.consumed[path] == raw), 'immutable read bytes')
        self.consumed[path] = raw
        return raw

    def binding(self, path):
        path = _path(path)
        need(path in self.consumed, 'consumed binding')
        return dict(Path=str(path), Sha256=sha(self.consumed[path]))

    def command(self, index, argv):
        need(type(index) is int and 0 <= index < 41 and index not in self.bound, 'one fixed command role')
        row, spec = self.commands[index], self.plan[index]
        need(type(row) is dict, 'command object')
        for key, value in (('Label', spec['Label']), ('Argv', argv), ('Cwd', str(self.root)),
                ('State', 'TERMINAL'), ('ExpectedExit', spec['ExpectedExit']), ('Exit', spec['ExpectedExit']),
                ('Status', 'EXPECTED-NONZERO' if spec['ExpectedExit'] else 'PASS'), ('TimedOut', False)):
            self.same(row.get(key), value, 'command %03d/' % index + key)
        need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0
             and row.get('Error') is None and type(row.get('JournalErrors', [])) is list
             and row.get('JournalErrors', []) == [], 'clean terminal command')
        prefix = 'commands/%03d' % index
        path = self.root / (prefix + '.json')
        self.same(_json(self.raw(path)), row, 'per-command journal %03d' % index)
        streams = []
        for key, suffix in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
            self.same(row.get(key), prefix + suffix, 'fixed command stream')
            streams.append(self.raw(self.root / (prefix + suffix), row.get(key + 'Sha256')))
        self.bound[index] = dict(Index=index, Label=spec['Label'], Argv=list(argv), ExpectedExit=spec['ExpectedExit'],
            Exit=spec['ExpectedExit'], Status=row['Status'], TimedOut=False, Journal=self.binding(path),
            Stdout=self.binding(self.root / (prefix + '.stdout')), Stderr=self.binding(self.root / (prefix + '.stderr')))
        return SimpleNamespace(returncode=row['Exit'], stdout=streams[0], stderr=streams[1], timed_out=False, State='TERMINAL')


def inspect(batch, native, root, core, helpers, read):
    """Replay exactly commands 0..40; only the pre-admitted manifest allows None."""
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == HELPERS, 'exact helpers')
    methods = dict(deps=('parse',), recipes=('batch_plan', 'require_capture_sources', 'compile_flags', 'link_recipe'),
        declarations=('emit_probes', 'inspect_provider_dependencies', 'inspect_preprocessed_attributes'),
        ordinary=('profile_contract',), plan=('control_plan',), diagnostics=('classify_undefined', 'classify_duplicate'),
        probes=('probe_flags', 'classify_undeclared'), port_runner=('parse_ir_definitions',), guard=('_same',),
        transport=('require_elf32le', 'section_records'))
    need(all(callable(getattr(helpers[key], name, None)) for key, names in methods.items() for name in names), 'neutral helper functions')
    need(callable(read) and callable(getattr(core, '_ELF', None))
         and callable(getattr(core, 'compare_load_images', None)), 'immutable core/read')
    _identity(batch);_identity(native)
    need(batch.get('Status') == 'BUILT-PENDING-READER', 'pending original batch')
    helpers['recipes'].require_capture_sources(native)
    watch = _Reader(batch, root, helpers, read)
    source_root = _path(batch.get('SourceSeed')) / 'source'
    capture = _path(batch.get('NativeCapture', {}).get('Build'))
    watch.same(native.get('SeedBuild'), batch.get('SourceSeed'), 'canonical native seed')
    for left, right in ((root, source_root), (root, capture), (source_root, capture)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'disjoint roots')
    receipt = capture / 'results.json'
    native_raw = watch.raw(receipt, batch['NativeCapture'].get('ReceiptSha256'))
    watch.same(_json(native_raw), native, 'reparsed native receipt')
    tools = dict(Gcc=capture / 'toolchain/bin/arm-none-eabi-gcc.exe', Nm=capture / 'toolchain/bin/arm-none-eabi-nm.exe',
        Readelf=capture / 'toolchain/bin/arm-none-eabi-readelf.exe', Ld=capture / 'toolchain/arm-none-eabi/bin/ld.exe',
        Plugin=capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll')
    watch.same(native.get('CapturedCompiler'), str(tools['Gcc']), 'native GCC role')
    need(type(native.get('LTOPlugin')) is dict, 'native plugin identity')
    watch.same(native['LTOPlugin'].get('Path'), str(tools['Plugin']), 'native plugin path')
    for name, path in tools.items():
        watch.raw(path, native['LTOPlugin'].get('Sha256') if name == 'Plugin' else None)
    sources, source_bindings = {}, []
    for path, digest in sorted(watch.authority.items()):
        if path.is_relative_to(source_root):
            name = _relative(path.relative_to(source_root).as_posix())
            sources[name] = watch.raw(path, digest)
            source_bindings.append(dict(Relative=name, **watch.binding(path)))
    providers = helpers['declarations'].inspect_provider_dependencies(sources, native_raw,
        source_root=str(source_root), capture_root=str(capture), ordinary=helpers['ordinary'])
    watch.same(providers, batch.get('DeclaredProviders'), 'recomputed provider declarations')
    objects, native_bindings = [], []
    flags = []
    for index, relative in enumerate(ORDER):
        row = native['Sources'][index]
        obj = capture / 'objects' / ('%02d-' % index + Path(relative).stem + '.o')
        watch.same(row['Source'], str(source_root / relative), 'native ordered source')
        watch.same(row['Object'], str(obj), 'native ordered object')
        watch.raw(obj, row['ObjectSha256'])
        objects.append(obj);native_bindings.append(dict(Index=index, **watch.binding(obj)))
        flags.append(helpers['recipes'].compile_flags(native, index))
    link_recipe = helpers['recipes'].link_recipe(native, objects)
    need(link_recipe[-2:] == ['-o', native['Links'][0]['Path']] and link_recipe.count('-o') == 1, 'native trailing output')
    object_strings = [str(path) for path in objects]
    need([arg for arg in link_recipe[:-2] if arg.endswith('.o')] == object_strings, 'native ordered link objects')
    dependency_bindings, copied, absent, accepted_saves = [], {}, [], {}

    def clean(result, *, output=False):
        need(result.stderr == b'' and (output or result.stdout == b''), 'clean successful streams')

    def absence(path, index):
        need(path not in watch.artifacts and path not in watch.authority, 'failed output present in admitted membership')
        absent.append(dict(CommandIndex=index, Path=str(path), ManifestSha256=sha(watch.consumed[root / 'artifacts.json']),
            NotInAdmittedManifest=True, PhysicalAbsenceChecked=False))

    def link(index, name, selected, failed):
        output, link_map = root / 'links' / name / 'image.elf', root / 'links' / name / 'image.map'
        argv, inserted = [], False
        for arg in link_recipe:
            if arg in object_strings:
                if not inserted:
                    argv.extend(str(path) for path in selected);inserted = True
            elif arg.startswith('-Wl,-Map='):
                argv.append('-Wl,-Map=' + str(link_map))
            elif arg == native['Links'][0]['Path']:
                argv.append(str(output))
            else:
                argv.append(arg)
        need(inserted and argv.count('-o') == 1 and argv[-2:] == ['-o', str(output)]
             and [arg for arg in argv[:-2] if arg.endswith('.o')] == [str(path) for path in selected], 'exact driver link inputs/output')
        result = watch.command(index, argv)
        if failed:
            absence(output, index)
        else:
            clean(result);watch.raw(output)
        partial = str(link_map) if link_map in watch.artifacts else None
        if partial is not None:
            watch.raw(link_map)
        need(failed or partial is not None, 'positive map required')
        return result, output, partial

    def nm(index, obj, definitions=False, prefix=None):
        options = ['-P', '-S', '--defined-only'] if definitions else ['-u']
        result = watch.command(index, [str(tools['Nm']), '--plugin', str(tools['Plugin']), *options, str(obj)])
        clean(result, output=True)
        if definitions:
            rows = helpers['port_runner'].parse_ir_definitions(result.stdout)
            need(rows and len({row['Name'] for row in rows}) == len(rows)
                 and all(type(row['Kind']) is str and re.fullmatch('[A-Za-z]', row['Kind']) is not None
                         and type(row['Value']) is int and row['Value'] == 0 and row['Size'] is None for row in rows), 'slim definition grammar')
            return rows
        names = []
        for line in result.stdout.decode('ascii').splitlines():
            match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line)
            need(match is not None, 'plugin undefined grammar');names.append(match[1])
        need(len(set(names)) == len(names), 'unique plugin imports')
        evidence = dict(Object=str(obj), Imports=names, Plugin=str(tools['Plugin']), RawNmSha256=sha(result.stdout))
        if prefix is not None:
            wanted = [name for name in names if name.startswith(prefix)]
            need(len(wanted) == 1, 'one expected imported identity');evidence['ExpectedImport'] = wanted[0]
        return names, evidence

    def slim(index, obj):
        raw = watch.raw(obj)
        header = helpers['transport'].require_elf32le(raw)
        result = watch.command(index, [str(tools['Readelf']), '-hSW', str(obj)])
        clean(result, output=True)
        text = result.stdout.decode('ascii')
        _readelf_metadata(text, raw, header)
        sections = helpers['transport'].section_records(text)
        watch.same(sections, _binary_sections(raw, header), 'readelf/actual section correspondence')
        need(any(row['Name'].startswith('.gnu.lto_') for row in sections)
             and not any(row['Size'] and 'X' in row['Flags'] for row in sections), 'actual slim IR without executable fallback')
        return dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=sections)

    def compile_pair(first, source, obj, discovery_flags, compile_flags, target, *, project, probe=False):
        discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        result = watch.command(first, [str(tools['Gcc']), *discovery_flags, '-M', '-MF', str(discovery), '-MT', target, str(source)])
        clean(result)
        result = watch.command(first + 1, [str(tools['Gcc']), *compile_flags, '-MD', '-MF', str(actual), '-MT', target,
                                          '-c', str(source), '-o', str(obj)])
        if first + 1 not in REJECTS:
            clean(result)
        before = helpers['deps'].parse(watch.raw(discovery), target=target)
        after = helpers['deps'].parse(watch.raw(actual), target=target)
        need(type(before) is tuple and type(after) is tuple and before == after and before
             and all(isinstance(path, Path) and _path(path) == path for path in before)
             and before == tuple(sorted(set(before))), 'canonical identical discovery/compile dependencies')
        required = {source, project / 'tools/fixtures/classic_final_image/main.h'}
        if probe:
            required.update(source_root / 'context' / name for name in ('context_port_abi.h', 'context_runtime_port_abi.h'))
        need(required <= set(after), 'mandatory same-attempt dependencies')
        dependencies = []
        native_inputs = {_path(path) for path in native['InputHashes']}
        for path in after:
            need(path == source or path.is_relative_to(project) or (not path.is_relative_to(root)
                 and not path.is_relative_to(source_root) and path in native_inputs), 'foreign-stage dependency')
            watch.raw(path);dependencies.append(watch.binding(path))
        dependency_bindings.append(dict(DiscoveryIndex=first, CompileIndex=first + 1, Target=target, Source=str(source),
            Discovery=watch.binding(discovery), Compile=watch.binding(actual), Dependencies=dependencies))
        return result, dependencies

    _, positive_path, positive_map = link(0, 'positive', objects, False)
    original_path = capture / 'ordinary/image.elf'
    watch.same(native['Links'][0]['Path'], str(original_path), 'positive ordinary original')
    original_raw = watch.raw(original_path, native['Links'][0]['Sha256'])
    positive_raw = watch.raw(positive_path)
    readers = [dict(Role=role, **watch.binding(path)) for role, path in (('OriginalELF', original_path), ('ReproducedELF', positive_path))]
    positive = dict(Original=str(original_path), OriginalSha256=sha(original_raw), Replayed=str(positive_path),
        ReplayedSha256=sha(positive_raw), Map=positive_map, MapSha256=sha(watch.consumed[Path(positive_map)]),
        RawElfByteIdentical=original_raw == positive_raw, Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_PENDING',
        LoadImageComparison=None, LoadImageValidated=False, ValidationDeferred=True, LinkCommandIndex=0, ReaderInputs=readers)
    watch.same(positive, batch.get('PositiveAuthority'), 'stored positive comparison target')
    deferred = dict(Kind='OS_POSITIVE_LOAD_IMAGE_REPRODUCTION', Status='PENDING', ValidationDeferred=True,
        Inputs=readers, Map=dict(Role='ReproducedMap', **watch.binding(Path(positive_map))), PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)
    watch.same(deferred, batch.get('ABIControlsDeferredReader'), 'stored pending positive obligation')
    comparison = core.compare_load_images(original_path, positive_path)
    positive.update(LoadImageComparison=copy.deepcopy(comparison), LoadImageValidated=True, ValidationDeferred=False, Scope=POSITIVE_SCOPE)
    runtime = nm(1, objects[3], True)
    private = [row for row in runtime if row['Name'].startswith('fiber_port_context_cohort_')]
    need(len(private) == 1 and private[0]['Kind'] == 'D' and private[0]['Name'].count('_g4_') == 1
         and len(re.findall(r'_g[0-9]+_', private[0]['Name'])) == 1, 'one original private g4 identity')
    original_private = private[0]['Name'];alternate = original_private.replace('_g4_', '_g5_', 1)
    _, anchor_import = nm(2, objects[4], prefix='fiber_internal_runtime_port_abi_')
    need(anchor_import['ExpectedImport'] == ANCHOR, 'unchanged v1 boot consumer')
    plan = helpers['plan'].control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM3', 'arm_cm3')
    need(type(plan) in (tuple, list) and tuple(row['Name'] for row in plan) == CONTROLS
         and tuple(row['Index'] for row in plan) == (6, 7, 1, 3, 3), 'fixed five-control plan')
    expected_names = (alternate, 'fiber_port_storage_cohort_arm_cm3_v999_r0', ANCHOR, 'SVC_Handler', 'PendSV_Handler')
    controls = []
    for position, (spec, first, link_index, expected) in enumerate(zip(plan, FIRSTS, LINKS, expected_names)):
        name, index, added = spec['Name'], spec['Index'], spec['Added']
        directory = root / 'compilations' / name
        deltas, control_flags = [], list(flags[index])
        if added is None:
            project = directory / 'source';changes = {row[0]: row[1:] for row in spec['Mutations']}
            need(len(changes) == len(spec['Mutations']) and set(changes) <= set(sources), 'unique source mutation anchors')
            copies = []
            for relative, raw in sources.items():
                changed = raw
                if relative in changes:
                    before, after = changes[relative]
                    need(type(before) is bytes and before and type(after) is bytes and raw.count(before) == 1, 'one exact source mutation')
                    changed = raw.replace(before, after, 1)
                    deltas.append(dict(Original=str(source_root / relative), Copy=str(project / relative), BeforeSha256=sha(raw),
                        AfterSha256=sha(changed), Before=before.hex(), After=after.hex(), Count=1))
                watch.same(watch.raw(project / relative), changed, 'canonical private source copy')
                copies.append(dict(Relative=relative, **watch.binding(project / relative)))
            need({path for path in watch.artifacts if path.is_relative_to(project)} == {Path(row['Path']) for row in copies}, 'exact private copy membership')
            copied[name] = copies
            source = project / ORDER[index]
            control_flags = [flag.replace(str(source_root), str(project)) for flag in control_flags]
        else:
            need(type(added) is bytes and spec['Mutations'] == (), 'added control source only')
            project = source_root;source = directory / (name.replace('-', '_') + '.c')
            watch.same(watch.raw(source), added, 'exact added handler source')
            deltas.append(dict(Kind='ADDED-CONTROL-TU', Source=str(source), Sha256=sha(added)))
        obj = directory / ('%02d-' % index + source.stem + '.o')
        _, dependencies = compile_pair(first, source, obj, control_flags, control_flags, 'pilot-source-' + str(index), project=project)
        object_raw = watch.raw(obj)
        compiled = dict(Name=name, TemplateIndex=index, OriginalSource=native['Sources'][index]['Source'], Source=str(source),
            SourceSha256=sha(watch.consumed[source]), OriginalObject=str(objects[index]), OriginalObjectSha256=native_bindings[index]['Sha256'],
            Object=str(obj), ObjectSha256=sha(object_raw), Assembly=None,
            ObjectByteIdenticalToOriginal=sha(object_raw) == native_bindings[index]['Sha256'], CompileFlags=control_flags,
            DiscoveryFlags=list(control_flags), Dependencies=dependencies, CompileDependenciesVerified=True,
            DiscoveryDependencyFile=str(obj.with_suffix('.discovery.d')), CompileDependencyFile=str(obj.with_suffix('.compile.d')),
            SourceDeltas=deltas, CommandIndices=[first, first + 1], SaveTemps=False, SemanticProof=False, CpuExecution=False)
        record = dict(Name=name, Expected=expected, Status='INTENDED-LINK-REJECTION-PASS', RequiredCellsSatisfied=0,
                      Compilation=compiled, SlimIR=slim(first + 2, obj))
        selected = list(objects)
        if added is None:
            selected[index] = obj
        else:
            selected.append(obj)
        if index in (6, 7):
            _, evidence = nm(first + 3, obj, prefix='fiber_port_context_cohort_' if index == 6 else 'fiber_port_storage_cohort_')
            need(evidence['ExpectedImport'] == expected, 'intended changed import');record['ImportEvidence'] = evidence
        else:
            definitions = nm(first + 3, obj, True)
            wanted = 'fiber_internal_runtime_port_abi_v2_anchor' if added is None else expected
            matches = [row for row in definitions if row['Name'] == wanted]
            need(len(matches) == 1 and matches[0]['Kind'] == ('D' if added is None else 'T'), 'changed data anchor/strong handler')
            record['ChangedDefinitions'] = definitions
            if added is None:
                need(ANCHOR not in {row['Name'] for row in definitions}, 'changed state does not define v1')
                imports, evidence = nm(first + 4, obj)
                need(ANCHOR not in imports, 'changed state does not import v1')
                record.update(ChangedImports=evidence, ImportEvidence=copy.deepcopy(anchor_import))
        result, output, partial = link(link_index, name, selected, True)
        if added is None:
            machine = Path(str(output) + '.ltrans0.ltrans.o');raw = watch.raw(machine)
            helpers['transport'].require_elf32le(raw)
            image = core._ELF(machine, 'ET_REL')
            need(image.data == raw and image.final is False, 'exact saved native LTRANS parser bytes')
            classification = helpers['diagnostics'].classify_undefined(result, expected, tools['Ld'], machine=machine)
            record['DiagnosticMachine'] = dict(**watch.binding(machine), Kind='ACTUAL_SAVED_ARM_ELF32_REL')
        else:
            classification = helpers['diagnostics'].classify_duplicate(result, expected, tools['Ld'], obj, objects[3], source)
        record.update(Classification=classification, LinkCommandIndex=link_index, FinalImageAbsent=True, PartialMap=partial,
            ConsumedObjects=[dict(Index=i, **watch.binding(path)) for i, path in enumerate(selected)])
        watch.same(_json(watch.raw(root / 'compilations' / name / 'receipt.json')), compiled, 'per-control compilation receipt')
        watch.same(_json(watch.raw(root / 'controls' / (name + '.json'))), record, 'per-control result')
        controls.append(record)
    watch.same(batch.get('Controls'), controls, 'stored five controls comparison')
    need(type(batch.get('Compilations')) is list and len(batch['Compilations']) >= 5, 'recorded compilation catalog')
    watch.same(batch['Compilations'][:5], [row['Compilation'] for row in controls], 'stored compilation catalog comparison')
    generated = helpers['declarations'].emit_probes(ordinary=helpers['ordinary'])
    need(type(generated) is dict and tuple(generated) == PROBES, 'fixed five probe oracles')
    probes = {}
    for position, (name, first) in enumerate(zip(PROBES, PROBE_FIRSTS)):
        oracle = generated[name];accepted = position < 2
        need(oracle['ExpectedCompile'] is accepted, 'fixed probe disposition')
        raw = oracle['Source'].encode('ascii');need(sha(raw) == oracle['SourceSha256'], 'probe oracle hash')
        source = root / 'abi' / name;watch.same(watch.raw(source), raw, 'exact emitted probe source')
        stem = Path(name).stem.replace('_', '-');obj = source.with_name(stem + '.o')
        discovery_flags, compile_flags = helpers['probes'].probe_flags(flags[0], oracle['RequiredCFlags'], accepted)
        result, dependencies = compile_pair(first, source, obj, discovery_flags, compile_flags,
                                            'pilot-source-0', project=source_root, probe=True)
        if accepted:
            classification = dict(AcceptedCompile=True)
            for path in (obj, obj.with_suffix('.i'), obj.with_suffix('.s')):
                watch.raw(path)
            accepted_saves[name] = dict(Preprocessed=watch.binding(obj.with_suffix('.i')), Assembly=watch.binding(obj.with_suffix('.s')))
        else:
            absence(obj, first + 1)
            classification = helpers['probes'].classify_undeclared(result, oracle['DiagnosticIdentifier'],
                object_exists=False, source_path=source, source_bytes=raw)
        record = dict(Source=str(source), SourceSha256=sha(raw), Object=str(obj) if accepted else None,
            Preprocessed=str(obj.with_suffix('.i')) if accepted else None, CompileFlags=compile_flags, DiscoveryFlags=discovery_flags,
            Dependencies=dependencies, CompileDependenciesVerified=True, DiscoveryDependencyFile=str(obj.with_suffix('.discovery.d')),
            CompileDependencyFile=str(obj.with_suffix('.compile.d')), CommandIndices=[first, first + 1], Classification=classification)
        if accepted:
            record['SlimIR'] = slim(first + 2, obj)
        probes[name] = record
    watch.same(batch.get('ABIProbes'), probes, 'stored accepted and rejected probe comparison')
    attributes = helpers['declarations'].inspect_preprocessed_attributes(watch.consumed[root / 'abi/attributes.i'], ordinary=helpers['ordinary'])
    watch.same(attributes, batch.get('PreprocessedAttributes'), 'same accepted CPP declaration comparison')
    for direction, name in (('forward', 'context_port_abi.h'), ('reverse', 'context_runtime_port_abi.h')):
        need(_path(attributes['CanonicalHeaders'][direction]) == source_root / 'context' / name, 'canonical accepted CPP origins')
    need(set(watch.bound) == set(range(41)), 'all forty-one commands replayed')
    inputs = dict(Manifest=watch.binding(root / 'artifacts.json'), NativeReceipt=watch.binding(receipt),
        CommandJournal=watch.binding(root / 'commands.json'), OriginalELF=watch.binding(original_path),
        ReproducedELF=watch.binding(positive_path), ReproducedMap=watch.binding(Path(positive_map)),
        Attributes=watch.binding(root / 'abi/attributes.i'))
    result = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=SOURCE, Root=str(root), SourceRoot=str(source_root), CaptureRoot=str(capture),
        Inputs=inputs, ToolBindings={name: watch.binding(path) for name, path in tools.items()},
        NativeObjectBindings=native_bindings, ProjectSources=source_bindings, ProjectSourceFiles=len(source_bindings),
        MutationCopies=copied, CommandBindings=[watch.bound[i] for i in range(41)], DependencyBindings=dependency_bindings,
        AcceptedSaves=accepted_saves, AbsentOutputs=absent, Controls=controls, ABIProbes=probes,
        DeclaredProviders=copy.deepcopy(providers), PreprocessedAttributes=copy.deepcopy(attributes), PositiveAuthority=positive,
        OriginalPrivate=original_private, AlternatePrivate=alternate, AnchorConsumer=copy.deepcopy(anchor_import),
        ReadInputs=[dict(Path=str(path), Sha256=sha(raw)) for path, raw in sorted(watch.consumed.items())], ReadFiles=len(watch.consumed),
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    return require_result(result)


def require_result(proof):
    """Closed, typed component result checks; not an alternative to replay."""
    need(type(proof) is dict and set(proof) == FIELDS, 'closed component schema')
    _identity(proof)
    need(proof['Status'] == STATUS and proof['Scope'] == SCOPE, 'bounded disposition')
    for key, value in COUNTS.items():
        need(type(proof[key]) is int and proof[key] == value, 'literal count/' + key)
    for key in FACTS:
        need(proof[key] is True, 'component fact/' + key)
    for key in NONCLAIMS:
        need(proof[key] is False, 'component nonclaim/' + key)
    root, source_root, capture = (_path(proof[key]) for key in ('Root', 'SourceRoot', 'CaptureRoot'))
    for left, right in ((root, source_root), (root, capture), (source_root, capture)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'result disjoint roots')
    reads = proof['ReadInputs'];need(type(reads) is list and type(proof['ReadFiles']) is int
        and len(reads) == proof['ReadFiles'] and reads, 'typed read count')
    read_map = {}
    for row in reads:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'typed read row')
        path = _path(row['Path']);need(path not in read_map, 'unique immutable reads');read_map[path] = _hash(row['Sha256'])
    used = set()

    def binding(row, path=None, *, extra=()):
        need(type(row) is dict and set(row) == {'Path', 'Sha256'} | set(extra), 'typed result binding')
        actual = _path(row['Path']);_hash(row['Sha256'])
        need((path is None or row['Path'] == str(path)) and read_map.get(actual) == row['Sha256'], 'result binding/read correspondence')
        used.add(actual)
        return actual

    fixed = dict(Manifest=root / 'artifacts.json', NativeReceipt=capture / 'results.json', CommandJournal=root / 'commands.json',
        OriginalELF=capture / 'ordinary/image.elf', ReproducedELF=root / 'links/positive/image.elf',
        ReproducedMap=root / 'links/positive/image.map', Attributes=root / 'abi/attributes.i')
    need(type(proof['Inputs']) is dict and set(proof['Inputs']) == set(fixed), 'fixed component input roles')
    for key, path in fixed.items():binding(proof['Inputs'][key], path)
    tool_paths = dict(Gcc=capture / 'toolchain/bin/arm-none-eabi-gcc.exe', Nm=capture / 'toolchain/bin/arm-none-eabi-nm.exe',
        Readelf=capture / 'toolchain/bin/arm-none-eabi-readelf.exe', Ld=capture / 'toolchain/arm-none-eabi/bin/ld.exe',
        Plugin=capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll')
    need(type(proof['ToolBindings']) is dict and set(proof['ToolBindings']) == set(tool_paths), 'five tool/plugin roles')
    for key, path in tool_paths.items():binding(proof['ToolBindings'][key], path)
    native = proof['NativeObjectBindings'];need(type(native) is list and len(native) == 9, 'nine native object bindings')
    for index, (row, relative) in enumerate(zip(native, ORDER)):
        need(type(row.get('Index')) is int and row['Index'] == index, 'native index')
        binding(row, capture / 'objects' / ('%02d-' % index + Path(relative).stem + '.o'), extra=('Index',))
    sources = proof['ProjectSources'];need(type(sources) is list and type(proof['ProjectSourceFiles']) is int
        and len(sources) == proof['ProjectSourceFiles'] >= 18, 'source cohort count')
    names = []
    for row in sources:
        relative = _relative(row['Relative']);names.append(relative)
        binding(row, source_root / relative, extra=('Relative',))
    need(len(set(names)) == len(names) and set(ORDER) <= set(names), 'canonical source cohort')
    copies = proof['MutationCopies'];need(type(copies) is dict and set(copies) == set(CONTROLS[:3]), 'three private cohorts')
    for name, rows in copies.items():
        need(type(rows) is list and len(rows) == len(names) and [row['Relative'] for row in rows] == names, 'full copied source cohort')
        for row in rows:binding(row, root / 'compilations' / name / 'source' / row['Relative'], extra=('Relative',))
    commands = proof['CommandBindings'];need(type(commands) is list and len(commands) == 41, 'full command bindings')
    for index, row in enumerate(commands):
        need(type(row) is dict and set(row) == {'Index', 'Label', 'Argv', 'ExpectedExit', 'Exit', 'Status', 'TimedOut',
            'Journal', 'Stdout', 'Stderr'} and type(row['Index']) is int and row['Index'] == index, 'indexed command binding')
        expected = 1 if index in REJECTS else 0
        need(type(row['ExpectedExit']) is int and type(row['Exit']) is int and row['Exit'] == row['ExpectedExit'] == expected
             and row['Status'] == ('EXPECTED-NONZERO' if expected else 'PASS') and row['TimedOut'] is False, 'typed terminal command binding')
        need(type(row['Label']) is str and row['Label'] == LABELS[index] and type(row['Argv']) is list and row['Argv']
             and all(type(arg) is str and arg for arg in row['Argv']), 'literal command argv/label')
        executable = tool_paths['Nm' if index in NMS else 'Readelf' if index in SLIMS else 'Gcc']
        need(row['Argv'][0] == str(executable), 'command tool role')
        for key, suffix in (('Journal', '.json'), ('Stdout', '.stdout'), ('Stderr', '.stderr')):
            binding(row[key], root / ('commands/%03d%s' % (index, suffix)))
    private = proof['OriginalPrivate'];need(type(private) is str and private.startswith('fiber_port_context_cohort_')
        and private.count('_g4_') == 1 and proof['AlternatePrivate'] == private.replace('_g4_', '_g5_', 1), 'derived alternate identity')
    anchor = proof['AnchorConsumer'];need(type(anchor) is dict and anchor.get('ExpectedImport') == ANCHOR
        and anchor.get('Object') == native[4]['Path'] and anchor.get('Plugin') == str(tool_paths['Plugin'])
        and type(anchor.get('Imports')) is list and ANCHOR in anchor['Imports']
        and anchor.get('RawNmSha256') == commands[2]['Stdout']['Sha256'], 'unchanged boot import binding')
    dependencies = proof['DependencyBindings'];need(type(dependencies) is list and len(dependencies) == 10, 'ten dependency pairs')
    firsts = FIRSTS + PROBE_FIRSTS
    for row, first in zip(dependencies, firsts):
        need(type(row) is dict and set(row) == {'DiscoveryIndex', 'CompileIndex', 'Target', 'Source', 'Discovery', 'Compile', 'Dependencies'}
             and type(row['DiscoveryIndex']) is int and row['DiscoveryIndex'] == first
             and type(row['CompileIndex']) is int and row['CompileIndex'] == first + 1, 'dependency command indices')
        source = _path(row['Source']);need(source in read_map and type(row['Target']) is str, 'dependency source/target')
        used.add(source)
        compile_argv = commands[first + 1]['Argv'];need(compile_argv[-2] == '-o' and compile_argv.count('-o') == 1, 'compile final output pair')
        obj = _path(compile_argv[-1]);binding(row['Discovery'], obj.with_suffix('.discovery.d'));binding(row['Compile'], obj.with_suffix('.compile.d'))
        items = row['Dependencies'];need(type(items) is list and items, 'nonempty bound dependencies')
        paths = [binding(item) for item in items];need(paths == sorted(set(paths)) and source in paths, 'canonical dependency list')
    absent = proof['AbsentOutputs'];need(type(absent) is list and len(absent) == 8, 'eight absent output records')
    for row, index in zip(absent, REJECTS):
        argv = commands[index]['Argv']
        need(type(row) is dict and set(row) == {'CommandIndex', 'Path', 'ManifestSha256', 'NotInAdmittedManifest', 'PhysicalAbsenceChecked'}
             and type(row['CommandIndex']) is int and row['CommandIndex'] == index and argv[-2:] == ['-o', row['Path']]
             and argv.count('-o') == 1 and _path(row['Path']) not in read_map
             and row['ManifestSha256'] == proof['Inputs']['Manifest']['Sha256']
             and row['NotInAdmittedManifest'] is True and row['PhysicalAbsenceChecked'] is False, 'manifest-only absence binding')
    controls = proof['Controls'];need(type(controls) is list and len(controls) == 5, 'five complete control results')
    for position, (row, name, first, link_index) in enumerate(zip(controls, CONTROLS, FIRSTS, LINKS)):
        index = (6, 7, 1, 3, 3)[position]
        need(type(row) is dict and row.get('Name') == name and row.get('Status') == 'INTENDED-LINK-REJECTION-PASS'
             and type(row.get('RequiredCellsSatisfied')) is int and row['RequiredCellsSatisfied'] == 0
             and type(row.get('LinkCommandIndex')) is int and row['LinkCommandIndex'] == link_index
             and row.get('FinalImageAbsent') is True, 'bounded control disposition')
        compiled = row.get('Compilation');need(type(compiled) is dict and compiled.get('Name') == name
             and type(compiled.get('TemplateIndex')) is int and compiled['TemplateIndex'] == index
             and _equal(compiled.get('CommandIndices'), [first, first + 1]) and compiled.get('SemanticProof') is False
             and compiled.get('CpuExecution') is False and compiled.get('SaveTemps') is False
             and compiled.get('CompileDependenciesVerified') is True and compiled.get('Assembly') is None, 'control compilation facts')
        source = _path(compiled['Source']);obj = _path(compiled['Object'])
        need(read_map.get(source) == compiled['SourceSha256'] and read_map.get(obj) == compiled['ObjectSha256'], 'control source/object read binding')
        used.update((source, obj))
        ir = row['SlimIR'];need(ir.get('Object') == str(obj) and ir.get('Sha256') == compiled['ObjectSha256'] and ir.get('SlimIR') is True
            and type(ir.get('Sections')) is list and ir['Sections'], 'control slim inspection')
        consumed = row['ConsumedObjects'];wanted = copy.deepcopy(native)
        if position < 3:wanted[index] = dict(Index=index, Path=str(obj), Sha256=compiled['ObjectSha256'])
        else:wanted.append(dict(Index=9, Path=str(obj), Sha256=compiled['ObjectSha256']))
        need(_equal(consumed, wanted), 'exact consumed native/replaced/added object order')
        kind = row['Classification'];need(type(kind) is dict
            and set(kind) == (UNDEFINED_FIELDS if position < 3 else DUPLICATE_FIELDS)
            and kind.get('ClosedGrammarValidated') is True
            and kind.get('Classification') == ('INTENDED-LTO-UNDEFINED' if position < 3 else 'INTENDED-LTO-DUPLICATE')
            and kind.get('DiagnosticSha256') == commands[link_index]['Stderr']['Sha256'], 'closed intended classifier byte binding')
        for key in ('CommandProvenanceVerified', 'PhysicalIdentityChecked', 'FullABIProof', 'Qualification',
                    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
            need(kind.get(key) is False, 'unchanged classifier nonclaim')
        need(type(kind.get('RequiredCellsSatisfied')) is int and kind['RequiredCellsSatisfied'] == 0, 'classifier zero credit')
        expected = (proof['AlternatePrivate'], 'fiber_port_storage_cohort_arm_cm3_v999_r0', ANCHOR, 'SVC_Handler', 'PendSV_Handler')[position]
        need(row['Expected'] == expected, 'intended control symbol')
        if position < 3:
            binding(row['DiagnosticMachine'], root / 'links' / name / 'image.elf.ltrans0.ltrans.o', extra=('Kind',))
            need(row['DiagnosticMachine']['Kind'] == 'ACTUAL_SAVED_ARM_ELF32_REL'
                 and kind.get('MissingSymbols') == [expected] and kind.get('MachinePathCallerBound') is True, 'bound undefined machine')
        else:
            need(kind.get('DuplicateSymbols') == [expected] and kind.get('SourceOwnershipProven') is False, 'duplicate symbol scope')
        if row['PartialMap'] is not None:used.add(_path(row['PartialMap']));need(_path(row['PartialMap']) in read_map, 'partial map read')
        for path in (root / 'compilations' / name / 'receipt.json', root / 'controls' / (name + '.json')):
            need(path in read_map, 'per-control receipt read');used.add(path)
    probes = proof['ABIProbes'];need(type(probes) is dict and set(probes) == set(PROBES), 'five complete probe results')
    need(type(proof['AcceptedSaves']) is dict and set(proof['AcceptedSaves']) == set(PROBES[:2]), 'two accepted saved output sets')
    for position, (name, first) in enumerate(zip(PROBES, PROBE_FIRSTS)):
        row = probes[name];source = root / 'abi' / name;obj = source.with_name(Path(name).stem.replace('_', '-') + '.o')
        need(type(row) is dict and row.get('Source') == str(source) and row.get('SourceSha256') == read_map.get(source)
             and _equal(row.get('CommandIndices'), [first, first + 1]) and row.get('CompileDependenciesVerified') is True, 'probe source/commands')
        used.add(source)
        classification = row['Classification']
        fields = {'AcceptedCompile'} if position < 2 else {'AcceptedCompile', 'UndeclaredIdentifier', 'DiagnosticSha256', 'ObjectAbsent'}
        need(type(classification) is dict and set(classification) == fields
             and classification.get('AcceptedCompile') is (position < 2), 'probe classification')
        if position < 2:
            need(row['Object'] == str(obj) and row['Preprocessed'] == str(obj.with_suffix('.i'))
                 and row['SlimIR']['SlimIR'] is True and row['SlimIR']['Sha256'] == read_map.get(obj), 'accepted slim/save roles')
            used.add(obj)
            saves = proof['AcceptedSaves'][name];need(type(saves) is dict and set(saves) == {'Preprocessed', 'Assembly'}, 'accepted save fields')
            binding(saves['Preprocessed'], obj.with_suffix('.i'));binding(saves['Assembly'], obj.with_suffix('.s'))
        else:
            need(row['Object'] is None and row['Preprocessed'] is None and classification.get('ObjectAbsent') is True
                 and classification.get('UndeclaredIdentifier') == 'fiber_internal_runtime_current_context_slot'
                 and classification.get('DiagnosticSha256') == commands[first + 1]['Stderr']['Sha256'], 'closed absent-slot evidence')
    provider, cpp = proof['DeclaredProviders'], proof['PreprocessedAttributes']
    need(type(provider) is dict and provider.get('DeclaredProviderDependenciesBound') is True
         and provider.get('ReceiptSha256') == proof['Inputs']['NativeReceipt']['Sha256']
         and type(provider.get('Providers')) is list and len(provider['Providers']) == 9, 'replayed provider facts')
    need(type(cpp) is dict and cpp.get('PreprocessedSha256') == proof['Inputs']['Attributes']['Sha256']
         and type(cpp.get('ForwardDeclarations')) is int and cpp['ForwardDeclarations'] == 8
         and type(cpp.get('ReverseDeclarations')) is int and cpp['ReverseDeclarations'] == 4
         and type(cpp.get('Declarations')) is list and len(cpp['Declarations']) == 12
         and cpp.get('PreprocessedNoSanitizeDeclarationsChecked') is True, 'replayed accepted CPP facts')
    for record in (provider, provider.get('SourceInspection'), cpp):
        need(type(record) is dict and record.get('Mode') == 'Os-lto' and record.get('LTO') is True
             and type(record.get('Scope')) is dict
             and set(record['Scope']) == set(DECLARATION_NONCLAIMS) | {'RequiredCellsSatisfied'}, 'bounded declaration helper result')
        need(all(record['Scope'][key] is False for key in DECLARATION_NONCLAIMS)
             and type(record['Scope']['RequiredCellsSatisfied']) is int
             and record['Scope']['RequiredCellsSatisfied'] == 0, 'declaration helper nonclaim')
    positive = proof['PositiveAuthority'];need(type(positive) is dict and set(positive) == {'Original', 'OriginalSha256', 'Replayed',
         'ReplayedSha256', 'Map', 'MapSha256', 'RawElfByteIdentical', 'Scope', 'LoadImageComparison', 'LoadImageValidated',
         'ValidationDeferred', 'LinkCommandIndex', 'ReaderInputs'} and positive.get('Scope') == POSITIVE_SCOPE
         and positive.get('LoadImageValidated') is True and positive.get('ValidationDeferred') is False
         and type(positive.get('LinkCommandIndex')) is int and positive['LinkCommandIndex'] == 0, 'positive link facts')
    need(positive.get('Original') == str(fixed['OriginalELF']) and positive.get('OriginalSha256') == proof['Inputs']['OriginalELF']['Sha256']
         and positive.get('Replayed') == str(fixed['ReproducedELF']) and positive.get('ReplayedSha256') == proof['Inputs']['ReproducedELF']['Sha256']
         and positive.get('Map') == str(fixed['ReproducedMap']) and positive.get('MapSha256') == proof['Inputs']['ReproducedMap']['Sha256']
         and type(positive.get('RawElfByteIdentical')) is bool
         and positive['RawElfByteIdentical'] == (positive['OriginalSha256'] == positive['ReplayedSha256']), 'positive image byte bindings')
    readers = [dict(Role=role, **proof['Inputs'][role]) for role in ('OriginalELF', 'ReproducedELF')]
    need(_equal(positive['ReaderInputs'], readers), 'positive reader input roles')
    comparison = positive.get('LoadImageComparison');need(type(comparison) is dict
         and set(comparison) == {'Entry', 'Identical', 'Segments', 'VectorAddress', 'VectorBytes'} and comparison.get('Identical') is True
         and type(comparison.get('Entry')) is int and comparison['Entry'] > 0
         and type(comparison.get('VectorAddress')) is int and comparison['VectorAddress'] >= 0
         and type(comparison.get('VectorBytes')) is str and re.fullmatch('[0-9a-f]{2048}', comparison['VectorBytes']) is not None
         and type(comparison.get('Segments')) is list and comparison['Segments'], 'positive load image comparison')
    for segment in comparison['Segments']:
        need(type(segment) is dict and set(segment) == {'Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align', 'BytesSha256'}
             and all(type(segment[key]) is int and segment[key] >= 0 for key in
                 ('Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align'))
             and segment['MemorySize'] >= segment['FileSize'], 'typed positive load segment')
        _hash(segment['BytesSha256'])
    need(used == set(read_map), 'exact bounded read-role accounting')
    return proof
