"""Immutable replay of the twelve recorded Os isolation commands, not a qualifier.

The caller admits the sealed batch/native scope, frozen helpers and core reader.
Only the supplied read callback touches bytes. Slot protocols remain delegated
to the separately authenticated Os adapter; no O2 driver or verdict is used.
"""

import copy
import hashlib
import math
from pathlib import Path
import re


STATUS = 'CM3-OS-LTO-ISOLATION-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_12_COMMAND_ISOLATION_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
HELPERS = frozenset(('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport',
                     'controls_replay', 'isolation_slots', 'os_slot', 'neutral_slot'))
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
ORDER = COMMON + ('fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
OWNERSHIP = COMMON + ('tools/runtime_sources.json',)
LABELS = tuple(label for name in COMMON for label in (
    'discover isolated ' + Path(name).stem, 'compile isolated ' + Path(name).stem,
    'inspect slim ' + Path(name).stem)) + (
    'link isolated-common', 'link isolated-common-emit', 'disassemble isolated-common-emit')
ROLE_NAMES = ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine', 'OriginalAssembly',
    'OriginalDisassembly', 'OriginalMap', 'IsolatedOrdinaryELF', 'IsolatedOrdinaryMap',
    'IsolatedEmitELF', 'IsolatedMachine', 'IsolatedAssembly', 'IsolatedMap',
    'IsolatedDisassembly', 'StartupObject', 'PortSource', 'IsolatedIR0', 'IsolatedIR1', 'IsolatedIR2')
COMPARISONS = (('OriginalToIsolated', 'OriginalOrdinaryELF', 'IsolatedOrdinaryELF'),
    ('IsolatedTwins', 'IsolatedOrdinaryELF', 'IsolatedEmitELF'),
    ('OriginalTwins', 'OriginalOrdinaryELF', 'OriginalEmitELF'))
COUNTS = dict(First=41, Stop=53, BatchCommands=134, CommandsReplayed=12, SuccessfulCommands=12,
    IsolatedCommonObjects=3, OriginalObjectsUnchanged=6, DependencyFiles=6, SlimIRInspections=3,
    OwnershipSources=4, DeferredInputs=18, LoadComparisons=3, SlotImages=2, RequiredCellsSatisfied=0)
FACTS = ('IsolationReplayed', 'RecordedCommandProvenanceReplayed', 'SourceOwnershipReplayed',
    'ConsumedDependenciesReplayed', 'ObjectReplacementReplayed', 'PositiveLinkRevalidated',
    'BoundedSlotProtocolsReplayed', 'CallerOwnsAdmissionAndImmutableScope',
    'CallerOwnsExactManifestMembership', 'CallerOwnsCoreImmutableBinding', 'CallerOwnsOriginalDumpJournalBinding')
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'CompleteCellProof',
    'FullABIProof', 'FullSemanticABIProof', 'CpuFreeCommonValidated', 'WholeSlotAccessIsolation',
    'IRImportClosureValidated', 'RawIRIdentityClaim', 'SourceToIRSemanticProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'FullInstructionSemantics',
    'CompleteHandlerBodiesValidated', 'CanonicalProtocolValidated', 'FinalRootTransferProtocolsValidated',
    'FinalReferenceParity', 'AttributeEffectsProven', 'ProducerCompilersReexecuted',
    'NativeCaptureProvenanceReplayed', 'OsProcessTraceVerified', 'CompilerExecuted',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
FIELDS = frozenset(COUNTS) | frozenset(FACTS + NONCLAIMS) | frozenset(('Status', 'Scope', 'Profile',
    'Mode', 'Linkage', 'LTO', 'Cohort', 'SourceInventorySha256', 'Root', 'SourceRoot', 'CaptureRoot',
    'AuthorityInputs', 'Inputs', 'ToolBindings', 'NativeObjectBindings', 'CommandBindings',
    'SourceOwnership', 'SourceOwnershipInputs', 'IsolatedCommon', 'DependencyBindings',
    'IsolatedLinkedObjects', 'LoadImageComparisons', 'SlotProofs', 'OriginalDumps', 'ReadInputs', 'ReadFiles'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-ISOLATION-REPLAY:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _same(left, right):
    if type(left) is not type(right):
        return False
    if type(right) is dict:
        return set(left) == set(right) and all(_same(left[k], right[k]) for k in right)
    if type(right) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    value = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', value) is not None and not any(c in value for c in '\0\r\n'), 'absolute drive path')
    parts = value[3:].replace('\\', '/').split('/')
    need(parts and all(p and p not in ('.', '..') and ':' not in p and p == p.rstrip(' .') for p in parts), 'canonical lexical path')
    return Path(value)


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _paths(root, source_root, capture):
    original = capture / 'emit-relocs/image.elf'
    ordinary = root / 'links/isolated-common/image.elf'
    emitted = root / 'links/isolated-common-emit/image.elf'
    return dict(zip(ROLE_NAMES, (capture / 'ordinary/image.elf', original, Path(str(original) + '.ltrans0.ltrans.o'),
        Path(str(original) + '.ltrans0.ltrans.s'), Path(str(original) + '.dis'), original.with_suffix('.map'),
        ordinary, ordinary.with_suffix('.map'), emitted, Path(str(emitted) + '.ltrans0.ltrans.o'),
        Path(str(emitted) + '.ltrans0.ltrans.s'), emitted.with_suffix('.map'), Path(str(emitted) + '.dis'),
        capture / 'objects/08-startup.o', source_root / ORDER[3],
        *(root / 'isolated-common' / (Path(name).stem + '.o') for name in COMMON))))


def _build_record():
    return dict(Status='BUILT-PENDING-READER', Scope='NATIVE_CM3_OS_LTO_ISOLATION_BUILD_ONLY_PENDING_READER',
        Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, First=41, Stop=53, Commands=12,
        IsolatedCommonObjects=3, OriginalObjectsUnchanged=6, DeferredReaderRequired=True,
        CpuFreeCommonValidated=False, WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False,
        RawIRIdentityClaim=False, Qualification=False, CellContractSatisfied=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False,
        SourceToMachineSemanticProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)


def _deferred(inputs):
    return dict(Status='PENDING', Scope='OS_ISOLATED_LOAD_IMAGES_SLOT_AND_PROVIDER_REPLAY_REQUIRED',
        ValidationDeferred=True, Inputs=[dict(Role=name, **inputs[name]) for name in ROLE_NAMES],
        LoadImageComparisons=[dict(Name=name, Left=left, Right=right) for name, left, right in COMPARISONS],
        SlotProofs=[dict(Kind=kind, Machine=prefix + 'Machine', Final=prefix + 'EmitELF',
            Assembly=prefix + 'Assembly', Disassembly=prefix + 'Disassembly', Map=prefix + 'Map',
            PortSource='PortSource', Startup='StartupObject') for kind, prefix in
            (('Original', 'Original'), ('Isolated', 'Isolated'))],
        GeneratedCommonProviderValidationRequired=True, IRImportClosureValidated=False,
        RawIRIdentityClaim=False, WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)


def _command(watch, primitive, index, argv):
    need(type(index) is int and 41 <= index < 53 and index not in watch.bound, 'one fixed isolation command')
    label = LABELS[index - 41]
    row = watch.commands[index]
    need(type(row) is dict, 'command object')
    for key, value in (('Label', label), ('Argv', argv), ('Cwd', str(watch.root)), ('State', 'TERMINAL'),
            ('ExpectedExit', 0), ('Exit', 0), ('Status', 'PASS'), ('TimedOut', False)):
        watch.same(row.get(key), value, 'command %03d/' % index + key)
    need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0
         and row.get('Error') is None and type(row.get('JournalErrors', [])) is list
         and row.get('JournalErrors', []) == [], 'clean terminal command')
    prefix = 'commands/%03d' % index
    journal = watch.root / (prefix + '.json')
    watch.same(primitive._json(watch.raw(journal)), row, 'per-command journal %03d' % index)
    streams = []
    for key, extension in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
        watch.same(row.get(key), prefix + extension, 'fixed isolation stream')
        streams.append(watch.raw(watch.root / (prefix + extension), row.get(key + 'Sha256')))
    need(streams[1] == b'' and (bool(streams[0]) if index in (43, 46, 49, 52) else streams[0] == b''), 'clean successful command streams')
    watch.bound[index] = dict(Index=index, Label=label, Argv=list(argv), ExpectedExit=0, Exit=0, Status='PASS',
        TimedOut=False, Journal=watch.binding(journal), Stdout=watch.binding(watch.root / (prefix + '.stdout')),
        Stderr=watch.binding(watch.root / (prefix + '.stderr')))
    return streams[0]


def _slim(watch, primitive, transport, tool, index, obj):
    raw = watch.raw(obj)
    header = transport.require_elf32le(raw)
    text = _command(watch, primitive, index, [str(tool), '-hSW', str(obj)]).decode('ascii')
    primitive._readelf_metadata(text, raw, header)
    rows = transport.section_records(text)
    watch.same(rows, primitive._binary_sections(raw, header), 'full readelf/actual section correspondence')
    need(any(r['Name'].startswith('.gnu.lto_') for r in rows)
         and not any(r['Size'] and 'X' in r['Flags'] for r in rows), 'slim IR without executable fallback')
    return dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=rows)


def _comparison(value):
    need(type(value) is dict and set(value) == {'Entry', 'Identical', 'Segments', 'VectorAddress', 'VectorBytes'}
         and value['Identical'] is True and type(value['Entry']) is int and value['Entry'] > 0
         and type(value['VectorAddress']) is int and value['VectorAddress'] >= 0
         and type(value['VectorBytes']) is str and re.fullmatch('[0-9a-f]{2048}', value['VectorBytes']) is not None
         and type(value['Segments']) is list and value['Segments'], 'closed load-image comparison')
    for row in value['Segments']:
        need(type(row) is dict and set(row) == {'Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align', 'BytesSha256'}
             and all(type(row[k]) is int and row[k] >= 0 for k in ('Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align'))
             and row['MemorySize'] >= row['FileSize'], 'typed load-image segment')
        _hash(row['BytesSha256'])


def inspect(batch, native, root, core, helpers, read, *, original_dumps):
    """Replay [41,53); original_dumps are caller-journal-bound content inputs."""
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == HELPERS and callable(read), 'exact explicit helpers/read')
    methods = dict(deps=('parse',), recipes=('batch_plan', 'require_capture_sources', 'compile_flags', 'link_recipe'),
        probes=('isolated_flags', 'isolated_dependencies'), ownership=('validate_common_sources',),
        guard=('_same',), transport=('require_elf32le', 'section_records'),
        controls_replay=('_Reader', '_json', '_identity', '_readelf_metadata', '_binary_sections'),
        isolation_slots=('inspect', 'require_result'), os_slot=('inspect', 'require_result'), neutral_slot=('Audit',))
    need(all(callable(getattr(helpers[key], name, None)) for key, names in methods.items() for name in names), 'neutral helper functions')
    need(callable(getattr(core, 'compare_load_images', None)), 'immutable core comparator')
    primitive = helpers['controls_replay']
    primitive._identity(batch);primitive._identity(native)
    need(batch.get('Status') == 'BUILT-PENDING-READER' and batch.get('IsolationBuilt') is True
         and batch.get('SourceOwnershipValidated') is True, 'built pending isolation batch')
    helpers['recipes'].require_capture_sources(native)
    watch = primitive._Reader(batch, root, helpers, read)
    plan = helpers['recipes'].batch_plan()['Commands'][41:53]
    need(len(plan) == 12 and tuple(r['Label'] for r in plan) == LABELS
         and all(type(r['Index']) is int and r['Index'] == 41 + i and r['ExpectedExit'] == 0
                 and r['Component'] == 'Isolation' for i, r in enumerate(plan)), 'fixed twelve-command isolation recipe')
    source_root = _path(batch.get('SourceSeed')) / 'source'
    capture = _path(batch.get('NativeCapture', {}).get('Build'))
    watch.same(native.get('SeedBuild'), batch.get('SourceSeed'), 'same native seed root')
    for left, right in ((root, source_root), (root, capture), (source_root, capture)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'disjoint input/batch roots')
    receipt = capture / 'results.json'
    watch.same(primitive._json(watch.raw(receipt, batch['NativeCapture'].get('ReceiptSha256'))), native, 'reparsed actual native receipt')
    tools = {name: capture / 'toolchain/bin' / ('arm-none-eabi-' + suffix + '.exe')
             for name, suffix in (('Gcc', 'gcc'), ('Readelf', 'readelf'), ('Objdump', 'objdump'))}
    watch.same(native.get('CapturedCompiler'), str(tools['Gcc']), 'native compiler identity')
    for path in tools.values(): watch.raw(path)
    need(tuple(helpers['ownership'].REQUIRED_SOURCES) == OWNERSHIP, 'fixed ownership source roles')
    sources = {name: watch.raw(source_root / name) for name in OWNERSHIP}
    ownership = helpers['ownership'].validate_common_sources(sources)
    ownership_inputs = [dict(Source=name, **watch.binding(source_root / name)) for name in OWNERSHIP]
    watch.same(ownership, batch.get('SourceOwnership'), 'recomputed source ownership comparison target')
    watch.same(ownership_inputs, batch.get('SourceOwnershipInputs'), 'source ownership role bindings')
    original_objects, native_bindings = [], []
    for index, name in enumerate(ORDER):
        row = native['Sources'][index]
        obj = capture / 'objects' / ('%02d-' % index + Path(name).stem + '.o')
        watch.same(row['Source'], str(source_root / name), 'native ordered source')
        watch.same(row['Object'], str(obj), 'native ordered object')
        watch.raw(obj, row['ObjectSha256'])
        original_objects.append(obj);native_bindings.append(dict(Index=index, **watch.binding(obj)))
    common, dependency_bindings = [], []
    for index, name in enumerate(COMMON):
        first = 41 + index * 3
        row = native['Sources'][index];source = source_root / name
        watch.raw(source, row['SourceSha256'])
        original_flags = helpers['recipes'].compile_flags(native, index)
        need([f for f in original_flags if f.startswith('-O')] == ['-Os']
             and original_flags.count('-flto') == original_flags.count('-fno-fat-lto-objects') == 1
             and '-fno-lto' not in original_flags and '-ffat-lto-objects' not in original_flags, 'genuine Os slim flags')
        flags = helpers['probes'].isolated_flags(original_flags, source_root)
        need([f for f in flags if f.startswith('-O')] == ['-Os'] and flags.count('-flto') == flags.count('-fno-fat-lto-objects') == 1
             and '-include' not in flags, 'isolated Os/slim flag preservation')
        obj = root / 'isolated-common' / (Path(name).stem + '.o')
        discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        target = 'pilot-source-' + str(index)
        _command(watch, primitive, first, [str(tools['Gcc']), *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)])
        _command(watch, primitive, first + 1, [str(tools['Gcc']), *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)])
        declared = row.get('ActualCompileDependencies')
        need(type(declared) is list and declared and all(type(r) is dict and set(r) == {'Path', 'Sha256'} for r in declared), 'native dependency declarations')
        admitted = {_path(r['Path']): _hash(r['Sha256']) for r in declared}
        need(len(admitted) == len(declared) and admitted.get(source) == row['SourceSha256'], 'native exact source dependency authority')
        before = helpers['deps'].parse(watch.raw(discovery), target=target)
        after = helpers['deps'].parse(watch.raw(actual), target=target)
        need(type(before) is tuple and type(after) is tuple and before == after and before
             and before == tuple(sorted(set(before))) and all(isinstance(p, Path) and _path(p) == p for p in before)
             and source in before, 'same canonical discovery/compile dependency sets')
        need(source_root / 'tools/fixtures/classic_final_image/main.h' not in before, 'no forced main dependency')
        deps = helpers['probes'].isolated_dependencies(list(before), admitted, root=source_root, cmsis=source_root.parent / 'cmsis')
        for dep in deps: watch.raw(_path(dep['Path']), dep['Sha256'])
        watch.same(deps, [watch.binding(path) for path in before], 'ordered consumed dependency bindings')
        slim = _slim(watch, primitive, helpers['transport'], tools['Readelf'], first + 2, obj)
        common.append(dict(Source=str(source), SourceSha256=row['SourceSha256'], TemplateIndex=index,
            OriginalObject=row['Object'], OriginalObjectSha256=row['ObjectSha256'], Object=str(obj), ObjectSha256=slim['Sha256'],
            SlimIR=slim, OriginalCompileFlags=original_flags, CompileFlags=list(flags), DiscoveryFlags=list(flags),
            IncludeDelta=dict(RemovedForcedHeader=str(source_root / 'tools/fixtures/classic_final_image/main.h'),
                ReplacementSearchPaths=[str(source_root / p) for p in ('context', 'fiber')] + [str(source_root)], OtherSemanticFlagsUnchanged=True),
            DiscoveryDependencies=deps, Dependencies=copy.deepcopy(deps), CompileDependenciesVerified=True,
            DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual), CommandIndices=[first, first + 1, first + 2],
            ForcedMainHeaderRemoved=True, CmsisAndSelectedPortIncludesRemoved=True, RawIRIdentityClaim=False,
            IRImportClosureValidated=False, SourceToMachineSemanticProof=False))
        dependency_bindings.append(dict(DiscoveryIndex=first, CompileIndex=first + 1, Target=target, Source=str(source),
            Discovery=watch.binding(discovery), Compile=watch.binding(actual), Dependencies=copy.deepcopy(deps)))
    watch.same(common, batch.get('IsolatedCommon'), 'reconstructed isolated compilation comparison target')
    selected = [Path(r['Object']) for r in common] + original_objects[3:]
    linked = [dict(Index=i, **watch.binding(path), OriginalUnchanged=i >= 3) for i, path in enumerate(selected)]
    watch.same(linked, batch.get('IsolatedLinkedObjects'), 'three replacements/six unchanged ordered inputs')
    recipe = helpers['recipes'].link_recipe(native, original_objects)
    need(recipe.count('-o') == 1 and recipe[-2:] == ['-o', native['Links'][0]['Path']]
         and [arg for arg in recipe[:-2] if arg.endswith('.o')] == [str(p) for p in original_objects], 'native link recipe inputs/output')
    link_script = source_root / 'tools/fixtures/classic_final_image/link.ld'
    need(recipe.count('-T') == 1 and recipe[recipe.index('-T') + 1] == str(link_script), 'fixed native link script')
    watch.raw(link_script)
    fixed = _paths(root, source_root, capture)
    for i, prefix in ((50, 'IsolatedOrdinary'), (51, 'IsolatedEmit')):
        output = fixed[prefix + 'ELF'];link_map = fixed['IsolatedOrdinaryMap' if i == 50 else 'IsolatedMap']
        argv, inserted = [], False
        for arg in recipe:
            if arg in [str(p) for p in original_objects]:
                if not inserted: argv.extend(str(p) for p in selected);inserted = True
            elif arg.startswith('-Wl,-Map='): argv.append('-Wl,-Map=' + str(link_map))
            elif arg == native['Links'][0]['Path']: argv.append(str(output))
            else: argv.append(arg)
        need(inserted and argv.count('-o') == 1 and argv[-2:] == ['-o', str(output)]
             and [arg for arg in argv[:-2] if arg.endswith('.o')] == [str(p) for p in selected]
             and not any('--emit-relocs' in arg for arg in argv), 'substituted fixed link recipe')
        if i == 51: argv.append('-Wl,--emit-relocs')
        _command(watch, primitive, i, argv);watch.raw(output);watch.raw(link_map)
    watch.same(batch.get('EmitLinkDelta'), ['-Wl,--emit-relocs'], 'saved emit delta')
    watch.same(batch.get('IsolatedLinkMap'), str(fixed['IsolatedOrdinaryMap']), 'saved ordinary link map')
    dump = _command(watch, primitive, 52, [str(tools['Objdump']), '-drwC', '-z', str(fixed['IsolatedEmitELF'])])
    watch.same(watch.raw(fixed['IsolatedDisassembly']), dump, 'isolated zero-inclusive disassembly bytes')
    for row, kind in zip(native['Links'], ('OriginalOrdinaryELF', 'OriginalEmitELF')):
        watch.same(row['Path'], str(fixed[kind]), 'fixed original twin ELF')
        watch.raw(fixed[kind], row['Sha256'])
    for path in fixed.values(): watch.raw(path)
    inputs = {name: watch.binding(path) for name, path in fixed.items()}
    pending = _deferred(inputs)
    watch.same(pending, batch.get('IsolationDeferredReader'), 'exact eighteen-role deferred comparison target')
    build = _build_record();watch.same(build, batch.get('IsolationBuild'), 'pending isolation build disposition')
    saved = root / 'isolation-build.json'
    watch.same(primitive._json(watch.raw(saved)), dict(Build=build, IsolatedCommon=common, SourceOwnership=ownership,
        DeferredReader=pending, Objects=linked), 'isolation build receipt comparison target')
    comparisons = {}
    for name, left, right in COMPARISONS:
        comparisons[name] = copy.deepcopy(core.compare_load_images(fixed[left], fixed[right]))
        _comparison(comparisons[name])
    need(type(original_dumps) is dict and set(original_dumps) == {'Final', 'Machine'}, 'two caller-bound original dumps')
    dump_inputs = {}
    for name, pair in original_dumps.items():
        need(type(pair) is tuple and len(pair) == 2 and type(pair[1]) is bytes and pair[1], 'original dump pair')
        path, digest = _path(pair[0]), sha(pair[1])
        need(path not in fixed.values() and path not in {Path(r['Path']) for r in dump_inputs.values()}, 'distinct supplementary original dump roles')
        if path in watch.authority: watch.same(watch.authority[path], digest, 'original dump authority hash')
        if path in watch.artifacts: watch.same(watch.artifacts[path], digest, 'original dump artifact hash')
        raw = read(path, digest)
        need(type(raw) is bytes and raw == pair[1] and (path not in watch.consumed or watch.consumed[path] == raw), 'admitted original dump bytes')
        watch.consumed[path] = raw
        dump_inputs[name] = dict(Path=str(path), Sha256=digest)

    def slot_read(path, expected):
        path = _path(path)
        if path in {Path(row['Path']) for row in dump_inputs.values()}:
            need(sha(watch.consumed[path]) == expected, 'supplementary slot dump hash')
            return watch.consumed[path]
        return watch.raw(path, expected)

    roles = {name: dict(Role=name, **inputs[name]) for name in ROLE_NAMES}
    slot_proof = helpers['isolation_slots'].inspect(core, slot_read, roles, helpers['os_slot'], helpers['neutral_slot'],
        original_dump=original_dumps['Final'])
    helpers['isolation_slots'].require_result(slot_proof)
    need(set(watch.bound) == set(range(41, 53)), 'complete isolation command coverage')
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=SOURCE, Root=str(root), SourceRoot=str(source_root), CaptureRoot=str(capture),
        AuthorityInputs={name: watch.binding(path) for name, path in (
            ('Manifest', root / 'artifacts.json'), ('CommandJournal', root / 'commands.json'),
            ('NativeReceipt', receipt), ('IsolationBuild', saved), ('LinkScript', link_script))}, Inputs=inputs,
        ToolBindings={name: watch.binding(path) for name, path in tools.items()}, NativeObjectBindings=native_bindings,
        CommandBindings=[watch.bound[i] for i in range(41, 53)], SourceOwnership=copy.deepcopy(ownership),
        SourceOwnershipInputs=ownership_inputs, IsolatedCommon=common, DependencyBindings=dependency_bindings,
        IsolatedLinkedObjects=linked, LoadImageComparisons=comparisons, SlotProofs=copy.deepcopy(slot_proof),
        OriginalDumps=dump_inputs, ReadInputs=[watch.binding(p) for p in sorted(watch.consumed)], ReadFiles=len(watch.consumed), **COUNTS)
    proof.update(dict.fromkeys(FACTS, True));proof.update(dict.fromkeys(NONCLAIMS, False))
    return require_result(proof)


def require_result(proof):
    """Strict bounded report validation, never evidence recomputation or credit."""
    need(type(proof) is dict and set(proof) == FIELDS, 'closed result schema')
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
            ('Linkage', 'direct'), ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(proof[key]) is str and proof[key] == value, 'fixed result/' + key)
    need(proof['LTO'] is True, 'literal LTO')
    for key, value in COUNTS.items(): need(type(proof[key]) is int and proof[key] == value, 'literal count/' + key)
    for key in FACTS: need(proof[key] is True, 'required fact/' + key)
    for key in NONCLAIMS: need(proof[key] is False, 'bounded nonclaim/' + key)
    root, source_root, capture = (_path(proof[k]) for k in ('Root', 'SourceRoot', 'CaptureRoot'))
    need(type(proof['ReadInputs']) is list and type(proof['ReadFiles']) is int
         and proof['ReadFiles'] == len(proof['ReadInputs']) > 0, 'read accounting')
    reads, used = {}, set()
    for row in proof['ReadInputs']:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'closed read binding')
        path = _path(row['Path']);need(path not in reads, 'unique read binding');reads[path] = _hash(row['Sha256'])

    def binding(row, path=None, extra=()):
        need(type(row) is dict and set(row) == {'Path', 'Sha256'} | set(extra), 'closed role binding')
        actual = _path(row['Path'])
        need((path is None or actual == path) and reads.get(actual) == _hash(row['Sha256']), 'consumed role binding')
        used.add(actual);return actual

    need(type(proof['Inputs']) is dict and set(proof['Inputs']) == set(ROLE_NAMES), 'exact eighteen input roles')
    for name, path in _paths(root, source_root, capture).items(): binding(proof['Inputs'][name], path)
    need(type(proof['AuthorityInputs']) is dict and set(proof['AuthorityInputs']) == {'Manifest', 'CommandJournal', 'NativeReceipt', 'IsolationBuild', 'LinkScript'}, 'authority roles')
    for name, path in (('Manifest', root / 'artifacts.json'), ('CommandJournal', root / 'commands.json'),
            ('NativeReceipt', capture / 'results.json'), ('IsolationBuild', root / 'isolation-build.json'),
            ('LinkScript', source_root / 'tools/fixtures/classic_final_image/link.ld')):
        binding(proof['AuthorityInputs'][name], path)
    need(type(proof['ToolBindings']) is dict and set(proof['ToolBindings']) == {'Gcc', 'Readelf', 'Objdump'}, 'tool roles')
    for name, stem in (('Gcc', 'gcc'), ('Readelf', 'readelf'), ('Objdump', 'objdump')):
        binding(proof['ToolBindings'][name], capture / 'toolchain/bin' / ('arm-none-eabi-' + stem + '.exe'))
    commands = proof['CommandBindings'];need(type(commands) is list and len(commands) == 12, 'twelve command bindings')
    for index, row in zip(range(41, 53), commands):
        need(type(row) is dict and set(row) == {'Index', 'Label', 'Argv', 'ExpectedExit', 'Exit', 'Status', 'TimedOut', 'Journal', 'Stdout', 'Stderr'}
             and type(row['Index']) is int and row['Index'] == index and row['Label'] == LABELS[index - 41]
             and type(row['Exit']) is int and row['Exit'] == 0 and type(row['ExpectedExit']) is int and row['ExpectedExit'] == 0
             and row['Status'] == 'PASS' and row['TimedOut'] is False and type(row['Argv']) is list
             and row['Argv'] and all(type(a) is str for a in row['Argv']), 'fixed command binding')
        for name, suffix in (('Journal', '.json'), ('Stdout', '.stdout'), ('Stderr', '.stderr')):
            binding(row[name], root / 'commands' / ('%03d' % index + suffix))
    need(type(proof['LoadImageComparisons']) is dict and set(proof['LoadImageComparisons']) == {r[0] for r in COMPARISONS}, 'three named load comparisons')
    for comparison in proof['LoadImageComparisons'].values(): _comparison(comparison)
    need(type(proof['OriginalDumps']) is dict and set(proof['OriginalDumps']) == {'Final', 'Machine'}, 'two content-only original dumps')
    for row in proof['OriginalDumps'].values():
        binding(row)
    # Additional nested validators are local: no retained helper/module state.
    _require_component(proof, binding, reads, used, root, source_root, capture)
    need(used == set(reads), 'exact bounded read-role closure')
    return proof


def _require_component(proof, binding, reads, used, root, source_root, capture):
    for left, right in ((root, source_root), (root, capture), (source_root, capture)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'disjoint result roots')
    ownership = proof['SourceOwnership']
    false_fields = ('InputAuthenticationProof', 'ActualProviderProof', 'DependencyProof', 'ElfProof', 'CompileProof',
        'CompilerExecution', 'FullABIProof', 'FullSemanticABIProof', 'ArbitraryPointerAliasProof', 'CpuExecution',
        'BoardExecution', 'RequiredCellSatisfied', 'GlobalFreezeQualified')
    need(type(ownership) is dict and set(ownership) == set(false_fields) | {'Status', 'Scope', 'SourceFactsOnly',
        'SourceRoles', 'SourceHashes', 'AuthoredIncludes', 'CheckedFunctions', 'CanonicalPrivateStorageDeclarations',
        'RuntimeSourceManifestMatched', 'RequiredCellsSatisfied'}, 'closed source ownership proof')
    need(ownership['Status'] == 'PASS' and ownership['Scope'] == 'CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY'
         and all(ownership[k] is True for k in ('SourceFactsOnly', 'CanonicalPrivateStorageDeclarations', 'RuntimeSourceManifestMatched'))
         and all(ownership[k] is False for k in false_fields) and type(ownership['RequiredCellsSatisfied']) is int
         and ownership['RequiredCellsSatisfied'] == 0, 'source-only ownership facts/nonclaims')
    need(_same(ownership['SourceRoles'], dict(zip(('engine', 'state', 'panic'), COMMON)))
         and type(ownership['SourceHashes']) is dict and set(ownership['SourceHashes']) == set(OWNERSHIP), 'fixed common source ownership roles')
    source_inputs = proof['SourceOwnershipInputs']
    need(type(source_inputs) is list and len(source_inputs) == 4, 'four ownership source bindings')
    for row, name in zip(source_inputs, OWNERSHIP):
        binding(row, source_root / name, extra=('Source',))
        need(row['Source'] == name and ownership['SourceHashes'][name] == row['Sha256'], 'ownership source hash join')
    authored = dict(engine=['context_api_decl.h', 'context_panic.h', 'context_runtime_port_abi.h', 'context_runtime_state.h', 'context_port_abi.h'],
        state=['context_runtime_state.h', 'context_panic.h', 'context_runtime_port_abi.h'], panic=['context_panic.h', 'context_port_abi.h'])
    need(_same(ownership['AuthoredIncludes'], authored), 'canonical authored includes')
    functions = ('fiber_internal_task_return', 'ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_start', 'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield',
        'fiber_internal_scheduler_store_pick_next', 'fiber_internal_runtime_load_current_context', 'fiber_internal_runtime_select_scheduler_candidate',
        'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context', 'fiber_internal_scheduler_is_configured',
        'fiber_internal_runtime_close_context_configuration', 'fiber_internal_runtime_context_configuration_is_open', 'fiber_panic')
    need(type(ownership['CheckedFunctions']) is list and len(ownership['CheckedFunctions']) == 15, 'fifteen source-only function predicates')
    for i, (row, name) in enumerate(zip(ownership['CheckedFunctions'], functions)):
        need(type(row) is dict and set(row) == {'Source', 'Function', 'Signature', 'CheckedBodyTextSha256'}
             and row['Function'] == name and row['Source'] == COMMON[0 if i < 6 else 1 if i < 14 else 2]
             and type(row['Signature']) is str and name + '(' in row['Signature'], 'fixed source function proof')
        _hash(row['CheckedBodyTextSha256'])
    native = proof['NativeObjectBindings']
    need(type(native) is list and len(native) == 9, 'nine native object bindings')
    for i, (row, name) in enumerate(zip(native, ORDER)):
        binding(row, capture / 'objects' / ('%02d-' % i + Path(name).stem + '.o'), extra=('Index',))
        need(type(row['Index']) is int and row['Index'] == i, 'native object order')
    common = proof['IsolatedCommon'];deps = proof['DependencyBindings'];commands = proof['CommandBindings']
    need(type(common) is list and len(common) == 3 and type(deps) is list and len(deps) == 3, 'three isolated compilations/dependency pairs')
    common_fields = {'Source', 'SourceSha256', 'TemplateIndex', 'OriginalObject', 'OriginalObjectSha256', 'Object', 'ObjectSha256',
        'SlimIR', 'OriginalCompileFlags', 'CompileFlags', 'DiscoveryFlags', 'IncludeDelta', 'DiscoveryDependencies', 'Dependencies',
        'CompileDependenciesVerified', 'DiscoveryDependencyFile', 'CompileDependencyFile', 'CommandIndices', 'ForcedMainHeaderRemoved',
        'CmsisAndSelectedPortIncludesRemoved', 'RawIRIdentityClaim', 'IRImportClosureValidated', 'SourceToMachineSemanticProof'}
    empty_hash = sha(b'')
    for i, (row, dep, name) in enumerate(zip(common, deps, COMMON)):
        source = source_root / name;obj = root / 'isolated-common' / (Path(name).stem + '.o');first = 41 + i * 3
        need(type(row) is dict and set(row) == common_fields and type(row['TemplateIndex']) is int and row['TemplateIndex'] == i
             and row['Source'] == str(source) and reads.get(source) == _hash(row['SourceSha256'])
             and row['Object'] == str(obj) and reads.get(obj) == _hash(row['ObjectSha256'])
             and row['OriginalObject'] == native[i]['Path'] and row['OriginalObjectSha256'] == native[i]['Sha256']
             and _same(row['CommandIndices'], [first, first + 1, first + 2]), 'closed isolated source/object/command joins')
        used.update((source, obj))
        need(all(row[k] is True for k in ('CompileDependenciesVerified', 'ForcedMainHeaderRemoved', 'CmsisAndSelectedPortIncludesRemoved'))
             and all(row[k] is False for k in ('RawIRIdentityClaim', 'IRImportClosureValidated', 'SourceToMachineSemanticProof')), 'bounded compilation facts')
        for key in ('OriginalCompileFlags', 'CompileFlags', 'DiscoveryFlags'):
            need(type(row[key]) is list and all(type(a) is str for a in row[key])
                 and [a for a in row[key] if a.startswith('-O')] == ['-Os']
                 and row[key].count('-flto') == row[key].count('-fno-fat-lto-objects') == 1, 'typed Os slim flags')
        need(_same(row['CompileFlags'], row['DiscoveryFlags']) and '-include' not in row['CompileFlags'], 'same isolated compile/discovery flags')
        need(_same(row['IncludeDelta'], dict(RemovedForcedHeader=str(source_root / 'tools/fixtures/classic_final_image/main.h'),
            ReplacementSearchPaths=[str(source_root / p) for p in ('context', 'fiber')] + [str(source_root)], OtherSemanticFlagsUnchanged=True)), 'exact include authority delta')
        need(type(dep) is dict and set(dep) == {'DiscoveryIndex', 'CompileIndex', 'Target', 'Source', 'Discovery', 'Compile', 'Dependencies'}
             and type(dep['DiscoveryIndex']) is int and dep['DiscoveryIndex'] == first and type(dep['CompileIndex']) is int
             and dep['CompileIndex'] == first + 1 and dep['Target'] == 'pilot-source-' + str(i) and dep['Source'] == str(source), 'dependency pair schema')
        before, after = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        binding(dep['Discovery'], before);binding(dep['Compile'], after)
        need(row['DiscoveryDependencyFile'] == str(before) and row['CompileDependencyFile'] == str(after)
             and _same(row['Dependencies'], dep['Dependencies']) and _same(row['DiscoveryDependencies'], dep['Dependencies']), 'dependency record joins')
        need(type(dep['Dependencies']) is list and dep['Dependencies'], 'nonempty consumed dependencies')
        paths = [binding(r) for r in dep['Dependencies']]
        need(paths == sorted(set(paths)) and source in paths and source_root / 'tools/fixtures/classic_final_image/main.h' not in paths
             and not any(p.is_relative_to(source_root.parent / 'cmsis') or p.is_relative_to(source_root / 'fiber/port') for p in paths), 'canonical CPU-independent dependencies')
        gcc = proof['ToolBindings']['Gcc']['Path']
        expected = [gcc, *row['DiscoveryFlags'], '-M', '-MF', str(before), '-MT', dep['Target'], str(source)]
        need(_same(commands[i * 3]['Argv'], expected), 'discovery command provenance')
        expected = [gcc, *row['CompileFlags'], '-MD', '-MF', str(after), '-MT', dep['Target'], '-c', str(source), '-o', str(obj)]
        need(_same(commands[i * 3 + 1]['Argv'], expected), 'compile command provenance')
        need(commands[i * 3 + 2]['Argv'] == [proof['ToolBindings']['Readelf']['Path'], '-hSW', str(obj)], 'slim command provenance')
        ir = row['SlimIR']
        need(type(ir) is dict and set(ir) == {'Object', 'Sha256', 'SlimIR', 'Sections'} and ir['SlimIR'] is True
             and ir['Object'] == str(obj) and ir['Sha256'] == row['ObjectSha256'] and type(ir['Sections']) is list and ir['Sections'], 'closed slim inspection')
        for index, section in enumerate(ir['Sections']):
            need(type(section) is dict and set(section) == {'Index', 'Name', 'Type', 'Address', 'Offset', 'Size', 'Flags'}
                 and type(section['Index']) is int and section['Index'] == index
                 and all(type(section[k]) is str for k in ('Name', 'Type', 'Flags'))
                 and all(type(section[k]) is int and section[k] >= 0 for k in ('Address', 'Offset', 'Size')), 'closed typed section claim')
        need(any(s['Name'].startswith('.gnu.lto_') for s in ir['Sections'])
             and not any(s['Size'] and 'X' in s['Flags'] for s in ir['Sections']), 'slim section inventory')
    linked = proof['IsolatedLinkedObjects']
    need(type(linked) is list and len(linked) == 9, 'nine linked object bindings')
    for i, row in enumerate(linked):
        expected = proof['Inputs']['IsolatedIR' + str(i)] if i < 3 else native[i]
        binding(row, Path(expected['Path']), extra=('Index', 'OriginalUnchanged'))
        need(row['Sha256'] == expected['Sha256'] and type(row['Index']) is int and row['Index'] == i
             and row['OriginalUnchanged'] is (i >= 3), 'exact three replacement/six unchanged objects')
    link_base = [proof['ToolBindings']['Gcc']['Path'], '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-flto',
        '-flto-partition=one', '-save-temps=obj', '-nostdlib', '-Wl,-plugin-opt=-save-temps',
        '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
        '-T', proof['AuthorityInputs']['LinkScript']['Path'], *(r['Path'] for r in linked)]
    for i, (elf_role, map_role) in enumerate((('IsolatedOrdinaryELF', 'IsolatedOrdinaryMap'), ('IsolatedEmitELF', 'IsolatedMap'))):
        expected = link_base + ['-Wl,-Map=' + proof['Inputs'][map_role]['Path'], '-o', proof['Inputs'][elf_role]['Path']]
        if i: expected.append('-Wl,--emit-relocs')
        need(_same(commands[9 + i]['Argv'], expected), 'exact link recipe, including emit-after-output')
    need(commands[11]['Argv'] == [proof['ToolBindings']['Objdump']['Path'], '-drwC', '-z', proof['Inputs']['IsolatedEmitELF']['Path']]
         and commands[11]['Stdout']['Sha256'] == proof['Inputs']['IsolatedDisassembly']['Sha256'], 'isolated zero-inclusive dump binding')
    for i, cmd in enumerate(commands):
        need(cmd['Stderr']['Sha256'] == empty_hash and (i in (2, 5, 8, 11) or cmd['Stdout']['Sha256'] == empty_hash), 'clean saved streams')
    values = list(proof['LoadImageComparisons'].values())
    need(all(_same(value, values[0]) for value in values), 'three identical load-image descriptions')
    _require_slots(proof['SlotProofs'], proof['Inputs'], proof['OriginalDumps']['Final'])


def _require_slots(value, inputs, final_dump):
    slot_false = ('CommonSourceOwnershipValidated', 'CompleteHandlerBodiesValidated', 'ArbitraryPointerAliasProof', 'WholeProgramMemorySafetyProof',
        'FullSemanticABIProof', 'FullABIProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'Qualification',
        'CellContractSatisfied', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied')
    adapter_false = slot_false + ('IRImportClosureValidated', 'RawIRIdentityClaim', 'LoadImageComparisonsReplayed',
        'FinalRootTransferProtocolsValidated', 'FullHandlerProtocolsValidated', 'CompilerExecuted', 'ProducerCompilersReexecuted')
    adapter_facts = ('SlotProofsReplayed', 'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsHelperAuthentication')
    need(type(value) is dict and set(value) == set(adapter_false + adapter_facts) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage',
        'LTO', 'Inputs', 'OriginalDump', 'SlotProofs', 'ReadInputs', 'InputRoles', 'SlotImages', 'ReadFiles', 'RequiredCellsSatisfied'}, 'closed slot adapter proof')
    need(type(value.get('Inputs')) is dict and _same(value['Inputs'], {name: dict(Role=name, **row) for name, row in inputs.items()}), 'exact slot adapter input roles')
    # The slot adapter owns its detailed evidence schema; this leaf closes the
    # cross-component authority and qualification boundary independently.
    need(value.get('Status') == 'CM3-OS-LTO-ISOLATION-SLOTS-REPLAYED-NOT-QUALIFIED'
         and value.get('Scope') == 'CM3_OS_LTO_ORIGINAL_AND_ISOLATED_EMITTED_SLOT_PROTOCOLS_ONLY'
         and value.get('Profile') == 'CM3' and value.get('Mode') == 'Os-lto'
         and value.get('Linkage') == 'direct' and value.get('LTO') is True, 'bounded Os slot adapter identity')
    for key in adapter_facts:
        need(value.get(key) is True, 'slot adapter fact/' + key)
    for key in adapter_false:
        need(value.get(key) is False, 'slot adapter nonclaim/' + key)
    need(type(value.get('InputRoles')) is int and value['InputRoles'] == 18 and type(value.get('SlotImages')) is int
         and value['SlotImages'] == 2 and type(value.get('RequiredCellsSatisfied')) is int and value['RequiredCellsSatisfied'] == 0,
         'slot adapter counts')
    need(_same(value['OriginalDump'], final_dump) and type(value['ReadFiles']) is int and value['ReadFiles'] == 19
         and type(value['ReadInputs']) is list and len(value['ReadInputs']) == 19, 'fresh original slot dump authority')
    expected_reads = sorted([dict(row) for row in inputs.values()] + [dict(final_dump)], key=lambda row: Path(row['Path']))
    need(_same(value['ReadInputs'], expected_reads), 'exact nineteen slot-adapter read bindings')
    need(type(value.get('SlotProofs')) is dict and set(value['SlotProofs']) == {'Original', 'Isolated'}, 'two delegated slot proofs')
    for kind, proof in value['SlotProofs'].items():
        slot_fields = set(slot_false) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'EmitRelocs', 'SlotIsolationValidated',
            'SlotOrigin', 'SlotAlias', 'SourceSha256', 'AssemblySha256', 'MachineSha256', 'FinalSha256', 'LinkMapSha256',
            'HandlerLoadPairs', 'HandlerLoads', 'SourcePairs', 'GeneratedPairs', 'ClosedCommonBodies', 'CommonBodies', 'CommonBytes',
            'CommonLoads', 'CommonStores', 'Publisher', 'SlotReferences', 'AppliedSlotReferences', 'RawSectionSymbolsPreserved',
            'AllSectionMediatedSlotReferencesValidated', 'RequiredCellsSatisfied'}
        need(type(proof) is dict and set(proof) == slot_fields and proof.get('Mode') == 'Os-lto' and proof.get('EmitRelocs') is True
             and proof.get('SlotIsolationValidated') is True and proof.get('Qualification') is False
             and proof.get('FullABIProof') is False and proof.get('SourceToMachineSemanticProof') is False
             and type(proof.get('RequiredCellsSatisfied')) is int and proof['RequiredCellsSatisfied'] == 0, 'bounded delegated Os proof')
        need(all(proof[k] is False for k in slot_false), 'delegated slot nonclaims')
        for key, count in (('HandlerLoadPairs', 2), ('ClosedCommonBodies', 6), ('CommonBytes', 272), ('CommonLoads', 5),
                ('CommonStores', 1), ('SlotReferences', 8), ('AppliedSlotReferences', 8)):
            need(type(proof[key]) is int and proof[key] == count, 'delegated slot count/' + key)
        for key, role in (('SourceSha256', 'PortSource'), ('AssemblySha256', kind + 'Assembly'),
                ('MachineSha256', kind + 'Machine'), ('FinalSha256', kind + 'EmitELF'), ('LinkMapSha256', kind + 'Map')):
            need(proof.get(key) == inputs[role]['Sha256'], 'delegated slot role hash')
