"""Pure replay of recorded Os common-attribute commands [53,98), not a verdict.

Admission, helper authentication and physical identity belong to the caller.
Only read touches bytes. The separately supplied lowered adapter owns worker
and ET_REL effect predicates; unresolved attribution never becomes policy proof.
"""

import copy
import hashlib
import math
from pathlib import Path
import re
from types import SimpleNamespace


STATUS = 'CM3-OS-LTO-COMMON-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_45_COMMAND_COMMON_ATTRIBUTES_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
HELPERS = frozenset(('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport',
    'controls_replay', 'attributes', 'attribute_runner', 'attributes_phase',
    'common_lowered', 'common_workers', 'common_effects'))
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
OWNERSHIP = COMMON + ('tools/runtime_sources.json',)
ROLES = ('engine', 'state', 'panic')
GROUPS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
BUILDS = (('positive', 0, 54), ('positive', 1, 58), ('positive', 2, 62),
    ('mutant-engine', 0, 68), ('mutant-state', 1, 74), ('mutant-panic', 2, 80),
    ('stress-protected', 0, 86), ('stress-unprotected', 0, 92))
LOWERS = (66, 72, 78, 84, 90, 96)
MUTATIONS = (None, 'ctxrt_v1_current', 'fiber_internal_runtime_load_current_context',
    'fiber_panic', None, 'ctxrt_attribute_stress')
RAW = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
    '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
LOWER_FLAGS = ('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
    '-nostdlib', '-r', '-flinker-output=nolto-rel')
ROLE_SUFFIXES = dict(Object='', Machine='.ltrans0.ltrans.o', WpaArguments='.ltrans_args',
    LtransArguments='.ltrans0.ltrans_args', WpaResponse='.wpa.args.0', LtransResponse='.ltrans0.ltrans.args.0',
    PartitionList='.ltrans.out', Intermediate='.ltrans0.o', Resolution='.res', Assembly='.ltrans0.ltrans.s')
ROLE_NAMES = frozenset(ROLE_SUFFIXES) | {'Disassembly', 'WrapperArgs', 'DriverSpecs', 'Diagnostics'}
OWNERSHIP_SIGNATURES = (
    (COMMON[0], 'void fiber_internal_task_return(void)'),
    (COMMON[0], 'void ctxrt_v1_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg)'),
    (COMMON[0], 'CtxrtContextV1 *ctxrt_v1_current(void)'),
    (COMMON[0], 'void ctxrt_v1_start(void)'),
    (COMMON[0], 'void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)'),
    (COMMON[0], 'void ctxrt_v1_yield(void)'),
    (COMMON[1], 'void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 pick_next, void *user)'),
    (COMMON[1], 'CtxrtContextV1 *fiber_internal_runtime_load_current_context(void)'),
    (COMMON[1], 'CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current)'),
    (COMMON[1], 'void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next)'),
    (COMMON[1], 'void fiber_internal_runtime_require_current_context(void)'),
    (COMMON[1], 'uint32_t fiber_internal_scheduler_is_configured(void)'),
    (COMMON[1], 'void fiber_internal_runtime_close_context_configuration(void)'),
    (COMMON[1], 'uint32_t fiber_internal_runtime_context_configuration_is_open(void)'),
    (COMMON[2], 'void fiber_panic(char code)'),
)
OWNERSHIP_CATALOG = tuple((source, re.search(r'([A-Za-z_][A-Za-z0-9_]*)\(', signature)[1], signature)
    for source, signature in OWNERSHIP_SIGNATURES)
COUNTS = dict(First=53, Stop=98, BatchCommands=134, CommandsReplayed=45, SuccessfulCommands=45,
    IRBuilds=8, DependencyFiles=16, SlimIRInspections=8, IRImportInspections=8, LoweringCohorts=6,
    LoweringRoleBindings=84, OwnershipSources=4, AnnotationMutants=3, StressSources=2, RequiredCellsSatisfied=0)
FACTS = ('CommonCommandsReplayed', 'RecordedCommandProvenanceReplayed', 'SourceOwnershipReplayed',
    'SourceAnnotationsReplayed', 'SourceCopiesReconstructed', 'ConsumedDependenciesReplayed',
    'SlimIRMetadataReplayed', 'IRImportSurfacesReplayed', 'DriverAdapterReplayed', 'LoweringCohortsReplayed',
    'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsExactManifestMembership', 'CallerOwnsHelperAuthentication',
    'CallerOwnsCoreImmutableBinding', 'CallerOwnsDetailedLoweredResultValidation')
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'CompleteCellProof',
    'CommonAttributePolicyProven', 'AllProtectedBodiesClean', 'FullAttributeEquivalence', 'TransitiveProtection',
    'FullABIProof', 'FullSemanticABIProof', 'FullInstructionSemantics', 'FullIRSemantics', 'SourceIRProof',
    'SourceToIRSemanticProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'IRImportClosureValidated', 'WholeSlotAccessIsolation', 'FinalLinkValidated', 'FinalRootTransferProtocolsValidated',
    'FinalReferenceParity', 'NativeCaptureProvenanceReplayed', 'ProducerCompilersReexecuted', 'CompilerExecuted',
    'OsProcessTraceVerified', 'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
LOWERED_NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof', 'FullSemanticABIProof',
    'SourceIRProof', 'IRImportClosureValidated', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'CommonAttributePolicyProven', 'FullAttributeEquivalence', 'TransitiveProtection', 'FinalLinkValidated', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'AllRelocationDestinationSemanticsValidated', 'WrapperSemanticsValidated',
    'ResolutionSemanticsValidated', 'AssemblySemanticsValidated', 'DisassemblySemanticsValidated', 'JournalBindingsValidated',
    'OsProcessTraceVerified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'HostedCIQualified', 'ProducerCompilersReexecuted')
LOWERED_FACTS = ('WorkerChainsReplayed', 'EffectsRecomputed', 'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsHelperAuthentication')
LOWERED_COUNTS = dict(LoweringCohorts=6, InputRoles=84, ELFImages=12, ReadFiles=89,
    RequiredCellCount=0, RequiredCellsSatisfied=0, ToolInvocations=0, CompilerInvocations=0)
FIELDS = frozenset(COUNTS) | frozenset(FACTS + NONCLAIMS) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage',
    'LTO', 'Cohort', 'SourceInventorySha256', 'Root', 'SourceRoot', 'CaptureRoot', 'AuthorityInputs',
    'ToolBindings', 'SourceOwnership', 'SourceOwnershipInputs', 'SourceAnnotations', 'SourceInputs',
    'SourceCopies', 'AnnotationControls', 'PairedStress', 'DriverAdapter', 'Compilations',
    'DependencyBindings', 'Lowerings', 'LoweringAuxiliaryInputs', 'LoweredProofs', 'CommandBindings', 'ReadInputs', 'ReadFiles'}
COMP_FIELDS = {'Group', 'Role', 'TemplateIndex', 'Source', 'SourceSha256', 'Object', 'ObjectSha256',
    'OriginalCompileFlags', 'CompileFlags', 'SlimIR', 'IRImports', 'IRImportProof', 'CoverageNotes',
    'DiscoveryDependencies', 'Dependencies', 'CompileDependenciesVerified', 'CpuFreeIncludes',
    'CommandIndices', 'RawIRIdentityClaim', 'SourceToMachineSemanticProof'}
LOWER_FIELDS = {'Group', 'Inputs', 'Mutation', 'Stress', 'Roles', 'CommandIndices',
    'DisassemblyIncludesZeroes', 'WorkerOptionsValidated', 'EffectsValidated', 'ValidationDeferred'}


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-REPLAY:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    text = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', text) is not None and not any(c in text for c in '\0\r\n'), 'absolute drive path')
    parts = text[3:].replace('\\', '/').split('/')
    need(parts and all(p and p not in ('.', '..') and ':' not in p and p == p.rstrip(' .') for p in parts), 'canonical lexical path')
    return Path(text)


def _same(a, b):
    if type(a) is not type(b): return False
    if type(b) is dict: return set(a) == set(b) and all(_same(a[k], b[k]) for k in b)
    if type(b) is list: return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _labels():
    labels = {53: 'dump compiler specs'}
    for group, index, first in BUILDS:
        stem = 'stress' if group.startswith('stress-') else Path(COMMON[index]).stem
        for offset, label in enumerate(('discover ' + group + ' ' + stem, 'compile ' + group + ' ' + stem,
                'inspect slim ' + stem, 'imports ' + group + ' ' + stem)):
            labels[first + offset] = label
    for group, first in zip(GROUPS, LOWERS):
        labels[first] = 'lower ' + group; labels[first + 1] = 'disassemble ' + group
    return tuple(labels[i] for i in range(53, 98))


def _annotation_catalog():
    catalog = []
    runtime = {'fiber_internal_task_return', 'fiber_internal_runtime_select_scheduler_candidate',
        'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context'}
    for source, name, _ in OWNERSHIP_CATALOG:
        if name == 'fiber_internal_scheduler_store_pick_next': continue
        if name in runtime: header = 'context/context_runtime_port_abi.h'
        elif source == COMMON[0]: header = 'context/context_api_decl.h'
        elif source == COMMON[1]: header = 'context/context_runtime_state.h'
        else: header = 'context/context_panic.h'
        catalog.extend(((name, 'Declaration', header), (name, 'Definition', source)))
    return tuple(catalog)


def _command(watch, primitive, index, argv):
    need(type(index) is int and 53 <= index < 98 and index not in watch.bound, 'fixed single common command')
    row = watch.commands[index];label = _labels()[index - 53]
    need(type(row) is dict, 'command object')
    for key, value in (('Label', label), ('Argv', argv), ('Cwd', str(watch.root)), ('State', 'TERMINAL'),
            ('ExpectedExit', 0), ('Exit', 0), ('Status', 'PASS'), ('TimedOut', False)):
        watch.same(row.get(key), value, 'command %03d/' % index + key)
    need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0
         and row.get('Error') is None and type(row.get('JournalErrors', [])) is list
         and row.get('JournalErrors', []) == [], 'clean terminal command')
    prefix = 'commands/%03d' % index;journal = watch.root / (prefix + '.json')
    watch.same(primitive._json(watch.raw(journal)), row, 'per-command journal %03d' % index)
    streams = []
    for key, suffix in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
        watch.same(row.get(key), prefix + suffix, 'fixed stream path')
        streams.append(watch.raw(watch.root / (prefix + suffix), row.get(key + 'Sha256')))
    output = index == 53 or any(index == first + n for _, _, first in BUILDS for n in (2, 3)) or index in tuple(i + 1 for i in LOWERS)
    if index == 89: output = False
    need((bool(streams[1]) and streams[0] == b'') if index in LOWERS else
         streams[1] == b'' and (bool(streams[0]) if output else streams[0] == b''), 'expected clean raw streams')
    watch.bound[index] = dict(Index=index, Label=label, Argv=list(argv), ExpectedExit=0, Exit=0, Status='PASS',
        TimedOut=False, Journal=watch.binding(journal), Stdout=watch.binding(watch.root / (prefix + '.stdout')),
        Stderr=watch.binding(watch.root / (prefix + '.stderr')))
    return tuple(streams)


def _flags(native, index, project, seed, helpers):
    original = helpers['recipes'].compile_flags(native, index)
    need(type(original) is list and [a for a in original if a.startswith('-O')] == ['-Os']
         and original.count('-flto') == original.count('-fno-fat-lto-objects') == 1, 'Os slim native flags')
    view = SimpleNamespace(base=seed, result=native, source=lambda i: native['Sources'][i])
    flags = helpers['attributes_phase'].flags_for(view, index, project, helpers)
    need(type(flags) is list and [a for a in flags if a.startswith('-O')] == ['-Os']
         and flags.count('-flto') == flags.count('-fno-fat-lto-objects') == 1
         and all(flags.count(a) == 1 for a in RAW) and not any(a.startswith(('-specs', '--specs')) for a in flags), 'hostile Os flags')
    return original, flags


def _role_paths(root, group, index, specs, artifacts):
    obj = root / 'attributes/lowered' / group / 'aggregate.o'
    paths = {name: Path(str(obj) + suffix) for name, suffix in ROLE_SUFFIXES.items()}
    directory = obj.parent
    local = Path(str(obj) + '.lto_wrapper_args')
    external = root / (''.join(obj.parts[1:]) + '.lto_wrapper_args')
    need((local in artifacts) != (external in artifacts), 'one canonical wrapper owner')
    paths.update(Disassembly=directory / 'aggregate.dis', WrapperArgs=local if local in artifacts else external,
        DriverSpecs=specs, Diagnostics=root / ('commands/%03d.stderr' % index))
    fixed = {paths[k] for k in ROLE_SUFFIXES} | {paths['Disassembly']}
    optional = {Path(str(obj) + suffix) for suffix in ('.wpa.gcno', '.ltrans0.ltrans.gcno', '.lto_wrapper_args')}
    members = {p for p in artifacts if p.is_relative_to(directory)}
    need(fixed <= members <= fixed | optional, 'complete bounded manifest lowering namespace')
    return paths, sorted(members - fixed)


def _saved(watch, roles, specs, helpers):
    for key, marker in (('WpaArguments', '-fwpa'), ('LtransArguments', '-fltrans')):
        args = helpers['attribute_runner'].argument_lines(watch.raw(Path(roles[key]['Path'])))
        need([a for a in args if a in ('-fwpa', '-fltrans')] == [marker], 'exact saved stage marker')
        need([a for a in args if a.startswith(('-specs', '--specs'))] == ['-specs=' + str(specs)], 'one canonical joined specs flag')
        metadata = [a for a in args if a.startswith(('-fltrans-output-list', '--fltrans-output-list'))]
        expected = ['-fltrans-output-list=' + roles['PartitionList']['Path']] if marker == '-fwpa' else []
        need(metadata == expected, 'canonical WPA output-list metadata, no split or foreign path')


def inspect(batch, native, root, core, helpers, read):
    """Reconstruct all common commands; delegated proofs use this same reader."""
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == HELPERS and callable(read), 'exact explicit helper set/read')
    methods = dict(deps=('parse',), recipes=('batch_plan', 'require_capture_sources', 'compile_flags'),
        probes=('isolated_dependencies',), ownership=('validate_common_sources',), guard=('_same',),
        transport=('require_elf32le', 'section_records'), controls_replay=('_Reader', '_json', '_identity', '_readelf_metadata', '_binary_sections'),
        attributes=('inspect_sources', 'annotation_mutant', 'stress_sources', 'adapt_specs', 'inspect_ir_undefined'),
        attribute_runner=('argument_lines',), attributes_phase=('flags_for', 'command_plan'),
        common_lowered=('inspect', 'require_result'), common_workers=('worker_chain',), common_effects=('inspect_lowered', 'require_result'))
    need(all(callable(getattr(helpers[k], name, None)) for k, names in methods.items() for name in names), 'explicit pure helper functions')
    primitive = helpers['controls_replay'];primitive._identity(batch);primitive._identity(native)
    need(batch.get('Status') == 'BUILT-PENDING-READER' and batch.get('CommonAttributesBuilt') is True
         and batch.get('SourceOwnershipValidated') is True, 'pending common batch')
    helpers['recipes'].require_capture_sources(native)
    watch = primitive._Reader(batch, root, helpers, read)
    # A receipt cannot self-hash. Its admission is caller-owned, like the manifest.
    batch_path = root / 'results.json';batch_raw = read(batch_path, watch.authority.get(batch_path))
    watch.same(primitive._json(batch_raw), batch, 'reparsed admitted batch receipt')
    watch.consumed[batch_path] = batch_raw
    plan = helpers['recipes'].batch_plan()['Commands'][53:98]
    need(len(plan) == 45 and tuple(r['Label'] for r in plan) == _labels()
         and helpers['attributes_phase'].command_plan() == _labels()
         and all(type(r['Index']) is int and r['Index'] == 53 + i and type(r['ExpectedExit']) is int
                 and r['ExpectedExit'] == 0 and r['Component'] == 'CommonAttributes' for i, r in enumerate(plan)), 'fixed common recipe')
    seed = _path(batch.get('SourceSeed'));source_root = seed / 'source'
    capture = _path(batch.get('NativeCapture', {}).get('Build'))
    watch.same(native.get('SeedBuild'), batch.get('SourceSeed'), 'same native source seed')
    for a, b in ((root, source_root), (root, capture), (source_root, capture)):
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'disjoint roots')
    receipt = capture / 'results.json'
    watch.same(primitive._json(watch.raw(receipt, batch['NativeCapture'].get('ReceiptSha256'))), native, 'reparsed admitted native receipt')
    tools = {name: capture / 'toolchain/bin' / ('arm-none-eabi-' + suffix + '.exe')
             for name, suffix in (('Gcc', 'gcc'), ('Nm', 'nm'), ('Readelf', 'readelf'), ('Objdump', 'objdump'))}
    tools['Plugin'] = capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll'
    watch.same(native.get('CapturedCompiler'), str(tools['Gcc']), 'native compiler')
    watch.same(native.get('LTOPlugin', {}).get('Path'), str(tools['Plugin']), 'native plugin path')
    for name, path in tools.items(): watch.raw(path, native['LTOPlugin'].get('Sha256') if name == 'Plugin' else None)
    need(tuple(helpers['ownership'].REQUIRED_SOURCES) == OWNERSHIP, 'fixed ownership roles')
    names, external = set(OWNERSHIP), {}
    for i, name in enumerate(COMMON):
        row = native['Sources'][i]
        watch.same(row.get('Source'), str(source_root / name), 'canonical native source')
        watch.raw(source_root / name, row.get('SourceSha256'))
        declared = row.get('ActualCompileDependencies')
        need(type(declared) is list and declared, 'native dependency declarations')
        seen = set()
        for dep in declared:
            need(type(dep) is dict and set(dep) == {'Path', 'Sha256'}, 'closed native dependency')
            path, digest = _path(dep['Path']), _hash(dep['Sha256'])
            need(path not in seen, 'unique native dependency');seen.add(path)
            if path.is_relative_to(source_root):
                if not path.is_relative_to(source_root / 'tools/fixtures/classic_final_image'):
                    names.add(path.relative_to(source_root).as_posix())
            else:
                need(path not in external or external[path] == digest, 'consistent external dependency')
                external[path] = digest
        need(source_root / name in seen, 'native source dependency role')
    sources = {name: watch.raw(source_root / name) for name in sorted(names)}
    for row in native['Sources'][:3]:
        for dep in row['ActualCompileDependencies']:
            path = Path(dep['Path'])
            if path.is_relative_to(source_root) and path.relative_to(source_root).as_posix() in sources:
                watch.raw(path, dep['Sha256'])
    ownership = helpers['ownership'].validate_common_sources({name: sources[name] for name in OWNERSHIP})
    ownership_inputs = [dict(Source=name, **watch.binding(source_root / name)) for name in OWNERSHIP]
    watch.same(ownership, batch.get('SourceOwnership'), 'recomputed source ownership')
    watch.same(ownership_inputs, batch.get('SourceOwnershipInputs'), 'canonical four-buffer projection')
    annotations = helpers['attributes'].inspect_sources(sources)
    stdout, _ = _command(watch, primitive, 53, [str(tools['Gcc']), '-dumpspecs'])
    original = root / 'attributes/driver/original.specs';specs = root / 'attributes/driver/no-auto-gcov.specs'
    watch.same(watch.raw(original), stdout, 'original specs from command 53')
    adapted = helpers['attributes'].adapt_specs(stdout)
    watch.same(watch.raw(specs, adapted['AdaptedSha256']), adapted['Specs'], 'exact adapted specs bytes')
    adapter = {k: v for k, v in adapted.items() if k != 'Specs'}
    adapter.update(OriginalPath=str(original), AdaptedPath=str(specs))
    trees = {'positive': (source_root, sources)};controls, copies = [], []
    positive_objects = [root / 'attributes/ir/positive' / (Path(name).stem + '.o') for name in COMMON]
    for i, role in enumerate(ROLES):
        change = helpers['attributes'].annotation_mutant(role, sources);group = 'mutant-' + role
        need(change['Function'] == MUTATIONS[i + 1], 'fixed mutation function')
        trees[group] = (root / 'private' / ('attributes-' + group), change['Sources'])
        controls.append(dict(Role=role, Function=change['Function'], Edits=copy.deepcopy(change['Edits']), ReplacedIRRole=role,
            UnchangedIR=[str(p) for j, p in enumerate(positive_objects) if j != i], Detected=False, OriginalProtectedPredicateRejected=False))
    stress = helpers['attributes'].stress_sources()
    for group, key in zip(GROUPS[4:], ('Protected', 'Unprotected')):
        trees[group] = (root / 'private' / ('attributes-' + group), dict(sources, **{'stress.c': stress[key]}))
    paired = dict(Function=stress['Function'], RequiredFamilies=copy.deepcopy(stress['RequiredFamilies']), OnlyDifference=stress['OnlyDifference'],
        ProtectedSha256=sha(stress['Protected']), UnprotectedSha256=sha(stress['Unprotected']))
    for group in GROUPS[1:]:
        project, buffers = trees[group]
        wanted = {project / name for name in buffers}
        need({p for p in watch.artifacts if p.is_relative_to(project)} == wanted, 'exact private source-copy manifest membership')
        rows = []
        for name, raw in sorted(buffers.items()):
            watch.same(watch.raw(project / name, sha(raw)), raw, 'reconstructed private source bytes')
            rows.append(dict(Source=name, **watch.binding(project / name)))
        copies.append(dict(Group=group, Root=str(project), Inputs=rows))
    compiled, dependencies = [], []
    for group, index, first in BUILDS:
        project, buffers = trees[group];is_stress = group.startswith('stress-')
        relative = 'stress.c' if is_stress else COMMON[index];source = project / relative
        watch.raw(source, sha(buffers[relative]));original_flags, flags = _flags(native, index, project, seed, helpers)
        obj = root / 'attributes/ir' / group / (source.stem + '.o')
        discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d');target = 'pilot-source-' + str(index)
        _command(watch, primitive, first, [str(tools['Gcc']), *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)])
        _command(watch, primitive, first + 1, [str(tools['Gcc']), *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)])
        before = helpers['deps'].parse(watch.raw(discovery), target=target)
        after = helpers['deps'].parse(watch.raw(actual), target=target)
        need(type(before) is tuple and type(after) is tuple and before == after and before == tuple(sorted(set(before)))
             and source in before and all(isinstance(p, Path) and _path(p) == p for p in before), 'canonical same dependency sets')
        admitted = dict(external);admitted.update({project / name: sha(raw) for name, raw in buffers.items()})
        rows = helpers['probes'].isolated_dependencies(list(before), admitted, root=project, cmsis=seed / 'cmsis')
        need(project / 'tools/fixtures/classic_final_image/main.h' not in before, 'no forced main dependency')
        for dep in rows: watch.raw(_path(dep['Path']), dep['Sha256'])
        watch.same(rows, [watch.binding(p) for p in before], 'consumed dependency bytes')
        raw = watch.raw(obj);header = helpers['transport'].require_elf32le(raw)
        text, _ = _command(watch, primitive, first + 2, [str(tools['Readelf']), '-hSW', str(obj)])
        text = text.decode('ascii');primitive._readelf_metadata(text, raw, header)
        sections = helpers['transport'].section_records(text)
        watch.same(sections, primitive._binary_sections(raw, header), 'full slim section correspondence')
        need(any(r['Name'].startswith('.gnu.lto_') for r in sections) and not any(r['Size'] and 'X' in r['Flags'] for r in sections), 'slim IR without executable fallback')
        slim = dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=sections)
        nm_raw, _ = _command(watch, primitive, first + 3, [str(tools['Nm']), '--plugin', str(tools['Plugin']), '-u', str(obj)])
        names = []
        for line in nm_raw.decode('ascii').splitlines():
            match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line)
            need(match is not None, 'plugin undefined grammar');names.append(match[1])
        need(len(names) == len(set(names)), 'unique plugin imports')
        if is_stress:
            attrs = helpers['attributes']
            need(set(names) <= set(attrs.HOOKS) | set(attrs.FORWARD) | set(attrs.PROTECTED) | {attrs.COLD}, 'bounded stress IR imports')
            ir_proof = dict(UndefinedValidated=True, MachineCodeValidated=False, Control=True)
        else:
            ir_proof = helpers['attributes'].inspect_ir_undefined(names, ROLES[index], mutation=group != 'positive')
        coverage = obj.with_suffix('.gcno');note = None
        if coverage in watch.artifacts:
            watch.raw(coverage);note = watch.binding(coverage)
        compiled.append(dict(Group=group, Role=ROLES[index], TemplateIndex=index, Source=str(source), SourceSha256=sha(buffers[relative]),
            Object=str(obj), ObjectSha256=sha(raw), OriginalCompileFlags=original_flags, CompileFlags=flags, SlimIR=slim,
            IRImports=dict(Object=str(obj), Imports=names, Plugin=str(tools['Plugin']), RawNmSha256=sha(nm_raw)), IRImportProof=ir_proof,
            CoverageNotes=note, DiscoveryDependencies=rows, Dependencies=copy.deepcopy(rows), CompileDependenciesVerified=True,
            CpuFreeIncludes=True, CommandIndices=list(range(first, first + 4)), RawIRIdentityClaim=False, SourceToMachineSemanticProof=False))
        dependencies.append(dict(DiscoveryIndex=first, CompileIndex=first + 1, Target=target, Source=str(source),
            Discovery=watch.binding(discovery), Compile=watch.binding(actual), Dependencies=copy.deepcopy(rows)))
    lowerings, auxiliary = [], []
    for position, (group, first) in enumerate(zip(GROUPS, LOWERS)):
        objects = list(positive_objects)
        if 1 <= position <= 3: objects[position - 1] = Path(compiled[position + 2]['Object'])
        if position >= 4: objects = [Path(compiled[position + 2]['Object'])]
        paths, optional = _role_paths(root, group, first, specs, watch.artifacts)
        _, flags = _flags(native, 0, source_root, seed, helpers)
        _command(watch, primitive, first, [str(tools['Gcc']), *flags, '-specs=' + str(specs), *LOWER_FLAGS, *map(str, objects), '-o', str(paths['Object'])])
        dis, _ = _command(watch, primitive, first + 1, [str(tools['Objdump']), '-drwC', '-z', str(paths['Object'])])
        for path in paths.values(): watch.raw(path)
        for path in optional: watch.raw(path)
        auxiliary.append(dict(Group=group, Inputs=[watch.binding(p) for p in optional]))
        watch.same(watch.raw(paths['Disassembly']), dis, 'disassembly from exact zero-inclusive journal')
        roles = {name: watch.binding(path) for name, path in paths.items()}
        _saved(watch, roles, specs, helpers)
        lowerings.append(dict(Group=group, Inputs=[watch.binding(p) for p in objects], Mutation=MUTATIONS[position], Stress=position >= 4,
            Roles=roles, CommandIndices=[first, first + 1], DisassemblyIncludesZeroes=True,
            WorkerOptionsValidated=False, EffectsValidated=False, ValidationDeferred=True))
    need(set(watch.bound) == set(range(53, 98)), 'all forty-five commands bound')
    record = dict(Status='BUILT-PENDING-READER', Scope='NATIVE_CM3_OS_LTO_COMMON_ATTRIBUTES_BUILD_ONLY_PENDING_READER',
        Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, First=53, Stop=98, Commands=45, Compilations=compiled,
        Lowerings=lowerings, AnnotationControls=controls, SourceOwnership=ownership, SourceAnnotations=annotations, DriverAdapter=adapter,
        PairedStress=paired, DeferredReaderRequired=True, Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0, SourceIRProof=False, SourceToMachineSemanticProof=False, FullABIProof=False, FullSemanticABIProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        **dict.fromkeys(('ProtectedEffectsValidated', 'AnnotationControlsValidated', 'DispatcherStressValidated', 'ActualLtransOptionsValidated', 'CommonAttributePolicyProven'), False))
    watch.same(record, batch.get('CommonAttributesDeferredReader'), 'reconstructed producer comparison target')
    watch.same(primitive._json(watch.raw(root / 'attributes/build.json')), record, 'manifest-bound common build receipt')
    all_common = [r for r in batch.get('Compilations', []) if type(r) is dict and r.get('Group') in GROUPS]
    watch.same(all_common, compiled, 'global eight compilation comparison target')
    lowered_helpers = {k: helpers[k] for k in ('attributes', 'attribute_runner', 'common_workers', 'common_effects', 'transport')}
    lowered = helpers['common_lowered'].inspect(core, watch.raw, copy.deepcopy(lowerings), native, lowered_helpers)
    helpers['common_lowered'].require_result(lowered, lowered_helpers)
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=SOURCE, Root=str(root), SourceRoot=str(source_root), CaptureRoot=str(capture),
        AuthorityInputs=dict(BatchReceipt=watch.binding(batch_path), NativeReceipt=watch.binding(receipt),
            Manifest=watch.binding(root / 'artifacts.json'), CommandJournal=watch.binding(root / 'commands.json'),
            CommonBuild=watch.binding(root / 'attributes/build.json'), OriginalSpecs=watch.binding(original), AdaptedSpecs=watch.binding(specs)),
        ToolBindings={k: watch.binding(p) for k, p in tools.items()}, SourceOwnership=ownership, SourceOwnershipInputs=ownership_inputs,
        SourceAnnotations=annotations, SourceInputs=[dict(Source=name, **watch.binding(source_root / name)) for name in sorted(sources)],
        SourceCopies=copies, AnnotationControls=controls, PairedStress=paired, DriverAdapter=adapter, Compilations=compiled,
        DependencyBindings=dependencies, Lowerings=lowerings, LoweringAuxiliaryInputs=auxiliary, LoweredProofs=lowered,
        CommandBindings=[watch.bound[i] for i in range(53, 98)],
        ReadInputs=[watch.binding(p) for p in sorted(watch.consumed)], ReadFiles=len(watch.consumed),
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    require_result(proof)
    return proof


def _closed(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), 'closed ' + label)


def _json_tree(value):
    if type(value) is dict:
        need(all(type(k) is str for k in value), 'JSON object keys')
        for v in value.values(): _json_tree(v)
    elif type(value) is list:
        for v in value: _json_tree(v)
    else:
        need(value is None or type(value) in (str, bool, int) or type(value) is float and math.isfinite(value), 'finite JSON evidence')


def require_result(proof):
    """Close component roles and nonclaims, not the delegated effect semantics.

    The composer also calls common_lowered.require_result with its authenticated
    helpers. No module or helper object is retained here for later validation.
    """
    _closed(proof, FIELDS, 'common result');_json_tree(proof)
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
            ('Linkage', 'direct'), ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(proof[key]) is str and proof[key] == value, 'fixed identity/' + key)
    need(proof['LTO'] is True, 'LTO')
    for key, value in COUNTS.items(): need(type(proof[key]) is int and proof[key] == value, 'typed count/' + key)
    for key in FACTS: need(proof[key] is True, 'fact/' + key)
    for key in NONCLAIMS: need(proof[key] is False, 'nonclaim/' + key)
    root, sr, capture = (_path(proof[k]) for k in ('Root', 'SourceRoot', 'CaptureRoot'))
    need(sr.name == 'source', 'canonical source-root suffix')
    for a, b in ((root, sr), (root, capture), (sr, capture)):
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'disjoint roots')
    reads = {};used = set()
    need(type(proof['ReadFiles']) is int and type(proof['ReadInputs']) is list
         and proof['ReadFiles'] == len(proof['ReadInputs']) > 0, 'read count')
    for row in proof['ReadInputs']:
        _closed(row, ('Path', 'Sha256'), 'read binding');path = _path(row['Path'])
        need(path not in reads, 'unique read path');reads[path] = _hash(row['Sha256'])
    need(list(reads) == sorted(reads), 'ordered read bindings')

    def binding(row, path=None, extra=()):
        _closed(row, {'Path', 'Sha256'} | set(extra), 'consumed binding')
        actual = _path(row['Path'])
        need((path is None or actual == path) and reads.get(actual) == _hash(row['Sha256']), 'read-role join')
        used.add(actual);return actual

    authorities = dict(BatchReceipt=root / 'results.json', NativeReceipt=capture / 'results.json', Manifest=root / 'artifacts.json',
        CommandJournal=root / 'commands.json', CommonBuild=root / 'attributes/build.json',
        OriginalSpecs=root / 'attributes/driver/original.specs', AdaptedSpecs=root / 'attributes/driver/no-auto-gcov.specs')
    _closed(proof['AuthorityInputs'], authorities, 'authority roles')
    for name, path in authorities.items(): binding(proof['AuthorityInputs'][name], path)
    tools = {name: capture / 'toolchain/bin' / ('arm-none-eabi-' + suffix + '.exe')
        for name, suffix in (('Gcc', 'gcc'), ('Nm', 'nm'), ('Readelf', 'readelf'), ('Objdump', 'objdump'))}
    tools['Plugin'] = capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll'
    _closed(proof['ToolBindings'], tools, 'tools')
    for name, path in tools.items(): binding(proof['ToolBindings'][name], path)
    tool = {name: str(path) for name, path in tools.items()}
    commands = proof['CommandBindings'];need(type(commands) is list and len(commands) == 45, '45 command bindings')
    by_index = {}
    for index, cmd in zip(range(53, 98), commands):
        _closed(cmd, ('Index', 'Label', 'Argv', 'ExpectedExit', 'Exit', 'Status', 'TimedOut', 'Journal', 'Stdout', 'Stderr'), 'command')
        need(type(cmd['Index']) is int and cmd['Index'] == index and cmd['Label'] == _labels()[index - 53]
             and type(cmd['ExpectedExit']) is int and cmd['ExpectedExit'] == 0 and type(cmd['Exit']) is int and cmd['Exit'] == 0
             and cmd['Status'] == 'PASS' and cmd['TimedOut'] is False and type(cmd['Argv']) is list
             and cmd['Argv'] and all(type(a) is str for a in cmd['Argv']), 'fixed command metadata')
        for key, suffix in (('Journal', '.json'), ('Stdout', '.stdout'), ('Stderr', '.stderr')):
            binding(cmd[key], root / ('commands/%03d%s' % (index, suffix)))
        need(cmd['Stderr']['Sha256'] != sha(b'') if index in LOWERS else cmd['Stderr']['Sha256'] == sha(b''), 'diagnostic stream disposition')
        if index == 89 or index not in (53,) + tuple(f + n for _, _, f in BUILDS for n in (2, 3)) + tuple(f + 1 for f in LOWERS):
            need(cmd['Stdout']['Sha256'] == sha(b''), 'clean command stdout')
        by_index[index] = cmd
    need(by_index[53]['Argv'] == [tool['Gcc'], '-dumpspecs']
         and by_index[53]['Stdout']['Sha256'] == proof['AuthorityInputs']['OriginalSpecs']['Sha256'], 'dumpspecs byte authority')
    adapter = proof['DriverAdapter']
    _closed(adapter, ('OriginalPath', 'AdaptedPath', 'OriginalSha256', 'AdaptedSha256', 'Offset', 'Original', 'Replacement', 'OnlyRemovedBytes', 'InstrumentationCounterFlagsAdded'), 'specs adapter')
    need(adapter['OriginalPath'] == str(authorities['OriginalSpecs']) and adapter['AdaptedPath'] == str(authorities['AdaptedSpecs'])
         and adapter['OriginalSha256'] == proof['AuthorityInputs']['OriginalSpecs']['Sha256']
         and adapter['AdaptedSha256'] == proof['AuthorityInputs']['AdaptedSpecs']['Sha256']
         and type(adapter['Offset']) is int and adapter['Offset'] >= 0
         and adapter['Original'] == '%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}'
         and adapter['Replacement'] == '%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:}'
         and adapter['OnlyRemovedBytes'] == '-lgcov' and adapter['InstrumentationCounterFlagsAdded'] is False, 'bounded spec deletion')
    source_rows = proof['SourceInputs'];need(type(source_rows) is list and len(source_rows) >= 4, 'source inventory')
    source_map = {}
    for row in source_rows:
        path = binding(row, extra=('Source',));name = row['Source']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name) is not None
             and path == sr / name and name not in source_map, 'canonical source inventory')
        source_map[name] = row['Sha256']
    need(list(source_map) == sorted(source_map) and set(OWNERSHIP) <= set(source_map), 'ordered source inventory')
    ownership_rows = proof['SourceOwnershipInputs'];need(type(ownership_rows) is list and len(ownership_rows) == 4, 'four-source ownership projection')
    for name, row in zip(OWNERSHIP, ownership_rows):
        binding(row, sr / name, ('Source',));need(row['Source'] == name and row['Sha256'] == source_map[name], 'ownership source join')
    _require_ownership(proof['SourceOwnership'], source_map)
    annotations = proof['SourceAnnotations'];_closed(annotations, ('ProtectedDefinitions', 'ProtectedDeclarations', 'Records', 'GeneratedEffectsValidated', 'RequiredCellCount'), 'annotations')
    need(type(annotations['ProtectedDefinitions']) is int and annotations['ProtectedDefinitions'] == 14
         and type(annotations['ProtectedDeclarations']) is int and annotations['ProtectedDeclarations'] == 14
         and annotations['GeneratedEffectsValidated'] is False and type(annotations['RequiredCellCount']) is int
         and annotations['RequiredCellCount'] == 0 and type(annotations['Records']) is list and len(annotations['Records']) == 28, 'source-only annotation counts')
    annotation_sites = set()
    for row, expected in zip(annotations['Records'], _annotation_catalog()):
        _closed(row, ('Name', 'Site', 'Path', 'SourceSha256', 'AnchorSha256'), 'annotation anchor')
        need((row['Name'], row['Site'], row['Path']) == expected and row['Path'] in source_map
             and row['SourceSha256'] == source_map[row['Path']] and (row['Name'], row['Site']) not in annotation_sites, 'annotation source hash join')
        annotation_sites.add((row['Name'], row['Site']));_hash(row['AnchorSha256'])
    copies = proof['SourceCopies'];need(type(copies) is list and len(copies) == 5, 'five source copy trees')
    copy_maps = {'positive': source_map}
    for group, copy_row in zip(GROUPS[1:], copies):
        _closed(copy_row, ('Group', 'Root', 'Inputs'), 'private copy tree');project = root / 'private' / ('attributes-' + group)
        need(copy_row['Group'] == group and copy_row['Root'] == str(project) and type(copy_row['Inputs']) is list, 'canonical private tree')
        expected_names = sorted(set(source_map) | ({'stress.c'} if group.startswith('stress-') else set()))
        need(len(copy_row['Inputs']) == len(expected_names), 'complete private copy tree');mapped = {}
        for name, row in zip(expected_names, copy_row['Inputs']):
            binding(row, project / name, ('Source',));need(row['Source'] == name, 'ordered private copy name');mapped[name] = row['Sha256']
        copy_maps[group] = mapped
    controls = proof['AnnotationControls'];need(type(controls) is list and len(controls) == 3, 'three annotation controls')
    positive = [root / 'attributes/ir/positive' / (Path(name).stem + '.o') for name in COMMON]
    for i, (role, control) in enumerate(zip(ROLES, controls)):
        _closed(control, ('Role', 'Function', 'Edits', 'ReplacedIRRole', 'UnchangedIR', 'Detected', 'OriginalProtectedPredicateRejected'), 'annotation control')
        need(control['Role'] == control['ReplacedIRRole'] == role and control['Function'] == MUTATIONS[i + 1]
             and control['Detected'] is False and control['OriginalProtectedPredicateRejected'] is False
             and _same(control['UnchangedIR'], [str(p) for j, p in enumerate(positive) if j != i])
             and type(control['Edits']) is list and len(control['Edits']) == 2, 'source-only mutation control')
        edits = set()
        expected_edits = [(path, site, name) for name, site, path in _annotation_catalog() if name == MUTATIONS[i + 1]]
        need(len(expected_edits) == 2, 'fixed mutant declaration/definition catalog')
        for edit, expected in zip(control['Edits'], expected_edits):
            _closed(edit, ('Path', 'BeforeSha256', 'AfterSha256', 'Function', 'RemovedTokens', 'Site'), 'mutation edit')
            name = edit['Path'];need((edit['Path'], edit['Site'], edit['Function']) == expected and name in source_map and name not in edits
                and type(edit['RemovedTokens']) is int and edit['RemovedTokens'] == 1 and edit['Site'] in ('Declaration', 'Definition')
                and edit['BeforeSha256'] == source_map[name] and edit['AfterSha256'] == copy_maps[GROUPS[i + 1]][name]
                and edit['BeforeSha256'] != edit['AfterSha256'], 'exact mutation edit hash joins');edits.add(name)
        need(edits == {n for n in source_map if source_map[n] != copy_maps[GROUPS[i + 1]][n]}, 'only two private mutation files')
    paired = proof['PairedStress'];_closed(paired, ('Function', 'RequiredFamilies', 'OnlyDifference', 'ProtectedSha256', 'UnprotectedSha256'), 'paired stress')
    families = dict(FunctionInstrumentation=['__cyg_profile_func_enter', '__cyg_profile_func_exit'], StackProtector=['__stack_chk_guard', '__stack_chk_fail'],
        Profiling=['__gcov_init', '__gcov_exit', '__gcov_merge_add'], UndefinedBehavior=['__ubsan_handle_add_overflow', '__ubsan_handle_out_of_bounds'], SanitizerCoverage=['__sanitizer_cov_trace_pc'])
    need(paired['Function'] == 'ctxrt_attribute_stress' and paired['OnlyDifference'] == 'one CTXRT_DISPATCH_ATTR definition token'
         and _same(paired['RequiredFamilies'], families) and paired['ProtectedSha256'] == copy_maps[GROUPS[4]]['stress.c']
         and paired['UnprotectedSha256'] == copy_maps[GROUPS[5]]['stress.c'] and paired['ProtectedSha256'] != paired['UnprotectedSha256'], 'paired stress hash joins')
    for group in GROUPS[4:]: need(all(copy_maps[group][n] == source_map[n] for n in source_map), 'unchanged stress support tree')
    _require_builds(proof, root, sr, tool, copy_maps, by_index, binding, reads, used)
    need(used == set(reads), 'exact bounded read-role closure')
    return proof


def _require_ownership(value, sources):
    false = ('InputAuthenticationProof', 'ActualProviderProof', 'DependencyProof', 'ElfProof', 'CompileProof', 'CompilerExecution',
        'FullABIProof', 'FullSemanticABIProof', 'ArbitraryPointerAliasProof', 'CpuExecution', 'BoardExecution', 'RequiredCellSatisfied', 'GlobalFreezeQualified')
    _closed(value, set(false) | {'Status', 'Scope', 'SourceFactsOnly', 'SourceRoles', 'SourceHashes', 'AuthoredIncludes', 'CheckedFunctions',
        'CanonicalPrivateStorageDeclarations', 'RuntimeSourceManifestMatched', 'RequiredCellsSatisfied'}, 'ownership proof')
    need(value['Status'] == 'PASS' and value['Scope'] == 'CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY'
         and all(value[k] is False for k in false) and all(value[k] is True for k in
            ('SourceFactsOnly', 'CanonicalPrivateStorageDeclarations', 'RuntimeSourceManifestMatched'))
         and type(value['RequiredCellsSatisfied']) is int and value['RequiredCellsSatisfied'] == 0
         and _same(value['SourceRoles'], dict(zip(ROLES, COMMON)))
         and _same(value['SourceHashes'], {n: sources[n] for n in OWNERSHIP}), 'source-only ownership closure')
    authored = dict(engine=['context_api_decl.h', 'context_panic.h', 'context_runtime_port_abi.h', 'context_runtime_state.h', 'context_port_abi.h'],
        state=['context_runtime_state.h', 'context_panic.h', 'context_runtime_port_abi.h'], panic=['context_panic.h', 'context_port_abi.h'])
    need(_same(value['AuthoredIncludes'], authored) and type(value['CheckedFunctions']) is list and len(value['CheckedFunctions']) == 15, 'fixed ownership source surface')
    for row, expected in zip(value['CheckedFunctions'], OWNERSHIP_CATALOG):
        _closed(row, ('Source', 'Function', 'Signature', 'CheckedBodyTextSha256'), 'ownership function')
        need((row['Source'], row['Function'], row['Signature']) == expected, 'ordered canonical ownership function/source/signature')
        _hash(row['CheckedBodyTextSha256'])


def _require_builds(proof, root, sr, tool, copy_maps, commands, binding, reads, used):
    builds, deps = proof['Compilations'], proof['DependencyBindings']
    need(type(builds) is list and len(builds) == 8 and type(deps) is list and len(deps) == 8, 'eight builds and dependency pairs')
    for (group, index, first), row, dep in zip(BUILDS, builds, deps):
        _closed(row, COMP_FIELDS, 'compilation');stress = group.startswith('stress-')
        project = sr if group == 'positive' else root / 'private' / ('attributes-' + group)
        name = 'stress.c' if stress else COMMON[index];source = project / name
        obj = root / 'attributes/ir' / group / (Path(name).stem + '.o')
        need(row['Group'] == group and row['Role'] == ROLES[index] and type(row['TemplateIndex']) is int and row['TemplateIndex'] == index
             and row['Source'] == str(source) and row['SourceSha256'] == copy_maps[group][name]
             and row['Object'] == str(obj) and reads.get(obj) == _hash(row['ObjectSha256'])
             and _same(row['CommandIndices'], list(range(first, first + 4))), 'fixed build roles')
        used.update((source, obj))
        need(row['CompileDependenciesVerified'] is row['CpuFreeIncludes'] is True
             and row['RawIRIdentityClaim'] is row['SourceToMachineSemanticProof'] is False, 'bounded compilation facts')
        for key in ('OriginalCompileFlags', 'CompileFlags'):
            flags = row[key];need(type(flags) is list and all(type(a) is str for a in flags)
                and [a for a in flags if a.startswith('-O')] == ['-Os']
                and flags.count('-flto') == flags.count('-fno-fat-lto-objects') == 1, 'Os slim compile flags')
        flags = row['CompileFlags'];need(all(flags.count(a) == 1 for a in RAW) and '-include' not in flags
             and not any(a.startswith(('-specs', '--specs')) for a in flags), 'raw hostile isolated flags')
        _closed(dep, ('DiscoveryIndex', 'CompileIndex', 'Target', 'Source', 'Discovery', 'Compile', 'Dependencies'), 'dependency pair')
        before, after = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d');target = 'pilot-source-' + str(index)
        need(type(dep['DiscoveryIndex']) is int and dep['DiscoveryIndex'] == first and type(dep['CompileIndex']) is int
             and dep['CompileIndex'] == first + 1 and dep['Target'] == target and dep['Source'] == str(source), 'dependency journal roles')
        binding(dep['Discovery'], before);binding(dep['Compile'], after)
        need(_same(row['DiscoveryDependencies'], dep['Dependencies']) and _same(row['Dependencies'], dep['Dependencies'])
             and type(dep['Dependencies']) is list and dep['Dependencies'], 'discovery/compile dependency join')
        paths = [binding(r) for r in dep['Dependencies']]
        need(paths == sorted(set(paths)) and source in paths and project / 'tools/fixtures/classic_final_image/main.h' not in paths
             and not any(p.is_relative_to(sr.parent / 'cmsis') or p.is_relative_to(project / 'fiber/port') for p in paths), 'canonical isolated dependency set')
        need(commands[first]['Argv'] == [tool['Gcc'], *flags, '-M', '-MF', str(before), '-MT', target, str(source)]
             and commands[first + 1]['Argv'] == [tool['Gcc'], *flags, '-MD', '-MF', str(after), '-MT', target, '-c', str(source), '-o', str(obj)]
             and commands[first + 2]['Argv'] == [tool['Readelf'], '-hSW', str(obj)]
             and commands[first + 3]['Argv'] == [tool['Nm'], '--plugin', tool['Plugin'], '-u', str(obj)], 'exact build command argv')
        ir = row['SlimIR'];_closed(ir, ('Object', 'Sha256', 'SlimIR', 'Sections'), 'slim IR')
        need(ir['Object'] == str(obj) and ir['Sha256'] == row['ObjectSha256'] and ir['SlimIR'] is True
             and type(ir['Sections']) is list and ir['Sections'], 'slim role join')
        for i, section in enumerate(ir['Sections']):
            _closed(section, ('Index', 'Name', 'Type', 'Address', 'Offset', 'Size', 'Flags'), 'section claim')
            need(type(section['Index']) is int and section['Index'] == i and all(type(section[k]) is str for k in ('Name', 'Type', 'Flags'))
                 and all(type(section[k]) is int and section[k] >= 0 for k in ('Address', 'Offset', 'Size')), 'typed full section claims')
        need(any(s['Name'].startswith('.gnu.lto_') for s in ir['Sections']) and not any(s['Size'] and 'X' in s['Flags'] for s in ir['Sections']), 'slim section census')
        imports = row['IRImports'];_closed(imports, ('Object', 'Imports', 'Plugin', 'RawNmSha256'), 'IR imports')
        need(imports['Object'] == str(obj) and imports['Plugin'] == tool['Plugin'] and imports['RawNmSha256'] == commands[first + 3]['Stdout']['Sha256']
             and type(imports['Imports']) is list and all(type(n) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) for n in imports['Imports'])
             and len(imports['Imports']) == len(set(imports['Imports'])), 'plugin raw stdout role join')
        ip = row['IRImportProof']
        _closed(ip, ('UndefinedValidated', 'MachineCodeValidated', 'Control') if stress else
            ('Role', 'ExpectedUndefined', 'CompilerImports', 'UndefinedValidated', 'MachineCodeValidated', 'RawFlagActivationValidated'), 'IR import proof')
        need(ip['UndefinedValidated'] is True and ip['MachineCodeValidated'] is False, 'IR-only import proof')
        if stress: need(ip['Control'] is True, 'stress import selector')
        else:
            need(ip['Role'] == ROLES[index] and ip['RawFlagActivationValidated'] is False
                 and type(ip['ExpectedUndefined']) is list and type(ip['CompilerImports']) is list
                 and all(type(n) is str for n in ip['ExpectedUndefined'] + ip['CompilerImports'])
                 and set(imports['Imports']) == set(ip['ExpectedUndefined']) | set(ip['CompilerImports']), 'IR proof import join')
        if row['CoverageNotes'] is not None: binding(row['CoverageNotes'], obj.with_suffix('.gcno'))
    lowerings = proof['Lowerings'];aux = proof['LoweringAuxiliaryInputs']
    need(type(lowerings) is list and len(lowerings) == 6 and type(aux) is list and len(aux) == 6, 'six lowered cohorts')
    specs = root / 'attributes/driver/no-auto-gcov.specs'
    for pos, (group, first, row, extra) in enumerate(zip(GROUPS, LOWERS, lowerings, aux)):
        _closed(row, LOWER_FIELDS, 'lowering');_closed(row['Roles'], ROLE_NAMES, 'fourteen lowering roles')
        need(row['Group'] == group and row['Mutation'] == MUTATIONS[pos] and row['Stress'] is (pos >= 4)
             and _same(row['CommandIndices'], [first, first + 1]) and row['DisassemblyIncludesZeroes'] is row['ValidationDeferred'] is True
             and row['WorkerOptionsValidated'] is row['EffectsValidated'] is False, 'fixed deferred lowering selectors')
        paths, optional = _role_paths(root, group, first, specs, reads)
        for name, path in paths.items(): binding(row['Roles'][name], path)
        _closed(extra, ('Group', 'Inputs'), 'lowering auxiliary roles')
        need(extra['Group'] == group and type(extra['Inputs']) is list and len(extra['Inputs']) == len(optional), 'auxiliary membership')
        for b, p in zip(extra['Inputs'], optional): binding(b, p)
        objects = [Path(r['Object']) for r in builds[:3]]
        if 1 <= pos <= 3: objects[pos - 1] = Path(builds[pos + 2]['Object'])
        if pos >= 4: objects = [Path(builds[pos + 2]['Object'])]
        need(type(row['Inputs']) is list and len(row['Inputs']) == len(objects), 'cohort object count')
        for item, obj in zip(row['Inputs'], objects): binding(item, obj)
        flags = builds[0]['CompileFlags']
        need(commands[first]['Argv'] == [tool['Gcc'], *flags, '-specs=' + str(specs), *LOWER_FLAGS, *map(str, objects), '-o', str(paths['Object'])]
             and commands[first + 1]['Argv'] == [tool['Objdump'], '-drwC', '-z', str(paths['Object'])]
             and row['Roles']['Diagnostics']['Sha256'] == commands[first]['Stderr']['Sha256']
             and row['Roles']['Disassembly']['Sha256'] == commands[first + 1]['Stdout']['Sha256'], 'lower journal/object/stream joins')
    delegated = proof['LoweredProofs']
    _closed(delegated, set(LOWERED_NONCLAIMS + LOWERED_FACTS) | set(LOWERED_COUNTS) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage',
        'LTO', 'Lowerings', 'ResolvedWorkers', 'WorkerChains', 'CommonMachines', 'UnresolvedAttribution', 'CommonAttributionClosed', 'ReadInputs'}, 'delegated outer result')
    need(_same(delegated['Lowerings'], lowerings) and delegated['Scope'] == 'CM3_OS_LTO_SIX_COMMON_LOWERED_COHORTS_ONLY'
         and delegated['Profile'] == 'CM3' and delegated['Mode'] == 'Os-lto' and delegated['Linkage'] == 'direct'
         and delegated['LTO'] is True, 'delegated lowered authority boundary')
    for key in LOWERED_NONCLAIMS: need(delegated[key] is False, 'delegated nonclaim/' + key)
    for key in LOWERED_FACTS: need(delegated[key] is True, 'delegated fact/' + key)
    for key, value in LOWERED_COUNTS.items(): need(type(delegated[key]) is int and delegated[key] == value, 'delegated count/' + key)
    unresolved = delegated['UnresolvedAttribution']
    need(type(unresolved) is list and delegated['CommonAttributionClosed'] is (not unresolved)
         and delegated['Status'] == ('CM3-OS-LTO-COMMON-LOWERED-PENDING-ATTRIBUTION' if unresolved else
             'CM3-OS-LTO-COMMON-LOWERED-REPLAYED-NOT-QUALIFIED'), 'explicit attribution disposition')
    for key, fields in (('WorkerChains', ('Group', 'Proof')), ('CommonMachines', ('Group', 'Machines'))):
        rows = delegated[key];need(type(rows) is list and len(rows) == 6, 'six delegated evidence cohorts')
        for group, row in zip(GROUPS, rows):
            _closed(row, fields, 'delegated cohort');need(row['Group'] == group, 'delegated cohort order')
            if key == 'WorkerChains': need(type(row['Proof']) is dict, 'delegated worker proof object')
            else:
                need(type(row['Machines']) is list and len(row['Machines']) == 2, 'two delegated machine roles')
                for role, machine in zip(('Object', 'Machine'), row['Machines']):
                    _closed(machine, ('Role', 'Proof', 'OriginalProtectedPredicateRejected'), 'delegated machine boundary')
                    pos = GROUPS.index(group)
                    need(machine['Role'] == role and type(machine['Proof']) is dict
                         and machine['OriginalProtectedPredicateRejected'] is (MUTATIONS[pos] is not None), 'delegated machine selector')
    delegated_reads = delegated.get('ReadInputs')
    need(type(delegated_reads) is list and len(delegated_reads) == 89
         and type(delegated.get('ReadFiles')) is int and delegated['ReadFiles'] == 89, 'delegated fixed reader closure')
    local = set()
    for row in delegated_reads:
        _closed(row, ('Path', 'Sha256', 'Bytes'), 'lowered read binding')
        need(type(row['Bytes']) is int and row['Bytes'] > 0, 'nonempty lowered input')
        path = binding(row, extra=('Bytes',));need(path not in local, 'unique delegated read');local.add(path)
    workers = delegated.get('ResolvedWorkers');_closed(workers, ('lto1', 'as'), 'delegated worker identities')
    for name, row in workers.items():
        path = binding(row);need(path in local and path.name == name + '.exe', 'delegated named worker join')
    expected = {Path(b['Path']) for row in lowerings for b in list(row['Roles'].values()) + row['Inputs']}
    expected.update(Path(b['Path']) for b in workers.values())
    need(local == expected, 'exact delegated eighty-nine role paths')
