"""Pure reconstruction of the recorded Os port component [98,134).

The caller owns source/helper admission and one immutable reader. This leaf
replays command provenance, not compilation or whole-cell semantics. Worker
and bounded machine checks belong to the explicit port_lowered adapter.
"""

import copy
import hashlib
import math
from pathlib import Path
import re
from types import SimpleNamespace


STATUS = 'CM3-OS-LTO-PORT-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_36_COMMAND_PORT_COMPONENT_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
HELPERS = frozenset(('deps', 'recipes', 'guard', 'transport', 'controls_replay', 'ownership',
    'attributes', 'port_phase', 'port_runner', 'policy', 'census', 'effects', 'port_lowered'))
ADAPTER_HELPERS = ('port_runner', 'port_phase', 'transport', 'census', 'policy', 'effects', 'attributes')
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
OWNERSHIP = COMMON + ('tools/runtime_sources.json',)
SELECTED = ('fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c', 'fiber/port/ARM_CM3/fiber_port_exception.c')
ORDER = COMMON + SELECTED + ('fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
GROUPS = ('selected', 'stress-supported', 'stress-raw', 'Final')
ROLES = ('runtime', 'boot', 'exception')
BUILDS = (('selected', 3, 99, 5), ('selected', 4, 104, 5), ('selected', 5, 109, 5),
    ('stress-supported', 3, 117, 4), ('stress-raw', 3, 124, 4))
LOWERS = (114, 121, 128, 131)
RAW = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs', '-ftest-coverage',
    '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
COUNTERS = ('-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs', '-fno-test-coverage',
    '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc', '-mgeneral-regs-only')
LOWER_FLAGS = ('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
    '-nostdlib', '-r', '-flinker-output=nolto-rel')
SUFFIXES = ('', '.ltrans.out', '.ltrans0.ltrans.args.0', '.ltrans0.ltrans.o', '.ltrans0.ltrans.s',
    '.ltrans0.ltrans_args', '.ltrans0.o', '.ltrans_args', '.res', '.wpa.args.0')
COUNTS = dict(First=98, Stop=134, BatchCommands=134, CommandsReplayed=36, SuccessfulCommands=36,
    IRBuilds=5, DependencyFiles=10, SlimIRInspections=5, IRImportInspections=5, IRDefinitionInspections=3,
    SelectedDefinitions=31, SelectedPublicFunctions=29, SelectedCohortObjects=2, SelectedSources=3,
    StressSources=2, WorkerPlans=4, DeferredRoles=18, MachineImages=8, NativeObjects=9,
    UnchangedOtherSix=6, RequiredCellsSatisfied=0)
FACTS = ('PortCommandsReplayed', 'RecordedCommandProvenanceReplayed', 'SourceOwnershipReplayed',
    'SelectedSourcesUnchanged', 'ConsumedDependenciesReplayed', 'SlimIRMetadataReplayed', 'IRImportSurfacesReplayed',
    'SelectedIRDefinitionSurfaceReplayed', 'DriverAdapterReplayed', 'PairedStressSourcesReconstructed',
    'LoweringCohortsReplayed', 'FinalRecipeReconstructed', 'OtherSixObjectHashesReplayed',
    'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsExactManifestMembership', 'CallerOwnsHelperAuthentication',
    'CallerOwnsDetailedLoweredResultValidation', 'CallerOwnsCoreImmutableBinding')
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'CompleteCellProof', 'WholeCellProof',
    'SelectedPortAttributePolicyProven', 'GeneralRegistersOnlyEffectProved', 'FullAttributeEquivalence', 'TransitiveProtection',
    'RawCommonAttributesAloneProved', 'UnchangedOtherSixGeneratedBodies', 'FullABIProof', 'FullSemanticABIProof',
    'FullInstructionSemantics', 'FullIRSemantics', 'SourceIRProof', 'SourceToIRSemanticProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'OriginalTranslationUnitMachineOwnership', 'AllRelocationDestinationSemanticsValidated',
    'CanonicalProtocolValidated', 'FinalRootTransferProtocolsValidated', 'FinalReferenceParity', 'IRImportClosureValidated',
    'WholeSlotAccessIsolation', 'ProducerCompilersReexecuted', 'CompilerExecuted', 'NativeCaptureProvenanceReplayed',
    'OsProcessTraceVerified', 'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
FIELDS = set(COUNTS) | set(FACTS + NONCLAIMS) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort',
    'SourceInventorySha256', 'Root', 'SourceRoot', 'CaptureRoot', 'AuthorityInputs', 'ToolBindings', 'SourceInputs',
    'SourceOwnershipInputs', 'SourceOwnership', 'SelectedSourceHashes', 'SourceCohort', 'NativeObjectBindings',
    'DriverAdapter', 'StressSourceInputs', 'PairedStress', 'Compilations', 'DependencyBindings', 'IRDefinitionSurface',
        'CommandBindings', 'Lowerings', 'FinalLink', 'Inputs', 'PlanBindings', 'LoweredProofs', 'ReadInputs', 'ReadFiles',
        'DependencyPairEntries', 'DependencyListedRows', 'UniqueDependencyPaths'}
COMP_FIELDS = {'Group', 'TemplateIndex', 'Source', 'SourceSha256', 'Object', 'ObjectSha256', 'OriginalCompileFlags',
    'CompileFlags', 'SlimIR', 'IRImports', 'IRDefinitions', 'CoverageNotes', 'DiscoveryDependencyFile', 'CompileDependencyFile',
    'DiscoveryDependencies', 'Dependencies', 'CompileDependenciesVerified', 'OriginalSelectedSourceUnchanged',
    'SupportedPolicy', 'CommandIndices', 'RawIRIdentityClaim', 'SourceToMachineSemanticProof'}
LOWER_FIELDS = {'Group', 'Object', 'ObjectSha256', 'Inputs', 'ActualWorker', 'Disassembly', 'WorkerDisassembly',
    'WrapperArgs', 'WrapperArgsSha256', 'SavedOutputs', 'SupportedPolicy', 'CommandIndices', 'MachineEffectsValidated', 'StressActivationValidated'}
FINAL_FALSE = ('RawCommonAttributesAloneProved', 'UnchangedOtherSixGeneratedBodies', 'OriginalTranslationUnitOwnership',
    'MachineEffectsValidated', 'FinalMappingValidated')
FINAL_FIELDS = set(FINAL_FALSE) | {'Path', 'Sha256', 'Map', 'MapSha256', 'ActualWorker', 'Disassembly', 'WorkerDisassembly',
    'Objects', 'UnchangedOtherSixObjects', 'OriginalFinalStageArgv', 'Argv', 'WrapperArgs', 'WrapperArgsSha256',
    'SavedOutputs', 'GlobalSupportedCounterPolicy', 'CommandIndices'}
PRIVATE = ('fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_'
    'u00010000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
RUNTIME = ('fiber_port_init_context_frame', 'fiber_port_panic_wait', 'fiber_port_require_scheduler_configuration_environment',
    'fiber_port_runtime_memory_barrier', 'fiber_port_runtime_prepare_start', 'fiber_port_runtime_schedule',
    'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_scheduler_pick_first_from_start',
    'fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
BOOT = ('fiber_fallback_initial_msp', 'fiber_port_runtime_prepare', 'fiber_port_boot_prepare_msp_for_start',
    'fiber_port_boot_record_compute_hash', 'fiber_port_boot_record_fast_check', 'fiber_port_boot_record_check',
    'fiber_port_boot_create', 'fiber_port_boot_check', 'fiber_port_require_start_environment', 'fiber_port_context_init',
    'fiber_port_context_validate_save_current', 'fiber_port_context_validate_restore', 'fiber_port_context_prepare_first_start',
    'fiber_port_require_start_interrupt_state')
DEFINITION_CATALOG = dict(runtime=dict([(n, 'T') for n in RUNTIME] + [(PRIVATE, 'D'), ('fiber_port_storage_cohort_arm_cm3_v1_r0', 'D')]),
    boot={n: 'W' if n == 'fiber_fallback_initial_msp' else 'T' for n in BOOT},
    exception=dict(fiber_exception_runtime_check='T', fiber_pendsv_init_lowest_priority='T'))
OWNERSHIP_SIGNATURES = (
    (COMMON[0], 'void fiber_internal_task_return(void)'),
    (COMMON[0], 'void ctxrt_v1_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg)'),
    (COMMON[0], 'CtxrtContextV1 *ctxrt_v1_current(void)'), (COMMON[0], 'void ctxrt_v1_start(void)'),
    (COMMON[0], 'void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)'), (COMMON[0], 'void ctxrt_v1_yield(void)'),
    (COMMON[1], 'void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 pick_next, void *user)'),
    (COMMON[1], 'CtxrtContextV1 *fiber_internal_runtime_load_current_context(void)'),
    (COMMON[1], 'CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current)'),
    (COMMON[1], 'void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next)'),
    (COMMON[1], 'void fiber_internal_runtime_require_current_context(void)'),
    (COMMON[1], 'uint32_t fiber_internal_scheduler_is_configured(void)'),
    (COMMON[1], 'void fiber_internal_runtime_close_context_configuration(void)'),
    (COMMON[1], 'uint32_t fiber_internal_runtime_context_configuration_is_open(void)'), (COMMON[2], 'void fiber_panic(char code)'))
LOWERED_NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'WholeCellProof', 'CompleteCellProof',
    'SelectedPortAttributePolicyProven', 'GeneralRegistersOnlyEffectProved', 'FullAttributeEquivalence', 'TransitiveProtection', 'FullABIProof',
    'FullSemanticABIProof', 'FullInstructionSemantics', 'FullIRSemantics', 'IRImportClosureValidated', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'OriginalTranslationUnitMachineOwnership', 'AllRelocationDestinationSemanticsValidated', 'CanonicalProtocolValidated',
    'FinalRootTransferProtocolsValidated', 'FinalReferenceParity', 'FinalMappingValidated', 'StartupTransferSemanticsValidated', 'WrapperSemanticsValidated',
    'ResolutionSemanticsValidated', 'AssemblySemanticsValidated', 'JournalBindingsValidated', 'OsProcessTraceVerified', 'ProducerCompilersReexecuted',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
LOWERED_FACTS = ('WorkerChainsReplayed', 'MachineCensusesRecomputed', 'PairedStressRecomputed', 'CallerOwnsAdmissionAndImmutableScope',
    'CallerOwnsHelperAuthentication', 'CallerOwnsPlanJournalBinding', 'CallerOwnsManifestAuthentication')
LOWERED_COUNTS = dict(WorkerPlans=4, InputRoles=18, ELFImages=8, SelectedImages=2, StressImages=4, FinalImages=2,
    ToolInvocations=0, CompilerInvocations=0, RequiredCellCount=0, RequiredCellsSatisfied=0)
CENSUS_FALSE = ('FullInstructionSemantics', 'SourceIRSemantics', 'OriginalTranslationUnitOwnership', 'AttributeOnlyProtection',
    'GeneralRegistersOnlyEffectProved', 'WorkerProvenanceValidated', 'CanonicalRootProtocolsValidated', 'CPUExecution', 'BoardExecution', 'GlobalQualification')
CENSUS_TRUE = ('CompleteExecutableCensus', 'ForbiddenDependenciesAbsent', 'RecognizedForbiddenFormsAbsent')
CENSUS_FIELDS = set(CENSUS_FALSE + CENSUS_TRUE) | {'Status', 'Scope', 'Profile', 'Mode', 'ObjectSha256', 'DisassemblySha256', 'FinalELF',
    'FunctionsAudited', 'FunctionEvidence', 'DefinitionsFromIR', 'DefinitionSurface', 'Undefined', 'AllowedMemoryHelpers', 'References', 'Padding',
    'UnownedMappedPools', 'ExecutableInstructionBytes', 'ExecutableMappedDataBytes', 'RecognizedForbiddenForms', 'RequiredCellsSatisfied'}
EFFECT_FIELDS = {'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'Stress', 'Mutation', 'ModeAuthority', 'HelperAuthenticationCallerOwned',
    'ObjectSha256', 'ProtectedFunctions', 'RootEvidence', 'Undefined', 'CompilerImports', 'OrdinaryEvidence', 'CounterDefinitions', 'References',
    'CompilerConstructors', 'MetadataReferences', 'UnresolvedAttribution', 'AllProtectedBodiesClean', 'CompiledAnnotationMutantDetected',
    'StressFamiliesActivated', 'StressCounterEvidence', 'ThreadSectionValidated', 'OrdinaryColdActivityValidated', 'ColdInlineAttributionValidated',
    'OriginalRELFieldsCensused', 'RelocationFields', 'RequiredCellCount', 'RequiredCellsSatisfied', 'TransitiveProtection', 'FullABI', 'FullSemanticABIProof',
    'FullIRSemantics', 'FullInstructionSemantics', 'FullAttributeEquivalence', 'CPUExecution', 'BoardExecution', 'GlobalQualification', 'Qualification',
    'CellContractSatisfied', 'RequiredCellSatisfied', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'OsCompilerOptionsValidated',
    'FinalLinkValidated', 'AllRelocationDestinationSemanticsValidated'}


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value: raise Rejected('REJECT:CM3-OS-LTO-PORT-REPLAY:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path');text = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', text) is not None and not any(ord(c) < 32 or ord(c) == 127 for c in text), 'absolute local path')
    need(all(p and p not in ('.', '..') and ':' not in p and p == p.rstrip(' .') for p in text[3:].replace('\\', '/').split('/')), 'canonical lexical path')
    return Path(text)


def _closed(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), 'closed ' + label)


def _same(a, b):
    if type(a) is not type(b): return False
    if type(b) is dict: return set(a) == set(b) and all(_same(a[k], b[k]) for k in b)
    if type(b) is list: return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def _labels():
    labels = {98: 'dump compiler specs'}
    for group, index, first, count in BUILDS:
        stem = Path(SELECTED[index - 3]).stem if group == 'selected' else 'stress'
        names = ['discover ' + group + ' ' + stem, 'compile ' + group + ' ' + stem,
            'inspect slim ' + stem, 'imports ' + group + ' ' + stem]
        if count == 5: names.append('definitions ' + group + ' ' + stem)
        labels.update({first + i: name for i, name in enumerate(names)})
    for group, first in zip(GROUPS, LOWERS):
        label = 'final-supported' if group == 'Final' else group
        labels.update({first: ('link ' if group == 'Final' else 'lower ') + label,
            first + 1: 'disassemble ' + label, first + 2: 'disassemble worker ' + label})
    return tuple(labels[i] for i in range(98, 134))


def _command(watch, primitive, index, argv):
    need(type(index) is int and 98 <= index < 134 and index not in watch.bound, 'fixed single port command')
    row = watch.commands[index];label = _labels()[index - 98]
    need(type(row) is dict, 'command object')
    for key, value in (('Label', label), ('Argv', argv), ('Cwd', str(watch.root)), ('State', 'TERMINAL'),
            ('ExpectedExit', 0), ('Exit', 0), ('Status', 'PASS'), ('TimedOut', False)):
        watch.same(row.get(key), value, 'command %03d/' % index + key)
    need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0
         and row.get('Error') is None and type(row.get('JournalErrors', [])) is list and row.get('JournalErrors', []) == [], 'clean terminal command')
    prefix = 'commands/%03d' % index;journal = watch.root / (prefix + '.json')
    watch.same(primitive._json(watch.raw(journal)), row, 'per-command journal %03d' % index)
    streams = []
    for key, suffix in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
        watch.same(row.get(key), prefix + suffix, 'fixed stream path')
        streams.append(watch.raw(watch.root / (prefix + suffix), row.get(key + 'Sha256')))
    output = index not in tuple(i + n for _, _, i, _ in BUILDS for n in (0, 1)) + LOWERS + (120,)
    need((streams[0] == b'' and bool(streams[1])) if index in LOWERS else
         streams[1] == b'' and (bool(streams[0]) if output else streams[0] == b''), 'expected clean raw streams')
    watch.bound[index] = dict(Index=index, Label=label, Argv=list(argv), ExpectedExit=0, Exit=0, Status='PASS', TimedOut=False,
        Journal=watch.binding(journal), Stdout=watch.binding(watch.root / (prefix + '.stdout')), Stderr=watch.binding(watch.root / (prefix + '.stderr')))
    return tuple(streams)


def _layout(root, group):
    return root / ('port-policy/final-supported/image.elf' if group == 'Final' else 'port-policy/lowered/' + group + '/aggregate.o')


def _saved_outputs(watch, output):
    fixed = {Path(str(output) + suffix) for suffix in SUFFIXES}
    if output.suffix == '.elf': fixed.add(output.with_suffix('.map'))
    dumps = {Path(str(output) + '.dis'), Path(str(output) + '.ltrans0.ltrans.o.dis')}
    optional = {Path(str(output) + suffix) for suffix in ('.wpa.gcno', '.ltrans0.ltrans.gcno', '.lto_wrapper_args')}
    actual = {p for p in watch.artifacts if p.is_relative_to(output.parent)}
    need(fixed | dumps <= actual <= fixed | dumps | optional, 'exact bounded saved-output namespace')
    local = Path(str(output) + '.lto_wrapper_args');external = watch.root / (''.join(output.parts[1:]) + '.lto_wrapper_args')
    need((local in watch.artifacts) != (external in watch.artifacts), 'one canonical wrapper owner')
    wrapper = local if local in watch.artifacts else external
    paths = sorted(actual - dumps)
    if wrapper not in paths: paths.append(wrapper)
    for path in paths: watch.raw(path)
    return wrapper, [watch.binding(p) for p in paths]


def _saved_options(watch, output, specs, supported, helpers, *, final):
    for suffix, marker in (('.ltrans_args', '-fwpa'), ('.ltrans0.ltrans_args', '-fltrans')):
        args = helpers['port_runner'].argument_lines(watch.raw(Path(str(output) + suffix)))
        metadata = [a for a in args if a.startswith(('-fltrans-output-list', '--fltrans-output-list'))]
        need(metadata == (['-fltrans-output-list=' + str(output) + '.ltrans.out'] if marker == '-fwpa' else []), 'canonical WPA output list')
        markers = [a for a in args if a.startswith(('-fwpa', '-fltrans', '--fwpa', '--fltrans')) and a not in metadata]
        need(markers == [marker] and not any(a.startswith('@') for a in args), 'exact stage, no unbound saved response')
        need([a for a in args if a.startswith(('-specs', '--specs'))] == ([] if specs is None else ['-specs=' + str(specs)]), 'only exact raw-stress specs')
        helpers['port_phase'].require_effective_options(args, supported=supported)
        need(all(a in args for a in ('-flto-partition=one', '-nostdlib')), 'saved partition/link options')
        need(not any(a in ('-marm', '-lgcov') or a.startswith(('--march', '--mlibarch')) for a in args), 'foreign target/runtime spelling')
        for a in args:
            need(not a.startswith('-flto-partition') or a == '-flto-partition=one', 'single partition')
            need(not a.startswith('-flinker-output') or a == ('-flinker-output=exec' if final else '-flinker-output=nolto-rel'), 'saved lowering kind')
        need('-r' not in args if final else '-r' in args and '-flinker-output=nolto-rel' in args, 'saved final/relocatable stage')


def _deferred(inputs):
    return dict(Status='PENDING', ValidationDeferred=True, Scope='OS_SELECTED_AGGREGATE_WORKER_FINAL_AND_PAIRED_STRESS_MACHINE_REPLAY_REQUIRED',
        Inputs=[dict(row) for row in inputs.values()], RequiredMachineRoles=8, RequiredStressRoles=4,
        RequiredSelectedSurface=dict(PublicFunctions=29, CohortObjects=2, ForwardFunctions=8, NakedFunctions=3),
        MachineEffectsValidated=False, StressActivationValidated=False, FinalMappingValidated=False, FinalTransferRootsValidated=False,
        RawCommonAttributesAloneProved=False, WholeCellProof=False, Qualification=False, RequiredCellsSatisfied=0)


def _build_record():
    return dict(Status='BUILT-PENDING-READER', Scope='NATIVE_CM3_OS_LTO_PORT_POLICY_BUILD_ONLY_PENDING_READER', Profile='CM3',
        Mode='Os-lto', Linkage='direct', LTO=True, First=98, Stop=134, Commands=36, SelectedSlimIRObjects=3, StressSlimIRObjects=2,
        SavedMachineRoles=8, ActualWorkerChains=4, GlobalSupportedCounterPolicy=True, RawFlags=list(RAW), SupportedCounterFlags=list(COUNTERS),
        WholeSelectedBodiesValidated=False, PairedStressValidated=False, FinalExecutableValidated=False, SelectedPortAttributePolicyProven=False,
        RawCommonAttributesAloneProved=False, UnchangedOtherSixGeneratedBodies=False, GeneralRegistersOnlyEffectProved=False,
        FullInstructionSemantics=False, FullABIProof=False, FullSemanticABIProof=False, CellContractSatisfied=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)


def inspect(batch, native, root, core, helpers, read):
    """Reconstruct this component only; no common/O2 predicate is invoked."""
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == HELPERS and callable(read), 'exact explicit helpers/read')
    methods = dict(deps=('parse',), recipes=('batch_plan', 'require_capture_sources', 'compile_flags', 'link_recipe'), guard=('_same',),
        transport=('require_elf32le', 'section_records'), controls_replay=('_Reader', '_json', '_identity', '_readelf_metadata', '_binary_sections'),
        ownership=('validate_common_sources',), attributes=('adapt_specs',), port_phase=('flags_for', 'final_arguments', 'require_effective_options', 'command_plan'),
        port_runner=('parse_ir_definitions', 'argument_lines'), policy=('stress_source', 'inspect_ir_definitions'),
        census=('inspect_lowered', 'inspect_final', 'inspect_stress'), effects=('inspect_lowered', 'require_result'), port_lowered=('inspect', 'require_result'))
    need(all(callable(getattr(helpers[k], n, None)) for k, names in methods.items() for n in names), 'pure helper methods')
    primitive = helpers['controls_replay'];primitive._identity(batch);primitive._identity(native)
    need(batch.get('Status') == 'BUILT-PENDING-READER' and batch.get('PortPolicyBuilt') is True and batch.get('SourceOwnershipValidated') is True, 'pending built port component')
    helpers['recipes'].require_capture_sources(native)
    watch = primitive._Reader(batch, root, helpers, read)
    batch_path = root / 'results.json';raw = read(batch_path, watch.authority.get(batch_path))
    watch.same(primitive._json(raw), batch, 'reparsed caller-admitted batch receipt');watch.consumed[batch_path] = raw
    seed = _path(batch.get('SourceSeed'));sr = seed / 'source';capture = _path(batch.get('NativeCapture', {}).get('Build'))
    watch.same(native.get('SeedBuild'), batch.get('SourceSeed'), 'same source seed')
    for a, b in ((root, sr), (root, capture), (sr, capture)):
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'disjoint roots')
    receipt = capture / 'results.json'
    watch.same(primitive._json(watch.raw(receipt, batch['NativeCapture'].get('ReceiptSha256'))), native, 'reparsed native receipt')
    plan = helpers['recipes'].batch_plan()['Commands'][98:134]
    need(len(plan) == 36 and tuple(r['Label'] for r in plan) == _labels() == helpers['port_phase'].command_plan()
         and all(type(r['Index']) is int and r['Index'] == 98 + i and type(r['ExpectedExit']) is int and r['ExpectedExit'] == 0
                 and r['Component'] == 'PortPolicy' for i, r in enumerate(plan)), 'fixed 36-command recipe')
    tools = {name: capture / 'toolchain/bin' / ('arm-none-eabi-' + suffix + '.exe')
        for name, suffix in (('Gcc', 'gcc'), ('Nm', 'nm'), ('Readelf', 'readelf'), ('Objdump', 'objdump'))}
    tools['Plugin'] = capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll'
    watch.same(native.get('CapturedCompiler'), str(tools['Gcc']), 'native GCC');watch.same(native.get('LTOPlugin', {}).get('Path'), str(tools['Plugin']), 'native plugin')
    for name, path in tools.items(): watch.raw(path, native['LTOPlugin'].get('Sha256') if name == 'Plugin' else None)
    admitted, source_names, objects, native_bindings = {}, set(OWNERSHIP), [], []
    for index, (name, row) in enumerate(zip(ORDER, native['Sources'])):
        source = sr / name;obj = capture / 'objects' / ('%02d-' % index + Path(name).stem + '.o')
        watch.same(row['Source'], str(source), 'ordered native source');watch.same(row['Object'], str(obj), 'ordered native object')
        watch.raw(obj, row['ObjectSha256']);objects.append(obj);native_bindings.append(dict(Index=index, **watch.binding(obj)))
        for dep in row['ActualCompileDependencies']:
            _closed(dep, ('Path', 'Sha256'), 'native dependency');path, digest = _path(dep['Path']), _hash(dep['Sha256'])
            need(path not in admitted or admitted[path] == digest, 'consistent dependency declarations');admitted[path] = digest
            if path.is_relative_to(sr): source_names.add(path.relative_to(sr).as_posix())
    sources = {name: watch.raw(sr / name, admitted.get(sr / name)) for name in sorted(source_names)}
    link_script = sr / 'tools/fixtures/classic_final_image/link.ld'
    watch.raw(link_script)
    for i in range(3, 6): watch.raw(sr / SELECTED[i - 3], native['Sources'][i]['SourceSha256'])
    ownership = helpers['ownership'].validate_common_sources({n: sources[n] for n in OWNERSHIP})
    ownership_inputs = [dict(Source=n, **watch.binding(sr / n)) for n in OWNERSHIP]
    watch.same(ownership, batch.get('SourceOwnership'), 'recomputed common ownership projection')
    watch.same(ownership_inputs, batch.get('SourceOwnershipInputs'), 'same four source bindings')
    selected_hashes = {n: sha(sources[n]) for n in SELECTED}
    watch.same(selected_hashes, batch.get('PortPolicySelectedSourceHashes'), 'unchanged selected source hashes')
    raw, _ = _command(watch, primitive, 98, [str(tools['Gcc']), '-dumpspecs'])
    original = root / 'port-policy/driver/original.specs';specs = root / 'port-policy/driver/no-auto-gcov.specs'
    watch.same(watch.raw(original), raw, 'original specs equals command 98 stdout')
    adapted = helpers['attributes'].adapt_specs(raw);watch.same(watch.raw(specs, adapted['AdaptedSha256']), adapted['Specs'], 'adapted specs bytes')
    adapter = {k: v for k, v in adapted.items() if k != 'Specs'};adapter.update(OriginalPath=str(original), AdaptedPath=str(specs))
    watch.same(adapter, batch.get('PortPolicyDriverAdapter'), 'specs comparison target')
    stress = helpers['policy'].stress_source(helpers['attributes']);stress_inputs = []
    need(sha(stress['Source']) == stress['SourceSha256'], 'neutral stress source hash')
    for group in GROUPS[1:3]:
        source = root / 'port-policy/private' / group / 'stress.c'
        need({p for p in watch.artifacts if p.is_relative_to(source.parent)} == {source}, 'exact stress source namespace')
        watch.same(watch.raw(source, stress['SourceSha256']), stress['Source'], 'identical generated ordinary stress bytes')
        stress_inputs.append(dict(Group=group, **watch.binding(source)))
    paired = dict(SourceSha256=stress['SourceSha256'], SameSourceBytes=True, OnlyPolicyFlagDifference=list(COUNTERS),
        RawOnlySpecsAdapter=True, StressActivationValidated=False, RawAttributesProof=False)
    watch.same(paired, batch.get('PortPolicyPairedStress'), 'paired stress comparison target')
    suite = SimpleNamespace(base=seed, result=native, source=lambda i: native['Sources'][i], objects=objects)
    compiled, dependency_bindings, cohort, definitions = [], [], [], {}
    for group, index, first, count in BUILDS:
        supported = group != 'stress-raw';selected = group == 'selected'
        source = sr / SELECTED[index - 3] if selected else root / 'port-policy/private' / group / 'stress.c'
        obj = root / 'port-policy/ir' / group / (source.stem + '.o')
        original_flags = helpers['recipes'].compile_flags(native, index)
        flags = helpers['port_phase'].flags_for(suite, {'recipes': helpers['recipes']}, index, supported=supported)
        before, after = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d');target = 'pilot-source-' + str(index)
        _command(watch, primitive, first, [str(tools['Gcc']), *flags, '-M', '-MF', str(before), '-MT', target, str(source)])
        _command(watch, primitive, first + 1, [str(tools['Gcc']), *flags, '-MD', '-MF', str(after), '-MT', target, '-c', str(source), '-o', str(obj)])
        a = helpers['deps'].parse(watch.raw(before), target=target);b = helpers['deps'].parse(watch.raw(after), target=target)
        need(type(a) is tuple and type(b) is tuple and a == b == tuple(sorted(set(a))) and source in a
             and all(isinstance(p, Path) and _path(p) == p for p in a), 'canonical same dependency sets')
        authority = dict(admitted);authority[source] = sha(watch.raw(source))
        rows = []
        for path in a:
            need(path in authority, 'no foreign compilation dependency');watch.raw(path, authority[path]);rows.append(watch.binding(path))
        raw = watch.raw(obj);header = helpers['transport'].require_elf32le(raw)
        text, _ = _command(watch, primitive, first + 2, [str(tools['Readelf']), '-hSW', str(obj)])
        text = text.decode('ascii');primitive._readelf_metadata(text, raw, header)
        sections = helpers['transport'].section_records(text);watch.same(sections, primitive._binary_sections(raw, header), 'full section correspondence')
        need(any(r['Name'].startswith('.gnu.lto_') for r in sections) and not any(r['Size'] and 'X' in r['Flags'] for r in sections), 'slim IR without executable fallback')
        slim = dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=sections)
        nm, _ = _command(watch, primitive, first + 3, [str(tools['Nm']), '--plugin', str(tools['Plugin']), '-u', str(obj)])
        imports = []
        for line in nm.decode('ascii').splitlines():
            match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line);need(match is not None, 'complete plugin import grammar');imports.append(match[1])
        need(len(imports) == len(set(imports)), 'unique plugin imports')
        defined = None
        if selected:
            nm_defs, _ = _command(watch, primitive, first + 4, [str(tools['Nm']), '--plugin', str(tools['Plugin']), '-P', '-S', '--defined-only', str(obj)])
            defined = helpers['port_runner'].parse_ir_definitions(nm_defs)
            need(type(defined) is list and defined and all(type(r['Kind']) is str and re.fullmatch('[A-Za-z]', r['Kind']) is not None
                 and type(r['Value']) is int and r['Value'] == 0 and r['Size'] is None for r in defined), 'slim definition grammar')
            role = ROLES[index - 3];definitions[role] = defined
            cohort.append(dict(Role=role, Source=str(source), SourceSha256=sha(watch.raw(source)), NativeObject=str(objects[index]),
                NativeObjectSha256=native['Sources'][index]['ObjectSha256'], SelectedObject=str(obj), SelectedObjectSha256=sha(raw),
                DefinitionCommandIndex=first + 4, DefinitionStdoutSha256=sha(nm_defs), Definitions=copy.deepcopy(defined)))
        note = obj.with_suffix('.gcno');coverage = None
        if note in watch.artifacts: watch.raw(note);coverage = watch.binding(note)
        compiled.append(dict(Group=group, TemplateIndex=index, Source=str(source), SourceSha256=sha(watch.raw(source)), Object=str(obj), ObjectSha256=sha(raw),
            OriginalCompileFlags=original_flags, CompileFlags=flags, SlimIR=slim,
            IRImports=dict(Object=str(obj), Imports=imports, Plugin=str(tools['Plugin']), RawNmSha256=sha(nm)), IRDefinitions=defined, CoverageNotes=coverage,
            DiscoveryDependencyFile=str(before), CompileDependencyFile=str(after), DiscoveryDependencies=rows, Dependencies=copy.deepcopy(rows),
            CompileDependenciesVerified=True, OriginalSelectedSourceUnchanged=selected, SupportedPolicy=supported,
            CommandIndices=list(range(first, first + count)), RawIRIdentityClaim=False, SourceToMachineSemanticProof=False))
        dependency_bindings.append(dict(DiscoveryIndex=first, CompileIndex=first + 1, Source=str(source), Target=target,
            Discovery=watch.binding(before), Compile=watch.binding(after), Dependencies=copy.deepcopy(rows)))
    surface = helpers['policy'].inspect_ir_definitions(definitions)
    watch.same(surface, batch.get('PortPolicyIRDefinitionSurface'), 'rederived exact 31-definition surface')
    watch.same(compiled, batch.get('PortPolicyCompilations'), 'five reconstructed compilation comparison targets')
    selected = [Path(r['Object']) for r in compiled[:3]];lowerings, plans, plan_bindings, inputs = [], [], [], {}
    stored_lowerings = batch.get('PortPolicyLowerings');need(type(stored_lowerings) is list and len(stored_lowerings) == 3, 'three lowering comparison targets')
    final = None
    for pos, (group, first) in enumerate(zip(GROUPS, LOWERS)):
        output = _layout(root, group);supported = group != 'stress-raw';raw_specs = specs if not supported else None
        if group == 'Final':
            argv, consumed = helpers['port_phase'].final_arguments(suite, {}, selected, output, output.with_suffix('.map'))
            need(helpers['recipes'].link_recipe(native, objects) == [a for a in next(r['Argv'] for r in native['Commands'] if r['Label'] == 'link ordinary') if a != '-v'], 'native final recipe authority')
        else:
            consumed = selected if pos == 0 else [Path(compiled[pos + 2]['Object'])]
            flags = helpers['port_phase'].flags_for(suite, {'recipes': helpers['recipes']}, 3, supported=supported)
            argv = [str(tools['Gcc']), *flags, *([] if raw_specs is None else ['-specs=' + str(raw_specs)]), *LOWER_FLAGS, *map(str, consumed), '-o', str(output)]
        _, diagnostics = _command(watch, primitive, first, argv)
        _saved_options(watch, output, raw_specs, supported, helpers, final=group == 'Final')
        worker = Path(str(output) + '.ltrans0.ltrans.o');dumps = []
        for offset, target in ((1, output), (2, worker)):
            raw_dump, _ = _command(watch, primitive, first + offset, [str(tools['Objdump']), '-drwC', '-z', str(target)])
            dump = Path(str(target) + '.dis');watch.same(watch.raw(dump), raw_dump, 'zero-inclusive dump bytes');dumps.append(watch.binding(dump))
        wrapper, saved = _saved_outputs(watch, output)
        target = batch.get('PortPolicyFinalLink') if group == 'Final' else stored_lowerings[pos]
        need(type(target) is dict and type(target.get('ActualWorker')) is dict, 'stored worker comparison target')
        plans.append(dict(Component='PortPolicy', Group=group, Output=output, Objects=list(consumed), Specs=raw_specs,
            Diagnostics=diagnostics, Supported=supported, StoredWorker=copy.deepcopy(target['ActualWorker'])))
        plan_bindings.append(dict(Component='PortPolicy', Group=group, Output=watch.binding(output), Objects=[watch.binding(p) for p in consumed],
            Specs=None if raw_specs is None else watch.binding(raw_specs), Diagnostics=watch.binding(root / ('commands/%03d.stderr' % first)), Supported=supported))
        if group == 'Final':
            final = dict(Path=str(output), Sha256=sha(watch.raw(output)), Map=str(output.with_suffix('.map')), MapSha256=sha(watch.raw(output.with_suffix('.map'))),
                ActualWorker=copy.deepcopy(target['ActualWorker']), Disassembly=dumps[0], WorkerDisassembly=dumps[1], Objects=list(map(str, consumed)),
                UnchangedOtherSixObjects=[dict(Index=i, **watch.binding(objects[i])) for i in (0, 1, 2, 6, 7, 8)],
                OriginalFinalStageArgv=copy.deepcopy(next(r['Argv'] for r in native['Commands'] if r['Label'] == 'link ordinary')), Argv=argv,
                WrapperArgs=str(wrapper), WrapperArgsSha256=sha(watch.raw(wrapper)), SavedOutputs=saved,
                GlobalSupportedCounterPolicy=True, CommandIndices=[first, first + 1, first + 2], **dict.fromkeys(FINAL_FALSE, False))
            role_paths = (('Final/ELF', output), ('Final/Map', output.with_suffix('.map')), ('Final/Disassembly', Path(dumps[0]['Path'])),
                ('Final/Machine', worker), ('Final/MachineDisassembly', Path(dumps[1]['Path'])), ('Final/Startup', objects[8]))
        else:
            lowerings.append(dict(Group=group, Object=str(output), ObjectSha256=sha(watch.raw(output)), Inputs=[watch.binding(p) for p in consumed],
                ActualWorker=copy.deepcopy(target['ActualWorker']), Disassembly=dumps[0], WorkerDisassembly=dumps[1], WrapperArgs=str(wrapper),
                WrapperArgsSha256=sha(watch.raw(wrapper)), SavedOutputs=saved, SupportedPolicy=supported,
                CommandIndices=[first, first + 1, first + 2], MachineEffectsValidated=False, StressActivationValidated=False))
            role_paths = ((group + '/Aggregate', output), (group + '/AggregateDisassembly', Path(dumps[0]['Path'])),
                (group + '/Machine', worker), (group + '/MachineDisassembly', Path(dumps[1]['Path'])))
        for name, path in role_paths: inputs[name] = dict(Role=name, **watch.binding(path))
    need(set(watch.bound) == set(range(98, 134)), 'all thirty-six commands bound')
    lowered_helpers = {k: helpers[k] for k in ADAPTER_HELPERS}
    def lowered_read(path, expected=None):
        path = _path(path)
        if path == root / 'artifacts.json':
            raw = watch.consumed[path]
            need(expected is None or expected == sha(raw), 'delegated admitted manifest hash')
            return raw
        return watch.raw(path, expected)
    lowered = helpers['port_lowered'].inspect(core, lowered_read, plans, native, lowered_helpers, roles=inputs, ir_definitions=surface)
    helpers['port_lowered'].require_result(lowered, lowered_helpers)
    # The adapter must compare each complete recomputed worker to StoredWorker.
    watch.same(lowerings, stored_lowerings, 'lowering comparison targets after delegated worker validation')
    watch.same(final, batch.get('PortPolicyFinalLink'), 'final comparison target after delegated worker validation')
    watch.same(_deferred(inputs), batch.get('PortPolicyDeferredReader'), 'eighteen deferred role comparison target')
    watch.same(_build_record(), batch.get('PortPolicyBuild'), 'pending build record')
    watch.same(primitive._json(watch.raw(root / 'port-policy-build.json')), dict(Build=_build_record(), Compilations=compiled,
        Lowerings=lowerings, FinalLink=final, DeferredReader=_deferred(inputs)), 'manifest-bound port build receipt')
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Cohort=COHORT,
        SourceInventorySha256=SOURCE, Root=str(root), SourceRoot=str(sr), CaptureRoot=str(capture),
        AuthorityInputs=dict(BatchReceipt=watch.binding(batch_path), NativeReceipt=watch.binding(receipt), Manifest=watch.binding(root / 'artifacts.json'),
            CommandJournal=watch.binding(root / 'commands.json'), PortBuild=watch.binding(root / 'port-policy-build.json'),
            OriginalSpecs=watch.binding(original), AdaptedSpecs=watch.binding(specs), LinkScript=watch.binding(link_script)),
        ToolBindings={n: watch.binding(p) for n, p in tools.items()}, SourceInputs=[dict(Source=n, **watch.binding(sr / n)) for n in sorted(sources)],
        SourceOwnership=ownership, SourceOwnershipInputs=ownership_inputs, SelectedSourceHashes=selected_hashes, SourceCohort=cohort,
        NativeObjectBindings=native_bindings, DriverAdapter=adapter, StressSourceInputs=stress_inputs, PairedStress=paired,
        Compilations=compiled, DependencyBindings=dependency_bindings, IRDefinitionSurface=surface,
        DependencyPairEntries=sum(len(r['Dependencies']) for r in dependency_bindings),
        DependencyListedRows=2 * sum(len(r['Dependencies']) for r in dependency_bindings),
        UniqueDependencyPaths=len({r['Path'] for pair in dependency_bindings for r in pair['Dependencies']}),
        CommandBindings=[watch.bound[i] for i in range(98, 134)], Lowerings=lowerings, FinalLink=final, Inputs=inputs,
        PlanBindings=plan_bindings, LoweredProofs=lowered, ReadInputs=[watch.binding(p) for p in sorted(watch.consumed)], ReadFiles=len(watch.consumed),
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    require_result(proof)
    return proof


def _json_tree(value):
    if type(value) is dict:
        need(all(type(k) is str for k in value), 'JSON object keys')
        for v in value.values(): _json_tree(v)
    elif type(value) is list:
        for v in value: _json_tree(v)
    else:
        need(value is None or type(value) in (str, bool, int) or type(value) is float and math.isfinite(value), 'finite JSON evidence')


def _definitions(rows, role):
    need(type(rows) is list and len(rows) == len(DEFINITION_CATALOG[role]), 'fixed definition count')
    found = {}
    for row in rows:
        _closed(row, ('Name', 'Kind', 'Value', 'Size'), 'IR definition')
        name = row['Name'];need(type(name) is str and name not in found and type(row['Kind']) is str
            and DEFINITION_CATALOG[role].get(name) == row['Kind'] and type(row['Value']) is int
            and row['Value'] == 0 and row['Size'] is None, 'canonical role/name/kind/zero slim definition')
        found[name] = row['Kind']
    need(found == DEFINITION_CATALOG[role], 'complete role definition catalog')


def _require_ownership(value, sources):
    false = ('InputAuthenticationProof', 'ActualProviderProof', 'DependencyProof', 'ElfProof', 'CompileProof', 'CompilerExecution',
        'FullABIProof', 'FullSemanticABIProof', 'ArbitraryPointerAliasProof', 'CpuExecution', 'BoardExecution', 'RequiredCellSatisfied', 'GlobalFreezeQualified')
    _closed(value, set(false) | {'Status', 'Scope', 'SourceFactsOnly', 'SourceRoles', 'SourceHashes', 'AuthoredIncludes', 'CheckedFunctions',
        'CanonicalPrivateStorageDeclarations', 'RuntimeSourceManifestMatched', 'RequiredCellsSatisfied'}, 'ownership')
    need(value['Status'] == 'PASS' and value['Scope'] == 'CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY'
         and all(value[k] is False for k in false) and all(value[k] is True for k in
            ('SourceFactsOnly', 'CanonicalPrivateStorageDeclarations', 'RuntimeSourceManifestMatched'))
         and type(value['RequiredCellsSatisfied']) is int and value['RequiredCellsSatisfied'] == 0
         and _same(value['SourceRoles'], dict(zip(('engine', 'state', 'panic'), COMMON)))
         and _same(value['SourceHashes'], {n: sources[n] for n in OWNERSHIP}), 'source-only ownership joins')
    authored = dict(engine=['context_api_decl.h', 'context_panic.h', 'context_runtime_port_abi.h', 'context_runtime_state.h', 'context_port_abi.h'],
        state=['context_runtime_state.h', 'context_panic.h', 'context_runtime_port_abi.h'], panic=['context_panic.h', 'context_port_abi.h'])
    need(_same(value['AuthoredIncludes'], authored) and type(value['CheckedFunctions']) is list and len(value['CheckedFunctions']) == 15, 'ownership catalog')
    for row, (source, signature) in zip(value['CheckedFunctions'], OWNERSHIP_SIGNATURES):
        _closed(row, ('Source', 'Function', 'Signature', 'CheckedBodyTextSha256'), 'ownership function')
        need((row['Source'], row['Function'], row['Signature']) == (source, re.search(r'([A-Za-z_][A-Za-z0-9_]*)\(', signature)[1], signature), 'ordered ownership function')
        _hash(row['CheckedBodyTextSha256'])


def require_result(proof):
    """Validate component accounting/joins; the composer also checks port_lowered.

    No authenticated helper is retained globally. inspect invokes the real
    adapter validator; a separately deserialized proof needs that validator at
    the composition boundary too, before any delegated machine fact is used.
    """
    _closed(proof, FIELDS, 'port result');_json_tree(proof)
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
            ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(proof[key]) is str and proof[key] == value, 'fixed identity/' + key)
    need(proof['LTO'] is True, 'LTO')
    for key, value in COUNTS.items(): need(type(proof[key]) is int and proof[key] == value, 'typed count/' + key)
    for key in FACTS: need(proof[key] is True, 'fact/' + key)
    for key in NONCLAIMS: need(proof[key] is False, 'nonclaim/' + key)
    root, sr, capture = (_path(proof[k]) for k in ('Root', 'SourceRoot', 'CaptureRoot'))
    need(sr.name == 'source', 'source-root suffix')
    for a, b in ((root, sr), (root, capture), (sr, capture)):
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'disjoint roots')
    reads, used = {}, set()
    need(type(proof['ReadFiles']) is int and type(proof['ReadInputs']) is list and proof['ReadFiles'] == len(proof['ReadInputs']) > 0, 'read accounting')
    for row in proof['ReadInputs']:
        _closed(row, ('Path', 'Sha256'), 'read binding');path = _path(row['Path'])
        need(path not in reads, 'unique reads');reads[path] = _hash(row['Sha256'])
    need(list(reads) == sorted(reads), 'ordered reads')

    def binding(row, path=None, extra=()):
        _closed(row, {'Path', 'Sha256'} | set(extra), 'consumed role')
        actual = _path(row['Path'])
        need((path is None or path == actual) and reads.get(actual) == _hash(row['Sha256']), 'read-role hash join')
        used.add(actual);return actual

    authorities = dict(BatchReceipt=root / 'results.json', NativeReceipt=capture / 'results.json', Manifest=root / 'artifacts.json',
        CommandJournal=root / 'commands.json', PortBuild=root / 'port-policy-build.json', OriginalSpecs=root / 'port-policy/driver/original.specs',
        AdaptedSpecs=root / 'port-policy/driver/no-auto-gcov.specs', LinkScript=sr / 'tools/fixtures/classic_final_image/link.ld')
    _closed(proof['AuthorityInputs'], authorities, 'authority inputs')
    for name, path in authorities.items(): binding(proof['AuthorityInputs'][name], path)
    tools = {name: capture / 'toolchain/bin' / ('arm-none-eabi-' + suffix + '.exe')
        for name, suffix in (('Gcc', 'gcc'), ('Nm', 'nm'), ('Readelf', 'readelf'), ('Objdump', 'objdump'))}
    tools['Plugin'] = capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll'
    _closed(proof['ToolBindings'], tools, 'tools')
    for name, path in tools.items(): binding(proof['ToolBindings'][name], path)
    tool = {n: str(p) for n, p in tools.items()}
    commands = proof['CommandBindings'];need(type(commands) is list and len(commands) == 36, '36 commands')
    by_index = {}
    nonempty = {98} | {first + i for _, _, first, count in BUILDS for i in range(2, count)} | {n + i for n in LOWERS for i in (1, 2)}
    nonempty.remove(120)
    for index, row in zip(range(98, 134), commands):
        _closed(row, ('Index', 'Label', 'Argv', 'ExpectedExit', 'Exit', 'Status', 'TimedOut', 'Journal', 'Stdout', 'Stderr'), 'command')
        need(type(row['Index']) is int and row['Index'] == index and row['Label'] == _labels()[index - 98]
            and type(row['ExpectedExit']) is int and row['ExpectedExit'] == 0 and type(row['Exit']) is int and row['Exit'] == 0
            and row['Status'] == 'PASS' and row['TimedOut'] is False and type(row['Argv']) is list and row['Argv']
            and all(type(a) is str and a and not any(c in a for c in '\0\r\n') for a in row['Argv']), 'command disposition')
        for key, suffix in (('Journal', '.json'), ('Stdout', '.stdout'), ('Stderr', '.stderr')):
            binding(row[key], root / ('commands/%03d%s' % (index, suffix)))
        need((row['Stdout']['Sha256'] != sha(b'')) is (index in nonempty)
             and (row['Stderr']['Sha256'] != sha(b'')) is (index in LOWERS), 'stream disposition')
        by_index[index] = row
    need(by_index[98]['Argv'] == [tool['Gcc'], '-dumpspecs'] and by_index[98]['Stdout']['Sha256'] == proof['AuthorityInputs']['OriginalSpecs']['Sha256'], 'dumpspecs authority')
    adapter = proof['DriverAdapter']
    _closed(adapter, ('OriginalPath', 'AdaptedPath', 'OriginalSha256', 'AdaptedSha256', 'Offset', 'Original', 'Replacement', 'OnlyRemovedBytes', 'InstrumentationCounterFlagsAdded'), 'specs adapter')
    need(adapter['OriginalPath'] == str(authorities['OriginalSpecs']) and adapter['AdaptedPath'] == str(authorities['AdaptedSpecs'])
         and adapter['OriginalSha256'] == proof['AuthorityInputs']['OriginalSpecs']['Sha256'] and adapter['AdaptedSha256'] == proof['AuthorityInputs']['AdaptedSpecs']['Sha256']
         and type(adapter['Offset']) is int and adapter['Offset'] >= 0
         and adapter['Original'] == '%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}'
         and adapter['Replacement'] == '%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:}'
         and adapter['OnlyRemovedBytes'] == '-lgcov' and adapter['InstrumentationCounterFlagsAdded'] is False, 'bounded specs deletion')
    source_map = {};need(type(proof['SourceInputs']) is list, 'source input list')
    for row in proof['SourceInputs']:
        path = binding(row, extra=('Source',));name = row['Source']
        need(type(name) is str and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name) is not None
             and name not in source_map and path == sr / name, 'canonical source name')
        source_map[name] = row['Sha256']
    need(list(source_map) == sorted(source_map) and set(OWNERSHIP + ORDER) <= set(source_map), 'complete ordered sources')
    need(type(proof['SourceOwnershipInputs']) is list and len(proof['SourceOwnershipInputs']) == 4, 'ownership projection')
    for name, row in zip(OWNERSHIP, proof['SourceOwnershipInputs']):
        binding(row, sr / name, ('Source',));need(row['Source'] == name and row['Sha256'] == source_map[name], 'ownership buffer join')
    _require_ownership(proof['SourceOwnership'], source_map)
    need(_same(proof['SelectedSourceHashes'], {n: source_map[n] for n in SELECTED}), 'selected original source hashes')
    native_objects = [];need(type(proof['NativeObjectBindings']) is list and len(proof['NativeObjectBindings']) == 9, 'native object cohort')
    for index, (name, row) in enumerate(zip(ORDER, proof['NativeObjectBindings'])):
        path = capture / 'objects' / ('%02d-' % index + Path(name).stem + '.o');binding(row, path, ('Index',))
        need(type(row['Index']) is int and row['Index'] == index, 'native object order');native_objects.append(path)
    stress_inputs = proof['StressSourceInputs'];need(type(stress_inputs) is list and len(stress_inputs) == 2, 'stress source pair')
    for group, row in zip(GROUPS[1:3], stress_inputs):
        binding(row, root / 'port-policy/private' / group / 'stress.c', ('Group',));need(row['Group'] == group, 'stress role')
    paired = proof['PairedStress'];_closed(paired, ('SourceSha256', 'SameSourceBytes', 'OnlyPolicyFlagDifference', 'RawOnlySpecsAdapter', 'StressActivationValidated', 'RawAttributesProof'), 'paired stress')
    need(paired['SourceSha256'] == stress_inputs[0]['Sha256'] == stress_inputs[1]['Sha256'] and paired['SameSourceBytes'] is paired['RawOnlySpecsAdapter'] is True
         and paired['StressActivationValidated'] is paired['RawAttributesProof'] is False and _same(paired['OnlyPolicyFlagDifference'], list(COUNTERS)), 'paired source/policy joins')
    builds, dep_pairs, cohort = proof['Compilations'], proof['DependencyBindings'], proof['SourceCohort']
    need(type(builds) is list and len(builds) == 5 and type(dep_pairs) is list and len(dep_pairs) == 5 and type(cohort) is list and len(cohort) == 3, 'five builds three source records')
    definitions = []
    for pos, ((group, index, first, count), row, dep) in enumerate(zip(BUILDS, builds, dep_pairs)):
        _closed(row, COMP_FIELDS, 'compilation');selected, supported = pos < 3, group != 'stress-raw'
        source = sr / SELECTED[index - 3] if selected else root / 'port-policy/private' / group / 'stress.c'
        obj = root / 'port-policy/ir' / group / (source.stem + '.o');before, after = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        need(row['Group'] == group and type(row['TemplateIndex']) is int and row['TemplateIndex'] == index and row['Source'] == str(source)
             and row['SourceSha256'] == reads.get(source) and row['Object'] == str(obj) and row['ObjectSha256'] == reads.get(obj)
             and _same(row['CommandIndices'], list(range(first, first + count))) and row['CompileDependenciesVerified'] is True
             and row['OriginalSelectedSourceUnchanged'] is selected and row['SupportedPolicy'] is supported
             and row['RawIRIdentityClaim'] is row['SourceToMachineSemanticProof'] is False, 'fixed compilation source/object selectors')
        used.update((source, obj));_hash(row['SourceSha256']);_hash(row['ObjectSha256'])
        original, flags = row['OriginalCompileFlags'], row['CompileFlags']
        need(type(original) is list and original and all(type(a) is str for a in original)
             and [a for a in original if a.startswith('-O')] == ['-Os']
             and all(original.count(a) == 1 for a in ('-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-flto', '-fno-fat-lto-objects'))
             and not any(a.startswith(('-specs', '--specs')) or a in RAW + COUNTERS for a in original)
             and _same(flags, original + list(RAW) + (list(COUNTERS) if supported else [])), 'Os flag preservation plus exact policy')
        need(row['DiscoveryDependencyFile'] == str(before) and row['CompileDependencyFile'] == str(after), 'canonical dependency files')
        _closed(dep, ('DiscoveryIndex', 'CompileIndex', 'Source', 'Target', 'Discovery', 'Compile', 'Dependencies'), 'dependency pair')
        target = 'pilot-source-' + str(index)
        need(type(dep['DiscoveryIndex']) is int and dep['DiscoveryIndex'] == first and type(dep['CompileIndex']) is int and dep['CompileIndex'] == first + 1
             and dep['Source'] == str(source) and dep['Target'] == target, 'dependency command roles')
        binding(dep['Discovery'], before);binding(dep['Compile'], after)
        need(type(dep['Dependencies']) is list and dep['Dependencies'] and _same(row['Dependencies'], dep['Dependencies'])
             and _same(row['DiscoveryDependencies'], dep['Dependencies']), 'same dependency projections')
        paths = [binding(b) for b in dep['Dependencies']];need(paths == sorted(set(paths)) and source in paths, 'canonical dependencies include own source')
        need(by_index[first]['Argv'] == [tool['Gcc'], *flags, '-M', '-MF', str(before), '-MT', target, str(source)]
             and by_index[first + 1]['Argv'] == [tool['Gcc'], *flags, '-MD', '-MF', str(after), '-MT', target, '-c', str(source), '-o', str(obj)]
             and by_index[first + 2]['Argv'] == [tool['Readelf'], '-hSW', str(obj)]
             and by_index[first + 3]['Argv'] == [tool['Nm'], '--plugin', tool['Plugin'], '-u', str(obj)], 'exact compilation argv')
        slim = row['SlimIR'];_closed(slim, ('Object', 'Sha256', 'SlimIR', 'Sections'), 'slim metadata')
        need(slim['Object'] == str(obj) and slim['Sha256'] == row['ObjectSha256'] and slim['SlimIR'] is True
             and type(slim['Sections']) is list and slim['Sections'], 'slim object join')
        for i, section in enumerate(slim['Sections']):
            _closed(section, ('Index', 'Name', 'Type', 'Address', 'Offset', 'Size', 'Flags'), 'section record')
            need(type(section['Index']) is int and section['Index'] == i and all(type(section[k]) is str for k in ('Name', 'Type', 'Flags'))
                 and all(type(section[k]) is int and section[k] >= 0 for k in ('Address', 'Offset', 'Size')), 'typed section metadata')
        need(any(s['Name'].startswith('.gnu.lto_') for s in slim['Sections']) and not any(s['Size'] and 'X' in s['Flags'] for s in slim['Sections']), 'slim no fallback')
        imports = row['IRImports'];_closed(imports, ('Object', 'Imports', 'Plugin', 'RawNmSha256'), 'IR import surface')
        need(imports['Object'] == str(obj) and imports['Plugin'] == tool['Plugin'] and imports['RawNmSha256'] == by_index[first + 3]['Stdout']['Sha256']
             and type(imports['Imports']) is list and all(type(n) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', n) for n in imports['Imports'])
             and len(imports['Imports']) == len(set(imports['Imports'])) and (imports['Imports'] == []) is (first + 3 == 120), 'plugin import bytes join')
        if row['CoverageNotes'] is not None: binding(row['CoverageNotes'], obj.with_suffix('.gcno'))
        if selected:
            role = ROLES[pos];_definitions(row['IRDefinitions'], role)
            need(by_index[first + 4]['Argv'] == [tool['Nm'], '--plugin', tool['Plugin'], '-P', '-S', '--defined-only', str(obj)], 'definition query argv')
            source_row = cohort[pos];_closed(source_row, ('Role', 'Source', 'SourceSha256', 'NativeObject', 'NativeObjectSha256', 'SelectedObject',
                'SelectedObjectSha256', 'DefinitionCommandIndex', 'DefinitionStdoutSha256', 'Definitions'), 'selected source cohort')
            need(source_row['Role'] == role and source_row['Source'] == str(source) and source_row['SourceSha256'] == row['SourceSha256']
                 and source_row['NativeObject'] == str(native_objects[index]) and source_row['NativeObjectSha256'] == reads[native_objects[index]]
                 and source_row['SelectedObject'] == str(obj) and source_row['SelectedObjectSha256'] == row['ObjectSha256']
                 and type(source_row['DefinitionCommandIndex']) is int and source_row['DefinitionCommandIndex'] == first + 4
                 and source_row['DefinitionStdoutSha256'] == by_index[first + 4]['Stdout']['Sha256']
                 and _same(source_row['Definitions'], row['IRDefinitions']), 'shared normal census source/definition joins')
            definitions.extend(dict(Role=role, **r) for r in row['IRDefinitions'])
        else: need(row['IRDefinitions'] is None, 'stress has no definition query')
    surface = proof['IRDefinitionSurface'];_closed(surface, ('IRDefinitionsValidated', 'Definitions', 'PublicFunctions', 'CohortObjects', 'OriginalTranslationUnitMachineOwnership'), 'definition surface')
    need(surface['IRDefinitionsValidated'] is True and surface['OriginalTranslationUnitMachineOwnership'] is False
         and type(surface['PublicFunctions']) is int and surface['PublicFunctions'] == 29 and type(surface['CohortObjects']) is int and surface['CohortObjects'] == 2
         and _same(surface['Definitions'], definitions), 'exact rederived 31-definition surface')
    pair_entries = sum(len(d['Dependencies']) for d in dep_pairs)
    for key, value in (('DependencyPairEntries', pair_entries), ('DependencyListedRows', pair_entries * 2),
            ('UniqueDependencyPaths', len({r['Path'] for d in dep_pairs for r in d['Dependencies']}))):
        need(type(proof[key]) is int and proof[key] == value, 'explicit dependency projection/' + key)
    _require_lowerings(proof, root, capture, tool, by_index, binding, reads, used, native_objects)
    _require_lowered(proof, binding, reads, used)
    need(used == set(reads), 'exact bounded read-role closure')
    return proof


def _require_lowerings(proof, root, capture, tool, commands, binding, reads, used, native_objects):
    lowers, final, plans, inputs = proof['Lowerings'], proof['FinalLink'], proof['PlanBindings'], proof['Inputs']
    need(type(lowers) is list and len(lowers) == 3 and type(plans) is list and len(plans) == 4, 'three lowerings/final plan')
    _closed(final, FINAL_FIELDS, 'final link');expected_roles = {}
    selected = [Path(b['Object']) for b in proof['Compilations'][:3]]
    for pos, (group, first, plan) in enumerate(zip(GROUPS, LOWERS, plans)):
        output = _layout(root, group);worker = Path(str(output) + '.ltrans0.ltrans.o');is_final = group == 'Final';supported = group != 'stress-raw'
        objects = native_objects[:3] + selected + native_objects[6:] if is_final else selected if pos == 0 else [Path(proof['Compilations'][pos + 2]['Object'])]
        row = final if is_final else lowers[pos];_closed(row, FINAL_FIELDS if is_final else LOWER_FIELDS, 'lowering record')
        need(_same(row['CommandIndices'], [first, first + 1, first + 2]), 'lower command indices')
        if is_final:
            need(row['Path'] == str(output) and row['Sha256'] == reads.get(output) and row['Map'] == str(output.with_suffix('.map'))
                and row['MapSha256'] == reads.get(output.with_suffix('.map')) and row['GlobalSupportedCounterPolicy'] is True
                and all(row[k] is False for k in FINAL_FALSE) and _same(row['Objects'], list(map(str, objects))), 'final paths/cohort/nonclaims')
            used.add(output.with_suffix('.map'));other = row['UnchangedOtherSixObjects'];need(type(other) is list and len(other) == 6, 'other six')
            for index, b in zip((0, 1, 2, 6, 7, 8), other):
                binding(b, native_objects[index], ('Index',));need(type(b['Index']) is int and b['Index'] == index, 'unchanged six order')
            original = [tool['Gcc'], '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-flto', '-flto-partition=one', '-save-temps=obj', '-v',
                '-nostdlib', '-Wl,-plugin-opt=-save-temps', '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
                '-T', proof['AuthorityInputs']['LinkScript']['Path'], *map(str, native_objects), '-Wl,-Map=' + str(capture / 'ordinary/image.map'), '-o', str(capture / 'ordinary/image.elf')]
            need(row['OriginalFinalStageArgv'] == original, 'original direct final recipe')
            argv = original[:original.index(str(native_objects[0]))] + ['-Wl,--emit-relocs', *RAW, *COUNTERS, *map(str, objects), '-Wl,-Map=' + str(output.with_suffix('.map')), '-o', str(output)]
            need(row['Argv'] == argv, 'Os final replacement recipe')
        else:
            need(row['Group'] == group and row['Object'] == str(output) and row['ObjectSha256'] == reads.get(output)
                 and row['SupportedPolicy'] is supported and row['MachineEffectsValidated'] is row['StressActivationValidated'] is False
                 and type(row['Inputs']) is list and len(row['Inputs']) == len(objects), 'lower path/cohort/nonclaims')
            for b, path in zip(row['Inputs'], objects): binding(b, path)
            argv = [tool['Gcc'], *proof['Compilations'][4 if not supported else 0]['CompileFlags'],
                *([] if supported else ['-specs=' + proof['AuthorityInputs']['AdaptedSpecs']['Path']]), *LOWER_FLAGS, *map(str, objects), '-o', str(output)]
        need(commands[first]['Argv'] == argv and argv.count('-o') == 1 and argv[-2:] == ['-o', str(output)]
             and [a for a in argv[:-2] if a.endswith('.o')] == list(map(str, objects)), 'driver ordered inputs exclude output aggregate.o')
        for offset, name, target in ((1, 'Disassembly', output), (2, 'WorkerDisassembly', worker)):
            binding(row[name], Path(str(target) + '.dis'))
            need(commands[first + offset]['Argv'] == [tool['Objdump'], '-drwC', '-z', str(target)]
                 and row[name]['Sha256'] == commands[first + offset]['Stdout']['Sha256'], 'dump journal join')
        local = Path(str(output) + '.lto_wrapper_args');external = root / (''.join(output.parts[1:]) + '.lto_wrapper_args')
        wrapper = _path(row['WrapperArgs']);need(wrapper in (local, external) and reads.get(wrapper) == _hash(row['WrapperArgsSha256']), 'wrapper owner/hash');used.add(wrapper)
        fixed = {Path(str(output) + s) for s in SUFFIXES}
        if is_final: fixed.add(output.with_suffix('.map'))
        optional = {Path(str(output) + s) for s in ('.wpa.gcno', '.ltrans0.ltrans.gcno', '.lto_wrapper_args')}
        saved = row['SavedOutputs'];need(type(saved) is list, 'saved outputs')
        paths = [binding(b) for b in saved];unique = set(paths)
        need(len(paths) == len(unique) and fixed | {wrapper} <= unique <= fixed | optional | {wrapper}
             and (local in unique) != (external in unique), 'exact saved output roles')
        need(paths == sorted(unique - ({external} if wrapper == external else set())) + ([external] if wrapper == external else []), 'producer saved output ordering')
        _closed(plan, ('Component', 'Group', 'Output', 'Objects', 'Specs', 'Diagnostics', 'Supported'), 'worker plan binding')
        need(plan['Component'] == 'PortPolicy' and plan['Group'] == group and plan['Supported'] is supported
             and type(plan['Objects']) is list and len(plan['Objects']) == len(objects), 'worker plan selectors')
        binding(plan['Output'], output);binding(plan['Diagnostics'], Path(commands[first]['Stderr']['Path']))
        for b, path in zip(plan['Objects'], objects): binding(b, path)
        if supported: need(plan['Specs'] is None, 'supported no specs')
        else: binding(plan['Specs'], Path(proof['AuthorityInputs']['AdaptedSpecs']['Path']))
        _require_worker(row['ActualWorker'], output, objects, supported, plan, binding, reads)
        role_paths = (('Final/ELF', output), ('Final/Map', output.with_suffix('.map')), ('Final/Disassembly', Path(str(output) + '.dis')),
            ('Final/Machine', worker), ('Final/MachineDisassembly', Path(str(worker) + '.dis')), ('Final/Startup', native_objects[8])) if is_final else (
            (group + '/Aggregate', output), (group + '/AggregateDisassembly', Path(str(output) + '.dis')),
            (group + '/Machine', worker), (group + '/MachineDisassembly', Path(str(worker) + '.dis')))
        expected_roles.update(role_paths)
    _closed(inputs, expected_roles, 'eighteen deferred roles')
    for name, path in expected_roles.items():
        binding(inputs[name], path, ('Role',));need(inputs[name]['Role'] == name, 'deferred role name')


def _require_worker(worker, output, objects, supported, plan, binding, reads):
    _closed(worker, ('SupportedPolicy', 'EffectiveOptionsVerified', 'WpaOptions', 'LtransOptions', 'Machine', 'MachineSha256', 'MachineHeader',
        'WpaArguments', 'LtransArguments', 'WpaInputs', 'Intermediate', 'IntermediateSha256', 'DriverSpecs', 'Execution'), 'recorded worker comparison target')
    machine, intermediate = Path(str(output) + '.ltrans0.ltrans.o'), Path(str(output) + '.ltrans0.o')
    need(worker['SupportedPolicy'] is supported and worker['EffectiveOptionsVerified'] is True and worker['Machine'] == str(machine)
        and worker['MachineSha256'] == reads.get(machine) and worker['Intermediate'] == str(intermediate)
        and worker['IntermediateSha256'] == reads.get(intermediate), 'recorded worker cohort')
    ir = [p for p in objects if p.name != '08-startup.o']
    need(type(worker['WpaInputs']) is list and len(worker['WpaInputs']) == len(ir), 'ordered WPA input records')
    for row, path in zip(worker['WpaInputs'], ir): binding(row, path)
    if supported: need(worker['DriverSpecs'] is None, 'worker no specs')
    else: need(_same(worker['DriverSpecs'], plan['Specs']), 'worker raw specs derived from adapter')
    for name, suffix in (('WpaArguments', '.ltrans_args'), ('LtransArguments', '.ltrans0.ltrans_args')):
        path = Path(str(output) + suffix);need(worker[name] == str(path) and path in reads, 'recorded saved argument path')
    for name in ('WpaOptions', 'LtransOptions'):
        row = worker[name];_closed(row, ('Mode', 'SupportedPolicy', 'EffectiveOptionsVerified', 'CanonicalWorkerArchitecture', 'RawPresent',
            'CanonicalizedRawAbsent', 'Counters', 'AttributeEffectsValidated'), 'worker options')
        need(row['Mode'] == 'Os-lto' and row['SupportedPolicy'] is supported and row['EffectiveOptionsVerified'] is True and row['AttributeEffectsValidated'] is False
             and type(row['CanonicalWorkerArchitecture']) is list
             and all(a in ('-march=armv7-m', '-mlibarch=armv7-m') for a in row['CanonicalWorkerArchitecture'])
             and type(row['RawPresent']) is list and type(row['CanonicalizedRawAbsent']) is list
             and len(set(row['RawPresent'] + row['CanonicalizedRawAbsent'])) == len(RAW)
             and set(row['RawPresent'] + row['CanonicalizedRawAbsent']) == set(RAW)
             and _same(row['Counters'], list(COUNTERS) if supported else []), 'bounded Os worker options')
    header = worker['MachineHeader'];_closed(header, ('Class', 'Data', 'Type', 'Machine', 'Version', 'HeaderSize', 'SectionOffset', 'SectionEntrySize', 'SectionCount'), 'machine header')
    need(header['Class'] == 'ELF32' and header['Data'] == 'little-endian' and header['Type'] == 'REL' and header['Machine'] == 'ARM' and header['Version'] == 1
         and header['HeaderSize'] == 52 and header['SectionEntrySize'] == 40
         and all(type(header[k]) is int and header[k] >= 0 for k in ('Version', 'HeaderSize', 'SectionEntrySize', 'SectionOffset', 'SectionCount'))
         and header['SectionCount'] > 0, 'ARM ELF32 REL metadata')
    execution = worker['Execution'];_closed(execution, ('CompilerReportedWorkerExecutionVerified', 'OsProcessTraceVerified', 'TranscriptSha256', 'WorkerInvocations', 'EffectiveOptions', 'Assembler'), 'worker execution')
    need(execution['CompilerReportedWorkerExecutionVerified'] is True and execution['OsProcessTraceVerified'] is False
         and execution['TranscriptSha256'] == plan['Diagnostics']['Sha256'] and type(execution['WorkerInvocations']) is list
         and len(execution['WorkerInvocations']) == 2 and type(execution['EffectiveOptions']) is list and len(execution['EffectiveOptions']) == 2, 'worker execution joins')
    for stage, suffix, row, options in zip(('-fwpa', '-fltrans'), ('.wpa.args.0', '.ltrans0.ltrans.args.0'), execution['WorkerInvocations'], execution['EffectiveOptions']):
        _closed(row, ('Stage', 'Executable', 'ExecutableSha256', 'Argv', 'Response', 'ResponseSha256'), 'worker invocation')
        executable = _path(row['Executable']);response = Path(str(output) + suffix)
        need(row['Stage'] == stage and executable.name == 'lto1.exe' and reads.get(executable) == _hash(row['ExecutableSha256'])
             and row['Response'] == str(response) and row['ResponseSha256'] == reads.get(response)
             and type(row['Argv']) is list and row['Argv'] and all(type(a) is str for a in row['Argv']), 'worker response bindings')
        binding(dict(Path=str(executable), Sha256=row['ExecutableSha256']))
        args = row['Argv'];expected = dict(Mode='Os-lto', SupportedPolicy=supported, EffectiveOptionsVerified=True,
            CanonicalWorkerArchitecture=[a for a in args if a.startswith(('-march', '-mlibarch'))], RawPresent=[a for a in RAW if a in args],
            CanonicalizedRawAbsent=[a for a in RAW if a not in args], Counters=list(COUNTERS) if supported else [], AttributeEffectsValidated=False)
        need(_same(options, expected), 'execution options rederived from argv')
    assembler = execution['Assembler'];_closed(assembler, ('Executable', 'ExecutableSha256', 'Argv'), 'assembler')
    path = _path(assembler['Executable']);need(path.name == 'as.exe' and reads.get(path) == _hash(assembler['ExecutableSha256'])
         and type(assembler['Argv']) is list and assembler['Argv'] and all(type(a) is str for a in assembler['Argv']), 'assembler identity')
    binding(dict(Path=str(path), Sha256=assembler['ExecutableSha256']))


def _require_lowered(proof, binding, reads, used):
    delegated = proof['LoweredProofs']
    _closed(delegated, set(LOWERED_NONCLAIMS + LOWERED_FACTS) | set(LOWERED_COUNTS) | {'Status', 'Scope', 'Profile', 'Mode', 'Linkage',
        'LTO', 'Root', 'ManifestInput', 'NativeObjects', 'ResolvedWorkers', 'IRDefinitionSurface', 'Inputs', 'Plans',
        'WorkerChains', 'Machines', 'ReadInputs', 'ReadFiles', 'ControlBytes'}, 'delegated adapter result')
    for key, value in (('Status', 'CM3-OS-LTO-PORT-LOWERED-REPLAYED-NOT-QUALIFIED'), ('Scope', 'CM3_OS_LTO_FOUR_PORT_CHAINS_EIGHT_IMAGES_ONLY'),
            ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('Root', proof['Root'])):
        need(type(delegated[key]) is str and delegated[key] == value, 'adapter identity/' + key)
    need(delegated['LTO'] is True, 'adapter LTO')
    for key in LOWERED_NONCLAIMS: need(delegated[key] is False, 'adapter nonclaim/' + key)
    for key in LOWERED_FACTS: need(delegated[key] is True, 'adapter fact/' + key)
    for key, value in LOWERED_COUNTS.items(): need(type(delegated[key]) is int and delegated[key] == value, 'adapter count/' + key)
    need(_same(delegated['Inputs'], proof['Inputs']) and _same(delegated['IRDefinitionSurface'], proof['IRDefinitionSurface'])
         and _same(delegated['ManifestInput'], proof['AuthorityInputs']['Manifest']), 'adapter surface/role/manifest joins')
    binding(delegated['ManifestInput'])
    originals = [{k: r[k] for k in ('Path', 'Sha256')} for r in proof['NativeObjectBindings']]
    need(_same(delegated['NativeObjects'], originals), 'adapter nine native object authorities')
    for row in delegated['NativeObjects']: binding(row)
    workers = delegated['ResolvedWorkers'];_closed(workers, ('lto1', 'as'), 'adapter workers')
    for name, row in workers.items():
        path = binding(row);need(path.name == name + '.exe' and not path.is_relative_to(Path(proof['Root'])), 'adapter external worker')
    plans, chains, machines = delegated['Plans'], delegated['WorkerChains'], delegated['Machines']
    need(type(plans) is list and len(plans) == 4 and type(chains) is list and len(chains) == 4
         and type(machines) is list and len(machines) == 4, 'four delegated cohorts')
    required = {Path(proof['AuthorityInputs']['Manifest']['Path'])} | {Path(r['Path']) for r in workers.values()}
    controls = set()
    for pos, (group, plan, public, chain, pair) in enumerate(zip(GROUPS, plans, proof['PlanBindings'], chains, machines)):
        source_row = (proof['Lowerings'] + [proof['FinalLink']])[pos]
        expected = dict(Group=group, Output=public['Output']['Path'], Objects=public['Objects'], Specs=public['Specs'],
            Diagnostics=public['Diagnostics'], Supported=public['Supported'], StoredWorker=source_row['ActualWorker'])
        need(_same(plan, expected), 'normalized adapter plan join')
        required.update(Path(b['Path']) for b in public['Objects'] + [public['Diagnostics']])
        if public['Specs'] is not None: required.add(Path(public['Specs']['Path']))
        required.update(Path(b['Path']) for b in source_row['SavedOutputs'])
        required.update(Path(b['Path']) for name, b in proof['Inputs'].items() if name.startswith(group + '/'))
        output = Path(public['Output']['Path'])
        controls.update(Path(str(output) + s) for s in ('.ltrans_args', '.ltrans0.ltrans_args', '.wpa.args.0', '.ltrans0.ltrans.args.0', '.ltrans.out'))
        controls.add(Path(public['Diagnostics']['Path']))
        _closed(chain, ('Group', 'Proof'), 'adapter worker cohort');_closed(pair, ('Group', 'Images'), 'adapter image pair')
        need(chain['Group'] == pair['Group'] == group and _same(chain['Proof'], source_row['ActualWorker']), 'adapter recomputed worker join')
        for row in chain['Proof']['Execution']['WorkerInvocations']:
            need(row['Executable'] == workers['lto1']['Path'] and row['ExecutableSha256'] == workers['lto1']['Sha256'], 'same resolved lto1')
        assembly = chain['Proof']['Execution']['Assembler']
        need(assembly['Executable'] == workers['as']['Path'] and assembly['ExecutableSha256'] == workers['as']['Sha256'], 'same resolved assembler')
        need(type(pair['Images']) is list and len(pair['Images']) == 2, 'two delegated images')
        for role, image in zip(('ELF', 'Machine') if pos == 3 else ('Aggregate', 'Machine'), pair['Images']):
            _closed(image, ('Role', 'Proof'), 'delegated image');need(image['Role'] == role, 'delegated image order')
            object_row = proof['Inputs'][group + '/' + role]
            dump = proof['Inputs'][group + '/' + ('Disassembly' if role == 'ELF' else role + 'Disassembly')]
            leaf = image['Proof']
            if pos in (0, 3): _census_metadata(leaf, object_row['Sha256'], dump['Sha256'], proof['IRDefinitionSurface'], final=role == 'ELF')
            else:
                supported = pos == 1
                _closed(leaf, {'Status', 'Effects', 'SupportedPolicy', 'RequiredCellsSatisfied', 'CleanMachine' if supported else 'CleanPredicateRejected'}, 'delegated stress leaf')
                need(leaf['Status'] == ('CM3-OS-LTO-PORT-STRESS-CLEAN' if supported else 'CM3-OS-LTO-PORT-STRESS-EFFECTS-DETECTED')
                     and leaf['SupportedPolicy'] is supported and type(leaf['RequiredCellsSatisfied']) is int and leaf['RequiredCellsSatisfied'] == 0, 'stress disposition')
                effect = leaf['Effects'];_closed(effect, EFFECT_FIELDS, 'stress effect metadata')
                need(effect['ObjectSha256'] == object_row['Sha256'] and effect['Profile'] == 'CM3' and effect['Mode'] == 'Os-lto'
                     and effect['Linkage'] == 'direct' and effect['Stress'] is True and effect['UnresolvedAttribution'] == [], 'effect object/scope join')
                for key in ('TransitiveProtection', 'FullABI', 'FullSemanticABIProof', 'FullIRSemantics', 'FullInstructionSemantics', 'FullAttributeEquivalence',
                        'CPUExecution', 'BoardExecution', 'GlobalQualification', 'Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'SourceToMachineSemanticProof',
                        'OriginalTranslationUnitOwnership', 'OsCompilerOptionsValidated', 'FinalLinkValidated', 'AllRelocationDestinationSemanticsValidated'):
                    need(effect[key] is False, 'effect nonclaim/' + key)
                for key in ('RequiredCellCount', 'RequiredCellsSatisfied'):
                    need(type(effect[key]) is int and effect[key] == 0, 'effect zero credit')
                if supported: _census_metadata(leaf['CleanMachine'], object_row['Sha256'], dump['Sha256'], None)
                else: need(leaf['CleanPredicateRejected'] is True, 'raw clean predicate rejected')
    local, sizes = set(), {}
    need(type(delegated['ReadFiles']) is int and type(delegated['ReadInputs']) is list
         and delegated['ReadFiles'] == len(delegated['ReadInputs']), 'adapter read accounting')
    for row in delegated['ReadInputs']:
        path = binding(row, extra=('Bytes',));need(path not in local and type(row['Bytes']) is int and row['Bytes'] > 0, 'adapter nonempty unique read')
        local.add(path);sizes[path] = row['Bytes']
    need(local == required and [r['Path'] for r in delegated['ReadInputs']] == [str(p) for p in sorted(local)], 'exact adapter read membership')
    raw_controls = delegated['ControlBytes'];_closed(raw_controls, {str(p) for p in controls}, 'adapter control buffers')
    for name, value in raw_controls.items():
        need(type(value) is str and re.fullmatch('(?:[0-9a-f]{2})+', value) is not None, 'literal control hex')
        raw = bytes.fromhex(value);path = Path(name)
        need(sha(raw) == reads[path] and len(raw) == sizes[path], 'control byte/hash/size join')


def _census_metadata(leaf, object_hash, dump_hash, surface, *, final=False):
    _closed(leaf, CENSUS_FIELDS | ({'FinalRootVectorBindings'} if final else set()), 'delegated census metadata')
    need(leaf['Status'] == 'CM3-OS-LTO-PORT-CENSUS-PASS' and leaf['Scope'] == 'CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY'
         and leaf['Profile'] == 'CM3' and leaf['Mode'] == 'Os-lto' and leaf['ObjectSha256'] == object_hash and leaf['DisassemblySha256'] == dump_hash
         and leaf['FinalELF'] is final and _same(leaf['DefinitionSurface'], surface) and type(leaf['RequiredCellsSatisfied']) is int
         and leaf['RequiredCellsSatisfied'] == 0 and leaf['AllowedMemoryHelpers'] == ['memcpy', 'memset'], 'census identity/hash joins')
    for key in CENSUS_FALSE: need(leaf[key] is False, 'census nonclaim/' + key)
    for key in CENSUS_TRUE: need(leaf[key] is True, 'census fact/' + key)
    need(type(leaf['FunctionsAudited']) is int and type(leaf['FunctionEvidence']) is list and leaf['FunctionsAudited'] == len(leaf['FunctionEvidence']) > 0, 'function census count')
    for row in leaf['FunctionEvidence']:
        _closed(row, ('Name', 'Symbol', 'Instructions', 'DataBytes', 'References', 'BodySha256'), 'census function metadata')
        _symbol_metadata(row['Symbol']);_hash(row['BodySha256'])
        need(row['Name'] == row['Symbol']['name'] and type(row['Instructions']) is int and row['Instructions'] > 0
             and type(row['DataBytes']) is int and row['DataBytes'] >= 0 and type(row['References']) is list, 'function metadata types')
    need(type(leaf['DefinitionsFromIR']) is list and len(leaf['DefinitionsFromIR']) == (0 if surface is None else 31), 'definition projection count')
    for row in leaf['DefinitionsFromIR']: _symbol_metadata(row)
    need(type(leaf['References']) is list, 'census REL rows')
    for row in leaf['References']:
        _closed(row, ('Section', 'Offset', 'Kind', 'Target', 'Owner', 'SiteForm', 'SiteBytes', 'FieldBytes', 'AddendSemanticsValidated', 'AppliedDestinationValidated'), 'census REL metadata')
        _symbol_metadata(row['Target']);need(row['AddendSemanticsValidated'] is row['AppliedDestinationValidated'] is False, 'REL nonclaims')
    for key, fields in (('Padding', ('Section', 'Address', 'Bytes')), ('UnownedMappedPools', ('Section', 'Address', 'Size', 'Bytes'))):
        need(type(leaf[key]) is list, 'padding/pool list')
        for row in leaf[key]: _closed(row, fields, 'padding/pool metadata')
    if final:
        vector = leaf['FinalRootVectorBindings'];_closed(vector, ('VectorSha256', 'Words', 'Entry', 'SVC', 'PendSV', 'AllocatedFileBackedLoadValidated', 'CanonicalRootProtocolsValidated'), 'final vector metadata')
        _hash(vector['VectorSha256']);need(type(vector['Words']) is int and vector['Words'] == 256
             and vector['AllocatedFileBackedLoadValidated'] is True and vector['CanonicalRootProtocolsValidated'] is False, 'bounded vector nonclaim')


def _symbol_metadata(row):
    _closed(row, ('name', 'section', 'value', 'size', 'kind', 'binding', 'visibility', 'index'), 'symbol metadata')
    need(type(row['name']) is str and type(row['section']) in (str, int) and all(type(row[k]) is str for k in ('kind', 'binding', 'visibility'))
         and all(type(row[k]) is int and row[k] >= 0 for k in ('value', 'size', 'index')), 'typed symbol metadata')
