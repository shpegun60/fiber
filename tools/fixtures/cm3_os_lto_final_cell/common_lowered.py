"""Pure six-cohort common worker/effect replay over caller-admitted bytes.

The caller authenticates helpers, journals, sources and one outer reader. This
adapter creates no reader or parser module. Retained files are hash bindings,
not evidence of wrapper, resolution, assembly or disassembly semantics.
"""

import copy
import hashlib
import ntpath
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import patch


SCOPE = 'CM3_OS_LTO_SIX_COMMON_LOWERED_COHORTS_ONLY'
PASS = 'CM3-OS-LTO-COMMON-LOWERED-REPLAYED-NOT-QUALIFIED'
PENDING = 'CM3-OS-LTO-COMMON-LOWERED-PENDING-ATTRIBUTION'
GROUPS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic',
          'stress-protected', 'stress-unprotected')
MUTATIONS = (None, 'ctxrt_v1_current', 'fiber_internal_runtime_load_current_context',
             'fiber_panic', None, 'ctxrt_attribute_stress')
STARTS = (66, 72, 78, 84, 90, 96)
ROLES = ('Object', 'Machine', 'Disassembly', 'WpaArguments', 'LtransArguments',
         'WpaResponse', 'LtransResponse', 'PartitionList', 'Intermediate',
         'Resolution', 'Assembly', 'WrapperArgs', 'DriverSpecs', 'Diagnostics')
LOWER_FIELDS = frozenset(('Group', 'Inputs', 'Mutation', 'Stress', 'Roles',
    'CommandIndices', 'DisassemblyIncludesZeroes', 'WorkerOptionsValidated',
    'EffectsValidated', 'ValidationDeferred'))
HELPERS = frozenset(('attributes', 'attribute_runner', 'common_workers',
                     'common_effects', 'transport'))
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied',
    'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof', 'IRImportClosureValidated',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'CommonAttributePolicyProven', 'FullAttributeEquivalence', 'TransitiveProtection',
    'FinalLinkValidated', 'FinalReferenceParity', 'FinalRootTransferProtocolsValidated',
    'AllRelocationDestinationSemanticsValidated', 'WrapperSemanticsValidated',
    'ResolutionSemanticsValidated', 'AssemblySemanticsValidated', 'DisassemblySemanticsValidated',
    'JournalBindingsValidated', 'OsProcessTraceVerified', 'CpuExecution', 'BoardExecution',
    'GlobalFreezeQualified', 'HostedCIQualified', 'ProducerCompilersReexecuted')
FACTS = ('WorkerChainsReplayed', 'EffectsRecomputed', 'CallerOwnsAdmissionAndImmutableScope',
         'CallerOwnsHelperAuthentication')
COUNTS = dict(LoweringCohorts=6, InputRoles=84, ELFImages=12, ReadFiles=89,
              RequiredCellCount=0, RequiredCellsSatisfied=0, ToolInvocations=0, CompilerInvocations=0)
FIELDS = frozenset(NONCLAIMS + FACTS) | frozenset(COUNTS) | frozenset((
    'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Lowerings', 'ResolvedWorkers',
    'WorkerChains', 'CommonMachines', 'UnresolvedAttribution', 'CommonAttributionClosed', 'ReadInputs'))
WORKER_FALSE = ('RuntimeLibraryProvided', 'AttributeEffectsValidated', 'Qualification',
    'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof', 'FullSemanticABIProof',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
WORKER_TRUE = ('ActualHostileOptionsVerified', 'SavedArgumentOsOptionsValidated',
    'ActualInvocationOsOptionsValidated', 'HelperAuthenticationCallerOwned',
    'PhysicalIdentityValidationCallerOwned', 'InputCohortJournalBindingCallerOwned')
WORKER_FIELDS = frozenset(WORKER_FALSE + WORKER_TRUE) | frozenset((
    'Profile', 'Mode', 'Scope', 'Linkage', 'LTO', 'RequiredCellCount', 'RequiredCellsSatisfied',
    'Stages', 'WpaArguments', 'LtransArguments', 'WpaInputs', 'Intermediate',
    'IntermediateSha256', 'Machine', 'MachineSha256', 'MachineHeader', 'DriverSpecs',
    'DriverSpecsSha256', 'AdmittedResolvedWorker', 'Execution', 'ActualInvocationOptions'))
EFFECT_FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'Stress', 'Mutation',
    'ModeAuthority', 'HelperAuthenticationCallerOwned', 'ObjectSha256', 'ProtectedFunctions',
    'RootEvidence', 'Undefined', 'CompilerImports', 'OrdinaryEvidence', 'CounterDefinitions',
    'References', 'CompilerConstructors', 'MetadataReferences', 'UnresolvedAttribution',
    'AllProtectedBodiesClean', 'CompiledAnnotationMutantDetected', 'StressFamiliesActivated',
    'StressCounterEvidence', 'ThreadSectionValidated', 'OrdinaryColdActivityValidated',
    'ColdInlineAttributionValidated', 'OriginalRELFieldsCensused', 'RelocationFields',
    'RequiredCellCount', 'RequiredCellsSatisfied', 'TransitiveProtection', 'FullABI',
    'FullSemanticABIProof', 'FullIRSemantics', 'FullInstructionSemantics', 'FullAttributeEquivalence',
    'CPUExecution', 'BoardExecution', 'GlobalQualification', 'Qualification', 'CellContractSatisfied',
    'RequiredCellSatisfied', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OsCompilerOptionsValidated', 'FinalLinkValidated', 'AllRelocationDestinationSemanticsValidated'))
REFERENCE_FIELDS = frozenset(('Section', 'Offset', 'Kind', 'Target', 'Owner', 'SiteBytes',
    'FieldBytes', 'OriginalAddend', 'ResolvedABS32', 'SemanticTarget', 'CompilerHook',
    'CompilerCounter', 'OriginalHookTransferValidated', 'AppliedDestinationValidated', 'ConstructorArray'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-LOWERED:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    text = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', text) is not None
         and not any(ord(c) < 32 or ord(c) == 127 for c in text), 'absolute local drive path')
    parts = text[3:].replace('\\', '/').split('/')
    need(parts and all(part and part not in ('.', '..') and ':' not in part
         and part == part.rstrip(' .') for part in parts), 'canonical lexical path')
    return Path(text)


def _reported(value):
    need(type(value) is str and re.match(r'^[A-Za-z]:[\\/]', value) is not None
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'absolute reported executable')
    return _path(ntpath.normpath(value))


def _binding(row):
    need(type(row) is dict and set(row) == {'Path', 'Sha256'} and type(row['Path']) is str,
         'exact path/hash binding')
    return _path(row['Path']), _hash(row['Sha256'])


def _helpers(helpers):
    need(type(helpers) is dict and set(helpers) == HELPERS, 'exact explicit helper set')
    for name, functions in (('common_workers', ('worker_chain', '_options')),
            ('common_effects', ('inspect_lowered', 'require_result')),
            ('attribute_runner', ('worker_chain', 'argument_lines', 'worker_diagnostics')),
            ('transport', ('require_elf32le',))):
        need(all(callable(getattr(helpers[name], f, None)) for f in functions), 'helper API/' + name)


def _layout(lowerings, workers):
    need(type(lowerings) is list and len(lowerings) == 6, 'six producer lowerings')
    need(type(workers) is dict and set(workers) == {'lto1', 'as'}, 'two explicit resolved workers')
    hashes, root = {}, None

    def add(row):
        path, digest = _binding(row)
        need(path not in hashes or hashes[path] == digest, 'consistent shared input digest')
        hashes[path] = digest
        return path

    for index, row in enumerate(lowerings):
        group, mutation, stress = GROUPS[index], MUTATIONS[index], index >= 4
        need(type(row) is dict and set(row) == LOWER_FIELDS and row['Group'] == group
             and row['Mutation'] == mutation and (mutation is None or type(row['Mutation']) is str)
             and row['Stress'] is stress, 'exact ordered selectors/' + group)
        need(row['DisassemblyIncludesZeroes'] is True and row['ValidationDeferred'] is True
             and row['WorkerOptionsValidated'] is False and row['EffectsValidated'] is False,
             'original deferred producer facts/' + group)
        need(type(row['CommandIndices']) is list and all(type(x) is int for x in row['CommandIndices'])
             and row['CommandIndices'] == [STARTS[index], STARTS[index] + 1], 'fixed command pair/' + group)
        values = row['Roles']
        need(type(values) is dict and set(values) == set(ROLES), 'fourteen exact producer roles/' + group)
        obj = _binding(values['Object'])[0]
        if root is None:
            need(len(obj.parents) >= 4, 'bounded lowering namespace')
            root = obj.parents[3]
        expected = root / 'attributes/lowered' / group / 'aggregate.o'
        need(obj == expected, 'fixed aggregate path/' + group)
        suffixes = dict(Machine='.ltrans0.ltrans.o', WpaArguments='.ltrans_args',
            LtransArguments='.ltrans0.ltrans_args', WpaResponse='.wpa.args.0',
            LtransResponse='.ltrans0.ltrans.args.0', PartitionList='.ltrans.out',
            Intermediate='.ltrans0.o', Resolution='.res', Assembly='.ltrans0.ltrans.s')
        fixed = dict(Object=obj, Disassembly=obj.parent / 'aggregate.dis',
            DriverSpecs=root / 'attributes/driver/no-auto-gcov.specs',
            Diagnostics=root / ('commands/%03d.stderr' % STARTS[index]))
        fixed.update({role: Path(str(obj) + suffix) for role, suffix in suffixes.items()})
        wrappers = {Path(str(obj) + '.lto_wrapper_args'),
                    root / (''.join(obj.parts[1:]) + '.lto_wrapper_args')}
        paths = {role: add(values[role]) for role in ROLES}
        need(len(set(paths.values())) == 14, 'distinct cohort roles/' + group)
        need(all(paths[role] == wanted for role, wanted in fixed.items())
             and paths['WrapperArgs'] in wrappers, 'fixed producer role paths/' + group)
    need(len(hashes) == 79, 'shared specs only across eighty-four roles')
    positive = [root / 'attributes/ir/positive' / name for name in
                ('context_core.o', 'context_runtime_state.o', 'context_panic.o')]
    for index, row in enumerate(lowerings):
        expected = list(positive)
        if 1 <= index <= 3:
            slot = index - 1
            expected[slot] = root / 'attributes/ir' / GROUPS[index] / positive[slot].name
        elif index >= 4:
            expected = [root / 'attributes/ir' / GROUPS[index] / 'stress.o']
        need(type(row['Inputs']) is list and len(row['Inputs']) == len(expected), 'fixed IR count/' + GROUPS[index])
        need([add(value) for value in row['Inputs']] == expected, 'fixed ordered IR cohort/' + GROUPS[index])
    need(len(hashes) == 87, 'eight distinct common IR builds')
    for name in ('lto1', 'as'):
        path, _ = _binding(workers[name])
        need(path not in hashes and path.name == name + '.exe', 'distinct named worker/' + name)
        add(workers[name])
    need(len(hashes) == 89, 'complete local reader closure')
    return hashes


def _options(record, stage, saved, helpers, argv=None, digest=None):
    if argv is not None:
        expected = helpers['common_workers']._options(argv, stage, saved=False)
    else:
        expected = dict(Stage=stage, Mode='Os-lto', SoleOsOptimization=True,
            RawFlags=list(helpers['common_workers'].RAW_FLAGS),
            ActualStageFlagVerified='-fwpa' if stage == 'WPA' else '-fltrans',
            UncancelledRawFlagsVerified=True, SavedNoltoRelOptionsValidated=saved,
            AttributeEffectsValidated=False, ArgumentsSha256=digest)
    need(type(record) is dict and record == expected
         and all(type(record[key]) is bool for key in ('SoleOsOptimization',
             'UncancelledRawFlagsVerified', 'SavedNoltoRelOptionsValidated', 'AttributeEffectsValidated')),
         'deep worker option record/' + stage)


def _worker(proof, row, workers, hashes, sizes, helpers):
    need(type(proof) is dict and set(proof) == WORKER_FIELDS, 'closed worker proof')
    for key, value in (('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
            ('Scope', 'NATIVE_CM3_OS_LTO_COMMON_RAW_WORKER_CHAIN_ONLY')):
        need(type(proof[key]) is str and proof[key] == value, 'worker identity/' + key)
    need(proof['LTO'] is True, 'worker LTO')
    for key in WORKER_TRUE:
        need(proof[key] is True, 'worker fact/' + key)
    for key in WORKER_FALSE:
        need(proof[key] is False, 'worker nonclaim/' + key)
    for key in ('RequiredCellCount', 'RequiredCellsSatisfied'):
        need(type(proof[key]) is int and proof[key] == 0, 'worker zero credit/' + key)
    roles = row['Roles']
    for key, role in (('WpaArguments', 'WpaArguments'), ('LtransArguments', 'LtransArguments'),
            ('Machine', 'Machine'), ('Intermediate', 'Intermediate'), ('DriverSpecs', 'DriverSpecs')):
        need(proof[key] == roles[role]['Path'], 'worker exact path/' + key)
    for key, role in (('MachineSha256', 'Machine'), ('IntermediateSha256', 'Intermediate'), ('DriverSpecsSha256', 'DriverSpecs')):
        need(proof[key] == roles[role]['Sha256'], 'worker exact bytes/' + key)
    need(proof['WpaInputs'] == row['Inputs'] and proof['AdmittedResolvedWorker'] == workers['lto1'], 'worker cohort/executable')
    header = proof['MachineHeader']
    need(type(header) is dict and set(header) == {'Class', 'Data', 'Type', 'Machine', 'Version',
         'HeaderSize', 'SectionOffset', 'SectionEntrySize', 'SectionCount'}, 'complete machine header')
    for key, value in (('Class', 'ELF32'), ('Data', 'little-endian'), ('Type', 'REL'), ('Machine', 'ARM')):
        need(type(header[key]) is str and header[key] == value, 'machine header identity')
    for key, value in (('Version', 1), ('HeaderSize', 52), ('SectionEntrySize', 40)):
        need(type(header[key]) is int and header[key] == value, 'machine header integer')
    need(type(header['SectionOffset']) is int and type(header['SectionCount']) is int
         and header['SectionCount'] > 0 and 52 <= header['SectionOffset']
         and header['SectionOffset'] + 40 * header['SectionCount'] <= sizes[_path(roles['Machine']['Path'])],
         'machine section table bounds')
    stages, options = proof['Stages'], proof['ActualInvocationOptions']
    need(type(stages) is list and len(stages) == 2 and type(options) is list and len(options) == 2, 'two saved/actual stages')
    execution = proof['Execution']
    need(type(execution) is dict and set(execution) == {'CompilerReportedWorkerExecutionVerified',
         'OsProcessTraceVerified', 'TranscriptSha256', 'WorkerInvocations', 'Assembler'}
         and execution['CompilerReportedWorkerExecutionVerified'] is True
         and execution['OsProcessTraceVerified'] is False
         and execution['TranscriptSha256'] == roles['Diagnostics']['Sha256'], 'compiler-reported transcript binding')
    invocations = execution['WorkerInvocations']
    need(type(invocations) is list and len(invocations) == 2, 'two actual invocation records')
    for i, (stage, marker, role) in enumerate((('WPA', '-fwpa', 'WpaResponse'), ('LTRANS', '-fltrans', 'LtransResponse'))):
        invocation = invocations[i]
        need(type(invocation) is dict and set(invocation) == {'Stage', 'Executable', 'ExecutableSha256', 'Argv', 'Response', 'ResponseSha256'}
             and invocation['Stage'] == marker and invocation['Executable'] == workers['lto1']['Path']
             and invocation['ExecutableSha256'] == workers['lto1']['Sha256']
             and invocation['Response'] == roles[role]['Path'] and invocation['ResponseSha256'] == roles[role]['Sha256'],
             'actual invocation authority/' + stage)
        argv = invocation['Argv']
        need(type(argv) is list and argv and all(type(x) is str and x for x in argv)
             and _reported(argv[0]) == _path(workers['lto1']['Path'])
             and [x for x in argv if x.startswith('@')] == ['@' + roles[role]['Path']], 'actual worker argv/' + stage)
        if i == 1:
            need(argv.count('-o') == 1 and argv.index('-o') + 1 < len(argv)
                 and argv[argv.index('-o') + 1] == roles['Assembly']['Path'], 'actual LTRANS assembly output')
        _options(stages[i], stage, True, helpers, digest=roles['WpaArguments' if i == 0 else 'LtransArguments']['Sha256'])
        _options(options[i], stage, False, helpers, argv=argv)
    assembler = execution['Assembler']
    need(type(assembler) is dict and set(assembler) == {'Executable', 'ExecutableSha256', 'Argv'}
         and assembler['Executable'] == workers['as']['Path']
         and assembler['ExecutableSha256'] == workers['as']['Sha256'], 'actual assembler authority')
    argv = assembler['Argv']
    need(type(argv) is list and argv and all(type(x) is str and x for x in argv)
         and _reported(argv[0]) == _path(workers['as']['Path']) and argv.count('-o') == 1
         and argv.index('-o') + 1 < len(argv) and argv[argv.index('-o') + 1] == roles['Machine']['Path']
         and argv[-1] == roles['Assembly']['Path'] and not any(x.startswith('@') for x in argv), 'actual assembler input/output')


def _effect(leaf, mutation, stress, helpers):
    need(type(leaf) is dict and set(leaf) == EFFECT_FIELDS, 'closed effect result')
    helpers['common_effects'].require_result(leaf, mutation=mutation, stress=stress)
    attrs = helpers['attributes']
    refs = leaf['References']
    for ref in refs:
        need(set(ref) == REFERENCE_FIELDS, 'closed original REL row')
        attrs._symbol_fields(ref['Target'])
        resolved = ref['ResolvedABS32']
        if resolved is not None:
            need(ref['Kind'] == 2 and type(resolved) is dict
                 and set(resolved) == {'Addend', 'TargetOffset', 'Symbol'}
                 and all(type(resolved[k]) is int and resolved[k] >= 0 for k in ('Addend', 'TargetOffset'))
                 and resolved['Addend'] == ref['OriginalAddend']
                 and (resolved['Symbol'] is None or type(resolved['Symbol']) is str and resolved['Symbol']),
                 'closed resolved original ABS32')
    root_names = set()
    for root in leaf['RootEvidence']:
        need(set(root) == {'Name', 'Symbol', 'Section', 'BodySha256', 'InstructionCount', 'MappedData',
             'References', 'DirectCompilerEffects', 'AnnotationMutant', 'CompleteBodyCovered'}, 'closed protected root')
        attrs._symbol_fields(root['Symbol'])
        root_names.add(root['Name'])
        start = root['Symbol']['value'] & ~1
        end = start + root['Symbol']['size']
        previous = start
        for mapped in root['MappedData']:
            need(type(mapped) is dict and set(mapped) == {'Offset', 'Size', 'BytesSha256'}
                 and type(mapped['Offset']) is int and type(mapped['Size']) is int
                 and mapped['Size'] > 0 and previous <= mapped['Offset']
                 and mapped['Offset'] + mapped['Size'] <= end, 'mapped data stays inside its root')
            _hash(mapped['BytesSha256'])
            previous = mapped['Offset'] + mapped['Size']
    constructor_names = []
    for constructor in leaf['CompilerConstructors']:
        need(set(constructor) == {'Name', 'Symbol', 'References', 'BodySha256'}
             and type(constructor['Name']) is str
             and re.fullmatch(helpers['common_effects'].CONSTRUCTOR, constructor['Name']) is not None,
             'closed compiler constructor')
        attrs._symbol_fields(constructor['Symbol'])
        need(constructor['Symbol']['name'] == constructor['Name']
             and constructor['Symbol']['kind'] == 'STT_FUNC'
             and constructor['References'] == [ref for ref in refs if ref['Owner'] == constructor['Name']],
             'complete constructor REL projection')
        _hash(constructor['BodySha256'])
        constructor_names.append(constructor['Name'])
    need(constructor_names == sorted(set(constructor_names)), 'unique ordered constructors')
    owners = root_names | set(constructor_names) | (set() if stress else {attrs.COLD})
    need(all(ref['Owner'] is None or ref['Owner'] in owners for ref in refs), 'every REL has a declared owner')
    counter_names = []
    for counter in leaf['CounterDefinitions']:
        attrs._symbol_fields(counter)
        need(counter['kind'] == 'STT_OBJECT' and counter['size'] > 0 and type(counter['section']) is int
             and counter['section'] > 0, 'defined compiler counter')
        allowed = ({attrs.COLD} if not stress else set()) | ({mutation} if mutation else set())
        need(counter['name'] in {prefix + name for prefix in ('__gcov0.', '__gcov_.') for name in allowed},
             'counter belongs to ordinary/mutant owner')
        counter_names.append(counter['name'])
    need(len(counter_names) == len(set(counter_names)), 'unique compiler counters')
    need(set(leaf['CompilerImports']) == set(leaf['Undefined']) & attrs.HOOKS, 'complete compiler import projection')
    for pending in leaf['UnresolvedAttribution']:
        need(set(pending) == {'Function', 'Effects', 'ColdCounterReferences', 'ColdAddressReferences', 'AttributionValidated'},
             'closed pending attribution')
        setter = [ref for ref in refs if ref['Owner'] == attrs.SETTER]
        need(pending['ColdCounterReferences'] == [ref for ref in setter
             if ref['SemanticTarget'] in ('__gcov0.' + attrs.COLD, '__gcov_.' + attrs.COLD)]
             and pending['ColdAddressReferences'] == [ref for ref in setter if ref['SemanticTarget'] == attrs.COLD],
             'complete pending cold evidence projections')
    if stress and mutation:
        counter = leaf['StressCounterEvidence']
        need(set(counter) == {'Definition', 'References'}
             and counter['Definition'] in leaf['CounterDefinitions']
             and counter['References'] == [ref for ref in refs if ref['Owner'] == attrs.STRESS and ref['Kind'] == 2
                 and ref['CompilerCounter'] and ref['ResolvedABS32'] is not None
                 and ref['ResolvedABS32']['Symbol'] == '__gcov0.' + attrs.STRESS], 'complete stress counter projection')


def require_result(proof, helpers):
    """Deep evidence checking with the same authenticated frozen leaf validator."""
    _helpers(helpers)
    need(type(proof) is dict and set(proof) == FIELDS, 'closed adapter proof')
    for key, value in (('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct')):
        need(type(proof[key]) is str and proof[key] == value, 'fixed adapter identity/' + key)
    need(proof['LTO'] is True, 'adapter LTO')
    for key, value in COUNTS.items():
        need(type(proof[key]) is int and proof[key] == value, 'typed adapter count/' + key)
    for key in NONCLAIMS:
        need(proof[key] is False, 'adapter nonclaim/' + key)
    for key in FACTS:
        need(proof[key] is True, 'adapter fact/' + key)
    hashes = _layout(proof['Lowerings'], proof['ResolvedWorkers'])
    reads = proof['ReadInputs']
    need(type(reads) is list and len(reads) == len(hashes), 'complete immutable read list')
    sizes = {}
    for row, path in zip(reads, sorted(hashes)):
        need(type(row) is dict and set(row) == {'Path', 'Sha256', 'Bytes'}
             and row['Path'] == str(path) and row['Sha256'] == hashes[path]
             and type(row['Bytes']) is int and row['Bytes'] > 0, 'exact ordered read binding')
        sizes[path] = row['Bytes']
    chains, common = proof['WorkerChains'], proof['CommonMachines']
    need(type(chains) is list and len(chains) == 6 and type(common) is list and len(common) == 6, 'six exact worker/machine pairs')
    unresolved = []
    for index, (chain, row, lower) in enumerate(zip(chains, common, proof['Lowerings'])):
        group, mutation, stress = GROUPS[index], MUTATIONS[index], index >= 4
        need(type(chain) is dict and set(chain) == {'Group', 'Proof'} and chain['Group'] == group, 'ordered worker cohort')
        _worker(chain['Proof'], lower, proof['ResolvedWorkers'], hashes, sizes, helpers)
        need(type(row) is dict and set(row) == {'Group', 'Machines'} and row['Group'] == group
             and type(row['Machines']) is list and len(row['Machines']) == 2, 'ordered image cohort')
        for machine, role in zip(row['Machines'], ('Object', 'Machine')):
            need(type(machine) is dict and set(machine) == {'Role', 'Proof', 'OriginalProtectedPredicateRejected'}
                 and machine['Role'] == role and machine['OriginalProtectedPredicateRejected'] is (mutation is not None), 'exact machine role/rejection')
            leaf = machine['Proof']
            _effect(leaf, mutation, stress, helpers)
            need(leaf['ObjectSha256'] == lower['Roles'][role]['Sha256'], 'effect proof binds actual image')
            if leaf['UnresolvedAttribution']:
                unresolved.append(dict(Group=group, Role=role, Evidence=copy.deepcopy(leaf['UnresolvedAttribution'])))
        first, second = [m['Proof'] for m in row['Machines']]
        need(first['Status'] == second['Status'] and first['Undefined'] == second['Undefined'], 'aggregate/worker disposition agrees')
    need(type(proof['UnresolvedAttribution']) is list and proof['UnresolvedAttribution'] == unresolved
         and proof['CommonAttributionClosed'] is (not unresolved)
         and proof['Status'] == (PENDING if unresolved else PASS), 'full unresolved projection cannot be promoted')
    return proof


def inspect(core, read, lowerings, native, helpers):
    """Replay six worker chains and twelve images inside the supplied reader."""
    _helpers(helpers)
    need(callable(read) and callable(getattr(core, '_ELF', None)), 'supplied immutable reader/core')
    need(type(native) is dict and native.get('Profile') == 'CM3' and native.get('Mode') == 'Os-lto'
         and native.get('Linkage') == 'direct' and native.get('LTO') is True
         and type(native.get('ResolvedWorkers')) is dict
         and all(name in native['ResolvedWorkers'] for name in ('lto1', 'as')), 'actual native worker authority')
    lowerings = copy.deepcopy(lowerings)
    workers = {name: copy.deepcopy(native['ResolvedWorkers'][name]) for name in ('lto1', 'as')}
    hashes = _layout(lowerings, workers)
    buffers = {}
    for path in sorted(hashes):
        raw = read(path, hashes[path])
        need(sha(raw) == hashes[path] and raw, 'bound nonempty local reader bytes/' + str(path))
        buffers[path] = raw

    def checked(value):
        path = _path(value)
        need(path in buffers, 'read outside explicit local input roles/' + str(path))
        return path

    def cached(value, digest=None):
        path = checked(value)
        need(digest is None or digest == hashes[path], 'local expected hash')
        return buffers[path]

    def stable(value):
        return checked(_reported(value))

    def text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None, 'strict local text decode')
        return cached(path).decode(encoding or 'utf-8')

    view = SimpleNamespace(watch=SimpleNamespace(read=cached), api=SimpleNamespace(checked_path=checked),
        result={'ResolvedWorkers': copy.deepcopy(workers)}, transport=helpers['transport'],
        admitted=SimpleNamespace(base=SimpleNamespace(stable_path=stable)))
    chains, common, unresolved = [], [], []
    with patch.object(Path, 'read_bytes', cached), patch.object(Path, 'read_text', text):
        for index, lower in enumerate(lowerings):
            group, mutation, stress = GROUPS[index], MUTATIONS[index], index >= 4
            roles = lower['Roles']
            machine, chain = helpers['common_workers'].worker_chain(view, _path(roles['Object']['Path']),
                [_path(row['Path']) for row in lower['Inputs']], _path(roles['DriverSpecs']['Path']),
                buffers[_path(roles['Diagnostics']['Path'])], helpers['attribute_runner'])
            need(machine == _path(roles['Machine']['Path']) and chain.get('MachineSha256') == roles['Machine']['Sha256'], 'worker exact derived machine')
            chains.append(dict(Group=group, Proof=chain))
            pair = []
            for role in ('Object', 'Machine'):
                path = _path(roles[role]['Path'])
                image = core._ELF(path, 'ET_REL')
                need(type(image.data) is bytes and image.data == buffers[path] and image.final is False, 'parser consumes exact admitted image')
                leaf = helpers['common_effects'].inspect_lowered(image, core, helpers['attributes'], mutation=mutation, stress=stress)
                helpers['common_effects'].require_result(leaf, mutation=mutation, stress=stress)
                rejected = False
                if mutation is not None:
                    try:
                        helpers['common_effects'].inspect_lowered(image, core, helpers['attributes'], stress=stress)
                    except helpers['common_effects'].Rejected:
                        rejected = True
                    need(rejected, 'unchanged clean predicate must reject actual mutant/' + group + '/' + role)
                if leaf['UnresolvedAttribution']:
                    unresolved.append(dict(Group=group, Role=role, Evidence=copy.deepcopy(leaf['UnresolvedAttribution'])))
                pair.append(dict(Role=role, Proof=leaf, OriginalProtectedPredicateRejected=rejected))
            common.append(dict(Group=group, Machines=pair))
    proof = dict(Status=PENDING if unresolved else PASS, Scope=SCOPE, Profile='CM3', Mode='Os-lto',
        Linkage='direct', LTO=True, Lowerings=lowerings, ResolvedWorkers=workers,
        WorkerChains=chains, CommonMachines=common, UnresolvedAttribution=unresolved,
        CommonAttributionClosed=not unresolved,
        ReadInputs=[dict(Path=str(p), Sha256=hashes[p], Bytes=len(buffers[p])) for p in sorted(buffers)],
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    return require_result(proof, helpers)
