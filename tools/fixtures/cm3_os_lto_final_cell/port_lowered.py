"""Pure four-chain/eight-image Os port replay in the caller's immutable reader.

The caller reconstructs and authenticates the command plans. Saved files, maps
and startup objects are byte bindings, not wrapper, assembler, linker-map or
startup-transfer semantics. No parser, reader scope or subprocess is created.
"""

import copy
import hashlib
import json
import ntpath
from pathlib import Path
import re
import struct
from types import SimpleNamespace
from unittest.mock import patch


PASS = 'CM3-OS-LTO-PORT-LOWERED-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_FOUR_PORT_CHAINS_EIGHT_IMAGES_ONLY'
GROUPS = ('selected', 'stress-supported', 'stress-raw', 'Final')
STARTS = (114, 121, 128, 131)
STEMS = ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')
HELPERS = frozenset(('port_runner', 'port_phase', 'transport', 'census',
                     'policy', 'effects', 'attributes'))
SUFFIXES = ('.ltrans.out', '.ltrans0.ltrans.args.0', '.ltrans0.ltrans.o',
    '.ltrans0.ltrans.s', '.ltrans0.ltrans_args', '.ltrans0.o', '.ltrans_args',
    '.res', '.wpa.args.0')
CONTROL_SUFFIXES = ('.ltrans_args', '.ltrans0.ltrans_args', '.wpa.args.0',
                    '.ltrans0.ltrans.args.0', '.ltrans.out')
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied',
    'WholeCellProof', 'CompleteCellProof', 'SelectedPortAttributePolicyProven',
    'GeneralRegistersOnlyEffectProved', 'FullAttributeEquivalence', 'TransitiveProtection',
    'FullABIProof', 'FullSemanticABIProof', 'FullInstructionSemantics', 'FullIRSemantics',
    'IRImportClosureValidated', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'OriginalTranslationUnitMachineOwnership',
    'AllRelocationDestinationSemanticsValidated', 'CanonicalProtocolValidated',
    'FinalRootTransferProtocolsValidated', 'FinalReferenceParity', 'FinalMappingValidated',
    'StartupTransferSemanticsValidated', 'WrapperSemanticsValidated',
    'ResolutionSemanticsValidated', 'AssemblySemanticsValidated',
    'JournalBindingsValidated', 'OsProcessTraceVerified', 'ProducerCompilersReexecuted',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')
FACTS = ('WorkerChainsReplayed', 'MachineCensusesRecomputed', 'PairedStressRecomputed',
    'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsHelperAuthentication',
    'CallerOwnsPlanJournalBinding', 'CallerOwnsManifestAuthentication')
COUNTS = dict(WorkerPlans=4, InputRoles=18, ELFImages=8, SelectedImages=2,
    StressImages=4, FinalImages=2, ToolInvocations=0, CompilerInvocations=0,
    RequiredCellCount=0, RequiredCellsSatisfied=0)
FIELDS = frozenset(NONCLAIMS + FACTS) | frozenset(COUNTS) | frozenset((
    'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Root', 'ManifestInput',
    'NativeObjects', 'ResolvedWorkers', 'IRDefinitionSurface', 'Inputs', 'Plans',
    'WorkerChains', 'Machines', 'ReadInputs', 'ReadFiles', 'ControlBytes'))
PLAN_FIELDS = frozenset(('Component', 'Group', 'Output', 'Objects', 'Specs',
                        'Diagnostics', 'Supported', 'StoredWorker'))
NORMAL_PLAN_FIELDS = frozenset(('Group', 'Output', 'Objects', 'Specs',
                               'Diagnostics', 'Supported', 'StoredWorker'))
WORKER_FIELDS = frozenset(('SupportedPolicy', 'EffectiveOptionsVerified', 'WpaOptions',
    'LtransOptions', 'Machine', 'MachineSha256', 'MachineHeader', 'WpaArguments',
    'LtransArguments', 'WpaInputs', 'Intermediate', 'IntermediateSha256',
    'DriverSpecs', 'Execution'))
CENSUS_FALSE = ('FullInstructionSemantics', 'SourceIRSemantics',
    'OriginalTranslationUnitOwnership', 'AttributeOnlyProtection',
    'GeneralRegistersOnlyEffectProved', 'WorkerProvenanceValidated',
    'CanonicalRootProtocolsValidated', 'CPUExecution', 'BoardExecution', 'GlobalQualification')
CENSUS_TRUE = ('CompleteExecutableCensus', 'ForbiddenDependenciesAbsent', 'RecognizedForbiddenFormsAbsent')
CENSUS_FIELDS = frozenset(CENSUS_FALSE + CENSUS_TRUE) | frozenset((
    'Status', 'Scope', 'Profile', 'Mode', 'ObjectSha256', 'DisassemblySha256',
    'FinalELF', 'FunctionsAudited', 'FunctionEvidence', 'DefinitionsFromIR',
    'DefinitionSurface', 'Undefined', 'AllowedMemoryHelpers', 'References', 'Padding',
    'UnownedMappedPools', 'ExecutableInstructionBytes', 'ExecutableMappedDataBytes',
    'RecognizedForbiddenForms', 'RequiredCellsSatisfied'))
SYMBOL_FIELDS = frozenset(('name', 'section', 'value', 'size', 'kind', 'binding', 'visibility', 'index'))
EFFECT_FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'Stress',
    'Mutation', 'ModeAuthority', 'HelperAuthenticationCallerOwned', 'ObjectSha256',
    'ProtectedFunctions', 'RootEvidence', 'Undefined', 'CompilerImports', 'OrdinaryEvidence',
    'CounterDefinitions', 'References', 'CompilerConstructors', 'MetadataReferences',
    'UnresolvedAttribution', 'AllProtectedBodiesClean', 'CompiledAnnotationMutantDetected',
    'StressFamiliesActivated', 'StressCounterEvidence', 'ThreadSectionValidated',
    'OrdinaryColdActivityValidated', 'ColdInlineAttributionValidated', 'OriginalRELFieldsCensused',
    'RelocationFields', 'RequiredCellCount', 'RequiredCellsSatisfied', 'TransitiveProtection',
    'FullABI', 'FullSemanticABIProof', 'FullIRSemantics', 'FullInstructionSemantics',
    'FullAttributeEquivalence', 'CPUExecution', 'BoardExecution', 'GlobalQualification',
    'Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OsCompilerOptionsValidated', 'FinalLinkValidated', 'AllRelocationDestinationSemanticsValidated'))
EFFECT_REF_FIELDS = frozenset(('Section', 'Offset', 'Kind', 'Target', 'Owner', 'SiteBytes',
    'FieldBytes', 'OriginalAddend', 'ResolvedABS32', 'SemanticTarget', 'CompilerHook',
    'CompilerCounter', 'OriginalHookTransferValidated', 'AppliedDestinationValidated', 'ConstructorArray'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-PORT-LOWERED:' + detail)


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
    need(all(part and part not in ('.', '..') and ':' not in part and part == part.rstrip(' .')
             for part in text[3:].replace('\\', '/').split('/')), 'canonical lexical path')
    return Path(text)


def _reported(value):
    need(type(value) is str and re.match(r'^[A-Za-z]:[\\/]', value) is not None
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'absolute reported executable')
    return _path(ntpath.normpath(value))


def _same(actual, expected, detail):
    need(type(actual) is type(expected), 'exact type/' + detail)
    if type(expected) is dict:
        need(set(actual) == set(expected), 'closed object/' + detail)
        for key in expected:
            _same(actual[key], expected[key], detail + '/' + key)
    elif type(expected) is list:
        need(len(actual) == len(expected), 'exact list/' + detail)
        for index, value in enumerate(expected):
            _same(actual[index], value, detail + '/' + str(index))
    else:
        need(actual == expected, 'exact value/' + detail)


def _binding(value):
    need(type(value) is dict and set(value) == {'Path', 'Sha256'}
         and type(value['Path']) is str, 'closed input binding')
    return _path(value['Path']), _hash(value['Sha256'])


def _helpers(helpers):
    need(type(helpers) is dict and set(helpers) == HELPERS, 'exact helper roles')
    for name, methods in (('port_runner', ('worker_chain', 'argument_lines')),
            ('port_phase', ('require_effective_options',)), ('transport', ('require_elf32le',)),
            ('census', ('inspect_lowered', 'inspect_final', 'inspect_stress')),
            ('policy', ('inspect_ir_definitions', '_header', '_symbols', '_disassembly', '_forms')),
            ('effects', ('inspect_lowered', 'require_result')), ('attributes', ('_symbol_fields',))):
        need(all(callable(getattr(helpers[name], f, None)) for f in methods), 'helper API/' + name)


def _surface(surface, helpers):
    policy = helpers['policy']
    need(type(surface) is dict and type(surface.get('Definitions')) is list, 'IR surface')
    grouped = {role: [] for role in policy.ROLES}
    for row in surface['Definitions']:
        need(type(row) is dict and set(row) == {'Role', 'Name', 'Kind', 'Value', 'Size'}
             and type(row['Role']) is str and row['Role'] in grouped, 'IR surface row')
        grouped[row['Role']].append({k: row[k] for k in ('Name', 'Kind', 'Value', 'Size')})
    _same(surface, policy.inspect_ir_definitions(grouped), 'recomputed neutral IR surface')


def _manifest(raw, root):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate manifest key')
            result[key] = value
        return result
    need(type(raw) is bytes and raw and b'\0' not in raw, 'immutable manifest bytes')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda value: need(False, 'manifest constant'))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-PORT-LOWERED:manifest grammar') from error
    need(type(value) is dict and set(value) == {'Artifacts'} and type(value['Artifacts']) is dict,
         'exact artifact registry')
    result = {}
    for name, digest in value['Artifacts'].items():
        need(type(name) is str and name and '\\' not in name and ':' not in name
             and all(part not in ('', '.', '..') for part in name.split('/'))
             and name != 'artifacts.json', 'relative artifact name')
        path = _path(root / name)
        need(path not in result, 'unique lexical artifact')
        result[path] = _hash(digest)
    return result


def _layout(root, plans, native_objects, workers, roles, available):
    root = _path(root)
    need(type(native_objects) is list and len(native_objects) == 9, 'nine native object authorities')
    originals = [_binding(row)[0] for row in native_objects]
    need(len(set(originals)) == 9 and all(not p.is_relative_to(root) for p in originals),
         'distinct native objects outside generated batch')
    need(type(workers) is dict and set(workers) == {'lto1', 'as'}, 'two resolved worker roles')
    worker_paths = [_binding(workers[name])[0] for name in ('lto1', 'as')]
    need(len(set(worker_paths)) == 2 and all(p.name == name + '.exe' and not p.is_relative_to(root)
         for name, p in zip(('lto1', 'as'), worker_paths)), 'named external workers')
    need(type(plans) is list and len(plans) == 4, 'four ordered port plans')
    selected = [root / 'port-policy/ir/selected' / (stem + '.o') for stem in STEMS]
    expected_roles, required = {}, {root / 'artifacts.json'}
    controls = set()
    for index, plan in enumerate(plans):
        group, supported = GROUPS[index], index != 2
        need(type(plan) is dict and set(plan) == NORMAL_PLAN_FIELDS and plan['Group'] == group
             and plan['Supported'] is supported and type(plan['StoredWorker']) is dict, 'closed ordered plan/' + group)
        output = root / 'port-policy/final-supported/image.elf' if index == 3 else root / 'port-policy/lowered' / group / 'aggregate.o'
        need(plan['Output'] == str(output), 'fixed plan output/' + group)
        objects = selected if index == 0 else ([root / 'port-policy/ir' / group / 'stress.o'] if index < 3
            else originals[:3] + selected + originals[6:])
        need(type(plan['Objects']) is list and [_binding(x)[0] for x in plan['Objects']] == objects,
             'exact ordered plan cohort/' + group)
        specs = root / 'port-policy/driver/no-auto-gcov.specs' if index == 2 else None
        need((plan['Specs'] is None) if specs is None else _binding(plan['Specs'])[0] == specs, 'raw-only specs')
        diagnostics = root / ('commands/%03d.stderr' % STARTS[index])
        need(_binding(plan['Diagnostics'])[0] == diagnostics, 'fixed diagnostic stream')
        required.update((output, diagnostics, *objects))
        required.update(Path(str(output) + suffix) for suffix in SUFFIXES)
        if specs is not None:
            required.add(specs)
        wrappers = {Path(str(output) + '.lto_wrapper_args'),
                    root / (''.join(output.parts[1:]) + '.lto_wrapper_args')}
        present = wrappers & set(available)
        need(len(present) == 1, 'one immutable wrapper binding/' + group)
        required.update(present)
        required.update(Path(str(output) + suffix) for suffix in ('.wpa.gcno', '.ltrans0.ltrans.gcno')
                        if Path(str(output) + suffix) in available)
        controls.update(Path(str(output) + suffix) for suffix in CONTROL_SUFFIXES)
        controls.add(diagnostics)
        machine = Path(str(output) + '.ltrans0.ltrans.o')
        values = (('Final/ELF', output), ('Final/Map', output.with_suffix('.map')),
            ('Final/Disassembly', Path(str(output) + '.dis')), ('Final/Machine', machine),
            ('Final/MachineDisassembly', Path(str(machine) + '.dis')), ('Final/Startup', originals[8])) if index == 3 else (
            (group + '/Aggregate', output), (group + '/AggregateDisassembly', Path(str(output) + '.dis')),
            (group + '/Machine', machine), (group + '/MachineDisassembly', Path(str(machine) + '.dis')))
        expected_roles.update(values)
        for binding in [*plan['Objects'], plan['Diagnostics'], *([] if plan['Specs'] is None else [plan['Specs']])]:
            path, digest = _binding(binding)
            need(available.get(path) == digest, 'plan/input hash agreement')
    need(type(roles) is dict and set(roles) == set(expected_roles), 'eighteen exact deferred roles')
    for name, path in expected_roles.items():
        row = roles[name]
        need(type(row) is dict and set(row) == {'Role', 'Path', 'Sha256'}
             and row['Role'] == name and row['Path'] == str(path)
             and available.get(path) == _hash(row['Sha256']), 'fixed deferred role/' + name)
        required.add(path)
    need(len(set(expected_roles.values())) == 18, 'distinct deferred files')
    required.update(worker_paths)
    for row in [*native_objects, *workers.values()]:
        path, digest = _binding(row)
        if path in required:
            need(available.get(path) == digest, 'native input hash authority')
    need(required <= set(available), 'all fixed worker input bindings')
    return required, controls


def _symbol(row):
    need(type(row) is dict and set(row) == SYMBOL_FIELDS, 'closed ELF symbol')
    for key in ('name', 'kind', 'binding', 'visibility'):
        need(type(row[key]) is str, 'literal symbol string')
    need(type(row['section']) is int and row['section'] > 0 or
         type(row['section']) is str and row['section'] in ('SHN_UNDEF', 'SHN_ABS', 'SHN_COMMON'), 'symbol section')
    need(all(type(row[k]) is int and row[k] >= 0 for k in ('value', 'size', 'index')), 'literal symbol integers')


def _header(header, size):
    need(type(header) is dict and set(header) == {'Class', 'Data', 'Type', 'Machine', 'Version',
         'HeaderSize', 'SectionOffset', 'SectionEntrySize', 'SectionCount'}, 'closed machine header')
    for key, value in (('Class', 'ELF32'), ('Data', 'little-endian'), ('Type', 'REL'), ('Machine', 'ARM'),
                       ('Version', 1), ('HeaderSize', 52), ('SectionEntrySize', 40)):
        _same(header[key], value, 'machine header/' + key)
    need(type(header['SectionOffset']) is int and type(header['SectionCount']) is int
         and header['SectionCount'] > 0 and 52 <= header['SectionOffset']
         and header['SectionOffset'] + header['SectionCount'] * 40 <= size, 'machine section bounds')


def _worker(proof, plan, workers, hashes, sizes, controls, startup, helpers):
    need(type(proof) is dict and set(proof) == WORKER_FIELDS, 'closed neutral worker proof')
    output, supported = _path(plan['Output']), plan['Supported']
    prefix = str(output)
    machine, intermediate = Path(prefix + '.ltrans0.ltrans.o'), Path(prefix + '.ltrans0.o')
    need(proof['SupportedPolicy'] is supported and proof['EffectiveOptionsVerified'] is True, 'worker literal flags')
    for key, value in (('Machine', str(machine)), ('MachineSha256', hashes[machine]),
        ('Intermediate', str(intermediate)), ('IntermediateSha256', hashes[intermediate]),
        ('WpaArguments', prefix + '.ltrans_args'), ('LtransArguments', prefix + '.ltrans0.ltrans_args')):
        _same(proof[key], value, 'worker binding/' + key)
    _same(proof['DriverSpecs'], plan['Specs'], 'worker specs')
    ir = [row for row in plan['Objects'] if _path(row['Path']) != startup]
    _same(proof['WpaInputs'], ir, 'worker ordered input hashes')
    _header(proof['MachineHeader'], sizes[machine])
    vectors = [helpers['port_runner'].argument_lines(controls[Path(prefix + suffix)])
               for suffix in ('.ltrans_args', '.ltrans0.ltrans_args')]
    for argv, marker, key in zip(vectors, ('-fwpa', '-fltrans'), ('WpaOptions', 'LtransOptions')):
        need([x for x in argv if x in ('-fwpa', '-fltrans')] == [marker], 'saved worker stage')
        _same(proof[key], helpers['port_phase'].require_effective_options(argv, supported=supported), key)
        need([x for x in argv if x.startswith('-specs=')] ==
             ([] if plan['Specs'] is None else ['-specs=' + plan['Specs']['Path']]), 'saved specs argv')
    need([x for x in vectors[0] if x.endswith('.o')] == [x['Path'] for x in ir], 'saved WPA order')
    need(helpers['port_runner'].argument_lines(controls[Path(prefix + '.wpa.args.0')]) == [x['Path'] for x in ir],
         'WPA response order')
    need(vectors[1][-1] == str(intermediate) and vectors[1].count('-o') == 1
         and vectors[1][vectors[1].index('-o') + 1] == str(machine), 'saved LTRANS input/output')
    need(helpers['port_runner'].argument_lines(controls[Path(prefix + '.ltrans0.ltrans.args.0')]) == [str(intermediate)],
         'LTRANS response')
    listed = controls[Path(prefix + '.ltrans.out')].decode('ascii').splitlines()
    need(len(listed) == 2 and re.fullmatch('[0-9]+', listed[0]) and listed[1] == str(intermediate), 'one partition')
    execution = proof['Execution']
    need(type(execution) is dict and set(execution) == {'CompilerReportedWorkerExecutionVerified',
         'OsProcessTraceVerified', 'TranscriptSha256', 'WorkerInvocations', 'EffectiveOptions', 'Assembler'}
         and execution['CompilerReportedWorkerExecutionVerified'] is True and execution['OsProcessTraceVerified'] is False,
         'closed compiler-reported execution')
    raw = controls[_path(plan['Diagnostics']['Path'])]
    need(execution['TranscriptSha256'] == sha(raw) == plan['Diagnostics']['Sha256'], 'actual diagnostics bytes')
    text = raw.decode('ascii')
    need(not re.search(r'(?im)(?:^|\s)(?:fatal error|error|warning):', text), 'clean diagnostic text')
    lines = [line.strip().split() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]lto1[.]exe ', line)]
    need(len(lines) == 2 and type(execution['WorkerInvocations']) is list
         and len(execution['WorkerInvocations']) == 2 and type(execution['EffectiveOptions']) is list
         and len(execution['EffectiveOptions']) == 2, 'exact actual stages')
    for index, (marker, suffix) in enumerate((('-fwpa', '.wpa.args.0'), ('-fltrans', '.ltrans0.ltrans.args.0'))):
        argv = lines[index]
        need(_reported(argv[0]) == _path(workers['lto1']['Path'])
             and [x for x in argv if x in ('-fwpa', '-fltrans')] == [marker]
             and [x for x in argv if x.startswith('@')] == ['@' + prefix + suffix], 'actual worker argv')
        expected = dict(Stage=marker, Executable=workers['lto1']['Path'], ExecutableSha256=workers['lto1']['Sha256'],
            Argv=argv, Response=prefix + suffix, ResponseSha256=hashes[Path(prefix + suffix)])
        _same(execution['WorkerInvocations'][index], expected, 'actual invocation')
        _same(execution['EffectiveOptions'][index],
            helpers['port_phase'].require_effective_options(argv, supported=supported), 'actual Os options')
        if index == 1:
            need(argv.count('-o') == 1 and argv[argv.index('-o') + 1] == prefix + '.ltrans0.ltrans.s', 'actual assembly output')
    lines = [line.strip().split() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]as[.]exe ', line)]
    need(len(lines) == 1, 'one actual assembler')
    argv = lines[0]
    need(_reported(argv[0]) == _path(workers['as']['Path']) and argv.count('-o') == 1
         and argv[argv.index('-o') + 1] == str(machine) and argv[-1] == prefix + '.ltrans0.ltrans.s'
         and not any(x.startswith('@') for x in argv), 'actual assembler chain')
    _same(execution['Assembler'], dict(Executable=workers['as']['Path'],
        ExecutableSha256=workers['as']['Sha256'], Argv=argv), 'assembler binding')
    _same(proof, plan['StoredWorker'], 'stored worker is only a complete comparison target')


def _census(proof, object_hash, dump_hash, surface, helpers, *, final=False, whole=False, stress=False):
    need(type(proof) is dict and set(proof) == CENSUS_FIELDS | ({'FinalRootVectorBindings'} if final else set()),
         'closed Os machine census')
    for key, value in (('Status', 'CM3-OS-LTO-PORT-CENSUS-PASS'), ('Scope', 'CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY'),
        ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('ObjectSha256', object_hash), ('DisassemblySha256', dump_hash),
        ('FinalELF', final), ('AllowedMemoryHelpers', ['memcpy', 'memset']), ('RequiredCellsSatisfied', 0)):
        _same(proof[key], value, 'census identity/' + key)
    for key in CENSUS_FALSE:
        need(proof[key] is False, 'census nonclaim/' + key)
    for key in CENSUS_TRUE:
        need(proof[key] is True, 'census fact/' + key)
    policy = helpers['policy']
    _same(proof['RecognizedForbiddenForms'], list(policy.FORBIDDEN_FORMS), 'bounded recognized forms')
    expected_imports = [] if final or stress else sorted(policy.FINAL_WORKER_UNDEFINED if whole else policy.UNDEFINED)
    _same(proof['Undefined'], expected_imports, 'exact census imports')
    _same(proof['DefinitionSurface'], None if stress else surface, 'complete IR surface projection')
    evidence, refs = proof['FunctionEvidence'], proof['References']
    need(type(evidence) is list and evidence and type(proof['FunctionsAudited']) is int
         and proof['FunctionsAudited'] == len(evidence) and type(refs) is list, 'complete function census')
    names, symbols = [], {}
    for row in evidence:
        need(type(row) is dict and set(row) == {'Name', 'Symbol', 'Instructions', 'DataBytes', 'References', 'BodySha256'},
             'closed function evidence')
        _symbol(row['Symbol'])
        name = row['Name']
        need(type(name) is str and name and name == row['Symbol']['name'] and name not in names
             and row['Symbol']['kind'] == 'STT_FUNC' and type(row['Symbol']['section']) is int
             and row['Symbol']['value'] & 1 and row['Symbol']['size'] > 0, 'unique Thumb function')
        need(type(row['Instructions']) is int and row['Instructions'] > 0
             and type(row['DataBytes']) is int and row['DataBytes'] >= 0, 'typed function coverage')
        _hash(row['BodySha256'])
        _same(row['References'], [ref for ref in refs if ref.get('Owner') == name], 'complete function REL projection')
        names.append(name)
        symbols[name] = row['Symbol']
    indices = [row['Symbol']['index'] for row in evidence]
    need(indices == sorted(set(indices)), 'original symbol-table function order')
    definitions = proof['DefinitionsFromIR']
    need(type(definitions) is list and len(definitions) == (0 if stress else len(surface['Definitions'])), 'IR definition count')
    for symbol, row in zip(definitions, [] if stress else surface['Definitions']):
        _symbol(symbol)
        need(symbol['name'] == row['Name'] and symbol['kind'] == ('STT_OBJECT' if row['Kind'] == 'D' else 'STT_FUNC'),
             'IR definition symbol kind')
        if symbol['kind'] == 'STT_FUNC':
            _same(symbol, symbols[symbol['name']], 'IR function projection')
    if not stress:
        need(set(policy.FORWARD + policy.NAKED) <= set(names), 'mandatory ABI/handlers')
        need(all(symbols[name]['binding'] == 'STB_GLOBAL' for name in policy.FORWARD + policy.NAKED), 'strong mandatory functions')
        if not final and not whole:
            need(set(policy.LOCAL) <= set(names), 'mandatory selected private helpers')
    else:
        need(names == [helpers['attributes'].STRESS], 'one clean stress carrier')
    sites, imported = [], set()
    for ref in refs:
        need(type(ref) is dict and set(ref) == {'Section', 'Offset', 'Kind', 'Target', 'Owner', 'SiteForm',
             'SiteBytes', 'FieldBytes', 'AddendSemanticsValidated', 'AppliedDestinationValidated'}, 'closed original/applied REL row')
        need(all(type(ref[k]) is int for k in ('Section', 'Offset', 'Kind', 'FieldBytes'))
             and ref['Section'] > 0 and ref['Offset'] >= 0 and ref['Kind'] in (2, 10, 30)
             and ref['FieldBytes'] == 4 and type(ref['SiteBytes']) is str
             and re.fullmatch('[0-9a-f]{8}', ref['SiteBytes']) is not None, 'literal REL field')
        _symbol(ref['Target'])
        need(ref['Owner'] is None or type(ref['Owner']) is str and ref['Owner'] in symbols, 'declared REL owner')
        need(ref['AddendSemanticsValidated'] is False and ref['AppliedDestinationValidated'] is False, 'no REL semantic claim')
        need(not policy.FORBIDDEN.search(ref['Target']['name']), 'forbidden REL target absent')
        need(ref['Offset'] % (4 if ref['Kind'] == 2 else 2) == 0
             and ref['SiteForm'] == {2: 'ABS32-DATA', 10: 'THM_CALL-BL', 30: 'THM_JUMP24-B.W'}[ref['Kind']], 'recognized REL site form')
        if ref['Kind'] != 2:
            first, second = struct.unpack('<HH', bytes.fromhex(ref['SiteBytes']))
            need(ref['Owner'] is not None and first & 0xF800 == 0xF000
                 and second & 0xD000 == (0xD000 if ref['Kind'] == 10 else 0x9000), 'Thumb transfer field')
        need(all(s != ref['Section'] or o + 4 <= ref['Offset'] or ref['Offset'] + 4 <= o for s, o in sites),
             'nonoverlapping REL fields')
        sites.append((ref['Section'], ref['Offset']))
        if ref['Target']['section'] == 'SHN_UNDEF':
            imported.add(ref['Target']['name'])
    need(set(expected_imports) <= imported, 'every import has a bound REL use')
    for key in ('ExecutableInstructionBytes', 'ExecutableMappedDataBytes'):
        need(type(proof[key]) is int and proof[key] >= (1 if key == 'ExecutableInstructionBytes' else 0), 'typed census bytes')
    for key, fields in (('Padding', {'Section', 'Address', 'Bytes'}), ('UnownedMappedPools', {'Section', 'Address', 'Size', 'Bytes'})):
        need(type(proof[key]) is list, 'literal padding/pool list')
        for row in proof[key]:
            need(type(row) is dict and set(row) == fields
                 and type(row['Section']) is int and row['Section'] > 0
                 and type(row['Address']) is int and row['Address'] >= 0, 'closed padding/pool row')
            need(row['Bytes'] in ('00bf', 'aff30080') if key == 'Padding' else
                 type(row['Size']) is int and row['Size'] == 4 and type(row['Bytes']) is str
                 and re.fullmatch('[0-9a-f]{8}', row['Bytes']) is not None, 'bounded padding/pool bytes')
    if final:
        vector = proof['FinalRootVectorBindings']
        need(type(vector) is dict and set(vector) == {'VectorSha256', 'Words', 'Entry', 'SVC', 'PendSV',
             'AllocatedFileBackedLoadValidated', 'CanonicalRootProtocolsValidated'}, 'bounded final vector evidence')
        _hash(vector['VectorSha256'])
        _same(vector['Words'], 256, 'vector words')
        for key, name in (('Entry', 'Reset_Handler'), ('SVC', 'SVC_Handler'), ('PendSV', 'PendSV_Handler')):
            _same(vector[key], symbols[name]['value'], 'vector/strong function/' + key)
        need(vector['AllocatedFileBackedLoadValidated'] is True and vector['CanonicalRootProtocolsValidated'] is False,
             'file-backed vector binding only')


def _effect(proof, object_hash, supported, helpers):
    need(type(proof) is dict and set(proof) == EFFECT_FIELDS, 'closed stress effect leaf')
    mutation = None if supported else helpers['attributes'].STRESS
    helpers['effects'].require_result(proof, mutation=mutation, stress=True)
    need(proof['ObjectSha256'] == object_hash and proof['UnresolvedAttribution'] == [], 'bound stress result')
    _same(proof['Undefined'], sorted({row['Target']['name'] for row in proof['References']
          if row['Target']['section'] == 'SHN_UNDEF'}), 'complete stress import/reference projection')
    _same(proof['CompilerImports'], sorted(set(proof['Undefined']) & helpers['attributes'].HOOKS),
          'complete stress compiler import projection')
    for row in proof['References']:
        need(set(row) == EFFECT_REF_FIELDS, 'closed stress REL evidence')
        _symbol(row['Target'])
        resolved = row['ResolvedABS32']
        if resolved is not None:
            need(type(resolved) is dict and set(resolved) == {'Addend', 'TargetOffset', 'Symbol'}
                 and all(type(resolved[k]) is int and resolved[k] >= 0 for k in ('Addend', 'TargetOffset'))
                 and (resolved['Symbol'] is None or type(resolved['Symbol']) is str), 'closed stress ABS32 target')
    for row in proof['RootEvidence']:
        need(set(row) == {'Name', 'Symbol', 'Section', 'BodySha256', 'InstructionCount', 'MappedData',
             'References', 'DirectCompilerEffects', 'AnnotationMutant', 'CompleteBodyCovered'}, 'closed stress root')
        _symbol(row['Symbol'])
        for data in row['MappedData']:
            need(type(data) is dict and set(data) == {'Offset', 'Size', 'BytesSha256'}
                 and type(data['Offset']) is int and type(data['Size']) is int and data['Size'] > 0
                 and (row['Symbol']['value'] & ~1) <= data['Offset']
                 and data['Offset'] + data['Size'] <= (row['Symbol']['value'] & ~1) + row['Symbol']['size'],
                 'closed mapped stress data')
            _hash(data['BytesSha256'])
    for row in proof['CounterDefinitions']:
        _symbol(row)
        need(mutation is not None and row['kind'] == 'STT_OBJECT' and row['size'] > 0
             and row['name'] in ('__gcov0.' + mutation, '__gcov_.' + mutation), 'stress-owned counter')
    for row in proof['CompilerConstructors']:
        need(set(row) == {'Name', 'Symbol', 'References', 'BodySha256'}, 'closed stress constructor')
        _symbol(row['Symbol'])
        need(row['Name'] == row['Symbol']['name'] and re.fullmatch(helpers['effects'].CONSTRUCTOR, row['Name'])
             and row['References'] == [ref for ref in proof['References'] if ref['Owner'] == row['Name']], 'constructor projection')
        _hash(row['BodySha256'])
    constructors = [row['Name'] for row in proof['CompilerConstructors']]
    need(constructors == sorted(set(constructors)), 'unique ordered stress constructors')
    owners = {helpers['attributes'].STRESS, *constructors}
    need(all(row['Owner'] is None or row['Owner'] in owners for row in proof['References']), 'stress REL owners')
    if not supported:
        counter = proof['StressCounterEvidence']
        need(set(counter) == {'Definition', 'References'} and counter['Definition'] in proof['CounterDefinitions']
             and counter['References'] == [ref for ref in proof['References'] if ref['Owner'] == mutation
                 and ref['Kind'] == 2 and ref['CompilerCounter'] and ref['ResolvedABS32'] is not None
                 and ref['ResolvedABS32']['Symbol'] == '__gcov0.' + mutation], 'complete raw counter projection')


def require_result(proof, helpers):
    """Validate returned evidence and joins; never authenticate a caller by counts."""
    _helpers(helpers)
    need(type(proof) is dict and set(proof) == FIELDS, 'closed adapter result')
    for key, value in (('Status', PASS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('LTO', True)):
        _same(proof[key], value, 'adapter identity/' + key)
    for key, value in COUNTS.items():
        _same(proof[key], value, 'adapter count/' + key)
    for key in NONCLAIMS:
        need(proof[key] is False, 'adapter nonclaim/' + key)
    for key in FACTS:
        need(proof[key] is True, 'adapter fact/' + key)
    _surface(proof['IRDefinitionSurface'], helpers)
    root = _path(proof['Root'])
    manifest, manifest_hash = _binding(proof['ManifestInput'])
    need(manifest == root / 'artifacts.json', 'fixed manifest binding')
    reads = proof['ReadInputs']
    need(type(reads) is list and type(proof['ReadFiles']) is int and proof['ReadFiles'] == len(reads), 'literal read count')
    hashes, sizes = {}, {}
    for row in reads:
        need(type(row) is dict and set(row) == {'Path', 'Sha256', 'Bytes'}
             and type(row['Bytes']) is int and row['Bytes'] > 0, 'closed immutable read binding')
        path, digest = _binding({k: row[k] for k in ('Path', 'Sha256')})
        need(path not in hashes, 'distinct immutable reads')
        hashes[path], sizes[path] = digest, row['Bytes']
    need([row['Path'] for row in reads] == [str(p) for p in sorted(hashes)]
         and hashes.get(manifest) == manifest_hash, 'ordered read/manifest projection')
    required, control_paths = _layout(root, proof['Plans'], proof['NativeObjects'], proof['ResolvedWorkers'], proof['Inputs'], hashes)
    need(set(hashes) == required, 'exact local immutable read closure')
    need(type(proof['ControlBytes']) is dict and set(proof['ControlBytes']) == {str(p) for p in control_paths}, 'fixed control byte buffers')
    controls = {}
    for name, value in proof['ControlBytes'].items():
        need(type(value) is str and re.fullmatch('(?:[0-9a-f]{2})+', value) is not None, 'literal control byte encoding')
        raw = bytes.fromhex(value)
        need(sha(raw) == hashes[_path(name)] and len(raw) == sizes[_path(name)], 'control raw/hash binding')
        controls[_path(name)] = raw
    chains, machines = proof['WorkerChains'], proof['Machines']
    need(type(chains) is list and len(chains) == 4 and type(machines) is list and len(machines) == 4, 'four worker/image cohorts')
    for index, (chain, pair, plan) in enumerate(zip(chains, machines, proof['Plans'])):
        group = GROUPS[index]
        need(type(chain) is dict and set(chain) == {'Group', 'Proof'} and chain['Group'] == group, 'ordered worker evidence')
        _worker(chain['Proof'], plan, proof['ResolvedWorkers'], hashes, sizes, controls,
                _path(proof['NativeObjects'][8]['Path']), helpers)
        need(type(pair) is dict and set(pair) == {'Group', 'Images'} and pair['Group'] == group
             and type(pair['Images']) is list and len(pair['Images']) == 2, 'ordered image pair')
        for row, role in zip(pair['Images'], ('ELF', 'Machine') if index == 3 else ('Aggregate', 'Machine')):
            need(type(row) is dict and set(row) == {'Role', 'Proof'} and row['Role'] == role, 'closed image evidence')
            binding = proof['Inputs'][group + '/' + role]
            dump = proof['Inputs'][group + '/' + ('Disassembly' if role == 'ELF' else role + 'Disassembly')]
            if index in (0, 3):
                _census(row['Proof'], binding['Sha256'], dump['Sha256'], proof['IRDefinitionSurface'], helpers,
                        final=role == 'ELF', whole=index == 3 and role == 'Machine')
            else:
                leaf = row['Proof']
                supported = index == 1
                need(type(leaf) is dict and set(leaf) == {'Status', 'Effects', 'SupportedPolicy', 'RequiredCellsSatisfied',
                     *(['CleanMachine'] if supported else ['CleanPredicateRejected'])}, 'closed stress result')
                _same(leaf['SupportedPolicy'], supported, 'stress selector')
                _same(leaf['RequiredCellsSatisfied'], 0, 'stress zero credit')
                _same(leaf['Status'], 'CM3-OS-LTO-PORT-STRESS-CLEAN' if supported else
                      'CM3-OS-LTO-PORT-STRESS-EFFECTS-DETECTED', 'stress disposition')
                _effect(leaf['Effects'], binding['Sha256'], supported, helpers)
                if supported:
                    _census(leaf['CleanMachine'], binding['Sha256'], dump['Sha256'], None, helpers, stress=True)
                else:
                    need(leaf['CleanPredicateRejected'] is True, 'raw stress rejects unchanged clean predicate')
        first, second = [row['Proof'] for row in pair['Images']]
        need(first['Status'] == second['Status'], 'aggregate/worker disposition')
        if index in (0, 3):
            need(first['DefinitionSurface'] == second['DefinitionSurface'], 'same retained selected surface')
    return proof


def inspect(core, read, plans, native, helpers, *, roles, ir_definitions):
    """Replay four caller-reconstructed plans, using seven explicit helpers."""
    _helpers(helpers)
    need(callable(read) and callable(getattr(core, '_ELF', None)), 'supplied reader/core')
    need(type(native) is dict and native.get('Status') == 'PASS' and native.get('Profile') == 'CM3'
         and native.get('Mode') == 'Os-lto' and native.get('Linkage') == 'direct' and native.get('LTO') is True,
         'actual native Os authority')
    need(type(native.get('Sources')) is list and len(native['Sources']) == 9
         and type(native.get('ResolvedWorkers')) is dict, 'native object/worker authorities')
    originals = [dict(Path=row['Object'], Sha256=row['ObjectSha256']) for row in native['Sources']]
    workers = {name: copy.deepcopy(native['ResolvedWorkers'][name]) for name in ('lto1', 'as')}
    need(type(plans) is list and len(plans) == 4 and all(type(p) is dict and set(p) == PLAN_FIELDS
         and p['Component'] == 'PortPolicy' and p['Group'] == group for p, group in zip(plans, GROUPS)),
         'four reconstructed port plans, not stored verdicts')
    output = _path(plans[0]['Output'])
    need(len(output.parents) >= 4, 'bounded port namespace')
    root = output.parents[3]
    manifest_path = root / 'artifacts.json'
    manifest_raw = read(manifest_path)
    available = _manifest(manifest_raw, root)
    available[manifest_path] = sha(manifest_raw)
    for row in [*originals, *workers.values()]:
        path, digest = _binding(row)
        need(path not in available or available[path] == digest, 'consistent native binding')
        available[path] = digest
    normalized = []
    def binding(path):
        path = _path(path)
        need(path in available, 'fixed input outside manifest/native authority')
        return dict(Path=str(path), Sha256=available[path])
    for plan in plans:
        need(isinstance(plan['Output'], Path) and type(plan['Objects']) is list
             and all(isinstance(p, Path) for p in plan['Objects'])
             and (plan['Specs'] is None or isinstance(plan['Specs'], Path))
             and type(plan['Diagnostics']) is bytes and plan['Diagnostics'], 'literal reconstructed plan values')
        index = GROUPS.index(plan['Group'])
        diagnostics = binding(root / ('commands/%03d.stderr' % STARTS[index]))
        need(sha(plan['Diagnostics']) == diagnostics['Sha256'], 'plan diagnostic byte binding')
        normalized.append(dict(Group=plan['Group'], Output=str(plan['Output']),
            Objects=[binding(p) for p in plan['Objects']], Specs=None if plan['Specs'] is None else binding(plan['Specs']),
            Diagnostics=diagnostics, Supported=plan['Supported'], StoredWorker=copy.deepcopy(plan['StoredWorker'])))
    roles, surface = copy.deepcopy(roles), copy.deepcopy(ir_definitions)
    _surface(surface, helpers)
    required, control_paths = _layout(root, normalized, originals, workers, roles, available)
    buffers = {manifest_path: manifest_raw}
    for path in sorted(required - {manifest_path}):
        raw = read(path, available[path])
        need(sha(raw) == available[path] and raw, 'bound nonempty local input/' + str(path))
        buffers[path] = raw

    def checked(value):
        path = _path(value)
        need(path in buffers, 'read outside explicit local buffers/' + str(path))
        return path
    def cached(value, digest=None):
        path = checked(value)
        need(digest is None or digest == available[path], 'local expected digest')
        return buffers[path]
    def text(value, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None, 'strict local text')
        return cached(value).decode(encoding or 'utf-8')
    view = SimpleNamespace(watch=SimpleNamespace(read=cached), api=SimpleNamespace(checked_path=checked),
        result={'ResolvedWorkers': copy.deepcopy(workers)}, objects=[_path(row['Path']) for row in originals],
        transport=helpers['transport'], modules={'policy': helpers['port_phase']},
        admitted=SimpleNamespace(base=SimpleNamespace(stable_path=lambda p: checked(_reported(p)))))
    chains, machines = [], []
    with patch.object(Path, 'read_bytes', cached), patch.object(Path, 'read_text', text):
        for index, plan in enumerate(normalized):
            output = _path(plan['Output'])
            worker = helpers['port_runner'].worker_chain(view, output, [_path(row['Path']) for row in plan['Objects']],
                buffers[_path(plan['Diagnostics']['Path'])], supported=plan['Supported'],
                specs=None if plan['Specs'] is None else _path(plan['Specs']['Path']))
            _same(worker, plan['StoredWorker'], 'recomputed worker comparison target')
            chains.append(dict(Group=GROUPS[index], Proof=worker))
            images = []
            for role in ('ELF', 'Machine') if index == 3 else ('Aggregate', 'Machine'):
                row = roles[GROUPS[index] + '/' + role]
                dump = roles[GROUPS[index] + '/' + ('Disassembly' if role == 'ELF' else role + 'Disassembly')]
                path, final = _path(row['Path']), role == 'ELF'
                image = core._ELF(path, 'ET_EXEC' if final else 'ET_REL')
                need(type(image.data) is bytes and image.data == buffers[path] and image.final is final,
                     'supplied parser consumes exact admitted image')
                disassembly = buffers[_path(dump['Path'])]
                if index in (1, 2):
                    leaf = helpers['census'].inspect_stress(image, core, disassembly, helpers['policy'],
                        helpers['effects'], helpers['attributes'], supported=plan['Supported'])
                elif final:
                    leaf = helpers['census'].inspect_final(image, core, disassembly, surface, helpers['policy'])
                else:
                    leaf = helpers['census'].inspect_lowered(image, core, disassembly, surface, helpers['policy'],
                        whole_image=index == 3)
                images.append(dict(Role=role, Proof=leaf))
            machines.append(dict(Group=GROUPS[index], Images=images))
    proof = dict(Status=PASS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Root=str(root), ManifestInput=binding(manifest_path), NativeObjects=copy.deepcopy(originals),
        ResolvedWorkers=workers, IRDefinitionSurface=surface, Inputs=roles, Plans=normalized,
        WorkerChains=chains, Machines=machines, ReadFiles=len(buffers),
        ReadInputs=[dict(Path=str(p), Sha256=available[p], Bytes=len(buffers[p])) for p in sorted(buffers)],
        ControlBytes={str(p): buffers[p].hex() for p in sorted(control_paths)},
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    return require_result(proof, helpers)
