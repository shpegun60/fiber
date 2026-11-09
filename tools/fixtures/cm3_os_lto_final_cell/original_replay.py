"""Caller-admitted original Os bindings and six canonical roots, not a cell.

Only inspect constructs binary readers. Its temporary Path facade has no disk
fallback. require_result checks detached evidence and control bytes without I/O;
it is not an independent admission or a substitute for inspecting ELF bytes.
"""

import copy
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
import re
from types import SimpleNamespace
from unittest.mock import patch


STATUS = 'CM3-OS-LTO-ORIGINAL-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_ORIGINAL_BINDINGS_AND_SIX_CANONICAL_ROOTS_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
HELPERS = frozenset(('abi', 'link_helpers', 'binding_helpers', 'native_roots',
    'reference_roots', 'native_protocol', 'reference_protocol', 'decoder',
    'checker', 'os_join', 'join', 'guard'))
ROLE_NAMES = {
    'NativeOrdinary': ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Attributes', 'MachineAttributes'),
    'NativeEmitted': ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Attributes', 'MachineAttributes', 'MachineDisassembly'),
    'Reference': ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly'),
    'LoadImages': ('Native', 'Reference'), 'Ledgers': ('Master', 'Policy')}
CONTROL_NAMES = ('NativeReceipt', 'NativeManifest', 'ReferenceReceipt', 'ReferenceManifest',
    'NativeLoadImages', 'ReferenceLoadImages', 'MasterLedger', 'PolicyLedger')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'OrdinaryRootPreservationProven', 'HandlerRoutingProven', 'FinalReferenceParity',
    'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'MutantsReexecuted', 'ProducerCompilersReexecuted', 'SelectedReplacementBodiesIdentical',
    'CompleteCellProof', 'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'ArchiveQualification', 'HostedCIQualified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort',
    'SourceInventorySha256', 'Authorities', 'Inputs', 'NativeBindings', 'LoadImageComparisons',
    'TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales', 'ControlBytes', 'ReadInputs',
    'ReadFiles', 'LogicalRoles', 'UniqueEvidencePaths', 'ToolInvocations', 'CompilerInvocations',
    'RequiredCellsSatisfied', 'Nonclaims'))
POLICY_SHA256 = '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019'
NATIVE_ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
REFERENCE_ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
LINK_RECORD_FIELDS = frozenset(('EntireDirectoryArtifacts', 'FinalHeader', 'Kind', 'Machine',
    'MachineHeader', 'MachineOwner', 'MachineSections', 'MachineSha256', 'MachineSymbols', 'Map',
    'MapSha256', 'OrdinarySymbolPredicatesApplied', 'Path', 'Sha256', 'VerboseObservedTools'))


class Rejected(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-ORIGINAL:' + label)


def sha(raw):
    need(type(raw) is bytes, 'literal bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _keys(row, names, label):
    need(type(row) is dict and all(type(key) is str for key in row)
         and set(row) == set(names), 'closed ' + label)
    return row


def _same(actual, expected, label):
    need(type(actual) is type(expected), 'typed equality/' + label)
    if type(expected) is dict:
        _keys(actual, expected, label)
        for key in expected:
            _same(actual[key], expected[key], label + '/' + key)
    elif type(expected) in (list, tuple):
        need(len(actual) == len(expected), 'ordered length/' + label)
        for index, (left, right) in enumerate(zip(actual, expected)):
            _same(left, right, label + '/' + str(index))
    else:
        need(actual == expected, 'equality/' + label)


def _hash(value):
    need(type(value) is str and re.fullmatch(r'[A-F0-9]{64}', value) is not None, 'uppercase SHA256')
    return value


def _int(value, minimum=0, maximum=0xFFFFFFFF):
    need(type(value) is int and minimum <= value <= maximum, 'bounded literal integer')
    return value


def _str(value, *, empty=False):
    need(type(value) is str and (empty or bool(value)) and '\0' not in value, 'literal text')
    return value


def _hex(value, size=None):
    need(type(value) is str and len(value) % 2 == 0
         and re.fullmatch(r'[0-9a-f]*', value) is not None
         and (size is None or len(value) == 2 * size), 'lowercase byte hex')
    return bytes.fromhex(value)


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'path string or Path')
    text = str(value)
    need(re.match(r'^[A-Za-z]:[\\/]', text) is not None
         and not any(ord(c) < 32 or ord(c) == 127 for c in text), 'absolute drive path')
    parts = text[3:].replace('\\', '/').split('/')
    need(parts and all(part and part not in ('.', '..') and ':' not in part
         and part == part.rstrip(' .') for part in parts), 'canonical lexical path')
    return Path(text)


def _identity(path):
    return str(PureWindowsPath(str(_path(path)))).replace('\\', '/').casefold()


def _binding(path, digest):
    return dict(Path=str(_path(path)), Sha256=_hash(digest))


def _require_binding(row):
    _keys(row, ('Path', 'Sha256'), 'binding')
    need(type(row['Path']) is str, 'returned path is text')
    _same(row, _binding(row['Path'], row['Sha256']), 'canonical binding')
    return row


def _json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key/' + key)
            result[key] = value
        return result

    def finite(text):
        value = float(text)
        need(math.isfinite(value), 'finite JSON float')
        return value

    def constant(_):
        raise Rejected('REJECT:CM3-OS-LTO-ORIGINAL:nonfinite JSON constant')

    need(type(raw) is bytes, 'JSON bytes')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite)
    except (UnicodeError, ValueError, OverflowError, RecursionError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-ORIGINAL:strict finite JSON: ' + str(error)) from error


def _json_value(value):
    """Detach frozen token tuples at their two documented token-list fields."""
    result = copy.deepcopy(value)
    for side in ('Native', 'Reference'):
        for row in result['Roots'][side]:
            for key in ('RawCanonicalTokens', 'ProjectedCanonicalTokens'):
                if key in row:
                    tokens = row[key]
                    need(type(tokens) is list and all(type(token) is tuple and len(token) == 2
                         and all(type(item) is str for item in token) for token in tokens), 'frozen token tuple contract')
                    row[key] = [list(token) for token in tokens]
    return result


def _helpers(helpers):
    _keys(helpers, HELPERS, 'helper dictionary')
    calls = {'abi': ('inspect', 'require_result'), 'link_helpers': ('_header', '_attributes'),
        'binding_helpers': ('Bindings',), 'native_roots': ('NativeCM3LTOImage',),
        'reference_roots': ('ReferenceCM3LTOImage',), 'native_protocol': ('NativeProtocolView',),
        'reference_protocol': ('ReferenceProtocolView',), 'decoder': ('Object',),
        'checker': ('check_pair',), 'os_join': ('check_join',),
        'join': ('_proof', '_tokens', 'expected_mechanisms', '_difference_ids', 'require_ledger'),
        'guard': ('_same',)}
    for key, names in calls.items():
        need(all(callable(getattr(helpers[key], name, None)) for name in names), 'helper API/' + key)
    _same(tuple(helpers['os_join'].NATIVE_ROOTS), NATIVE_ROOTS, 'Os native catalog')
    _same(tuple(helpers['os_join'].REFERENCE_ROOTS), REFERENCE_ROOTS, 'Os reference catalog')
    _same(helpers['os_join'].COHORT, COHORT, 'Os cohort')


def _manifest(artifacts):
    need(type(artifacts) is dict and artifacts, 'artifact hash map')
    names = set()
    for name, digest in artifacts.items():
        need(type(name) is str and name and '\\' not in name and ':' not in name
             and all(part and part not in ('.', '..') and part == part.rstrip(' .')
                     for part in name.split('/')) and not any(ord(c) < 32 for c in name), 'relative artifact key')
        need(name.casefold() not in names, 'case-unique artifact key')
        names.add(name.casefold())
        _hash(digest)


def _capture_layout(root, result, artifacts, side):
    root = _path(root)
    need(type(result) is dict, 'capture receipt dictionary')
    for key, value in (('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('Cohort', COHORT)):
        _same(result.get(key), value, side + '/' + key)
    need(result.get('LTO') is True, 'capture literal LTO/' + side)
    _manifest(artifacts)

    def member(path, digest=None):
        path = _path(path)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-ORIGINAL:artifact escapes capture') from error
        need(relative in artifacts, 'capture artifact membership/' + relative)
        if digest is not None:
            _same(_hash(digest), artifacts[relative], 'capture hash/' + relative)
        return _binding(path, artifacts[relative])

    links = result.get('Links')
    need(type(links) is list and len(links) == 2, 'two captured links/' + side)
    sources = result.get('Sources')
    count = 9 if side == 'Native' else 4
    need(type(sources) is list and len(sources) == count and type(sources[-1]) is dict, 'source rows/' + side)
    startup = root / 'objects' / ('%02d-startup.o' % (count - 1))
    _same(str(_path(sources[-1].get('Object'))), str(startup), 'independently derived startup/' + side)
    startup_binding = member(startup, sources[-1].get('ObjectSha256'))
    rows = []
    for link, kind in zip(links, ('ordinary', 'emit-relocs')):
        _keys(link, LINK_RECORD_FIELDS, 'captured link/' + side + '/' + kind)
        _same(link['Kind'], kind, 'link kind')
        final, machine, link_map = root / kind / 'image.elf', root / kind / 'image.elf.ltrans0.ltrans.o', root / kind / 'image.map'
        for key, path in (('Path', final), ('Machine', machine), ('Map', link_map)):
            _same(str(_path(link[key])), str(path), 'fixed capture path/' + key)
        directory = link['EntireDirectoryArtifacts']
        need(type(directory) is dict and directory, 'captured directory artifact map')
        for name, digest in directory.items():
            need(type(name) is str and '/' not in name and '\\' not in name, 'single directory artifact name')
            member(root / kind / name, digest)
        row = dict(Machine=member(machine, link['MachineSha256']), Final=member(final, link['Sha256']),
            Disassembly=member(Path(str(final) + '.dis')), LinkMap=member(link_map, link['MapSha256']),
            Startup=copy.deepcopy(startup_binding))
        if side == 'Native':
            row.update(Attributes=member(Path(str(final) + '.readelf')),
                       MachineAttributes=member(Path(str(machine) + '.readelf')))
        if kind == 'emit-relocs':
            row['MachineDisassembly'] = member(Path(str(machine) + '.dis'))
        rows.append(row)
    load_path = root / 'load-image.json'
    _same(str(_path(result.get('TwinLoadImagesPath'))), str(load_path), 'capture load-image path')
    load = member(load_path, result.get('TwinLoadImagesSha256'))
    inventory = _keys(result.get('CurrentInventory'), ('Build', 'ReceiptSha256', 'ArtifactsSha256'), 'capture inventory')
    inventory_root = _path(inventory['Build'])
    _hash(inventory['ReceiptSha256'])
    _hash(inventory['ArtifactsSha256'])
    need(_identity(result.get('SourceInventoryReceipt')) == _identity(inventory_root), 'inventory receipt string path')
    source_hash = _hash(result.get('SourceInventorySha256'))
    master = inventory_root / 'inputs' / 'FREERTOS_ASM_PARITY.md'
    input_hashes = result.get('InputHashes')
    need(type(input_hashes) is dict, 'capture input hashes')
    matches = [digest for path, digest in input_hashes.items() if _identity(path) == _identity(master)]
    need(len(matches) == 1, 'unique captured master ledger authority')
    master_binding = _binding(master, matches[0])
    return rows, load, master_binding, copy.deepcopy(inventory), source_hash


def _layout(authorities, controls):
    _keys(authorities, ('Native', 'Reference'), 'authorities')
    parsed, layouts, loads, masters, inventories, hashes = {}, {}, {}, {}, {}, {}
    for side in ('Native', 'Reference'):
        authority = _keys(authorities[side], ('Root', 'Receipt', 'Manifest'), 'authority/' + side)
        need(type(authority['Root']) is str, 'returned authority root')
        root = _path(authority['Root'])
        for kind, filename in (('Receipt', 'results.json'), ('Manifest', 'artifacts.json')):
            binding = _require_binding(authority[kind])
            _same(binding['Path'], str(root / filename), 'fixed authority path')
            raw = controls[side + kind]
            _same(sha(raw), binding['Sha256'], 'authority control hash')
        parsed[side] = _json(controls[side + 'Receipt'])
        manifest = _keys(_json(controls[side + 'Manifest']), ('Artifacts',), 'artifact manifest')
        layouts[side], loads[side], masters[side], inventories[side], hashes[side] = _capture_layout(
            root, parsed[side], manifest['Artifacts'], side)
    need(_identity(authorities['Native']['Root']) != _identity(authorities['Reference']['Root']), 'distinct capture roots')
    _same(inventories['Native'], inventories['Reference'], 'same captured source inventory')
    _same(hashes['Native'], hashes['Reference'], 'same source inventory fingerprint')
    _same(masters['Native'], masters['Reference'], 'same master ledger binding')
    reference = layouts['Reference'][1]
    reference['Plain'] = layouts['Reference'][0]['Final']
    inputs = dict(NativeOrdinary=layouts['Native'][0], NativeEmitted=layouts['Native'][1],
        Reference=reference, LoadImages=loads, Ledgers=dict(Master=masters['Native'],
            Policy=_binding(Path(__file__).parents[1] / 'cm3_final_join' / 'POLICY_DIFFERENCES.md', POLICY_SHA256)))
    return inputs, parsed, hashes['Native']


def _input_rows(authorities, inputs):
    logical = []
    for side in ('Native', 'Reference'):
        logical.extend(authorities[side][key] for key in ('Receipt', 'Manifest'))
    _keys(inputs, ROLE_NAMES, 'input groups')
    for group, names in ROLE_NAMES.items():
        _keys(inputs[group], names, 'input roles/' + group)
        logical.extend(inputs[group][name] for name in names)
    need(len(logical) == 30, 'thirty logical rows')
    unique, identities = {}, {}
    shared = inputs['NativeOrdinary']['Startup']
    for row in logical:
        _require_binding(row)
        identity = _identity(row['Path'])
        if identity in identities:
            need(row is not None and row == shared and identities[identity] == shared, 'only native startup alias permitted')
            _same(row, identities[identity], 'literal shared startup binding')
        else:
            identities[identity] = row
        unique[row['Path']] = row['Sha256']
    need(len(identities) == len(unique) == 29, '29 canonical unique paths')
    _same(inputs['NativeOrdinary']['Startup'], inputs['NativeEmitted']['Startup'], 'native startup only alias')
    return unique


def _schema(value, spec, label='record'):
    if type(spec) is dict:
        _keys(value, spec, label)
        for key, child in spec.items():
            _schema(value[key], child, label + '/' + key)
    elif callable(spec):
        spec(value)
    else:
        _same(value, spec, label)


def _list(item, count=None):
    def check(value):
        need(type(value) is list and (count is None or len(value) == count), 'literal ordered list')
        for row in value:
            _schema(row, item)
    return check


def _enum(*values):
    def check(value):
        need(any(type(value) is type(expected) and value == expected for expected in values), 'closed enum')
    return check


def _positive(value):
    return _int(value, 1)


def _boolean(value):
    need(type(value) is bool, 'literal boolean')


def _word(value):
    return _hex(value, 4)


def _symbol(row):
    _schema(row, dict(name=lambda v: _str(v, empty=True), section=_positive, value=_int,
        size=_int, kind=_enum('STT_FUNC', 'STT_OBJECT', 'STT_SECTION'),
        binding=_enum('STB_LOCAL', 'STB_GLOBAL', 'STB_WEAK'), visibility='STV_DEFAULT', index=_int), 'raw symbol')


def _startup_symbol(row):
    if type(row) is dict and row.get('section') == 'SHN_UNDEF':
        _schema(row, dict(name=_enum('SVC_Handler', 'PendSV_Handler'), section='SHN_UNDEF',
            value=0, size=0, kind='STT_NOTYPE', binding='STB_GLOBAL', visibility='STV_DEFAULT',
            index=_positive), 'external startup handler symbol')
    else:
        _symbol(row)


def _instruction(row):
    _schema(row, dict(Mnemonic=_str, Operands=lambda v: _str(v, empty=True), Bytes=_hex), 'instruction')
    need(len(_hex(row['Bytes'])) in (2, 4), 'Thumb instruction width')


ORIGIN_FIELDS = ('Name', 'Original', 'Final', 'Provider', 'InputSection', 'InputSectionIndex',
    'SectionAddress', 'SectionSize', 'SymbolOffset', 'Size', 'Entry', 'OutputSection',
    'OutputSectionIndex', 'OutputSectionOffset', 'GeneratedMachineOriginBound', 'StartupOriginBound')


def _origin(row, roles):
    spec = dict.fromkeys(('Name', 'Provider', 'InputSection', 'OutputSection'), _str)
    spec.update(dict.fromkeys(('InputSectionIndex', 'OutputSectionIndex', 'SectionSize', 'Size'), _positive))
    spec.update(dict.fromkeys(('SectionAddress', 'SymbolOffset', 'Entry', 'OutputSectionOffset'), _int))
    spec.update(Original=_symbol, Final=_symbol, GeneratedMachineOriginBound=_boolean, StartupOriginBound=_boolean)
    _schema(row, spec, 'ABI origin')
    owners = {_identity(roles['Machine']['Path']): True, _identity(roles['Startup']['Path']): False}
    need(row['Provider'] in owners, 'ABI own canonical provider')
    generated = owners[row['Provider']]
    need(row['GeneratedMachineOriginBound'] is generated and row['StartupOriginBound'] is not generated, 'ABI origin role flags')
    before, after = row['Original'], row['Final']
    for key in ('name', 'kind', 'binding', 'visibility', 'size'):
        _same(before[key], after[key], 'ABI symbol preservation/' + key)
    _same(row['Name'], before['name'], 'ABI origin symbol name')
    for value, expected in ((row['Size'], before['size']), (row['InputSectionIndex'], before['section']),
            (row['OutputSectionIndex'], after['section'])):
        _same(value, expected, 'ABI origin symbol coordinate')
    mask = ~1 if before['kind'] == 'STT_FUNC' else 0xFFFFFFFF
    _same(row['SymbolOffset'], before['value'] & mask, 'original symbol offset')
    _same(row['Entry'], after['value'] & mask, 'final symbol entry')
    _same(row['Entry'], row['SectionAddress'] + row['SymbolOffset'], 'whole input-section placement')
    need(row['SymbolOffset'] + row['Size'] <= row['SectionSize'], 'complete ABI symbol extent')


ABI_NONCLAIMS = ('AllStartupVectorRelocationsAudited', 'OtherReverseConsumersAudited',
    'CallerBodySemanticsProven', 'CalleeRegisterPreservationProven', 'ControlFlowOrDominanceProven',
    'Qualification', 'TypedABIProof', 'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated',
    'InstructionEquivalence', 'PolicyEquivalence', 'FinalReferenceParity', 'CompleteObjectProof',
    'KernelRuntimeProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied')
LINK_NONCLAIMS = ('Qualification', 'FullABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated', 'InstructionEquivalence',
    'PolicyEquivalence', 'FinalReferenceParity', 'CompleteObjectProof', 'KernelRuntimeProof',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied')


def _require_abi(proof, roles, emitted, helpers):
    abi = helpers['abi']
    abi.require_result(proof, emit_relocs=emitted)
    _same(tuple(abi.NONCLAIMS), ABI_NONCLAIMS, 'frozen ABI nonclaim catalog')
    origin = lambda row: _origin(row, roles)
    optional_symbol = lambda row: _same(row, None, 'ordinary applied symbol') if not emitted else _symbol(row)
    applied = emitted
    counts = dict(MandatoryDefinitionCount=30, AdditionalConsumerCount=3, ForwardProviderCount=8,
        ReverseProviderCount=4, ReverseReferenceCount=5, ReverseBLReferences=4, TaskReturnABS32References=1,
        ColdAnchorReadCount=2, StartupVectorReferenceCount=3, OriginalBindingRelocations=10,
        AppliedBindingRelocations=10 if emitted else 0, RequiredCellsSatisfied=0)
    names = (*abi.PUBLIC, *abi.FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault', 'Reset_Handler',
        'fiber_panic', abi.ANCHOR, abi.PRIVATE, abi.STORAGE, abi.SLOT, *abi.EXPECTATIONS,
        'pilot_context_roots', 'pilot_vectors')
    mandatory_names = (*names, *abi.REVERSE)
    instruction_or_none = lambda row: _same(row, None, 'noninstruction') if row is None else _instruction(row)
    reference = dict(Consumer=_str, ConsumerOrigin=origin, Symbol=_str, Kind=_enum(2, 10),
        **dict.fromkeys(('InputSectionIndex', 'InputOffset', 'ConsumerOffset', 'OutputSectionIndex',
                       'OutputOffset', 'Place', 'ResolvedValue'), _int),
        Addend=lambda v: _int(v, -4), OriginalBytes=_word, FinalBytes=_word, TargetOrigin=origin,
        OriginalRelocationSymbol=_symbol, FinalRelocationSymbol=optional_symbol,
        FinalInstruction=instruction_or_none, AppliedRelocationMetadataChecked=applied)
    anchor_reference = dict(Consumer=_str, Symbol=abi.ANCHOR, Kind=2,
        **dict.fromkeys(('InputOffset', 'ConsumerOffset', 'OutputSectionIndex', 'OutputOffset', 'Place',
            'OriginalAddend', 'ByteDisplacement', 'ResolvedPointer', 'ResolvedByteAddress'), _int),
        OriginalBytes=_word, FinalBytes=_word,
        AddressForm=_enum('NAMED_ANCHOR', 'SECTION_BASE_PLUS_BYTE_DISPLACEMENT'),
        OriginalRelocationSymbol=_symbol, FinalRelocationSymbol=optional_symbol,
        OriginalTargetSection=_str, FinalTargetSection=_str, TargetOrigin=origin,
        AppliedRelocationMetadataChecked=applied)
    cold = dict(Function=_str, ConsumerOrigin=origin,
        **dict.fromkeys(('LoadOffset', 'ReadOffset', 'BaseRegister', 'DestinationRegister', 'ByteDisplacement'), _int),
        LoadInstruction=_instruction, ReadInstruction=_instruction, AnchorReference=anchor_reference,
        RetainedByteRead=True, StaticBaseRegisterBindingValidated=True,
        InterveningCallOffsets=_list(_int), AAPCSCalleeSavedRegisterAssumption=_boolean,
        CalleeRegisterPreservationProven=False, ControlFlowOrDominanceProven=False,
        OriginalBodySha256=_hash, FinalBodySha256=_hash)
    wide_call = dict(Offset=_int, Name=_str, TargetOrigin=origin, OriginalBytes=_word, FinalBytes=_word,
        FinalInstruction=_instruction, AAPCSCalleeSavedRegisterAssumption=True, CalleeRegisterPreservationProven=False)

    def cold_record(row):
        wide = type(row) is dict and 'InterveningCalls' in row
        spec = dict(cold)
        if wide:
            spec.update(InterveningCalls=_list(wide_call),
                EntryToAnchorInstructions=_list(dict(Offset=_int, Bytes=_hex, FinalInstruction=_instruction)),
                InitialCohortReadIsNotABIAnchorRead=True)
        _schema(row, spec, 'cold read')
        need(not wide or row['Function'] == abi.COLD[1], 'only context-init wide cold form')
        if wide:
            _same(row['InterveningCallOffsets'], [call['Offset'] for call in row['InterveningCalls']], 'wide call offsets')
            for call in row['InterveningCalls']:
                _same(call['Name'], call['TargetOrigin']['Name'], 'wide callee identity')
                _same(call['FinalInstruction']['Bytes'], call['FinalBytes'], 'wide BL bytes')
            offset = 0
            for instruction in row['EntryToAnchorInstructions']:
                _same(instruction['Offset'], offset, 'contiguous entry-to-anchor instructions')
                calls = [call for call in row['InterveningCalls'] if call['Offset'] == offset]
                need(len(calls) <= 1, 'unique entry live-range call')
                _same(instruction['FinalInstruction']['Bytes'], calls[0]['FinalBytes'] if calls else instruction['Bytes'],
                      'entry instruction final bytes')
                if calls:
                    _same(instruction['Bytes'], calls[0]['OriginalBytes'], 'entry instruction original call bytes')
                offset += len(_hex(instruction['Bytes']))
            _same(offset, row['ReadOffset'] + len(_hex(row['ReadInstruction']['Bytes'])), 'complete entry-to-anchor stream')
        _same(row['AAPCSCalleeSavedRegisterAssumption'], bool(row['InterveningCallOffsets']), 'cold call assumption')
        _same(row['Function'], row['ConsumerOrigin']['Name'], 'cold consumer identity')
        _same(row['Function'], row['AnchorReference']['Consumer'], 'anchor consumer identity')
        _same(row['ByteDisplacement'], row['AnchorReference']['ByteDisplacement'], 'cold displacement')
        _same(row['AnchorReference']['ResolvedPointer'] + row['ByteDisplacement'],
              row['AnchorReference']['ResolvedByteAddress'], 'cold resolved byte')

    placement = dict(Provider=_str, ProviderSha256=_hash, InputSection=_str, InputSectionIndex=_positive,
        SectionAddress=_int, SectionSize=_positive, OutputSection=_str, OutputSectionIndex=_positive, LinkMapSha256=_hash)
    vector_ref = dict(Symbol=_str, Offset=_int, Kind=2, Addend=0, Value=_int,
        OriginalRelocationSymbol=_startup_symbol, FinalRelocationSymbol=optional_symbol, OriginalBytes=_word, FinalBytes=_word,
        InputPlacement=placement, TargetOrigin=origin, AppliedRelocationMetadataChecked=applied)
    pointer = dict(Offset=_int, Kind=2, Name=_str, Addend=0, Value=_int,
        OriginalRelocationSymbol=_symbol, FinalRelocationSymbol=optional_symbol)
    table = dict(Name=_str, Provider=_str, OriginalSectionIndex=_positive, FinalSectionIndex=_positive,
        Address=_int, Size=_positive, OriginalBytes=_hex, FinalBytes=_hex, OriginalRelocationsValidated=True,
        AppliedRelocationsValidated=applied, Pointers=_list(pointer))
    vector = dict(Name='pilot_vectors', SectionIndex=_positive, Address=0, Words=256, InitialMsp=0x20010000,
        Entry=_int, Bytes=lambda value: _hex(value, 1024), StrongSlots=[1, 11, 14], ZeroSlots=[7, 8, 9, 10, 13],
        DefaultFaultEntries=247, OriginalVectorRelocationsAudited=False)
    attributes = lambda value: need(type(value) is dict and value
        and all(type(key) is str and key.startswith('Tag_') and type(item) is str for key, item in value.items()), 'attribute map')
    link_spec = dict(Status='CM3-OS-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_OS_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY', Profile='CM3', Mode='Os-lto', Linkage='direct',
        EmitRelocs=emitted, FinalLinkContractValidated=True,
        Headers=dict(Machine=dict(Type='ET_REL', Entry=_int, Flags=0x05000000),
                     Final=dict(Type='ET_EXEC', Entry=_int, Flags=0x05000200)),
        Attributes=dict(Machine=attributes, Final=attributes), Symbols=dict.fromkeys(names, origin),
        PointerTables=_list(table, 2), LinkMapSha256=roles['LinkMap']['Sha256'], Vectors=vector,
        OriginalPointerRelocations=7, AppliedPointerRelocations=7 if emitted else 0,
        RequiredCellsSatisfied=0, **dict.fromkeys(LINK_NONCLAIMS, False))
    spec = dict(Status=abi.STATUS, Scope=abi.SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        EmitRelocs=emitted, RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True,
        LinkContract=link_spec, MandatoryDefinitions=dict.fromkeys(mandatory_names, origin),
        AdditionalConsumerOrigins=_list(origin, 3), ForwardProviders=_list(origin, 8), ReverseProviders=_list(origin, 4),
        ReverseReferences=_list(reference, 5), ColdAnchorReads=_list(cold_record, 2), StartupVectors=_list(vector_ref, 3),
        AnchorDefinition=origin, MachineProvider=_identity(roles['Machine']['Path']),
        StartupProvider=_identity(roles['Startup']['Path']),
        MachineSha256=roles['Machine']['Sha256'], FinalSha256=roles['Final']['Sha256'],
        StartupSha256=roles['Startup']['Sha256'], LinkMapSha256=roles['LinkMap']['Sha256'],
        OriginalStartupVectorRelocationsAudited=True, **counts, **dict.fromkeys(ABI_NONCLAIMS, False))
    _schema(proof, spec, 'full ABI proof')
    definitions, link = proof['MandatoryDefinitions'], proof['LinkContract']
    for name, row in definitions.items():
        _same(row['Name'], name, 'mandatory definition identity')
        if name in ('SVC_Handler', 'PendSV_Handler'):
            for symbol in (row['Original'], row['Final']):
                _same((symbol['kind'], symbol['binding']), ('STT_FUNC', 'STB_GLOBAL'), 'strong handler definition')
        startup = name in ('Reset_Handler', 'pilot_vectors')
        _same(row['Provider'], proof['StartupProvider'] if startup else proof['MachineProvider'], 'mandatory owner/' + name)
        if name in link['Symbols']:
            _same(row, link['Symbols'][name], 'same link and ABI definition')
    for key, expected in (('ForwardProviders', abi.FORWARD), ('ReverseProviders', abi.REVERSE)):
        _same(proof[key], [definitions[name] for name in expected], 'ordered ' + key)
    _same(proof['AnchorDefinition'], definitions[abi.ANCHOR], 'same ABI anchor')
    consumers = {row['Name']: row for row in proof['AdditionalConsumerOrigins']}
    need(len(consumers) == 3, 'distinct additional ABI consumers')
    all_origins = dict(definitions, **consumers)
    for row in proof['ReverseReferences']:
        _same(row['ConsumerOrigin'], all_origins[row['Consumer']], 'reverse consumer extent')
        _same(row['TargetOrigin'], definitions[row['Symbol']], 'reverse target extent')
        _same(row['OriginalRelocationSymbol'], definitions[row['Symbol']]['Original'], 'original named reverse target')
        _same(row['FinalRelocationSymbol'], definitions[row['Symbol']]['Final'] if emitted else None, 'applied named reverse target')
        _same(row['Place'], row['ConsumerOrigin']['Entry'] + row['ConsumerOffset'], 'reverse place')
        _same(row['InputOffset'], row['ConsumerOrigin']['SymbolOffset'] + row['ConsumerOffset'], 'reverse input offset')
        if row['Kind'] == 10:
            need(row['FinalInstruction'] is not None, 'BL instruction evidence')
            _same(row['FinalInstruction']['Bytes'], row['FinalBytes'], 'reverse instruction bytes')
        else:
            _same(row['FinalInstruction'], None, 'ABS32 is not an instruction')
    for row in proof['ColdAnchorReads']:
        _same(row['ConsumerOrigin'], definitions[row['Function']], 'cold function extent')
        _same(row['AnchorReference']['TargetOrigin'], proof['AnchorDefinition'], 'cold target anchor')
    for row, (offset, name) in zip(proof['StartupVectors'], abi.VECTORS):
        _same(row['Offset'], offset, 'selected vector offset')
        _same(row['Symbol'], name, 'selected vector symbol')
        _same(row['OriginalBytes'], '00000000', 'zero original vector addend')
        _same(row['TargetOrigin'], definitions[name], 'vector target')
        _same(row['InputPlacement']['Provider'], proof['StartupProvider'], 'vector startup provider')
        _same(row['InputPlacement']['ProviderSha256'], proof['StartupSha256'], 'vector startup bytes')
        _same(row['InputPlacement']['LinkMapSha256'], proof['LinkMapSha256'], 'vector map')
        for field in ('InputSection', 'InputSectionIndex', 'SectionAddress', 'SectionSize',
                      'OutputSection', 'OutputSectionIndex'):
            _same(row['InputPlacement'][field], definitions['pilot_vectors'][field], 'vector input placement/' + field)
        if name in ('SVC_Handler', 'PendSV_Handler'):
            symbol = row['OriginalRelocationSymbol']
            _startup_symbol(symbol)
            _same((symbol['name'], symbol['section']), (name, 'SHN_UNDEF'), 'external startup vector target')
        else:
            _same(row['OriginalRelocationSymbol'], definitions[name]['Original'], 'vector original named target')
        _same(row['FinalRelocationSymbol'], definitions[name]['Final'] if emitted else None, 'vector applied named target')
        _same(row['Value'], definitions[name]['Final']['value'], 'vector final value')
        _same(int.from_bytes(_word(row['FinalBytes']), 'little'), row['Value'], 'vector final bytes')
    for row, targets, name in zip(link['PointerTables'], ((abi.STORAGE, abi.PRIVATE), abi.PUBLIC),
                                  (abi.EXPECTATION_SECTION, '.pilot_roots')):
        _same(row['Name'], name, 'pointer table identity')
        _same(row['Provider'], proof['MachineProvider'], 'pointer table provider')
        _same(row['Size'], 4 * len(targets), 'complete pointer table size')
        _same(_hex(row['OriginalBytes']), bytes(row['Size']), 'zero original pointer addends')
        final_bytes = _hex(row['FinalBytes'], row['Size'])
        need(len(row['Pointers']) == len(targets), 'pointer membership')
        for index, (pointer_row, target) in enumerate(zip(row['Pointers'], targets)):
            _same(pointer_row['Offset'], 4 * index, 'ordered pointer offset')
            _same(pointer_row['Name'], target, 'pointer target name')
            _same(pointer_row['Value'], definitions[target]['Final']['value'], 'pointer resolved value')
            _same(int.from_bytes(final_bytes[4 * index:4 * index + 4], 'little'), pointer_row['Value'], 'pointer final bytes')
            _same(pointer_row['OriginalRelocationSymbol'], definitions[target]['Original'], 'original pointer target')
            _same(pointer_row['FinalRelocationSymbol'], definitions[target]['Final'] if emitted else None, 'applied pointer target')
    for text in link['Attributes'].values():
        reparsed = helpers['link_helpers']._attributes('\n'.join(key + ': ' + value for key, value in text.items()))
        _same(reparsed, text, 'closed soft attributes')
    _same(link['Vectors']['Entry'], link['Headers']['Final']['Entry'], 'vector and ELF entry')
    _same(link['Vectors']['SectionIndex'], definitions['pilot_vectors']['OutputSectionIndex'], 'vector section')
    words = [definitions['pilot_fault']['Final']['value']] * 256
    words[0] = 0x20010000
    for index in (7, 8, 9, 10, 13):
        words[index] = 0
    for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
        words[index] = definitions[name]['Final']['value']
    _same(_hex(link['Vectors']['Bytes']), b''.join(word.to_bytes(4, 'little') for word in words), 'whole vector template')


TRANSPORT_NONCLAIMS = ('OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated', 'FinalReferenceParity',
    'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
TRANSPORT_ORIGIN_NONCLAIMS = ('OriginalTranslationUnitOwnership', 'CalleeBodyProof', 'CalleeRelocationSemanticsChecked')


def _transport_origin(row, roles):
    spec = dict(Name=_str, Provider=_identity(roles['Machine']['Path']), ProviderSha256=roles['Machine']['Sha256'],
        InputSection=_str, InputSectionIndex=_positive, SectionAddress=_int, SectionSize=_positive,
        SymbolOffset=_int, Size=_positive, Entry=_int, OutputSection=_str, OutputSectionIndex=_positive,
        OutputSectionOffset=_int, LinkMapSha256=roles['LinkMap']['Sha256'], GeneratedMachineOriginBound=True,
        **dict.fromkeys(TRANSPORT_ORIGIN_NONCLAIMS, False))
    _schema(row, spec, 'transport origin')
    need(row['SymbolOffset'] + row['Size'] <= row['SectionSize'], 'complete transport origin extent')
    _same(row['Entry'], row['SectionAddress'] + row['SymbolOffset'], 'transport whole-section placement')


def _transport_reference(row):
    _schema(row, dict(Offset=_int, Kind=_enum(2, 10), Symbol=_str, Addend=lambda v: _int(v, -4),
        Place=_int, ResolvedValue=_int, OriginalBytes=_word, Bytes=_word,
        OriginalRelocationSymbol=_symbol, FinalRelocationSymbol=_symbol,
        Binding=_enum('STB_LOCAL', 'STB_GLOBAL'), OriginalTargetSection=_str, FinalTargetSection=_str), 'transport reference')


def _require_transport(row, side, name, roles, helpers):
    origin = lambda value: _transport_origin(value, roles)
    spec = dict(Name=name, Address=_int, Size=_positive, BodySha256=_hash, MachineBodySha256=_hash,
        InstructionCount=_positive, Instructions=_list(dict(Offset=_int, Bytes=_hex, Mnemonic=_str,
            Operands=lambda value: _str(value, empty=True))),
        MappedData=_list(dict(Offset=_int, Bytes=_hex)), References=_list(_transport_reference),
        RootOrigin=origin, DefinitionOrigins=_list(origin), GeneratedMachineBoundRootPreservation=True,
        RequiredCellsSatisfied=0, **dict.fromkeys(TRANSPORT_NONCLAIMS, False))
    if side == 'Reference':
        spec['FullABIProof'] = False
    _schema(row, spec, 'unchanged complete transport/' + name)
    adapter = helpers['native_roots'] if side == 'Native' else helpers['reference_roots']
    size, count, references = adapter.ROOTS[name]
    _same(row['Size'], size, 'fixed transport extent')
    _same(row['InstructionCount'], count, 'fixed transport instruction count')
    need(len(row['Instructions']) == count and len(row['References']) == references and row['MappedData'], 'complete transport rows')
    root = row['RootOrigin']
    _same(root['Name'], name, 'root origin name')
    _same(root['Entry'], row['Address'], 'root entry')
    _same(root['Size'], row['Size'], 'root extent')
    body, covered = bytearray(size), set()
    previous = -1
    for instruction in row['Instructions']:
        offset, raw = instruction['Offset'], _hex(instruction['Bytes'])
        need(len(raw) in (2, 4) and offset % 2 == 0 and offset > previous, 'ordered Thumb instructions')
        previous = offset
        need(offset + len(raw) <= size and not covered.intersection(range(offset, offset + len(raw))), 'bounded disjoint instructions')
        body[offset:offset + len(raw)] = raw
        covered.update(range(offset, offset + len(raw)))
    previous = -1
    for data in row['MappedData']:
        offset, raw = data['Offset'], _hex(data['Bytes'])
        need(raw and offset > previous and offset + len(raw) <= size
             and not covered.intersection(range(offset, offset + len(raw))), 'ordered disjoint mapped data')
        previous = offset
        body[offset:offset + len(raw)] = raw
        covered.update(range(offset, offset + len(raw)))
    _same(covered, set(range(size)), 'whole transport byte coverage')
    _same(sha(bytes(body)), row['BodySha256'], 'whole applied root hash')
    targets = sorted({reference['Symbol'] for reference in row['References']})
    _same([definition['Name'] for definition in row['DefinitionOrigins']], targets, 'ordered unique transport dependencies')
    definitions = {definition['Name']: definition for definition in row['DefinitionOrigins']}
    sites = adapter.REFERENCE_SITES[name] if side == 'Native' else adapter.SITES[name]
    _same([reference['Offset'] for reference in row['References']], sorted(sites), 'fixed reference sites')
    patched = set()
    for reference in row['References']:
        offset = reference['Offset']
        _same((reference['Kind'], reference['Symbol']), tuple(sites[offset]), 'fixed reference role')
        need(offset + 4 <= size and not patched.intersection(range(offset, offset + 4)), 'disjoint whole root REL fields')
        _same(reference['Place'], row['Address'] + offset, 'root REL place')
        _same(bytes(body[offset:offset + 4]), _word(reference['Bytes']), 'applied root REL bytes')
        body[offset:offset + 4] = _word(reference['OriginalBytes'])
        patched.update(range(offset, offset + 4))
        target = definitions[reference['Symbol']]
        _same(reference['ResolvedValue'], target['Entry'], 'root target entry')
        _same(reference['OriginalTargetSection'], target['InputSection'], 'original target section')
        _same(reference['FinalTargetSection'], target['OutputSection'], 'final target section')
        _same(reference['OriginalRelocationSymbol']['binding'], reference['Binding'], 'original binding')
        _same(reference['FinalRelocationSymbol']['binding'], reference['Binding'], 'final binding')
        _same(reference['OriginalRelocationSymbol']['section'], target['InputSectionIndex'], 'original target section index')
        _same(reference['FinalRelocationSymbol']['section'], target['OutputSectionIndex'], 'final target section index')
        if reference['Kind'] == 10:
            _same(reference['Addend'], -4, 'BL original minus-four addend')
            for symbol, offset_value in ((reference['OriginalRelocationSymbol'], target['SymbolOffset']),
                                        (reference['FinalRelocationSymbol'], target['Entry'])):
                _same(symbol['name'], reference['Symbol'], 'named BL target')
                _same(symbol['kind'], 'STT_FUNC', 'BL function kind')
                _same(symbol['size'], target['Size'], 'BL target extent')
                _same(symbol['value'], offset_value | 1, 'BL Thumb symbol entry')
        else:
            _same(reference['Addend'], 0, 'slot original zero addend')
            _same(reference['OriginalBytes'], '00000000', 'zero original slot literal')
            _same(int.from_bytes(_word(reference['Bytes']), 'little'), target['Entry'], 'mapped slot literal')
    _same(sha(bytes(body)), row['MachineBodySha256'], 'whole unapplied root hash')


def _require_load(row):
    _schema(row, dict(Identical=True, Entry=_int, VectorAddress=_int, VectorBytes=_hex,
        Segments=_list(dict(Vaddr=_int, Paddr=_int, FileSize=_int, MemorySize=_int, Flags=_int,
            Align=_positive, BytesSha256=_hash))), 'load-image comparison')
    need(row['Segments'] and _hex(row['VectorBytes']), 'nonempty load image and vector')
    for segment in row['Segments']:
        need(segment['FileSize'] <= segment['MemorySize'] and segment['Vaddr'] + segment['MemorySize'] <= 1 << 32,
             'bounded load comparison extent')


def _tokens(tokens):
    need(type(tokens) is list and tokens and all(type(token) is list and len(token) == 2
         and all(type(item) is str for item in token) for token in tokens), 'JSON canonical token pairs')
    islands = [token for token in tokens if token[0] == '@literal-island']
    need(len(islands) == 1, 'one complete canonical literal island')
    for _, text in islands:
        descriptor = _json(text.encode('ascii'))
        _schema(descriptor, dict(Offset=_int, Bytes=_hex,
            References=_list(dict(Instruction=_int, Offset=_int)),
            Relocations=_list(dict(Offset=_int, Kind=2, Target=_str))), 'canonical literal island')
    return [tuple(token) for token in tokens]


JOIN_NONCLAIMS = ('Qualification', 'FinalReferenceParity', 'FullABIProof', 'FinalElfProof', 'SourceIRProof',
    'SourceToIRSemanticProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'InstructionEquivalence', 'PolicyEquivalence', 'CompleteObjectProof', 'KernelRuntimeProof', 'HandlerRoutingProven',
    'ProducerCompilersReexecuted', 'MutantsReexecuted', 'CpuExecution', 'BoardExecution',
    'GlobalFreezeQualified', 'RequiredCellSatisfied')
PROTOCOL_NONCLAIMS = ('RequiredCellSatisfied', 'CompleteObjectProof', 'InstructionEquivalence', 'CpuExecution',
    'FinalElfProof', 'GlobalFreezeQualified')


def _require_join(proof, transports, inputs, controls, helpers):
    frozen = helpers['join']
    mechanisms, identities = frozen.expected_mechanisms(), frozen._difference_ids()
    root_match = dict(Side=_enum('Native', 'Reference'), Name=_str, Tokens=_positive, LiteralIslands=1,
        TailNops=0, BodySha256=_hash)
    protocol = dict(Verdict='CM3-CLOSED-ROOTS-PASS', Roots=list(NATIVE_ROOTS), ClosedBodies=6,
        DifferenceIds=identities, Mechanisms=mechanisms, RootEvidence=_list(root_match, 6),
        ProofScope='CM3_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY',
        DifferenceSource=dict(Spec='tools/freertos_asm_parity.ps1:Assert-Cm3Mechanisms', Ledger='FREERTOS_ASM_PARITY.md'),
        ReferenceSvcObligation=dict(StartRoot=REFERENCE_ROOTS[0], RestoreRoot=REFERENCE_ROOTS[1],
            FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
        **dict.fromkeys(PROTOCOL_NONCLAIMS, False))
    schema = dict(Status='CM3-OS-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED',
        Scope='CM3_OS_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY', Profile='CM3', Mode='Os-lto', Cohort=COHORT,
        Linkage='direct', LTO=True, ClosedBodies=6, Mechanisms=mechanisms, DifferenceIds=identities,
        ProtocolProof=protocol, Roots=lambda value: _keys(value, ('Native', 'Reference'), 'canonical root groups'),
        RawTransportRoots=transports, OriginalTransportRecordsUnmodified=True,
        DifferenceRationales=lambda value: _keys(value, identities, 'master rationales'),
        LedgerSha256=inputs['Ledgers']['Master']['Sha256'],
        MachineSha256=dict(Native=inputs['NativeEmitted']['Machine']['Sha256'], Reference=inputs['Reference']['Machine']['Sha256']),
        FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR', ReferenceCoreSlots=8,
            ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False), CanonicalProtocolValidated=True,
        NativeCommandsExecuted=0, RequiredCellsSatisfied=0, **dict.fromkeys(JOIN_NONCLAIMS, False))
    _schema(proof, schema, 'closed Os canonical join')
    frozen._proof(proof['ProtocolProof'])
    views = {}
    for side, names, role_group in (('Native', NATIVE_ROOTS, 'NativeEmitted'), ('Reference', REFERENCE_ROOTS, 'Reference')):
        rows = proof['Roots'][side]
        need(type(rows) is list and len(rows) == 3, 'three canonical evidence rows/' + side)
        evidence = {}
        for row, name, transport in zip(rows, names, transports[side]):
            spec = dict(Name=name, MachineBodySha256=transport['MachineBodySha256'], FinalBodySha256=transport['BodySha256'],
                MachineProviderSha256=inputs[role_group]['Machine']['Sha256'], RawCanonicalTokens=_tokens,
                RawTokenSha256=_hash, ProjectionEvidence=_list(dict(Kind='PROVED_SECTION_TO_LOGICAL_SLOT_ROLE_ONLY',
                    LoadToken=_int, IslandToken=_int, Reference=_transport_reference,
                    Origin=lambda value: _transport_origin(value, inputs[role_group]))),
                HashDomains=copy.deepcopy(frozen.HASH_DOMAINS), TransportRecord=transport)
            if side == 'Native':
                spec.update(ProjectedCanonicalTokens=_tokens, ProjectedTokenSha256=_hash)
            _schema(row, spec, 'closed canonical root/' + name)
            raw = _tokens(row['RawCanonicalTokens'])
            _same(row['RawTokenSha256'], frozen._tokens(raw, name), 'raw canonical token hash')
            if side == 'Native':
                canonical = _tokens(row['ProjectedCanonicalTokens'])
                _same(row['ProjectedTokenSha256'], frozen._tokens(canonical, name), 'projected canonical token hash')
                expected = copy.deepcopy(row['RawCanonicalTokens'])
                projections = row['ProjectionEvidence']
                need(len(projections) == (0 if name == names[0] else 1), 'exact native semantic projection count')
                for projection in projections:
                    slot_references = [reference for reference in transport['References'] if reference['Kind'] == 2]
                    need(len(slot_references) == 1, 'unique projected native slot')
                    _same(projection['Reference'], slot_references[0], 'projection unchanged raw reference')
                    origins = [origin for origin in transport['DefinitionOrigins'] if origin['Name'] == slot_references[0]['Symbol']]
                    need(len(origins) == 1, 'unique projected native slot origin')
                    _same(projection['Origin'], origins[0], 'projection unchanged raw origin')
                    load, island = projection['LoadToken'], projection['IslandToken']
                    need(load < len(expected) and island < len(expected), 'bounded projection indices')
                    register = 'r0' if name == 'SVC_Handler' else 'r1'
                    section, slot = helpers['native_protocol'].SECTION, helpers['native_protocol'].SLOT
                    _same(expected[load], ['ldr', register + ',=' + section + '+0'], 'raw slot load token')
                    expected[load] = ['ldr', register + ',=' + slot + '+0']
                    _same(expected[island][0], '@literal-island', 'projection literal island token')
                    descriptor = _json(expected[island][1].encode('ascii'))
                    need(len(descriptor['Relocations']) == 1 and descriptor['Relocations'][0]['Target'] == section,
                         'one raw section slot relocation')
                    descriptor['Relocations'][0]['Target'] = slot
                    expected[island][1] = json.dumps(descriptor, sort_keys=True, separators=(',', ':'))
                _same(row['ProjectedCanonicalTokens'], expected, 'only proved native slot token projection')
            else:
                canonical = raw
                _same(row['ProjectionEvidence'], [], 'reference has no semantic projection')
            need(len(canonical) == transport['InstructionCount'] + 1, 'complete canonical body and literal island')
            evidence[name] = canonical

        def function(name, *, literal_islands=False, evidence=evidence):
            need(literal_islands is True and name in evidence, 'closed token-view request')
            return copy.deepcopy(evidence[name])
        views[side] = SimpleNamespace(function=function)
    regenerated = helpers['checker'].check_pair(views['Native'], views['Reference'])
    _same(proof['ProtocolProof'], regenerated, 'complete unchanged checker over reported tokens')
    master = controls['MasterLedger'].decode('ascii')
    policy = controls['PolicyLedger'].decode('ascii')
    _same(proof['DifferenceRationales'], frozen.require_ledger(master, regenerated), 'captured master rationale bytes')
    return frozen.require_ledger(policy, regenerated)


def _control_bindings(authorities, inputs):
    result = {}
    for side in ('Native', 'Reference'):
        for kind in ('Receipt', 'Manifest'):
            result[side + kind] = authorities[side][kind]
        result[side + 'LoadImages'] = inputs['LoadImages'][side]
    result['MasterLedger'] = inputs['Ledgers']['Master']
    result['PolicyLedger'] = inputs['Ledgers']['Policy']
    return result


def _parsed_image(image, roles, buffers):
    machine, final, startup = (_path(roles[name]['Path']) for name in ('Machine', 'Final', 'Startup'))
    need(type(image.prelink.data) is bytes and image.prelink.data == buffers[machine]
         and image.prelink.final is False and type(image.final.data) is bytes
         and image.final.data == buffers[final] and image.final.final is True, 'constructor exact own image bytes')
    need(type(image.providers) is dict and set(image.providers) == {_identity(machine), _identity(startup)},
         'constructor exact provider roles')
    for path in (machine, startup):
        provider = image.providers[_identity(path)]
        need(provider.final is False and type(provider.data) is bytes and provider.data == buffers[path],
             'constructor own admitted provider bytes')
    _same(image.link_map_hash, roles['LinkMap']['Sha256'], 'constructor admitted map bytes')
    need(type(image.hashes) is dict, 'constructor input hashes')
    for key, role in (('PrelinkSha256', 'Machine'), ('FinalSha256', 'Final'), ('DisassemblySha256', 'Disassembly')):
        _same(image.hashes.get(key), roles[role]['Sha256'], 'constructor binding/' + key)


def inspect(core, read, native, reference, helpers, *, roles, ledgers):
    """Replay admitted originals; no helper loading, physical discovery or tools.

    Role/ledger leaves are exact Path-string/Sha256 dictionaries. Capture
    descriptors are comparison targets; reread authority bytes derive every
    role independently before any binary constructor can see them.
    """
    _helpers(helpers)
    need(callable(read) and callable(getattr(core, 'FinalImage', None))
         and callable(getattr(core, 'compare_load_images', None)), 'explicit reader/core interfaces')
    authorities, controls, buffers = {}, {}, {}

    def consume(path, digest):
        path, digest = _path(path), _hash(digest)
        if path not in buffers:
            raw = read(path, digest)
            need(type(raw) is bytes and sha(raw) == digest, 'immutable byte/hash binding/' + str(path))
            buffers[path] = raw
        else:
            _same(sha(buffers[path]), digest, 'same-path reader hash')
        return buffers[path]

    for side, descriptor in (('Native', native), ('Reference', reference)):
        _keys(descriptor, ('Root', 'Result', 'Artifacts', 'ReceiptSha256', 'ManifestSha256'), 'capture descriptor/' + side)
        root = _path(descriptor['Root'])
        authority = dict(Root=str(root), Receipt=_binding(root / 'results.json', descriptor['ReceiptSha256']),
                         Manifest=_binding(root / 'artifacts.json', descriptor['ManifestSha256']))
        authorities[side] = authority
        for kind, comparison in (('Receipt', descriptor['Result']), ('Manifest', dict(Artifacts=descriptor['Artifacts']))):
            binding = authority[kind]
            controls[side + kind] = consume(binding['Path'], binding['Sha256'])
            parsed = _json(controls[side + kind])
            _same(parsed, comparison, 'reread descriptor/' + side + '/' + kind)
            helpers['guard']._same(parsed, comparison, 'original capture descriptor/' + side + '/' + kind)
    inputs, captures, source_hash = _layout(authorities, controls)
    _keys(roles, ('NativeOrdinary', 'NativeEmitted', 'Reference', 'LoadImages'), 'caller role groups')
    _keys(ledgers, ('Master', 'Policy'), 'caller ledger roles')
    caller_inputs = dict(roles, Ledgers=ledgers)
    for group, names in ROLE_NAMES.items():
        _keys(caller_inputs[group], names, 'caller role group/' + group)
        for name in names:
            _require_binding(caller_inputs[group][name])
    _same(caller_inputs, inputs, 'independently derived original roles and ledger authorities')
    unique = _input_rows(authorities, inputs)
    for path, digest in unique.items():
        consume(path, digest)
    for name, binding in _control_bindings(authorities, inputs).items():
        controls[name] = buffers[_path(binding['Path'])]
    comparisons = {}
    for side in ('Native', 'Reference'):
        captured = _json(controls[side + 'LoadImages'])
        _require_load(captured)
        _same(captured, captures[side].get('TwinLoadImages'), 'saved load-image record/' + side)

    def buffered(path):
        path = _path(path)
        need(path in buffers, 'binary constructor read escapes admitted roles/' + str(path))
        return buffers[path]

    def text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None,
             'strict buffer-only text decoding')
        return buffered(path).decode(encoding or 'utf-8')

    bindings = {}
    with patch.object(Path, 'read_bytes', buffered), patch.object(Path, 'read_text', text):
        for kind, group, emitted in (('Ordinary', 'NativeOrdinary', False), ('Emitted', 'NativeEmitted', True)):
            row = inputs[group]
            machine, final, startup, disassembly, link_map = (_path(row[name]['Path'])
                for name in ('Machine', 'Final', 'Startup', 'Disassembly', 'LinkMap'))
            image = core.FinalImage(machine, final, disassembly,
                provider_objects={str(machine): machine, str(startup): startup}, link_map=link_map, float_abi='soft')
            _parsed_image(image, row, buffers)
            proof = helpers['abi'].inspect(image, core, helpers['link_helpers'], helpers['binding_helpers'],
                buffered(_path(row['Attributes']['Path'])).decode('ascii'), emit_relocs=emitted,
                machine_attributes_text=buffered(_path(row['MachineAttributes']['Path'])).decode('ascii'))
            _require_abi(proof, row, emitted, helpers)
            bindings[kind] = copy.deepcopy(proof)
        for side, plain, emitted in (('Native', inputs['NativeOrdinary']['Final'], inputs['NativeEmitted']['Final']),
                                     ('Reference', inputs['Reference']['Plain'], inputs['Reference']['Final'])):
            comparison = core.compare_load_images(_path(plain['Path']), _path(emitted['Path']))
            _require_load(comparison)
            _same(comparison, _json(controls[side + 'LoadImages']), 'recomputed own load-image twins/' + side)
            comparisons[side] = copy.deepcopy(comparison)
        views = {}
        for side, group, adapter, protocol in (
                ('Native', 'NativeEmitted', helpers['native_roots'].NativeCM3LTOImage,
                 helpers['native_protocol'].NativeProtocolView),
                ('Reference', 'Reference', helpers['reference_roots'].ReferenceCM3LTOImage,
                 helpers['reference_protocol'].ReferenceProtocolView)):
            row = inputs[group]
            machine, final, startup, disassembly, link_map, machine_dump = (_path(row[name]['Path']) for name in
                ('Machine', 'Final', 'Startup', 'Disassembly', 'LinkMap', 'MachineDisassembly'))
            transport = adapter(core, machine, final, disassembly,
                provider_objects={str(machine): machine, str(startup): startup}, link_map=link_map)
            _parsed_image(transport.image, row, buffers)
            decoded = helpers['decoder'].Object(machine, machine_dump)
            need(type(decoded.data) is bytes and decoded.data == buffers[machine], 'decoder exact own whole machine/' + side)
            views[side] = protocol(decoded, transport)
        joined = helpers['os_join'].check_join(views['Native'], views['Reference'], helpers['checker'],
            controls['MasterLedger'].decode('ascii'), helpers['join'])
    joined = _json_value(joined)
    transports = copy.deepcopy(joined['RawTransportRoots'])
    policy_rationales = helpers['join'].require_ledger(controls['PolicyLedger'].decode('ascii'), joined['ProtocolProof'])
    result = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=source_hash, Authorities=authorities, Inputs=inputs,
        NativeBindings=bindings, LoadImageComparisons=comparisons, TransportRoots=transports,
        CanonicalJoin=joined, PolicyDifferenceRationales=policy_rationales,
        ControlBytes={name: controls[name].hex() for name in CONTROL_NAMES},
        ReadInputs=[dict(Path=str(path), Sha256=sha(raw), Bytes=len(raw)) for path, raw in sorted(buffers.items())],
        ReadFiles=29, LogicalRoles=30, UniqueEvidencePaths=25, ToolInvocations=0, CompilerInvocations=0,
        RequiredCellsSatisfied=0, Nonclaims=dict.fromkeys(NONCLAIMS, False))
    return require_result(result, helpers)


def require_result(proof, helpers):
    """I/O-free closed report checks, not renewed capture or ELF admission."""
    _helpers(helpers)
    _keys(proof, FIELDS, 'original replay result')
    for key, expected in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
            ('Linkage', 'direct'), ('LTO', True), ('Cohort', COHORT), ('ReadFiles', 29), ('LogicalRoles', 30),
            ('UniqueEvidencePaths', 25), ('ToolInvocations', 0), ('CompilerInvocations', 0), ('RequiredCellsSatisfied', 0)):
        _same(proof[key], expected, 'result/' + key)
    _same(proof['Nonclaims'], dict.fromkeys(NONCLAIMS, False), 'closed all-false original nonclaims')
    _keys(proof['ControlBytes'], CONTROL_NAMES, 'eight control buffers')
    controls = {name: _hex(proof['ControlBytes'][name]) for name in CONTROL_NAMES}
    inputs, captures, source_hash = _layout(proof['Authorities'], controls)
    _same(proof['SourceInventorySha256'], source_hash, 'original source inventory fingerprint')
    _same(proof['Inputs'], inputs, 'original authority-derived role reconstruction')
    unique = _input_rows(proof['Authorities'], inputs)
    rows = proof['ReadInputs']
    need(type(rows) is list and len(rows) == 29, '29 unique consumed byte rows')
    reported = {}
    for row in rows:
        _keys(row, ('Path', 'Sha256', 'Bytes'), 'read inventory row')
        need(type(row['Path']) is str and row['Path'] not in reported, 'unique reported input path')
        _same(row['Path'], str(_path(row['Path'])), 'canonical read path')
        reported[row['Path']] = _hash(row['Sha256'])
        _int(row['Bytes'])
        need(row['Bytes'] > 0, 'original evidence inputs are nonempty')
    _same(reported, unique, 'exact authority and evidence read membership/hashes')
    _same([row['Path'] for row in rows], [str(path) for path in sorted(_path(path) for path in unique)], 'sorted unique read inventory')
    sizes = {row['Path']: row['Bytes'] for row in rows}
    for name, binding in _control_bindings(proof['Authorities'], inputs).items():
        _same(sha(controls[name]), binding['Sha256'], 'control buffer hash/' + name)
        _same(len(controls[name]), sizes[binding['Path']], 'control buffer byte count/' + name)
    _keys(proof['NativeBindings'], ('Ordinary', 'Emitted'), 'native binding twins')
    _require_abi(proof['NativeBindings']['Ordinary'], inputs['NativeOrdinary'], False, helpers)
    _require_abi(proof['NativeBindings']['Emitted'], inputs['NativeEmitted'], True, helpers)
    _keys(proof['LoadImageComparisons'], ('Native', 'Reference'), 'load-image twin comparisons')
    for side in ('Native', 'Reference'):
        _require_load(proof['LoadImageComparisons'][side])
        _same(proof['LoadImageComparisons'][side], _json(controls[side + 'LoadImages']), 'actual saved twin load-image JSON')
        _same(proof['LoadImageComparisons'][side], captures[side].get('TwinLoadImages'), 'same capture twin record')
    _keys(proof['TransportRoots'], ('Native', 'Reference'), 'transport side groups')
    for side, names, group in (('Native', NATIVE_ROOTS, 'NativeEmitted'), ('Reference', REFERENCE_ROOTS, 'Reference')):
        roots = proof['TransportRoots'][side]
        need(type(roots) is list and len(roots) == 3, 'three original transport roots/' + side)
        for row, name in zip(roots, names):
            _require_transport(row, side, name, inputs[group], helpers)
    rationales = _require_join(proof['CanonicalJoin'], proof['TransportRoots'], inputs, controls, helpers)
    _same(proof['PolicyDifferenceRationales'], rationales, 'fixed policy ledger rationales')
    native_vectors = proof['NativeBindings']['Ordinary']['LinkContract']['Vectors']
    for kind in ('Ordinary', 'Emitted'):
        _same(proof['NativeBindings'][kind]['LinkContract']['Vectors']['Bytes'],
              proof['LoadImageComparisons']['Native']['VectorBytes'], 'ABI/captured native vector bytes')
        _same(proof['NativeBindings'][kind]['LinkContract']['Vectors']['Address'],
              proof['LoadImageComparisons']['Native']['VectorAddress'], 'ABI/captured native vector address')
    _same(native_vectors['Entry'], proof['LoadImageComparisons']['Native']['Entry'], 'ABI/captured native entry')
    return proof
