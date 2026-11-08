"""Pure caller-admitted original/isolated Os slot composition.

The caller authenticates the core and both supplied slot modules. Only the Os
predicate runs; the neutral module supplies its frozen encoding machinery.
Result checking binds returned evidence, never substitutes for recomputation.
"""

import copy
import hashlib
import json
from pathlib import Path
import re
from unittest.mock import patch


STATUS = 'CM3-OS-LTO-ISOLATION-SLOTS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_ORIGINAL_AND_ISOLATED_EMITTED_SLOT_PROTOCOLS_ONLY'
ROLES = ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine',
    'OriginalAssembly', 'OriginalDisassembly', 'OriginalMap',
    'IsolatedOrdinaryELF', 'IsolatedOrdinaryMap', 'IsolatedEmitELF',
    'IsolatedMachine', 'IsolatedAssembly', 'IsolatedMap', 'IsolatedDisassembly',
    'StartupObject', 'PortSource', 'IsolatedIR0', 'IsolatedIR1', 'IsolatedIR2')
KINDS = ('Original', 'Isolated')
SLOT_STATUS = 'CM3-OS-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED'
SLOT_SCOPE = 'NATIVE_CM3_OS_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY'
SLOT = 'fiber_internal_runtime_current_context_slot'
PUBLISHER = 'fiber_internal_runtime_publish_current_context'
BODIES = ('fiber_internal_runtime_load_current_context',
    'fiber_internal_runtime_context_configuration_is_open',
    'fiber_internal_runtime_select_scheduler_candidate', PUBLISHER,
    'fiber_internal_runtime_require_current_context', 'ctxrt_v1_set_dispatcher')
SIZES = (16, 48, 80, 32, 32, 64)
REFERENCE_COUNTS = (2, 5, 6, 4, 4, 7)
SLOT_FALSE = ('CommonSourceOwnershipValidated', 'CompleteHandlerBodiesValidated',
    'ArbitraryPointerAliasProof', 'WholeProgramMemorySafetyProof',
    'FullSemanticABIProof', 'FullABIProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'Qualification', 'CellContractSatisfied',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied')
NONCLAIMS = SLOT_FALSE + ('IRImportClosureValidated', 'RawIRIdentityClaim',
    'LoadImageComparisonsReplayed', 'FinalRootTransferProtocolsValidated',
    'FullHandlerProtocolsValidated', 'CompilerExecuted', 'ProducerCompilersReexecuted')
FACTS = ('SlotProofsReplayed', 'CallerOwnsAdmissionAndImmutableScope',
    'CallerOwnsHelperAuthentication')
COUNTS = dict(InputRoles=18, SlotImages=2, ReadFiles=19, RequiredCellsSatisfied=0)
FIELDS = frozenset(NONCLAIMS + FACTS) | frozenset(COUNTS) | frozenset((
    'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Inputs', 'OriginalDump', 'SlotProofs', 'ReadInputs'))
SLOT_FIELDS = frozenset(SLOT_FALSE) | frozenset(('Status', 'Scope', 'Profile',
    'Mode', 'Linkage', 'EmitRelocs', 'SlotIsolationValidated', 'SlotOrigin',
    'SlotAlias', 'SourceSha256', 'AssemblySha256', 'MachineSha256', 'FinalSha256',
    'LinkMapSha256', 'HandlerLoadPairs', 'HandlerLoads', 'SourcePairs',
    'GeneratedPairs', 'ClosedCommonBodies', 'CommonBodies', 'CommonBytes',
    'CommonLoads', 'CommonStores', 'Publisher', 'SlotReferences',
    'AppliedSlotReferences', 'RawSectionSymbolsPreserved',
    'AllSectionMediatedSlotReferencesValidated', 'RequiredCellsSatisfied'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-ISOLATION-SLOTS:' + detail)


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


def _identity(path):
    return str(path).replace('\\', '/').casefold()


def _roles(roles):
    need(type(roles) is dict and set(roles) == set(ROLES), 'exact eighteen role names')
    paths, hashes = {}, {}
    for name in ROLES:
        row = roles[name]
        need(type(row) is dict and set(row) == {'Role', 'Path', 'Sha256'}
             and type(row['Role']) is str and row['Role'] == name
             and type(row['Path']) is str, 'exact typed role/' + name)
        path = _path(row['Path'])
        need(path not in hashes, 'distinct role paths/' + name)
        paths[name], hashes[path] = path, _hash(row['Sha256'])
    return paths, hashes


def _reference(ref, owner):
    need(type(ref) is dict and ref.get('Owner') == owner, 'own slot reference')
    need(type(ref.get('Kind')) is int and ref['Kind'] in (2, 10, 30), 'typed slot reference kind')
    for key in ('FunctionOffset', 'InputSectionIndex', 'InputOffset', 'Address'):
        need(type(ref.get(key)) is int and 0 <= ref[key] <= 0xFFFFFFFF, 'reference coordinate/' + key)
    need(type(ref.get('Target')) is str and ref['Target'], 'named reference target')
    for key in ('OriginalBytes', 'FinalBytes'):
        need(type(ref.get(key)) is str and re.fullmatch('[0-9a-f]{8}', ref[key]), 'reference bytes/' + key)
    for key in ('OriginalRelocationSymbol', 'FinalRelocationSymbol'):
        symbol = ref.get(key)
        need(type(symbol) is dict and set(symbol) == {'name', 'value', 'size', 'kind', 'binding',
             'section', 'visibility', 'index'}, 'complete raw reference symbol/' + key)
        for field in ('value', 'size', 'section', 'index'):
            need(type(symbol[field]) is int and symbol[field] >= 0, 'raw symbol coordinate/' + field)
        for field in ('name', 'kind', 'binding', 'visibility'):
            need(type(symbol[field]) is str, 'raw symbol text/' + field)


def _proof(proof, kind, paths, hashes):
    need(type(proof) is dict and set(proof) == SLOT_FIELDS, 'closed Os slot result/' + kind)
    for key, value in (('Status', SLOT_STATUS), ('Scope', SLOT_SCOPE),
            ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('Publisher', PUBLISHER)):
        need(type(proof[key]) is str and proof[key] == value, 'Os slot identity/' + key)
    for key, value in (('ClosedCommonBodies', 6), ('CommonBytes', 272),
            ('HandlerLoadPairs', 2), ('CommonLoads', 5), ('CommonStores', 1),
            ('SlotReferences', 8), ('AppliedSlotReferences', 8), ('RequiredCellsSatisfied', 0)):
        need(type(proof[key]) is int and proof[key] == value, 'Os slot count/' + key)
    for key in ('EmitRelocs', 'SlotIsolationValidated', 'RawSectionSymbolsPreserved',
                'AllSectionMediatedSlotReferencesValidated'):
        need(proof[key] is True, 'Os slot fact/' + key)
    for key in SLOT_FALSE:
        need(proof[key] is False, 'Os slot nonclaim/' + key)
    for key, role in (('SourceSha256', 'PortSource'), ('AssemblySha256', kind + 'Assembly'),
            ('MachineSha256', kind + 'Machine'), ('FinalSha256', kind + 'EmitELF'),
            ('LinkMapSha256', kind + 'Map')):
        need(_hash(proof[key]) == hashes[paths[role]], 'Os slot input binding/' + kind + '/' + key)
    slot = proof['SlotOrigin']
    need(type(slot) is dict and slot.get('Name') == SLOT
         and slot.get('Provider') == _identity(paths[kind + 'Machine']), 'explicit slot provider/' + kind)
    for key, value in (('Size', 4), ('SectionSize', 4), ('SymbolOffset', 0)):
        need(type(slot.get(key)) is int and slot[key] == value, 'slot extent/' + key)
    need(type(proof['SlotAlias']) is str and re.fullmatch(r'\.LANCHOR[0-9]+', proof['SlotAlias']), 'slot alias')
    bodies = proof['CommonBodies']
    need(type(bodies) is list and len(bodies) == 6, 'six complete common bodies')
    for row, name, size, count in zip(bodies, BODIES, SIZES, REFERENCE_COUNTS):
        need(type(row) is dict and row.get('Name') == name and row.get('CompleteBodyValidated') is True
             and type(row.get('Size')) is int and row['Size'] == size
             and type(row.get('TailNops')) is int and row['TailNops'] == 0, 'complete common body/' + name)
        origin = row.get('Origin')
        need(type(origin) is dict and origin.get('Name') == name
             and origin.get('Provider') == slot['Provider'], 'bound common provider/' + name)
        for key in ('MachineBodySha256', 'FinalBodySha256'):
            _hash(row.get(key))
        refs = row.get('References')
        need(type(refs) is list and len(refs) == count
             and all(type(ref) is dict and ref.get('Owner') == name for ref in refs), 'own common references/' + name)
        for ref in refs:
            _reference(ref, name)
        need(sum(ref['Target'] == SLOT and ref['Kind'] == 2 for ref in refs) == 1,
             'one common slot reference/' + name)
    handlers = proof['HandlerLoads']
    need(type(handlers) is list and len(handlers) == 2, 'two handler loads')
    for row, name, register in zip(handlers, ('SVC_Handler', 'PendSV_Handler'), ('r0', 'r1')):
        need(type(row) is dict and row.get('Owner') == name and row.get('Register') == register
             and type(row.get('Kind')) is int and row['Kind'] == 2 and row.get('Target') == SLOT,
             'own handler slot load/' + name)
        _reference(row, name)
        for key, value in (('MachineLiteralLoads', 1), ('FinalLiteralLoads', 1), ('SlotBearingWordsCensused', 8)):
            need(type(row.get(key)) is int and row[key] == value, 'handler load count/' + key)
        need(type(row.get('LoadOffset')) is int and row['LoadOffset'] >= 0
             and type(row.get('DereferenceOffset')) is int
             and row['DereferenceOffset'] == row['LoadOffset'] + 2, 'immediate handler dereference')
        for key in ('BothInstructionStreamsCensused', 'UnsupportedPCAddressFormsRejected', 'CrossOwnerSlotLiteralUsesRejected'):
            need(row.get(key) is True, 'bounded handler census/' + key)
    for key in ('SourcePairs', 'GeneratedPairs'):
        need(type(proof[key]) is list and len(proof[key]) == 2
             and all(type(row) is dict for row in proof[key]), 'two inline pairs/' + key)
    need({row.get('Register') for row in proof['SourcePairs']} == {'r0', 'r1'}, 'two source register pairs')
    for row in proof['SourcePairs']:
        need(set(row) == {'Register', 'SourceLine'} and type(row['SourceLine']) is int
             and row['SourceLine'] > 0, 'typed source pair line')
    for row, owner, register in zip(proof['GeneratedPairs'], ('SVC_Handler', 'PendSV_Handler'), ('r0', 'r1')):
        need(set(row) == {'Owner', 'Register', 'GeneratedLine'} and row['Owner'] == owner
             and row['Register'] == register and type(row['GeneratedLine']) is int
             and row['GeneratedLine'] > 0, 'typed generated pair')


def inspect(core, read, roles, os_slot, neutral_slot, *, original_dump):
    """Use the caller-bound fresh original dump, not its producer spelling."""
    need(callable(read) and callable(getattr(core, 'FinalImage', None)), 'explicit reader/core')
    need(callable(getattr(os_slot, 'inspect', None)) and callable(getattr(os_slot, 'require_result', None)), 'explicit Os slot API')
    paths, hashes = _roles(roles)
    inputs = copy.deepcopy(roles)
    buffers = {}
    for name in ROLES:
        path = paths[name]
        raw = read(path, hashes[path])
        need(sha(raw) == hashes[path], 'immutable reader bytes/' + name)
        buffers[path] = raw
    need(type(original_dump) is tuple and len(original_dump) == 2
         and isinstance(original_dump[0], Path) and type(original_dump[1]) is bytes
         and original_dump[1], 'explicit fresh original dump pair')
    dump_path, dump_raw = _path(original_dump[0]), original_dump[1]
    need(dump_path not in buffers, 'distinct fresh original dump path')
    dump_hash = sha(dump_raw)
    bound_dump = read(dump_path, dump_hash)
    need(sha(bound_dump) == dump_hash and bound_dump == dump_raw, 'immutable fresh original dump bytes')
    buffers[dump_path] = dump_raw

    def read_bytes(path):
        path = _path(path)
        need(path in buffers, 'constructor read outside local role buffers/' + str(path))
        return buffers[path]

    def read_text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict')
             and newline is None, 'bounded strict text decode')
        return read_bytes(path).decode(encoding or 'utf-8')

    proofs = {}
    with patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
        for kind in KINDS:
            machine, final = paths[kind + 'Machine'], paths[kind + 'EmitELF']
            disassembly = dump_path if kind == 'Original' else paths[kind + 'Disassembly']
            link_map = paths[kind + 'Map']
            startup = paths['StartupObject']
            image = core.FinalImage(machine, final, disassembly,
                provider_objects={str(machine): machine, str(startup): startup},
                link_map=link_map, float_abi='soft')
            need(type(image.prelink.data) is bytes and image.prelink.data == buffers[machine]
                 and image.prelink.final is False and type(image.final.data) is bytes
                 and image.final.data == buffers[final] and image.final.final is True,
                 'exact parsed image bytes/' + kind)
            need(type(image.providers) is dict and set(image.providers) == {_identity(machine), _identity(startup)}
                 and all(type(image.providers[_identity(path)].data) is bytes
                    and image.providers[_identity(path)].data == buffers[path]
                    and image.providers[_identity(path)].final is False for path in (machine, startup)),
                 'exact explicit provider bytes/' + kind)
            need(image.link_map_hash == hashes[link_map] and type(image.hashes) is dict
                 and image.hashes.get('PrelinkSha256') == hashes[machine]
                 and image.hashes.get('FinalSha256') == hashes[final]
                 and image.hashes.get('DisassemblySha256') == sha(buffers[disassembly]), 'parsed image input hashes/' + kind)
            proof = os_slot.inspect(image, core, neutral_slot, port_source=buffers[paths['PortSource']],
                assembly=buffers[paths[kind + 'Assembly']], emit_relocs=True)
            os_slot.require_result(proof, emit_relocs=True)
            _proof(proof, kind, paths, hashes)
            proofs[kind] = copy.deepcopy(proof)
    result = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        LTO=True, Inputs=inputs, OriginalDump=dict(Path=str(dump_path), Sha256=dump_hash), SlotProofs=proofs,
        ReadInputs=[dict(Path=str(path), Sha256=sha(raw)) for path, raw in sorted(buffers.items())],
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    return require_result(result)


def require_result(result):
    """Check closed returned bindings; this does not rerun the slot predicate."""
    need(type(result) is dict and set(result) == FIELDS, 'closed adapter result')
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct')):
        need(type(result[key]) is str and result[key] == value, 'adapter identity/' + key)
    need(result['LTO'] is True, 'literal Os LTO')
    for key, value in COUNTS.items():
        need(type(result[key]) is int and result[key] == value, 'adapter count/' + key)
    for key in FACTS:
        need(result[key] is True, 'adapter fact/' + key)
    for key in NONCLAIMS:
        need(result[key] is False, 'adapter nonclaim/' + key)
    paths, hashes = _roles(result['Inputs'])
    dump = result['OriginalDump']
    need(type(dump) is dict and set(dump) == {'Path', 'Sha256'} and type(dump['Path']) is str,
         'typed fresh original dump binding')
    dump_path = _path(dump['Path'])
    need(dump_path not in hashes, 'distinct original dump binding')
    hashes[dump_path] = _hash(dump['Sha256'])
    reads = result['ReadInputs']
    need(type(reads) is list and len(reads) == 19, 'complete read bindings')
    actual = {}
    for row in reads:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'} and type(row['Path']) is str, 'typed read binding')
        path = _path(row['Path'])
        need(path not in actual, 'duplicate read binding')
        actual[path] = _hash(row['Sha256'])
    need(actual == hashes, 'exact input/read hash correspondence')
    need(type(result['SlotProofs']) is dict and set(result['SlotProofs']) == set(KINDS), 'two complete Os proofs')
    for kind in KINDS:
        _proof(result['SlotProofs'][kind], kind, paths, hashes)
    return result
