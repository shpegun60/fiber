"""Native CM3 LTO canonical composition over independently preserved roots.

No files, imports of selected helpers, tools, targets or reference-side substitute.
Raw ELF records remain unchanged; only two proved slot roles are projected.
"""
import copy
import hashlib
import json
import struct

ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
SLOT = 'fiber_internal_runtime_current_context_slot'
SECTION = '.bss.fiber_runtime_current_context_slot'
SITES = {'SVC_Handler': (180, 104, 'r0'), 'PendSV_Handler': (200, 40, 'r1')}


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-LTO-PROTOCOL:' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def tokens_sha(tokens):
    return sha(json.dumps(tokens, separators=(',', ':'), ensure_ascii=True).encode('ascii'))


def integers(row, keys):
    return type(row) is dict and all(type(row.get(key)) is int for key in keys)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate descriptor key')
        result[key] = value
    return result


class NativeProtocolView:
    def __init__(self, decoded_machine, transport_image):
        need(type(decoded_machine.data) is bytes and decoded_machine.data == transport_image.machine.data,
             'canonical decoder must consume the exact preserved machine bytes')
        self.decoded, self.transport = decoded_machine, transport_image
        self.machine_sha = sha(decoded_machine.data)
        self.evidence = {}

    def _record(self, name):
        record = self.transport.function(name)
        need(record['Name'] == name and record['GeneratedMachineBoundRootPreservation'] is True
             and record['CanonicalProtocolValidated'] is False, 'unchanged complete transport record required')
        definitions = [row for row in self.decoded.symbols if row['name'] == name and row['section'] != 0]
        need(len(definitions) == 1, 'unique decoded root definition')
        symbol = definitions[0]
        need(integers(symbol, ('section', 'info', 'size', 'value'))
             and integers(record, ('Size', 'InstructionCount')) and symbol['section'] > 0 and symbol['info'] == 0x12
             and type(symbol['size']) is int and symbol['size'] == record['Size']
             and symbol['value'] & 1 == 1, 'decoded root metadata differs')
        origin = record['RootOrigin']
        need(integers(origin, ('InputSectionIndex', 'SymbolOffset', 'Size'))
             and origin['GeneratedMachineOriginBound'] is True and origin['Name'] == name
             and origin['ProviderSha256'] == self.machine_sha and origin['InputSectionIndex'] == symbol['section']
             and origin['SymbolOffset'] == symbol['value'] & ~1 and origin['Size'] == symbol['size'],
             'decoded root differs from preserved machine origin')
        body = self.decoded.read(symbol['section'], symbol['value'] & ~1, symbol['size'])
        need(len(body) == symbol['size'] and sha(body) == record['MachineBodySha256'], 'machine root body hash mismatch')
        return record, symbol

    def _slot(self, name, record):
        references = [row for row in record['References'] if row['Kind'] == 2]
        if name not in SITES:
            need(not references, 'first-start must not project a slot')
            return None
        offset, instruction, register = SITES[name]
        need(len(references) == 1, 'exactly one proved slot reference per handler')
        reference = references[0]
        need(integers(reference, ('Offset', 'Kind', 'Addend', 'ResolvedValue'))
             and reference['Offset'] == offset and reference['Symbol'] == SLOT and reference['Addend'] == 0
             and reference['OriginalBytes'] == '00000000' and reference['OriginalTargetSection'] == SECTION
             and reference['FinalTargetSection'] == '.bss' and reference['Binding'] == 'STB_LOCAL',
             'only exact proved slot role can project')
        origins = [row for row in record['DefinitionOrigins'] if row['Name'] == SLOT]
        need(len(origins) == 1, 'unique slot origin required')
        origin = origins[0]
        need(integers(origin, ('Size', 'SectionSize', 'SymbolOffset', 'Entry', 'InputSectionIndex',
                              'OutputSectionIndex', 'OutputSectionOffset'))
             and origin['GeneratedMachineOriginBound'] is True and origin['ProviderSha256'] == self.machine_sha
             and origin['InputSection'] == SECTION and origin['OutputSection'] == '.bss'
             and origin['Size'] == origin['SectionSize'] == 4 and origin['SymbolOffset'] == 0
             and origin['Entry'] == reference['ResolvedValue'] and type(origin['Entry']) is int
             and 0 <= origin['Entry'] < 1 << 32 and origin['Entry'] % 4 == 0
             and reference['Bytes'] == struct.pack('<I', origin['Entry']).hex(), 'mapped slot extent/value binding')
        for key, section, value in (('OriginalRelocationSymbol', origin['InputSectionIndex'], 0),
                                  ('FinalRelocationSymbol', origin['OutputSectionIndex'],
                                   origin['Entry'] - origin['OutputSectionOffset'])):
            target = reference[key]
            need(integers(target, ('section', 'size', 'value'))
                 and target['name'] == '' and target['kind'] == 'STT_SECTION' and target['binding'] == 'STB_LOCAL'
                 and target['visibility'] == 'STV_DEFAULT' and target['size'] == 0
                 and target['section'] == section and target['value'] == value, 'raw section target must remain unnormalized')
        return reference, origin, instruction, register

    def function(self, name, *, literal_islands=False):
        need(name in ROOTS and literal_islands is True, 'three exact roots and complete literal islands required')
        record, symbol = self._record(name)
        raw = self.decoded.function(name, literal_islands=True)
        need(type(raw) is list and raw and all(type(row) is tuple and len(row) == 2
             and all(type(item) is str for item in row) for row in raw), 'complete canonical token list required')
        projected, projection = copy.deepcopy(raw), []
        slot = self._slot(name, record)
        if slot:
            reference, origin, instruction, register = slot
            operand = (register + ',=' + SECTION + '+0')
            loads = [index for index, row in enumerate(raw) if row == ('ldr', operand)]
            islands = [(index, json.loads(value, object_pairs_hook=unique)) for index, (op, value) in enumerate(raw)
                       if op == '@literal-island']
            need(len(loads) == len(islands) == 1, 'exact slot LDR and literal descriptor projection required')
            index, descriptor = islands[0]
            need(set(descriptor) == {'Offset', 'Bytes', 'References', 'Relocations'}, 'complete literal descriptor shape')
            need(integers(descriptor, ('Offset',))
                 and type(descriptor['References']) is list and type(descriptor['Relocations']) is list
                 and all(integers(row, ('Instruction', 'Offset')) for row in descriptor['References'])
                 and all(integers(row, ('Offset', 'Kind')) for row in descriptor['Relocations']), 'typed literal descriptor fields')
            relative = reference['Offset'] - descriptor['Offset']
            need(relative in (0, 2) and descriptor['References'] == [dict(Instruction=instruction, Offset=relative)]
                 and descriptor['Relocations'] == [dict(Offset=relative, Kind=2, Target=SECTION)],
                 'descriptor must name the exact proved slot relocation and LDR')
            data = bytes.fromhex(descriptor['Bytes'])
            need(len(data) == relative + 4 and data == bytes(len(data)) and
                 self.decoded.read(symbol['section'], (symbol['value'] & ~1) + descriptor['Offset'], len(data)) == data,
                 'complete original slot island bytes required')
            projected[loads[0]] = ('ldr', register + ',=' + SLOT + '+0')
            semantic = copy.deepcopy(descriptor)
            semantic['Relocations'][0]['Target'] = SLOT
            projected[index] = ('@literal-island', json.dumps(semantic, sort_keys=True, separators=(',', ':')))
            projection = [dict(Kind='PROVED_SECTION_TO_LOGICAL_SLOT_ROLE_ONLY', LoadToken=loads[0], IslandToken=index,
                               Reference=copy.deepcopy(reference), Origin=copy.deepcopy(origin))]
        need(sum(SECTION in value for _, value in raw) == (2 if slot else 0)
             and all(SECTION not in value for _, value in projected), 'no missing or extra semantic slot projection')
        self.evidence[name] = dict(Name=name, MachineBodySha256=record['MachineBodySha256'],
            FinalBodySha256=record['BodySha256'], MachineProviderSha256=self.machine_sha,
            RawCanonicalTokens=copy.deepcopy(raw), ProjectedCanonicalTokens=copy.deepcopy(projected),
            RawTokenSha256=tokens_sha(raw), ProjectedTokenSha256=tokens_sha(projected), ProjectionEvidence=projection,
            HashDomains=dict(MachineRoot='SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES',
                            FinalRoot='SHA256-APPLIED-FINAL-FUNCTION-BYTES', Canonical='SHA256-JSON-TOKENS'),
            TransportRecord=copy.deepcopy(record))
        return projected


def check_native(decoded_machine, transport_image, checker):
    need(tuple(checker._NATIVE) == ROOTS, 'exact frozen three-native-root checker required')
    view = NativeProtocolView(decoded_machine, transport_image)
    matched = [checker._match(view, 'Native', name, checker._NATIVE[name]) for name in ROOTS]
    need(len(matched) == 3 and all(type(row['TailNops']) is int and row['TailNops'] == 0 for row in matched),
         'O2-lto requires zero tail NOPs on every root')
    return dict(Status='NATIVE-CANONICAL-PASS-NOT-REFERENCE-QUALIFIED',
        Scope='NATIVE_CM3_O2_LTO_THREE_CANONICAL_PROTOCOLS_ONLY', CanonicalProtocolValidated=True,
        ClosedBodies=3, MatchEvidence=matched, Roots=[view.evidence[name] for name in ROOTS],
        OriginalTransportRecordsUnmodified=True, SourceToMachineSemanticProof=False,
        FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False, CompleteObjectProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
