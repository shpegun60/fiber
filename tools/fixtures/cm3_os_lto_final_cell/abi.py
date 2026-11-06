"""Pure Os-specific CM3 direct-link surface and selected runtime bindings.

The caller authenticates Os recipes, image bytes and both supplied helpers.
Only mode-neutral link predicates and the unchanged Bindings class are reused;
neither O2 entry point is called. Unsupported cold-read forms reject, rather
than silently omitting an obligation. This is not a typed/full ABI or cell proof.
"""

import hashlib
import re
import struct


PUBLIC = ('ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_set_dispatcher',
          'ctxrt_v1_start', 'ctxrt_v1_yield')
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier',
           'fiber_port_panic_wait', 'fiber_port_require_scheduler_configuration_environment',
           'fiber_port_runtime_prepare_start', 'fiber_port_runtime_select_first',
           'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
SLOT = 'fiber_internal_runtime_current_context_slot'
PRIVATE = ('fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_'
           'u00010000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
STORAGE = 'fiber_port_storage_cohort_arm_cm3_v1_r0'
EXPECTATION_SECTION = '.fiber_port_context_cohort_expectation'
EXPECTATIONS = ('fiber_port_storage_cohort_consumer_expectation',
                'fiber_port_context_cohort_build_expectation')
SLOT_SECTION = '.bss.fiber_runtime_current_context_slot'
REVERSE = ('fiber_internal_runtime_select_scheduler_candidate',
           'fiber_internal_runtime_publish_current_context',
           'fiber_internal_runtime_require_current_context', 'fiber_internal_task_return')
REFERENCES = (('fiber_port_runtime_schedule', 10, REVERSE[2]),
              ('fiber_port_scheduler_pick_first_from_start', 10, REVERSE[0]),
              ('fiber_port_scheduler_pick_next_from_pendsv', 10, REVERSE[0]),
              ('fiber_port_scheduler_pick_next_from_pendsv', 10, REVERSE[1]),
              ('fiber_port_init_context_frame', 2, REVERSE[3]))
COLD = ('fiber_port_runtime_prepare_start', 'fiber_port_context_init')
VECTORS = ((4, 'Reset_Handler'), (44, 'SVC_Handler'), (56, 'PendSV_Handler'))
STATUS = 'CM3-OS-LTO-ABI-BINDINGS-PASS-NOT-QUALIFIED'
SCOPE = 'NATIVE_CM3_OS_LTO_DIRECT_LINK_AND_SELECTED_RUNTIME_BINDINGS_ONLY'
NONCLAIMS = ('AllStartupVectorRelocationsAudited', 'OtherReverseConsumersAudited',
    'CallerBodySemanticsProven', 'CalleeRegisterPreservationProven', 'ControlFlowOrDominanceProven',
    'Qualification', 'TypedABIProof', 'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated',
    'InstructionEquivalence', 'PolicyEquivalence', 'FinalReferenceParity', 'CompleteObjectProof',
    'KernelRuntimeProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-ABI:' + message)


def _helpers(link, binding):
    for name in ('PUBLIC', 'FORWARD', 'ANCHOR', 'SLOT', 'PRIVATE', 'STORAGE',
                 'EXPECTATION_SECTION', 'EXPECTATIONS', 'SLOT_SECTION'):
        need(getattr(link, name, None) == globals()[name], 'fixed link helper contract: ' + name)
    for name in ('FORWARD', 'REVERSE', 'REFERENCES', 'COLD', 'VECTORS', 'ANCHOR'):
        need(getattr(binding, name, None) == globals()[name], 'fixed binding helper contract: ' + name)
    need(all(callable(getattr(link, name, None)) for name in
             ('_header', '_attributes', '_surface', '_bound', '_readonly', '_table', '_section'))
         and callable(getattr(binding, 'Bindings', None)), 'explicit pure helper interfaces')


def _link_contract(image, link, attributes_text, emitted, machine_attributes_text):
    machine, final = image.prelink, image.final
    headers = dict(Machine=link._header(machine, False), Final=link._header(final, True))
    attributes = dict(Machine=link._attributes(machine_attributes_text),
                      Final=link._attributes(attributes_text))
    need(type(image.providers) is dict and len(image.providers) == 2
         and type(image.placements) is dict, 'exact generated-machine/startup provider pair')
    need(type(image.link_map_hash) is str and re.fullmatch(r'[A-F0-9]{64}', image.link_map_hash),
         'authenticated link-map SHA256')
    owners = []
    for identity, provider in image.providers.items():
        need(type(identity) is str and identity, 'literal provider identity')
        link._header(provider, False)
        if provider.data == machine.data:
            owners.append(identity)
    need(len(owners) == 1, 'unique actual generated-machine provider')
    machine_owner = owners[0]
    startup_owner = next(identity for identity in image.providers if identity != machine_owner)
    link._surface(machine)
    link._surface(final)
    need(emitted or not final.relocations, 'ordinary twin must not contain applied REL metadata')

    class Inputs:
        pass

    model = Inputs()
    model.prelink, model.final = machine, final
    model.providers, model.placements = image.providers, image.placements
    model._contract_machine_owner = machine_owner
    definitions = {}
    for name in (*PUBLIC, *FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault'):
        definitions[name] = link._bound(model, name, 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    definitions['Reset_Handler'] = link._bound(model, 'Reset_Handler', 'STT_FUNC', ('STB_GLOBAL',), startup_owner)
    definitions['fiber_panic'] = link._bound(model, 'fiber_panic', 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    for name in (ANCHOR, PRIVATE, STORAGE):
        allowed = ('STB_LOCAL',) if name == ANCHOR else ('STB_GLOBAL',)
        definitions[name] = link._bound(model, name, 'STT_OBJECT', allowed, machine_owner, 1)
        need(link._readonly(model, definitions[name], 1) == (b'\x01', b'\x01'), 'one-byte ABI/cohort identity')
    definitions[SLOT] = link._bound(model, SLOT, 'STT_OBJECT', ('STB_LOCAL',), machine_owner, 4)
    slot = definitions[SLOT]
    need(slot['InputSection'] == SLOT_SECTION and slot['SectionSize'] == 4 and slot['SymbolOffset'] == 0
         and slot['OutputSection'] == '.bss' and slot['Entry'] % 4 == 0, 'dedicated mapped four-byte BSS slot')
    for elf, row in ((machine, slot['Original']), (final, slot['Final'])):
        header = elf.sections[row['section']].header
        need(header.sh_type == 'SHT_NOBITS' and header.sh_flags & 7 == 3 and row['value'] % 4 == 0,
             'zero-fill slot storage')
    for index, name in enumerate(EXPECTATIONS):
        definitions[name] = link._bound(model, name, 'STT_OBJECT', ('STB_LOCAL', 'STB_GLOBAL'), machine_owner, 4)
        row = definitions[name]
        need(row['InputSection'] == row['OutputSection'] == EXPECTATION_SECTION
             and row['SymbolOffset'] == 4 * index, 'exact expectation object offset')
        link._readonly(model, row, 4)
    name = 'pilot_context_roots'
    definitions[name] = link._bound(model, name, 'STT_OBJECT', ('STB_GLOBAL',), machine_owner, 20)
    need(definitions[name]['InputSection'] == definitions[name]['OutputSection'] == '.pilot_roots'
         and definitions[name]['SymbolOffset'] == 0, 'complete five-public-function pointer array')
    link._readonly(model, definitions[name], 20)
    tables = [link._table(model, EXPECTATION_SECTION, (STORAGE, PRIVATE), definitions, emitted, machine_owner),
              link._table(model, '.pilot_roots', PUBLIC, definitions, emitted, machine_owner)]
    definitions['pilot_vectors'] = link._bound(model, 'pilot_vectors', 'STT_OBJECT', ('STB_GLOBAL',), startup_owner, 1024)
    vector = definitions['pilot_vectors']
    need(vector['InputSection'] == vector['OutputSection'] == '.isr_vector' and vector['SymbolOffset'] == 0
         and vector['Entry'] == 0 and vector['SectionSize'] == 1024, 'whole startup vector placement at zero')
    _, vector_bytes = link._readonly(model, vector, 1024)
    vector_index, section = link._section(final, '.isr_vector')
    need(section.header.sh_size == 1024 and section.header.sh_addralign == 1024,
         'fixed 256-word vector extent/alignment')
    expected = [definitions['pilot_fault']['Final']['value']] * 256
    expected[0] = 0x20010000
    for index in (7, 8, 9, 10, 13):
        expected[index] = 0
    for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
        expected[index] = definitions[name]['Final']['value']
    need(list(struct.unpack('<256I', vector_bytes)) == expected
         and headers['Final']['Entry'] == definitions['Reset_Handler']['Final']['value'],
         'exact strong-handler vector template, entry and MSP')
    need(len(definitions) == 26, '26 mandatory link definitions')
    return dict(Status='CM3-OS-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_OS_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY', Profile='CM3', Mode='Os-lto', Linkage='direct',
        EmitRelocs=emitted, FinalLinkContractValidated=True, Headers=headers, Attributes=attributes,
        Symbols=definitions, PointerTables=tables, LinkMapSha256=image.link_map_hash,
        Vectors=dict(Name='pilot_vectors', SectionIndex=vector_index, Address=0, Words=256,
                     InitialMsp=expected[0], Entry=headers['Final']['Entry'], Bytes=vector_bytes.hex(),
                     StrongSlots=[1, 11, 14], ZeroSlots=[7, 8, 9, 10, 13], DefaultFaultEntries=247,
                     OriginalVectorRelocationsAudited=False),
        OriginalPointerRelocations=7, AppliedPointerRelocations=7 if emitted else 0,
        Qualification=False, FullABIProof=False, SourceIRProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False, InstructionEquivalence=False,
        PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)


def _preserves_r8(raw):
    """Closed write-effect subset for the Os anchor live range, not a decoder.

    True denotes a BL requiring separately bound target and AAPCS evidence.
    False denotes a supported non-call which cannot change r8. None rejects.
    """
    first = struct.unpack_from('<H', raw)[0]
    if len(raw) == 2:
        if first < 0x4400 or 0x4800 <= first < 0xB000:
            return False  # These Thumb-1 forms can only write low registers/SP.
        if first & 0xFC00 == 0x4400:
            opcode = (first >> 8) & 3
            destination = (first & 7) | ((first >> 4) & 8)
            if opcode == 1 or opcode in (0, 2) and destination not in (8, 15):
                return False
        if (first & 0xFF00 == 0xB000 or first & 0xF500 == 0xB100
                or first & 0xF000 == 0xD000 and (first >> 8) & 15 < 14
                or first & 0xF800 == 0xE000 or first == 0xBF00):
            return False
        return None
    if len(raw) != 4:
        return None
    second = struct.unpack_from('<H', raw, 2)[0]
    if first & 0xF800 == 0xF000 and second & 0xD000 == 0xD000:
        return True
    if raw in (bytes.fromhex('bff34f8f'), bytes.fromhex('bff36f8f')):
        return False
    if first == 0xF898 and second == 0x3000:
        return False  # Distinct cohort-byte read, not the ABI anchor read.
    opcode = first & 0xFBE0
    if (opcode in (0xF000, 0xF020, 0xF040, 0xF060, 0xF080, 0xF100, 0xF140, 0xF160, 0xF1A0, 0xF1C0)
            and second & 0x8000 == 0 and first & 15 != 15):
        destination = (second >> 8) & 15
        if destination not in (8, 15):
            return False
        if destination == 15 and first & 0x10 and opcode in (0xF000, 0xF080, 0xF100, 0xF1A0):
            return False  # TST/TEQ/CMN/CMP aliases do not write a register.
    return None


def _wide_cold_read(bindings, helper):
    """Os context-init anchor read, not the earlier private-cohort byte read."""
    owner = COLD[1]
    origin, source, final = bindings.function(owner)
    start, final_start = origin['SymbolOffset'], origin['OutputSectionOffset']
    need(source[1].get(start) == bytes.fromhex('2de9f043'), 'Os context-init r4-r9/lr stack-save prefix')
    load = start + 4
    literal = source[1].get(load)
    need(type(literal) is bytes and len(literal) == 4, 'Os T32 literal load on instruction boundary')
    first, second = struct.unpack('<HH', literal)
    need(first == 0xF8DF and second >> 12 == 8, 'Os positive PC-relative LDR.W into r8')
    pool = ((load + 4) & ~3) + (second & 0xFFF)
    candidates = [offset for offset, raw in source[1].items()
                  if offset > load and raw == bytes.fromhex('98f80130')]
    need(len(candidates) == 1, 'one Os LDRB.W r3,[r8,#1] anchor read, not cohort displacement zero')
    read = candidates[0]
    expected_moves = bytes.fromhex('1f4604460d461646')
    need(source[0][8:16] == expected_moves and read >= start + 20,
         'Os argument-preserving MOV prefix after r8 literal load')
    need(source[1].get(start + 16) == bytes.fromhex('98f80030'), 'separate initial cohort byte read')
    reference = bindings._anchor_pointer(owner, pool, 1)
    need(reference['AddressForm'] == 'SECTION_BASE_PLUS_BYTE_DISPLACEMENT', 'Os raw section-relative anchor authority')
    records, calls, call_offsets = [], [], []
    cursor = start
    while cursor <= read:
        raw = source[1].get(cursor)
        need(type(raw) is bytes and len(raw) in (2, 4), 'contiguous mapped Os entry-to-anchor instructions')
        final_offset = final_start + cursor - start
        after = final[1].get(final_offset)
        place = origin['Entry'] + cursor - start
        need(type(after) is bytes and len(after) == len(raw), 'matching Os final instruction boundary')
        effect = _preserves_r8(raw) if load < cursor < read else False
        need(effect is not None, 'unsupported instruction or possible r8 write in Os anchor live range')
        if effect:
            authority = bindings.source_refs.get((origin['InputSectionIndex'], cursor))
            need(authority is not None and authority[0] == 10 and type(authority[0]) is int,
                 'Os live-range BL original named REL authority')
            target = authority[1]
            need(target['kind'] == 'STT_FUNC' and target['name'] and type(target['section']) is int,
                 'Os live-range call requires an actual defined function')
            definition = bindings.audit._bound(bindings.model, target['name'], 'STT_FUNC',
                                               ('STB_LOCAL', 'STB_GLOBAL'), bindings.machine_owner)
            helper._same_symbol(bindings.machine, target, definition['Original'])
            bindings._site(owner, cursor, 10)
            before_form = bindings.core._address_form(raw, cursor)
            after_form = bindings.core._address_form(after, place)
            need(before_form is not None and after_form is not None
                 and before_form[0] == after_form[0] == 'bl' and before_form[3] == -4
                 and after_form[1] == definition['Entry'], 'Os original BL -4 and map-bound final call destination')
            applied = bindings.applied_refs.get((origin['OutputSectionIndex'], final_offset))
            if bindings.emitted:
                need(applied is not None and type(applied[0]) is int and applied[0] == 10,
                     'Os live-range BL matching emitted REL')
                helper._same_symbol(bindings.final, applied[1], definition['Final'])
            else:
                need(applied is None, 'no applied ordinary Os live-range REL')
            instruction = helper._instruction(bindings.image, origin['OutputSectionIndex'], place, after, 'bl')
            operand = re.fullmatch(r'([0-9a-fA-F]+)(?:\s+<[^>]+>)?', instruction['Operands'])
            need(operand is not None and int(operand[1], 16) == definition['Entry'], 'Os BL text/raw destination agreement')
            calls.append(dict(Offset=cursor - start, Name=target['name'], TargetOrigin=definition,
                              OriginalBytes=raw.hex(), FinalBytes=after.hex(), FinalInstruction=instruction,
                              AAPCSCalleeSavedRegisterAssumption=True, CalleeRegisterPreservationProven=False))
            call_offsets.append(cursor)
        else:
            need(raw == after, 'Os non-call entry-to-anchor bytes changed')
        instruction = helper._instruction(bindings.image, origin['OutputSectionIndex'], place, after)
        records.append(dict(Offset=cursor - start, Bytes=raw.hex(), FinalInstruction=instruction))
        cursor += len(raw)
    need(cursor == read + 4, 'complete Os anchor byte-read instruction')
    for refs, section, low in ((bindings.source_refs, origin['InputSectionIndex'], start),
                               (bindings.applied_refs, origin['OutputSectionIndex'], final_start)):
        allowed = {low + offset - start for offset in call_offsets} if refs is bindings.source_refs or bindings.emitted else set()
        need({offset for (index, offset) in refs if index == section
              and offset < low + read - start + 4 and low < offset + 4} == allowed,
             'no unclassified or overlapping REL in Os entry-to-anchor range')
    load_place = origin['Entry'] + 4
    final_literal = final[1][final_start + 4]
    final_first, final_second = struct.unpack('<HH', final_literal)
    need(final_first == 0xF8DF and final_second >> 12 == 8
         and ((load_place + 4) & ~3) + (final_second & 0xFFF) == reference['Place'],
         'Os final T32 PC-relative load addresses bound applied literal')
    load_record = helper._instruction(bindings.image, origin['OutputSectionIndex'], load_place, final_literal, 'ldr')
    operand = re.fullmatch(r'r8,\s*\[pc,\s*#(0x[0-9a-fA-F]+|[0-9]+)\]', load_record['Operands'])
    need(operand is not None and int(operand[1], 0 if operand[1].startswith('0x') else 10) == second & 0xFFF,
         'Os wide literal text/raw immediate agreement')
    read_place = origin['Entry'] + read - start
    read_record = helper._instruction(bindings.image, origin['OutputSectionIndex'], read_place,
                                      final[1][final_start + read - start], 'ldrb')
    need(re.fullmatch(r'r3,\s*\[r8,\s*#(?:1|0x1)\]', read_record['Operands']) is not None,
         'Os anchor LDRB.W text/raw displacement one')
    return dict(Function=owner, ConsumerOrigin=origin, LoadOffset=4, ReadOffset=read - start,
        BaseRegister=8, DestinationRegister=3, ByteDisplacement=1, LoadInstruction=load_record,
        ReadInstruction=read_record, AnchorReference=reference, RetainedByteRead=True,
        StaticBaseRegisterBindingValidated=True, InterveningCallOffsets=[row['Offset'] for row in calls],
        InterveningCalls=calls, AAPCSCalleeSavedRegisterAssumption=bool(calls),
        CalleeRegisterPreservationProven=False, ControlFlowOrDominanceProven=False,
        EntryToAnchorInstructions=records, InitialCohortReadIsNotABIAnchorRead=True,
        OriginalBodySha256=hashlib.sha256(source[0]).hexdigest().upper(),
        FinalBodySha256=hashlib.sha256(final[0]).hexdigest().upper())


def inspect(image, core, link_helpers, binding_helpers, attributes_text, *,
            emit_relocs=True, machine_attributes_text=None):
    """Validate own Os machine/final roles; unsupported inherited shapes reject.

    The image alone cannot establish optimization flags or current inventory
    authority. Those remain mandatory caller-side authenticated prerequisites.
    Failure returns no partial success record or required-cell credit.
    """
    need(type(emit_relocs) is bool and getattr(image, 'float_abi', None) == 'soft',
         'literal twin selector and soft core reader')
    _helpers(link_helpers, binding_helpers)
    proof = _link_contract(image, link_helpers, attributes_text, emit_relocs, machine_attributes_text)
    bindings = binding_helpers.Bindings(image, core, link_helpers, proof, emit_relocs)
    reverse = bindings.reverse_references()
    cold = []
    for name in COLD:
        try:
            origin, source, _ = bindings.function(name)
            first_load = source[1].get(origin['SymbolOffset'] + 4, b'')
            if name == COLD[1] and first_load[:2] == bytes.fromhex('dff8'):
                cold.append(_wide_cold_read(bindings, binding_helpers))
            else:
                cold.append(bindings.cold_read(name))
        except binding_helpers.Rejected as error:
            raise Rejected('REJECT:CM3-OS-LTO-ABI:unsupported or invalid cold read in '
                           + name + ': ' + str(error)) from error
    vectors = bindings.vectors()
    need(len(bindings.used_applied) == (10 if emit_relocs else 0), 'ten selected original/applied binding roles')
    mandatory = dict(proof['Symbols'], **{name: bindings.definitions[name] for name in REVERSE})
    consumers = [bindings.definitions[name] for name in dict.fromkeys(row[0] for row in REFERENCES)
                 if name not in mandatory]
    need(len(mandatory) == 30 and len(consumers) == 3, 'distinct mandatory providers and consumer extents')
    result = dict(Status=STATUS, Scope=SCOPE,
        Profile='CM3', Mode='Os-lto', Linkage='direct', EmitRelocs=emit_relocs,
        RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True, LinkContract=proof,
        MandatoryDefinitions=mandatory, MandatoryDefinitionCount=30,
        AdditionalConsumerOrigins=consumers, AdditionalConsumerCount=3,
        ForwardProviders=[proof['Symbols'][name] for name in FORWARD], ForwardProviderCount=8,
        ReverseProviders=[bindings.definitions[name] for name in REVERSE], ReverseProviderCount=4,
        ReverseReferences=reverse, ReverseReferenceCount=5, ReverseBLReferences=4, TaskReturnABS32References=1,
        ColdAnchorReads=cold, ColdAnchorReadCount=2, StartupVectors=vectors, StartupVectorReferenceCount=3,
        OriginalBindingRelocations=10, AppliedBindingRelocations=10 if emit_relocs else 0,
        AnchorDefinition=proof['Symbols'][ANCHOR], MachineProvider=bindings.machine_owner,
        StartupProvider=bindings.startup_owner, MachineSha256=hashlib.sha256(image.prelink.data).hexdigest().upper(),
        FinalSha256=hashlib.sha256(image.final.data).hexdigest().upper(),
        StartupSha256=hashlib.sha256(image.providers[bindings.startup_owner].data).hexdigest().upper(),
        LinkMapSha256=image.link_map_hash, OriginalStartupVectorRelocationsAudited=True,
        AllStartupVectorRelocationsAudited=False, OtherReverseConsumersAudited=False,
        CallerBodySemanticsProven=False, CalleeRegisterPreservationProven=False, ControlFlowOrDominanceProven=False,
        Qualification=False, TypedABIProof=False, FullABIProof=False, FullSemanticABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, InstructionEquivalence=False, PolicyEquivalence=False,
        FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    require_result(result, emit_relocs=emit_relocs)
    return result


def require_result(proof, *, emit_relocs):
    """Require the fresh result schema, not receipt-only proof authenticity."""
    need(type(emit_relocs) is bool and type(proof) is dict, 'literal result and twin selector')
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'),
                       ('Mode', 'Os-lto'), ('Linkage', 'direct')):
        need(type(proof.get(key)) is str and proof[key] == value, 'exact result/' + key)
    need(proof.get('EmitRelocs') is emit_relocs, 'exact result twin role')
    for key in ('RuntimeProviderBindingsValidated', 'FinalLinkContractValidated',
                'OriginalStartupVectorRelocationsAudited'):
        need(proof.get(key) is True, 'completed result/' + key)
    for key in NONCLAIMS:
        need(proof.get(key) is False, 'no promotion: ' + key)
    for key, count in (('MandatoryDefinitionCount', 30), ('AdditionalConsumerCount', 3),
                       ('ForwardProviderCount', 8), ('ReverseProviderCount', 4),
                       ('ReverseReferenceCount', 5), ('ReverseBLReferences', 4),
                       ('TaskReturnABS32References', 1), ('ColdAnchorReadCount', 2),
                       ('StartupVectorReferenceCount', 3), ('OriginalBindingRelocations', 10),
                       ('AppliedBindingRelocations', 10 if emit_relocs else 0), ('RequiredCellsSatisfied', 0)):
        need(type(proof.get(key)) is int and proof[key] == count, 'literal result count/' + key)
    link = proof.get('LinkContract')
    need(type(link) is dict and link.get('Status') == 'CM3-OS-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED'
         and link.get('Scope') == 'NATIVE_CM3_OS_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY'
         and link.get('Profile') == 'CM3' and link.get('Mode') == 'Os-lto'
         and link.get('Linkage') == 'direct' and link.get('EmitRelocs') is emit_relocs
         and link.get('FinalLinkContractValidated') is True, 'own Os link-contract result')
    for key, count in (('OriginalPointerRelocations', 7), ('AppliedPointerRelocations', 7 if emit_relocs else 0),
                       ('RequiredCellsSatisfied', 0)):
        need(type(link.get(key)) is int and link[key] == count, 'literal link count/' + key)
    for key in ('Qualification', 'FullABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof',
                'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated', 'InstructionEquivalence',
                'PolicyEquivalence', 'FinalReferenceParity', 'CompleteObjectProof', 'KernelRuntimeProof',
                'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
        need(link.get(key) is False, 'no link promotion: ' + key)
    names = (*PUBLIC, *FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault', 'Reset_Handler', 'fiber_panic',
             ANCHOR, PRIVATE, STORAGE, SLOT, *EXPECTATIONS, 'pilot_context_roots', 'pilot_vectors')
    need(type(link.get('Symbols')) is dict and set(link['Symbols']) == set(names), '26 exact link definitions')
    mandatory = proof.get('MandatoryDefinitions')
    need(type(mandatory) is dict and set(mandatory) == set(names).union(REVERSE), '30 exact mandatory definitions')
    for key, expected, field in (
            ('ForwardProviders', FORWARD, 'Name'), ('ReverseProviders', REVERSE, 'Name'),
            ('AdditionalConsumerOrigins', tuple(dict.fromkeys(row[0] for row in REFERENCES if row[0] not in mandatory)), 'Name'),
            ('ColdAnchorReads', COLD, 'Function'), ('StartupVectors', tuple(row[1] for row in VECTORS), 'Symbol')):
        rows = proof.get(key)
        need(type(rows) is list and len(rows) == len(expected)
             and all(type(row) is dict and row.get(field) == name for row, name in zip(rows, expected)),
             'exact ordered result/' + key)
    rows = proof.get('ReverseReferences')
    need(type(rows) is list and len(rows) == 5 and all(type(row) is dict
         and (row.get('Consumer'), row.get('Kind'), row.get('Symbol')) == expected
         and type(row.get('Kind')) is int for row, expected in zip(rows, REFERENCES)), 'five exact reverse roles')
    for key in ('MachineSha256', 'FinalSha256', 'StartupSha256', 'LinkMapSha256'):
        need(type(proof.get(key)) is str and re.fullmatch(r'[A-F0-9]{64}', proof[key]), 'result hash/' + key)
    need(link.get('LinkMapSha256') == proof['LinkMapSha256'], 'same map throughout result')
    need(all(type(proof.get(key)) is str and proof[key] for key in ('MachineProvider', 'StartupProvider'))
         and proof['MachineProvider'] != proof['StartupProvider'], 'distinct result provider identities')
