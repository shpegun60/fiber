"""Pure CM3 BASEPRI16/32 direct-link surfaces, not policy or ABI equivalence.

The caller authenticates the image and both supplied helper modules. BASEPRI16
delegates to the unchanged fixed audit. BASEPRI32 composes its fixed predicates
with one explicitly selected private cohort; no helper globals are patched.
"""

import struct


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-LTO-COHORT:' + message)


def _private(basepri, frozen, identity):
    need(type(basepri) is int and basepri in (16, 32), 'literal policy threshold 16 or 32')
    first, second, storage = identity.PRIVATE16, identity.PRIVATE32, identity.STORAGE
    need(all(type(value) is str for value in (first, second, storage)), 'literal cohort identities')
    need(first == frozen.PRIVATE and first.count('_u00010000_') == 1
         and second == first.replace('_u00010000_', '_u00100000_')
         and storage == frozen.STORAGE, 'only fixed scheduler-policy bits may differ; storage is unchanged')
    return first if basepri == 16 else second


def _surface(elf, private, frozen):
    need(all(type(row) is dict and type(row.get('name')) is str for row in elf.symbols),
         'literal named symbol metadata')
    names = {row['name'] for row in elf.symbols}
    need(not frozen.LEGACY.intersection(names) and not any(name.startswith('fiber_v1_') for name in names),
         'legacy public or optional lifecycle/configuration symbols are forbidden')
    need({name for name in names if name.startswith('ctxrt_v')} == set(frozen.PUBLIC),
         'exact five versioned public Context symbols')
    need({name for name in names if name.startswith('fiber_port_context_cohort_')}
         == {private, frozen.EXPECTATIONS[1]}
         and {name for name in names if name.startswith('fiber_port_storage_cohort_')}
         == {frozen.STORAGE, frozen.EXPECTATIONS[0]},
         'exact selected private/storage identities and expectation names')
    if elf.final:
        need(not any(row['name'] and row.get('section') == 'SHN_UNDEF' for row in elf.symbols),
             'undefined final symbol')


def _audit32(image, attributes_text, emit_relocs, machine_attributes_text, private, frozen):
    machine, final = image.prelink, image.final
    headers = dict(Machine=frozen._header(machine, False), Final=frozen._header(final, True))
    attributes = dict(Machine=frozen._attributes(machine_attributes_text), Final=frozen._attributes(attributes_text))
    need(type(image.providers) is dict and len(image.providers) == 2 and type(image.placements) is dict,
         'one generated machine and one startup provider with captured map placements')
    need(type(image.link_map_hash) is str and len(image.link_map_hash) == 64
         and all(char in '0123456789ABCDEF' for char in image.link_map_hash), 'authenticated link-map hash')
    owners = []
    for owner, provider in image.providers.items():
        need(type(owner) is str and owner, 'literal original provider identity')
        frozen._header(provider, False)
        if provider.data == machine.data:
            owners.append(owner)
    need(len(owners) == 1, 'unique actual generated-machine provider')
    machine_owner = owners[0]
    startup_owner = next(owner for owner in image.providers if owner != machine_owner)
    _surface(machine, private, frozen)
    _surface(final, private, frozen)
    need(emit_relocs or not final.relocations, 'ordinary twin must not retain applied REL metadata')

    # This facade is local; the core image and frozen module remain unchanged.
    class Inputs:
        pass

    model = Inputs()
    model.prelink, model.final = machine, final
    model.providers, model.placements = image.providers, image.placements
    model._contract_machine_owner = machine_owner
    definitions = {}
    for name in (*frozen.PUBLIC, *frozen.FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault'):
        definitions[name] = frozen._bound(model, name, 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    definitions['Reset_Handler'] = frozen._bound(model, 'Reset_Handler', 'STT_FUNC', ('STB_GLOBAL',), startup_owner)
    definitions['fiber_panic'] = frozen._bound(model, 'fiber_panic', 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    for name in (frozen.ANCHOR, private, frozen.STORAGE):
        bindings = ('STB_LOCAL',) if name == frozen.ANCHOR else ('STB_GLOBAL',)
        definitions[name] = frozen._bound(model, name, 'STT_OBJECT', bindings, machine_owner, 1)
        need(frozen._readonly(model, definitions[name], 1) == (b'\x01', b'\x01'),
             'one-byte ABI/cohort identity value')
    definitions[frozen.SLOT] = frozen._bound(model, frozen.SLOT, 'STT_OBJECT', ('STB_LOCAL',), machine_owner, 4)
    slot = definitions[frozen.SLOT]
    need(slot['InputSection'] == frozen.SLOT_SECTION and slot['SectionSize'] == 4 and slot['SymbolOffset'] == 0
         and slot['OutputSection'] == '.bss' and slot['Entry'] % 4 == 0,
         'dedicated four-byte input slot and mapped final BSS role')
    for elf, row in ((machine, slot['Original']), (final, slot['Final'])):
        h = elf.sections[row['section']].header
        need(h.sh_type == 'SHT_NOBITS' and h.sh_flags & 7 == 3 and row['value'] % 4 == 0, 'zero-fill slot storage')
    for index, name in enumerate(frozen.EXPECTATIONS):
        definitions[name] = frozen._bound(model, name, 'STT_OBJECT', ('STB_LOCAL', 'STB_GLOBAL'), machine_owner, 4)
        value = definitions[name]
        need(value['InputSection'] == value['OutputSection'] == frozen.EXPECTATION_SECTION
             and value['SymbolOffset'] == 4 * index, 'exact original expectation object offset')
        frozen._readonly(model, value, 4)
    definitions['pilot_context_roots'] = frozen._bound(model, 'pilot_context_roots', 'STT_OBJECT',
                                                       ('STB_GLOBAL',), machine_owner, 20)
    roots = definitions['pilot_context_roots']
    need(roots['InputSection'] == roots['OutputSection'] == '.pilot_roots' and roots['SymbolOffset'] == 0,
         'complete five-function consumer pointer array')
    frozen._readonly(model, roots, 20)
    tables = [frozen._table(model, frozen.EXPECTATION_SECTION, (frozen.STORAGE, private), definitions,
                           emit_relocs, machine_owner),
              frozen._table(model, '.pilot_roots', frozen.PUBLIC, definitions, emit_relocs, machine_owner)]
    definitions['pilot_vectors'] = frozen._bound(model, 'pilot_vectors', 'STT_OBJECT', ('STB_GLOBAL',), startup_owner, 1024)
    vector = definitions['pilot_vectors']
    need(vector['InputSection'] == vector['OutputSection'] == '.isr_vector' and vector['SymbolOffset'] == 0
         and vector['Entry'] == 0 and vector['SectionSize'] == 1024, 'whole startup vector placement at zero')
    _, vector_bytes = frozen._readonly(model, vector, 1024)
    vector_index, vector_section = frozen._section(final, '.isr_vector')
    need(vector_section.header.sh_size == 1024 and vector_section.header.sh_addralign == 1024,
         'fixed 256-word vector extent/alignment')
    expected = [definitions['pilot_fault']['Final']['value']] * 256
    expected[0] = 0x20010000
    for index in (7, 8, 9, 10, 13):
        expected[index] = 0
    for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
        expected[index] = definitions[name]['Final']['value']
    need(list(struct.unpack('<256I', vector_bytes)) == expected
         and headers['Final']['Entry'] == definitions['Reset_Handler']['Final']['value'],
         'exact strong-handler vector template and entry/MSP')
    return dict(Profile='CM3', Mode='O2-lto', Linkage='direct', EmitRelocs=emit_relocs,
        FinalLinkContractValidated=True, Headers=headers, Attributes=attributes, Symbols=definitions,
        PointerTables=tables, LinkMapSha256=image.link_map_hash,
        Vectors=dict(Name='pilot_vectors', SectionIndex=vector_index, Address=0, Words=256, InitialMsp=expected[0],
            Entry=headers['Final']['Entry'], Bytes=vector_bytes.hex(), StrongSlots=[1, 11, 14],
            ZeroSlots=[7, 8, 9, 10, 13], DefaultFaultEntries=247, OriginalVectorRelocationsAudited=False),
        OriginalPointerRelocations=7, AppliedPointerRelocations=7 if emit_relocs else 0,
        Qualification=False, FullABIProof=False, SourceIRProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False, InstructionEquivalence=False,
        PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)


def audit(image, attributes_text, *, basepri, emit_relocs=True, machine_attributes_text=None, frozen_audit, identity):
    """Audit one authenticated own-machine twin for exactly policy 16 or 32."""
    private = _private(basepri, frozen_audit, identity)
    need(type(emit_relocs) is bool and getattr(image, 'float_abi', None) == 'soft',
         'literal twin selector and soft core reader')
    try:
        if basepri == 16:
            result = dict(frozen_audit.audit(image, attributes_text, emit_relocs=emit_relocs,
                                           machine_attributes_text=machine_attributes_text))
        else:
            result = _audit32(image, attributes_text, emit_relocs, machine_attributes_text, private, frozen_audit)
    except frozen_audit.Rejected as error:
        raise Rejected('REJECT:CM3-LTO-COHORT:' + str(error)) from error
    expected = {*frozen_audit.PUBLIC, *frozen_audit.FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault',
                'Reset_Handler', 'fiber_panic', frozen_audit.ANCHOR, private, frozen_audit.STORAGE, frozen_audit.SLOT,
                *frozen_audit.EXPECTATIONS, 'pilot_context_roots', 'pilot_vectors'}
    need(type(result.get('Symbols')) is dict and len(expected) == 26 and set(result['Symbols']) == expected,
         'all exact 26 policy-selected definitions')
    need(type(result.get('OriginalPointerRelocations')) is int and result['OriginalPointerRelocations'] == 7
         and type(result.get('AppliedPointerRelocations')) is int
         and result['AppliedPointerRelocations'] == (7 if emit_relocs else 0), 'all seven original/applied pointer roles')
    result.update(Status='CM3-LTO-COHORT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_O2_LTO_POLICY_COHORT_DIRECT_LINK_CONTRACT_ONLY', Basepri=basepri,
        PrivateCohort=private, StorageCohort=identity.STORAGE, DefinitionCount=26,
        FrozenAuditDelegated=basepri == 16, FrozenPredicatesReused=True,
        PolicyCohortLinkContractValidated=True, CanonicalProtocolValidated=False, PolicyEquivalence=False)
    return result
