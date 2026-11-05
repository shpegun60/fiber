"""Pure native CM3 O2-lto direct-link surface, not ABI or IR equivalence.

Input is an already authenticated generic core.FinalImage. Original machine
RELs bind seven fixed pointer roles; emitted final RELs are required only for
the emit-relocs twin. No helper loading, file access, decoding or execution.
"""
import re
import struct


PUBLIC = ('ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_set_dispatcher', 'ctxrt_v1_start', 'ctxrt_v1_yield')
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
           'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
           'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
HANDLERS = ('Reset_Handler', 'SVC_Handler', 'PendSV_Handler')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
SLOT = 'fiber_internal_runtime_current_context_slot'
PRIVATE = ('fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_'
           'u00010000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
STORAGE = 'fiber_port_storage_cohort_arm_cm3_v1_r0'
EXPECTATION_SECTION = '.fiber_port_context_cohort_expectation'
EXPECTATIONS = ('fiber_port_storage_cohort_consumer_expectation', 'fiber_port_context_cohort_build_expectation')
SLOT_SECTION = '.bss.fiber_runtime_current_context_slot'
REQUIRED_ATTRIBUTES = {'Tag_CPU_name': '"7-M"', 'Tag_CPU_arch': 'v7',
                       'Tag_CPU_arch_profile': 'Microcontroller', 'Tag_THUMB_ISA_use': 'Thumb-2'}
FORBIDDEN_ATTRIBUTES = frozenset(name.casefold() for name in ('Tag_FP_arch', 'Tag_ABI_HardFP_use',
    'Tag_MVE_arch', 'Tag_Advanced_SIMD_arch', 'Tag_ABI_VFP_args', 'Tag_PAC_extension', 'Tag_BTI_extension'))
LEGACY = frozenset(('fiber_init', 'fiber_current', 'fiber_start', 'fiber_schedule', 'fiber_scheduler_set_pick_next',
                   'fiber_set_dispatcher', 'fiber_yield', 'fiber_internal_runtime_context_configuration_abi_v1_anchor',
                   'fiber_internal_runtime_require_context_configuration_open'))


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-LTO-LINK-CONTRACT:' + message)


def _integer(value, label, *, minimum=0, maximum=0xFFFFFFFF):
    need(type(value) is int and minimum <= value <= maximum, 'literal bounded integer required: ' + label)
    return value


def _attributes(text):
    need(type(text) is str and '\0' not in text, 'machine and final attribute texts are required')
    result, names = {}, set()
    for line in text.splitlines():
        if not line.lstrip().casefold().startswith('tag_'):
            continue
        match = re.fullmatch(r'\s*(Tag_[A-Za-z0-9_]+):[^\S\r\n]*(.*?)\s*', line)
        need(match is not None, 'malformed attribute record')
        name, value = match.groups()
        folded = name.casefold()
        need(folded not in names and folded not in FORBIDDEN_ATTRIBUTES,
             'duplicate/case-aliased or hardware FP/MVE/SIMD/PAC/BTI attribute')
        names.add(folded)
        result[name] = value
    need(all(result.get(name) == value for name, value in REQUIRED_ATTRIBUTES.items()), 'exact soft CM3 codegen attributes')
    return result


def _header(elf, final):
    need(getattr(elf, 'final', None) is final and type(getattr(elf, 'data', None)) is bytes and len(elf.data) >= 52,
         'supplied ARM ELF bytes and literal image role required')
    data = elf.data
    need(data[:7] == b'\x7fELF\x01\x01\x01', 'ARM ELF32 little-endian version-one identity')
    kind, machine, version, entry = struct.unpack_from('<HHII', data, 16)
    flags = struct.unpack_from('<I', data, 36)[0]
    need(kind == (2 if final else 1) and machine == 40 and version == 1
         and struct.unpack_from('<H', data, 40)[0] == 52, 'exact ARM ET_EXEC/ET_REL header')
    need(flags == (0x05000200 if final else 0x05000000), 'fixed EABI5 soft final/unmarked generated-machine flags')
    need(type(getattr(elf, 'sections', None)) is list and type(getattr(elf, 'symbols', None)) is list
         and type(getattr(elf, 'relocations', None)) is dict, 'authenticated core ELF metadata required')
    return dict(Type='ET_EXEC' if final else 'ET_REL', Entry=entry, Flags=flags)


def _section(elf, name):
    rows = [(index, section) for index, section in enumerate(elf.sections) if section.name == name]
    need(len(rows) == 1 and rows[0][0] > 0, 'one exact section required: ' + name)
    index, section = rows[0]
    h = section.header
    for field in ('sh_addr', 'sh_offset', 'sh_size', 'sh_flags', 'sh_addralign'):
        _integer(getattr(h, field), name + '/' + field)
    need(type(h.sh_type) is str, 'literal section type: ' + name)
    return index, section


def _bytes(elf, index, offset, size):
    _integer(index, 'section index', minimum=1, maximum=len(elf.sections) - 1)
    _integer(offset, 'section byte offset')
    _integer(size, 'section byte size', minimum=1)
    h = elf.sections[index].header
    for field in ('sh_offset', 'sh_size'):
        _integer(getattr(h, field), 'file-backed section/' + field)
    need(h.sh_type == 'SHT_PROGBITS' and offset + size <= h.sh_size
         and h.sh_offset + offset + size <= len(elf.data), 'bounded actual PROGBITS bytes required')
    return elf.data[h.sh_offset + offset:h.sh_offset + offset + size]


def _load(elf, address, size, *, slot=False):
    need(type(getattr(elf, 'loads', None)) is list, 'final PT_LOAD metadata required')
    owners = []
    for row in elf.loads:
        need(type(row) is dict, 'literal load record')
        for field in ('Vaddr', 'MemorySize', 'FileSize', 'Flags', 'Offset'):
            _integer(row.get(field), 'load/' + field)
        need(row['FileSize'] <= row['MemorySize'] and row['Vaddr'] + row['MemorySize'] <= 1 << 32
             and row['Offset'] + row['FileSize'] <= len(elf.data), 'bounded load extent')
        if row['Vaddr'] <= address and address + size <= row['Vaddr'] + row['MemorySize']:
            owners.append(row)
    need(len(owners) == 1, 'unique full symbol/section load coverage')
    owner = owners[0]
    if slot:
        need(owner['Flags'] & 3 == 2 and address >= owner['Vaddr'] + owner['FileSize'],
             'BSS slot must be writable, non-executable and outside file-backed bytes')
    else:
        need(address + size <= owner['Vaddr'] + owner['FileSize'], 'complete file-backed load coverage')
    return owner


def _symbol(elf, name, kind, bindings, size=None):
    need(all(type(row) is dict and type(row.get('name')) is str for row in elf.symbols), 'literal symbol rows required')
    rows = [row for row in elf.symbols if row['name'] == name and row.get('section') != 'SHN_UNDEF']
    need(len(rows) == 1, 'one defined symbol required: ' + name)
    row = rows[0]
    for key in ('section', 'value', 'size', 'index'):
        _integer(row.get(key), name + '/' + key, minimum=1 if key == 'section' else 0,
                 maximum=len(elf.sections) - 1 if key == 'section' else 0xFFFFFFFF)
    need(row.get('kind') == kind and row.get('binding') in bindings and row.get('visibility') == 'STV_DEFAULT'
         and row['size'] > 0 and (size is None or row['size'] == size), 'exact symbol role/size/binding: ' + name)
    section = elf.sections[row['section']]
    h = section.header
    for key in ('sh_addr', 'sh_size', 'sh_flags', 'sh_addralign'):
        _integer(getattr(h, key), name + '/' + key)
    address = row['value'] & ~1 if kind == 'STT_FUNC' else row['value']
    base = h.sh_addr if elf.final else 0
    need(base <= address and address + row['size'] <= base + h.sh_size, 'bounded symbol extent: ' + name)
    for other in elf.symbols:
        if other['name'] == name or other.get('kind') != kind or other.get('section') != row['section']:
            continue
        _integer(other.get('size'), 'peer size')
        _integer(other.get('value'), 'peer value')
        start = other['value'] & ~1 if kind == 'STT_FUNC' else other['value']
        need(not other['size'] or not (start < address + row['size'] and address < start + other['size']),
             'cross-name positive-size alias/overlap: ' + name)
    if kind == 'STT_FUNC':
        need(row['value'] & 1 and row['size'] % 2 == 0 and h.sh_type == 'SHT_PROGBITS' and h.sh_flags & 7 == 6
             and elf.mapping(row['section'], address)[0] == 't', 'Thumb executable complete function: ' + name)
    if elf.final:
        owner = _load(elf, address, row['size'], slot=h.sh_type == 'SHT_NOBITS')
        if kind == 'STT_FUNC':
            need(owner['Flags'] & 1 != 0, 'function requires executable load: ' + name)
        if h.sh_type == 'SHT_PROGBITS':
            raw = _bytes(elf, row['section'], address - h.sh_addr, row['size'])
            at = owner['Offset'] + address - owner['Vaddr']
            need(elf.data[at:at + row['size']] == raw, 'section/load byte mapping mismatch: ' + name)
    return row


def _bound(image, name, kind, bindings, owner, size=None):
    owners = [(identity, elf) for identity, elf in image.providers.items()
              if any(row.get('name') == name and row.get('section') != 'SHN_UNDEF' for row in elf.symbols)]
    need(len(owners) == 1 and owners[0][0] == owner, 'unique prescribed generated-machine/startup owner: ' + name)
    identity, source = owners[0]
    before = _symbol(source, name, kind, bindings, size)
    after = _symbol(image.final, name, kind, bindings, size)
    original, final = source.sections[before['section']], image.final.sections[after['section']]
    h, last = original.header, final.header
    need(sum(section.name == original.name for section in source.sections) == 1
         and (identity, original.name) in image.placements, 'unique full input-section placement: ' + name)
    placement = image.placements[identity, original.name]
    need(type(placement) is tuple and len(placement) == 2, 'literal section placement pair')
    address, extent = placement
    _integer(address, 'placement address')
    _integer(extent, 'placement size', minimum=1)
    offset = before['value'] & ~1 if kind == 'STT_FUNC' else before['value']
    entry = after['value'] & ~1 if kind == 'STT_FUNC' else after['value']
    need(h.sh_addr == 0 and extent == h.sh_size and offset + before['size'] <= extent
         and address + extent <= 1 << 32 and address + offset == entry and before['size'] == after['size']
         and before['binding'] == after['binding'] and address % max(1, h.sh_addralign) == 0
         and last.sh_addr <= address and address + extent <= last.sh_addr + last.sh_size
         and h.sh_type == last.sh_type and h.sh_flags & 7 == last.sh_flags & 7,
         'whole input-section/offset/size/binding must place exact final definition: ' + name)
    return dict(Name=name, Original=dict(before), Final=dict(after), Provider=identity,
        InputSection=original.name, InputSectionIndex=before['section'], SectionAddress=address, SectionSize=extent,
        SymbolOffset=offset, Size=before['size'], Entry=entry, OutputSection=final.name,
        OutputSectionIndex=after['section'], OutputSectionOffset=entry - last.sh_addr,
        GeneratedMachineOriginBound=owner == image._contract_machine_owner,
        StartupOriginBound=owner != image._contract_machine_owner)


def _readonly(image, evidence, size):
    before, after = evidence['Original'], evidence['Final']
    source = image.providers[evidence['Provider']]
    for elf, row in ((source, before), (image.final, after)):
        h = elf.sections[row['section']].header
        need(h.sh_type == 'SHT_PROGBITS' and h.sh_flags & 7 == 2 and row['size'] == size,
             'exact allocated read-only object: ' + row['name'])
        if elf.final:
            need(_load(elf, row['value'], size)['Flags'] & 2 == 0, 'read-only object in writable load')
    return _bytes(source, before['section'], before['value'], size), _bytes(image.final, after['section'],
        after['value'] - image.final.sections[after['section']].header.sh_addr, size)


def _relocations(elf, section):
    result = {}
    for key, value in elf.relocations.items():
        need(type(key) is tuple and len(key) == 2, 'literal section-relative REL key')
        _integer(key[0], 'REL target section', minimum=1, maximum=len(elf.sections) - 1)
        _integer(key[1], 'REL offset')
        need(type(value) is tuple and len(value) == 2, 'literal REL kind/target pair')
        _integer(value[0], 'REL kind')
        if key[0] == section:
            result[key[1]] = value
    return result


def _target(actual, expected):
    need(type(actual) is dict, 'actual raw named relocation symbol required')
    for key in ('section', 'value', 'size', 'index'):
        _integer(actual.get(key), 'REL symbol/' + key, minimum=1 if key == 'section' else 0)
    need(set(actual) == set(expected) and all(type(actual[key]) is type(expected[key]) and actual[key] == expected[key]
         for key in expected), 'REL must name the exact original/final symbol-table definition')


def _table(image, name, targets, definitions, emit_relocs, machine_owner):
    machine, final = image.prelink, image.final
    original_index, original = _section(machine, name)
    final_index, last = _section(final, name)
    size = 4 * len(targets)
    for section in (original, last):
        h = section.header
        need(h.sh_type == 'SHT_PROGBITS' and h.sh_flags & 7 == 2 and h.sh_size == size
             and h.sh_addralign >= 4 and h.sh_addralign % 4 == 0, 'fixed complete read-only pointer table: ' + name)
    placement = image.placements.get((machine_owner, name))
    need(type(placement) is tuple and len(placement) == 2 and all(type(value) is int for value in placement)
         and placement == (last.header.sh_addr, size), 'whole machine pointer-table placement required')
    load = _load(final, last.header.sh_addr, size)
    need(load['Flags'] & 2 == 0, 'read-only pointer table load')
    before, after = _bytes(machine, original_index, 0, size), _bytes(final, final_index, 0, size)
    at = load['Offset'] + last.header.sh_addr - load['Vaddr']
    need(final.data[at:at + size] == after and before == bytes(size), 'actual zero original ABS32 addends and mapped final table')
    source_refs, applied_refs = _relocations(machine, original_index), _relocations(final, final_index)
    offsets = set(range(0, size, 4))
    need(set(source_refs) == offsets and set(applied_refs) == (offsets if emit_relocs else set()),
         'exact original/final pointer-table REL membership: ' + name)
    rows = []
    for index, target in enumerate(targets):
        offset = 4 * index
        definition = definitions[target]
        kind, symbol = source_refs[offset]
        need(type(kind) is int and kind == 2, 'only named original R_ARM_ABS32+0 pointer roles')
        _target(symbol, definition['Original'])
        value = struct.unpack_from('<I', after, offset)[0]
        need(value == definition['Final']['value'], 'applied pointer differs from map-bound exact definition')
        applied = None
        if emit_relocs:
            final_kind, final_symbol = applied_refs[offset]
            need(type(final_kind) is int and final_kind == 2, 'only matching applied R_ARM_ABS32 pointer roles')
            _target(final_symbol, definition['Final'])
            applied = dict(final_symbol)
        rows.append(dict(Offset=offset, Kind=2, Name=target, Addend=0, Value=value,
            OriginalRelocationSymbol=dict(symbol), FinalRelocationSymbol=applied))
    return dict(Name=name, Provider=machine_owner, OriginalSectionIndex=original_index, FinalSectionIndex=final_index,
                Address=last.header.sh_addr, Size=size, OriginalBytes=before.hex(), FinalBytes=after.hex(),
                OriginalRelocationsValidated=True, AppliedRelocationsValidated=emit_relocs, Pointers=rows)


def _surface(elf):
    need(all(type(row) is dict and type(row.get('name')) is str for row in elf.symbols), 'literal named symbol metadata')
    names = {row['name'] for row in elf.symbols}
    need(not LEGACY.intersection(names) and not any(name.startswith('fiber_v1_') for name in names),
         'legacy public or optional lifecycle/configuration symbols are forbidden')
    need({name for name in names if name.startswith('ctxrt_v')} == set(PUBLIC), 'exact five versioned public Context symbols')
    need({name for name in names if name.startswith('fiber_port_context_cohort_')} == {PRIVATE, EXPECTATIONS[1]}
         and {name for name in names if name.startswith('fiber_port_storage_cohort_')} == {STORAGE, EXPECTATIONS[0]},
         'exact CM3 private/storage identities and expectation names')
    if elf.final:
        need(not any(row['name'] and row.get('section') == 'SHN_UNDEF' for row in elf.symbols), 'undefined final symbol')


def audit(image, attributes_text, *, emit_relocs=True, machine_attributes_text=None):
    """Audit each own-machine twin; missing machine attributes fail closed.

    Function sizes/entries bind to the supplied machine and whole-section map,
    not learned instruction hashes. Raw vector bytes follow the fixed fixture
    template; this is not startup execution or arbitrary REL interpretation.
    """
    need(type(emit_relocs) is bool and getattr(image, 'float_abi', None) == 'soft', 'literal twin selector and soft core reader')
    machine, final = image.prelink, image.final
    headers = dict(Machine=_header(machine, False), Final=_header(final, True))
    attributes = dict(Machine=_attributes(machine_attributes_text), Final=_attributes(attributes_text))
    need(type(image.providers) is dict and len(image.providers) == 2 and type(image.placements) is dict,
         'one generated machine and one startup provider with captured map placements')
    need(type(image.link_map_hash) is str and re.fullmatch(r'[A-F0-9]{64}', image.link_map_hash) is not None,
         'authenticated link-map hash required')
    owners = []
    for identity, provider in image.providers.items():
        need(type(identity) is str and identity, 'literal original provider identity')
        _header(provider, False)
        if provider.data == machine.data:
            owners.append(identity)
    need(len(owners) == 1, 'unique actual generated-machine provider')
    machine_owner = owners[0]
    startup_owner = next(identity for identity in image.providers if identity != machine_owner)
    _surface(machine)
    _surface(final)
    need(emit_relocs or not final.relocations, 'ordinary twin must not retain applied REL metadata')
    # Pass the owner explicitly through a local facade; never mutate core objects.
    class Inputs:
        pass
    model = Inputs()
    model.prelink, model.final, model.providers, model.placements = machine, final, image.providers, image.placements
    model._contract_machine_owner = machine_owner
    definitions = {}
    for name in (*PUBLIC, *FORWARD, 'SVC_Handler', 'PendSV_Handler', 'pilot_fault'):
        definitions[name] = _bound(model, name, 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    definitions['Reset_Handler'] = _bound(model, 'Reset_Handler', 'STT_FUNC', ('STB_GLOBAL',), startup_owner)
    definitions['fiber_panic'] = _bound(model, 'fiber_panic', 'STT_FUNC', ('STB_GLOBAL',), machine_owner)
    for name in (ANCHOR, PRIVATE, STORAGE):
        bindings = ('STB_LOCAL',) if name == ANCHOR else ('STB_GLOBAL',)
        definitions[name] = _bound(model, name, 'STT_OBJECT', bindings, machine_owner, 1)
        need(_readonly(model, definitions[name], 1) == (b'\x01', b'\x01'), 'one-byte ABI/cohort identity value')
    definitions[SLOT] = _bound(model, SLOT, 'STT_OBJECT', ('STB_LOCAL',), machine_owner, 4)
    slot = definitions[SLOT]
    need(slot['InputSection'] == SLOT_SECTION and slot['SectionSize'] == 4 and slot['SymbolOffset'] == 0
         and slot['OutputSection'] == '.bss' and slot['Entry'] % 4 == 0,
         'dedicated four-byte input slot and mapped final BSS role')
    for elf, row in ((machine, slot['Original']), (final, slot['Final'])):
        h = elf.sections[row['section']].header
        need(h.sh_type == 'SHT_NOBITS' and h.sh_flags & 7 == 3 and row['value'] % 4 == 0, 'zero-fill slot storage')
    for index, name in enumerate(EXPECTATIONS):
        definitions[name] = _bound(model, name, 'STT_OBJECT', ('STB_LOCAL', 'STB_GLOBAL'), machine_owner, 4)
        value = definitions[name]
        need(value['InputSection'] == value['OutputSection'] == EXPECTATION_SECTION and value['SymbolOffset'] == 4 * index,
             'exact original expectation object offset')
        _readonly(model, value, 4)
    definitions['pilot_context_roots'] = _bound(model, 'pilot_context_roots', 'STT_OBJECT', ('STB_GLOBAL',), machine_owner, 20)
    need(definitions['pilot_context_roots']['InputSection'] == definitions['pilot_context_roots']['OutputSection'] == '.pilot_roots'
         and definitions['pilot_context_roots']['SymbolOffset'] == 0, 'complete five-function consumer pointer array')
    _readonly(model, definitions['pilot_context_roots'], 20)
    tables = [_table(model, EXPECTATION_SECTION, (STORAGE, PRIVATE), definitions, emit_relocs, machine_owner),
              _table(model, '.pilot_roots', PUBLIC, definitions, emit_relocs, machine_owner)]
    definitions['pilot_vectors'] = _bound(model, 'pilot_vectors', 'STT_OBJECT', ('STB_GLOBAL',), startup_owner, 1024)
    vector = definitions['pilot_vectors']
    need(vector['InputSection'] == vector['OutputSection'] == '.isr_vector' and vector['SymbolOffset'] == 0
         and vector['Entry'] == 0 and vector['SectionSize'] == 1024, 'whole startup vector placement at zero')
    _, vector_bytes = _readonly(model, vector, 1024)
    vector_index, vector_section = _section(final, '.isr_vector')
    need(vector_section.header.sh_size == 1024 and vector_section.header.sh_addralign == 1024,
         'fixed 256-word vector extent/alignment')
    expected = [definitions['pilot_fault']['Final']['value']] * 256
    expected[0] = 0x20010000
    for index in (7, 8, 9, 10, 13):
        expected[index] = 0
    for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
        expected[index] = definitions[name]['Final']['value']
    need(list(struct.unpack('<256I', vector_bytes)) == expected
         and headers['Final']['Entry'] == definitions['Reset_Handler']['Final']['value'], 'exact strong-handler vector template and entry/MSP')
    return dict(Status='CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY', Profile='CM3', Mode='O2-lto', Linkage='direct',
        EmitRelocs=emit_relocs, FinalLinkContractValidated=True, Headers=headers, Attributes=attributes,
        Symbols=definitions, PointerTables=tables, LinkMapSha256=image.link_map_hash,
        Vectors=dict(Name='pilot_vectors', SectionIndex=vector_index, Address=0, Words=256, InitialMsp=expected[0],
                     Entry=headers['Final']['Entry'], Bytes=vector_bytes.hex(), StrongSlots=[1, 11, 14],
                     ZeroSlots=[7, 8, 9, 10, 13], DefaultFaultEntries=247, OriginalVectorRelocationsAudited=False),
        OriginalPointerRelocations=7, AppliedPointerRelocations=7 if emit_relocs else 0,
        Qualification=False, FullABIProof=False, SourceIRProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False, InstructionEquivalence=False,
        PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
