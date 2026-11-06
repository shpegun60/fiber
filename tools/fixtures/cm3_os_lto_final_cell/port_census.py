"""Pure CM3 Os-LTO machine census using explicitly supplied neutral helpers.

The caller authenticates helpers and supplies actual captured ELF/disassembly
bytes. This owns its Os predicates and result; it never relabels an O2 scan.
REL addends, final transfer protocols and worker provenance are separate proofs.
"""

import hashlib
import struct


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-PORT-CENSUS:' + detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def _scan(image, core, disassembly, policy, *, expected_undefined,
          surface=None, mandatory_locals=False):
    policy._header(image, core, image.final)
    definitions, functions, undefined = policy._symbols(image)
    need(undefined == sorted(expected_undefined), 'exact generated undefined surface')
    required = ()
    if surface is not None:
        need(type(surface) is dict and surface.get('IRDefinitionsValidated') is True,
             'validated IR definition surface')
        grouped = {role: [] for role in policy.ROLES}
        need(type(surface.get('Definitions')) is list, 'IR definition records')
        for row in surface['Definitions']:
            need(type(row) is dict and set(row) == {'Role', 'Name', 'Kind', 'Value', 'Size'}
                 and type(row['Role']) is str and row['Role'] in grouped, 'IR projection row')
            grouped[row['Role']].append({key: row[key] for key in ('Name', 'Kind', 'Value', 'Size')})
        surface = policy.inspect_ir_definitions(grouped)
        required = tuple(row['Name'] for row in surface['Definitions'])
        for row in surface['Definitions']:
            name = row['Name']
            need(name in definitions and definitions[name]['kind'] ==
                 ('STT_OBJECT' if row['Kind'] == 'D' else 'STT_FUNC'), 'retained IR kind/' + name)
        for name in policy.FORWARD + policy.NAKED:
            need(name in functions and functions[name]['binding'] == 'STB_GLOBAL',
                 'strong mandatory ABI/handler/' + name)
        if mandatory_locals:
            need(set(policy.LOCAL) <= set(functions), 'source-derived private helper extents')
    records = policy._disassembly(disassembly, image)
    consumed, pool_targets, loose_data, padding = set(), set(), [], []
    evidence = {}
    for name, item in functions.items():
        section = item['section']
        origin = image.sections[section].header.sh_addr if image.final else 0
        evidence[name] = dict(Name=name, Symbol=dict(item), Instructions=0, DataBytes=0, References=[],
            BodySha256=sha(image.section_read(section, (item['value'] & ~1) - origin, item['size'])))
    code_bytes = data_bytes = 0
    for section, segment in enumerate(image.sections):
        h = segment.header
        if not h.sh_flags & 4 or not h.sh_flags & 2 or not h.sh_size:
            continue
        need(h.sh_type == 'SHT_PROGBITS', 'file-backed executable section')
        origin = h.sh_addr if image.final else 0
        position, end = origin, origin + h.sh_size
        while position < end:
            mapping, limit = image.mapping(section, position)
            need(mapping in ('t', 'd') and type(limit) is int and position < limit,
                 'closed Thumb/data mappings')
            key = section, position
            need(key in records, 'missing byte-bound disassembly row')
            op, operands, raw = records[key]
            owners = [name for name, item in functions.items() if item['section'] == section
                      and (item['value'] & ~1) <= position < (item['value'] & ~1) + item['size']]
            need(len(owners) <= 1, 'unique complete-body owner')
            if mapping == 't':
                first = struct.unpack('<H', image.section_read(section, position - origin, 2))[0]
                width = core._width(first)
                need(type(width) is int and width in (2, 4) and len(raw) == width
                     and not op.startswith('.'), 'actual Thumb instruction width')
                policy._forms(op, operands, raw)
                if first & 0xF800 == 0x4800:
                    form = core._address_form(raw, position)
                    need(form is not None and form[0] == 'ldr', 'frozen literal form')
                    pool_targets.add((section, form[1]))
                if not owners:
                    need(raw in (bytes.fromhex('00bf'), bytes.fromhex('aff30080')),
                         'unowned executable non-NOP bytes')
                    padding.append(dict(Section=section, Address=position, Bytes=raw.hex()))
                else:
                    evidence[owners[0]]['Instructions'] += 1
                code_bytes += width
            else:
                width = len(raw)
                need((op, width) in (('.word', 4), ('.short', 2)), 'mapped literal descriptor')
                if owners:
                    evidence[owners[0]]['DataBytes'] += width
                else:
                    loose_data.append(dict(Section=section, Address=position, Size=width, Bytes=raw.hex()))
                data_bytes += width
            need(position + width <= min(limit, end)
                 and raw == image.section_read(section, position - origin, width),
                 'disassembly/mapping/raw-byte agreement')
            if owners:
                need(position + width <= (functions[owners[0]]['value'] & ~1) + functions[owners[0]]['size'],
                     'instruction/data crosses function extent')
            consumed.add(key)
            position += width
    need(set(records) == consumed, 'extra/unconsumed disassembly rows')
    for row in loose_data:
        need(row['Size'] == 4 and (row['Section'], row['Address']) in pool_targets,
             'unowned mapped pool word has actual LDR reference')
    refs, fields, used_imports = [], {}, set()
    for (section, offset), (kind, target) in sorted(image.relocations.items()):
        need(all(type(x) is int for x in (section, offset, kind)) and 0 < section < len(image.sections)
             and kind in (2, 10, 30) and offset >= 0 and target in image.symbols,
             'closed ABS32/THM_CALL/THM_JUMP24 original/applied REL')
        need(not policy.FORBIDDEN.search(target['name']), 'forbidden runtime REL target')
        h = image.sections[section].header
        need(h.sh_type == 'SHT_PROGBITS' and offset + 4 <= h.sh_size, 'complete file-backed REL field')
        need(all(other_section != section or offset + 4 <= other or other + 4 <= offset
                 for other_section, other in fields), 'nonoverlapping REL fields')
        fields[section, offset] = kind
        address = offset + (h.sh_addr if image.final else 0)
        owners = [name for name, item in functions.items() if item['section'] == section
                  and (item['value'] & ~1) <= address < (item['value'] & ~1) + item['size']]
        need(len(owners) <= 1, 'unique REL owner')
        raw, key = image.section_read(section, offset, 4), (section, address)
        if kind == 2:
            need(address % 4 == 0, 'word-aligned ABS32 field')
            if h.sh_flags & 4:
                mapping, limit = image.mapping(section, address)
                need(mapping == 'd' and address + 4 <= limit and key in consumed
                     and records[key][0] == '.word' and records[key][2] == raw,
                     'ABS32 executable site is complete mapped literal word')
            site = 'ABS32-DATA'
        else:
            need(address % 2 == 0 and h.sh_flags & 6 == 6 and len(owners) == 1,
                 'aligned uniquely owned Thumb transfer')
            mapping, limit = image.mapping(section, address)
            need(mapping == 't' and address + 4 <= limit and key in consumed
                 and records[key][0] == ('bl' if kind == 10 else 'b') and records[key][2] == raw
                 and address + 4 <= (functions[owners[0]]['value'] & ~1) + functions[owners[0]]['size'],
                 'REL transfer is complete byte-bound Thumb instruction')
            first, second = struct.unpack('<HH', raw)
            need(first & 0xF800 == 0xF000 and second & 0xD000 == (0xD000 if kind == 10 else 0x9000),
                 'REL kind agrees with BL/B.W encoding')
            site = 'THM_CALL-BL' if kind == 10 else 'THM_JUMP24-B.W'
        row = dict(Section=section, Offset=offset, Kind=kind, Target=dict(target),
            Owner=owners[0] if owners else None, SiteForm=site, SiteBytes=raw.hex(), FieldBytes=4,
            AddendSemanticsValidated=False, AppliedDestinationValidated=False)
        refs.append(row)
        if owners:
            evidence[owners[0]]['References'].append(row)
        if target['section'] == 'SHN_UNDEF':
            used_imports.add(target['name'])
    need(set(undefined) <= used_imports, 'every allowed external import has actual REL use')
    need(all(row['Instructions'] > 0 for row in evidence.values()), 'covered instructions in every function')
    return dict(Status='CM3-OS-LTO-PORT-CENSUS-PASS', Scope='CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY',
        Profile='CM3', Mode='Os-lto', ObjectSha256=sha(image.data), DisassemblySha256=sha(disassembly),
        FinalELF=image.final, FunctionsAudited=len(functions), FunctionEvidence=list(evidence.values()),
        DefinitionsFromIR=[dict(definitions[name]) for name in required], DefinitionSurface=surface,
        Undefined=undefined, AllowedMemoryHelpers=['memcpy', 'memset'], References=refs, Padding=padding,
        UnownedMappedPools=loose_data, ExecutableInstructionBytes=code_bytes, ExecutableMappedDataBytes=data_bytes,
        CompleteExecutableCensus=True, ForbiddenDependenciesAbsent=True, RecognizedForbiddenFormsAbsent=True,
        RecognizedForbiddenForms=list(policy.FORBIDDEN_FORMS), FullInstructionSemantics=False,
        SourceIRSemantics=False, OriginalTranslationUnitOwnership=False, AttributeOnlyProtection=False,
        GeneralRegistersOnlyEffectProved=False, WorkerProvenanceValidated=False,
        CanonicalRootProtocolsValidated=False, CPUExecution=False, BoardExecution=False,
        GlobalQualification=False, RequiredCellsSatisfied=0)


def inspect_lowered(image, core, disassembly, ir_definitions, policy, *, whole_image=False):
    need(type(whole_image) is bool and image.final is False, 'literal lowered role')
    need(type(ir_definitions) is dict and ir_definitions.get('IRDefinitionsValidated') is True,
         'mandatory lowered provider surface')
    return _scan(image, core, disassembly, policy,
        expected_undefined=policy.FINAL_WORKER_UNDEFINED if whole_image else policy.UNDEFINED,
        surface=ir_definitions, mandatory_locals=not whole_image)


def inspect_final(image, core, disassembly, ir_definitions, policy):
    need(image.final is True, 'final executable role')
    need(type(ir_definitions) is dict and ir_definitions.get('IRDefinitionsValidated') is True,
         'mandatory final provider surface')
    result = _scan(image, core, disassembly, policy, expected_undefined=(), surface=ir_definitions)
    definitions, functions, _ = policy._symbols(image)
    need('pilot_vectors' in definitions and 'Reset_Handler' in functions, 'fixed vector/startup providers')
    vector = definitions['pilot_vectors']
    need(vector['kind'] == 'STT_OBJECT' and vector['size'] == 1024 and vector['binding'] == 'STB_GLOBAL'
         and type(vector['section']) is int and 0 < vector['section'] < len(image.sections),
         '256-word strong vector table')
    h = image.sections[vector['section']].header
    need(image.names[vector['section']] == '.isr_vector' and h.sh_type == 'SHT_PROGBITS'
         and h.sh_flags & 2 and not h.sh_flags & 4, 'allocated file-backed vector section')
    loads = image.loads
    need(type(loads) is list and loads, 'actual final load image')
    for load in loads:
        need(type(load) is dict and all(type(load.get(key)) is int and load[key] >= 0
             for key in ('Vaddr', 'FileSize', 'MemorySize', 'Flags', 'Offset')),
             'literal final load fields')
    owners = [load for load in loads if load['Vaddr'] <= vector['value']
              and vector['value'] + 1024 <= load['Vaddr'] + load['MemorySize']]
    need(len(owners) == 1, 'unique vector load owner')
    owner = owners[0]
    file_offset = owner['Offset'] + vector['value'] - owner['Vaddr']
    need(owner['Flags'] & 4 and vector['value'] + 1024 <= owner['Vaddr'] + owner['FileSize']
         and file_offset == h.sh_offset + vector['value'] - h.sh_addr
         and file_offset + 1024 <= len(image.data), 'readable file-backed vector load coverage')
    raw = image.section_read(vector['section'], vector['value'] - h.sh_addr, 1024)
    need(image.data[file_offset:file_offset + 1024] == raw, 'vector section/load raw bytes agree')
    words = struct.unpack('<256I', raw)
    for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
        need(words[index] == functions[name]['value'], 'strong vector binding/' + name)
    need(image.elf.header.e_entry == functions['Reset_Handler']['value'], 'ELF entry binding')
    result['FinalRootVectorBindings'] = dict(VectorSha256=sha(raw), Words=256,
        Entry=words[1], SVC=words[11], PendSV=words[14], AllocatedFileBackedLoadValidated=True,
        CanonicalRootProtocolsValidated=False)
    return result


def inspect_stress(image, core, disassembly, policy, effects, effect_helpers, *, supported):
    need(type(supported) is bool, 'literal stress disposition')
    proof = effects.inspect_lowered(image, core, effect_helpers, stress=True,
                                    mutation=None if supported else effect_helpers.STRESS)
    if supported:
        clean = _scan(image, core, disassembly, policy, expected_undefined=())
        need({row['Name'] for row in clean['FunctionEvidence']} == {effect_helpers.STRESS},
             'ordinary supported stress carrier')
        return dict(Status='CM3-OS-LTO-PORT-STRESS-CLEAN', CleanMachine=clean, Effects=proof,
                    SupportedPolicy=True, RequiredCellsSatisfied=0)
    need(proof.get('StressFamiliesActivated') is True and proof.get('StressCounterEvidence') is not None,
         'actual raw stress families and carrier counter')
    rejected = False
    try:
        effects.inspect_lowered(image, core, effect_helpers, stress=True)
    except effects.Rejected:
        rejected = True
    need(rejected, 'unchanged clean predicate rejects raw stress')
    return dict(Status='CM3-OS-LTO-PORT-STRESS-EFFECTS-DETECTED', Effects=proof,
                SupportedPolicy=False, CleanPredicateRejected=True, RequiredCellsSatisfied=0)
