"""Private actual-ELF controls for fixed native CM3 LTO root transport."""
from pathlib import Path
import os
import re
import struct
from unittest.mock import patch


CASES = (
    ('machine-nonrelocation-byte', 'LTO-PRESERVATION'),
    ('machine-bl-addend', 'LTO-RELOC'),
    ('machine-slot-addend', 'LTO-SLOT'),
    ('applied-slot-word', 'LTO-SLOT'),
    ('coherent-slot-in-bss', 'LTO-(ORIGIN|SYMBOL)'),
    ('globalized-slot', 'LTO-SYMBOL'),
    ('wrong-slot-section-target', 'LTO-SLOT'),
    ('function-alias', 'LTO-SYMBOL'),
    ('slot-object-alias', 'LTO-SYMBOL'),
    ('code-without-execute', 'LTO-SYMBOL'),
    ('callee-data-mapping', 'LTO-SYMBOL'),
    ('coherent-callee-entry', 'LTO-ORIGIN'),
    ('wrong-machine-section-size', '(LTO-)?ORIGIN'),
    ('foreign-map-provider', '(LTO-)?ORIGIN'),
    ('missing-root-reference', 'LTO-RELOC'),
    ('extra-root-reference', 'LTO-RELOC'),
)


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-mutation: ' + message)


def stable_path(path):
    return Path(os.path.abspath(os.fspath(path)))


def encode_bl(place, target):
    need(type(place) is int and type(target) is int and 0 <= place < 1 << 32 and 0 <= target < 1 << 32
         and place % 2 == target % 2 == 0, 'bounded aligned BL addresses')
    displacement = target - place - 4
    need(displacement % 2 == 0 and -(1 << 24) <= displacement < (1 << 24), 'BL displacement')
    value = displacement & ((1 << 25) - 1)
    sign, i1, i2 = (value >> 24) & 1, (value >> 23) & 1, (value >> 22) & 1
    first = 0xF000 | sign << 10 | (value >> 12) & 1023
    second = 0xD000 | (1 ^ i1 ^ sign) << 13 | (1 ^ i2 ^ sign) << 11 | (value >> 1) & 2047
    return struct.pack('<HH', first, second)


def _symbol(elf, name):
    rows = [row for row in elf.symbols if row['name'] == name and row['section'] != 'SHN_UNDEF']
    need(len(rows) == 1, 'unique original symbol')
    return rows[0]


def _symbol_file_offset(elf, symbol):
    table = elf.sections[next(iter(elf.tables))]
    need(table.header.sh_entsize == 16, 'ELF32 symbol extent')
    return table.header.sh_offset + symbol['index'] * 16


def _address_offset(elf, section, address):
    h = elf.sections[section].header
    offset = address - (h.sh_addr if elf.final else 0)
    need(0 <= offset < h.sh_size and h.sh_type != 'SHT_NOBITS', 'file-backed patch address')
    return h.sh_offset + offset


def _relocation_offset(elf, section, address):
    found = []
    for row in elf.elf.iter_sections():
        if row.header.sh_type == 'SHT_REL' and row.header.sh_info == section:
            for index, rel in enumerate(row.iter_relocations()):
                if rel.entry.r_offset == address:
                    found.append(row.header.sh_offset + index * row.header.sh_entsize)
    need(len(found) == 1, 'unique actual relocation field')
    return found[0]


def mutate(name, core, adapter, original, paths, edits):
    machine, final = original.machine, original.final
    svc, slot = _symbol(machine, 'SVC_Handler'), _symbol(final, adapter.SLOT)
    final_svc = _symbol(final, 'SVC_Handler')
    def edit(role, offset, data):
        path = paths[role]
        before = path.read_bytes()
        need(0 <= offset and offset + len(data) <= len(before), 'bounded artifact patch')
        need(before[offset:offset + len(data)] != data, 'nonempty actual edit')
        path.write_bytes(before[:offset] + data + before[offset + len(data):])
        edits.append(dict(Role=role, FileOffset=offset, Before=before[offset:offset + len(data)].hex(), After=data.hex()))
    if name == 'machine-nonrelocation-byte':
        edit('Machine', _address_offset(machine, svc['section'], 0), bytes([machine.data[machine.sections[svc['section']].header.sh_offset] ^ 1]))
    elif name == 'machine-bl-addend':
        edit('Machine', _address_offset(machine, svc['section'], 0x72), bytes.fromhex('fff7ffff'))
    elif name == 'machine-slot-addend':
        edit('Machine', _address_offset(machine, svc['section'], 0xB4), struct.pack('<I', 4))
    elif name in ('applied-slot-word', 'coherent-slot-in-bss'):
        target = slot['value'] - 4
        for root in ('SVC_Handler', 'PendSV_Handler') if name == 'coherent-slot-in-bss' else ('SVC_Handler',):
            symbol = _symbol(final, root)
            relative = 0xB4 if root == 'SVC_Handler' else 0xC8
            edit('Final', _address_offset(final, symbol['section'], (symbol['value'] & ~1) + relative), struct.pack('<I', target))
        if name == 'coherent-slot-in-bss':
            edit('Final', _symbol_file_offset(final, slot) + 4, struct.pack('<I', target))
            changed = core._ELF(paths['Final'], 'ET_EXEC')
            changed_slot = _symbol(changed, adapter.SLOT)
            h = changed.sections[changed_slot['section']].header
            need(changed_slot['value'] == target and h.sh_type == 'SHT_NOBITS'
                 and h.sh_addr <= target and target + 4 <= h.sh_addr + h.sh_size, 'coherent valid-BSS slot definition')
            for root in ('SVC_Handler', 'PendSV_Handler'):
                symbol = _symbol(changed, root)
                relative = 0xB4 if root == 'SVC_Handler' else 0xC8
                offset = _address_offset(changed, symbol['section'], (symbol['value'] & ~1) + relative)
                need(struct.unpack_from('<I', changed.data, offset)[0] == target, 'both coherent slot words')
            edits[-1]['VerifiedCoherentSlotAddress'] = target
    elif name == 'globalized-slot':
        edit('Final', _symbol_file_offset(final, slot) + 12, b'\x11')
    elif name == 'wrong-slot-section-target':
        section_symbol = next(row for row in final.symbols if row['kind'] == 'STT_SECTION' and row['section'] == final_svc['section'])
        offset = _relocation_offset(final, final_svc['section'], (final_svc['value'] & ~1) + 0xB4)
        edit('Final', offset + 4, struct.pack('<I', section_symbol['index'] << 8 | 2))
    elif name in ('function-alias', 'slot-object-alias'):
        slot_case = name == 'slot-object-alias'
        target = _symbol(machine, adapter.SLOT) if slot_case else svc
        alias = next(row for row in machine.symbols if row['name'] not in (*adapter.ROOTS, *adapter.CALLEES, adapter.SLOT)
                     and row['kind'] == target['kind'] and type(row['section']) is int and row['section'] > 0 and row['size'] > 0)
        offset = _symbol_file_offset(machine, alias)
        if (alias['value'], alias['size']) != (target['value'], 4):
            edit('Machine', offset + 4, struct.pack('<II', target['value'], 4))
        if alias['section'] != target['section']:
            edit('Machine', offset + 14, struct.pack('<H', target['section']))
    elif name == 'code-without-execute':
        address = final_svc['value'] & ~1
        loads = [(index, segment) for index, segment in enumerate(final.elf.iter_segments())
                 if segment.header.p_type == 'PT_LOAD' and segment.header.p_vaddr <= address
                 < segment.header.p_vaddr + segment.header.p_memsz]
        need(len(loads) == 1, 'executable program-header owner')
        index, segment = loads[0]
        offset = final.elf.header.e_phoff + index * final.elf.header.e_phentsize + 24
        edit('Final', offset, struct.pack('<I', segment.header.p_flags & ~1))
    elif name == 'callee-data-mapping':
        callee = _symbol(machine, 'fiber_panic')
        mappings = [row for row in machine.symbols if row['name'].split('.')[0] == '$t'
                    and row['section'] == callee['section'] and row['value'] <= (callee['value'] & ~1)]
        mapping = max(mappings, key=lambda row: row['value'])
        table = machine.sections[next(iter(machine.tables))]
        strings = machine.sections[table.header.sh_link].data()
        position = strings.find(b'\x00$d\x00')
        need(position >= 0, 'existing raw data-mapping name')
        edit('Machine', _symbol_file_offset(machine, mapping), struct.pack('<I', position + 1))
    elif name == 'coherent-callee-entry':
        callee = _symbol(final, 'fiber_port_context_validate_restore')
        need(callee['size'] > 4, 'callee mutation extent')
        edit('Final', _symbol_file_offset(final, callee) + 4, struct.pack('<II', callee['value'] + 2, callee['size'] - 2))
        place = (final_svc['value'] & ~1) + 0x72
        edit('Final', _address_offset(final, final_svc['section'], place), encode_bl(place, (callee['value'] & ~1) + 2))
        changed = core._ELF(paths['Final'], 'ET_EXEC')
        changed_callee = _symbol(changed, 'fiber_port_context_validate_restore')
        offset = _address_offset(changed, final_svc['section'], place)
        form = core._address_form(changed.data[offset:offset + 4], place)
        need(form is not None and form[0] == 'bl' and form[1] == changed_callee['value'] & ~1,
             'coherent actual BL bits and final callee entry')
        edits[-1]['VerifiedCoherentBLTarget'] = form[1]
    elif name == 'wrong-machine-section-size':
        data = paths['LinkMap'].read_bytes()
        text = data.decode('utf-8')
        matches = list(re.finditer(r'(?m)^\s+\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+' + re.escape(str(paths['OriginalMachine'])) + r'\s*$', text))
        need(len(matches) == 1, 'unique full machine text placement')
        match = matches[0]
        changed = text[:match.start(2)] + hex(int(match[2], 16) - 2) + text[match.end(2):]
        paths['LinkMap'].write_bytes(changed.encode('utf-8'))
        edits.append(dict(Role='LinkMap', BeforeSha256=core.sha256(data), AfterSha256=core.sha256(changed.encode('utf-8'))))
    elif name == 'foreign-map-provider':
        data = paths['LinkMap'].read_bytes()
        changed = data.replace(str(paths['OriginalMachine']).encode('utf-8'), b'C:/unbound-lto-machine.o')
        need(changed != data, 'actual map provider replacement')
        paths['LinkMap'].write_bytes(changed)
        edits.append(dict(Role='LinkMap', BeforeSha256=core.sha256(data), AfterSha256=core.sha256(changed)))
    elif name in ('missing-root-reference', 'extra-root-reference'):
        address = 0x72 if name == 'missing-root-reference' else min(offset for (section, offset) in machine.relocations
                  if section == svc['section'] and 0x184 <= offset < 0x41C)
        offset = _relocation_offset(machine, svc['section'], address)
        edit('Machine', offset, struct.pack('<I', 0xB8 if name == 'missing-root-reference' else 2))
    else:
        raise ValueError('unknown fixed mutation')


def run_cases(core, adapter, original, inputs, output):
    results = []
    need(len(CASES) == 16 and len({row[0] for row in CASES}) == 16, 'fixed actual mutation catalog')
    for name, expected in CASES:
        directory = Path(output) / 'mutants' / name
        directory.mkdir(parents=True)
        paths = {}
        for role, source in inputs.items():
            target = directory / (role + Path(source).suffix)
            target.write_bytes(Path(source).read_bytes())
            paths[role] = target
        paths['OriginalMachine'] = Path(inputs['Machine'])
        record = dict(Name=name, Expected=expected, Status='FAIL', Edits=[])
        results.append(record)
        try:
            mutate(name, core, adapter, original, paths, record['Edits'])
            need(record['Edits'], 'actual private artifact edits required')
            snapshots = {stable_path(paths[role]): paths[role].read_bytes() for role in inputs}
            record['Files'] = [dict(Role=role, Path=str(paths[role]), Sha256=core.sha256(snapshots[stable_path(paths[role])]))
                               for role in inputs]
            def fixed_read(path):
                selected = stable_path(path)
                need(selected in snapshots, 'unknown private reader input outside immutable buffers')
                return snapshots[selected]
            rejected = False
            try:
                with patch.object(Path, 'read_bytes', fixed_read):
                    candidate = adapter.NativeCM3LTOImage(core, paths['Machine'], paths['Final'], paths['Disassembly'],
                        provider_objects={str(inputs['Machine']): paths['Machine'], str(inputs['Startup']): paths['Startup']},
                        link_map=paths['LinkMap'])
                    if name == 'coherent-callee-entry':
                        callee, svc = _symbol(candidate.final, 'fiber_port_context_validate_restore'), _symbol(candidate.final, 'SVC_Handler')
                        place = (svc['value'] & ~1) + 0x72
                        offset = _address_offset(candidate.final, svc['section'], place)
                        form = core._address_form(candidate.final.data[offset:offset + 4], place)
                        need(form is not None and form[0] == 'bl' and form[1] == callee['value'] & ~1,
                             'immutable callee/BL coherence')
                        record['ImmutableOriginControlCoherenceChecked'] = True
                    elif name == 'coherent-slot-in-bss':
                        slot = _symbol(candidate.final, adapter.SLOT)
                        for root in ('SVC_Handler', 'PendSV_Handler'):
                            symbol = _symbol(candidate.final, root)
                            relative = 0xB4 if root == 'SVC_Handler' else 0xC8
                            offset = _address_offset(candidate.final, symbol['section'], (symbol['value'] & ~1) + relative)
                            need(struct.unpack_from('<I', candidate.final.data, offset)[0] == slot['value'], 'immutable slot/literal coherence')
                        record['ImmutableOriginControlCoherenceChecked'] = True
                    for root in adapter.ROOTS:
                        candidate.function(root)
            except core.Rejected as error:
                record['Rejection'] = str(error)
                if re.search('REJECT:' + expected + ':', str(error)):
                    rejected = True
            need(all(path.read_bytes() == data for path, data in snapshots.items()), 'private reader input drift')
            need({stable_path(path) for path in directory.iterdir()} == set(snapshots), 'private artifact membership drift')
            record.update(ImmutableInputBuffersConsumed=True, ClosingFilesVerified=len(snapshots))
            if rejected:
                record['Status'] = 'PASS'
        except Exception as error:
            record['Error'] = type(error).__name__ + ': ' + str(error)
        if 'Files' not in record:
            record['Files'] = [dict(Role=role, Path=str(paths[role]), Sha256=core.sha256(paths[role].read_bytes())) for role in inputs]
    return results
