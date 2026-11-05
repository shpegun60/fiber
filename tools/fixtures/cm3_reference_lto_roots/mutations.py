"""Private actual-ELF controls for fixed reference CM3 LTO root transport."""
from pathlib import Path
import os
import re
import stat
import struct
from unittest.mock import patch


ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')
ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
SLOT, CALLEE = 'pxCurrentTCB', 'vTaskSwitchContext'
CASES = (
    ('machine-nonrelocation-byte', 'REF-LTO-PRESERVATION'),
    ('machine-bl-addend', 'REF-LTO-RELOC'),
    ('machine-slot-addend', 'REF-LTO-SLOT'),
    ('applied-slot-word', 'REF-LTO-SLOT'),
    ('coherent-slot-in-bss', 'REF-LTO-ORIGIN'),
    ('localized-slot', 'REF-LTO-SYMBOL'),
    ('wrong-slot-named-target', 'REF-LTO-RELOC'),
    ('function-alias', 'REF-LTO-SYMBOL'),
    ('slot-object-alias', 'REF-LTO-SYMBOL'),
    ('code-without-execute', 'REF-LTO-SYMBOL'),
    ('callee-data-mapping', 'REF-LTO-SYMBOL'),
    ('coherent-callee-entry', 'REF-LTO-ORIGIN'),
    ('wrong-machine-section-size', 'REF-LTO-ORIGIN'),
    ('foreign-map-provider', 'REF-LTO-ORIGIN'),
    ('missing-root-reference', 'REF-LTO-RELOC'),
    ('extra-root-reference', 'REF-LTO-RELOC'),
)


def need(condition, message):
    if not condition:
        raise ValueError('cm3-reference-lto-mutation: ' + message)


def stable_path(path):
    return Path(os.path.abspath(os.fspath(path)))


def _physical(path):
    selected = stable_path(path)
    for ancestor in (selected, *selected.parents):
        info = ancestor.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
             'private path reparse/symlink')
    need(selected.resolve(strict=True) == selected, 'private lexical/physical path mismatch')
    info = selected.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_ino != 0,
         'private regular single-link physical file required')
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_nlink)


def _symbol(elf, name):
    rows = [row for row in elf.symbols if row['name'] == name and row['section'] != 'SHN_UNDEF']
    need(len(rows) == 1, 'unique actual definition: ' + name)
    return rows[0]


def _symbol_offset(elf, symbol):
    need(len(elf.tables) == 1, 'one actual symbol table')
    table = elf.sections[next(iter(elf.tables))]
    need(table.header.sh_entsize == 16 and 0 <= symbol['index'] < table.header.sh_size // 16,
         'bounded ELF32 symbol field')
    return table.header.sh_offset + symbol['index'] * 16


def _address_offset(elf, section, address, size=4):
    h = elf.sections[section].header
    offset = address - (h.sh_addr if elf.final else 0)
    need(0 <= offset and offset + size <= h.sh_size and h.sh_type != 'SHT_NOBITS',
         'bounded file-backed patch address')
    return h.sh_offset + offset


def _relocation_offset(elf, section, address):
    found = []
    for row in elf.elf.iter_sections():
        if row.header.sh_type == 'SHT_REL' and row.header.sh_info == section:
            need(row.header.sh_entsize == 8, 'actual ELF32 REL extent')
            for index, rel in enumerate(row.iter_relocations()):
                if rel.entry.r_offset == address:
                    found.append(row.header.sh_offset + index * 8)
    need(len(found) == 1, 'unique actual relocation field')
    return found[0]


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


def _dis_line(data, section, address):
    text, current, offset, matches = data.decode('utf-8'), None, 0, []
    for line in text.splitlines(keepends=True):
        heading = re.fullmatch(r'Disassembly of section (.+):\s*', line)
        if heading:
            current = heading[1]
        row = re.fullmatch(r'\s*([0-9a-fA-F]+):\s+(.+?)\s*', line)
        if current == section and row and int(row[1], 16) == address:
            matches.append((offset, len(line.encode('utf-8')), line))
        offset += len(line.encode('utf-8'))
    need(len(matches) == 1, 'unique actual disassembly address')
    return matches[0]


def _dis_record(data, section, address):
    _, _, line = _dis_line(data, section, address)
    row = re.fullmatch(r'\s*[0-9a-fA-F]+:\s+([0-9a-fA-F]{8}|[0-9a-fA-F]{4}(?:\s+[0-9a-fA-F]{4})?)'
                       r'\s+([.]?[a-zA-Z][a-zA-Z0-9_.]*)(?:\s+(.*))?\s*', line)
    need(row is not None, 'actual disassembly record shape')
    words = row[1].split()
    raw = struct.pack('<I', int(words[0], 16)) if len(words) == 1 and len(words[0]) == 8 else \
        b''.join(struct.pack('<H', int(word, 16)) for word in words)
    operands = re.split(r'[;@]|\s+[0-9a-fA-F]+:\s+R_ARM_', row[3] or '')[0].strip()
    return raw, row[2], operands


def mutate(name, core, adapter, original, paths, edits):
    machine, final = original.machine, original.final
    svc, pend = _symbol(machine, ROOTS[1]), _symbol(machine, ROOTS[2])
    slot, final_svc, final_pend = _symbol(final, SLOT), _symbol(final, ROOTS[1]), _symbol(final, ROOTS[2])

    def edit(role, offset, data, length=None):
        path, before = paths[role], paths[role].read_bytes()
        length = len(data) if length is None else length
        need(0 <= offset and offset + length <= len(before), 'bounded private artifact patch')
        old = before[offset:offset + length]
        need(old != data, 'nonempty actual private edit')
        _physical(path)
        path.write_bytes(before[:offset] + data + before[offset + length:])
        edits.append(dict(Role=role, FileOffset=offset, Before=old.hex(), After=data.hex()))

    def disassembly(address, raw, target=None):
        offset, length, old = _dis_line(paths['Disassembly'].read_bytes(), final.sections[final_svc['section']].name, address)
        end = '\r\n' if old.endswith('\r\n') else '\n' if old.endswith('\n') else ''
        if target is None:
            word = struct.unpack('<I', raw)[0]
            text = ' %x:\t%08x \t.word\t0x%08x\t%x: R_ARM_ABS32\t%s' % (address, word, word, address, SLOT)
        else:
            a, b = struct.unpack('<HH', raw)
            text = ' %x:\t%04x %04x \tbl\t%x <%s>\t%x: R_ARM_THM_CALL\t%s' % (address, a, b, target, CALLEE, address, CALLEE)
        edit('Disassembly', offset, (text + end).encode('utf-8'), length)

    if name == 'machine-nonrelocation-byte':
        offset = _address_offset(machine, svc['section'], 0x54, 1)
        edit('Machine', offset, bytes([machine.data[offset] ^ 1]))
    elif name == 'machine-bl-addend':
        edit('Machine', _address_offset(machine, pend['section'], 0xB4), encode_bl(0xB4, 0xB8))
    elif name == 'machine-slot-addend':
        edit('Machine', _address_offset(machine, svc['section'], 0x74), struct.pack('<I', 4))
    elif name in ('applied-slot-word', 'coherent-slot-in-bss'):
        target = slot['value'] - 4
        selected = ((final_svc, 32), (final_pend, 64)) if name == 'coherent-slot-in-bss' else ((final_svc, 32),)
        for symbol, relative in selected:
            place = (symbol['value'] & ~1) + relative
            edit('Final', _address_offset(final, symbol['section'], place), struct.pack('<I', target))
            if name == 'coherent-slot-in-bss':
                disassembly(place, struct.pack('<I', target))
        if name == 'coherent-slot-in-bss':
            peer = _symbol(final, 'ulMaxPRIGROUPValue')
            need(peer['kind'] == 'STT_OBJECT' and peer['binding'] == 'STB_LOCAL' and peer['size'] == 4
                 and peer['section'] == slot['section'] and peer['value'] == target,
                 'fixed occupied neighboring BSS object')
            edit('Final', _symbol_offset(final, peer) + 4, struct.pack('<I', slot['value']))
            edits[-1].update(NeighborMetadataSwapped=True, OriginalName=peer['name'], ProviderSemanticsClaimed=False)
            edit('Final', _symbol_offset(final, slot) + 4, struct.pack('<I', target))
    elif name == 'localized-slot':
        edit('Final', _symbol_offset(final, slot) + 12, b'\x01')
    elif name == 'wrong-slot-named-target':
        wrong = _symbol(final, 'reference_failure_code')
        offset = _relocation_offset(final, final_svc['section'], (final_svc['value'] & ~1) + 32)
        edit('Final', offset + 4, struct.pack('<I', wrong['index'] << 8 | 2))
    elif name in ('function-alias', 'slot-object-alias'):
        target = _symbol(machine, SLOT) if name == 'slot-object-alias' else svc
        alias = _symbol(machine, 'reference_failure_code' if name == 'slot-object-alias' else 'reference_reset_forbidden')
        need(alias['kind'] == target['kind'], 'actual alias symbol role')
        edit('Machine', _symbol_offset(machine, alias) + 4, struct.pack('<II', target['value'], 4))
        if alias['section'] != target['section']:
            edit('Machine', _symbol_offset(machine, alias) + 14, struct.pack('<H', target['section']))
    elif name == 'code-without-execute':
        address = final_svc['value'] & ~1
        loads = [(index, row) for index, row in enumerate(final.elf.iter_segments())
                 if row.header.p_type == 'PT_LOAD' and row.header.p_vaddr <= address < row.header.p_vaddr + row.header.p_memsz]
        need(len(loads) == 1 and loads[0][1].header.p_flags & 1, 'actual executable load owner')
        index, row = loads[0]
        edit('Final', final.elf.header.e_phoff + index * final.elf.header.e_phentsize + 24,
             struct.pack('<I', row.header.p_flags & ~1))
    elif name == 'callee-data-mapping':
        callee = _symbol(machine, CALLEE)
        rows = [row for row in machine.symbols if row['name'].split('.')[0] == '$t'
                and row['section'] == callee['section'] and row['value'] == callee['value'] & ~1]
        need(len(rows) == 1, 'exact callee code mapping')
        table = machine.sections[next(iter(machine.tables))]
        position = machine.sections[table.header.sh_link].data().find(b'\x00$d\x00')
        need(position >= 0, 'existing raw data-mapping name')
        edit('Machine', _symbol_offset(machine, rows[0]), struct.pack('<I', position + 1))
    elif name == 'coherent-callee-entry':
        callee = _symbol(final, CALLEE)
        need(callee['size'] == 12, 'fixed actual callee extent')
        target, place = (callee['value'] & ~1) + 2, (final_pend['value'] & ~1) + 28
        edit('Final', _symbol_offset(final, callee) + 4, struct.pack('<II', callee['value'] + 2, callee['size'] - 2))
        raw = encode_bl(place, target)
        edit('Final', _address_offset(final, final_pend['section'], place), raw)
        disassembly(place, raw, target)
    elif name in ('wrong-machine-section-size', 'foreign-map-provider'):
        data = paths['LinkMap'].read_bytes()
        text = data.decode('utf-8')
        pattern = r'(?m)^\s+\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(' + re.escape(str(paths['OriginalMachine'])) + r')\s*$'
        matches = list(re.finditer(pattern, text))
        need(len(matches) == 1, 'unique full actual machine text placement')
        match = matches[0]
        group = 2 if name == 'wrong-machine-section-size' else 3
        replacement = hex(int(match[2], 16) - 2) if group == 2 else 'C:/unbound-reference-lto-machine.o'
        offset = len(text[:match.start(group)].encode('utf-8'))
        edit('LinkMap', offset, replacement.encode('utf-8'), len(match[group].encode('utf-8')))
    elif name in ('missing-root-reference', 'extra-root-reference'):
        address, target = (0xB4, 0xDC) if name == 'missing-root-reference' else (0x20, 0x7C)
        edit('Machine', _relocation_offset(machine, svc['section'], address), struct.pack('<I', target))
    else:
        raise ValueError('unknown fixed reference mutation')


def _coherence(name, core, original, paths, record):
    changed = core._ELF(paths['Final'], 'ET_EXEC')
    dis = paths['Disassembly'].read_bytes()
    if name == 'coherent-slot-in-bss':
        slot, old = _symbol(changed, SLOT), _symbol(original.final, SLOT)
        peer = _symbol(changed, 'ulMaxPRIGROUPValue')
        h = changed.sections[slot['section']].header
        need(slot['kind'] == 'STT_OBJECT' and slot['binding'] == 'STB_GLOBAL' and slot['size'] == 4
             and slot['value'] == old['value'] - 4 and slot['value'] % 4 == 0
             and slot['section'] == old['section'] and h.sh_type == 'SHT_NOBITS'
             and peer['binding'] == 'STB_LOCAL' and peer['kind'] == 'STT_OBJECT' and peer['size'] == 4
             and peer['section'] == slot['section'] and peer['value'] == old['value'], 'coherent BSS metadata swap')
        intervals = sorted((row['value'], row['value'] + row['size']) for row in changed.symbols
                           if row['kind'] == 'STT_OBJECT' and row['section'] == slot['section'] and row['size'] > 0)
        need(all(h.sh_addr <= a < b <= h.sh_addr + h.sh_size for a, b in intervals)
             and all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), 'coherent nonoverlapping BSS extents')
        for root, relative in ((ROOTS[1], 32), (ROOTS[2], 64)):
            symbol = _symbol(changed, root)
            place = (symbol['value'] & ~1) + relative
            raw = changed.data[_address_offset(changed, symbol['section'], place):][:4]
            shown, operation, operands = _dis_record(dis, changed.sections[symbol['section']].name, place)
            need(struct.unpack('<I', raw)[0] == slot['value'] and shown == raw and operation == '.word'
                 and int(operands, 16) == slot['value'], 'immutable both-slot-word/disassembly coherence')
        record.update(VerifiedCoherentSlotAddress=slot['value'], NeighborMetadataSwapped=True, ProviderSemanticsClaimed=False)
    else:
        callee, old = _symbol(changed, CALLEE), _symbol(original.final, CALLEE)
        pend = _symbol(changed, ROOTS[2])
        place = (pend['value'] & ~1) + 28
        offset = _address_offset(changed, pend['section'], place)
        raw = changed.data[offset:offset + 4]
        form = core._address_form(raw, place)
        shown, operation, operands = _dis_record(dis, changed.sections[pend['section']].name, place)
        need(callee['value'] == old['value'] + 2 and callee['size'] == old['size'] - 2
             and callee['kind'] == 'STT_FUNC' and callee['binding'] == 'STB_GLOBAL'
             and changed.mapping(callee['section'], callee['value'] & ~1)[0] == 't'
             and form is not None and form[0] == 'bl' and form[1] == callee['value'] & ~1
             and shown == raw and operation == 'bl' and int(operands.split()[0], 16) == form[1],
             'immutable final callee/BL/disassembly coherence')
        record['VerifiedCoherentBLTarget'] = form[1]
    record['ImmutableOriginControlCoherenceChecked'] = True


def run_cases(core, adapter, original, inputs, output):
    need(type(inputs) is dict and set(inputs) == set(ROLES), 'exact five input roles')
    need(tuple(adapter.ROOTS) == ROOTS and adapter.SLOT == SLOT and adapter.CALLEE == CALLEE,
         'fixed reference adapter only')
    need(len(CASES) == len({name for name, _ in CASES}) == 16, 'fixed sixteen-case catalog')
    for name, offset, size, binding in ((ROOTS[0], 0x78, 32, 'STB_LOCAL'),
                                      (ROOTS[1], 0x54, 36, 'STB_GLOBAL'), (ROOTS[2], 0x98, 68, 'STB_GLOBAL')):
        symbol = _symbol(original.machine, name)
        need(symbol['value'] == offset | 1 and symbol['size'] == size and symbol['binding'] == binding,
             'fixed actual reference machine layout')
    raw_read = Path.read_bytes
    originals = {role: stable_path(inputs[role]) for role in ROLES}
    identities = [_physical(path)[:2] for path in originals.values()]
    need(len(set(originals.values())) == len(set(identities)) == 5, 'five distinct physical original roles')
    source_bytes = {role: raw_read(path) for role, path in originals.items()}
    need(source_bytes['Machine'] == original.machine.data and source_bytes['Final'] == original.final.data,
         'actual original parser bytes bound to copied inputs')
    results = []
    for name, expected in CASES:
        directory = stable_path(Path(output) / 'mutants' / name)
        paths = {role: directory / (role + originals[role].suffix) for role in ROLES}
        paths['OriginalMachine'] = originals['Machine']
        record = dict(Name=name, Expected=expected, Status='FAIL', Edits=[], Files=[],
                      ImmutableInputBuffersConsumed=False, ClosingFilesVerified=0)
        results.append(record)
        try:
            directory.mkdir(parents=True, exist_ok=False)
            for role in ROLES:
                with paths[role].open('xb') as stream:
                    stream.write(source_bytes[role])
            mutate(name, core, adapter, original, paths, record['Edits'])
            need(record['Edits'], 'actual private artifact edits required')
            snapshots, physical = {}, {}
            for role in ROLES:
                path = stable_path(paths[role])
                physical[path] = _physical(path)
                snapshots[path] = raw_read(path)
                need(_physical(path) == physical[path], 'physical file changed while prebinding')
                record['Files'].append(dict(Role=role, Path=str(path), Sha256=core.sha256(snapshots[path]),
                    PhysicalIdentity=dict(Device=physical[path][0], FileId=physical[path][1], Links=physical[path][3])))
            need(len(set(value[:2] for value in physical.values())) == 5, 'five distinct physical private inputs')
            need({stable_path(path) for path in directory.iterdir()} == set(snapshots), 'exact private membership before parser')
            record['PrivateFilesBoundBeforeParser'] = 5
            consumed = set()

            def fixed_read(path):
                selected = stable_path(path)
                need(Path(path).is_absolute() and Path(path) == selected and selected in snapshots,
                     'unknown or noncanonical input outside strict immutable private buffers')
                consumed.add(selected)
                return snapshots[selected]

            rejected = False
            try:
                with patch.object(Path, 'read_bytes', fixed_read):
                    if name in ('coherent-slot-in-bss', 'coherent-callee-entry'):
                        need(snapshots[stable_path(paths['Machine'])] == original.machine.data,
                             'coherent final-only controls must not change machine')
                        _coherence(name, core, original, paths, record)
                    try:
                        candidate = adapter.ReferenceCM3LTOImage(core, paths['Machine'], paths['Final'], paths['Disassembly'],
                            provider_objects={str(originals['Machine']): paths['Machine'], str(originals['Startup']): paths['Startup']},
                            link_map=paths['LinkMap'])
                        for root in ROOTS:
                            candidate.function(root)
                    except core.Rejected as error:
                        record['Rejection'] = str(error)
                        rejected = re.search(r'^REJECT:' + expected + ':', str(error)) is not None
            finally:
                need({stable_path(path) for path in directory.iterdir()} == set(snapshots), 'closing exact private membership')
                for path, data in snapshots.items():
                    need(_physical(path) == physical[path] and raw_read(path) == data, 'closing physical identity/byte drift')
                record.update(ImmutableInputBuffersConsumed=True, ClosingFilesVerified=5,
                              ParserInputsRead=[role for role in ROLES if stable_path(paths[role]) in consumed])
            if rejected:
                record['Status'] = 'PASS'
        except Exception as error:
            record['Error'] = type(error).__name__ + ': ' + str(error)
    return results
