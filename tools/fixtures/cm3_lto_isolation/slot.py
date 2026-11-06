"""Pure bounded CM3 O2-LTO slot isolation over own merged-machine bytes.

Six complete common bodies are source-derived fixed code-generation protocols,
not hashes learned from an output. Handler obligations here are only their two
immediate address/load pairs; their complete canonical protocols are separate.
The caller authenticates source ownership, compiler recipes, parsers and images.
"""

import hashlib
import re
import struct


SLOT = 'fiber_internal_runtime_current_context_slot'
SECTION = '.bss.fiber_runtime_current_context_slot'
SCHEDULER = 'fiber_internal_runtime_scheduler_pick_next'
BARRIER = 'fiber_port_runtime_memory_barrier'
PUBLISHER = 'fiber_internal_runtime_publish_current_context'
HANDLERS = {'SVC_Handler': 0, 'PendSV_Handler': 1}
SYMBOL_KEYS = frozenset(('name', 'value', 'size', 'kind', 'binding', 'section', 'visibility', 'index'))

# These protocols retain guards, calls, branches, all stores and literal pools.
# 'align' is exactly the assembler's word-pool alignment, including any NOP.
PROGRAMS = {
    'fiber_internal_runtime_load_current_context': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r0,[r3]
pop {r3,pc}
align
pool:
word slot
''',
    'fiber_internal_runtime_context_configuration_is_open': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r2,[r3,#4]
cbnz r2,closed
ldr r2,pool+4
ldr r2,[r2]
cbz r2,checkfirst
closed:
bl fiber_port_runtime_memory_barrier
movs r0,#0
pop {r3,pc}
checkfirst:
ldr r3,[r3,#8]
cmp r3,#0
bne closed
bl fiber_port_runtime_memory_barrier
movs r0,#1
pop {r3,pc}
align
pool:
word scheduler
word slot
''',
    'fiber_internal_runtime_select_scheduler_candidate': '''
push {r4,r5,r6,lr}
mov r4,r0
cbz r0,first
ldr r5,pool
selected:
ldr r6,[r5]
bl fiber_port_runtime_memory_barrier
ldr r1,[r5,#16]
cbz r6,badpick
mov r0,r4
blx r6
cbz r0,badnext
pop {r4,r5,r6,pc}
first:
ldr r3,pool+4
ldr r3,[r3]
cbnz r3,already
ldr r5,pool
ldr r3,[r5,#8]
cbnz r3,already
ldr r3,[r5]
cbz r3,badpick
bl fiber_port_runtime_memory_barrier
movs r3,#1
str r3,[r5,#8]
bl fiber_port_runtime_memory_barrier
b selected
badpick:
movs r0,#75
bl fiber_panic
badnext:
movs r0,#78
bl fiber_panic
already:
movs r0,#107
bl fiber_panic
align
pool:
word scheduler
word slot
''',
    PUBLISHER: '''
push {r4,lr}
cbz r0,badnext
mov r4,r0
bl fiber_port_runtime_memory_barrier
ldr r3,pool
str r4,[r3]
pop {r4,lr}
b fiber_port_runtime_memory_barrier
badnext:
movs r0,#78
bl fiber_panic
align
pool:
word slot
''',
    'fiber_internal_runtime_require_current_context': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r3,[r3]
cbz r3,missing
pop {r3,lr}
b fiber_port_runtime_memory_barrier
missing:
movs r0,#71
bl fiber_panic
align
pool:
word slot
''',
    'ctxrt_v1_set_dispatcher': '''
push {r4,r5,r6,lr}
mov r4,r0
mov r5,r1
bl fiber_port_require_scheduler_configuration_environment
ldr r3,pool
ldr r3,[r3]
cbnz r3,already
ldr r6,pool+4
ldr r3,[r6,#8]
cbnz r3,already
cbz r4,badpick
bl fiber_port_runtime_memory_barrier
str r5,[r6,#16]
bl fiber_port_runtime_memory_barrier
str r4,[r6]
pop {r4,r5,r6,lr}
b fiber_port_runtime_memory_barrier
already:
movs r0,#107
bl fiber_panic
badpick:
movs r0,#75
bl fiber_panic
align
pool:
word slot
word scheduler
''',
}


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('REJECT:CM3-LTO-SLOT:' + message)


def integer(value, label, minimum=0):
    need(type(value) is int and minimum <= value <= 0xFFFFFFFF, 'literal integer/' + label)
    return value


def sha(raw):
    need(type(raw) is bytes, 'literal immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def normalized(text):
    text = re.sub(r'\s+', '', text.lower())
    text = re.sub(r'\[(r[0-7])\]', r'[\1,#0]', text)
    return text


def _fixed(op, args):
    """Encode only the named fixed protocol forms, not a general decoder."""
    if op in ('push', 'pop'):
        need(re.fullmatch(r'\{(?:r[0-7],)*(?:lr|pc)\}', args) is not None, 'fixed stack register list')
        registers = args[1:-1].split(',')
        need(len(registers) == len(set(registers)), 'unique stack registers')
        mask = sum(1 << int(reg[1:]) for reg in registers[:-1])
        if op == 'pop' and registers[-1] == 'lr':
            return struct.pack('<HH', 0xE8BD, mask | 0x4000)
        need(registers[-1] == ('lr' if op == 'push' else 'pc'), 'exact stack return role')
        return struct.pack('<H', (0xB500 if op == 'push' else 0xBD00) | mask)
    match = re.fullmatch(r'r([0-7]),r([0-7])', args)
    if op == 'mov' and match:
        return struct.pack('<H', 0x4600 | int(match[2]) << 3 | int(match[1]))
    match = re.fullmatch(r'r([0-7]),#([0-9]+)', args)
    if op in ('movs', 'cmp') and match:
        immediate = int(match[2])
        need(immediate < 256, 'fixed immediate range')
        return struct.pack('<H', (0x2000 if op == 'movs' else 0x2800) | int(match[1]) << 8 | immediate)
    match = re.fullmatch(r'r([0-7]),\[r([0-7]),#([0-9]+)\]', args)
    if op in ('ldr', 'str') and match:
        offset = int(match[3])
        need(offset % 4 == 0 and offset < 128, 'fixed word access offset')
        return struct.pack('<H', (0x6800 if op == 'ldr' else 0x6000)
                           | (offset // 4) << 6 | int(match[2]) << 3 | int(match[1]))
    if op == 'blx' and re.fullmatch(r'r[0-7]', args):
        return struct.pack('<H', 0x4780 | int(args[1:]) << 3)
    need(False, 'unsupported fixed protocol instruction: ' + op + ' ' + args)


def _program(text, aliases=None):
    """Resolve complete protocol labels/pools without dropping instructions."""
    rows, labels, position = [], {}, 0
    for line in text.splitlines():
        line = line.split('@', 1)[0].strip()
        if not line:
            continue
        if line in ('.syntax unified', '.thumb'):
            continue
        if line.endswith(':'):
            label = line[:-1].lower()
            need(re.fullmatch(r'[.A-Za-z_][.A-Za-z0-9_]*', label) is not None and label not in labels,
                 'unique local protocol label')
            labels[label] = position
            continue
        if line in ('align', '.align\t2', '.align 2'):
            rows.append((position, 'align', ''))
            position = (position + 3) & ~3
            continue
        parts = line.split(None, 1)
        need(len(parts) == 2, 'complete generated statement')
        op, args = parts[0], normalized(parts[1])
        if op == '.word':
            need(aliases is not None and args in aliases, 'only exact admitted section aliases in common pools')
            op, args = 'word', aliases[args]
        if op == 'word':
            need(args in ('slot', 'scheduler'), 'fixed pool role')
            width = 4
        elif op == 'ldr' and '[' not in args:
            op, width = 'literal', 2
        elif op == 'bl' or op == 'b' and not args.startswith('.') and args.startswith('fiber_'):
            width = 4
        elif op in ('b', 'bne', 'cbz', 'cbnz'):
            width = 2
        else:
            width = len(_fixed(op, args))
        rows.append((position, op, args))
        position += width
    resolved = []
    for offset, op, args in rows:
        if op == 'literal':
            register, expression = args.split(',', 1)
            match = re.fullmatch(r'([.A-Za-z_][.A-Za-z0-9_]*)(?:\+([0-9]+))?', expression)
            need(match is not None and match[1] in labels, 'local literal label')
            args = (register, labels[match[1]] + int(match[2] or 0))
        elif op in ('cbz', 'cbnz') or op in ('b', 'bne') and args in labels:
            register, label = args.split(',', 1) if op in ('cbz', 'cbnz') else ('', args)
            need(label in labels, 'complete local branch label')
            args = (register, labels[label])
        resolved.append((offset, op, args))
    return resolved, position


def _long_branch(place, target, call):
    delta = target - place - 4
    need(delta % 2 == 0 and -(1 << 24) <= delta < 1 << 24, 'bounded Thumb long branch')
    value = delta & ((1 << 25) - 1)
    s, i1, i2 = value >> 24 & 1, value >> 23 & 1, value >> 22 & 1
    return struct.pack('<HH', 0xF000 | s << 10 | (value >> 12 & 1023),
        (0xD000 if call else 0x9000) | (1 ^ i1 ^ s) << 13 | (1 ^ i2 ^ s) << 11 | (value >> 1 & 2047))


def _local_branch(op, args, offset):
    register, target = args
    delta = target - offset - 4
    need(delta % 2 == 0, 'aligned local branch')
    if op in ('cbz', 'cbnz'):
        need(re.fullmatch(r'r[0-7]', register) and 0 <= delta <= 126, 'fixed forward compare branch')
        word = 0xB100 | (op == 'cbnz') << 11 | (delta >> 6) << 9 | (delta >> 1 & 31) << 3 | int(register[1:])
    elif op == 'bne':
        need(-256 <= delta <= 254, 'fixed conditional branch range')
        word = 0xD100 | (delta >> 1 & 255)
    else:
        need(op == 'b' and -2048 <= delta <= 2046, 'fixed local branch range')
        word = 0xE000 | (delta >> 1 & 2047)
    return struct.pack('<H', word)


def _bytes(elf, section, offset, size):
    integer(section, 'section', 1)
    integer(offset, 'section offset')
    integer(size, 'byte count', 1)
    need(section < len(elf.sections), 'section index bounds')
    h = elf.sections[section].header
    need(h.sh_type == 'SHT_PROGBITS' and offset + size <= h.sh_size
         and h.sh_offset + offset + size <= len(elf.data), 'bounded real section bytes')
    return elf.data[h.sh_offset + offset:h.sh_offset + offset + size]


def _symbol(elf, name, kind, binding):
    rows = [row for row in elf.symbols if row.get('name') == name and row.get('section') != 'SHN_UNDEF']
    need(len(rows) == 1, 'unique definition: ' + name)
    row = rows[0]
    need(set(row) == SYMBOL_KEYS and row['kind'] == kind and row['binding'] == binding
         and row['visibility'] == 'STV_DEFAULT', 'exact symbol metadata: ' + name)
    for key in ('section', 'value', 'size', 'index'):
        integer(row[key], 'symbol/' + key, 1 if key in ('section', 'size') else 0)
    need(row['section'] < len(elf.sections) and row['index'] < len(elf.symbols)
         and elf.symbols[row['index']] == row, 'actual symbol table membership')
    start = row['value'] & ~1 if kind == 'STT_FUNC' else row['value']
    h = elf.sections[row['section']].header
    base = h.sh_addr if elf.final else 0
    need(base <= start and start + row['size'] <= base + h.sh_size, 'complete symbol extent')
    for other in elf.symbols:
        if other['name'] == name or other['section'] != row['section'] or other['kind'] != kind:
            continue
        begin = other['value'] & ~1 if kind == 'STT_FUNC' else other['value']
        need(not other['size'] or not (begin < start + row['size'] and start < begin + other['size']),
             'overlapping positive-size alias')
    if kind == 'STT_FUNC':
        need(row['value'] & 1 and row['size'] % 2 == 0 and h.sh_type == 'SHT_PROGBITS'
             and h.sh_flags & 7 == 6, 'complete Thumb executable function')
    return row


def _origin(image, name, kind='STT_FUNC', binding='STB_GLOBAL'):
    before, after = _symbol(image.prelink, name, kind, binding), _symbol(image.final, name, kind, binding)
    providers = [(key, elf) for key, elf in image.providers.items() if any(
        row['name'] == name and row['section'] != 'SHN_UNDEF' for row in elf.symbols)]
    need(len(providers) == 1 and providers[0][1].data == image.prelink.data, 'own generated-machine provider')
    owner = providers[0][0]
    h = image.prelink.sections[before['section']].header
    section = image.prelink.sections[before['section']].name
    need(sum(row.name == section for row in image.prelink.sections) == 1, 'unique input section name')
    placement = image.placements.get((owner, section))
    need(type(placement) is tuple and len(placement) == 2 and all(type(x) is int for x in placement)
         and placement[1] == h.sh_size and h.sh_addr == 0, 'complete actual input-section placement')
    offset = before['value'] & ~1 if kind == 'STT_FUNC' else before['value']
    entry = after['value'] & ~1 if kind == 'STT_FUNC' else after['value']
    last = image.final.sections[after['section']].header
    need(placement[0] + offset == entry and before['size'] == after['size']
         and placement[0] % max(1, h.sh_addralign) == 0
         and last.sh_addr <= placement[0] and placement[0] + placement[1] <= last.sh_addr + last.sh_size
         and h.sh_type == last.sh_type and h.sh_flags & 7 == last.sh_flags & 7,
         'map-bound function/object origin, size and storage')
    return dict(Name=name, Provider=owner, Original=before, Final=after, Size=before['size'],
        SymbolOffset=offset, Entry=entry, InputSection=section, InputSectionIndex=before['section'],
        OutputSectionIndex=after['section'], OutputSectionOffset=entry - last.sh_addr,
        SectionAddress=placement[0], SectionSize=placement[1])


def _raw_target(elf, row):
    need(type(row) is dict and set(row) == SYMBOL_KEYS, 'complete raw REL target')
    index = integer(row['index'], 'REL symbol index')
    need(index < len(elf.symbols) and all(type(row[key]) is type(elf.symbols[index][key])
         and row[key] == elf.symbols[index][key] for key in SYMBOL_KEYS), 'actual raw REL symbol membership')
    return row


def _mapped(elf, section, address, size, kind):
    actual, end = elf.mapping(section, address)
    need(type(end) is int and actual == kind and address + size <= end, 'whole instruction/data mapping')


def _port_source(raw):
    text = raw.decode('ascii')
    comment = r'/\*(?:[^*]|\*(?!/))*\*/'
    pair = re.compile(r'"ldr[ \t]+(?P<r>r[01]),[ \t]*=' + SLOT
        + r'[ \t]*\\n"(?P<trivia>(?:\s|' + comment + r')*)'
        + r'"ldr[ \t]+(?P=r),[ \t]*\[(?P=r)\][ \t]*\\n"')
    rows = list(pair.finditer(text))
    need(len(re.findall(r'\b' + SLOT + r'\b', text)) == len(rows) == 2
         and {row['r'] for row in rows} == {'r0', 'r1'}
         and all('\\' not in row['trivia'] for row in rows), 'only two source inline address/load pairs')
    return [dict(Register=row['r'], SourceLine=text.count('\n', 0, row.start()) + 1) for row in rows]


def _assembly(raw):
    text = raw.decode('ascii')
    definition = re.compile(r'(?m)^\s*\.section\s+' + re.escape(SECTION)
        + r',"aw",%nobits\s*\n\s*\.align\s+2\s*\n\s*\.set\s+(?P<alias>\.LANCHOR[0-9]+),\.\s*\+\s*0\s*\n'
        + r'\s*\.type\s+' + SLOT + r',\s*%object\s*\n\s*\.size\s+' + SLOT + r',\s*4\s*\n'
        + SLOT + r':\s*\n\s*\.space\s+4\s*(?=\n\s*\.section)')
    definitions = list(definition.finditer(text))
    need(len(definitions) == 1, 'one complete dedicated four-byte local slot definition')
    alias = definitions[0]['alias']
    base = re.findall(r'(?m)^\s*\.bss\s*\n\s*\.align\s+[0-9]+\s*\n\s*\.set\s+'
        r'(\.LANCHOR[0-9]+),\.\s*\+\s*0\s*\n\s*\.type\s+' + SCHEDULER + r',\s*%object', text)
    need(len(base) == 1 and base[0] != alias, 'distinct scheduler BSS section alias')
    aliases = {alias.lower(): 'slot', base[0].lower(): 'scheduler'}
    functions, handler_rows, spans = {}, [], [definitions[0].span()]
    for name in (*PROGRAMS, *HANDLERS):
        starts = list(re.finditer(r'(?m)^' + name + r':\s*$', text))
        ends = list(re.finditer(r'(?m)^\s*\.size\s+' + name + r',\s*\.-' + name + r'\s*$', text))
        need(len(starts) == len(ends) == 1 and starts[0].end() < ends[0].start(), 'one complete generated body: ' + name)
        body = text[starts[0].end():ends[0].start()]
        if name in PROGRAMS:
            actual = _program(body, aliases)
            expected = _program(PROGRAMS[name])
            need(actual == expected, 'complete source-derived generated common body: ' + name)
            functions[name] = expected
            # An alias is admitted only as the complete operand of a matched word.
            for match in re.finditer(r'(?m)^\s*\.word\s+' + re.escape(alias) + r'\s*$', body):
                spans.append((starts[0].end() + match.start(), starts[0].end() + match.end()))
        else:
            register = 'r' + str(HANDLERS[name])
            pair = list(re.finditer(r'(?m)^[ \t]*ldr[ \t]+' + register + r',[ \t]*=' + SLOT
                + r'[ \t]*\r?\n[ \t]*ldr[ \t]+' + register + r',[ \t]*\[' + register + r'\][ \t]*\r?$', body))
            need(len(pair) == 1, 'one immediate generated handler address/load pair: ' + name)
            begin, end = starts[0].end() + pair[0].start(), starts[0].end() + pair[0].end()
            spans.append((begin, end))
            handler_rows.append(dict(Owner=name, Register=register, GeneratedLine=text.count('\n', 0, begin) + 1))
    # This textual membership check supplements, never replaces, the ELF REL scan.
    for token in (SLOT, alias):
        mentions = list(re.finditer(r'(?<![A-Za-z0-9_.])' + re.escape(token) + r'(?![A-Za-z0-9_])', text))
        need(all(any(start <= row.start() < row.end() <= end for start, end in spans) for row in mentions),
             'unclassified generated slot definition, alias use or address escape')
    need(len(re.findall(r'(?m)^\s*\.set\s+' + re.escape(alias) + r',', text)) == 1,
         'slot alias defined exactly once')
    return functions, handler_rows, alias


class Audit:
    def __init__(self, image, core, emitted):
        self.image, self.core, self.emitted = image, core, emitted
        self.machine, self.final = image.prelink, image.final
        self.slot = _origin(image, SLOT, 'STT_OBJECT', 'STB_LOCAL')
        self.scheduler = _origin(image, SCHEDULER, 'STT_OBJECT', 'STB_LOCAL')
        slot = self.slot
        h = self.machine.sections[slot['InputSectionIndex']].header
        last = self.final.sections[slot['OutputSectionIndex']].header
        need(slot['Size'] == slot['SectionSize'] == 4 and slot['SymbolOffset'] == 0
             and slot['InputSection'] == SECTION and h.sh_type == last.sh_type == 'SHT_NOBITS'
             and h.sh_flags & 7 == last.sh_flags & 7 == 3 and h.sh_addralign >= 4
             and slot['Entry'] % 4 == 0, 'dedicated mapped local four-byte writable slot')
        loads = [row for row in self.final.loads if row['Vaddr'] <= slot['Entry']
                 and slot['Entry'] + 4 <= row['Vaddr'] + row['MemorySize']]
        need(len(loads) == 1 and loads[0]['Flags'] & 3 == 2
             and slot['Entry'] >= loads[0]['Vaddr'] + loads[0]['FileSize'], 'slot is zero-fill, non-executable writable load')
        need(self.scheduler['Provider'] == slot['Provider'] and self.scheduler['Size'] == 4
             and self.scheduler['SymbolOffset'] == 0 and self.scheduler['InputSection'] == '.bss',
             'distinct complete base scheduler object for other common state accesses')
        self.expected_slot, self.used_final, self.origins = set(), set(), {}

    def origin(self, name):
        if name not in self.origins:
            self.origins[name] = _origin(self.image, name)
        return self.origins[name]

    def record(self, origin, offset, raw, op=None, operands=None, data=False):
        section = origin['OutputSectionIndex']
        address = origin['Entry'] + offset
        entry = self.image.instructions.get((section, address))
        if data and entry is None and (section, address) not in self.image.instructions:
            return
        need(type(entry) is tuple and len(entry) == 3 and entry[2] == raw
             and (op is None or entry[0] == op)
             and (operands is None or normalized(entry[1]) == normalized(operands)), 'final instruction/data text bound to exact bytes')
        need(not any((section, address + n) in self.image.instructions for n in range(1, len(raw))),
             'interior disassembly record')

    def bytes(self, origin, offset, size, kind):
        at = origin['SymbolOffset'] + offset
        final_offset = origin['OutputSectionOffset'] + offset
        need(0 <= offset and offset + size <= origin['Size'], 'full field inside containing function')
        before = _bytes(self.machine, origin['InputSectionIndex'], at, size)
        after = _bytes(self.final, origin['OutputSectionIndex'], final_offset, size)
        _mapped(self.machine, origin['InputSectionIndex'], at, size, kind)
        _mapped(self.final, origin['OutputSectionIndex'], origin['Entry'] + offset, size, kind)
        return before, after

    def reference(self, origin, offset, kind, definition, *, section_target=False):
        input_key = origin['InputSectionIndex'], origin['SymbolOffset'] + offset
        final_key = origin['OutputSectionIndex'], origin['OutputSectionOffset'] + offset
        before, after = self.bytes(origin, offset, 4, 'd' if kind == 2 else 't')
        refs = []
        for elf, key, required in ((self.machine, input_key, True), (self.final, final_key, self.emitted)):
            value = elf.relocations.get(key)
            if not required:
                need(value is None, 'ordinary selected site has no applied REL')
                refs.append(None)
                continue
            need(type(value) is tuple and len(value) == 2 and type(value[0]) is int and value[0] == kind,
                 'exact original/applied relocation kind and site')
            target = _raw_target(elf, value[1])
            expected = definition['Final' if elf.final else 'Original']
            if section_target:
                need(target['name'] == '' and target['kind'] == 'STT_SECTION' and target['binding'] == 'STB_LOCAL'
                     and target['visibility'] == 'STV_DEFAULT' and type(target['section']) is int
                     and target['section'] == expected['section'] and type(target['size']) is int and target['size'] == 0
                     and type(target['value']) is int and target['value'] == (
                         elf.sections[target['section']].header.sh_addr if elf.final else 0), 'raw empty-name section target, never relabelled')
            else:
                need(all(type(target[k]) is type(expected[k]) and target[k] == expected[k] for k in SYMBOL_KEYS),
                     'exact named call definition')
            need(not any(sec == key[0] and other != key[1] and other < key[1] + 4 and key[1] < other + 4
                         for sec, other in elf.relocations), 'no overlapping selected relocation field')
            refs.append(dict(target))
        if kind == 2:
            need(before == bytes(4) and after == struct.pack('<I', definition['Entry']), 'section ABS32 zero addend and applied exact object address')
            if definition is self.slot:
                self.expected_slot.add(input_key)
        else:
            need(before == _long_branch(input_key[1], input_key[1], kind == 10)
                 and after == _long_branch(origin['Entry'] + offset, definition['Entry'], kind == 10),
                 'named original branch REL -4 and independently encoded applied destination')
            self.record(origin, offset, after, 'bl' if kind == 10 else 'b')
            operand = self.image.instructions[origin['OutputSectionIndex'], origin['Entry'] + offset][1]
            target_text = re.fullmatch(r'([0-9a-fA-F]+)(?:\s+<[^>]+>)?', operand)
            need(target_text is not None and int(target_text[1], 16) == definition['Entry'], 'final branch text and bits agree')
        if self.emitted:
            need(final_key not in self.used_final, 'applied reference not consumed twice')
            self.used_final.add(final_key)
        return dict(Owner=origin['Name'], FunctionOffset=offset, Kind=kind,
            InputSectionIndex=input_key[0], InputOffset=input_key[1], Address=origin['Entry'] + offset,
            OriginalRelocationSymbol=refs[0], FinalRelocationSymbol=refs[1],
            OriginalBytes=before.hex(), FinalBytes=after.hex(), Target=definition['Name'])

    def common(self, name, program):
        origin = self.origin(name)
        rows, size = program
        need(origin['Size'] == size and origin['SymbolOffset'] % 4 == 0 and origin['Entry'] % 4 == 0,
             'complete word-aligned fixed common body size')
        used, addresses, references = set(), set(), []
        for offset, op, args in rows:
            addresses.add(origin['Entry'] + offset)
            if op == 'word':
                definition = self.slot if args == 'slot' else self.scheduler
                references.append(self.reference(origin, offset, 2, definition, section_target=True))
                used.add(origin['SymbolOffset'] + offset)
                self.record(origin, offset, bytes.fromhex(references[-1]['FinalBytes']), data=True)
                continue
            if op in ('bl', 'b') and type(args) is str:
                references.append(self.reference(origin, offset, 10 if op == 'bl' else 30, self.origin(args)))
                used.add(origin['SymbolOffset'] + offset)
                continue
            if op == 'align':
                count = (-offset) % 4
                if count:
                    need(count == 2, 'bounded exact alignment NOP')
                    before, after = self.bytes(origin, offset, count, 't')
                    need(before == after == b'\x00\xbf', 'retained actual Thumb alignment NOP')
                    self.record(origin, offset, after, 'nop', '')
                continue
            if op == 'literal':
                register, target = args
                delta = target - ((offset + 4) & ~3)
                need(re.fullmatch(r'r[0-7]', register) and delta % 4 == 0 and 0 <= delta <= 1020,
                     'complete local literal load')
                expected = struct.pack('<H', 0x4800 | int(register[1:]) << 8 | delta // 4)
            elif type(args) is tuple:
                expected = _local_branch(op, args, offset)
            else:
                expected = _fixed(op, args)
            before, after = self.bytes(origin, offset, len(expected), 't')
            need(before == after == expected and self.core._width(struct.unpack_from('<H', before)[0]) == len(expected),
                 'exact source-derived instruction encoding')
            display_op, display_args = op, args
            if op == 'pop' and args.endswith('lr}'):
                display_op, display_args = 'ldmia', 'sp!,' + args
            if op == 'literal':
                display_op, display_args = 'ldr', None
            elif type(args) is tuple:
                display_args = None
            self.record(origin, offset, after, display_op, display_args)
            if op == 'literal':
                form = self.core._address_form(after, origin['Entry'] + offset)
                need(form is not None and form[:3] == ('ldr', origin['Entry'] + args[1], int(args[0][1:])),
                     'literal load bits point at prescribed complete pool word')
        for elf, section, start in ((self.machine, origin['InputSectionIndex'], origin['SymbolOffset']),
                                    (self.final, origin['OutputSectionIndex'], origin['OutputSectionOffset'])):
            actual = {offset for sec, offset in elf.relocations if sec == section and start <= offset < start + size}
            expected = {offset - origin['SymbolOffset'] + start for offset in used} if not elf.final or self.emitted else set()
            need(actual == expected, 'complete body relocation membership')
        need(not any(section == origin['OutputSectionIndex'] and origin['Entry'] <= address < origin['Entry'] + size
                     and address not in addresses for section, address in self.image.instructions), 'unclassified body disassembly record')
        before = _bytes(self.machine, origin['InputSectionIndex'], origin['SymbolOffset'], size)
        after = _bytes(self.final, origin['OutputSectionIndex'], origin['OutputSectionOffset'], size)
        return dict(Name=name, Origin=origin, MachineBodySha256=sha(before), FinalBodySha256=sha(after),
            CompleteBodyValidated=True, Size=size, References=references, TailNops=0)

    def handlers(self):
        rows = []
        machine_words, final_words = self.slot_word_positions()
        for name, register in HANDLERS.items():
            origin = self.origin(name)
            refs = [(offset, value) for (section, offset), value in self.machine.relocations.items()
                    if section == origin['InputSectionIndex'] and origin['SymbolOffset'] <= offset
                    < origin['SymbolOffset'] + origin['Size'] and value[1]['section'] == self.slot['InputSectionIndex']]
            need(len(refs) == 1 and refs[0][1][0] == 2, 'one section-backed handler slot literal')
            pool = refs[0][0] - origin['SymbolOffset']
            evidence = self.reference(origin, pool, 2, self.slot, section_target=True)
            machine_loads = self.handler_loads(self.machine, origin['InputSectionIndex'], origin['SymbolOffset'],
                origin['Size'], origin['SymbolOffset'] + pool, machine_words)
            final_loads = self.handler_loads(self.final, origin['OutputSectionIndex'], origin['Entry'],
                origin['Size'], origin['Entry'] + pool, final_words)
            need(machine_loads == final_loads and len(machine_loads) == 1 and machine_loads[0][1] == register,
                 'both handler streams have the same single narrow slot literal load')
            offset = machine_loads[0][0]
            first, applied = self.bytes(origin, offset, 2, 't')
            following, applied_next = self.bytes(origin, offset + 2, 2, 't')
            expected_load = struct.pack('<H', 0x6800 | register << 3 | register)
            need(first == applied and following == applied_next == expected_load,
                 'immediate load-only slot dereference, no intervening escape or store')
            self.record(origin, offset, applied, 'ldr')
            self.record(origin, offset + 2, applied_next, 'ldr', 'r%d,[r%d,#0]' % (register, register))
            evidence.update(Register='r' + str(register), LoadOffset=offset, DereferenceOffset=offset + 2,
                MachineLiteralLoads=len(machine_loads), FinalLiteralLoads=len(final_loads),
                BothInstructionStreamsCensused=True, UnsupportedPCAddressFormsRejected=True,
                SlotBearingWordsCensused=len(machine_words), CrossOwnerSlotLiteralUsesRejected=True)
            rows.append(evidence)
        return rows

    def slot_word_positions(self):
        """Project every original slot-bearing word, even on nonemit finals.

        The input section/REL census is authority; final emitted REL presence
        is deliberately not needed to discover the cross-pool address domain.
        """
        machine_words, final_words = set(), set()
        for (section, offset), (kind, target) in self.machine.relocations.items():
            _raw_target(self.machine, target)
            if target['section'] != self.slot['InputSectionIndex'] and target['name'] != SLOT:
                continue
            need(type(kind) is int and kind == 2, 'only ABS32 slot-bearing words')
            integer(section, 'slot word section', 1)
            integer(offset, 'slot word offset')
            need(section < len(self.machine.sections), 'slot word section bounds')
            source = self.machine.sections[section]
            h = source.header
            placement = self.image.placements.get((self.slot['Provider'], source.name))
            need(type(placement) is tuple and len(placement) == 2 and all(type(v) is int for v in placement)
                 and h.sh_addr == 0 and placement[1] == h.sh_size
                 and placement[0] % max(1, h.sh_addralign) == 0
                 and offset % 4 == 0 and offset + 4 <= h.sh_size
                 and sum(row.name == source.name for row in self.machine.sections) == 1,
                 'whole input-section authority for every slot-bearing word')
            address = placement[0] + offset
            outputs = [(index, row) for index, row in enumerate(self.final.sections)
                       if row.header.sh_flags & 2 and row.header.sh_addr <= placement[0]
                       and placement[0] + placement[1] <= row.header.sh_addr + row.header.sh_size]
            need(len(outputs) == 1, 'unique complete output placement for slot-bearing words')
            output, last = outputs[0]
            need(h.sh_type == last.header.sh_type == 'SHT_PROGBITS'
                 and h.sh_flags & 7 == last.header.sh_flags & 7,
                 'slot-bearing word input/output storage agreement')
            _mapped(self.machine, section, offset, 4, 'd')
            _mapped(self.final, output, address, 4, 'd')
            need(_bytes(self.machine, section, offset, 4) == bytes(4)
                 and _bytes(self.final, output, address - last.header.sh_addr, 4)
                 == struct.pack('<I', self.slot['Entry']), 'all slot-bearing word bytes and applied values')
            machine_words.add((section, offset))
            need(address not in final_words, 'slot-bearing word placements cannot alias')
            final_words.add(address)
        need(len(machine_words) == len(final_words) == 8, 'complete eight-word slot literal address domain')
        return machine_words, final_words

    def handler_loads(self, elf, section, start, size, pool, slot_words):
        """Census both streams; no unsupported PC-based alias route is skipped.

        Only narrow word LDR literals are interpreted. Other legal literal/
        address forms fail closed rather than treating unknown bytes as inert.
        This width/mapping walk is not a complete handler instruction decoder.
        """
        address, end, loads = start, start + size, []
        while address < end:
            kind, boundary = elf.mapping(section, address)
            need(type(boundary) is int and boundary > address, 'bounded handler mapping')
            if kind == 'd':
                address = min(boundary, end)
                continue
            need(kind == 't', 'only Thumb/data handler mapping')
            section_base = elf.sections[section].header.sh_addr if elf.final else 0
            first = _bytes(elf, section, address - section_base, 2)
            word = struct.unpack('<H', first)[0]
            width = self.core._width(word)
            need(type(width) is int and width in (2, 4) and address + width <= min(boundary, end),
                 'complete handler instruction')
            if width == 2:
                need(word & 0xF800 != 0xA000, 'unsupported narrow ADR/PC-address construction')
                need(not (word & 0xFC00 == 0x4400 and (word >> 8) & 3 in (0, 2)
                          and (word >> 3) & 15 == 15), 'unsupported narrow ADD/MOV from PC')
                if word & 0xF800 == 0x4800:
                    form = self.core._address_form(first, address)
                    need(form is not None and form[0] == 'ldr', 'narrow literal decoding')
                    is_slot = form[1] in slot_words if elf.final else (section, form[1]) in slot_words
                    if is_slot:
                        need(form[1] == pool, 'cross-owner slot literal use in handler stream')
                        loads.append((address - start, form[2]))
            else:
                # F8/F9: word/byte/halfword/signed and preload PC-base forms.
                # E8/E9: doubleword/table and other PC-base memory forms.
                # EC/ED: coprocessor/VFP literals. F20F/F2AF: ADR ADDW/SUBW.
                need(word & 0xFE0F not in (0xF80F, 0xE80F)
                     and word & 0xEE0F != 0xEC0F and word & 0xFB0F != 0xF20F,
                     'unsupported T32 PC literal/address form in handler stream')
            address += width
        return loads

    def all_slot_references(self):
        found = set()
        for owner, elf in self.image.providers.items():
            for key, (kind, target) in elf.relocations.items():
                _raw_target(elf, target)
                target_section = target['section']
                touches = (target['name'] == SLOT or type(target_section) is int
                    and 0 < target_section < len(elf.sections) and elf.sections[target_section].name == SECTION)
                if touches:
                    need(owner == self.slot['Provider'] and kind == 2, 'no foreign or non-ABS32 slot alias reference')
                    found.add(key)
        need(found == self.expected_slot and len(found) == 8, 'all eight original slot section/alias references, no escapes')
        actual_final = set()
        for key, (kind, target) in self.final.relocations.items():
            _raw_target(self.final, target)
            if target['section'] == self.slot['OutputSectionIndex'] or target['name'] == SLOT:
                need(kind == 2, 'no unsupported applied relocation to slot-containing BSS')
                value = struct.unpack('<I', _bytes(self.final, key[0], key[1], 4))[0]
                if self.slot['Entry'] <= value < self.slot['Entry'] + 4:
                    actual_final.add(key)
        expected_final = {(self.origin(name)['OutputSectionIndex'], self.origin(name)['OutputSectionOffset']
            + offset - self.origin(name)['SymbolOffset']) for section, offset in found
            for name in (*PROGRAMS, *HANDLERS) if section == self.origin(name)['InputSectionIndex']
            and self.origin(name)['SymbolOffset'] <= offset < self.origin(name)['SymbolOffset'] + self.origin(name)['Size']}
        need(actual_final == (expected_final if self.emitted else set()), 'all applied slot values/metadata match original reference census')


def inspect(port_source, assembly, image, core, *, emit_relocs=True):
    """No I/O or helper loading; both supplied ELF roles must be authenticated."""
    need(type(port_source) is bytes and type(assembly) is bytes and type(emit_relocs) is bool,
         'literal source/assembly buffers and emitted selector')
    try:
        source_pairs = _port_source(port_source)
        programs, generated_pairs, alias = _assembly(assembly)
    except UnicodeError as error:
        raise Rejected('REJECT:CM3-LTO-SLOT:ASCII source and generated assembly') from error
    audit = Audit(image, core, emit_relocs)
    bodies = [audit.common(name, programs[name]) for name in PROGRAMS]
    handlers = audit.handlers()
    audit.all_slot_references()
    return dict(Status='CM3-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_O2_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY',
        Profile='CM3', Mode='O2-lto', Linkage='direct', EmitRelocs=emit_relocs,
        SlotIsolationValidated=True, SlotOrigin=audit.slot, SlotAlias=alias,
        SourceSha256=sha(port_source), AssemblySha256=sha(assembly),
        MachineSha256=sha(image.prelink.data), FinalSha256=sha(image.final.data), LinkMapSha256=image.link_map_hash,
        HandlerLoadPairs=2, HandlerLoads=handlers, SourcePairs=source_pairs, GeneratedPairs=generated_pairs,
        ClosedCommonBodies=6, CommonBodies=bodies, CommonLoads=5, CommonStores=1, Publisher=PUBLISHER,
        SlotReferences=8, AppliedSlotReferences=8 if emit_relocs else 0,
        RawSectionSymbolsPreserved=True, AllSectionMediatedSlotReferencesValidated=True,
        CommonSourceOwnershipValidated=False, CompleteHandlerBodiesValidated=False,
        ArbitraryPointerAliasProof=False, WholeProgramMemorySafetyProof=False, FullSemanticABIProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        Qualification=False, CellContractSatisfied=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
