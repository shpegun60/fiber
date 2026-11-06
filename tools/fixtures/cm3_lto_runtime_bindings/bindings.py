"""Pure fixed CM3 O2-LTO runtime bindings, not source-TU or C-body proof.

The caller authenticates the generic FinalImage, core and unchanged link-audit
module. Only selected call/literal/vector applications are decoded. C callers
are walked by mapping and Thumb width, never passed to the closed-root decoder.
"""

from collections import Counter
import hashlib
import re
import struct


SELECT = 'fiber_internal_runtime_select_scheduler_candidate'
PUBLISH = 'fiber_internal_runtime_publish_current_context'
CURRENT = 'fiber_internal_runtime_require_current_context'
RETURN = 'fiber_internal_task_return'
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
           'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
           'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
REVERSE = (SELECT, PUBLISH, CURRENT, RETURN)
REFERENCES = (('fiber_port_runtime_schedule', 10, CURRENT),
              ('fiber_port_scheduler_pick_first_from_start', 10, SELECT),
              ('fiber_port_scheduler_pick_next_from_pendsv', 10, SELECT),
              ('fiber_port_scheduler_pick_next_from_pendsv', 10, PUBLISH),
              ('fiber_port_init_context_frame', 2, RETURN))
COLD = ('fiber_port_runtime_prepare_start', 'fiber_port_context_init')
VECTORS = ((4, 'Reset_Handler'), (44, 'SVC_Handler'), (56, 'PendSV_Handler'))
SYMBOL_KEYS = frozenset(('name', 'value', 'size', 'kind', 'binding', 'section', 'visibility', 'index'))


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-LTO-RUNTIME-BINDINGS:' + message)


def _integer(value, label, minimum=0, maximum=0xFFFFFFFF):
    need(type(value) is int and minimum <= value <= maximum, 'literal bounded integer: ' + label)
    return value


def _sha(raw):
    need(type(raw) is bytes, 'immutable ELF bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _raw_symbol(elf, row):
    need(type(row) is dict and set(row) == SYMBOL_KEYS, 'complete raw relocation symbol')
    index = _integer(row['index'], 'symbol index', maximum=len(elf.symbols) - 1)
    expected = elf.symbols[index]
    need(type(expected) is dict and set(expected) == SYMBOL_KEYS
         and all(type(row[key]) is type(expected[key]) and row[key] == expected[key] for key in SYMBOL_KEYS),
         'relocation must retain the actual raw symbol-table row')
    for key in ('value', 'size'):
        _integer(row[key], 'symbol/' + key)
    for key in ('name', 'kind', 'binding', 'visibility'):
        need(type(row[key]) is str, 'literal symbol/' + key)
    return row


def _same_symbol(elf, actual, expected):
    _raw_symbol(elf, actual)
    need(set(expected) == SYMBOL_KEYS and all(type(actual[key]) is type(expected[key])
         and actual[key] == expected[key] for key in SYMBOL_KEYS), 'exact named definition target')


def _section_symbol(elf, row, section):
    _raw_symbol(elf, row)
    _integer(section, 'section-symbol index', 1, len(elf.sections) - 1)
    need(type(row['section']) is int and row['section'] == section and row['name'] == ''
         and row['kind'] == 'STT_SECTION' and row['binding'] == 'STB_LOCAL'
         and row['visibility'] == 'STV_DEFAULT' and row['size'] == 0
         and row['value'] == (elf.sections[section].header.sh_addr if elf.final else 0),
         'exact empty-name input/output STT_SECTION target')


def _mapped(elf, section, address, size, kind):
    actual, boundary = elf.mapping(section, address)
    _integer(boundary, 'mapping boundary', address + 1)
    need(actual == kind and address + size <= boundary, 'complete ' + kind + ' mapping')


def _walk(elf, symbol, core, audit):
    section, start = symbol['section'], symbol['value'] & ~1
    base = elf.sections[section].header.sh_addr if elf.final else 0
    body = audit._bytes(elf, section, start - base, symbol['size'])
    instructions, data, address = {}, [], start
    while address < start + len(body):
        kind, boundary = elf.mapping(section, address)
        _integer(boundary, 'function mapping boundary', address + 1)
        boundary = min(boundary, start + len(body))
        need(kind in ('t', 'd'), 'only mapped Thumb or literal data in tracked function')
        if kind == 'd':
            data.append((address - start, boundary - start))
            address = boundary
            continue
        need(address % 2 == 0 and address + 2 <= boundary, 'mapped instruction halfword')
        offset = address - start
        width = core._width(struct.unpack_from('<H', body, offset)[0])
        need(type(width) is int and width in (2, 4) and address + width <= boundary,
             'instruction width contained in mapping and function')
        instructions[address - base] = body[offset:offset + width]
        address += width
    need(instructions, 'nonempty tracked function')
    return body, instructions, data


def _instruction(image, section, address, raw, mnemonic=None):
    record = image.instructions.get((section, address))
    need(type(record) is tuple and len(record) == 3 and type(record[0]) is str
         and type(record[1]) is str and type(record[2]) is bytes and record[2] == raw
         and (mnemonic is None or record[0] == mnemonic), 'selected final instruction bytes/mnemonic')
    need(not any((section, address + offset) in image.instructions for offset in range(1, len(raw))),
         'interior selected-instruction disassembly record')
    return dict(Mnemonic=record[0], Operands=record[1], Bytes=raw.hex())


class Bindings:
    def __init__(self, image, core, audit, proof, emitted):
        self.image, self.core, self.audit, self.proof, self.emitted = image, core, audit, proof, emitted
        self.machine, self.final = image.prelink, image.final
        self.machine_owner = proof['Symbols'][ANCHOR]['Provider']
        self.startup_owner = proof['Symbols']['Reset_Handler']['Provider']
        need(self.machine_owner != self.startup_owner and image.providers[self.machine_owner].data == self.machine.data,
             'own generated-machine and distinct original startup identities')

        class Inputs:
            pass

        self.model = Inputs()
        for key in ('prelink', 'final', 'providers', 'placements'):
            setattr(self.model, key, getattr(image, key))
        self.model._contract_machine_owner = self.machine_owner
        self.definitions = dict(proof['Symbols'])
        for name in (*REVERSE, *(row[0] for row in REFERENCES)):
            if name not in self.definitions:
                self.definitions[name] = audit._bound(self.model, name, 'STT_FUNC', ('STB_GLOBAL',), self.machine_owner)
        self.source_refs, self.applied_refs = self._references(self.machine), self._references(self.final)
        need(emitted or not self.applied_refs, 'ordinary twin cannot retain applied relocations')
        self.walks, self.used_applied = {}, set()

    def _references(self, elf):
        rows = {}
        need(type(elf.relocations) is dict, 'literal relocation map')
        for key, value in elf.relocations.items():
            need(type(key) is tuple and len(key) == 2 and type(value) is tuple and len(value) == 2,
                 'literal section/offset REL pair')
            _integer(key[0], 'relocation section', 1, len(elf.sections) - 1)
            _integer(key[1], 'relocation offset')
            _integer(value[0], 'relocation kind')
            _raw_symbol(elf, value[1])
            rows[key] = value
        return rows

    def function(self, name):
        if name not in self.walks:
            origin = self.definitions[name]
            source = _walk(self.machine, origin['Original'], self.core, self.audit)
            final = _walk(self.final, origin['Final'], self.core, self.audit)
            need(source[2] == final[2] and [(p - origin['SymbolOffset'], len(raw)) for p, raw in source[1].items()]
                 == [(p - origin['OutputSectionOffset'], len(raw)) for p, raw in final[1].items()],
                 'tracked function instruction/data mapping layout preserved')
            self.walks[name] = (origin, source, final)
        return self.walks[name]

    def _placement(self, provider, section):
        obj = self.image.providers[provider]
        h = obj.sections[section].header
        name = obj.sections[section].name
        need(sum(row.name == name for row in obj.sections) == 1, 'unique placed input section')
        placed = self.image.placements.get((provider, name))
        need(type(placed) is tuple and len(placed) == 2, 'whole input-section placement')
        address, size = placed
        _integer(address, 'section address')
        _integer(size, 'section size', 1)
        need(size == h.sh_size and h.sh_addr == 0 and address % max(1, h.sh_addralign) == 0,
             'complete aligned input-section map extent')
        targets = [(i, row) for i, row in enumerate(self.final.sections)
                   if row.header.sh_flags & 2 and row.header.sh_addr <= address
                   and address + size <= row.header.sh_addr + row.header.sh_size]
        need(len(targets) == 1, 'unique complete mapped output section')
        index, target = targets[0]
        need(target.header.sh_type == h.sh_type and target.header.sh_flags & 7 == h.sh_flags & 7,
             'placed input/output storage class')
        return dict(Provider=provider, ProviderSha256=_sha(obj.data), InputSection=name,
            InputSectionIndex=section, SectionAddress=address, SectionSize=size,
            OutputSection=target.name, OutputSectionIndex=index, LinkMapSha256=self.image.link_map_hash)

    def _site(self, owner, offset, kind):
        origin, source, final = self.function(owner)
        section = origin['InputSectionIndex']
        need(type(offset) is int and origin['SymbolOffset'] <= offset
             and offset + 4 <= origin['SymbolOffset'] + origin['Size'], 'complete containing consumer function')
        containers = [row for row in self.machine.symbols if row['kind'] == 'STT_FUNC'
            and row['section'] == section and row['size'] > 0 and (row['value'] & ~1) <= offset
            and offset + 4 <= (row['value'] & ~1) + row['size']]
        need(len(containers) == 1 and containers[0]['name'] == owner, 'unique containing consumer function')
        need(self.source_refs.get((section, offset), (None,))[0] == kind, 'original reference site/kind')
        relative = offset - origin['SymbolOffset']
        place = origin['Entry'] + relative
        output = origin['OutputSectionIndex']
        final_offset = place - self.final.sections[output].header.sh_addr
        for rows, index, at in ((self.source_refs, section, offset), (self.applied_refs, output, final_offset)):
            need(not any(s == index and other != at and other < at + 4 and at < other + 4
                         for s, other in rows), 'overlapping selected REL fields')
        before = self.audit._bytes(self.machine, section, offset, 4)
        after = self.audit._bytes(self.final, output, final_offset, 4)
        return origin, source, final, place, output, final_offset, before, after

    def _applied(self, section, offset, kind):
        key = (section, offset)
        if not self.emitted:
            need(key not in self.applied_refs, 'ordinary selected site contains applied REL')
            return None
        need(key in self.applied_refs and self.applied_refs[key][0] == kind, 'matching emitted selected REL')
        need(key not in self.used_applied, 'selected emitted REL consumed twice')
        self.used_applied.add(key)
        return self.applied_refs[key][1]

    def reverse_references(self):
        found = []
        for owner in dict.fromkeys(row[0] for row in REFERENCES):
            origin, _, _ = self.function(owner)
            for (section, offset), (kind, target) in self.source_refs.items():
                if section == origin['InputSectionIndex'] and origin['SymbolOffset'] <= offset < origin['SymbolOffset'] + origin['Size']:
                    if target['name'] in REVERSE:
                        found.append((owner, kind, target['name'], offset))
                    elif target['kind'] == 'STT_SECTION' and owner == 'fiber_port_init_context_frame':
                        need(target['section'] != self.definitions[RETURN]['Original']['section'],
                             'unsupported section-relative task-return function reference')
        need(Counter(row[:3] for row in found) == Counter(REFERENCES),
             'exact prescribed consumer/function/kind/reverse-target multiplicities')
        rows, expected_applied = [], set()
        for owner, kind, name in REFERENCES:
            offset = next(row[3] for row in found if row[:3] == (owner, kind, name))
            origin, source, final, place, output, final_offset, before, after = self._site(owner, offset, kind)
            definition = self.definitions[name]
            target = self.source_refs[origin['InputSectionIndex'], offset][1]
            _same_symbol(self.machine, target, definition['Original'])
            if kind == 10:
                need(source[1].get(offset) == before and final[1].get(final_offset) == after,
                     'reverse call on complete original/final instruction boundaries')
                old, new = self.core._address_form(before, offset), self.core._address_form(after, place)
                need(old is not None and new is not None and old[0] == new[0] == 'bl' and old[3] == -4
                     and new[1] == definition['Entry'], 'named reverse BL addend -4 and exact applied entry')
                instruction = _instruction(self.image, output, place, after, 'bl')
                operand = re.fullmatch(r'([0-9a-fA-F]+)(?:\s+<[^>]+>)?', instruction['Operands'])
                need(operand is not None and int(operand[1], 16) == definition['Entry'], 'reverse BL text/bit destination')
                addend, resolved = -4, definition['Entry']
            else:
                need(kind == 2 and offset % 4 == place % 4 == 0 and before == bytes(4),
                     'named task-return ABS32 zero addend and alignment')
                _mapped(self.machine, origin['InputSectionIndex'], offset, 4, 'd')
                _mapped(self.final, output, place, 4, 'd')
                addend, resolved, instruction = 0, definition['Final']['value'], None
                need(struct.unpack('<I', after)[0] == resolved, 'task-return pointer includes exact final Thumb bit')
            applied = self._applied(output, final_offset, kind)
            if applied is not None:
                _same_symbol(self.final, applied, definition['Final'])
                expected_applied.add((output, final_offset))
            rows.append(dict(Consumer=owner, ConsumerOrigin=origin, Symbol=name, Kind=kind,
                InputSectionIndex=origin['InputSectionIndex'], InputOffset=offset,
                ConsumerOffset=offset - origin['SymbolOffset'], OutputSectionIndex=output,
                OutputOffset=final_offset, Place=place, Addend=addend, ResolvedValue=resolved,
                OriginalBytes=before.hex(), FinalBytes=after.hex(), TargetOrigin=definition,
                OriginalRelocationSymbol=dict(target), FinalRelocationSymbol=dict(applied) if applied is not None else None,
                FinalInstruction=instruction, AppliedRelocationMetadataChecked=self.emitted))
        actual_applied = set()
        for (section, offset), (_, target) in self.applied_refs.items():
            if target['name'] not in REVERSE:
                continue
            for owner in dict.fromkeys(row[0] for row in REFERENCES):
                origin = self.definitions[owner]
                at = self.final.sections[section].header.sh_addr + offset
                if section == origin['OutputSectionIndex'] and origin['Entry'] <= at < origin['Entry'] + origin['Size']:
                    actual_applied.add((section, offset))
        need(actual_applied == expected_applied, 'no extra or missing scoped applied reverse references')
        return rows

    def _anchor_pointer(self, owner, pool, displacement):
        origin, _, _, place, output, final_offset, before, after = self._site(owner, pool, 2)
        need(pool % 4 == place % 4 == 0, 'aligned cold literal pointer')
        _mapped(self.machine, origin['InputSectionIndex'], pool, 4, 'd')
        _mapped(self.final, output, place, 4, 'd')
        anchor = self.definitions[ANCHOR]
        target = self.source_refs[origin['InputSectionIndex'], pool][1]
        addend = struct.unpack('<I', before)[0]
        if target['name'] == ANCHOR:
            _same_symbol(self.machine, target, anchor['Original'])
            need(addend == 0 and displacement == 0, 'named cold anchor must use ABS32+0 and zero byte displacement')
            resolved = anchor['Final']['value']
            form = 'NAMED_ANCHOR'
        else:
            _section_symbol(self.machine, target, anchor['Original']['section'])
            need(addend + displacement == anchor['Original']['value'],
                 'section-relative pointer plus LDRB displacement must equal original anchor byte')
            resolved = anchor['SectionAddress'] + addend
            form = 'SECTION_BASE_PLUS_BYTE_DISPLACEMENT'
        need(resolved + displacement == anchor['Final']['value'] and struct.unpack('<I', after)[0] == resolved,
             'applied cold literal and byte displacement must equal map-bound final anchor')
        applied = self._applied(output, final_offset, 2)
        if applied is not None:
            if form == 'NAMED_ANCHOR':
                _same_symbol(self.final, applied, anchor['Final'])
            else:
                _section_symbol(self.final, applied, anchor['Final']['section'])
        return dict(Consumer=owner, Symbol=ANCHOR, Kind=2, InputOffset=pool,
            ConsumerOffset=pool - origin['SymbolOffset'], OutputSectionIndex=output, OutputOffset=final_offset,
            Place=place, OriginalAddend=addend, ByteDisplacement=displacement, ResolvedPointer=resolved,
            ResolvedByteAddress=anchor['Final']['value'], OriginalBytes=before.hex(), FinalBytes=after.hex(),
            AddressForm=form, OriginalRelocationSymbol=dict(target),
            FinalRelocationSymbol=dict(applied) if applied is not None else None,
            OriginalTargetSection=self.machine.sections[target['section']].name,
            FinalTargetSection=self.final.sections[anchor['Final']['section']].name,
            TargetOrigin=anchor, AppliedRelocationMetadataChecked=self.emitted)

    def cold_read(self, owner):
        origin, source, final = self.function(owner)
        candidates = []
        for read_offset, raw in source[1].items():
            if len(raw) != 2:
                continue
            half = struct.unpack('<H', raw)[0]
            if half & 0xF800 != 0x7800:
                continue
            register, displacement, destination = (half >> 3) & 7, (half >> 6) & 31, half & 7
            for load_offset, literal in source[1].items():
                if load_offset >= read_offset or len(literal) != 2 or struct.unpack('<H', literal)[0] & 0xF800 != 0x4800:
                    continue
                form = self.core._address_form(literal, load_offset)
                if form[2] != register:
                    continue
                pool = form[1]
                ref = self.source_refs.get((origin['InputSectionIndex'], pool))
                if ref is None or ref[0] != 2:
                    continue
                target = ref[1]
                anchor = self.definitions[ANCHOR]['Original']
                word = struct.unpack('<I', self.audit._bytes(self.machine, origin['InputSectionIndex'], pool, 4))[0]
                matches = ((target['name'] == ANCHOR and word == displacement == 0)
                    or (target['kind'] == 'STT_SECTION' and target['section'] == anchor['section']
                        and word + displacement == anchor['value']))
                if matches:
                    candidates.append((load_offset, read_offset, pool, register, destination, displacement))
        need(len(candidates) == 1, 'one exact literal-base/LDRB anchor-byte pair in each prescribed cold function')
        load, read, pool, register, destination, displacement = candidates[0]
        prefix = [raw for offset, raw in source[1].items() if offset < load]
        need(all(_stack_save(raw) for raw in prefix), 'cold literal executes in the straight stack-save entry prefix')
        between = [(offset, raw) for offset, raw in source[1].items() if load < offset < read]
        calls = []
        for offset, raw in between:
            final_offset = origin['OutputSectionOffset'] + offset - origin['SymbolOffset']
            applied = final[1][final_offset]
            call = _preserves_register(raw, register)
            need(call is not None and _preserves_register(applied, register) is call,
                 'unsupported/clobbering raw instruction between cold base load and byte read')
            if call:
                authority = self.source_refs.get((origin['InputSectionIndex'], offset))
                need(register in (4, 5, 6, 7) and authority is not None and authority[0] == 10
                     and authority[1]['kind'] == 'STT_FUNC' and authority[1]['name']
                     and type(authority[1]['section']) is int,
                     'across-call cold base must be AAPCS callee-saved and have original named BL authority')
                calls.append(offset - origin['SymbolOffset'])
            else:
                need(raw == applied, 'cold base live-range non-call instruction bytes changed')
        load_place = origin['Entry'] + load - origin['SymbolOffset']
        read_place = origin['Entry'] + read - origin['SymbolOffset']
        load_final = origin['OutputSectionOffset'] + load - origin['SymbolOffset']
        read_final = origin['OutputSectionOffset'] + read - origin['SymbolOffset']
        need(final[1][load_final] == source[1][load] and final[1][read_final] == source[1][read],
             'retained literal-load and LDRB bytes')
        literal = self.core._address_form(final[1][load_final], load_place)
        reference = self._anchor_pointer(owner, pool, displacement)
        need(literal[:3] == ('ldr', reference['Place'], register), 'final cold literal load addresses selected applied pointer')
        load_record = _instruction(self.image, origin['OutputSectionIndex'], load_place, final[1][load_final], 'ldr')
        operand = re.fullmatch(r'r([0-7]),\s*\[pc,\s*#(0x[0-9a-fA-F]+|[0-9]+)\]', load_record['Operands'])
        need(operand is not None and int(operand[1]) == register and int(operand[2], 0 if operand[2].startswith('0x') else 10) == literal[3],
             'cold literal operands agree with encoded address/register')
        read_record = _instruction(self.image, origin['OutputSectionIndex'], read_place, final[1][read_final], 'ldrb')
        operand = re.fullmatch(r'r([0-7]),\s*\[r([0-7])(?:,\s*#(0x[0-9a-fA-F]+|[0-9]+))?\]', read_record['Operands'])
        need(operand is not None and int(operand[1]) == destination and int(operand[2]) == register
             and (int(operand[3], 0 if operand[3].startswith('0x') else 10) if operand[3] else 0) == displacement,
             'cold LDRB operands agree with raw register/displacement')
        return dict(Function=owner, ConsumerOrigin=origin, LoadOffset=load - origin['SymbolOffset'],
            ReadOffset=read - origin['SymbolOffset'], BaseRegister=register, DestinationRegister=destination,
            ByteDisplacement=displacement, LoadInstruction=load_record, ReadInstruction=read_record,
            AnchorReference=reference, RetainedByteRead=True, StaticBaseRegisterBindingValidated=True,
            InterveningCallOffsets=calls, AAPCSCalleeSavedRegisterAssumption=bool(calls),
            CalleeRegisterPreservationProven=False, ControlFlowOrDominanceProven=False,
            OriginalBodySha256=_sha(source[0]), FinalBodySha256=_sha(final[0]))

    def vectors(self):
        startup = self.image.providers[self.startup_owner]
        vector = self.proof['Symbols']['pilot_vectors']
        index, output = vector['InputSectionIndex'], vector['OutputSectionIndex']
        original = self._references(startup)
        expected = {(index, offset): name for offset, name in VECTORS}
        named = {key: row[1]['name'] for key, row in original.items() if row[1]['name'] in dict(VECTORS).values()}
        need(named == expected, 'exact original startup handler ABS32 membership at 4/44/56')
        placement = self._placement(self.startup_owner, index)
        need(placement['SectionSize'] == 1024 and placement['SectionAddress'] == 0, 'whole original 256-word vector placement')
        rows = []
        for offset, name in VECTORS:
            kind, target = original[index, offset]
            need(kind == 2, 'original startup handler reference must be ABS32')
            definition = self.definitions[name]
            if name == 'Reset_Handler':
                _same_symbol(startup, target, definition['Original'])
            else:
                need(target['name'] == name and target['section'] == 'SHN_UNDEF' and target['binding'] == 'STB_GLOBAL'
                     and target['kind'] == 'STT_NOTYPE' and target['visibility'] == 'STV_DEFAULT'
                     and target['value'] == target['size'] == 0, 'original startup external strong-handler target')
            before = self.audit._bytes(startup, index, offset, 4)
            after = self.audit._bytes(self.final, output, offset, 4)
            need(before == bytes(4) and struct.unpack('<I', after)[0] == definition['Final']['value'],
                 'original zero vector addend and exact applied strong Thumb handler')
            _mapped(startup, index, offset, 4, 'd')
            _mapped(self.final, output, offset, 4, 'd')
            applied = self._applied(output, offset, 2)
            if applied is not None:
                _same_symbol(self.final, applied, definition['Final'])
            rows.append(dict(Symbol=name, Offset=offset, Kind=2, Addend=0, Value=definition['Final']['value'],
                OriginalRelocationSymbol=dict(target), FinalRelocationSymbol=dict(applied) if applied is not None else None,
                OriginalBytes=before.hex(), FinalBytes=after.hex(), InputPlacement=placement,
                TargetOrigin=definition, AppliedRelocationMetadataChecked=self.emitted))
        actual = {key: row[1]['name'] for key, row in self.applied_refs.items()
                  if key[0] == output and row[1]['name'] in dict(VECTORS).values()}
        expected_applied = {(output, offset): name for offset, name in VECTORS} if self.emitted else {}
        need(actual == expected_applied,
             'exact applied selected vector handler membership')
        return rows


def _stack_save(raw):
    first = struct.unpack_from('<H', raw)[0]
    return ((len(raw) == 2 and first & 0xFE00 == 0xB400)
            or (len(raw) == 4 and first == 0xE92D and struct.unpack_from('<H', raw, 2)[0] & 0x8000 == 0))


def _preserves_register(raw, register):
    """Narrow write-effect predicate, not a general instruction/CFG decoder.

    False means a known non-call cannot write the selected low register; True
    means BL and requires the explicitly reported AAPCS callee-save assumption.
    Unsupported encodings and possible writes return None (fail closed).
    """
    first = struct.unpack_from('<H', raw)[0]
    if len(raw) == 4:
        second = struct.unpack_from('<H', raw, 2)[0]
        if first & 0xF800 == 0xF000 and second & 0xD000 == 0xD000:
            return True
        if raw in (bytes.fromhex('bff34f8f'), bytes.fromhex('bff36f8f')):
            return False
        # Thumb-2 data-processing immediate or shifted-register destinations.
        if ((first & 0xF800 == 0xF000 and second & 0x8000 == 0)
                or first & 0xFE00 == 0xEA00):
            return False if (second >> 8) & 15 != register else None
        return None
    if len(raw) != 2:
        return None
    if first < 0x2000 or first & 0xFC00 == 0x4000:
        destination = first & 7
    elif first < 0x4000 or first & 0xF800 == 0x4800 or first & 0xF000 in (0x9000, 0xA000):
        destination = (first >> 8) & 7
    elif first & 0xFC00 == 0x4400 and (first >> 8) & 3 != 3:
        destination = (first & 7) | ((first >> 4) & 8)
    elif first & 0xF000 in (0x5000, 0x6000, 0x7000, 0x8000):
        destination = first & 7
    elif first & 0xFF00 == 0xB000 or first & 0xFE00 == 0xB400:
        return False
    elif first & 0xF000 == 0xD000 and (first >> 8) & 15 < 14 or first & 0xF800 == 0xE000:
        return False
    else:
        return None
    return False if destination != register else None


def inspect(image, core, link_audit, attributes_text, *, emit_relocs=True, machine_attributes_text=None):
    """Audit selected own-machine bindings; the caller owns all I/O/closure."""
    need(type(emit_relocs) is bool, 'literal emitted-relocation selector')
    proof = link_audit.audit(image, attributes_text, emit_relocs=emit_relocs,
                             machine_attributes_text=machine_attributes_text)
    need(type(proof) is dict and proof.get('Status') == 'CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED'
         and proof.get('Scope') == 'NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY'
         and proof.get('Profile') == 'CM3' and proof.get('Mode') == 'O2-lto'
         and proof.get('Linkage') == 'direct' and proof.get('EmitRelocs') is emit_relocs
         and proof.get('FinalLinkContractValidated') is True, 'fresh fixed own-machine link-contract proof')
    need(type(proof.get('Symbols')) is dict and len(proof['Symbols']) == 26
         and not set(REVERSE).intersection(proof['Symbols']), '26 frozen definitions plus four new reverse providers')
    bindings = Bindings(image, core, link_audit, proof, emit_relocs)
    reverse = bindings.reverse_references()
    cold = [bindings.cold_read(name) for name in COLD]
    vectors = bindings.vectors()
    need(len(bindings.used_applied) == (10 if emit_relocs else 0), 'ten selected original/applied binding roles')
    mandatory = dict(proof['Symbols'], **{name: bindings.definitions[name] for name in REVERSE})
    consumers = [bindings.definitions[name] for name in dict.fromkeys(row[0] for row in REFERENCES)
                 if name not in mandatory]
    need(len(mandatory) == 30 and len(consumers) == 3, 'distinct mandatory surface and additional consumer extents')
    return dict(Status='CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED',
        Scope='NATIVE_CM3_O2_LTO_DIRECT_MERGED_MACHINE_RUNTIME_BINDINGS_ONLY',
        Profile='CM3', Mode='O2-lto', Linkage='direct', EmitRelocs=emit_relocs,
        RuntimeProviderBindingsValidated=True, FinalLinkContractValidated=True, LinkContract=proof,
        MandatoryDefinitions=mandatory, MandatoryDefinitionCount=30,
        AdditionalConsumerOrigins=consumers, AdditionalConsumerCount=3,
        ForwardProviders=[proof['Symbols'][name] for name in FORWARD], ForwardProviderCount=8,
        ReverseProviders=[bindings.definitions[name] for name in REVERSE], ReverseProviderCount=4,
        ReverseReferences=reverse, ReverseReferenceCount=5, ReverseBLReferences=4, TaskReturnABS32References=1,
        ColdAnchorReads=cold, ColdAnchorReadCount=2, StartupVectors=vectors, StartupVectorReferenceCount=3,
        OriginalBindingRelocations=10, AppliedBindingRelocations=10 if emit_relocs else 0,
        AnchorDefinition=proof['Symbols'][ANCHOR], MachineProvider=bindings.machine_owner,
        StartupProvider=bindings.startup_owner, MachineSha256=_sha(image.prelink.data),
        FinalSha256=_sha(image.final.data), StartupSha256=_sha(image.providers[bindings.startup_owner].data),
        LinkMapSha256=image.link_map_hash, OriginalStartupVectorRelocationsAudited=True,
        AllStartupVectorRelocationsAudited=False,
        OtherReverseConsumersAudited=False, CallerBodySemanticsProven=False,
        CalleeRegisterPreservationProven=False, ControlFlowOrDominanceProven=False,
        Qualification=False, TypedABIProof=False, FullABIProof=False, FullSemanticABIProof=False,
        SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
        CanonicalProtocolValidated=False, InstructionEquivalence=False, PolicyEquivalence=False,
        FinalReferenceParity=False, CompleteObjectProof=False, KernelRuntimeProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
