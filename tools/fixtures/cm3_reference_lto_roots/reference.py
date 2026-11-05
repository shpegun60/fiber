"""Fixed generated reference CM3 LTO machine-to-final roots, not protocol proof."""
import re
import struct

ROOTS = {'prvPortStartFirstTask': (32, 10, 0), 'vPortSVCHandler': (36, 10, 1),
         'xPortPendSVHandler': (68, 19, 2)}
SLOT, CALLEE = 'pxCurrentTCB', 'vTaskSwitchContext'
SITES = {'prvPortStartFirstTask': {}, 'vPortSVCHandler': {32: (2, SLOT)},
         'xPortPendSVHandler': {28: (10, CALLEE), 64: (2, SLOT)}}


class ReferenceCM3LTOImage:
    def __init__(self, core, machine, final, disassembly, *, provider_objects, link_map):
        self.core, self.require = core, core.require
        self.require(type(provider_objects) is dict and len(provider_objects) == 2 and link_map is not None,
                     'REF-LTO-ORIGIN', 'one generated machine and one native startup provider required')
        self.image = core.FinalImage(machine, final, disassembly, provider_objects=provider_objects,
                                     link_map=link_map, float_abi='soft')
        self.machine, self.final = self.image.prelink, self.image.final
        self.origins = {}
        self.require(sum(provider.data == self.machine.data for provider in self.image.providers.values()) == 1,
                     'REF-LTO-ORIGIN', 'unique actual generated machine provider')
        self.require(not any(section.name.startswith('.gnu.lto_') for section in self.machine.sections),
                     'REF-LTO-ELF', 'IR is not machine authority')
        self.require(bool(self.final.relocations), 'REF-LTO-RELOC', 'actual final applied REL records required')

    def _symbol(self, elf, name):
        self.require(name in (*ROOTS, SLOT, CALLEE), 'REF-LTO-SCOPE', 'undeclared definition')
        rows = [row for row in elf.symbols if row['name'] == name and row['section'] != 'SHN_UNDEF']
        self.require(len(rows) == 1, 'REF-LTO-SYMBOL', 'one exact definition required ' + name)
        row, slot = rows[0], name == SLOT
        self.require(row['kind'] == ('STT_OBJECT' if slot else 'STT_FUNC')
                     and row['binding'] == ('STB_LOCAL' if name == 'prvPortStartFirstTask' else 'STB_GLOBAL')
                     and row['visibility'] == 'STV_DEFAULT' and type(row['section']) is int
                     and 0 < row['section'] < len(elf.sections) and row['size'] > 0,
                     'REF-LTO-SYMBOL', 'exact generated reference definition role ' + name)
        section = elf.sections[row['section']]
        h = section.header
        address = row['value'] if slot else row['value'] & ~1
        base = h.sh_addr if elf.final else 0
        self.require(h.sh_flags & 7 == (3 if slot else 6) and base <= address
                     and address + row['size'] <= base + h.sh_size, 'REF-LTO-SYMBOL', 'bounded definition storage')
        peers = [other for other in elf.symbols if other['name'] != name and other['kind'] == row['kind']
                 and other['section'] == row['section'] and other['size'] > 0]
        self.require(not any((other['value'] if slot else other['value'] & ~1) < address + row['size']
                     and address < (other['value'] if slot else other['value'] & ~1) + other['size'] for other in peers),
                     'REF-LTO-SYMBOL', 'cross-name overlap or alias')
        if elf.final:
            loads = [load for load in elf.loads if load['Vaddr'] <= address
                     and address + row['size'] <= load['Vaddr'] + load['MemorySize']]
            self.require(len(loads) == 1 and (loads[0]['Flags'] & 3 == 2 if slot else loads[0]['Flags'] & 1 != 0),
                         'REF-LTO-SYMBOL', 'exact writable/non-executable slot or executable function load')
            if slot:
                self.require(address >= loads[0]['Vaddr'] + loads[0]['FileSize'],
                             'REF-LTO-SYMBOL', 'BSS slot must not have file-backed load bytes')
        if slot:
            self.require(row['size'] == 4 and row['value'] % 4 == 0 and h.sh_type == 'SHT_NOBITS'
                         and section.name == '.bss', 'REF-LTO-SYMBOL', 'four-byte global BSS slot required')
            if not elf.final:
                self.require(row['value'] == 8 and h.sh_size == 12,
                             'REF-LTO-SLOT', 'exact observed reference input BSS slot offset and extent')
        else:
            self.require(row['value'] & 1 and row['size'] % 2 == 0 and h.sh_type == 'SHT_PROGBITS'
                         and elf.mapping(row['section'], address)[0] == 't',
                         'REF-LTO-SYMBOL', 'Thumb entry, complete even extent and code storage required')
        return row

    def _definition(self, name):
        if name in self.origins:
            return self.origins[name]
        before, after = self._symbol(self.machine, name), self._symbol(self.final, name)
        owners = [(identity, provider) for identity, provider in self.image.providers.items()
                  if any(row['name'] == name and row['section'] != 'SHN_UNDEF' for row in provider.symbols)]
        self.require(len(owners) == 1 and owners[0][1].data == self.machine.data,
                     'REF-LTO-ORIGIN', 'exact generated machine owns definition ' + name)
        identity, provider = owners[0]
        section, final_section = self.machine.sections[before['section']], self.final.sections[after['section']]
        h, final_h = section.header, final_section.header
        self.require(provider.names.count(section.name) == 1 and (identity, section.name) in self.image.placements,
                     'REF-LTO-ORIGIN', 'unique complete generated section placement required')
        address, size = self.image.placements[identity, section.name]
        offset = before['value'] if name == SLOT else before['value'] & ~1
        actual = after['value'] if name == SLOT else after['value'] & ~1
        self.require(size == h.sh_size and offset + before['size'] <= size
                     and address + offset == actual and before['size'] == after['size']
                     and address % max(1, h.sh_addralign) == 0
                     and final_h.sh_addr <= address and address + size <= final_h.sh_addr + final_h.sh_size
                     and h.sh_type == final_h.sh_type and h.sh_flags & 7 == final_h.sh_flags & 7,
                     'REF-LTO-ORIGIN', 'whole section/offset/size must place exact final definition ' + name)
        self.origins[name] = dict(Name=name, Provider=identity, ProviderSha256=self.core.sha256(provider.data),
            InputSection=section.name, InputSectionIndex=before['section'], SectionAddress=address, SectionSize=size,
            SymbolOffset=offset, Size=before['size'], Entry=actual, OutputSection=final_section.name,
            OutputSectionIndex=after['section'], OutputSectionOffset=actual - final_h.sh_addr,
            LinkMapSha256=self.image.link_map_hash, GeneratedMachineOriginBound=True,
            OriginalTranslationUnitOwnership=False, CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False)
        return self.origins[name]

    def _relocations(self, elf, symbol):
        base = symbol['value'] & ~1
        origin = elf.sections[symbol['section']].header.sh_addr if elf.final else 0
        return {offset + origin - base: row for (section, offset), row in elf.relocations.items()
                if section == symbol['section'] and base <= offset + origin < base + symbol['size']}

    def function(self, name):
        self.require(name in ROOTS, 'REF-LTO-SCOPE', 'only three fixed reference roots')
        first, last = self._symbol(self.machine, name), self._symbol(self.final, name)
        origin = self._definition(name)
        before, source_instructions, source_data = self.image._body(self.machine, first)
        after, instructions, data_ranges = self.image._body(self.final, last)
        size, count, ref_count = ROOTS[name]
        self.require(len(before) == len(after) == size and len(instructions) == len(source_instructions) == count
                     and source_data == data_ranges
                     and [(offset, len(raw)) for offset, raw, _ in source_instructions]
                     == [(offset, len(raw)) for offset, raw, _ in instructions],
                     'REF-LTO-PRESERVATION', 'exact complete root extents and mapping boundaries')
        refs, final_refs = self._relocations(self.machine, first), self._relocations(self.final, last)
        self.require(len(refs) == ref_count and set(refs) == set(final_refs) == set(SITES[name]),
                     'REF-LTO-RELOC', 'exact complete named reference membership')
        start, source_start = last['value'] & ~1, first['value'] & ~1
        by_offset = {offset: (raw, form) for offset, raw, form in instructions}
        source_by_offset = {offset: (raw, form) for offset, raw, form in source_instructions}
        references, patched = [], set()
        for offset, (kind, target) in sorted(refs.items()):
            final_kind, final_target = final_refs[offset]
            self.require((kind, target['name']) == SITES[name][offset] and kind == final_kind
                         and offset + 4 <= size and not patched.intersection(range(offset, offset + 4)),
                         'REF-LTO-RELOC', 'exact fixed named REL site and kind')
            symbol = target['name']
            original, final = self._symbol(self.machine, symbol), self._symbol(self.final, symbol)
            self.require(all(target[key] == original[key] and final_target[key] == final[key]
                         for key in ('name', 'kind', 'binding', 'visibility', 'section', 'value', 'size')),
                         'REF-LTO-RELOC', 'exact original and final named definition targets')
            self._definition(symbol)
            if kind == 10:
                self.require(offset in by_offset and offset in source_by_offset, 'REF-LTO-RELOC', 'BL instruction boundary')
                form, original_form = by_offset[offset][1], source_by_offset[offset][1]
                resolved, addend = final['value'] & ~1, -4
                self.require(form is not None and original_form is not None and form[0] == original_form[0] == 'bl'
                             and original_form[3] == addend and form[1] == resolved,
                             'REF-LTO-RELOC', 'original minus-four BL addend and exact applied destination')
            else:
                resolved, addend = final['value'], 0
                self.require(kind == 2 and symbol == SLOT and any(a <= offset and offset + 4 <= b for a, b in data_ranges)
                             and (start + offset) % 4 == 0 and struct.unpack_from('<I', before, offset)[0] == 0
                             and struct.unpack_from('<I', after, offset)[0] == resolved,
                             'REF-LTO-SLOT', 'original zero ABS32 addend and exact applied global slot')
            references.append(dict(Offset=offset, Kind=kind, Symbol=symbol, Addend=addend, Place=start + offset,
                ResolvedValue=resolved, OriginalBytes=before[offset:offset + 4].hex(), Bytes=after[offset:offset + 4].hex(),
                OriginalRelocationSymbol=dict(target), FinalRelocationSymbol=dict(final_target), Binding=final['binding'],
                OriginalTargetSection=self.machine.sections[target['section']].name,
                FinalTargetSection=self.final.sections[final_target['section']].name))
            patched.update(range(offset, offset + 4))
        self.require(all(a == b for offset, (a, b) in enumerate(zip(before, after)) if offset not in patched),
                     'REF-LTO-PRESERVATION', 'non-relocation machine bytes changed')
        decoded, literal_bytes, used = [], set(), set()
        for offset, raw, form in instructions:
            row = self.image.instructions.get((last['section'], start + offset))
            self.require(row is not None and row[2] == raw, 'REF-LTO-DECODE', 'actual disassembly bytes')
            if form is not None:
                original_form = source_by_offset[offset][1]
                self.require(original_form is not None and original_form[0] == form[0] == row[0],
                             'REF-LTO-DECODE', 'address-bearing mnemonic agrees with bits')
                if form[0] == 'bl':
                    self.require(offset in refs and refs[offset][0] == 10, 'REF-LTO-DECODE', 'unrelocated call forbidden')
                    used.add(offset)
                elif form[0] == 'bx':
                    self.require(row[1].lower() == 'lr', 'REF-LTO-DECODE', 'exact BX LR')
                else:
                    self.require(original_form[1] - source_start == form[1] - start,
                                 'REF-LTO-DECODE', 'local address form preserved')
                    if form[0] == 'ldr':
                        pool = form[1] - start
                        self.require(any(a <= pool and pool + 4 <= b for a, b in data_ranges)
                                     and (start + pool) % 4 == 0, 'REF-LTO-DECODE', 'bounded aligned mapped literal')
                        argument = re.fullmatch(r'r([0-7]),\s*\[pc,\s*#(0x[0-9a-fA-F]+|[0-9]+)\]', row[1].lower())
                        self.require(argument is not None and int(argument[1]) == form[2]
                                     and int(argument[2], 0 if argument[2].startswith('0x') else 10) == form[3],
                                     'REF-LTO-DECODE', 'literal operands agree with bits')
                        literal_bytes.update(range(pool, pool + 4))
                        if pool in refs:
                            self.require(refs[pool][0] == 2, 'REF-LTO-DECODE', 'literal REL kind')
                            used.add(pool)
                    else:
                        self.require(form[1] - start in by_offset, 'REF-LTO-DECODE', 'local branch instruction boundary')
                if form[0] in ('bl', 'b') or form[0] in self.core.CONDITIONS:
                    argument = re.fullmatch(r'([0-9a-fA-F]+)(?:\s+<[^>]+>)?', row[1])
                    self.require(argument is not None and int(argument[1], 16) == form[1],
                                 'REF-LTO-DECODE', 'branch text agrees with applied bits')
            else:
                self.require(row[0] in self.core.ORDINARY | {'orr'} and not row[0].startswith('v')
                             and re.search(r'\b(pc|r15)\b', row[1], re.I) is None,
                             'REF-LTO-DECODE', 'fixed soft reference ordinary instruction without PC use')
            decoded.append(dict(Offset=offset, Bytes=raw.hex(), Mnemonic=row[0], Operands=row[1]))
        self.require(used == set(refs), 'REF-LTO-DECODE', 'every root REL consumed')
        for a, b in data_ranges:
            self.require(all(offset in literal_bytes or (start + offset < ((start + a + 3) & ~3)
                         and after[offset] == before[offset] == 0) for offset in range(a, b)),
                         'REF-LTO-DECODE', 'unreferenced data or nonzero padding')
        for (section, address), row in self.image.instructions.items():
            if section == last['section'] and start <= address < start + size and address - start not in by_offset:
                offset = address - start
                self.require(row is not None and row[0] in ('.word', '.short', '.byte')
                             and any(a <= offset and offset + len(row[2]) <= b for a, b in data_ranges)
                             and after[offset:offset + len(row[2])] == row[2], 'REF-LTO-DECODE', 'extra disassembly record')
        return dict(Name=name, Address=start, Size=size, BodySha256=self.core.sha256(after),
            MachineBodySha256=self.core.sha256(before), InstructionCount=count, Instructions=decoded,
            MappedData=[dict(Offset=a, Bytes=after[a:b].hex()) for a, b in data_ranges], References=references,
            RootOrigin=origin, DefinitionOrigins=[self.origins[item] for item in sorted({row['Symbol'] for row in references})],
            GeneratedMachineBoundRootPreservation=True, OriginalTranslationUnitOwnership=False,
            CanonicalProtocolValidated=False, FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False,
            CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
