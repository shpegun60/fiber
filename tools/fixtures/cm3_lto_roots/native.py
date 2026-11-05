"""Fixed CM3 O2-LTO generated-machine root transport, never original-TU proof.

The caller authenticates the capture producer and the unchanged core reader.
This adapter consumes real post-LTO ET_REL bytes, not GIMPLE or source IR.
"""
import re
import struct


ROOTS = {"SVC_Handler": (184, 64, 5), "PendSV_Handler": (204, 72, 6),
         "fiber_port_start_first_context": (104, 34, 2)}
CALLEES = frozenset(("fiber_panic", "fiber_port_context_validate_restore",
                    "fiber_port_context_validate_save_current", "fiber_port_scheduler_pick_next_from_pendsv"))
SLOT = "fiber_internal_runtime_current_context_slot"
SLOT_SECTION = ".bss.fiber_runtime_current_context_slot"
REFERENCE_SITES = {
    "SVC_Handler": {0x72: (10, "fiber_port_context_validate_restore"),
                    0x9E: (10, "fiber_panic"), 0xA6: (10, "fiber_panic"),
                    0xAE: (10, "fiber_panic"), 0xB4: (2, SLOT)},
    "PendSV_Handler": {0x34: (10, "fiber_port_context_validate_save_current"),
                       0x82: (10, "fiber_port_scheduler_pick_next_from_pendsv"),
                       0xB0: (10, "fiber_panic"), 0xB8: (10, "fiber_panic"),
                       0xC0: (10, "fiber_panic"), 0xC8: (2, SLOT)},
    "fiber_port_start_first_context": {0x56: (10, "fiber_panic"), 0x5E: (10, "fiber_panic")},
}


class NativeCM3LTOImage:
    def __init__(self, core, machine, final, disassembly, *, provider_objects, link_map):
        self.core, self.require = core, core.require
        self.require(type(provider_objects) is dict and len(provider_objects) == 2 and link_map is not None,
                     "LTO-ORIGIN", "one generated machine and one native startup provider required")
        # Only generic ELF/map/disassembly construction is reused. The ordinary
        # function/symbol predicates are not invoked or patched by this adapter.
        self.image = core.FinalImage(machine, final, disassembly, provider_objects=provider_objects,
                                     link_map=link_map, float_abi="soft")
        self.machine, self.final = self.image.prelink, self.image.final
        self.origins = {}
        self.require(sum(provider.data == self.machine.data for provider in self.image.providers.values()) == 1,
                     "LTO-ORIGIN", "unique actual machine provider required")
        self.require(not any(section.name.startswith(".gnu.lto_") for section in self.machine.sections),
                     "LTO-ELF", "GIMPLE cannot replace generated machine authority")
        self.require(bool(self.final.relocations), "LTO-RELOC", "actual applied final REL records required")

    def _symbol(self, elf, name):
        self.require(name in ROOTS or name in CALLEES or name == SLOT, "LTO-SCOPE", "undeclared definition")
        rows = [row for row in elf.symbols if row["name"] == name and row["section"] != "SHN_UNDEF"]
        self.require(len(rows) == 1, "LTO-SYMBOL", "one exact definition required " + name)
        row = rows[0]
        slot = name == SLOT
        self.require(row["kind"] == ("STT_OBJECT" if slot else "STT_FUNC")
                     and row["binding"] == ("STB_LOCAL" if slot else "STB_GLOBAL")
                     and row["visibility"] == "STV_DEFAULT" and type(row["section"]) is int
                     and 0 < row["section"] < len(elf.sections) and row["size"] > 0,
                     "LTO-SYMBOL", "fixed generated-machine definition role " + name)
        section = elf.sections[row["section"]]
        h = section.header
        origin = h.sh_addr if elf.final else 0
        offset = row["value"] if slot else row["value"] & ~1
        self.require(h.sh_flags & 7 == (3 if slot else 6) and origin <= offset
                     and offset + row["size"] <= origin + h.sh_size,
                     "LTO-SYMBOL", "bounded definition storage " + name)
        peers = [other for other in elf.symbols if other["name"] != name and other["kind"] == row["kind"]
                 and other["section"] == row["section"] and other["size"] > 0]
        self.require(not any((other["value"] if slot else other["value"] & ~1) < offset + row["size"]
                             and offset < (other["value"] if slot else other["value"] & ~1) + other["size"]
                             for other in peers),
                     "LTO-SYMBOL", "overlapping definition or cross-name alias " + name)
        if elf.final:
            loads = [load for load in elf.loads if load["Vaddr"] <= offset
                     and offset + row["size"] <= load["Vaddr"] + load["MemorySize"]]
            self.require(len(loads) == 1 and (loads[0]["Flags"] & 3 == 2 if slot else loads[0]["Flags"] & 1 != 0),
                         "LTO-SYMBOL", "exact writable/non-executable slot or executable function load coverage")
        if slot:
            self.require(row["size"] == 4 and row["value"] % 4 == 0 and h.sh_type == "SHT_NOBITS",
                         "LTO-SYMBOL", "four-byte aligned local slot required")
            if not elf.final:
                self.require(section.name == SLOT_SECTION and row["value"] == 0 and h.sh_size == 4,
                             "LTO-SLOT", "exact dedicated input slot section required")
            else:
                self.require(section.name == ".bss", "LTO-SLOT", "fixed output slot section required")
        else:
            self.require(row["value"] & 1 and row["size"] % 2 == 0 and h.sh_type == "SHT_PROGBITS",
                         "LTO-SYMBOL", "bounded Thumb function required")
            self.require(elf.mapping(row["section"], offset)[0] == "t",
                         "LTO-SYMBOL", "Thumb mapping at exact function entry required")
        return row

    def _definition(self, name):
        if name in self.origins:
            return self.origins[name]
        before, after = self._symbol(self.machine, name), self._symbol(self.final, name)
        owners = [(identity, provider) for identity, provider in self.image.providers.items()
                  if any(row["name"] == name and row["section"] != "SHN_UNDEF" for row in provider.symbols)]
        self.require(len(owners) == 1 and owners[0][1].data == self.machine.data,
                     "LTO-ORIGIN", "definition must belong to actual generated machine " + name)
        identity, provider = owners[0]
        section, final_section = self.machine.sections[before["section"]], self.final.sections[after["section"]]
        h, final_h = section.header, final_section.header
        self.require(provider.names.count(section.name) == 1, "LTO-ORIGIN", "ambiguous generated section")
        key = (identity, section.name)
        self.require(key in self.image.placements, "LTO-ORIGIN", "missing full machine-section placement")
        address, size = self.image.placements[key]
        offset = before["value"] if name == SLOT else before["value"] & ~1
        actual = after["value"] if name == SLOT else after["value"] & ~1
        self.require(size == h.sh_size and offset + before["size"] <= size
                     and address + offset == actual and before["size"] == after["size"]
                     and address % max(1, h.sh_addralign) == 0
                     and final_h.sh_addr <= address and address + size <= final_h.sh_addr + final_h.sh_size
                     and h.sh_type == final_h.sh_type and h.sh_flags & 7 == final_h.sh_flags & 7,
                     "LTO-ORIGIN", "full machine section/offset/size must place final definition " + name)
        evidence = dict(Name=name, Provider=identity, ProviderSha256=self.core.sha256(provider.data),
            InputSection=section.name, InputSectionIndex=before["section"], SectionAddress=address, SectionSize=size,
            SymbolOffset=offset, Size=before["size"], Entry=actual, OutputSection=final_section.name,
            OutputSectionIndex=after["section"], OutputSectionOffset=actual - final_h.sh_addr,
            LinkMapSha256=self.image.link_map_hash, GeneratedMachineOriginBound=True,
            OriginalTranslationUnitOwnership=False, CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False)
        self.origins[name] = evidence
        return evidence

    def _relocations(self, elf, symbol):
        base = symbol["value"] & ~1
        origin = elf.sections[symbol["section"]].header.sh_addr if elf.final else 0
        return {offset + origin - base: row for (section, offset), row in elf.relocations.items()
                if section == symbol["section"] and base <= offset + origin < base + symbol["size"]}

    def _section_target(self, target, elf, definition):
        h = elf.sections[definition["section"]].header
        self.require(target["kind"] == "STT_SECTION" and target["binding"] == "STB_LOCAL"
                     and target["visibility"] == "STV_DEFAULT" and target["section"] == definition["section"]
                     and target["name"] == "" and target["size"] == 0
                     and target["value"] == (h.sh_addr if elf.final else 0),
                     "LTO-SLOT", "exact input/output slot section-symbol relationship required")

    def function(self, name):
        self.require(name in ROOTS, "LTO-SCOPE", "only three fixed CM3 generated roots admitted")
        before_symbol, after_symbol = self._symbol(self.machine, name), self._symbol(self.final, name)
        root_origin = self._definition(name)
        before, source_instructions, source_data = self.image._body(self.machine, before_symbol)
        after, instructions, data_ranges = self.image._body(self.final, after_symbol)
        size, count, ref_count = ROOTS[name]
        self.require(len(before) == len(after) == size and len(instructions) == len(source_instructions) == count
                     and source_data == data_ranges
                     and [(off, len(raw)) for off, raw, _ in source_instructions]
                     == [(off, len(raw)) for off, raw, _ in instructions],
                     "LTO-PRESERVATION", "exact fixed root extent/mapping boundaries required")
        source_refs, final_refs = self._relocations(self.machine, before_symbol), self._relocations(self.final, after_symbol)
        self.require(len(source_refs) == ref_count and set(source_refs) == set(final_refs) == set(REFERENCE_SITES[name]),
                     "LTO-RELOC", "exact applied-reference membership required")
        start, source_start = after_symbol["value"] & ~1, before_symbol["value"] & ~1
        by_offset = {offset: (raw, form) for offset, raw, form in instructions}
        source_by_offset = {offset: (raw, form) for offset, raw, form in source_instructions}
        references, patched = [], set()
        for offset, (kind, target) in sorted(source_refs.items()):
            final_kind, final_target = final_refs[offset]
            self.require(kind == final_kind and kind in (2, 10) and offset + 4 <= size
                         and not patched.intersection(range(offset, offset + 4)),
                         "LTO-RELOC", "supported disjoint complete REL fields required")
            self.require(REFERENCE_SITES[name][offset] == (kind, target["name"] if kind == 10 else SLOT),
                         "LTO-RELOC", "fixed root call/literal site role required")
            if kind == 10:
                self.require(offset in source_by_offset and offset in by_offset, "LTO-RELOC", "BL instruction boundary")
                source_form, form = source_by_offset[offset][1], by_offset[offset][1]
                self.require(source_form is not None and form is not None and source_form[0] == form[0] == "bl"
                             and source_form[3] == -4 and target["name"] in CALLEES,
                             "LTO-RELOC", "named BL with original REL addend -4 required")
                symbol = target["name"]
                definition, original_definition = self._symbol(self.final, symbol), self._symbol(self.machine, symbol)
                self.require(all(target[key] == original_definition[key] and final_target[key] == definition[key]
                                 for key in ("name", "kind", "binding", "visibility", "section", "value", "size")),
                             "LTO-RELOC", "exact named generated/final callee required")
                self._definition(symbol)
                resolved, addend = definition["value"] & ~1, source_form[3]
                self.require(form[1] == resolved, "LTO-RELOC", "BL final destination differs from mapped callee")
            else:
                self.require(any(a <= offset and offset + 4 <= b for a, b in data_ranges)
                             and (start + offset) % 4 == 0 and struct.unpack_from("<i", before, offset)[0] == 0,
                             "LTO-SLOT", "aligned slot literal with original REL addend zero required")
                symbol, addend = SLOT, 0
                original_definition, definition = self._symbol(self.machine, SLOT), self._symbol(self.final, SLOT)
                self._section_target(target, self.machine, original_definition)
                self._section_target(final_target, self.final, definition)
                self._definition(SLOT)
                resolved = definition["value"]
                self.require(struct.unpack_from("<I", after, offset)[0] == resolved,
                             "LTO-SLOT", "applied section-symbol word must equal exact mapped local slot")
            references.append(dict(Offset=offset, Kind=kind, Symbol=symbol, Addend=addend, Place=start + offset,
                ResolvedValue=resolved, OriginalBytes=before[offset:offset + 4].hex(), Bytes=after[offset:offset + 4].hex(),
                OriginalRelocationSymbol=dict(target), FinalRelocationSymbol=dict(final_target), Binding=definition["binding"],
                OriginalTargetSection=self.machine.sections[target["section"]].name,
                FinalTargetSection=self.final.sections[final_target["section"]].name))
            patched.update(range(offset, offset + 4))
        self.require(all(a == b for offset, (a, b) in enumerate(zip(before, after)) if offset not in patched),
                     "LTO-PRESERVATION", "non-relocation machine bytes changed")
        # Raw mapping boundaries and every byte are covered here. Canonical
        # protocol/reference composition remains a separate gate.
        decoded, literal_bytes, used = [], set(), set()
        for offset, raw, form in instructions:
            record = self.image.instructions.get((after_symbol["section"], start + offset))
            self.require(record is not None and record[2] == raw, "LTO-DECODE", "actual disassembly bytes required")
            if form is not None:
                source_form = source_by_offset[offset][1]
                self.require(source_form is not None and source_form[0] == form[0] == record[0],
                             "LTO-DECODE", "address-bearing mnemonic disagrees with bits")
                if form[0] == "bl":
                    self.require(offset in source_refs and source_refs[offset][0] == 10,
                                 "LTO-DECODE", "unrelocated BL is not admitted")
                    used.add(offset)
                elif form[0] == "bx":
                    self.require(record[1].lower() == "lr", "LTO-DECODE", "exact BX LR operand required")
                else:
                    self.require(source_form[1] - source_start == form[1] - start,
                                 "LTO-DECODE", "local address form changed")
                    if form[0] == "ldr":
                        pool = form[1] - start
                        self.require(any(a <= pool and pool + 4 <= b for a, b in data_ranges)
                                     and (start + pool) % 4 == 0,
                                     "LTO-DECODE", "literal must name bounded aligned mapped data")
                        argument = re.fullmatch(r"r([0-7]),\s*\[pc,\s*#(0x[0-9a-fA-F]+|[0-9]+)\]", record[1].lower())
                        self.require(argument is not None and int(argument[1]) == form[2]
                                     and int(argument[2], 0 if argument[2].startswith("0x") else 10) == form[3],
                                     "LTO-DECODE", "literal operands disagree with bits")
                        literal_bytes.update(range(pool, pool + 4))
                        if pool in source_refs:
                            self.require(source_refs[pool][0] == 2, "LTO-DECODE", "literal relocation kind")
                            used.add(pool)
                    else:
                        self.require(form[1] - start in by_offset, "LTO-DECODE", "branch leaves local instruction boundaries")
                if form[0] in ("bl", "b") or form[0] in self.core.CONDITIONS:
                    argument = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", record[1])
                    self.require(argument is not None and int(argument[1], 16) == form[1],
                                 "LTO-DECODE", "branch text disagrees with applied bits")
            else:
                self.require(record[0] in self.core.ORDINARY and not record[0].startswith("v")
                             and re.search(r"\b(pc|r15)\b", record[1], re.I) is None,
                             "LTO-DECODE", "unsupported CM3 ordinary instruction or PC use")
            decoded.append(dict(Offset=offset, Bytes=raw.hex(), Mnemonic=record[0], Operands=record[1]))
        self.require(used == set(source_refs), "LTO-DECODE", "unconsumed root relocation")
        for a, b in data_ranges:
            self.require(all(offset in literal_bytes or (start + offset < ((start + a + 3) & ~3)
                             and after[offset] == before[offset] == 0) for offset in range(a, b)),
                         "LTO-DECODE", "unreferenced data or nonzero alignment padding")
        covered = {start + offset for offset in by_offset}
        for (section, address), record in self.image.instructions.items():
            if section == after_symbol["section"] and start <= address < start + size and address not in covered:
                offset = address - start
                self.require(record is not None and record[0] in (".word", ".short", ".byte")
                             and any(a <= offset and offset + len(record[2]) <= b for a, b in data_ranges)
                             and after[offset:offset + len(record[2])] == record[2],
                             "LTO-DECODE", "extra/interior/mismatched disassembly record")
        return dict(Name=name, Address=start, Size=size, BodySha256=self.core.sha256(after),
            MachineBodySha256=self.core.sha256(before), InstructionCount=count, Instructions=decoded,
            MappedData=[dict(Offset=a, Bytes=after[a:b].hex()) for a, b in data_ranges], References=references,
            RootOrigin=root_origin, DefinitionOrigins=[self.origins[item] for item in sorted({r["Symbol"] for r in references})],
            GeneratedMachineBoundRootPreservation=True, OriginalTranslationUnitOwnership=False,
            CanonicalProtocolValidated=False, FinalReferenceParity=False, PolicyEquivalence=False,
            CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
