"""Pure named panic-call application audit, not C-body or IR semantics."""

import hashlib
import re
import struct


PANIC = "fiber_panic"
_SYMBOL_KEYS = {"name", "value", "size", "kind", "binding", "section", "visibility", "index"}


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected("REJECT:CM3-LTO-OVERRIDE-CALLS:" + message)


def _integer(value, label, minimum=0, maximum=0xFFFFFFFF):
    need(type(value) is int and minimum <= value <= maximum, "literal bounded integer: " + label)
    return value


def _sha(data):
    need(type(data) is bytes, "immutable ELF bytes")
    return hashlib.sha256(data).hexdigest().upper()


def _metadata(row):
    need(type(row) is dict and set(row) == _SYMBOL_KEYS, "complete raw symbol metadata")
    for key in ("value", "size", "index"):
        _integer(row[key], "symbol/" + key)
    need(type(row["section"]) is int or type(row["section"]) is str, "literal symbol section")
    for key in ("name", "kind", "binding", "visibility"):
        need(type(row[key]) is str, "literal symbol/" + key)
    return row


def _same_symbol(actual, expected):
    _metadata(actual)
    _metadata(expected)
    need(all(type(actual[key]) is type(expected[key]) and actual[key] == expected[key]
             for key in _SYMBOL_KEYS), "relocation/contract must name exact symbol-table definition")


def _function(elf, name):
    need(type(name) is str and name, "nonempty function name")
    need(type(elf.symbols) is list and type(elf.sections) is list, "core symbol/section lists")
    matches = [row for row in elf.symbols if _metadata(row)["name"] == name
               and row["section"] != "SHN_UNDEF"]
    need(len(matches) == 1, "unique function: " + name)
    row = matches[0]
    section = _integer(row["section"], "function section", 1, len(elf.sections) - 1)
    need(row["kind"] == "STT_FUNC" and row["binding"] in ("STB_LOCAL", "STB_GLOBAL")
         and row["visibility"] == "STV_DEFAULT" and row["value"] & 1
         and row["size"] > 0 and row["size"] % 2 == 0, "positive Thumb function role: " + name)
    h = elf.sections[section].header
    for key in ("sh_addr", "sh_size", "sh_flags", "sh_addralign", "sh_offset"):
        _integer(getattr(h, key), "function section/" + key)
    origin = h.sh_addr if elf.final else 0
    start = row["value"] & ~1
    need(h.sh_type == "SHT_PROGBITS" and h.sh_flags & 7 == 6
         and origin <= start and start + row["size"] <= origin + h.sh_size
         and h.sh_offset + h.sh_size <= len(elf.data), "bounded executable function: " + name)
    mapping = elf.mapping(section, start)
    need(type(mapping) is tuple and len(mapping) == 2 and mapping[0] == "t",
         "Thumb-mapped function entry: " + name)
    for other in elf.symbols:
        if other is row or other["kind"] != "STT_FUNC" or other["section"] != section or not other["size"]:
            continue
        at = other["value"] & ~1
        need(not (at < start + row["size"] and start < at + other["size"]), "positive function alias/overlap")
    if elf.final:
        owners = []
        for load in elf.loads:
            need(type(load) is dict, "literal load metadata")
            for key in ("Vaddr", "FileSize", "MemorySize", "Offset", "Flags"):
                _integer(load.get(key), "load/" + key)
            if load["Vaddr"] <= start and start + row["size"] <= load["Vaddr"] + load["MemorySize"]:
                owners.append(load)
        need(len(owners) == 1 and owners[0]["Flags"] & 1
             and start + row["size"] <= owners[0]["Vaddr"] + owners[0]["FileSize"],
             "unique complete executable file-backed function load")
        at = owners[0]["Offset"] + start - owners[0]["Vaddr"]
        raw = elf.section_read(section, start - origin, row["size"])
        need(elf.data[at:at + row["size"]] == raw, "function section/load byte mapping")
    return row


def _bind(image, provider, name):
    before, after = _function(image.prelink, name), _function(image.final, name)
    source, final = image.prelink.sections[before["section"]], image.final.sections[after["section"]]
    h, last = source.header, final.header
    need(sum(section.name == source.name for section in image.prelink.sections) == 1,
         "unique original section name")
    placement = image.placements.get((provider, source.name))
    need(type(placement) is tuple and len(placement) == 2, "whole-section map placement")
    address, extent = placement
    _integer(address, "placement address")
    _integer(extent, "placement extent", 1)
    offset, entry = before["value"] & ~1, after["value"] & ~1
    need(h.sh_addr == 0 and extent == h.sh_size and offset + before["size"] <= extent
         and address + extent <= 1 << 32 and address + offset == entry
         and before["size"] == after["size"] and before["binding"] == after["binding"]
         and address % max(1, h.sh_addralign) == 0
         and last.sh_addr <= address and address + extent <= last.sh_addr + last.sh_size
         and h.sh_type == last.sh_type and h.sh_flags & 7 == last.sh_flags & 7,
         "exact whole-section/offset/extent/binding final function origin")
    return dict(Name=name, Original=dict(before), Final=dict(after), Provider=provider,
                InputSection=source.name, InputSectionIndex=before["section"], SectionAddress=address,
                SectionSize=extent, SymbolOffset=offset, Size=before["size"], Entry=entry,
                OutputSection=final.name, OutputSectionIndex=after["section"],
                OutputSectionOffset=entry - last.sh_addr)


def _boundaries(elf, symbol):
    """Walk only mappings and Thumb widths; unrelated C opcodes are not decoded."""
    section, start = symbol["section"], symbol["value"] & ~1
    origin = elf.sections[section].header.sh_addr if elf.final else 0
    body = elf.section_read(section, start - origin, symbol["size"])
    need(type(body) is bytes and len(body) == symbol["size"], "complete caller bytes")
    result, address, end = {}, start, start + len(body)
    while address < end:
        mapping = elf.mapping(section, address)
        need(type(mapping) is tuple and len(mapping) == 2 and mapping[0] in ("t", "d"),
             "caller Thumb/data mapping")
        boundary = _integer(mapping[1], "mapping boundary", address + 1)
        boundary = min(boundary, end)
        if mapping[0] == "d":
            address = boundary
            continue
        need(address % 2 == 0 and address + 2 <= boundary, "caller halfword extent")
        offset = address - start
        first = struct.unpack_from("<H", body, offset)[0]
        width = 4 if first >> 11 in (29, 30, 31) else 2
        need(address + width <= boundary, "caller instruction crosses mapping/extent")
        result[address - origin] = body[offset:offset + width]
        address += width
    return body, result


def _bl(raw):
    need(type(raw) is bytes and len(raw) == 4, "four-byte relocated Thumb call")
    first, second = struct.unpack("<HH", raw)
    need(first & 0xF800 == 0xF000 and second & 0xD000 == 0xD000, "relocation must encode BL T1")
    sign = (first >> 10) & 1
    i1, i2 = 1 ^ ((second >> 13) & 1) ^ sign, 1 ^ ((second >> 11) & 1) ^ sign
    value = (sign << 24) | (i1 << 23) | (i2 << 22) | ((first & 1023) << 12) | ((second & 2047) << 1)
    return value - (1 << 25) if value & (1 << 24) else value


def _relocations(elf):
    need(type(elf.relocations) is dict, "core relocation mapping")
    for key, row in elf.relocations.items():
        need(type(key) is tuple and len(key) == 2 and type(row) is tuple and len(row) == 2,
             "literal section/offset and kind/symbol relocation pairs")
        _integer(key[0], "relocation section", 1, len(elf.sections) - 1)
        _integer(key[1], "relocation offset")
        _integer(row[0], "relocation kind")
        _metadata(row[1])
    return elf.relocations


def _no_overlap(relocations, section, offset):
    need(not any(other_section == section and other != offset and other < offset + 4 and offset < other + 4
                 for other_section, other in relocations), "another relocation overlaps panic transfer")


def audit_calls(core_image, link_contract_proof, *, emit_relocs):
    """Bind every named original panic transfer, never source-TU/IR semantics."""
    image, proof = core_image, link_contract_proof
    need(type(emit_relocs) is bool and type(proof) is dict, "literal twin selector and contract proof")
    need(proof.get("Status") == "CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED"
         and proof.get("Scope") == "NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY"
         and proof.get("Profile") == "CM3" and proof.get("Mode") == "O2-lto"
         and proof.get("Linkage") == "direct" and proof.get("EmitRelocs") is emit_relocs
         and proof.get("FinalLinkContractValidated") is True, "fixed own-twin direct-link contract")
    machine, final = image.prelink, image.final
    need(machine.final is False and final.final is True and image.float_abi == "soft", "own soft machine/final roles")
    need(type(machine.data) is bytes and type(final.data) is bytes, "immutable machine/final buffers")
    need(type(image.instructions) is dict, "final disassembly records")
    for key in image.instructions:
        need(type(key) is tuple and len(key) == 2, "literal disassembly section/address pair")
        _integer(key[0], "disassembly section", 1, len(final.sections) - 1)
        _integer(key[1], "disassembly address")
    need(type(image.link_map_hash) is str and re.fullmatch(r"[A-F0-9]{64}", image.link_map_hash)
         and proof.get("LinkMapSha256") == image.link_map_hash, "same authenticated map")
    need(type(image.providers) is dict and len(image.providers) == 2 and type(image.placements) is dict,
         "generated machine/startup providers and placements")
    owners = [identity for identity, elf in image.providers.items() if elf.data == machine.data]
    need(len(owners) == 1 and type(owners[0]) is str and owners[0], "unique own generated-machine identity")
    provider = owners[0]
    need(type(proof.get("Symbols")) is dict and type(proof["Symbols"].get(PANIC)) is dict,
         "link-contract panic definition")
    panic = _bind(image, provider, PANIC)
    contract = proof["Symbols"][PANIC]
    for key, value in panic.items():
        if key in ("Original", "Final"):
            _same_symbol(contract.get(key), value)
        else:
            need(type(contract.get(key)) is type(value) and contract[key] == value, "contract panic origin/placement")
    need(panic["Original"]["binding"] == panic["Final"]["binding"] == "STB_GLOBAL"
         and contract.get("GeneratedMachineOriginBound") is True
         and contract.get("StartupOriginBound") is False, "exact strong generated-machine panic role")
    source_refs, final_refs = _relocations(machine), _relocations(final)
    named = [(key, row) for key, row in source_refs.items() if row[1]["name"] == PANIC]
    need(named, "nonempty all-machine named panic relocation coverage")
    need(emit_relocs or not final_refs, "ordinary twin cannot retain applied relocations")
    sites, callers, expected_applied = [], {}, set()
    for (section, offset), (kind, target) in sorted(named):
        need(kind == 10, "unsupported named panic transfer kind (only observed R_ARM_THM_CALL is admitted)")
        _same_symbol(target, panic["Original"])
        candidates = []
        for row in machine.symbols:
            if row["kind"] == "STT_FUNC" and row["section"] == section and row["size"]:
                start = row["value"] & ~1
                if start <= offset and offset + 4 <= start + row["size"]:
                    candidates.append(row)
        need(len(candidates) == 1, "unique complete containing input function")
        name = candidates[0]["name"]
        if name not in callers:
            origin = _bind(image, provider, name)
            before, original_boundaries = _boundaries(machine, origin["Original"])
            after, final_boundaries = _boundaries(final, origin["Final"])
            callers[name] = (origin, before, after, original_boundaries, final_boundaries)
        origin, before, after, original_boundaries, final_boundaries = callers[name]
        relative = offset - origin["SymbolOffset"]
        place = origin["Entry"] + relative
        final_section = origin["Final"]["section"]
        final_offset = place - final.sections[final_section].header.sh_addr
        raw, applied = original_boundaries.get(offset), final_boundaries.get(final_offset)
        need(_bl(raw) == -4, "original REL BL addend must be -4")
        need(place + 4 + _bl(applied) == panic["Entry"], "applied BL destination must equal map-bound panic entry")
        _no_overlap(source_refs, section, offset)
        _no_overlap(final_refs, final_section, final_offset)
        record = image.instructions.get((final_section, place))
        need(type(record) is tuple and len(record) == 3 and record[0] == "bl"
             and type(record[1]) is str and type(record[2]) is bytes and record[2] == applied,
             "actual final call bytes/mnemonic record")
        operand = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", record[1])
        need(operand is not None and int(operand[1], 16) == panic["Entry"], "final disassembly target disagrees with bits")
        need(not any((final_section, place + interior) in image.instructions for interior in (1, 2, 3)),
             "interior disassembly record in panic transfer")
        final_target = None
        if emit_relocs:
            key = (final_section, final_offset)
            need(key in final_refs and final_refs[key][0] == kind, "matching applied panic relocation site/kind")
            final_target = final_refs[key][1]
            _same_symbol(final_target, panic["Final"])
            expected_applied.add(key)
        sites.append(dict(Caller=name, CallerOrigin=origin, OriginalSectionIndex=section, OriginalOffset=offset,
            CallerOffset=relative, FinalSectionIndex=final_section, FinalOffset=final_offset, Place=place,
            Kind=kind, Transfer="BL", OriginalAddend=-4, ResolvedValue=panic["Entry"],
            OriginalBytes=raw.hex(), FinalBytes=applied.hex(), OriginalRelocationSymbol=dict(target),
            FinalRelocationSymbol=dict(final_target) if final_target is not None else None,
            FinalInstruction=dict(Mnemonic=record[0], Operands=record[1], Bytes=record[2].hex()),
            CallerOriginalBodySha256=_sha(before), CallerFinalBodySha256=_sha(after),
            InstructionBoundaryValidated=True, CallerBodySemanticsProven=False))
    actual_applied = {key for key, row in final_refs.items() if row[1]["name"] == PANIC}
    need(actual_applied == expected_applied, "no extra or missing applied named panic relocations")
    return dict(Status="CM3-LTO-OVERRIDE-CALLS-PASS-NOT-QUALIFIED",
        Scope="NATIVE_CM3_O2_LTO_ALL_NAMED_MACHINE_PANIC_CALLS_ONLY", Profile="CM3", Mode="O2-lto",
        Linkage="direct", EmitRelocs=emit_relocs, CallCount=len(sites), CallerCount=len(callers), CallSites=sites,
        PanicDefinition=panic, MachineSha256=_sha(machine.data), FinalSha256=_sha(final.data),
        LinkMapSha256=image.link_map_hash, OriginalNamedRelocations=len(named), AppliedNamedRelocations=len(actual_applied),
        AllNamedPanicCallsValidated=True, SupportedRelocationKinds=[10], CallerBodySemanticsProven=False,
        CallerBodyPreservationProven=False, UnrelocatedTransfersAudited=False, PanicResolutionSelectionProven=False,
        CalleeBodyProof=False, Qualification=False, FullABIProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
        InstructionEquivalence=False, PolicyEquivalence=False, FinalReferenceParity=False, CompleteObjectProof=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
