"""Fixed pinned ARM_CM3 reference roots; not a kernel, CPU or parity proof.

Contracts transcribe portable/GCC/ARM_CM3/port.c at PIN, functions at
228/247/455. The enclosing receipt authenticates sources, mode, providers and
the map from the actual link. No caller-selected protocols or symbols exist.
The frozen classic readers are imported unchanged, never patched.
"""

import importlib.util
from pathlib import Path
import re
import struct


_spec = importlib.util.spec_from_file_location(
    "cm3_reference_fixed_symbols", Path(__file__).resolve().parents[1]
    / "classic_final_image/reference_elf.py")
_classic = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_classic)
core = _classic.core
native = core
Rejected = core.Rejected
compare_load_images = core.compare_load_images
require = core.require

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
FIRST = "prvPortStartFirstTask"
SVC = "vPortSVCHandler"
PENDSV = "xPortPendSVHandler"
ROOTS = frozenset((FIRST, SVC, PENDSV))
CALLEE, SLOT = "vTaskSwitchContext", "pxCurrentTCB"
MODES = ("O0", "Og", "O2", "Os", "O3")
_FRAME = "{r4,r5,r6,r7,r8,r9,r10,r11}"

# Offset, original little-endian instruction bytes, mnemonic and operand.
# The only patched fields are one BL and two ABS32 words, checked below.
_PROTOCOL = {
    FIRST: (
        (0, "0648", "ldr", "r0,[pc,#24]"),
        (2, "0068", "ldr", "r0,[r0,#0]"),
        (4, "0068", "ldr", "r0,[r0,#0]"),
        (6, "80f30888", "msr", "msp,r0"),
        (10, "62b6", "cpsie", "i"),
        (12, "61b6", "cpsie", "f"),
        (14, "bff34f8f", "dsb", "#15"),
        (18, "bff36f8f", "isb", "#15"),
        (22, "00df", "svc", "0"),
        (24, "00bf", "nop", "")),
    SVC: (
        (0, "074b", "ldr", "r3,[pc,#28]"),
        (2, "1968", "ldr", "r1,[r3,#0]"),
        (4, "0868", "ldr", "r0,[r1,#0]"),
        (6, "b0e8f00f", "ldmia", "r0!," + _FRAME),
        (10, "80f30988", "msr", "psp,r0"),
        (14, "bff36f8f", "isb", "#15"),
        (18, "4ff00000", "mov", "r0,#0"),
        (22, "80f31188", "msr", "basepri,r0"),
        (26, "4ef00d0e", "orr", "lr,lr,#13"),
        (30, "7047", "bx", "lr")),
    PENDSV: (
        (0, "eff30980", "mrs", "r0,psp"),
        (4, "bff36f8f", "isb", "#15"),
        (8, "0d4b", "ldr", "r3,[pc,#52]"),
        (10, "1a68", "ldr", "r2,[r3,#0]"),
        (12, "20e9f00f", "stmdb", "r0!," + _FRAME),
        (16, "1060", "str", "r0,[r2,#0]"),
        (18, "08b5", "push", "{r3,lr}"),
        (20, "4ff01000", "mov", "r0,#16"),
        (24, "80f31188", "msr", "basepri,r0"),
        (28, "fff7feff", "bl", CALLEE),
        (32, "4ff00000", "mov", "r0,#0"),
        (36, "80f31188", "msr", "basepri,r0"),
        (40, "bde80840", "ldmia", "sp!,{r3,lr}"),
        (44, "1968", "ldr", "r1,[r3,#0]"),
        (46, "0868", "ldr", "r0,[r1,#0]"),
        (48, "b0e8f00f", "ldmia", "r0!," + _FRAME),
        (52, "80f30988", "msr", "psp,r0"),
        (56, "bff36f8f", "isb", "#15"),
        (60, "7047", "bx", "lr")),
}
_SIZES = {FIRST: 32, SVC: 36, PENDSV: 68}
_DATA = {FIRST: ((26, 28), (28, 32)), SVC: ((32, 36),),
         PENDSV: ((62, 64), (64, 68))}
_ISLANDS = {FIRST: (26, 32), SVC: (32, 36), PENDSV: (62, 68)}
_LITERALS = {FIRST: (0, 28), SVC: (0, 32), PENDSV: (8, 64)}
_RELOCS = {FIRST: {}, SVC: {32: (2, SLOT)},
           PENDSV: {28: (10, CALLEE), 64: (2, SLOT)}}


def _operand(op, text):
    text = re.sub(r"\s+", "", text.lower())
    text = re.sub(r"\b(sl|fp|r14)\b",
                  lambda m: {"sl": "r10", "fp": "r11", "r14": "lr"}[m[0]], text)
    return "#15" if op in ("dsb", "isb") and text == "sy" else text


class ReferenceCM3FinalImage(core.FinalImage):
    """Three fixed soft-ABI roots, four direct provider objects, one GNU ld map."""
    ROOTS = ROOTS

    def __init__(self, prelink, final, disassembly, *, provider_objects=None,
                 link_map=None, mode="O2"):
        require(type(self) is ReferenceCM3FinalImage, "SCOPE", "only fixed CM3 reader admitted")
        require(type(mode) is str and mode in MODES, "SCOPE", "mode must be O0, Og, O2, Os or O3")
        require(type(provider_objects) is dict and len(provider_objects) == 4,
                "ORIGIN", "exact four provider objects required")
        paths = [Path(path).resolve(strict=True) for path in provider_objects.values()]
        require(all(not left.samefile(right) for i, left in enumerate(paths) for right in paths[i + 1:]),
                "ORIGIN", "physical provider alias")
        require(link_map is not None, "ORIGIN", "explicit linker map required")
        self.profile, self.mode = "CM3", mode
        super().__init__(prelink, final, disassembly, provider_objects=provider_objects,
                         link_map=link_map, float_abi="soft")
        require(len(self.providers) == 4 and {identity for identity, _ in self.placements} == set(self.providers),
                "ORIGIN", "map must place exactly the four declared providers")
        self.prelink = _classic._FixedSymbols(self.prelink)
        self.final = _classic._FixedSymbols(self.final)
        self.providers = {identity: _classic._FixedSymbols(provider)
                          for identity, provider in self.providers.items()}

    def _origin(self, name, definition):
        require(name in ROOTS or name in (CALLEE, SLOT), "SCOPE", "foreign CM3 reference origin")
        owners = {}
        for required_name in (*sorted(ROOTS), CALLEE, SLOT):
            matches = [(identity, provider) for identity, provider in self.providers.items()
                       for symbol in provider.symbols
                       if symbol["name"] == required_name and symbol["section"] != "SHN_UNDEF"]
            require(len(matches) == 1, "ORIGIN", "unique original definition required " + required_name)
            identity, provider = matches[0]
            owners[required_name] = identity
            if required_name in ROOTS:
                require(provider.data == self.prelink.data,
                        "ORIGIN", "root provider differs from bound prelink object")
        require(len({owners[root] for root in ROOTS}) == 1 and owners[CALLEE] == owners[SLOT]
                and owners[CALLEE] != owners[FIRST], "ORIGIN", "fixed port/provider definition ownership")
        return super()._origin(name, definition)

    def function(self, name):
        require(type(name) is str and name in ROOTS, "SCOPE", "only three pinned CM3 reference roots admitted")
        original = self.prelink.symbol(name, "STT_FUNC", root=True)
        final = self.final.symbol(name, "STT_FUNC", root=True)
        tail = int(self.mode == "O0")
        require(original["size"] == final["size"] == _SIZES[name] + 2 * tail,
                "PRESERVATION", "root extent changed")
        origin = self._origin(name, final)
        before, source_rows, source_data = self._body(self.prelink, original)
        after, final_rows, data = self._body(self.final, final)
        rows = _PROTOCOL[name] + (((_SIZES[name], "00bf", "nop", ""),) if tail else ())
        layout = [(offset, len(bytes.fromhex(raw))) for offset, raw, _, _ in rows]
        require(source_data == data == list(_DATA[name]) and layout
                == [(offset, len(raw)) for offset, raw, _ in source_rows]
                == [(offset, len(raw)) for offset, raw, _ in final_rows],
                "PRESERVATION", "mapping/layout changed")
        start, source_start = final["value"] & ~1, original["value"] & ~1

        def relocations(elf, symbol):
            base = symbol["value"] & ~1
            section_base = elf.sections[symbol["section"]].header.sh_addr if elf.final else 0
            return {offset + section_base - base: row for (section, offset), row in elf.relocations.items()
                    if section == symbol["section"] and base <= offset + section_base < base + symbol["size"]}

        source_relocs, final_relocs = relocations(self.prelink, original), relocations(self.final, final)
        require(set(source_relocs) == set(final_relocs) == set(_RELOCS[name]),
                "RELOC", "relocation membership changed")
        source_forms = {offset: form for offset, _, form in source_rows}
        final_forms = {offset: form for offset, _, form in final_rows}
        references, patched = [], set()
        # GNU ld --emit-relocs retains applied REL metadata, not original REL
        # addends. AAELF32 5.6.2 (Idempotency) requires separate original bytes.
        # https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002demit_002drelocs
        # https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#562-idempotency
        for offset, (expected_kind, target_name) in _RELOCS[name].items():
            kind, target = source_relocs[offset]
            final_kind, final_target = final_relocs[offset]
            require(kind == final_kind == expected_kind and target["name"] == final_target["name"] == target_name,
                    "RELOC", "relocation kind/identity changed or unsupported")
            if kind == 10:
                source_form, final_form = source_forms[offset], final_forms[offset]
                require(source_form is not None and final_form is not None
                        and source_form[0] == final_form[0] == "bl" and source_form[3] == -4,
                        "RELOC", "only original BL addend -4 admitted")
                definition = self.final.symbol(CALLEE, "STT_FUNC")
                self._origin(CALLEE, definition)
                resolved, addend = definition["value"] & ~1, source_form[3]
                require(final_form[1] == resolved, "RELOC", "applied BL destination differs from expected entry")
            else:
                addend = struct.unpack_from("<i", before, offset)[0]
                require(addend == 0, "RELOC", "only current-slot ABS32+0 admitted")
                require((start + offset) % 4 == 0 and any(a <= offset and offset + 4 <= b for a, b in data),
                        "RELOC", "ABS32 not an aligned literal word")
                definition = self.final.symbol(SLOT, "STT_OBJECT")
                slot_origin = self._origin(SLOT, definition)
                require(definition["size"] == 4 and definition["value"] % 4 == 0
                        and slot_origin["InputSection"] == ".bss.pxCurrentTCB"
                        and self.final.sections[definition["section"]].header.sh_type == "SHT_NOBITS",
                        "SYMBOL", "current-TCB requires aligned four-byte BSS storage")
                resolved = definition["value"]
                require(struct.unpack_from("<I", after, offset)[0] == resolved,
                        "RELOC", "applied ABS32 word differs from expected symbol+original addend")
            require(all(final_target[key] == definition[key] for key in ("section", "value", "kind", "binding")),
                    "RELOC", "final relocation does not name exact definition")
            references.append(dict(Offset=offset, Kind=kind, Symbol=target_name, Addend=addend,
                Place=start + offset, ResolvedValue=resolved, OriginalBytes=before[offset:offset + 4].hex(),
                Bytes=after[offset:offset + 4].hex(), Binding=definition["binding"]))
            patched.update(range(offset, offset + 4))
        require(all(a == b for offset, (a, b) in enumerate(zip(before, after)) if offset not in patched),
                "PRESERVATION", "non-relocation bytes changed")
        for offset, raw, _, _ in rows:
            require(before[offset:offset + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                    "PROTOCOL", "original instruction differs from fixed CM3 source contract")
        a, b = _ISLANDS[name]
        require(before[a:b] == (bytes.fromhex("000008ed00e0") if name == FIRST else bytes(b - a)),
                "PROTOCOL", "original literal island differs from source contract")

        section = self.prelink.sections[original["section"]]
        section_before = section.data()
        require(section.name == ".text." + name and source_start == 0
                and len(section_before) == ((len(before) + 3) & ~3),
                "PRESERVATION", "fixed owning input-section extent")
        section_after = self.read(origin["SectionAddress"], origin["SectionSize"])
        require(section_before[len(before):] == section_after[len(after):] == bytes.fromhex("00bf") * tail
                and all(left == right for offset, (left, right) in enumerate(zip(section_before, section_after))
                        if offset not in patched), "PRESERVATION", "owning section bytes changed")
        if tail:
            for elf, symbol, base in ((self.prelink, original, source_start), (self.final, final, start)):
                kind, boundary = elf.mapping(symbol["section"], base + len(before))
                require(kind == "t" and boundary >= base + len(section_before),
                        "PRESERVATION", "outside-function alignment mapping changed")

        output = []
        literal_instruction, pool = _LITERALS[name]
        for offset, raw, expected_op, expected_operand in rows:
            raw_final = after[offset:offset + len(bytes.fromhex(raw))]
            record = self.instructions.get((final["section"], start + offset))
            require(record is not None and record[2] == raw_final,
                    "DECODE", "missing/mismatched disassembly instruction")
            op, operands, _ = record
            require(op == expected_op, "PROTOCOL", "instruction mnemonic differs from fixed CM3 source contract")
            form, target_address = final_forms[offset], None
            if op == "bl":
                require(form is not None and form[0] == "bl", "DECODE", "BL mnemonic disagrees with bits")
                target_address = form[1]
                argument = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", operands)
                require(argument is not None and int(argument[1], 16) == target_address,
                        "DECODE", "branch disassembly target disagrees with bits")
            else:
                require(_operand(op, operands) == expected_operand,
                        "PROTOCOL", "instruction operands differ from fixed CM3 source contract")
                if offset == literal_instruction:
                    require(form is not None and form[0] == "ldr" and form[1] == start + pool
                            and source_forms[offset] is not None and source_forms[offset][1] == source_start + pool,
                            "DECODE", "literal target not preserved bounded mapped data")
                    target_address = form[1]
                    self.read(target_address, 4)
                elif op == "bx":
                    require(form is not None and form[0] == "bx", "DECODE", "BX LR mnemonic disagrees with bits")
                else:
                    require(form is None, "DECODE", "unexpected address-bearing instruction")
            output.append(dict(Offset=offset, Bytes=raw_final.hex(), Mnemonic=op,
                               Operands=operands, Target=target_address))
        covered = {start + offset for offset, _, _, _ in rows}
        for (sec, address), record in self.instructions.items():
            if sec == final["section"] and start <= address < start + final["size"] and address not in covered:
                offset = address - start
                require(record is not None and record[0] in (".word", ".short", ".byte")
                        and any(begin <= offset and offset + len(record[2]) <= end for begin, end in data)
                        and after[offset:offset + len(record[2])] == record[2],
                        "DECODE", "extra/interior/mismatched disassembly record")
        return dict(Name=name, Address=start, Size=len(after), BodySha256=core.sha256(after),
            InstructionCount=len(output), Instructions=output,
            LiteralIslands=[dict(Offset=a, Bytes=after[a:b].hex(),
                References=[dict(Instruction=literal_instruction, Offset=pool - a)])],
            DataMappings=[dict(Offset=begin, Size=end - begin, Bytes=after[begin:end].hex()) for begin, end in data],
            References=references, Complete=True, PrelinkBoundRootPreservation=True, RootOrigin=origin,
            DefinitionOrigins=[self.origin_evidence[target] for target in sorted({r["Symbol"] for r in references})],
            InputSectionSize=len(section_before), InputSectionSha256=core.sha256(section_before),
            AppliedInputSectionSha256=core.sha256(section_after), OutsideFunctionAlignmentBytes=section_after[len(after):].hex(),
            ProofScope="PINNED_REFERENCE_CM3_THREE_TRANSFER_ROOTS_ONLY", ExpectedFreeRTOSPin=PIN,
            Profile="CM3", Mode=self.mode, TailNops=tail, SoftwareFrameWords=8,
            SourcePinBindingVerified=False, CohortBindingVerified=False, ModeBindingVerified=False,
            RequiredCellSatisfied=False, FinalParity=False, KernelRuntimeProof=False, CPUProof=False, GlobalProof=False)
