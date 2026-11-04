"""Fixed pinned CM4/CM7 hard-float reference roots, not kernel/CPU proof.

The enclosing receipt must bind the pin, CM4/CM7 hard/eager p4/b16 cohort,
ordinary link inputs and map to their captured bytes. This reader does not
establish those source/cohort identities, routing, FPCCR policy or runtime
kernel functionality. Fail-stop link-only providers remain link-only.

The instruction contracts are transcribed from FreeRTOS ARM_CM4F/port.c
at PIN (260/278/504) and ARM_CM7/r0p1/port.c (254/272/492).
Modes select fixed layouts, not proof of compiler flags. Encodings are instruction-level
contracts, not learned body hashes. Shared ELF/load/origin machinery is
loaded unchanged from the adjacent native reader; it is never patched.
"""

import importlib.util
from pathlib import Path
import re
import struct


_spec = importlib.util.spec_from_file_location(
    "classic_final_image_reference_core", Path(__file__).with_name("elf.py"))
native = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(native)
core = native
Rejected = native.Rejected
compare_load_images = native.compare_load_images
require = native.require

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
FIRST = "prvPortStartFirstTask"
SVC = "vPortSVCHandler"
PENDSV = "xPortPendSVHandler"
ROOTS = frozenset((FIRST, SVC, PENDSV))
CALLEE = "vTaskSwitchContext"
SLOT = "pxCurrentTCB"
MODES = ("O0", "Og", "O2", "Os", "O3")
_CORE = "{r4,r5,r6,r7,r8,r9,r10,r11,lr}"
_FP = "{s16-s31}"

# Offset, original little-endian encoding, mnemonic, exact operand contract.
# Only the one applied BL instruction and two applied ABS32 words may differ
# in the final image, after independent original-addend/address checks.
_PROTOCOL = {
    FIRST: (
        (0, "0848", "ldr", "r0,[pc,#32]"),
        (2, "0068", "ldr", "r0,[r0,#0]"),
        (4, "0068", "ldr", "r0,[r0,#0]"),
        (6, "80f30888", "msr", "msp,r0"),
        (10, "4ff00000", "mov", "r0,#0"),
        (14, "80f31488", "msr", "control,r0"),
        (18, "62b6", "cpsie", "i"),
        (20, "61b6", "cpsie", "f"),
        (22, "bff34f8f", "dsb", "#15"),
        (26, "bff36f8f", "isb", "#15"),
        (30, "00df", "svc", "0"),
        (32, "00bf", "nop", "")),
    SVC: (
        (0, "064b", "ldr", "r3,[pc,#24]"),
        (2, "1968", "ldr", "r1,[r3,#0]"),
        (4, "0868", "ldr", "r0,[r1,#0]"),
        (6, "b0e8f04f", "ldmia", "r0!," + _CORE),
        (10, "80f30988", "msr", "psp,r0"),
        (14, "bff36f8f", "isb", "#15"),
        (18, "4ff00000", "mov", "r0,#0"),
        (22, "80f31188", "msr", "basepri,r0"),
        (26, "7047", "bx", "lr")),
    PENDSV: (
        (0, "eff30980", "mrs", "r0,psp"),
        (4, "bff36f8f", "isb", "#15"),
        (8, "134b", "ldr", "r3,[pc,#76]"),
        (10, "1a68", "ldr", "r2,[r3,#0]"),
        (12, "1ef0100f", "tst", "lr,#16"),
        (16, "08bf", "it", "eq"),
        (18, "20ed108a", "vstmdbeq", "r0!," + _FP),
        (22, "20e9f04f", "stmdb", "r0!," + _CORE),
        (26, "1060", "str", "r0,[r2,#0]"),
        (28, "09b4", "push", "{r0,r3}"),
        (30, "4ff01000", "mov", "r0,#16"),
        (34, "80f31188", "msr", "basepri,r0"),
        (38, "bff34f8f", "dsb", "#15"),
        (42, "bff36f8f", "isb", "#15"),
        (46, "fff7feff", "bl", CALLEE),
        (50, "4ff00000", "mov", "r0,#0"),
        (54, "80f31188", "msr", "basepri,r0"),
        (58, "09bc", "pop", "{r0,r3}"),
        (60, "1968", "ldr", "r1,[r3,#0]"),
        (62, "0868", "ldr", "r0,[r1,#0]"),
        (64, "b0e8f04f", "ldmia", "r0!," + _CORE),
        (68, "1ef0100f", "tst", "lr,#16"),
        (72, "08bf", "it", "eq"),
        (74, "b0ec108a", "vldmiaeq", "r0!," + _FP),
        (78, "80f30988", "msr", "psp,r0"),
        (82, "bff36f8f", "isb", "#15"),
        (86, "7047", "bx", "lr")),
}
_SIZES = {FIRST: 40, SVC: 32, PENDSV: 92}
_DATA = {FIRST: ((34, 36), (36, 40)), SVC: ((28, 32),), PENDSV: ((88, 92),)}
# Logical literal-island envelopes retain the existing evidence interface;
# the separate padding/pool mapping boundaries above are required exactly.
_ISLAND_SPAN = {FIRST: (34, 40), SVC: (28, 32), PENDSV: (88, 92)}
_LITERALS = {FIRST: (0, 36), SVC: (0, 28), PENDSV: (8, 88)}
_RELOCATIONS = {FIRST: {}, SVC: {28: (2, SLOT)},
                PENDSV: {46: (10, CALLEE), 88: (2, SLOT)}}

# CM7 r0p1 has a source-owned PRIMASK envelope around the entry BASEPRI
# write and barriers (erratum 837070), not the CM4 sequence plus ignored ops.
_CM7_PENDSV = (
    (0, "eff30980", "mrs", "r0,psp"),
    (4, "bff36f8f", "isb", "#15"),
    (8, "144b", "ldr", "r3,[pc,#80]"),
    (10, "1a68", "ldr", "r2,[r3,#0]"),
    (12, "1ef0100f", "tst", "lr,#16"),
    (16, "08bf", "it", "eq"),
    (18, "20ed108a", "vstmdbeq", "r0!," + _FP),
    (22, "20e9f04f", "stmdb", "r0!," + _CORE),
    (26, "1060", "str", "r0,[r2,#0]"),
    (28, "09b4", "push", "{r0,r3}"),
    (30, "4ff01000", "mov", "r0,#16"),
    (34, "72b6", "cpsid", "i"),
    (36, "80f31188", "msr", "basepri,r0"),
    (40, "bff34f8f", "dsb", "#15"),
    (44, "bff36f8f", "isb", "#15"),
    (48, "62b6", "cpsie", "i"),
    (50, "fff7feff", "bl", CALLEE),
    (54, "4ff00000", "mov", "r0,#0"),
    (58, "80f31188", "msr", "basepri,r0"),
    (62, "09bc", "pop", "{r0,r3}"),
    (64, "1968", "ldr", "r1,[r3,#0]"),
    (66, "0868", "ldr", "r0,[r1,#0]"),
    (68, "b0e8f04f", "ldmia", "r0!," + _CORE),
    (72, "1ef0100f", "tst", "lr,#16"),
    (76, "08bf", "it", "eq"),
    (78, "b0ec108a", "vldmiaeq", "r0!," + _FP),
    (82, "80f30988", "msr", "psp,r0"),
    (86, "bff36f8f", "isb", "#15"),
    (90, "7047", "bx", "lr"))
_CM4 = dict(Protocol=_PROTOCOL, Sizes=_SIZES, Data=_DATA, IslandSpan=_ISLAND_SPAN,
            Literals=_LITERALS, Relocations=_RELOCATIONS)
_CM7 = dict(Protocol={FIRST: _PROTOCOL[FIRST], SVC: _PROTOCOL[SVC], PENDSV: _CM7_PENDSV},
            Sizes={FIRST: 40, SVC: 32, PENDSV: 96},
            Data={FIRST: ((34, 36), (36, 40)), SVC: ((28, 32),), PENDSV: ((92, 96),)},
            IslandSpan={FIRST: (34, 40), SVC: (28, 32), PENDSV: (92, 96)},
            Literals={FIRST: (0, 36), SVC: (0, 28), PENDSV: (8, 92)},
            Relocations={FIRST: {}, SVC: {28: (2, SLOT)}, PENDSV: {50: (10, CALLEE), 92: (2, SLOT)}})


def _operand(op, text):
    text = re.sub(r"\s+", "", text.lower())
    text = re.sub(r"\b(sl|fp|r14)\b", lambda m: {"sl": "r10", "fp": "r11", "r14": "lr"}[m[0]], text)
    return "#15" if op in ("dsb", "isb") and text == "sy" else text


class _FixedSymbols:
    """Read-only parsed-ELF view with one explicitly local function exception."""
    def __init__(self, parsed):
        self._parsed = parsed

    def __getattr__(self, name):
        return getattr(self._parsed, name)

    def symbol(self, name, kind, *, root=False):
        require(name in ROOTS or name in (CALLEE, SLOT), "SCOPE", "foreign reference symbol")
        if name != FIRST:
            result = self._parsed.symbol(name, kind, root=root or name in ROOTS)
            require(result["binding"] == "STB_GLOBAL", "SYMBOL", "strong global reference definition required " + name)
            return result
        matches = [item for item in self.symbols if item["name"] == name and item["section"] != "SHN_UNDEF"]
        require(len(matches) == 1, "SYMBOL", "missing/ambiguous " + name)
        item = matches[0]
        require(kind == item["kind"] == "STT_FUNC" and item["binding"] == "STB_LOCAL"
                and type(item["section"]) is int and 0 < item["section"] < len(self.sections)
                and item["size"] > 0, "SYMBOL", "only first-start requires local function definition")
        h = self.sections[item["section"]].header
        base = item["value"] & ~1
        origin = h.sh_addr if self.final else 0
        require(h.sh_flags & 2 and origin <= base and base + item["size"] <= origin + h.sh_size,
                "SYMBOL", "definition bounds " + name)
        require(item["value"] & 1 and h.sh_flags & 4 and h.sh_type == "SHT_PROGBITS",
                "SYMBOL", "Thumb executable definition required " + name)
        for other in self.symbols:
            if other is item or other["kind"] != "STT_FUNC" or other["section"] != item["section"]:
                continue
            other_base = other["value"] & ~1
            require(not (base <= other_base < base + item["size"]
                         or other_base <= base < other_base + other["size"]),
                    "SYMBOL", "overlapping function/alias " + name)
        if self.final:
            self.read(base, item["size"])
            require(any(load["Flags"] & 1 and load["Vaddr"] <= base
                        and base + item["size"] <= load["Vaddr"] + load["FileSize"]
                        for load in self.loads), "SYMBOL", "function load is not executable")
            require(self.mapping(item["section"], base)[0] == "t", "SYMBOL", "callee not Thumb mapped")
        return item


class _ReferenceFinalImage(native.FinalImage):
    ROOTS = ROOTS

    def __init__(self, prelink, final, disassembly, *, provider_objects=None, link_map=None, mode="O2"):
        require(type(mode) is str and mode in MODES, "SCOPE", "mode must be O0, Og, O2, Os or O3")
        profiles = {ReferenceCM4FinalImage: ("CM4", _CM4), ReferenceCM7FinalImage: ("CM7", _CM7)}
        require(type(self) in profiles, "SCOPE", "only fixed reference CM4/CM7 reader classes admitted")
        self.profile, self._contract = profiles[type(self)]
        self.mode = mode
        super().__init__(prelink, final, disassembly, provider_objects=provider_objects,
                         link_map=link_map, float_abi="hard")
        self.prelink = _FixedSymbols(self.prelink)
        self.final = _FixedSymbols(self.final)
        self.providers = {identity: _FixedSymbols(provider) for identity, provider in self.providers.items()}

    def _origin(self, name, definition):
        require(name in ROOTS or name in (CALLEE, SLOT), "SCOPE", "foreign reference origin")
        if name in ROOTS:
            matches = [provider for provider in self.providers.values() for symbol in provider.symbols
                       if symbol["name"] == name and symbol["section"] != "SHN_UNDEF"]
            require(len(matches) == 1, "ORIGIN", "unique original definition required " + name)
            require(matches[0].data == self.prelink.data,
                    "ORIGIN", "root provider differs from bound prelink object")
        return super()._origin(name, definition)

    def function(self, name):
        require(type(name) is str and name in ROOTS, "SCOPE", "only three pinned reference " + self.profile + " transfer roots admitted")
        original = self.prelink.symbol(name, "STT_FUNC", root=True)
        final = self.final.symbol(name, "STT_FUNC", root=True)
        base_size = self._contract["Sizes"][name]
        tail_nops = int(self.mode == "O0")
        require(original["size"] == final["size"] == base_size + 2 * tail_nops,
                "PRESERVATION", "root extent changed")
        root_origin = self._origin(name, final)
        before, source_instructions, source_data = self._body(self.prelink, original)
        after, instructions, data = self._body(self.final, final)
        rows = self._contract["Protocol"][name]
        if tail_nops:
            rows += ((base_size, "00bf", "nop", ""),)
        expected_layout = [(offset, len(bytes.fromhex(raw))) for offset, raw, _, _ in rows]
        require(source_data == data == list(self._contract["Data"][name]) and expected_layout
                == [(off, len(raw)) for off, raw, _ in source_instructions]
                == [(off, len(raw)) for off, raw, _ in instructions],
                "PRESERVATION", "mapping/layout changed")
        start, source_start = final["value"] & ~1, original["value"] & ~1
        def relocs(elf, symbol):
            origin = elf.sections[symbol["section"]].header.sh_addr if elf.final else 0
            base = symbol["value"] & ~1
            return {off + origin - base: item for (sec, off), item in elf.relocations.items()
                    if sec == symbol["section"] and base <= off + origin < base + symbol["size"]}
        source_relocs, final_relocs = relocs(self.prelink, original), relocs(self.final, final)
        expected_relocs = self._contract["Relocations"][name]
        require(set(source_relocs) == set(final_relocs) == set(expected_relocs),
                "RELOC", "relocation membership changed")
        source_forms = {off: form for off, _, form in source_instructions}
        final_forms = {off: form for off, _, form in instructions}
        references, patched = [], set()
        for offset, (expected_kind, target_name) in expected_relocs.items():
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
                require(definition["size"] == 4 and definition["value"] % 4 == 0,
                        "SYMBOL", "current-slot size/alignment")
                self._origin(SLOT, definition)
                resolved = definition["value"]
                require(struct.unpack_from("<I", after, offset)[0] == resolved,
                        "RELOC", "applied ABS32 word differs from expected symbol+original addend")
            require(all(final_target[key] == definition[key] for key in ("section", "value", "kind", "binding")),
                    "RELOC", "final relocation does not name exact definition")
            references.append(dict(Offset=offset, Kind=kind, Symbol=target_name, Addend=addend,
                                   Place=start + offset, ResolvedValue=resolved,
                                   OriginalBytes=before[offset:offset + 4].hex(),
                                   Bytes=after[offset:offset + 4].hex(), Binding=definition["binding"]))
            patched.update(range(offset, offset + 4))
        require(all(a == b for offset, (a, b) in enumerate(zip(before, after)) if offset not in patched),
                "PRESERVATION", "non-relocation bytes changed")
        for offset, raw, _, _ in rows:
            if offset not in expected_relocs:
                require(before[offset:offset + len(bytes.fromhex(raw))] == bytes.fromhex(raw),
                        "PROTOCOL", "original instruction differs from fixed " + self.profile + " source contract")
        a, b = self._contract["IslandSpan"][name]
        expected_data = bytes.fromhex("000008ed00e0") if name == FIRST else bytes(4)
        require(before[a:b] == expected_data, "PROTOCOL", "original literal island differs from source contract")
        output = []
        literal_instruction, pool = self._contract["Literals"][name]
        for offset, raw, expected_op, expected_operand in rows:
            size = len(bytes.fromhex(raw))
            raw_final = after[offset:offset + size]
            record = self.instructions.get((final["section"], start + offset))
            require(record is not None and record[2] == raw_final,
                    "DECODE", "missing/mismatched disassembly instruction")
            op, operands, _ = record
            require(op == expected_op, "PROTOCOL", "instruction mnemonic differs from fixed " + self.profile + " source contract")
            form, target_address = final_forms[offset], None
            if op == "bl":
                require(form is not None and form[0] == "bl", "DECODE", "BL mnemonic disagrees with bits")
                target_address = form[1]
                argument = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", operands)
                require(argument is not None and int(argument[1], 16) == target_address,
                        "DECODE", "branch disassembly target disagrees with bits")
            else:
                require(_operand(op, operands) == expected_operand,
                        "PROTOCOL", "instruction operands differ from fixed " + self.profile + " source contract")
                if offset == literal_instruction:
                    require(form is not None and form[0] == "ldr" and form[1] == start + pool
                            and source_forms[offset] is not None
                            and source_forms[offset][1] == source_start + pool,
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
        for (section, address), record in self.instructions.items():
            if section == final["section"] and start <= address < start + final["size"] and address not in covered:
                offset = address - start
                require(record is not None and record[0] in (".word", ".short", ".byte")
                        and any(begin <= offset and offset + len(record[2]) <= end for begin, end in data)
                        and after[offset:offset + len(record[2])] == record[2],
                        "DECODE", "extra/interior/mismatched disassembly record")
        return dict(Name=name, Address=start, Size=len(after), BodySha256=native.sha256(after),
                    InstructionCount=len(output), Instructions=output,
                    LiteralIslands=[dict(Offset=a, Bytes=after[a:b].hex(),
                                        References=[dict(Instruction=literal_instruction, Offset=pool - a)])],
                    DataMappings=[dict(Offset=begin, Size=end - begin, Bytes=after[begin:end].hex())
                                  for begin, end in data],
                    References=references, Complete=True, PrelinkBoundRootPreservation=True,
                    RootOrigin=root_origin, DefinitionOrigins=[self.origin_evidence[target] for target in sorted(
                        {reference["Symbol"] for reference in references})],
                    ProofScope="PINNED_REFERENCE_" + self.profile + "_THREE_TRANSFER_ROOTS_ONLY", ExpectedFreeRTOSPin=PIN,
                    Profile=self.profile, Mode=self.mode, TailNops=tail_nops,
                    SourcePinBindingVerified=False, CohortBindingVerified=False, ModeBindingVerified=False,
                    RequiredCellSatisfied=False, FinalParity=False, KernelRuntimeProof=False,
                    CPUProof=False, GlobalProof=False)


class ReferenceCM4FinalImage(_ReferenceFinalImage):
    """Only the fixed pinned ARM_CM4F transfer-root contract."""


class ReferenceCM7FinalImage(_ReferenceFinalImage):
    """Only the fixed pinned ARM_CM7/r0p1 transfer-root contract."""
