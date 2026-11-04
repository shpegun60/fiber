"""Fixed pinned CM0 reference final roots; not kernel, routing or CPU proof.

The caller authenticates sources, providers, compiler mode and link map and
separately matches the same two owning objects' five complete protocols.
Section-end pools are retained separately, never absorbed into function size.
The shared classic reader is loaded unchanged; none of its globals is patched.
"""

import importlib.util
from pathlib import Path
import re
import struct


_spec = importlib.util.spec_from_file_location(
    "cm0_final_roots_immutable_core",
    Path(__file__).resolve().parents[1] / "classic_final_image/elf.py")
core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(core)
Rejected = core.Rejected
compare_load_images = core.compare_load_images
require = core.require

PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"
MODES = ("O0", "Og", "O2", "Os", "O3")
FIRST = "vStartFirstTask"
SVC = "SVC_Handler"
HELPER = "vPortSVCHandler_C"
RESTORE = "vRestoreContextOfFirstTask"
PENDSV = "PendSV_Handler"
SLOT = "pxCurrentTCB"
SCHEDULER = "vTaskSwitchContext"
ROOT_OWNERS = {FIRST: 1, SVC: 1, HELPER: 0, RESTORE: 1, PENDSV: 1}
ROOTS = frozenset(ROOT_OWNERS)


def _rows(text):
    result, offset = [], 0
    for line in text.strip().splitlines():
        raw, op, operands = line.strip().split(" ", 2)
        result.append((offset, bytes.fromhex(raw), op, operands))
        offset += len(result[-1][1])
    return tuple(result)


# Source-transcribed instruction contracts, not learned object fingerprints.
# Branch operands name exact root-relative targets; literals are checked from
# their instruction bits and the separately bounded external pool below.
_ASM = {
    FIRST: _rows("""
62b6 cpsie i
bff34f8f dsb #15
bff36f8f isb #15
64df svc 100
c046 nop -
c046 nop -
"""),
    SVC: _rows("""
0420 movs r0,#4
7146 mov r1,lr
0842 tst r0,r1
03d0 beq @16
eff30980 mrs r0,psp
044b ldr literal
1847 bx r3
eff30880 mrs r0,msp
024b ldr literal
1847 bx r3
c046 nop -
c046 nop -
c046 nop -
c046 nop -
"""),
    RESTORE: _rows("""
074a ldr literal
1168 ldr r1,[r2,#0]
0868 ldr r0,[r1,#0]
04c8 ldmia r0!,{r2}
0221 movs r1,#2
81f31488 msr control,r1
2030 adds r0,#32
80f30988 msr psp,r0
bff36f8f isb #15
1047 bx r2
c046 nop -
c046 nop -
c046 nop -
"""),
    PENDSV: _rows("""
eff30980 mrs r0,psp
0e4a ldr literal
1168 ldr r1,[r2,#0]
2438 subs r0,#36
0860 str r0,[r1,#0]
7346 mov r3,lr
f8c0 stmia r0!,{r3,r4,r5,r6,r7}
4446 mov r4,r8
4d46 mov r5,r9
5646 mov r6,r10
5f46 mov r7,r11
f0c0 stmia r0!,{r4,r5,r6,r7}
72b6 cpsid i
fff7feff bl vTaskSwitchContext
62b6 cpsie i
074a ldr literal
1168 ldr r1,[r2,#0]
0868 ldr r0,[r1,#0]
1430 adds r0,#20
f0c8 ldmia r0!,{r4,r5,r6,r7}
a046 mov r8,r4
a946 mov r9,r5
b246 mov r10,r6
bb46 mov r11,r7
80f30988 msr psp,r0
2438 subs r0,#36
f8c8 ldmia r0!,{r3,r4,r5,r6,r7}
1847 bx r3
c046 nop -
"""),
}
_C_SPEED = _rows("""
10b5 push {r4,lr}
8369 ldr r3,[r0,#24]
023b subs r3,#2
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
00d0 beq @14
fee7 b @12
fff7feff bl vRestoreContextOfFirstTask
10bd pop {r4,pc}
""")
_C_SIZE = _rows("""
10b5 push {r4,lr}
8369 ldr r3,[r0,#24]
023b subs r3,#2
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
02d1 bne @18
fff7feff bl vRestoreContextOfFirstTask
10bd pop {r4,pc}
fee7 b @18
""")
_C_O0 = _rows("""
80b5 push {r7,lr}
84b0 sub sp,#16
00af add r7,sp,#0
7860 str r0,[r7,#4]
7b68 ldr r3,[r7,#4]
9b69 ldr r3,[r3,#24]
fb60 str r3,[r7,#12]
fb68 ldr r3,[r7,#12]
023b subs r3,#2
1a00 movs r2,r3
0b21 movs r1,#11
7b18 adds r3,r7,r1
1278 ldrb r2,[r2,#0]
1a70 strb r2,[r3,#0]
7b18 adds r3,r7,r1
1b78 ldrb r3,[r3,#0]
642b cmp r3,#100
02d1 bne @42
fff7feff bl vRestoreContextOfFirstTask
01e0 b @46
c046 nop -
fde7 b @42
c046 nop -
bd46 mov sp,r7
04b0 add sp,#16
80bd pop {r7,pc}
""")
_LITERAL_REGS = {SVC: {12: 3, 20: 3}, RESTORE: {0: 2}, PENDSV: {4: 2, 34: 2}}
_BASE_SIZES = {FIRST: 16, SVC: 32, RESTORE: 32, PENDSV: 64}


def _contract(name, mode):
    o0 = int(mode == "O0")
    if name == HELPER:
        rows = _C_O0 if o0 else _C_SIZE if mode == "Os" else _C_SPEED
        size = 54 if o0 else 20
        return dict(Rows=rows, Size=size, SectionSize=size, Mappings=((0, "t"),),
                    Pool=None, Relocations={36 if o0 else 12 if mode == "Os" else 14: (10, RESTORE)},
                    TailNops=0)
    rows = tuple((offset, bytes((raw[0] + 1, raw[1])) if o0 and operand == "literal" else raw,
                  op, operand) for offset, raw, op, operand in _ASM[name])
    base = _BASE_SIZES[name]
    if o0:
        rows += ((base, bytes.fromhex("c046"), "nop", "-"),)
    size = base + 2 * o0
    pool = None if name == FIRST else base + 4 * o0
    mappings = ((0, "t"),) if pool is None else (
        ((0, "t"), (size, "d"), (pool, "d")) if o0 else ((0, "t"), (pool, "d")))
    relocs = {} if pool is None else {pool: (2, HELPER if name == SVC else SLOT)}
    if name == PENDSV:
        relocs[28] = (10, SCHEDULER)
    return dict(Rows=rows, Size=size, SectionSize=(20 if o0 else 16) if pool is None else pool + 4,
                Mappings=mappings, Pool=pool, Relocations=relocs,
                TailNops={FIRST: 2, SVC: 4, RESTORE: 3, PENDSV: 1}[name] + o0)


def _operand(op, text):
    text = re.sub(r"\s+", "", text.lower())
    text = re.sub(r"\b(sl|fp|r14)\b",
                  lambda m: {"sl": "r10", "fp": "r11", "r14": "lr"}[m[0]], text)
    return "#15" if op in ("dsb", "isb") and text == "sy" else text


class ReferenceCM0FinalImage(core.FinalImage):
    """Only five fixed non-MPU, soft-ABI, pinned ARM_CM0 reference roots."""

    ROOTS = ROOTS

    def __init__(self, port_object, portasm_object, final_elf, disassembly, *,
                 provider_objects, link_map, mode="O2"):
        require(type(self) is ReferenceCM0FinalImage and type(mode) is str and mode in MODES,
                "SCOPE", "fixed CM0 reader and ordinary mode required")
        if isinstance(provider_objects, (list, tuple)):
            require(len(provider_objects) == 5, "ORIGIN", "exactly five provider paths required")
            provider_objects = {str(path): path for path in provider_objects}
        require(type(provider_objects) is dict and len(provider_objects) == 5 and link_map is not None,
                "ORIGIN", "exactly five direct providers and a linker map required")
        self.mode = mode
        super().__init__(port_object, final_elf, disassembly, provider_objects=provider_objects,
                         link_map=link_map, float_abi="soft")
        self.owners = (self.prelink, core._ELF(portasm_object, "ET_REL"))
        require(self.owners[1].elf.header.e_flags == self.prelink.elf.header.e_flags,
                "ELF", "owning object ABI flags differ")
        self.hashes["PortasmSha256"] = core.sha256(self.owners[1].data)
        require(len(self.providers) == 5, "ORIGIN", "five unique provider identities required")
        identities = [Path(path).stat() for path in provider_objects.values()]
        require(len({(info.st_dev, info.st_ino) for info in identities}) == 5,
                "ORIGIN", "five physically distinct provider objects required")
        self.owner_identities = []
        for image in self.owners:
            matches = [identity for identity, provider in self.providers.items() if provider.data == image.data]
            require(len(matches) == 1,
                    "ORIGIN", "owning object must be exactly one supplied provider")
            self.owner_identities.append(matches[0])
        require(len(set(self.owner_identities)) == 2, "ORIGIN", "distinct port and portasm owners required")
        for name, kind in ((SCHEDULER, "STT_FUNC"), (SLOT, "STT_OBJECT")):
            matches = [identity for identity, provider in self.providers.items() for symbol in provider.symbols
                       if symbol["name"] == name and symbol["section"] != "SHN_UNDEF"]
            require(len(matches) == 1 and matches[0] not in self.owner_identities,
                    "ORIGIN", "unique unavailable-kernel provider required " + name)
            if name == SCHEDULER:
                self.kernel_identity = matches[0]
            require(matches[0] == self.kernel_identity, "ORIGIN", "scheduler and current-TCB must share provider")
            self.providers[matches[0]].symbol(name, kind)

    def _origin(self, name, definition):
        require(name in ROOTS or name in (SCHEDULER, SLOT), "ORIGIN", "foreign definition origin")
        if name in self.origin_evidence:
            return self.origin_evidence[name]
        matches = [(identity, provider) for identity, provider in self.providers.items()
                   for symbol in provider.symbols
                   if symbol["name"] == name and symbol["section"] != "SHN_UNDEF"]
        require(len(matches) == 1, "ORIGIN", "unique original definition required " + name)
        identity, provider = matches[0]
        expected_identity = self.owner_identities[ROOT_OWNERS[name]] if name in ROOTS else self.kernel_identity
        require(identity == expected_identity, "ORIGIN", "wrong owning object " + name)
        original = provider.symbol(name, definition["kind"], root=name in ROOTS)
        require(original["visibility"] == definition["visibility"] == "STV_DEFAULT",
                "ORIGIN", "source/final definition visibility differs " + name)
        section = provider.sections[original["section"]]
        h = section.header
        require(provider.names.count(section.name) == 1, "ORIGIN", "ambiguous original section")
        require(section.name == (".bss." if name == SLOT else ".text.") + name,
                "ORIGIN", "exact named source section required " + name)
        key = (identity, section.name)
        require(key in self.placements, "ORIGIN", "missing original section placement " + name)
        address, size = self.placements[key]
        function = original["kind"] == "STT_FUNC"
        offset = original["value"] & ~1 if function else original["value"]
        actual = definition["value"] & ~1 if function else definition["value"]
        final_header = self.final.sections[definition["section"]].header
        require(offset == 0 and size == h.sh_size and offset + original["size"] <= size
                and address + offset == actual and original["size"] == definition["size"]
                and address % max(1, h.sh_addralign) == 0
                and final_header.sh_addr <= address
                and address + size <= final_header.sh_addr + final_header.sh_size,
                "ORIGIN", "original section/offset/size does not place final definition " + name)
        require((h.sh_type == "SHT_NOBITS") == (final_header.sh_type == "SHT_NOBITS")
                and h.sh_flags & 7 == final_header.sh_flags & 7,
                "ORIGIN", "original/final definition storage differs " + name)
        if name == SLOT:
            require(original["size"] == size == 4 and address % 4 == 0 and h.sh_type == "SHT_NOBITS"
                    and h.sh_flags & 7 == 3, "ORIGIN", "exact current-TCB zero-filled storage required")
        if function:
            require(any(load["Flags"] & 1 and load["Vaddr"] <= address
                        and address + size <= load["Vaddr"] + load["FileSize"] for load in self.final.loads),
                    "ORIGIN", "complete owning section requires executable file-backed load")
        evidence = dict(Name=name, Provider=identity, ProviderSha256=core.sha256(provider.data),
                        InputSection=section.name, SectionAddress=address, SectionSize=size,
                        SymbolOffset=offset, Size=original["size"], Entry=actual,
                        LinkMapSha256=self.link_map_hash, SymbolOriginBound=True,
                        CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False)
        self.origin_evidence[name] = evidence
        return evidence

    @staticmethod
    def _mappings(image, section, address, size):
        result = []
        for symbol in image.symbols:
            match = re.fullmatch(r"\$([atd])(?:\..*)?", symbol["name"])
            if match and symbol["section"] == section and address <= symbol["value"] < address + size:
                require(symbol["kind"] == "STT_NOTYPE" and symbol["binding"] == "STB_LOCAL"
                        and symbol["size"] == 0, "MAPPING", "invalid owning-section mapping symbol")
                result.append((symbol["value"] - address, match[1]))
        result.sort()
        require(len({offset for offset, _ in result}) == len(result), "MAPPING", "duplicate mapping boundary")
        return tuple(result)

    @staticmethod
    def _relocations(image, section, address, size):
        origin = image.sections[section].header.sh_addr if image.final else 0
        result = {}
        for (number, offset), relocation in image.relocations.items():
            if number == section and address <= origin + offset < address + size:
                position = origin + offset - address
                require(position + 4 <= size, "RELOC", "relocation crosses owning-section extent")
                result[position] = relocation
        return result

    @staticmethod
    def _form(raw, address, name, offset):
        # These three fixed stack/dispatch transfers are the only exceptions
        # to the immutable core's BX-LR-only decoder. No runtime target claim.
        if len(raw) == 2 and struct.unpack("<H", raw)[0] & 0xFF00 == 0x4700:
            expected = {SVC: {14: bytes.fromhex("1847"), 22: bytes.fromhex("1847")},
                        RESTORE: {24: bytes.fromhex("1047")},
                        PENDSV: {60: bytes.fromhex("1847")}}
            require(expected.get(name, {}).get(offset) == raw,
                    "DECODE", "only exact fixed CM0 dispatch/stack BX sites admitted")
            return "bx", None, (struct.unpack("<H", raw)[0] >> 3) & 15, None
        return core._address_form(raw, address)

    def _section(self, name, original, final, contract):
        source = self.owners[ROOT_OWNERS[name]]
        section = source.sections[original["section"]]
        origin = self._origin(name, final)
        start, size = origin["SectionAddress"], contract["SectionSize"]
        require(original["size"] == final["size"] == contract["Size"]
                and section.header.sh_size == origin["SectionSize"] == size,
                "PRESERVATION", "fixed function or owning-section extent changed")
        require(self._mappings(source, original["section"], 0, size) == contract["Mappings"]
                and self._mappings(self.final, final["section"], start, size) == contract["Mappings"],
                "MAPPING", "exact complete owning-section mappings required")
        for image, number, begin in ((source, original["section"], 0), (self.final, final["section"], start)):
            for symbol in image.symbols:
                if symbol["kind"] == "STT_FUNC" and symbol["section"] == number and symbol["name"] != name:
                    other = symbol["value"] & ~1
                    require(not (other < begin + size and begin < other + max(1, symbol["size"])),
                            "SYMBOL", "foreign function overlaps whole root section")
        before = source.section_read(original["section"], 0, size)
        after = self.final.read(start, size)
        rows, cursor = contract["Rows"], 0
        for offset, raw, op, _ in rows:
            require(offset == cursor and core._width(struct.unpack_from("<H", raw)[0]) == len(raw),
                    "DECODE", "fixed instruction extent")
            cursor += len(raw)
            if op != "bl":
                require(before[offset:cursor] == raw, "PRESERVATION", "original fixed CM0 instruction differs")
        require(cursor == contract["Size"], "PRESERVATION", "complete fixed function consumption required")
        pool = contract["Pool"]
        if pool is not None:
            require(before[cursor:pool] == bytes(pool - cursor),
                    "PRESERVATION", "original external pool alignment differs")
        else:
            expected_suffix = bytes.fromhex("c046") if name == FIRST and self.mode == "O0" else b""
            require(before[cursor:] == expected_suffix, "PRESERVATION", "original section padding differs")
        return source, origin, start, before, after

    def _references(self, name, original, final, contract, source, start, before, after):
        source_relocs = self._relocations(source, original["section"], 0, len(before))
        final_relocs = self._relocations(self.final, final["section"], start, len(after))
        expected = contract["Relocations"]
        require(set(source_relocs) == set(final_relocs) == set(expected), "RELOC", "whole-section relocation membership changed")
        result, patched = [], set()
        rows = {offset: raw for offset, raw, _, _ in contract["Rows"]}
        for offset, (expected_kind, target_name) in sorted(expected.items()):
            kind, target = source_relocs[offset]
            final_kind, final_target = final_relocs[offset]
            require(kind == final_kind == expected_kind and target["name"] == final_target["name"] == target_name,
                    "RELOC", "relocation kind or target differs")
            require(target["section"] == "SHN_UNDEF" and target["binding"] == "STB_GLOBAL"
                    and target["kind"] == "STT_NOTYPE" and target["value"] == target["size"] == 0,
                    "RELOC", "exact original external relocation symbol required")
            require(not patched.intersection(range(offset, offset + 4)), "RELOC", "overlapping relocation fields")
            definition = self.final.symbol(target_name, "STT_OBJECT" if target_name == SLOT else "STT_FUNC",
                                           root=target_name in ROOTS)
            self._origin(target_name, definition)
            if kind == 10:
                require(offset in rows and len(rows[offset]) == 4, "RELOC", "BL must begin at fixed instruction boundary")
                source_form = self._form(before[offset:offset + 4], offset, name, offset)
                final_form = self._form(after[offset:offset + 4], start + offset, name, offset)
                require(source_form is not None and final_form is not None
                        and source_form[0] == final_form[0] == "bl" and source_form[3] == -4,
                        "RELOC", "original BL addend -4 required")
                addend, resolved = source_form[3], definition["value"] & ~1
                require(final_form[1] == resolved, "RELOC", "applied BL destination differs from bound entry")
            else:
                require(offset == contract["Pool"] and offset >= original["size"] and (start + offset) % 4 == 0,
                        "RELOC", "ABS32 must occupy the separately mapped external pool")
                addend = struct.unpack_from("<i", before, offset)[0]
                resolved = definition["value"]
                require(addend == 0 and struct.unpack_from("<I", after, offset)[0] == resolved,
                        "RELOC", "applied ABS32 differs from exact original addend-zero target")
                require(target_name != HELPER or resolved & 1, "RELOC", "SVC helper pool must retain Thumb entry bit")
            require(all(final_target[key] == definition[key] for key in
                        ("name", "section", "value", "size", "kind", "binding", "visibility")),
                    "RELOC", "final relocation does not name exact bound definition")
            result.append(dict(Offset=offset, Kind=kind, Symbol=target_name, Addend=addend,
                               Place=start + offset, ResolvedValue=resolved,
                               OriginalBytes=before[offset:offset + 4].hex(), Bytes=after[offset:offset + 4].hex(),
                               Binding=definition["binding"]))
            patched.update(range(offset, offset + 4))
        require(all(old == new for offset, (old, new) in enumerate(zip(before, after)) if offset not in patched),
                "PRESERVATION", "non-relocation owning-section bytes changed")
        return result

    def function(self, name):
        require(type(name) is str and name in ROOTS, "SCOPE", "only five pinned CM0 reference roots")
        contract = _contract(name, self.mode)
        source = self.owners[ROOT_OWNERS[name]]
        original = source.symbol(name, "STT_FUNC", root=True)
        final = self.final.symbol(name, "STT_FUNC", root=True)
        source, origin, start, before, after = self._section(name, original, final, contract)
        references = self._references(name, original, final, contract, source, start, before, after)
        output, literal_references = [], []
        rows = contract["Rows"]
        boundaries = {offset for offset, _, _, _ in rows}
        for offset, raw, expected_op, expected_operand in rows:
            actual = after[offset:offset + len(raw)]
            record = self.instructions.get((final["section"], start + offset))
            require(record is not None and record[2] == actual, "DECODE", "missing/mismatched disassembly instruction")
            op, operands, _ = record
            require(op == expected_op, "DECODE", "fixed instruction mnemonic differs")
            source_form = self._form(raw, offset, name, offset)
            form = self._form(actual, start + offset, name, offset)
            target_address = None
            if expected_operand == "literal":
                pool, register = contract["Pool"], _LITERAL_REGS[name][offset]
                require(source_form is not None and form is not None and source_form[0] == form[0] == "ldr"
                        and source_form[1] == pool and form[1] == start + pool
                        and source_form[2] == form[2] == register,
                        "DECODE", "literal bits must name exact separately mapped pool/register")
                require(_operand(op, operands) == "r%d,[pc,#%d]" % (register, form[3]),
                        "DECODE", "literal disassembly operands disagree with bits")
                target_address = form[1]
                literal_references.append(dict(Instruction=offset, Offset=pool, Address=target_address, Register=register))
            elif op == "bl" or expected_operand.startswith("@"):
                require(source_form is not None and form is not None and source_form[0] == form[0] == op,
                        "DECODE", "branch mnemonic disagrees with instruction bits")
                if op != "bl":
                    target = int(expected_operand[1:])
                    require(target in boundaries and source_form[1] == target and form[1] == start + target,
                            "DECODE", "branch must name exact fixed in-function instruction, not tail/pool")
                else:
                    require(contract["Relocations"].get(offset) == (10, expected_operand),
                            "RELOC", "unowned BL instruction")
                target_address = form[1]
                argument = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", operands)
                require(argument is not None and int(argument[1], 16) == target_address,
                        "DECODE", "branch disassembly target disagrees with bits")
            else:
                expected_operand = "" if expected_operand == "-" else expected_operand
                require(_operand(op, operands) == expected_operand, "DECODE", "fixed instruction operands differ")
                require((op == "bx" and form is not None and form[0] == "bx")
                        or (op != "bx" and source_form is None and form is None),
                        "DECODE", "unexpected address-bearing instruction")
            output.append(dict(Offset=offset, Bytes=actual.hex(), Mnemonic=op, Operands=operands, Target=target_address))
        self._disassembly_extent(name, final, contract, start, after, boundaries)
        pool = contract["Pool"]
        external = [] if pool is None else [dict(Offset=pool, Address=start + pool, Size=4,
            Bytes=after[pool:pool + 4].hex(), OriginalBytes=before[pool:pool + 4].hex(),
            References=literal_references, OutsideFunction=True, Mapping="d")]
        padding_end = pool if pool is not None else len(after)
        padding = [] if padding_end == contract["Size"] else [dict(Offset=contract["Size"],
            Address=start + contract["Size"], Size=padding_end - contract["Size"],
            Bytes=after[contract["Size"]:padding_end].hex(), Mapping="t" if name == FIRST else "d",
            CountedAsRootInstruction=False, UnreachabilityProven=False)]
        data_mappings = []
        for i, (offset, kind) in enumerate(contract["Mappings"]):
            if kind == "d":
                end = contract["Mappings"][i + 1][0] if i + 1 < len(contract["Mappings"]) else len(after)
                data_mappings.append(dict(Offset=offset, Size=end - offset, Bytes=after[offset:end].hex(),
                                          OutsideFunction=offset >= contract["Size"]))
        return dict(Name=name, Address=start, Size=contract["Size"], BodySha256=core.sha256(after[:contract["Size"]]),
            InstructionCount=len(output), Instructions=output, References=references, ExternalPools=external,
            ExternalPadding=padding,
            LiteralIslands=[], DataMappings=data_mappings,
            RootOrigin=origin, DefinitionOrigins=[self.origin_evidence[target] for target in sorted(
                {reference["Symbol"] for reference in references})],
            OwningSection=dict(Size=len(after), Sha256=core.sha256(after), OriginalSha256=core.sha256(before),
                Mappings=[dict(Offset=off, Kind=kind) for off, kind in contract["Mappings"]],
                OutsideFunctionBytes=after[contract["Size"]:].hex()),
            Complete=True, PrelinkBoundRootPreservation=True, ExpectedFreeRTOSPin=PIN, Mode=self.mode,
            TailNops=contract["TailNops"], ProofScope="PINNED_CM0_FIVE_REFERENCE_ROOTS_AND_EXTERNAL_POOLS_ONLY",
            SourcePinBindingVerified=False, CohortBindingVerified=False, ModeBindingVerified=False,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FinalParity=False, KernelRuntimeProof=False,
            PolicyEquivalence=False, HandlerRoutingProof=False, RuntimeBranchTargetProof=False,
            UnreachabilityProof=False, CPUProof=False, GlobalProof=False)

    def _disassembly_extent(self, name, final, contract, start, after, boundaries):
        covered = {start + offset for offset in boundaries}
        if name == FIRST and self.mode == "O0":
            record = self.instructions.get((final["section"], start + contract["Size"]))
            require(record is not None and record[0] == "nop" and record[2] == bytes.fromhex("c046")
                    and _operand("nop", record[1]) == "", "DECODE", "missing exact out-of-function start padding NOP")
        for (section, address), record in self.instructions.items():
            if section != final["section"] or not start <= address < start + len(after) or address in covered:
                continue
            offset = address - start
            require(record is not None and record[2] == after[offset:offset + len(record[2])],
                    "DECODE", "extra/interior/mismatched disassembly record")
            if name == FIRST and self.mode == "O0" and offset == contract["Size"]:
                require(record[0] == "nop" and record[2] == bytes.fromhex("c046")
                        and _operand("nop", record[1]) == "", "DECODE", "exact out-of-function start padding NOP")
                continue
            ranges = [(begin, contract["Mappings"][i + 1][0] if i + 1 < len(contract["Mappings"]) else len(after))
                      for i, (begin, kind) in enumerate(contract["Mappings"]) if kind == "d"]
            require(record[0] in (".word", ".short", ".byte")
                    and any(begin <= offset and offset + len(record[2]) <= end for begin, end in ranges),
                    "DECODE", "unowned instruction or data record inside complete section")
