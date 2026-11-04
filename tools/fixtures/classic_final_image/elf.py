"""Strict native classic CM4/CM7 final-image reader, not a parity proof.

The caller separately checks the prelink object's source-transcribed protocol.
Ordinary instructions are bound byte-for-byte, not independently decompiled.
Only the observed address-bearing forms are independently decoded here.

GNU ld --emit-relocs retains applied relocation metadata:
https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002demit_002drelocs
REL application destroys the original addend; take it only from prelink bytes:
https://github.com/ARM-software/abi-aa/blob/main/aaelf32/aaelf32.rst#562-idempotency
Thumb encodings: Arm DDI0403, B (T1/T2/T3), BL (T1), LDR literal (T1).
T3 field layout also specified in Arm DDI0597 (2024-03), B, page 52:
https://documentation-service.arm.com/static/66054b941bc22b03bca913ed
"""

from bisect import bisect_right
import hashlib
from io import BytesIO
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import struct
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection


if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")


class Rejected(Exception):
    pass


def require(condition, code, detail):
    if not condition:
        raise Rejected("REJECT:" + code + ":" + str(detail).replace("\n", " "))


ROOTS = frozenset(("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler"))
CALLEES = frozenset(("fiber_panic", "fiber_port_context_validate_restore",
                     "fiber_port_context_validate_save_current",
                     "fiber_port_scheduler_pick_next_from_pendsv"))
SLOT = "fiber_internal_runtime_current_context_slot"
CONDITIONS = ("beq", "bne", "bcs", "bcc", "bmi", "bpl", "bvs", "bvc",
              "bhi", "bls", "bge", "blt", "bgt", "ble")
ORDINARY = frozenset(("cpsid", "cpsie", "dsb", "isb", "movs", "mov", "msr",
                      "mrs", "tst", "cmp", "lsrs", "lsls", "str", "svc", "mvn",
                      "ldr", "ldrb", "subs", "ubfx", "push", "pop", "ldmia",
                      "vldmia", "bic", "vstmdb", "stmdb", "nop"))


def sha256(data):
    return hashlib.sha256(data).hexdigest().upper()


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _width(halfword):
    return 4 if halfword >> 11 in (29, 30, 31) else 2


def _address_form(raw, place):
    """Return (operation, target, register, immediate), or no address form.

    BL T1 uses I1=NOT(J1 XOR S), I2=NOT(J2 XOR S), then sign-extends
    S:I1:I2:imm10:imm11:0. Branch PC is P+4, not Align(P+4,4).
    """
    require(len(raw) in (2, 4), "DECODE", "instruction width")
    first = struct.unpack_from("<H", raw)[0]
    require(len(raw) == _width(first), "DECODE", "encoded instruction width")
    if len(raw) == 2:
        if first & 0xF800 == 0xE000:
            return "b", place + 4 + _signed((first & 2047) << 1, 12), None, None
        if first & 0xF000 == 0xD000 and (first >> 8) & 15 < 14:
            return CONDITIONS[(first >> 8) & 15], place + 4 + _signed((first & 255) << 1, 9), None, None
        if first & 0xF800 == 0x4800:
            immediate = (first & 255) << 2
            return "ldr", ((place + 4) & ~3) + immediate, (first >> 8) & 7, immediate
        if first & 0xFF00 == 0x4700:
            require(first == 0x4770, "DECODE", "only BX LR register transfer is admitted")
            return "bx", None, None, None
        require(first & 0xF500 != 0xB100, "DECODE", "CBZ/CBNZ unsupported")
    else:
        second = struct.unpack_from("<H", raw, 2)[0]
        if first & 0xF800 == 0xF000:
            form = second & 0xD000
            if form == 0xD000:
                sign = (first >> 10) & 1
                i1 = 1 ^ ((second >> 13) & 1) ^ sign
                i2 = 1 ^ ((second >> 11) & 1) ^ sign
                immediate = _signed((sign << 24) | (i1 << 23) | (i2 << 22)
                                    | ((first & 1023) << 12) | ((second & 2047) << 1), 25)
                return "bl", place + 4 + immediate, None, immediate
            require(form != 0xC000, "DECODE", "BLX immediate unsupported")
            require(form != 0x9000, "DECODE", "T32 B.W unsupported")
            if form == 0x8000 and (first >> 6) & 15 < 14:
                require((first >> 6) & 15 == 1, "DECODE", "only T32 BNE.W conditional branch admitted")
                # B T3 concatenates J2/J1 directly, unlike BL's complemented
                # I1/I2 encoding. The signed immediate has 21 bits, not 25.
                immediate = _signed((((first >> 10) & 1) << 20)
                                    | (((second >> 11) & 1) << 19)
                                    | (((second >> 13) & 1) << 18)
                                    | ((first & 63) << 12) | ((second & 2047) << 1), 21)
                return "bne", place + 4 + immediate, None, None
            # Conditions 14/15 select related encodings (MRS/MSR/barriers),
            # not branches. Leave ordinary decoding intact; branch text with
            # no decoded branch form is rejected by function().
        require(first & 0xFF7F != 0xF85F, "DECODE", "T32 literal load unsupported")
    return None


class _ELF:
    def __init__(self, path, expected_type):
        self.data = Path(path).read_bytes()
        try:
            self.elf = ELFFile(BytesIO(self.data))
            require(self.elf.elfclass == 32 and self.elf.little_endian
                    and self.elf.header.e_machine == "EM_ARM"
                    and self.elf.header.e_type == expected_type,
                    "ELF", "expected ARM ELF32LE " + expected_type)
            self.final = expected_type == "ET_EXEC"
            self.sections = list(self.elf.iter_sections())
            self.names = [section.name for section in self.sections]
            self.symbols = []
            self.tables = {}
            for index, section in enumerate(self.sections):
                if isinstance(section, SymbolTableSection):
                    require(section.header.sh_type == "SHT_SYMTAB", "ELF", "dynamic symbols unsupported")
                    entries = []
                    for number, symbol in enumerate(section.iter_symbols()):
                        item = dict(name=symbol.name, value=symbol.entry.st_value,
                                    size=symbol.entry.st_size, kind=symbol.entry.st_info.type,
                                    binding=symbol.entry.st_info.bind, section=symbol.entry.st_shndx,
                                    visibility=symbol.entry.st_other.visibility, index=number)
                        self.symbols.append(item)
                        entries.append(item)
                    self.tables[index] = entries
            require(len(self.tables) == 1, "ELF", "one static symbol table required")
            self.loads = []
            for segment in self.elf.iter_segments():
                require(segment.header.p_type not in ("PT_INTERP", "PT_DYNAMIC"),
                        "ELF", "dynamic loading unsupported")
                if segment.header.p_type != "PT_LOAD":
                    continue
                h = segment.header
                item = dict(Vaddr=h.p_vaddr, Paddr=h.p_paddr, FileSize=h.p_filesz,
                            MemorySize=h.p_memsz, Flags=h.p_flags, Align=h.p_align,
                            Offset=h.p_offset)
                require(0 < h.p_memsz and h.p_filesz <= h.p_memsz
                        and h.p_vaddr + h.p_memsz <= 1 << 32
                        and h.p_paddr + h.p_memsz <= 1 << 32
                        and h.p_offset + h.p_filesz <= len(self.data), "ELF", "load bounds")
                require(h.p_align in (0, 1) or (h.p_align & (h.p_align - 1) == 0
                        and h.p_offset % h.p_align == h.p_vaddr % h.p_align),
                        "ELF", "load alignment")
                self.loads.append(item)
            self.loads.sort(key=lambda item: item["Vaddr"])
            require(all(a["Vaddr"] + a["MemorySize"] <= b["Vaddr"]
                        for a, b in zip(self.loads, self.loads[1:])), "ELF", "overlapping loads")
            require(not self.final or self.loads, "ELF", "missing load image")
            allocated = sorted((section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
                               for section in self.sections
                               if self.final and section.header.sh_flags & 2 and section.header.sh_size)
            require(all(a[1] <= b[0] for a, b in zip(allocated, allocated[1:])),
                    "ELF", "overlapping allocated sections")
            for section in self.sections:
                h = section.header
                if h.sh_type != "SHT_NOBITS":
                    require(h.sh_offset + h.sh_size <= len(self.data), "ELF", "section file bounds")
                if self.final and h.sh_flags & 2 and h.sh_size:
                    owners = [load for load in self.loads if load["Vaddr"] <= h.sh_addr
                              and h.sh_addr + h.sh_size <= load["Vaddr"] + load["MemorySize"]]
                    require(len(owners) == 1, "ELF", "allocated section load coverage")
                    require(not h.sh_flags & 1 or owners[0]["Flags"] & 2,
                            "ELF", "writable allocated section owner lacks PF_W")
                    if h.sh_type != "SHT_NOBITS":
                        require(self.read(h.sh_addr, h.sh_size) == section.data()
                                and owners[0]["Offset"] + h.sh_addr - owners[0]["Vaddr"] == h.sh_offset,
                                "ELF", "section/load disagreement")
            if self.final:
                for section in self.sections:
                    h = section.header
                    if h.sh_flags & 2 and h.sh_type == "SHT_NOBITS" and h.sh_size:
                        require(not any(h.sh_addr < load["Vaddr"] + load["FileSize"]
                                        and load["Vaddr"] < h.sh_addr + h.sh_size
                                        for load in self.loads if load["FileSize"]),
                                "ELF", "NOBITS overlaps file-backed load bytes")
            self.relocations = {}
            for section in self.sections:
                if not isinstance(section, RelocationSection):
                    continue
                require(section.header.sh_type == "SHT_REL", "RELOC", "only REL is admitted")
                target = section.header.sh_info
                require(0 < target < len(self.sections) and section.header.sh_link in self.tables,
                        "RELOC", "relocation section links")
                header = self.sections[target].header
                if not header.sh_flags & 2:
                    continue
                for relocation in section.iter_relocations():
                    offset = relocation.entry.r_offset - (header.sh_addr if self.final else 0)
                    symbol_index = relocation.entry.r_info_sym
                    require(0 <= offset < header.sh_size
                            and symbol_index < len(self.tables[section.header.sh_link]),
                            "RELOC", "relocation bounds")
                    key = (target, offset)
                    require(key not in self.relocations, "RELOC", "duplicate relocation")
                    self.relocations[key] = (relocation.entry.r_info_type,
                                             self.tables[section.header.sh_link][symbol_index])
        except Rejected:
            raise
        except Exception as error:
            raise Rejected("REJECT:ELF:malformed ELF: " + str(error)) from error

    def read(self, address, size):
        require(type(address) is int and type(size) is int and size > 0,
                "ELF", "read arguments")
        owners = [load for load in self.loads if load["Vaddr"] <= address
                  and address + size <= load["Vaddr"] + load["FileSize"]]
        require(len(owners) == 1, "ELF", "read requires unique file-backed load bytes")
        start = owners[0]["Offset"] + address - owners[0]["Vaddr"]
        return self.data[start:start + size]

    def section_read(self, section, offset, size):
        h = self.sections[section].header
        require(h.sh_type == "SHT_PROGBITS" and 0 <= offset and size > 0
                and offset + size <= h.sh_size, "ELF", "section read bounds/type")
        return self.data[h.sh_offset + offset:h.sh_offset + offset + size]

    def symbol(self, name, kind, *, root=False):
        matches = [item for item in self.symbols if item["name"] == name
                   and item["section"] != "SHN_UNDEF"]
        require(len(matches) == 1, "SYMBOL", "missing/ambiguous " + name)
        item = matches[0]
        bindings = ("STB_GLOBAL",) if root or name != "fiber_panic" else ("STB_GLOBAL", "STB_WEAK")
        require(item["kind"] == kind and item["binding"] in bindings
                and type(item["section"]) is int and 0 < item["section"] < len(self.sections)
                and item["size"] > 0, "SYMBOL", "invalid definition " + name)
        h = self.sections[item["section"]].header
        base = item["value"] & ~1 if kind == "STT_FUNC" else item["value"]
        origin = h.sh_addr if self.final else 0
        require(h.sh_flags & 2 and origin <= base and base + item["size"] <= origin + h.sh_size,
                "SYMBOL", "definition bounds " + name)
        if kind == "STT_FUNC":
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
        elif kind == "STT_OBJECT":
            require(h.sh_flags & 1 and not h.sh_flags & 4,
                    "SYMBOL", "current-slot requires writable non-executable storage")
        return item

    def mapping(self, section, address):
        h = self.sections[section].header
        origin = h.sh_addr if self.final else 0
        values = {}
        for symbol in self.symbols:
            match = re.fullmatch(r"\$([atd])(?:\..*)?", symbol["name"])
            if symbol["section"] != section or not match:
                continue
            require(symbol["kind"] == "STT_NOTYPE" and symbol["binding"] == "STB_LOCAL"
                    and symbol["size"] == 0 and origin <= symbol["value"] < origin + h.sh_size,
                    "MAPPING", "invalid mapping symbol")
            require(symbol["value"] not in values or values[symbol["value"]] == match[1],
                    "MAPPING", "conflicting mapping symbols")
            values[symbol["value"]] = match[1]
        starts = sorted(values)
        index = bisect_right(starts, address) - 1
        require(index >= 0 and address < origin + h.sh_size, "MAPPING", "missing mapping")
        return values[starts[index]], starts[index + 1] if index + 1 < len(starts) else origin + h.sh_size


def compare_load_images(plain_elf, emit_elf, *, vector_section=".isr_vector"):
    """Compare actual loader-visible bytes, including loaded metadata and fill."""
    plain, emit = _ELF(plain_elf, "ET_EXEC"), _ELF(emit_elf, "ET_EXEC")
    require(plain.elf.header.e_entry == emit.elf.header.e_entry
            and plain.elf.header.e_flags == emit.elf.header.e_flags, "TWIN", "entry/flags differ")
    def image(elf):
        return [(tuple((key, value) for key, value in load.items() if key != "Offset"),
                 elf.read(load["Vaddr"], load["FileSize"]) if load["FileSize"] else b"")
                for load in elf.loads]
    require(image(plain) == image(emit), "TWIN", "load geometry/bytes differ")
    def allocated(elf):
        result = []
        for section in elf.sections:
            h = section.header
            if h.sh_flags & 2:
                result.append((section.name, h.sh_type, h.sh_flags, h.sh_addr, h.sh_size,
                               h.sh_addralign, h.sh_entsize,
                               None if h.sh_type == "SHT_NOBITS" else section.data()))
        return sorted(result)
    require(allocated(plain) == allocated(emit), "TWIN", "allocated sections differ")
    vectors = [section for section in plain.sections if section.name == vector_section]
    require(len(vectors) == 1 and vectors[0].header.sh_flags & 2
            and vectors[0].header.sh_type == "SHT_PROGBITS" and vectors[0].header.sh_size > 0,
            "TWIN", "unique allocated vector section required")
    vector = vectors[0]
    segments = []
    for load in plain.loads:
        item = {key: value for key, value in load.items() if key != "Offset"}
        item["BytesSha256"] = sha256(plain.read(load["Vaddr"], load["FileSize"])) if load["FileSize"] else sha256(b"")
        segments.append(item)
    return dict(Identical=True, Entry=plain.elf.header.e_entry,
                VectorAddress=vector.header.sh_addr, VectorBytes=vector.data().hex(), Segments=segments)


def _object_identity(path):
    text = str(path).replace("\\", "/")
    windows = PureWindowsPath(text)
    if windows.is_absolute():
        require(".." not in windows.parts, "ORIGIN", "parent traversal in object identity")
        return windows.as_posix().casefold()
    posix = PurePosixPath(text)
    require(posix.is_absolute() and ".." not in posix.parts,
            "ORIGIN", "absolute object identity required")
    return posix.as_posix()


class FinalImage:
    def __init__(self, prelink_object, final_elf, disassembly, *, provider_objects=None, link_map=None):
        self.prelink = _ELF(prelink_object, "ET_REL")
        self.final = _ELF(final_elf, "ET_EXEC")
        # ET_REL normally leaves the float-ABI e_flags bits unset; GCC's final
        # hard-float link sets EF_ARM_ABI_FLOAT_HARD. Attributes remain the
        # outer cohort gate's responsibility, not a CPU claim by this reader.
        before_flags, after_flags = self.prelink.elf.header.e_flags, self.final.elf.header.e_flags
        require(before_flags & 0x600 in (0, 0x400)
                and after_flags == (before_flags | 0x400),
                "ELF", "prelink/final ABI flags differ")
        dis_bytes = Path(disassembly).read_bytes()
        self.hashes = dict(PrelinkSha256=sha256(self.prelink.data), FinalSha256=sha256(self.final.data),
                           DisassemblySha256=sha256(dis_bytes))
        self.providers = {}
        self.placements = {}
        self.origin_evidence = {}
        self.link_map_hash = None
        require(provider_objects is None or isinstance(provider_objects, dict),
                "ORIGIN", "provider_objects must map original absolute paths to captured files")
        for identity, captured in (provider_objects or {}).items():
            key = _object_identity(identity)
            require(key not in self.providers, "ORIGIN", "duplicate provider identity")
            provider = _ELF(captured, "ET_REL")
            require(provider.elf.header.e_flags == before_flags,
                    "ORIGIN", "provider ABI flags differ from prelink")
            self.providers[key] = provider
        if link_map is not None:
            require(self.providers, "ORIGIN", "map needs explicit provider objects")
            map_bytes = Path(link_map).read_bytes()
            self.link_map_hash = sha256(map_bytes)
            self._placements(map_bytes)
        self.instructions = {}
        section_index = None
        try:
            lines = dis_bytes.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise Rejected("REJECT:DECODE:disassembly encoding") from error
        for line in lines:
            heading = re.fullmatch(r"Disassembly of section (.+):", line)
            if heading:
                require(self.final.names.count(heading[1]) == 1, "DECODE", "ambiguous disassembly section")
                section_index = self.final.names.index(heading[1])
                continue
            match = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
            if not match or section_index is None:
                continue
            address = int(match[1], 16)
            row = re.fullmatch(r"([0-9a-fA-F]{8}|[0-9a-fA-F]{4}(?:\s+[0-9a-fA-F]{4})?)\s+([.]?[a-zA-Z][a-zA-Z0-9_.]*)(?:\s+(.*))?", match[2])
            key = (section_index, address)
            require(key not in self.instructions, "DECODE", "duplicate disassembly record")
            if row is None:
                self.instructions[key] = None
                continue
            words = row[1].split()
            raw = struct.pack("<I", int(words[0], 16)) if len(words) == 1 and len(words[0]) == 8 else b"".join(struct.pack("<H", int(word, 16)) for word in words)
            op = re.sub(r"\.[nw]$", "", row[2].lower())
            op = {"bhs": "bcs", "blo": "bcc"}.get(op, op)
            operands = re.split(r"[;@]|\s+[0-9a-fA-F]+:\s+R_ARM_", row[3] or "")[0].strip()
            self.instructions[key] = (op, operands, raw)

    def _placements(self, data):
        """Parse only GNU ld input-section placements, never symbol printouts.

        The outer build receipt binds this map to the recorded link command,
        object identities and captured bytes. No paths found in it are opened.
        """
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise Rejected("REJECT:ORIGIN:map encoding") from error
        marker = "Linker script and memory map"
        require(text.count(marker) == 1, "ORIGIN", "unique GNU ld map body required")
        wanted = {section.name for provider in self.providers.values()
                  for section in provider.sections if section.header.sh_flags & 2 and section.header.sh_size}
        pending = None
        for line in text.split(marker, 1)[1].splitlines():
            heading = re.fullmatch(r" ([.][^\s]+)(?:\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+))?\s*", line)
            if heading is not None and heading[1] in wanted:
                require(pending is None, "ORIGIN", "missing input-section placement")
                if heading[2] is None:
                    pending = heading[1]
                    continue
                name, address, size, identity = heading.groups()
            elif pending is not None:
                continuation = re.fullmatch(r"\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*", line)
                require(continuation is not None, "ORIGIN", "malformed input-section placement")
                name, (address, size, identity) = pending, continuation.groups()
                pending = None
            else:
                continue
            require(identity.endswith(".o"), "ORIGIN", "only direct object placements admitted")
            key = (_object_identity(identity), name)
            require(key not in self.placements, "ORIGIN", "duplicate input-section placement")
            self.placements[key] = (int(address, 16), int(size, 16))
        require(pending is None, "ORIGIN", "unfinished input-section placement")

    def _origin(self, name, definition):
        if name in self.origin_evidence:
            return self.origin_evidence[name]
        require(self.providers and self.link_map_hash is not None,
                "ORIGIN", "explicit provider objects and linker map required")
        matches = [(identity, provider, symbol) for identity, provider in self.providers.items()
                   for symbol in provider.symbols
                   if symbol["name"] == name and symbol["section"] != "SHN_UNDEF"]
        require(len(matches) == 1, "ORIGIN", "unique original definition required " + name)
        identity, provider, original = matches[0]
        original = provider.symbol(name, definition["kind"], root=name in ROOTS)
        if name in ROOTS:
            require(provider.data == self.prelink.data,
                    "ORIGIN", "root provider differs from bound prelink object")
        section = provider.sections[original["section"]]
        h = section.header
        require(provider.names.count(section.name) == 1, "ORIGIN", "ambiguous original section name")
        key = (identity, section.name)
        require(key in self.placements, "ORIGIN", "missing original section placement " + name)
        address, size = self.placements[key]
        function = original["kind"] == "STT_FUNC"
        offset = original["value"] & ~1 if function else original["value"]
        actual = definition["value"] & ~1 if function else definition["value"]
        final_header = self.final.sections[definition["section"]].header
        require(size == h.sh_size and offset + original["size"] <= size
                and address + offset == actual and original["size"] == definition["size"]
                and address % max(1, h.sh_addralign) == 0
                and final_header.sh_addr <= address
                and address + size <= final_header.sh_addr + final_header.sh_size,
                "ORIGIN", "original section/offset/size does not place final definition " + name)
        require((h.sh_type == "SHT_NOBITS") == (final_header.sh_type == "SHT_NOBITS")
                and h.sh_flags & 7 == final_header.sh_flags & 7,
                "ORIGIN", "original/final definition storage differs " + name)
        evidence = dict(Name=name, Provider=identity, ProviderSha256=sha256(provider.data),
                        InputSection=section.name, SectionAddress=address, SectionSize=size,
                        SymbolOffset=offset, Size=original["size"], Entry=actual,
                        LinkMapSha256=self.link_map_hash, SymbolOriginBound=True,
                        CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False)
        self.origin_evidence[name] = evidence
        return evidence

    def read(self, address, size):
        return self.final.read(address, size)

    def _body(self, elf, symbol):
        section = symbol["section"]
        start = symbol["value"] & ~1
        origin = elf.sections[section].header.sh_addr if elf.final else 0
        body = elf.section_read(section, start - origin, symbol["size"])
        result, data = [], []
        address, end = start, start + symbol["size"]
        while address < end:
            kind, boundary = elf.mapping(section, address)
            boundary = min(boundary, end)
            require(kind in ("t", "d"), "MAPPING", "non-Thumb root mapping")
            if kind == "d":
                data.append((address - start, boundary - start))
                address = boundary
                continue
            require(address % 2 == 0 and address + 2 <= boundary, "DECODE", "instruction alignment/extent")
            offset = address - start
            width = _width(struct.unpack_from("<H", body, offset)[0])
            require(address + width <= boundary, "DECODE", "instruction crosses mapping/extent")
            raw = body[offset:offset + width]
            result.append((offset, raw, _address_form(raw, address)))
            address += width
        require(result, "DECODE", "empty root")
        return body, result, data

    def function(self, name):
        require(name in ROOTS, "SCOPE", "only three native classic CM4/CM7 transfer roots admitted")
        original = self.prelink.symbol(name, "STT_FUNC", root=True)
        final = self.final.symbol(name, "STT_FUNC", root=True)
        require(original["size"] == final["size"], "PRESERVATION", "root extent changed")
        root_origin = self._origin(name, final)
        before, source_instructions, source_data = self._body(self.prelink, original)
        after, instructions, data_ranges = self._body(self.final, final)
        require(source_data == data_ranges and [(off, len(raw)) for off, raw, _ in source_instructions]
                == [(off, len(raw)) for off, raw, _ in instructions], "PRESERVATION", "mapping/layout changed")
        start = final["value"] & ~1
        source_start = original["value"] & ~1
        final_origin = self.final.sections[final["section"]].header.sh_addr
        def relocations(elf, symbol, base, origin):
            return {offset + origin - base: relocation for (section, offset), relocation in elf.relocations.items()
                    if section == symbol["section"] and base <= offset + origin < base + symbol["size"]}
        source_relocs = relocations(self.prelink, original, source_start, 0)
        final_relocs = relocations(self.final, final, start, final_origin)
        require(set(source_relocs) == set(final_relocs), "RELOC", "relocation membership changed")
        by_offset = {offset: (raw, form) for offset, raw, form in instructions}
        source_by_offset = {offset: (raw, form) for offset, raw, form in source_instructions}
        references, patched = [], set()
        for offset, (kind, target) in sorted(source_relocs.items()):
            final_kind, final_target = final_relocs[offset]
            require(kind == final_kind and target["name"] == final_target["name"]
                    and kind in (2, 10), "RELOC", "relocation kind/identity changed or unsupported")
            require(offset + 4 <= len(before) and not patched.intersection(range(offset, offset + 4)),
                    "RELOC", "overlapping/out-of-bounds relocation fields")
            if kind == 10:
                require(offset in source_by_offset and offset in by_offset, "RELOC", "call not on instruction boundary")
                source_form, final_form = source_by_offset[offset][1], by_offset[offset][1]
                require(source_form is not None and final_form is not None
                        and source_form[0] == final_form[0] == "bl" and source_form[3] == -4,
                        "RELOC", "only original BL addend -4 admitted")
                require(target["name"] in CALLEES, "RELOC", "foreign call target")
                definition = self.final.symbol(target["name"], "STT_FUNC")
                self._origin(target["name"], definition)
                resolved, addend = definition["value"] & ~1, source_form[3]
                require(final_form[1] == resolved, "RELOC", "applied BL destination differs from expected entry")
            else:
                require(any(a <= offset and offset + 4 <= b for a, b in data_ranges)
                        and (start + offset) % 4 == 0, "RELOC", "ABS32 not an aligned literal word")
                addend = struct.unpack_from("<i", before, offset)[0]
                require(target["name"] == SLOT and addend == 0, "RELOC", "only current-slot ABS32+0 admitted")
                definition = self.final.symbol(SLOT, "STT_OBJECT")
                require(definition["size"] == 4 and definition["value"] % 4 == 0,
                        "SYMBOL", "current-slot size/alignment")
                self._origin(SLOT, definition)
                resolved = definition["value"]
                require(struct.unpack_from("<I", after, offset)[0] == resolved,
                        "RELOC", "applied ABS32 word differs from expected symbol+original addend")
            require(final_target["section"] == definition["section"]
                    and final_target["value"] == definition["value"]
                    and final_target["kind"] == definition["kind"]
                    and final_target["binding"] == definition["binding"],
                    "RELOC", "final relocation does not name exact definition")
            references.append(dict(Offset=offset, Kind=kind, Symbol=target["name"], Addend=addend,
                                   Place=start + offset, ResolvedValue=resolved,
                                   OriginalBytes=before[offset:offset + 4].hex(),
                                   Bytes=after[offset:offset + 4].hex(), Binding=definition["binding"]))
            patched.update(range(offset, offset + 4))
        require(all(a == b for offset, (a, b) in enumerate(zip(before, after)) if offset not in patched),
                "PRESERVATION", "non-relocation bytes changed")
        output, literals, used = [], set(), set()
        literal_references = []
        for offset, raw, form in instructions:
            address = start + offset
            record = self.instructions.get((final["section"], address))
            require(record is not None and record[2] == raw, "DECODE", "missing/mismatched disassembly instruction")
            op, operands, _ = record
            target_address = None
            if form is not None:
                expected, target_address, register, immediate = form
                require(op == expected, "DECODE", "address-bearing mnemonic disagrees with bits")
                if op == "bl":
                    require(offset in source_relocs and source_relocs[offset][0] == 10,
                            "RELOC", "BL requires bound original call relocation")
                    used.add(offset)
                elif op == "bx":
                    require(operands.lower() == "lr", "DECODE", "BX LR text disagrees with bits")
                elif op == "ldr":
                    argument = re.fullmatch(r"r([0-7]),\s*\[pc,\s*#(0x[0-9a-fA-F]+|[0-9]+)\]", operands.lower())
                    require(argument is not None and int(argument[1]) == register
                            and int(argument[2], 16 if argument[2].startswith("0x") else 10) == immediate,
                            "DECODE", "literal operand disagrees with bits")
                    pool = target_address - start
                    original_form = source_by_offset[offset][1]
                    require(original_form is not None and original_form[0] == "ldr"
                            and original_form[1] - source_start == pool
                            and any(a <= pool and pool + 4 <= b for a, b in data_ranges),
                            "DECODE", "literal target not preserved bounded mapped data")
                    self.read(target_address, 4)
                    literals.update(range(pool, pool + 4))
                    literal_references.append((offset, pool))
                    if pool in source_relocs:
                        require(source_relocs[pool][0] == 2, "RELOC", "literal relocation kind")
                        used.add(pool)
                else:
                    require(target_address - start in by_offset
                            and source_by_offset[offset][1] is not None
                            and source_by_offset[offset][1][1] - source_start == target_address - start,
                            "DECODE", "branch not preserved exact local instruction boundary")
                if op == "bl" or op in CONDITIONS or op == "b":
                    argument = re.fullmatch(r"([0-9a-fA-F]+)(?:\s+<[^>]+>)?", operands)
                    require(argument is not None and int(argument[1], 16) == target_address,
                            "DECODE", "branch disassembly target disagrees with bits")
            else:
                require(op not in CONDITIONS, "DECODE", "unsupported/reserved conditional branch encoding")
                require(op in ORDINARY and re.search(r"\b(pc|r15)\b", operands, re.I) is None,
                        "DECODE", "unsupported instruction or PC use")
            output.append(dict(Offset=offset, Bytes=raw.hex(), Mnemonic=op,
                               Operands=operands, Target=target_address))
        require(used == set(source_relocs), "RELOC", "unconsumed relocation")
        islands = []
        for a, b in data_ranges:
            require(all(offset in literals or (start + offset < ((start + a + 3) & ~3)
                        and after[offset] == before[offset] == 0) for offset in range(a, b)),
                    "DECODE", "unreferenced data/padding")
            islands.append(dict(Offset=a, Bytes=after[a:b].hex(),
                                References=[dict(Instruction=offset, Offset=pool - a)
                                            for offset, pool in literal_references if a <= pool < b]))
        covered = {start + offset for offset, _, _ in instructions}
        for (section, address), record in self.instructions.items():
            if section == final["section"] and start <= address < start + final["size"]:
                if address in covered:
                    continue
                offset = address - start
                require(record is not None and record[0] in (".word", ".short", ".byte")
                        and any(a <= offset and offset + len(record[2]) <= b for a, b in data_ranges)
                        and after[offset:offset + len(record[2])] == record[2],
                        "DECODE", "extra/interior/mismatched disassembly record")
        return dict(Name=name, Address=start, Size=len(after), BodySha256=sha256(after),
                    InstructionCount=len(output), Instructions=output, LiteralIslands=islands,
                    References=references, Complete=True, PrelinkBoundRootPreservation=True,
                    RootOrigin=root_origin,
                    DefinitionOrigins=[self.origin_evidence[target] for target in sorted(
                        {reference["Symbol"] for reference in references})])
