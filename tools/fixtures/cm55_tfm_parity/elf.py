"""ELF/objdump decoder derived from the frozen C3FP parity fixture.

No instruction is filtered; consumers must match a complete closed body.
"""
import json
from pathlib import Path
import re
import struct
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")


class Rejected(Exception):
    pass


def require(ok, code, detail):
    if not ok:
        raise Rejected("REJECT:" + code + ":" + str(detail).replace("\n", " "))


def canonical(text):
    if text.strip().startswith("@"):
        return text.strip()
    text = re.split(r"[;@]", text)[0].strip().lower()
    aliases = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}
    text = re.sub(r"\b(sb|sl|fp|ip)\b", lambda m: aliases[m[0]], text)
    text = re.sub(r"#(0x[0-9a-f]+|[0-9]+)", lambda m: "#" + str(int(m[1], 0)), text)
    text = re.sub(r"\s+", "", text)

    def registers(match):
        result = []
        for item in match[1].split(","):
            span = re.fullmatch(r"([rs])(\d+)-([rs])(\d+)", item)
            if span:
                require(span[1] == span[3], "DECODE", "mixed register range")
                result += [span[1] + str(n) for n in range(int(span[2]), int(span[4]) + 1)]
            else:
                result.append(item)
        return "{" + ",".join(result) + "}"

    text = re.sub(r"\{([^}]+)\}", registers, text)
    text = re.sub(r"\[(r\d+|sp)\]", r"[\1,#0]", text)
    return text


class Object:
    def __init__(self, path, disassembly):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "ELF", "not little-endian ELF32")
        h = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data)
        require(h[1:3] == (1, 40), "ELF", "expected ARM ET_REL")
        self.sections = [struct.unpack_from("<10I", self.data, h[6] + i*h[11]) for i in range(h[12])]
        names = self.section_bytes(h[13])
        self.names = [self.string(names, s[0]) for s in self.sections]
        self.symbols = []
        tables = {}
        for index, s in enumerate(self.sections):
            if s[1] != 2:
                continue
            strings = self.section_bytes(s[6])
            entries = []
            for offset in range(s[4], s[4]+s[5], s[9]):
                name, value, size, info, other, section = struct.unpack_from("<IIIBBH", self.data, offset)
                item = dict(name=self.string(strings, name), value=value, size=size,
                            info=info, section=section)
                if not item['name'] and info & 15 == 3 and section < len(self.names):
                    item['name'] = self.names[section]
                entries.append(item)
                self.symbols.append(item)
            tables[index] = entries
        self.relocations = {}
        for s in self.sections:
            if s[1] != 9:
                continue
            for offset in range(s[4], s[4]+s[5], s[9]):
                address, info = struct.unpack_from("<II", self.data, offset)
                key = (s[7], address)
                require(key not in self.relocations, "RELOC", "overlapping relocations")
                self.relocations[key] = (info & 255, tables[s[6]][info >> 8])
        self.instructions = {}
        section = None
        for line in Path(disassembly).read_text().splitlines():
            match = re.fullmatch(r"Disassembly of section (.+):", line)
            if match:
                require(self.names.count(match[1]) == 1, "DECODE", "ambiguous section")
                section = self.names.index(match[1])
                continue
            match = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?:\s+[0-9a-f]{4})?)\s+([a-z][a-z0-9.]*)(?:\s+(.*))?$", line)
            if not match or section is None:
                continue
            address = int(match[1], 16)
            raw = b"".join(struct.pack("<H", int(word, 16)) for word in match[2].split())
            require(self.read(section, address, len(raw)) == raw, "DECODE", "disassembly bytes disagree with ELF")
            key = (section, address)
            require(key not in self.instructions, "DECODE", "duplicate instruction")
            self.instructions[key] = (re.sub(r"\.[nw]$", "", match[3]), match[4] or "", raw)

    @staticmethod
    def string(data, start):
        return data[start:data.index(0, start)].decode("ascii")

    def section_bytes(self, index):
        s = self.sections[index]
        return self.data[s[4]:s[4]+s[5]]

    def read(self, section, address, count):
        s = self.sections[section]
        require(0 <= address <= s[5] and address+count <= s[5], "ELF", "section bounds")
        return self.data[s[4]+address:s[4]+address+count]

    def function(self, name, *, literal_islands=False):
        """Decode a complete body; optionally retain one structural literal island.

        The opt-in form returns an @literal-island descriptor in address order
        and retains all NOPs. It does not establish island/tail unreachability.
        Local branch indices count descriptor tokens as well as instructions.
        Consumers must match the complete returned sequence, including data
        descriptors and the exact bounded (zero, one or two) tail NOP count.
        """
        require(type(literal_islands) is bool, "DECODE", "literal-islands option must be boolean")
        symbols = [s for s in self.symbols if s["name"] == name and s["section"] != 0]
        require(len(symbols) == 1 and symbols[0]["info"] & 15 == 2 and symbols[0]["info"] >> 4 in (0, 1) and symbols[0]["size"],
                "SYMBOL", "missing/ambiguous function " + name)
        symbol = symbols[0]
        section, start, end = symbol["section"], symbol["value"] & ~1, (symbol["value"] & ~1)+symbol["size"]
        mappings = sorted((s["value"], s["name"][1]) for s in self.symbols
                          if s["section"] == section and re.fullmatch(r"\$[tda](?:\.\d+)?", s["name"]))
        decoded, data_ranges = [], []
        address = start
        while address < end:
            previous = [m for m in mappings if m[0] <= address]
            require(previous, "DECODE", "missing mapping symbol")
            kind = previous[-1][1]
            boundary = min([m[0] for m in mappings if m[0] > address] + [end])
            if kind == "d":
                data_ranges.append((address, boundary))
                address = boundary
                continue
            require(kind == "t" and (section, address) in self.instructions,
                    "DECODE", name + "/undecoded executable bytes at " + hex(address))
            op, arg, raw = self.instructions[(section, address)]
            require(address+len(raw) <= boundary, "DECODE", "instruction crosses mapping")
            decoded.append((address, op, arg, raw))
            address += len(raw)
        require(decoded, "DECODE", "empty function")
        if literal_islands:
            contiguous = []
            for a, b in data_ranges:
                if contiguous and contiguous[-1][1] == a:
                    contiguous[-1] = (contiguous[-1][0], b)
                else:
                    contiguous.append((a, b))
            data_ranges = contiguous
            require(len(data_ranges) <= 1, "DECODE", "multiple literal islands unsupported")
            if data_ranges:
                a, b = data_ranges[0]
                tail = [row for row in decoded if row[0] >= b]
                require(len(tail) <= 2 and all(
                    row[0] == b+2*i and row[1:3] == ("nop", "") and row[3] == b"\x00\xbf"
                    for i, row in enumerate(tail)), "DECODE", "unsupported literal-island executable tail")
                require((tail[-1][0]+2 if tail else b) == end,
                        "DECODE", "literal-island tail extent")
        indices = {row[0]: i + (sum(b <= row[0] for a, b in data_ranges) if literal_islands else 0)
                   for i, row in enumerate(decoded)}
        result, literals, used_relocs = [], set(), set()
        literal_references = []
        for address, op, original, raw in decoded:
            arg = canonical(original)
            reloc = self.relocations.get((section, address))
            if op in ("bl", "b") and reloc:
                kind, target = reloc
                require(kind == (10 if op == "bl" else 30) and target["name"], "RELOC", "branch relocation kind/target")
                # These actual assembler call relocations carry addend -4. Do
                # not discard a changed relocation addend while naming a call.
                hi, lo = struct.unpack("<HH", raw)
                sign = (hi >> 10) & 1
                i1, i2 = 1 ^ ((lo >> 13) & 1) ^ sign, 1 ^ ((lo >> 11) & 1) ^ sign
                value = (sign << 24) | (i1 << 23) | (i2 << 22) | ((hi & 1023) << 12) | ((lo & 2047) << 1)
                if sign:
                    value -= 1 << 25
                require(value == -4, "RELOC", "unexpected call addend " + str(value))
                arg = target["name"]
                used_relocs.add(address)
            elif op in ("b", "beq", "bne", "blt", "bcc", "bcs", "bhi", "bls", "bpl", "bmi", "bge", "bgt", "ble", "cbz", "cbnz"):
                target = re.search(r"(?:^|,\s*)([0-9a-f]+)\s+<", original.strip())
                require(target is not None and int(target[1], 16) in indices, "DECODE", "non-local branch")
                arg = (canonical(original.split(",")[0]) + "," if op in ("cbz", "cbnz") else "") + "@" + str(indices[int(target[1], 16)])
            elif op == "ldr" and re.match(r"r\d+,\[pc,", arg):
                match = re.match(r"(r\d+),\[pc,#(\d+)\]", arg)
                require(match is not None, "DECODE", "unsupported literal form")
                pool = ((address+4) & ~3)+int(match[2])
                pool_mappings = [m for m in mappings if m[0] <= pool]
                pool_end = min([m[0] for m in mappings if m[0] > pool] + [self.sections[section][5]])
                # The actual pin shares a section-end pool among several
                # functions; it need not be inside this function's st_size.
                require(pool_mappings and pool_mappings[-1][1] == "d" and pool+4 <= pool_end,
                        "DECODE", "literal not mapped data")
                value = struct.unpack("<I", self.read(section, pool, 4))[0]
                literal_reloc = self.relocations.get((section, pool))
                if literal_reloc:
                    kind, target = literal_reloc
                    require(kind == 2 and target["name"], "RELOC", "unsupported literal relocation")
                    arg = match[1]+",="+target["name"]+"+"+str(value)
                    used_relocs.add(pool)
                else:
                    arg = match[1]+",="+str(value)
                literals.update(range(pool, pool+4))
                literal_references.append((address, pool))
            else:
                require(reloc is None, "RELOC", "unexpected instruction relocation")
            # GNU calls increment-after transfers ldm/stm in narrow encodings.
            op = {"ldm": "ldmia", "stm": "stmia"}.get(op, op)
            if op in ("push", "pop"):
                op, arg = ("stmdb" if op == "push" else "ldmia"), "sp!,"+arg
            if op in ("dsb", "dmb", "isb") and arg == "sy":
                arg = "#15"
            result.append((op, arg))
        if not literal_islands:
            require(all(a > decoded[-1][0] for a, _ in data_ranges), "DECODE", "non-trailing naked data")
        for a, b in data_ranges:
            for address in range(a, b):
                padding = address < ((a+3) & ~3) and self.read(section, address, 1) == b"\0"
                require(address in literals or padding, "DECODE", "unreferenced literal/data")
        for (sec, address), _ in self.relocations.items():
            if sec == section and start <= address < end:
                require(address in used_relocs, "RELOC", "unconsumed function relocation")
        if literal_islands and data_ranges:
            a, b = data_ranges[0]
            descriptor = dict(Offset=a-start, Bytes=self.read(section, a, b-a).hex(),
                References=[dict(Instruction=address-start, Offset=pool-a)
                            for address, pool in literal_references if a <= pool < b],
                Relocations=[dict(Offset=address-a, Kind=kind, Target=target["name"])
                             for (sec, address), (kind, target) in sorted(self.relocations.items())
                             if sec == section and a <= address < b])
            index = sum(row[0] < a for row in decoded)
            result.insert(index, ("@literal-island", json.dumps(descriptor, sort_keys=True, separators=(",", ":"))))
        # A sole final NOP may align a trailing pool after a terminal branch.
        if not literal_islands and result[-1] == ("nop", "") and len(result) > 1 and (result[-2][0] in ("b", "bx", "bl") or result[-2][0] == "ldmia" and "pc}" in result[-2][1]):
            result.pop()
        return result
