"""Closed ARM object-code comparison, followed by symbolic transfer checks.

This is not a CPU emulator or evidence for the C validators' behavior.
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

    def function(self, name):
        symbols = [s for s in self.symbols if s["name"] == name and s["section"] != 0]
        require(len(symbols) == 1 and symbols[0]["info"] & 15 == 2 and symbols[0]["info"] >> 4 == 1 and symbols[0]["size"],
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
        indices = {row[0]: i for i, row in enumerate(decoded)}
        result, literals, used_relocs = [], set(), set()
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
            elif op in ("b", "beq", "bne", "blt"):
                target = re.match(r"([0-9a-f]+)\s+<", original.strip())
                require(target is not None and int(target[1], 16) in indices, "DECODE", "non-local branch")
                arg = "@" + str(indices[int(target[1], 16)])
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
            else:
                require(reloc is None, "RELOC", "unexpected instruction relocation")
            # GNU calls increment-after transfers ldm/stm in narrow encodings.
            op = {"ldm": "ldmia", "stm": "stmia"}.get(op, op)
            if op in ("push", "pop"):
                op, arg = ("stmdb" if op == "push" else "ldmia"), "sp!,"+arg
            if op in ("dsb", "dmb", "isb") and arg == "sy":
                arg = "#15"
            result.append((op, arg))
        require(all(a > decoded[-1][0] for a, _ in data_ranges), "DECODE", "non-trailing naked data")
        for a, b in data_ranges:
            for address in range(a, b):
                padding = address < ((a+3) & ~3) and self.read(section, address, 1) == b"\0"
                require(address in literals or padding, "DECODE", "unreferenced literal/data")
        for (sec, address), _ in self.relocations.items():
            if sec == section and start <= address < end:
                require(address in used_relocs, "RELOC", "unconsumed function relocation")
        # A sole final NOP may align a trailing pool after a terminal branch.
        if result[-1] == ("nop", "") and len(result) > 1 and result[-2][0] in ("b", "bx"):
            result.pop()
        return result


CORE = "{r4-r11}"
HIGH, LOW = "{s16-s31}", "{s0-s16}"


def spec(text):
    result, labels = [], {}
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith(":"):
            require(line[:-1] not in labels, "ORACLE", "duplicate label")
            labels[line[:-1]] = len(result)
        else:
            op, _, arg = line.partition(" ")
            normalized = arg.replace(" ", "") if op in ("bl", "b") or ",=" in arg else canonical(arg)
            if op in ("push", "pop"):
                op, normalized = ("stmdb" if op == "push" else "ldmia"), "sp!,"+normalized
            result.append((op, normalized))
    return [(op, "@"+str(labels[arg[1:]]) if arg.startswith("@") else arg) for op, arg in result], labels


def reference_spec(regions):
    blocks = ""
    for region in range(4, regions, 4):
        blocks += f"movs r3,#{region}\nstr r3,[r1]\nldmia r0!,{CORE}\nstmia r2,{CORE}\n"
    return spec(f"""
ldr r2,=pxCurrentTCB+0
ldr r0,[r2]
ldr r1,[r0]
mrs r2,psp
save:
add r2,r2,#32
tst lr,#16
ittt eq
vstmiaeq r1!,{HIGH}
vldmiaeq r2,{LOW}
vstmiaeq r1!,{LOW}
sub r2,r2,#32
stmia r1!,{CORE}
ldmia r2,{CORE}
stmia r1!,{CORE}
mrs r3,psplim
mrs r4,control
stmia r1!,{{r2-r4,lr}}
str r1,[r0]
saved:
mov r0,#128
msr basepri,r0
dsb #15
isb #15
bl vTaskSwitchContext
mov r0,#0
msr basepri,r0
ldr r2,=pxCurrentTCB+0
ldr r0,[r2]
dmb #15
ldr r1,=3758157204
ldr r2,[r1]
bic r2,r2,#1
str r2,[r1]
adds r0,#4
ldr r1,[r0]
ldr r2,=3758157248
str r1,[r2]
adds r0,#4
ldr r1,=3758157208
ldr r2,=3758157212
{blocks}
ldr r1,=3758157204
ldr r2,[r1]
orr r2,r2,#1
str r2,[r1]
dsb #15
ldr r2,=pxCurrentTCB+0
ldr r0,[r2]
ldr r1,[r0]
restore:
ldmdb r1!,{{r2-r4,lr}}
msr psp,r2
msr psplim,r3
msr control,r4
ldmdb r1!,{CORE}
stmia r2!,{CORE}
ldmdb r1!,{CORE}
tst lr,#16
ittt eq
vldmdbeq r1!,{LOW}
vstmiaeq r2!,{LOW}
vldmdbeq r1!,{HIGH}
str r1,[r0]
restored:
bx lr
""")


def fiber_spec():
    return spec(f"""
mrs r3,ipsr
cmp r3,#14
bne @panic_l
mvn r3,#67
cmp lr,r3
beq @origin_ok
bic r3,r3,#16
cmp lr,r3
bne @panic_l
origin_ok:
tst lr,#4
beq @panic_l
mrs r0,psp
tst r0,#7
bne @panic_p
ldr r1,=fiber_internal_runtime_current_context_slot+0
ldr r1,[r1]
cmp r1,#0
beq @panic_c
push {{r0,r1,r2,lr}}
mov r2,lr
mov r3,r0
mov r0,r1
mov r1,r3
bl fiber_port_pendsv_validate_save_current
pop {{r0,r1,r2,lr}}
mov r2,r1
ldr r1,[r2,#0]
save:
adds r0,#32
tst lr,#16
bne @basic_save
vstmia r1!,{HIGH}
vldmia r0,{LOW}
vstmia r1!,{LOW}
basic_save:
subs r0,#32
stmia r1!,{CORE}
ldmia r0,{CORE}
stmia r1!,{CORE}
mrs r3,psplim
mrs r4,control
stmia r1!,{{r0,r3,r4,lr}}
str r1,[r2,#0]
saved:
movs r0,#128
msr basepri,r0
dsb #15
isb #15
mov r0,r2
bl fiber_port_scheduler_pick_next_from_pendsv
cpsid i
dsb #15
isb #15
push {{r0,lr}}
bl fiber_port_mpu_switch_to_context
pop {{r2,lr}}
movs r0,#0
msr basepri,r0
dsb #15
isb #15
mrs r3,basepri
cmp r3,#0
bne @panic_b
ldr r1,[r2,#0]
restore:
ldmdb r1!,{{r0,r3,r4,lr}}
msr psp,r0
isb #15
mrs r5,psp
cmp r5,r0
bne @panic_p
msr psplim,r3
isb #15
mrs r5,psplim
cmp r5,r3
bne @panic_limit
msr control,r4
isb #15
mrs r5,control
and r5,r5,#7
cmp r5,r4
bne @panic_l
ldmdb r1!,{CORE}
stmia r0!,{CORE}
ldmdb r1!,{CORE}
tst lr,#16
bne @basic_restore
vldmdb r1!,{LOW}
vstmia r0!,{LOW}
vldmdb r1!,{HIGH}
basic_restore:
str r1,[r2,#0]
restored:
mrs r3,primask
cmp r3,#1
bne @panic_l
mrs r3,faultmask
cmp r3,#0
bne @panic_l
cpsie i
dsb #15
isb #15
bx lr
panic_l:
movs r0,#108
bl fiber_panic
b @panic_l
panic_p:
movs r0,#80
bl fiber_panic
b @panic_p
panic_c:
movs r0,#67
bl fiber_panic
b @panic_c
panic_b:
movs r0,#98
bl fiber_panic
b @panic_b
panic_limit:
movs r0,#76
bl fiber_panic
b @panic_limit
""")


def svc_spec():
    return spec("""
mrs r3,ipsr
cmp r3,#11
bne @panic_i
mov r1,lr
mvn r3,#71
cmp r1,r3
beq @msp
mvn r3,#67
cmp r1,r3
beq @psp
bic r3,r3,#16
cmp r1,r3
bne @panic_l
psp:
mrs r0,psp
b @dispatch
msp:
mrs r0,msp
dispatch:
ldr r2,=fiber_internal_runtime_current_context_slot+0
ldr r2,[r2]
ldr r3,=fiber_port_svc_dispatch+1
bx r3
panic_i:
movs r0,#105
bl fiber_panic
b @panic_i
panic_l:
movs r0,#108
bl fiber_panic
b @panic_l
""")


def reference_svc_spec():
    return spec("""
tst lr,#4
ite eq
mrseq r0,msp
mrsne r0,psp
ldr r1,[r0,#24]
ldrb r2,[r1,#-2]
cmp r2,#70
blt @enter
cmp r2,#104
beq @exit
b vPortSVCHandler_C
enter:
mov r1,lr
b vSystemCallEnter
exit:
mov r1,lr
b vSystemCallExit
""")


def expect(actual, expected, code):
    require(len(actual) == len(expected), code, f"instruction count {len(actual)} != {len(expected)}")
    for index, (got, wanted) in enumerate(zip(actual, expected)):
        require(got == wanted, code, f"instruction {index}: {got} != {wanted}")


class Transfer:
    """Symbolically interpret only the closed, compared transfer subgraphs."""
    def __init__(self, extended, control=None):
        self.extended = extended
        self.registers = {"r"+str(i): "R"+str(i) for i in range(13)}
        self.registers.update({"s"+str(i): "S"+str(i) for i in range(32)})
        self.registers["lr"] = 0xFFFFFFAC if extended else 0xFFFFFFBC
        self.special = {"psp": 0x20002000, "psplim": 0x20001000,
                        "control": (1 | (4 if extended else 0)) if control is None else control}
        self.memory, self.writes, self.special_writes = {}, [], []
        self.backing, self.context = 0x30000000, 0x30001000
        for n in range(8):
            self.memory[self.special["psp"]+4*n] = "H"+str(n)
        for n in range(17):
            self.memory[self.special["psp"]+32+4*n] = "L"+str(n)
        self.memory[self.special["psp"]+100] = "RESERVED25"
        for n in range(54):
            self.memory[self.backing+4*n] = "STALE"+str(n)
        self.memory[self.context] = self.backing
        self.equal = False

    def run(self, instructions, begin, end):
        pc, predicate = begin, 0
        while pc < end:
            op, arg = instructions[pc]
            pc += 1
            if op == "ittt":
                require(arg == "eq", "TRANSFER", "IT condition")
                predicate = 3
                continue
            if predicate:
                require(op.endswith("eq"), "TRANSFER", "unpredicated IT instruction")
                op = op[:-2]
                predicate -= 1
                if not self.equal:
                    continue
            if op == "bne":
                if not self.equal:
                    pc = int(arg[1:])
                    require(begin <= pc <= end, "TRANSFER", "branch escaped transfer")
                continue
            if op == "tst":
                reg, number = arg.split(",#")
                self.equal = (self.registers[reg] & int(number)) == 0
                continue
            if op in ("add", "adds", "sub", "subs"):
                parts = arg.split(",")
                dst, source, number = (parts[0], parts[0], parts[1]) if len(parts) == 2 else parts
                self.registers[dst] = self.registers[source] + (-1 if op.startswith("sub") else 1)*int(number[1:])
                continue
            if op in ("mrs", "msr"):
                a, b = arg.split(",")
                if op == "mrs":
                    self.registers[a] = self.special[b]
                else:
                    self.special[a] = self.registers[b]
                    self.special_writes.append((a, self.registers[b]))
                continue
            if op == "str":
                match = re.fullmatch(r"(r\d+),\[(r\d+),#0\]", arg)
                require(match is not None, "TRANSFER", "unexpected cursor store")
                address = self.registers[match[2]]
                self.memory[address] = self.registers[match[1]]
                self.writes.append(address)
                continue
            match = re.fullmatch(r"(v?)(ldm|stm)(ia|db)", op)
            if match:
                operands = re.fullmatch(r"(r\d+)(!?),\{([^}]+)\}", arg)
                require(operands is not None, "TRANSFER", "transfer operands")
                base, writeback, regs = operands[1], operands[2], operands[3].split(",")
                address = self.registers[base]
                if match[3] == "db":
                    address -= 4*len(regs)
                for n, reg in enumerate(regs):
                    slot = address+4*n
                    if match[2] == "ldm":
                        require(slot in self.memory, "TRANSFER", "load outside seeded memory")
                        self.registers[reg] = self.memory[slot]
                    else:
                        self.memory[slot] = self.registers[reg]
                        self.writes.append(slot)
                if writeback:
                    self.registers[base] = address if match[3] == "db" else address+4*len(regs)
                continue
            # Restore readback hardening is already closed-template checked.
            require(op in ("isb", "cmp", "and"), "TRANSFER", "unsupported transfer operation " + op)
            if op == "cmp":
                a, b = arg.split(",")
                self.equal = self.registers[a] == (int(b[1:]) if b.startswith("#") else self.registers[b])
            elif op == "and":
                a, b, number = arg.split(",")
                self.registers[a] = self.registers[b] & int(number[1:])
        require(predicate == 0, "TRANSFER", "incomplete IT group")


def transfer_proof(instructions, labels, fiber):
    evidence = []
    for outgoing, control in ((form, value) for form in (False, True) for value in (1, 5)):
        # Captured live FPCA is deliberately independent of EXC_RETURN.FTYPE.
        state = Transfer(outgoing, control)
        psp = state.special["psp"]
        state.registers["r1"] = state.backing
        state.registers["r2" if fiber else "r0"] = state.context
        state.registers["r0" if fiber else "r2"] = psp
        state.run(instructions, labels["save"], labels["saved"])
        expected = (["S"+str(i) for i in range(16, 32)] + ["L"+str(i) for i in range(17)] if outgoing else [])
        expected += ["R"+str(i) for i in range(4, 12)] + ["H"+str(i) for i in range(8)]
        expected += [psp, 0x20001000, control, 0xFFFFFFAC if outgoing else 0xFFFFFFBC]
        words = 53 if outgoing else 20
        require(len(expected) == words, "ORACLE", "numeric saved payload")
        require([state.memory[state.backing+4*i] for i in range(words)] == expected, "TRANSFER", "saved word representation")
        require(state.memory[state.context] == state.backing+4*words, "TRANSFER", "saved cursor")
        require(state.writes == [state.backing+4*i for i in range(words)]+[state.context], "TRANSFER", "save bounds/order")
        require(state.memory[state.backing+4*53] == "STALE53", "TRANSFER", "permanent guard touched")
        for incoming in (False, True):
            # Different incoming shape: this is not a same-task-only round trip.
            restore = Transfer(incoming, control)
            source = state if incoming == outgoing else Transfer(incoming, control)
            if incoming != outgoing:
                source.registers.update(r1=source.backing)
                source.registers["r2" if fiber else "r0"] = source.context
                source.registers["r0" if fiber else "r2"] = source.special["psp"]
                source.run(instructions, labels["save"], labels["saved"])
            restore.memory = dict(source.memory)
            restore.registers = {reg: "POISON:"+reg for reg in restore.registers}
            for n in range(25):
                restore.memory[psp+4*n] = "POISON:stack"+str(n)
            restore.registers["r1"] = source.memory[source.context]
            restore.registers["r2" if fiber else "r0"] = restore.context
            restore.special = {"psp": 0, "psplim": 0, "control": 0}
            restore.run(instructions, labels["restore"], labels["restored"])
            require(restore.memory[restore.context] == restore.backing, "TRANSFER", "restore cursor not reset to zero")
            require([restore.registers["r"+str(i)] for i in range(4, 12)] == ["R"+str(i) for i in range(4, 12)], "TRANSFER", "integer inverse")
            require([restore.memory[psp+4*i] for i in range(8)] == ["H"+str(i) for i in range(8)], "TRANSFER", "core inverse/raw PSP")
            require(restore.special_writes == [("psp", psp), ("psplim", 0x20001000), ("control", control)], "TRANSFER", "special-register order/value")
            if incoming:
                require([restore.registers["s"+str(i)] for i in range(16, 32)] == ["S"+str(i) for i in range(16, 32)], "TRANSFER", "high FP inverse")
                require([restore.memory[psp+32+4*i] for i in range(17)] == ["L"+str(i) for i in range(17)], "TRANSFER", "low FP/FPSCR inverse")
            else:
                require(all(restore.registers["s"+str(i)] == "POISON:s"+str(i) for i in range(32)), "TRANSFER", "basic restore touched FP registers")
                require(all(restore.memory[psp+32+4*i] == "POISON:stack"+str(8+i) for i in range(17)), "TRANSFER", "basic restore touched low FP area")
            restore_words = 25 if incoming else 8
            require(restore.writes == [psp+4*i for i in range(restore_words)]+[restore.context], "TRANSFER", "restore bounds/order")
            require(restore.memory[psp+100] == "RESERVED25", "TRANSFER", "FP reserved word touched")
            evidence.append(dict(Outgoing="extended" if outgoing else "basic", Incoming="extended" if incoming else "basic", CapturedControl=control, SaveCursorWords=words, RestoreCursorWords=0))
    # Reuse an extended backing image for a later basic save: words 20..52
    # are stale payload, not required-zero fields or a basic guard.
    extended = Transfer(True)
    extended.registers.update(r1=extended.backing)
    extended.registers["r2" if fiber else "r0"] = extended.context
    extended.registers["r0" if fiber else "r2"] = extended.special["psp"]
    extended.run(instructions, labels["save"], labels["saved"])
    basic = Transfer(False)
    basic.memory.update({basic.backing+4*i: extended.memory[extended.backing+4*i] for i in range(54)})
    basic.registers["r1"] = basic.backing
    basic.registers["r2" if fiber else "r0"] = basic.context
    basic.registers["r0" if fiber else "r2"] = basic.special["psp"]
    basic.run(instructions, labels["save"], labels["saved"])
    require(basic.memory[basic.backing+80] == "L4" and basic.memory[basic.backing+212] == "STALE53", "TRANSFER", "extended-to-basic tail/guard")
    return evidence


def main():
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    reference = Object(manifest["Reference"], manifest["ReferenceDisassembly"])
    ref = reference.function("PendSV_Handler")
    expected, ref_labels = reference_spec(manifest["Regions"])
    expect(ref, expected, "REFERENCE")
    ref_transfer = transfer_proof(ref, ref_labels, False)
    expect(reference.function("SVC_Handler"), reference_svc_spec()[0], "REFERENCE-SVC")
    fiber = Object(manifest["Fiber"], manifest["FiberDisassembly"])
    actual = fiber.function("PendSV_Handler")
    expected, fiber_labels = fiber_spec()
    expect(actual, expected, "PENDSV")
    transfers = transfer_proof(actual, fiber_labels, True)
    require(transfers == ref_transfer, "TRANSFER", "reference/Fiber transfer contract differs")
    svc = Object(manifest["Svc"], manifest["SvcDisassembly"])
    expect(svc.function("SVC_Handler"), svc_spec()[0], "SVC")
    expect(svc.function("fiber_port_yield_from_thread"), spec("svc 71\nbx lr")[0], "SVC-YIELD")
    expect(svc.function("fiber_port_unprivileged_task_return"), spec("svc 72\nstop:\nb @stop")[0], "SVC-RETURN")
    receipt = dict(Status="PASS", RuntimeProfileAdded=False, Regions=manifest["Regions"],
                   ReferenceInstructions=len(ref), FiberInstructions=len(actual),
                   TransferPairs=transfers, ExtendedToBasicStaleTail=True,
                   RunningSvcEntry="closed basic/extended raw-PSP bridge; C dispatch behavior separate",
                   Proof="actual ARM ET_REL closed code/relocations plus symbolic transfer; not CPU execution")
    Path(manifest["Receipt"]).write_text(json.dumps(receipt, indent=2)+"\n")
    print("PASS:C3FP-RUNNING:closed-PendSV+SVC+4-transfer-pairs*2-controls+stale-tail")


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        print(str(error))
        raise SystemExit(1)
