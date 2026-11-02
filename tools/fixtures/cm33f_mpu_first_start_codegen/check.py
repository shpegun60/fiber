"""Static final-ELF qualification. No ARM instruction is executed here."""
import json
from pathlib import Path
import re
import struct
import sys


class Rejected(Exception):
    pass


def require(condition, code, detail):
    if not condition:
        raise Rejected(f"REJECT:{code}:{detail}")


class Elf:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "ELF", str(path))
        header = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data)
        require(header[2] == 40, "ELF", "not ARM")
        self.sections = [struct.unpack_from("<10I", self.data, header[6] + n * header[11])
                         for n in range(header[12])]
        self.symbols = {}
        self.symbol_entries = []
        self.symbol_groups = {}
        self.mappings = {}
        for section in self.sections:
            if section[1] != 2:
                continue
            strings = self.section_data(self.sections[section[6]])
            for offset in range(section[4], section[4] + section[5], section[9]):
                name, value, size, info, other, index = struct.unpack_from("<IIIBBH", self.data, offset)
                if not name:
                    continue
                end = strings.index(0, name)
                text = strings[name:end].decode("ascii")
                item = dict(name=text, value=value, size=size, info=info, index=index)
                self.symbol_entries.append(item)
                self.symbol_groups.setdefault(text, []).append(item)
                # Keep no last-definition-wins lookup. Every actual lookup
                # below rejects duplicate definitions (mapping names may repeat).
                self.symbols.setdefault(text, item)
                mapping = re.fullmatch(r"\$([tda])(?:\.\d+)?", text)
                if mapping:
                    entries = self.mappings.setdefault(index, {})
                    require(value not in entries or entries[value] == mapping[1], "DECODE", "conflicting mapping symbols")
                    entries[value] = mapping[1]

    def section_data(self, section):
        return self.data[section[4]:section[4] + section[5]]

    def read(self, address, size):
        for section in self.sections:
            if section[1] != 8 and section[3] <= address and address + size <= section[3] + section[5]:
                start = section[4] + address - section[3]
                return self.data[start:start + size]
        raise Rejected(f"REJECT:ELF:unmapped {address:#x}/{size}")

    def symbol(self, name):
        require(name in self.symbols, "SYMBOL", name)
        definitions = [item for item in self.symbol_groups[name] if item["index"] != 0]
        require(len(definitions) == 1, "SYMBOL", "ambiguous/undefined symbol " + name)
        return definitions[0]

    def address(self, name):
        return self.symbol(name)["value"] & ~1

    def words(self, name):
        symbol = self.symbol(name)
        require(symbol["size"] % 4 == 0, "GEOMETRY", name)
        return list(struct.unpack("<" + "I" * (symbol["size"] // 4),
                                  self.read(symbol["value"], symbol["size"])))


ALIASES = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12"}


def operands(text):
    text = re.split(r"[;@]", text)[0].strip().lower()
    text = re.sub(r"\b(sb|sl|fp|ip)\b", lambda m: ALIASES[m[0]], text)
    text = re.sub(r"#(0x[0-9a-f]+|[0-9]+)", lambda m: "#" + str(int(m[1], 0)), text)
    return re.sub(r"\s+", "", text)


class Image:
    def __init__(self, elf_path, dis_path):
        self.elf = Elf(elf_path)
        self.instructions = {}
        self.widths = {}
        self.literal_bytes = set()
        for line in Path(dis_path).read_text().splitlines():
            match = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)[ ]*\t([a-z][a-z0-9.]*)(?:\s+(.*))?$", line)
            if not match:
                continue
            address, mnemonic, raw = int(match[1], 16), match[3].lower(), match[4] or ""
            encoded = b"".join(struct.pack("<H", int(word, 16)) for word in match[2].split())
            require(len(encoded) in (2, 4) and self.elf.read(address, len(encoded)) == encoded,
                    "DECODE", f"instruction byte mismatch {address:#x}")
            require(address not in self.instructions, "DECODE", f"duplicate disassembly address {address:#x}")
            mnemonic = re.sub(r"\.(w|n)$", "", mnemonic)
            mnemonic = {"movs": "mov", "adds": "add", "ldm": "ldmia", "stm": "stmia"}.get(mnemonic, mnemonic)
            arg = operands(raw)
            literal = re.fullmatch(r"(r\d+),\[pc,#(\d+)\]", arg)
            if mnemonic == "ldr" and literal:
                pool = ((address + 4) & ~3) + int(literal[2])
                value = struct.unpack("<I", self.elf.read(pool, 4))[0]
                arg = literal[1] + ",=" + hex(value)
                self.literal_bytes.update(range(pool, pool + 4))
            self.instructions[address] = (mnemonic, arg)
            self.widths[address] = len(encoded)

    def body(self, name):
        symbol = self.elf.symbol(name)
        return self.body_record(symbol)

    def calls(self, name):
        result = []
        for address, op, arg in self.body(name):
            if op not in ("bl", "b"):
                continue
            match = re.match(r"([0-9a-f]+)<", arg)
            require(match is not None, "DECODE", f"direct edge {name}/{address:#x}")
            target = int(match[1], 16)
            functions = [item for item in self.elf.symbol_entries
                         if item["info"] & 15 == 2 and item["value"] & ~1 == target]
            if functions:
                require(len(functions) == 1, "SYMBOL", f"ambiguous direct callee {name}/{target:#x}")
                result.append((address, functions[0]))
        return result

    def body_record(self, symbol):
        name = symbol["name"]
        require(symbol["info"] & 15 == 2 and symbol["size"] > 0, "SYMBOL", f"not function {name}")
        start = symbol["value"] & ~1
        body = [(address, *insn) for address, insn in sorted(self.instructions.items())
                if start <= address < start + symbol["size"]]
        require(body, "DECODE", name)
        # Account for every byte, including literal pools and padding. An
        # objdump .word/.inst/UDF encoding in a $t range is not ignorable data.
        mappings = sorted(self.elf.mappings.get(symbol["index"], {}).items())
        require(mappings, "DECODE", f"missing ARM mapping symbols {name}")
        end = start + symbol["size"]
        address = start
        code_end = max(row[0] + self.widths[row[0]] for row in body)
        naked = name in ("SVC_Handler", "PendSV_Handler", "fiber_port_yield_from_thread",
                         "fiber_port_runtime_schedule",
                         "fiber_port_unprivileged_task_return", "fiber_port_start_first_context", "fiber_port_restore_first_context_from_svc",
                         "vStartFirstTask", "vRestoreContextOfFirstTask")
        while address < end:
            previous = [item for item in mappings if item[0] <= address]
            require(previous, "DECODE", f"unmapped function byte {name}/{address:#x}")
            kind = previous[-1][1]
            next_mapping = min([item[0] for item in mappings if item[0] > address] + [end])
            if kind == "d":
                require(not naked or address >= code_end, "DECODE", f"non-trailing naked data {name}/{address:#x}")
                # Naked pools consist only of actual PC-relative literal words
                # and up to two zero alignment bytes immediately before them.
                if naked:
                    for byte in range(address, min(next_mapping, end)):
                        padding = byte < ((address + 3) & ~3) and self.elf.read(byte, 1) == b"\0"
                        require(byte in self.literal_bytes or padding, "DECODE", f"unreferenced naked data {name}/{byte:#x}")
                address = min(next_mapping, end)
                continue
            require(kind == "t" and address in self.instructions, "DECODE", f"undecoded executable bytes {name}/{address:#x}")
            width = self.widths[address]
            require(address + width <= min(next_mapping, end), "DECODE", f"instruction straddles mapping/end {name}/{address:#x}")
            require(self.instructions[address][0] not in ("stc", "stc2", "ldc", "ldc2"),
                    "DECODE", f"unsupported coprocessor form {name}/{address:#x}")
            address += width
        return body

    def normalized(self, name):
        body = self.body(name)
        by_address = {row[0]: row[1:] for row in body}
        result = []
        for address, mnemonic, arg in body:
            if mnemonic in ("bl", "b", "bne", "beq"):
                match = re.match(r"([0-9a-f]+)<", arg)
                require(match is not None, "DECODE", f"branch {address:#x}/{arg}")
                target = int(match[1], 16)
                if mnemonic == "bl":
                    names = [item["name"] for item in self.elf.symbol_entries
                             if item["info"] & 15 == 2 and item["value"] & ~1 == target]
                    require(len(names) == 1, "DECODE", f"call {target:#x}/{names}")
                    arg = names[0]
                elif mnemonic == "b" and target == address:
                    arg = "self"
                else:
                    target_op = by_address.get(target)
                    if name == "SVC_Handler" and target_op is not None and target_op[0] != "mov":
                        # The complete handler expectation below fixes each
                        # nonterminal origin-routing edge by instruction index.
                        arg = "step:" + str(next(n for n, row in enumerate(body) if row[0] == target))
                        result.append(mnemonic + " " + arg)
                        continue
                    require(target_op is not None and target_op[0] == "mov" and
                            re.fullmatch(r"r0,#\d+", target_op[1]), "NAKED", f"unexpected failure edge {name}/{arg}")
                    arg = "panic:" + target_op[1].split("#")[1]
                    if mnemonic in ("bne", "beq"):
                        # Every rejection edge must reach the real terminal provider.
                        index = next(n for n, row in enumerate(body) if row[0] == target)
                        require(index + 2 < len(body) and body[index + 1][1] == "bl" and
                                body[index + 2][1] == "b", "NAKED", f"failure sink {name}/{arg}")
            result.append(mnemonic + (" " + arg if arg else ""))
        return result


CORE = "{r4,r5,r6,r7,r8,r9,r10,r11}"


def expect_body(image, name, expected, code):
    actual = image.normalized(name)
    # GNU may emit an alignment NOP before a literal pool, not on a live path.
    if actual and actual[-1] == "nop":
        actual.pop()
    require(actual == expected, code,
            name + ": " + json.dumps(dict(expected=expected, actual=actual), separators=(",", ":")))


def panic_tail(codes):
    result = []
    for code in codes:
        result += [f"mov r0,#{code}", "bl fiber_panic", f"b panic:{code}"]
    return result


def region_blocks(regions):
    result = []
    for region in range(4, regions, 4):
        result += [f"mov r3,#{region}", "str r3,[r1,#0]",
                   f"ldmia r0!,{CORE}", f"stmia r2,{CORE}"]
    return result


def constant_memory_sites(body):
    registers = {}
    sites = []
    for address, op, arg in body:
        immediate = re.fullmatch(r"(r\d+),#(\d+)", arg)
        literal = re.fullmatch(r"(r\d+),=(0x[0-9a-f]+)", arg)
        memory = re.fullmatch(r"(r\d+),\[(r\d+),#(\d+)\]", arg)
        if op == "mov" and immediate:
            registers[immediate[1]] = int(immediate[2])
        elif op == "ldr" and literal:
            registers[literal[1]] = int(literal[2], 16)
        elif op in ("ldr", "ldrb", "str") and memory:
            if memory[2] in registers:
                sites.append((op, registers[memory[2]] + int(memory[3])))
            if op in ("ldr", "ldrb"):
                registers.pop(memory[1], None)
        elif op in ("bl", "blx"):
            registers.clear()
        elif op not in ("str", "cmp", "tst", "push", "dsb", "isb", "dmb"):
            destination = re.match(r"r\d+", arg)
            if destination:
                registers.pop(destination[0], None)
    return sites


def private_name_matches(actual, expected):
    # Separate C translation units may legitimately contain the same static
    # helper name. LTO disambiguates those locals with this exact GCC suffix.
    return actual == expected or re.fullmatch(re.escape(expected) + r"\.lto_priv\.\d+", actual) is not None


def production(image, regions):
    elf = image.elf
    forbidden = r"__cyg_profile|__stack_chk|__gcov|__ubsan|__asan|__sanitizer|__sancov|llvm_profile|__gnu_mcount|mcount"
    require(not any(re.search(forbidden, name) for name in elf.symbols), "INSTRUMENTATION", "compiler dependency/counter")
    functions = [item for item in elf.symbol_entries if item["info"] & 15 == 2 and item["size"]]
    services = []
    fp_transfers = []
    for item in functions:
        name = item["name"]
        for address, mnemonic, arg in image.body_record(item):
            if mnemonic.startswith("v"):
                require(name == "PendSV_Handler", "FP", f"{name}/{address:#x}/{mnemonic}")
                fp_transfers.append((mnemonic, arg))
            require("vpr" not in arg, "FP", f"{name}/{address:#x}/{mnemonic}")
            require(mnemonic != "blx", "CALLGRAPH", f"indirect call {name}/{address:#x}")
            if mnemonic == "svc":
                services.append((name, int(arg, 0)))
    require(sorted(services) == sorted([
        ("fiber_port_start_first_context", 70), ("fiber_port_yield_from_thread", 71),
        ("fiber_port_unprivileged_task_return", 72)]), "STAGED", "exact owned SVC surface: " + repr(services))
    # Six bounded scalar transfers are the only FP instructions admitted in the
    # retained real PendSV. This is not a proof of its branches or FP execution.
    require(fp_transfers == [
        ("vstmia", "r1!,{s16-s31}"), ("vldmia", "r0,{s0-s16}"),
        ("vstmia", "r1!,{s0-s16}"), ("vldmdb", "r1!,{s0-s16}"),
        ("vstmia", "r0!,{s0-s16}"), ("vldmdb", "r1!,{s16-s31}")],
        "FP", "exact PendSV scalar transfer forms/order: " + repr(fp_transfers))
    component = "fiber_port_arm_cm33f_mpu_pendsv_handler_component_v1_anchor"
    for name in ("SVC_Handler", "PendSV_Handler", component):
        require(elf.symbol(name)["info"] >> 4 == 1, "SYMBOL", name + " must be strong global")
    reverse = elf.symbol("fiber_internal_runtime_port_abi_v1_anchor")
    require(reverse["info"] & 15 == 1 and reverse["info"] >> 4 in (0, 1) and reverse["size"] == 1 and
            0 < reverse["index"] < len(elf.sections) and not (elf.sections[reverse["index"]][2] & 1) and
            elf.read(reverse["value"], 1) == b"\x01", "REVERSE", "readonly one-byte v1 provider (possibly LTO-internalized)")
    for name in ("fiber_port_prepare_first_start", "fiber_port_runtime_prepare_start", component):
        require(("ldrb", reverse["value"]) in constant_memory_sites(image.body(name)),
                "REVERSE", "cold volatile v1 read missing: " + name)
    privileged = ("fiber_port_context_init", "fiber_port_runtime_prepare_start",
                  "fiber_port_runtime_start_first", "fiber_port_runtime_select_first", "fiber_port_panic_wait",
                  "fiber_port_require_scheduler_configuration_environment", "fiber_port_handler_bundle_v1_anchor",
                  "fiber_port_primask_save_disable", "fiber_port_primask_restore",
                  "fiber_port_scheduler_pick_first_from_start", component, "SVC_Handler", "PendSV_Handler")
    placements = ((privileged, 0x08000000, 0x08010000),
                  (("fiber_current", "fiber_schedule", "fiber_port_runtime_memory_barrier"), 0x08010000, 0x08020000),
                  (("fiber_port_runtime_schedule",), 0x08020000, 0x08021000))
    for names, start, end in placements:
        for name in names:
            symbol = elf.symbol(name)
            require(symbol["info"] >> 4 == 1 and symbol["info"] & 15 == 2 and symbol["size"] > 0 and
                    start <= elf.address(name) < elf.address(name) + symbol["size"] <= end,
                    "PLACEMENT", "strong production function/terminal fixture: " + name)
    identities = elf.words("codegen_cohort_identities")
    for prefix, address in zip(("fiber_port_context_cohort_", "fiber_port_storage_cohort_"), identities):
        definitions = [item for item in elf.symbol_entries if item["name"].startswith(prefix) and item["index"] != 0]
        require(len(definitions) == 1, "COHORT", "exact provider count " + prefix)
        symbol = definitions[0]
        require(symbol["value"] == address and symbol["info"] == 0x11 and symbol["size"] == 1 and
                not (elf.sections[symbol["index"]][2] & 1) and elf.read(address, 1) == b"\x01",
                "COHORT", "strong readonly exact provider " + symbol["name"])
    require(len(identities) == 2, "COHORT", "context/storage expectation pair")
    context_address = identities[0]
    for name in ("fiber_port_context_init", "fiber_port_runtime_prepare_start", "fiber_port_prepare_first_start", component):
        require(("ldrb", context_address) in constant_memory_sites(image.body(name)),
                "COHORT", "cold volatile exact context read missing: " + name)
    for absent in ("fiber_init", "fiber_start", "fiber_scheduler_set_pick_next"):
        require(absent not in elf.symbols, "STAGED", absent)
    # These public spellings are only placement dependencies, never common-runtime implementations.
    for name, immediate in (("fiber_current", 73), ("fiber_schedule", 74)):
        body = image.body(name)
        require(len(body) == 2 and body[0][1:] == ("udf", "#" + str(immediate)) and
                body[1][1] == "b" and int(body[1][2].split("<")[0], 16) == body[0][0],
                "FIXTURE", "unexecuted public-name terminal stub " + name)
    geometry = elf.words("codegen_geometry")
    require(geometry == [54, 20, 352 if regions == 8 else 416,
                         40 if regions == 8 else 104, 3, 0xffffffb8, 0xffffffbc, regions, 1],
            "GEOMETRY", repr(geometry))
    vectors = elf.words("codegen_vectors")
    require(len(vectors) == 512 and vectors[11] == elf.address("SVC_Handler") | 1 and
            vectors[14] == elf.address("PendSV_Handler") | 1, "VECTOR", "strong slots 11 and 14")

    expect_body(image, "SVC_Handler", [
        "mrs r3,ipsr", "cmp r3,#11", "bne panic:105", "mov r1,lr",
        "mvn r3,#71", "cmp r1,r3", "beq step:15",
        "mvn r3,#67", "cmp r1,r3", "beq step:13",
        "bic r3,r3,#16", "cmp r1,r3", "bne panic:108",
        "mrs r0,psp", "b step:16", "mrs r0,msp",
        "ldr r2,=" + hex(elf.address("fiber_internal_runtime_current_context_slot")),
        "ldr r2,[r2,#0]", "ldr r3,=" + hex(elf.address("fiber_port_svc_dispatch") | 1), "bx r3"
    ] + panic_tail([105, 108]), "ORIGIN")

    expect_body(image, "fiber_port_yield_from_thread", ["svc 71", "bx lr"], "VENEER")
    expect_body(image, "fiber_port_unprivileged_task_return", ["svc 72", "b self"], "VENEER")
    schedule = image.body("fiber_port_runtime_schedule")
    require(len(schedule) == 1 and schedule[0][1] == "b" and
            int(schedule[0][2].split("<")[0], 16) == elf.address("fiber_port_yield_from_thread"),
            "VENEER", "generic schedule must tail to the unchanged production SVC71 site")

    prefix = ["mvn r3,#71", "cmp r1,r3", "bne panic:108", "mov lr,r1", "push {r0,lr}",
              "dmb sy", "ldr r1,=0xe000ed94", "ldr r2,[r1,#0]", "bic r2,r2,#1", "str r2,[r1,#0]",
              "dsb sy", "isb sy", "add r0,#4", "ldr r1,[r0,#0]", "ldr r2,=0xe000edc0",
              "str r1,[r2,#0]", "add r0,#4", "ldr r1,=0xe000ed98", "ldr r2,=0xe000ed9c"]
    restore = prefix + region_blocks(regions) + [
        "ldr r1,=0xe000ed94", "mov r2,#5", "str r2,[r1,#0]", "dsb sy", "isb sy",
        "ldr r0,[sp,#0]", "bl fiber_port_mpu_validate_active_initial_context", "ldr r0,[sp,#0]",
        "add sp,#8", "ldr r1,[r0,#0]", "ldmdb r1!,{r2,r3,r4,lr}",
        "msr psp,r2", "isb sy", "mrs r5,psp", "cmp r5,r2", "bne panic:80",
        "msr psplim,r3", "isb sy", "mrs r5,psplim", "cmp r5,r3", "bne panic:80",
        "msr control,r4", "isb sy", "mrs r5,control", "and r5,r5,#7", "cmp r5,#3", "bne panic:108",
        "mvn r5,#67", "cmp lr,r5", "bne panic:120", f"ldmdb r1!,{CORE}", f"stmia r2!,{CORE}",
        f"ldmdb r1!,{CORE}", "str r1,[r0,#0]", "mov r0,#0", "msr basepri,r0", "dsb sy", "isb sy",
        "mrs r1,basepri", "cmp r1,#0", "bne panic:98", "cpsie i", "dsb sy", "isb sy", "bx lr"
    ] + panic_tail([80, 108, 120, 98])
    expect_body(image, "fiber_port_restore_first_context_from_svc", restore, "RESTORE")

    expect_body(image, "fiber_port_start_first_context", [
        "bl fiber_port_prepare_first_start", "mrs r3,ipsr", "cmp r3,#0", "bne panic:108",
        "mrs r3,control", "cmp r3,#0", "bne panic:108", "mrs r3,primask", "cmp r3,#0", "bne panic:112",
        "mrs r3,basepri", "cmp r3,#0", "bne panic:98", "mrs r3,faultmask", "cmp r3,#0", "bne panic:108",
        "cpsid i", "dsb sy", "isb sy", "ldr r3,=0xe000ed08", "ldr r3,[r3,#0]", "tst r3,#127",
        "bne panic:86", "ldr r2,[r3,#44]", "ldr r1,=" + hex(elf.address("SVC_Handler") | 1),
        "cmp r2,r1", "bne panic:86", "ldr r0,[r3,#0]", "cmp r0,#0", "beq panic:80",
        "tst r0,#7", "bne panic:80", "msr msp,r0", "isb sy", "mrs r2,msp", "cmp r2,r0", "bne panic:80",
        "ldr r3,=0xe000ed04", "mov r2,#134217728", "str r2,[r3,#0]", "dsb sy", "isb sy",
        "cpsie f", "cpsie i", "dsb sy", "isb sy", "svc 70",
        "mov r0,#121", "bl fiber_panic", "b self"
    ] + panic_tail([108, 112, 98, 86, 80]), "START")
    for name, site in (
        ("fiber_port_start_first_context", "fiber_port_svc_start_return_site"),
        ("fiber_port_yield_from_thread", "fiber_port_svc_yield_return_site"),
        ("fiber_port_unprivileged_task_return", "fiber_port_svc_return_return_site")):
        service_address = [address for address, op, arg in image.body(name) if op == "svc"]
        return_site = elf.symbol(site)
        require(len(service_address) == 1 and return_site["info"] >> 4 == 1 and
                return_site["value"] == service_address[0] + 2, "START", "owned post-SVC return label " + site)

    # Independently compiled C envelopes: structural call/MMIO evidence only.
    # Branch-condition execution and MPU enforcement belong to the parent's execution proof.
    required_edges = {
        "fiber_port_runtime_prepare_start": ["fiber_port_handler_bundle_v1_anchor",
                                             "fiber_port_require_scheduler_configuration_environment"],
        "fiber_port_handler_bundle_v1_anchor": [component],
        "fiber_port_runtime_select_first": ["fiber_port_scheduler_pick_first_from_start"],
        "fiber_port_scheduler_pick_first_from_start": ["fiber_port_primask_save_disable", "fiber_port_capture_scheduler_cpu_state",
                                                       "fiber_internal_runtime_select_scheduler_candidate",
                                                       "fiber_port_validate_scheduler_cpu_state", "fiber_port_context_validate_initial_restore",
                                                       "fiber_port_primask_restore"],
        "fiber_port_prepare_first_start": [component, "fiber_port_context_validate_initial_restore", "fiber_port_fpu_prepare",
                                           "fiber_port_configure_first_start_exceptions"],
        "fiber_port_svc_dispatch": ["fiber_port_validate_start_svc_frame", "fiber_port_validate_start_svc_site",
                                    "fiber_port_mpu_program_global_image_while_disabled",
                                    "fiber_port_restore_first_context_from_svc"],
        "fiber_port_mpu_program_global_image_while_disabled": ["fiber_port_mpu_build_global_regions",
                                                              "fiber_port_mpu_write_region",
                                                              "fiber_port_mpu_validate_region_readback"],
        "fiber_port_mpu_validate_active_initial_context": ["fiber_port_context_validate_initial_restore",
                                                          "fiber_port_mpu_validate_region_readback"]
    }
    resolved_edges = {}
    for caller, callees in required_edges.items():
        edges = image.calls(caller)
        offsets = []
        for callee in callees:
            matches = [(address, item) for address, item in edges if private_name_matches(item["name"], callee)]
            require(matches, "ENVELOPE", f"{caller}->{callee}")
            require(len({item["value"] for _, item in matches}) == 1,
                    "SYMBOL", f"ambiguous named callee {caller}->{callee}")
            resolved_edges[caller, callee] = matches[0][1]
            offsets.append(matches[0][0])
        require(offsets == sorted(offsets), "ENVELOPE", f"call order {caller}")
    readback = resolved_edges["fiber_port_mpu_program_global_image_while_disabled", "fiber_port_mpu_validate_region_readback"]
    sites = constant_memory_sites(image.body_record(readback))
    require(sites == [("str", 0xe000ed98), ("ldr", 0xe000ed98),
                      ("ldr", 0xe000ed9c), ("ldr", 0xe000eda0)],
            "ENVELOPE", "MPU readback MMIO: " + repr(sites))

    require(not any(item["index"] == 0 for name, item in elf.symbols.items() if item["info"] >> 4 in (1, 2)),
            "UNDEFINED", "final ELF")
    return dict(functions=len(functions), restored_basic_words=20, backing_words=54,
                naked_functions=5, first_start_naked_functions=3, service_veneers=2,
                region_alias_blocks=(regions - 4) // 4,
                scope="unchanged first-basic-restore sequence; exact retained service/handler surface, not running execution",
                production_forward_operations=8, production_bundle=True, production_cohort_providers=2,
                providers_not_executed=["fiber_panic", "fiber_internal_task_return",
                                        "fiber_internal_runtime_select_scheduler_candidate",
                                        "fiber_internal_runtime_publish_current_context",
                                        "fiber_internal_runtime_current_context_slot", "fiber_internal_runtime_require_current_context",
                                        "terminal public-name fiber_current/fiber_schedule fixtures"])


def reference(image, regions):
    elf = image.elf
    facts = elf.words("codegen_reference_geometry")
    require(facts == [54, 54, 40 if regions == 8 else 104, regions, 0], "REFERENCE", repr(facts))
    restore = ["ldr r2,=" + hex(elf.address("pxCurrentTCB")), "ldr r0,[r2,#0]", "dmb sy",
               "ldr r1,=0xe000ed94", "ldr r2,[r1,#0]", "bic r2,r2,#1", "str r2,[r1,#0]",
               "add r0,#4", "ldr r1,[r0,#0]", "ldr r2,=0xe000edc0", "str r1,[r2,#0]", "add r0,#4",
               "ldr r1,=0xe000ed98", "ldr r2,=0xe000ed9c"] + region_blocks(regions) + [
               "ldr r1,=0xe000ed94", "ldr r2,[r1,#0]", "orr r2,r2,#1", "str r2,[r1,#0]", "dsb sy",
               "ldr r2,=" + hex(elf.address("pxCurrentTCB")), "ldr r0,[r2,#0]", "ldr r1,[r0,#0]",
               "ldmdb r1!,{r2,r3,r4,lr}", "msr psp,r2", "msr psplim,r3", "msr control,r4",
               f"ldmdb r1!,{CORE}", f"stmia r2!,{CORE}", f"ldmdb r1!,{CORE}", "str r1,[r0,#0]",
               "mov r0,#0", "msr basepri,r0", "bx lr"]
    expect_body(image, "vRestoreContextOfFirstTask", restore, "REFERENCE")
    start = image.body("vStartFirstTask")
    expect_body(image, "vStartFirstTask", ["ldr r0,=0xe000ed08", "ldr r0,[r0,#0]", "ldr r0,[r0,#0]",
                "msr msp,r0", "cpsie i", "cpsie f", "dsb sy", "isb sy", "svc 102"], "REFERENCE")
    for name in ("vPortSVCHandler_C", "pxPortInitialiseStack", "SVC_Handler"):
        image.body(name)
    return dict(actual_sources=["portasm.c", "port.c"], basic_restore_words=4 + 8 + 8,
                full_reference_sections_retained=True,
                uncalled_test_only_kernel_providers=["vTaskSwitchContext", "xTaskIncrementTick", "xTaskGetMPUSettings",
                                                     "pxCurrentTCB", "uxSystemCallImplementations", "codegen_reference_task_return"])


def main():
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    image = Image(manifest["Elf"], manifest["Disassembly"])
    result = production(image, manifest["Regions"])
    if manifest.get("ReferenceElf"):
        result["reference"] = reference(Image(manifest["ReferenceElf"], manifest["ReferenceDisassembly"]), manifest["Regions"])
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        print(error)
        sys.exit(1)
