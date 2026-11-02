"""Static inspection of actual pinned objects/ELFs. No target code executes."""
import json
from pathlib import Path
import re
import struct
import sys


class Rejected(Exception):
    pass


def require(condition, category, detail):
    if not condition:
        raise Rejected(f"REJECT:{category}:{detail}")


class Image:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b"\x7fELF\x01\x01\x01", "ELF", str(path))
        header = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data)
        require(header[2] == 40, "ELF", "not ARM")
        self.sections = [struct.unpack_from("<10I", self.data, header[6] + n * header[11])
                         for n in range(header[12])]
        self.symbols = {}
        self.mappings = {}
        for section in self.sections:
            if section[1] != 2:
                continue
            strings_section = self.sections[section[6]]
            strings = self.data[strings_section[4]:strings_section[4] + strings_section[5]]
            for offset in range(section[4], section[4] + section[5], section[9]):
                name, value, size, info, _, index = struct.unpack_from("<IIIBBH", self.data, offset)
                if not name:
                    continue
                text = strings[name:strings.index(0, name)].decode("ascii")
                item = dict(name=text, value=value, size=size, info=info, index=index)
                self.symbols.setdefault(text, []).append(item)
                mapping = re.fullmatch(r"\$([tda])(?:\.\d+)?", text)
                if mapping:
                    self.mappings.setdefault(index, {})[value] = mapping[1]
        self.instructions = {}
        for line in Path(str(path) + ".dis").read_text().splitlines():
            row = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4}(?: [0-9a-f]{4})?)\s+([a-z][a-z0-9.]*)(?:\s+(.*))?$", line)
            if not row:
                continue
            address = int(row[1], 16)
            encoded = b"".join(struct.pack("<H", int(word, 16)) for word in row[2].split())
            require(self.read(address, len(encoded)) == encoded, "DECODE", f"bytes {address:#x}")
            op = re.sub(r"\.(w|n)$", "", row[3].lower())
            op = {"movs": "mov", "adds": "add", "orrs": "orr", "lsls": "lsl", "ldm": "ldmia"}.get(op, op)
            arg = re.split(r"[;@]", row[4] or "")[0].strip().lower()
            arg = re.sub(r"\b(sb|sl|fp|ip)\b", lambda m: {"sb":"r9", "sl":"r10", "fp":"r11", "ip":"r12"}[m[0]], arg)
            arg = re.sub(r"#(0x[0-9a-f]+|[0-9]+)", lambda m: "#" + str(int(m[1], 0)), arg)
            arg = re.sub(r"\s+", "", arg)
            arg = re.sub(r"\[(r\d+)\]", r"[\1,#0]", arg)
            literal = re.fullmatch(r"(r\d+),\[pc,#(\d+)\]", arg)
            if op == "ldr" and literal:
                pool = ((address + 4) & ~3) + int(literal[2])
                arg = literal[1] + ",=" + hex(struct.unpack("<I", self.read(pool, 4))[0])
            if op == "stmdb" and arg.startswith("sp!,"):
                op, arg = "push", arg[4:]
            elif op == "ldmia" and arg.startswith("sp!,"):
                op, arg = "pop", arg[4:]
            require(address not in self.instructions, "DECODE", f"duplicate instruction {address:#x}")
            self.instructions[address] = (op, arg, len(encoded))

    def read(self, address, size):
        for section in self.sections:
            if section[1] != 8 and section[3] <= address and address + size <= section[3] + section[5]:
                start = section[4] + address - section[3]
                return self.data[start:start + size]
        raise Rejected(f"REJECT:ELF:unmapped {address:#x}/{size}")

    def symbol(self, name):
        definitions = [item for item in self.symbols.get(name, []) if item["index"] != 0]
        require(len(definitions) == 1, "SYMBOL", "missing/ambiguous " + name)
        return definitions[0]

    def address(self, name):
        return self.symbol(name)["value"] & ~1

    def body(self, name):
        symbol = self.symbol(name)
        require(symbol["info"] & 15 == 2 and symbol["size"] > 0, "SYMBOL", "not a body " + name)
        start, end = symbol["value"] & ~1, (symbol["value"] & ~1) + symbol["size"]
        rows = [(address, *self.instructions[address][:2]) for address in sorted(self.instructions) if start <= address < end]
        require(rows, "DECODE", "empty " + name)
        mappings = sorted(self.mappings.get(symbol["index"], {}).items())
        address = start
        while address < end:
            prior = [item for item in mappings if item[0] <= address]
            require(prior, "DECODE", "missing ARM mapping " + name)
            boundary = min([item[0] for item in mappings if item[0] > address] + [end])
            if prior[-1][1] == "d":
                require(address > rows[-1][0], "DECODE", "nontrailing naked data " + name)
                address = min(boundary, end)
                continue
            require(prior[-1][1] == "t" and address in self.instructions, "DECODE", f"gap {name}/{address:#x}")
            width = self.instructions[address][2]
            require(address + width <= min(boundary, end), "DECODE", "straddled instruction " + name)
            address += width
        return rows

    def callee(self, address, names):
        for name in names:
            target = self.address(name)
            if address == target:
                return name
            # GNU's long-branch import veneer must contain the exact pointer,
            # not merely a suggestive __Name_veneer symbol spelling.
            data = self.read(address, 8)
            if data[:4] in (b"\xdf\xf8\x00\xf0", b"\x5f\xf8\x00\xf0") and struct.unpack_from("<I", data, 4)[0] == target | 1:
                return name
        raise Rejected(f"REJECT:CALL:unexpected target {address:#x}")

    def compare(self, name, expected, callees=()):
        labels = {}
        wanted = []
        for row in expected:
            if row.startswith("@") and row.endswith(":"):
                labels[row[1:-1]] = len(wanted)
            else:
                wanted.append(row)
        wanted = [re.sub(r"@(\w+)", lambda m: "row:" + str(labels[m[1]]), row) for row in wanted]
        wanted = [re.sub(r"=([A-Za-z_]\w*)", lambda m: "=" + hex(self.symbol(m[1])["value"]), row) for row in wanted]
        body = self.body(name)
        actual = []
        for address, op, arg in body:
            if op == "bl":
                target = re.fullmatch(r"([0-9a-f]+)<[^>]+>", arg)
                require(target is not None, "CALL", name)
                arg = self.callee(int(target[1], 16), callees)
            elif op in ("bmi", "cbz"):
                target = re.fullmatch(r"(?:(r\d+),)?([0-9a-f]+)<[^>]+>", arg)
                require(target is not None, "BRANCH", name)
                matches = [index for index, row in enumerate(body) if row[0] == int(target[2], 16)]
                require(len(matches) == 1, "BRANCH", name + " outside body")
                arg = (target[1] + "," if target[1] else "") + "row:" + str(matches[0])
            actual.append(op + (" " + arg if arg else ""))
        if len(actual) == len(wanted) + 1 and actual[-1] == "nop":
            actual.pop()
        require(actual == wanted, "BODY", name + ": " + json.dumps(dict(expected=wanted, actual=actual)))
        return len(wanted)


CORE = "{r4,r5,r6,r7,r8,r9,r10,r11}"
PENDSV = [
    "ldr r3,=xSecureContext", "ldr r0,[r3,#0]", "ldr r3,=pxCurrentTCB", "ldr r1,[r3,#0]", "mrs r2,psp",
    "cbz r0,@save_ns", "push {r0,r1,r2,lr}", "bl SecureContext_SaveContext", "pop {r0,r1,r2,lr}",
    "@save_ns:", "mov r3,lr", "lsl r3,r3,#25", "bmi @save_special",
    "tst lr,#16", "it eq", "vstmdbeq r2!,{s16-s31}", "stmdb r2!," + CORE,
    "@save_special:", "mrs r3,psplim", "stmdb r2!,{r0,r3,lr}", "str r2,[r1,#0]",
    "mov r0,#128", "msr basepri,r0", "dsb sy", "isb sy", "bl vTaskSwitchContext", "mov r0,#0", "msr basepri,r0",
    "ldr r3,=pxCurrentTCB", "ldr r1,[r3,#0]", "ldr r2,[r1,#0]", "ldmia r2!,{r0,r3,lr}", "msr psplim,r3",
    "ldr r3,=xSecureContext", "str r0,[r3,#0]", "cbz r0,@restore_ns", "push {r1,r2,r3,lr}",
    "bl SecureContext_LoadContext", "pop {r1,r2,r3,lr}",
    "@restore_ns:", "mov r0,lr", "lsl r0,r0,#25", "bmi @done", "ldmia r2!," + CORE,
    "tst lr,#16", "it eq", "vldmiaeq r2!,{s16-s31}", "@done:", "msr psp,r2", "bx lr"
]
FIRST = [
    "ldr r2,=pxCurrentTCB", "ldr r3,[r2,#0]", "ldr r0,[r3,#0]", "ldmia r0!,{r1,r2,r3}",
    "ldr r4,=xSecureContext", "str r1,[r4,#0]", "msr psplim,r2", "mrs r1,control", "orr r1,r1,#2",
    "msr control,r1", "add r0,#32", "msr psp,r0", "isb sy", "mov r0,#0", "msr basepri,r0", "bx r3"
]
LOAD = ["mrs r1,ipsr", "cbz r1,@done", "ldmia r0!,{r1,r2}", "msr psplim,r2", "msr psp,r1", "@done:", "bx lr"]
SAVE = ["mrs r1,ipsr", "cbz r1,@done", "mrs r1,psp", "vstmdb r1!,{s0}", "vldmia r1!,{s0}",
        "str r1,[r0,#0]", "mov r1,#0", "msr psplim,r1", "msr psp,r1", "@done:", "bx lr"]


def check_geometry(image, secure, hard):
    symbol = image.symbol("reference_geometry")
    require(symbol["size"] == 21 * 4, "GEOMETRY", "tuple length")
    actual = list(struct.unpack("<21I", image.read(symbol["value"], symbol["size"])))
    expected = [0, 1, 1, 0, 0, 0, 0, 4, 16, 4, 0, 4, 8, 12, 4, 8, 0, 0, 4, 3 if secure else 1, 1 if hard else 0]
    require(actual == expected, "GEOMETRY", repr(actual))


def assembly(path, name):
    text = Path(path).read_text()
    start = re.search(r"(?m)^" + re.escape(name) + r":\s*(?:@[^\n]*)?$", text)
    require(start is not None, "ASSEMBLY", name)
    end = re.search(r"(?m)^\s*\.size\s+" + re.escape(name) + r"\s*,", text[start.end():])
    require(end is not None, "ASSEMBLY", "complete generated body " + name)
    return text[start.start():start.end() + end.end()]


def inspect(manifest):
    ns = Image(manifest["NonsecureElf"])
    secure = Image(manifest["SecureElf"])
    ns_fp = [(op, arg) for _, op, arg in ns.body("PendSV_Handler") if op.startswith("v")]
    require(ns_fp == [("vstmdbeq", "r2!,{s16-s31}"), ("vldmiaeq", "r2!,{s16-s31}")], "NS_FP", repr(ns_fp))
    trigger = [(op, arg) for _, op, arg in secure.body("SecureContext_SaveContextAsm") if op.startswith("v")]
    require(trigger == [("vstmdb", "r1!,{s0}"), ("vldmia", "r1!,{s0}")], "SECURE_FP_TRIGGER", repr(trigger))
    check_geometry(ns, False, manifest["Abi"] == "hard")
    check_geometry(secure, True, manifest["Abi"] == "hard")
    counts = {
        "PendSV_Handler": ns.compare("PendSV_Handler", PENDSV, ("SecureContext_SaveContext", "SecureContext_LoadContext", "vTaskSwitchContext")),
        "vRestoreContextOfFirstTask": ns.compare("vRestoreContextOfFirstTask", FIRST),
        "SecureContext_LoadContextAsm": secure.compare("SecureContext_LoadContextAsm", LOAD),
        "SecureContext_SaveContextAsm": secure.compare("SecureContext_SaveContextAsm", SAVE)
    }
    ns.compare("SVC_Handler", ["tst lr,#4", "ite eq", "mrseq r0,msp", "mrsne r0,psp", "ldr r1,=vPortSVCHandler_C", "bx r1"])
    ns.compare("vPortAllocateSecureContext", ["svc 100", "bx lr"])
    ns.compare("vPortFreeSecureContext", ["ldr r2,[r0,#0]", "ldr r1,[r2,#0]", "cmp r1,#0", "it ne", "svcne 101", "bx lr"])
    ns.compare("vStartFirstTask", ["ldr r0,=0xe000ed08", "ldr r0,[r0,#0]", "ldr r0,[r0,#0]", "msr msp,r0",
                                  "cpsie i", "cpsie f", "dsb sy", "isb sy", "svc 102", "nop"])
    start = assembly(manifest["NonsecureAssembly"], "vPortSVCHandler_C")
    for callee in ("SecureInit_DePrioritizeNSExceptions", "SecureContext_Init", "SecureInit_EnableNSFPUAccess",
                   "SecureContext_AllocateContext", "SecureContext_LoadContext", "SecureContext_FreeContext", "vRestoreContextOfFirstTask"):
        require(re.search(r"\b(?:bl|b)\s+" + re.escape(callee) + r"\b", start) is not None, "POLICY", "real NS C dependency " + callee)
    for name, path, masks in (
            ("SecureInit_EnableNSFPUAccess", manifest["SecureInitAssembly"], (3072, 536870912, 67108864)),
            ("vPortSVCHandler_C", manifest["NonsecureAssembly"], (15728640, 3221225472))):
        body = assembly(path, name)
        immediates = {int(value, 0) & 0xffffffff for value in re.findall(r"#(-?(?:0x[0-9a-fA-F]+|[0-9]+))", body)}
        require(all(mask in immediates for mask in masks), "POLICY", name + " exact grant/FPCCR masks")
    exports = ("SecureContext_Init", "SecureContext_AllocateContext", "SecureContext_FreeContext", "SecureContext_LoadContext",
               "SecureContext_SaveContext", "SecureInit_DePrioritizeNSExceptions", "SecureInit_EnableNSFPUAccess")
    stub_section = secure.symbol(exports[0])["index"]
    stub_names = [item["name"] for group in secure.symbols.values() for item in group
                  if item["info"] & 15 == 2 and item["index"] == stub_section]
    require(sorted(stub_names) == sorted(exports), "IMPORT", "exact seven real SG exports")
    require(sorted(secure.address(name) for name in exports) == list(range(0x10020000, 0x10020038, 8)),
            "IMPORT", "contiguous eight-byte SG veneers before alignment padding")
    cmse_forms = {}
    for name in exports:
        imported = ns.symbol(name)
        require(imported["index"] == 0xfff1 and 0x10020000 <= (imported["value"] & ~1) < 0x10020040,
                "IMPORT", "actual CMSE import " + name)
        require(secure.symbol(name)["info"] == 0x12 and secure.symbol(name)["size"] == 8 and
                imported["value"] == secure.symbol(name)["value"], "IMPORT", "matching real SG export " + name)
        stub = secure.body(name)
        require(len(stub) == 2 and stub[0][1:] == ("sg", "") and stub[1][1] == "b" and
                int(stub[1][2].split("<")[0], 16) == secure.address("__acle_se_" + name),
                "IMPORT", "SG branch to complete real C implementation " + name)
        path = manifest["SecureInitAssembly"] if name.startswith("SecureInit_") else manifest["SecureContextAssembly"]
        body = assembly(path, name)
        cmse_forms[name] = [line.strip() for line in body.splitlines()
                            if re.match(r"^\s*(?:v[a-z][a-z0-9.]*|bxns)\s", line)]
        require(any(line.startswith("bxns") for line in cmse_forms[name]), "IMPORT", "compiler CMSE return " + name)
    return dict(status="PASS", naked_instruction_counts=counts, cmse_exports=list(exports),
                observed_compiler_cmse_fp_and_return_forms=cmse_forms,
                frame_forms={"NS_basic_words":19, "NS_extended_words":53, "Secure_origin_NS_prefix_words":3,
                             "NS_high_fp_words":16, "Secure_record_words":4, "Secure_s0_scratch_bytes":4,
                             "Secure_stack_seal_bytes":8, "PendSV_companion_call_MSP_spill_bytes":16},
                sfpa_dcrs="No explicit handwritten SFPA/DCRS branch; EXC_RETURN is preserved, bit6 gates NS transfers, bit4 gates high FP transfers. Not an execution proof.",
                limits="Actual pinned reference only; no Fiber equivalence, branch execution, hardware or stack-depth qualification")


if __name__ == "__main__":
    try:
        print(json.dumps(inspect(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))), sort_keys=True))
    except Rejected as error:
        print(error)
        sys.exit(1)
