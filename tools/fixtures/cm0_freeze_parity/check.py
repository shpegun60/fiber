"""Bounded CM0 final-ELF mechanism checks; not instruction/CPU emulation."""
from pathlib import Path
import re
import struct
import sys

OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for CM0 freeze parity"
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)


class Rejection(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(code + ": " + detail)
        self.code = code


def require(ok, code, detail):
    if not ok:
        raise Rejection(code, detail)


def ordered(text, checks):
    cursor, evidence = 0, []
    for code, pattern in checks:
        match = re.search(pattern, text[cursor:], re.I)
        require(match is not None, code, "missing ordered instruction: " + pattern)
        evidence.append(dict(Code=code, Text=match[0]))
        cursor += match.end()
    return evidence


def body(disassembly, name):
    headers = list(re.finditer(r"(?m)^([0-9a-f]+) <([^>]+)>:\s*$", disassembly))
    found = [i for i, match in enumerate(headers)
             if match[2] == name or match[2].startswith(name + ".")]
    require(len(found) == 1, "BODY", "missing/ambiguous actual function: " + name)
    index = found[0]
    return disassembly[headers[index].end():headers[index + 1].start() if index + 1 < len(headers) else None]


def cursor_strides(text, prefix):
    values = re.findall(r"\bsubs\s+r0,\s*#(0x[0-9a-f]+|[0-9]+)\b", text, re.I)
    require(len(values) == 2, prefix + ".PENDSV.CURSOR_INVENTORY", "exact save and restore decrements")
    require(int(values[0], 0) == 36, prefix + ".PENDSV.SAVE_STRIDE", "first decrement must reserve nine words")
    require(int(values[1], 0) == 36, prefix + ".PENDSV.LOW_CURSOR", "second decrement must recover the saved base")


def mechanisms(disassembly, reference):
    prefix = "REFERENCE" if reference else "FIBER"
    def check(name, pattern):
        return prefix + "." + name, pattern
    start_name = "vStartFirstTask" if reference else "fiber_port_start_first_context"
    restore_name = "vRestoreContextOfFirstTask" if reference else "SVC_Handler"
    start = ([check("START.UNMASK", r"\bcpsie\s+i\b"),
              check("START.DSB", r"\bdsb\b"), check("START.ISB", r"\bisb\b"),
              check("START.SVC", r"\bsvc\s+(?:0x0*64|100)\b")] if reference else
             [check("START.MASK", r"\bcpsid\s+i\b"), check("START.CONTROL", r"\bmsr\s+CONTROL\b"),
              check("START.MSP", r"\bmsr\s+MSP\b"), check("START.UNMASK", r"\bcpsie\s+i\b"),
              check("START.DSB", r"\bdsb\b"), check("START.ISB", r"\bisb\b"),
              check("START.SVC", r"\bsvc\s+(?:0x0*46|70)\b")])
    restore = ([check("RESTORE.EXCRET", r"\bldmia\s+r0!,\s*\{r2\}"),
                check("RESTORE.CONTROL", r"\bmsr\s+CONTROL\b"),
                check("RESTORE.SKIP", r"\badds\s+r0,\s*#(?:32|0x20)\b"),
                check("RESTORE.PSP", r"\bmsr\s+PSP\b"), check("RESTORE.ISB", r"\bisb\b"),
                check("RESTORE.RETURN", r"\bbx\s+r2\b")] if reference else
               [check("RESTORE.VALIDATE", r"\bbl\s+[^\n]*<fiber_port_context_validate_restore(?:\.[^>]*)?>"),
                check("RESTORE.HIGH", r"\badds\s+r0,\s*#(?:20|0x14)\b"),
                check("RESTORE.LOAD_HIGH", r"\bldmia\s+r0!,\s*\{r4[^}\n]*r7\}"),
                check("RESTORE.PSP", r"\bmsr\s+PSP\b"),
                check("RESTORE.BASE", r"\bsubs\s+r0,\s*#(?:36|0x24)\b"),
                check("RESTORE.LOAD_LOW", r"\bldmia\s+r0!,\s*\{r3[^}\n]*r7\}"),
                check("RESTORE.RETURN", r"\bbx\s+(?:lr|r14)\b")])
    pend = [check("PENDSV.PSP", r"\bmrs\s+r0,\s*PSP\b")]
    if not reference:
        pend.append(check("PENDSV.VALIDATE", r"\bbl\s+[^\n]*<fiber_port_context_validate_save_current(?:\.[^>]*)?>"))
    pend += [check("PENDSV.SAVE_STRIDE", r"\bsubs\s+r0,\s*#(?:36|0x24)\b"),
             check("PENDSV.SAVE_LOW", r"\bstmia\s+r0!,\s*\{r3[^}\n]*r7\}"),
             check("PENDSV.SAVE_HIGH", r"\bstmia\s+r0!,\s*\{r4[^}\n]*r7\}")]
    if not reference:
        pend.append(check("PENDSV.MASK_CAPTURE", r"\bmrs\s+r3,\s*PRIMASK\b"))
    pend += [check("PENDSV.MASK", r"\bcpsid\s+i\b"),
             check("PENDSV.SELECT", r"\bbl\s+[^\n]*<" +
                   ("vTaskSwitchContext" if reference else "fiber_port_scheduler_pick_next_from_pendsv") + r"(?:\.[^>]*)?>")]
    pend.append(check("PENDSV.MASK_RESTORE", r"\bcpsie\s+i\b" if reference else r"\bmsr\s+PRIMASK,\s*r3\b"))
    pend += [check("PENDSV.HIGH_CURSOR", r"\badds\s+r0,\s*#(?:20|0x14)\b"),
             check("PENDSV.LOAD_HIGH", r"\bldmia\s+r0!,\s*\{r4[^}\n]*r7\}"),
             check("PENDSV.RESTORE_R9", r"\bmov\s+r9,\s*r5\b"),
             check("PENDSV.WRITE_PSP", r"\bmsr\s+PSP\b"),
             check("PENDSV.LOW_CURSOR", r"\bsubs\s+r0,\s*#(?:36|0x24)\b"),
             check("PENDSV.LOAD_LOW", r"\bldmia\s+r0!,\s*\{r3[^}\n]*r7\}"),
             check("PENDSV.RETURN", r"\bbx\s+" + (r"r3\b" if reference else r"(?:lr|r14)\b"))]
    cursor_strides(body(disassembly, "PendSV_Handler"), prefix)
    return {name: ordered(body(disassembly, symbol), patterns) for name, symbol, patterns in (
        ("FirstStart", start_name, start), ("FirstRestore", restore_name, restore), ("PendSV", "PendSV_Handler", pend))}


def elf_basics(path, elf_type):
    with Path(path).open("rb") as stream:
        elf = elf_type(stream)
        require(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_ARM" and
                elf["e_type"] == "ET_EXEC", "ELF", "requires final ARM ELF32 executable")
        sections = list(elf.iter_sections())
        require(not any(section.name.startswith(".gnu.lto_") for section in sections), "ELF", "intermediate LTO IR in final image")
        stack = [segment for segment in elf.iter_segments() if segment["p_type"] == "PT_GNU_STACK"]
        require(len(stack) == 1 and not stack[0]["p_flags"] & 1, "ELF", "missing/executable GNU_STACK")
        table = elf.get_section_by_name(".symtab")
        require(table is not None, "ELF", "missing symbols")
        symbols = list(table.iter_symbols())
        require(not [s.name for s in symbols if s.name and s["st_shndx"] == "SHN_UNDEF"], "ELF", "unresolved final imports")
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                begin, end = segment["p_vaddr"], segment["p_vaddr"] + segment["p_memsz"]
                require(0 <= begin <= end <= 0x40000 or 0x20000000 <= begin <= end <= 0x20004000,
                        "ELF", "load outside bounded synthetic map")


def reference_elf(path, elf_type, owners, lto):
    elf_basics(path, elf_type)
    with Path(path).open("rb") as stream:
        elf = elf_type(stream)
        symbols = list(elf.get_section_by_name(".symtab").iter_symbols())
        def symbol(name, kind, allow_local=False):
            matches = [s for s in symbols if s.name == name and s["st_shndx"] != "SHN_UNDEF"]
            require(len(matches) == 1, "REFERENCE.OWNER", name)
            value = matches[0]
            require(value["st_info"]["type"] == kind and value["st_size"] > 0 and
                    value["st_info"]["bind"] in (("STB_GLOBAL", "STB_LOCAL") if allow_local else ("STB_GLOBAL",)),
                    "REFERENCE.OWNER", "bad binding/type: " + name)
            return value
        require(not any(s.name.startswith(("fiber_", "ctxrt_")) for s in symbols), "REFERENCE.CLOSURE", "project code in upstream image")
        vector = elf.get_section_by_name(".isr_vector")
        require(vector is not None and vector["sh_addr"] == 0 and vector["sh_size"] == 192 and
                vector["sh_flags"] & 2 and not vector["sh_flags"] & 1, "REFERENCE.VECTOR", "48 immutable architectural vectors")
        words = struct.unpack("<48I", vector.data())
        require(words[0] == 0x20004000 and words[1] == (symbol("Reset_Handler", "STT_FUNC")["st_value"] | 1),
                "REFERENCE.VECTOR", "MSP/reset")
        for index, name in ((11, "SVC_Handler"), (14, "PendSV_Handler"), (15, "SysTick_Handler")):
            require(words[index] == symbol(name, "STT_FUNC")["st_value"] | 1, "REFERENCE.VECTOR", name)
        roots = [symbol(name, "STT_FUNC", allow_local=lto and owners[name]["NmType"] == "T")["st_value"] | 1
                 for name in ("pxPortInitialiseStack", "xPortStartScheduler")]
        section = elf.get_section_by_name(".freeze_roots")
        require(section is not None and section["sh_flags"] & 2 and not section["sh_flags"] & 1 and
                section.data() == struct.pack("<2I", *roots), "REFERENCE.ROOTS", "typed actual upstream roots")
        contract = elf.get_section_by_name(".reference_contract")
        require(contract is not None and not contract["sh_flags"] & 1 and
                contract.data() == struct.pack("<6I", 1, 4, 4, 4, 8, 0), "REFERENCE.FACTS", "numeric header facts")
        tcb = symbol("pxCurrentTCB", "STT_OBJECT")
        require(tcb["st_size"] == 4 and elf.get_section(tcb["st_shndx"])["sh_type"] == "SHT_NOBITS",
                "REFERENCE.TCB", "opaque null BSS boundary")
        return dict(Roots=roots, Vectors={str(i): words[i] for i in (11, 14, 15)}, Executed=False)


def parser_controls():
    controls = []
    for code, pattern in (("SAVE", r"\bsubs\s+r0,\s*#36\b"), ("MASK", r"\bmsr\s+PRIMASK,\s*r3\b")):
        text = "subs r0, #36\nmsr PRIMASK, r3"
        ordered(text, [(code, pattern)])
        try:
            ordered("nop", [(code, pattern)])
        except Rejection as error:
            require(error.code == code, "CLASSIFIER", "wrong rejection identity")
        else:
            raise Rejection("CLASSIFIER", "missing instruction accepted")
        controls += [dict(Name=code + "-present", Accepted=True), dict(Name=code + "-missing", Accepted=False)]
    cursor_strides("subs r0, #36\nstmia r0!, {r3-r7}\nsubs r0, #36", "FIBER")
    try:
        cursor_strides("subs r0, #32\nstmia r0!, {r3-r7}\nsubs r0, #36", "FIBER")
    except Rejection as error:
        require(error.code == "FIBER.PENDSV.SAVE_STRIDE", "CLASSIFIER", "later restore cannot satisfy save stride")
    else:
        raise Rejection("CLASSIFIER", "greedy later-stride false acceptance")
    controls += [dict(Name="cursor-positive", Accepted=True), dict(Name="later-stride-counterexample", Accepted=False)]
    return controls
