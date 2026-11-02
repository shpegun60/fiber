"""Execute actual ARM constructors; never model a replacement constructor.

Unicorn 2.1.4 Cortex-M33 executes the linked production/reference instructions.
Mapped CPACR/FPCCR words below are explicit FPU-policy read/write test doubles,
not a model of hardware FP stacking, MPU enforcement, or exception behavior.
"""
import sys

# This must execute for every entry path, including runpy/import consumers of
# Machine.call as a classifier. An assert here would itself disappear with -O.
# __debug__ also detects compile(..., optimize=1/2) in an ordinary interpreter.
if sys.flags.optimize or not __debug__:
    raise SystemExit("C3FP proof rejects Python optimization; remove -O/-OO and unset PYTHONOPTIMIZE")

import collections
import hashlib
import json
import re
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
                     UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_INVALID, UC_MEM_WRITE)
from unicorn.arm_const import (UC_CPU_ARM_CORTEX_M33, UC_ARM_REG_R0,
    UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R9,
    UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_MSP,
    UC_ARM_REG_PSP, UC_ARM_REG_CONTROL, UC_ARM_REG_PRIMASK,
    UC_ARM_REG_BASEPRI, UC_ARM_REG_FAULTMASK, UC_ARM_REG_XPSR)


REQUIRED = (
    "fiber_port_context_init", "fiber_port_mpu_load_linker_layout",
    "fiber_port_mpu_linker_layout_check", "fiber_port_mpu_try_encode_exact_region",
    "fiber_port_mpu_build_global_regions", "fiber_port_context_compute_seal",
    "fiber_port_context_seal_check", "fiber_port_context_validate_initial_restore",
    "fiber_port_fpu_prepare", "fiber_port_fpu_require_configured",
    "fiber_port_fpu_require_ready")
BOUNDARIES = (
    "privileged_flash_start", "privileged_flash_end", "unprivileged_flash_start",
    "unprivileged_flash_end", "unprivileged_syscalls_start",
    "unprivileged_syscalls_end", "privileged_sram_start", "privileged_sram_end",
    "current_context_slot_start", "current_context_slot_end",
    "unprivileged_ram_start", "unprivileged_ram_end")
LAYOUT = (0x08000000, 0x08010000, 0x08010000, 0x08020000,
          0x08020000, 0x08021000, 0x30000020, 0x30010000,
          0x30000000, 0x30000020, 0x24000000, 0x24010000)
CPACR, FPCCR = 0xE000ED88, 0xE000EF34
RECEIPTS = []


def words(data):
    return list(struct.unpack("<" + "I" * (len(data) // 4), data))


def packed(values):
    return struct.pack("<" + "I" * len(values), *values)


class Image:
    def __init__(self, path):
        self.path = Path(path)
        with self.path.open("rb") as stream:
            elf = ELFFile(stream)
            self.sections = {s.name: (s["sh_addr"], s["sh_size"], s["sh_type"])
                             for s in elf.iter_sections()}
            self.symbols = {}
            for symbol in elf.get_section_by_name(".symtab").iter_symbols():
                section = symbol["st_shndx"]
                self.symbols[symbol.name] = {
                    "value": symbol["st_value"], "size": symbol["st_size"],
                    "type": symbol["st_info"]["type"],
                    "bind": symbol["st_info"]["bind"],
                    "section": elf.get_section(section).name if isinstance(section, int) else section}
            self.loads = [(s["p_vaddr"], s.data()) for s in elf.iter_segments()
                          if s["p_type"] == "PT_LOAD" and s["p_filesz"]]

    def address(self, name):
        return self.symbols[name]["value"]

    def undefined(self):
        return {name for name, s in self.symbols.items() if name and
                s["section"] == "SHN_UNDEF" and s["bind"] != "STB_LOCAL"}


def audit_disassembly(path, function=None):
    text = Path(path).read_text()
    if function:
        match = re.search(r"(?ms)^\s*[0-9a-f]+ <" + re.escape(function) +
                          r">:\n(.*?)(?=^\s*[0-9a-f]+ <|\Z)", text)
        assert match, f"missing disassembled function {function}: {path}"
        text = match[1]
    instructions = []
    for line in text.splitlines():
        match = re.match(r"\s*[0-9a-f]+:\s+(?:[0-9a-f]{4,8}\s+)+([a-z][a-z0-9.]*)\s*(.*)", line)
        if match:
            mnemonic, operands = match.groups()
            instructions.append(mnemonic)
            assert not mnemonic.startswith("v"), f"FP/SIMD instruction: {path}: {line}"
            assert not mnemonic.startswith(("svc", "msr", "cpsie", "cpsid", "smc")), (
                f"CPU control write/exception instruction: {path}: {line}")
            assert not re.search(r"\b(?:mve|vpr)\b", operands), line
    assert instructions, f"no decoded instructions: {path}"
    return len(instructions)


def audit_objects(run):
    directory = Path(run["Directory"])
    for path in (directory / "boot-eager.attributes", directory / "boot-lazy.attributes",
                 directory / "reference" / "reference.attributes"):
        attributes = path.read_text()
        assert re.search(r"Tag_CPU_arch:\s+v8-M\.mainline\s*$", attributes, re.M), path
        assert re.search(r"Tag_ABI_HardFP_use:\s+SP only", attributes), path
        assert ("Tag_ABI_VFP_args: VFP registers" in attributes) == ("-hard-" in run["Name"]), path
        assert not re.search(r"Tag_MVE_arch|Tag_PAC_extension|Tag_BTI_extension", attributes), path
    cpp = Image(directory / "linkage.o")
    assert cpp.undefined() == set(REQUIRED), "private C++ API acquired mangling/helper dependencies"
    assert not any(n.startswith(("_GLOBAL_", "__cxx", "__gxx")) for n in cpp.symbols)
    for policy in ("eager", "lazy"):
        image = Image(directory / f"boot-{policy}.o")
        undefined = image.undefined()
        cohort = [s for s in undefined if s.startswith("fiber_port_context_cohort_")]
        assert len(cohort) == 1, (image.path, cohort)
        layout = f"0x000100{run['Regions']:02x}u"
        assert all(token in cohort[0] for token in
                   ("armv8m_mainline", "p0x43334650u", "l" + layout)), cohort
        assert "armv81m" not in cohort[0], cohort
        expected = {f"__fiber_mpu_{name}__" for name in BOUNDARIES}
        expected.update({"fiber_panic", "fiber_port_unprivileged_task_return", cohort[0],
                         "fiber_internal_runtime_port_abi_v1_anchor"})
        assert undefined == expected, f"dependency drift {image.path}: {undefined ^ expected}"
        for name in REQUIRED:
            symbol = image.symbols[name]
            assert symbol["bind"] == "STB_GLOBAL" and symbol["type"] == "STT_FUNC", (name, symbol)
            assert symbol["section"] == ".fiber_port_privileged_functions", (name, symbol)
        for name, symbol in image.symbols.items():
            if symbol["type"] == "STT_FUNC" and symbol["section"] != "SHN_UNDEF":
                assert symbol["section"] == ".fiber_port_privileged_functions", (name, symbol)
                assert not re.search(r"\.(?:isra|constprop|part|clone)\.", name), name
        assert not any(re.search(r"(?:SVC_Handler|PendSV_Handler|fiber_port_runtime_)", n)
                       for n in image.symbols), image.path
        audit_disassembly(directory / f"boot-{policy}.dis")
        audit_disassembly(directory / f"boot-{policy}.dis", "fiber_port_context_init")
    for policy in ("Eager", "Lazy"):
        image = Image(run[policy])
        assert not image.undefined(), image.undefined()
        assert not any(n in image.symbols for n in ("SVC_Handler", "PendSV_Handler"))
        storage = [n for n, s in image.symbols.items() if
                   n.startswith("fiber_port_storage_cohort_") and s["bind"] == "STB_GLOBAL"]
        assert storage == [f"fiber_port_storage_cohort_arm_cm33f_mpu_v1_r{run['Regions']}"], storage
        for name, expected in zip(BOUNDARIES, LAYOUT):
            assert image.address(f"__fiber_mpu_{name}__") == expected, name
        slot = image.sections[".fiber_current_context_slot"]
        assert slot == (0x30000000, 32, "SHT_NOBITS"), slot
        for section, lo, hi in ((".fiber_port_privileged_code", 0x08000000, 0x08010000),
                (".fiber_port_unprivileged_code", 0x08010000, 0x08020000),
                (".fiber_port_syscalls", 0x08020000, 0x08021000),
                (".fiber_port_privileged_data", 0x30000020, 0x30010000),
                (".fiber_port_unprivileged_ram", 0x24000000, 0x24010000)):
            address, size, _ = image.sections[section]
            assert size > 0 and lo <= address < address + size <= hi, (section, address, size)
        ctx = image.symbols["constructor_fixture_context"]
        assert ctx["size"] == (352 if run["Regions"] == 8 else 416) and ctx["value"] % 8 == 0, ctx
    audit_disassembly(directory / "reference" / "reference.dis", "pxPortInitialiseStack")
    hostile = Image(directory / "boot-hostile.o")
    baseline = Image(directory / "boot-eager.o")
    assert hostile.undefined() == baseline.undefined(), (
        f"hostile dependency drift {hostile.path}: {hostile.undefined() ^ baseline.undefined()}")
    for name, symbol in hostile.symbols.items():
        if symbol["type"] == "STT_FUNC" and symbol["section"] != "SHN_UNDEF":
            assert symbol["section"] == ".fiber_port_privileged_functions", (name, symbol)
    audit_disassembly(directory / "boot-hostile.dis")


def reference_function_bytes(path):
    with Path(path).open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        function = symbols.get_symbol_by_name("pxPortInitialiseStack")[0]
        section_index = function["st_shndx"]
        section = elf.get_section(section_index)
        begin, size = function["st_value"] & ~1, function["st_size"]
        data = bytearray(section.data()[begin:begin + size])
        relocations = []
        for candidate in elf.iter_sections():
            if candidate["sh_type"] not in ("SHT_REL", "SHT_RELA") or candidate["sh_info"] != section_index:
                continue
            table = elf.get_section(candidate["sh_link"])
            for relocation in candidate.iter_relocations():
                offset = relocation["r_offset"] - begin
                if 0 <= offset < size:
                    target = table.get_symbol(relocation["r_info_sym"]).name
                    relocations.append((offset, relocation["r_info_type"], target))
                    # ABS32 literal retains the same symbolic target. There
                    # must be no external call or other transformed relocation.
                    assert relocation["r_info_type"] == 2, (path, relocation)
        return bytes(data), relocations


def extract_reference(source, destination):
    assembly = Path(source).read_text()
    matches = list(re.finditer(r"(?ms)^\s*\.type\s+pxPortInitialiseStack,\s*%function\s*\n"
        r"pxPortInitialiseStack:.*?^\s*\.size\s+pxPortInitialiseStack,\s*\.-pxPortInitialiseStack\s*$", assembly))
    assert len(matches) == 1, "compiler-generated constructor boundary changed"
    prefix = assembly[:assembly.index("\t.text")]
    with Path(source).with_suffix(".o").open("rb") as stream:
        elf = ELFFile(stream)
        symbol = elf.get_section_by_name(".symtab").get_symbol_by_name("pxPortInitialiseStack")[0]
        alignment_offset = (symbol["st_value"] & ~1) % 4
    assert alignment_offset in (0, 2)
    # Os can place the function at 2 mod 4. Preserve that placement so literal
    # alignment/padding and PC-relative instruction bytes remain identical.
    output = prefix + '\n.section .text.pxPortInitialiseStack,"ax",%progbits\n' + (
        f".align 2\n.space {alignment_offset}\n.global pxPortInitialiseStack\n.syntax unified\n.thumb\n.thumb_func\n") + matches[0][0] + "\n"
    Path(destination).write_text(output)


class Machine:
    stop = 0x0803FFF0
    sp = 0x2003F000

    def __init__(self, path, label):
        self.image, self.label = Image(path), label
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
        for base, size in ((0x08000000, 0x40000), (0x20000000, 0x40000),
                           (0x24000000, 0x10000), (0x30000000, 0x10000),
                           (0xE000E000, 0x2000)):
            self.uc.mem_map(base, size)
        for address, data in self.image.loads:
            self.uc.mem_write(address, data)
        self.panic_address = self.image.symbols.get("fiber_panic", {}).get("value", 0) & ~1
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._memory)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid)
        self.pending_fault = None

    def address(self, name):
        return self.image.address(name)

    def read(self, address, size):
        return bytes(self.uc.mem_read(address, size))

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def get(self, address):
        return words(self.read(address, 4))[0]

    def _code(self, uc, address, size, data):
        self.instructions += 1
        if self.pending_fault:
            target, replacement = self.pending_fault
            self.put(target, replacement)
            self.pending_fault = None
        if address == self.panic_address:
            self.panic = chr(uc.reg_read(UC_ARM_REG_R0) & 255)
            uc.emu_stop()
        elif address == self.stop:
            self.returned = True
            uc.emu_stop()

    def _memory(self, uc, kind, address, size, value, data):
        self.accesses.append((kind, address, size, value))
        if address >= 0xE0000000:
            if not self.allow_mmio or address not in (CPACR, FPCCR) or size != 4:
                self.invalid.append(("unmodeled MMIO", address, size))
                uc.emu_stop()
            if kind == UC_MEM_WRITE and self.fault and address == self.fault[0]:
                self.pending_fault = self.fault

    def _invalid(self, uc, kind, address, size, value, data):
        self.invalid.append((kind, address, size))
        return False

    def call(self, name, *args, panic=None, r9=0xA9A9A9A9,
             category="other", allow_mmio=False, fault=None):
        self.panic, self.returned = None, False
        self.accesses, self.invalid, self.instructions = [], [], 0
        self.allow_mmio, self.fault, self.pending_fault = allow_mmio, fault, None
        for reg, value in ((UC_ARM_REG_CONTROL, 0), (UC_ARM_REG_PRIMASK, 0),
                (UC_ARM_REG_BASEPRI, 0), (UC_ARM_REG_FAULTMASK, 0),
                (UC_ARM_REG_XPSR, 0x01000000), (UC_ARM_REG_MSP, self.sp),
                (UC_ARM_REG_SP, self.sp), (UC_ARM_REG_PSP, 0x2400FFF0),
                (UC_ARM_REG_R9, r9), (UC_ARM_REG_LR, self.stop | 1)):
            self.uc.reg_write(reg, value)
        for register, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(register, value)
        if len(args) > 4:
            self.uc.mem_write(self.sp, packed(args[4:]))
        try:
            self.uc.emu_start(self.address(name) | 1, self.stop + 2, count=300000)
        except UcError as exc:
            raise AssertionError(f"{self.label}/{name} at {self.uc.reg_read(UC_ARM_REG_PC):#x}: {exc}") from exc
        assert not self.invalid, (self.label, name, self.invalid)
        assert self.panic == panic, (self.label, name, self.panic, panic)
        assert panic is not None or self.returned, (self.label, name, "did not return")
        assert self.uc.reg_read(UC_ARM_REG_CONTROL) == 0, name
        assert self.uc.reg_read(UC_ARM_REG_PSP) == 0x2400FFF0, name
        assert all(self.uc.reg_read(reg) == 0 for reg in
                   (UC_ARM_REG_PRIMASK, UC_ARM_REG_BASEPRI, UC_ARM_REG_FAULTMASK)), name
        RECEIPTS.append({"Config": self.label, "Category": category, "Function": name,
                         "Panic": panic, "Instructions": self.instructions})
        return self.uc.reg_read(UC_ARM_REG_R0)


def fnv(values):
    result = 2166136261
    for byte in packed(values):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def geometry(regions):
    protected = 8 + (regions - 4) * 8
    return protected, protected + 220, (352 if regions == 8 else 416)


def seal(m, ctx, regions):
    _, boot, _ = geometry(regions)
    values = words(m.read(ctx + boot, 72))
    values.append(struct.unpack("<H", m.read(ctx + boot + 72, 2))[0])
    values.extend(words(m.read(ctx + boot + 76, 8)))
    values.extend(words(m.read(ctx + 4, 4 + (regions - 4) * 8)))
    return fnv(values)


def construct(m, regions, begin=0x24000000, length=2048, seed=0xA9A9A9A9, argument=0x12345678):
    protected, boot, size = geometry(regions)
    ctx = m.address("constructor_fixture_context")
    entry = m.address("constructor_fixture_task")
    end, base = begin + length, begin + 32
    m.uc.mem_write(ctx, b"\xA5" * size)
    m.uc.mem_write(begin, b"\xCC" * length)
    slot_before = m.read(0x30000000, 32)
    m.call("fiber_port_context_init", ctx, begin, end, entry, argument,
           r9=seed, category="constructor-valid")
    expected_image = [0] * 54
    expected_image[5], expected_image[8] = seed, argument
    expected_image[13:20] = [m.address("fiber_port_unprivileged_task_return") | 1,
        entry & ~1, 0x01000000, end - 32, base, 3, 0xFFFFFFBC]
    assert words(m.read(ctx + protected, 216)) == expected_image, "numeric initial backing"
    assert m.get(ctx) == ctx + protected + 80, "basic one-past cursor"
    assert m.get(ctx + 4) == 0x04FF, "numeric MAIR0"
    pairs = [begin | 3, (end - 1) & ~31 | 1, 0x30000007, 0x30000001]
    pairs += [0] * (2 * (regions - 6))
    assert words(m.read(ctx + 8, (regions - 4) * 8)) == pairs, "numeric context map"
    assert m.get(ctx + protected + 216) == 0, "runtime flags"
    expected_boot = [begin, end, base, end, length - 32, entry, argument,
        0x43334650, 0x00010000 + regions, size, 8, 0x1C87,
        0xFFFFFFBC, 3, regions, regions - 4, 54, 0x46424F54]
    expected_record = packed(expected_boot) + struct.pack("<HHIII", 1, 1,
        0xA5A5A5A5, 0x5A5A5A5A, seal(m, ctx, regions))
    assert m.read(ctx + boot, 88) == expected_record, "numeric complete boot record/seal"
    assert m.read(begin, length) == packed([0xDEADBEEF]) + b"\xCC" * (length - 4), (
        "constructor prewrote user frame or redzone")
    assert m.read(0x30000000, 32) == slot_before, "constructor published current context"
    for kind, address, count, _ in m.accesses:
        if kind == UC_MEM_WRITE:
            assert (ctx <= address < address + count <= ctx + size or
                    address == begin and count == 4 or
                    m.sp - 0x4000 <= address < address + count <= m.sp), (
                        "unexpected constructor write", hex(address), count)
    m.call("fiber_port_context_validate_initial_restore", ctx, r9=seed ^ 0xFFFFFFFF,
           category="initial-valid")
    assert m.call("fiber_port_context_compute_seal", ctx, category="seal-valid") == seal(m, ctx, regions)
    return expected_image


def reference(run):
    directory = Path(run["Directory"]) / "reference"
    original = reference_function_bytes(directory / "port.o")
    isolated = reference_function_bytes(directory / "constructor.o")
    assert original == isolated, "isolated reference changed compiler-generated bytes/relocations"
    (directory / "constructor-identity.json").write_text(json.dumps({
        "Function": "pxPortInitialiseStack", "Bytes": len(original[0]),
        "Sha256": hashlib.sha256(original[0]).hexdigest(), "Relocations": original[1],
        "Comparison": "Every function byte and relocation identical to full pinned port.o"}, indent=2) + "\n")
    m = Machine(run["Reference"], run["Name"])
    regions = run["Regions"]
    geometry_data = words(m.read(m.address("constructor_reference_geometry"), 36))
    count, image_bytes, offset, flags, size, system, top_offset, limit_offset, task_offset = geometry_data
    assert (count, image_bytes, offset, flags, system) == (
        54, 216, 4 + (regions - 4) * 8, 220 + (regions - 4) * 8, 224 + (regions - 4) * 8)
    assert size >= task_offset + 4 and top_offset != limit_offset != task_offset
    ctx = m.address("constructor_reference_settings")
    results = []
    for privileged in (0, 1):
        for argument in (0, 0x12345678):
            m.uc.mem_write(ctx, b"\xA5" * size)
            m.uc.mem_write(0x24000000, b"\xCC" * 2048)
            result = m.call("pxPortInitialiseStack", 0x24000800, 0x24000020,
                0x08010001, argument, privileged, ctx, category="reference-constructor")
            expected = [0x04040404, 0x05050505, 0x06060606, 0x07070707,
                0x08080808, 0x09090909, 0x10101010, 0x11111111,
                argument, 0x01010101, 0x02020202, 0x03030303, 0x12121212,
                m.address("constructor_reference_return"), 0x08010001,
                0x01000000, 0x240007E0, 0x24000020, 2 if privileged else 3, 0xFFFFFFBC]
            actual = words(m.read(ctx + offset, 216))
            assert actual[:20] == expected, ("actual pinned constructor", actual[:20], expected)
            assert actual[20:] == [0xA5A5A5A5] * 34, "reference tail is deliberately untouched"
            assert result == ctx + offset + 80, "reference basic one-past cursor"
            assert m.get(ctx + flags) == ((0xA5A5A5A5 | 2) if privileged else (0xA5A5A5A5 & ~2))
            assert m.get(ctx + top_offset) == (ctx + system + 127 * 4) & ~7
            assert m.get(ctx + limit_offset) == (ctx + system + 7) & ~7
            assert m.get(ctx + task_offset) == 0
            assert m.read(0x24000000, 2048) == b"\xCC" * 2048, "reference prewrote user PSP"
            if privileged == 0 and argument == 0x12345678:
                results = actual[:20]
    return results


def constructor_cases(run, reference_image):
    regions = run["Regions"]
    m = Machine(run["Eager"], run["Name"])
    assert words(m.read(m.address("constructor_fixture_cpp_symbols"), len(REQUIRED) * 4)) == [
        m.address(name) for name in REQUIRED], "actual private C++-to-C ELF linkage"
    for length in (160, 2048, 65536):
        for seed in (0, 0xA9A9A9A9, 0xFEDCBA98):
            image = construct(m, regions, length=length, seed=seed)
            if length == 2048:
                # Actual images agree on their processor-state backbone. Entry
                # bit normalization and distinct return targets are intentional.
                for index in (8, 15, 16, 17, 18, 19):
                    assert image[index] == reference_image[index], (index, image, reference_image)
                assert image[14] == reference_image[14] & ~1
    construct(m, regions, begin=0x24000020, length=2048, argument=0)
    ctx = m.address("constructor_fixture_context")
    entry = m.address("constructor_fixture_task")
    _, _, size = geometry(regions)
    good = [ctx, 0x24000000, 0x24000800, entry, 0x12345678]
    cases = [
        ("null-context", {0: 0}, "C"), ("null-begin", {1: 0}, "B"),
        ("null-end", {2: 0}, "T"), ("null-entry", {3: 0}, "E"),
        ("unaligned-context", {0: ctx + 4}, "A"),
        ("wrapped-context", {0: 0xFFFFFFF8}, "O"),
        ("foreign-context", {0: 0x24001000}, "C"),
        ("cross-boundary-context", {0: 0x30010000 - size + 8}, "C"),
        ("context-in-current-slot", {0: 0x30000000}, "C"),
        ("empty-stack", {2: 0x24000000}, "N"),
        ("reversed-stack", {1: 0x24000800, 2: 0x24000000}, "N"),
        ("wrapped-stack", {1: 0xFFFFFFE0, 2: 0x20}, "N"),
        ("unaligned-begin", {1: 0x24000008}, "A"),
        ("unaligned-end", {2: 0x24000808}, "A"),
        ("overlapping-context", {1: ctx & ~31, 2: (ctx & ~31) + 1024}, "O"),
        ("foreign-stack", {1: 0x24010000, 2: 0x24010800}, "P"),
        ("raw-prefix-outside-map", {1: 0x23FFFFE0}, "P"),
        ("raw-tail-outside-map", {1: 0x2400FFE0, 2: 0x24010020}, "P"),
        ("non-thumb-entry", {3: entry & ~1}, "e"),
        ("privileged-entry", {3: 0x08000001}, "c"),
        ("syscall-entry", {3: 0x08020001}, "c"),
        ("foreign-entry", {3: 0xFFFFFFFD}, "c"),
        ("redzone-only", {2: 0x24000020}, "H"),
        ("too-small-usable-stack", {2: 0x24000080}, "H")]
    for name, overrides, panic in cases:
        args = good.copy()
        for index, value in overrides.items():
            args[index] = value
        m.uc.mem_write(ctx, b"\xA5" * size)
        before_priv = m.read(0x30000000, 65536)
        before_user = m.read(0x24000000, 65536)
        m.call("fiber_port_context_init", *args, panic=panic, category="constructor-rejection/" + name)
        assert m.read(0x30000000, 65536) == before_priv, (name, "modified privileged output")
        assert m.read(0x24000000, 65536) == before_user, (name, "modified user stack")
        assert not any(0x24000000 <= a < 0x24010000 or 0x30000000 <= a < 0x30010000
                       for _, a, _, _ in m.accesses), (name, "accessed rejected data before bounds proof")


def encoder_cases(run):
    m = Machine(run["Eager"], run["Name"])
    out = m.address("constructor_fixture_scratch")
    regions = run["Regions"]
    for begin, end in ((0x24000100, 0x24000120), (0x24000000, 0x24010000),
                       (0xFFFFFF00, 0xFFFFFFE0)):
        for ap in range(4):
            for sh in (0, 2, 3):
                for xn in (0, 1):
                    for attr in (0, 1):
                        for region in (0, regions - 1):
                            m.uc.mem_write(out, b"\xA5" * 8)
                            rbar = ap << 1 | sh << 3 | xn
                            assert m.call("fiber_port_mpu_try_encode_exact_region", begin, end,
                                region, rbar, attr << 1, out, category="encoder-valid") == 1
                            assert words(m.read(out, 8)) == [begin | rbar, ((end - 1) & ~31) | attr << 1 | 1]
    bad = [(0x24000000, 0x24000000, 4, 3, 0, out),
           (0x24000020, 0x24000000, 4, 3, 0, out),
           (0xFFFFFFE0, 0x20, 4, 3, 0, out),
           (0x24000001, 0x24000020, 4, 3, 0, out),
           (0x24000000, 0x24000021, 4, 3, 0, out),
           (0x24000000, 0x24000020, regions, 3, 0, out),
           (0x24000000, 0x24000020, 0xFFFFFFFF, 3, 0, out),
           (0x24000000, 0x24000020, 4, 3, 0, 0)]
    bad += [(0x24000000, 0x24000020, 4, rb, 0, out)
            for rb in (8, 9, 10, 15, 32, 0x80000000, 0xFFFFFFFF)]
    bad += [(0x24000000, 0x24000020, 4, 3, rl, out)
            for rl in (1, 3, 4, 6, 8, 10, 12, 14, 16, 18, 32, 0x80000000, 0xFFFFFFFF)]
    for args in bad:
        m.uc.mem_write(out, b"\xA5" * 8)
        assert m.call("fiber_port_mpu_try_encode_exact_region", *args, category="encoder-rejection") == 0
        assert m.read(out, 8) == b"\xA5" * 8, "encoder changed output on failure"
        assert not any(k == UC_MEM_WRITE and out <= a < out + 8 for k, a, _, _ in m.accesses)
    m.call("fiber_port_mpu_load_linker_layout", out, category="layout-valid")
    assert words(m.read(out, 48)) == list(LAYOUT)
    m.call("fiber_port_mpu_linker_layout_check", out, category="layout-valid")
    for index in range(12):
        altered = list(LAYOUT)
        altered[index] += 1
        m.uc.mem_write(out, packed(altered))
        m.call("fiber_port_mpu_linker_layout_check", out, panic="L", category="layout-rejection")
    for start, end in ((0, 1), (2, 3), (4, 5), (6, 7), (10, 11)):
        altered = list(LAYOUT)
        altered[end] = altered[start]
        m.uc.mem_write(out, packed(altered))
        m.call("fiber_port_mpu_linker_layout_check", out, panic="L", category="layout-rejection")
    # A narrower but still exact unprivileged RAM map is a valid layout.
    altered = list(LAYOUT)
    altered[10] += 32
    m.uc.mem_write(out, packed(altered))
    m.call("fiber_port_mpu_linker_layout_check", out, category="layout-valid")
    m.call("fiber_port_mpu_build_global_regions", out, category="global-map-valid")
    assert words(m.read(out, 32)) == [0x08000004, 0x0800FFE1,
        0x08010006, 0x0801FFE1, 0x08020006, 0x08020FE1, 0x30000021, 0x3000FFE1]


def corruption_cases(run):
    m = Machine(run["Eager"], run["Name"])
    regions = run["Regions"]
    construct(m, regions)
    ctx = m.address("constructor_fixture_context")
    protected, boot, size = geometry(regions)
    original = m.read(ctx, size)
    # Every immutable ABI field is tested against a separately computed seal;
    # restoring a valid hash must not bypass mandatory structural validation.
    fields = [(0, "A"), (4, "A"), (8, "Z"), (12, "z"), (16, "a"),
              (20, "c"), (24, "h")] + [(i, "q") for i in range(28, 68, 4)]
    fields += [(68, "m"), (72, "v"), (76, "g"), (80, "G"), (84, "h")]
    for offset, panic in fields:
        m.uc.mem_write(ctx, original)
        value = m.get(ctx + boot + offset)
        # The entry must remain Thumb but move into privileged flash.
        replacement = 0x08000001 if offset == 20 else value ^ 1
        m.put(ctx + boot + offset, replacement)
        m.call("fiber_port_context_seal_check", ctx, panic=panic, category="metadata-corruption")
    m.uc.mem_write(ctx, original)
    m.uc.mem_write(ctx + boot + 74, b"\x00\x00")
    m.call("fiber_port_context_seal_check", ctx, panic="s", category="metadata-corruption")
    for offset in [4] + list(range(8, protected, 4)):
        m.uc.mem_write(ctx, original)
        m.put(ctx + offset, m.get(ctx + offset) ^ 1)
        m.put(ctx + boot + 84, seal(m, ctx, regions))
        m.call("fiber_port_context_seal_check", ctx, panic="M", category="map-corruption-resealed")
    # Seal intentionally excludes the mutable image/cursor/runtime flags.
    image_cases = [(0, "P"), (protected + 80, "P"),
        (protected + 8 * 4, "0"), (protected + 13 * 4, "R"),
        (protected + 14 * 4, "x"), (protected + 15 * 4, "X"),
        (protected + 16 * 4, "A"), (protected + 17 * 4, "L"),
        (protected + 18 * 4, "q"), (protected + 19 * 4, "x"),
        (protected + 216, "F")]
    image_cases += [(protected + i * 4, "R") for i in (0, 1, 2, 3, 4, 6, 7, 9, 10, 11, 12)]
    image_cases += [(protected + i * 4, "F") for i in range(21, 54)]
    for offset, panic in image_cases:
        m.uc.mem_write(ctx, original)
        m.put(ctx + offset, m.get(ctx + offset) ^ 1)
        assert seal(m, ctx, regions) == words(original[boot + 84:boot + 88])[0]
        m.call("fiber_port_context_validate_initial_restore", ctx, panic=panic, category="initial-image-corruption")
    m.uc.mem_write(ctx, original)
    m.put(ctx + protected + 20, 0xDEADBEEF)
    m.call("fiber_port_context_validate_initial_restore", ctx, r9=0, category="r9-private-semantics-valid")
    m.uc.mem_write(ctx, original)
    m.put(0x24000000, 0)
    m.call("fiber_port_context_validate_initial_restore", ctx, panic="c", category="canary-corruption")
    m.put(0x24000000, 0xDEADBEEF)
    m.put(ctx + boot, 0x23FFFFE0)
    m.put(ctx + boot + 84, seal(m, ctx, regions))
    m.call("fiber_port_context_validate_initial_restore", ctx, panic="P", category="bounds-before-canary")
    assert not any(0x23FFFFE0 <= a < 0x24000020 for _, a, _, _ in m.accesses)


def fpu_cases(run):
    for policy, lazy in (("Eager", 0), ("Lazy", 1)):
        m = Machine(run[policy], run["Name"] + "/fpu-" + policy.lower())
        expected_fp = 0x80000000 | lazy << 30
        for cpacr, fpccr in ((0, 0), (0x550055, 0x123400), (0x123, 0x40001200),
                              (0xF00000, expected_fp)):
            m.put(CPACR, cpacr)
            m.put(FPCCR, fpccr)
            m.call("fiber_port_fpu_prepare", allow_mmio=True, category="fpu-prepare-valid")
            assert m.get(CPACR) == cpacr | 0xF00000
            assert m.get(FPCCR) == (fpccr | 0x80000000 | lazy << 30) & (0xFFFFFFFF if lazy else ~0x40000000)
            assert any(a == CPACR for _, a, _, _ in m.accesses)
            assert any(a == FPCCR for _, a, _, _ in m.accesses)
        m.put(CPACR, 0xF00000)
        m.put(FPCCR, expected_fp | 1)
        m.call("fiber_port_fpu_require_configured", allow_mmio=True, category="fpu-configured-lspact-valid")
        m.call("fiber_port_fpu_require_ready", allow_mmio=True, panic="E", category="fpu-ready-lspact-rejection")
        m.put(FPCCR, expected_fp)
        m.call("fiber_port_fpu_require_ready", allow_mmio=True, category="fpu-ready-valid")
        for cpacr, fpccr, panic in ((0, expected_fp, "e"),
                (0xF00000, expected_fp ^ 0x80000000, "E"),
                (0xF00000, expected_fp ^ 0x40000000, "E")):
            m.put(CPACR, cpacr)
            m.put(FPCCR, fpccr)
            m.call("fiber_port_fpu_require_configured", allow_mmio=True, panic=panic, category="fpu-config-rejection")
        for target, replacement, panic in ((CPACR, 0, "e"),
                (FPCCR, expected_fp ^ 0x80000000, "E"),
                (FPCCR, expected_fp ^ 0x40000000, "E")):
            m.put(CPACR, 0)
            m.put(FPCCR, 0x40000000 if not lazy else 0)
            m.call("fiber_port_fpu_prepare", allow_mmio=True, fault=(target, replacement),
                   panic=panic, category="fpu-write-readback-fault")
            assert any(k == UC_MEM_WRITE and a == target for k, a, _, _ in m.accesses)


def main():
    manifest = Path(sys.argv[1])
    runs = json.loads(manifest.read_text(encoding="utf-8-sig"))
    assert len(runs) == 8
    assert {r["Name"] for r in runs} == {
        f"r{regions}-{abi}-{opt}" for regions in (8, 16)
        for abi in ("hard", "softfp") for opt in ("O2", "Os")}
    static_failures = []
    for run in runs:
        try:
            audit_objects(run)
        except AssertionError as exc:
            # Keep behavioral evidence for every baseline even when a static
            # contract is broken; the overall maintained run still must fail.
            static_failures.append(f"{run['Name']}: {exc}")
        reference_image = reference(run)
        constructor_cases(run, reference_image)
        encoder_cases(run)
        corruption_cases(run)
        fpu_cases(run)
        print(f"Actual ARM constructor/FPU-policy execution PASS {run['Name']}")
    counts = collections.Counter(r["Category"].split("/")[0] for r in RECEIPTS)
    summary = {"Configurations": len(runs), "Calls": len(RECEIPTS),
        "ExpectedPanics": sum(r["Panic"] is not None for r in RECEIPTS),
        "StaticFailures": static_failures,
        "Categories": dict(sorted(counts.items())), "CallsExecuted": RECEIPTS,
        "Scope": "Actual pinned/production ARM C instructions on Unicorn Cortex-M33. CPACR/FPCCR policy uses explicitly mapped test words and write-readback fault injection; not CPU exception/MPU/FPU hardware qualification."}
    (manifest.parent / "execution.json").write_text(json.dumps(summary, indent=2) + "\n")
    assert not static_failures, "Static constructor contract failed:\n" + "\n".join(static_failures)
    print(f"PASS {len(RECEIPTS)} actual ARM calls, {summary['ExpectedPanics']} expected panic paths; 8 constructor configurations, 16 separate FPU-policy variants")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--extract-reference":
        extract_reference(sys.argv[2], sys.argv[3])
    else:
        main()
