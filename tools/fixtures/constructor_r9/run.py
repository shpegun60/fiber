"""Execute actual public-init chains and bounded R9 restore instruction slices.

Ordinary AAPCS never fixes R9 and does not assign static-base meaning to its
initial frame word. A separate explicitly reserved-R9 ABI uses -ffixed-r9.
No constructor interception or register repair is permitted.
"""
import sys

OPT_ERROR = "Disable PYTHONOPTIMIZE and do not use -O/-OO for constructor R9 regressions"
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import traceback

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

for _package, _version in (("unicorn", "2.1.4"), ("pyelftools", "0.33")):
    try:
        _actual = importlib.metadata.version(_package)
    except importlib.metadata.PackageNotFoundError:
        raise SystemExit(f"Constructor R9 requires {_package}=={_version}; package missing")
    if _actual != _version:
        raise SystemExit(f"Constructor R9 requires {_package}=={_version}; found {_actual}")

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R9, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP,
    UC_ARM_REG_MSP, UC_ARM_REG_CONTROL, UC_ARM_REG_XPSR,
    UC_CPU_ARM_CORTEX_M0, UC_CPU_ARM_CORTEX_M3, UC_CPU_ARM_CORTEX_M4,
    UC_CPU_ARM_CORTEX_M7,
)

SEEDS = (0x13579BDF, 0x2468ACE1, 0x90ABCDEF, 0x0BADCAFE)
HOSTILE = ("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs",
           "-ftest-coverage", "-fsanitize-coverage=trace-pc")

COMMON_ROLES = ("engine", "state", "optional_configuration", "legacy_compat")
VALIDATION_ROLES = ("engine", "state", "panic", "optional_configuration", "legacy_compat", "facade_bridge")


def runtime_reader(repo):
    spec = importlib.util.spec_from_file_location("r9_runtime_sources", Path(repo) / "tools/runtime_sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
MODES = ("O2", "Os", "O2-lto", "Os-lto", "O2-hostile", "Os-hostile",
         "O2-lto-hostile", "Os-lto-hostile")
COHORTS = ("legacy", "fiber")
FRAME_BAD = 0xDEADC0DE
CONTEXT, BEGIN, END, ARG, CALL_SP = 0x20008000, 0x20010000, 0x20012000, 0x20009000, 0x2002F000


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def interpreter_image():
    if os.name == "nt":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer))
        require(0 < length < len(buffer), "Cannot identify running Python image")
        return Path(buffer.value).resolve()
    return Path(sys.executable).resolve()


def profiles(include_cm0_mpu=False):
    result = []
    rows = (
        ("CM33NTZ", "ARM_CM33_NTZ/non_secure", 33, "ARMV8M_MAINLINE", "ntz", False),
        ("CM55NTZ", "ARM_CM55_NTZ/non_secure", 55, "ARMV81M_MAINLINE", "ntz", False),
        ("CM23NTZ", "ARM_CM23_NTZ/non_secure", 23, "ARMV8M_BASELINE", "ntz", False),
        ("CM33TFM", "ARM_CM33_TFM/non_secure", 33, "ARMV8M_MAINLINE", "ntz", False),
        ("CM33FNTZ", "ARM_CM33F_NTZ/non_secure", 33, "ARMV8M_MAINLINE", "ntz", True),
        ("CM55FNTZ", "ARM_CM55F_NTZ/non_secure", 55, "ARMV81M_MAINLINE", "ntz", True),
        ("CM55MVEFNTZ", "ARM_CM55_MVEF_NTZ/non_secure", 55, "ARMV81M_MAINLINE", "mve", True),
        ("CM33S", "ARM_CM33/non_secure", 33, "ARMV8M_MAINLINE", "secure", False),
        ("CM0", "ARM_CM0", 0, "ARMV6M", "classic0", False),
        ("CM3", "ARM_CM3", 3, "ARMV7M", "classic", False),
        ("CM4", "ARM_CM4", 4, "ARMV7EM", "classic", True),
        ("CM7", "ARM_CM7/r0p1", 7, "ARMV7EM", "classic", True),
    )
    if include_cm0_mpu:
        rows += (("CM0MPU", "ARM_CM0_MPU", 0, "ARMV6M", "mpu0", False),)
    for name, directory, core, architecture, frame, fp in rows:
        abis = ("hard", "softfp") if fp else ("soft",)
        if name in ("CM4", "CM7"):
            abis = ("soft", "hard", "softfp")
        for abi in abis:
            cpu = "cortex-m" + str(core)
            if frame == "mpu0":
                cpu = "cortex-m0plus"
            if name == "CM55FNTZ":
                cpu += "+nomve"
            flags = ["-mcpu=" + cpu, "-mthumb", "-mfloat-abi=" + abi]
            if fp and frame != "mve" and abi != "soft":
                flags += ["-mfpu=" + ("fpv4-sp-d16" if core == 4 else "fpv5-sp-d16" if core == 33 else "fpv5-d16")]
            result.append(dict(name=name + "-" + abi, port=name, directory=directory,
                               core=core, architecture=architecture, frame=frame,
                               fp=int(fp), abi=abi, flags=flags))
    return result


def source_group(profile):
    names = ["fiber_port.c", "fiber_port_boot.c"]
    if profile["port"] in ("CM0", "CM3", "CM4", "CM7"):
        names += ["fiber_port_exception.c"]
    elif profile["port"] in ("CM55FNTZ", "CM55MVEFNTZ"):
        names += ["fiber_port_svc.c"]
    elif profile["port"] == "CM33TFM":
        names += ["fiber_port_tfm.c", "fiber_port_tfm_os_wrapper.c"]
    elif profile["port"] == "CM33S":
        names += ["fiber_port_secure_context.c", "fiber_port_svc.c"]
    return sorted(names)


def rejection(result, diagnostic):
    return result.returncode == 1 and result.stdout == "" and result.stderr.splitlines() == [diagnostic]


def warning_scope(source, diagnostic, core, port):
    if core != 0 or Path(source).resolve().parent != Path(port).resolve():
        return None
    if Path(source).name == "fiber_portmacro.h" and diagnostic == (
            "[fiber] Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000."):
        return "expected-no-VTOR-manifest"
    if Path(source).name == "fiber_port_exception.c" and diagnostic == (
            "array subscript 0 is outside array bounds of 'const uint32_t[0]' "
            "{aka 'const long unsigned int[]'} [-Warray-bounds=]"):
        return "non-R9-cold-vector-read-warning"
    return None


def preflight():
    script = str(Path(__file__).resolve())
    calls = 0
    for flag in ("-O", "-OO"):
        for source in (None,
                       f"import runpy; runpy.run_path({script!r}, run_name='import_fixture')",
                       "import importlib.util; "
                       f"s=importlib.util.spec_from_file_location('r9_fixture',{script!r}); "
                       "m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"):
            args = [sys.executable, flag, script] if source is None else [sys.executable, flag, "-c", source]
            r = subprocess.run(args, capture_output=True, text=True, timeout=20)
            require(rejection(r, OPT_ERROR), "Optimized direct/import guard failed: " + repr(r))
            calls += 1
    fake = subprocess.run([sys.executable, "-c", f"raise RuntimeError({OPT_ERROR!r})"],
                          capture_output=True, text=True, timeout=20)
    require(not rejection(fake, OPT_ERROR), "Counterfeit traceback accepted as exact rejection")
    for package in ("unicorn", "pyelftools"):
        versions = {"unicorn": "2.1.4", "pyelftools": "0.33", package: "0.0"}
        code = (f"import importlib.metadata as m; m.version={versions!r}.__getitem__; "
                f"import runpy; runpy.run_path({script!r},run_name='import_fixture')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
        expected = f"Constructor R9 requires {package}=={dict(unicorn='2.1.4', pyelftools='0.33')[package]}; found 0.0"
        require(rejection(r, expected), "Dependency guard failed: " + package)
        calls += 1
    require(classify(1, 1, 1, [1], None) == "PASS", "Classifier positive control")
    require(classify(1, 2, 1, [1], None) == "BORROWED-R9", "Ordinary frame is not a static-base contract")
    require(classify(1, 2, 1, [1], None, True) == "STATIC-BASE-R9", "Reserved frame negative")
    require(classify(1, 1, 2, [1], None) == "RETURN-R9", "Classifier return negative")
    require(classify(1, 1, 1, [1], "X") == "PANIC", "Classifier panic must not pass")
    manifest = "[fiber] Selected ARMv6-M port has no SCB->VTOR; falling back to base table at 0x00000000."
    require(warning_scope("expected-port/fiber_portmacro.h", manifest, 0, "expected-port") == "expected-no-VTOR-manifest", "Expected manifest warning")
    require(warning_scope("foreign-port/fiber_portmacro.h", manifest, 0, "expected-port") is None, "Foreign warning must not be accepted")
    require(warning_scope("expected-port/fiber_portmacro.h", "unrelated warning", 0, "expected-port") is None, "Unrelated warning must not be accepted")
    return calls + 1 + 5 + 3


def classify(seed, frame, post, public_entries, panic, reserved=False):
    if panic is not None:
        return "PANIC"
    if public_entries != [seed]:
        return "PUBLIC-SEED"
    if post != seed:
        return "RETURN-R9"
    if frame == seed:
        return "PASS"
    return "STATIC-BASE-R9" if reserved else "BORROWED-R9"


class Machine:
    def __init__(self, elf_path, profile, cohort="legacy"):
        self.elf_path = elf_path
        self.cohort = cohort
        self.public_api = "fiber_v1_init" if cohort == "fiber" else "fiber_init"
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        core = profile["core"]
        model = {0: UC_CPU_ARM_CORTEX_M0, 23: UC_CPU_ARM_CORTEX_M0,
                 3: UC_CPU_ARM_CORTEX_M3, 7: UC_CPU_ARM_CORTEX_M7}.get(core, UC_CPU_ARM_CORTEX_M4)
        self.uc.ctl_set_cpu_model(model)
        self.uc.mem_map(0x08000000, 0x40000)
        self.uc.mem_map(0x20000000, 0x40000 if profile["frame"] == "mpu0" else 0x30000)
        self.symbols = {}
        with elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            require(elf["e_machine"] == "EM_ARM" and elf.elfclass == 32 and elf.little_endian,
                    "ELF is not 32-bit little-endian ARM")
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    address, size = segment["p_vaddr"], segment["p_memsz"]
                    ram_ok = 0x20000000 <= address <= address + size <= CONTEXT
                    if profile["frame"] == "mpu0":
                        ram_ok = ram_ok or (address == 0x20030000 and size == 256 and
                                            segment["p_filesz"] == 0)
                    require(0x08000000 <= address <= address + size <= 0x08040000 or ram_ok,
                            "Linked image overlaps fixture-owned RAM or exceeds its flash map")
                    if segment["p_filesz"]:
                        self.uc.mem_write(address, segment.data())
            for symbol in elf.get_section_by_name(".symtab").iter_symbols():
                if symbol.name and symbol["st_shndx"] != "SHN_UNDEF":
                    self.symbols[symbol.name] = symbol["st_value"]
        for name in (self.public_api, "fiber_port_context_init", "r9_call_init", "r9_stop", "fiber_panic",
                     "fiber_addr_plausible_ram", "fiber_addr_plausible_code", "r9_task_entry", "fiber_internal_task_return"):
            require(name in self.symbols, "Real ELF symbol missing: " + name)
        if cohort == "fiber":
            for name in ("ctxrt_v1_init", "r9_fiber_layout",
                         "fiber_internal_runtime_close_context_configuration",
                         "fiber_internal_runtime_require_context_configuration_open"):
                require(name in self.symbols, "Real consumer/configuration symbol missing: " + name)
            require(not {"fiber_init", "fiber_current", "fiber_start", "fiber_schedule",
                         "fiber_scheduler_set_pick_next"} & self.symbols.keys(),
                    "Fiber consumer unexpectedly linked the legacy five-operation shim")
        self.trace, self.invalid = [], []
        self.instructions = []
        for line in elf_path.with_name("image.dis").read_text().splitlines():
            match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{4}\s+){1,2})([a-z][a-z0-9.]*)\s*(.*)$", line)
            if match:
                self.instructions.append(dict(pc=int(match[1], 16), size=len(match[2].split()) * 2,
                                              op=match[3], args=match[4].split(";")[0].strip()))
        self.returned, self.panic = False, None
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self.bad_memory)

    def word(self, address):
        return struct.unpack("<I", self.uc.mem_read(address, 4))[0]

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack("<I", value))

    def code(self, uc, address, size, data):
        for name in (self.public_api, "ctxrt_v1_init", "fiber_port_context_init", "fiber_port_init_context_frame",
                     "fiber_addr_plausible_ram", "fiber_addr_plausible_code",
                     "fiber_internal_runtime_require_context_configuration_open"):
            if name in self.symbols and address == (self.symbols[name] & ~1):
                self.trace.append(dict(name=name, pc=address, r9=uc.reg_read(UC_ARM_REG_R9)))
        if address == (self.symbols["fiber_panic"] & ~1):
            self.panic = chr(uc.reg_read(UC_ARM_REG_R0) & 255)
            uc.emu_stop()
        elif address == (self.symbols["r9_stop"] & ~1):
            self.returned = True
            uc.emu_stop()
        elif "__stack_chk_fail" in self.symbols and address == (self.symbols["__stack_chk_fail"] & ~1):
            self.panic = "STACK-PROTECTOR"
            uc.emu_stop()

    def bad_memory(self, uc, kind, address, size, value, data):
        self.invalid.append(dict(kind=kind, address=address, size=size))
        return False

    def call(self, name, args, seed):
        self.uc.reg_write(UC_ARM_REG_CONTROL, 0)
        self.uc.reg_write(UC_ARM_REG_XPSR, 0x01000000)
        self.uc.reg_write(UC_ARM_REG_MSP, CALL_SP)
        self.uc.reg_write(UC_ARM_REG_SP, CALL_SP)
        self.uc.reg_write(UC_ARM_REG_R9, 0xA9A9A9A9)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        self.put(CALL_SP, args[4] if len(args) > 4 else 0)
        self.put(CALL_SP + 4, seed)
        self.uc.reg_write(UC_ARM_REG_LR, self.symbols["r9_stop"] | 1)
        try:
            self.uc.emu_start(self.symbols[name] | 1, 0, count=2000000)
        except UcError as error:
            raise RuntimeError(f"Unqualified emulator fault at {self.uc.reg_read(UC_ARM_REG_PC):#x}: {error}; {self.invalid}") from error
        require(self.returned or self.panic is not None, "Instruction budget exhausted, not an R9 result")
        require(not self.invalid, "Unmapped/MMIO access, not an R9 result: " + repr(self.invalid))
        return self.uc.reg_read(UC_ARM_REG_R0)

    def fault_control(self):
        address = self.symbols["r9_fault_probe"] & ~1
        try:
            self.uc.emu_start(address | 1, 0, count=8)
        except UcError as error:
            require(self.uc.reg_read(UC_ARM_REG_PC) == address and not self.invalid,
                    "Fault control was not the explicit UDF instruction")
            return dict(site=address, error=str(error), classifier="INFRASTRUCTURE-FAULT-NOT-R9")
        raise RuntimeError("Explicit UDF fault control unexpectedly returned")

    def restore_slice(self, profile, frame, expected, handler, mutant):
        start = self.symbols[handler] & ~1
        with Path(self.elf_path).open("rb") as stream:
            symbols = ELFFile(stream).get_section_by_name(".symtab")
            size = next(s["st_size"] for s in symbols.iter_symbols() if s.name == handler)
        body = [i for i in self.instructions if start <= i["pc"] < start + size]
        writes = [n for n, i in enumerate(body) if
                  (i["op"].startswith("ldm") and re.search(r"\br9\b", i["args"])) or
                  (i["op"].startswith("mov") and re.match(r"r9,\s*r[458]$", i["args"]))]
        altered = ((mutant == "wrong-restore" and handler in ("SVC_Handler", "fiber_port_restore_first_context_from_svc")) or
                   (mutant == "wrong-switch" and handler == "PendSV_Handler"))
        require(len(writes) == (2 if altered else 1), "Restore R9 instruction inventory drift: " + handler)
        n = writes[0]
        instruction = body[n]
        pointer = frame
        pointer_reg = UC_ARM_REG_R0
        if profile["frame"] == "mpu0":
            require(instruction["op"] == "mov" and instruction["args"] == "r9, r5", "MPU Thumb1 restore anchor drift")
            n -= 2
            require(body[n]["op"].startswith("ldm") and body[n]["args"] == "r1!, {r4, r5, r6, r7}" and
                    body[n + 1]["op"] == "mov" and body[n + 1]["args"] == "r8, r4", "MPU high-register restore drift")
            pointer_reg, pointer = UC_ARM_REG_R1, frame + 16
        elif profile["frame"] in ("classic0",) or profile["core"] == 23:
            require(instruction["op"] == "mov" and instruction["args"] == "r9, r5", "Thumb1 restore anchor drift")
            n -= 2
            require(body[n]["op"].startswith("ldm") and body[n]["args"] == "r0!, {r4, r5, r6, r7}" and
                    body[n + 1]["op"] == "mov" and body[n + 1]["args"] == "r8, r4", "Thumb1 high-register restore drift")
            pointer += (5 if profile["frame"] == "classic0" else 6) * 4
        elif profile["frame"] == "secure" and handler == "PendSV_Handler":
            require(instruction["args"] == "r2!, {r4, r5, r6, r7, r8, r9, r10, r11}", "Secure-aware NS restore anchor drift")
            pointer_reg, pointer = UC_ARM_REG_R2, frame + 12
        else:
            require(instruction["op"].startswith("ldm") and instruction["args"].startswith("r0!, {"), "Restore load anchor drift")
        end_instruction = body[writes[-1]]
        if altered:
            require(end_instruction["op"] == "mov" and end_instruction["args"] == "r9, r8" and
                    end_instruction["pc"] == instruction["pc"] + instruction["size"], "Compiled restore control drift")
        entry, end = body[n]["pc"], end_instruction["pc"] + end_instruction["size"]
        require(all(i["op"].startswith(("ldm", "mov")) for i in body[n:writes[-1] + 1]), "Restore slice contains non-register effects")
        self.uc.reg_write(UC_ARM_REG_CONTROL, 0)
        self.uc.reg_write(UC_ARM_REG_XPSR, 0x01000000)
        self.uc.reg_write(pointer_reg, pointer)
        self.uc.reg_write(UC_ARM_REG_R9, expected ^ 0xFFFFFFFF)
        try:
            self.uc.emu_start(entry | 1, end, count=8)
        except UcError as error:
            raise RuntimeError("Unsupported restore-slice instruction, not an R9 result: " + str(error)) from error
        require(self.uc.reg_read(UC_ARM_REG_PC) == end and not self.invalid, "Restore slice did not stop at exact boundary")
        actual = self.uc.reg_read(UC_ARM_REG_R9)
        return dict(handler=handler, entry=entry, end=end, pointer=pointer,
                    expected_r9=expected, actual_r9=actual, matched=actual == expected,
                    instructions=body[n:writes[-1] + 1])

    def execute(self, profile, seed, hostile, reserved, mutant, closed=False):
        if hostile:
            value = self.call("r9_hostile_probe", [7], 0)
            require(value == 8, "Hostile probe did not execute")
            for name in ("r9_instrument_calls", "r9_coverage_calls"):
                require(self.word(self.symbols[name]) > 0, "Hostile flags ineffective: " + name)
            self.returned = False
        self.uc.mem_write(CONTEXT, bytes([0xCC]) * 512)
        layout = None
        if self.cohort == "fiber":
            layout = list(struct.unpack("<6I", self.uc.mem_read(self.symbols["r9_fiber_layout"], 24)))
            size, prefix, state, alignment, empty, initialized = layout
            require(0 < prefix <= state and state + 4 <= size <= 508 and
                    alignment != 0 and CONTEXT % alignment == 0 and empty == 0 and initialized == 1,
                    "Complete Fiber storage/layout facts invalid")
            self.uc.mem_write(CONTEXT - 4, bytes([0xCC]) * 4)
            self.uc.mem_write(CONTEXT, bytes(size))
            if closed:
                self.call("fiber_internal_runtime_close_context_configuration", [], 0)
                require(self.returned and self.panic is None, "Actual configuration close failed")
                self.returned = False
        self.uc.mem_write(BEGIN, bytes([0xA5]) * (END - BEGIN))
        post = self.call("r9_call_init", [CONTEXT, BEGIN, END, self.symbols["r9_task_entry"] | 1, ARG], seed)
        if closed:
            if mutant == "consumer-configuration":
                require(self.panic is None and self.returned and
                        self.word(CONTEXT + state) == initialized and
                        self.word(CONTEXT) != 0 and
                        any(t["name"] == "fiber_port_context_init" for t in self.trace) and
                        not any(t["name"] == "fiber_internal_runtime_require_context_configuration_open" for t in self.trace),
                        "Removed consumer gate must observably construct after actual configuration close")
                return dict(seed=seed, classification="CONFIGURATION-BYPASSED", post_r9=post,
                            fiber_state=self.word(CONTEXT + state), trace=self.trace)
            require(self.panic == "k" and not self.returned and
                    self.uc.mem_read(CONTEXT, size) == bytes(size) and
                    self.uc.mem_read(BEGIN, END - BEGIN) == bytes([0xA5]) * (END - BEGIN) and
                    not any(t["name"] == "fiber_port_context_init" for t in self.trace),
                    "Closed real configuration must reject before constructor/storage effects")
            return dict(seed=seed, classification="CONFIGURATION-CLOSED", panic=self.panic,
                        storage_unchanged=True, stack_unchanged=True, trace=self.trace)
        if self.panic is not None:
            return dict(seed=seed, classification="PANIC", panic=self.panic, trace=self.trace)
        if layout:
            require(self.word(CONTEXT + state) == initialized and
                    self.uc.mem_read(CONTEXT - 4, 4) == bytes([0xCC]) * 4 and
                    self.uc.mem_read(CONTEXT + size, 512 - size) == bytes([0xCC]) * (512 - size),
                    "Fiber state transition or complete-object canary corrupted")
            names = [t["name"] for t in self.trace]
            expected_guard = int(mutant != "consumer-configuration")
            require(names.count(self.public_api) == 1 and names.count("ctxrt_v1_init") == 1 and
                    names.count("fiber_internal_runtime_require_context_configuration_open") == expected_guard and
                    names.index(self.public_api) < names.index("ctxrt_v1_init") < names.index("fiber_port_context_init") and
                    (not expected_guard or names.index(self.public_api) <
                     names.index("fiber_internal_runtime_require_context_configuration_open") < names.index("ctxrt_v1_init")),
                    "Actual Fiber/configuration/Context/port constructor chain missing or reordered")
        require(self.uc.reg_read(UC_ARM_REG_R9) == 0xA9A9A9A9, "Assembly seed wrapper violated outer AAPCS R9")
        frame_kind = profile["frame"]
        if frame_kind == "mpu0":
            return self.execute_mpu_frame(profile, seed, post, reserved, mutant)
        sw = 9 if frame_kind.startswith("classic") else 11 if frame_kind == "secure" else 10
        expected_sp = END - (sw + 8) * 4
        require(self.word(CONTEXT) == expected_sp,
                f"Independent numeric frame pointer mismatch: {self.word(CONTEXT):#x} != {expected_sp:#x}")
        expected = [0] * (sw + 8)
        if frame_kind == "classic0":
            expected[0], index = 0xFFFFFFFD, 6
        elif frame_kind == "classic":
            expected[8], index = 0xFFFFFFFD, 5
        elif frame_kind == "secure":
            expected[1], expected[2], index = BEGIN + 32, 0xFFFFFFBC, 8
        else:
            expected[0], expected[1], index = BEGIN + 32, 0xFFFFFFBC, 7
        expected[index] = seed
        expected[sw], expected[sw + 5] = ARG, self.symbols["fiber_internal_task_return"] | 1
        expected[sw + 6], expected[sw + 7] = self.symbols["r9_task_entry"] & ~1, 0x01000000
        actual = list(struct.unpack("<" + "I" * len(expected), self.uc.mem_read(expected_sp, len(expected) * 4)))
        for n, (wanted, found) in enumerate(zip(expected, actual)):
            if n != index:
                require(found == wanted, f"Independent frame word {n}: {found:#x} != {wanted:#x}")
        boot = [self.word(CONTEXT + 4 + i * 4) for i in range(7)]
        require(boot == [BEGIN, END, BEGIN + 32, END, END - BEGIN - 32,
                         self.symbols["r9_task_entry"] | 1, ARG], "Independent boot geometry mismatch")
        public = [r["r9"] for r in self.trace if r["name"] == self.public_api]
        require(any(r["name"] == "fiber_port_context_init" for r in self.trace), "Public init did not reach real constructor")
        require(any(r["name"] == "fiber_addr_plausible_ram" for r in self.trace), "Real RAM policy not called")
        require(any(r["name"] == "fiber_addr_plausible_code" for r in self.trace), "Real code policy not called")
        first = self.restore_slice(profile, expected_sp, actual[index], "SVC_Handler", mutant)
        saved = seed ^ 0x5A5A5A5A
        self.put(expected_sp + index * 4, saved)
        running = self.restore_slice(profile, expected_sp, saved, "PendSV_Handler", mutant)
        classification = classify(seed, actual[index], post, public, self.panic, reserved)
        if not first["matched"]:
            classification = "FIRST-RESTORE-R9"
        elif not running["matched"]:
            classification = "SWITCH-RESTORE-R9"
        return dict(seed=seed, frame_r9=actual[index], post_r9=post, first_restore=first,
                    switch_restore=running, classification=classification, trace=self.trace, fiber_layout=layout)

    def execute_mpu_frame(self, profile, seed, post, reserved, mutant):
        image = CONTEXT + 36
        require(self.word(CONTEXT) == image + 76, "Independent MPU one-past cursor geometry mismatch")
        actual = list(struct.unpack("<20I", self.uc.mem_read(image, 80)))
        expected = [0] * 20
        expected[5], expected[8] = seed, ARG
        expected[13] = self.symbols["fiber_port_unprivileged_task_return"] | 1
        expected[14:19] = [self.symbols["r9_task_entry"] & ~1, 0x01000000, END - 32, 3, 0xFFFFFFFD]
        for index, (wanted, found) in enumerate(zip(expected, actual)):
            if index != 5:
                require(wanted == found, "Independent protected MPU word mismatch: " + str(index))
        boot = [self.word(CONTEXT + 120 + i * 4) for i in range(17)]
        require(boot == [BEGIN, END, BEGIN + 32, END, END - BEGIN - 32,
                         self.symbols["r9_task_entry"] | 1, ARG, 0x434D304D, 0x10001,
                         208, 8, 0x1C04, 0xFFFFFFFD, 3, 8, 4, 20], "Independent MPU boot geometry/identity mismatch")
        require(self.word(BEGIN) == 0xDEADBEEF and self.uc.mem_read(END - 32, 32) == bytes([0xA5]) * 32,
                "MPU construction changed protected-frame placement or raw canary")
        public = [r["r9"] for r in self.trace if r["name"] == self.public_api]
        require(any(r["name"] == "fiber_port_context_init" for r in self.trace), "MPU public init did not reach real constructor")
        first = self.restore_slice(profile, image, actual[5], "fiber_port_restore_first_context_from_svc", mutant)
        saved = seed ^ 0x5A5A5A5A
        self.put(image + 20, saved)
        running = self.restore_slice(profile, image, saved, "PendSV_Handler", mutant)
        classification = classify(seed, actual[5], post, public, self.panic, reserved)
        if not first["matched"]:
            classification = "FIRST-RESTORE-R9"
        elif not running["matched"]:
            classification = "SWITCH-RESTORE-R9"
        return dict(seed=seed, frame_r9=actual[5], post_r9=post, first_restore=first,
                    switch_restore=running, classification=classification, trace=self.trace)


class Suite:
    def __init__(self, args):
        self.a = args
        self.repo, self.build = Path(args.repo).resolve(), Path(args.build).resolve()
        self.fixture = Path(__file__).resolve().parent
        self.bin = Path(args.arm_gcc).parent
        self.commands, self.runs, self.controls, self.unqualified = [], [], [], []
        self.warnings, self.assembly_probes = [], []

    def attempt(self, profile, mode, mutant=None, reserved=False, cohort="legacy"):
        try:
            self.build_case(profile, mode, mutant, reserved, cohort)
        except Exception as error:
            directory = self.build / (cohort + "-" + profile["name"] + "-" + ("reserved-r9" if reserved else "ordinary-aapcs") +
                                      "-" + mode + ("-" + mutant if mutant else ""))
            sites = []
            for assembly in directory.glob("*.s"):
                function, origin = None, None
                for number, line in enumerate(assembly.read_text().splitlines(), 1):
                    match = re.match(r"\s*\.type\s+([^,]+),\s*%function", line)
                    if match:
                        function = match[1]
                    match = re.match(r'@ (\d+) "([^"]*fiber_portmacro.h)" 1', line)
                    if match:
                        origin = dict(header=match[2], line=int(match[1]))
                    if line.startswith("@ 0 "):
                        origin = None
                    match = re.match(r"\s*ldr (r\d+|fp|sl), \[(r\d+|fp|sl)\]$", line)
                    if origin and match and any(value not in {"r"+str(i) for i in range(8)} for value in match.groups()):
                        sites.append(dict(assembly=str(assembly), assembly_line=number, function=function,
                                          instruction=line.strip(), **origin))
            self.unqualified.append(dict(profile=profile["name"], mode=mode, mutant=mutant,
                                         cohort=cohort, reserved_r9=reserved, error=str(error), traceback=traceback.format_exc(),
                                         scope="actual-header-assembly-only-register-constraint" if sites else "unclassified-qualification-failure",
                                         assembly_sites=sites))
            print("QUALIFICATION-FAIL " + profile["name"] + " " + mode + " " +
                  (mutant or ("reserved-r9" if reserved else "ordinary-aapcs")), flush=True)

    def command(self, args, allow_failure=False):
        args = list(map(str, args))
        require(not any("no-branch-count" in arg for arg in args), "Forbidden CPU masking flag")
        p = subprocess.run(args, cwd=self.repo, capture_output=True, text=True, timeout=120)
        row = dict(args=args, exit=p.returncode, stdout=p.stdout, stderr=p.stderr)
        path = self.build / f"command-{len(self.commands):05d}.json"
        path.write_text(json.dumps(row, indent=2) + "\n", encoding="ascii")
        self.commands.append(str(path))
        if not allow_failure:
            require(p.returncode == 0, "Command failed: " + str(path) + "\n" + p.stdout + p.stderr)
        warnings = re.findall(r"^(.+?):\d+:\d+: warning: (.+)$", p.stderr, re.M)
        for source, diagnostic in warnings:
            scope = warning_scope(source, diagnostic, 0 if "-mcpu=cortex-m0" in args else -1,
                                  self.repo/"fiber/port/ARM_CM0")
            require(scope is not None, "Unexpected compiler warning: " + str(path))
            self.warnings.append(dict(command=str(path), source=source, diagnostic=diagnostic, scope=scope))
        require(len(warnings) == len(re.findall(r"^.*?: warning: ", p.stderr, re.M)), "Unclassified warning: " + str(path))
        return row if allow_failure else p.stdout

    def thumb1_probe(self, profile):
        directory = self.build / "assembly-only-CM0-initial-MSP"
        directory.mkdir()
        port = self.repo / "fiber/port" / profile["directory"]
        for optimization in ("O2", "Os"):
            for reserved in (False, True):
                for register in (0, 8):
                    name = optimization + ("-reserved" if reserved else "-ordinary") + "-r" + str(register)
                    assembly = directory / (name + ".s")
                    flags = profile["flags"] + ["-"+optimization, "-std=gnu11", "-ffreestanding", "-fno-builtin",
                        "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Wundef",
                        "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_"+profile["architecture"]+"=1",
                        "-DR9_CORE=0", "-DR9_FPU=0", "-DR9_PROBE_REGISTER="+str(register),
                        "-I"+str(self.fixture), "-I"+str(port), "-I"+str(self.repo),
                        "-I"+self.a.cmsis_core, "-include", str(self.fixture/"main.h")]
                    if reserved:
                        flags += ["-ffixed-r9"]
                    self.command([self.a.arm_gcc, *flags, "-S", self.fixture/"m0_initial_msp_probe.c", "-o", assembly])
                    result = self.command([self.a.arm_gcc, *profile["flags"], "-c", assembly,
                                           "-o", directory/(name+".o")], allow_failure=True)
                    text = assembly.read_text()
                    high = bool(re.search(r"\bldr r8, \[r\d+\]", text))
                    failures = re.findall(r"^.*?: Error: (.+)$", result["stderr"], re.M)
                    if register == 0:
                        require(result["exit"] == 0 and not high, "Low-register actual-header control must assemble")
                    elif high:
                        require(result["exit"] != 0 and len(failures) == 1 and
                                re.fullmatch(r"lo register required -- `ldr r8,\[r\d+\]'", failures[0]),
                                "High-register finding must be the exact actual-header Thumb1 instruction")
                        require('fiber_portmacro.h"' in text and "ldr r8, [" in text, "Missing actual-header assembly provenance")
                    else:
                        require(result["exit"] == 0, "Unexpected assembly-probe failure")
                    self.assembly_probes.append(dict(name=name, register=register, reserved_r9=reserved,
                        assembly=str(assembly), sha256=sha(assembly), exit=result["exit"],
                        finding="actual-header-Thumb1-register-constraint" if high else None,
                        scope="assembly-only-initial-MSP-helper-not-public-constructor-execution"))
                    if register == 8 and not high and optimization == "O2":
                        preprocessed = directory / (name + ".i")
                        self.command([self.a.arm_gcc, *flags, "-E", self.fixture/"m0_initial_msp_probe.c", "-o", preprocessed])
                        original = preprocessed.read_text()
                        fixed = '\"ldr %0, [%1]\" : \"=l\"(value) : \"l\"(base)'
                        restored = '\"ldr %0, [%1]\" : \"=r\"(value) : \"r\"(base)'
                        require(original.count(fixed) == 1, "Exact repaired actual-header constraint anchor drift")
                        mutant_source = directory / (name + "-restored-constraints.i")
                        mutant_source.write_text(original.replace(fixed, restored), encoding="ascii")
                        mutant_assembly = directory / (name + "-restored-constraints.s")
                        codegen = profile["flags"] + ["-"+optimization, "-std=gnu11", "-ffreestanding", "-fno-builtin",
                                                       "-ffunction-sections", "-fdata-sections"]
                        if reserved:
                            codegen += ["-ffixed-r9"]
                        self.command([self.a.arm_gcc, *codegen, "-S", mutant_source, "-o", mutant_assembly])
                        result = self.command([self.a.arm_gcc, *profile["flags"], "-c", mutant_assembly,
                                               "-o", directory/(name+"-restored-constraints.o")], allow_failure=True)
                        failures = re.findall(r"^.*?: Error: (.+)$", result["stderr"], re.M)
                        text = mutant_assembly.read_text()
                        require(result["exit"] != 0 and len(failures) == 1 and
                                re.fullmatch(r"lo register required -- `ldr r8,\[r\d+\]'", failures[0]) and
                                'fiber_portmacro.h\"' in text and "ldr r8, [" in text,
                                "Restored actual-header constraints did not reject the exact Thumb1 instruction")
                        self.assembly_probes.append(dict(name=name+"-restored-constraints", register=8,
                            reserved_r9=reserved, assembly=str(mutant_assembly), sha256=sha(mutant_assembly),
                            source=str(mutant_source), source_sha256=sha(mutant_source), exit=result["exit"],
                            finding=None, control="actual-preprocessed-header-constraint-restoration",
                            expected="THUMB1-LOW-REGISTER-REQUIRED",
                            scope="compiled-negative-control-not-a-production-failure"))
        require(not any(p["finding"] for p in self.assembly_probes),
                "Actual CM0 initial-MSP helper still permits an invalid Thumb1 register operand")

    def build_case(self, profile, mode, mutant=None, reserved=False, cohort="legacy"):
        contract = "reserved-r9" if reserved else "ordinary-aapcs"
        directory = self.build / (cohort + "-" + profile["name"] + "-" + contract + "-" + mode + ("-" + mutant if mutant else ""))
        directory.mkdir()
        port = self.repo / "fiber/port" / profile["directory"]
        options = ["-" + mode.split("-")[0]] + (["-flto"] if "lto" in mode else [])
        hostile = "hostile" in mode
        hostile_flags = list(HOSTILE) if hostile else []
        base = profile["flags"] + ["-std=gnu11", "-ffreestanding", "-fno-builtin", "-fno-common",
                "-ffunction-sections", "-fdata-sections", "-Wall", "-Wextra", "-Werror", "-Wundef",
                "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_" + profile["architecture"] + "=1",
                "-I" + str(self.fixture), "-I" + str(port), "-I" + str(self.repo / "fiber"),
                "-I" + str(self.repo), "-I" + str(self.repo / "context"), "-I" + self.a.cmsis_core,
                "-DR9_CORE=" + str(profile["core"]), "-DR9_FPU=" + str(profile["fp"]),
                "-DR9_MPU=" + str(int(profile["frame"] == "mpu0"))]
        base += ["-DR9_RESERVED=" + str(int(reserved)), "-DR9_FIBER=" + str(int(cohort == "fiber")),
                 "-I" + str(self.repo / "fiber/lifecycle")]
        if profile["core"] == 0:
            # GCC's optionless pragma warning cannot be selected by -Wno-error=.
            # command() records only exact, source-scoped known diagnostics.
            base.remove("-Werror")
            base += ["-Werror=implicit-function-declaration"]
        if reserved:
            base += ["-ffixed-r9"]
        runtime = runtime_reader(self.repo)
        roles = COMMON_ROLES if cohort == "legacy" else tuple(r for r in COMMON_ROLES if r != "legacy_compat")
        common = list(runtime.get_runtime_source_paths(self.repo, roles))
        consumer = self.repo / "fiber/lifecycle/fiber_v1.c"
        if cohort == "fiber":
            common.append(consumer)
        engines = runtime.get_runtime_source_paths(self.repo, ("engine",))
        require(len(engines) == 1, "Constructor control requires one actual engine owner")
        engine = engines[0]
        expected_sources = source_group(profile)
        require(sorted(p.name for p in port.glob("*.c")) == expected_sources, "Selected source inventory drift: " + str(port))
        sources = common + [port / name for name in expected_sources]
        objects = []
        source_objects = []
        replacement_count = 0
        for source in sources:
            original = source
            text = source.read_text()
            if mutant == "caller-scratch" and source == engine:
                calls = [call for call in ("fiber_port_context_init(ctx, stack_begin, stack_end, entry, arg);",
                                          "fiber_port_context_init(context, stack_begin, stack_end, entry, arg);")
                         if call in text]
                require(len(calls) == 1 and text.count(calls[0]) == 1, "Caller control anchor drift")
                call = calls[0]
                text = text.replace(call, 'register uint32_t scratch __asm("r9") = 0xDEADC0DEu;\n'
                    '\t__asm volatile("" : "+r"(scratch) :: "memory");\n\t' + call +
                    '\n\t__asm volatile("" : "+r"(scratch) :: "memory");')
                replacement_count += 1
            consumer_call = "ctxrt_v1_init(&fiber->private_context, stack_begin, stack_end, entry, arg);"
            if mutant == "consumer-scratch" and source == consumer:
                require(text.count(consumer_call) == 1, "Consumer scratch control anchor drift")
                text = text.replace(consumer_call,
                    'register uint32_t scratch __asm("r9") = 0xDEADC0DEu;\n'
                    '\t__asm volatile("" : "+r"(scratch) :: "memory");\n\t' + consumer_call +
                    '\n\t__asm volatile("" : "+r"(scratch) :: "memory");')
                replacement_count += 1
            if mutant == "consumer-configuration" and source == consumer:
                gate = "fiber_internal_runtime_require_context_configuration_open(&fiber->private_context);"
                require(text.count(gate) == 1, "Consumer configuration control anchor drift")
                text = text.replace(gate, "/* Compiled control: omitted real consumer gate. */")
                replacement_count += 1
            if mutant == "wrong-frame" and source not in common:
                pattern = (r"(const uint32_t initial_r9\s*=\s*)(fiber_port_read_r9\(\))" if profile["frame"] == "mpu0" else
                           r"(frame\[fiber_portFRAME_R9\]\s*=\s*|\*\(--sp\)\s*=\s*)((?:fiber_port|fiber_arm_cm7_r0p1)_read_r9\(\))")
                text, count = re.subn(pattern, lambda m: m[1] + "0xDEADC0DEu", text)
                replacement_count += count
            handler = "PendSV_Handler" if mutant == "wrong-switch" else "SVC_Handler"
            if profile["frame"] == "mpu0" and mutant == "wrong-restore":
                handler = "fiber_port_restore_first_context_from_svc"
            declaration = "void " + handler + "("
            if mutant in ("wrong-restore", "wrong-switch") and declaration in text:
                head, body = text.split(declaration, 1)
                pattern = r'("(?:ldmia\s+r[02]!,\s+\{(?:r[12]-r11|r4-r11, r14|r4-r11)\}|mov\s+r9,\s+r5)\s+\\n")'
                body, count = re.subn(pattern, lambda m: m[0] + '\n\t\t\t"mov r9, r8 \\n"', body, count=1)
                replacement_count += count
                text = head + declaration + body
            if text != original.read_text():
                source = directory / original.name
                source.write_text(text, encoding="ascii", newline="\n")
            obj = directory / (original.stem + ".o")
            selected = [] if original in common else ["-include", str(self.fixture / "main.h")]
            self.command([self.a.arm_gcc, *base, *options, *hostile_flags, *selected,
                          *(["-save-temps=obj"] if profile["core"] == 0 else []),
                          "-c", source, "-o", obj])
            objects.append(obj)
            source_objects.append(dict(original=str(original), original_sha256=sha(original),
                                       compiled=str(source), compiled_sha256=sha(source),
                                       object=str(obj), object_sha256=sha(obj), command=self.commands[-1]))
        if mutant:
            require(replacement_count == 1, "Compiled control must change exactly one source site")
        fixtures = ("boundary.c", "hostile_probe.c", "bootstrap.S")
        if cohort == "fiber":
            fixtures += ("consumer_layout.c",)
        for name in fixtures:
            obj = directory / (Path(name).stem + ".o")
            flags = base + [options[0]]
            if name == "hostile_probe.c":
                flags += options[1:] + hostile_flags
            self.command([self.a.arm_gcc, *flags, "-c", self.fixture / name, "-o", obj])
            objects.append(obj)
            source_objects.append(dict(original=str(self.fixture / name), original_sha256=sha(self.fixture / name),
                                       compiled=str(self.fixture / name), compiled_sha256=sha(self.fixture / name),
                                       object=str(obj), object_sha256=sha(obj), command=self.commands[-1]))
        elf = directory / "constructor.elf"
        self.command([self.a.arm_gcc, *profile["flags"], *options, *hostile_flags,
                      *(["-ffixed-r9"] if reserved else []), "-nostdlib",
                      "-ffunction-sections", "-fdata-sections",
                      "-save-temps=obj",
                      "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
                      "-Wl,--undefined=r9_stop", "-Wl,--undefined=r9_hostile_probe",
                      "-Wl,--undefined=r9_task_entry", "-Wl,--undefined=r9_fault_probe",
                      "-Wl,--undefined=SVC_Handler", "-Wl,--undefined=PendSV_Handler",
                      *(["-Wl,--undefined=r9_fiber_layout",
                         "-Wl,--undefined=fiber_internal_runtime_close_context_configuration",
                         "-Wl,--undefined=fiber_internal_runtime_require_context_configuration_open"]
                        if cohort == "fiber" else []),
                      *(["-Wl,--undefined=fiber_addr_plausible_ram", "-Wl,--undefined=fiber_addr_plausible_code"]
                        if profile["frame"] == "mpu0" else []),
                      "-T", self.fixture / ("cm0_mpu.ld" if profile["frame"] == "mpu0" else "image.ld"),
                      "-Wl,-Map=" + str(directory / "image.map"),
                      *objects, "-o", elf])
        for program, flags, output in (("arm-none-eabi-objdump.exe", ["-dr", "-Mreg-names-std"], "image.dis"),
                                       ("arm-none-eabi-readelf.exe", ["-A"], "attributes.txt"),
                                       ("arm-none-eabi-gcc-nm.exe", ["-a"], "symbols.txt")):
            evidence = self.command([self.bin / program, *flags, elf])
            if output == "attributes.txt":
                architecture = {0: "v6S-M", 3: "v7", 4: "v7E-M", 7: "v7E-M", 23: "v8-M.baseline",
                                33: "v8-M.mainline", 55: "v8.1-M.mainline"}[profile["core"]]
                require(re.search(r"Tag_CPU_arch: " + re.escape(architecture) + r"$", evidence, re.M),
                        "ELF architecture differs from role-specific target")
            (directory / output).write_text(evidence, encoding="ascii")
        cases = [Machine(elf, profile, cohort).execute(profile, seed, hostile, reserved, mutant) for seed in SEEDS]
        closed = [Machine(elf, profile, cohort).execute(profile, seed, hostile, reserved, mutant, closed=True)
                  for seed in SEEDS] if cohort == "fiber" else []
        fault = Machine(elf, profile, cohort).fault_control()
        row = dict(profile=profile, mode=mode, contract=contract, reserved_r9=reserved,
                   cohort=cohort, public_api="fiber_v1_init" if cohort == "fiber" else "fiber_init",
                   mutant=mutant, elf=str(elf), elf_sha256=sha(elf), cases=cases,
                   source_objects=source_objects, configuration_closed=closed, fault_control=fault)
        (directory / "execution.json").write_text(json.dumps(row, indent=2) + "\n", encoding="ascii")
        if mutant:
            for case in cases:
                expected = {"wrong-restore": "FIRST-RESTORE-R9", "wrong-switch": "SWITCH-RESTORE-R9"}.get(
                    mutant, "STATIC-BASE-R9" if reserved else "BORROWED-R9")
                permitted = {"PASS", "BORROWED-R9"} if mutant == "consumer-configuration" else {expected}
                require(case["classification"] in permitted and case["post_r9"] == case["seed"],
                        "Compiled control did not produce its exact classification/preserve caller: " + str(directory))
                if mutant == "wrong-frame":
                    require(case["frame_r9"] == FRAME_BAD, "Wrong-frame control did not execute its changed assignment")
                elif mutant == "caller-scratch":
                    entries = [t["r9"] for t in case["trace"] if t["name"] == "fiber_port_context_init"]
                    require(entries == [FRAME_BAD], "Caller-scratch control did not borrow R9 at its ABI boundary")
                elif mutant == "consumer-scratch":
                    entries = [t["r9"] for t in case["trace"] if t["name"] == "ctxrt_v1_init"]
                    require(entries == [FRAME_BAD], "Consumer scratch must borrow at the actual Context boundary")
                elif mutant == "consumer-configuration":
                    require(case["classification"] in ("PASS", "BORROWED-R9"), "Configuration control changed constructor ABI")
            self.controls.append(row)
            print("CONTROL qualified " + directory.name, flush=True)
        else:
            self.runs.append(row)
            good = all(c["classification"] in ("PASS", "BORROWED-R9") for c in cases)
            borrowed = any(c["classification"] == "BORROWED-R9" for c in cases)
            print(("OBSERVED-BORROW " if good and borrowed else "PASS " if good else "ABI-FAIL ") + directory.name, flush=True)


def snapshot(repo, fixture, selected, cmsis):
    files = set(fixture.rglob("*"))
    files.add(repo / "tools/test_constructor_r9.ps1")
    files.update((repo / "fiber").glob("*.h"))
    files.update((repo / "fiber/lifecycle").glob("*.h"))
    files.add(repo / "fiber/lifecycle/fiber_v1.c")
    files.add(repo / "fiber/lifecycle/README.md")
    files.update(runtime_reader(repo).get_runtime_source_inputs(repo, VALIDATION_ROLES))
    files.update((repo / "context").glob("*.h"))
    files.update((repo / "fiber/port").glob("*.h"))
    files.update(Path(cmsis).rglob("*.h"))
    files.update((repo / "mcu_core.h", repo / "basic_types.h"))
    for profile in selected:
        files.update((repo / "fiber/port" / profile["directory"]).glob("*.h"))
        files.update((repo / "fiber/port" / profile["directory"]).glob("*.c"))
        if profile["port"] == "CM33S":
            files.update((repo / "fiber/port/ARM_CM33/secure").glob("*.h"))
    return {str(p.resolve()): sha(p) for p in sorted(files) if p.is_file() and "__pycache__" not in p.parts}


def run_immutable(args, selected):
    repo, cmsis = Path(args.repo).resolve(), Path(args.cmsis_core).resolve()
    root = Path(args.build).resolve() / "immutable-inputs"
    root.mkdir()
    before = snapshot(repo, Path(__file__).resolve().parent, selected, cmsis)
    material = []
    for source_name, expected in before.items():
        source = Path(source_name)
        if source.is_relative_to(repo):
            target = root / "repo" / source.relative_to(repo)
        else:
            require(source.is_relative_to(cmsis), "Unmapped immutable input: " + source_name)
            target = root / "cmsis" / source.relative_to(cmsis)
        data = source.read_bytes()
        require(hashlib.sha256(data).hexdigest().upper() == expected, "Input changed while snapshotting: " + source_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        require(sha(target) == expected, "Immutable byte-copy mismatch")
        material.append(dict(source=source_name, copy=str(target), sha256=expected))
    require(before == snapshot(repo, Path(__file__).resolve().parent, selected, cmsis), "Inputs changed during immutable snapshot construction")
    (root / "manifest.json").write_text(json.dumps(material, indent=2) + "\n", encoding="ascii")
    child = [sys.executable, "-B", str(root / "repo/tools/fixtures/constructor_r9/run.py"),
             "--repo", str(root / "repo"), "--cmsis-core", str(root / "cmsis"),
             "--arm-gcc", args.arm_gcc, "--build", args.build]
    if args.profiles:
        child += ["--profiles", args.profiles]
    if args.modes:
        child += ["--modes", args.modes]
    if args.constructor_cohorts:
        child += ["--constructor-cohorts", args.constructor_cohorts]
    (root / "child-command.json").write_text(json.dumps(child, indent=2) + "\n", encoding="ascii")
    print("Constructor R9 immutable source/CMSIS snapshot: " + str(root), flush=True)
    return subprocess.run(child, cwd=root / "repo").returncode


def main():
    parser = argparse.ArgumentParser()
    for name in ("repo", "arm-gcc", "cmsis-core", "build"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--profiles")
    parser.add_argument("--modes")
    parser.add_argument("--constructor-cohorts")
    parser.add_argument("--immutable-inputs", action="store_true")
    args = parser.parse_args()
    suite = Suite(args)
    selected = profiles(include_cm0_mpu=bool(args.profiles and "CM0MPU" in args.profiles.split(",")))
    if args.profiles:
        names = args.profiles.split(",")
        require(set(names) <= {p["port"] for p in selected}, "Unknown development profile")
        selected = [p for p in selected if p["port"] in names]
    modes = args.modes.split(",") if args.modes else list(MODES)
    require(bool(modes) and len(set(modes)) == len(modes) and set(modes) <= set(MODES), "Unknown/duplicate mode")
    cohorts = args.constructor_cohorts.split(",") if args.constructor_cohorts else list(COHORTS)
    require(bool(cohorts) and len(set(cohorts)) == len(cohorts) and set(cohorts) <= set(COHORTS),
            "Unknown/duplicate constructor cohort")
    if args.immutable_inputs:
        raise SystemExit(run_immutable(args, selected))
    before = snapshot(suite.repo, suite.fixture, selected, args.cmsis_core)
    (suite.build / "inputs.before.json").write_text(json.dumps(before, indent=2) + "\n")
    report = dict(Verdict="FAIL", CompleteSuite=not (args.profiles or args.modes) and set(cohorts) == set(COHORTS),
                  ConstructorCohorts=cohorts, DefaultConstructorCohorts=list(COHORTS),
                  ArtifactManifest="artifacts.sha256.json",
                  Python=sys.executable, PythonPath=os.environ.get("PYTHONPATH", ""),
                  PythonVersion=sys.version, Dependencies={p: importlib.metadata.version(p) for p in ("unicorn", "pyelftools")},
                  Contracts={"ordinary-aapcs": "No fixed-R9 flag; caller return preservation, valid frame and actual first/running R9 restore slices required; initial frame value has no static-base meaning.",
                             "reserved-r9": "Explicit -ffixed-r9 on all C compile and final LTO link commands; strict initial/first-restored static-base seed plus return/switch preservation."},
                  SupersededOracle="The preserved fiber-constructor-r9-4778c794c8e3492bb5d0c112c8dc071c ordinary-frame-only FAIL receipts used an overstrong oracle, not a reserved-ABI bug. Current classification keeps ordinary borrowing separate.",
                  PriorExtent={"Root": "fiber-constructor-r9-fec4e1435a99482aa62c3c68ec0d2bcb",
                               "Unqualified": 61, "LiteralPool": 48, "Thumb1Operands": 4, "WarningPolicy": 9,
                               "Policy": "Preserved failures. Function sections qualify the sectioned LTO configuration only; the 48 literal-pool failures are not dismissed as harness-only. Unsectioned production assembly requires separate qualification. Scoped warning diagnostics and operand constraints are tracked separately from ABI failures."},
                  Limits="Actual compiled constructor and bounded GPR restore instruction effects only; M23/M33/M55 use supported Unicorn instruction subsets, not actual CPU/security/exception/FP execution. Running restore uses an independently seeded saved-image R9, not a full save/exception switch. Reserved-register probe is not arbitrary PIC/TLS ABI qualification. No hardware/TF-M/Secure-runtime claim.")
    error = None
    try:
        report["PreflightChecks"] = preflight()
        report["CompilerVersion"] = suite.command([args.arm_gcc, "--version"])
        tool_paths = {Path(args.arm_gcc).resolve(), interpreter_image()}
        for program in ("cc1", "lto1", "as", "ld"):
            path = Path(suite.command([args.arm_gcc, "-print-prog-name=" + program]).strip()).resolve()
            require(path.is_file(), "Compiler subprocess unavailable: " + str(path))
            tool_paths.add(path)
        plugins = {Path(suite.command([args.arm_gcc, "-print-file-name=" + name]).strip()).resolve()
                   for name in ("liblto_plugin.dll", "liblto_plugin-0.dll", "liblto_plugin.so")}
        plugins = {p for p in plugins if p.is_file()}
        require(len(plugins) == 1, "Native LTO plugin missing/ambiguous")
        tool_paths.update(plugins)
        for name in ("arm-none-eabi-objdump.exe", "arm-none-eabi-readelf.exe", "arm-none-eabi-gcc-nm.exe"):
            tool_paths.add((suite.bin / name).resolve())
        report["ToolInputsBefore"] = {str(p): sha(p) for p in sorted(tool_paths)}
        cm0 = next((p for p in selected if p["port"] == "CM0"), None)
        if cm0 is not None:
            suite.thumb1_probe(cm0)
        for profile in selected:
            for cohort in cohorts:
                for mode in modes:
                    for reserved in (False, True):
                        suite.attempt(profile, mode, reserved=reserved, cohort=cohort)
                # Controls stay O2: an unrelated production LTO failure must
                # never serve as the expected failure of a different control.
                suite.attempt(profile, "O2", "wrong-frame", cohort=cohort)
                suite.attempt(profile, "O2", "caller-scratch", cohort=cohort)
                suite.attempt(profile, "O2", "wrong-frame", reserved=True, cohort=cohort)
                suite.attempt(profile, "O2", "wrong-restore", reserved=True, cohort=cohort)
                suite.attempt(profile, "O2", "wrong-switch", reserved=True, cohort=cohort)
                if cohort == "fiber":
                    suite.attempt(profile, "O2", "consumer-scratch", cohort=cohort)
                    suite.attempt(profile, "O2", "consumer-configuration", cohort=cohort)
        failures = [r for r in suite.runs if any(c["classification"] not in ("PASS", "BORROWED-R9") for c in r["cases"])]
        report["AffectedProfiles"] = sorted({r["profile"]["port"] for r in failures})
        report["ProductionFailingConfigurations"] = len(failures)
        report["OrdinaryBorrowObserved"] = sorted({r["profile"]["port"] for r in suite.runs
            if any(c["classification"] == "BORROWED-R9" for c in r["cases"])})
        report["ReservedAbiFailures"] = sorted({r["profile"]["port"] for r in failures if r["reserved_r9"]})
        report["OrdinaryAapcsFailures"] = sorted({r["profile"]["port"] for r in failures if not r["reserved_r9"]})
        require(not failures, "Public constructor ABI R9 contract failed: " + ", ".join(report["AffectedProfiles"]))
        require(not suite.unqualified, f"{len(suite.unqualified)} constructor R9 configurations/controls unqualified; inspect Unqualified in results.json")
        report["Verdict"] = "PASS"
    except Exception as exc:
        error = exc
        report["Error"] = str(exc)
        report["Traceback"] = traceback.format_exc()
    finally:
        after = snapshot(suite.repo, suite.fixture, selected, args.cmsis_core)
        report["InputDrift"] = [p for p in set(before) | set(after) if before.get(p) != after.get(p)]
        if report["InputDrift"]:
            report["Verdict"] = "FAIL"
            error = RuntimeError("Constructor R9 inputs changed during test")
        report["Runs"], report["Controls"] = suite.runs, suite.controls
        report["Unqualified"] = suite.unqualified
        report["KnownNonR9Diagnostics"] = suite.warnings
        report["AssemblyOnlyProbes"] = suite.assembly_probes
        report["ProductionFindings"] = [{
            "Id": "CM0-INITIAL-MSP-THUMB1-CONSTRAINT",
            "Source": str(suite.repo/"fiber/port/ARM_CM0/fiber_portmacro.h"),
            "SourceSha256": sha(suite.repo/"fiber/port/ARM_CM0/fiber_portmacro.h"),
            "Scope": "Actual header helper assembly; not an executed constructor R9 ABI mismatch.",
            "Cause": "The ldr template uses general-register output/base constraints although Thumb1 requires low registers.",
            "Probes": [p["name"] for p in suite.assembly_probes if p["finding"]],
        }] if any(p["finding"] for p in suite.assembly_probes) else []
        report["ExecutionCalls"] = 4 * (len(suite.runs) + len(suite.controls))
        report["ConfigurationClosedCalls"] = sum(len(r["configuration_closed"]) for r in suite.runs + suite.controls)
        report["RestoreSlices"] = sum(2 for r in suite.runs + suite.controls for c in r["cases"] if "first_restore" in c)
        report["Commands"] = suite.commands
        report["InputCount"] = len(before)
        report["ToolInputsAfter"] = {p: sha(p) for p in report.get("ToolInputsBefore", {})}
        report["ToolDrift"] = [p for p, value in report.get("ToolInputsBefore", {}).items()
                               if report["ToolInputsAfter"].get(p) != value]
        if report["ToolDrift"]:
            report["Verdict"] = "FAIL"
            error = RuntimeError("Constructor R9 tool inputs changed during test")
        report["ConfirmedAbiFailuresSoFar"] = sorted({r["profile"]["port"] for r in suite.runs
            if any(c["classification"] not in ("PASS", "BORROWED-R9") for c in r["cases"])})
        (suite.build / "inputs.after.json").write_text(json.dumps(after, indent=2) + "\n")
        (suite.build / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        artifacts = {str(p.relative_to(suite.build)): sha(p) for p in sorted(suite.build.rglob("*"))
                     if p.is_file() and p.name != "artifacts.sha256.json"}
        (suite.build / "artifacts.sha256.json").write_text(json.dumps(artifacts, indent=2) + "\n")
    if error:
        raise SystemExit(str(error))
    print("PASS constructor R9 " + str(suite.build), flush=True)


if __name__ == "__main__":
    main()
