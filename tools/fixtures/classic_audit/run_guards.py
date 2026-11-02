"""Execute compiled guard paths, not Cortex-M exception/MPU hardware behavior.

Required packages: unicorn==2.1.4, pyelftools==0.33. Missing dependencies fail;
the PowerShell entry point never skips these maintained tests.
"""
import json
import struct
import sys
from pathlib import Path

if not __debug__:
    raise SystemExit("Disable PYTHONOPTIMIZE and do not use -O/-OO for classic audit regressions")

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_HOOK_MEM_INVALID
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R9, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP,
    UC_ARM_REG_MSP, UC_ARM_REG_PSP, UC_ARM_REG_CONTROL,
    UC_ARM_REG_PRIMASK, UC_ARM_REG_BASEPRI, UC_ARM_REG_FAULTMASK,
    UC_CPU_ARM_CORTEX_M0, UC_CPU_ARM_CORTEX_M3,
    UC_CPU_ARM_CORTEX_M4, UC_CPU_ARM_CORTEX_M7,
)


class Machine:
    stop = 0x0803FFF0
    call_count = 0

    def __init__(self, run):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        model = {0: UC_CPU_ARM_CORTEX_M0, 1: UC_CPU_ARM_CORTEX_M0,
                 3: UC_CPU_ARM_CORTEX_M3, 4: UC_CPU_ARM_CORTEX_M4,
                 7: UC_CPU_ARM_CORTEX_M7}[run["Core"]]
        self.uc.ctl_set_cpu_model(model)
        for base, size in [(0, 0x40000), (0x08000000, 0x40000),
                           (0x20000000, 0x50000), (0xE000E000, 0x2000)]:
            self.uc.mem_map(base, size)
        self.symbols = {}
        with open(run["Elf"], "rb") as stream:
            elf = ELFFile(stream)
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]:
                    self.uc.mem_write(segment["p_vaddr"], segment.data())
            for symbol in elf.get_section_by_name(".symtab").iter_symbols():
                self.symbols[symbol.name] = symbol["st_value"]
        self.panic = None
        self.returned = False
        self.invalid_accesses = []
        self.unmodeled_mmio = []
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._mmio,
                         begin=0xE000E000, end=0xE000FFFF)
        self.put(0, 0x20040000)
        self.put(0xE000ED08, self.symbols.get("audit_vector_table", 0x08000000))

    def _code(self, uc, address, size, data):
        if address == (self.symbols["fiber_panic"] & ~1):
            self.panic = chr(uc.reg_read(UC_ARM_REG_R0) & 255)
            uc.emu_stop()
        elif address == self.stop:
            self.returned = True
            uc.emu_stop()

    def _invalid(self, uc, kind, address, size, value, data):
        self.invalid_accesses.append((kind, address, size))
        return False

    def _mmio(self, uc, kind, address, size, value, data):
        # No NVIC priority/MPU/alias simulation is used to make a guard pass.
        if not (address == 0xE000ED08 and size == 4):
            self.unmodeled_mmio.append((kind, address, size))
            uc.emu_stop()

    def address(self, name):
        return self.symbols[name]

    def put(self, address, value):
        if isinstance(address, str):
            address = self.address(address)
        self.uc.mem_write(address, struct.pack("<I", value))

    def get(self, address):
        if isinstance(address, str):
            address = self.address(address)
        return struct.unpack("<I", self.uc.mem_read(address, 4))[0]

    def call(self, name, *args, panic=None, r9=0xA9A9A9A9):
        Machine.call_count += 1
        self.panic, self.returned = None, False
        self.uc.reg_write(UC_ARM_REG_CONTROL, 0)
        self.uc.reg_write(UC_ARM_REG_PRIMASK, 0)
        self.uc.reg_write(UC_ARM_REG_BASEPRI, 0)
        self.uc.reg_write(UC_ARM_REG_FAULTMASK, 0)
        self.uc.reg_write(UC_ARM_REG_MSP, 0x20040000)
        self.uc.reg_write(UC_ARM_REG_SP, 0x20040000)
        self.uc.reg_write(UC_ARM_REG_R9, r9)
        for register, value in zip(
                [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3], args):
            self.uc.reg_write(register, value)
        self.uc.reg_write(UC_ARM_REG_LR, self.stop | 1)
        try:
            self.uc.emu_start(self.address(name) | 1, self.stop + 2, count=2000000)
        except UcError as exc:
            pc = self.uc.reg_read(UC_ARM_REG_PC)
            raise AssertionError(f"{name}: emulation failed at {pc:#x}: {exc}") from exc
        lr = self.uc.reg_read(UC_ARM_REG_LR)
        assert not self.invalid_accesses, f"{name}: invalid access {self.invalid_accesses}"
        assert not self.unmodeled_mmio, f"{name}: unsupported MMIO {self.unmodeled_mmio}"
        assert self.panic == panic, f"{name}: panic {self.panic!r}, expected {panic!r}, LR={lr:#x}"
        assert panic is not None or self.returned, f"{name}: did not return"
        return self.uc.reg_read(UC_ARM_REG_R0)

    def watch(self, begin, end):
        accesses = []

        def access(uc, kind, address, size, value, data):
            if address < end and address + size > begin:
                accesses.append((kind, address, size))

        hook = self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, access)
        return hook, accesses


def classic(run):
    m = Machine(run)
    assert m.call("audit_fallback_result") == 0x2003F000, "strong override lost"
    assert m.call("fiber_fallback_initial_msp") == 0x2003F000
    # The production boot wrapper actually reads address zero twice at O2/Os.
    if run["Vtor"] == 0:
        hook, accesses = m.watch(0, 4)
        m.call("audit_prepare_msp")
        m.uc.hook_del(hook)
        assert len(accesses) == 2, f"expected two address-zero reads: {accesses}"
        m.call("audit_prepare_msp", panic="M")
    m.call("audit_init")
    context = m.address("audit_context")
    m.uc.reg_write(UC_ARM_REG_PSP, 0x200101E0)
    m.call("audit_validate")
    m.call("audit_boot_check", context)
    # Constructor negative: normalized usable base is legal, raw canary is not.
    n = Machine(run)
    n.put("audit_raw_begin", 0x2000FFF0)
    hook, accesses = n.watch(0x2000FFF0, 0x20010000)
    n.call("audit_init", panic="P")
    assert not accesses, f"constructor accessed rejected raw prefix: {accesses}"
    n.uc.hook_del(hook)
    # Switch negative: the formerly approved allocation is revoked only below
    # usable stack_base. The canary must not be read on the rejected map.
    m.put("audit_allowed_begin", 0x20010010)
    hook, accesses = m.watch(0x20010000, 0x20010010)
    m.call("audit_validate", panic="P")
    m.call("audit_boot_check", context, panic="P")
    assert not accesses, f"switch/start check read rejected canary: {accesses}"
    m.uc.hook_del(hook)
    # Re-approve the map, then prove the mandatory value check still executes.
    m.put("audit_allowed_begin", 0x20010000)
    m.put(0x20010000, 0)
    m.call("audit_validate", panic="c")


def mpu(run):
    # Independent real call frames with unrelated r9 values, no -ffixed-r9.
    for seed in [0x11111111, 0x99999999, 0xFEDCBA98]:
        m = Machine(run)
        m.call("audit_init", r9=seed)
        saved_r9 = m.get(m.address("audit_context") + 36 + 20)
        assert saved_r9 != (seed ^ 0xFFFFFFFF), "r9 contrast fixture became ineffective"
        m.call("audit_validate", r9=seed ^ 0xFFFFFFFF)
        # Other seeded-register checks remain strict.
        m.put(m.address("audit_context") + 36, 1)
        m.call("audit_validate", panic="x")
    m = Machine(run)
    m.call("audit_vectors")
    if run["Vtor"]:
        table = bytes(m.uc.mem_read(m.address("audit_vector_table"), 192))
        # Both of the accepted code maps are read-only to the user.
        unpriv = m.address("__fiber_mpu_unprivileged_code_start__") + 0x8000
        m.uc.mem_write(unpriv, table)
        m.put(0xE000ED08, unpriv)
        m.call("audit_vectors")
        for base in [0x20010000, 0x20000800, 0x20001000,
                     0x0800FF80, 0x30000000, 0xFFFFFF80]:
            if base < 0x20020000:
                m.uc.mem_write(base, table)
            m.put(0xE000ED08, base)
            hook, accesses = m.watch(base, min(base + 192, 0x100000000))
            m.call("audit_vectors", panic="V")
            assert not accesses, f"rejected vector placement was read: {base:#x} {accesses}"
            m.uc.hook_del(hook)
        # A 128-byte-aligned table can fit, but corrupt Thumb ownership cannot.
        m.put(0xE000ED08, m.address("audit_vector_table"))
        m.put(m.address("audit_vector_table") + 44, 0)
        m.call("audit_vectors", panic="y")
        m.put(0xE000ED08, m.address("audit_vector_table") + 4)
        m.call("audit_vectors", panic="V")


def main():
    manifest = Path(sys.argv[1])
    runs = json.loads(manifest.read_text(encoding="utf-8-sig"))
    results = []
    for run in runs:
        before = Machine.call_count
        try:
            if run["Mpu"]:
                mpu(run)
            else:
                classic(run)
        except AssertionError as exc:
            raise AssertionError(f"{run['Name']}: {exc}") from exc
        results.append({"name": run["Name"], "checks": Machine.call_count - before,
                        "status": "PASS"})
    summary = {"status": "PASS", "elfs": len(runs),
               "checks": sum(item["checks"] for item in results),
               "invalid_memory_accesses": 0, "unsupported_mmio_accesses": 0,
               "boundary": "Unicorn C-path execution; no hardware MPU, exceptions, or board qualification",
               "results": results}
    (manifest.parent / "results.json").write_text(json.dumps(summary, indent=2), encoding="ascii")
    print(f"PASS {summary['elfs']} ELFs, {summary['checks']} focused checks")


if __name__ == "__main__":
    main()
