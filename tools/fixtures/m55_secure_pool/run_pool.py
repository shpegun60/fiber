"""Run the actual M55-target pool ELF on Unicorn's scalar Cortex-M33 model.

No pool algorithm, CPU-register stub, TrustZone gateway, or exception model is
substituted. This qualifies compiled C paths, not M55 hardware behavior.
"""
import json
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import (
    Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
    UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID,
    UC_MEM_READ, UC_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
    UC_ERR_EXCEPTION, UC_ERR_INSN_INVALID,
)
from unicorn.arm_const import (
    UC_CPU_ARM_CORTEX_M33, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
    UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10,
    UC_ARM_REG_R11, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP,
    UC_ARM_REG_MSP, UC_ARM_REG_CONTROL,
)

if not __debug__:
    raise RuntimeError("Disable PYTHONOPTIMIZE/-O: maintained assertions must execute")


API = {
    "init": "fiber_secure_context_pool_boot_initialize",
    "allocate": "fiber_secure_context_pool_allocate",
    "lookup": "fiber_secure_context_pool_lookup_owned",
}
POISON = 0xA5
FLASH, FLASH_SIZE = 0x0C000000, 0x20000
RAM, RAM_SIZE = 0x30000000, 0x10000
STACK_BEGIN, STACK_END = RAM + 0xC000, RAM + 0xF000
STOP = FLASH + FLASH_SIZE - 16
SAVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
         UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]


class MissingTrap(AssertionError):
    def __init__(self, function, value):
        super().__init__(f"{function}: returned {value:#x} instead of fail-closed UDF")
        self.function, self.value = function, value


class Image:
    def __init__(self, run):
        self.run = run
        self.symbols = {}
        self.function_sizes = {}
        self.segments = []
        with open(run["Elf"], "rb") as stream:
            elf = ELFFile(stream)
            assert elf.elfclass == 32 and elf.little_endian
            assert elf["e_machine"] == "EM_ARM"
            sections = list(elf.iter_sections())
            symbols = list(elf.get_section_by_name(".symtab").iter_symbols())
            for symbol in symbols:
                if symbol.name:
                    self.symbols[symbol.name] = symbol["st_value"]
                    if symbol["st_info"]["type"] == "STT_FUNC":
                        self.function_sizes[symbol.name] = symbol["st_size"]
                assert not (symbol["st_shndx"] == "SHN_UNDEF" and symbol.name), \
                    f"unresolved symbol: {symbol.name}"
                assert not symbol.name.startswith("_Z"), \
                    f"unexpected C++-mangled dependency: {symbol.name}"
                assert not symbol.name.startswith("__acle_se_"), "pool became NSC"
            pool = elf.get_section_by_name(".fiber_secure_context_pool")
            bss = elf.get_section_by_name(".bss")
            assert pool is not None and pool["sh_type"] == "SHT_NOBITS"
            assert bss is not None and bss["sh_type"] == "SHT_NOBITS"
            assert pool["sh_addralign"] >= 8 and pool["sh_flags"] == 3
            assert bss["sh_size"] == 4, "one-way state must be exactly four BSS bytes"
            self.pool, self.size = pool["sh_addr"], pool["sh_size"]
            self.state = bss["sh_addr"]
            assert self.pool % 8 == 0 and self.state % 4 == 0
            assert self.pool + self.size <= self.state
            pool_index = next(i for i, s in enumerate(sections) if s.name == pool.name)
            bss_index = next(i for i, s in enumerate(sections) if s.name == bss.name)
            pool_objects = [s for s in symbols if s["st_info"]["type"] == "STT_OBJECT"
                            and s["st_shndx"] == pool_index]
            bss_objects = [s for s in symbols if s["st_info"]["type"] == "STT_OBJECT"
                           and s["st_shndx"] == bss_index]
            assert len(pool_objects) == 1, "NOLOAD must contain exactly one image"
            assert pool_objects[0]["st_size"] == self.size
            assert pool_objects[0]["st_info"]["bind"] == "STB_LOCAL"
            assert len(bss_objects) == 1 and bss_objects[0]["st_size"] == 4
            assert bss_objects[0]["st_info"]["bind"] == "STB_LOCAL"
            for section in sections:
                if section["sh_flags"] & 3 == 3 and section["sh_size"]:
                    assert section.name in (".fiber_secure_context_pool", ".bss"), \
                        f"unexpected mutable storage: {section.name}"
            for name in list(API.values()) + ["m55_pool_cpp_initialize",
                    "m55_pool_cpp_allocate", "m55_pool_cpp_lookup", "m55_pool_geometry"]:
                assert name in self.symbols, f"missing C-linkage symbol {name}"
            pool_functions = {name for name in self.function_sizes
                              if name.startswith("fiber_secure_context_pool_")}
            assert len(pool_functions) == 9, "sensitive private call graph was cloned, folded, or inlined"
            assert len({self.symbols[name] for name in pool_functions}) == 9
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]:
                    start, end = segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"]
                    assert FLASH <= start < end <= FLASH + FLASH_SIZE, \
                        "NOLOAD or BSS unexpectedly acquired file contents"
                    self.segments.append((start, segment.data()))
            self.count, self.capacity, record_size, alignment, seal_size, self.seal = \
                struct.unpack("<6I", self.file_bytes(self.symbols["m55_pool_geometry"], 24))
            assert self.count == run["Count"] and self.capacity == run["Capacity"]
            assert (record_size, alignment, seal_size, self.seal) == (24, 8, 8, 0xFEF5EDA5)
            assert self.size == self.count * (24 + self.capacity + 8)
        self.checks = 0
        self.traps = 0
        self.trap_pcs = set()
        self.cuts = []
        self.verification_injection = None
        self.ready_injection = None
        self.later_record_checks = 0

    def file_bytes(self, address, size):
        for start, data in self.segments:
            if start <= address and address + size <= start + len(data):
                return data[address - start:address - start + size]
        raise AssertionError(f"not file-backed: {address:#x}+{size}")

    def record(self, index):
        return self.pool + 24 * index

    def stack(self, index):
        return self.pool + 24 * self.count + (self.capacity + 8) * index


class Machine:
    def __init__(self, image):
        self.image = image
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
        self.uc.mem_map(FLASH, FLASH_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(RAM, RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_write(RAM, bytes([POISON]) * RAM_SIZE)
        for address, data in image.segments:
            self.uc.mem_write(address, data)
        # Model C startup for BSS only; the production initializer owns NOLOAD.
        self.uc.mem_write(image.state, bytes(4))
        self.events = []
        self.reads = []
        self.invalid = []
        self.returned = False
        self.cut = None
        self.cut_kind = None
        self.touched = set()
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._memory)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid)

    def _code(self, uc, address, size, data):
        if address == STOP:
            self.returned = True
            uc.emu_stop()
        elif self.cut_kind:
            state = self.get(self.image.state)
            progress = len(self.touched)
            if state != 0 and ((self.cut_kind == "gate" and progress == 0)
                    or (self.cut_kind == "half" and progress >= self.image.size // 2)):
                self.cut = {"kind": self.cut_kind, "pc": address,
                            "state": state, "written_pool_bytes": progress}
                uc.emu_stop()

    def _memory(self, uc, kind, address, size, value, data):
        image = self.image
        in_pool = image.pool <= address and address + size <= image.pool + image.size
        in_state = image.state <= address and address + size <= image.state + 4
        in_stack = STACK_BEGIN <= address and address + size <= STACK_END
        in_flash = FLASH <= address and address + size <= FLASH + FLASH_SIZE
        if not (in_pool or in_state or in_stack or (in_flash and kind != UC_MEM_WRITE)):
            self.invalid.append((kind, address, size))
            uc.emu_stop()
        elif (in_pool or in_state) and kind == UC_MEM_WRITE:
            self.events.append((address, size, value))
            if in_pool:
                self.touched.update(range(address, address + size))
        elif in_pool and kind == UC_MEM_READ:
            self.reads.append((address, size))

    def _invalid(self, uc, kind, address, size, value, data):
        self.invalid.append((kind, address, size))
        return False

    def get(self, address):
        return struct.unpack("<I", self.uc.mem_read(address, 4))[0]

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))

    def pool(self):
        return bytes(self.uc.mem_read(self.image.pool, self.image.size))

    def snapshot(self):
        return self.pool(), self.get(self.image.state)

    def call(self, name, *args, trap=False, interrupt=None):
        self.image.checks += 1
        name = API.get(name, name)
        self.returned, self.cut = False, None
        self.cut_kind = interrupt
        self.events, self.reads, self.invalid, self.touched = [], [], [], set()
        self.uc.reg_write(UC_ARM_REG_CONTROL, 0)
        self.uc.reg_write(UC_ARM_REG_MSP, STACK_END)
        self.uc.reg_write(UC_ARM_REG_SP, STACK_END)
        for register, value in zip([UC_ARM_REG_R0, UC_ARM_REG_R1,
                                   UC_ARM_REG_R2, UC_ARM_REG_R3], list(args) + [0] * 4):
            self.uc.reg_write(register, value)
        seeds = [0x44440000 + i * 0x1111 for i in range(len(SAVED))]
        for register, value in zip(SAVED, seeds):
            self.uc.reg_write(register, value)
        self.uc.reg_write(UC_ARM_REG_LR, STOP | 1)
        fault = None
        try:
            self.uc.emu_start(self.image.symbols[name] | 1, STOP + 2, count=1000000)
        except UcError as exc:
            fault = exc
        pc = self.uc.reg_read(UC_ARM_REG_PC)
        assert not self.invalid, f"{name}: unexpected access {self.invalid} at {pc:#x}"
        if fault is None and self.returned:
            assert self.uc.reg_read(UC_ARM_REG_SP) == STACK_END, f"{name}: SP not restored"
            assert [self.uc.reg_read(r) for r in SAVED] == seeds, f"{name}: callee-saved register corruption"
            self.redzones()
        if interrupt:
            assert fault is None and self.cut and not self.returned, \
                f"{name}: actual instruction hook did not interrupt initialization: {fault}"
            self.image.cuts.append(self.cut)
        elif trap:
            if fault is None and self.returned:
                raise MissingTrap(name, self.uc.reg_read(UC_ARM_REG_R0))
            assert fault and fault.errno in (UC_ERR_EXCEPTION, UC_ERR_INSN_INVALID), \
                f"{name}: expected actual UDF, got {fault}, returned={self.returned}, PC={pc:#x}"
            fail_name = "fiber_secure_context_pool_fail_closed"
            fail_start = self.image.symbols[fail_name] & ~1
            assert fail_start <= pc < fail_start + self.image.function_sizes[fail_name], \
                f"{name}: UDF did not originate in the real fail-closed helper"
            opcode, next_half = struct.unpack("<HH", self.uc.mem_read(pc, 4))
            assert opcode & 0xFF00 == 0xDE00 or \
                (opcode & 0xFFF0 == 0xF7F0 and next_half & 0xF000 == 0xA000), \
                f"{name}: fault is not an explicit UDF: {opcode:04x} {next_half:04x}"
            self.image.traps += 1
            self.image.trap_pcs.add(pc)
        else:
            assert fault is None and self.returned, f"{name}: failed at {pc:#x}: {fault}"
        self.cut_kind = None
        self.redzones()
        return self.uc.reg_read(UC_ARM_REG_R0)

    def redzones(self):
        for address, size in [(self.image.pool - 32, 32),
                (self.image.pool + self.image.size, 32),
                (self.image.state - 32, 32), (self.image.state + 4, 32)]:
            assert bytes(self.uc.mem_read(address, size)) == bytes([POISON]) * size, \
                f"RAM redzone changed at {address:#x}"

    def unchanged_call(self, name, *args, expected=0):
        before = self.snapshot()
        assert self.call(name, *args) == expected, f"{name}{args}: wrong result"
        assert not self.events and self.snapshot() == before, f"{name}{args}: mutated pool/state"


def initialized(image):
    m = Machine(image)
    assert m.pool() == bytes([POISON]) * image.size
    assert m.call("init") == 1
    assert m.pool() == bytes(image.size), "initializer did not clear every NOLOAD byte"
    assert m.get(image.state) != 0
    state_writes = [event for event in m.events if event[0] == image.state]
    assert len(state_writes) == 2 and all(event[1] == 4 for event in state_writes)
    assert state_writes[0][2] not in (0, state_writes[1][2])
    assert state_writes[1][2] == m.get(image.state)
    assert m.events[0] == state_writes[0], "destructive write preceded one-way gate"
    assert m.events[-1] == state_writes[-1], "READY published before clearing finished"
    return m


def allocated(image, count=1):
    m = initialized(image)
    for index in range(count):
        assert m.call("allocate", image.capacity, owner(index)) == index + 1
    return m


def owner(index):
    # Unmapped, deliberately non-pointer-aligned opaque tokens.
    return 0xDEAD0001 + 0x1000 * index


def valid_paths(image):
    m = initialized(image)
    for handle in [0, 1, image.count, image.count + 1, 0xFFFFFFFF]:
        m.unchanged_call("lookup", handle, owner(0))
    for size in [0, 1, 7, 9, image.capacity + 8, 0x80000000, 0xFFFFFFF8, 0xFFFFFFFF]:
        m.unchanged_call("allocate", size, owner(0))
    m.unchanged_call("allocate", 8, 0)
    m.unchanged_call("init")
    allocation_states = set()
    for index in range(image.count):
        size = [8, image.capacity, max(8, image.capacity - 8)][index % 3]
        assert m.call("allocate", size, owner(index)) == index + 1
        record, stack = image.record(index), image.stack(index)
        actual = struct.unpack("<6I", m.uc.mem_read(record, 24))
        assert actual[:5] == (stack + size, stack, stack + size, owner(index), size)
        assert actual[5] != 0
        allocation_states.add(actual[5])
        assert bytes(m.uc.mem_read(stack, size)) == bytes(size)
        assert bytes(m.uc.mem_read(stack + size, 8)) == struct.pack("<2I", image.seal, image.seal)
        seal_writes = [event for event in m.events if stack + size <= event[0] < stack + size + 8]
        assert [(event[0], event[1]) for event in seal_writes] == \
            [(stack + size + byte, 1) for byte in range(8)], "seal stores are not bytewise"
        tail = image.capacity - size
        assert bytes(m.uc.mem_read(stack + size + 8, tail)) == bytes(tail)
        m.unchanged_call("lookup", index + 1, owner(index), expected=record)
        seal_reads = [(address, width) for address, width in m.reads
                      if stack + size <= address < stack + size + 8]
        assert seal_reads == [(stack + size + byte, 1) for byte in range(8)], \
            "seal reads are not bytewise"
        m.unchanged_call("allocate", size, owner(index))
        m.unchanged_call("lookup", index + 1, 0)
        m.unchanged_call("lookup", index + 1, owner(index) + 1)
        for psp in sorted({stack, stack + 8, stack + size}):
            m.put(record, psp)
            m.unchanged_call("lookup", index + 1, owner(index), expected=record)
        m.put(record, stack + size)
    assert len(allocation_states) == 1
    m.unchanged_call("allocate", 8, owner(image.count))
    for handle in [0, image.count + 1, 0x80000000, 0xFFFFFFFF]:
        m.unchanged_call("lookup", handle, owner(0))
    # Nonzero data proves repeat initialization does not erase a live pool.
    m.uc.mem_write(image.stack(0), b"\x42" * 8)
    m.unchanged_call("init")
    retained = Machine(image)
    retained.uc.mem_write(image.pool, m.pool())
    assert retained.call("init") == 1, "fresh BSS did not reset retained valid pool data"
    assert retained.pool() == bytes(image.size)
    # Execute all three C++ callers, rather than merely keeping dead references.
    cpp = Machine(image)
    assert cpp.call("m55_pool_cpp_initialize") == 1
    assert cpp.call("m55_pool_cpp_allocate", image.capacity, owner(0)) == 1
    assert cpp.call("m55_pool_cpp_lookup", 1, owner(0)) == image.record(0)


def corruption(image):
    # Both lookup and allocation must reject corruption before using the record.
    for operation in ["lookup", "allocate"]:
        args = (1, owner(0)) if operation == "lookup" else (8, owner(image.count))
        for byte in range(8):
            m = allocated(image)
            address = image.stack(0) + image.capacity + byte
            old = bytes(m.uc.mem_read(address, 1))[0]
            m.uc.mem_write(address, bytes([old ^ 1]))
            m.call(operation, *args, trap=True)
        stack, top = image.stack(0), image.stack(0) + image.capacity
        mutations = [(0, stack + 1), (0, stack - 8), (0, top + 8),
                     (4, 0), (4, stack + 8), (8, 0), (8, top + 8),
                     (12, 0), (16, 0), (16, 1), (16, image.capacity + 8),
                     (16, 0xFFFFFFF8), (16, 0xFFFFFFFF), (20, 0), (20, 1)]
        for offset, value in mutations:
            m = allocated(image)
            m.put(image.record(0) + offset, value)
            m.call(operation, *args, trap=True)
            assert not any(image.stack(0) <= address < image.stack(0) + image.capacity + 8
                           for address, _ in m.reads), "invalid metadata reached a stack/seal read"
        for offset in range(0, 20, 4):
            m = initialized(image)
            m.put(image.record(0) + offset, 0x12345678)
            m.call(operation, *args, trap=True)
    if image.count > 1:
        m = allocated(image, 2)
        m.put(image.record(1) + 12, owner(0))
        m.call("allocate", 8, owner(0), trap=True)
        # A duplicate request must not hide a later record's independent corruption.
        m = allocated(image, 2)
        m.put(image.record(1) + 4, 0)
        m.call("allocate", 8, owner(0), trap=True)


def incomplete_init(image):
    for kind in ["gate", "half"]:
        m = Machine(image)
        m.call("init", interrupt=kind)
        before = m.snapshot()
        assert before[1] != 0 and POISON in before[0]
        if kind == "gate":
            assert before[0] == bytes([POISON]) * image.size
        else:
            assert 0 in before[0], "mid-clear interruption did not execute actual clearing"
        m.unchanged_call("init")
        assert m.snapshot() == before, "interrupted initialization became retryable"
        # Private operations fail closed before touching retained records.
        for operation, args in [("allocate", (8, owner(0))), ("lookup", (1, owner(0)))]:
            m.call(operation, *args, trap=True)
            assert m.snapshot() == before and not m.events
    m = Machine(image)
    for operation, args in [("allocate", (8, owner(0))), ("lookup", (1, owner(0)))]:
        m.call(operation, *args, trap=True)
        assert m.snapshot() == (bytes([POISON]) * image.size, 0) and not m.events
    # A random nonzero marker is corruption, not a second spelling of UNINIT.
    for operation, args in [("init", ()), ("allocate", (8, owner(0))),
                            ("lookup", (1, owner(0)))]:
        m = Machine(image)
        m.put(image.state, 0xA5A5A5A5)
        before = m.snapshot()
        m.call(operation, *args, trap=True)
        assert m.snapshot() == before and not m.events
    # Inject one retained byte after the actual final clear store, before the
    # actual verifier reads it. No verification or state transition is modeled.
    m = Machine(image)
    injected = []

    def corrupt_after_clear(uc, address, size, data):
        if not injected and len(m.touched) == image.size:
            uc.mem_write(image.pool + image.size - 1, b"\x01")
            injected.append(address)

    hook = m.uc.hook_add(UC_HOOK_CODE, corrupt_after_clear)
    m.call("init", trap=True)
    m.uc.hook_del(hook)
    assert len(injected) == 1
    image.verification_injection = {"pc": injected[0],
                                    "corrupted_address": image.pool + image.size - 1}
    assert len([event for event in m.events if event[0] == image.state]) == 1, \
        "failed readback published READY"
    m.unchanged_call("init")


def ready_publication_readback(image):
    ready = initialized(image).get(image.state)
    m = Machine(image)
    injected = []
    corrupted = ready ^ 1

    def corrupt_published_ready(uc, address, size, data):
        # The store has committed before this next instruction hook. Change
        # the real marker before the initializer's real volatile readback.
        if not injected and m.get(image.state) == ready:
            uc.mem_write(image.state, struct.pack("<I", corrupted))
            injected.append(address)

    hook = m.uc.hook_add(UC_HOOK_CODE, corrupt_published_ready)
    try:
        try:
            m.call("init", trap=True)
        except MissingTrap:
            assert len(injected) == 1 and m.get(image.state) == corrupted, \
                "mutant returned without the READY fault injection executing"
            assert m.pool() == bytes(image.size)
            raise
    finally:
        m.uc.hook_del(hook)
    assert len(injected) == 1, "READY-store readback injection did not execute"
    assert m.pool() == bytes(image.size) and m.get(image.state) == corrupted
    assert len([event for event in m.events if event[0] == image.state]) == 2
    image.ready_injection = {"pc": injected[0], "published": ready, "corrupted": corrupted}
    before = m.snapshot()
    m.call("init", trap=True)
    assert m.snapshot() == before and not m.events, "unknown marker retry erased retained data"


def later_record_after_free(image):
    assert image.count > 1
    # Construct a consistent FREE record before an independently valid later
    # allocation; holes are a corruption-test arrangement, not a free API.
    m = allocated(image, 2)
    m.uc.mem_write(image.record(0), bytes(24))
    m.unchanged_call("lookup", 2, owner(1), expected=image.record(1))
    assert m.call("allocate", 8, owner(image.count)) == 1
    m.unchanged_call("lookup", 2, owner(1), expected=image.record(1))
    for damage in ["metadata", "seal"]:
        m = allocated(image, 2)
        m.uc.mem_write(image.record(0), bytes(24))
        if damage == "metadata":
            m.put(image.record(1) + 4, 0)
        else:
            address = image.stack(1) + image.capacity
            m.uc.mem_write(address, b"\x00")
        before = m.snapshot()
        m.call("allocate", 8, owner(image.count), trap=True)
        assert m.snapshot() == before and not m.events, \
            "allocator published the first FREE slot before checking later corruption"
        image.later_record_checks += 1


def mutants(manifest):
    runs = json.loads(manifest.read_text(encoding="utf-8-sig"))
    results = []
    for run in runs:
        image = Image(run)
        scenario = run["Scenario"]
        if scenario == "ready-readback":
            check, function = ready_publication_readback, API["init"]
        elif scenario == "early-free-break":
            check, function = later_record_after_free, API["allocate"]
        else:
            raise AssertionError(f"unknown mutant scenario {scenario}")
        try:
            check(image)
        except MissingTrap as exc:
            assert exc.function == function and exc.value == 1, \
                f"{run['Name']}: mutant failed with the wrong return: {exc}"
            results.append({"name": run["Name"], "status": "KILLED",
                            "function": exc.function, "unexpected_success_return": exc.value,
                            "checks": image.checks, "scenario": scenario,
                            "execution_counterflag": "-fno-branch-count-reg"})
        else:
            raise AssertionError(f"{run['Name']}: guard-removal mutant survived")
        print(f"PASS killed {run['Name']}: actual unexpected success return 1", flush=True)
    summary = {"status": "PASS", "killed": len(results),
               "checks": sum(result["checks"] for result in results), "results": results}
    (manifest.parent / "mutant_results.json").write_text(json.dumps(summary, indent=2), encoding="ascii")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--mutants":
        mutants(Path(sys.argv[2]))
        return
    manifest = Path(sys.argv[1])
    runs = json.loads(manifest.read_text(encoding="utf-8-sig"))
    results = []
    for run in runs:
        try:
            baseline = Image(dict(run, Elf=run["BaselineElf"]))
            if run.get("AttributeElf"):
                Image(dict(run, Elf=run["AttributeElf"]))
            image = Image(run)
            assert (baseline.size, baseline.count, baseline.capacity) == \
                (image.size, image.count, image.capacity)
            valid_paths(image)
            corruption(image)
            incomplete_init(image)
            ready_publication_readback(image)
            if image.count > 1:
                later_record_after_free(image)
        except (AssertionError, UcError) as exc:
            raise AssertionError(f"{run['Name']}: {exc}") from exc
        results.append({"name": run["Name"], "status": "PASS", "checks": image.checks,
                        "pool_bytes": image.size, "bss_state_bytes": 4,
                        "baseline_elf": run["BaselineElf"],
                        "execution_counterflag": run["ExecutionCounterflag"],
                        "expected_udf_traps": image.traps,
                        "verified_udf_pcs": sorted(image.trap_pcs),
                        "verification_fault_injection": image.verification_injection,
                        "ready_publication_fault_injection": image.ready_injection,
                        "later_allocated_record_corruptions_after_free": image.later_record_checks,
                        "instruction_hook_interruptions": image.cuts})
        print(f"PASS {run['Name']}: {image.checks} actual ARM calls", flush=True)
    summary = {"status": "PASS", "elfs": len(results),
               "baseline_elfs": len(results),
               "checks": sum(result["checks"] for result in results),
               "expected_udf_traps": sum(result["expected_udf_traps"] for result in results),
               "invalid_memory_accesses": 0,
               "boundary": "M55-target scalar Thumb C with -fno-branch-count-reg on Unicorn Cortex-M33; untouched M55 baseline ELF proof only; no M55 hardware, TrustZone, CPU-register or exception qualification",
               "results": results}
    (manifest.parent / "results.json").write_text(json.dumps(summary, indent=2), encoding="ascii")
    print(f"PASS {summary['elfs']} ARM ELFs, {summary['checks']} calls; exact NOLOAD/BSS and C++ linkage")


if __name__ == "__main__":
    main()
