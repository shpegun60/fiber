"""Real C3FS machine bodies with explicit system-register/MMIO fault doubles.

No SG, security banking, FP stacking or arbitrary-MSP containment is emulated.
The complete body/veneer codegen audit is separate from these fault injections.
"""
import re
import struct
import hashlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
                     UC_HOOK_CODE, UC_HOOK_MEM_WRITE)
from unicorn.arm_const import *
from run import Image, require, pack

AIRCR, CPACR, NSACR, FPCCR, FPCCR_NS = (
    0xe000ed0c, 0xe000ed88, 0xe000ed8c, 0xe000ef34, 0xe002ef34)
INIT, READY, POOL_INIT, POOL_READY = 0x53464742, 0x53464752, 0x53465042, 0x53465052


def instructions(path):
    result = {}
    for line in Path(path + '.dis').read_text().splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{4,8}\s+)+)'
                     r'([a-z][a-z0-9.]*)\s*(.*)', line)
        if m:
            result[int(m[1], 16)] = (sum(len(x)//2 for x in m[2].split()), m[3], m[4])
    return result


def register(name):
    aliases = {'ip': 'R12', 'sl': 'R10', 'fp': 'R11', 'sb': 'R9'}
    return globals()['UC_ARM_REG_' + aliases.get(name.lower(), name.upper())]


class Boot:
    def __init__(self, path, **policy):
        self.image = Image(path)
        self.insns = instructions(path)
        self.policy = policy
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
        for address, size in ((0x10000000, 0x40000), (0x30000000, 0x10000),
                              (0xe000e000, 0x30000)):
            self.uc.mem_map(address, size)
        for address, data in self.image.loads:
            self.uc.mem_write(address, data)
        self.gate = self.address('fiber_secure_context_gateway_state')
        self.pool = self.address('fiber_secure_context_pool_state')
        self.storage = self.address('fiber_secure_context_pool_image')
        self.storage_size = self.image.symbols['fiber_secure_context_pool_image'][1]
        require(self.storage_size == 864 and self.storage % 8 == 0, 'INIT_POOL_GEOMETRY')
        self.put(self.gate, policy.get('gateway', 0))
        self.put(self.pool, policy.get('pool', 0))
        self.uc.mem_write(self.storage, b'\xa5' * self.storage_size)
        self.cpu = dict(CONTROL=policy.get('control', 0), CONTROL_NS=policy.get('control_ns', 0),
                        IPSR=policy.get('ipsr', 11), PSP=0x30002000, PSPLIM=0x30001000)
        self.initial_cpu = self.cpu.copy()
        self.put(AIRCR, policy.get('aircr', 0xfa050502))
        self.put(CPACR, policy.get('cpacr', 0xf00000))
        self.put(NSACR, 0x102)
        self.put(FPCCR, policy.get('fpccr', 0xe8000000))
        self.put(FPCCR_NS, policy.get('fpccr_ns', 0xc0000000))
        self.put(0xe002ed88, 0x500000)
        self.before = {a: self.get(a) for a in (AIRCR, CPACR, NSACR, FPCCR, FPCCR_NS, 0xe002ed88)}
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.calls = 0

    def address(self, name):
        return self.image.symbols[name][0] & ~1

    def get(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]

    def put(self, address, value):
        self.uc.mem_write(address, pack([value]))

    def write(self, uc, kind, address, size, value, _):
        # Stack spills/CMSE integer prologue are intentionally not backend effects.
        if address in (self.gate, self.pool) or self.storage <= address < self.storage+self.storage_size or address >= 0xe0000000:
            self.writes.append((address, size, value))
        override = None
        if address == self.gate:
            if value == INIT and self.policy.get('lose_gateway_latch'):
                override = 0
            if value == READY and self.policy.get('lose_gateway_ready'):
                override = INIT
        if address == self.pool:
            if value == POOL_INIT and self.policy.get('lose_pool_latch'):
                override = 0
            if value == POOL_READY and self.policy.get('lose_pool_ready'):
                override = POOL_INIT
        if address == self.storage and self.policy.get('lose_scrub'):
            override = 0xa5
        if address == AIRCR and self.policy.get('lose_aircr'):
            override = self.before[AIRCR]
        if address == NSACR and self.policy.get('lose_nsacr'):
            override = self.before[NSACR]
        if address == FPCCR and self.policy.get('lose_lspens') and not value & (1 << 29):
            override = value | (1 << 29)
        if address == FPCCR and self.policy.get('lose_ts') and value & (1 << 26):
            override = value & ~(1 << 26)
        if override is not None:
            # Unicorn's write hook runs before the write. Apply on the next
            # instruction, so a subsequent real volatile load sees the fault.
            self.pending.append((address, size, override))

    def code(self, uc, address, size, _):
        for target, width, value in self.pending:
            uc.mem_write(target, value.to_bytes(width, 'little'))
        self.pending.clear()
        if address == 0x1003fff0:
            self.returned = True
            uc.emu_stop()
            return
        raw = int.from_bytes(uc.mem_read(address, 2), 'little')
        if raw & 0xff00 == 0xde00:
            self.trap = raw & 255
            uc.emu_stop()
            return
        if raw == 0x4774:  # stop BEFORE BXNS; never pretend this is SG execution
            self.returned = True
            uc.emu_stop()
            return
        if address == self.address('fiber_secure_context_pool_boot_initialize'):
            self.order.append('pool')
            if 'pool_result' in self.policy:
                uc.reg_write(UC_ARM_REG_R0, self.policy['pool_result'])
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
        _, op, args = self.insns.get(address, (size, '', ''))
        require(not op.startswith('v'), 'INIT_FP_ENVELOPE')
        if op in ('mrs', 'msr'):
            parts = [x.strip() for x in args.split(',')]
            special = parts[1] if op == 'mrs' else parts[0]
            if special.upper() in self.cpu:
                special = special.upper()
                general = register(parts[0] if op == 'mrs' else parts[1])
                if op == 'mrs':
                    value = self.cpu[special]
                    if special == 'CONTROL' and self.wrote_control:
                        value = self.policy.get('control_after', value)
                    uc.reg_write(general, value)
                else:
                    value = uc.reg_read(general)
                    self.order.append((special, value))
                    if special == 'CONTROL':
                        self.wrote_control = True
                    if self.policy.get('lose_'+special.lower()):
                        value = self.cpu[special]
                    self.cpu[special] = value
                uc.reg_write(UC_ARM_REG_PC, (address + size) | 1)

    def call(self, private=None):
        self.calls += 1
        self.returned, self.trap, self.wrote_control = False, None, False
        self.writes, self.order, self.pending = [], [], []
        for r, v in ((UC_ARM_REG_CONTROL, 0), (UC_ARM_REG_XPSR, 0x0100000b),
                     (UC_ARM_REG_MSP, 0x3000f000), (UC_ARM_REG_SP, 0x3000f000),
                     (UC_ARM_REG_R9, 0x13579bdf),
                     (UC_ARM_REG_LR, 0x1003fff1 if private else
                         (0xfffffffd if self.policy.get('secure_caller') else 0xfffffffe))):
            self.uc.reg_write(r, v)
        name = private or '__acle_se_fiber_secure_context_gateway_c3fs_v1_initialize'
        try:
            self.uc.emu_start(self.address(name) | 1, 0x1003fff2, count=100000)
        except Exception as error:
            raise RuntimeError(f'INIT_EXECUTION:PC={self.uc.reg_read(UC_ARM_REG_PC):#x}:'
                               f'policy={self.policy}:{error}') from error
        require(self.returned or self.trap is not None, 'INIT_NO_TERMINATION')
        if self.returned:
            require(self.uc.reg_read(UC_ARM_REG_MSP) == 0x3000f000 and
                    self.uc.reg_read(UC_ARM_REG_R9) == 0x13579bdf, 'INIT_CALLEE_SAVE')
        return self.uc.reg_read(UC_ARM_REG_R0)


def codegen(path):
    image = Image(path)
    decoded = instructions(path)
    name = '__acle_se_fiber_secure_context_gateway_c3fs_v1_initialize'
    start = image.symbols[name][0] & ~1
    # ld replaces the public C symbol with its 8-byte veneer and leaves the
    # __acle_se alias size zero. Derive its actual text interval from ELF
    # function/section boundaries, not that deliberately zero-sized alias.
    with open(path, 'rb') as stream:
        elf = ELFFile(stream)
        symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
        symbol = next(s for s in symbols if s.name == name)
        section = elf.get_section(symbol['st_shndx'])
        ends = [s['st_value'] & ~1 for s in symbols if
                s['st_info']['type'] == 'STT_FUNC' and
                s['st_shndx'] == symbol['st_shndx'] and (s['st_value'] & ~1) > start]
        end = min(ends + [section['sh_addr'] + section['sh_size']])
        interval = section.data()[start-section['sh_addr']:end-section['sh_addr']]
        code_bytes, data_bytes, whole_hash = 0, 0, hashlib.sha256()
        # Every production text byte must be decoded Thumb code or explicitly
        # marked literal data. No unknown .inst/.word may hide an FP instruction
        # in a $t span. The separate veneer oracle accounts for all nine SGs.
        for index, text_section in enumerate(elf.iter_sections()):
            if not text_section['sh_flags'] & 4 or text_section.name == '.gnu.sgstubs':
                continue
            lo = text_section['sh_addr']
            hi = lo + text_section['sh_size']
            marks = sorted(set((s['st_value'], s.name[:2]) for s in symbols if
                s['st_shndx'] == index and s.name[:2] in ('$t', '$d')))
            require(marks and marks[0][0] == lo, 'INIT_TEXT_MAPPING_START')
            marks.append((hi, '$end'))
            for (a, kind), (b, _) in zip(marks, marks[1:]):
                if kind == '$d':
                    data_bytes += b-a
                    continue
                require(kind == '$t', 'INIT_TEXT_MAPPING_KIND')
                while a < b:
                    require(a in decoded, 'INIT_TEXT_DECODE_COVERAGE')
                    width, op, _ = decoded[a]
                    require(a+width <= b and not op.startswith('v'), 'INIT_FP_ENVELOPE')
                    raw = text_section.data()[a-lo:a-lo+width]
                    whole_hash.update(raw)
                    code_bytes += width
                    a += width
    extent = end - start
    body = [(a, *i) for a, i in decoded.items() if start <= a < end]
    require(body, 'INIT_BODY')
    require(not any(op.startswith('v') for _, _, op, _ in body), 'INIT_FP_ENVELOPE')
    text = '\n'.join(op+' '+args for _, _, op, args in body)
    require('udf #75' in text and re.search(r'mrs .*CONTROL', text) and
            'fiber_secure_context_pool_c3fs_g2_cohort_provider' in text and
            'fiber_secure_context_pool_boot_initialize' in text and
            re.search(r'mrs .*CONTROL_NS', text), 'INIT_PREFLIGHT_CODEGEN')
    require(not any(op.startswith('cps') or (op == 'msr' and
                args.split(',')[0].upper() in ('PRIMASK','BASEPRI','FAULTMASK','CONTROL_NS'))
                for _, _, op, args in body), 'INIT_UNOWNED_CPU_WRITE')
    return {'InitializerTextIntervalBytes': extent, 'Instructions': len(body),
            'InitializerTextIntervalSHA256': hashlib.sha256(interval).hexdigest().upper(),
            'WholeCompanionDecodedInstructionBytes': code_bytes,
            'WholeCompanionLiteralBytes': data_bytes,
            'WholeCompanionInstructionSHA256': whole_hash.hexdigest().upper(), 'Status': 'PASS'}


def execute(path):
    calls = 0
    for state in (0, POOL_INIT, POOL_READY, 1):
        m = Boot(path, pool=state)
        require(m.call('fiber_secure_context_pool_boot_is_pristine') == int(state == 0) and
                not m.writes and not m.order and not m.trap, 'POOL_PRISTINE_READ_ONLY')
        result = m.call('fiber_secure_context_pool_boot_initialize')
        if state == 0:
            require(result == 1 and m.returned and not m.trap and
                    m.get(m.pool) == POOL_READY and
                    bytes(m.uc.mem_read(m.storage, m.storage_size)) == bytes(m.storage_size),
                    'POOL_DIRECT_SCRUB')
            require(m.call('fiber_secure_context_pool_boot_initialize') == 0 and
                    m.returned and not m.writes, 'POOL_DIRECT_REPEAT')
        elif state in (POOL_INIT, POOL_READY):
            require(result == 0 and m.returned and not m.writes and
                    bytes(m.uc.mem_read(m.storage, m.storage_size)) == b'\xa5'*m.storage_size,
                    'POOL_DIRECT_NO_ERASE')
        else:
            require(m.trap is not None and not m.returned and not m.writes, 'POOL_UNKNOWN_STATE_TRAP')
        calls += m.calls
    for settings in ({}, {'control': 2, 'control_ns': 3},
                     {'fpccr': 0, 'fpccr_ns': 0}, {'fpccr': 0xfc000000}):
        m = Boot(path, **settings)
        require(m.call() == 1 and m.returned and m.trap is None, 'INIT_SUCCESS')
        require(m.get(m.gate) == READY and m.get(m.pool) == POOL_READY and
                bytes(m.uc.mem_read(m.storage, m.storage_size)) == bytes(m.storage_size), 'INIT_SCRUB')
        require(m.order == [('PSPLIM', 0), ('PSP', 0), 'pool', ('CONTROL', 2)], 'INIT_REFERENCE_CPU_ORDER')
        mmio = [(a, v) for a, _, v in m.writes if a >= 0xe0000000]
        expected_fpccr = m.before[FPCCR] & ~(1 << 29)
        require(mmio == [(AIRCR, (m.before[AIRCR] & ~0xffff4000) | 0x05fa4000),
                         (NSACR, m.before[NSACR] | 0xc00), (FPCCR, expected_fpccr),
                         (FPCCR, expected_fpccr | (1 << 26))], 'INIT_REFERENCE_MMIO_ORDER')
        require(m.get(CPACR) == m.before[CPACR] and
                m.get(0xe002ed88) == m.before[0xe002ed88] and
                m.get(FPCCR_NS) == m.before[FPCCR_NS] and
                m.cpu['CONTROL_NS'] == m.initial_cpu['CONTROL_NS'], 'INIT_UNOWNED_PRESERVATION')
        require(m.call() == 0 and m.returned and not m.writes and not m.order, 'INIT_REPEAT')
        calls += m.calls
    rejected = [dict(secure_caller=True), dict(ipsr=0), dict(ipsr=14), dict(aircr=0xfa052000),
                dict(gateway=INIT), dict(gateway=READY), dict(gateway=1),
                dict(pool=POOL_INIT), dict(pool=POOL_READY), dict(pool=1),
                dict(control=4), dict(control=6), dict(control=8), dict(control=10), dict(control=14),
                dict(control_ns=4), dict(control_ns=6), dict(fpccr=0xe8000001),
                dict(fpccr_ns=0xc0000001)]
    for settings in rejected:
        m = Boot(path, **settings)
        require(m.call() == 0 and m.returned and m.trap is None and
                not m.writes and not m.order, 'INIT_ADMISSION')
        calls += m.calls
    for settings in (dict(cpacr=0), dict(cpacr=0x500000), dict(control=1)):
        m = Boot(path, **settings)
        m.call()
        require(m.trap == 75 and not m.returned and not m.writes and not m.order, 'INIT_QUERY_PREREQUISITE')
        calls += m.calls
    faults = [dict(lose_aircr=True), dict(lose_psplim=True), dict(lose_psp=True),
              dict(pool_result=0), dict(pool_result=2), dict(control_after=6),
              dict(control_after=10), dict(control_after=14), dict(lose_nsacr=True),
              dict(lose_lspens=True), dict(lose_ts=True)]
    for settings in faults:
        m = Boot(path, **settings)
        require(m.call() == 0 and m.returned and m.trap is None and
                m.get(m.gate) == INIT, 'INIT_STICKY_FAILURE')
        require(m.call() == 0 and m.returned and not m.writes and not m.order, 'INIT_FAILED_RETRY')
        calls += m.calls
    for settings in (dict(lose_gateway_latch=True), dict(lose_pool_latch=True),
                     dict(lose_scrub=True), dict(lose_pool_ready=True), dict(lose_gateway_ready=True)):
        m = Boot(path, **settings)
        m.call()
        require(m.trap is not None and not m.returned, 'INIT_LATCH_OR_SCRUB_TRAP')
        calls += m.calls
    return {'InitializerBodyCalls': calls, 'SGExecuted': False,
            'RegisterModel': 'explicit bank/MMIO doubles, not FP/security emulation', 'Status': 'PASS'}
