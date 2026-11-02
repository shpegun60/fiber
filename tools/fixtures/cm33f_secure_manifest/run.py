"""Actual staged C3FS constructor execution; no CMSE/FP-stack emulation claim."""
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit("C3FS proof rejects Python optimization")
import json
import re
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_WRITE)
from unicorn.arm_const import *

def require(value, message):
    if not value:
        raise RuntimeError(message)

def pack(values):
    return struct.pack('<' + 'I' * len(values), *values)

class Image:
    def __init__(self, path):
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            self.symbols = {s.name: (s['st_value'], s['st_size'])
                            for s in elf.get_section_by_name('.symtab').iter_symbols()}
            self.bindings = {s.name: s['st_info']['bind']
                             for s in elf.get_section_by_name('.symtab').iter_symbols()}
            self.loads = [(s['p_vaddr'], s.data()) for s in elf.iter_segments()
                          if s['p_type'] == 'PT_LOAD' and s['p_filesz']]

class Machine:
    def __init__(self, path):
        self.image = Image(path)
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
        self.uc.mem_map(0x08000000, 0x40000)
        self.uc.mem_map(0x20000000, 0x40000)
        for address, data in self.image.loads:
            self.uc.mem_write(address, data)
        self.uc.hook_add(UC_HOOK_CODE, self.code)
        self.stop = 0x0803fff0
        self.calls = 0
        self.sample_addresses = {value & ~1 for name, (value, _) in self.image.symbols.items()
                                 if name.startswith('fiber_c3fs_r9_capture_')}
    def address(self, name):
        return self.image.symbols[name][0]
    def get(self, address, n=1):
        return list(struct.unpack('<' + 'I' * n, self.uc.mem_read(address, 4*n)))
    def put(self, address, value):
        self.uc.mem_write(address, pack([value]))
    def code(self, uc, address, size, _):
        if address == (self.image.symbols.get('fiber_panic', (0, 0))[0] & ~1):
            self.panic = chr(uc.reg_read(UC_ARM_REG_R0) & 255)
            uc.emu_stop()
        if address == self.stop:
            self.returned = True
            uc.emu_stop()
        if address in self.sample_addresses and size == 2:
            insn = int.from_bytes(uc.mem_read(address, 2), 'little')
            if insn & 0xff00 == 0x4600 and (insn >> 3) & 15 == 9:
                self.samples.append(uc.reg_read(UC_ARM_REG_R9))
    def call(self, name, *args, panic=None):
        self.panic, self.returned, self.samples = None, False, []
        self.calls += 1
        registers = ((UC_ARM_REG_CONTROL, 0), (UC_ARM_REG_XPSR, 0x01000000),
                     (UC_ARM_REG_MSP, 0x2003f000), (UC_ARM_REG_SP, 0x2003f000),
                     (UC_ARM_REG_PSP, 0x2003e000), (UC_ARM_REG_PRIMASK, 0),
                     (UC_ARM_REG_BASEPRI, 0), (UC_ARM_REG_FAULTMASK, 0),
                     (UC_ARM_REG_R9, 0x13579bdf), (UC_ARM_REG_LR, self.stop | 1))
        for reg, value in registers:
            self.uc.reg_write(reg, value)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        if len(args) > 4:
            self.uc.mem_write(0x2003f000, pack(list(args[4:])))
        self.uc.emu_start(self.address(name) | 1, self.stop + 2, count=500000)
        require(self.panic == panic and (panic is not None or self.returned),
                f'{name}: panic={self.panic!r} expected={panic!r}, returned={self.returned}')
        if panic is None:
            require(self.uc.reg_read(UC_ARM_REG_R9) == 0x13579bdf, 'CALLER_R9')
            require(self.uc.reg_read(UC_ARM_REG_MSP) == 0x2003f000, 'CALLER_MSP')
            require(all(self.uc.reg_read(r) == 0 for r in
                        (UC_ARM_REG_CONTROL, UC_ARM_REG_PRIMASK, UC_ARM_REG_BASEPRI,
                         UC_ARM_REG_FAULTMASK)), 'CPU_STATE')
        return self.uc.reg_read(UC_ARM_REG_R0)

def execute(run):
    m = Machine(run['Elf'])
    ctx, begin, end = 0x20001000, 0x20010000, 0x20010800
    task, argument = m.address('fixture_task'), 0x12345678
    def construct():
        m.uc.mem_write(ctx, b'\xa5' * 80)
        m.uc.mem_write(begin, b'\xcc' * 2048)
        m.call('fiber_init', ctx, begin, end, task, argument)
        samples = m.samples[:]
        require(len(samples) == 1, 'EXACT_R9_SAMPLE')
        require(all(m.image.bindings[n] == 'STB_LOCAL' for n in m.image.symbols
                    if n.startswith('fiber_c3fs_r9_capture_')), 'R9_SAMPLE_NOT_EXPORTED')
        frame = m.get(ctx)[0]
        expected = [0, begin+32, 0xffffffbc, 0, 0, 0, 0, 0, samples[0], 0, 0,
                    argument, 0, 0, 0, 0, m.address('fiber_internal_task_return') | 1,
                    task & ~1, 0x01000000]
        require(frame == end-76 and frame % 8 == 4, 'INITIAL_CURSOR')
        require(m.get(frame, 19) == expected, 'FRAME_SEED_OR_GEOMETRY')
        if run['Reserved']:
            require(samples[0] == 0x13579bdf, 'RESERVED_R9_SEED')
        boot = m.get(ctx+4, 19)
        require(boot[:14] == [begin, end, begin+32, end, 2016, task, argument, 0,
                             0x43334653, 0x00010001, 80, 4, 0x8b, 0xffffffbc],
                'BOOT_FIELDS')
        require(m.get(begin)[0] == 0xdeadbeef, 'CANARY')
        m.call('fiber_port_context_initial_frame_check', ctx)
        return frame
    frame = construct()
    m.call('fiber_port_secure_context_attach', ctx, 128)
    require(m.get(ctx+32)[0] == 128 and m.get(frame)[0] == 0, 'ATTACH_NO_ALLOCATION')
    require(m.get(m.address('fixture_query_count'))[0] == 8, 'EIGHT_QUERIES')
    m.call('fiber_port_secure_context_attach', ctx, 128, panic='D')
    for request in (0, 1, 7, 9, 264, 0xffffffff):
        construct()
        before = bytes(m.uc.mem_read(ctx, 80))
        m.call('fiber_port_secure_context_attach', ctx, request, panic='D')
        require(bytes(m.uc.mem_read(ctx, 80)) == before, 'REJECT_BEFORE_MUTATION')
    for index in range(1, 9):
        construct()
        m.put(m.address('fixture_query_index'), index)
        m.put(m.address('fixture_query_value'), 0)
        m.call('fiber_port_secure_context_attach', ctx, 128, panic='Q')
        m.put(m.address('fixture_query_index'), 0)
    construct()
    m.put(m.address('fixture_closed'), 1)
    m.call('fiber_port_secure_context_attach', ctx, 128, panic='k')
    m.put(m.address('fixture_closed'), 0)
    for word in range(1, 20):
        construct()
        address = ctx + 4 * word
        m.put(address, m.get(address)[0] ^ 1)
        # Exact panic comes from the production checker, but never accept a
        # fault or nonreturn as equivalent to a caught fiber_panic.
        m.panic, m.returned, m.samples = None, False, []
        # Discovering a panic is not an expected oracle: the independent seal
        # mutation merely requires a real nonzero panic, not arbitrary failure.
        m.uc.reg_write(UC_ARM_REG_R0, ctx)
        m.uc.reg_write(UC_ARM_REG_SP, 0x2003f000)
        m.uc.reg_write(UC_ARM_REG_LR, m.stop | 1)
        m.uc.emu_start(m.address('fiber_port_context_initial_frame_check') | 1,
                       m.stop + 2, count=500000)
        require(m.panic is not None and not m.returned, 'BOOT_MUTATION_REJECTED')
        m.calls += 1
    for args, code in (((0, begin, end, task, argument), 'C'),
                       ((ctx, begin, begin, task, argument), 'N'),
                       ((begin, begin, end, task, argument), 'C'),
                       ((ctx, begin, end, task & ~1, argument), 'e'),
                       ((ctx, begin, begin+200, task, argument), 'H')):
        m.call('fiber_init', *args, panic=code)
    return {'Calls': m.calls, 'Mode': run['Name'], 'Reserved': run['Reserved'],
            'QueryExecution': 'labelled NS doubles, not SG', 'Status': 'PASS'}

def reference(path):
    m = Machine(path)
    begin, end, task, arg = 0x20010000, 0x20010800, 0x08030001, 0x12345678
    frame = m.call('pxPortInitialiseStack', end, begin, task, arg)
    words = m.get(frame, 19)
    require(frame == end-76 and words[:3] == [0, begin, 0xffffffbc], 'REFERENCE_PREFIX')
    require(words[11] == arg and words[17] == task and words[18] == 0x01000000,
            'REFERENCE_CORE')
    require(words[8] == 0x09090909, 'REFERENCE_DEBUG_R9')
    return {'ReferenceCalls': 1, 'Status': 'PASS'}

def query_codegen(path):
    text = Path(path).read_text()
    bodies = re.split(r'(?m)^[0-9a-f]+ <', text)
    count = 0
    for body in bodies:
        if not body.startswith(('fiber_secure_gateway_c3fs_v1_',
                                'fiber_secure_context_gateway_c3fs_v1_',
                                '__acle_se_fiber_secure_gateway_c3fs_v1_',
                                '__acle_se_fiber_secure_context_gateway_c3fs_v1_')):
            continue
        # Objects carry real body symbols; final public spellings are SG veneers.
        instructions = re.findall(r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{4,8}\s+)+([a-z][a-z0-9.]*)\s*(.*)$', body, re.M)
        require(instructions, 'QUERY_BODY')
        require(not any(op.startswith('v') for op, _ in instructions), 'QUERY_FP_ENVELOPE')
        require(re.search(r'\bmrs\b.*CONTROL', body, re.I) and
                re.search(r'\btst(?:\.w)?\b.*#1\b', body) and
                re.search(r'\budf\b.*#75\b', body) and
                len(re.findall(r'#15728640\b', body)) >= 2 and
                'fiber_secure_context_manifest_c3fs_v1_cohort_provider' in body,
                'QUERY_PREFLIGHT')
        # GNU objdump spells GCC's flags-only APSR_nzcvqg cleanup CPSR_fs.
        # Admit that exact encoding, never a CONTROL/mask-policy write.
        if any(op == 'msr' and args.lower().startswith('cpsr_fs')
               for op, args in instructions):
            require(re.search(r'f38e\s+8c00\s+msr\s+CPSR_fs, lr', body),
                    'QUERY_APSR_ENCODING')
        require(not any(op.startswith(('v', 'cps')) or (op == 'msr' and
                    not args.lower().startswith(('apsr', 'cpsr_fs,')))
                    for op, args in instructions),
                'QUERY_CPU_WRITE')
        count += 1
    require(count == 4, f'QUERY_COUNT:{count}')
    return {'QueryBodies': count, 'Status': 'PASS'}

def query_bodies(path):
    """Execute real body/preflight only; deliberately stop BEFORE BXNS.

    CPACR and CONTROL are explicit register doubles. No SG instruction, CMSE
    transition, SFPA hardware behavior or FP/security stacking is emulated.
    """
    image = Image(path)
    expected = {'fiber_secure_gateway_c3fs_v1_abi_version': 1,
        'fiber_secure_gateway_c3fs_v1_context_port_id': 0x43334653,
        'fiber_secure_gateway_c3fs_v1_context_layout_version': 0x10001,
        'fiber_secure_gateway_c3fs_v1_context_feature_mask': 0x8b,
        'fiber_secure_context_gateway_c3fs_v1_abi_version': 1,
        'fiber_secure_context_gateway_c3fs_v1_stack_alignment': 8,
        'fiber_secure_context_gateway_c3fs_v1_max_stack_bytes': 256,
        'fiber_secure_context_gateway_c3fs_v1_max_contexts': 3}
    count = 0
    for name, result in expected.items():
        for control, cpacr, accepted in ((0,0,False), (0,0xf00000,True),
                (0,0x80f00000,True), (0,0x500000,False), (0,0x300000,False),
                (1,0xf00000,False)):
            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
            uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_M33)
            uc.mem_map(0x10000000, 0x40000)
            uc.mem_map(0x30000000, 0x10000)
            uc.mem_map(0xe000e000, 0x2000)
            for address, data in image.loads:
                uc.mem_write(address, data)
            uc.mem_write(0xe000ed88, pack([cpacr]))
            uc.reg_write(UC_ARM_REG_XPSR, 0x01000000)
            uc.reg_write(UC_ARM_REG_CONTROL, control)
            uc.reg_write(UC_ARM_REG_MSP, 0x3000f000)
            uc.reg_write(UC_ARM_REG_SP, 0x3000f000)
            uc.reg_write(UC_ARM_REG_PSP, 0x3000e000)
            uc.reg_write(UC_ARM_REG_LR, 0x12345679)
            observations = {'terminal': False, 'return': False, 'provider': False,
                            'cpacr_reads': 0, 'mmio_writes': 0}
            provider = image.symbols['fiber_secure_context_manifest_c3fs_v1_cohort_provider'][0] & ~1
            def code(cpu, address, size, _):
                if address == provider:
                    observations['provider'] = True
                if size == 2:
                    instruction = int.from_bytes(cpu.mem_read(address, 2), 'little')
                    if instruction == 0xde4b:
                        observations['terminal'] = True
                        cpu.emu_stop()
                    if instruction == 0x4774:  # stop before actual BXNS
                        observations['return'] = True
                        cpu.emu_stop()
            def memory(cpu, kind, address, size, value, _):
                if address == 0xe000ed88 and kind != UC_MEM_WRITE:
                    observations['cpacr_reads'] += 1
                if kind == UC_MEM_WRITE and address >= 0xe0000000:
                    observations['mmio_writes'] += 1
            uc.hook_add(UC_HOOK_CODE, code)
            uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory)
            try:
                uc.emu_start(image.symbols['__acle_se_'+name][0] | 1, 0x1003fff0, count=50000)
            except Exception as error:
                raise RuntimeError(f'QUERY_BODY:{name}:CONTROL={control}:CPACR={cpacr:#x}:'
                    f'PC={uc.reg_read(UC_ARM_REG_PC):#x}:SP={uc.reg_read(UC_ARM_REG_SP):#x}:{error}') from error
            require(observations['return'] == accepted and
                    observations['terminal'] != accepted, 'QUERY_ADMISSION')
            require(observations['provider'] == accepted and
                    observations['cpacr_reads'] == (0 if control else 1) and
                    observations['mmio_writes'] == 0, 'QUERY_PREFLIGHT_ORDER')
            if accepted:
                require(uc.reg_read(UC_ARM_REG_R0) == result and
                        uc.reg_read(UC_ARM_REG_MSP) == 0x3000f000, 'QUERY_VALUE_OR_STACK')
            count += 1
    return {'QueryBodyCalls': count, 'SGExecuted': False, 'Status': 'PASS'}

def query_entries(path):
    """Account for every byte before the real C body: SG plus direct B.W."""
    image = Image(path)
    text = Path(path + '.dis').read_text()
    names = [name for name in image.symbols if
             name.startswith(('fiber_secure_gateway_c3fs_v1_',
                              'fiber_secure_context_gateway_c3fs_v1_'))]
    require(len(names) == 8, 'QUERY_ENTRY_COUNT')
    for name in names:
        match = re.search(r'(?ms)^([0-9a-f]+) <' + re.escape(name) +
                          r'>:\n(.*?)(?=^[0-9a-f]+ <|\Z)', text)
        require(match is not None, 'QUERY_ENTRY_SYMBOL')
        instructions = re.findall(r'^[ \t]*([0-9a-f]+):[ \t]+'
            r'((?:[0-9a-f]{4,8}[ \t]+)+)([a-z][a-z0-9.]*)[ \t]*(.*)$',
            match[2], re.M)
        require(len(instructions) == 2, 'QUERY_ENTRY_EXTENT')
        start = image.symbols[name][0] & ~1
        first, branch = instructions
        require(int(first[0],16) == start and
                sum(len(token)//2 for token in first[1].split()) == 4 and
                first[2:] == ('sg','') and
                int(branch[0],16) == start+4 and
                sum(len(token)//2 for token in branch[1].split()) == 4 and
                branch[2] in ('b','b.w') and
                int(branch[3].split()[0],16) ==
                    (image.symbols['__acle_se_'+name][0] & ~1),
                'QUERY_ENTRY_BRANCH')
    return {'ActualVeneers': 8, 'BytesCovered': 64, 'Status': 'PASS'}

def main():
    mode, path = sys.argv[1:3]
    if mode == 'execute':
        result = execute(json.loads(Path(path).read_text(encoding='utf-8-sig')))
    elif mode == 'reference':
        result = reference(path)
    elif mode == 'query-codegen':
        result = query_codegen(path)
    elif mode == 'query-bodies':
        result = query_bodies(path)
    elif mode == 'query-entries':
        result = query_entries(path)
    else:
        raise RuntimeError('unknown mode')
    print(json.dumps(result))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('REJECT:' + str(error))
        sys.exit(1)
