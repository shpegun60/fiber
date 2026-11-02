"""Numeric oracles over actual decoded instructions, not CPU/TF-M execution."""
import importlib.util
from pathlib import Path
import re
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

from elf import require

HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


integer = load_module('c3ft_integer', HERE.parent/'cm33_secure_parity/machine.py')
protected = load_module('c3ft_transfer', HERE.parent/'cm33f_mpu_running_parity/check.py')
CPACR, FPCCR, MASK = 0xE000ED88, 0xE000EF34, 0xFFFFFFFF


class State(integer.Machine):
    def __init__(self, functions):
        super().__init__(functions)
        self.store(CPACR, 0x00F00000)
        self.store(FPCCR, 0x80000000)

    def execute(self, body):
        # The shared integer engine has AND, but not Thumb's two-register
        # flag-setting ANDS. Keep the closed stream untouched; this execution
        # view performs its identical bit operation and then updates N/Z.
        observer, pending = self.instruction_observer, []

        def observe(m, op, arg):
            if pending:
                m.flags(m.r[pending.pop()])
            if observer:
                observer(m,op,arg)

        translated = []
        flagged = {arg for op,arg in body if op == 'ands'}
        require(not any(op == 'and' and arg in flagged for op,arg in body),
                'SYMBOLIC','ambiguous AND/ANDS execution view')
        for op,arg in body:
            if op == 'ands':
                require(re.fullmatch(r'r\d+,r\d+',arg) is not None,'SYMBOLIC','unsupported ANDS form')
                op = 'and'
            translated.append((op,arg))

        def with_flags(m,op,arg):
            observe(m,op,arg)
            if op == 'and' and arg in flagged:
                pending.append(arg.split(',')[0])

        self.instruction_observer = with_flags
        try:
            super().execute(translated)
        finally:
            if pending:
                self.flags(self.r[pending.pop()])
            self.instruction_observer = observer


def panic(state, code, name, *args):
    try:
        state.run(name, *args)
    except integer.Panic as e:
        require(e.code == ord(code), 'POLICY', name+'/wrong panic '+str(e.code))
    else:
        require(False, 'POLICY', name+'/missing panic '+code)


def constructor(fiber, reference):
    count = 0
    for top in (0x20004000, 0x20009000):
        for entry in (0x08004000, 0x08004001):
            for arg in (0, 0xCAFEBABE):
                for seed in (0x12345678, MASK):
                    for is_fiber, body in ((True, fiber), (False, reference)):
                        s, ctx, base = State({'constructor': body}), 0x22000000, top-0x1000
                        s.r['r9'] = seed
                        s.store(ctx, 0xBAD0BAD0)
                        for offset, value in ((12, base), (16, top), (24, entry), (28, arg)):
                            s.store(ctx+offset, value)
                        s.store(top-76, 0x11223344)
                        s.store(top, 0x55667788)
                        s.writes.clear()

                        def admit(m, a):
                            require(a[0] == ctx+4, 'CONSTRUCTOR', 'boot admission argument')
                            return 0

                        s.external['fiber_port_boot_record_check'] = admit
                        cursor = s.run('constructor', *( (ctx,) if is_fiber else (top, base, entry, arg) ))
                        if is_fiber:
                            cursor = s.load(ctx)
                        registers = [0]*8 if is_fiber else [int(f'{n:02d}'*4, 16) for n in range(4,12)]
                        if is_fiber:
                            registers[5] = seed
                        expected = [base, 0xFFFFFFBC, *registers, arg,
                            *([0]*4 if is_fiber else [0x01010101,0x02020202,0x03030303,0x12121212]),
                            s.symbols['fiber_internal_task_return']|1 if is_fiber else s.symbols['prvTaskExitError'],
                            entry & ~1 if is_fiber else entry, 0x01000000]
                        require(cursor == top-72 and [s.load(cursor+4*n) for n in range(18)] == expected,
                                'CONSTRUCTOR', 'independent basic image/cursor')
                        require(s.load(top-76) == 0x11223344 and s.load(top) == 0x55667788,
                                'CONSTRUCTOR', 'frame canaries')
                        frame_writes = [a for a, _ in s.writes if top-72 <= a < top]
                        require(sorted(frame_writes) == list(range(top-72,top,4)), 'CONSTRUCTOR', 'each basic word written once')
                        require(all(0x2000EC00 <= a < 0x2000F000 or top-72 <= a < top or is_fiber and a == ctx for a,_ in s.writes),
                                'CONSTRUCTOR', 'out-of-frame store')
                        require([n for n,_ in s.trace] == (['fiber_port_boot_record_check'] if is_fiber else []),
                                'CONSTRUCTOR', 'unexpected dependency')
                        count += 1
    panic(State({'constructor':fiber}), 'C', 'constructor', 0)
    return count+1


def first_start(fiber, reference):
    class AtSvc(Exception):
        pass

    count = 0
    for is_fiber, functions, name in ((True,fiber,'fiber_port_start_first_context'),
                                     (False,reference,'vStartFirstTask')):
        for msp in (0x20008000,0x2000A000):
            s = State(functions)
            s.cpu.update(primask=1,msp=0x20006000,control=4 if is_fiber else 0)
            s.store(0xE000ED08,0x08000000)
            s.store(0x08000000,msp)
            s.r['r0'] = msp

            def stop(m, op, arg):
                if op == 'svc':
                    require(int(arg) == (70 if is_fiber else 102), 'POLICY','actual first-start SVC number')
                    require({k:m.cpu[k] for k in ('control','primask','basepri','faultmask','msp')} ==
                            dict(control=0,primask=0,basepri=0,faultmask=0,msp=msp),
                            'POLICY','numeric first-SVC CPU preparation')
                    raise AtSvc()

            s.instruction_observer = stop
            try:
                s.call(name)
            except AtSvc:
                count += 1
            else:
                require(False,'POLICY','first start did not reach its one SVC')
    return count


def first_restore(fiber, reference):
    count = 0
    for is_fiber,functions,name in ((True,fiber,'SVC_Handler'),(False,reference,'vRestoreContextOfFirstTask')):
        for seed in (0x10203040,0xE1E2E3E4):
            s,ctx,cursor,raw,base = State(functions),0x22000000,0x20004000,0x20004028,0x20003000
            s.cpu.update(ipsr=11,control=0,primask=0,msp=0x20000800)
            s.symbols.update(fiber_internal_runtime_current_context_slot=0x30002000,pxCurrentTCB=0x30002000)
            s.store(0x30002000,ctx)
            s.store(ctx,cursor)
            words = [base,0xFFFFFFBC,*[0xAA000000+n for n in range(4,12)]]
            words[7] = seed
            for n,v in enumerate(words):
                s.store(cursor+4*n,v)
            s.store(0x20000800+28,0x01000000)
            s.store(0x20000800+24,0x08004002)
            s.store(0x08004000,70,1)
            s.store(0x08004001,0xDF,1)
            s.r['lr'] = 0xFFFFFFB8
            s.external['fiber_port_context_validate_restore'] = lambda m,a: (
                require(a[0] == ctx,'POLICY','first restore context admission argument') or 0)
            s.call(name)
            require((s.cpu['psp'],s.cpu['psplim'],s.cpu['control'],s.cpu['basepri']) == (raw,base,2,0),
                    'POLICY','first restore shared PSP/PSPLIM/CONTROL/BASEPRI')
            require(s.return_target == 0xFFFFFFBC,'POLICY','first exception return template')
            if is_fiber:
                require([s.r['r'+str(n)] for n in range(4,12)] == words[2:],
                        'POLICY','Fiber restores initialized GPRs including private R9 seed')
                require([n for n,_ in s.trace] == ['fiber_port_context_validate_restore'],
                        'POLICY','first restore dependency order')
                require(s.cpu['primask'] == 0,'POLICY','first restore unmasks after publication')
            count += 1
    return count


class Transfer(protected.Transfer):
    """Reuse the reviewed bit-transfer engine, adding non-MPU control flow."""
    def run(self, body, begin, end):
        pc, predicate = begin, 0
        while pc < end:
            op, arg = body[pc]
            pc += 1
            if op in ('it', 'ittt'):
                require(arg == 'eq' and predicate == 0, 'FP_TRANSFER', 'IT state')
                predicate = 1 if op == 'it' else 3
                continue
            if predicate:
                require(op.endswith('eq'), 'FP_TRANSFER', 'predicated operation')
                predicate -= 1
                op = op[:-2]
                if not self.equal:
                    continue
            if op in ('b','beq','bne'):
                if op == 'b' or self.equal == (op == 'beq'):
                    pc = int(arg[1:])
                    require(begin <= pc <= end, 'FP_TRANSFER', 'branch escaped admitted transfer')
                continue
            if op in ('dsb','isb','dmb','nop'):
                continue
            if op in ('mov','movs','mvn'):
                a,b = arg.split(',')
                value = int(b[1:]) if b.startswith('#') else self.registers[b]
                self.registers[a] = value ^ MASK if op == 'mvn' else value
                if op == 'movs':
                    self.equal = value == 0
                continue
            if op == 'bic':
                dst,src,mask = arg.split(',')
                require(mask.startswith('#'), 'FP_TRANSFER', 'BIC operand')
                self.registers[dst] = self.registers[src] & (~int(mask[1:]) & MASK)
                continue
            if op == 'ldr':
                match = re.fullmatch(r'(r\d+),\[(r\d+),#(\d+)\]',arg)
                if match:
                    address = self.registers[match[2]]+int(match[3])
                    require(address in self.memory, 'FP_TRANSFER', 'unseeded metadata read')
                    self.registers[match[1]] = self.memory[address]
                else:
                    require(arg in ('r2,=pxCurrentTCB+0','r1,=pxCurrentTCB+0'), 'FP_TRANSFER', 'unexpected literal')
                    self.registers[arg.split(',')[0]] = 0x30002000
                continue
            try:
                super().run([(op,arg)],0,1)
            except protected.Rejected as e:
                require(False, 'FP_TRANSFER', str(e))
        require(predicate == 0, 'FP_TRANSFER', 'incomplete IT')


def unique(body, predicate, name):
    found = [n for n,row in enumerate(body) if predicate(row)]
    require(len(found) == 1, 'FP_TRANSFER', 'ambiguous/missing '+name)
    return found[0]


def slices(body):
    high = unique(body, lambda r:r[0] in ('vstmdb','vstmdbeq'), 'high FP save')
    publish = unique(body, lambda r:r == ('str','r0,[r1,#0]'), 'cursor publication')
    restore = unique(body, lambda r:r == ('ldmia','r0!,{r2,r3,r4,r5,r6,r7,r8,r9,r10,r11}'), 'core restore')
    psp = unique(body, lambda r:r == ('msr','psp,r0'), 'PSP restore')
    require(high >= 2 and high < publish < restore < psp, 'FP_TRANSFER', 'transfer ordering')
    return high-2,publish+1,restore,psp+1


def transfer(fiber, reference):
    count = 0
    for is_fiber, body in ((True,fiber),(False,reference)):
        save, saved, restore, restored = slices(body)
        for outgoing in (False,True):
            for incoming in (False,True):
                for seed in (0x10203040,0xE1E2E3E4):
                    states = []
                    for task,form in enumerate((outgoing,incoming)):
                        s = Transfer(form)
                        s.context += task*0x100
                        s.special['psp'] += task*0x1000
                        s.special['psplim'] += task*0x1000
                        raw, ctx, base = s.special['psp'], s.context, s.special['psplim']
                        s.memory.clear()
                        for n in range(26):
                            s.memory[raw+4*n] = 'TASK%d_HW%d' % (task,n)
                        for n in range(4,12):
                            s.registers['r'+str(n)] = 'TASK%d_R%d' % (task,n)
                        for n in range(16,32):
                            s.registers['s'+str(n)] = 'TASK%d_S%d' % (task,n)
                        s.registers.update(r0=raw,r1=ctx)
                        s.registers['r9'] = seed ^ (task << 8)
                        s.memory.update({ctx:0,ctx+12:base,0x30002000:ctx})
                        hardware = {a:v for a,v in s.memory.items() if raw <= a <= raw+100}
                        gpr = [s.registers['r'+str(n)] for n in range(4,12)]
                        high = [s.registers['s'+str(n)] for n in range(16,32)]
                        s.writes.clear()
                        s.run(body,save,saved)
                        cursor = raw-(104 if form else 40)
                        expected = [base,0xFFFFFFAC if form else 0xFFFFFFBC,*gpr,*high] if form else [base,0xFFFFFFBC,*gpr]
                        require(s.memory[ctx] == cursor and [s.memory.get(cursor+4*n) for n in range(len(expected))] == expected,
                                'FP_TRANSFER','numeric software image/cursor')
                        require(sorted(s.writes) == sorted([ctx,*range(cursor,raw,4)]), 'FP_TRANSFER','save extent/write count')
                        require(all(s.memory[a] == value for a,value in hardware.items()), 'FP_TRANSFER','hardware core/low-FP image changed')
                        states.append((s,raw,base,gpr,high,hardware))
                    s = states[0][0]
                    incoming_state,raw,base,gpr,high,hardware = states[1]
                    outgoing_high = [s.registers['s'+str(n)] for n in range(16,32)]
                    outgoing_cursor = s.memory[s.context]
                    outgoing_image = {a:v for a,v in s.memory.items() if outgoing_cursor <= a < states[0][1]}
                    s.memory.update(incoming_state.memory)
                    for n in range(2,12):
                        s.registers['r'+str(n)] = 'POISON_R'+str(n)
                    s.registers['r0'] = s.memory[incoming_state.context]
                    s.special.update(psp=0xBAD00000,psplim=0xBAD00004)
                    s.run(body,restore,restored)
                    require(s.special['psp'] == raw and s.special['psplim'] == base,
                            'FP_TRANSFER','restored PSP/PSPLIM')
                    require([s.registers['r'+str(n)] for n in range(4,12)] == gpr, 'FP_TRANSFER','GPR inverse')
                    require(s.registers['r3'] == (0xFFFFFFAC if incoming else 0xFFFFFFBC), 'FP_TRANSFER','EXC_RETURN inverse')
                    expected_fp = high if incoming else outgoing_high
                    require([s.registers['s'+str(n)] for n in range(16,32)] == expected_fp, 'FP_TRANSFER','conditional high-FP inverse')
                    require(s.special_writes[-2:] == [('psplim',base),('psp',raw)], 'FP_TRANSFER','limit/PSP order')
                    require(all(s.memory[a] == value for a,value in hardware.items()), 'FP_TRANSFER','hardware image changed on restore')
                    require(all(s.memory[a] == value for a,value in outgoing_image.items()), 'FP_TRANSFER','outgoing saved image changed')
                    count += 1
    return count


def fpu(functions, reference):
    count = 0
    for cpacr in (0,0x00100000,0x00F00000,0xA0F01234):
        for fpccr in (0,0x40000000,0x80001200,0xC0001200):
            for funcs, name, lazy in ((functions,'fiber_port_fpu_prepare',False),(reference,'prvSetupFPU',True)):
                s = State(funcs)
                s.store(CPACR,cpacr)
                s.store(FPCCR,fpccr)
                s.run(name)
                expected = fpccr | 0xC0000000 if lazy else (fpccr | 0x80000000) & ~0x40000000
                require((s.load(CPACR),s.load(FPCCR)) == (cpacr|0x00F00000,expected),
                        'FPU','numeric eager/lazy policy/preserved unrelated bits')
                count += 1
    s = State(functions)
    s.store(FPCCR,0x80000001)
    s.run('fiber_port_fpu_require_configured')
    panic(s,'E','fiber_port_fpu_require_ready')
    return count+2


def policy(init, wrapper, reference):
    functions, count = dict(init,**wrapper), 0
    state, mutex = 0x21000000,0x21000100
    for initial,result,expected in ((0,0,0),(0,MASK,MASK),(1,0,MASK),(2,MASK,0),(3,0,MASK)):
        for control in (0,4):
            s,calls = State(functions),[]
            s.cpu['control'] = control
            s.store(state,initial)

            def provider(m,a):
                require(m.load(state) == 1,'POLICY','INITIALIZING before provider')
                calls.append(1)
                return result

            s.external['tfm_ns_interface_init'] = provider
            for _ in range(2):
                require(s.run('fiber_port_tfm_initialize') == expected,'POLICY','sticky init/repeat result')
                count += 1
            require(len(calls) == int(initial == 0),'POLICY','one-shot call count')
            wanted = (2 if result == 0 else 3) if initial == 0 else initial
            require(s.load(state) == wanted,'POLICY','sticky state')
    for reg,code in (('ipsr','i'),('primask','p'),('basepri','b'),('faultmask','f'),('control','l'),('psplim','L'),('cpacr','e'),('fpccr','E')):
        s = State(functions)

        def corrupt(m,a,reg=reg):
            if reg in ('cpacr','fpccr'):
                addr = CPACR if reg == 'cpacr' else FPCCR
                m.store(addr,m.load(addr)^1)
            else:
                m.cpu[reg] ^= 4 if reg == 'control' else 1
            return 0

        s.external['tfm_ns_interface_init'] = corrupt
        panic(s,code,'fiber_port_tfm_initialize')
        require(s.load(state) == 1,'POLICY','READY published despite corrupt provider')
        count += 1
    for control in (2,6):
        s,current,yielded = State(functions),0x22000000,[]
        s.external['fiber_current'] = lambda m,a:current

        def schedule(m,a):
            require(m.cpu['primask'] == 0 and m.load(mutex) == current+4,'POLICY','masked cooperative retry')
            yielded.append(1)
            m.store(mutex,0)
            return 0

        s.external['fiber_port_runtime_schedule'] = schedule
        require(s.run('os_wrapper_mutex_create') == mutex and s.run('os_wrapper_mutex_create') == 0,'POLICY','single static mutex')
        s.cpu['control'] = control
        for name,args,expected in (
            ('os_wrapper_mutex_acquire',(0,0),MASK),('os_wrapper_mutex_acquire',(mutex,0),0),
            ('os_wrapper_mutex_acquire',(mutex,MASK),MASK),('os_wrapper_mutex_delete',(mutex,),MASK),
            ('os_wrapper_mutex_release',(mutex+4,),MASK),('os_wrapper_mutex_release',(mutex,),0),
            ('os_wrapper_mutex_release',(mutex,),MASK)):
            require(s.run(name,*args) == expected and s.cpu['primask'] == 0,'POLICY','owner/recursive/handle/mask')
            count += 1
        s.store(mutex,current+4)
        for timeout in (0,5):
            require(s.run('os_wrapper_mutex_acquire',mutex,timeout) == MASK and not yielded,'POLICY','finite timeout is polling')
            count += 1
        require(s.run('os_wrapper_mutex_acquire',mutex,MASK) == 0 and len(yielded) == 1,'POLICY','unmasked cooperative retry')
        require(s.run('os_wrapper_mutex_release',mutex) == 0 and s.run('os_wrapper_mutex_delete',mutex) == 0,'POLICY','owner release/free-only delete')
        count += 4
    for timeout in (0,5,MASK):
        for result in (0,1):
            s = State(reference)
            s.external['xQueueSemaphoreTake'] = lambda m,a,result=result:result
            require(s.run('os_wrapper_mutex_acquire',mutex,timeout) == (0 if result else MASK),'POLICY','reference semaphore result')
            require(s.trace[0][1][:2] == [mutex,timeout],'POLICY','reference timeout forwarding')
            count += 1
    return count
