"""Bounded M33 branch interpreter derived from the frozen C5TF fixture.

This is neither an ARM emulator nor CPU/exception/security qualification.
External calls and register values are explicit admission assumptions.
"""
import re
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

from elf import require

MASK = 0xFFFFFFFF


class Panic(Exception):
    def __init__(self, code):
        self.code = code


class Machine:
    def __init__(self, functions):
        self.functions = functions
        self.r = {"r" + str(i): 0xA0000000 + i for i in range(13)}
        self.r.update(sp=0x2000F000, lr=0x101)
        self.cpu = dict(ipsr=0, primask=0, basepri=0, faultmask=0, control=0, psplim=0, psp=0, msp=0)
        self.mem, self.writes, self.trace, self.external = {}, [], [], {}
        self.function = None
        self.instruction_observer = self.read_observer = None
        self.call_observer = self.return_observer = None
        self.symbols = {"fiber_internal_task_return": 0x8001010, "prvTaskExitError": 0x8002021,
                        ".bss.fiber_port_tfm_initialization_state": 0x21000000,
                        ".bss.fiber_port_tfm_mutex": 0x21000100,
                        "xSecureMutexBuffer": 0x21000200}
        self.z, self.n, self.c, self.v = False, False, False, False
        self.steps = 0
        for address in range(0x2000EC00, 0x2000F000):
            self.mem[address] = 0xA5
        for address in range(0x21000000, 0x21000300):
            self.mem[address] = 0

    def load(self, address, count=4):
        if self.read_observer:
            self.read_observer(self, address, count)
        require(all(address+i in self.mem for i in range(count)), "SYMBOLIC", "uninitialized/out-of-range read " + hex(address))
        return sum(self.mem[address+i] << (8*i) for i in range(count))

    def store(self, address, value, count=4):
        require(address % count == 0, "SYMBOLIC", "unaligned write")
        self.writes.append((address, count))
        for i in range(count):
            self.mem[address+i] = (value >> (8*i)) & 255

    def value(self, text):
        if text.startswith("#"):
            return int(text[1:]) & MASK
        if text.startswith("="):
            name, addend = text[1:].rsplit("+", 1) if "+" in text else (text[1:], "0")
            if name.isdecimal():
                return int(name)
            require(name in self.symbols, "SYMBOLIC", "unknown data address " + name)
            return self.symbols[name] + int(addend)
        require(text in self.r, "SYMBOLIC", "unknown register " + text)
        return self.r[text]

    def condition(self, text):
        return dict(eq=self.z, ne=not self.z, cs=self.c, cc=not self.c,
                    hi=self.c and not self.z, ls=not self.c or self.z,
                    mi=self.n, pl=not self.n, ge=self.n == self.v,
                    lt=self.n != self.v, gt=not self.z and self.n == self.v,
                    le=self.z or self.n != self.v)[text]

    def flags(self, value, carry=None, overflow=False):
        self.z, self.n = not (value & MASK), bool(value & 0x80000000)
        if carry is not None:
            self.c, self.v = carry, overflow

    def address(self, arg):
        m = re.fullmatch(r"\[(r\d+|sp),#(-?\d+)\](!?)", arg)
        require(m is not None, "SYMBOLIC", "unsupported addressing " + arg)
        address = (self.r[m[1]] + int(m[2])) & MASK
        if m[3]:
            self.r[m[1]] = address
        return address

    def external_call(self, name):
        args = [self.r['r'+str(i)] for i in range(4)]
        self.trace.append((name, args))
        if name == "fiber_panic":
            raise Panic(args[0])
        require(name in self.external, "SYMBOLIC", "unprovided external call " + name)
        result = self.external[name](self, args)
        for i in (0, 1, 2, 3, 12):
            self.r['r'+str(i)] = 0xDEAD0000 + i
        self.r['lr'] = 0xDEAD0014
        self.r['r0'] = result & MASK

    def execute(self, body):
        ip = 0
        while ip < len(body):
            self.steps += 1
            require(self.steps < 10000, "SYMBOLIC", "nontermination")
            op, arg = body[ip]
            ip += 1
            if self.instruction_observer:
                self.instruction_observer(self, op, arg)
            a = arg.split(',')
            if op in ('it', 'ite', 'nop', 'dsb', 'isb', 'dmb'):
                continue
            if op in ('moveq', 'movne', 'mrseq', 'mrsne'):
                if not self.condition(op[-2:]):
                    continue
                op = op[:-2]
            if op in ('b', 'beq', 'bne', 'bcc', 'bcs', 'bhi', 'bls', 'bmi', 'bpl', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz'):
                take = op == 'b' or (op not in ('cbz', 'cbnz') and self.condition(op[1:]))
                target = arg
                if op in ('cbz', 'cbnz'):
                    target = a[1]
                    take = (self.value(a[0]) == 0) == (op == 'cbz')
                if take:
                    if target.startswith('@'):
                        ip = int(target[1:])
                    else:
                        self.call(target)
                        return
                continue
            if op == 'bl':
                self.r['lr'] = 0x101
                self.call(arg)
                continue
            if op == 'bx':
                require(arg == 'lr' or self.r[arg] in (0xFFFFFFBC, 0xFFFFFFFC, 0xFFFFFFFD), "SYMBOLIC", "unexpected branch register")
                self.return_target = self.r[arg]
                return
            if op in ('stmdb', 'ldmia'):
                m = re.fullmatch(r"(r\d+|sp)(!?),\{([^}]+)\}", arg)
                require(m is not None, "SYMBOLIC", "transfer syntax")
                base, update, regs = m[1], m[2], m[3].split(',')
                address = self.r[base] - (4*len(regs) if op == 'stmdb' else 0)
                values = [self.r.get(reg, 0x101) for reg in regs] if op == 'stmdb' else [self.load(address+4*i) for i in range(len(regs))]
                for i, reg in enumerate(regs):
                    if op == 'stmdb':
                        self.store(address+4*i, values[i])
                    elif reg != 'pc':
                        self.r[reg] = values[i]
                if update:
                    self.r[base] = address if op == 'stmdb' else address+4*len(regs)
                if 'pc' in regs:
                    return
                continue
            if op in ('ldr', 'ldrb', 'ldrd', 'str', 'strb', 'strd'):
                if op == 'ldr' and a[1].startswith('='):
                    self.r[a[0]] = self.value(a[1])
                    continue
                offset = 2 if op in ('strd', 'ldrd') else 1
                address = self.address(','.join(a[offset:]))
                if op.startswith('ldr'):
                    self.r[a[0]] = self.load(address, 1 if op == 'ldrb' else 4)
                    if op == 'ldrd':
                        self.r[a[1]] = self.load(address+4)
                else:
                    self.store(address, self.r[a[0]], 1 if op == 'strb' else 4)
                    if op == 'strd':
                        self.store(address+4, self.r[a[1]])
                continue
            if op in ('mov', 'movs', 'mvn'):
                value = self.value(a[1])
                self.r[a[0]] = value ^ MASK if op == 'mvn' else value
                if op == 'movs':
                    self.flags(value)
                continue
            if op == 'mrs':
                require(a[1] in self.cpu, "SYMBOLIC", "unknown CPU register")
                self.r[a[0]] = self.cpu[a[1]]
                continue
            if op == 'msr':
                require(a[0] in self.cpu, "SYMBOLIC", "unknown CPU register")
                self.cpu[a[0]] = self.value(a[1])
                continue
            if op in ('cpsid', 'cpsie'):
                self.cpu['primask' if arg == 'i' else 'faultmask'] = int(op == 'cpsid')
                continue
            if op == 'cmn':
                x, y = self.value(a[0]), self.value(a[1])
                value = (x+y) & MASK
                self.flags(value, x+y > MASK, bool((~(x ^ y) & (x ^ value)) & 0x80000000))
                continue
            if op in ('cmp', 'tst'):
                x, y = self.value(a[0]), self.value(a[1])
                self.flags(x-y if op == 'cmp' else x & y, x >= y if op == 'cmp' else None,
                           bool((x ^ y) & (x ^ ((x-y) & MASK)) & 0x80000000))
                continue
            if op in ('add', 'adds', 'sub', 'subs', 'and', 'orr', 'orrs', 'bic', 'eor', 'eors', 'lsls', 'lsrs', 'negs', 'adcs'):
                dest = a[0]
                x = self.value(a[1]) if len(a) == 3 or op == 'negs' else self.r[dest]
                y = self.value(a[2]) if len(a) == 3 else (0 if op == 'negs' else self.value(a[1]))
                if op in ('add', 'adds', 'adcs'):
                    value = x+y+(int(self.c) if op == 'adcs' else 0)
                    carry = value > MASK
                elif op in ('sub', 'subs', 'negs'):
                    value = -x if op == 'negs' else x-y
                    carry = x == 0 if op == 'negs' else x >= y
                else:
                    value = {'and': lambda: x & y, 'orr': lambda: x | y, 'orrs': lambda: x | y,
                             'bic': lambda: x & ~y, 'eor': lambda: x ^ y, 'eors': lambda: x ^ y,
                             'lsls': lambda: x << y, 'lsrs': lambda: x >> y}[op]()
                    carry = bool((x >> (32-y if op == 'lsls' else y-1)) & 1) if op in ('lsls', 'lsrs') and y else None
                self.r[dest] = value & MASK
                if op.endswith('s'):
                    self.flags(value, carry)
                continue
            if op == 'ubfx':
                self.r[a[0]] = (self.value(a[1]) >> self.value(a[2])) & ((1 << self.value(a[3]))-1)
                continue
            if op == 'uxtb':
                self.r[a[0]] = self.value(a[1]) & 255
                continue
            if op == 'clz':
                self.r[a[0]] = 32 - self.value(a[1]).bit_length()
                continue
            require(False, "SYMBOLIC", "unimplemented instruction " + op + ' ' + arg)
        require(False, "SYMBOLIC", "function fell through")

    def call(self, name):
        if self.call_observer:
            self.call_observer(self, name)
        previous = self.function
        self.function = name
        try:
            if name in self.functions:
                self.execute(self.functions[name])
            else:
                self.external_call(name)
        finally:
            self.function = previous
        if self.return_observer:
            self.return_observer(self, name)

    def run(self, name, *args):
        saved = {r: self.r[r] for r in ('sp', *('r'+str(i) for i in range(4, 12)))}
        self.r['lr'] = 0x101
        for i, arg in enumerate(args):
            if i < 4:
                self.r['r'+str(i)] = arg
            else:
                self.store(self.r['sp']+4*(i-4), arg)
        self.steps = 0
        self.call(name)
        require(all(self.r[r] == value for r, value in saved.items()), "SYMBOLIC", "callee-saved register/stack drift " + name)
        return self.r['r0']
