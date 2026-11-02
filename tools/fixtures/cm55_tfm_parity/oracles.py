"""Independent numeric scalar frame oracle applied to actual decoded code."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

from elf import require
from symbolic import Machine, Panic


def constructor_checks(fiber, reference):
    count = 0
    for top in (0x20004000, 0x20009000):
        for entry in (0x8004000, 0x8004001):
            for arg in (0, 0xCAFEBABE):
                for initial_r9 in (0x12345678, 0xFFFFFFFF):
                    actual = []
                    for is_fiber, body in ((True, fiber), (False, reference)):
                        s = Machine({})
                        ctx, base = 0x22000000, top-0x1000
                        # A C caller may already use live R9 for context_end.
                        # The builder must consume its explicit R1 argument.
                        s.r['r9'] = ctx+76
                        s.store(ctx, 0xBAD0BAD0)
                        for offset, value in ((12, base), (16, top), (24, entry), (28, arg)):
                            s.store(ctx+offset, value)
                        s.store(top-76, 0x11223344)
                        s.store(top, 0x55667788)
                        s.writes.clear()
                        def boot(m, a):
                            require(a[0] == ctx+4, 'CONSTRUCTOR', 'boot admission argument')
                            return 0
                        s.external['fiber_port_boot_record_check'] = boot
                        s.functions['constructor'] = body
                        if is_fiber:
                            s.run('constructor', ctx, initial_r9)
                            cursor = s.load(ctx)
                        else:
                            cursor = s.run('constructor', top, base, entry, arg)
                        words = [s.load(top-72+4*i) for i in range(18)]
                        require(cursor == top-72 and s.load(top-76) == 0x11223344 and s.load(top) == 0x55667788,
                                'CONSTRUCTOR', 'cursor/canary')
                        registers = [0]*8 if is_fiber else [int(f'{i:02d}'*4, 16) for i in range(4, 12)]
                        if is_fiber:
                            registers[5] = initial_r9
                        expected = [base, 0xFFFFFFBC, *registers, arg,
                            *([0]*4 if is_fiber else [0x01010101, 0x02020202, 0x03030303, 0x12121212]),
                            s.symbols['fiber_internal_task_return'] | 1 if is_fiber else s.symbols['prvTaskExitError'],
                            entry & ~1 if is_fiber else entry, 0x01000000]
                        require(words == expected, 'CONSTRUCTOR', 'independent 18-word values differ')
                        frame_writes = [a for a, size in s.writes if top-72 <= a < top]
                        require(sorted(frame_writes) == list(range(top-72, top, 4)), 'CONSTRUCTOR', 'each frame word written once')
                        require(all(0x2000EC00 <= a < 0x2000F000 or top-72 <= a < top or is_fiber and a == ctx
                                    for a, _ in s.writes), 'CONSTRUCTOR', 'out-of-frame store')
                        require([n for n, _ in s.trace] == (['fiber_port_boot_record_check'] if is_fiber else []),
                                'CONSTRUCTOR', 'unexpected constructor dependency')
                        actual.append(words)
                        count += 1
                    require(actual[0][:2] == actual[1][:2] and actual[0][10] == actual[1][10] and actual[0][17] == actual[1][17],
                            'CONSTRUCTOR', 'shared geometry/value relation')
    s = Machine({'constructor': fiber})
    try:
        s.run('constructor', 0, 0x12345678)
    except Panic as e:
        require(e.code == 67, 'CONSTRUCTOR', 'wrong NULL panic')
    else:
        require(False, 'CONSTRUCTOR', 'missing NULL panic')
    return count+1


def r9_capture_checks(constructor, builder, cohort):
    """Run actual caller+builder instructions with narrow admission providers.

    Boot creation/seal validity and full address-policy behavior are not proven
    here. Providers obey AAPCS and never clobber callee-saved R9. All observed
    R9 reuse comes from the actual compiled constructor instructions.
    """
    count = 0
    for ctx in (0x22000000, 0x22001000):
        for initial_r9 in (0, 0x12345678, 0x80808080, 0xFFFFFFFF):
            for corrupt_after_builder in (False, True):
                s = Machine({'fiber_port_context_init': constructor, 'fiber_port_init_context_frame': builder})
                begin, end, entry, arg = 0x20003000, 0x20006000, 0x08001001, 0xCAFEBABE
                s.r['r9'] = initial_r9
                for offset in range(76):
                    s.store(ctx+offset, 0xA5, 1)
                anchors = {0x21001000, 0x21001010}
                s.symbols.update(fiber_internal_runtime_port_abi_v1_anchor=0x21001000)
                s.symbols[cohort] = 0x21001010
                for address in anchors:
                    s.store(address, 1, 1)
                events, forwarded = [], []

                def instruction(m, op, operand):
                    if m.function == 'fiber_port_context_init' and op == 'mov' and operand.endswith(',r9'):
                        events.append(('r9-read', m.r['r9']))

                def read(m, address, size):
                    if address in anchors:
                        require(events and events[0] == ('r9-read', initial_r9), 'R9_CAPTURE', 'cold anchor read before entry R9 capture')
                        events.append(('cold-read', address))

                def call(m, name):
                    if name.startswith('fiber_addr_plausible_'):
                        require(events and events[0] == ('r9-read', initial_r9), 'R9_CAPTURE', 'address hook before entry R9 capture')
                        events.append(('hook', name))
                    if name == 'fiber_port_init_context_frame':
                        require(m.r['r0'] == ctx and m.r['r1'] == initial_r9, 'R9_CAPTURE', 'wrong captured R9 argument')
                        forwarded.append((m.r['r1'], m.r['r9']))

                def returned(m, name):
                    if name == 'fiber_port_init_context_frame' and corrupt_after_builder:
                        m.store(m.load(ctx)+28, initial_r9 ^ 0x101)

                def boot_create(m, a):
                    require(a[1:4] == [begin, end, entry] and m.load(m.r['sp']) == arg,
                            'R9_CAPTURE', 'boot factory AAPCS arguments')
                    # Actual factory's admitted result is an independently
                    # numbered 72-byte boot dictionary. Its seals are outside
                    # this narrow capture/forward/readback proof.
                    words = [begin, end, begin+8, end, end-begin-8, entry, arg,
                             0x43355446, 0x10001, 76, 4, 0x82, 0xFFFFFFBC, 0, 0, 0, 0, 0]
                    for i, word in enumerate(words):
                        m.store(a[0]+4*i, word)
                    return a[0]

                def copy(m, a):
                    require(a[0] == ctx+4 and a[2] == 72, 'R9_CAPTURE', 'boot copy extent')
                    data = [m.load(a[1]+i, 1) for i in range(a[2])]
                    for i, value in enumerate(data):
                        m.store(a[0]+i, value, 1)
                    return a[0]

                def validate_boot(m, a):
                    require(a[0] == ctx+4, 'R9_CAPTURE', 'builder boot admission argument')
                    return 0

                def validate_frame(m, a):
                    require(a[0] == ctx, 'R9_CAPTURE', 'initial-frame admission argument')
                    return 0

                s.external.update(fiber_addr_plausible_ram=lambda m, a: 1,
                    fiber_addr_plausible_code=lambda m, a: 1, fiber_port_boot_create=boot_create,
                    memcpy=copy, fiber_port_boot_record_check=validate_boot,
                    fiber_port_validate_initial_frame=validate_frame)
                s.instruction_observer, s.read_observer = instruction, read
                s.call_observer, s.return_observer = call, returned
                trapped = False
                try:
                    s.run('fiber_port_context_init', ctx, begin, end, entry, arg)
                except Panic as e:
                    require(corrupt_after_builder and e.code == 57, 'R9_CAPTURE', 'unexpected constructor panic ' + str(e.code))
                    trapped = True
                require(trapped == corrupt_after_builder, 'R9_CAPTURE', 'missing exact R9 readback panic')
                require(len(forwarded) == 1 and forwarded[0][0] != forwarded[0][1], 'R9_CAPTURE', 'fixture failed to exercise real compiler R9 reuse')
                require(len([e for e in events if e[0] == 'cold-read']) == 2 and any(e[0] == 'hook' for e in events),
                        'R9_CAPTURE', 'cold-anchor/hook path not exercised')
                if not corrupt_after_builder:
                    require(s.load(s.load(ctx)+28) == initial_r9, 'R9_CAPTURE', 'stored entry R9 changed')
                count += 1
    return count


def transfer_checks(fiber, reference, svc):
    count = 0
    for raw in (0x20004000, 0x20008000):
        for r9 in (0xA9A9A9A9, 0xFFFFFFFF):
            saved = []
            for is_fiber, body in ((True, fiber), (False, reference)):
                s = Machine({})
                ctx, base = 0x22000000, raw-0x1000
                s.cpu.update(psp=raw, psplim=base)
                s.r.update(r0=raw, r1=ctx, lr=0xFFFFFFBC)
                s.r['r9'] = r9
                values = [s.r['r'+str(i)] for i in range(4, 12)]
                s.store(ctx, 0)
                s.store(ctx+12, base)
                # Closed complete bodies are checked separately. Here only
                # data-transfer slices run, with a fixture return sentinel.
                start, end = (41, 49) if is_fiber else (0, 4)
                s.execute(body[start:end] + [('bx', 'lr')])
                cursor = s.r['r0']
                require(cursor == raw-40, 'TRANSFER', 'save cursor')
                expected = [base, 0xFFFFFFBC, *values]
                require([s.load(cursor+4*i) for i in range(10)] == expected, 'TRANSFER', 'save slot order')
                if is_fiber:
                    require(s.load(ctx) == cursor, 'TRANSFER', 'published cursor')
                for i in range(2, 12):
                    s.r['r'+str(i)] = 0xDEAD0000+i
                s.r.update(r0=cursor, r1=ctx)
                s.cpu.update(psp=0xBAD00000, psplim=0xBAD00004)
                s.execute((body[65:81] if is_fiber else body[17:20]) + [('bx', 'lr')])
                require(s.cpu['psp'] == raw and s.cpu['psplim'] == base and s.r['r3'] == 0xFFFFFFBC,
                        'TRANSFER', 'restore cursor/limits/EXC_RETURN')
                require([s.r['r'+str(i)] for i in range(4, 12)] == values, 'TRANSFER', 'restore GPR inverse')
                if is_fiber:
                    s.r.update(r2=ctx, r0=0, r9=0xBAD00009)
                    s.cpu.update(control=0, psp=0)
                    s.execute(svc[48:71] + [('bx', 'lr')])
                    require(s.r['r9'] == r9 and s.cpu['control'] == 2 and s.cpu['psp'] == raw,
                            'TRANSFER', 'first restore/live CONTROL2')
                    count += 1
                saved.append(expected)
                count += 1
            require(saved[0] == saved[1], 'TRANSFER', 'reference/Fiber software layout')
    return count
