"""Bounded instruction data-flow cases for the declared TF-M policy."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

from elf import require
from symbolic import Machine, Panic, MASK


def expect_panic(machine, code, name, *args):
    try:
        machine.run(name, *args)
    except Panic as e:
        require(e.code == ord(code), 'POLICY', 'wrong panic ' + name + '/' + str(e.code))
        return
    require(False, 'POLICY', 'missing panic ' + name)


def policy_checks(init, wrapper, refwrapper):
    count = 0
    all_functions = dict(init, **wrapper)
    state, mutex = 0x21000000, 0x21000100
    for initial, provider_result, expected in ((0, 0, 0), (0, MASK, MASK), (1, 0, MASK), (2, MASK, 0), (3, 0, MASK)):
        s = Machine(all_functions)
        s.store(state, initial)
        calls = []
        def provider(m, a):
            require(m.load(state) == 1, 'POLICY', 'INITIALIZING precedes TF-M provider')
            calls.append(1)
            return provider_result
        s.external['tfm_ns_interface_init'] = provider
        for _ in range(2):
            require(s.run('fiber_port_tfm_initialize') == expected, 'POLICY', 'init/repeat result')
            count += 1
        require(len(calls) == int(initial == 0), 'POLICY', 'one-shot provider call count')
        wanted = (2 if provider_result == 0 else 3) if initial == 0 else initial
        require(s.load(state) == wanted, 'POLICY', 'sticky state')
    for reg, code in (('ipsr', 'i'), ('primask', 'p'), ('basepri', 'b'), ('faultmask', 'f'), ('control', 'l'), ('psplim', 'L')):
        s = Machine(all_functions)
        def corrupt(m, a, reg=reg):
            m.cpu[reg] ^= 1
            return 0
        s.external['tfm_ns_interface_init'] = corrupt
        expect_panic(s, code, 'fiber_port_tfm_initialize')
        count += 1

    s = Machine(all_functions)
    current = 0x22000000
    s.external['fiber_current'] = lambda m, a: current
    yielded = []
    def yield_now(m, a):
        require(m.cpu['primask'] == 0 and m.load(mutex) == current+4, 'POLICY', 'masked/bad cooperative yield')
        yielded.append(1)
        m.store(mutex, 0)
        return 0
    s.external['fiber_port_runtime_schedule'] = yield_now
    require(s.run('os_wrapper_mutex_create') == mutex and s.run('os_wrapper_mutex_create') == 0,
            'POLICY', 'single static mutex')
    count += 2
    s.cpu['control'] = 2
    cases = [('os_wrapper_mutex_acquire', (0, 0), MASK), ('os_wrapper_mutex_acquire', (mutex+4, 0), MASK),
             ('os_wrapper_mutex_acquire', (mutex, 0), 0), ('os_wrapper_mutex_acquire', (mutex, MASK), MASK),
             ('os_wrapper_mutex_delete', (mutex,), MASK), ('os_wrapper_mutex_release', (mutex+4,), MASK),
             ('os_wrapper_mutex_release', (mutex,), 0), ('os_wrapper_mutex_release', (mutex,), MASK)]
    for name, args, expected in cases:
        require(s.run(name, *args) == expected and s.cpu['primask'] == 0, 'POLICY', 'wrapper result/mask ' + name)
        count += 1
    s.store(mutex, current+4)
    for timeout in (0, 5):
        require(s.run('os_wrapper_mutex_acquire', mutex, timeout) == MASK and not yielded, 'POLICY', 'finite wait is polling')
        count += 1
    require(s.run('os_wrapper_mutex_release', mutex) == MASK, 'POLICY', 'foreign owner release')
    require(s.run('os_wrapper_mutex_acquire', mutex, MASK) == 0 and len(yielded) == 1 and s.load(mutex) == current,
            'POLICY', 'WAIT_FOREVER cooperative retry/owner')
    require(s.run('os_wrapper_mutex_release', mutex) == 0 and s.run('os_wrapper_mutex_delete', mutex) == 0 and
            s.run('os_wrapper_mutex_delete', mutex) == MASK, 'POLICY', 'free-only delete')
    count += 5
    for reg, value, code in (('ipsr', 1, 'i'), ('primask', 1, 'p'), ('control', 0, 'l')):
        t = Machine(all_functions)
        t.external['fiber_current'] = lambda m, a: current
        t.cpu.update(control=2)
        t.cpu[reg] = value
        expect_panic(t, code, 'os_wrapper_mutex_acquire', mutex, 0)
        count += 1

    for timeout in (0, 5, MASK):
        for result in (0, 1):
            r = Machine(refwrapper)
            r.external['xQueueSemaphoreTake'] = lambda m, a, result=result: result
            require(r.run('os_wrapper_mutex_acquire', mutex, timeout) == (0 if result == 1 else MASK),
                    'POLICY', 'pinned semaphore status')
            require(r.trace[0][1][:2] == [mutex, timeout], 'POLICY', 'pinned timeout forwarding')
            count += 1
    r = Machine(refwrapper)
    require(r.run('os_wrapper_mutex_acquire', 0, MASK) == MASK and not r.trace, 'POLICY', 'pinned NULL guard')
    r.external['vQueueDelete'] = lambda m, a: 0
    require(r.run('os_wrapper_mutex_delete', 0) == 0 and r.trace[-1][1][0] == 0, 'POLICY', 'pinned delete is unconditional')
    return count+2
