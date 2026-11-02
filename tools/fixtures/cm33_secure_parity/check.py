"""Closed complete object bodies and independent scalar branch data flow."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

HERE = Path(__file__).resolve().parent
sys.path.append(str(HERE.parent/'cm55_tfm_parity'))
from elf import Object, Rejected, require
from machine import Machine, Panic


def encode(body):
    return json.dumps(body,separators=(',',':')).encode('ascii')


def collect(m):
    objects, bodies, records = {}, {}, {}
    for side in ('Fiber','Boot','Reference','ReferenceConstructor','Handlers','Attachment'):
        if side not in m: continue
        obj = Object(m[side],m[side+'Disassembly'])
        objects[side] = obj
        names = (['pxPortInitialiseStack','vPortSVCHandler_C'] if side == 'ReferenceConstructor' else
                 [s['name'] for s in obj.symbols if s['section'] and s['info'] & 15 == 2])
        bodies[side] = {n:obj.function(n) for n in names}
        deps = sorted({s['name'] for s in obj.symbols if not s['section'] and s['name']})
        records[side] = dict(Dependencies=deps,Functions={name:dict(Instructions=len(body),
            Sha256=hashlib.sha256(encode(body)).hexdigest().upper()) for name,body in bodies[side].items()})
        attributes = Path(m[side]+'.elf.txt').read_text()
        cpu_names = ('cortex-m55','8.1-M.MAIN') if m['Mode'] == 'C5SO' else ('cortex-m33','8-M.MAIN')
        arch = 'v8.1-M.mainline' if m['Mode'] == 'C5SO' else 'v8-M.mainline'
        require(any('Tag_CPU_name: "'+n+'"' in attributes for n in cpu_names) and 'Tag_CPU_arch: '+arch+'\n' in attributes,
                'INSTRUCTION',side+'/wrong CPU attributes')
        require(not re.search(r'Tag_(?:FP_arch|MVE_arch|Advanced_SIMD_arch|ABI_VFP_args|PAC_extension|BTI_extension):',attributes),
                'INSTRUCTION',side+'/foreign attributes')
        require(not any(op.startswith('v') or op in ('pac','bti','pacbti','aut') for op,_,_ in obj.instructions.values()),
                'INSTRUCTION',side+'/FP/MVE/PAC/BTI')
    receipt = Path(m['Receipt'])
    receipt.with_suffix('.canonical.json').write_text(json.dumps(bodies,indent=2)+'\n',encoding='ascii')
    receipt.with_suffix('.closed-records.json').write_text(json.dumps(records,indent=2)+'\n',encoding='ascii')
    return bodies, records


def cold_memory_checks(bodies):
    sites = sorted((side,name,op,arg) for side,functions in bodies.items()
                   for name,body in functions.items() for op,arg in body
                   if op in ('bl','b') and arg in ('memset','memcpy'))
    require(sites == [('Boot','fiber_port_boot_create','bl','memcpy'),
                      ('Boot','fiber_port_boot_create','bl','memset'),
                      ('Boot','fiber_port_context_init','bl','memcpy')],
            'BRANCH','exact cold-only memory-helper call sites')
    class ReachedZeroingBoundary(Exception):
        pass
    state = Machine({'factory':bodies['Boot']['fiber_port_boot_create']})
    seen = []
    def zeroing(m,args):
        require(args[0] == m.r['sp'] and args[1:3] == [0,72],
                'BRANCH','factory memset must zero exactly the 72-byte stack-local boot record')
        require(0x2000EC00 <= args[0] <= 0x2000F000-72,
                'BRANCH','factory memset destination outside admitted stack')
        seen.append(args[:3])
        raise ReachedZeroingBoundary()
    state.external['memset'] = zeroing
    try:
        state.run('factory',0x22000000,0x20002000,0x20003000,0x08001001)
    except ReachedZeroingBoundary:
        pass
    require(len(seen) == 1,'BRANCH','factory zeroing prefix did not reach its exact boundary')
    return 1


def pendsv_case(body, reference, mode, outgoing, incoming, edge=None, bad=None):
    companion = mode == 'A30'
    m = Machine({'handler':body})
    current, next_ctx, slot, secure_slot = 0x22000000,0x22000100,0x21001000,0x21001010
    raw, next_raw, base, next_base = 0x20003000,0x20007000,0x20002000,0x20006000
    if edge == 'reserve': base = raw-16
    top = raw if edge == 'top' else raw+0x100
    m.symbols.update(fiber_internal_runtime_current_context_slot=slot,pxCurrentTCB=slot,xSecureContext=secure_slot)
    m.store(slot,current)
    m.store(secure_slot,1)
    m.store(current,0)
    m.store(current+12,base)
    m.store(current+16,top)
    m.store(next_ctx+12,next_base)
    m.store(next_ctx+16,next_raw+(0 if incoming else 32))
    m.cpu.update(ipsr=14,psp=raw,psplim=base)
    m.r['lr'] = bad if bad is not None else (0xFFFFFFFC if outgoing else 0xFFFFFFBC) if companion else 0xFFFFFFFD
    old_regs = [0xA0000000+i for i in range(4,12)]
    next_regs = [0xB0000000+i for i in range(4,12)]
    header = [2,next_base,0xFFFFFFFC if incoming else 0xFFFFFFBC] if companion else [next_base,0xFFFFFFFD]
    words = header + ([] if incoming else next_regs)
    cursor = next_raw-4*len(words)
    m.store(next_ctx,cursor)
    for i,v in enumerate(words): m.store(cursor+4*i,v)
    if not outgoing:
        for i in range(8): m.store(raw+4*i,0x01000000 if i == 7 else 0x8000000+i)
    m.writes.clear()
    cpu_events = []
    def instruction(s,op,arg):
        if op == 'msr': cpu_events.append((arg.split(',')[0],s.value(arg.split(',')[1])))
    m.instruction_observer = instruction
    def validate(s,a):
        require(a[0] == current,'BRANCH','current validation argument')
        return 0
    def save(s,a):
        require(a[0:2] == [current,0xFFFFFFFC if outgoing else 0xFFFFFFBC],'BRANCH','Secure-save arguments')
        return 1
    def ref_save(s,a):
        require(a[0:2] == [1,current],'BRANCH','reference Secure-save arguments')
        return 0
    def select(s,a):
        if not reference: require(a[0] == current,'BRANCH','scheduler current')
        actual_cursor = s.load(current)
        expected = ([1,base,0xFFFFFFFC if outgoing else 0xFFFFFFBC] if companion else [base,0xFFFFFFFD]) + ([] if outgoing else old_regs)
        require(actual_cursor == raw-4*len(expected),'BRANCH','save cursor/reserve')
        require([s.load(actual_cursor+4*i) for i in range(len(expected))] == expected,'BRANCH','save count/order/data')
        writes = [address for address,size in s.writes if base <= address < raw]
        require(sorted(writes) == list(range(actual_cursor,raw,4)),'BRANCH','save write extent')
        s.store(slot,next_ctx)
        return next_ctx
    def prepare(s,a):
        require(a[0] == next_ctx,'BRANCH','prepare next')
        return 2
    def load(s,a):
        require(a[0:2] == [next_ctx,2] and s.cpu['psplim'] == next_base,'BRANCH','Secure-load arguments/order')
        return 0
    def ref_load(s,a):
        require(a[0:2] == [2,next_ctx] and s.cpu['psplim'] == next_base,'BRANCH','reference Secure-load arguments/order')
        return 0
    m.external.update(fiber_port_context_validate_save_current=validate,
        fiber_port_secure_context_save_current_from_pendsv=save,SecureContext_SaveContext=ref_save,
        fiber_port_scheduler_pick_next_from_pendsv=select,vTaskSwitchContext=select,
        fiber_port_secure_context_prepare_next_from_pendsv=prepare,
        fiber_port_secure_context_load_next_from_pendsv=load,SecureContext_LoadContext=ref_load)
    try:
        m.call('handler')
    except Panic as e:
        require(not reference and (bad is not None and e.code == 106 or not outgoing and edge and e.code == 100),
                'BRANCH','unexpected panic '+str(e.code))
        require(not any(n in ('fiber_port_secure_context_save_current_from_pendsv','fiber_port_scheduler_pick_next_from_pendsv') for n,_ in m.trace),
                'BRANCH','rejected entry mutated context')
        return
    require(bad is None and (not edge or outgoing),'BRANCH','invalid origin/bounds accepted')
    require(m.cpu['psp'] == next_raw and m.cpu['psplim'] == next_base,'BRANCH','restore PSP/PSPLIM')
    require(m.return_target == (0xFFFFFFFC if incoming else 0xFFFFFFBC) if companion else m.return_target == 0xFFFFFFFD,
            'BRANCH','restore EXC_RETURN')
    require([m.r['r'+str(i)] for i in range(4,12)] == (old_regs if incoming else next_regs),'BRANCH','restore GPR branch/inverse')
    require(m.r['sp'] == 0x2000F000,'BRANCH','MSP drift')
    require(cpu_events[-1] == ('psp',next_raw) and ('psplim',next_base) in cpu_events,'BRANCH','PSPLIM before PSP')


def branches(m,bodies):
    count = 0
    mode = m['Mode']
    if mode != 'A30':
        count += cold_memory_checks(bodies)
    fiber = bodies['Handlers' if mode == 'A30' else 'Fiber']['PendSV_Handler']
    ref = bodies['Reference']['PendSV_Handler']
    try:
        count += constructor_checks(m['Mode'],bodies)
        count += first_start_checks(m['Mode'],bodies)
        for outgoing in ((False,True) if mode == 'A30' else (False,)):
            for incoming in ((False,True) if mode == 'A30' else (False,)):
                for reference,body in ((False,fiber),(True,ref)):
                    pendsv_case(body,reference,mode,outgoing,incoming)
                    count += 1
        if mode == 'A30':
            for edge in ('reserve','top'):
                for outgoing in (False,True):
                    pendsv_case(fiber,False,mode,outgoing,False,edge=edge)
                    count += 1
            for bad in (0xFFFFFFB8,0xFFFFFFBD,0xFFFFFFEC,0xFFFFFFFD,0xFFFFFFAC,0):
                pendsv_case(fiber,False,mode,False,False,bad=bad)
                count += 1
            count += restore_checks(bodies['Boot'])
            count += cpu_preservation_checks(bodies['Attachment'])
            count += secure_save_checks(bodies['Attachment'])
    except Rejected as e:
        if str(e).startswith('REJECT:BRANCH:'): raise
        raise Rejected('REJECT:BRANCH:'+str(e)) from None
    return count


def constructor_checks(mode,bodies):
    companion = mode == 'A30'
    count = 0
    for top in (0x20004000,0x20008000):
        for arg in (0,0xCAFEBABE):
            for seed in (0x12345678,0xFFFFFFFF):
                for reference in (False,True):
                    name = 'pxPortInitialiseStack' if reference else 'fiber_port_init_context_frame'
                    s = Machine({'constructor':bodies['ReferenceConstructor' if reference else 'Fiber'][name]})
                    ctx,base,entry = 0x22000000,top-0x1000,0x08001001
                    s.r['r9'] = seed if companion else ctx+80
                    for off,val in ((0,0),(12,base),(16,top),(24,entry),(28,arg)):
                        s.store(ctx+off,val)
                    size = 76 if companion else 72
                    s.store(top-size-4,0x11223344)
                    s.store(top,0x55667788)
                    def admit(m,a):
                        require(a[0] == ctx+4,'BRANCH','constructor boot admission')
                        return 0
                    s.external['fiber_port_boot_record_check'] = admit
                    s.writes.clear()
                    if reference: cursor = s.run('constructor',top,base,entry,arg)
                    else:
                        s.run('constructor',ctx,seed)
                        cursor = s.load(ctx)
                    regs = [int('%02d' % i * 4,16) for i in range(4,12)] if reference else [0]*8
                    if not reference: regs[5] = seed
                    expected = ([0] if companion else [])+[base,0xFFFFFFBC if companion else 0xFFFFFFFD]+regs+[
                        arg,*([0x01010101,0x02020202,0x03030303,0x12121212] if reference else [0]*4),
                        s.symbols['prvTaskExitError'] if reference else s.symbols['fiber_internal_task_return']|1,
                        entry if reference else entry&~1,0x01000000]
                    require(cursor == top-size and [s.load(cursor+4*i) for i in range(len(expected))] == expected,
                            'BRANCH','constructor numeric words/cursor')
                    require(s.load(top-size-4) == 0x11223344 and s.load(top) == 0x55667788,'BRANCH','constructor canaries')
                    require(sorted(a for a,n in s.writes if top-size <= a < top) == list(range(top-size,top,4)),
                            'BRANCH','constructor each word exactly once')
                    count += 1
    return count


def first_start_checks(mode,bodies):
    companion = mode == 'A30'
    count = 0
    for reference in (False,True):
        for invalid in ((None,) if reference else (None,'origin','xpsr','immediate')):
            side,name = ('Reference','vRestoreContextOfFirstTask') if reference else ('Handlers' if companion else 'Fiber','SVC_Handler')
            s = Machine({'first':bodies[side][name]})
            ctx,slot,base,raw,msp,code = 0x22000000,0x21001000,0x20003000,0x20004000,0x20001000,0x08004000
            exc = 0xFFFFFFBC if companion else 0xFFFFFFFD
            regs = [0xB0000000+i for i in range(4,12)]
            words = ([1] if companion else [])+[base,exc]+regs
            cursor = raw-4*len(words)
            s.symbols.update(fiber_internal_runtime_current_context_slot=slot,pxCurrentTCB=slot,xSecureContext=slot+16)
            s.store(slot,ctx)
            s.store(ctx,cursor)
            for i,val in enumerate(words): s.store(cursor+4*i,val)
            for i in range(8): s.store(msp+4*i,code+2 if i == 6 else 0x01000000 if i == 7 else 0)
            s.store(code,69 if invalid == 'immediate' else 70,1)
            s.store(code+1,0xDF,1)
            if invalid == 'xpsr': s.store(msp+28,0)
            s.cpu.update(ipsr=11,msp=msp)
            s.r['lr'] = (0xFFFFFFB8 if companion else 0xFFFFFFF9) ^ (1 if invalid == 'origin' else 0)
            def prepare(m,a):
                require(a[0] == ctx,'BRANCH','first admission argument')
                return 0
            s.external.update(fiber_port_secure_context_prepare_first_start=prepare,fiber_port_context_validate_restore=prepare)
            try: s.call('first')
            except Panic as e:
                require(invalid and e.code == (117 if invalid == 'immediate' else 108),'BRANCH','first unexpected panic')
            else:
                require(invalid is None,'BRANCH','first invalid entry accepted')
                require(s.return_target == exc and s.cpu['psp'] == raw and s.cpu['psplim'] == base and s.cpu['control'] == 2,
                        'BRANCH','first restore CPU value plumbing')
                if not reference:
                    require([s.r['r'+str(i)] for i in range(4,12)] == regs,'BRANCH','first complete GPR restore')
                    require(s.cpu['primask'] == 0,'BRANCH','first unmask')
            count += 1
    return count


def restore_checks(boot):
    # Sealed descriptor/hash/canary admission is an explicit provider boundary;
    # the actual compiled variable representation/bounds/PC/xPSR guard runs.
    cases = [
        ('fc-12',12,0xFFFFFFFC,1,64,0,0,None),
        ('fc-4',4,0xFFFFFFFC,1,64,0,0,88),
        ('fc-zero',12,0xFFFFFFFC,0,64,0,0,68),
        ('fc-unattached',12,0xFFFFFFFC,1,0,0,0,68),
        ('fc-empty',12,0xFFFFFFFC,0,0,0,0,68),
        ('bc-76',76,0xFFFFFFBC,0,0,0x8001000,0x01000000,None),
        ('bc-attached',76,0xFFFFFFBC,2,64,0x8001000,0x01000000,None),
        ('bc-12',12,0xFFFFFFBC,0,0,0,0,88),
        ('bc-alignment-short',76,0xFFFFFFBC,0,0,0x8001000,0x01000200,88),
        ('bc-alignment',84,0xFFFFFFBC,0,0,0x8001000,0x01000200,None),
        ('bc-pc',76,0xFFFFFFBC,0,0,0x8001001,0x01000000,120),
        ('bc-xpsr',76,0xFFFFFFBC,0,0,0x8001000,0,120),
        ('bc-handler',76,0xFFFFFFBC,0,0,0x8001000,0x01000001,120),
        ('foreign-fd',12,0xFFFFFFFD,1,64,0,0,120),
    ]
    for name,available,exc,handle,attached,pc,xpsr,panic in cases:
        functions = {'restore':boot['fiber_port_context_validate_restore']}
        if 'fiber_port_validate_context_pointer' in boot:
            functions['fiber_port_validate_context_pointer'] = boot['fiber_port_validate_context_pointer']
        s = Machine(functions)
        ctx,sp,base = 0x22000000,0x20004004,0x20003000
        for offset in range(0,80,4): s.store(ctx+offset,0)
        s.store(ctx,sp)
        s.store(ctx+12,base)
        s.store(ctx+16,sp+available)
        s.store(ctx+32,attached)
        s.store(ctx+76,0x12345678)
        for offset,value in ((0,handle),(4,base),(8,exc)):
            if offset < available: s.store(sp+offset,value)
        if exc == 0xFFFFFFBC and available >= 76:
            s.store(sp+68,pc)
            s.store(sp+72,xpsr)
        def descriptor(m,a):
            require(a[0] == ctx+4,'BRANCH','descriptor admission '+name)
            return 0
        def canary(m,a):
            require(a[0] == ctx,'BRANCH','canary admission '+name)
            return 0
        s.external.update(fiber_port_boot_record_fast_check=descriptor,
            fiber_port_boot_record_check=descriptor,
            fiber_port_boot_record_compute_hash=lambda m,a:0x12345678,
            fiber_port_validate_stack_canary=canary)
        try: s.run('restore',ctx)
        except Panic as e: require(e.code == panic,'BRANCH','restore '+name+'/panic '+str(e.code))
        else: require(panic is None,'BRANCH','restore '+name+'/missing panic')
    return len(cases)


def cpu_preservation_checks(attachment):
    functions = {n:attachment[n] for n in ('fiber_port_capture_attachment_cpu_state','fiber_port_validate_attachment_cpu_state')}
    fields = [('ipsr',105),('primask',112),('basepri',98),('faultmask',102),('control',108),('psplim',76),('psp',80)]
    for bad in (None,*fields):
        s = Machine(functions)
        s.cpu.update(ipsr=14,psplim=0x20002000,psp=0x20003000)
        before = dict(s.cpu)
        state = 0x22000000
        s.run('fiber_port_capture_attachment_cpu_state',state)
        require([s.load(state+4*i) for i in range(7)] == [before[n] for n,_ in fields],'BRANCH','captured seven-register state')
        if bad: s.cpu[bad[0]] ^= 8
        try: s.run('fiber_port_validate_attachment_cpu_state',state)
        except Panic as e: require(bad and e.code == bad[1],'BRANCH','CPU readback exact panic')
        else: require(bad is None,'BRANCH','missing '+str(bad)+' preservation guard')
    return len(fields)+1


def secure_save_checks(attachment):
    cases = [(0xFFFFFFBC,0,0,False,None),(0xFFFFFFBC,1,64,False,None),
             (0xFFFFFFFC,1,64,False,None),(0xFFFFFFFC,0,0,False,68),
             (0xFFFFFFFC,0,64,False,68),(0xFFFFFFFC,1,0,False,68),
             (0xFFFFFFFD,1,64,False,120),(0xFFFFFFFC,1,64,True,80)]
    for exc,handle,attached,corrupt,panic in cases:
        s = Machine(attachment)
        ctx,mirror = 0x22000000,0x21001000
        s.symbols['.bss.fiber_port_current_secure_context_handle'] = mirror
        s.store(mirror,handle)
        s.store(ctx+32,attached)
        s.cpu.update(ipsr=14,psplim=0x20002000,psp=0x20003000)
        calls = []
        def provider(m,a):
            require(a[0:2] == [handle,ctx],'BRANCH','Secure-save owned gateway arguments')
            calls.append(a[0:2])
            if corrupt: m.cpu['psp'] += 8
            return 1
        s.external['fiber_secure_context_gateway_v1_save'] = provider
        try: result = s.run('fiber_port_secure_context_save_current_from_pendsv',ctx,exc)
        except Panic as e:
            require(e.code == panic,'BRANCH','Secure-save exact panic '+str(e.code))
            require(bool(calls) == corrupt,'BRANCH','invalid Secure-save reached gateway')
        else:
            require(panic is None and result == handle and s.load(mirror) == 0 and len(calls) == 1,
                    'BRANCH','Secure-save mirror/return/call count')
    return len(cases)


def main():
    only = len(sys.argv) == 3 and sys.argv[1] == '--behavior-only'
    require(only or len(sys.argv) == 2,'INVENTORY','arguments')
    manifest = json.loads(Path(sys.argv[2] if only else sys.argv[1]).read_text())
    bodies, records = collect(manifest)
    if only:
        n = branches(manifest,bodies)
        print('PASS SCALAR_BRANCH_ONLY scenarios=%d (not a parity receipt)' % n)
        return
    geometry = Object(manifest['Geometry'],manifest['GeometryDisassembly'])
    symbols = [s for s in geometry.symbols if s['name'] == 'm33_closed_geometry' and s['section']]
    numeric = ([0x43333353,0x20001,0x8A,80,76,4,12,16,11,76,4,0xFFFFFFBC] if manifest['Mode'] == 'A30' else
               [0x4335534F if manifest['Mode'] == 'C5SO' else 0x4333534F,0x10001,2,76,72,4,12,16,10,72,0,0xFFFFFFFD])
    require(len(symbols) == 1 and symbols[0]['size'] == 48,'INVENTORY','geometry symbol')
    s = symbols[0]
    require(geometry.read(s['section'],s['value'],48) == struct.pack('<12I',*numeric),'INVENTORY','independent numeric geometry')
    expected = json.loads((HERE/('expected-'+manifest['Mode']+'-'+manifest['Optimization'][1:]+'.json')).read_text())
    require(records.keys() == expected.keys(),'INVENTORY','object set')
    for side in records:
        require(records[side]['Dependencies'] == expected[side]['Dependencies'],'DEPENDENCY',side+'/exact undefined set')
        require(records[side]['Functions'].keys() == expected[side]['Functions'].keys(),'INVENTORY',side+'/function set')
        for name,r in records[side]['Functions'].items():
            require(r == expected[side]['Functions'][name],'BODY',side+'/'+name+'/complete instruction graph changed')
    count = branches(manifest,bodies)
    result = dict(Status='PASS',Mode=manifest['Mode'],Optimization=manifest['Optimization'],
        Functions=sum(len(v) for v in bodies.values()),Scenarios=count,
        Evidence='complete generated bodies + bounded integer data-flow; not CPU execution',RuntimeProfileAdded=False)
    Path(manifest['Receipt']).write_text(json.dumps(result,indent=2)+'\n',encoding='ascii')
    print('PASS M33_CLOSED bodies=%d scenarios=%d' % (result['Functions'],count))


if __name__ == '__main__':
    try: main()
    except Rejected as e: raise SystemExit(str(e)) from None
