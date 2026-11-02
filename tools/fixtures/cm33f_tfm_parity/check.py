"""Closed decoded ARM objects plus bounded numeric oracles, not CPU execution."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

import hashlib
import json
from pathlib import Path
import re
import struct
sys.path.append(str(Path(__file__).resolve().parent.parent/'cm55_tfm_parity'))
from elf import Object, Rejected, require
import oracles

COHORT = 'fiber_port_context_cohort_armv8m_mainline_p0x43334654u_l0x00010001u_f1_e1_h1_j1_v1_d1_r1_z8u_y1_w2_g4_u00010000_i0_o0xFFFFFFBCu_c0_s1_x0_m0_a0_b0_t1_n1_k0_q0'
DEPENDENCIES = {
    'Fiber': {'fiber_internal_runtime_current_context_slot','fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_runtime_publish_current_context','fiber_internal_runtime_require_current_context',
        'fiber_internal_runtime_select_scheduler_candidate','fiber_internal_task_return','fiber_panic',
        'fiber_port_arm_cm33f_tfm_integration_bundle_v1_anchor','fiber_port_boot_record_check',
        'fiber_port_context_prepare_first_start','fiber_port_context_validate_restore',
        'fiber_port_context_validate_save_current','fiber_port_require_start_environment',
        'fiber_port_require_start_interrupt_state','fiber_port_runtime_prepare','fiber_port_tfm_require_initialized'},
    'Boot': {'fiber_addr_plausible_code','fiber_addr_plausible_ram','fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_task_return','fiber_panic',COHORT,'fiber_port_fpu_prepare',
        'fiber_port_fpu_require_configured','fiber_port_fpu_require_ready','fiber_port_init_context_frame'},
    'Init': {'fiber_panic','tfm_ns_interface_init'},
    'Wrapper': {'fiber_current','fiber_panic','fiber_port_runtime_schedule'},
    'Reference': {'pxCurrentTCB','vPortSVCHandler_C','vTaskSwitchContext'},
    'ReferenceConstructor': {'PendSV_Handler','SVC_Handler','ulSetInterruptMask','vClearInterruptMask',
        'vRestoreContextOfFirstTask','vStartFirstTask','vTaskSwitchContext','xTaskIncrementTick'},
    'ReferenceWrapper': {'vQueueDelete','xQueueCreateMutexStatic','xQueueGenericSend','xQueueSemaphoreTake'},
}
DEPENDENCIES['ReferenceFpuProbe'] = DEPENDENCIES['ReferenceConstructor']


def fingerprint(body):
    return dict(Instructions=len(body),Sha256=hashlib.sha256(
        json.dumps(body,separators=(',',':')).encode('ascii')).hexdigest().upper())


def collect(m, strict):
    bodies, actual = {}, {}
    for side in DEPENDENCIES:
        obj = Object(m[side],m[side+'Disassembly'])
        if strict:
            undefined = {s['name'] for s in obj.symbols if not s['section'] and s['name']}
            require(undefined == DEPENDENCIES[side],'DEPENDENCY',side+'/'+str(sorted(undefined ^ DEPENDENCIES[side])))
            attrs = Path(m[side]+'.elf.txt').read_text()
            require('Tag_CPU_name: "8-M.MAIN"' in attrs and 'Tag_CPU_arch: v8-M.mainline' in attrs
                    and 'Tag_THUMB_ISA_use: Yes' in attrs and 'Tag_FP_arch: FPv5/FP-D16 for ARMv8' in attrs
                    and 'Tag_ABI_HardFP_use: SP only' in attrs,
                    'ATTRIBUTE',side+'/actual M33 scalar FP codegen')
            require(('Tag_ABI_VFP_args: VFP registers' in attrs) == (m['FloatAbi'] == 'hard'),
                    'ATTRIBUTE',side+'/float ABI')
            require(not re.search(r'Tag_(?:MVE_arch|Advanced_SIMD_arch|PAC_extension|BTI_extension):',attrs),
                    'ATTRIBUTE',side+'/foreign ISA attribute')
        names = (['pxPortInitialiseStack','vPortSVCHandler_C','xPortStartScheduler'] if side == 'ReferenceConstructor' else
                 ['prvSetupFPU'] if side == 'ReferenceFpuProbe' else
                 [s['name'] for s in obj.symbols if s['section'] and s['info'] & 15 == 2])
        bodies[side] = {name:obj.function(name) for name in names}
        for name,body in bodies[side].items():
            actual[side+'/'+name] = body
            if strict:
                vector = [row for row in body if row[0].startswith('v')]
                high = '{'+','.join('s'+str(n) for n in range(16,32))+'}'
                expected = [('vstmdb','r0!,'+high),('vldmia','r0!,'+high)] if side == 'Fiber' and name == 'PendSV_Handler' else (
                    [('vstmdbeq','r0!,'+high),('vldmiaeq','r0!,'+high)] if side == 'Reference' and name == 'PendSV_Handler' else [])
                require(vector == expected,'INSTRUCTION',side+'/'+name+'/exact FP transfer inventory')
                require(not any(op in ('pac','pacbti','bti','aut') for op,_ in body),'INSTRUCTION','foreign control-flow instruction')
    return bodies,actual


def main():
    independent = len(sys.argv) == 3 and sys.argv[1] == '--oracles-only'
    require(independent or len(sys.argv) == 2,'MANIFEST','arguments')
    m = json.loads(Path(sys.argv[2] if independent else sys.argv[1]).read_text())
    require(m['Optimization'] in ('-O2','-Os') and m['FloatAbi'] in ('hard','softfp'),'MANIFEST','tuple')
    bodies,actual = collect(m,not independent)
    if not independent:
        expected = json.loads((Path(__file__).parent/('expected-'+m['Optimization'][1:]+'.json')).read_text())
        require(actual.keys() == expected.keys(),'INVENTORY','function inventory changed')
        for key,body in actual.items():
            require(fingerprint(body) == expected[key],'BODY',key+'/exact decoded stream differs')
        Path(m['Receipt']).with_name('decoded-bodies.json').write_text(json.dumps(actual,indent=2)+'\n',encoding='ascii')
        geometry = Object(m['Geometry'],m['GeometryDisassembly'])
        symbols = [s for s in geometry.symbols if s['name'] == 'c3ft_parity_geometry']
        numeric = [76,72,0,4,12,16,24,28,0x43334654,0x10001,0x83,72,40,
                   0xFFFFFFBC,0xFFFFFFAC,212,32,72,64,0,0]
        require(len(symbols) == 1 and symbols[0]['size'] == 4*len(numeric),'GEOMETRY','table size')
        s = symbols[0]
        require(geometry.read(s['section'],s['value'],s['size']) == struct.pack('<21I',*numeric),
                'GEOMETRY','actual selected-header numeric fields')
    ctor = bodies['Fiber']['fiber_port_init_context_frame']
    require(not any(op in ('mrs','msr','cpsid','cpsie','svc') or op.startswith('v') for op,_ in ctor),
            'CONSTRUCTOR','CPU/FP operation in builder')
    counts = dict(Constructor=oracles.constructor(ctor,bodies['ReferenceConstructor']['pxPortInitialiseStack']),
        FirstStart=oracles.first_start(bodies['Fiber'],bodies['Reference']),
        FirstRestore=oracles.first_restore(bodies['Fiber'],bodies['Reference']),
        Transfer=oracles.transfer(bodies['Fiber']['PendSV_Handler'],bodies['Reference']['PendSV_Handler']),
        FpuPolicy=oracles.fpu(bodies['Fiber'],bodies['ReferenceFpuProbe']),
        TfmPolicy=oracles.policy(bodies['Init'],bodies['Wrapper'],bodies['ReferenceWrapper']))
    if independent:
        print('PASS C3FT_ORACLES_ONLY scenarios=%d (not a parity receipt)' % sum(counts.values()))
        return
    Path(m['Receipt']).write_text(json.dumps(dict(Status='PASS',Optimization=m['Optimization'],FloatAbi=m['FloatAbi'],
        Functions=len(actual),Scenarios=counts,RuntimeProfileAdded=False,
        ReferenceFpuProbe='actual port.c compiled with separately labelled -fno-inline; not default-codegen evidence',
        Scope='closed default decoded bodies + bounded numeric oracles; no CPU/exception/TF-M execution'),indent=2)+'\n',encoding='ascii')
    print('PASS C3FT closed bodies=%d scenarios=%d' % (len(actual),sum(counts.values())))


if __name__ == '__main__':
    try:
        main()
    except Rejected as e:
        raise SystemExit(str(e)) from None
    except oracles.integer.Panic as e:
        raise SystemExit('REJECT:POLICY:unexpected panic '+str(e.code)) from None
