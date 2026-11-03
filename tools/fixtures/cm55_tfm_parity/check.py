"""Relocation-aware C5TF generated-code checks; not hardware execution."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

import json
from pathlib import Path
import re
import struct
from elf import Object, Rejected, require
from oracles import constructor_checks, transfer_checks, r9_capture_checks
from policy import policy_checks

COHORT = 'fiber_port_context_cohort_armv81m_mainline_p0x43355446u_l0x00010001u_f0_e0_h1_j1_v1_d1_r1_z8u_y0_w2_g4_u00010000_i0_o0xFFFFFFBCu_c0_s1_x0_m0_a0_b0_t1_n1_k0_q0'
DEPENDENCIES = {
    'Fiber': {'fiber_internal_runtime_current_context_slot', 'fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context',
        'fiber_internal_runtime_select_scheduler_candidate', 'fiber_internal_task_return', 'fiber_panic',
        'fiber_port_arm_cm55_tfm_integration_bundle_v1_anchor', 'fiber_port_boot_record_check',
        'fiber_port_context_prepare_first_start', 'fiber_port_context_validate_restore',
        'fiber_port_context_validate_save_current', 'fiber_port_require_start_environment',
        'fiber_port_require_start_interrupt_state', 'fiber_port_runtime_prepare', 'fiber_port_tfm_require_initialized'},
    'Boot': {'fiber_addr_plausible_code', 'fiber_addr_plausible_ram', 'fiber_internal_runtime_port_abi_v1_anchor',
        'fiber_internal_task_return', 'fiber_panic', COHORT, 'fiber_port_init_context_frame', 'memcpy', 'memset'},
    'Init': {'fiber_panic', 'tfm_ns_interface_init'},
    'Wrapper': {'ctxrt_v1_current', 'fiber_panic', 'fiber_port_runtime_schedule'},
    'Reference': {'pxCurrentTCB', 'vPortSVCHandler_C', 'vTaskSwitchContext'},
    'ReferenceConstructor': {'PendSV_Handler', 'SVC_Handler', 'ulSetInterruptMask', 'vClearInterruptMask',
        'vRestoreContextOfFirstTask', 'vStartFirstTask', 'vTaskSwitchContext', 'xTaskIncrementTick'},
    'ReferenceWrapper': {'vQueueDelete', 'xQueueCreateMutexStatic', 'xQueueGenericSend', 'xQueueSemaphoreTake'},
}


def main():
    dataflow_only = len(sys.argv) == 3 and sys.argv[1] == '--r9-dataflow-only'
    require(dataflow_only or len(sys.argv) == 2, 'MANIFEST', 'arguments')
    m = json.loads(Path(sys.argv[2] if dataflow_only else sys.argv[1]).read_text())
    require(m['Optimization'] in ('-O2', '-Os'), 'MANIFEST', 'optimization')
    if dataflow_only:
        # An explicitly scoped independent oracle for compiled guard mutants.
        # It never creates a general parity PASS receipt or admits baselines.
        fiber = Object(m['Fiber'], m['FiberDisassembly'])
        boot = Object(m['Boot'], m['BootDisassembly'])
        reference = Object(m['ReferenceConstructor'], m['ReferenceConstructorDisassembly'])
        builder = fiber.function('fiber_port_init_context_frame')
        count = constructor_checks(builder, reference.function('pxPortInitialiseStack'))
        count += r9_capture_checks(boot.function('fiber_port_context_init'), builder, COHORT)
        print('PASS C5TF_R9_DATAFLOW_ONLY scenarios=%d (not a parity receipt)' % count)
        return
    expected = json.loads((Path(__file__).parent / ('expected-' + m['Optimization'][1:] + '.json')).read_text())
    geometry = Object(m['Geometry'], m['GeometryDisassembly'])
    symbols = [s for s in geometry.symbols if s['name'] == 'c5tf_parity_geometry']
    numeric = [76, 72, 0, 4, 12, 16, 24, 28, 0x43355446, 0x10001, 0x82, 72, 40, 0xFFFFFFBC, 1]
    require(len(symbols) == 1 and symbols[0]['size'] == 4*len(numeric), 'GEOMETRY', 'geometry table size')
    s = symbols[0]
    require(geometry.read(s['section'], s['value'], s['size']) == struct.pack('<15I', *numeric),
            'GEOMETRY', 'actual selected-header numeric layout differs')
    bodies, actual = {}, {}
    for side in DEPENDENCIES:
        obj = Object(m[side], m[side+'Disassembly'])
        dependencies = {s['name'] for s in obj.symbols if not s['section'] and s['name']}
        require(dependencies == DEPENDENCIES[side], 'DEPENDENCY', side + '/' + str(sorted(dependencies ^ DEPENDENCIES[side])))
        attributes = Path(m[side] + '.elf.txt').read_text()
        require('Tag_CPU_name: "cortex-m55"' in attributes and 'Tag_CPU_arch: v8.1-M.mainline' in attributes,
                'ATTRIBUTE', side + '/actual M55 codegen')
        require(not re.search(r'Tag_(?:FP_arch|MVE_arch|Advanced_SIMD_arch|ABI_VFP_args|PAC_extension|BTI_extension):', attributes),
                'ATTRIBUTE', side + '/foreign instruction/ABI attribute')
        require(not any(op.startswith('v') or op in ('pac', 'pacbti', 'bti', 'aut') for op, _, _ in obj.instructions.values()),
                'INSTRUCTION', side + '/FP/MVE/PAC/BTI codegen')
        names = (['fiber_port_context_init'] if side == 'Boot' else
                 ['pxPortInitialiseStack', 'vPortSVCHandler_C'] if side == 'ReferenceConstructor' else [
                     s['name'] for s in obj.symbols if s['section'] and s['info'] & 15 == 2])
        bodies[side] = {n: obj.function(n) for n in names}
        for name, body in bodies[side].items():
            actual[side+'/'+name] = [' '.join(row).rstrip() for row in body]
    require(actual.keys() == expected.keys(), 'INVENTORY', 'generated function inventory changed')
    for key, body in actual.items():
        if body != expected[key]:
            position = next((i for i, (a, b) in enumerate(zip(body, expected[key])) if a != b), min(len(body), len(expected[key])))
            require(False, 'BODY', key + '/instruction ' + str(position) + '/actual ' + str(body[position:position+2]) + '/expected ' + str(expected[key][position:position+2]))
    ctor = bodies['Fiber']['fiber_port_init_context_frame']
    require(not any(op in ('mrs', 'msr', 'cpsid', 'cpsie', 'svc') or op.startswith('v') for op, _ in ctor),
            'CONSTRUCTOR', 'CPU/FP instruction in constructor')
    counts = dict(Constructor=constructor_checks(ctor, bodies['ReferenceConstructor']['pxPortInitialiseStack']),
                  CapturedR9=r9_capture_checks(bodies['Boot']['fiber_port_context_init'], ctor, COHORT),
                  Transfer=transfer_checks(bodies['Fiber']['PendSV_Handler'], bodies['Reference']['PendSV_Handler'], bodies['Fiber']['SVC_Handler']),
                  Policy=policy_checks(bodies['Init'], bodies['Wrapper'], bodies['ReferenceWrapper']))
    result = dict(Status='PASS', Optimization=m['Optimization'], Functions=len(actual), Scenarios=counts,
                  Evidence='closed generated code + bounded integer data-flow; not CPU execution', RuntimeProfileAdded=False)
    Path(m['Receipt']).write_text(json.dumps(result, indent=2)+'\n', encoding='ascii')
    print('PASS C5TF closed bodies=%d scenarios=%d' % (len(actual), sum(counts.values())))


if __name__ == '__main__':
    try:
        main()
    except Rejected as e:
        raise SystemExit(str(e)) from None
