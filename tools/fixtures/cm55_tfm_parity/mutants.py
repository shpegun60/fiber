"""Single-anchor mutations of fixture COPIES of real production/reference C."""
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

R9_DATAFLOW_MUTANTS = frozenset(('constructor-r9', 'builder-live-r9',
    'builder-context-end-r9', 'constructor-recapture-r9', 'constructor-zero-r9-argument',
    'constructor-context-end-r9-argument', 'constructor-r9-after-cold-read',
    'constructor-r9-readback'))


def cases():
    # Name, object side, optional final function marker, old bytes, new bytes.
    return [
        ('save-count', 'Fiber', 'void PendSV_Handler(void)', 'stmdb r0!, {r2-r11}', 'stmdb r0!, {r2-r10}'),
        ('save-writeback', 'Fiber', 'void PendSV_Handler(void)', 'stmdb r0!, {r2-r11}', 'stmdb r0, {r2-r11}'),
        ('save-slot-order', 'Fiber', 'void PendSV_Handler(void)', 'mov   r2, r3', 'mov   r2, lr'),
        ('restore-count', 'Fiber', 'void PendSV_Handler(void)', 'ldmia r0!, {r2-r11}', 'ldmia r0!, {r2-r10}'),
        ('restore-writeback', 'Fiber', 'void PendSV_Handler(void)', 'ldmia r0!, {r2-r11}', 'ldmia r0, {r2-r11}'),
        ('restore-psplim-source', 'Fiber', 'void PendSV_Handler(void)', 'msr   psplim, r2', 'msr   psplim, r3'),
        ('restore-psp-source', 'Fiber', 'void PendSV_Handler(void)', 'msr   psp, r0', 'msr   psp, r2'),
        ('origin-fp-extended', 'Fiber', 'void PendSV_Handler(void)', 'mvn   r3, #67', 'mvn   r3, #83'),
        ('xpsr-offset', 'Fiber', 'void PendSV_Handler(void)', '[xpsr] "I" (fiber_portOFFSET_STACKED_XPSR)', '[xpsr] "I" (24u)'),
        ('software-bound', 'Fiber', 'void PendSV_Handler(void)', '[swbytes] "I" (FIBER_PORT_SOFTWARE_FRAME_BYTES)', '[swbytes] "I" (36u)'),
        ('scheduler-call-addend', 'Fiber', 'void PendSV_Handler(void)', 'bl    fiber_port_scheduler_pick_next_from_pendsv ', 'bl    fiber_port_scheduler_pick_next_from_pendsv+2 '),
        ('unexpected-instruction', 'Fiber', 'void PendSV_Handler(void)', '".syntax unified', '"udf #19\\n.syntax unified'),
        ('first-restore-r9', 'Fiber', 'void SVC_Handler(void)', 'ldmia r0!, {r2-r11}', 'ldmia r0!, {r2-r8,r10-r11}'),
        ('first-control-readback', 'Fiber', 'void SVC_Handler(void)', 'cmp   r1, #2', 'cmp   r1, #0'),
        ('svc-opcode', 'Fiber', 'void SVC_Handler(void)', 'cmp   r2, #0xDF', 'cmp   r2, #0xDE'),
        ('svc-raw-core-offset', 'Fiber', 'void SVC_Handler(void)', 'mrs   r0, msp', 'mrs   r0, psp'),
        ('constructor-r9', 'Fiber', None, 'frame[fiber_portFRAME_R9] = initial_r9;', 'frame[fiber_portFRAME_R9] = initial_r9 & 0u;'),
        ('builder-live-r9', 'Fiber', None, 'frame[fiber_portFRAME_R9] = initial_r9;', 'frame[fiber_portFRAME_R9] = ((void)initial_r9, fiber_port_read_r9());'),
        ('builder-context-end-r9', 'Fiber', None, 'frame[fiber_portFRAME_R9] = initial_r9;', 'frame[fiber_portFRAME_R9] = ((void)initial_r9, (uint32_t)((uintptr_t)ctx + sizeof(*ctx)));'),
        ('constructor-recapture-r9', 'Boot', None, 'fiber_port_init_context_frame(ctx, initial_r9);', 'fiber_port_init_context_frame(ctx, fiber_port_read_r9());'),
        ('constructor-zero-r9-argument', 'Boot', None, 'fiber_port_init_context_frame(ctx, initial_r9);', 'fiber_port_init_context_frame(ctx, 0u);'),
        ('constructor-context-end-r9-argument', 'Boot', None, 'fiber_port_init_context_frame(ctx, initial_r9);', 'fiber_port_init_context_frame(ctx, (uint32_t)context_end);'),
        ('constructor-r9-after-cold-read', 'Boot', None,
            'const uint32_t initial_r9 = fiber_port_read_r9();\n\tFIBER_RUNTIME_PORT_ABI_RETAIN_V1();\n\tFIBER_PORT_CONTEXT_COHORT_RETAIN();',
            'FIBER_RUNTIME_PORT_ABI_RETAIN_V1();\n\tFIBER_PORT_CONTEXT_COHORT_RETAIN();\n\tconst uint32_t initial_r9 = fiber_port_read_r9();'),
        ('constructor-r9-readback', 'Boot', None, "FIBER_REQUIRE(ctx->sp[7] == initial_r9, '9');", '(void)initial_r9;'),
        ('constructor-argument', 'Fiber', None, 'frame[fiber_portFRAME_R0] = (uint32_t)(uintptr_t)ctx->boot.arg;', 'frame[fiber_portFRAME_R0] = 0u;'),
        ('constructor-psplim', 'Fiber', None, 'frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_base;', 'frame[fiber_portFRAME_PSPLIM] = (uint32_t)ctx->boot.stack_top;'),
        ('constructor-cursor', 'Fiber', None, 'ctx->sp = frame;', 'ctx->sp = frame + 1;'),
        ('constructor-cpu-write', 'Fiber', None, 'frame[fiber_portFRAME_R4] = 0u;', '__set_CONTROL(0u); frame[fiber_portFRAME_R4] = 0u;'),
        ('constructor-helper', 'Fiber', None, 'frame[fiber_portFRAME_R4] = 0u;', 'extern uint32_t unexpected_helper(void); frame[fiber_portFRAME_R4] = unexpected_helper();'),
        ('preflight-init-order', 'Fiber', None, 'fiber_port_tfm_require_initialized();', 'fiber_port_runtime_prepare(); fiber_port_tfm_require_initialized();'),
        ('init-sticky', 'Init', None, 'fiber_port_tfm_initialization_state = fiber_portTFM_FAILED;', 'fiber_port_tfm_initialization_state = fiber_portTFM_UNINITIALIZED;'),
        ('init-cpu-preservation', 'Init', None, 'fiber_port_tfm_validate_cpu_state(&cpu_state);', '(void)cpu_state;'),
        ('init-ready-readback', 'Init', None, "fiber_portTFM_READY, 'Q'", "fiber_portTFM_INITIALIZING, 'Q'"),
        ('mutex-owner', 'Wrapper', None, 'fiber_port_tfm_mutex.owner != current', 'fiber_port_tfm_mutex.owner == current'),
        ('mutex-recursion', 'Wrapper', None, 'if (fiber_port_tfm_mutex.owner == current)', 'if (fiber_port_tfm_mutex.owner == NULL)'),
        ('mutex-finite-timeout', 'Wrapper', None, 'timeout != FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER', 'timeout == FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER'),
        ('mutex-yield-target', 'Wrapper', None, 'fiber_port_runtime_schedule();', 'extern void wrong_yield(void); wrong_yield();'),
        ('reference-save-count', 'Reference', 'void PendSV_Handler( void )', 'stmdb r0!, {r2-r11}', 'stmdb r0!, {r2-r10}'),
        ('reference-restore-writeback', 'Reference', 'void PendSV_Handler( void )', 'ldmia r0!, {r2-r11}', 'ldmia r0, {r2-r11}'),
        ('reference-first-skip', 'Reference', 'void vRestoreContextOfFirstTask( void )', 'adds r0, #32', 'adds r0, #28'),
        ('reference-svc-route', 'Reference', 'void SVC_Handler( void )', '=vPortSVCHandler_C', '=vPortSVCHandler_C+2'),
        ('reference-constructor-xpsr', 'ReferenceConstructor', None, '*pxTopOfStack = portINITIAL_XPSR;', '*pxTopOfStack = 0u;', 2),
        ('reference-wrapper-status', 'ReferenceWrapper', 'uint32_t os_wrapper_mutex_acquire', 'xRet != pdPASS', 'xRet == pdPASS'),
    ]
