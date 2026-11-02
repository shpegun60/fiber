"""Bounded changes to compiled copies, never either source checkout."""
import sys
if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")


def cases(mode):
    if mode == 'A30':
        return [
            ('origin-mask','Handlers','bic   r3, r3, #0x40','bic   r3, r3, #0x20',1,True),
            ('secure-reserve','Handlers','subs  r3, #%c[securebytes]','subs  r3, #%c[swbytes]',1,True),
            ('ns-reserve','Handlers','subs  r3, #%c[swbytes]','subs  r3, #%c[securebytes]',1,True),
            ('secure-hw-read','Handlers','bne   83f','beq   83f',1,True),
            ('save-gpr-branch','Handlers','bne   84f','beq   84f',1,True),
            ('restore-gpr-branch','Handlers','bne   85f','beq   85f',1,True),
            ('save-gpr-count','Handlers','stmdb r0!, {r4-r11}','stmdb r0!, {r4-r10}',1,True),
            ('save-gpr-writeback','Handlers','stmdb r0!, {r4-r11}','stmdb r0, {r4-r11}',1,True),
            ('save-special-order','Handlers','mov   r2, r3','mov   r2, r2',1,True),
            ('restore-gpr-count','Handlers','ldmia r2!, {r4-r11}','ldmia r2!, {r4-r10}',1,True),
            ('restore-gpr-writeback','Handlers','ldmia r2!, {r4-r11}','ldmia r2, {r4-r11}',1,True),
            ('restore-handle','Handlers','cmp   r0, r3','cmp   r0, r0',1,False),
            ('restore-origin-mask','Handlers','bic   r12, r12, #0x40','bic   r12, r12, #0x20',1,True),
            ('xpsr-offset','Handlers','[r0, %c[xpsr]]','[r0, #24]',1,False),
            ('restore-header-minimum','Boot','available >= (uintptr_t)fiber_portSECURE_HEADER_BYTES','available >= (uintptr_t)FIBER_PORT_INITIAL_CONTEXT_BYTES',1,True),
            ('restore-fc-attachment','Boot','ctx->boot.secure_stack_bytes != 0u &&\n\t\t\t\tsecure_handle != fiber_portNO_SECURE_CONTEXT','ctx->boot.secure_stack_bytes != 0u ||\n\t\t\t\tsecure_handle != fiber_portNO_SECURE_CONTEXT',1,True),
            ('restore-fc-no-return','Boot','\t\treturn;\n\t}\n\tFIBER_REQUIRE(available >=','\t\t/* removed Secure-origin return */\n\t}\n\tFIBER_REQUIRE(available >=',1,True),
            ('restore-ns-minimum','Boot',"FIBER_REQUIRE(available >= (uintptr_t)FIBER_PORT_INITIAL_CONTEXT_BYTES, 'X');","FIBER_REQUIRE(available >= (uintptr_t)fiber_portSECURE_HEADER_BYTES, 'X');",1,True),
            ('save-fc-attachment','Attachment','if (exc_return == fiber_portSECURE_ORIGIN_EXC_RETURN)','if (exc_return == 0u)',1,True),
            ('psp-capture','Attachment','state->psp = __get_PSP();','state->psp = 0u;',1,True),
            ('psp-preservation','Attachment','FIBER_REQUIRE(__get_PSP() == before->psp, \'P\');','(void)before->psp;',1,True),
            ('reference-skip','Reference','lsls r0, r0, #25','lsls r0, r0, #24',2,True),
            ('reference-save-count','Reference','stmdb r2!, {r4-r11}','stmdb r2!, {r4-r10}',1,True),
        ]
    return [
        ('save-count','Fiber','stmdb r0!, {r2-r11}','stmdb r0!, {r2-r10}',1,True),
        ('save-writeback','Fiber','stmdb r0!, {r2-r11}','stmdb r0, {r2-r11}',1,True),
        ('restore-count','Fiber','ldmia r0!, {r2-r11}','ldmia r0!, {r2-r10}',2,True),
        ('restore-writeback','Fiber','ldmia r0!, {r2-r11}','ldmia r0, {r2-r11}',2,True),
        ('wrong-security','Fiber','mvn   r3, #2','mvn   r3, #67',1,True),
        ('wrong-first-origin','Fiber','mvn   r3, #6','mvn   r3, #71',1,True),
        ('first-control-readback','Fiber','cmp   r1, #2','cmp   r1, #0',1,True),
        ('xpsr-offset','Fiber','[r0, %c[xpsr]]','[r0, #24]',1,False),
        ('builder-r9','Fiber','frame[fiber_portFRAME_R9] = initial_r9;','frame[fiber_portFRAME_R9] = (initial_r9 & 0u);',1,True),
        ('builder-pc','Fiber','fiber_port_stacked_pc((uintptr_t)ctx->boot.entry)','(uint32_t)(uintptr_t)ctx->boot.entry',1,True),
        ('builder-xpsr','Fiber','frame[fiber_portFRAME_XPSR] = fiber_port_initial_xpsr();','frame[fiber_portFRAME_XPSR] = 0u;',1,True),
        ('reference-save-count','Reference','stmdb r0!, {r2-r11}','stmdb r0!, {r2-r10}',1,True),
        ('reference-restore-count','Reference','ldmia r0!, {r2-r11}','ldmia r0!, {r2-r10}',1,True),
    ]
